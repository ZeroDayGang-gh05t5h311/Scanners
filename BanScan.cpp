#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <condition_variable>
#include <algorithm>  // For std::sort
using namespace std::chrono;
static const size_t BANNER_READ_BYTES = 8192;
static std::map<int, std::string> DEFAULT_PORTS = {
    {21,  "ftp"},
    {22,  "ssh"},
    {23,  "telnet"},
    {25,  "smtp"},
    {53,  "dns-tcp"},
    {80,  "http"},
    {110, "pop3"},
    {143, "imap"},
    {443, "https"},
    {3306,"mysql"},
    {6379,"redis"},
    {8080,"http-alt"},
    {8443,"https-alt"}
};
class AutoSocket {f
public:
    int fd = -1;
    AutoSocket() {}
    explicit AutoSocket(int f) : fd(f) {}
    ~AutoSocket() { if (fd >= 0) close(fd); }
    AutoSocket(const AutoSocket&) = delete;
    AutoSocket& operator=(const AutoSocket&) = delete;
    AutoSocket(AutoSocket&& o) noexcept { fd = o.fd; o.fd = -1; }
    AutoSocket& operator=(AutoSocket&& o) noexcept {
        if (fd >= 0) close(fd);
        fd = o.fd;
        o.fd = -1;
        return *this;
    }
};
struct ScanResult {
    std::string host;
    int port;
    std::string service_guess;
    bool reachable = false;
    std::string banner;
    std::map<std::string,std::string> extra;      // TLS info, MySQL info, etc.
    std::map<std::string,std::string> http_headers;
    std::vector<std::string> notes;
    double duration_s = 0.0;
};
static bool set_socket_timeout(int sockfd, double seconds) {
    struct timeval tv;
    tv.tv_sec = (int)seconds;
    tv.tv_usec = (int)((seconds - tv.tv_sec) * 1e6);
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return false;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return true;
}
static std::string recv_all(int sockfd, double timeout, size_t max_bytes = BANNER_READ_BYTES) {
    set_socket_timeout(sockfd, timeout);
    std::string buffer;
    buffer.reserve(max_bytes);
    char tmp[2048];
    while (buffer.size() < max_bytes) {
        ssize_t n = recv(sockfd, tmp, sizeof(tmp), 0);
        if (n > 0) {
            buffer.append(tmp, n);
            if (buffer.find("\r\n\r\n") != std::string::npos) break;
        } else if (n == 0) break;
        else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            break;
        }
    }
    return buffer;
}
static const unsigned char MINIMAL_TLS_CH[] = {
    0x16,0x03,0x01,0x00,0x31, // TLS handshake record
    0x01,0x00,0x00,0x2d,      // ClientHello
    0x03,0x03,                // TLS 1.2
    // Random (32 bytes)
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,                     // sessionID length
    0x00,0x02,                // cipher suites length
    0x00,0x3c,                // TLS_RSA_WITH_AES_128_CBC_SHA256
    0x01,                     // compression methods length
    0x00                      // null compression
};
static void parse_tls_server_hello(const std::string& data, ScanResult& out) {
    if (data.size() < 10)
        return;
    // Extremely superficial: detect TLS version
    if ((unsigned char)data[1] == 0x03) {
        int minor = (unsigned char)data[2];
        out.extra["tls_version"] = std::string("TLS 1.") + std::to_string(minor - 1);
    }
    // Full certificate parsing would require ASN.1 — NOT included for safety.
    // Instead: detect if handshake contains certificate header.
    if (data.find("CERTIFICATE") != std::string::npos)
        out.extra["tls_note"] = "Certificate blob detected (not parsed)";
}
static void parse_mysql_hello(const std::string& b, ScanResult& out) {
    if (b.size() < 10) return;
    unsigned char protocol = b[4];
    out.extra["mysql_protocol"] = std::to_string(protocol);
    size_t p = 5;
    std::string version;
    while (p < b.size() && b[p] != '\0') version.push_back(b[p++]);
    if (!version.empty())
        out.extra["mysql_version"] = version;
}
static void parse_redis(const std::string& b, ScanResult& out) {
    if (b.size() == 0) return;
    if (b[0] == '+') out.extra["redis_type"] = "simple-string";
    else if (b[0] == '-') out.extra["redis_type"] = "error";
    else if (b[0] == ':') out.extra["redis_type"] = "integer";
    else if (b[0] == '$') out.extra["redis_type"] = "bulk-string";
    else if (b[0] == '*') out.extra["redis_type"] = "array";
}
static void parse_http(const std::string& data, ScanResult& out) {
    std::istringstream ss(data);
    std::string line;
    bool first = true;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first) {
            out.http_headers["status_line"] = line;
            first = false;
            continue;
        }
        auto p = line.find(':');
        if (p != std::string::npos) {
            std::string k = line.substr(0, p);
            std::string v = line.substr(p + 1);
            size_t a = v.find_first_not_of(" \t");
            if (a != std::string::npos) v = v.substr(a);
            out.http_headers[k] = v;
        }
    }
}
static ScanResult probe_tcp_banner(const std::string& host, int port, double timeout) {
    ScanResult out;
    out.host = host;
    out.port = port;
    out.service_guess = DEFAULT_PORTS.count(port) ? DEFAULT_PORTS[port] : "tcp";
    auto start = high_resolution_clock::now();
    addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
    if (gai != 0) {
        out.notes.push_back(std::string("resolve: ") + gai_strerror(gai));
        out.duration_s = duration<double>(high_resolution_clock::now() - start).count();
        return out;
    }
    AutoSocket sock;
    for (auto rp = res; rp; rp = rp->ai_next) {
        sock.fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock.fd < 0) continue;
        int flags = fcntl(sock.fd, F_GETFL, 0);
        fcntl(sock.fd, F_SETFL, flags | O_NONBLOCK);
        int c = connect(sock.fd, rp->ai_addr, rp->ai_addrlen);
        if (c == 0) {   // immediate connect
            fcntl(sock.fd, F_SETFL, flags);
            out.reachable = true;
            break;
        }
        if (errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock.fd, &wfds);
            timeval tv{
                (int)timeout,
                (int)((timeout - (int)timeout) * 1e6)
            };
            int sel = select(sock.fd + 1, nullptr, &wfds, nullptr, &tv);
            if (sel > 0) {
                int soerr = 0; socklen_t sl = sizeof(soerr);
                getsockopt(sock.fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
                if (soerr == 0) {
                    fcntl(sock.fd, F_SETFL, flags);
                    out.reachable = true;
                    break;
                }
            }
        }
        sock = AutoSocket();  // drop
    }
    freeaddrinfo(res);
    if (!out.reachable) {
        out.notes.push_back("unreachable: connect failed");
        out.duration_s = duration<double>(high_resolution_clock::now() - start).count();
        return out;
    }
    set_socket_timeout(sock.fd, timeout);
    if (port == 80 || port == 8080) {
        std::string req = "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: banner-scan\r\n\r\n";
        send(sock.fd, req.c_str(), req.size(), 0);
        out.banner = recv_all(sock.fd, timeout);
        parse_http(out.banner, out);
    }
    return out;
}
class TaskQueue {
public:
    std::queue<std::pair<std::string,int>> q;
    std::mutex m;

    void push(std::pair<std::string,int> t) {
        std::lock_guard<std::mutex> lk(m);
        q.push(t);
    }

    bool try_pop(std::pair<std::string,int>& o) {
        std::lock_guard<std::mutex> lk(m);
        if (q.empty()) return false;
        o = q.front();
        q.pop();
        return true;
    }
};
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: "<<argv[0]<<" host [--timeout 3] [--threads 8] [--json f] [--ports p1,p2,...]\n";
        return 1;
    }  
    std::string host = argv[1];
    double timeout = 3.0;
    int threads = 8;
    std::string json_file;
    std::string ports_override;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--timeout" && i + 1 < argc) timeout = std::stod(argv[++i]);
        else if (a == "--threads" && i + 1 < argc) threads = std::stoi(argv[++i]);
        else if (a == "--json" && i + 1 < argc) json_file = argv[++i];
        else if (a == "--ports" && i + 1 < argc) ports_override = argv[++i];
    }
    // Override default ports if specified
    if (!ports_override.empty()) {
        DEFAULT_PORTS.clear();
        std::stringstream ss(ports_override);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            int p = std::stoi(tok);
            DEFAULT_PORTS[p] = "tcp";
        }
    }
    // Output header
    std::cout << "[+] Banner scanner (ethical use only)\n";
    std::cout << "[+] Host: "<<host<<"\n";
    std::cout << "[+] Ports:";
    for (auto &p : DEFAULT_PORTS) std::cout << " " << p.first;
    std::cout << "\n";
    // Build tasks
    TaskQueue tq;
    for (auto& p : DEFAULT_PORTS) tq.push({host, p.first});
    std::vector<ScanResult> results;
    std::mutex results_mtx;
    // Worker thread function
    auto worker = [&]{
        while (true) {
            std::pair<std::string,int> t;
            if (!tq.try_pop(t)) break;
            ScanResult r = probe_tcp_banner(t.first, t.second, timeout);
            std::lock_guard<std::mutex> lk(results_mtx);
            results.push_back(std::move(r));
        }
    };
    int n = std::min(threads, (int)DEFAULT_PORTS.size());
    std::vector<std::thread> pool;
    for (int i = 0; i < n; i++) pool.emplace_back(worker);
    // Join threads
    for (auto& th : pool) th.join();
    // Sort results by port number
    std::sort(results.begin(), results.end(), [](const ScanResult& a, const ScanResult& b) {
        return a.port < b.port;
    });
    // Display results (you can implement custom output formatting here)
    for (const auto& res : results) {
        std::cout << "Host: " << res.host << " Port: " << res.port << " Service: " << res.service_guess;
        if (res.reachable) std::cout << " [reachable]";
        else std::cout << " [unreachable]";
        std::cout << "\n";
    }
    return 0;
};
