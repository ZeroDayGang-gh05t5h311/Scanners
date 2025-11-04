// Usage:
//   ./banner_scanner target_host [--timeout 3.0] [--threads 8] [--json out.json]
// Only run against systems you own or have explicit permission to test.
#include <iostream>
#include <vector>
#include <string>
#include <algorithm> 
#include <functional> 
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
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <queue>
#include <condition_variable>
#include <fstream>
#include <iomanip>

using namespace std::chrono;

static const std::map<int, std::string> DEFAULT_PORTS = {
    {21, "ftp"},
    {22, "ssh"},
    {23, "telnet"},
    {25, "smtp"},
    {80, "http"}
};

static const size_t BANNER_READ_BYTES = 4096;

struct ScanResult {
    std::string host;
    int port;
    std::string service_guess;
    bool reachable = false;
    std::string banner;
    // HTTP headers parsed (very simple map)
    std::map<std::string,std::string> http_headers;
    std::vector<std::string> notes;
    double duration_s = 0.0;
};

// Utility: set receive timeout on a socket (seconds as double)
static bool set_socket_timeout(int sockfd, double seconds) {
    struct timeval tv;
    tv.tv_sec = static_cast<int>(seconds);
    tv.tv_usec = static_cast<int>((seconds - tv.tv_sec) * 1e6);
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return false;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        // non-fatal
    }
    return true;
}

// recv_all: read up to max_bytes, return string (latin1-like, just raw bytes)
static std::string recv_all(int sockfd, double timeout, size_t max_bytes = BANNER_READ_BYTES) {
    set_socket_timeout(sockfd, timeout);
    std::string buffer;
    buffer.reserve(std::min(max_bytes, static_cast<size_t>(1024)));
    char tmp[2048];
    ssize_t n = 0;
    while (buffer.size() < max_bytes) {
        size_t to_read = std::min(sizeof(tmp), max_bytes - buffer.size());
        n = ::recv(sockfd, tmp, to_read, 0);
        if (n > 0) {
            buffer.append(tmp, static_cast<size_t>(n));
            // break early if HTTP headers likely complete
            if (buffer.find("\r\n\r\n") != std::string::npos) break;
            continue;
        } else if (n == 0) {
            // connection closed
            break;
        } else {
            // -1: error or timeout
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                // treat as timeout/temporary -> stop reading
                break;
            } else {
                // other error
                break;
            }
        }
    }
    return buffer;
}

// Attempt TCP connect to host:port and probe banner/headers
static ScanResult probe_tcp_banner(const std::string& host, int port, double timeout) {
    ScanResult out;
    out.host = host;
    out.port = port;
    auto it = DEFAULT_PORTS.find(port);
    out.service_guess = (it != DEFAULT_PORTS.end() ? it->second : "tcp");

    auto start = high_resolution_clock::now();

    // Resolve host
    struct addrinfo hints;
    struct addrinfo *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (gai != 0) {
        out.notes.push_back(std::string("getaddrinfo: ") + gai_strerror(gai));
        out.duration_s = duration<double>(high_resolution_clock::now() - start).count();
        return out;
    }

    // Try each addr until one connects
    int sockfd = -1;
    struct addrinfo *rp;
    for (rp = res; rp != nullptr; rp = rp->ai_next) {
        // set port in sockaddr
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)rp->ai_addr;
            sa->sin_port = htons(static_cast<uint16_t>(port));
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)rp->ai_addr;
            sa6->sin6_port = htons(static_cast<uint16_t>(port));
        } else {
            continue;
        }

        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) continue;

        // set connect timeout by making socket non-blocking, attempt connect, then select
        int flags = fcntl(sockfd, F_GETFL, 0);
        if (flags >= 0) fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        int c = connect(sockfd, rp->ai_addr, rp->ai_addrlen);
        if (c == 0) {
            // connected immediately
            // restore blocking
            if (flags >= 0) fcntl(sockfd, F_SETFL, flags);
            out.reachable = true;
            break;
        } else {
            if (errno == EINPROGRESS) {
                // wait for writability with timeout
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(sockfd, &wfds);
                struct timeval tv;
                tv.tv_sec = static_cast<int>(timeout);
                tv.tv_usec = static_cast<int>((timeout - tv.tv_sec) * 1e6);
                int sel = select(sockfd + 1, nullptr, &wfds, nullptr, &tv);
                if (sel > 0 && FD_ISSET(sockfd, &wfds)) {
                    // check for connect error
                    int soerr = 0;
                    socklen_t len = sizeof(soerr);
                    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0 || soerr != 0) {
                        close(sockfd);
                        sockfd = -1;
                        continue;
                    } else {
                        // connected
                        if (flags >= 0) fcntl(sockfd, F_SETFL, flags);
                        out.reachable = true;
                        break;
                    }
                } else {
                    // timeout or error
                    close(sockfd);
                    sockfd = -1;
                    continue;
                }
            } else {
                // immediate error
                close(sockfd);
                sockfd = -1;
                continue;
            }
        }
    }

    if (res) freeaddrinfo(res);

    if (sockfd < 0) {
        out.notes.push_back("unreachable: connect failed");
        out.duration_s = duration<double>(high_resolution_clock::now() - start).count();
        return out;
    }

    // Set timeouts for recv/send
    set_socket_timeout(sockfd, timeout);

    // Behavior by port
    if (port == 80) {
        // send HEAD request and read response
        std::ostringstream req;
        req << "HEAD / HTTP/1.1\r\nHost: " << host << "\r\nUser-Agent: banner-scanner/1.0\r\n\r\n";
        std::string reqs = req.str();
        ssize_t sent = send(sockfd, reqs.c_str(), (int)reqs.size(), 0);
        if (sent < 0) {
            out.notes.push_back(std::string("HTTP send error: ") + strerror(errno));
            // fallback to reading whatever arrives
            std::string data = recv_all(sockfd, timeout);
            out.banner = data;
        } else {
            std::string data = recv_all(sockfd, timeout);
            out.banner = data;
            // parse simple headers
            std::istringstream ss(data);
            std::string line;
            bool first = true;
            while (std::getline(ss, line)) {
                // remove possible '\r'
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (first) {
                    out.http_headers["status_line"] = line;
                    first = false;
                    continue;
                }
                auto pos = line.find(':');
                if (pos != std::string::npos) {
                    std::string k = line.substr(0, pos);
                    std::string v = line.substr(pos + 1);
                    // trim v
                    size_t a = v.find_first_not_of(" \t");
                    if (a != std::string::npos) v = v.substr(a);
                    else v.clear();
                    out.http_headers[k] = v;
                }
            }
        }
    } else if (port == 21 || port == 25 || port == 22 || port == 23) {
        // For FTP/SMTP/SSH/TELNET, try to read initial banner/greeting
        std::string data = recv_all(sockfd, timeout);
        out.banner = data;
    } else {
        std::string data = recv_all(sockfd, timeout);
        out.banner = data;
    }

    // Close socket
    close(sockfd);

    out.duration_s = duration<double>(high_resolution_clock::now() - start).count();
    return out;
}

// Thread-safe queue of (host,port) tasks
class TaskQueue {
public:
    void push(const std::pair<std::string,int>& t) {
        std::lock_guard<std::mutex> lk(m);
        q.push(t);
        cv.notify_one();
    }
    bool try_pop(std::pair<std::string,int>& out) {
        std::lock_guard<std::mutex> lk(m);
        if (q.empty()) return false;
        out = q.front();
        q.pop();
        return true;
    }
    bool empty() {
        std::lock_guard<std::mutex> lk(m);
        return q.empty();
    }

private:
    std::queue<std::pair<std::string,int>> q;
    std::mutex m;
    std::condition_variable cv;
};

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " target_host [--timeout 3.0] [--threads 8] [--json out.json]\n";
        return 1;
    }

    std::string host = argv[1];
    double timeout = 3.0;
    int threads = 8;
    std::string json_file;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--timeout" || a == "-t") {
            if (i + 1 < argc) { timeout = std::stod(argv[++i]); }
        } else if (a == "--threads" || a == "-T") {
            if (i + 1 < argc) { threads = std::stoi(argv[++i]); }
        } else if (a == "--json" || a == "-j") {
            if (i + 1 < argc) { json_file = argv[++i]; }
        } else {
            // ignore unknown
        }
    }

    std::cout << "[+] Ethical banner scanner - targeting " << host << "\n";
    std::cout << "[+] Ports:";
    for (const auto &p : DEFAULT_PORTS) std::cout << " " << p.first << "/" << p.second;
    std::cout << "\n[+] Timeout=" << timeout << "s   Threads=" << threads << "\n";
    std::cout << "Only run this against systems you own or have permission to test.\n\n";

    // build tasks
    TaskQueue tq;
    for (const auto &p : DEFAULT_PORTS) {
        tq.push({host, p.first});
    }

    std::vector<ScanResult> results;
    std::mutex results_mtx;

    // worker lambda
    auto worker = [&](void) {
        while (true) {
            std::pair<std::string,int> task;
            if (!tq.try_pop(task)) break;
            ScanResult r = probe_tcp_banner(task.first, task.second, timeout);
            {
                std::lock_guard<std::mutex> lk(results_mtx);
                results.push_back(std::move(r));
            }
        }
    };

    int use_threads = std::min<int>(threads, (int)DEFAULT_PORTS.size());
    std::vector<std::thread> pool;
    for (int i = 0; i < use_threads; ++i) pool.emplace_back(worker);
    for (auto &t : pool) if (t.joinable()) t.join();

    // sort results by port
    std::sort(results.begin(), results.end(), [](const ScanResult& a, const ScanResult& b){
        return a.port < b.port;
    });

    // print results
    for (const auto &r : results) {
        std::cout << std::string(60, '=') << "\n";
        std::cout << "Host: " << r.host << "  Port: " << r.port << "  Service-guess: " << r.service_guess << "\n";
        std::cout << "Reachable: " << (r.reachable ? "true" : "false") << "  Duration: " << std::fixed << std::setprecision(3) << r.duration_s << "s\n";
        if (!r.banner.empty()) {
            std::cout << "Banner / Response snippet:\n";
            std::string snippet = r.banner.substr(0, std::min<size_t>(1000, r.banner.size()));
            std::cout << snippet << "\n";
        }
        if (!r.http_headers.empty()) {
            std::cout << "HTTP headers (parsed):\n";
            for (const auto &kv : r.http_headers) {
                std::cout << "  " << kv.first << ": " << kv.second << "\n";
            }
        }
        if (!r.notes.empty()) {
            std::cout << "Notes: ";
            for (size_t i = 0; i < r.notes.size(); ++i) {
                if (i) std::cout << "; ";
                std::cout << r.notes[i];
            }
            std::cout << "\n";
        }
    }
    std::cout << std::string(60, '=') << "\n";

    if (!json_file.empty()) {
        // very simple JSON writer (no external deps)
        std::ofstream ofs(json_file);
        if (!ofs) {
            std::cerr << "[!] Failed to open " << json_file << " for writing\n";
        } else {
            ofs << "[\n";
            for (size_t i = 0; i < results.size(); ++i) {
                const auto &r = results[i];
                ofs << "  {\n";
                ofs << "    \"host\": " << std::quoted(r.host) << ",\n";
                ofs << "    \"port\": " << r.port << ",\n";
                ofs << "    \"service_guess\": " << std::quoted(r.service_guess) << ",\n";
                ofs << "    \"reachable\": " << (r.reachable ? "true" : "false") << ",\n";
                ofs << "    \"banner\": " << std::quoted(r.banner) << ",\n";
                ofs << "    \"http_headers\": {\n";
                size_t j = 0;
                for (const auto &h : r.http_headers) {
                    ofs << "      " << std::quoted(h.first) << ": " << std::quoted(h.second);
                    if (++j < r.http_headers.size()) ofs << ",";
                    ofs << "\n";
                }
                ofs << "    },\n";
                ofs << "    \"notes\": [";
                for (size_t k = 0; k < r.notes.size(); ++k) {
                    if (k) ofs << ", ";
                    ofs << std::quoted(r.notes[k]);
                }
                ofs << "],\n";
                ofs << "    \"duration_s\": " << std::fixed << std::setprecision(3) << r.duration_s << "\n";
                ofs << "  }";
                if (i + 1 < results.size()) ofs << ",";
                ofs << "\n";
            }
            ofs << "]\n";
            ofs.close();
            std::cout << "[+] Results written to " << json_file << "\n";
        }
    }

    return 0;
}
