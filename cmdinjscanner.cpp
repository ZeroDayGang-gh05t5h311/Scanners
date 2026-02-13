//g++ -w cmd_inj_scan_0.6.cpp $(pkg-config --cflags --libs -libs libxml-2.0) -lcurl -lssl -lcrypto -lpthread -o scanner
//sudo apt install libcurl4-openssl-dev libssl-dev libxml2-dev
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>
#include <iomanip>
#include <algorithm>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <libxml/HTMLparser.h>
using namespace std;
static const int CONCURRENCY = 8;
static const int REQUEST_TIMEOUT = 15;
static const double RATE_LIMIT_DELAY = 0.15;
static const int MAX_RETRIES = 2;
static const vector<string> SUPPORTED_METHODS =
    {"GET","POST","PUT","DELETE","PATCH"};
static const int METHOD_FAIL_LIMIT = 12;
static const vector<string> HEADER_KEYS_TO_TEST =
    {"User-Agent","Referer","X-Forwarded-For","X-Client-IP"};
static const vector<string> CMD_SEPARATORS = {";","|","&&","||"};
class Logger {
    mutex mtx;
    ofstream fh;
public:
    explicit Logger(const string& path) {
        fh.open(path, ios::app);
    }
    void log(const string& msg) {
        lock_guard<mutex> lock(mtx);
        auto t = chrono::system_clock::to_time_t(chrono::system_clock::now());
        fh << "[" << put_time(localtime(&t), "%F %T") << "] " << msg << "\n";
        cout << "[" << put_time(localtime(&t), "%F %T") << "] " << msg << endl;
    }
};
string sha256(const string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.data(), data.size(), hash);
    return string((char*)hash, SHA256_DIGEST_LENGTH);
}
string make_marker(const string& prefix="INJ") {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    random_device rd; mt19937 gen(rd());
    uniform_int_distribution<> d(0, sizeof(tbl)-2);
    string s = prefix + "-";
    for (int i=0;i<6;i++) s+=tbl[d(gen)];
    return s;
}
string percent_encode(const string& s) {
    ostringstream o;
    for (unsigned char c: s)
        o << "%" << hex << uppercase << setw(2) << setfill('0') << int(c);
    return o.str();
}
struct HttpResponse {
    string final_url;
    long status = 0;
    map<string,string> headers;
    string body;
};
class HTTPClient {
    Logger& logger;
    static size_t write_cb(void* c, size_t s, size_t n, void* p) {
        ((string*)p)->append((char*)c, s*n);
        return s*n;
    }
    static size_t header_cb(char* b, size_t s, size_t n, void* p) {
        string line(b, s*n);
        auto* h = (map<string,string>*)p;
        auto pos = line.find(':');
        if (pos != string::npos)
            (*h)[line.substr(0,pos)] = line.substr(pos+1);
        return s*n;
    }
public:
    explicit HTTPClient(Logger& l) : logger(l) {
        curl_global_init(CURL_GLOBAL_ALL);
    }
    vector<string> options(const string& url) {
        CURL* c = curl_easy_init();
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, "OPTIONS");
        curl_easy_setopt(c, CURLOPT_TIMEOUT, REQUEST_TIMEOUT);
        map<string,string> hdrs;
        curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(c, CURLOPT_HEADERDATA, &hdrs);
        curl_easy_perform(c);
        curl_easy_cleanup(c);
        if (hdrs.count("Allow")) {
            vector<string> out;
            stringstream ss(hdrs["Allow"]);
            string m;
            while (getline(ss,m,',')) {
                transform(m.begin(),m.end(),m.begin(),::toupper);
                out.push_back(m);
            }
            return out;
        }
        return {};
    }
    HttpResponse fetch(const string& url,
                       const string& method="GET",
                       const string& data="",
                       const map<string,string>& extra={}) {
        HttpResponse r;
        CURL* c = curl_easy_init();
        struct curl_slist* hdrs = nullptr;
        hdrs = curl_slist_append(hdrs, "User-Agent: SafeScannerStdLib/1.1");
        hdrs = curl_slist_append(hdrs, "Accept: */*");
        for (auto& h: extra)
            hdrs = curl_slist_append(hdrs,
                (h.first + ": " + h.second).c_str());
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, REQUEST_TIMEOUT);
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &r.body);
        curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(c, CURLOPT_HEADERDATA, &r.headers);
        if (method != "GET")
            curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
        if (!data.empty())
            curl_easy_setopt(c, CURLOPT_POSTFIELDS, data.c_str());
        logger.log("REQUEST " + method + " " + url);
        if (curl_easy_perform(c)==CURLE_OK) {
            curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.status);
            char* eff=nullptr;
            curl_easy_getinfo(c, CURLINFO_EFFECTIVE_URL, &eff);
            if (eff) r.final_url=eff;
        }
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(c);
        return r;
    }
};
class BaselineResponse {
    string url;
    long status;
    string hdr_hash;
    string body_hash;
public:
    explicit BaselineResponse(const HttpResponse& r) {
        url=r.final_url; status=r.status;
        vector<pair<string,string>> hs(r.headers.begin(),r.headers.end());
        sort(hs.begin(),hs.end());
        string h;
        for (auto& x:hs) h+=x.first+x.second;
        hdr_hash=sha256(h);
        body_hash=sha256(r.body);
    }
    bool differs(const HttpResponse& r) const {
        if (r.status!=status||r.final_url!=url) return true;
        vector<pair<string,string>> hs(r.headers.begin(),r.headers.end());
        sort(hs.begin(),hs.end());
        string h;
        for (auto& x:hs) h+=x.first+x.second;
        return sha256(h)!=hdr_hash || sha256(r.body)!=body_hash;
    }
};
struct Finding {
    double ts;
    string ctx,url,method,final;
    long status;
    vector<string> hits;
};
class SafeInjectionScanner {
    vector<string> targets;
    HTTPClient& client;
    Logger& logger;
    mutex mtx;
    vector<Finding> results;
    map<string,map<string,int>> method_fail;
    bool method_ok(const string& u,const string& m) {
        return method_fail[u][m] < METHOD_FAIL_LIMIT;
    }
    void record_fail(const string& u,const string& m) {
        if (++method_fail[u][m]==METHOD_FAIL_LIMIT)
            logger.log("SKIP "+m+" "+u+" (failure limit reached)");
    }
    void record(const Finding& f) {
        lock_guard<mutex> l(mtx);
        results.push_back(f);
        logger.log("FINDING "+f.ctx+" "+f.final);
    }
public:
    SafeInjectionScanner(const vector<string>& t,HTTPClient& c,Logger& l)
        : targets(t),client(c),logger(l){}
    void scan_target(const string& url) {
        logger.log("TARGET start "+url);
        auto allowed = client.options(url);
        auto methods = allowed.empty()?SUPPORTED_METHODS:allowed;
        auto base = client.fetch(url);
        BaselineResponse baseline(base);
        for (auto& m: methods) {
            if (!method_ok(url,m)) continue;
            try {
                for (auto& h: HEADER_KEYS_TO_TEST) {
                    string mk = make_marker();
                    auto r = client.fetch(url,m,"",{{h,mk}});
                    if (baseline.differs(r)&&r.body.find(mk)!=string::npos)
                        record({time(nullptr),"header:"+h,url,m,r.final_url,r.status,{"reflection"}});
                    this_thread::sleep_for(chrono::milliseconds(int(RATE_LIMIT_DELAY*1000)));
                }
            } catch (...) {
                record_fail(url,m);
            }
        }
        logger.log("TARGET done "+url);
    }
    void run() {
        atomic<size_t> i{0};
        vector<thread> th;
        for (int n=0;n<CONCURRENCY;n++)
            th.emplace_back([&](){
                while (true) {
                    size_t idx=i++;
                    if (idx>=targets.size()) break;
                    scan_target(targets[idx]);
                }
            });
        for (auto& t:th) t.join();
    }
};
int main(int argc,char* argv[]) {
    if (argc<2) {
        cerr<<"Usage: "<<argv[0]<<" <url>...\n";
        return 1;
    }
    vector<string> targets;
    for (int i=1;i<argc;i++) targets.push_back(argv[i]);
    Logger logger("scan.log");
    logger.log("Scan started");
    HTTPClient client(logger);
    SafeInjectionScanner scanner(targets,client,logger);
    scanner.run();
    logger.log("Scan complete");
    return 0;
};
