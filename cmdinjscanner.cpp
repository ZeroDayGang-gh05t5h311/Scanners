// cmdinjscanner.cpp
// Extended: adds POST form testing, cookie/session support, and expanded crawler (recursive)
// Requires libcurl and C++17
// Compile: g++ -std=c++17 -lcurl -pthread -o safe_cmdinj_scanner safe_cmdinj_scanner_with_post_and_cookies.cpp
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <map>
#include <set>
#include <curl/curl.h>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <fstream>
using namespace std;

static mutex out_mtx;
static const int MAX_CRAWL_DEPTH = 2; // expanded crawler depth

// Simple curl writer
struct Memory {
    string data;
};
static size_t write_cb(void* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t realsize = size * nmemb;
    Memory* mem = (Memory*)userdata;
    mem->data.append((char*)ptr, realsize);
    return realsize;
}

string url_encode(const string &value) {
    CURL* curl = curl_easy_init();
    if (!curl) return value;
    char* output = curl_easy_escape(curl, value.c_str(), (int)value.length());
    string out = output ? string(output) : string();
    if (output) curl_free(output);
    curl_easy_cleanup(curl);
    return out;
}

// HTTP GET using a provided cookie file (session preservation)
string http_get_with_cookies(const string& url, long& out_code, double& elapsed, const string& cookiefile, struct curl_slist* headers = nullptr) {
    CURL* curl = curl_easy_init();
    Memory chunk;
    out_code = 0;
    elapsed = 0.0;
    if (!curl) return "";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    // cookies
    if (!cookiefile.empty()) {
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookiefile.c_str());
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookiefile.c_str());
    }
    if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        // leave data empty
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out_code);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
    curl_easy_cleanup(curl);
    return chunk.data;
}

// HTTP POST form (application/x-www-form-urlencoded) using cookies
string http_post_with_cookies(const string& url, const string& postfields, long& out_code, double& elapsed, const string& cookiefile, struct curl_slist* headers = nullptr) {
    CURL* curl = curl_easy_init();
    Memory chunk;
    out_code = 0;
    elapsed = 0.0;
    if (!curl) return "";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (!cookiefile.empty()) {
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookiefile.c_str());
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookiefile.c_str());
    }
    // set content-type if not provided
    struct curl_slist* local_headers = nullptr;
    if (headers) {
        local_headers = headers;
    } else {
        local_headers = curl_slist_append(nullptr, "Content-Type: application/x-www-form-urlencoded");
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, local_headers);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        // leave data empty
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out_code);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
    if (local_headers && !headers) curl_slist_free_all(local_headers);
    curl_easy_cleanup(curl);
    return chunk.data;
}

// find links with query parameters and simple form inputs (superficial)
vector<string> extract_urls_from_html(const string& base_url, const string& html) {
    vector<string> urls;
    try {
        regex href_re(R"((?i)href\s*=\s*['"]([^'"]+)['"])" );
        auto begin = sregex_iterator(html.begin(), html.end(), href_re);
        auto end_it = sregex_iterator();
        for (auto it = begin; it != end_it; ++it) {
            string href = (*it)[1].str();
            if (href.rfind("http://",0) == 0 || href.rfind("https://",0) == 0) {
                urls.push_back(href);
            } else if (!href.empty() && href[0] == '/') {
                try {
                    regex host_re(R"(^((?:https?://[^/]+)))");
                    smatch m;
                    if (regex_search(base_url, m, host_re)) {
                        urls.push_back(m[1].str() + href);
                    }
                } catch(...) {}
            }
        }
        // also scan simple forms (action attr)
        regex form_re(R"((?i)<form[^>]*action\s*=\s*['"]?([^'">\s]+))");
        begin = sregex_iterator(html.begin(), html.end(), form_re);
        for (auto it = begin; it != end_it; ++it) {
            string action = (*it)[1].str();
            if (action.rfind("http://",0) == 0 || action.rfind("https://",0) == 0) {
                urls.push_back(action);
            } else if (!action.empty() && action[0] == '/') {
                regex host_re(R"(^((?:https?://[^/]+)))");
                smatch m;
                if (regex_search(base_url, m, host_re)) {
                    urls.push_back(m[1].str() + action);
                }
            }
        }
    } catch(...) {}
    // de-duplicate
    set<string> s(urls.begin(), urls.end());
    vector<string> out(s.begin(), s.end());
    return out;
}

// Form representation (superficial extraction)
struct Form {
    string action;
    string method; // GET or POST
    map<string,string> inputs; // name -> value (default if available)
};

// extract forms and inputs (superficial) from HTML
vector<Form> extract_forms(const string& base_url, const string& html) {
    vector<Form> forms;
    try {
        regex form_block_re(R"((?i)<form\b([^>]*)>([\s\S]*?)</form>)");
        auto begin = sregex_iterator(html.begin(), html.end(), form_block_re);
        auto end_it = sregex_iterator();
        for (auto it = begin; it != end_it; ++it) {
            string attrs = (*it)[1].str();
            string inner = (*it)[2].str();
            Form f;
            // extract action
            try {
                regex action_re(R"((?i)action\s*=\s*['"]([^'"]+)['"])" );
                smatch m;
                if (regex_search(attrs, m, action_re)) {
                    f.action = m[1].str();
                }
                // method
                regex method_re(R"((?i)method\s*=\s*['"]?([a-zA-Z]+)['"]?)");
                if (regex_search(attrs, m, method_re)) {
                    f.method = m[1].str();
                } else {
                    f.method = "GET";
                }
                if (f.action.empty()) {
                    // treat as same-page
                    f.action = base_url;
                } else if (f.action.rfind("http://",0) != 0 && f.action.rfind("https://",0) != 0 && f.action[0] == '/') {
                    regex host_re(R"(^((?:https?://[^/]+)))");
                    smatch hm;
                    if (regex_search(base_url, hm, host_re)) {
                        f.action = hm[1].str() + f.action;
                    }
                } else if (f.action.rfind("http://",0) != 0 && f.action.rfind("https://",0) != 0) {
                    // relative path without leading slash: append to base path
                    // naive: remove query/fragment from base_url
                    auto qpos = base_url.find('?');
                    string base = (qpos==string::npos) ? base_url : base_url.substr(0,qpos);
                    auto last_slash = base.rfind('/');
                    if (last_slash != string::npos) base = base.substr(0, last_slash+1);
                    f.action = base + f.action;
                }
            } catch(...) {}

            // find input fields within inner HTML
            try {
                regex input_re(R"((?i)<input\b([^>]*)>)");
                auto ibegin = sregex_iterator(inner.begin(), inner.end(), input_re);
                for (auto it2 = ibegin; it2 != end_it; ++it2) {
                    string iattrs = (*it2)[1].str();
                    smatch im;
                    regex name_re(R"((?i)name\s*=\s*['"]([^'"]+)['"])" );
                    if (regex_search(iattrs, im, name_re)) {
                        string name = im[1].str();
                        string value = "";
                        regex value_re(R"((?i)value\s*=\s*['"]([^'"]*)['"])" );
                        smatch vm;
                        if (regex_search(iattrs, vm, value_re)) value = vm[1].str();
                        // ignore type=submit without name
                        forms.push_back(Form()); // placeholder to keep indices consistent
                        f.inputs[name] = value;
                    }
                }
                // also textarea
                regex ta_re(R"((?i)<textarea\b([^>]*)>([\s\S]*?)</textarea>)");
                auto tbegin = sregex_iterator(inner.begin(), inner.end(), ta_re);
                for (auto it3 = tbegin; it3 != end_it; ++it3) {
                    string attrs2 = (*it3)[1].str();
                    string val = (*it3)[2].str();
                    smatch tm;
                    regex name_re(R"((?i)name\s*=\s*['"]([^'"]+)['"])" );
                    if (regex_search(attrs2, tm, name_re)) {
                        string name = tm[1].str();
                        f.inputs[name] = val;
                    }
                }
                // select elements (pick first option)
                regex sel_re(R"((?i)<select\b([^>]*)>([\s\S]*?)</select>)");
                auto sbegin = sregex_iterator(inner.begin(), inner.end(), sel_re);
                for (auto it4 = sbegin; it4 != end_it; ++it4) {
                    string sattrs = (*it4)[1].str();
                    string inneroptions = (*it4)[2].str();
                    smatch smt;
                    regex name_re(R"((?i)name\s*=\s*['"]([^'"]+)['"])" );
                    if (regex_search(sattrs, smt, name_re)) {
                        string name = smt[1].str();
                        // find first option value or inner text
                        regex option_re(R"((?i)<option\b([^>]*)>([\s\S]*?)</option>)");
                        smatch om;
                        if (regex_search(inneroptions, om, option_re)) {
                            string optattrs = om[1].str();
                            string optval = om[2].str();
                            smatch ovm;
                            regex val_re(R"((?i)value\s*=\s*['"]([^'"]+)['"])" );
                            if (regex_search(optattrs, ovm, val_re)) f.inputs[name] = ovm[1].str();
                            else f.inputs[name] = optval;
                        }
                    }
                }
            } catch(...) {}
            forms.push_back(f);
        }
    } catch(...) {}
    return forms;
}

map<string, vector<string>> gather_parameters(const string& url) {
    map<string, vector<string>> params;
    try {
        regex q_re(R"(\?(.+))");
        smatch m;
        if (regex_search(url, m, q_re)) {
            string qs = m[1].str();
            auto pos = qs.find('#'); if (pos != string::npos) qs = qs.substr(0,pos);
            regex pair_re(R"(([^&=]+)=([^&]*)?)");
            auto it = sregex_iterator(qs.begin(), qs.end(), pair_re);
            auto end_it = sregex_iterator();
            for (; it != end_it; ++it) {
                string k = (*it)[1].str();
                string v = (*it)[2].str();
                params[k].push_back(v);
            }
        }
    } catch(...) {}
    return params;
}

struct ProbeResult {
    string url;
    string param;
    string payload;
    bool reflected = false;
    bool status_changed = false;
    bool length_changed = false;
    string note;
};

vector<string> safe_payloads() {
    return {
        "INJTEST_123;echo;",
        "INJTEST_123&&true",
        "INJTEST_123|true",
        "INJTEST_123`echo`",
        "INJTEST_123>out",
        "INJTEST_123<in",
        "INJTEST_123$((1))",
        "INJTEST_'\";--",
        "INJTEST_`rm`"
    };
}

vector<string> error_indicators() {
    return {
        "syntax error", "command not found", "sh:", "bash:", "error executing", "unexpected token",
        "php error", "warning:", "exception", "traceback"
    };
}

void safe_println(const string& s) {
    lock_guard<mutex> g(out_mtx);
    cout << s << endl;
}

// Test GET parameter (same as before, but uses cookiefile)
ProbeResult test_parameter_get(const string& base_url, const string& param, const string& baseline_body, long baseline_code, size_t baseline_len, const string& cookiefile) {
    ProbeResult pr;
    pr.url = base_url;
    pr.param = param;
    vector<string> payloads = safe_payloads();
    for (const string& payload : payloads) {
        auto qpos = base_url.find('?');
        if (qpos==string::npos) continue;
        string base = base_url.substr(0,qpos);
        string qs = base_url.substr(qpos+1);
        vector<string> parts;
        size_t start = 0;
        while (start < qs.size()) {
            auto amp = qs.find('&', start);
            if (amp==string::npos) amp = qs.size();
            parts.push_back(qs.substr(start, amp-start));
            start = amp + 1;
        }
        bool found=false;
        for (auto &p : parts) {
            auto eq = p.find('=');
            string k = eq==string::npos ? p : p.substr(0,eq);
            if (k == param) {
                string newv = url_encode(payload);
                p = k + "=" + newv;
                found=true;
            }
        }
        if (!found) continue;
        string newqs;
        for (size_t i=0;i<parts.size();++i) {
            if (i) newqs += "&";
            newqs += parts[i];
        }
        string target = base + "?" + newqs;
        long code=0; double elapsed=0.0;
        string body = http_get_with_cookies(target, code, elapsed, cookiefile);
        size_t len = body.size();
        bool reflected = (body.find(payload) != string::npos);
        bool status_changed = (code != baseline_code);
        bool length_changed = (len != baseline_len);
        bool suspicious_error = false;
        for (const auto& ind : error_indicators()) {
            string lwr = body;
            transform(lwr.begin(), lwr.end(), lwr.begin(), [](unsigned char c){ return tolower(c); });
            string lind = ind;
            transform(lind.begin(), lind.end(), lind.begin(), [](unsigned char c){ return tolower(c); });
            if (lwr.find(lind) != string::npos) { suspicious_error = true; break; }
        }
        if (reflected || status_changed || length_changed || suspicious_error) {
            pr.payload = payload;
            pr.reflected = reflected;
            pr.status_changed = status_changed;
            pr.length_changed = length_changed;
            stringstream ss;
            if (reflected) ss << "Payload reflected in response. ";
            if (status_changed) ss << "HTTP status changed (" << baseline_code << " -> " << code << "). ";
            if (length_changed) ss << "Response length changed (" << baseline_len << " -> " << len << "). ";
            if (suspicious_error) ss << "Suspicious error text found. ";
            ss << "Elapsed=" << fixed << setprecision(2) << elapsed << "s.";
            pr.note = ss.str();
            return pr;
        }
    }
    pr.note = "No suspicious differences detected with safe payloads.";
    return pr;
}

// Test POST form inputs. We will submit application/x-www-form-urlencoded posts with payloads substituted into each named input.
ProbeResult test_form_post(const Form& form, const string& param, const string& baseline_body, long baseline_code, size_t baseline_len, const string& cookiefile) {
    ProbeResult pr;
    pr.url = form.action;
    pr.param = param;
    vector<string> payloads = safe_payloads();
    for (const string& payload : payloads) {
        // build postfields by taking all inputs and replacing the one named param
        vector<string> parts;
        for (auto &kv : form.inputs) {
            string k = kv.first;
            string v = kv.second;
            if (k == param) v = payload;
            parts.push_back(url_encode(k) + "=" + url_encode(v));
        }
        string postfields;
        for (size_t i=0;i<parts.size();++i) {
            if (i) postfields += "&";
            postfields += parts[i];
        }
        long code=0; double elapsed=0.0;
        string body = http_post_with_cookies(form.action, postfields, code, elapsed, cookiefile);
        size_t len = body.size();
        bool reflected = (body.find(payload) != string::npos);
        bool status_changed = (code != baseline_code);
        bool length_changed = (len != baseline_len);
        bool suspicious_error = false;
        for (const auto& ind : error_indicators()) {
            string lwr = body;
            transform(lwr.begin(), lwr.end(), lwr.begin(), [](unsigned char c){ return tolower(c); });
            string lind = ind;
            transform(lind.begin(), lind.end(), lind.begin(), [](unsigned char c){ return tolower(c); });
            if (lwr.find(lind) != string::npos) { suspicious_error = true; break; }
        }
        if (reflected || status_changed || length_changed || suspicious_error) {
            pr.payload = payload;
            pr.reflected = reflected;
            pr.status_changed = status_changed;
            pr.length_changed = length_changed;
            stringstream ss;
            if (reflected) ss << "Payload reflected in response. ";
            if (status_changed) ss << "HTTP status changed (" << baseline_code << " -> " << code << "). ";
            if (length_changed) ss << "Response length changed (" << baseline_len << " -> " << len << "). ";
            if (suspicious_error) ss << "Suspicious error text found. ";
            ss << "Elapsed=" << fixed << setprecision(2) << elapsed << "s.";
            pr.note = ss.str();
            return pr;
        }
    }
    pr.note = "No suspicious differences detected with safe payloads (POST).";
    return pr;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <target-url> [--aggressive]" << endl;
        cout << "Example: " << argv[0] << " https://example.com/page?arg=1" << endl;
        cout << "\nNOTE: This tool is non-destructive by default and intended for use only\n";
        cout << "on sites you own or have explicit permission to test.\n";
        return 1;
    }
    string target = argv[1];
    bool aggressive = false;
    if (argc >=3 && string(argv[2]) == "--aggressive") aggressive = true;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    // create a temporary cookie file path in current directory
    string cookiefile = "scanner_cookies.txt";
    try {
        // ensure file exists
        ofstream cf(cookiefile, ios::app);
        cf.close();
    } catch(...) {}
    // Fetch baseline (using cookie/session)
    long base_code = 0; double base_elapsed = 0.0;
    string base_body = http_get_with_cookies(target, base_code, base_elapsed, cookiefile);
    size_t base_len = base_body.size();
    safe_println("[*] Baseline fetched. HTTP code: " + to_string(base_code) + "  length: " + to_string(base_len));
    // Expanded crawler: BFS up to MAX_CRAWL_DEPTH
    vector<string> to_crawl;
    set<string> seen;
    to_crawl.push_back(target);
    seen.insert(target);
    vector<string> discovered_urls; // will hold all discovered URLs
    vector<Form> discovered_forms;
    for (int depth = 0; depth <= MAX_CRAWL_DEPTH; ++depth) {
        vector<string> next_round;
        for (const auto& url : to_crawl) {
            long code=0; double elapsed=0.0;
            string body = http_get_with_cookies(url, code, elapsed, cookiefile);
            if (body.empty()) continue;
            // extract urls and add unseen
            auto urls = extract_urls_from_html(url, body);
            for (auto &u : urls) {
                if (seen.insert(u).second) {
                    next_round.push_back(u);
                }
            }
            // extract forms and collect
            auto forms = extract_forms(url, body);
            for (auto &f : forms) discovered_forms.push_back(f);
            // also consider the page itself for parameter testing
            discovered_urls.push_back(url);
        }
        to_crawl = move(next_round);
        if (to_crawl.empty()) break;
    }
    // dedupe discovered_urls
    sort(discovered_urls.begin(), discovered_urls.end());
    discovered_urls.erase(unique(discovered_urls.begin(), discovered_urls.end()), discovered_urls.end());
    safe_println("[*] Found " + to_string(discovered_urls.size()) + " page(s) and " + to_string(discovered_forms.size()) + " form(s) to examine.");

    vector<ProbeResult> findings;
    mutex findings_mtx;
    atomic<int> idx(0);

    // Combine both GET parameter testing on discovered_urls and POST form testing on discovered_forms
    // We'll create a worker that iterates both lists deterministically: first pages, then forms
    vector<string> pages = discovered_urls; // copy
    vector<Form> forms = discovered_forms; // copy
    auto worker_fn = [&](){
        // process pages
        while (true) {
            int i = idx.fetch_add(1);
            if (i < (int)pages.size()) {
                string url = pages[i];
                auto params = gather_parameters(url);
                if (params.empty()) continue;
                for (auto &kv : params) {
                    string param = kv.first;
                    ProbeResult pr = test_parameter_get(url, param, base_body, base_code, base_len, cookiefile);
                    if (!(pr.payload.empty() && pr.note.find("No suspicious")!=string::npos)) {
                        lock_guard<mutex> g(findings_mtx);
                        findings.push_back(pr);
                    }
                }
                continue;
            }
            // pages finished; process forms - compute index by offset
            int form_index = i - (int)pages.size();
            if (form_index >= (int)forms.size()) break;
            Form f = forms[form_index];
            for (auto &kv : f.inputs) {
                string param = kv.first;
                // only test POST forms for POST method; if method is GET we can build URL with params
                if (f.method.empty()) f.method = "GET";
                if (f.method == "GET" || f.method == "get") {
                    // build a URL with query string from inputs
                    string constructed = f.action;
                    string qs;
                    for (auto &ip : f.inputs) {
                        if (!qs.empty()) qs += "&";
                        qs += url_encode(ip.first) + "=" + url_encode(ip.second);
                    }
                    if (constructed.find('?')==string::npos) constructed += "?" + qs;
                    ProbeResult pr = test_parameter_get(constructed, param, base_body, base_code, base_len, cookiefile);
                    if (!(pr.payload.empty() && pr.note.find("No suspicious")!=string::npos)) {
                        lock_guard<mutex> g(findings_mtx);
                        findings.push_back(pr);
                    }
                } else {
                    ProbeResult pr = test_form_post(f, param, base_body, base_code, base_len, cookiefile);
                    if (!(pr.payload.empty() && pr.note.find("No suspicious")!=string::npos)) {
                        lock_guard<mutex> g(findings_mtx);
                        findings.push_back(pr);
                    }
                }
            }
        }
    };

    int threads_n = min(8, (int)pages.size() + (int)forms.size());
    if (threads_n <= 0) threads_n = 1;
    vector<thread> workers;
    for (int t=0;t<threads_n;++t) workers.emplace_back(worker_fn);
    for (auto &th : workers) if (th.joinable()) th.join();
    // Report
    safe_println("\n=== Scan report ===");
    if (findings.empty()) {
        safe_println("No suspicious handling detected using safe probes. Review manually for logic flaws.");
    } else {
        for (auto &f : findings) {
            safe_println("URL: " + f.url);
            safe_println(" Param: " + f.param);
            safe_println(" Payload: " + f.payload);
            safe_println(" Findings: " + f.note);
            safe_println("-----------------------------");
        }
    }
    if (aggressive) {
        safe_println("\n[!] Aggressive mode was requested. WARNING: aggressive tests may run commands on the server.");
        safe_println("This tool will not auto-run aggressive tests — implement them yourself only after confirming ownership.");
    } else {
        safe_println("\n[+] Finished (safe mode). To enable more intrusive tests, re-run with --aggressive (ONLY on systems you own).");
    }
    // cleanup cookie file
    try {
        // keep cookie file for session debugging; comment out the remove if you want to preserve it
        // filesystem::remove(cookiefile);
    } catch(...) {}
    curl_global_cleanup();
    return 0;
}
