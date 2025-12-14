#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <sstream>
#include <vector>
#include <regex>
#include <filesystem>
#include <set>
#include <fstream>
#include <future>
#include <mutex>
#include <thread>
using namespace std;
namespace fs = std::filesystem;
constexpr size_t LINES_PER_TASK = 500;
struct PatternGroup {
    string name;
    vector<regex> patterns;
};
vector<PatternGroup> get_asm_vuln_patterns() {
    return {
        {"Buffer Overflow / Unsafe Memory Operations", {
            regex(R"(\b(call\s+)?strcpy\b)", regex_constants::icase),
            regex(R"(\b(call\s+)?strncpy\b)", regex_constants::icase),
            regex(R"(\b(call\s+)?strcat\b)", regex_constants::icase),
            regex(R"(\b(call\s+)?strncat\b)", regex_constants::icase),
            regex(R"(\b(call\s+)?gets\b)", regex_constants::icase),
            regex(R"(\b(call\s+)?scanf\b)", regex_constants::icase),
            regex(R"(\b(call\s+)?fscanf\b)", regex_constants::icase),
            regex(R"(\b(call\s+)?sscanf\b)", regex_constants::icase),
            regex(R"(\b(call\s+)?memcpy\b)", regex_constants::icase),
            regex(R"(\b(call\s+)?memmove\b)", regex_constants::icase),
            regex(R"(\bmovs\b)", regex_constants::icase),
            regex(R"(\bstosb\b|\bstosd\b|\bstosw\b)", regex_constants::icase),
            regex(R"(\bcmps\b)", regex_constants::icase),
            regex(R"(\blods\b|lodsb|lodsw|lodsd)", regex_constants::icase),
            regex(R"(\b(xor|add|sub)\s+[a-z0-9]+,\s*\[.*\])", regex_constants::icase)
        }},
        {"Unsafe Function Call / Library Routines", {
            regex(R"(\bcall\s+strcpy\b)", regex_constants::icase),
            regex(R"(\bcall\s+strncpy\b)", regex_constants::icase),
            regex(R"(\bcall\s+strcat\b)", regex_constants::icase),
            regex(R"(\bcall\s+strncat\b)", regex_constants::icase),
            regex(R"(\bcall\s+gets\b)", regex_constants::icase),
            regex(R"(\bcall\s+scanf\b)", regex_constants::icase),
            regex(R"(\bcall\s+fscanf\b)", regex_constants::icase),
            regex(R"(\bcall\s+sscanf\b)", regex_constants::icase),
            regex(R"(\bcall\s+system\b)", regex_constants::icase),
            regex(R"(\bcall\s+popen\b)", regex_constants::icase),
            regex(R"(\bcall\s+execve\b)", regex_constants::icase)
        }},
        {"Hardcoded Secrets / Data Strings", {
            regex(R"(\b(db|data)\s+\".*(password|secret|key|token|credential).*\")", regex_constants::icase)
        }},
        {"Privilege / Permissions / Escalation Instructions", {
            regex(R"(\biopl\b)", regex_constants::icase),
            regex(R"(\bitsl\b)", regex_constants::icase),
            regex(R"(\bcli\b)", regex_constants::icase),
            regex(R"(\bsti\b)", regex_constants::icase),
            regex(R"(\bout\s+)", regex_constants::icase),
            regex(R"(\bin\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\b(setuid|setgid|chmod|chown|rwx)\b)", regex_constants::icase)
        }},
        {"Suspicious Syscalls / Interrupts", {
            regex(R"(\bint\s+0x80\b)", regex_constants::icase),
            regex(R"(\bsyscall\b)", regex_constants::icase),
            regex(R"(\bint\s+0x2e\b)", regex_constants::icase),
            regex(R"(\bint\s+0x81\b)", regex_constants::icase),
            regex(R"(\bint\s+0x82\b)", regex_constants::icase),
            regex(R"(\bint\s+0x90\b)", regex_constants::icase),
            regex(R"(\btrap\b)", regex_constants::icase),
            regex(R"(\beret\b)", regex_constants::icase)
        }},
        {"Control Flow / Return Oriented Programming (ROP) / Jump Gadgets", {
            regex(R"(\bjmp\s*\[.*\])", regex_constants::icase),
            regex(R"(\bcall\s*\[.*\])", regex_constants::icase),
            regex(R"(\b(push|pop)\s+[^\n]*;\s*ret\b)", regex_constants::icase),
            regex(R"(ret\s*$)", regex_constants::icase),
            regex(R"(leave\s*$)", regex_constants::icase)
        }},
        {"Format String / Debug / Info Leakage", {
            regex(R"(\b(odbc|printf|sprintf|vsprintf|wprintf|wprintf_s|debug|printk)\b)", regex_constants::icase)
        }},
        {"Arithmetic / Overflow Risks", {
            regex(R"(\b(add|sub|mul|imul|div|divl)\b.*\[(rbp|rsp)[^\]]*\])", regex_constants::icase),
            regex(R"(\bjo\b|\bjc\b)", regex_constants::icase)
        }}
    };
}
string exec_objdump(const string& binary_path, bool verbose) {
    array<char, 256> buf{};
    unique_ptr<FILE, decltype(&pclose)> chk(
        popen("objdump --version 2>/dev/null", "r"), pclose);
    if (!chk || !fgets(buf.data(), buf.size(), chk.get()))
        throw runtime_error("objdump not available");
    string cmd = "objdump -d \"" + binary_path + "\" 2>/dev/null";
    if (verbose) cerr << "[DEBUG] " << cmd << "\n";
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw runtime_error("objdump failed");
    string out;
    while (fgets(buf.data(), buf.size(), pipe.get()))
        out += buf.data();
    if (out.empty()) throw runtime_error("objdump produced no output");
    return out;
}
vector<string> scan_asm_text(
    const string& asm_text,
    const vector<PatternGroup>& pattern_groups,
    const string& source_name,
    size_t max_workers,
    bool verbose
) {
    vector<string> results;
    set<string> seen;
    mutex seen_mutex;

    if (!max_workers) {
        max_workers = thread::hardware_concurrency();
        if (!max_workers) max_workers = 4;
    }
    istringstream iss(asm_text);
    vector<pair<int,string>> chunk;
    vector<future<vector<string>>> futures;
    string line;
    int ln = 0;
    auto worker = [&](vector<pair<int,string>> c) {
        return async(launch::async, [&, c]() {
            vector<string> local;
            for (auto& [n, txt] : c) {
                string norm = regex_replace(txt, regex("\\s+"), " ");
                for (auto& g : pattern_groups) {
                    for (auto& re : g.patterns) {
                        if (regex_search(norm, re)) {
                            string id = g.name + ":" + to_string(n);
                            lock_guard<mutex> lg(seen_mutex);
                            if (seen.insert(id).second)
                                local.push_back("[" + g.name + "] " +
                                    source_name + ":" + to_string(n) + ": " + txt);
                        }
                    }
                }
            }
            return local;
        });
    };
    while (getline(iss, line)) {
        chunk.emplace_back(++ln, line);
        if (chunk.size() >= LINES_PER_TASK) {
            if (futures.size() >= max_workers) {
                auto r = futures.front().get();
                results.insert(results.end(), r.begin(), r.end());
                futures.erase(futures.begin());
            }
            futures.push_back(worker(chunk));
            chunk.clear();
        }
    }
    if (!chunk.empty())
        futures.push_back(worker(chunk));
    for (auto& f : futures) {
        auto r = f.get();
        results.insert(results.end(), r.begin(), r.end());
    }
    return results;
}
int main(int argc, char** argv) {
    if (argc < 3) {
        cerr << "Usage:\n"
             << "  asm_scanner --asm <asm_file_path> [--verbose] [--log <log_file>]\n"
             << "  asm_scanner --bin <binary_file_path> [--verbose] [--log <log_file>]\n";
        return 1;
    }
    string mode = argv[1], path = argv[2];
    bool verbose = false;
    string log_path;
    for (int i = 3; i < argc; ++i) {
        if (string(argv[i]) == "--verbose") verbose = true;
        else if (string(argv[i]) == "--log" && i + 1 < argc) log_path = argv[++i];
    }
    ofstream log;
    if (!log_path.empty()) log.open(log_path);
    try {
        string asm_text;
        if (mode == "--asm") {
            ifstream f(path);
            if (!f) throw runtime_error("ASM file open failed");
            ostringstream ss; ss << f.rdbuf();
            asm_text = ss.str();
        } else if (mode == "--bin") {
            asm_text = exec_objdump(path, verbose);
        } else throw runtime_error("Unknown mode");
        auto issues = scan_asm_text(
            asm_text, get_asm_vuln_patterns(), path,
            thread::hardware_concurrency(), verbose);
        if (issues.empty()) {
            cout << " No potential vulnerabilities found.\n";
            if (log) log << " No potential vulnerabilities found.\n";
        } else {
            cout << " Potential vulnerabilities detected:\n";
            if (log) log << " Potential vulnerabilities detected:\n";
            for (auto& i : issues) {
                cout << i << "\n";
                if (log) log << i << "\n";
            }
        }
    } catch (const exception& e) {
        cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
};
