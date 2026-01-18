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
#include <future>  // Added for parallelism
#include <mutex>
#include <thread>
#include <chrono>
using namespace std;
namespace fs = std::filesystem;
struct PatternGroup {
    string name;
    vector<regex> patterns; // precompiled regexes
};
// Extended patterns for assembly vulnerabilities
vector<PatternGroup> get_asm_vuln_patterns() {
    return {
        {"Buffer Overflow / Unsafe Memory Operations", {
            regex(R"(\bstrcpy\b)", regex_constants::icase),
            regex(R"(\bstrncpy\b)", regex_constants::icase),
            regex(R"(\bstrcat\b)", regex_constants::icase),
            regex(R"(\bstrncat\b)", regex_constants::icase),
            regex(R"(\bgets\b)", regex_constants::icase),
            regex(R"(\bscanf\b)", regex_constants::icase),
            regex(R"(\bfscanf\b)", regex_constants::icase),
            regex(R"(\bsscanf\b)", regex_constants::icase),
            regex(R"(\bmemcpy\b)", regex_constants::icase),
            regex(R"(\bmemmove\b)", regex_constants::icase),
            regex(R"(\bmovs\b)", regex_constants::icase),
            regex(R"(\bstosb\b|\bstosd\b|\bstosw\b)", regex_constants::icase),
            regex(R"(\bcmps\b)", regex_constants::icase),
            regex(R"(\blods\b|lodsb|lodsw|lodsd)", regex_constants::icase),
            regex(R"(\bxor\s+[a-z0-9]+,\s*\[.*\])", regex_constants::icase),
            regex(R"(\badd\s+[a-z0-9]+,\s*\[.*\])", regex_constants::icase),
            regex(R"(\bsub\s+[a-z0-9]+,\s*\[.*\])", regex_constants::icase)
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
            regex(R"(\bdb\s+\".*password.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*secret.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*key.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*token.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*credential.*\")", regex_constants::icase),
            regex(R"(\bdata\s+\".*password.*\")", regex_constants::icase),
            regex(R"(\bdata\s+\".*secret.*\")", regex_constants::icase)
        }},
        {"Privilege / Permissions / Escalation Instructions", {
            regex(R"(\biopl\b)", regex_constants::icase),
            regex(R"(\bitsl\b)", regex_constants::icase),
            regex(R"(\bcli\b)", regex_constants::icase),
            regex(R"(\bsti\b)", regex_constants::icase),
            regex(R"(\bout\s+)", regex_constants::icase),
            regex(R"(\bin\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\bsetuid\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\bsetgid\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\bchmod\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\bchown\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\brwx\b)", regex_constants::icase)
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
            regex(R"(\bjmp\s+[a-zA-Z0-9_]+\b)", regex_constants::icase),
            regex(R"(\bjmp\s*\[.*\])", regex_constants::icase),
            regex(R"(\bcall\s*\[.*\])", regex_constants::icase),
            regex(R"(\bpush\s+[^\n]*; ret\b)", regex_constants::icase),
            regex(R"(\bpop\s+[^\n]*; ret\b)", regex_constants::icase),
            regex(R"(\bret\b)", regex_constants::icase),
            regex(R"(\bleave\b)", regex_constants::icase)
        }},
        {"Format String / Debug / Info Leakage", {
            regex(R"(\bodbc\b|\bprintf\b|\bsprintf\b|\bvsprintf\b)", regex_constants::icase),
            regex(R"(\bprintf\b)", regex_constants::icase),
            regex(R"(\bsprintf\b)", regex_constants::icase),
            regex(R"(\bvsprintf\b)", regex_constants::icase),
            regex(R"(\bwprintf\b)", regex_constants::icase),
            regex(R"(\bwprintf_s\b)", regex_constants::icase),
            regex(R"(\bdebug\b)", regex_constants::icase),
            regex(R"(\bprintk\b)", regex_constants::icase)
        }},
        {"Arithmetic / Overflcow Risks", {
            regex(R"(\badd\b)", regex_constants::icase),
            regex(R"(\bsub\b)", regex_constants::icase),
            regex(R"(\bmul\b)", regex_constants::icase),
            regex(R"(\bdiv\b)", regex_constants::icase),
            regex(R"(\bimul\b)", regex_constants::icase),
            regex(R"(\bdivl\b)", regex_constants::icase),
            regex(R"(\bjo\b|\bjc\b|\bbe\b|\bja\b|\bjb\b|\bjl\b|\bjg\b)", regex_constants::icase)
        }}
    };
} // <-- END get_asm_vuln_patterns()
// Execute objdump (disassemble) on a binary
// returns disassembly output or throws runtime_error on failure
string exec_objdump(const string& binary_path, bool verbose) {
    // Check objdump exists by trying `objdump --version` (quietly)
    {
        array<char, 256> chkbuf{};
        string chkcmd = "objdump --version 2>/dev/null";
        unique_ptr<FILE, decltype(&pclose)> chkpipe(popen(chkcmd.c_str(), "r"), pclose);
        if (!chkpipe) {
            throw runtime_error("popen() failed when checking objdump availability");
        }

        bool any = false;
        while (fgets(chkbuf.data(), chkbuf.size(), chkpipe.get()) != nullptr) {
            any = true;
        }

        if (!any) {
            throw runtime_error("objdump not found or not functioning. Please install binutils (objdump).");
        }
    }
    array<char, 256> buffer{};
    string result;
    string cmd = "objdump -d \"" + binary_path + "\" 2>/dev/null";
    if (verbose) {
        cerr << "[DEBUG] Running: " << cmd << "\n";
    }
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed when running objdump!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    if (result.empty()) {
        throw runtime_error("objdump produced no output (binary may be invalid or objdump failed).");
    }
    return result;
} // <-- FIXED: closing brace restored
// Scan asm text with pattern groups (parallelized but with limited concurrency)
vector<string> scan_asm_text(
    const string& asm_text,
    const vector<PatternGroup>& pattern_groups,
    const string& source_name = "asm_text",
    size_t max_workers = 0,
    bool verbose = false
) {
    vector<string> results;
    set<string> seen_issues;
    mutex seen_mutex;
    mutex results_mutex;
    // Determine max_workers if not provided
    if (max_workers == 0) {
        unsigned int hc = thread::hardware_concurrency();
        max_workers = (hc == 0) ? 4u : max(1u, hc); // fallback to 4 if unknown
    }
    if (verbose) {
        cerr << "[DEBUG] Using up to " << max_workers << " worker(s) for scanning.\n";
    }
    istringstream iss(asm_text);
    string line;
    int line_number = 0;
    vector<future<vector<string>>> active_futures;
    active_futures.reserve(max_workers * 2);
    auto launch_task = [&](string line_copy, int ln) -> future<vector<string>> {
        return async(launch::async, [line_copy, ln, &pattern_groups, &seen_issues, &seen_mutex, &source_name]() -> vector<string> {
            vector<string> local_results;
            // Normalize line
            string normalized_line = regex_replace(line_copy, regex("\\s+"), " ");
            for (const auto& group : pattern_groups) {
                for (const auto& re : group.patterns) {
                    if (regex_search(normalized_line, re)) {
                        string issue_identifier =
                            group.name + ":" + to_string(ln) + ":" + normalized_line;
                        bool should_add = false;
                        {
                            lock_guard<mutex> lg(seen_mutex);
                            if (seen_issues.find(issue_identifier) == seen_issues.end()) {
                                seen_issues.insert(issue_identifier);
                                should_add = true;
                            }
                        }
                        if (should_add) {
                            local_results.push_back(
                                "[" + group.name + "] " +
                                source_name + ":" +
                                to_string(ln) + ": " +
                                line_copy
                            );
                        }
                    }
                }
            }
            return local_results;
        });
    };
    while (getline(iss, line)) {
        ++line_number;
        while (active_futures.size() >= max_workers) {
            auto &f = active_futures.front();
            try {
                auto r = f.get();
                if (!r.empty()) {
                    lock_guard<mutex> lg(results_mutex);
                    results.insert(results.end(), r.begin(), r.end());
                }
            } catch (...) {}

            active_futures.erase(active_futures.begin());
        }
        active_futures.push_back(launch_task(line, line_number));
    }
    for (auto& f : active_futures) {
        try {
            auto r = f.get();
            if (!r.empty()) {
                lock_guard<mutex> lg(results_mutex);
                results.insert(results.end(), r.begin(), r.end());
            }
        } catch (...) {}
    }
    return results;
} // <-- END scan_asm_text()
int main(int argc, char** argv) {
    if (argc < 3) {
        cerr << "Usage:\n"
             << "  asm_scanner --asm <asm_file_path> [--verbose] [--log <log_file>]\n"
             << "  asm_scanner --bin <binary_file_path> [--verbose] [--log <log_file>]\n";
        return 1;
    }
    string mode;
    string path;
    bool verbose = false;
    string log_path;
    vector<string> args(argv + 1, argv + argc);
    mode = args.size() > 0 ? args[0] : "";
    if (args.size() > 1) path = args[1];
    for (size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--verbose") {
            verbose = true;
        }
        else if (args[i] == "--log") {
            if (i + 1 < args.size()) {
                log_path = args[i + 1];
                ++i;
            } else {
                cerr << "Error: --log requires a file path argument\n";
                return 1;
            }
        }
        else if (args[i] == "--help" || args[i] == "-h") {
            cerr << "Usage:\n"
                 << "  asm_scanner --asm <asm_file_path> [--verbose] [--log <log_file>]\n"
                 << "  asm_scanner --bin <binary_file_path> [--verbose] [--log <log_file>]\n";
            return 0;
        }
        else {
            if (!args[i].empty() && args[i][0] == '-') {
                cerr << "Warning: Unknown flag '" << args[i] << "' ignored.\n";
            }
        }
    }
    if (mode.empty() || path.empty()) {
        cerr << "Error: mode and path required.\n";
        return 1;
    }
    vector<PatternGroup> patterns = get_asm_vuln_patterns();
    vector<string> issues;
    ofstream log_ofs;
    bool log_enabled = false;
    if (!log_path.empty()) {
        log_ofs.open(log_path, ios::out | ios::trunc);
        if (!log_ofs) {
            cerr << "Error: Could not open log file: " << log_path << "\n";
            return 1;
        }
        log_enabled = true;
    }
    try {
        if (mode == "--asm") {
            ifstream file(path);
            if (!file) {
                cerr << "Error opening asm file: " << path << endl;
                return 1;
            }
            string asm_text;
            {
                ostringstream ss;
                ss << file.rdbuf();
                asm_text = ss.str();
            }
            unsigned int hc = thread::hardware_concurrency();
            size_t workers = (hc == 0) ? 4u : max(1u, hc);
            issues = scan_asm_text(asm_text, patterns, path, workers, verbose);
        }
        else if (mode == "--bin") {
            if (!fs::exists(path)) {
                cerr << "Error: Binary file does not exist: " << path << "\n";
                return 1;
            }
            string asm_text = exec_objdump(path, verbose);
            unsigned int hc = thread::hardware_concurrency();
            size_t workers = (hc == 0) ? 4u : max(1u, hc);
            issues = scan_asm_text(asm_text, patterns, path, workers, verbose);
        }
        else {
            cerr << "Unknown mode: " << mode << "\n";
            cerr << "Use --asm or --bin\n";
            return 1;
        }
        if (issues.empty()) {
            cout << " No potential vulnerabilities found.\n";
            if (log_enabled) log_ofs << " No potential vulnerabilities found.\n";
        }
        else {
            cout << " Potential vulnerabilities detected:\n";
            if (log_enabled) log_ofs << " Potential vulnerabilities detected:\n";

            for (auto& issue : issues) {
                cout << issue << "\n";
                if (log_enabled) log_ofs << issue << "\n";
            }
        }
    }
    catch (const exception& e) {
        cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
} // <-- END main() 
