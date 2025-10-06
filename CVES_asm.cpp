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
        {"Arithmetic / Overflow Risks", {
            regex(R"(\badd\b)", regex_constants::icase),
            regex(R"(\bsub\b)", regex_constants::icase),
            regex(R"(\bmul\b)", regex_constants::icase),
            regex(R"(\bdiv\b)", regex_constants::icase),
            regex(R"(\bimul\b)", regex_constants::icase),
            regex(R"(\bdivl\b)", regex_constants::icase),
            regex(R"(\bjo\b|\bjc\b|\bbe\b|\bja\b|\bjb\b|\bjl\b|\bjg\b)", regex_constants::icase)
        }}
    };
};
// Execute objdump (disassemble) on a binary
string exec_objdump(const string& binary_path) {
    array<char, 256> buffer{};
    string result;
    string cmd = "objdump -d \"" + binary_path + "\"";
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed!");
    };
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    };
    return result;
};
// Scan asm text with pattern groups (parallelized)
vector<string> scan_asm_text(const string& asm_text, const vector<PatternGroup>& pattern_groups, const string& source_name = "asm_text") {
    vector<string> results;
    set<string> seen_issues;
    istringstream iss(asm_text);
    string line;
    int line_number = 0;
    vector<future<vector<string>>> tasks;
    while (getline(iss, line)) {
        ++line_number;
        // Create task for each line
        tasks.push_back(async(launch::async, [line, line_number, &pattern_groups, &seen_issues, source_name]() -> vector<string> {
            vector<string> local_results;
            // Normalize line: collapse multiple spaces into single space
            string normalized_line = regex_replace(line, regex("\\s+"), " ");
            for (const auto& group : pattern_groups) {
                for (const auto& re : group.patterns) {
                    if (regex_search(normalized_line, re)) {
                        string issue_identifier = group.name + ":" + to_string(line_number) + ":" + normalized_line;
                        if (seen_issues.find(issue_identifier) == seen_issues.end()) {
                            seen_issues.insert(issue_identifier);
                            local_results.push_back("[" + group.name + "] " + source_name + ":" + to_string(line_number) + ": " + line);
                        }
                    }
                }
            }
            return local_results;
        }));
    }
    // Collect results from all tasks
    for (auto& task : tasks) {
        auto task_results = task.get();
        results.insert(results.end(), task_results.begin(), task_results.end());
    }
    return results;
};
int main(int argc, char** argv) {
    if (argc < 3) {
        cerr << "Usage:\n"
             << "  asm_scanner --asm <asm_file_path>\n"
             << "  asm_scanner --bin <binary_file_path>\n";
        return 1;
    }
    string mode = argv[1];
    string path = argv[2];
    vector<PatternGroup> patterns = get_asm_vuln_patterns();
    vector<string> issues;
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
            issues = scan_asm_text(asm_text, patterns, path);
        }
        else if (mode == "--bin") {
            string asm_text = exec_objdump(path);
            issues = scan_asm_text(asm_text, patterns, path);
        }
        else {
            cerr << "Unknown mode: " << mode << "\n";
            cerr << "Use --asm or --bin\n";
            return 1;
        }
        if (issues.empty()) {
            cout << " No potential vulnerabilities found.\n";
        } else {
            cout << " Potential vulnerabilities detected:\n";
            for (auto& issue : issues) {
                cout << issue << "\n";
            }
        }
    }
    catch (const exception& e) {
        cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
};
