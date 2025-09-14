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
#include <future>
#include <set>
#include <fstream>

using namespace std;
namespace fs = std::filesystem;

struct PatternGroup {
    string name;
    vector<string> patterns;
};

// Extended patterns for assembly vulnerabilities
vector<PatternGroup> get_asm_vuln_patterns() {
    return {
        {"Buffer Overflow / Unsafe Memory Operations", {
            R"(\bstrcpy\b)",
            R"(\bstrncpy\b)",
            R"(\bstrcat\b)",
            R"(\bstrncat\b)",
            R"(\bgets\b)",
            R"(\bscanf\b)",
            R"(\bfscanf\b)",
            R"(\bsscanf\b)",
            R"(\bmemcpy\b)",
            R"(\bmemmove\b)",
            R"(\bmovs\b)",             // rep movs / movs without bounds
            R"(\bstosb\b|\bstosd\b|\bstosw\b)", // repeated store
            R"(\bcmps\b)",             // repeated compare
            R"(\blods\b|lodsb|lodsw|lodsd)", 
            R"(\bxor\s+[a-z0-9]+,\s*\[.*\])",     // XOR reg, [mem]
            R"(\badd\s+[a-z0-9]+,\s*\[.*\])",
            R"(\bsub\s+[a-z0-9]+,\s*\[.*\])"
        }},
        {"Unsafe Function Call / Library Routines", {
            R"(\bcall\s+strcpy\b)",
            R"(\bcall\s+strncpy\b)",
            R"(\bcall\s+strcat\b)",
            R"(\bcall\s+strncat\b)",
            R"(\bcall\s+gets\b)",
            R"(\bcall\s+scanf\b)",
            R"(\bcall\s+fscanf\b)",
            R"(\bcall\s+sscanf\b)",
            R"(\bcall\s+system\b)",
            R"(\bcall\s+popen\b)",
            R"(\bcall\s+execve\b)"
        }},
        {"Hardcoded Secrets / Data Strings", {
            R"(\bdb\s+\".*password.*\")",
            R"(\bdb\s+\".*secret.*\")",
            R"(\bdb\s+\".*key.*\")",
            R"(\bdb\s+\".*token.*\")",
            R"(\bdb\s+\".*credential.*\")",
            R"(\bdata\s+\".*password.*\")",
            R"(\bdata\s+\".*secret.*\")"
        }},
        {"Privilege / Permissions / Escalation Instructions", {
            R"(\biopl\b)",                        // change in I/O privilege level
            R"(\bitsl\b)",                        // test I/O privilege
            R"(\bcli\b)",                         // disable interrupts
            R"(\bsti\b)",                         // enable interrupts
            R"(\bout\s+)",                       // writing to ports
            R"(\bin\b)",                         // reading from ports
            R"(\bint\s+0x80\b.*\bsetuid\b)",
            R"(\bint\s+0x80\b.*\bsetgid\b)",
            R"(\bint\s+0x80\b.*\bchmod\b)",
            R"(\bint\s+0x80\b.*\bchown\b)",
            R"(\bint\s+0x80\b.*\brwx\b)"
        }},
        {"Suspicious Syscalls / Interrupts", {
            R"(\bint\s+0x80\b)",
            R"(\bsyscall\b)",
            R"(\bint\s+0x2e\b)",
            R"(\bint\s+0x81\b)",
            R"(\bint\s+0x82\b)", // some other interrupts
            R"(\bint\s+0x90\b)", // NOP / debug / weird
            R"(\btrap\b)",
            R"(\beret\b)"       // maybe suspicious return / misuse
        }},
        {"Control Flow / Return Oriented Programming (ROP) / Jump Gadgets", {
            R"(\bjmp\s+[a-zA-Z0-9_]+\b)",         // indirect jumps
            R"(\bjmp\s*\[.*\])",                   // memory-based jump
            R"(\bcall\s*\[.*\])",
            R"(\bpush\s+[^\n]*; ret\b)",            // push + ret combos
            R"(\bpop\s+[^\n]*; ret\b)",
            R"(\bret\b)",                          // suspect unless it's function return
            R"(\bleave\b)",                        // stack frame unwind
        }},
        {"Format String / Debug / Info Leakage", {
            R"(\bodbc\b|\bprintf\b|\bsprintf\b|\bvsprintf\b)",
            R"(\bprintf\b)",
            R"(\bsprintf\b)",
            R"(\bvsprintf\b)",
            R"(\bwprintf\b)",
            R"(\bwprintf_s\b)",
            R"(\bdebug\b)",
            R"(\bprintk\b)" // kernel debug
        }},
        {"Arithmetic / Overflow Risks", {
            R"(\badd\b)",
            R"(\bsub\b)",
            R"(\bmul\b)",
            R"(\bdiv\b)",
            R"(\bimul\b)",
            R"(\bdivl\b)",
            R"(\bjo\b|\bjc\b|\bbe\b|\bja\b|\bjb\b|\bjl\b|\bjg\b)" // jump on overflow/carry
        }}
    };
}

// Execute objdump (disassemble) on a binary
string exec_objdump(const string& binary_path) {
    array<char, 256> buffer{};
    string result;

    string cmd = "objdump -d \"" + binary_path + "\"";

    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// Scan asm text with pattern groups
vector<string> scan_asm_text(const string& asm_text, const vector<PatternGroup>& pattern_groups, const string& source_name = "asm_text") {
    vector<string> results;
    set<string> seen_issues; // Set to track unique issues (pattern + line number)

    istringstream iss(asm_text);
    string line;
    int line_number = 0;

    while (getline(iss, line)) {
        ++line_number;
        // Normalize line by removing extra whitespace, which can happen in objdump output
        string normalized_line = line;
        normalized_line.erase(remove(normalized_line.begin(), normalized_line.end(), ' '), normalized_line.end());
        
        for (const auto& group : pattern_groups) {
            for (const auto& pattern : group.patterns) {
                regex re(pattern, regex_constants::icase);
                if (regex_search(normalized_line, re)) {
                    // Create a unique issue identifier with both pattern, line number and the actual line content
                    string issue_identifier = group.name + ":" + to_string(line_number) + ":" + pattern + ":" + normalized_line;
                    // Ensure uniqueness by checking if this issue has been seen already
                    if (seen_issues.find(issue_identifier) == seen_issues.end()) {
                        seen_issues.insert(issue_identifier);  // Add to set if not already seen
                        results.push_back("[" + group.name + "] " + source_name + ":" + to_string(line_number) + ": " + line);  // Store unique issue
                    }
                }
            }
        }
    }
    return results;
}

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
            // Load asm file from disk
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
            // Disassemble binary in memory
            string asm_text = exec_objdump(path);
            issues = scan_asm_text(asm_text, patterns, path);
        }
        else {
            cerr << "Unknown mode: " << mode << "\n";
            cerr << "Use --asm or --bin\n";
            return 1;
        }

        if (issues.empty()) {
            cout << "✅ No potential vulnerabilities found.\n";
        } else {
            cout << "🚨 Potential vulnerabilities detected:\n";
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
}
