#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <filesystem>
#include <thread>
#include <future>
#include <set>

using namespace std;
namespace fs = std::filesystem;

// =====================
// Default pattern groups
// =====================

const vector<string> SQL_INJECTION_PATTERNS = {
    R"(\bselect\s+\*\s+from\s+\w+)",
    R"(\binsert\s+into\s+\w+\s+\(.*\)\s+values\s+\(.*\))",
    R"(\bupdate\s+\w+\s+set\s+.*\s+where\s+.*)",
    R"(\bdrop\s+table\s+\w+)",
    R"(\bunion\s+select\s+.*)",
    R"(\band\s+1\s*=\s*1)",
    R"(\bor\s+1\s*=\s*1)",
    R"(\bselect\s+from\s+information_schema\.tables)",
    R"(\bselect\s+from\s+mysql.*user)",
    R"(\bselect\s+from\s+pg_catalog.*pg_user)",
    R"(\bselect\s+from\s+sys\.databases)",
    R"(\bselect\s+from\s+sqlite_master)"
};

const vector<string> XSS_PATTERNS = {
    R"(\bdocument\.write\s*\()",
    R"(\beval\((.*)\)\s*;)",
    R"(\binnerHTML\s*=\s*)",
    R"(\bwindow\.location\s*=\s*)",
    R"(\blocation\.href\s*=\s*)",
    R"(\balert\s*\()",
    R"(\bconfirm\s*\()",
    R"(\bdocument\.cookie)",
    R"(\beval\s*\(\s*['\"][^\"]+['\"]\s*\))"
};

const vector<string> COMMAND_INJECTION_PATTERNS = {
    R"(\bsystem\s*\()",
    R"(\bpopen\s*\()",
    R"(\bexec\s*\()",
    R"(\bRuntime\.getRuntime\s*\(\)\.exec\s*\()",
    R"(\bsubprocess\.(call|Popen)\s*\()",
    R"(\bchild_process\.exec\s*\()",
    R"(\bnc\s+-e\s*)",
    R"(\$\([^\)]*\))",
    R"(\beval\s*\(\s*['\"]\$\([^\)]+\)['\"]\))"
};

const vector<string> PATH_TRAVERSAL_PATTERNS = {
    R"(\.\./)",
    R"((\.\./){2,})",
    R"(\b(c:|/)[^:]+/)",
    R"(\bfile:\/\/)",
    R"(\bopen\s*\(\s*\"(\.\./|/)[^\"]+\")",
    R"(\bchroot\s*\(\s*\"(\.\./|/)[^\"]+\")"
};

const vector<string> INSECURE_DESERIALIZATION_PATTERNS = {
    R"(\bpickle\.load\s*\()",
    R"(\bunserialize\s*\()",
    R"(\bObjectInputStream\s*\()",
    R"(\bdeserialize\s*\()",
    R"(\bjson\.parse\s*\()",
    R"(\bXMLDecoder\s*\()"
};

const vector<string> BUFFER_OVERFLOW_PATTERNS = {
    R"(\bstrcpy\s*\(\s*\w+,\s*\w+\))",
    R"(\bstrcat\s*\(\s*\w+,\s*\w+\))",
    R"(\bgets\s*\()",
    R"(\bscanf\s*\()",
    R"(\bmemcpy\s*\()",
    R"(\bfgets\s*\()"
};

const vector<string> CSRF_PATTERNS = {
    R"(\bdocument\.location\.href\s*=\s*['\"][^\"]+['\"])",
    R"(\bform\s+action\s*=\s*['\"][^\"]+['\"])",
    R"(\bwindow\.location\s*=\s*['\"][^\"]+['\"])",
    R"(\$\('[^']+'\)\.submit\s*\()",
    R"(\bpost\s+method\s*=\s*['\"][^\"]+['\"])"
};

const vector<string> IMPROPER_AUTHENTICATION_PATTERNS = {
    R"(\bsession_id\s*=\s*['\"][a-zA-Z0-9]{32}['\"])",
    R"(\brequest\.cookies\s*\['session_id'\])",
    R"(\bAuthorization\s*:\s*['\"][A-Za-z0-9\-_]+['\"])",
    R"(\bauth_token\s*=\s*['\"][A-Za-z0-9\-_]+['\"])",
    R"(\brequest\.headers\s*\['Authorization'\])"
};

const vector<string> INSECURE_API_PATTERNS = {
    R"(/api/v[0-9]+/users)",
    R"(/api/v[0-9]+/admin)",
    R"(/api/v[0-9]+/token)",
    R"(/api/v[0-9]+/password)",
    R"(/api/v[0-9]+/login)"
};

const vector<string> INSECURE_CRYPTOGRAPHIC_PATTERNS = {
    R"(\bMD5\s*\()",
    R"(\bSHA1\s*\()",
    R"(\bbase64\s*\()",
    R"(\bplaintext\s*=\s*['\"][a-zA-Z0-9]+['\"])"
};

const vector<string> RACE_CONDITION_PATTERNS = {
    R"(\bpthread_mutex_lock\s*\()",
    R"(\bpthread_mutex_unlock\s*\()",
    R"(\bfsync\s*\()",
    R"(\bwait\s*\()"
};

const vector<string> PRIVILEGE_ESCALATION_PATTERNS = {
    R"(\bsudo\s+)",
    R"(\bchmod\s*777)",
    R"(\bsetuid\s*\()"
};

// Pattern group struct
struct PatternGroup {
    string name;
    vector<string> patterns;
};

// Combine into labeled pattern groups
vector<PatternGroup> get_labeled_patterns() {
    return {
        {"SQL Injection", SQL_INJECTION_PATTERNS},
        {"Cross-Site Scripting (XSS)", XSS_PATTERNS},
        {"Command Injection", COMMAND_INJECTION_PATTERNS},
        {"Path Traversal", PATH_TRAVERSAL_PATTERNS},
        {"Insecure Deserialization", INSECURE_DESERIALIZATION_PATTERNS},
        {"Buffer Overflow", BUFFER_OVERFLOW_PATTERNS},
        {"CSRF", CSRF_PATTERNS},
        {"Improper Authentication", IMPROPER_AUTHENTICATION_PATTERNS},
        {"Insecure API Usage", INSECURE_API_PATTERNS},
        {"Insecure Cryptographic Usage", INSECURE_CRYPTOGRAPHIC_PATTERNS},
        {"Race Condition", RACE_CONDITION_PATTERNS},
        {"Privilege Escalation", PRIVILEGE_ESCALATION_PATTERNS}
    };
}

// Optional: load additional patterns from plain text file
vector<string> load_custom_patterns_plain(const string& config_file) {
    vector<string> custom_patterns;
    ifstream file(config_file);
    string line;
    while (getline(file, line)) {
        if (!line.empty()) {
            custom_patterns.push_back(line);
        }
    }
    return custom_patterns;
}

// Scan a single file
vector<string> detect_injections_in_file(const fs::path& filepath, const vector<PatternGroup>& pattern_groups) {
    vector<string> results;
    set<string> seen_issues;

    try {
        ifstream file(filepath);
        string line;
        int line_number = 0;
        while (getline(file, line)) {
            line_number++;
            for (const auto& group : pattern_groups) {
                for (const auto& pattern : group.patterns) {
                    regex re(pattern);
                    if (regex_search(line, re)) {
                        string issue = "[" + group.name + "] " + filepath.string() + ":" + to_string(line_number) + ": " + line;
                        if (seen_issues.find(issue) == seen_issues.end()) {
                            seen_issues.insert(issue);
                            results.push_back(issue);
                        }
                    }
                }
            }
        }
    } catch (const exception& e) {
        results.push_back("[!] Error reading " + filepath.string() + ": " + e.what());
    }

    return results;
}

// Scan directory using threads
vector<string> scan_directory_for_injections(const fs::path& root_dir, const vector<PatternGroup>& pattern_groups) {
    vector<string> issues_found;
    vector<future<vector<string>>> futures;

    for (const auto& entry : fs::recursive_directory_iterator(root_dir)) {
        if (fs::is_regular_file(entry.status())) {
            futures.push_back(async(launch::async, detect_injections_in_file, entry.path(), pattern_groups));
        }
    }

    for (auto& future : futures) {
        auto result = future.get();
        issues_found.insert(issues_found.end(), result.begin(), result.end());
    }

    return issues_found;
}

// Main
int main(int argc, char** argv) {
    if (argc < 2) {
        cerr << "Usage: scanner <directory> [--config <pattern_file.txt>]" << endl;
        return 1;
    }

    string dir = argv[1];
    auto pattern_groups = get_labeled_patterns();

    if (argc > 2 && string(argv[2]) == "--config") {
        if (argc > 3) {
            vector<string> custom_patterns = load_custom_patterns_plain(argv[3]);
            pattern_groups.push_back({"Custom", custom_patterns});
        } else {
            cerr << "Error: --config requires a filename." << endl;
            return 1;
        }
    }

    vector<string> issues = scan_directory_for_injections(dir, pattern_groups);

    if (issues.empty()) {
        cout << "✅ No potential vulnerabilities found." << endl;
    } else {
        cout << "🚨 Potential vulnerabilities detected:\n";
        for (const auto& issue : issues) {
            cout << issue << endl;
        }
    }

    return 0;
}
