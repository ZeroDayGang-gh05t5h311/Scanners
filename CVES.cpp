// improved_scanner.cpp
// Direct C++17 translation of the provided Python scanner (CSV-only).
// Compile: g++ -std=c++17 -O2 -pthread -o improved_scanner improved_scanner.cpp
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <locale>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>
namespace fs = std::filesystem;
// -------------------------
// Simple types
// -------------------------
struct Issue {
    std::string file;
    int line;
    std::string pattern;
    std::string match_text;
    std::string snippet;
};
// -------------------------
// File extension -> language
// -------------------------
static const std::unordered_map<std::string, std::string> LANG_EXTENSIONS = {
    {".py","python"}, {".js","javascript"}, {".c","c"}, {".cpp","cpp"}, {".cc","cpp"},
    {".h","c"}, {".hpp","cpp"}, {".java","java"}, {".sh","shell"}, {".bash","shell"}
};
// -------------------------
// Full pattern lists (translated as raw string literals where appropriate)
// -------------------------
static const std::vector<std::string> SQL_INJECTION_PATTERNS = {
    R"((?i)select\s+\*\s+from\s+\w+)",
    R"((?i)insert\s+into\s+\w+\s+\(.*\)\s+values\s+\(.*\))",
    R"((?i)update\s+\w+\s+set\s+.*\s+where\s+.*)",
    R"((?i)drop\s+table\s+\w+)",
    R"((?i)union\s+select\s+.*)",
    R"((?i)and\s+1\s*=\s*1)",
    R"((?i)or\s+1\s*=\s*1)",
    R"((?i)select\s+from\s+information_schema.tables)",
    R"((?i)select\s+from\s+mysql.*user)",
    R"((?i)select\s+from\s+pg_catalog.*pg_user)",
    R"((?i)select\s+from\s+sys\.databases)",
    R"((?i)select\s+from\s+sqlite_master)",
    R"((?i)execute\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+)",
    R"((?i)cursor\.execute\s*\(\s*.*\))",
    R"((?i)prepareStatement\s*\()",
    R"((?i)WHERE\s+1=1\s+--)",
    R"((?i)--\s*$|#\s*$)",
    R"((?i)UNION\s+ALL\s+SELECT)",
    R"((?i)CAST\(.+AS\s+VARCHAR)"
};
static const std::vector<std::string> XSS_PATTERNS = {
    R"((?i)document\.write\s*\()",
    R"((?i)eval\((.*)\)\s*;)",
    R"((?i)innerHTML\s*=\s*)",
    R"((?i)window\.location\s*=)",
    R"((?i)location\.href\s*=)",
    R"((?i)alert\s*\()",
    R"((?i)confirm\s*\()",
    R"((?i)document\.cookie)",
    R"((?i)eval\s*\(\s*["\'].*["\']\s*\))",
    R"((?i)response\.write\()",
    R"((?i)res\.send\()",
    R"((?i)innerText\s*=)",
    R"((?i)document\.createElement\(['\"]script['\"]\))",
    R"((?i)setAttribute\(\s*['\"]on\w+['\"]\s*,)",
    R"((?i)dangerouslySetInnerHTML)",
    R"((?i)style\.cssText\s*=)",
    R"((?i)location\.replace\s*\()",
    R"((?i)res\.end\s*\()"
};
static const std::vector<std::string> COMMAND_INJECTION_PATTERNS = {
    R"((?i)system\s*\()",
    R"((?i)popen\s*\()",
    R"((?i)exec\s*\()",
    R"((?i)Runtime\.getRuntime\s*\(\)\.exec\s*\()",
    R"((?i)subprocess\.(call|Popen)\s*\()",
    R"((?i)child_process\.exec\s*\()",
    R"((?i)nc\s+-e\s+)",
    R"((?i)\$\([^\)]*\))",
    R"((?i)eval\s*\(\s*['\"]\$\([^\)]+\)['\"]\))",
    R"((?i)shell=True)",
    R"((?i)cmd\.exe\s*/c)",
    R"((?i)system\([^,]+;)",
    R"((?i)exec\([^,]+\+)",
    R"((?i)popen\([^,]+\+)",
    R"((?i)ProcessBuilder\s*\(.+builder\.command\()",
    R"((?i)Runtime\.exec\(.+\+)",
    R"((?i)popen2|popen3)",
    R"((?i)subprocess\.(call|check_output)\s*\(.*\+)"
};
static const std::vector<std::string> PATH_TRAVERSAL_PATTERNS = {
    R"(\.\./)",
    R"((\.\./){2,})",
    R"((?i)(c:|/)[^:]+/)",
    R"((?i)file://)",
    R"((?i)open\s*\(\s*\"(\.\./|/)[^\"]+\" )",
    R"((?i)chroot\s*\(\s*\"(\.\./|/)[^\"]+\" )",
    R"((?i)normalizePath\(|path\.normalize\()",
    R"((?i)realpath\(|os\.realpath\()",
    R"(\.\.\\)",
    R"((?i)zipfile\.ZipFile\(|tarfile\.open\()",
    R"((?i)upload_tmp_dir|tmp_name)",
    R"((?i)save_path\s*=)",
    R"((?i)path\.join\([^,]+,\s*\.\.)",
    R"((?i)filename\s*=\s*request\.)",
    R"((?i)Content-Disposition:\s*filename=)"
};
static const std::vector<std::string> INSECURE_DESERIALIZATION_PATTERNS = {
    R"((?i)pickle\.load\s*\()",
    R"((?i)unserialize\s*\()",
    R"((?i)ObjectInputStream\s*\()",
    R"((?i)deserialize\s*\()",
    R"((?i)json\.parse\s*\()",
    R"((?i)XMLDecoder\s*\()",
    R"((?i)XStream\.fromXML\s*\()",
    R"((?i)yaml\.load\s*\()",
    R"((?i)Marshal\.load\s*\()",
    R"((?i)Marshal\.restore\s*\()",
    R"((?i)eval\(.+base64_decode\()",
    R"((?i)gob\.NewDecoder\(|encoding/gob)",
    R"((?i)serde_json::from_str\()",
    R"((?i)perl\s+Storable::thaw)",
    R"((?i)apache\.commons\.collections)",
    R"((?i)readObject\(|writeReplace\()",
    R"((?i)readObject\s*\()",
    R"((?i)writeObject\s*\()",
    R"((?i)ObjectInputStream\.resolveClass)",
    R"((?i)XStream\.fromXML\s*\()",
    R"((?i)Gson\.fromJson\s*\()"
};
static const std::vector<std::string> BUFFER_OVERFLOW_PATTERNS = {
    R"((?i)strcpy\s*\(\s*\w+,\s*\w+\))",
    R"((?i)strcat\s*\(\s*\w+,\s*\w+\))",
    R"((?i)gets\s*\()",
    R"((?i)scanf\s*\()",
    R"((?i)memcpy\s*\()",
    R"((?i)fgets\s*\()",
    R"((?i)XStream\.fromXML\s*\()",
    R"((?i)yaml\.load\s*\()",
    R"((?i)Marshal\.load\s*\()",
    R"((?i)Marshal\.restore\s*\()",
    R"((?i)eval\(.+base64_decode\()",
    R"((?i)gob\.NewDecoder\(|encoding/gob)",
    R"((?i)serde_json::from_str\()",
    R"((?i)perl\s+Storable::thaw)",
    R"((?i)apache\.commons\.collections)",
    R"((?i)readObject\(|writeReplace\()",
    R"((?i)readObject\s*\()",
    R"((?i)writeObject\s*\()",
    R"((?i)ObjectInputStream\.resolveClass)",
    R"((?i)XStream\.fromXML\s*\()",
    R"((?i)Gson\.fromJson\s*\()",
    R"((?i)malloc\s*\(|(?i)calloc\s*\()",
    R"((?i)stack_exec|mprotect\s*\()",
    R"((?i)memset\(.+0x00)"
};
static const std::vector<std::string> CSRF_PATTERNS = {
    R"((?i)document\.location\.href\s*=\s*['\"]\S+['\"])",
    R"((?i)form\s+action\s*=\s*['\"]\S+['\"])",
    R"((?i)window\.location\s*=\s*['\"]\S+['\"])",
    R"((?i)\$\('[^']+'\)\.submit\s*\()",
    R"((?i)post\s+method\s*=\s*['\"]\S+['\"])",
    R"((?i)input\s+type\s*=\s*['\"]hidden['\"]\s+name\s*=\s*['\"]csrf)",
    R"((?i)X-CSRF-Token)",
    R"((?i)SameSite=None)",
    R"((?i)document\.forms\[[0-9]+\]\.submit)",
    R"((?i)action\s*=\s*\"/external)",
    R"((?i)autofill)"
};
static const std::vector<std::string> IMPROPER_AUTHENTICATION_PATTERNS = {
    R"((?i)session_id\s*=\s*['\"][a-zA-Z0-9]{32}['\"])",
    R"((?i)request\.cookies\s*\['session_id'\])",
    R"((?i)Authorization\s*:\s*['\"]Bearer\s+[A-Za-z0-9\-_]+['\"])",
    R"((?i)auth_token\s*=\s*['\"][A-Za-z0-9\-_]+['\"])",
    R"((?i)request\.headers\s*\['Authorization'\])",
    R"((?i)password\s*=\s*['\"][^'\"]{1,}['\"])",
    R"((?i)api_key\s*=\s*['\"][A-Za-z0-9\-_]+['\"])",
    R"((?i)hardcoded_secret|hardcoded_key|private_key\s*=)",
    R"((?i)Basic\s+[A-Za-z0-9=]+)",
    R"((?i)set_cookie\(|cookie\.set\()",
    R"((?i)session\.(start|destroy))",
    R"((?i)bcrypt\.hashpw\(|password_hash\()",
    R"((?i)compare_digest\(|hmac\.compare_digest\()",
    R"((?i)token_expiry|exp\s*:)",
    R"((?i)Authorization\s*:\s*Bearer)"
};
static const std::vector<std::string> INSECURE_API_PATTERNS = {
    R"((?i)/api/v[0-9]+/users)",
    R"((?i)/api/v[0-9]+/admin)",
    R"((?i)/api/v[0-9]+/token)",
    R"((?i)/api/v[0-9]+/password)",
    R"((?i)/api/v[0-9]+/login)",
    R"((?i)/internal/|/private/|/debug/)",
    R"((?i)swagger.json|api-docs|/v2/api-docs)",
    R"((?i)X-Forwarded-For)",
    R"((?i)introspect|.well-known/openid-configuration)",
    R"((?i)graphql)",
    R"((?i)rate_limit|throttle)",
    R"((?i)Authorization\s*:\s*Bearer # token leakage in logs/header)"
};
static const std::vector<std::string> INSECURE_CRYPTOGRAPHIC_PATTERNS = {
    R"((?i)MD5\s*\()",
    R"((?i)SHA1\s*\()",
    R"((?i)base64\s*\()",
    R"((?i)plaintext\s*=\s*['\"][a-zA-Z0-9]+['\"])",
    R"((?i)AES-ECB|AES128-ECB|ECB_MODE)",
    R"((?i)openssl\s+enc\s+-aes-128-cbc)",
    R"((?i)RSA_padding\(|RSA_NO_PADDING)",
    R"((?i)SSLv3|ssl3)",
    R"((?i)RC4|DES|3DES|EXPORT)",
    R"((?i)hardcoded_key|hardcoded_password|private_key.*=)",
    R"((?i)PBKDF2|bcrypt|scrypt)",
    R"((?i)iteration_count\s*=\s*\d{1,4})",
    R"((?i)random\.random\(|Math\.random\()",
    R"((?i)secure_random|SystemRandom)",
    R"((?i)HMAC-SHA1)",
    R"((?i)cryptography\.hazmat|from\s+Crypto\.)"
};
static const std::vector<std::string> RACE_CONDITION_PATTERNS = {
    R"((?i)pthread_mutex_lock\s*\()",
    R"((?i)pthread_mutex_unlock\s*\()",
    R"((?i)fsync\s*\()",
    R"((?i)wait\s*\()",
    R"((?i)open\([^,]+,\s*O_CREAT\|O_EXCL)",
    R"((?i)rename\()",
    R"((?i)stat\(|lstat\()",
    R"((?i)mktemp\s*\()",
    R"((?i)lockf\s*\()",
    R"((?i)sem_wait|sem_post)",
    R"((?i)volatile\s+)",
    R"((?i)atomic_compare_exchange)",
    R"((?i)nsync|pthread_create)"
};
static const std::vector<std::string> PRIVILEGE_ESCALATION_PATTERNS = {
    R"((?i)sudo\s+)",
    R"((?i)chmod\s+777\s+)",
    R"((?i)chown\s+)",
    R"((?i)setuid\(|setgid\(|seteuid\(|setegid\()",
    R"((?i)cap_set_file|cap_get_proc)",
    R"((?i)passwd\s+)",
    R"((?i)/etc/shadow|/etc/passwd)",
    R"((?i)su\s+-)",
    R"((?i)mount\s+-o\s+)",
    R"((?i)docker\s+run\s+--privileged)",
    R"((?i)iptables\s+)",
    R"((?i)chroot\s*\()"
};
// LANGUAGE -> patterns
static const std::unordered_map<std::string, std::vector<std::string>> LANGUAGE_PATTERNS = {
    {"python", [](){
        std::vector<std::string> v;
        v.insert(v.end(), SQL_INJECTION_PATTERNS.begin(), SQL_INJECTION_PATTERNS.end());
        v.insert(v.end(), XSS_PATTERNS.begin(), XSS_PATTERNS.end());
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), INSECURE_CRYPTOGRAPHIC_PATTERNS.begin(), INSECURE_CRYPTOGRAPHIC_PATTERNS.end());
        return v;
    }()},
    {"javascript", [](){
        std::vector<std::string> v;
        v.insert(v.end(), XSS_PATTERNS.begin(), XSS_PATTERNS.end());
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), INSECURE_API_PATTERNS.begin(), INSECURE_API_PATTERNS.end());
        return v;
    }()},
    {"c", [](){
        std::vector<std::string> v;
        v.insert(v.end(), SQL_INJECTION_PATTERNS.begin(), SQL_INJECTION_PATTERNS.end());
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), BUFFER_OVERFLOW_PATTERNS.begin(), BUFFER_OVERFLOW_PATTERNS.end());
        v.insert(v.end(), PATH_TRAVERSAL_PATTERNS.begin(), PATH_TRAVERSAL_PATTERNS.end());
        return v;
    }()},
    {"cpp", [](){
        std::vector<std::string> v;
        v.insert(v.end(), SQL_INJECTION_PATTERNS.begin(), SQL_INJECTION_PATTERNS.end());
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), BUFFER_OVERFLOW_PATTERNS.begin(), BUFFER_OVERFLOW_PATTERNS.end());
        v.insert(v.end(), PATH_TRAVERSAL_PATTERNS.begin(), PATH_TRAVERSAL_PATTERNS.end());
        return v;
    }()},
    {"java", [](){
        std::vector<std::string> v;
        v.insert(v.end(), SQL_INJECTION_PATTERNS.begin(), SQL_INJECTION_PATTERNS.end());
        v.insert(v.end(), INSECURE_DESERIALIZATION_PATTERNS.begin(), INSECURE_DESERIALIZATION_PATTERNS.end());
        v.insert(v.end(), IMPROPER_AUTHENTICATION_PATTERNS.begin(), IMPROPER_AUTHENTICATION_PATTERNS.end());
        return v;
    }()},
    {"shell", [](){
        std::vector<std::string> v;
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), PRIVILEGE_ESCALATION_PATTERNS.begin(), PRIVILEGE_ESCALATION_PATTERNS.end());
        return v;
    }()}
};
// -------------------------
// Defaults
// -------------------------
static const std::set<std::string> DEFAULT_IGNORED_DIRS = {
    ".git", "node_modules", "__pycache__", "venv", ".venv", ".idea", ".gradle"
};
// -------------------------
// Utilities
// -------------------------
std::map<std::string, std::vector<std::regex>> compile_patterns_map(const std::map<std::string, std::vector<std::string>>& src) {
    std::map<std::string, std::vector<std::regex>> out;
    for (auto const& [k, vec] : src) {
        std::vector<std::regex> compiled;
        for (auto const& p : vec) {
            try {
                // Use ECMAScript with icase; note: Python (?i) style inline flags remain part of the pattern
                compiled.emplace_back(p, std::regex_constants::ECMAScript | std::regex_constants::icase);
            } catch (const std::regex_error&) {
                // fallback to literal match (escape)
                std::string esc;
                for (char ch : p) {
                    if (std::ispunct((unsigned char)ch)) esc.push_back('\\');
                    esc.push_back(ch);
                }
                try { compiled.emplace_back(esc, std::regex_constants::ECMAScript | std::regex_constants::icase); }
                catch (...) {}
            }
        }
        out[k] = std::move(compiled);
    }
    return out;
}
std::vector<std::regex> compile_patterns_vector(const std::vector<std::string>& vec) {
    std::vector<std::regex> compiled;
    for (auto const& p : vec) {
        try {
            compiled.emplace_back(p, std::regex_constants::ECMAScript | std::regex_constants::icase);
        } catch (const std::regex_error&) {
            std::string esc;
            for (char ch : p) {
                if (std::ispunct((unsigned char)ch)) esc.push_back('\\');
                esc.push_back(ch);
            }
            try { compiled.emplace_back(esc, std::regex_constants::ECMAScript | std::regex_constants::icase); }
            catch (...) {}
        }
    }
    return compiled;
}
// rudimentary text detection
bool is_text_file(const fs::path& path, std::size_t max_bytes = 2048, double printable_threshold = 0.75) {
    std::ifstream fh(path, std::ios::binary);
    if (!fh) return false;
    std::vector<char> chunk;
    chunk.reserve(max_bytes);
    char buf;
    std::size_t i = 0;
    while (i < max_bytes && fh.get(buf)) {
        chunk.push_back(buf);
        ++i;
    }
    if (chunk.empty()) return true;
    for (char c : chunk) {
        if (c == '\0') return false;
    }
    std::string printable_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\v\f";
    std::size_t printable_count = 0;
    for (char c : chunk) {
        if (printable_chars.find(c) != std::string::npos) ++printable_count;
    }
    double ratio = (double)printable_count / (double)chunk.size();
    return ratio >= printable_threshold;
}
// -------------------------
// Tokenizer: blank comments & strings preserving newlines
// -------------------------
std::string remove_comments_and_strings_preserve_offsets(const std::string& text, const std::string& lang) {
    // We'll work on a mutable copy of chars
    std::string chars = text;
    std::vector<std::pair<std::regex, std::string>> patterns;
    // Patterns are designed to capture common string/comment spans using [\s\S]*? to allow across-line matches
    if (lang == "python") {
        // triple, single, double, comment
        patterns.emplace_back(std::regex(R"(('''[\s\S]*?'''|"""[\s\S]*?"""|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|#.*?$))",
                                          std::regex_constants::ECMAScript | std::regex_constants::icase),
                              ""); // the regex groups all spans
    } else if (lang == "javascript") {
        patterns.emplace_back(std::regex(R"((`(?:\\.|[^`\\\n])*`|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|//.*?$|/\*[\s\S]*?\*/))",
                                          std::regex_constants::ECMAScript | std::regex_constants::icase),
                              "");
    } else if (lang == "shell") {
        patterns.emplace_back(std::regex(R"((`(?:\\.|[^`\\\n])*`|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|#.*?$))",
                                          std::regex_constants::ECMAScript | std::regex_constants::icase),
                              "");
    } else if (lang == "c" || lang == "cpp" || lang == "java") {
        patterns.emplace_back(std::regex(R"((\'(?:\\.|[^'\\\n])*\'|"(?:\\.|[^"\\\n])*"|//.*?$|/\*[\s\S]*?\*/))",
                                          std::regex_constants::ECMAScript | std::regex_constants::icase),
                              "");
    } else {
        patterns.emplace_back(std::regex(R"(('(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|#.*?$))",
                                          std::regex_constants::ECMAScript | std::regex_constants::icase),
                              "");
    }
    // apply each pattern's matches and blank them (keeping newlines)
    for (auto const& pr : patterns) {
        const std::regex& re = pr.first;
        std::sregex_iterator it(text.begin(), text.end(), re);
        std::sregex_iterator end;
        for (; it != end; ++it) {
            try {
                auto m = *it;
                auto s = m.position(0);
                auto len = m.length(0);
                for (size_t i = 0; i < (size_t)len; ++i) {
                    char &c = chars[s + i];
                    if (c != '\n') c = ' ';
                }
            } catch (...) {
                // ignore mapping errors
            }
        }
    }
    return chars;
}
// -------------------------
// Matching & line mapping
// -------------------------
static int offset_to_lineno(const std::vector<std::size_t>& offsets, std::size_t offset) {
    // upper_bound - 1
    auto it = std::upper_bound(offsets.begin(), offsets.end(), offset);
    if (it == offsets.begin()) return 1;
    --it;
    return static_cast<int>(std::distance(offsets.begin(), it) + 1);
}
std::vector<Issue> find_matches_in_text(const std::string& text,
                                        const std::vector<std::regex>& compiled_patterns,
                                        const fs::path& path,
                                        const std::string& lang) {
    std::vector<Issue> matches;
    if (compiled_patterns.empty()) return matches;
    std::string cleaned = remove_comments_and_strings_preserve_offsets(text, lang);
    // compute line offsets from original text
    std::vector<std::size_t> offsets;
    std::vector<std::string> lines;
    {
        std::istringstream ss(text);
        std::string line;
        std::size_t pos = 0;
        while (std::getline(ss, line)) {
            lines.push_back(line);
            offsets.push_back(pos);
            pos += line.size() + 1; // assume newline length == 1
        }
        if (offsets.empty()) { offsets.push_back(0); lines.push_back(std::string()); }
    }
    for (auto const& pat : compiled_patterns) {
        try {
            std::sregex_iterator it(cleaned.begin(), cleaned.end(), pat);
            std::sregex_iterator end;
            for (; it != end; ++it) {
                try {
                    auto m = *it;
                    auto start = static_cast<std::size_t>(m.position(0));
                    int line_no = offset_to_lineno(offsets, start);
                    int line_idx = std::max(0, std::min((int)lines.size()-1, line_no - 1));
                    std::string snippet = lines[line_idx];
                    // trim
                    auto first_non = snippet.find_first_not_of(" \t\r\n");
                    auto last_non = snippet.find_last_not_of(" \t\r\n");
                    if (first_non == std::string::npos) snippet = "";
                    else snippet = snippet.substr(first_non, last_non - first_non + 1);
                    std::string match_text = m.length(0) > 0 ? m.str(0) : std::string();
                    if (match_text.size() > 300) match_text = match_text.substr(0, 300);
                    Issue itc;
                    itc.file = path.string();
                    itc.line = line_no;
                    itc.pattern = pat.mark_count() ? "(complex)" : "(pattern)"; // can't extract original pattern string from std::regex
                    // We'll attempt to get the pattern as a string by re-creating from pat — not available.
                    // So as a compromise, store a placeholder with the regex as textual pattern if needed:
                    // But std::regex doesn't expose pattern string; we preserve user's pattern in wrappers below.
                    itc.match_text = match_text;
                    itc.snippet = snippet;
                    // IMPORTANT: later, caller may overwrite pattern with original string if we keep mapping.
                    matches.push_back(std::move(itc));
                } catch (...) {
                    Issue e;
                    e.file = path.string();
                    e.line = 0;
                    e.pattern = "(ERROR_MATCH)";
                    e.match_text = "";
                    e.snippet = "Error mapping match to line";
                    matches.push_back(e);
                }
            }
        } catch (...) {
            // ignore pattern runtime errors
        }
    }
    return matches;
}
// -------------------------
// Per-file detection & scanning
// -------------------------
std::vector<Issue> detect_injections_in_file(const fs::path& path,
                                             const std::unordered_map<std::string, std::vector<std::pair<std::string,std::regex>>>&compiled_by_lang,
                                             const std::vector<std::pair<std::string,std::regex>>&default_patterns,
                                             std::size_t min_size, std::size_t max_size,
                                             const std::vector<std::string>& ignore_exts) {
    std::vector<Issue> rv;
    try {
        std::string suffix = path.extension().string();
        std::transform(suffix.begin(), suffix.end(), suffix.begin(), [](unsigned char c){ return std::tolower(c); });
        if (!suffix.empty() && std::find(ignore_exts.begin(), ignore_exts.end(), suffix) != ignore_exts.end()) {
            return rv;
        }
        auto st = fs::file_size(path);
        if (st < min_size || (max_size > 0 && st > max_size)) {
            return rv;
        }
    } catch (...) {
        return rv;
    }
    if (!is_text_file(path)) return rv;

    std::string lang;
    {
        auto it = LANG_EXTENSIONS.find(path.extension().string());
        if (it != LANG_EXTENSIONS.end()) lang = it->second;
        else {
            std::string suf = path.extension().string();
            std::transform(suf.begin(), suf.end(), suf.begin(), [](unsigned char c){ return std::tolower(c); });
            auto it2 = LANG_EXTENSIONS.find(suf);
            if (it2 != LANG_EXTENSIONS.end()) lang = it2->second;
        }
    }
    // Build compiled pattern vector containing pairs (orig_pattern_string, regex)
    std::vector<std::pair<std::string,std::regex>> compiled_patterns_pairs;
    if (!lang.empty()) {
        auto it = compiled_by_lang.find(lang);
        if (it != compiled_by_lang.end()) {
            compiled_patterns_pairs.insert(compiled_patterns_pairs.end(), it->second.begin(), it->second.end());
        }
    }
    compiled_patterns_pairs.insert(compiled_patterns_pairs.end(), default_patterns.begin(), default_patterns.end());
    if (compiled_patterns_pairs.empty()) return rv;
    std::string text;
    {
        std::ifstream fh(path, std::ios::binary);
        if (!fh) {
            Issue e;
            e.file = path.string();
            e.line = 0;
            e.pattern = "ERROR_READING";
            e.match_text = "";
            e.snippet = "Error reading file";
            rv.push_back(e);
            return rv;
        }
        std::ostringstream ss;
        ss << fh.rdbuf();
        text = ss.str();
    }
    // We need to call find_matches_in_text for each pattern, but since that function accepts vector<regex>
    // and cannot capture original pattern string, we'll call pattern-by-pattern and then attach the original
    for (auto const& [pat_str, pat_re] : compiled_patterns_pairs) {
        std::vector<std::regex> single = { pat_re };
        std::vector<Issue> found = find_matches_in_text(text, single, path, lang);
        // attach original pattern string
        for (auto &it : found) {
            it.pattern = pat_str;
            rv.push_back(std::move(it));
        }
    }
    return rv;
}
// -------------------------
// Directory scan (multithreaded using async)
// -------------------------
std::vector<Issue> scan_directory_for_injections(const fs::path& root_dir,
    const std::unordered_map<std::string, std::vector<std::pair<std::string,std::regex>>>& compiled_by_lang,
    const std::vector<std::pair<std::string,std::regex>>& default_patterns,
    int threads,
    std::size_t min_size, std::size_t max_size,
    const std::vector<std::string>& ignore_exts,
    const std::vector<std::string>& ignore_dirs) {
    std::vector<std::future<std::vector<Issue>>> futures;
    futures.reserve(1024);
    for (auto const& entry : fs::recursive_directory_iterator(root_dir)) {
        try {
            if (!entry.is_regular_file()) continue;
            // check if any path part is in ignore_dirs
            bool skip = false;
            for (auto const& part : entry.path()) {
                std::string p = part.string();
                std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c){ return std::tolower(c); });
                for (auto const& id : ignore_dirs) {
                    std::string idl = id;
                    std::transform(idl.begin(), idl.end(), idl.begin(), [](unsigned char c){ return std::tolower(c); });
                    if (p == idl) { skip = true; break; }
                }
                if (skip) break;
            }
            if (skip) continue;
            // schedule task
            auto p = entry.path();
            futures.emplace_back(std::async(std::launch::async, [p, &compiled_by_lang, &default_patterns, min_size, max_size, &ignore_exts]() {
                return detect_injections_in_file(p, compiled_by_lang, default_patterns, min_size, max_size, ignore_exts);
            }));
            // If too many outstanding futures, wait for some to finish to avoid memory blowup
            if ((int)futures.size() > threads * 16) {
                // poll and collect a completed one
                for (auto it = futures.begin(); it != futures.end(); ) {
                    if (it->wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                        it = futures.erase(it);
                    } else ++it;
                    if ((int)futures.size() <= threads * 8) break;
                }
            }
        } catch (...) {
            continue;
        }
    }
    std::vector<Issue> issues;
    for (auto &fut : futures) {
        try {
            auto res = fut.get();
            for (auto &it : res) issues.push_back(std::move(it));
        } catch (...) { continue; }
    }
    // Deduplicate by (file, line, pattern, match_text_excerpt[:80])
    struct KeyHash {
        std::size_t operator()(std::tuple<std::string,int,std::string,std::string> const& t) const noexcept {
            auto h1 = std::hash<std::string>{}(std::get<0>(t));
            auto h2 = std::hash<int>{}(std::get<1>(t));
            auto h3 = std::hash<std::string>{}(std::get<2>(t));
            auto h4 = std::hash<std::string>{}(std::get<3>(t));
            return h1 ^ (h2<<1) ^ (h3<<2) ^ (h4<<3);
        }
    };
    std::unordered_set<std::tuple<std::string,int,std::string,std::string>, KeyHash> seen;
    std::vector<Issue> unique;
    for (auto &ii : issues) {
        std::string excerpt = ii.match_text;
        if (excerpt.size() > 80) excerpt = excerpt.substr(0,80);
        auto key = std::make_tuple(ii.file, ii.line, ii.pattern, excerpt);
        if (seen.find(key) == seen.end()) {
            seen.insert(key);
            unique.push_back(std::move(ii));
        }
    }
    return unique;
}
// -------------------------
// Save results (CSV)
// -------------------------
void save_results_csv(const std::vector<Issue>& issues, const fs::path& output_file) {
    std::ofstream fh(output_file);
    if (!fh) {
        std::cerr << "[!] Failed to open output file: " << output_file << std::endl;
        return;
    }
    fh << "File,Line,Pattern,Match,Snippet\n";
    for (auto const& it : issues) {
        // Basic CSV escaping: wrap in quotes and escape internal quotes by doubling
        auto escape_csv = [](const std::string& s) {
            std::string r = "\"";
            for (char c : s) {
                if (c == '"') r += "\"\"";
                else r += c;
            }
            r += "\"";
            return r;
        };
        fh << escape_csv(it.file) << "," << it.line << "," << escape_csv(it.pattern) << "," << escape_csv(it.match_text) << "," << escape_csv(it.snippet) << "\n";
    }
    std::cout << "Results saved to " << fs::absolute(output_file) << std::endl;
}
// -------------------------
// Build compiled sets (from LANGUAGE_PATTERNS and optional custom patterns)
// -------------------------
std::unordered_map<std::string, std::vector<std::pair<std::string,std::regex>>> build_compiled_pattern_sets(
    const std::map<std::string, std::vector<std::string>>& custom_patterns) {
    std::unordered_map<std::string, std::vector<std::pair<std::string,std::regex>>> compiled_by_lang;
    // compile default language patterns
    for (auto const& kv : LANGUAGE_PATTERNS) {
        std::vector<std::pair<std::string,std::regex>> vec;
        for (auto const& p : kv.second) {
            try {
                vec.emplace_back(p, std::regex(p, std::regex_constants::ECMAScript | std::regex_constants::icase));
            } catch (const std::regex_error&) {
                std::string esc;
                for (char ch : p) {
                    if (std::ispunct((unsigned char)ch)) esc.push_back('\\');
                    esc.push_back(ch);
                }
                try { vec.emplace_back(p, std::regex(esc, std::regex_constants::ECMAScript | std::regex_constants::icase)); } catch(...) {}
            }
        }
        compiled_by_lang[kv.first] = std::move(vec);
    }
    // default_patterns (those under "all" in custom patterns)
    std::vector<std::pair<std::string,std::regex>> default_patterns;
    if (!custom_patterns.empty()) {
        for (auto const& [k, v] : custom_patterns) {
            if (k == "all") {
                for (auto const& p : v) {
                    try { default_patterns.emplace_back(p, std::regex(p, std::regex_constants::ECMAScript | std::regex_constants::icase)); }
                    catch (...) {
                        std::string esc;
                        for (char ch : p) {
                            if (std::ispunct((unsigned char)ch)) esc.push_back('\\');
                            esc.push_back(ch);
                        }
                        try { default_patterns.emplace_back(p, std::regex(esc, std::regex_constants::ECMAScript | std::regex_constants::icase)); } catch(...) {}
                    }
                }
            } else {
                std::string kl = k;
                std::transform(kl.begin(), kl.end(), kl.begin(), [](unsigned char c){ return std::tolower(c); });
                auto &slot = compiled_by_lang[kl];
                for (auto const& p : v) {
                    try { slot.emplace_back(p, std::regex(p, std::regex_constants::ECMAScript | std::regex_constants::icase)); }
                    catch (...) {
                        std::string esc;
                        for (char ch : p) {
                            if (std::ispunct((unsigned char)ch)) esc.push_back('\\');
                            esc.push_back(ch);
                        }
                        try { slot.emplace_back(p, std::regex(esc, std::regex_constants::ECMAScript | std::regex_constants::icase)); } catch(...) {}
                    }
                }
            }
        }
    }
    // We'll return compiled_by_lang, plus the default_patterns via an out parameter-like approach:
    // but to keep API same as Python, store default patterns under key "__default__".
    compiled_by_lang["__default__"] = std::move(default_patterns);
    return compiled_by_lang;
}
// -------------------------
// Simple custom pattern loader from JSON-like file (VERY lightweight)
// NOTE: To keep dependencies zero, we accept a simple newline-separated "lang:pattern" or "all:pattern" file
// The original python accepted JSON; for parity we will try a very simple JSON detection fallback:
// If the file starts with '{', parse a very tiny JSON using naive parsing to extract top-level arrays of strings.
// This is intentionally lightweight and brittle but provides parity without adding libs.
// -------------------------
std::map<std::string, std::vector<std::string>> load_custom_patterns(const fs::path& config_file) {
    std::map<std::string, std::vector<std::string>> out;
    std::ifstream fh(config_file);
    if (!fh) return out;
    std::string first;
    std::getline(fh, first);
    // naive JSON detection
    if (!first.empty() && first.find('{') != std::string::npos) {
        // Try a very tiny JSON parser for structure like {"python": ["pat1","pat2"], "all": ["p"] }
        // This is intentionally minimal — if parsing fails we return empty and print an error.
        fh.clear();
        fh.seekg(0);
        std::string all((std::istreambuf_iterator<char>(fh)), std::istreambuf_iterator<char>());
        try {
            // Remove whitespace outside quotes for easier parsing
            std::string s;
            bool inq = false;
            for (char c : all) {
                if (c == '"' && (s.empty() || s.back() != '\\')) inq = !inq;
                if (!inq && std::isspace((unsigned char)c)) continue;
                s.push_back(c);
            }
            // This parser is extremely naive; we look for "key":[...] patterns
            std::regex kv_re(R""("([^"]+)"\s*:\s*\[([^\]]*)\])"");
            std::sregex_iterator it(s.begin(), s.end(), kv_re);
            std::sregex_iterator end;
            for (; it != end; ++it) {
                auto m = *it;
                std::string key = m.str(1);
                std::string arr = m.str(2);
                // split arr by commas respecting quoted strings
                std::vector<std::string> items;
                std::string cur;
                bool inq2 = false;
                for (size_t i=0;i<arr.size();++i) {
                    char c = arr[i];
                    if (c == '"' && (i==0 || arr[i-1] != '\\')) {
                        inq2 = !inq2;
                        if (!inq2) {
                            items.push_back(cur);
                            cur.clear();
                            // skip possible following comma
                            size_t j = i+1;
                            while (j < arr.size() && (arr[j] == ',' || isspace((unsigned char)arr[j]))) ++j;
                            i = j-1;
                        }
                        continue;
                    }
                    if (inq2) cur.push_back(c);
                }
                for (auto &it2 : items) {
                    out[key].push_back(it2);
                }
            }
        } catch (...) {
            std::cerr << "[!] Error parsing custom patterns JSON (naive parser) - ignoring custom patterns\n";
            return {};
        }
    } else {
        // Accept simple "lang:pattern" per-line format
        try {
            fh.clear();
            fh.seekg(0);
            std::string line;
            while (std::getline(fh, line)) {
                if (line.empty()) continue;
                auto pos = line.find(':');
                if (pos == std::string::npos) continue;
                std::string key = line.substr(0,pos);
                std::string pat = line.substr(pos+1);
                // trim
                key.erase(0, key.find_first_not_of(" \t\r\n"));
                key.erase(key.find_last_not_of(" \t\r\n")+1);
                pat.erase(0, pat.find_first_not_of(" \t\r\n"));
                pat.erase(pat.find_last_not_of(" \t\r\n")+1);
                if (!key.empty() && !pat.empty()) out[key].push_back(pat);
            }
        } catch (...) {}
    }
    return out;
}
// -------------------------
// Arg parsing (very similar options to Python script but CSV-only)
// -------------------------
struct Args {
    std::string directory;
    std::string config;
    std::string output = "vulnerabilities_report";
    int threads = 8;
    std::vector<std::string> ignore_ext;
    std::vector<std::string> ignore_dir;
    std::size_t min_size = 0;
    std::size_t max_size = 5000000;
};
Args parse_args(int argc, char** argv) {
    Args a;
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <directory> [--config file] [--output name] [--threads N] [--ignore-ext .png .bin] [--ignore-dir node_modules .git] [--min-size N] [--max-size N]\n";
        std::exit(1);
    }
    a.directory = argv[1];
    for (int i=2;i<argc;++i) {
        std::string s = argv[i];
        if (s == "--config" && i+1<argc) { a.config = argv[++i]; }
        else if (s == "--output" && i+1<argc) { a.output = argv[++i]; }
        else if (s == "--threads" && i+1<argc) { a.threads = std::stoi(argv[++i]); }
        else if (s == "--ignore-ext") {
            ++i;
            while (i < argc && argv[i][0] == '.') { a.ignore_ext.push_back(argv[i]); ++i; }
            --i;
        } else if (s == "--ignore-dir") {
            ++i;
            while (i < argc && argv[i][0] != '-') { a.ignore_dir.push_back(argv[i]); ++i; }
            --i;
        } else if (s == "--min-size" && i+1<argc) { a.min_size = static_cast<std::size_t>(std::stoull(argv[++i])); }
        else if (s == "--max-size" && i+1<argc) { a.max_size = static_cast<std::size_t>(std::stoull(argv[++i])); }
        else {
            std::cerr << "[!] Unknown arg: " << s << "\n";
        }
    }
    return a;
}
// -------------------------
// Main
// -------------------------
int main(int argc, char** argv) {
    Args args = parse_args(argc, argv);
    fs::path root(args.directory);
    if (!fs::exists(root) || !fs::is_directory(root)) {
        std::cerr << "[!] Directory not found: " << root << std::endl;
        return 1;
    }
    std::map<std::string, std::vector<std::string>> custom;
    if (!args.config.empty()) {
        custom = load_custom_patterns(args.config);
    }
    // Build compiled sets
    auto compiled_all = build_compiled_pattern_sets(custom);
    // extract default patterns and remove from compiled_by_lang map
    std::vector<std::pair<std::string,std::regex>> default_patterns;
    auto it_def = compiled_all.find("__default__");
    if (it_def != compiled_all.end()) default_patterns = std::move(it_def->second), compiled_all.erase(it_def);
    // Now compiled_all holds per-lang compiled patterns
    std::unordered_map<std::string, std::vector<std::pair<std::string,std::regex>>> compiled_by_lang;
    for (auto &kv : compiled_all) compiled_by_lang[kv.first] = std::move(kv.second);
    // normalize ignore lists
    std::vector<std::string> ignore_exts_norm;
    for (auto &ext : args.ignore_ext) {
        std::string e = ext;
        if (!e.empty() && e[0] != '.') e = "." + e;
        std::transform(e.begin(), e.end(), e.begin(), [](unsigned char c){ return std::tolower(c); });
        ignore_exts_norm.push_back(e);
    }
    std::vector<std::string> ignore_dirs_norm;
    for (auto &d : args.ignore_dir) {
        std::string s = d;
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        ignore_dirs_norm.push_back(s);
    }
    for (auto &d : DEFAULT_IGNORED_DIRS) ignore_dirs_norm.push_back(d);
    // scan
    std::vector<Issue> issues = scan_directory_for_injections(root, compiled_by_lang, default_patterns,
                                                              args.threads, args.min_size, args.max_size,
                                                              ignore_exts_norm, ignore_dirs_norm);
    if (issues.empty()) {
        std::cout << " <| No potential vulnerabilities found.\n";
    } else {
        std::cout << "<| Potential vulnerabilities detected:\n\n";
        for (auto const& it : issues) {
            std::cout << it.file << ":" << it.line << "  -- " << it.pattern << "  -- " << it.snippet << "\n";
        }
        fs::path out_path = args.output + ".csv";
        save_results_csv(issues, out_path);
    }
    return 0;
};
