import os
import re

# Map of file extensions to language
LANG_EXTENSIONS = {
    '.py': 'python',
    '.js': 'javascript',
    '.c': 'c',
    '.cpp': 'cpp',
    '.java': 'java',
    '.sh': 'shell',
    '.bash': 'shell',
}

# Common Vulnerability Patterns

# SQL Injection Patterns
SQL_INJECTION_PATTERNS = [
    r"(?i)select\s+\*\s+from\s+\w+",  # Simple SELECT
    r"(?i)insert\s+into\s+\w+\s+\(.*\)\s+values\s+\(.*\)",  # INSERT INTO
    r"(?i)update\s+\w+\s+set\s+.*\s+where\s+.*",  # UPDATE
    r"(?i)drop\s+table\s+\w+",  # DROP TABLE
    r"(?i)union\s+select\s+.*",  # UNION SELECT
    r"(?i)and\s+1\s*=\s*1",  # Typical true/false conditions in injections
    r"(?i)or\s+1\s*=\s*1",  # Common boolean condition
    r"(?i)select\s+from\s+information_schema.tables",  # Information Schema access
    r"(?i)select\s+from\s+mysql.*user",  # Accessing MySQL user data
    r"(?i)select\s+from\s+pg_catalog.*pg_user",  # PostgreSQL user access
    r"(?i)select\s+from\s+sys\.databases",  # SQL Server databases
    r"(?i)select\s+from\s+sqlite_master",  # SQLite schema access
]

# Cross-Site Scripting (XSS) Patterns
XSS_PATTERNS = [
    r'(?i)document\.write\s*\(',  # Dangerous method for writing content
    r'(?i)eval\((.*)\)\s*;',  # `eval()` method
    r'(?i)innerHTML\s*=\s*',  # Setting innerHTML
    r'(?i)window\.location\s*=',  # Manipulation of window location
    r'(?i)location\.href\s*=',  # Manipulation of location.href
    r'(?i)alert\s*\(',  # Use of `alert` for XSS payloads
    r'(?i)confirm\s*\(',  # Use of `confirm` for XSS payloads
    r'(?i)document\.cookie',  # Cookie manipulation
    r'(?i)eval\s*\(\s*["\'].*["\']\s*\)',  # Dangerous dynamic execution
]

# Command Injection Patterns
COMMAND_INJECTION_PATTERNS = [
    r"(?i)system\s*\(",  # system() call
    r"(?i)popen\s*\(",  # popen() call
    r"(?i)exec\s*\(",  # exec() call
    r"(?i)Runtime\.getRuntime\s*\(\)\.exec\s*\(",  # Java exec
    r"(?i)subprocess\.(call|Popen)\s*\(",  # Python subprocess
    r"(?i)child_process\.exec\s*\(",  # Node.js exec
    r"(?i)nc\s+-e\s+",  # Netcat reverse shell (nc)
    r"(?i)\$\([^\)]*\)",  # Shell command substitution
    r"(?i)eval\s*\(\s*['\"]\$\([^\)]+\)['\"]\)",  # Shell eval injection
]

# Path Traversal Patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",  # Parent directory traversal
    r"(\.\./){2,}",  # Multiple parent directory traversals
    r"(?i)(c:|/)[^:]+/",  # Windows/Linux path traversal
    r"(?i)file://",  # Accessing files with file:// protocol
    r"(?i)open\s*\(\s*\"(\.\./|/)[^\"]+\"",  # File open with traversal
    r"(?i)chroot\s*\(\s*\"(\.\./|/)[^\"]+\"",  # chroot with traversal
]

# Insecure Deserialization Patterns
INSECURE_DESERIALIZATION_PATTERNS = [
    r"(?i)pickle\.load\s*\(",  # Pickle deserialization in Python
    r"(?i)unserialize\s*\(",  # PHP unserialize function
    r"(?i)ObjectInputStream\s*\(",  # Java ObjectInputStream
    r"(?i)deserialize\s*\(",  # Generic deserialization method
    r"(?i)json\.parse\s*\(",  # JSON parsing in untrusted sources
    r"(?i)XMLDecoder\s*\(",  # Insecure XML deserialization
]

# Buffer Overflow Patterns
BUFFER_OVERFLOW_PATTERNS = [
    r"(?i)strcpy\s*\(\s*\w+,\s*\w+\)",  # strcpy function call (unsafe string copy)
    r"(?i)strcat\s*\(\s*\w+,\s*\w+\)",  # strcat function call (unsafe string concatenation)
    r"(?i)gets\s*\(",  # gets function (unsafe input)
    r"(?i)scanf\s*\(",  # scanf function (unsafe input)
    r"(?i)memcpy\s*\(",  # memcpy function (unsafe memory copy)
    r"(?i)fgets\s*\(",  # fgets function (unsafe input)
]

# Cross-Site Request Forgery (CSRF) Patterns
CSRF_PATTERNS = [
    r"(?i)document\.location\.href\s*=\s*['\"]\S+['\"]",  # Redirecting to another URL
    r"(?i)form\s+action\s*=\s*['\"]\S+['\"]",  # Form action URL
    r"(?i)window\.location\s*=\s*['\"]\S+['\"]",  # Window location manipulation
    r"(?i)\$\('[^']+'\)\.submit\s*\(",  # Auto-submit form via JavaScript
    r"(?i)post\s+method\s*=\s*['\"]\S+['\"]",  # POST method in forms
]

# Improper Authentication Patterns
IMPROPER_AUTHENTICATION_PATTERNS = [
    r"(?i)session_id\s*=\s*['\"][a-zA-Z0-9]{32}['\"]",  # Hardcoded session IDs
    r"(?i)request\.cookies\s*\['session_id'\]",  # Improper session handling
    r"(?i)Authorization\s*:\s*['\"]Bearer\s+[A-Za-z0-9\-_]+['\"]",  # Token handling
    r"(?i)auth_token\s*=\s*['\"][A-Za-z0-9\-_]+['\"]",  # Token assignment
    r"(?i)request\.headers\s*\['Authorization'\]",  # Token from HTTP headers
]

# Insecure API Patterns
INSECURE_API_PATTERNS = [
    r"(?i)/api/v[0-9]+/users",  # Sensitive user data API endpoint
    r"(?i)/api/v[0-9]+/admin",  # Admin access API endpoint
    r"(?i)/api/v[0-9]+/token",  # Token-based API endpoints
    r"(?i)/api/v[0-9]+/password",  # Password change endpoint
    r"(?i)/api/v[0-9]+/login",  # Login endpoint
]

# Insecure Cryptographic Practices Patterns
INSECURE_CRYPTOGRAPHIC_PATTERNS = [
    r"(?i)MD5\s*\(",  # MD5 hashing (insecure)
    r"(?i)SHA1\s*\(",  # SHA1 hashing (insecure)
    r"(?i)base64\s*\(",  # base64 encoding/decoding (unsafe for encryption)
    r"(?i)plaintext\s*=\s*['\"][a-zA-Z0-9]+['\"]",  # Plaintext passwords or keys
]

# Race Condition Patterns
RACE_CONDITION_PATTERNS = [
    r"(?i)pthread_mutex_lock\s*\(",  # pthread mutex lock (possible race condition)
    r"(?i)pthread_mutex_unlock\s*\(",  # pthread mutex unlock (possible race condition)
    r"(?i)fsync\s*\(",  # fsync() not used in file operations
    r"(?i)wait\s*\(",  # wait() function call (race condition potential)
]

# Privilege Escalation Patterns
PRIVILEGE_ESCALATION_PATTERNS = [
    r"(?i)sudo\s+",  # Use of sudo without proper validation
    r"(?i)chmod\s*777",  # Setting permissions to 777 (world writable)
    r"(?i)setuid\s*\(",  # setuid system call (privilege escalation)
]

# Extended unsafe patterns grouped by language
LANGUAGE_PATTERNS = {
    'python': [
        r"(?i)subprocess\.(call|Popen)\s*\(",  # Dangerous subprocess calls
        r"(?i)eval\s*\(",  # eval (code injection)
        r"(?i)exec\s*\(",  # exec (code injection)
        r"(?i)pickle\.load\s*\(",  # Insecure deserialization
        r"(?i)open\s*\(\s*\"[^\"]+\"",  # File operations
        r"(?i)os\.system\s*\(",  # os.system (command injection)
        r"(?i)os\.popen\s*\(",  # os.popen (command injection)
        *SQL_INJECTION_PATTERNS,
        *XSS_PATTERNS,
        *COMMAND_INJECTION_PATTERNS,
        *PATH_TRAVERSAL_PATTERNS,
        *INSECURE_DESERIALIZATION_PATTERNS,
        *BUFFER_OVERFLOW_PATTERNS,
    ],
    'javascript': [
        r"(?i)child_process\.exec\s*\(",  # Unsafe child process execution
        r"(?i)eval\s*\(",  # eval (code injection)
        r"(?i)Function\s*\(",  # Function constructor (code injection)
        r"(?i)JSON\.parse\s*\(",  # Unsafe JSON.parse
        r"(?i)__proto__\s*=",  # Prototype pollution
        r"(?i)--",  # SQL injection attempt
        r"(?i)/\*",  # SQL injection attempt
        r"(?i)\"[^\"]+\s*\+\s*\w+\s*\+\s*\"'",  # String concatenation in queries
        r"(?i)\.\./",  # Path traversal
        *SQL_INJECTION_PATTERNS,
        *XSS_PATTERNS,
        *COMMAND_INJECTION_PATTERNS,
        *PATH_TRAVERSAL_PATTERNS,
        *INSECURE_DESERIALIZATION_PATTERNS,
        *BUFFER_OVERFLOW_PATTERNS,
    ],
    'c': [
        r"(?i)system\s*\(",  # system() call (command injection)
        r"(?i)popen\s*\(",  # popen() call (command injection)
        r"(?i)execl\s*\(",  # exec calls
        r"(?i)strcpy\s*\(",  # strcpy() buffer overflow
        r"(?i)memcpy\s*\(",  # memcpy() buffer overflow
        r"(?i)gets\s*\(",  # gets() buffer overflow
        *SQL_INJECTION_PATTERNS,
        *BUFFER_OVERFLOW_PATTERNS,
        *COMMAND_INJECTION_PATTERNS,
    ],
    'cpp': [
        r"(?i)system\s*\(",  # system() call (command injection)
        r"(?i)popen\s*\(",  # popen() call (command injection)
        r"(?i)strcpy\s*\(",  # strcpy() buffer overflow
        r"(?i)memcpy\s*\(",  # memcpy() buffer overflow
        r"(?i)rand\(\)",  # Random number generation
        r"(?i)\.\./",  # Path traversal
        *SQL_INJECTION_PATTERNS,
        *BUFFER_OVERFLOW_PATTERNS,
        *COMMAND_INJECTION_PATTERNS,
    ],
    'java': [
        r"(?i)Runtime\.getRuntime\s*\(\)\.exec\s*\(",  # Runtime exec (command injection)
        r"(?i)ObjectInputStream\s*\(",  # Deserialization vulnerability
        r"(?i)--",  # SQL injection attempt
        r"(?i)\"http://[^\s]+\"",  # Open redirect
        *SQL_INJECTION_PATTERNS,
        *INSECURE_DESERIALIZATION_PATTERNS,
        *COMMAND_INJECTION_PATTERNS,
    ],
    'shell': [
        r"(?i)`[^`]+`",  # Command substitution
        r"(?i)eval\s+\(",  # eval() usage
        r"(?i)\$\([^)]+\)",  # Command substitution
        r"(?i)rm\s+-rf\s+",  # rm -rf command
        r"(?i)ncat\s+-l\s+\d+",  # Netcat reverse shell
        *SQL_INJECTION_PATTERNS,
        *COMMAND_INJECTION_PATTERNS,
        *XSS_PATTERNS,
    ]
}
def detect_injections_in_file(filepath):
    _, ext = os.path.splitext(filepath)
    lang = LANG_EXTENSIONS.get(ext)
    if not lang:
        return []

    patterns = LANGUAGE_PATTERNS.get(lang, [])
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return [f"[!] Error reading {filepath}: {e}"]

    for i, line in enumerate(lines):
        for pattern in patterns:
            if re.search(pattern, line):
                results.append(f"{filepath}:{i+1}: {line.strip()}  <-- ⚠️ Potential Vulnerability")
    return results

def scan_directory_for_injections(root_dir):
    issues_found = []
    for subdir, _, files in os.walk(root_dir):
        for file in files:
            full_path = os.path.join(subdir, file)
            results = detect_injections_in_file(full_path)
            if results:
                issues_found.extend(results)
    return issues_found

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Static scanner for potential vulnerabilities.")
    parser.add_argument("directory", help="Directory to scan")
    args = parser.parse_args()
    issues = scan_directory_for_injections(args.directory)
    if not issues:
        print("✅ No potential vulnerabilities found.")
    else:
        print("🚨 Potential vulnerabilities detected:\n")
        for issue in issues:
            print(issue)
