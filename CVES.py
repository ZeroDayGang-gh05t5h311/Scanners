import os
import re
import json
import csv
import argparse
import concurrent.futures

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
    r"(?i)chmod\s+777\s+",  # Weak file permissions
    r"(?i)chown\s+",  # Changing ownership of files
]

# List of all patterns for easy use
LANGUAGE_PATTERNS = {
    'python': SQL_INJECTION_PATTERNS + XSS_PATTERNS + COMMAND_INJECTION_PATTERNS,
    'javascript': XSS_PATTERNS + COMMAND_INJECTION_PATTERNS + INSECURE_API_PATTERNS,
    'c': SQL_INJECTION_PATTERNS + COMMAND_INJECTION_PATTERNS + BUFFER_OVERFLOW_PATTERNS,
    'cpp': SQL_INJECTION_PATTERNS + COMMAND_INJECTION_PATTERNS + BUFFER_OVERFLOW_PATTERNS,
    'java': SQL_INJECTION_PATTERNS + INSECURE_DESERIALIZATION_PATTERNS + IMPROPER_AUTHENTICATION_PATTERNS,
    'shell': COMMAND_INJECTION_PATTERNS + PRIVILEGE_ESCALATION_PATTERNS,
}

def load_custom_patterns(config_file):
    """Load custom patterns from a JSON file."""
    try:
        with open(config_file, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error loading custom patterns: {e}")
        return []

def detect_injections_in_file(filepath, patterns):
    """Detect vulnerabilities in a single file."""
    results = []
    seen_issues = set()  # Set to track unique vulnerabilities (file, line number)
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return [f"[!] Error reading {filepath}: {e}"]

    for i, line in enumerate(lines):
        for pattern in patterns:
            if re.search(pattern, line):
                issue = (filepath, i + 1)  # Use file path and line number as unique identifier
                if issue not in seen_issues:
                    seen_issues.add(issue)
                    results.append(f"{filepath}:{i + 1}: {line.strip()}  <-- ⚠️ Potential Vulnerability")

    return results

def scan_directory_for_injections(root_dir, patterns):
    """Scan all files in the directory for potential vulnerabilities."""
    issues_found = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for subdir, _, files in os.walk(root_dir):
            for file in files:
                full_path = os.path.join(subdir, file)
                futures.append(executor.submit(detect_injections_in_file, full_path, patterns))
        
        for future in concurrent.futures.as_completed(futures):
            results = future.result()
            if results:
                issues_found.extend(results)

    # Remove duplicates (same file, same line number, same vulnerability)
    seen_issues = set()
    unique_issues = []
    for issue in issues_found:
        file, line, content = issue.split(':', 2)
        issue_tuple = (file, line.strip())  # Unique identifier: (file, line)
        if issue_tuple not in seen_issues:
            seen_issues.add(issue_tuple)
            unique_issues.append(issue)

    return unique_issues

def save_results(issues, output_file, file_format):
    """Save issues to a file in JSON or CSV format."""
    if file_format == "json":
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(issues, f, indent=4)
    elif file_format == "csv":
        with open(output_file, "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["File", "Line", "Vulnerability"])
            for issue in issues:
                file, line, content = issue.split(":", 2)
                writer.writerow([file, line.strip(), content.strip()])
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static scanner for potential vulnerabilities.")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--config", help="Custom pattern configuration file (JSON)", default=None)
    parser.add_argument("--output", help="Output file name", default="vulnerabilities_report")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format (json or csv)")
    args = parser.parse_args()

    # Load custom patterns from config file if provided
    custom_patterns = []
    if args.config:
        custom_patterns = load_custom_patterns(args.config)

    # Use default patterns plus any custom patterns
    patterns = []
    for lang in LANGUAGE_PATTERNS.values():
        patterns.extend(lang)
    patterns.extend(custom_patterns)

    # Scan the directory for vulnerabilities
    issues = scan_directory_for_injections(args.directory, patterns)

    # Output results
    if not issues:
        print("✅ No potential vulnerabilities found.")
    else:
        print("🚨 Potential vulnerabilities detected:\n")
        for issue in issues:
            print(issue)
        save_results(issues, args.output + "." + args.format, args.format)
        print(f"\nResults saved to {args.output}.{args.format}")
