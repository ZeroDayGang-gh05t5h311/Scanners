#!/usr/bin/env python3
"""
Improved static scanner for potential vulnerabilities.
- Scans files by extension -> apply language-specific compiled regexes.
- Scans whole file (not line-by-line) and maps matches to line numbers.
- Deduplicates results robustly (path, line, pattern).
- Structured JSON/CSV output.
- Skips binary/very large files by default.
"""

import argparse
import concurrent.futures
import json
import csv
import os
import re
from pathlib import Path
from typing import List, Dict

# Map of file extensions to language
LANG_EXTENSIONS = {
    '.py': 'python',
    '.js': 'javascript',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.h': 'c',
    '.hpp': 'cpp',
    '.java': 'java',
    '.sh': 'shell',
    '.bash': 'shell',
}

# --- Full vulnerability pattern lists (from the original script) ---

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
    r"(?i)execute\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+",
    r"(?i)cursor\.execute\s*\(\s*.*\)",
    r"(?i)prepareStatement\s*\(",
    r"(?i)WHERE\s+1=1\s+--",
    r"(?i)--\s*$|#\s*$",
    r"(?i)UNION\s+ALL\s+SELECT",
    r"(?i)CAST\(.+AS\s+VARCHAR",
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
    r"(?i)response\.write\(",
    r"(?i)res\.send\(",
    r"(?i)innerText\s*=",
    r"(?i)document\.createElement\(['\"]script['\"]\)",
    r"(?i)setAttribute\(\s*['\"]on\w+['\"]\s*,",
    r"(?i)dangerouslySetInnerHTML",
    r"(?i)style\.cssText\s*=",
    r"(?i)location\.replace\s*\(",
    r"(?i)res\.end\s*\(",
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
    r"(?i)System\.exec",                # not in original but left commented for awareness (not active)
    r"(?i)\$\([^)]+\)",                 # backticks / command substitution (shell)
    r"(?i)shell=True",
    r"(?i)cmd\.exe\s*/c",
    r"(?i)system\([^,]+;",              # chained multiple commands
    r"(?i)exec\([^,]+\+",               # concatenated exec args
    r"(?i)popen\([^,]+\+",
    r"(?i)ProcessBuilder\s*\(.+builder\.command\(",
    r"(?i)Runtime\.exec\(.+\+",
    r"(?i)popen2|popen3",
    r"(?i)subprocess\.(call|check_output)\s*\(.*\+",
]

# Path Traversal Patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",  # Parent directory traversal
    r"(\.\./){2,}",  # Multiple parent directory traversals
    r"(?i)(c:|/)[^:]+/",  # Windows/Linux path traversal
    r"(?i)file://",  # Accessing files with file:// protocol
    r"(?i)open\s*\(\s*\"(\.\./|/)[^\"]+\"",  # File open with traversal
    r"(?i)chroot\s*\(\s*\"(\.\./|/)[^\"]+\"",  # chroot with traversal
     r"(?i)normalizePath\(|path\.normalize\(",
    r"(?i)realpath\(|os\.realpath\(",
    r"(?i)\.\.\\",                    # windows backslash traversal
    r"(?i)zipfile\.ZipFile\(|tarfile\.open\(",
    r"(?i)upload_tmp_dir|tmp_name",
    r"(?i)save_path\s*=",
    r"(?i)path\.join\([^,]+,\s*\.\.",
    r"(?i)filename\s*=\s*request\.",
    r"(?i)Content-Disposition:\s*filename=",
]

# Insecure Deserialization Patterns
INSECURE_DESERIALIZATION_PATTERNS = [
    r"(?i)pickle\.load\s*\(",  # Pickle deserialization in Python
    r"(?i)unserialize\s*\(",  # PHP unserialize function
    r"(?i)ObjectInputStream\s*\(",  # Java ObjectInputStream
    r"(?i)deserialize\s*\(",  # Generic deserialization method
    r"(?i)json\.parse\s*\(",  # JSON parsing in untrusted sources
    r"(?i)XMLDecoder\s*\(",  # Insecure XML deserialization
    r"(?i)XStream\.fromXML\s*\(",
    r"(?i)yaml\.load\s*\(",
    r"(?i)Marshal\.load\s*\(",
    r"(?i)Marshal\.restore\s*\(",
    r"(?i)eval\(.+base64_decode\(",
    r"(?i)gob\.NewDecoder\(|encoding/gob",
    r"(?i)serde_json::from_str\(",
    r"(?i)perl\s+Storable::thaw",
    r"(?i)apache\.commons\.collections",
    r"(?i)readObject\(|writeReplace\(",
    r"(?i)readObject\s*\(",
    r"(?i)writeObject\s*\(",
    r"(?i)ObjectInputStream\.resolveClass",
    r"(?i)XStream\.fromXML\s*\(",
    r"(?i)Gson\.fromJson\s*\(",
]

# Buffer Overflow Patterns
BUFFER_OVERFLOW_PATTERNS = [
    r"(?i)strcpy\s*\(\s*\w+,\s*\w+\)",  # strcpy function call (unsafe string copy)
    r"(?i)strcat\s*\(\s*\w+,\s*\w+\)",  # strcat function call (unsafe string concatenation)
    r"(?i)gets\s*\(",  # gets function (unsafe input)
    r"(?i)scanf\s*\(",  # scanf function (unsafe input)
    r"(?i)memcpy\s*\(",  # memcpy function (unsafe memory copy)
    r"(?i)fgets\s*\(",  # fgets function (unsafe input)
    r"(?i)XStream\.fromXML\s*\(",
    r"(?i)yaml\.load\s*\(",
    r"(?i)Marshal\.load\s*\(",
    r"(?i)Marshal\.restore\s*\(",
    r"(?i)eval\(.+base64_decode\(",
    r"(?i)gob\.NewDecoder\(|encoding/gob",
    r"(?i)serde_json::from_str\(",
    r"(?i)perl\s+Storable::thaw",
    r"(?i)apache\.commons\.collections",
    r"(?i)readObject\(|writeReplace\(",
    r"(?i)readObject\s*\(",
    r"(?i)writeObject\s*\(",
    r"(?i)ObjectInputStream\.resolveClass",
    r"(?i)XStream\.fromXML\s*\(",
    r"(?i)Gson\.fromJson\s*\(",
    r"(?i)malloc\s*\(|(?i)calloc\s*\(",
    r"(?i)stack_exec|mprotect\s*\(",
    r"(?i)memset\(.+0x00",
]

# Cross-Site Request Forgery (CSRF) Patterns
CSRF_PATTERNS = [
    r"(?i)document\.location\.href\s*=\s*['\"]\S+['\"]",  # Redirecting to another URL
    r"(?i)form\s+action\s*=\s*['\"]\S+['\"]",  # Form action URL
    r"(?i)window\.location\s*=\s*['\"]\S+['\"]",  # Window location manipulation
    r"(?i)\$\('[^']+'\)\.submit\s*\(",  # Auto-submit form via JavaScript
    r"(?i)post\s+method\s*=\s*['\"]\S+['\"]",  # POST method in forms
    r"(?i)input\s+type\s*=\s*['\"]hidden['\"]\s+name\s*=\s*['\"]csrf",
    r"(?i)X-CSRF-Token",
    r"(?i)SameSite=None",
    r"(?i)document\.forms\[[0-9]+\]\.submit",
    r"(?i)action\s*=\s*\"/external",
    r"(?i)autofill",
]

# Improper Authentication Patterns
IMPROPER_AUTHENTICATION_PATTERNS = [
    r"(?i)session_id\s*=\s*['\"][a-zA-Z0-9]{32}['\"]",  # Hardcoded session IDs
    r"(?i)request\.cookies\s*\['session_id'\]",  # Improper session handling
    r"(?i)Authorization\s*:\s*['\"]Bearer\s+[A-Za-z0-9\-_]+['\"]",  # Token handling
    r"(?i)auth_token\s*=\s*['\"][A-Za-z0-9\-_]+['\"]",  # Token assignment
    r"(?i)request\.headers\s*\['Authorization'\]",  # Token from HTTP headers
    r"(?i)password\s*=\s*['\"][^'\"]{1,}['\"]",
    r"(?i)api_key\s*=\s*['\"][A-Za-z0-9\-_]+['\"]",
    r"(?i)hardcoded_secret|hardcoded_key|private_key\s*=",
    r"(?i)Basic\s+[A-Za-z0-9=]+",
    r"(?i)set_cookie\(|cookie\.set\(",
    r"(?i)session\.(start|destroy)",
    r"(?i)bcrypt\.hashpw\(|password_hash\(",
    r"(?i)compare_digest\(|hmac\.compare_digest\(",
    r"(?i)token_expiry|exp\s*:",
    r"(?i)Authorization\s*:\s*Bearer",
]

# Insecure API Patterns
INSECURE_API_PATTERNS = [
    r"(?i)/api/v[0-9]+/users",  # Sensitive user data API endpoint
    r"(?i)/api/v[0-9]+/admin",  # Admin access API endpoint
    r"(?i)/api/v[0-9]+/token",  # Token-based API endpoints
    r"(?i)/api/v[0-9]+/password",  # Password change endpoint
    r"(?i)/api/v[0-9]+/login",  # Login endpoint
    r"(?i)/internal/|/private/|/debug/",
    r"(?i)swagger.json|api-docs|/v2/api-docs",
    r"(?i)X-Forwarded-For",
    r"(?i)introspect|.well-known/openid-configuration",
    r"(?i)graphql",
    r"(?i)rate_limit|throttle",
    r"(?i)Authorization\s*:\s*Bearer # token leakage in logs/header",
]

# Insecure Cryptographic Practices Patterns
INSECURE_CRYPTOGRAPHIC_PATTERNS = [
    r"(?i)MD5\s*\(",  # MD5 hashing (insecure)
    r"(?i)SHA1\s*\(",  # SHA1 hashing (insecure)
    r"(?i)base64\s*\(",  # base64 encoding/decoding (unsafe for encryption)
    r"(?i)plaintext\s*=\s*['\"][a-zA-Z0-9]+['\"]",  # Plaintext passwords or keys
    r"(?i)AES-ECB|AES128-ECB|ECB_MODE",
    r"(?i)openssl\s+enc\s+-aes-128-cbc",
    r"(?i)RSA_padding\(|RSA_NO_PADDING",
    r"(?i)SSLv3|ssl3",
    r"(?i)RC4|DES|3DES|EXPORT",
    r"(?i)hardcoded_key|hardcoded_password|private_key.*=",
    r"(?i)PBKDF2|bcrypt|scrypt",
    r"(?i)iteration_count\s*=\s*\d{1,4}",
    r"(?i)random\.random\(|Math\.random\(",
    r"(?i)secure_random|SystemRandom",
    r"(?i)HMAC-SHA1",
    r"(?i)cryptography\.hazmat|from\s+Crypto\.",
]

# Race Condition Patterns
RACE_CONDITION_PATTERNS = [
    r"(?i)pthread_mutex_lock\s*\(",  # pthread mutex lock (possible race condition)
    r"(?i)pthread_mutex_unlock\s*\(",  # pthread mutex unlock (possible race condition)
    r"(?i)fsync\s*\(",  # fsync() not used in file operations
    r"(?i)wait\s*\(",  # wait() function call (race condition potential)
    r"(?i)open\([^,]+,\s*O_CREAT\|O_EXCL",
    r"(?i)rename\(",
    r"(?i)stat\(|lstat\(",
    r"(?i)mktemp\s*\(",
    r"(?i)lockf\s*\(",
    r"(?i)sem_wait|sem_post",
    r"(?i)volatile\s+",
    r"(?i)atomic_compare_exchange",
    r"(?i)nsync|pthread_create",
]

# Privilege Escalation Patterns
PRIVILEGE_ESCALATION_PATTERNS = [
    r"(?i)sudo\s+",  # Use of sudo without proper validation
    r"(?i)chmod\s+777\s+",  # Weak file permissions
    r"(?i)chown\s+",  # Changing ownership of files
    r"(?i)setuid\(|setgid\(|seteuid\(|setegid\(",
    r"(?i)cap_set_file|cap_get_proc",
    r"(?i)passwd\s+",
    r"(?i)/etc/shadow|/etc/passwd",
    r"(?i)su\s+-",
    r"(?i)mount\s+-o\s+",
    r"(?i)docker\s+run\s+--privileged",
    r"(?i)iptables\s+",
    r"(?i)chroot\s*\(",
]

# List of all patterns for easy use (language mapping)
LANGUAGE_PATTERNS = {
    'python': SQL_INJECTION_PATTERNS + XSS_PATTERNS + COMMAND_INJECTION_PATTERNS,
    'javascript': XSS_PATTERNS + COMMAND_INJECTION_PATTERNS + INSECURE_API_PATTERNS,
    'c': SQL_INJECTION_PATTERNS + COMMAND_INJECTION_PATTERNS + BUFFER_OVERFLOW_PATTERNS,
    'cpp': SQL_INJECTION_PATTERNS + COMMAND_INJECTION_PATTERNS + BUFFER_OVERFLOW_PATTERNS,
    'java': SQL_INJECTION_PATTERNS + INSECURE_DESERIALIZATION_PATTERNS + IMPROPER_AUTHENTICATION_PATTERNS,
    'shell': COMMAND_INJECTION_PATTERNS + PRIVILEGE_ESCALATION_PATTERNS,
}

# --- End full lists ---

def load_custom_patterns(config_file: Path) -> Dict[str, List[str]]:
    """Load custom patterns JSON. Expect format: { "python": ["pattern1", ...], "all": [...] }"""
    try:
        with open(config_file, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("Custom patterns JSON must be an object/dictionary.")
            return data
    except Exception as e:
        print(f"[!] Error loading custom patterns: {e}")
        return {}

def is_text_file(path: Path, max_bytes=2048) -> bool:
    """Rudimentary text file detection: read small chunk and check for null bytes."""
    try:
        with open(path, 'rb') as fh:
            chunk = fh.read(max_bytes)
            if b'\x00' in chunk:
                return False
            # heuristics: mostly printable?
            return True
    except Exception:
        return False

def compile_patterns(pattern_list: List[str]) -> List[re.Pattern]:
    """Compile a list of regex strings into compiled patterns with IGNORECASE flag."""
    compiled = []
    for p in pattern_list:
        try:
            compiled.append(re.compile(p, re.IGNORECASE | re.MULTILINE))
        except re.error:
            # fallback: escape and compile
            compiled.append(re.compile(re.escape(p), re.IGNORECASE | re.MULTILINE))
    return compiled

def find_matches_in_text(text: str, compiled_patterns: List[re.Pattern], path: Path) -> List[Dict]:
    """Return list of matches as dicts with file, line number, snippet, and pattern."""
    matches = []
    if not compiled_patterns:
        return matches
    # Pre-split lines for fast access
    lines = text.splitlines()
    # Build cumulative positions for mapping offset->line number
    newline_positions = []
    pos = 0
    for ln in lines:
        newline_positions.append(pos)
        pos += len(ln) + 1  # +1 for the newline that was removed by splitlines

    def offset_to_line(offset: int) -> int:
        # binary search
        lo = 0
        hi = len(newline_positions) - 1
        if not newline_positions:
            return 1
        if offset < newline_positions[0]:
            return 1
        if offset >= pos:
            return len(newline_positions)
        while lo <= hi:
            mid = (lo + hi) // 2
            if newline_positions[mid] <= offset:
                lo = mid + 1
            else:
                hi = mid - 1
        return lo

    for pat in compiled_patterns:
        for m in pat.finditer(text):
            start = m.start()
            line_no = offset_to_line(start)
            idx = max(0, min(line_no - 1, len(lines) - 1))
            snippet = lines[idx].strip()
            matches.append({
                "file": str(path),
                "line": line_no,
                "pattern": pat.pattern,
                "match_text": m.group(0)[:300],
                "snippet": snippet
            })
    return matches

def detect_injections_in_file(path: Path, compiled_by_lang: Dict[str, List[re.Pattern]], default_patterns: List[re.Pattern], min_size: int, max_size: int, ignore_exts: List[str]) -> List[Dict]:
    """Detect vulnerabilities in a single file and return structured dicts."""
    try:
        if path.suffix.lower() in ignore_exts:
            return []
        if path.stat().st_size < min_size or (max_size > 0 and path.stat().st_size > max_size):
            return []
    except Exception:
        return []

    if not is_text_file(path):
        return []

    # Choose pattern set based on extension
    lang = LANG_EXTENSIONS.get(path.suffix.lower())
    compiled_patterns = compiled_by_lang.get(lang, []) + default_patterns

    if not compiled_patterns:
        return []

    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        return [{"file": str(path), "line": 0, "pattern": "ERROR_READING", "match_text": "", "snippet": f"Error reading file: {e}"}]

    return find_matches_in_text(text, compiled_patterns, path)

def scan_directory_for_injections(root_dir: Path, compiled_by_lang: Dict[str, List[re.Pattern]],
                                  default_patterns: List[re.Pattern], threads: int,
                                  min_size: int, max_size: int, ignore_exts: List[str]) -> List[Dict]:
    issues: List[Dict] = []
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for p in root_dir.rglob("*"):
            if p.is_file():
                futures.append(ex.submit(detect_injections_in_file, p, compiled_by_lang, default_patterns, min_size, max_size, ignore_exts))
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
                if res:
                    issues.extend(res)
            except Exception:
                pass
    # Deduplicate by (file, line, pattern)
    seen = set()
    unique = []
    for ii in issues:
        key = (ii.get("file"), ii.get("line"), ii.get("pattern"))
        if key not in seen:
            seen.add(key)
            unique.append(ii)
    return unique

def save_results(issues: List[Dict], output_file: Path, file_format: str):
    if file_format == "json":
        with open(output_file, "w", encoding='utf-8') as fh:
            json.dump(issues, fh, indent=2, ensure_ascii=False)
    elif file_format == "csv":
        with open(output_file, "w", newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            writer.writerow(["File", "Line", "Pattern", "Match", "Snippet"])
            for it in issues:
                writer.writerow([it.get("file"), it.get("line"), it.get("pattern"), it.get("match_text"), it.get("snippet")])
    print(f"Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Improved static scanner for potential vulnerabilities.")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--config", help="Custom pattern configuration file (JSON)", default=None)
    parser.add_argument("--output", help="Output file name (without extension)", default="vulnerabilities_report")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads")
    parser.add_argument("--ignore-ext", nargs="*", default=[], help="File extensions to ignore (e.g. .png .jpg)")
    parser.add_argument("--min-size", type=int, default=0, help="Minimum file size in bytes to scan")
    parser.add_argument("--max-size", type=int, default=5_000_000, help="Maximum file size in bytes to scan (0 for no limit)")
    args = parser.parse_args()

    root = Path(args.directory)
    if not root.exists() or not root.is_dir():
        print(f"[!] Directory not found: {root}")
        return

    # Build compiled pattern sets
    compiled_by_lang = {}
    for lang, pats in LANGUAGE_PATTERNS.items():
        compiled_by_lang[lang] = compile_patterns(pats)

    default_patterns = []  # patterns applied to all files (if any)
    # Load custom patterns if provided
    if args.config:
        custom = load_custom_patterns(Path(args.config))
        # Expecting {"python": [...], "all": [...]} etc.
        for k, v in custom.items():
            if not isinstance(v, list):
                continue
            if k.lower() == "all":
                default_patterns.extend(compile_patterns(v))
            else:
                compiled_by_lang.setdefault(k.lower(), [])
                compiled_by_lang[k.lower()].extend(compile_patterns(v))

    default_patterns = compile_patterns([p.pattern if isinstance(p, re.Pattern) else p for p in default_patterns]) if default_patterns else []

    issues = scan_directory_for_injections(root, compiled_by_lang, default_patterns, args.threads, args.min_size, args.max_size, [ext.lower() for ext in args.ignore_ext])

    if not issues:
        print(" <| No potential vulnerabilities found.")
    else:
        print("<| Potential vulnerabilities detected:\n")
        for it in issues:
            print(f"{it['file']}:{it['line']}  -- {it['pattern']}  -- {it['snippet']}")
        out_path = Path(f"{args.output}.{args.format}")
        save_results(issues, out_path, args.format)

if __name__ == "__main__":
    main()
