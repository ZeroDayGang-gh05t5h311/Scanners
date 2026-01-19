#!/usr/bin/python3
from __future__ import annotations
import argparse
import concurrent.futures
import json
import csv
import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple
import bisect
import string
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
SQL_INJECTION_PATTERNS = [
    r"(?i)select\s+\*\s+from\s+\w+",
    r"(?i)insert\s+into\s+\w+\s+\(.*\)\s+values\s*\(.*\)",
    r"(?i)update\s+\w+\s+set\s+.*\s+where\s+.*",
    r"(?i)drop\s+table\s+\w+",
    r"(?i)union\s+select\s+.*",
    r"(?i)and\s+1\s*=\s*1",
    r"(?i)or\s+1\s*=\s*1",
    r"(?i)select\s+from\s+information_schema.tables",
    r"(?i)select\s+from\s+mysql.*user",
    r"(?i)select\s+from\s+pg_catalog.*pg_user",
    r"(?i)select\s+from\s+sys\.databases",
    r"(?i)select\s+from\s+sqlite_master",
    r"(?i)execute\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+",
    r"(?i)cursor\.execute\s*\(\s*.*\)",
    r"(?i)prepareStatement\s*\(",
    r"(?i)WHERE\s+1=1\s+--",
    r"(?i)--\s*$|#\s*$",
    r"(?i)UNION\s+ALL\s+SELECT",
    r"(?i)CAST\(.+AS\s+VARCHAR",
]
XSS_PATTERNS = [
    r'(?i)document\.write\s*\(',
    r'(?i)eval\((.*)\)\s*;',
    r'(?i)innerHTML\s*=\s*',
    r'(?i)window\.location\s*=',
    r'(?i)location\.href\s*=',
    r'(?i)alert\s*\(',
    r'(?i)confirm\s*\(',
    r'(?i)document\.cookie',
    r'(?i)eval\s*\(\s*["\'].*["\']\s*\)',
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
COMMAND_INJECTION_PATTERNS = [
    r"(?i)system\s*\(",
    r"(?i)popen\s*\(",
    r"(?i)exec\s*\(",
    r"(?i)Runtime\.getRuntime\s*\(\)\.exec\s*\(",
    r"(?i)subprocess\.(call|Popen)\s*\(",
    r"(?i)child_process\.exec\s*\(",
    r"(?i)nc\s+-e\s+",
    r"(?i)\$\([^\)]*\)",
    r"(?i)eval\s*\(\s*['\"]\$\([^\)]+\)['\"]\)",
    r"(?i)shell=True",
    r"(?i)cmd\.exe\s*/c",
    r"(?i)system\([^,]+;",
    r"(?i)exec\([^,]+\+",
    r"(?i)popen\([^,]+\+",
    r"(?i)ProcessBuilder\s*\(.+builder\.command\(",
    r"(?i)Runtime\.exec\(.+\+",
    r"(?i)popen2|popen3",
    r"(?i)subprocess\.(call|check_output)\s*\(.*\+",
]
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"(\.\./){2,}",
    r"(?i)(c:|/)[^:]+/",
    r"(?i)file://",
    r"(?i)open\s*\(\s*\"(\.\./|/)[^\"]+\"",
    r"(?i)chroot\s*\(\s*\"(\.\./|/)[^\"]+\"",
    r"(?i)normalizePath\(|path\.normalize\(",
    r"(?i)realpath\(|os\.realpath\(",
    r"(?i)\.\.\\",
    r"(?i)zipfile\.ZipFile\(|tarfile\.open\(",
    r"(?i)upload_tmp_dir|tmp_name",
    r"(?i)save_path\s*=",
    r"(?i)path\.join\([^,]+,\s*\.\.",
    r"(?i)filename\s*=\s*request\.",
    r"(?i)Content-Disposition:\s*filename=",
]
INSECURE_DESERIALIZATION_PATTERNS = [
    r"(?i)pickle\.load\s*\(",
    r"(?i)unserialize\s*\(",
    r"(?i)ObjectInputStream\s*\(",
    r"(?i)deserialize\s*\(",
    r"(?i)json\.parse\s*\(",
    r"(?i)XMLDecoder\s*\(",
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
BUFFER_OVERFLOW_PATTERNS = [
    r"(?i)strcpy\s*\(\s*\w+,\s*\w+\)",
    r"(?i)strcat\s*\(\s*\w+,\s*\w+\)",
    r"(?i)gets\s*\(",
    r"(?i)scanf\s*\(",
    r"(?i)memcpy\s*\(",
    r"(?i)fgets\s*\(",
    r"(?i)(malloc\s*\(|calloc\s*\()",
    r"(?i)stack_exec|mprotect\s*\(",
    r"(?i)memset\(.+0x00",
]
CSRF_PATTERNS = [
    r"(?i)document\.location\.href\s*=\s*['\"]\S+['\"]",
    r"(?i)form\s+action\s*=\s*['\"]\S+['\"]",
    r"(?i)window\.location\s*=\s*['\"]\S+['\"]",
    r"(?i)\$\('[^']+'\)\.submit\s*\(",
    r"(?i)post\s+method\s*=\s*['\"]\S+['\"]",
    r"(?i)input\s+type\s*=\s*['\"]hidden['\"]\s+name\s*=\s*['\"]csrf",
    r"(?i)X-CSRF-Token",
    r"(?i)SameSite=None",
    r"(?i)document\.forms\[[0-9]+\]\.submit",
    r"(?i)action\s*=\s*\"/external",
    r"(?i)autofill",
]
IMPROPER_AUTHENTICATION_PATTERNS = [
    r"(?i)session_id\s*=\s*['\"][a-zA-Z0-9]{32}['\"]",
    r"(?i)request\.cookies\s*\['session_id'\]",
    r"(?i)Authorization\s*:\s*['\"]Bearer\s+[A-Za-z0-9\-_]+['\"]",
    r"(?i)auth_token\s*=\s*['\"][A-Za-z0-9\-_]+['\"]",
    r"(?i)request\.headers\s*\['Authorization'\]",
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
INSECURE_API_PATTERNS = [
    r"(?i)/api/v[0-9]+/users",
    r"(?i)/api/v[0-9]+/admin",
    r"(?i)/api/v[0-9]+/token",
    r"(?i)/api/v[0-9]+/password",
    r"(?i)/api/v[0-9]+/login",
    r"(?i)/internal/|/private/|/debug/",
    r"(?i)swagger.json|api-docs|/v2/api-docs",
    r"(?i)X-Forwarded-For",
    r"(?i)introspect|.well-known/openid-configuration",
    r"(?i)graphql",
    r"(?i)rate_limit|throttle",
    r"(?i)Authorization\s*:\s*Bearer # token leakage in logs/header",
]
INSECURE_CRYPTOGRAPHIC_PATTERNS = [
    r"(?i)MD5\s*\(",
    r"(?i)SHA1\s*\(",
    r"(?i)base64\s*\(",
    r"(?i)plaintext\s*=\s*['\"][a-zA-Z0-9]+['\"]",
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
RACE_CONDITION_PATTERNS = [
    r"(?i)pthread_mutex_lock\s*\(",
    r"(?i)pthread_mutex_unlock\s*\(",
    r"(?i)fsync\s*\(",
    r"(?i)wait\s*\(",
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
PRIVILEGE_ESCALATION_PATTERNS = [
    r"(?i)sudo\s+",
    r"(?i)chmod\s+777\s+",
    r"(?i)chown\s+",
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
LANGUAGE_PATTERNS = {
    'python': SQL_INJECTION_PATTERNS + XSS_PATTERNS + COMMAND_INJECTION_PATTERNS + INSECURE_CRYPTOGRAPHIC_PATTERNS,
    'javascript': XSS_PATTERNS + COMMAND_INJECTION_PATTERNS + INSECURE_API_PATTERNS,
    'c': SQL_INJECTION_PATTERNS + COMMAND_INJECTION_PATTERNS + BUFFER_OVERFLOW_PATTERNS + PATH_TRAVERSAL_PATTERNS,
    'cpp': SQL_INJECTION_PATTERNS + COMMAND_INJECTION_PATTERNS + BUFFER_OVERFLOW_PATTERNS + PATH_TRAVERSAL_PATTERNS,
    'java': SQL_INJECTION_PATTERNS + INSECURE_DESERIALIZATION_PATTERNS + IMPROPER_AUTHENTICATION_PATTERNS,
    'shell': COMMAND_INJECTION_PATTERNS + PRIVILEGE_ESCALATION_PATTERNS,
}
DEFAULT_IGNORED_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', '.idea', '.gradle'}
def compile_patterns(pattern_list: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in pattern_list if isinstance(p, str)]
def remove_comments_and_strings_preserve_offsets(text: str, lang: str) -> str:
    chars = list(text)
    if lang == 'shell':
        # FIX #4: quoted # is not treated as comment
        pattern = re.compile(
            r"(\"(?:\\.|[^\"])*\")|('(?:\\.|[^'])*')|(^\s*#.*$)",
            re.MULTILINE
        )
    elif lang == 'python':
        pattern = re.compile(
            r"('''[\s\S]*?'''|\"\"\"[\s\S]*?\"\"\"|'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\"|#.*$)",
            re.MULTILINE
        )
    else:
        pattern = re.compile(
            r"('(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\"|//.*$|/\*[\s\S]*?\*/)",
            re.MULTILINE
        )
    for m in pattern.finditer(text):
        for i in range(m.start(), m.end()):
            if chars[i] != '\n':
                chars[i] = ' '
    return ''.join(chars)
def find_matches_in_text(text: str, compiled_patterns: List[re.Pattern], path: Path, lang: str):
    cleaned = remove_comments_and_strings_preserve_offsets(text, lang)
    # FIX #3: fast pre-check (performance only)
    if not any(k in cleaned.lower() for k in (
        'exec', 'select', 'insert', 'system', 'pickle',
        'yaml', 'marshal', 'strcpy', '../', 'chmod'
    )):
        return []
    lines = text.splitlines()
    offsets = []
    pos = 0
    for l in lines:
        offsets.append(pos)
        pos += len(l) + 1
    def offset_to_line(o):
        return bisect.bisect_right(offsets, o)
    results = []
    for pat in compiled_patterns:
        for m in pat.finditer(cleaned):
            line = offset_to_line(m.start())
            snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            results.append({
                "file": str(path),
                "line": line,
                "pattern": pat.pattern,
                "match_text": m.group(0)[:300],
                "snippet": snippet
            })
    return results
def detect_injections_in_file(path: Path, compiled_by_lang, min_size, max_size):
    try:
        size = path.stat().st_size
        if size < min_size or (max_size and size > max_size):
            return []
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return []
    lang = LANG_EXTENSIONS.get(path.suffix.lower())
    if not lang:
        return []
    return find_matches_in_text(text, compiled_by_lang.get(lang, []), path, lang)
def scan_directory(root: Path, threads: int, min_size: int, max_size: int):
    compiled_by_lang = {k: compile_patterns(v) for k, v in LANGUAGE_PATTERNS.items()}
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = []
        for p in root.rglob("*"):
            if p.is_file() and not any(d in p.parts for d in DEFAULT_IGNORED_DIRS):
                futures.append(ex.submit(detect_injections_in_file, p, compiled_by_lang, min_size, max_size))
        for f in concurrent.futures.as_completed(futures):
            results.extend(f.result())
    seen = set()
    uniq = []
    for r in results:
        k = (r['file'], r['line'], r['pattern'], r['snippet'])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--min-size", type=int, default=0)
    ap.add_argument("--max-size", type=int, default=5_000_000)
    ap.add_argument("--output", default="vulnerabilities_report.json")
    args = ap.parse_args()
    issues = scan_directory(Path(args.directory), args.threads, args.min_size, args.max_size)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(issues, f, indent=2)
    print(f"Scan complete. Findings: {len(issues)}")
if __name__ == "__main__":
    main()
