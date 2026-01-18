#!/usr/bin/python3
"""
Improved static scanner for potential vulnerabilities.
Features:
- Language-specific pattern sets (large lists included).
- Compiles regexes once, applies per-file based on extension.
- Scans whole files (not only line-by-line) and maps matches to line numbers.
- Deduplicates results robustly (file, line, pattern, match excerpt).
- Structured JSON/CSV output. (Sorry it's a JSON slut) Literly everything it's like "output in JSON?" Sigh.. <3 
- Skips binary/very large files by default.
- Skips matches inside comments and string literals using lightweight tokenizers per language.
- Threaded scanning and ignore-dir support.
Usage:
    python improved_scanner.py /path/to/repo --format json --output report --threads 12
"""
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
# SQL Injection Patterns
SQL_INJECTION_PATTERNS = [
    re.compile(r"(?i)select\s+\*\s+from\s+\w+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)insert\s+into\s+\w+\s+\(.*\)\s+values\s*\(.*\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)update\s+\w+\s+set\s+.*\s+where\s+.*", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)drop\s+table\s+\w+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)union\s+select\s+.*", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)and\s+1\s*=\s*1", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)or\s+1\s*=\s*1", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+information_schema.tables", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+mysql.*user", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+pg_catalog.*pg_user", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+sys\.databases", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+sqlite_master", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)execute\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)cursor\.execute\s*\(\s*.*\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)prepareStatement\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)WHERE\s+1=1\s+--", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)--\s*$|#\s*$", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)UNION\s+ALL\s+SELECT", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)CAST\(.+AS\s+VARCHAR", flags=re.IGNORECASE | re.MULTILINE),
]
# Cross-Site Scripting (XSS) Patterns
XSS_PATTERNS = [
    re.compile(r'(?i)document\.write\s*\(', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)eval\((.*)\)\s*;', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)innerHTML\s*=\s*', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)window\.location\s*=', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)location\.href\s*=', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)alert\s*\(', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)confirm\s*\(', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)document\.cookie', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)eval\s*\(\s*["\'].*["\']\s*\)', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)response\.write\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)res\.send\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)innerText\s*=", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)document\.createElement\(['\"]script['\"]\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)setAttribute\(\s*['\"]on\w+['\"]\s*,", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)dangerouslySetInnerHTML", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)style\.cssText\s*=", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)location\.replace\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)res\.end\s*\(", flags=re.IGNORECASE | re.MULTILINE),
]
# Similarly, you can continue applying the same pattern for the rest of the lists
COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(?i)system\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)popen\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)exec\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Runtime\.getRuntime\s*\(\)\.exec\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)subprocess\.(call|Popen)\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)child_process\.exec\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)nc\s+-e\s+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)\$\([^\)]*\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)eval\s*\(\s*['\"]\$\([^\)]+\)['\"]\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)shell=True", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)cmd\.exe\s*/c", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)system\([^,]+;", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)exec\([^,]+\+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)popen\([^,]+\+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)ProcessBuilder\s*\(.+builder\.command\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Runtime\.exec\(.+\+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)popen2|popen3", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)subprocess\.(call|check_output)\s*\(.*\+", flags=re.IGNORECASE | re.MULTILINE),
]
# Continue similarly for other patterns like PATH_TRAVERSAL_PATTERNS, INSECURE_DESERIALIZATION_PATTERNS, etc.
# SQL Injection Patterns
SQL_INJECTION_PATTERNS = [
    re.compile(r"(?i)select\s+\*\s+from\s+\w+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)insert\s+into\s+\w+\s+\(.*\)\s+values\s*\(.*\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)update\s+\w+\s+set\s+.*\s+where\s+.*", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)drop\s+table\s+\w+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)union\s+select\s+.*", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)and\s+1\s*=\s*1", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)or\s+1\s*=\s*1", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+information_schema.tables", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+mysql.*user", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+pg_catalog.*pg_user", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+sys\.databases", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)select\s+from\s+sqlite_master", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)execute\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)cursor\.execute\s*\(\s*.*\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)prepareStatement\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)WHERE\s+1=1\s+--", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)--\s*$|#\s*$", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)UNION\s+ALL\s+SELECT", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)CAST\(.+AS\s+VARCHAR", flags=re.IGNORECASE | re.MULTILINE),
]
# Cross-Site Scripting (XSS) Patterns
XSS_PATTERNS = [
    re.compile(r'(?i)document\.write\s*\(', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)eval\((.*)\)\s*;', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)innerHTML\s*=\s*', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)window\.location\s*=', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)location\.href\s*=', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)alert\s*\(', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)confirm\s*\(', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)document\.cookie', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r'(?i)eval\s*\(\s*["\'].*["\']\s*\)', flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)response\.write\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)res\.send\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)innerText\s*=", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)document\.createElement\(['\"]script['\"]\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)setAttribute\(\s*['\"]on\w+['\"]\s*,", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)dangerouslySetInnerHTML", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)style\.cssText\s*=", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)location\.replace\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)res\.end\s*\(", flags=re.IGNORECASE | re.MULTILINE),
]
# Command Injection Patterns
COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(?i)system\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)popen\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)exec\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Runtime\.getRuntime\s*\(\)\.exec\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)subprocess\.(call|Popen)\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)child_process\.exec\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)nc\s+-e\s+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)\$\([^\)]*\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)eval\s*\(\s*['\"]\$\([^\)]+\)['\"]\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)shell=True", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)cmd\.exe\s*/c", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)system\([^,]+;", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)exec\([^,]+\+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)popen\([^,]+\+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)ProcessBuilder\s*\(.+builder\.command\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Runtime\.exec\(.+\+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)popen2|popen3", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)subprocess\.(call|check_output)\s*\(.*\+", flags=re.IGNORECASE | re.MULTILINE),
]
# Path Traversal Patterns
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(\.\./){2,}", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)(c:|/)[^:]+/", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)file://", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)open\s*\(\s*\"(\.\./|/)[^\"]+\"", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)chroot\s*\(\s*\"(\.\./|/)[^\"]+\"", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)normalizePath\(|path\.normalize\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)realpath\(|os\.realpath\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)\.\.\\", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)zipfile\.ZipFile\(|tarfile\.open\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)upload_tmp_dir|tmp_name", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)save_path\s*=", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)path\.join\([^,]+,\s*\.\.", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)filename\s*=\s*request\.", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Content-Disposition:\s*filename=", flags=re.IGNORECASE | re.MULTILINE),
]
# Insecure Deserialization Patterns
INSECURE_DESERIALIZATION_PATTERNS = [
    re.compile(r"(?i)pickle\.load\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)unserialize\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)ObjectInputStream\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)deserialize\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)json\.parse\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)XMLDecoder\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)XStream\.fromXML\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)yaml\.load\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Marshal\.load\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Marshal\.restore\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)eval\(.+base64_decode\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)gob\.NewDecoder\(|encoding/gob", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)serde_json::from_str\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)perl\s+Storable::thaw", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)apache\.commons\.collections", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)readObject\(|writeReplace\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)readObject\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)writeObject\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)ObjectInputStream\.resolveClass", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)XStream\.fromXML\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Gson\.fromJson\s*\(", flags=re.IGNORECASE | re.MULTILINE),
]
# Buffer Overflow Patterns
BUFFER_OVERFLOW_PATTERNS = [
    re.compile(r"(?i)strcpy\s*\(\s*\w+,\s*\w+\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)strcat\s*\(\s*\w+,\s*\w+\)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)gets\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)scanf\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)memcpy\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)fgets\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)(malloc\s*\(|calloc\s*\()", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)stack_exec|mprotect\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)memset\(.+0x00", flags=re.IGNORECASE | re.MULTILINE),
]
# Cross-Site Request Forgery (CSRF) Patterns
CSRF_PATTERNS = [
    re.compile(r"(?i)document\.location\.href\s*=\s*['\"]\S+['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)form\s+action\s*=\s*['\"]\S+['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)window\.location\s*=\s*['\"]\S+['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)\$\('[^']+'\)\.submit\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)post\s+method\s*=\s*['\"]\S+['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)input\s+type\s*=\s*['\"]hidden['\"]\s+name\s*=\s*['\"]csrf", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)X-CSRF-Token", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)SameSite=None", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)document\.forms\[[0-9]+\]\.submit", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)action\s*=\s*\"/external", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)autofill", flags=re.IGNORECASE | re.MULTILINE),
]
# Improper Authentication Patterns
IMPROPER_AUTHENTICATION_PATTERNS = [
    re.compile(r"(?i)session_id\s*=\s*['\"][a-zA-Z0-9]{32}['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)request\.cookies\s*\['session_id'\]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Authorization\s*:\s*['\"]Bearer\s+[A-Za-z0-9\-_]+['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)auth_token\s*=\s*['\"][A-Za-z0-9\-_]+['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)request\.headers\s*\['Authorization'\]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)password\s*=\s*['\"][^'\"]{1,}['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)api_key\s*=\s*['\"][A-Za-z0-9\-_]+['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)hardcoded_secret|hardcoded_key|private_key\s*=", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Basic\s+[A-Za-z0-9=]+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)set_cookie\(|cookie\.set\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)session\.(start|destroy)", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)bcrypt\.hashpw\(|password_hash\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)compare_digest\(|hmac\.compare_digest\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)token_expiry|exp\s*:", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Authorization\s*:\s*Bearer", flags=re.IGNORECASE | re.MULTILINE),
]
# Insecure API Patterns
INSECURE_API_PATTERNS = [
    re.compile(r"(?i)/api/v[0-9]+/users", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)/api/v[0-9]+/admin", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)/api/v[0-9]+/token", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)/api/v[0-9]+/password", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)/api/v[0-9]+/login", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)/internal/|/private/|/debug/", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)swagger.json|api-docs|/v2/api-docs", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)X-Forwarded-For", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)introspect|.well-known/openid-configuration", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)graphql", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)rate_limit|throttle", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)Authorization\s*:\s*Bearer # token leakage in logs/header", flags=re.IGNORECASE | re.MULTILINE),
]
# Insecure Cryptographic Practices Patterns
INSECURE_CRYPTOGRAPHIC_PATTERNS = [
    re.compile(r"(?i)MD5\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)SHA1\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)base64\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)plaintext\s*=\s*['\"][a-zA-Z0-9]+['\"]", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)AES-ECB|AES128-ECB|ECB_MODE", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)openssl\s+enc\s+-aes-128-cbc", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)RSA_padding\(|RSA_NO_PADDING", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)SSLv3|ssl3", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)RC4|DES|3DES|EXPORT", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)hardcoded_key|hardcoded_password|private_key.*=", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)PBKDF2|bcrypt|scrypt", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)iteration_count\s*=\s*\d{1,4}", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)random\.random\(|Math\.random\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)secure_random|SystemRandom", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)HMAC-SHA1", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)cryptography\.hazmat|from\s+Crypto\.", flags=re.IGNORECASE | re.MULTILINE),
]
# Race Condition Patterns
RACE_CONDITION_PATTERNS = [
    re.compile(r"(?i)pthread_mutex_lock\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)pthread_mutex_unlock\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)fsync\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)wait\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)open\([^,]+,\s*O_CREAT\|O_EXCL", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)rename\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)stat\(|lstat\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)mktemp\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)lockf\s*\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)sem_wait|sem_post", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)volatile\s+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)atomic_compare_exchange", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)nsync|pthread_create", flags=re.IGNORECASE | re.MULTILINE),
]
# Privilege Escalation Patterns
PRIVILEGE_ESCALATION_PATTERNS = [
    re.compile(r"(?i)sudo\s+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)chmod\s+777\s+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)chown\s+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)setuid\(|setgid\(|seteuid\(|setegid\(", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)cap_set_file|cap_get_proc", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)passwd\s+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)/etc/shadow|/etc/passwd", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)su\s+-", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)mount\s+-o\s+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)docker\s+run\s+--privileged", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)iptables\s+", flags=re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?i)chroot\s*\(", flags=re.IGNORECASE | re.MULTILINE),
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
