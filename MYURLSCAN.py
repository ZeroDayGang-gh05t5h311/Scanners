#!/usr/bin/env python3
"""
Safe Reflection / Command-Injection Candidate Scanner (standard-library-only, extended)
Author: ChatGPT (GPT-5 Thinking mini)
Purpose: Find reflected markers in URLs, forms, headers, and discovered resources.
Extended with:
 - result saving to CSV or plaintext via --output <filename>
 - more encodings (UTF-7, UTF-16LE/BE percent-encoded, HTML entities, hex-escape)
 - targeted non-destructive payload templates to probe filtering / separators
 - ADDED: improved error handling & retries, more payload templates (still non-destructive),
          proxy support, and simple authentication handling (basic auth + cookie header)

Legal: Only run against targets you own or have explicit written permission to test.

Usage:
    python safe_injection_scanner_stdlib_extended.py [--output results.csv] [--proxy http://127.0.0.1:8080]
        [--auth-basic user:pass] [--cookies "k=v; ..."] https://example.com/page1 ...
"""
#am sharing and maintaining
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode, quote_plus, quote, quote_from_bytes
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import json
import random
import string
import time
import sys
import io
import argparse
import csv
import html
import base64
import traceback

# --- Configuration ---
CONCURRENCY = 8
REQUEST_TIMEOUT = 15  # seconds for urlopen (socket timeout)
RATE_LIMIT_DELAY = 0.15  # delay between requests per worker (politeness)
HEADER_KEYS_TO_TEST = ["User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP"]
DEFAULT_HEADERS = {
    "User-Agent": "SafeScannerStdLib/1.0",
    "Accept": "*/*",
}

# New globals for proxy/auth/cookie support (set via CLI)
GLOBAL_PROXY = None            # e.g. "http://127.0.0.1:8080"
GLOBAL_BASIC_AUTH_HEADER = None  # "Basic <base64>"
GLOBAL_COOKIE_HEADER = None     # "k=v; k2=v2"

# Error logging
ERROR_LOGFILE = "scanner_errors.log"
MAX_RETRIES = 2  # number of retries for transient errors

_lock_print = threading.Lock()

def safe_print(*a, **k):
    with _lock_print:
        print(*a, **k)

def log_error(msg):
    # append error details to ERROR_LOGFILE with timestamp
    try:
        with open(ERROR_LOGFILE, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")
    except Exception:
        pass

def make_marker():
    rnd = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"INJ-{rnd}"

# --- Extra encodings ---
def percent_encode_bytes(b):
    return ''.join('%{:02X}'.format(x) for x in b)

def enc_plain(m):
    return m

def enc_url_quote(m):
    return quote(m, safe='')

def enc_quote_plus(m):
    return quote_plus(m)

def enc_space_percent20(m):
    return m.replace(" ", "%20")

def enc_percent_prefix(m):
    return "%25" + quote(m, safe='')

def enc_utf7_percent(m):
    # produce UTF-7 bytes then percent-encode each byte
    try:
        b = m.encode('utf-7')
    except Exception:
        b = m.encode('utf-8', errors='replace')
    return percent_encode_bytes(b)

def enc_utf16le_percent(m):
    try:
        b = m.encode('utf-16le')
    except Exception:
        b = m.encode('utf-8', errors='replace')
    return percent_encode_bytes(b)

def enc_utf16be_percent(m):
    try:
        b = m.encode('utf-16be')
    except Exception:
        b = m.encode('utf-8', errors='replace')
    return percent_encode_bytes(b)

def enc_html_entities(m):
    # replace special chars with HTML entities
    return html.escape(m)

def enc_hex_escape(m):
    # \xNN style hex escape for ASCII bytes (useful for some interpreters)
    b = m.encode('utf-8', errors='replace')
    return ''.join('\\x{:02x}'.format(x) for x in b)

def enc_double_percent(m):
    # percent-encode then percent-encode the percent signs (double-encoding)
    first = quote(m, safe='')
    return quote(first, safe='')

# New encoding variants list (keeps all prior plus new ones)
ENCODING_VARIANTS = [
    enc_plain,
    enc_url_quote,
    enc_quote_plus,
    enc_space_percent20,
    enc_percent_prefix,
    enc_utf7_percent,
    enc_utf16le_percent,
    enc_utf16be_percent,
    enc_html_entities,
    enc_hex_escape,
    enc_double_percent,
]

# --- Targeted non-destructive payload templates (extended) ---
# Use {m} where the marker should be inserted.
# These do not contain time-based or destructive commands.
TARGETED_PAYLOAD_TEMPLATES = [
    "{m};",          # trailing command separator character
    "{m}|",          # pipe separator
    "{m}&&",         # logical-and separator
    ";{m};",         # surrounded separators
    "'{m}'",         # single-quoted
    "\"{m}\"",       # double-quoted
    "({m})",         # parenthesized
    "${{ {m} }}",    # templating-like pattern
    "{{{m}}}",       # mustache-like
    "\\`{m}\\`",     # backticks escaped (non-executing literal)
    "{m}%20;",       # encoded space + semicolon
    "{m}%0A",        # newline encoded (often filtered)
    "%0d%0a{m}",     # CRLF around the marker
    "{m}/",          # path-separator adjacent
    "{m}&&true",     # non-destructive append (no external commands; 'true' as text)
    "pre{m}post",    # surrounding text
    # Extended templates (still non-destructive):
    "{m}%00",        # null-byte encoded (often filtered/stripped)
    "%00{m}",        # leading null encoded
    "../{m}",        # path-traversal contextual marker
    "..%2F{m}",      # encoded path traversal
    "/..\\{m}",      # mixed separators
    "/*{m}*/",       # C-style comment wrapper
    "-- {m}",        # SQL-line-comment style, only for detection of filtering behavior
    "#{m}",          # shell-comment style (as text)
    "{m}%2F%2F",     # double slash sequence encoded
    "{m}%3B{m}",     # semicolon between markers encoded
]

# --- HTML Parsing (forms + resource URLs) ---
class FormAndResourceParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms = []  # list of {action, method, inputs: {name: value}}
        self._current_form = None
        self.resource_urls = set()

    def handle_starttag(self, tag, attrs):
        attrsd = dict(attrs)
        # Resources
        if tag == "script" and "src" in attrsd:
            self.resource_urls.add(urljoin(self.base_url, attrsd["src"]))
        elif tag == "img" and "src" in attrsd:
            self.resource_urls.add(urljoin(self.base_url, attrsd["src"]))
        elif tag == "iframe" and "src" in attrsd:
            self.resource_urls.add(urljoin(self.base_url, attrsd["src"]))
        elif tag == "link" and "href" in attrsd:
            self.resource_urls.add(urljoin(self.base_url, attrsd["href"]))

        # Forms
        if tag == "form":
            action = attrsd.get("action", "")
            method = attrsd.get("method", "get").lower()
            action = urljoin(self.base_url, action)
            self._current_form = {"action": action, "method": method, "inputs": {}}
            self.forms.append(self._current_form)
        elif self._current_form is not None and tag in ("input", "textarea", "select"):
            name = attrsd.get("name")
            if not name:
                return
            value = attrsd.get("value", "")
            # for select, we can't know which option; keep default empty or value
            self._current_form["inputs"][name] = value

# --- HTTP utilities (using urllib only) ---
def build_opener_with_cookies_and_proxy(proxy=None):
    # default opener that follows redirects, supports cookies and optional proxy
    handlers = [HTTPCookieProcessor(), HTTPRedirectHandler()]
    if proxy:
        handlers.append(ProxyHandler({"http": proxy, "https": proxy}))
    return build_opener(*handlers)

def fetch_url(url, method="GET", data=None, headers=None, timeout=REQUEST_TIMEOUT):
    """
    Perform a request and return (final_url, status_code, headers_dict, body_text)
    Implements retries for transient errors and richer logging.
    Non-fatal exceptions return None and print an error.
    """
    last_exc = None
    for attempt in range(0, MAX_RETRIES + 1):
        opener = build_opener_with_cookies_and_proxy(GLOBAL_PROXY)
        hdrs = DEFAULT_HEADERS.copy()
        if headers:
            hdrs.update(headers)
        # apply global cookie/header/auth options
        if GLOBAL_COOKIE_HEADER:
            hdrs["Cookie"] = GLOBAL_COOKIE_HEADER
        if GLOBAL_BASIC_AUTH_HEADER:
            hdrs["Authorization"] = GLOBAL_BASIC_AUTH_HEADER
        req = Request(url, data=(urlencode_dict_to_bytes(data) if data and method.upper() == "POST" else None), headers=hdrs, method=method.upper())
        try:
            with opener.open(req, timeout=timeout) as resp:
                final = resp.geturl()
                code = resp.getcode()
                hdict = {}
                for k, v in resp.info().items():
                    hdict[k] = v
                body = resp.read()
                try:
                    text = body.decode("utf-8", errors="replace")
                except Exception:
                    try:
                        text = body.decode("latin-1", errors="replace")
                    except Exception:
                        text = str(body)
                return final, code, hdict, text
        except HTTPError as e:
            # HTTPError is often not transient; capture body and return
            try:
                body = e.read()
                try:
                    text = body.decode("utf-8", errors="replace")
                except Exception:
                    text = body.decode("latin-1", errors="replace")
            except Exception:
                text = ""
            safe_print(f"[!] HTTPError for {url}: {getattr(e,'code', 'N/A')} {getattr(e,'reason', '')}")
            # log full traceback to error log
            tb = traceback.format_exc()
            log_error(f"HTTPError {url} attempt {attempt}: {tb}")
            return (e.geturl() if hasattr(e, "geturl") else url, getattr(e, "code", None), dict(e.headers if hasattr(e, "headers") else {}), text)
        except URLError as e:
            # URLError may be transient; retry a few times with backoff
            last_exc = e
            safe_print(f"[!] URLError for {url}: {getattr(e, 'reason', e)} (attempt {attempt})")
            tb = traceback.format_exc()
            log_error(f"URLError {url} attempt {attempt}: {tb}")
            if attempt < MAX_RETRIES:
                time.sleep(1 + attempt * 1.5)
                continue
            return None
        except Exception as e:
            last_exc = e
            safe_print(f"[!] Exception fetching {url}: {e} (attempt {attempt})")
            tb = traceback.format_exc()
            log_error(f"Exception {url} attempt {attempt}: {tb}")
            if attempt < MAX_RETRIES:
                time.sleep(1 + attempt * 1.5)
                continue
            return None
    # if we fell through
    if last_exc:
        log_error(f"Failed to fetch {url} after retries: {last_exc}")
    return None

def urlencode_dict_to_bytes(d):
    try:
        return urlencode(d).encode("utf-8")
    except Exception:
        items = []
        for k, v in (d.items() if isinstance(d, dict) else []):
            items.append(f"{quote_plus(str(k))}={quote_plus(str(v))}")
        return "&".join(items).encode("utf-8")

# --- Scanner class ---
class SafeScannerStdlib:
    def __init__(self, targets, concurrency=CONCURRENCY, output_file=None):
        self.targets = targets
        self.results = []
        self.executor = ThreadPoolExecutor(max_workers=concurrency)
        self.rate_limit = RATE_LIMIT_DELAY
        self.lock = threading.Lock()
        self.output_file = output_file

    def scan_all(self):
        futures = []
        for t in self.targets:
            futures.append(self.executor.submit(self.scan_target, t))
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                safe_print(f"[!] Exception in worker: {e}")
                log_error(traceback.format_exc())
        self.executor.shutdown(wait=True)
        # after run, optionally save results
        if self.output_file:
            try:
                self.save_results(self.output_file)
            except Exception as e:
                safe_print(f"[!] Failed to save results to {self.output_file}: {e}")
                log_error(traceback.format_exc())

    def scan_target(self, target):
        parsed_target = urlparse(target)
        if not parsed_target.scheme:
            safe_print(f"[!] Invalid URL (missing scheme): {target}")
            return
        safe_print(f"[+] Scanning: {target}")
        self._sleep_rate()
        initial = fetch_url(target)
        if not initial:
            safe_print(f"[!] Failed initial fetch for {target}")
            return
        final_url, status, headers, body = initial
        parser = FormAndResourceParser(final_url)
        try:
            parser.feed(body)
        except Exception:
            # log parser errors but continue
            log_error(f"HTML parser error for {target}:\n" + traceback.format_exc())
        forms = parser.forms
        resources = parser.resource_urls

        qparams = parse_qs(parsed_target.query, keep_blank_values=True)
        if qparams:
            self.test_query_params(target, parsed_target, qparams, body)

        for form in forms:
            self.test_form(form)

        self.test_headers(final_url)

        for r in resources:
            self.test_resource_url(r)

        safe_print(f"[+] Finished scanning: {target}")

    def _record_finding(self, entry):
        with self.lock:
            self.results.append(entry)

    def _sleep_rate(self):
        time.sleep(self.rate_limit)

    def test_query_params(self, original_target, parsed_url, params, original_body):
        for pname in list(params.keys()):
            marker = make_marker()
            # First, baseline checks with encoding variants
            for enc in ENCODING_VARIANTS:
                candidate = enc(marker)
                new_qs = {k: (v[:] if isinstance(v, list) else [v]) for k, v in params.items()}
                new_qs[pname] = [candidate]
                parsed = parsed_url._replace(query=urlencode({k: v[0] for k, v in new_qs.items()}))
                new_url = urlunparse(parsed)
                context = f"query param '{pname}' on {original_target}"
                self._sleep_rate()
                res = fetch_url(new_url)
                if not res:
                    continue
                final, code, resp_headers, text = res
                findings = []
                if marker in text:
                    findings.append(("body", "marker_reflected"))
                for hk, hv in resp_headers.items():
                    if marker in hv:
                        findings.append((f"response-header:{hk}", "marker_reflected"))
                if marker in final:
                    findings.append(("final_url", "marker_present"))
                if code and (code >= 500 or code == 403):
                    findings.append(("status", str(code)))
                if findings:
                    entry = {
                        "timestamp": time.time(),
                        "context": context,
                        "tested_url": new_url,
                        "method": "GET",
                        "headers_sent": {},
                        "data_sent_keys": None,
                        "status": code,
                        "final_url": final,
                        "findings": findings,
                    }
                    safe_print(f"[!] Candidate reflection found: {context} -> {new_url} ; findings: {findings}")
                    self._record_finding(entry)

            # Then targeted payload templates (marker inserted into templates, with encoding variants applied)
            for tpl in TARGETED_PAYLOAD_TEMPLATES:
                tpl_raw = tpl.replace("{m}", marker)
                for enc in ENCODING_VARIANTS:
                    candidate = enc(tpl_raw)
                    new_qs = {k: (v[:] if isinstance(v, list) else [v]) for k, v in params.items()}
                    new_qs[pname] = [candidate]
                    parsed = parsed_url._replace(query=urlencode({k: v[0] for k, v in new_qs.items()}))
                    new_url = urlunparse(parsed)
                    context = f"targeted tpl param '{pname}' on {original_target} tpl='{tpl}'"
                    self._sleep_rate()
                    res = fetch_url(new_url)
                    if not res:
                        continue
                    final, code, resp_headers, text = res
                    findings = []
                    if marker in text:
                        findings.append(("body", "marker_reflected"))
                    for hk, hv in resp_headers.items():
                        if marker in hv:
                            findings.append((f"response-header:{hk}", "marker_reflected"))
                    if marker in final:
                        findings.append(("final_url", "marker_present"))
                    if code and (code >= 500 or code == 403):
                        findings.append(("status", str(code)))
                    if findings:
                        entry = {
                            "timestamp": time.time(),
                            "context": context,
                            "tested_url": new_url,
                            "method": "GET",
                            "headers_sent": {},
                            "data_sent_keys": None,
                            "status": code,
                            "final_url": final,
                            "findings": findings,
                        }
                        safe_print(f"[!] Candidate reflection found: {context} -> {new_url} ; findings: {findings}")
                        self._record_finding(entry)

    def test_form(self, form):
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", {})
        if not inputs:
            return
        for field in list(inputs.keys()):
            marker = make_marker()
            # baseline encodings
            for enc in ENCODING_VARIANTS:
                candidate = enc(marker)
                payload = {k: (candidate if k == field else v) for k, v in inputs.items()}
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                context = f"form {method.upper()} field '{field}' -> {action}"
                self._sleep_rate()
                if method == "get":
                    parsed = urlparse(action)
                    parsed = parsed._replace(query=urlencode(payload))
                    url_with_q = urlunparse(parsed)
                    res = fetch_url(url_with_q, method="GET")
                    if not res:
                        continue
                    final, code, resp_headers, text = res
                    findings = []
                    if marker in text:
                        findings.append(("body", "marker_reflected"))
                    for hk, hv in resp_headers.items():
                        if marker in hv:
                            findings.append((f"response-header:{hk}", "marker_reflected"))
                    if marker in final:
                        findings.append(("final_url", "marker_present"))
                    if code and (code >= 500 or code == 403):
                        findings.append(("status", str(code)))
                    if findings:
                        entry = {
                            "timestamp": time.time(),
                            "context": context,
                            "tested_url": url_with_q,
                            "method": "GET",
                            "headers_sent": headers,
                            "data_sent_keys": list(payload.keys()),
                            "status": code,
                            "final_url": final,
                            "findings": findings,
                        }
                        safe_print(f"[!] Candidate reflection found: {context} -> {url_with_q} ; findings: {findings}")
                        self._record_finding(entry)
                else:
                    res = fetch_url(action, method="POST", data=payload, headers=headers)
                    if not res:
                        continue
                    final, code, resp_headers, text = res
                    findings = []
                    if marker in text:
                        findings.append(("body", "marker_reflected"))
                    for hk, hv in resp_headers.items():
                        if marker in hv:
                            findings.append((f"response-header:{hk}", "marker_reflected"))
                    if marker in final:
                        findings.append(("final_url", "marker_present"))
                    if code and (code >= 500 or code == 403):
                        findings.append(("status", str(code)))
                    if findings:
                        entry = {
                            "timestamp": time.time(),
                            "context": context,
                            "tested_url": action,
                            "method": "POST",
                            "headers_sent": headers,
                            "data_sent_keys": list(payload.keys()),
                            "status": code,
                            "final_url": final,
                            "findings": findings,
                        }
                        safe_print(f"[!] Candidate reflection found: {context} -> {action} ; findings: {findings}")
                        self._record_finding(entry)

            # targeted templates for forms
            for tpl in TARGETED_PAYLOAD_TEMPLATES:
                tpl_raw = tpl.replace("{m}", marker)
                for enc in ENCODING_VARIANTS:
                    candidate = enc(tpl_raw)
                    payload = {k: (candidate if k == field else v) for k, v in inputs.items()}
                    headers = {"Content-Type": "application/x-www-form-urlencoded"}
                    context = f"form {method.upper()} targeted field '{field}' tpl='{tpl}' -> {action}"
                    self._sleep_rate()
                    if method == "get":
                        parsed = urlparse(action)
                        parsed = parsed._replace(query=urlencode(payload))
                        url_with_q = urlunparse(parsed)
                        res = fetch_url(url_with_q, method="GET")
                        if not res:
                            continue
                        final, code, resp_headers, text = res
                        findings = []
                        if marker in text:
                            findings.append(("body", "marker_reflected"))
                        for hk, hv in resp_headers.items():
                            if marker in hv:
                                findings.append((f"response-header:{hk}", "marker_reflected"))
                        if marker in final:
                            findings.append(("final_url", "marker_present"))
                        if code and (code >= 500 or code == 403):
                            findings.append(("status", str(code)))
                        if findings:
                            entry = {
                                "timestamp": time.time(),
                                "context": context,
                                "tested_url": url_with_q,
                                "method": "GET",
                                "headers_sent": headers,
                                "data_sent_keys": list(payload.keys()),
                                "status": code,
                                "final_url": final,
                                "findings": findings,
                            }
                            safe_print(f"[!] Candidate reflection found: {context} -> {url_with_q} ; findings: {findings}")
                            self._record_finding(entry)
                    else:
                        res = fetch_url(action, method="POST", data=payload, headers=headers)
                        if not res:
                            continue
                        final, code, resp_headers, text = res
                        findings = []
                        if marker in text:
                            findings.append(("body", "marker_reflected"))
                        for hk, hv in resp_headers.items():
                            if marker in hv:
                                findings.append((f"response-header:{hk}", "marker_reflected"))
                        if marker in final:
                            findings.append(("final_url", "marker_present"))
                        if code and (code >= 500 or code == 403):
                            findings.append(("status", str(code)))
                        if findings:
                            entry = {
                                "timestamp": time.time(),
                                "context": context,
                                "tested_url": action,
                                "method": "POST",
                                "headers_sent": headers,
                                "data_sent_keys": list(payload.keys()),
                                "status": code,
                                "final_url": final,
                                "findings": findings,
                            }
                            safe_print(f"[!] Candidate reflection found: {context} -> {action} ; findings: {findings}")
                            self._record_finding(entry)

    def test_headers(self, url):
        for header in HEADER_KEYS_TO_TEST:
            marker = make_marker()
            for enc in ENCODING_VARIANTS:
                value = enc(marker)
                hdrs = {header: value}
                context = f"header '{header}'"
                self._sleep_rate()
                res = fetch_url(url, method="GET", headers=hdrs)
                if not res:
                    continue
                final, code, resp_headers, text = res
                findings = []
                if marker in text:
                    findings.append(("body", "marker_reflected"))
                for hk, hv in resp_headers.items():
                    if marker in hv:
                        findings.append((f"response-header:{hk}", "marker_reflected"))
                if marker in final:
                    findings.append(("final_url", "marker_present"))
                if code and (code >= 500 or code == 403):
                    findings.append(("status", str(code)))
                if findings:
                    entry = {
                        "timestamp": time.time(),
                        "context": context,
                        "tested_url": url,
                        "method": "GET",
                        "headers_sent": hdrs,
                        "data_sent_keys": None,
                        "status": code,
                        "final_url": final,
                        "findings": findings,
                    }
                    safe_print(f"[!] Candidate reflection found: {context} -> {url} ; findings: {findings}")
                    self._record_finding(entry)
            # targeted templates for headers
            for tpl in TARGETED_PAYLOAD_TEMPLATES:
                tpl_raw = tpl.replace("{m}", marker)
                for enc in ENCODING_VARIANTS:
                    value = enc(tpl_raw)
                    hdrs = {header: value}
                    context = f"header-targeted '{header}' tpl='{tpl}'"
                    self._sleep_rate()
                    res = fetch_url(url, method="GET", headers=hdrs)
                    if not res:
                        continue
                    final, code, resp_headers, text = res
                    findings = []
                    if marker in text:
                        findings.append(("body", "marker_reflected"))
                    for hk, hv in resp_headers.items():
                        if marker in hv:
                            findings.append((f"response-header:{hk}", "marker_reflected"))
                    if marker in final:
                        findings.append(("final_url", "marker_present"))
                    if code and (code >= 500 or code == 403):
                        findings.append(("status", str(code)))
                    if findings:
                        entry = {
                            "timestamp": time.time(),
                            "context": context,
                            "tested_url": url,
                            "method": "GET",
                            "headers_sent": hdrs,
                            "data_sent_keys": None,
                            "status": code,
                            "final_url": final,
                            "findings": findings,
                        }
                        safe_print(f"[!] Candidate reflection found: {context} -> {url} ; findings: {findings}")
                        self._record_finding(entry)

    def test_resource_url(self, resource_url):
        parsed = urlparse(resource_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return
        self.test_query_params(resource_url, parsed, qs, "")

    def save_results(self, filename):
        if filename.lower().endswith(".csv"):
            # write CSV with columns: timestamp,context,tested_url,method,status,final_url,headers_sent,data_keys,findings
            with open(filename, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["timestamp", "context", "tested_url", "method", "status", "final_url", "headers_sent", "data_keys", "findings"])
                for r in self.results:
                    writer.writerow([
                        r.get("timestamp"),
                        r.get("context"),
                        r.get("tested_url"),
                        r.get("method"),
                        r.get("status"),
                        r.get("final_url"),
                        json.dumps(r.get("headers_sent", {}), ensure_ascii=False),
                        json.dumps(r.get("data_sent_keys", []), ensure_ascii=False),
                        json.dumps(r.get("findings", []), ensure_ascii=False),
                    ])
            safe_print(f"[+] Results saved to CSV: {filename}")
        else:
            # plain text output (human readable)
            with open(filename, "w", encoding="utf-8") as fh:
                if not self.results:
                    fh.write("No candidate reflections found.\n")
                else:
                    fh.write(f"Found {len(self.results)} candidate reflection(s)\n\n")
                    for r in self.results:
                        fh.write("=== ENTRY ===\n")
                        fh.write(json.dumps(r, indent=2, ensure_ascii=False))
                        fh.write("\n\n")
            safe_print(f"[+] Results saved to text file: {filename}")

# --- CLI / main ---
def main(argv):
    global GLOBAL_PROXY, GLOBAL_BASIC_AUTH_HEADER, GLOBAL_COOKIE_HEADER
    parser = argparse.ArgumentParser(description="Safe Reflection / Command-Injection Candidate Scanner (stdlib-only, extended)")
    parser.add_argument("targets", nargs="+", help="Target URL(s) to scan (must include scheme: https:// or http://)")
    parser.add_argument("--output", "-o", help="Optional output filename (.csv for CSV, otherwise plain text)", default=None)
    parser.add_argument("--proxy", help="Optional proxy URL (e.g. http://127.0.0.1:8080) to route requests through", default=None)
    parser.add_argument("--auth-basic", help="Optional basic auth in format user:pass (will set Authorization header)", default=None)
    parser.add_argument("--cookies", help="Optional Cookie header string (e.g. \"k=v; k2=v2\")", default=None)
    args = parser.parse_args(argv[1:])

    # set global proxy/auth/cookie
    if args.proxy:
        GLOBAL_PROXY = args.proxy
        safe_print(f"[i] Using proxy: {GLOBAL_PROXY}")
    if args.auth_basic:
        try:
            usr, pwd = args.auth_basic.split(":", 1)
            token = base64.b64encode(f"{usr}:{pwd}".encode("utf-8")).decode("ascii")
            GLOBAL_BASIC_AUTH_HEADER = "Basic " + token
            safe_print(f"[i] Using basic auth for user: {usr}")
        except Exception:
            safe_print("[!] Invalid --auth-basic format; expected user:pass")
    if args.cookies:
        GLOBAL_COOKIE_HEADER = args.cookies
        safe_print(f"[i] Using Cookie header: {GLOBAL_COOKIE_HEADER}")

    targets = args.targets
    scanner = SafeScannerStdlib(targets, output_file=args.output)
    start = time.time()
    scanner.scan_all()
    end = time.time()
    print("\n=== SUMMARY ===")
    if not scanner.results:
        print("No candidate reflections found. (Absence of reflection does not mean absence of vulnerability.)")
    else:
        print(f"Found {len(scanner.results)} candidate reflection(s) in {end - start:.2f}s. Review results:")
        print(json.dumps(scanner.results, indent=2, default=str))
    if args.output:
        print(f"[+] Output saved to: {args.output}")
    safe_print(f"[i] Error log (if any) written to: {ERROR_LOGFILE}")
if __name__ == "__main__":
    main(sys.argv)
