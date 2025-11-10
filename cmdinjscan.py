#!/usr/bin/python3
"""
Safe Reflection / Command-Injection Scanner (standard-library-only, extended)
Author: gh05t5h311
Usage:
    python safe_injection_scanner_stdlib_extended.py [--output results.csv] [--proxy http://127.0.0.1:8080]
        [--auth-basic user:pass] [--cookies "k=v; ..."] [--verify] https://example.com/page1 ...
Legal: Only run against targets you own or have explicit written permission to test.
Very rough at the moment and clearly needs improvement but still.
"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode, quote_plus, quote_from_bytes
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import random
import string
import time
import sys
import argparse
import csv
import html
import base64
import traceback

# --- Configuration ---
CONCURRENCY = 8
REQUEST_TIMEOUT = 15  # seconds for urlopen
RATE_LIMIT_DELAY = 0.15
HEADER_KEYS_TO_TEST = ["User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP"]
DEFAULT_HEADERS = {
    "User-Agent": "SafeScannerStdLib/1.0",
    "Accept": "*/*",
}
GLOBAL_PROXY = None
GLOBAL_BASIC_AUTH_HEADER = None
GLOBAL_COOKIE_HEADER = None
ERROR_LOGFILE = "scanner_errors.log"
MAX_RETRIES = 2
_lock_print = threading.Lock()
def safe_print(*a, **k):
    with _lock_print:
        print(*a, **k)
def log_error(msg):
    try:
        with open(ERROR_LOGFILE, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")
    except Exception:
        pass

def make_marker():
    rnd = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"INJ-{rnd}"

# --- Encodings ---
def percent_encode_bytes(b):
    return ''.join('%{:02X}'.format(x) for x in b)

def encode_utf7(s):
    try:
        return s.encode('utf-7')
    except Exception:
        return s.encode('utf-8')

def encode_utf16le_percent(s):
    b = s.encode('utf-16le', errors='ignore')
    return percent_encode_bytes(b)

def encode_utf16be_percent(s):
    b = s.encode('utf-16be', errors='ignore')
    return percent_encode_bytes(b)

def encode_html_entities(s):
    return ''.join(f'&#x{ord(c):x};' for c in s)

def encode_hex_escape(s):
    return ''.join('\\x{:02x}'.format(ord(c)) for c in s)

def encode_utf8_percent(s):
    return percent_encode_bytes(s.encode('utf-8', errors='ignore'))

ENCODERS = {
    "raw": lambda s: s,
    "utf7": lambda s: encode_utf7(s).decode('latin-1', errors='ignore'),
    "utf8_pct": lambda s: encode_utf8_percent(s),
    "utf16le_pct": lambda s: encode_utf16le_percent(s),
    "utf16be_pct": lambda s: encode_utf16be_percent(s),
    "html_ent": lambda s: encode_html_entities(s),
    "hex_esc": lambda s: encode_hex_escape(s),
}

# --- HTTP utilities ---
def build_opener_with_cookies_and_proxy(proxy=None):
    handlers = [HTTPCookieProcessor(), HTTPRedirectHandler()]
    if proxy:
        handlers.append(ProxyHandler({"http": proxy, "https": proxy}))
    return build_opener(*handlers)

def urlencode_dict_to_bytes(d):
    try:
        return urlencode(d, doseq=True).encode("utf-8")
    except Exception:
        items = []
        for k, v in (d.items() if isinstance(d, dict) else []):
            if isinstance(v, (list, tuple)):
                for vi in v:
                    items.append(f"{quote_plus(str(k))}={quote_plus(str(vi))}")
            else:
                items.append(f"{quote_plus(str(k))}={quote_plus(str(v))}")
        return "&".join(items).encode("utf-8")

def fetch_url(url, method="GET", data=None, headers=None, timeout=REQUEST_TIMEOUT):
    last_exc = None
    for attempt in range(0, MAX_RETRIES + 1):
        opener = build_opener_with_cookies_and_proxy(GLOBAL_PROXY)
        hdrs = DEFAULT_HEADERS.copy()
        if headers:
            hdrs.update(headers)
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
            try:
                body = e.read()
                try:
                    text = body.decode("utf-8", errors="replace")
                except Exception:
                    text = body.decode("latin-1", errors="replace")
            except Exception:
                text = ""
            safe_print(f"[!] HTTPError for {url}: {getattr(e,'code', 'N/A')} {getattr(e,'reason', '')}")
            tb = traceback.format_exc()
            log_error(f"HTTPError {url} attempt {attempt}: {tb}")
            return (e.geturl() if hasattr(e, "geturl") else url, getattr(e, "code", None), dict(e.headers if hasattr(e, "headers") else {}), text)
        except URLError as e:
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
    if last_exc:
        log_error(f"Failed to fetch {url} after retries: {last_exc}")
    return None

# --- HTML parsing to discover forms and resources ---
class SimpleHTMLScanner(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.forms = []  # list of dicts: {action, method, inputs: {name: [values]}}
        self.links = set()
        self.resources = set()

        self._in_form = False
        self._current_form = None
        # select processing
        self._in_select = False
        self._current_select_name = None
        self._current_select_options = []
        self._in_textarea = False
        self._current_textarea_name = None
        self._current_textarea_buf = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            action = attrs.get("action", "")
            action_abs = urljoin(self.base, action)
            method = attrs.get("method", "GET").upper()
            self._in_form = True
            self._current_form = {"action": action_abs, "method": method, "inputs": {}}
        elif tag == "input" and self._in_form and self._current_form is not None:
            if attrs.get("disabled"):
                return
            name = attrs.get("name")
            if not name:
                return
            itype = attrs.get("type", "text").lower()
            # checkboxes/radios: may have multiple inputs with same name
            if itype in ("checkbox", "radio"):
                value = attrs.get("value", "on")
                self._current_form["inputs"].setdefault(name, []).append(value)
            else:
                value = attrs.get("value", "")
                self._current_form["inputs"].setdefault(name, []).append(value)
        elif tag == "textarea" and self._in_form and self._current_form is not None:
            if attrs.get("disabled"):
                return
            name = attrs.get("name")
            if not name:
                return
            self._in_textarea = True
            self._current_textarea_name = name
            self._current_textarea_buf = []
        elif tag == "select" and self._in_form and self._current_form is not None:
            if attrs.get("disabled"):
                return
            name = attrs.get("name")
            if not name:
                return
            self._in_select = True
            self._current_select_name = name
            self._current_select_options = []
        elif tag == "option" and self._in_select:
            opt_value = attrs.get("value")
            selected = 'selected' in attrs or attrs.get('selected') is not None
            # temporarily store option; actual text between tags handled in handle_data if no value
            self._current_select_options.append((opt_value, selected))
        elif tag == "a":
            href = attrs.get("href")
            if href:
                self.links.add(urljoin(self.base, href))
        elif tag in ("img", "script", "iframe", "link"):
            src = attrs.get("src") or attrs.get("href")
            if src:
                self.resources.add(urljoin(self.base, src))

    def handle_endtag(self, tag):
        if tag == "form" and self._in_form:
            # finalize current form
            self.forms.append(self._current_form)
            self._current_form = None
            self._in_form = False
        elif tag == "select" and self._in_select:
            # commit select options into inputs: choose selected option(s) or first non-empty
            name = self._current_select_name
            opts = self._current_select_options or []
            values = []
            # prefer selected, else first with value, else empty string
            for val, sel in opts:
                if sel:
                    values.append(val if val is not None else "")
            if not values and opts:
                val, sel = opts[0]
                values.append(val if val is not None else "")
            if name and values:
                self._current_form["inputs"].setdefault(name, []).extend(values)
            self._in_select = False
            self._current_select_name = None
            self._current_select_options = []
        elif tag == "textarea" and self._in_textarea:
            name = self._current_textarea_name
            val = "".join(self._current_textarea_buf)
            if name is not None:
                self._current_form["inputs"].setdefault(name, []).append(val)
            self._in_textarea = False
            self._current_textarea_name = None
            self._current_textarea_buf = []

    def handle_data(self, data):
        if self._in_textarea:
            self._current_textarea_buf.append(data)

# --- Scanner class ---
class SafeScannerStdlib:
    def __init__(self, targets, concurrency=CONCURRENCY, output_file=None, verify=False):
        self.targets = targets
        self.results = []
        self.executor = ThreadPoolExecutor(max_workers=concurrency)
        self.rate_limit = RATE_LIMIT_DELAY
        self.lock = threading.Lock()
        self.output_file = output_file
        self.verify = verify

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
        if self.output_file:
            try:
                self.save_results(self.output_file)
                safe_print(f"[+] Results saved to {self.output_file}")
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
        # parse HTML
        scanner = SimpleHTMLScanner(final_url)
        try:
            scanner.feed(body)
        except Exception:
            pass

        # test query string parameters in the URL
        self.test_url_query(final_url)

        # test discovered links that have query params
        for link in list(scanner.links):
            self._sleep_rate()
            if "?" in link:
                self.test_url_query(link)

        # test forms
        for form in scanner.forms:
            self._sleep_rate()
            self.test_form(form)

        # test headers
        self.test_headers(final_url)

        safe_print(f"[+] Finished scanning: {target}")

    def _sleep_rate(self):
        time.sleep(self.rate_limit)

    def record_result(self, target, vector, evidence, location=None, extra=None):
        with self.lock:
            self.results.append({
                "target": target,
                "vector": vector,
                "evidence": evidence,
                "location": location or "",
                "extra": extra or ""
            })
            safe_print(f"[+] Reflection found: target={target} vector={vector} evidence={evidence} location={location}")

    # core detection helpers
    def _check_reflection_in_response(self, resp_tuple, marker):
        if not resp_tuple:
            return None
        final_url, status, headers, body = resp_tuple
        found = []
        # check body
        if marker in body:
            found.append(("body", final_url))
        # check headers
        for k, v in headers.items():
            if marker in v:
                found.append((f"header:{k}", final_url))
        # check redirect location
        loc = headers.get("Location") or headers.get("location")
        if loc and marker in loc:
            found.append(("redirect_location", loc))
        return found if found else None

    # verification helpers for each vector
    def _verify_get_param(self, base, qs_pairs, param_name, encoder_name):
        # produce a second marker and inject same encoder
        marker2 = make_marker()
        enc = ENCODERS.get(encoder_name, ENCODERS["raw"])
        injected2 = enc(marker2)
        new_qs = []
        for n, v in qs_pairs:
            if n == param_name:
                new_qs.append((n, injected2))
            else:
                new_qs.append((n, v))
        new_qs_str = urlencode(new_qs, doseq=True)
        test_url2 = base + ("?" + new_qs_str if new_qs_str else "")
        self._sleep_rate()
        resp2 = fetch_url(test_url2, method="GET")
        return self._check_reflection_in_response(resp2, marker2)

    def _verify_header(self, url, header_name, encoder_name):
        marker2 = make_marker()
        enc = ENCODERS.get(encoder_name, ENCODERS["raw"])
        injected2 = enc(marker2)
        hdr = {header_name: injected2}
        self._sleep_rate()
        resp2 = fetch_url(url, headers=hdr)
        return self._check_reflection_in_response(resp2, marker2)

    def _verify_form(self, action, method, inputs, target_input_name, encoder_name):
        marker2 = make_marker()
        enc = ENCODERS.get(encoder_name, ENCODERS["raw"])
        injected2 = enc(marker2)
        # build data preserving lists: inputs dict values are lists
        data = {}
        for k, vals in inputs.items():
            if k == target_input_name:
                # replace every occurrence for that name with injected2
                # if it's a multi-value field, keep same arity but replace each with injected2 once
                if isinstance(vals, (list, tuple)):
                    data[k] = [injected2 for _ in vals]
                else:
                    data[k] = injected2
            else:
                data[k] = vals
        # perform request
        parsed = urlparse(action)
        if method.upper() == "GET":
            base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
            # flatten data for query string
            qlist = []
            for k, v in data.items():
                if isinstance(v, (list, tuple)):
                    for vv in v:
                        qlist.append((k, vv))
                else:
                    qlist.append((k, v))
            new_q = urlencode(qlist, doseq=True)
            test_url2 = base + ("?" + new_q if new_q else "")
            self._sleep_rate()
            resp2 = fetch_url(test_url2, method="GET")
        else:
            # POST: ensure data passed as dict with lists allowed
            self._sleep_rate()
            resp2 = fetch_url(action, method="POST", data=data)
        return self._check_reflection_in_response(resp2, marker2)

    # test GET query parameters by replacing values with marker variants
    def test_url_query(self, url):
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        if not qs:
            return
        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
        for name, orig_val in qs:
            marker = make_marker()
            for enc_name, enc in ENCODERS.items():
                injected = enc(marker)
                # build new query with only this parameter replaced
                new_qs = []
                for n, v in qs:
                    if n == name:
                        new_qs.append((n, injected))
                    else:
                        new_qs.append((n, v))
                new_qs_str = urlencode(new_qs, doseq=True)
                test_url = base + ("?" + new_qs_str if new_qs_str else "")
                self._sleep_rate()
                resp = fetch_url(test_url, method="GET")
                found = self._check_reflection_in_response(resp, marker)
                if found:
                    # perform verification if requested
                    verified = True
                    if self.verify:
                        verified = False
                        ver = self._verify_get_param(base, qs, name, enc_name)
                        if ver:
                            verified = True
                    if verified:
                        for where, loc in found:
                            self.record_result(test_url, f"GET param {name} ({enc_name})", where, location=loc)
                    break

    # test simple non-destructive header injection
    def test_headers(self, url):
        marker = make_marker()
        for header_name in HEADER_KEYS_TO_TEST:
            for enc_name, enc in ENCODERS.items():
                injected = enc(marker)
                hdr = {header_name: injected}
                self._sleep_rate()
                resp = fetch_url(url, headers=hdr)
                found = self._check_reflection_in_response(resp, marker)
                if found:
                    verified = True
                    if self.verify:
                        verified = False
                        ver = self._verify_header(url, header_name, enc_name)
                        if ver:
                            verified = True
                    if verified:
                        for where, loc in found:
                            self.record_result(url, f"Header:{header_name} ({enc_name})", where, location=loc)
                    break

    # test forms (handles multi-value inputs/lists)
    def test_form(self, form):
        action = form.get("action")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", {})  # mapping name -> [values]
        if not inputs:
            inputs = {"q": [""]}
        # normalize inputs so each value is a list
        normalized = {}
        for k, v in inputs.items():
            if isinstance(v, list):
                normalized[k] = v
            else:
                normalized[k] = [v]
        for name in list(normalized.keys()):
            marker = make_marker()
            for enc_name, enc in ENCODERS.items():
                injected = enc(marker)
                # construct data preserving list arity
                data = {}
                for k, vals in normalized.items():
                    if k == name:
                        data[k] = [injected for _ in vals]
                    else:
                        data[k] = list(vals)
                # perform request
                if method == "GET":
                    parsed = urlparse(action)
                    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
                    qlist = []
                    for k, v in data.items():
                        if isinstance(v, (list, tuple)):
                            for vv in v:
                                qlist.append((k, vv))
                        else:
                            qlist.append((k, v))
                    new_q = urlencode(qlist, doseq=True)
                    test_url = base + ("?" + new_q if new_q else "")
                    self._sleep_rate()
                    resp = fetch_url(test_url, method="GET")
                else:
                    # POST: pass data as dict where values may be lists
                    self._sleep_rate()
                    resp = fetch_url(action, method="POST", data=data)
                found = self._check_reflection_in_response(resp, marker)
                if found:
                    verified = True
                    if self.verify:
                        verified = False
                        ver = self._verify_form(action, method, normalized, name, enc_name)
                        if ver:
                            verified = True
                    if verified:
                        for where, loc in found:
                            self.record_result(action, f"FORM:{name} ({method}) ({enc_name})", where, location=loc, extra=str(data))
                    break

    def save_results(self, output_file):
        if output_file.lower().endswith(".csv"):
            keys = ["target", "vector", "evidence", "location", "extra"]
            with open(output_file, "w", newline='', encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=keys)
                writer.writeheader()
                for r in self.results:
                    writer.writerow(r)
        else:
            with open(output_file, "w", encoding="utf-8") as fh:
                for r in self.results:
                    fh.write(f"TARGET: {r['target']}\nVECTOR: {r['vector']}\nEVIDENCE: {r['evidence']}\nLOCATION: {r['location']}\nEXTRA: {r['extra']}\n\n")

# --- CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SafeScanner StdLib Extended")
    parser.add_argument("targets", nargs="+", help="Target URLs to scan")
    parser.add_argument("--output", help="Output to file (CSV if endswith .csv)", default=None)
    parser.add_argument("--proxy", help="Proxy to route traffic through (e.g. http://127.0.0.1:8080)", default=None)
    parser.add_argument("--auth-basic", help="HTTP Basic Auth (user:pass)", default=None)
    parser.add_argument("--cookies", help="Cookies to send with requests", default=None)
    parser.add_argument("--verify", help="Enable verification step (re-requests with second marker to reduce false positives)", action="store_true")
    args = parser.parse_args()

    if args.proxy:
        GLOBAL_PROXY = args.proxy
    if args.auth_basic:
        encoded_auth = base64.b64encode(args.auth_basic.encode()).decode()
        GLOBAL_BASIC_AUTH_HEADER = f"Basic {encoded_auth}"
    if args.cookies:
        GLOBAL_COOKIE_HEADER = args.cookies

    scanner = SafeScannerStdlib(args.targets, output_file=args.output, verify=args.verify)
    scanner.scan_all()
