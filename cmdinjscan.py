#!/usr/bin/python3
"""
Legal: Only run against targets you own or have explicit written permission to test, Still just POC basically
"""
import time, json, csv, sys, argparse, base64, threading, random, string, html, hashlib, os
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote, quote_plus, urljoin
from urllib.request import Request, build_opener, HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor
CONCURRENCY = 8
REQUEST_TIMEOUT = 15
RATE_LIMIT_DELAY = 0.15
MAX_RETRIES = 2
ERROR_THRESHOLD = 5
SUPPORTED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
METHOD_FAIL_LIMIT = 12
HEADER_KEYS_TO_TEST = ["User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP"]
DEFAULT_HEADERS = {
    "User-Agent": "SafeScannerStdLib/1.1",
    "Accept": "*/*",
}
CMD_SEPARATORS = [";", "|", "&&", "||"]
_global_rate_sem = threading.Semaphore(CONCURRENCY)
class Logger:
    def __init__(self, path):
        self.lock = threading.Lock()
        logdir = os.path.dirname(path)
        if logdir:
            os.makedirs(logdir, exist_ok=True)
        self.fh = open(path, "a", encoding="utf-8", buffering=1)

    def log(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        with self.lock:
            self.fh.write(line + "\n")
            print(line, flush=True)

    def close(self):
        with self.lock:
            self.fh.close()
def make_marker(prefix="INJ"):
    return f"{prefix}-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
def percent_encode_bytes(b):
    return ''.join('%{:02X}'.format(x) for x in b)
def enc_plain(m): return m
def enc_url_quote(m): return quote(m, safe='')
def enc_quote_plus(m): return quote_plus(m)
def enc_space_percent20(m): return m.replace(" ", "%20")
def enc_percent_prefix(m): return "%25" + quote(m, safe='')
def enc_utf7_percent(m): return percent_encode_bytes(m.encode("utf-7", errors="replace"))
def enc_utf16le_percent(m): return percent_encode_bytes(m.encode("utf-16le", errors="replace"))
def enc_utf16be_percent(m): return percent_encode_bytes(m.encode("utf-16be", errors="replace"))
def enc_html_entities(m): return html.escape(m)
def enc_hex_escape(m): return ''.join('\\x{:02x}'.format(x) for x in m.encode())
def enc_double_percent(m): return quote(quote(m, safe=''), safe='')
ENCODING_VARIANTS = [
    enc_plain, enc_url_quote, enc_quote_plus, enc_space_percent20,
    enc_percent_prefix, enc_utf7_percent, enc_utf16le_percent,
    enc_utf16be_percent, enc_html_entities, enc_hex_escape,
    enc_double_percent,
]
TARGETED_PAYLOAD_TEMPLATES = [
    "{m};", "{m}|", "{m}&&", "'{m}'", "\"{m}\"", "({m})",
    "{m}%0A", "%0d%0a{m}", "{m}/", "{m}&&true",
    "pre{m}post", "{m}%00", "../{m}", "/*{m}*/", "#{m}",
]
class FormAndResourceParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms = []
        self._current = None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base" and "href" in attrs:
            self.base_url = urljoin(self.base_url, attrs["href"])
        if tag == "form":
            self._current = {
                "action": urljoin(self.base_url, attrs.get("action", "")),
                "method": attrs.get("method", "get").lower(),
                "inputs": {}
            }
            self.forms.append(self._current)
        if self._current and tag in ("input", "textarea", "select"):
            name = attrs.get("name")
            if name:
                self._current["inputs"][name] = attrs.get("value", "")
class BaselineResponse:
    def __init__(self, final_url, status, headers, body):
        self.final_url = final_url
        self.status = status
        self.header_hash = hashlib.sha256(json.dumps(dict(headers), sort_keys=True).encode()).digest()
        self.body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).digest()
    def differs(self, final_url, status, headers, body):
        return (
            status != self.status or
            final_url != self.final_url or
            self.header_hash != hashlib.sha256(json.dumps(dict(headers), sort_keys=True).encode()).digest() or
            self.body_hash != hashlib.sha256(body.encode("utf-8", errors="replace")).digest()
        )
class HTTPClient:
    def __init__(self, logger, proxy=None, auth=None, cookies=None):
        self.logger = logger
        self.auth = auth
        self.cookies = cookies
        handlers = [HTTPCookieProcessor(), HTTPRedirectHandler()]
        if proxy:
            handlers.append(ProxyHandler({"http": proxy, "https": proxy}))
        self.opener = build_opener(*handlers)
    def options(self, url):
        try:
            req = Request(url, method="OPTIONS", headers=DEFAULT_HEADERS)
            with self.opener.open(req, timeout=REQUEST_TIMEOUT) as r:
                allow = r.headers.get("Allow")
                if allow:
                    return [m.strip().upper() for m in allow.split(",")]
        except Exception:
            pass
        return None
    def fetch(self, url, method="GET", data=None, headers=None):
        hdrs = DEFAULT_HEADERS.copy()
        if headers:
            hdrs.update(headers)
        if self.cookies:
            hdrs["Cookie"] = self.cookies
        if self.auth:
            hdrs["Authorization"] = self.auth
        req = Request(url, data=data, headers=hdrs, method=method)
        with _global_rate_sem:
            for attempt in range(MAX_RETRIES + 1):
                try:
                    self.logger.log(f"REQUEST {method} {url} (attempt {attempt + 1})")
                    with self.opener.open(req, timeout=REQUEST_TIMEOUT) as r:
                        body = r.read().decode("utf-8", errors="replace")
                        return r.geturl(), r.getcode(), dict(r.headers), body
                except Exception as e:
                    self.logger.log(f"ERROR {method} {url}: {e}")
                    if attempt == MAX_RETRIES:
                        return None
                    time.sleep(1 + attempt)
class WAFDetector:
    HEADER_HINTS = ["cf-ray", "x-sucuri", "x-waf", "x-akamai", "x-firewall"]
    def analyze(self, baseline, final_url, status, headers, body, marker):
        waf = {}
        for h in headers:
            if h.lower() in self.HEADER_HINTS:
                waf["header"] = h
        if status in (403, 406, 429) and marker:
            waf["blocking_status"] = status
        if marker and baseline.differs(final_url, status, headers, body):
            waf["behavioral_change"] = True
        return waf
class Finding:
    def __init__(self, context, tested_url, method, status, final_url, findings, waf=None):
        self.timestamp = time.time()
        self.context = context
        self.tested_url = tested_url
        self.method = method
        self.status = status
        self.final_url = final_url
        self.findings = findings
        self.waf = waf or {}
    def to_row(self):
        return [
            self.timestamp, self.context, self.tested_url,
            self.method, self.status, self.final_url,
            json.dumps(self.findings), json.dumps(self.waf)
        ]
class SafeInjectionScanner:
    def __init__(self, targets, client, logger, output=None):
        self.targets = targets
        self.client = client
        self.logger = logger
        self.output = output
        self.results = []
        self.lock = threading.Lock()
        self.waf = WAFDetector()
        self.method_failures = {}
    def _method_ok(self, url, method):
        return self.method_failures.get(url, {}).get(method, 0) < METHOD_FAIL_LIMIT
    def _record_method_fail(self, url, method):
        self.method_failures.setdefault(url, {})
        self.method_failures[url][method] = self.method_failures[url].get(method, 0) + 1
        if self.method_failures[url][method] == METHOD_FAIL_LIMIT:
            self.logger.log(f"SKIP {method} {url} (failure limit reached)")
    def _record(self, finding):
        with self.lock:
            self.results.append(finding)
            self.logger.log(f"FINDING {finding.context} {finding.final_url} {finding.findings}")
    def _detect(self, baseline, marker, context, url, method, res):
        final, status, headers, body = res
        hits = []
        if marker in body:
            hits.append("body_reflection")
        for hk, hv in headers.items():
            if marker in hv:
                hits.append(f"header_reflection:{hk}")
        if marker in final:
            hits.append("final_url")
        if hits and baseline.differs(final, status, headers, body):
            waf = self.waf.analyze(baseline, final, status, headers, body, marker)
            self._record(Finding(context, url, method, status, final, hits, waf))
    def scan_target(self, url):
        self.logger.log(f"TARGET start {url}")
        allowed = self.client.options(url)
        methods = [m for m in (allowed or SUPPORTED_METHODS) if m in SUPPORTED_METHODS]
        base = self.client.fetch(url)
        if not base:
            self.logger.log(f"TARGET failed {url}")
            return
        final, status, headers, body = base
        baseline = BaselineResponse(final, status, headers, body)
        parser = FormAndResourceParser(final)
        try:
            parser.feed(body)
        except Exception:
            pass
        parsed = urlparse(final)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for method in methods:
            if not self._method_ok(url, method):
                continue
            try:
                if params:
                    self.scan_query_params(final, parsed, params, baseline)
                    self.scan_cmd_injection(final, parsed, params, baseline)
                self.scan_forms(parser.forms)
                self.scan_headers(final, baseline)
            except Exception:
                self._record_method_fail(url, method)
        self.logger.log(f"TARGET done {url}")
    def scan_query_params(self, base_url, parsed, params, baseline):
        for pname in params:
            marker = make_marker()
            for tpl in ["{m}"] + TARGETED_PAYLOAD_TEMPLATES:
                raw = tpl.replace("{m}", marker)
                for enc in ENCODING_VARIANTS:
                    new_params = params.copy()
                    new_params[pname] = [enc(raw)]
                    new_url = urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in new_params.items()})))
                    res = self.client.fetch(new_url)
                    if res:
                        self._detect(baseline, marker, f"query:{pname}", new_url, "GET", res)
                    time.sleep(RATE_LIMIT_DELAY)
    def scan_cmd_injection(self, base_url, parsed, params, baseline):
        for pname in params:
            for sep in CMD_SEPARATORS:
                marker = make_marker("CMD")
                payload = sep + marker
                for enc in ENCODING_VARIANTS:
                    new_qs = params.copy()
                    new_qs[pname] = [enc(payload)]
                    new_url = urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in new_qs.items()})))
                    res = self.client.fetch(new_url)
                    if res:
                        self._detect(baseline, marker, f"cmd_query:{pname}", new_url, "GET", res)
                    time.sleep(RATE_LIMIT_DELAY)
    def scan_forms(self, forms):
        for form in forms:
            benign = self.client.fetch(form["action"], method=form["method"].upper(), data=urlencode(form["inputs"]).encode())
            if not benign:
                continue
            baseline = BaselineResponse(*benign)
            for field in form["inputs"]:
                marker = make_marker()
                for tpl in ["{m}"] + TARGETED_PAYLOAD_TEMPLATES:
                    raw = tpl.replace("{m}", marker)
                    for enc in ENCODING_VARIANTS:
                        payload = {k: enc(raw) if k == field else v for k, v in form["inputs"].items()}
                        res = self.client.fetch(form["action"], method=form["method"].upper(), data=urlencode(payload).encode())
                        if res:
                            self._detect(baseline, marker, f"form:{field}", form["action"], form["method"].upper(), res)
                        time.sleep(RATE_LIMIT_DELAY)
    def scan_headers(self, url, baseline):
        for header in HEADER_KEYS_TO_TEST:
            marker = make_marker()
            for tpl in ["{m}"] + TARGETED_PAYLOAD_TEMPLATES:
                raw = tpl.replace("{m}", marker)
                for enc in ENCODING_VARIANTS:
                    res = self.client.fetch(url, headers={header: enc(raw)})
                    if res:
                        self._detect(baseline, marker, f"header:{header}", url, "GET", res)
                    time.sleep(RATE_LIMIT_DELAY)
    def scan_all(self):
        with ThreadPoolExecutor(CONCURRENCY) as ex:
            ex.map(self.scan_target, self.targets)
    def save(self):
        if not self.output:
            return
        if self.output.endswith(".csv"):
            with open(self.output, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["timestamp", "context", "url", "method", "status", "final_url", "findings", "waf"])
                for r in self.results:
                    w.writerow(r.to_row())
        else:
            with open(self.output, "w", encoding="utf-8") as fh:
                for r in self.results:
                    fh.write(json.dumps(r.__dict__, indent=2) + "\n")
def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--output")
    ap.add_argument("--proxy")
    ap.add_argument("--auth-basic")
    ap.add_argument("--cookies")
    ap.add_argument("--logfile", default=f"scan_{int(time.time())}.log")
    args = ap.parse_args(argv[1:])
    logger = Logger(args.logfile)
    logger.log("Scan started")
    auth = None
    if args.auth_basic:
        u, p = args.auth_basic.split(":", 1)
        auth = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
    client = HTTPClient(logger, args.proxy, auth, args.cookies)
    scanner = SafeInjectionScanner(args.targets, client, logger, args.output)
    scanner.scan_all()
    scanner.save()
    logger.log("Scan complete")
    logger.close()
if __name__ == "__main__":
    main(sys.argv)
