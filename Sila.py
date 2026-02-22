#!/usr/bin/env python3
import socket
import ssl
import argparse
import logging
import json
import time
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,3306,6379,8080,8443"
BANNER_READ_BYTES = 4096
SCHEMA_VERSION = "1.0"
def configure_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
class ScanResult:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.reachable = False
        self.duration_s = 0.0
        self.banner = ""
        self.http: Dict[str, str] = {}
        self.tls: Dict[str, str] = {}
        self.certificate: Dict[str, str] = {}
        self.notes: List[str] = []
        self.errors: List[str] = []
    def to_dict(self):
        return {
            "host": self.host,
            "port": self.port,
            "reachable": self.reachable,
            "duration_s": self.duration_s,
            "banner": self.banner,
            "http": self.http,
            "tls": self.tls,
            "certificate": self.certificate,
            "notes": self.notes,
            "errors": self.errors,
        }
def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    for p in ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"Invalid port: {p}")
    return sorted(ports)
def recv_all(sock, timeout: float, max_bytes: int):
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    except Exception:
        pass
    return data.decode(errors="ignore")
def parse_http_response(data: str, result: ScanResult):
    lines = data.split("\r\n")
    if not lines:
        return
    status_line = lines[0]
    result.http["status_line"] = status_line
    parts = status_line.split(" ", 2)
    if len(parts) >= 2:
        result.http["status_code"] = parts[1]
        if len(parts) == 3:
            result.http["reason"] = parts[2]
    else:
        result.notes.append("Malformed HTTP status line")

    for line in lines[1:]:
        if line == "":
            break
        if ":" in line:
            key, value = line.split(":", 1)
            result.http[key.lower()] = value.strip()
def inspect_tls(sock, host: str, timeout: float, insecure: bool, result: ScanResult):
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            tls_sock.settimeout(timeout)
            tls_sock.do_handshake()
            result.tls["version"] = tls_sock.version()
            cipher = tls_sock.cipher()
            if cipher:
                result.tls["cipher_suite"] = cipher[0]
                result.tls["cipher_protocol"] = cipher[1]
                result.tls["cipher_bits"] = str(cipher[2])
            cert = tls_sock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))

                result.certificate["subject_cn"] = subject.get("commonName", "")
                result.certificate["issuer_cn"] = issuer.get("commonName", "")
                result.certificate["not_before"] = cert.get("notBefore", "")
                result.certificate["not_after"] = cert.get("notAfter", "")

            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: banner-scanner/2.0\r\n"
                f"Connection: close\r\n\r\n"
            )

            tls_sock.sendall(request.encode())
            data = recv_all(tls_sock, timeout, BANNER_READ_BYTES)
            result.banner = data
            parse_http_response(data, result)

    except ssl.SSLError as e:
        result.errors.append(f"TLS error: {e}")
    except Exception as e:
        result.errors.append(f"TLS failure: {e}")
def probe(host: str, port: int, timeout: float, insecure: bool) -> ScanResult:
    result = ScanResult(host, port)
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result.reachable = True
    except Exception as e:
        result.duration_s = time.time() - start
        result.errors.append("Connection failed")
        return result
    result.duration_s = time.time() - start
    try:
        if port in (443, 8443):
            inspect_tls(sock, host, timeout, insecure, result)
        elif port in (80, 8080):
            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: banner-scanner/2.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            data = recv_all(sock, timeout, BANNER_READ_BYTES)
            result.banner = data
            parse_http_response(data, result)
        else:
            data = recv_all(sock, timeout, BANNER_READ_BYTES)
            result.banner = data

    except Exception as e:
        result.errors.append(str(e))
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result
def setup_signal_handler():
    def handler(sig, frame):
        logging.warning("Interrupted. Exiting.")
        sys.exit(1)
    signal.signal(signal.SIGINT, handler)
def parse_args():
    parser = argparse.ArgumentParser(
        description="Threaded TCP banner and TLS metadata scanner"
    )
    parser.add_argument("host", help="Target host")
    parser.add_argument("--ports", default=DEFAULT_PORTS,
                        help="Ports (e.g. 80,443 or 1-1024)")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--json", help="Write output to JSON file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification")
    return parser.parse_args()
def main():
    args = parse_args()
    configure_logging(args.verbose)
    setup_signal_handler()
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        logging.error(str(e))
        sys.exit(1)
    logging.info(f"Scanning {args.host} on {len(ports)} ports")
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(probe, args.host, p, args.timeout, args.insecure)
            for p in ports
        ]
        for f in as_completed(futures):
            results.append(f.result())
    results.sort(key=lambda r: r.port)
    for r in results:
        if not r.reachable:
            print(f"[{r.host}:{r.port}] unreachable")
            continue
        print(f"[{r.host}:{r.port}] reachable ({r.duration_s:.2f}s)")
        if r.banner:
            print(r.banner.strip())
        if r.tls:
            for k, v in r.tls.items():
                print(f"  TLS {k}: {v}")
        if r.certificate:
            for k, v in r.certificate.items():
                print(f"  Cert {k}: {v}")
        if r.errors:
            for e in r.errors:
                print(f"  Error: {e}")
        print()
    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "schema_version": SCHEMA_VERSION,
                    "results": [r.to_dict() for r in results]
                },
                f,
                indent=2
            )
        logging.info(f"Results written to {args.json}")
if __name__ == "__main__":
    main()
