#!/usr/bin/python3
import asyncio
import ssl
import argparse
import json
import csv
import os
import sys
from datetime import datetime
from typing import List, Dict
SCHEMA_VERSION = "3.0"
DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,3306,6379,8080,8443"
BANNER_READ_BYTES = 4096
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
            "tls_version": self.tls.get("version", ""),
            "cipher_suite": self.tls.get("cipher_suite", ""),
            "cert_subject": self.certificate.get("subject_cn", ""),
            "cert_expiry_days": self.certificate.get("days_until_expiry", ""),
            "errors": "; ".join(self.errors),
        }
def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)
def load_hosts(target: str) -> List[str]:
    if os.path.isfile(target):
        with open(target) as f:
            return [line.strip() for line in f if line.strip()]
    return [target]
async def read_banner(reader: asyncio.StreamReader):
    try:
        data = await asyncio.wait_for(reader.read(BANNER_READ_BYTES), timeout=3)
        return data.decode(errors="ignore")
    except:
        return ""
async def inspect_tls(host, port, timeout, insecure, result: ScanResult):
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    start = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=timeout,
        )
        result.reachable = True
        result.duration_s = asyncio.get_event_loop().time() - start
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            result.tls["version"] = ssl_obj.version()
            cipher = ssl_obj.cipher()
            if cipher:
                result.tls["cipher_suite"] = cipher[0]
            cert = ssl_obj.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                result.certificate["subject_cn"] = subject.get("commonName", "")
                try:
                    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.utcnow()).days
                    result.certificate["days_until_expiry"] = days_left
                    if days_left < 30:
                        result.notes.append("Certificate expiring soon")
                except:
                    pass
        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: async-scanner/3.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        result.banner = await read_banner(reader)
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        result.errors.append(str(e))
async def probe(host, port, timeout, insecure, semaphore):
    result = ScanResult(host, port)
    async with semaphore:
        start = asyncio.get_event_loop().time()
        try:
            if port in (443, 8443):
                await inspect_tls(host, port, timeout, insecure, result)
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                result.reachable = True
                result.duration_s = asyncio.get_event_loop().time() - start
                result.banner = await read_banner(reader)
                writer.close()
                await writer.wait_closed()

        except Exception as e:
            result.duration_s = asyncio.get_event_loop().time() - start
            result.errors.append(str(e))
    return result
def generate_html(results: List[ScanResult], output_file: str):
    rows = ""
    for r in results:
        status = "OPEN" if r.reachable else "CLOSED"
        rows += f"""
        <tr>
            <td>{r.host}</td>
            <td>{r.port}</td>
            <td>{status}</td>
            <td>{r.tls.get("version","")}</td>
            <td>{r.tls.get("cipher_suite","")}</td>
            <td>{r.certificate.get("subject_cn","")}</td>
            <td>{r.certificate.get("days_until_expiry","")}</td>
        </tr>
        """
    html = f"""
    <html>
    <head>
        <title>Enterprise Scan Report</title>
        <style>
            body {{ font-family: Arial; background:#f4f6f8; }}
            h2 {{ background:#1f2937; color:white; padding:10px; }}
            table {{ border-collapse: collapse; width:100%; background:white; }}
            th {{ background:#111827; color:white; padding:8px; }}
            td {{ padding:8px; border:1px solid #ddd; }}
            tr:nth-child(even) {{ background:#f9fafb; }}
        </style>
    </head>
    <body>
        <h2>Enterprise Network Scan Report</h2>
        <p>Generated: {datetime.utcnow().isoformat()} UTC</p>
        <table>
            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Status</th>
                <th>TLS Version</th>
                <th>Cipher</th>
                <th>Cert CN</th>
                <th>Days Until Expiry</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
def export_csv(results: List[ScanResult], filename: str):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "host", "port", "reachable", "duration_s",
                "tls_version", "cipher_suite",
                "cert_subject", "cert_expiry_days", "errors"
            ],
        )
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_dict())
def parse_args():
    parser = argparse.ArgumentParser(description="Async Enterprise TCP/TLS Scanner")
    parser.add_argument("target", help="Host or file of hosts")
    parser.add_argument("--ports", default=DEFAULT_PORTS)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--concurrency", type=int, default=500,
                        help="Max concurrent connections")
    parser.add_argument("--json", help="JSON output file")
    parser.add_argument("--csv", help="CSV output file")
    parser.add_argument("--html", help="Enterprise HTML report")
    parser.add_argument("--insecure", action="store_true")
    return parser.parse_args()
async def main_async():
    args = parse_args()
    ports = parse_ports(args.ports)
    hosts = load_hosts(args.target)
    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [
        probe(host, port, args.timeout, args.insecure, semaphore)
        for host in hosts
        for port in ports
    ]
    results = await asyncio.gather(*tasks)
    results.sort(key=lambda r: (r.host, r.port))
    for r in results:
        status = "OPEN" if r.reachable else "CLOSED"
        print(f"[{r.host}:{r.port}] {status}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {"schema_version": SCHEMA_VERSION,
                 "generated": datetime.utcnow().isoformat(),
                 "results": [r.to_dict() for r in results]},
                f,
                indent=2,
            )
    if args.csv:
        export_csv(results, args.csv)
    if args.html:
        generate_html(results, args.html)
if __name__ == "__main__":
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main_async())
