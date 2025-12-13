#!/usr/bin/ python3
import argparse
import os
import subprocess
import re
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from pathlib import Path
@dataclass
class PatternGroup:
    name: str
    patterns: list  # list of compiled regex objects
def get_asm_vuln_patterns():
    return [
        PatternGroup("Buffer Overflow / Unsafe Memory Operations", [
            re.compile(r"\bstrcpy\b", re.I),
            re.compile(r"\bstrncpy\b", re.I),
            re.compile(r"\bstrcat\b", re.I),
            re.compile(r"\bstrncat\b", re.I),
            re.compile(r"\bgets\b", re.I),
            re.compile(r"\bscanf\b", re.I),
            re.compile(r"\bfscanf\b", re.I),
            re.compile(r"\bsscanf\b", re.I),
            re.compile(r"\bmemcpy\b", re.I),
            re.compile(r"\bmemmove\b", re.I),
            re.compile(r"\bmovs\b", re.I),
            re.compile(r"\bstosb\b|\bstosd\b|\bstosw\b", re.I),
            re.compile(r"\bcmps\b", re.I),
            re.compile(r"\blods\b|lodsb|lodsw|lodsd", re.I),
            re.compile(r"\bxor\s+[a-z0-9]+,\s*\[.*\]", re.I),
            re.compile(r"\badd\s+[a-z0-9]+,\s*\[.*\]", re.I),
            re.compile(r"\bsub\s+[a-z0-9]+,\s*\[.*\]", re.I),
        ]),
        PatternGroup("Unsafe Function Call / Library Routines", [
            re.compile(r"\bcall\s+strcpy\b", re.I),
            re.compile(r"\bcall\s+strncpy\b", re.I),
            re.compile(r"\bcall\s+strcat\b", re.I),
            re.compile(r"\bcall\s+strncat\b", re.I),
            re.compile(r"\bcall\s+gets\b", re.I),
            re.compile(r"\bcall\s+scanf\b", re.I),
            re.compile(r"\bcall\s+fscanf\b", re.I),
            re.compile(r"\bcall\s+sscanf\b", re.I),
            re.compile(r"\bcall\s+system\b", re.I),
            re.compile(r"\bcall\s+popen\b", re.I),
            re.compile(r"\bcall\s+execve\b", re.I),
        ]),
        PatternGroup("Hardcoded Secrets / Data Strings", [
            re.compile(r'\bdb\s+".*password.*"', re.I),
            re.compile(r'\bdb\s+".*secret.*"', re.I),
            re.compile(r'\bdb\s+".*key.*"', re.I),
            re.compile(r'\bdb\s+".*token.*"', re.I),
            re.compile(r'\bdb\s+".*credential.*"', re.I),
            re.compile(r'\bdata\s+".*password.*"', re.I),
            re.compile(r'\bdata\s+".*secret.*"', re.I),
        ]),
        PatternGroup("Privilege / Permissions / Escalation Instructions", [
            re.compile(r"\biopl\b", re.I),
            re.compile(r"\bitsl\b", re.I),
            re.compile(r"\bcli\b", re.I),
            re.compile(r"\bsti\b", re.I),
            re.compile(r"\bout\s+", re.I),
            re.compile(r"\bin\b", re.I),
            re.compile(r"\bint\s+0x80\b.*\bsetuid\b", re.I),
            re.compile(r"\bint\s+0x80\b.*\bsetgid\b", re.I),
            re.compile(r"\bint\s+0x80\b.*\bchmod\b", re.I),
            re.compile(r"\bint\s+0x80\b.*\bchown\b", re.I),
            re.compile(r"\bint\s+0x80\b.*\brwx\b", re.I),
        ]),
        PatternGroup("Suspicious Syscalls / Interrupts", [
            re.compile(r"\bint\s+0x80\b", re.I),
            re.compile(r"\bsyscall\b", re.I),
            re.compile(r"\bint\s+0x2e\b", re.I),
            re.compile(r"\bint\s+0x81\b", re.I),
            re.compile(r"\bint\s+0x82\b", re.I),
            re.compile(r"\bint\s+0x90\b", re.I),
            re.compile(r"\btrap\b", re.I),
            re.compile(r"\beret\b", re.I),
        ]),
        PatternGroup("Control Flow / ROP / Jump Gadgets", [
            re.compile(r"\bjmp\s+[a-zA-Z0-9_]+\b", re.I),
            re.compile(r"\bjmp\s*\[.*\]", re.I),
            re.compile(r"\bcall\s*\[.*\]", re.I),
            re.compile(r"\bpush\s+.*; ret\b", re.I),
            re.compile(r"\bpop\s+.*; ret\b", re.I),
            re.compile(r"\bret\b", re.I),
            re.compile(r"\bleave\b", re.I),
        ]),
        PatternGroup("Format String / Debug / Info Leakage", [
            re.compile(r"\bodbc\b|\bprintf\b|\bsprintf\b|\bvsprintf\b", re.I),
            re.compile(r"\bprintf\b", re.I),
            re.compile(r"\bsprintf\b", re.I),
            re.compile(r"\bvsprintf\b", re.I),
            re.compile(r"\bwprintf\b", re.I),
            re.compile(r"\bwprintf_s\b", re.I),
            re.compile(r"\bdebug\b", re.I),
            re.compile(r"\bprintk\b", re.I),
        ]),
        PatternGroup("Arithmetic / Overflcow Risks", [
            re.compile(r"\badd\b", re.I),
            re.compile(r"\bsub\b", re.I),
            re.compile(r"\bmul\b", re.I),
            re.compile(r"\bdiv\b", re.I),
            re.compile(r"\bimul\b", re.I),
            re.compile(r"\bdivl\b", re.I),
            re.compile(r"\bjo\b|\bjc\b|\bbe\b|\bja\b|\bjb\b|\bjl\b|\bjg\b", re.I),
        ]),
    ]
def exec_objdump(binary_path: str, verbose: bool):
    # Test objdump availability
    try:
        subprocess.run(["objdump", "--version"],
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE,
                       check=True)
    except Exception:
        raise RuntimeError("objdump not found or not functional. Install binutils.")
    cmd = ["objdump", "-d", binary_path]
    if verbose:
        print(f"[DEBUG] Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not proc.stdout:
        raise RuntimeError("objdump produced no output. Binary invalid?")
    return proc.stdout.decode(errors="replace")
def scan_asm_text(asm_text, pattern_groups, source_name, max_workers, verbose=False):
    results = []
    seen = set()
    seen_lock = Lock()
    lines = asm_text.splitlines()
    if verbose:
        print(f"[DEBUG] Using up to {max_workers} worker(s)")
    def scan_line(line_tuple):
        ln, line = line_tuple
        normalized = re.sub(r"\s+", " ", line)
        local_hits = []
        for group in pattern_groups:
            for pattern in group.patterns:
                if pattern.search(normalized):
                    identifier = f"{group.name}:{ln}:{normalized}"
                    with seen_lock:
                        if identifier in seen:
                            continue
                        seen.add(identifier)
                    local_hits.append(
                        f"[{group.name}] {source_name}:{ln}: {line}"
                    )
        return local_hits
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(scan_line, (i + 1, line))
                   for i, line in enumerate(lines)]
        for f in as_completed(futures):
            hits = f.result()
            if hits:
                results.extend(hits)
    return results
def main():
    parser = argparse.ArgumentParser(description="Assembly Vulnerability Scanner")
    parser.add_argument("--asm", help="Path to assembly file")
    parser.add_argument("--bin", help="Path to binary file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--log", help="Log file path")
    args = parser.parse_args()
    if not args.asm and not args.bin:
        print("Error: must specify either --asm or --bin")
        return 1
    patterns = get_asm_vuln_patterns()
    issues = []
    # Setup logging
    if args.log:
        log_file = open(args.log, "w")
    else:
        log_file = None
    try:
        if args.asm:
            if not os.path.exists(args.asm):
                print(f"Error: asm file not found: {args.asm}")
                return 1
            with open(args.asm, "r", encoding="utf8", errors="replace") as f:
                asm_text = f.read()
        else:  # --bin
            if not os.path.exists(args.bin):
                print(f"Error: binary not found: {args.bin}")
                return 1
            asm_text = exec_objdump(args.bin, args.verbose)
        # Determine worker count
        import multiprocessing
        workers = max(1, multiprocessing.cpu_count())
        source_name = args.asm or args.bin
        issues = scan_asm_text(asm_text, patterns, source_name, workers, args.verbose)
        # Output results
        if not issues:
            msg = " No potential vulnerabilities found."
            print(msg)
            if log_file:
                log_file.write(msg + "\n")
        else:
            header = " Potential vulnerabilities detected:"
            print(header)
            if log_file:
                log_file.write(header + "\n")
            for issue in issues:
                print(issue)
                if log_file:
                    log_file.write(issue + "\n")
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1
    finally:
        if log_file:
            log_file.close()
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
