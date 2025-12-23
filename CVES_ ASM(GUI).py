#!/usr/bin/python3
import sys,os,re,subprocess
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import multiprocessing
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QTextEdit, QLabel,
    QRadioButton, QCheckBox, QProgressBar, QSplitter
)
from PySide6.QtGui import QTextCharFormat, QColor, QSyntaxHighlighter, QDropEvent
from PySide6.QtCore import Qt, QThread, Signal, Slot
@dataclass
class PatternGroup:
    name: str
    patterns: list
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
            re.compile(r"\bstos(b|d|w)\b", re.I),
            re.compile(r"\bcmps\b", re.I),
            re.compile(r"\blods(b|w|d)?\b", re.I),
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
            re.compile(r"\bint\s+0x80\b.*setuid", re.I),
            re.compile(r"\bint\s+0x80\b.*setgid", re.I),
            re.compile(r"\bint\s+0x80\b.*chmod", re.I),
            re.compile(r"\bint\s+0x80\b.*chown", re.I),
            re.compile(r"\bint\s+0x80\b.*rwx", re.I),
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
            re.compile(r"\bjmp\s+[A-Za-z0-9_]+\b", re.I),
            re.compile(r"\bjmp\s*\[.*\]", re.I),
            re.compile(r"\bcall\s*\[.*\]", re.I),
            re.compile(r"\bpush\s+.*; ret\b", re.I),
            re.compile(r"\bpop\s+.*; ret\b", re.I),
            re.compile(r"\bret\b", re.I),
            re.compile(r"\bleave\b", re.I),
        ]),
        PatternGroup("Format String / Debug / Info Leakage", [
            re.compile(r"\b(printf|sprintf|vsprintf|odbc|printk)\b", re.I),
            re.compile(r"\bwprintf\b", re.I),
            re.compile(r"\bwprintf_s\b", re.I),
            re.compile(r"\bdebug\b", re.I),
        ]),
        PatternGroup("Arithmetic / Overflow Risks", [
            re.compile(r"\badd\b", re.I),
            re.compile(r"\bsub\b", re.I),
            re.compile(r"\bmul\b", re.I),
            re.compile(r"\bdiv\b", re.I),
            re.compile(r"\bimul\b", re.I),
            re.compile(r"\bdivl\b", re.I),
            re.compile(r"\b(jg|jl|jb|ja|be|jc|jo)\b", re.I),
        ]),
    ]
def exec_objdump(binary_path, verbose=False):
    try:
        subprocess.run(["objdump", "--version"],
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE,
                       check=True)
    except Exception:
        raise RuntimeError("objdump not found (install binutils).")
    cmd = ["objdump", "-d", binary_path]
    if verbose:
        print("[DEBUG] Running:", " ".join(cmd))
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = proc.stdout.decode(errors="replace")
    if not out:
        raise RuntimeError("objdump returned no output (invalid binary?)")
    return out
def scan_asm_text(asm_text, pattern_groups, source_name, max_workers=4, verbose=False, progress_callback=None):
    results = []
    seen = set()
    lock = Lock()
    lines = asm_text.splitlines()
    total_lines = len(lines)
    completed = 0
    def scan_line(task):
        nonlocal completed
        ln, line = task
        normalized = re.sub(r"\s+", " ", line)
        hits = []
        for group in pattern_groups:
            for pattern in group.patterns:
                if pattern.search(normalized):
                    key = f"{group.name}:{ln}:{normalized}"
                    with lock:
                        if key in seen:
                            continue
                        seen.add(key)
                    hits.append(f"[{group.name}] {source_name}:{ln}: {line}")
        completed += 1
        if progress_callback:
            progress_callback(completed / total_lines * 100)
        return hits
    workers = max(1, multiprocessing.cpu_count())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_line, (i+1, line)) for i, line in enumerate(lines)]
        for f in futures:
            res = f.result()
            if res:
                results.extend(res)
    return results
class ASMSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super().__init__(parent)
        self.keywords = ["mov", "add", "sub", "xor", "jmp", "call", "ret", "push", "pop"]
        self.format = QTextCharFormat()
        self.format.setForeground(QColor("#ff5c5c"))
    def highlightBlock(self, text):
        for kw in self.keywords:
            for match in re.finditer(r"\b{}\b".format(kw), text):
                start, end = match.start(), match.end()
                self.setFormat(start, end-start, self.format)
class ScanThread(QThread):
    progress = Signal(float)
    finished = Signal(list)
    error = Signal(str)
    def __init__(self, file_path, mode, verbose, log_path):
        super().__init__()
        self.file_path = file_path
        self.mode = mode
        self.verbose = verbose
        self.log_path = log_path
    def run(self):
        try:
            patterns = get_asm_vuln_patterns()
            if self.mode == "asm":
                with open(self.file_path, "r", encoding="utf8", errors="replace") as f:
                    asm = f.read()
            else:
                asm = exec_objdump(self.file_path, verbose=self.verbose)
            issues = scan_asm_text(
                asm, patterns, self.file_path,
                max_workers=multiprocessing.cpu_count(),
                verbose=self.verbose,
                progress_callback=lambda val: self.progress.emit(val)
            )
            if self.log_path:
                with open(self.log_path, "w") as f:
                    if not issues:
                        f.write("No potential vulnerabilities found.\n")
                    else:
                        for i in issues:
                            f.write(i + "\n")
            self.finished.emit(issues)
        except Exception as e:
            self.error.emit(str(e))
class ASMScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ASM Vulnerability Scanner")
        self.resize(900, 650)
        self.setAcceptDrops(True)
        # Central Widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        # Top Controls
        controls = QHBoxLayout()
        layout.addLayout(controls)
        self.file_path_edit = QLineEdit()
        controls.addWidget(self.file_path_edit)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        controls.addWidget(browse_btn)
        self.mode_asm = QRadioButton("ASM")
        self.mode_asm.setChecked(True)
        self.mode_bin = QRadioButton("Binary")
        controls.addWidget(self.mode_asm)
        controls.addWidget(self.mode_bin)
        self.verbose_cb = QCheckBox("Verbose")
        controls.addWidget(self.verbose_cb)
        self.log_path_edit = QLineEdit()
        layout.addWidget(self.log_path_edit)
        browse_log_btn = QPushButton("Browse Log")
        browse_log_btn.clicked.connect(self.browse_log)
        layout.addWidget(browse_log_btn)
        self.scan_btn = QPushButton("Run Scan")
        self.scan_btn.clicked.connect(self.run_scan)
        layout.addWidget(self.scan_btn)
        # Progress Bar
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        # Splitter for output (resizable)
        self.splitter = QSplitter(Qt.Vertical)
        layout.addWidget(self.splitter)
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color:#1e1e1e; color:#d4d4d4;")
        self.splitter.addWidget(self.output)
        self.highlighter = ASMSyntaxHighlighter(self.output.document())
    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select ASM/Binary File")
        if path:
            self.file_path_edit.setText(path)
    def browse_log(self):
        path, _ = QFileDialog.getSaveFileName(self, "Select Log File")
        if path:
            self.log_path_edit.setText(path)
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            self.file_path_edit.setText(urls[0].toLocalFile())
    def run_scan(self):
        path = self.file_path_edit.text().strip()
        if not path or not os.path.exists(path):
            self.output.setPlainText("Error: File does not exist.")
            return
        mode = "asm" if self.mode_asm.isChecked() else "bin"
        verbose = self.verbose_cb.isChecked()
        log_path = self.log_path_edit.text().strip()
        self.scan_btn.setEnabled(False)
        self.output.clear()
        self.progress.setValue(0)
        self.thread = ScanThread(path, mode, verbose, log_path)
        self.thread.progress.connect(self.progress.setValue)
        self.thread.finished.connect(self.display_results)
        self.thread.error.connect(self.display_error)
        self.thread.start()
    @Slot(list)
    def display_results(self, issues):
        if not issues:
            self.output.setPlainText("No potential vulnerabilities found.")
        else:
            self.output.setPlainText("\n".join(issues))
        self.scan_btn.setEnabled(True)
    @Slot(str)
    def display_error(self, msg):
        self.output.setPlainText(f"Error: {msg}")
        self.scan_btn.setEnabled(True)
if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Dark mode
    app.setStyleSheet("""
        QMainWindow { background-color: #1e1e1e; color: #d4d4d4; }
        QPushButton { background-color: #2b7cff; color: white; }
        QLineEdit { background-color: #2e2e2e; color: #d4d4d4; }
        QRadioButton, QCheckBox { color: #d4d4d4; }
        QProgressBar { background-color: #2e2e2e; color: #d4d4d4; }
    """)
    window = ASMScannerGUI()
    window.show()
    sys.exit(app.exec())
"""
1. Install Python 3
python3 --version
If Python 3 is missing or too old:
sudo apt update
sudo apt install python3 python3-pip
2. Install Required Python Packages
The script uses PySide6. Install it via pip:
python3 -m pip install --upgrade pip
python3 -m pip install PySide6
Optionally, if you want to run the scanner on binaries, ensure binutils is installed (for objdump):
sudo apt install binutils
3. Save the Python Script
Open your text editor (e.g., VSCode, gedit, nano).
Copy the PySide6 script I provided.
Save it as:
asm_scanner_gui.py
4. Make the Script Executable (Optional)
chmod +x asm_scanner_gui.py
5. Run the Application
python3 asm_scanner_gui.py
"""
