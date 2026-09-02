"""
NanoShield Desktop GUI
Native Tkinter application for offline code security scanning.
Run: python gui/desktop_app.py
"""
import os, sys, re, tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

VULNERABILITY_PATTERNS = {
    "SQL Injection": [r"execute\s*\(.*\+\s*", r"query\s*\(.*%s", r"cursor\.execute\s*\(.+format"],
    "XSS": [r"innerHTML\s*=", r"document\.write\s*\(", r"eval\s*\(\s*req\."],
    "Hardcoded Credentials": [r'password\s*=\s*["\'][^"\']+["\']', r'api_key\s*=\s*["\'][^"\']+["\']', r'secret\s*=\s*["\'][^"\']+["\']'],
    "Weak Crypto": [r"md5\(", r"sha1\(", r"DES\.", r"RC4"],
    "Command Injection": [r"os\.system\s*\(", r"subprocess\.call\s*\(.*shell\s*=\s*True", r"eval\s*\(\s*input"],
    "Path Traversal": [r"open\s*\(.*\.\./", r"os\.path\.join\s*\(.*\.\."],
    "Buffer Overflow Risk": [r"strcpy\s*\(", r"gets\s*\(", r"sprintf\s*\("],
    "Insecure Deserialization": [r"pickle\.loads?\s*\(", r"yaml\.load\s*\((?!.*Loader)"],
    "Race Condition": [r"global\s+\w+.*\n.*\w+\s*=\s*\w+\s*\+"],
}

SECURITY_EXPLANATIONS = {
    "SQL Injection": "Use parameterized queries or ORM binding.",
    "XSS": "Encode output and use CSP headers.",
    "Hardcoded Credentials": "Use environment variables or a vault service.",
    "Weak Crypto": "Migrate to SHA-256+ / AES-256.",
    "Command Injection": "Use subprocess with list args, not shell=True.",
    "Path Traversal": "Validate and sanitize file paths with os.path.realpath.",
    "Buffer Overflow Risk": "Use strncpy/snprintf or safer languages.",
    "Insecure Deserialization": "Use yaml.safe_load or json.loads.",
    "Race Condition": "Use locks or atomic operations.",
}


def scan_code(code):
    findings = []
    for vuln, patterns in VULNERABILITY_PATTERNS.items():
        for pattern in patterns:
            for m in re.finditer(pattern, code, re.MULTILINE):
                line_num = code[: m.start()].count("\n") + 1
                findings.append({
                    "type": vuln,
                    "severity": "HIGH" if vuln in ["SQL Injection", "Command Injection", "Hardcoded Credentials"] else "MEDIUM",
                    "line": line_num,
                    "match": m.group()[:80],
                    "explanation": SECURITY_EXPLANATIONS.get(vuln, ""),
                })
    return findings


class NanoShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NanoShield - Security Scanner")
        self.root.geometry("900x750")
        self.root.configure(bg="#0a0e17")
        self.root.resizable(True, True)

        # Header
        header = tk.Frame(root, bg="#0d1321", pady=12, padx=20)
        header.pack(fill=tk.X)
        tk.Label(header, text="🛡️ NanoShield", font=("Segoe UI", 22, "bold"),
                 fg="#00d4ff", bg="#0d1321").pack(side=tk.LEFT)
        tk.Label(header, text=" LOCAL · PRIVATE · OFFLINE ", font=("Segoe UI", 9),
                 fg="#00ff88", bg="#1a3a2a", padx=8, pady=2).pack(side=tk.LEFT, padx=10)

        # Main container
        main = tk.Frame(root, bg="#0a0e17", padx=20, pady=15)
        main.pack(fill=tk.BOTH, expand=True)

        # Input section
        input_frame = tk.Frame(main, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        tk.Label(input_frame, text="📝 SOURCE CODE", font=("Segoe UI", 10, "bold"),
                 fg="#94a3b8", bg="#111827", anchor="w", padx=12, pady=(8, 0)).pack(fill=tk.X)

        self.code_input = scrolledtext.ScrolledText(
            input_frame, bg="#0a0e17", fg="#e2e8f0", insertbackground="#e2e8f0",
            font=("Consolas", 12), relief=tk.FLAT, padx=12, pady=8,
            selectbackground="#7b2fff44", wrap=tk.WORD
        )
        self.code_input.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 8))
        self.code_input.insert(tk.END, 'import sqlite3\nconn = sqlite3.connect("users.db")\nusername = request.args.get("user")\nquery = "SELECT * FROM users WHERE name = \'" + username + "\'"\ncursor.execute(query)\n\npassword = "admin123"\napi_key = "sk-1234567890abcdef"\n\nimport hashlib\nhash = md5(password.encode()).hexdigest()\n\nos.system("cat " + filename)')

        # Buttons
        btn_frame = tk.Frame(main, bg="#0a0e17")
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        self.scan_btn = tk.Button(
            btn_frame, text="🔍  Scan for Vulnerabilities", font=("Segoe UI", 12, "bold"),
            bg="#7b2fff", fg="white", activebackground="#6b1fee", relief=tk.FLAT,
            padx=20, pady=10, cursor="hand2", command=self.scan_code
        )
        self.scan_btn.pack(side=tk.LEFT)

        tk.Button(
            btn_frame, text="📂 Open File", font=("Segoe UI", 11),
            bg="#1e293b", fg="#94a3b8", activebackground="#334155", relief=tk.FLAT,
            padx=16, pady=10, cursor="hand2", command=self.open_file
        ).pack(side=tk.LEFT, padx=8)

        tk.Button(
            btn_frame, text="Clear", font=("Segoe UI", 11),
            bg="#1e293b", fg="#94a3b8", activebackground="#334155", relief=tk.FLAT,
            padx=16, pady=10, cursor="hand2",
            command=lambda: self.code_input.delete("1.0", tk.END)
        ).pack(side=tk.LEFT)

        # Stats row
        self.stats_frame = tk.Frame(main, bg="#0a0e17")
        self.stats_frame.pack(fill=tk.X, pady=(0, 10))

        # Results section
        results_frame = tk.Frame(main, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        results_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(results_frame, text="📋 SCAN RESULTS", font=("Segoe UI", 10, "bold"),
                 fg="#94a3b8", bg="#111827", anchor="w", padx=12, pady=(8, 0)).pack(fill=tk.X)

        self.results_text = scrolledtext.ScrolledText(
            results_frame, bg="#0a0e17", fg="#e2e8f0",
            font=("Consolas", 11), relief=tk.FLAT, padx=12, pady=8,
            state=tk.DISABLED, wrap=tk.WORD
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 8))

        self.setup_tags()

    def setup_tags(self):
        self.results_text.tag_configure("high", foreground="#ef4444", font=("Consolas", 12, "bold"))
        self.results_text.tag_configure("medium", foreground="#eab308", font=("Consolas", 12, "bold"))
        self.results_text.tag_configure("safe", foreground="#22c55e", font=("Consolas", 13, "bold"))
        self.results_text.tag_configure("fix", foreground="#22c55e", font=("Consolas", 10))
        self.results_text.tag_configure("line", foreground="#94a3b8", font=("Consolas", 10))
        self.results_text.tag_configure("header", foreground="#7b2fff", font=("Consolas", 11, "bold"))

    def open_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Python", "*.py"), ("JavaScript", "*.js"), ("C", "*.c *.h"),
                       ("All Files", "*.*")]
        )
        if path:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self.code_input.delete("1.0", tk.END)
                self.code_input.insert(tk.END, f.read())

    def scan_code(self):
        code = self.code_input.get("1.0", tk.END)
        findings = scan_code(code)

        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)

        high = sum(1 for f in findings if f["severity"] == "HIGH")
        med = sum(1 for f in findings if f["severity"] == "MEDIUM")

        if not findings:
            self.results_text.insert(tk.END, "✅ No vulnerabilities detected. Code looks secure!\n", "safe")
        else:
            self.results_text.insert(tk.END, f"⚠️  Found {len(findings)} issue(s): {high} HIGH · {med} MEDIUM\n\n", "header")
            for f in findings:
                tag = "high" if f["severity"] == "HIGH" else "medium"
                icon = "🔴" if f["severity"] == "HIGH" else "🟡"
                self.results_text.insert(tk.END, f"{icon} [{f['severity']}] {f['type']}\n", tag)
                self.results_text.insert(tk.END, f"   Line {f['line']}: {f['match']}\n", "line")
                self.results_text.insert(tk.END, f"   💡 {f['explanation']}\n\n", "fix")

        self.results_text.config(state=tk.DISABLED)

        # Update stats
        for w in self.stats_frame.winfo_children():
            w.destroy()
        for label, val, color in [("HIGH", high, "#ef4444"), ("MEDIUM", med, "#eab308"), ("TOTAL", len(findings), "#00d4ff")]:
            f = tk.Frame(self.stats_frame, bg="#111827", padx=16, pady=8)
            f.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=4)
            tk.Label(f, text=str(val), font=("Segoe UI", 24, "bold"), fg=color, bg="#111827").pack()
            tk.Label(f, text=label, font=("Segoe UI", 9), fg="#64748b", bg="#111827").pack()


if __name__ == "__main__":
    root = tk.Tk()
    app = NanoShieldApp(root)
    root.mainloop()
