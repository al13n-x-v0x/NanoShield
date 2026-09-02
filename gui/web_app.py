"""
NanoShield Web GUI
Local browser-based security scanner interface.
Run: python gui/web_app.py
"""
import os, sys, json, re
from flask import Flask, render_template_string, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.model import NanoShield, ModelConfig

app = Flask(__name__)

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


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NanoShield - Security Scanner</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0e17; color: #e0e0e0; min-height: 100vh; }
  .header { background: linear-gradient(135deg, #0d1321, #1a1f35); border-bottom: 1px solid #2a3050; padding: 20px 40px; display: flex; align-items: center; gap: 16px; }
  .header h1 { font-size: 28px; font-weight: 700; background: linear-gradient(90deg, #00d4ff, #7b2fff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .header .badge { background: #1a3a2a; color: #00ff88; font-size: 11px; padding: 4px 10px; border-radius: 20px; border: 1px solid #00ff8844; }
  .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
  .panel { background: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
  .panel h2 { font-size: 16px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }
  textarea { width: 100%; height: 300px; background: #0a0e17; border: 1px solid #2a3050; border-radius: 8px; color: #e2e8f0; font-family: 'Fira Code', 'Consolas', monospace; font-size: 14px; padding: 16px; resize: vertical; outline: none; }
  textarea:focus { border-color: #7b2fff; }
  .btn-row { display: flex; gap: 12px; margin-top: 16px; }
  .btn { padding: 12px 28px; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
  .btn-primary { background: linear-gradient(135deg, #7b2fff, #00d4ff); color: white; }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 4px 20px #7b2fff44; }
  .btn-secondary { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
  .btn-secondary:hover { background: #334155; color: white; }
  .results { margin-top: 20px; }
  .finding { background: #1a0a0a; border: 1px solid #3b1515; border-left: 4px solid #ef4444; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
  .finding.medium { background: #1a1a0a; border-color: #3b3515; border-left-color: #eab308; }
  .finding .type { font-weight: 700; font-size: 15px; margin-bottom: 6px; }
  .finding .line { color: #94a3b8; font-size: 13px; margin-bottom: 4px; }
  .finding .fix { color: #22c55e; font-size: 13px; }
  .stat-row { display: flex; gap: 20px; margin-bottom: 20px; }
  .stat { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 16px 24px; flex: 1; text-align: center; }
  .stat .num { font-size: 32px; font-weight: 800; }
  .stat .label { color: #64748b; font-size: 12px; text-transform: uppercase; margin-top: 4px; }
  .stat.safe .num { color: #22c55e; }
  .stat.warn .num { color: #eab308; }
  .stat.danger .num { color: #ef4444; }
  .safe-msg { text-align: center; padding: 40px; color: #22c55e; font-size: 18px; }
  .footer { text-align: center; padding: 30px; color: #475569; font-size: 13px; }
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ NanoShield</h1>
  <span class="badge">LOCAL · PRIVATE · OFFLINE</span>
</div>
<div class="container">
  <div class="panel">
    <h2>📝 Paste Code to Scan</h2>
    <textarea id="codeInput" placeholder="Paste your Python, JavaScript, C, or any source code here...">import sqlite3
conn = sqlite3.connect("users.db")
username = request.args.get("user")
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)

password = "admin123"
api_key = "sk-1234567890abcdef"

import hashlib
hash = md5(password.encode()).hexdigest()

os.system("cat " + filename)</textarea>
    <div class="btn-row">
      <button class="btn btn-primary" onclick="scanCode()">🔍 Scan for Vulnerabilities</button>
      <button class="btn btn-secondary" onclick="document.getElementById('codeInput').value=''">Clear</button>
    </div>
  </div>

  <div id="stats" class="stat-row" style="display:none;"></div>
  <div id="results" class="results"></div>
</div>
<div class="footer">NanoShield v0.1.0 · On-device security assistant · No data leaves your machine</div>

<script>
async function scanCode() {
  const code = document.getElementById('codeInput').value;
  const res = await fetch('/scan', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({code}) });
  const data = await res.json();
  const high = data.findings.filter(f => f.severity === 'HIGH').length;
  const med = data.findings.filter(f => f.severity === 'MEDIUM').length;

  const stats = document.getElementById('stats');
  stats.style.display = 'flex';
  stats.innerHTML = `
    <div class="stat danger"><div class="num">${high}</div><div class="label">High Severity</div></div>
    <div class="stat warn"><div class="num">${med}</div><div class="label">Medium Severity</div></div>
    <div class="stat safe"><div class="num">${data.findings.length === 0 ? '✓' : data.findings.length}</div><div class="label">${data.findings.length === 0 ? 'All Clear' : 'Total Issues'}</div></div>
  `;

  const results = document.getElementById('results');
  if (data.findings.length === 0) {
    results.innerHTML = '<div class="safe-msg">✅ No vulnerabilities detected. Code looks secure!</div>';
  } else {
    results.innerHTML = data.findings.map(f => `
      <div class="finding ${f.severity === 'MEDIUM' ? 'medium' : ''}">
        <div class="type">${f.severity === 'HIGH' ? '🔴' : '🟡'} ${f.type}</div>
        <div class="line">Line ${f.line}: <code>${f.match}</code></div>
        <div class="fix">💡 Fix: ${f.explanation}</div>
      </div>
    `).join('');
  }
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/scan", methods=["POST"])
def scan():
    code = request.json.get("code", "")
    findings = scan_code(code)
    return jsonify({"findings": findings, "count": len(findings)})

if __name__ == "__main__":
    print("NanoShield Web GUI starting at http://localhost:5000")
    app.run(debug=True, port=5000)
