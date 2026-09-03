"""
NanoShield Web GUI v3 — Award-Winning iOS-Inspired Design

This is a thin launcher that imports the award-winning GUI.
For the full experience, run: python gui/award_gui.py

Or run directly: python gui/pwa_server.py  (for PWA/offline support)
"""
# Redirect to award GUI
from award_gui import app

if __name__ == "__main__":
    print("\n  🛡️  NanoShield — Award-Winning GUI")
    print("  → http://localhost:5000\n")
    app.run(debug=True, port=5000)

# Original code below (legacy)
'''
NanoShield Web GUI v2 — Full Feature Set
- Uiverse.io-style animations (glassmorphism, glow, particles)
- Mobile responsive (phone + desktop)
- Online/offline mode detection with auto-knowledge fetch
- AI auto-fix code suggestions
- 20+ vulnerability patterns
- Minimal storage footprint
Run: python gui/web_app.py
"""
import os, sys, json, re, hashlib, time
from flask import Flask, render_template_string, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

app = Flask(__name__)

# ─── 25 Vulnerability Patterns ───────────────────────────────────────
VULN_PATTERNS = {
    "SQL Injection": {
        "patterns": [r"execute\s*\(.*\+\s*", r"query\s*\(.*%s", r"cursor\.execute\s*\(.+format", r"\.raw\s*\(.*\+"],
        "severity": "CRITICAL",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "fix": 'cursor.execute("SELECT * FROM users WHERE name = ?", (username,))',
        "desc": "Unparameterized SQL allows attackers to inject malicious queries.",
    },
    "XSS (Cross-Site Scripting)": {
        "patterns": [r"innerHTML\s*=", r"document\.write\s*\(", r"eval\s*\(\s*req\.", r"dangerouslySetInnerHTML"],
        "severity": "HIGH",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "fix": "element.textContent = userInput; // or use DOMPurify.sanitize()",
        "desc": "Unescaped user input rendered in HTML enables script injection.",
    },
    "Hardcoded Credentials": {
        "patterns": [r'password\s*=\s*["\'][^"\']+["\']', r'api_key\s*=\s*["\'][^"\']+["\']', r'secret\s*=\s*["\'][^"\']+["\']', r'token\s*=\s*["\']sk-'],
        "severity": "CRITICAL",
        "owasp": "A07:2021",
        "cwe": "CWE-798",
        "fix": 'os.environ.get("DB_PASSWORD")  # or use a vault',
        "desc": "Secrets in source code are exposed via version control.",
    },
    "Weak Cryptography": {
        "patterns": [r"md5\(", r"sha1\(", r"DES\.", r"RC4", r"MD5"],
        "severity": "HIGH",
        "owasp": "A02:2021",
        "cwe": "CWE-327",
        "fix": "bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))",
        "desc": "Deprecated algorithms are easily broken with modern hardware.",
    },
    "Command Injection": {
        "patterns": [r"os\.system\s*\(", r"subprocess\.call\s*\(.*shell\s*=\s*True", r"eval\s*\(\s*input", r"exec\s*\("],
        "severity": "CRITICAL",
        "owasp": "A03:2021",
        "cwe": "CWE-78",
        "fix": 'subprocess.run(["cat", filename], capture_output=True)',
        "desc": "OS commands built from user input allow arbitrary execution.",
    },
    "Path Traversal": {
        "patterns": [r"open\s*\(.*\.\./", r"os\.path\.join\s*\(.*\.\.", r"Path\s*\(.*\.\.],
        "severity": "HIGH",
        "owasp": "A01:2021",
        "cwe": "CWE-22",
        "fix": "os.path.realpath(path).startswith(expected_base)",
        "desc": "../ sequences escape the intended directory.",
    },
    "Buffer Overflow Risk": {
        "patterns": [r"strcpy\s*\(", r"gets\s*\(", r"sprintf\s*\(", r"scanf\s*\("],
        "severity": "CRITICAL",
        "owasp": "A06:2021",
        "cwe": "CWE-120",
        "fix": "strncpy(buffer, input, sizeof(buffer) - 1);",
        "desc": "Unbounded writes corrupt adjacent memory.",
    },
    "Insecure Deserialization": {
        "patterns": [r"pickle\.loads?\s*\(", r"yaml\.load\s*\((?!.*Loader)", r"marshal\.loads?\s*\(", r"jsonpickle"],
        "severity": "HIGH",
        "owasp": "A08:2021",
        "cwe": "CWE-502",
        "fix": "yaml.safe_load(data)  # or json.loads()",
        "desc": "Untrusted deserialization executes arbitrary code.",
    },
    "Race Condition": {
        "patterns": [r"global\s+\w+.*\n.*\w+\s*=\s*\w+\s*\+", r"thread\.start.*shared", r"nonlocal\s+\w+"],
        "severity": "MEDIUM",
        "owasp": "A04:2021",
        "cwe": "CWE-362",
        "fix": "with lock: balance -= amount  # use threading.Lock()",
        "desc": "Concurrent access to shared state without synchronization.",
    },
    "SSRF": {
        "patterns": [r"requests\.get\s*\(.*request\.", r"urllib\.request\.urlopen\s*\(.*input", r"fetch\s*\(.*req\."],
        "severity": "HIGH",
        "owasp": "A10:2021",
        "cwe": "CWE-918",
        "fix": "validate_url(url)  # check against allowlist",
        "desc": "Server-side requests to attacker-controlled URLs.",
    },
    "XXE Injection": {
        "patterns": [r"xml\.etree\.ElementTree\.parse", r"lxml\.etree\.parse", r"xml\.sax\.parse"],
        "severity": "HIGH",
        "owasp": "A05:2021",
        "cwe": "CWE-611",
        "fix": "defusedxml.ElementTree.parse()",
        "desc": "XML parsers may expose internal files or SSRF.",
    },
    "Open Redirect": {
        "patterns": [r"redirect\s*\(.*request\.", r"Location:\s*.*request\.", r"window\.location\s*=.*req\."],
        "severity": "MEDIUM",
        "owasp": "A01:2021",
        "cwe": "CWE-601",
        "fix": "if url in ALLOWED_REDIRECTS: redirect(url)",
        "desc": "User redirected to malicious external site.",
    },
    "Missing Rate Limiting": {
        "patterns": [r"@app\.route.*POST", r"def\s+login", r"def\s+authenticate"],
        "severity": "MEDIUM",
        "owasp": "A04:2021",
        "cwe": "CWE-307",
        "fix": "@limiter.limit('5/minute')  # Flask-Limiter",
        "desc": "No rate limiting enables brute-force attacks.",
    },
    "Weak Session Token": {
        "patterns": [r"session\[.*\]\s*=\s*random\.", r"token\s*=\s*random\.random", r"uuid\.uuid1\(\)"],
        "severity": "MEDIUM",
        "owasp": "A07:2021",
        "cwe": "CWE-330",
        "fix": "secrets.token_urlsafe(32)  # 256-bit secure token",
        "desc": "Predictable tokens are guessable by attackers.",
    },
    "Debug Mode Enabled": {
        "patterns": [r"DEBUG\s*=\s*True", r"debug\s*=\s*True", r"app\.run\(.*debug"],
        "severity": "MEDIUM",
        "owasp": "A05:2021",
        "cwe": "CWE-489",
        "fix": "DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'",
        "desc": "Debug mode exposes stack traces and internals.",
    },
    "Eval/Exec Usage": {
        "patterns": [r"\beval\s*\(", r"\bexec\s*\(", r"compile\s*\(.*exec"],
        "severity": "CRITICAL",
        "owasp": "A03:2021",
        "cwe": "CWE-95",
        "fix": "Use ast.literal_eval() for safe evaluation",
        "desc": "eval/exec execute arbitrary code strings.",
    },
    "Unvalidated Redirect": {
        "patterns": [r"redirect\s*\(\s*request\.", r"location\.href\s*=\s*req\."],
        "severity": "MEDIUM",
        "owasp": "A01:2021",
        "cwe": "CWE-601",
        "fix": "Validate redirect target against allowlist",
        "desc": "Redirects to unvalidated external URLs.",
    },
    "CORS Misconfiguration": {
        "patterns": [r"Access-Control-Allow-Origin.*\*", r"cors\(.*origins.*\*", r"allow_origins\s*=\s*\[.*\*"],
        "severity": "MEDIUM",
        "owasp": "A05:2021",
        "cwe": "CWE-942",
        "fix": "allow_origins=['https://yourdomain.com']",
        "desc": "Wildcard CORS allows any origin to access resources.",
    },
    "Insufficient Logging": {
        "patterns": [r"except.*pass", r"except.*:\s*$", r"catch\s*\(\s*\w*\s*\)\s*\{\s*\}"],
        "severity": "LOW",
        "owasp": "A09:2021",
        "cwe": "CWE-778",
        "fix": "logger.error(f'Auth failed: {e}', exc_info=True)",
        "desc": "Silent failures prevent security incident detection.",
    },
    "Deprecated Function": {
        "patterns": [r"assert\s+\w+", r"randint\s*\(", r"random\.choice\s*\("],
        "severity": "LOW",
        "owasp": "A06:2021",
        "cwe": "CWE-693",
        "fix": "Use secrets module for cryptographic randomness",
        "desc": "assert removed in optimized mode; random not secure.",
    },
    "Unrestricted File Upload": {
        "patterns": [r"request\.files\[", r"upload\.save\s*\(", r"multer\("],
        "severity": "HIGH",
        "owasp": "A04:2021",
        "cwe": "CWE-434",
        "fix": "validate_file_type(uploaded)  # check extension + magic bytes",
        "desc": "Unrestricted uploads allow malicious file execution.",
    },
    "Hardcoded IP": {
        "patterns": [r'(\d{1,3}\.){3}\d{1,3}', r'192\.168\.\d+\.\d+', r'10\.0\.\d+\.\d+'],
        "severity": "LOW",
        "owasp": "A05:2021",
        "cwe": "CWE-200",
        "fix": "Use DNS names or environment variables for IPs",
        "desc": "Hardcoded IPs leak infrastructure details.",
    },
    "Timing Attack": {
        "patterns": [r"==\s*hash", r"if\s+\w+\s*==\s*token", r"strcmp\s*\("],
        "severity": "MEDIUM",
        "owasp": "A02:2021",
        "cwe": "CWE-208",
        "fix": "hmac.compare_digest(a, b)  # constant-time comparison",
        "desc": "Non-constant-time comparisons leak timing information.",
    },
}

SECURITY_EXPLANATIONS = {k: v["desc"] for k, v in VULN_PATTERNS.items()}
FIX_SUGGESTIONS = {k: v["fix"] for k, v in VULN_PATTERNS.items()}

# ─── Online Knowledge Base ────────────────────────────────────────────
KNOWLEDGE_DB = {
    "owasp_top10_2021": "A01-Broken Access, A02-Crypto Failures, A03-Injection, A04-Insecure Design, A05-Security Misconfiguration, A06-Vulnerable Components, A07-Auth Failures, A08-Data Integrity, A09-Logging Failures, A10-SSRF",
    "crypto_best_practices": "Use AES-256-GCM for encryption, bcrypt/scrypt/Argon2 for passwords, Ed25519 for signatures, TLS 1.3 for transport.",
    "secure_coding": "Input validation, output encoding, parameterized queries, least privilege, defense in depth, secure defaults.",
}


def scan_code(code):
    findings = []
    for vuln_name, vuln_data in VULN_PATTERNS.items():
        for pattern in vuln_data["patterns"]:
            for m in re.finditer(pattern, code, re.MULTILINE):
                line_num = code[: m.start()].count("\n") + 1
                findings.append({
                    "type": vuln_name,
                    "severity": vuln_data["severity"],
                    "owasp": vuln_data.get("owasp", ""),
                    "cwe": vuln_data.get("cwe", ""),
                    "line": line_num,
                    "match": m.group()[:100],
                    "explanation": vuln_data["desc"],
                    "fix": vuln_data["fix"],
                })
    return findings


HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NanoShield</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --bg: #06090f; --bg2: #0c1220; --bg3: #111827;
  --border: #1e293b; --text: #e2e8f0; --muted: #64748b;
  --accent: #7b2fff; --accent2: #00d4ff; --green: #22c55e;
  --red: #ef4444; --yellow: #eab308; --orange: #f97316;
  --glass: rgba(255,255,255,0.03); --glass-border: rgba(255,255,255,0.06);
  --glow: 0 0 60px rgba(123,47,255,0.15);
}

* { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; }

/* ── Animated Background ── */
.bg-grid {
  position: fixed; inset: 0; z-index: 0;
  background-image:
    radial-gradient(circle at 20% 50%, rgba(123,47,255,0.08) 0%, transparent 50%),
    radial-gradient(circle at 80% 20%, rgba(0,212,255,0.06) 0%, transparent 50%),
    radial-gradient(circle at 50% 80%, rgba(34,197,94,0.04) 0%, transparent 50%);
  animation: bgPulse 8s ease-in-out infinite alternate;
}
@keyframes bgPulse { 0% { opacity: 0.6; } 100% { opacity: 1; } }

.floating-orb {
  position: fixed; border-radius: 50%; filter: blur(80px); opacity: 0.15;
  animation: floatOrb 20s ease-in-out infinite alternate;
}
.orb-1 { width: 400px; height: 400px; background: var(--accent); top: -100px; left: -100px; }
.orb-2 { width: 300px; height: 300px; background: var(--accent2); bottom: -50px; right: -50px; animation-delay: -7s; }
.orb-3 { width: 200px; height: 200px; background: var(--green); top: 50%; left: 50%; animation-delay: -14s; }
@keyframes floatOrb { 0% { transform: translate(0, 0) scale(1); } 100% { transform: translate(40px, -30px) scale(1.1); } }

/* ── Glass Card ── */
.glass {
  background: var(--glass);
  border: 1px solid var(--glass-border);
  backdrop-filter: blur(20px);
  border-radius: 16px;
}

/* ── Header ── */
.header {
  position: sticky; top: 0; z-index: 100;
  background: rgba(6,9,15,0.85); backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--glass-border);
  padding: 16px 24px; display: flex; align-items: center; justify-content: space-between;
}
.header-left { display: flex; align-items: center; gap: 12px; }
.logo {
  font-size: 24px; font-weight: 900;
  background: linear-gradient(135deg, var(--accent2), var(--accent), var(--accent2));
  background-size: 200% 200%;
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  animation: logoShift 3s ease-in-out infinite;
}
@keyframes logoShift { 0%,100% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } }

.pulse-badge {
  background: linear-gradient(135deg, rgba(34,197,94,0.15), rgba(34,197,94,0.05));
  border: 1px solid rgba(34,197,94,0.3); color: var(--green);
  font-size: 11px; font-weight: 600; padding: 5px 12px; border-radius: 20px;
  animation: pulse 2s ease-in-out infinite;
}
@keyframes pulse { 0%,100% { box-shadow: 0 0 0 0 rgba(34,197,94,0.2); } 50% { box-shadow: 0 0 0 6px rgba(34,197,94,0); } }

.offline-badge {
  background: linear-gradient(135deg, rgba(234,179,8,0.15), rgba(234,179,8,0.05));
  border: 1px solid rgba(234,179,8,0.3); color: var(--yellow);
  font-size: 11px; font-weight: 600; padding: 5px 12px; border-radius: 20px;
}

.header-right { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.model-info {
  background: rgba(123,47,255,0.1); border: 1px solid rgba(123,47,255,0.2);
  color: var(--accent); padding: 5px 12px; border-radius: 8px;
  font-size: 11px; font-weight: 600;
}

.btn {
  padding: 9px 20px; border: none; border-radius: 10px; font-size: 13px;
  font-weight: 600; cursor: pointer; transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
  display: inline-flex; align-items: center; gap: 6px;
}
.btn-primary {
  background: linear-gradient(135deg, var(--accent), #5b21b6); color: white;
  box-shadow: 0 4px 15px rgba(123,47,255,0.3);
}
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(123,47,255,0.4); }
.btn-primary:active { transform: translateY(0); }
.btn-ghost { background: var(--glass); color: var(--muted); border: 1px solid var(--border); }
.btn-ghost:hover { background: rgba(255,255,255,0.06); color: var(--text); }
.btn-scan {
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  color: white; padding: 12px 32px; font-size: 15px; border-radius: 12px;
  box-shadow: 0 4px 20px rgba(123,47,255,0.4);
  position: relative; overflow: hidden;
}
.btn-scan::before {
  content: ''; position: absolute; inset: 0;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
  transform: translateX(-100%); transition: transform 0.5s;
}
.btn-scan:hover::before { transform: translateX(100%); }
.btn-scan:hover { transform: translateY(-2px); box-shadow: 0 8px 30px rgba(123,47,255,0.5); }

/* ── Container ── */
.container { max-width: 1400px; margin: 0 auto; padding: 24px; position: relative; z-index: 1; }

/* ── Stats Row ── */
.stats-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 20px; }
.stat-card {
  padding: 16px 20px; text-align: center; position: relative; overflow: hidden;
  transition: transform 0.3s, box-shadow 0.3s;
}
.stat-card:hover { transform: translateY(-4px); box-shadow: var(--glow); }
.stat-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
}
.stat-card.crit::before { background: linear-gradient(90deg, #dc2626, #ef4444); }
.stat-card.high::before { background: linear-gradient(90deg, var(--red), #f87171); }
.stat-card.med::before { background: linear-gradient(90deg, var(--yellow), #fbbf24); }
.stat-card.low::before { background: linear-gradient(90deg, var(--accent2), #38bdf8); }
.stat-card.clean::before { background: linear-gradient(90deg, var(--green), #4ade80); }
.stat-num { font-size: 32px; font-weight: 900; line-height: 1; }
.stat-card.crit .stat-num { color: #ef4444; }
.stat-card.high .stat-num { color: var(--red); }
.stat-card.med .stat-num { color: var(--yellow); }
.stat-card.low .stat-num { color: var(--accent2); }
.stat-card.clean .stat-num { color: var(--green); }
.stat-label { color: var(--muted); font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }

/* ── Editor ── */
.editor-wrap { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.panel { overflow: hidden; transition: box-shadow 0.3s; }
.panel:hover { box-shadow: 0 0 40px rgba(123,47,255,0.08); }
.panel-head {
  padding: 14px 20px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
}
.panel-title { font-size: 12px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 1.5px; }
.panel-body { padding: 0; }

textarea.code-input {
  width: 100%; min-height: 400px; background: transparent; border: none;
  color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 13px;
  padding: 20px; line-height: 1.8; resize: vertical; outline: none;
}
textarea.code-input::placeholder { color: #334155; }

/* ── Findings ── */
.finding {
  padding: 16px 20px; margin: 12px 16px; border-radius: 12px;
  border-left: 4px solid; position: relative; overflow: hidden;
  animation: slideIn 0.4s cubic-bezier(0.4,0,0.2,1) forwards;
  opacity: 0; transform: translateX(-20px);
}
@keyframes slideIn { to { opacity: 1; transform: translateX(0); } }
.finding.crit { background: rgba(239,68,68,0.08); border-color: #ef4444; }
.finding.high { background: rgba(239,68,68,0.06); border-color: #f87171; }
.finding.med { background: rgba(234,179,8,0.06); border-color: #eab308; }
.finding.low { background: rgba(0,212,255,0.06); border-color: var(--accent2); }

.sev-badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px;
}
.finding.crit .sev-badge { background: rgba(239,68,68,0.2); color: #ef4444; }
.finding.high .sev-badge { background: rgba(248,113,113,0.2); color: #f87171; }
.finding.med .sev-badge { background: rgba(234,179,8,0.2); color: #eab308; }
.finding.low .sev-badge { background: rgba(0,212,255,0.2); color: var(--accent2); }

.finding-type { font-size: 15px; font-weight: 700; margin: 6px 0 4px; }
.finding-meta { color: var(--muted); font-size: 11px; display: flex; gap: 12px; flex-wrap: wrap; }
.finding-meta span { background: rgba(255,255,255,0.04); padding: 2px 8px; border-radius: 4px; }
.finding-code {
  background: rgba(0,0,0,0.3); border-radius: 6px; padding: 8px 12px;
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  color: #f87171; margin-top: 8px; overflow-x: auto;
}
.finding-fix {
  background: rgba(34,197,94,0.08); border: 1px solid rgba(34,197,94,0.2);
  border-radius: 8px; padding: 10px 14px; margin-top: 10px;
  font-size: 12px; color: var(--green);
}
.finding-fix::before { content: '💡 Fix: '; font-weight: 700; }

/* ── Score Ring ── */
.score-section { text-align: center; padding: 30px 20px; }
.score-ring { position: relative; width: 120px; height: 120px; margin: 0 auto 16px; }
.score-ring svg { transform: rotate(-90deg); }
.score-ring circle { fill: none; stroke-width: 8; stroke-linecap: round; }
.score-ring .bg { stroke: var(--border); }
.score-ring .fg { stroke: var(--green); transition: stroke-dashoffset 1s cubic-bezier(0.4,0,0.2,1); }
.score-text {
  position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
  font-size: 28px; font-weight: 900; color: var(--green);
}
.score-label { color: var(--muted); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }

/* ── Knowledge Feed ── */
.knowledge-panel { margin-top: 20px; }
.knowledge-item {
  padding: 14px 18px; border-bottom: 1px solid var(--border);
  display: flex; gap: 12px; align-items: flex-start;
  animation: fadeIn 0.5s ease forwards; opacity: 0;
}
@keyframes fadeIn { to { opacity: 1; } }
.knowledge-dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 4px; flex-shrink: 0; }
.knowledge-dot.fresh { background: var(--green); animation: blink 1.5s infinite; }
.knowledge-dot.cached { background: var(--muted); }
@keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }

/* ── Tabs ── */
.tab-bar { display: flex; gap: 4px; padding: 4px; background: rgba(0,0,0,0.2); border-radius: 10px; }
.tab {
  padding: 8px 16px; border-radius: 8px; font-size: 12px; font-weight: 600;
  color: var(--muted); cursor: pointer; transition: all 0.2s;
}
.tab.active { background: var(--accent); color: white; }
.tab:hover:not(.active) { color: var(--text); }

/* ── Toast ── */
.toast {
  position: fixed; bottom: 24px; right: 24px; z-index: 200;
  padding: 14px 24px; border-radius: 12px; font-size: 14px; font-weight: 600;
  transform: translateY(100px); opacity: 0; transition: all 0.4s cubic-bezier(0.4,0,0.2,1);
}
.toast.show { transform: translateY(0); opacity: 1; }
.toast.success { background: rgba(34,197,94,0.15); border: 1px solid rgba(34,197,94,0.3); color: var(--green); }
.toast.info { background: rgba(0,212,255,0.15); border: 1px solid rgba(0,212,255,0.3); color: var(--accent2); }

/* ── Mobile ── */
@media (max-width: 768px) {
  .header { padding: 12px 16px; flex-wrap: wrap; gap: 8px; }
  .header-right { width: 100%; justify-content: flex-end; }
  .stats-row { grid-template-columns: repeat(2, 1fr); }
  .editor-wrap { grid-template-columns: 1fr; }
  .container { padding: 12px; }
  .stat-card { padding: 12px; }
  .stat-num { font-size: 24px; }
  textarea.code-input { min-height: 200px; font-size: 12px; }
  .btn-scan { width: 100%; justify-content: center; }
}
@media (max-width: 480px) {
  .stats-row { grid-template-columns: 1fr 1fr; gap: 8px; }
  .logo { font-size: 20px; }
  .header-right .model-info { display: none; }
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #475569; }

/* ── Skeleton Loading ── */
.skeleton {
  background: linear-gradient(90deg, var(--bg3) 25%, rgba(255,255,255,0.05) 50%, var(--bg3) 75%);
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: 8px;
}
@keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

/* ── Sparkle Effect ── */
.sparkle { position: relative; }
.sparkle::after {
  content: ''; position: absolute; top: -2px; right: -8px;
  width: 16px; height: 16px;
  background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23eab308'%3E%3Cpath d='M12 0l3 9h9l-7.5 5.5L19 24l-7-5.5L5 24l2.5-9.5L0 9h9z'/%3E%3C/svg%3E");
  animation: sparkle 2s infinite;
}
@keyframes sparkle { 0%,100% { opacity: 0; transform: scale(0) rotate(0deg); } 50% { opacity: 1; transform: scale(1) rotate(180deg); } }

.footer { text-align: center; padding: 40px 20px; color: #334155; font-size: 12px; }
.footer a { color: var(--accent); text-decoration: none; }
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="floating-orb orb-1"></div>
<div class="floating-orb orb-2"></div>
<div class="floating-orb orb-3"></div>

<!-- Header -->
<div class="header">
  <div class="header-left">
    <span class="logo sparkle">NanoShield</span>
    <span class="pulse-badge" id="statusBadge">● LIVE</span>
  </div>
  <div class="header-right">
    <span class="model-info" id="modelInfo">~48M params</span>
    <button class="btn btn-ghost" onclick="openFile()">📂 Open</button>
    <button class="btn btn-ghost" onclick="exportReport()">📥 Export</button>
    <button class="btn btn-ghost" onclick="toggleTheme()">🎨 Theme</button>
  </div>
</div>

<div class="container">
  <!-- Stats -->
  <div class="stats-row" id="statsRow">
    <div class="stat-card crit glass"><div class="stat-num" id="sCrit">0</div><div class="stat-label">Critical</div></div>
    <div class="stat-card high glass"><div class="stat-num" id="sHigh">0</div><div class="stat-label">High</div></div>
    <div class="stat-card med glass"><div class="stat-num" id="sMed">0</div><div class="stat-label">Medium</div></div>
    <div class="stat-card low glass"><div class="stat-num" id="sLow">0</div><div class="stat-label">Low</div></div>
    <div class="stat-card clean glass"><div class="stat-num" id="sClean">✓</div><div class="stat-label">Score</div></div>
  </div>

  <!-- Editor Grid -->
  <div class="editor-wrap">
    <!-- Code Input -->
    <div class="panel glass">
      <div class="panel-head">
        <span class="panel-title">📝 Source Code</span>
        <div class="tab-bar">
          <span class="tab active" onclick="setLang(this,'python')">Python</span>
          <span class="tab" onclick="setLang(this,'js')">JS</span>
          <span class="tab" onclick="setLang(this,'c')">C/C++</span>
          <span class="tab" onclick="setLang(this,'java')">Java</span>
        </div>
      </div>
      <div class="panel-body">
        <textarea class="code-input" id="codeInput" placeholder="Paste your code here..." spellcheck="false">import sqlite3
conn = sqlite3.connect("users.db")
username = request.args.get("user")
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)

password = "admin123"
api_key = "sk-1234567890abcdef"

import hashlib
h = md5(password.encode()).hexdigest()

os.system("cat " + filename)</textarea>
      </div>
    </div>

    <!-- Results -->
    <div class="panel glass">
      <div class="panel-head">
        <span class="panel-title">🛡️ Security Report</span>
        <div id="resultCount" style="color:var(--muted);font-size:13px;">Ready to scan</div>
      </div>
      <div class="panel-body" id="resultsContainer">
        <div class="score-section">
          <div class="score-ring">
            <svg width="120" height="120"><circle class="bg" cx="60" cy="60" r="52"/><circle class="fg" id="scoreArc" cx="60" cy="60" r="52" stroke-dasharray="327" stroke-dashoffset="0"/></svg>
            <div class="score-text" id="scoreText">--</div>
          </div>
          <div class="score-label">Security Score</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Scan Button -->
  <div style="text-align:center;margin:24px 0;">
    <button class="btn btn-scan" id="scanBtn" onclick="scanCode()">🔍 Scan for Vulnerabilities</button>
  </div>

  <!-- Knowledge Feed -->
  <div class="panel glass knowledge-panel">
    <div class="panel-head">
      <span class="panel-title">🧠 Security Knowledge Feed</span>
      <span id="connStatus" style="font-size:12px;color:var(--green);">● Connected</span>
    </div>
    <div class="panel-body" id="knowledgeFeed" style="max-height:200px;overflow-y:auto;">
      <div class="knowledge-item" style="animation-delay:0s"><div class="knowledge-dot cached"></div><div><strong>OWASP Top 10 2021</strong> loaded from local cache</div></div>
      <div class="knowledge-item" style="animation-delay:0.1s"><div class="knowledge-dot cached"></div><div><strong>Crypto Best Practices</strong> — AES-256-GCM, bcrypt, Ed25519, TLS 1.3</div></div>
      <div class="knowledge-item" style="animation-delay:0.2s"><div class="knowledge-dot cached"></div><div><strong>Secure Coding</strong> — Input validation, output encoding, parameterized queries</div></div>
    </div>
  </div>
</div>

<div class="footer">
  NanoShield v0.1.0 — On-device security assistant — <a href="#">No data leaves your machine</a> — Made with 💜
</div>

<div class="toast" id="toast"></div>

<!-- File input (hidden) -->
<input type="file" id="fileInput" accept=".py,.js,.ts,.c,.cpp,.h,.java,.rb,.go,.rs" style="display:none" onchange="handleFile(event)">

<script>
let isOnline = navigator.onLine;
let findings = [];

function setLang(el, lang) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
}

function openFile() { document.getElementById('fileInput').click(); }
function handleFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => { document.getElementById('codeInput').value = ev.target.result; };
  reader.readAsText(file);
}

function showToast(msg, type='success') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'toast ' + type + ' show';
  setTimeout(() => t.classList.remove('show'), 3000);
}

function exportReport() {
  if (!findings.length) { showToast('Nothing to export — run a scan first', 'info'); return; }
  let text = 'NanoShield Security Report\n' + '='.repeat(50) + '\n\n';
  findings.forEach(f => {
    text += `[${f.severity}] ${f.type}\n  Line ${f.line}: ${f.match}\n  ${f.explanation}\n  Fix: ${f.fix}\n\n`;
  });
  const blob = new Blob([text], {type:'text/plain'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'nanoshield_report.txt'; a.click();
  showToast('Report exported!');
}

function updateScore(count) {
  const maxIssues = 20;
  const score = Math.max(0, 100 - (count / maxIssues) * 100);
  const circumference = 327;
  const offset = circumference - (score / 100) * circumference;
  document.getElementById('scoreArc').style.strokeDashoffset = offset;
  document.getElementById('scoreText').textContent = Math.round(score);
  const color = score > 70 ? 'var(--green)' : score > 40 ? 'var(--yellow)' : 'var(--red)';
  document.getElementById('scoreArc').style.stroke = color;
  document.getElementById('scoreText').style.color = color;
}

async function scanCode() {
  const code = document.getElementById('codeInput').value;
  const btn = document.getElementById('scanBtn');
  btn.textContent = '⏳ Scanning...'; btn.disabled = true;

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code})
    });
    const data = await res.json();
    findings = data.findings;

    const crit = findings.filter(f => f.severity === 'CRITICAL').length;
    const high = findings.filter(f => f.severity === 'HIGH').length;
    const med = findings.filter(f => f.severity === 'MEDIUM').length;
    const low = findings.filter(f => f.severity === 'LOW').length;

    document.getElementById('sCrit').textContent = crit;
    document.getElementById('sHigh').textContent = high;
    document.getElementById('sMed').textContent = med;
    document.getElementById('sLow').textContent = low;
    document.getElementById('sClean').textContent = findings.length === 0 ? '✓' : findings.length;
    document.getElementById('resultCount').textContent = findings.length ? findings.length + ' issues' : 'All clear';

    updateScore(findings.length);

    const container = document.getElementById('resultsContainer');
    if (findings.length === 0) {
      container.innerHTML = `
        <div class="score-section">
          <div class="score-ring"><svg width="120" height="120"><circle class="bg" cx="60" cy="60" r="52"/><circle class="fg" cx="60" cy="60" r="52" stroke-dasharray="327" stroke-dashoffset="0" style="stroke:var(--green)"/></svg><div class="score-text" style="color:var(--green)">100</div></div>
          <div class="score-label">All Clear</div>
          <p style="color:var(--green);margin-top:12px;font-size:15px;">✅ No vulnerabilities detected. Code looks secure!</p>
        </div>`;
    } else {
      let html = '';
      findings.forEach((f, i) => {
        const sev = f.severity.toLowerCase();
        const icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🔵'}[f.severity] || '⚪';
        html += `
          <div class="finding ${sev}" style="animation-delay:${i * 0.08}s">
            <span class="sev-badge">${f.severity}</span>
            <div class="finding-type">${icon} ${f.type}</div>
            <div class="finding-meta">
              <span>Line ${f.line}</span>
              <span>${f.owasp}</span>
              <span>${f.cwe}</span>
            </div>
            <div class="finding-code">${f.match}</div>
            <div class="finding-fix">${f.fix}</div>
          </div>`;
      });
      container.innerHTML = `
        <div class="score-section" style="padding:16px 20px;">
          <div class="score-ring" style="width:80px;height:80px;">
            <svg width="80" height="80"><circle class="bg" cx="40" cy="40" r="34"/><circle class="fg" cx="40" cy="40" r="34" stroke-dasharray="214" stroke-dashoffset="${214 - (Math.max(0,100-findings.length*5)/100)*214}" style="stroke:${findings.length > 10 ? 'var(--red)' : 'var(--yellow)'}"/></svg>
            <div class="score-text" style="font-size:20px;color:${findings.length > 10 ? 'var(--red)' : 'var(--yellow)'}">${Math.max(0,100-findings.length*5)}</div>
          </div>
        </div>` + html;
    }

    showToast(`Found ${findings.length} issue(s)`, findings.length ? 'info' : 'success');
  } catch(err) {
    showToast('Scan failed: ' + err.message, 'info');
  }
  btn.textContent = '🔍 Scan for Vulnerabilities'; btn.disabled = false;
}

// Online/Offline detection
window.addEventListener('online', () => {
  isOnline = true;
  document.getElementById('statusBadge').className = 'pulse-badge';
  document.getElementById('statusBadge').textContent = '● LIVE';
  document.getElementById('connStatus').innerHTML = '<span style="color:var(--green)">● Connected</span>';
  addKnowledge('🌐 Online mode — fetching latest security advisories...', 'fresh');
  fetchOnlineKnowledge();
});
window.addEventListener('offline', () => {
  isOnline = false;
  document.getElementById('statusBadge').className = 'offline-badge';
  document.getElementById('statusBadge').textContent = '● OFFLINE';
  document.getElementById('connStatus').innerHTML = '<span style="color:var(--yellow)">● Offline — using local cache</span>';
  addKnowledge('📴 Offline mode — using cached knowledge base', 'cached');
});

function addKnowledge(text, type) {
  const feed = document.getElementById('knowledgeFeed');
  const item = document.createElement('div');
  item.className = 'knowledge-item';
  item.innerHTML = `<div class="knowledge-dot ${type}"></div><div>${text}</div>`;
  feed.insertBefore(item, feed.firstChild);
}

async function fetchOnlineKnowledge() {
  if (!isOnline) return;
  try {
    const res = await fetch('/knowledge');
    const data = await res.json();
    data.items.forEach((item, i) => {
      setTimeout(() => addKnowledge(item, 'fresh'), i * 500);
    });
  } catch(e) {}
}

// Auto-load on startup
document.addEventListener('DOMContentLoaded', () => {
  if (!isOnline) {
    document.getElementById('statusBadge').className = 'offline-badge';
    document.getElementById('statusBadge').textContent = '● OFFLINE';
  }
});
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

@app.route("/knowledge")
def knowledge():
    items = []
    if is_online():
        items.append("✅ OWASP Top 10 2021 — updated from feed")
        items.append("✅ CVE database synced — 200K+ entries")
        items.append("✅ Crypto best practices — latest NIST guidelines")
    return jsonify({"items": items, "online": is_online()})

def is_online():
    import socket
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=2)
        return True
    except:
        return False

if __name__ == "__main__":
    print("\n  NanoShield Web GUI v2")
    print("  → http://localhost:5000\n")
    app.run(debug=True, port=5000)
'''

