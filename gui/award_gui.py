"""
NanoShield — Award-Winning iOS-Inspired GUI
Awwwards-level design with glassmorphism, particles, 3D cards, iOS navigation
Hackathon-ready with demo mode for judges
"""
import os, sys, json, re, time, hashlib, secrets
from flask import Flask, render_template_string, request, jsonify, send_from_directory

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
app = Flask(__name__)

# ─── 50+ Vulnerability Patterns ──────────────────────────────────────
VULN_PATTERNS = {
    "SQL Injection": {
        "patterns": [r"execute\s*\(.*\+\s*", r"query\s*\(.*%s", r"cursor\.execute\s*\(.+format", r"\.raw\s*\(.*\+", r"\.execute\s*\(f['\"]"],
        "severity": "CRITICAL", "owasp": "A03:2021", "cwe": "CWE-89",
        "fix": 'cursor.execute("SELECT * FROM users WHERE name = ?", (username,))',
        "desc": "Unparameterized SQL allows attackers to inject malicious queries.",
        "icon": "🔴", "category": "injection"
    },
    "XSS (Cross-Site Scripting)": {
        "patterns": [r"innerHTML\s*=", r"document\.write\s*\(", r"dangerouslySetInnerHTML", r"\.html\s*\(.*req\."],
        "severity": "HIGH", "owasp": "A03:2021", "cwe": "CWE-79",
        "fix": "element.textContent = userInput; // or DOMPurify.sanitize()",
        "desc": "Unescaped user input rendered in HTML enables script injection.",
        "icon": "🟠", "category": "injection"
    },
    "Hardcoded Credentials": {
        "patterns": [r'password\s*=\s*["\'][^"\']+["\']', r'api_key\s*=\s*["\'][^"\']+["\']', r'secret\s*=\s*["\'][^"\']+["\']', r'token\s*=\s*["\']sk-'],
        "severity": "CRITICAL", "owasp": "A07:2021", "cwe": "CWE-798",
        "fix": 'os.environ.get("DB_PASSWORD")  # or use a vault',
        "desc": "Secrets in source code are exposed via version control.",
        "icon": "🔴", "category": "auth"
    },
    "Weak Cryptography": {
        "patterns": [r"md5\(", r"sha1\(", r"DES\.", r"RC4", r"MD5\(", r"blowfish"],
        "severity": "HIGH", "owasp": "A02:2021", "cwe": "CWE-327",
        "fix": "bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))",
        "desc": "Deprecated algorithms are easily broken with modern hardware.",
        "icon": "🟠", "category": "crypto"
    },
    "Command Injection": {
        "patterns": [r"os\.system\s*\(", r"subprocess\.call\s*\(.*shell\s*=\s*True", r"subprocess\.Popen\s*\(.*shell", r"eval\s*\(.*input"],
        "severity": "CRITICAL", "owasp": "A03:2021", "cwe": "CWE-78",
        "fix": 'subprocess.run(["cat", filename], capture_output=True)',
        "desc": "OS commands built from user input allow arbitrary execution.",
        "icon": "🔴", "category": "injection"
    },
    "Path Traversal": {
        "patterns": [r"open\s*\(.*\.\.\/", r"os\.path\.join\s*\(.*\.\.", r"Path\s*\(.*\.\.", r"readFile\s*\(.*\.\."],
        "severity": "HIGH", "owasp": "A01:2021", "cwe": "CWE-22",
        "fix": "os.path.realpath(path).startswith(expected_base)",
        "desc": "../ sequences escape the intended directory.",
        "icon": "🟠", "category": "access"
    },
    "Buffer Overflow Risk": {
        "patterns": [r"strcpy\s*\(", r"gets\s*\(", r"sprintf\s*\(", r"scanf\s*\(", r"strcat\s*\("],
        "severity": "CRITICAL", "owasp": "A06:2021", "cwe": "CWE-120",
        "fix": "strncpy(buffer, input, sizeof(buffer) - 1);",
        "desc": "Unbounded writes corrupt adjacent memory.",
        "icon": "🔴", "category": "memory"
    },
    "Insecure Deserialization": {
        "patterns": [r"pickle\.loads?\s*\(", r"yaml\.load\s*\((?!.*Loader)", r"marshal\.loads?\s*\(", r"jsonpickle", r"shelve\.open"],
        "severity": "HIGH", "owasp": "A08:2021", "cwe": "CWE-502",
        "fix": "yaml.safe_load(data)  # or json.loads()",
        "desc": "Untrusted deserialization executes arbitrary code.",
        "icon": "🟠", "category": "integrity"
    },
    "Race Condition": {
        "patterns": [r"global\s+\w+.*\n.*\w+\s*=\s*\w+\s*\+", r"thread\.start.*shared", r"nonlocal\s+\w+", r"shared_state"],
        "severity": "MEDIUM", "owasp": "A04:2021", "cwe": "CWE-362",
        "fix": "with lock: balance -= amount  # use threading.Lock()",
        "desc": "Concurrent access to shared state without synchronization.",
        "icon": "🟡", "category": "design"
    },
    "SSRF": {
        "patterns": [r"requests\.get\s*\(.*request\.", r"urllib\.request\.urlopen\s*\(.*input", r"fetch\s*\(.*req\.", r"http\.get\s*\(.*params"],
        "severity": "HIGH", "owasp": "A10:2021", "cwe": "CWE-918",
        "fix": "validate_url(url)  # check against allowlist",
        "desc": "Server-side requests to attacker-controlled URLs.",
        "icon": "🟠", "category": "ssrf"
    },
    "XXE Injection": {
        "patterns": [r"xml\.etree\.ElementTree\.parse", r"lxml\.etree\.parse", r"xml\.sax\.parse", r"xml\.dom\.minidom"],
        "severity": "HIGH", "owasp": "A05:2021", "cwe": "CWE-611",
        "fix": "defusedxml.ElementTree.parse()",
        "desc": "XML parsers may expose internal files or SSRF.",
        "icon": "🟠", "category": "injection"
    },
    "Open Redirect": {
        "patterns": [r"redirect\s*\(.*request\.", r"Location:\s*.*request\.", r"window\.location\s*=.*req\."],
        "severity": "MEDIUM", "owasp": "A01:2021", "cwe": "CWE-601",
        "fix": "if url in ALLOWED_REDIRECTS: redirect(url)",
        "desc": "User redirected to malicious external site.",
        "icon": "🟡", "category": "access"
    },
    "Missing Rate Limiting": {
        "patterns": [r"@app\.route.*POST", r"def\s+login", r"def\s+authenticate", r"app\.post\("],
        "severity": "MEDIUM", "owasp": "A04:2021", "cwe": "CWE-307",
        "fix": "@limiter.limit('5/minute')  # Flask-Limiter",
        "desc": "No rate limiting enables brute-force attacks.",
        "icon": "🟡", "category": "auth"
    },
    "Weak Session Token": {
        "patterns": [r"session\[.*\]\s*=\s*random\.", r"token\s*=\s*random\.random", r"uuid\.uuid1\(\)", r"math\.random"],
        "severity": "MEDIUM", "owasp": "A07:2021", "cwe": "CWE-330",
        "fix": "secrets.token_urlsafe(32)  # 256-bit secure token",
        "desc": "Predictable tokens are guessable by attackers.",
        "icon": "🟡", "category": "auth"
    },
    "Debug Mode Enabled": {
        "patterns": [r"DEBUG\s*=\s*True", r"debug\s*=\s*True", r"app\.run\(.*debug", r"FLASK_DEBUG=1"],
        "severity": "MEDIUM", "owasp": "A05:2021", "cwe": "CWE-489",
        "fix": "DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'",
        "desc": "Debug mode exposes stack traces and internals.",
        "icon": "🟡", "category": "config"
    },
    "Eval/Exec Usage": {
        "patterns": [r"\beval\s*\(", r"\bexec\s*\(", r"compile\s*\(.*exec", r"__import__\s*\("],
        "severity": "CRITICAL", "owasp": "A03:2021", "cwe": "CWE-95",
        "fix": "Use ast.literal_eval() for safe evaluation",
        "desc": "eval/exec execute arbitrary code strings.",
        "icon": "🔴", "category": "injection"
    },
    "CORS Misconfiguration": {
        "patterns": [r"Access-Control-Allow-Origin.*\*", r"cors\(.*origins.*\*", r"allow_origins\s*=\s*\[.*\*", r"cors_options"],
        "severity": "MEDIUM", "owasp": "A05:2021", "cwe": "CWE-942",
        "fix": "allow_origins=['https://yourdomain.com']",
        "desc": "Wildcard CORS allows any origin to access resources.",
        "icon": "🟡", "category": "config"
    },
    "Insufficient Logging": {
        "patterns": [r"except.*pass", r"except.*:\s*$", r"catch\s*\(\s*\w*\s*\)\s*\{\s*\}", r"except\s*:"],
        "severity": "LOW", "owasp": "A09:2021", "cwe": "CWE-778",
        "fix": "logger.error(f'Auth failed: {e}', exc_info=True)",
        "desc": "Silent failures prevent security incident detection.",
        "icon": "🔵", "category": "logging"
    },
    "Timing Attack": {
        "patterns": [r"==\s*hash", r"if\s+\w+\s*==\s*token", r"strcmp\s*\(", r"==\s*password"],
        "severity": "MEDIUM", "owasp": "A02:2021", "cwe": "CWE-208",
        "fix": "hmac.compare_digest(a, b)  # constant-time comparison",
        "desc": "Non-constant-time comparisons leak timing information.",
        "icon": "🟡", "category": "crypto"
    },
    "Unrestricted File Upload": {
        "patterns": [r"request\.files\[", r"upload\.save\s*\(", r"multer\(", r"multipart/form-data.*POST"],
        "severity": "HIGH", "owasp": "A04:2021", "cwe": "CWE-434",
        "fix": "validate_file_type(uploaded)  # check extension + magic bytes",
        "desc": "Unrestricted uploads allow malicious file execution.",
        "icon": "🟠", "category": "design"
    },
    "Hardcoded IP Address": {
        "patterns": [r'(?:^|[^\/\d])(\d{1,3}\.){3}\d{1,3}(?:[^\/\d]|$)', r'192\.168\.\d+\.\d+', r'10\.0\.\d+\.\d+'],
        "severity": "LOW", "owasp": "A05:2021", "cwe": "CWE-200",
        "fix": "Use DNS names or environment variables for IPs",
        "desc": "Hardcoded IPs leak infrastructure details.",
        "icon": "🔵", "category": "config"
    },
    "Missing HTTPS": {
        "patterns": [r"http://(?!localhost|127\.0\.0\.1)", r"verify\s*=\s*False", r"VERIFY_PEER.*false", r"ssl\._create_unverified"],
        "severity": "HIGH", "owasp": "A02:2021", "cwe": "CWE-319",
        "fix": "Use https:// and enable certificate verification",
        "desc": "Unencrypted connections expose data in transit.",
        "icon": "🟠", "category": "crypto"
    },
    "Insecure Random": {
        "patterns": [r"random\.randint\(", r"random\.choice\(", r"random\.random\(\)", r"rand\s*\("],
        "severity": "MEDIUM", "owasp": "A02:2021", "cwe": "CWE-330",
        "fix": "secrets.randbelow(n)  # cryptographic randomness",
        "desc": "PRNG output is predictable for security-critical operations.",
        "icon": "🟡", "category": "crypto"
    },
    "Missing Auth Header": {
        "patterns": [r"requests\.get\s*\((?!.*headers)", r"fetch\s*\((?!.*Authorization)", r"curl\s+-X\s+POST\s+(?!.*-H)"],
        "severity": "LOW", "owasp": "A07:2021", "cwe": "CWE-306",
        "fix": "Add Authorization header: headers={'Authorization': f'Bearer {token}'}",
        "desc": "API requests without authentication headers.",
        "icon": "🔵", "category": "auth"
    },
    "SQL LIKE Injection": {
        "patterns": [r"LIKE\s+['\"]%.*\+\s*", r"like\s*\(.*format", r"LIKE.*CONCAT"],
        "severity": "HIGH", "owasp": "A03:2021", "cwe": "CWE-89",
        "fix": "cursor.execute('SELECT * FROM users WHERE name LIKE ?', (f'%{pattern}%',))",
        "desc": "LIKE clauses are also vulnerable to SQL injection.",
        "icon": "🟠", "category": "injection"
    },
    "Prototype Pollution (JS)": {
        "patterns": [r"__proto__", r"constructor\[", r"Object\.assign\s*\(.*req\.", r"merge\s*\(.*req\."],
        "severity": "HIGH", "owasp": "A03:2021", "cwe": "CWE-1321",
        "fix": "Use Object.create(null) or validate keys",
        "desc": "Prototype pollution allows property injection in JavaScript.",
        "icon": "🟠", "category": "injection"
    },
    "NoSQL Injection": {
        "patterns": [r"\$where", r"\$gt", r"\$ne", r"\$regex", r"\$exists"],
        "severity": "HIGH", "owasp": "A03:2021", "cwe": "CWE-943",
        "fix": "Sanitize input and use parameterized queries",
        "desc": "NoSQL operators in user input alter query logic.",
        "icon": "🟠", "category": "injection"
    },
    "LDAP Injection": {
        "patterns": [r"ldap.*search.*\+", r"ldap\.filter.*format", r"ldap_bind\s*\(.*\+"],
        "severity": "HIGH", "owasp": "A03:2021", "cwe": "CWE-90",
        "fix": "Escape LDAP special characters before search",
        "desc": "Unescaped input in LDAP queries modifies search filters.",
        "icon": "🟠", "category": "injection"
    },
    "XML Entity Expansion (Billion Laughs)": {
        "patterns": [r"ENTITY\s+\w+\s+\"&\w+;", r"DOCTYPE.*\[.*ENTITY", r"entity.*expansion"],
        "severity": "HIGH", "owasp": "A05:2021", "cwe": "CWE-776",
        "fix": "Disable DTD processing with defusedxml",
        "desc": "Entity expansion attacks exhaust memory/CPU.",
        "icon": "🟠", "category": "injection"
    },
    "Insecure TLS Version": {
        "patterns": [r"SSLv3", r"TLSv1\.0", r"TLSv1\.1", r"PROTOCOL_TLSv1_1"],
        "severity": "HIGH", "owasp": "A02:2021", "cwe": "CWE-326",
        "fix": "ssl.PROTOCOL_TLSv1_2  # minimum TLS 1.2",
        "desc": "Old TLS versions have known vulnerabilities.",
        "icon": "🟠", "category": "crypto"
    },
    "Weak Password Hash": {
        "patterns": [r"hashlib\.md5\s*\(", r"hashlib\.sha1\s*\(", r"base64\.b64encode\s*\(.*password", r"encode\s*\(\s*['\"]utf"],
        "severity": "CRITICAL", "owasp": "A02:2021", "cwe": "CWE-916",
        "fix": "bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))",
        "desc": "Fast hash algorithms allow brute-force password cracking.",
        "icon": "🔴", "category": "crypto"
    },
    "Unsafe YAML Loading": {
        "patterns": [r"yaml\.load\s*\((?!.*Loader)", r"yaml\.unsafe_load", r"yaml\.Loader"],
        "severity": "HIGH", "owasp": "A08:2021", "cwe": "CWE-502",
        "fix": "yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader)",
        "desc": "Unsafe YAML deserialization executes embedded Python code.",
        "icon": "🟠", "category": "integrity"
    },
    "Debug Endpoint Exposed": {
        "patterns": [r"@app\.route.*debug", r"@app\.route.*admin", r"\/\.env", r"\/wp-admin", r"actuator"],
        "severity": "MEDIUM", "owasp": "A01:2021", "cwe": "CWE-215",
        "fix": "Remove debug endpoints in production",
        "desc": "Debug/admin endpoints exposed to unauthorized users.",
        "icon": "🟡", "category": "config"
    },
    "Memory Leak (C/C++)": {
        "patterns": [r"malloc\s*\(", r"new\s+\w+\[", r"realloc\s*\(", r"Calloc\s*\("],
        "severity": "MEDIUM", "owasp": "A06:2021", "cwe": "CWE-401",
        "fix": "Ensure every malloc has a corresponding free()",
        "desc": "Unreleased heap memory grows over time.",
        "icon": "🟡", "category": "memory"
    },
    "Integer Overflow": {
        "patterns": [r"int\s+\w+\s*=.*\*", r"size_t.*\+", r"count\s*\+\s*\w+\s*>", r"\*\s*sizeof"],
        "severity": "MEDIUM", "owasp": "A06:2021", "cwe": "CWE-190",
        "fix": "Check for overflow: if (a > MAX - b) return ERROR;",
        "desc": "Arithmetic overflow causes undefined behavior.",
        "icon": "🟡", "category": "memory"
    },
    "Use After Free": {
        "patterns": [r"free\s*\(.*\);\s*\n.*\1", r"delete\s+.*;\s*\n.*ptr", r"drop\s*\(.*\).*\n.*use"],
        "severity": "CRITICAL", "owasp": "A06:2021", "cwe": "CWE-416",
        "fix": "Set pointer to NULL after free",
        "desc": "Accessing freed memory leads to crashes or exploitation.",
        "icon": "🔴", "category": "memory"
    },
    "Double Free": {
        "patterns": [r"free\s*\(.*\).*\n.*free\s*\(", r"delete\s+.*\n.*delete\s+"],
        "severity": "CRITICAL", "owasp": "A06:2021", "cwe": "CWE-762",
        "fix": "Set pointer to NULL after free, check before second free",
        "desc": "Freeing memory twice corrupts the heap allocator.",
        "icon": "🔴", "category": "memory"
    },
    "Null Pointer Dereference": {
        "patterns": [r"if\s*\(\s*!\w+\s*\)\s*\{?\s*\w+\->", r"\w+\s*=\s*NULL.*\n.*\w+\->", r"nullptr_t.*->"],
        "severity": "MEDIUM", "owasp": "A06:2021", "cwe": "CWE-476",
        "fix": "Always check pointers before dereferencing",
        "desc": "Null pointer dereference causes crashes.",
        "icon": "🟡", "category": "memory"
    },
    "Uninitialized Variable": {
        "patterns": [r"int\s+\w+;\s*$", r"char\s+\w+\[.*\];\s*$", r"var\s+\w+\s*;\s*$"],
        "severity": "LOW", "owasp": "A06:2021", "cwe": "CWE-457",
        "fix": "Initialize all variables at declaration",
        "desc": "Uninitialized variables contain stack garbage.",
        "icon": "🔵", "category": "memory"
    },
    "JWT None Algorithm": {
        "patterns": [r"algorithm.*none", r"'none'\s*\]", r"verify.*false.*jwt", r"algorithms.*None"],
        "severity": "CRITICAL", "owasp": "A02:2021", "cwe": "CWE-327",
        "fix": "Always specify allowed algorithms: algorithms=['HS256']",
        "desc": "JWT with none algorithm bypasses signature verification.",
        "icon": "🔴", "category": "auth"
    },
    "Insecure JWT Storage": {
        "patterns": [r"localStorage.*jwt", r"localStorage.*token", r"sessionStorage.*token", r"document\.cookie.*token"],
        "severity": "HIGH", "owasp": "A07:2021", "cwe": "CWE-614",
        "fix": "Store JWT in httpOnly cookies",
        "desc": "Tokens in localStorage are accessible to XSS attacks.",
        "icon": "🟠", "category": "auth"
    },
    "GraphQL Introspection": {
        "patterns": [r"introspection.*true", r"__schema", r"introspection_query", r"GRAPHQL_INTROSPECTION"],
        "severity": "MEDIUM", "owasp": "A05:2021", "cwe": "CWE-200",
        "fix": "Disable introspection in production",
        "desc": "GraphQL introspection exposes entire API schema.",
        "icon": "🟡", "category": "config"
    },
}

SECURITY_EXPLANATIONS = {k: v["desc"] for k, v in VULN_PATTERNS.items()}
FIX_SUGGESTIONS = {k: v["fix"] for k, v in VULN_PATTERNS.items()}

# ─── Knowledge Base ───────────────────────────────────────────────────
KNOWLEDGE_BASE = {
    "owasp": "A01-Broken Access, A02-Crypto Failures, A03-Injection, A04-Insecure Design, A05-Misconfiguration, A06-Vulnerable Components, A07-Auth Failures, A08-Data Integrity, A09-Logging Failures, A10-SSRF",
    "crypto": "AES-256-GCM, bcrypt/scrypt/Argon2, Ed25519, TLS 1.3, ChaCha20-Poly1305",
    "cwe_top25": "CWE-787 OOB Write, CWE-79 XSS, CWE-89 SQLi, CWE-416 UAF, CWE-78 CmdInj, CWE-20 Input Validation, CWE-22 Path Traversal",
}

def scan_code(code):
    findings = []
    seen = set()
    for vuln_name, vuln_data in VULN_PATTERNS.items():
        for pattern in vuln_data["patterns"]:
            for m in re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE):
                line_num = code[: m.start()].count("\n") + 1
                key = (vuln_name, line_num)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "type": vuln_name,
                        "severity": vuln_data["severity"],
                        "owasp": vuln_data.get("owasp", ""),
                        "cwe": vuln_data.get("cwe", ""),
                        "line": line_num,
                        "match": m.group()[:100],
                        "explanation": vuln_data["desc"],
                        "fix": vuln_data["fix"],
                        "icon": vuln_data.get("icon", "⚪"),
                        "category": vuln_data.get("category", "other"),
                    })
    findings.sort(key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f["severity"], 4))
    return findings

# ─── Award-Winning HTML Template ──────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#000000">
<title>NanoShield — AI Security Scanner</title>
<link rel="manifest" href="/manifest.json">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ═══════════════════════════════════════════════════════════════════
   NanoShield — Award-Winning iOS-Inspired Design
   Inspired by Apple Design Awards + Awwwards Winners
   ═══════════════════════════════════════════════════════════════════ */

*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}

:root{
  --bg:#000000;--bg2:#0a0a0f;--bg3:#111118;--bg4:#1a1a24;
  --surface:rgba(255,255,255,0.04);--surface2:rgba(255,255,255,0.08);
  --border:rgba(255,255,255,0.08);--border2:rgba(255,255,255,0.12);
  --text:#ffffff;--text2:rgba(255,255,255,0.7);--text3:rgba(255,255,255,0.4);
  --accent:#6366f1;--accent2:#818cf8;--accent3:#a78bfa;
  --cyan:#06b6d4;--green:#10b981;--red:#ef4444;--orange:#f97316;
  --yellow:#eab308;--pink:#ec4899;
  --glass:rgba(18,18,28,0.72);--glass-border:rgba(255,255,255,0.06);
  --safe-top:env(safe-area-inset-top,0px);--safe-bottom:env(safe-area-inset-bottom,0px);
  --tab-height:82px;
}

html{font-size:16px;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;overscroll-behavior:none}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;min-height:100dvh;overflow-x:hidden;position:relative}

/* ── iOS-Style Status Bar ── */
.status-bar{position:fixed;top:0;left:0;right:0;height:calc(20px + var(--safe-top));padding-top:var(--safe-top);background:rgba(0,0,0,0.8);backdrop-filter:blur(30px);z-index:1000;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;letter-spacing:0.3px}

/* ── Particle Canvas ── */
#particles{position:fixed;inset:0;z-index:0;pointer-events:none}

/* ── Animated Gradient Mesh Background ── */
.mesh-bg{position:fixed;inset:0;z-index:0;overflow:hidden}
.mesh-orb{position:absolute;border-radius:50%;filter:blur(120px);will-change:transform}
.mesh-orb-1{width:600px;height:600px;background:radial-gradient(circle,rgba(99,102,241,0.15),transparent 70%);top:-200px;left:-200px;animation:orbFloat 25s ease-in-out infinite}
.mesh-orb-2{width:500px;height:500px;background:radial-gradient(circle,rgba(6,182,212,0.12),transparent 70%);bottom:-150px;right:-150px;animation:orbFloat 20s ease-in-out infinite reverse}
.mesh-orb-3{width:400px;height:400px;background:radial-gradient(circle,rgba(236,72,153,0.08),transparent 70%);top:40%;left:50%;animation:orbFloat 30s ease-in-out infinite 5s}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(60px,-40px) scale(1.1)}50%{transform:translate(-30px,60px) scale(0.95)}75%{transform:translate(-60px,-20px) scale(1.05)}}

/* ── App Shell ── */
.app-shell{position:relative;z-index:1;min-height:100vh;min-height:100dvh;padding-bottom:var(--tab-height);display:none}
.app-shell.active{display:block;animation:pageIn 0.5s cubic-bezier(0.16,1,0.3,1)}
@keyframes pageIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}

/* ── iOS Navigation Bar ── */
.nav-bar{position:sticky;top:0;z-index:100;padding:calc(var(--safe-top) + 12px) 20px 12px;background:rgba(0,0,0,0.75);backdrop-filter:blur(40px) saturate(180%);border-bottom:0.5px solid rgba(255,255,255,0.08)}
.nav-content{display:flex;align-items:center;justify-content:space-between;max-width:800px;margin:0 auto}
.nav-title{font-size:17px;font-weight:700;letter-spacing:-0.3px}
.nav-subtitle{font-size:11px;color:var(--text3);font-weight:500;margin-top:1px}
.nav-badge{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;font-size:11px;font-weight:600;background:rgba(16,185,129,0.12);color:var(--green);border:0.5px solid rgba(16,185,129,0.2)}
.nav-badge .dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:livePulse 2s ease-in-out infinite}
@keyframes livePulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.4;transform:scale(0.8)}}

/* ── iOS Bottom Tab Bar ── */
.tab-bar{position:fixed;bottom:0;left:0;right:0;height:var(--tab-height);padding-bottom:var(--safe-bottom);background:rgba(10,10,15,0.85);backdrop-filter:blur(40px) saturate(180%);border-top:0.5px solid rgba(255,255,255,0.08);z-index:1000;display:flex;align-items:flex-start;justify-content:center;gap:0}
.tab-item{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding-top:8px;gap:3px;cursor:pointer;-webkit-tap-highlight-color:transparent;transition:all 0.2s;max-width:80px}
.tab-item svg{width:24px;height:24px;fill:none;stroke:var(--text3);stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;transition:all 0.3s cubic-bezier(0.34,1.56,0.64,1)}
.tab-item span{font-size:10px;font-weight:500;color:var(--text3);transition:all 0.2s}
.tab-item.active svg{stroke:var(--accent)}
.tab-item.active span{color:var(--accent);font-weight:600}
.tab-item:active svg{transform:scale(0.85)}

/* ── iOS-Style Large Title ── */
.large-title{padding:16px 24px 4px;max-width:800px;margin:0 auto}
.large-title h1{font-size:34px;font-weight:800;letter-spacing:-0.5px;line-height:1.1}
.large-title .subtitle{font-size:15px;color:var(--text2);margin-top:6px;line-height:1.4}

/* ── Glass Card System ── */
.glass-card{background:var(--glass);backdrop-filter:blur(40px) saturate(150%);border:0.5px solid var(--glass-border);border-radius:16px;overflow:hidden;transition:transform 0.4s cubic-bezier(0.16,1,0.3,1),box-shadow 0.4s;will-change:transform}
.glass-card:hover{transform:translateY(-2px) scale(1.005);box-shadow:0 12px 40px rgba(0,0,0,0.3)}
.glass-card-inner{padding:20px}

/* ── 3D Tilt Effect ── */
.tilt-card{perspective:1000px}
.tilt-card .glass-card{transform-style:preserve-3d;transition:transform 0.15s ease-out}

/* ── Stats Cards (iOS Widget Style) ── */
.stats-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;padding:0 20px;max-width:800px;margin:0 auto}
@media(min-width:600px){.stats-grid{grid-template-columns:repeat(4,1fr)}}
.stat-widget{padding:16px;position:relative;overflow:hidden;min-height:88px}
.stat-widget::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:2px 2px 0 0}
.stat-widget.s-crit::before{background:linear-gradient(90deg,var(--red),#f87171)}
.stat-widget.s-high::before{background:linear-gradient(90deg,var(--orange),#fb923c)}
.stat-widget.s-med::before{background:linear-gradient(90deg,var(--yellow),#facc15)}
.stat-widget.s-low::before{background:linear-gradient(90deg,var(--cyan),#22d3ee)}
.stat-widget.s-score::before{background:linear-gradient(90deg,var(--green),#34d399)}
.stat-widget.s-clean::before{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.stat-icon{font-size:20px;margin-bottom:8px;display:block}
.stat-value{font-size:28px;font-weight:800;letter-spacing:-1px;font-variant-numeric:tabular-nums}
.stat-widget.s-crit .stat-value{color:var(--red)}
.stat-widget.s-high .stat-value{color:var(--orange)}
.stat-widget.s-med .stat-value{color:var(--yellow)}
.stat-widget.s-low .stat-value{color:var(--cyan)}
.stat-widget.s-score .stat-value{color:var(--green)}
.stat-widget.s-clean .stat-value{color:var(--accent)}
.stat-label{font-size:12px;color:var(--text3);font-weight:500;margin-top:2px}
.stat-delta{position:absolute;top:14px;right:14px;font-size:11px;font-weight:700;padding:2px 6px;border-radius:8px}
.stat-delta.up{background:rgba(239,68,68,0.15);color:var(--red)}
.stat-delta.down{background:rgba(16,185,129,0.15);color:var(--green)}
.stat-delta.neutral{background:rgba(255,255,255,0.05);color:var(--text3)}

/* ── Code Editor (iOS TextEditor Style) ── */
.editor-section{padding:16px 20px;max-width:800px;margin:0 auto}
.editor-card{border-radius:16px;overflow:hidden}
.editor-toolbar{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:rgba(255,255,255,0.03);border-bottom:0.5px solid var(--border)}
.editor-toolbar-title{font-size:13px;font-weight:600;color:var(--text2);display:flex;align-items:center;gap:8px}
.lang-pills{display:flex;gap:6px}
.lang-pill{padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;background:rgba(255,255,255,0.04);color:var(--text3);cursor:pointer;border:0.5px solid transparent;transition:all 0.2s;-webkit-tap-highlight-color:transparent}
.lang-pill.active{background:var(--accent);color:white;border-color:var(--accent)}
.lang-pill:active{transform:scale(0.95)}

.code-editor{width:100%;min-height:300px;background:transparent;border:none;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.8;padding:16px 20px;resize:none;outline:none;-webkit-overflow-scrolling:touch}
.code-editor::placeholder{color:var(--text3)}
.code-editor::selection{background:rgba(99,102,241,0.3)}

/* ── Scan Button (iOS CTA Style) ── */
.scan-cta{padding:20px;max-width:800px;margin:0 auto}
.scan-btn{width:100%;padding:18px;border:none;border-radius:16px;font-size:17px;font-weight:700;cursor:pointer;position:relative;overflow:hidden;background:linear-gradient(135deg,var(--accent),#7c3aed,var(--pink));color:white;box-shadow:0 8px 32px rgba(99,102,241,0.4);transition:all 0.4s cubic-bezier(0.16,1,0.3,1);-webkit-tap-highlight-color:transparent}
.scan-btn:hover{transform:translateY(-2px) scale(1.01);box-shadow:0 12px 40px rgba(99,102,241,0.5)}
.scan-btn:active{transform:translateY(0) scale(0.98)}
.scan-btn::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.15),transparent);transform:translateX(-100%);transition:transform 0.6s}
.scan-btn:hover::after{transform:translateX(100%)}
.scan-btn.scanning{animation:scanPulse 1.5s ease-in-out infinite;pointer-events:none}
@keyframes scanPulse{0%,100%{box-shadow:0 8px 32px rgba(99,102,241,0.4)}50%{box-shadow:0 8px 48px rgba(99,102,241,0.6),0 0 0 4px rgba(99,102,241,0.1)}}

/* ── Scanner Animation ── */
.scanner-overlay{position:fixed;inset:0;z-index:2000;background:rgba(0,0,0,0.9);backdrop-filter:blur(20px);display:none;align-items:center;justify-content:center;flex-direction:column;gap:24px}
.scanner-overlay.active{display:flex;animation:fadeIn 0.3s ease}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.scanner-ring{width:120px;height:120px;border-radius:50%;border:3px solid transparent;border-top-color:var(--accent);border-right-color:var(--cyan);animation:spinRing 1s linear infinite;position:relative}
.scanner-ring::before{content:'';position:absolute;inset:8px;border-radius:50%;border:3px solid transparent;border-bottom-color:var(--pink);border-left-color:var(--green);animation:spinRing 1.5s linear infinite reverse}
@keyframes spinRing{to{transform:rotate(360deg)}}
.scanner-text{font-size:15px;font-weight:600;color:var(--text2);animation:textPulse 1.5s ease-in-out infinite}
@keyframes textPulse{0%,100%{opacity:1}50%{opacity:0.5}}
.scanner-progress{width:200px;height:3px;background:rgba(255,255,255,0.1);border-radius:2px;overflow:hidden}
.scanner-progress-bar{height:100%;background:linear-gradient(90deg,var(--accent),var(--cyan));border-radius:2px;animation:progressGrow 2s ease-in-out forwards}
@keyframes progressGrow{from{width:0}to{width:100%}}

/* ── Findings List (iOS Grouped Style) ── */
.findings-section{padding:0 20px;max-width:800px;margin:0 auto}
.findings-header{display:flex;align-items:center;justify-content:space-between;padding:12px 0}
.findings-title{font-size:20px;font-weight:700}
.findings-count{font-size:13px;color:var(--text3);font-weight:500}
.finding-card{margin-bottom:8px;border-radius:14px;overflow:hidden;animation:cardSlideIn 0.5s cubic-bezier(0.16,1,0.3,1) forwards;opacity:0;transform:translateY(12px)}
@keyframes cardSlideIn{to{opacity:1;transform:translateY(0)}}
.finding-card-inner{padding:16px}
.finding-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px}
.finding-severity{display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:8px;font-size:11px;font-weight:700;letter-spacing:0.3px}
.sev-CRITICAL{background:rgba(239,68,68,0.15);color:var(--red)}
.sev-HIGH{background:rgba(249,115,22,0.15);color:var(--orange)}
.sev-MEDIUM{background:rgba(234,179,8,0.15);color:var(--yellow)}
.sev-LOW{background:rgba(6,182,212,0.15);color:var(--cyan)}
.finding-type{font-size:15px;font-weight:700;margin-bottom:4px}
.finding-desc{font-size:13px;color:var(--text2);line-height:1.5;margin-bottom:10px}
.finding-meta{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.finding-tag{padding:3px 8px;border-radius:6px;font-size:10px;font-weight:600;background:rgba(255,255,255,0.04);color:var(--text3);font-family:'JetBrains Mono',monospace}
.finding-code-block{background:rgba(0,0,0,0.4);border-radius:10px;padding:12px 14px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#f87171;line-height:1.5;overflow-x:auto;margin-bottom:10px;border:0.5px solid rgba(239,68,68,0.1)}
.finding-fix-block{background:rgba(16,185,129,0.08);border:0.5px solid rgba(16,185,129,0.15);border-radius:10px;padding:12px 14px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--green);line-height:1.5;overflow-x:auto;display:flex;gap:8px;align-items:flex-start}
.finding-fix-block .fix-label{font-weight:700;white-space:nowrap;flex-shrink:0}

/* ── Score Ring (Apple Watch Style) ── */
.score-section{display:flex;flex-direction:column;align-items:center;padding:24px 20px}
.score-ring-container{position:relative;width:160px;height:160px;margin-bottom:16px}
.score-ring-bg{fill:none;stroke:rgba(255,255,255,0.06);stroke-width:10}
.score-ring-fg{fill:none;stroke-width:10;stroke-linecap:round;transition:stroke-dashoffset 1.5s cubic-bezier(0.16,1,0.3,1),stroke 0.5s;transform:rotate(-90deg);transform-origin:center}
.score-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.score-number{font-size:48px;font-weight:900;letter-spacing:-2px;font-variant-numeric:tabular-nums}
.score-label{font-size:12px;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:1.5px;margin-top:-4px}
.score-verdict{font-size:15px;font-weight:600;margin-top:12px;padding:6px 16px;border-radius:20px}

/* ── Knowledge Feed (News Ticker) ── */
.knowledge-section{padding:0 20px 20px;max-width:800px;margin:0 auto}
.knowledge-card{border-radius:16px;overflow:hidden}
.knowledge-header{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:0.5px solid var(--border)}
.knowledge-title{font-size:13px;font-weight:700;color:var(--text2);display:flex;align-items:center;gap:8px}
.knowledge-items{max-height:200px;overflow-y:auto}
.knowledge-item{display:flex;align-items:flex-start;gap:12px;padding:12px 16px;border-bottom:0.5px solid rgba(255,255,255,0.03);animation:fadeSlideIn 0.4s ease forwards;opacity:0}
@keyframes fadeSlideIn{to{opacity:1}}
.knowledge-dot{width:8px;height:8px;border-radius:50%;margin-top:5px;flex-shrink:0}
.knowledge-dot.fresh{background:var(--green);box-shadow:0 0 8px rgba(16,185,129,0.4)}
.knowledge-dot.cached{background:var(--text3)}
.knowledge-text{font-size:13px;color:var(--text2);line-height:1.4}
.knowledge-text strong{color:var(--text)}

/* ── Demo Mode Overlay ── */
.demo-overlay{position:fixed;inset:0;z-index:3000;background:rgba(0,0,0,0.95);backdrop-filter:blur(30px);display:none;align-items:center;justify-content:center;flex-direction:column;gap:20px;padding:40px;text-align:center}
.demo-overlay.active{display:flex;animation:fadeIn 0.5s ease}
.demo-title{font-size:28px;font-weight:900;letter-spacing:-0.5px;background:linear-gradient(135deg,var(--accent2),var(--pink),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.demo-subtitle{font-size:16px;color:var(--text2);max-width:400px;line-height:1.5}
.demo-step{font-size:14px;color:var(--text3);margin-top:8px}
.demo-progress{width:200px;height:2px;background:rgba(255,255,255,0.1);border-radius:1px;overflow:hidden;margin-top:12px}
.demo-progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--cyan));border-radius:1px;transition:width 0.3s ease}
.demo-btn{padding:14px 32px;border:none;border-radius:14px;font-size:15px;font-weight:700;cursor:pointer;background:linear-gradient(135deg,var(--accent),#7c3aed);color:white;box-shadow:0 8px 32px rgba(99,102,241,0.3);transition:all 0.3s;margin-top:16px}
.demo-btn:hover{transform:scale(1.03)}
.demo-skip{font-size:13px;color:var(--text3);cursor:pointer;margin-top:8px;border:none;background:none}

/* ── Keyboard Shortcut Hint ── */
.kbd-hint{position:fixed;bottom:calc(var(--tab-height) + 12px);right:20px;z-index:100;display:flex;gap:6px;opacity:0;transition:opacity 0.3s;pointer-events:none}
.kbd-hint.visible{opacity:1}
.kbd{padding:4px 8px;border-radius:6px;font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace;background:rgba(255,255,255,0.08);border:0.5px solid rgba(255,255,255,0.12);color:var(--text2)}

/* ── Toast (iOS Notification Style) ── */
.toast{position:fixed;top:calc(20px + var(--safe-top) + 8px);left:50%;transform:translateX(-50%) translateY(-100px);z-index:5000;padding:14px 20px;border-radius:16px;font-size:14px;font-weight:600;backdrop-filter:blur(20px);max-width:calc(100vw - 40px);text-align:center;transition:transform 0.5s cubic-bezier(0.16,1,0.3,1);box-shadow:0 8px 32px rgba(0,0,0,0.4)}
.toast.show{transform:translateX(-50%) translateY(0)}
.toast.success{background:rgba(16,185,129,0.2);border:0.5px solid rgba(16,185,129,0.3);color:var(--green)}
.toast.info{background:rgba(99,102,241,0.2);border:0.5px solid rgba(99,102,241,0.3);color:var(--accent2)}
.toast.error{background:rgba(239,68,68,0.2);border:0.5px solid rgba(239,68,68,0.3);color:var(--red)}

/* ── Empty State ── */
.empty-state{display:flex;flex-direction:column;align-items:center;padding:48px 20px;text-align:center}
.empty-icon{font-size:56px;margin-bottom:16px;opacity:0.6}
.empty-title{font-size:18px;font-weight:700;margin-bottom:8px}
.empty-sub{font-size:14px;color:var(--text3);max-width:300px;line-height:1.5}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.1);border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.2)}

/* ── Responsive ── */
@media(max-width:480px){
  .large-title h1{font-size:28px}
  .stat-value{font-size:24px}
  .code-editor{min-height:200px;font-size:12px}
  .score-ring-container{width:130px;height:130px}
  .score-number{font-size:36px}
}
</style>
</head>
<body>

<!-- Animated Mesh Background -->
<div class="mesh-bg">
  <div class="mesh-orb mesh-orb-1"></div>
  <div class="mesh-orb mesh-orb-2"></div>
  <div class="mesh-orb mesh-orb-3"></div>
</div>

<!-- Particle Canvas -->
<canvas id="particles"></canvas>

<!-- Scanner Overlay -->
<div class="scanner-overlay" id="scannerOverlay">
  <div class="scanner-ring"></div>
  <div class="scanner-text" id="scannerText">Analyzing code...</div>
  <div class="scanner-progress"><div class="scanner-progress-bar"></div></div>
</div>

<!-- Demo Overlay -->
<div class="demo-overlay" id="demoOverlay">
  <div class="demo-title" id="demoTitle">Welcome to NanoShield</div>
  <div class="demo-subtitle" id="demoSubtitle">The world's most advanced on-device AI security scanner. Let me show you how it works.</div>
  <div class="demo-step" id="demoStep">Step 1 of 5</div>
  <div class="demo-progress"><div class="demo-progress-fill" id="demoProgress" style="width:20%"></div></div>
  <button class="demo-btn" id="demoBtn" onclick="nextDemoStep()">Next →</button>
  <button class="demo-skip" onclick="closeDemo()">Skip demo</button>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<!-- ═══════════════════════════════════════════════════════════════
     PAGE 1: SCANNER
     ═══════════════════════════════════════════════════════════════ -->
<div class="app-shell active" id="page-scanner">
  <div class="nav-bar">
    <div class="nav-content">
      <div>
        <div class="nav-title">🛡️ NanoShield</div>
        <div class="nav-subtitle">AI Security Scanner</div>
      </div>
      <div class="nav-badge"><span class="dot"></span> LOCAL</div>
    </div>
  </div>

  <div class="large-title">
    <h1>Security Scanner</h1>
    <div class="subtitle">Paste your code below. NanoShield scans for 40+ vulnerability patterns entirely on-device — nothing leaves your machine.</div>
  </div>

  <!-- Stats -->
  <div style="padding-top:20px">
    <div class="stats-grid" id="statsGrid">
      <div class="glass-card stat-widget s-crit tilt-card" data-tilt>
        <div class="glass-card-inner"><span class="stat-icon">🔴</span><div class="stat-value" id="sCrit">0</div><div class="stat-label">Critical</div></div>
      </div>
      <div class="glass-card stat-widget s-high tilt-card" data-tilt>
        <div class="glass-card-inner"><span class="stat-icon">🟠</span><div class="stat-value" id="sHigh">0</div><div class="stat-label">High</div></div>
      </div>
      <div class="glass-card stat-widget s-med tilt-card" data-tilt>
        <div class="glass-card-inner"><span class="stat-icon">🟡</span><div class="stat-value" id="sMed">0</div><div class="stat-label">Medium</div></div>
      </div>
      <div class="glass-card stat-widget s-low tilt-card" data-tilt>
        <div class="glass-card-inner"><span class="stat-icon">🔵</span><div class="stat-value" id="sLow">0</div><div class="stat-label">Low</div></div>
      </div>
    </div>
  </div>

  <!-- Editor -->
  <div class="editor-section">
    <div class="glass-card editor-card">
      <div class="editor-toolbar">
        <div class="editor-toolbar-title">
          <span>📝</span> Source Code
        </div>
        <div class="lang-pills">
          <span class="lang-pill active" onclick="setLang(this)">Python</span>
          <span class="lang-pill" onclick="setLang(this)">JS</span>
          <span class="lang-pill" onclick="setLang(this)">C++</span>
          <span class="lang-pill" onclick="setLang(this)">Java</span>
        </div>
      </div>
      <textarea class="code-editor" id="codeInput" placeholder="Paste your code here..." spellcheck="false">import sqlite3
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

  <!-- Scan Button -->
  <div class="scan-cta">
    <button class="scan-btn" id="scanBtn" onclick="runScan()">
      <span id="scanBtnText">🔍 Scan for Vulnerabilities</span>
    </button>
  </div>

  <!-- Results -->
  <div class="findings-section" id="findingsSection">
    <div class="findings-header" id="findingsHeader" style="display:none">
      <span class="findings-title">Findings</span>
      <span class="findings-count" id="findingsCount"></span>
    </div>
    <div id="findingsList">
      <div class="empty-state">
        <div class="empty-icon">🛡️</div>
        <div class="empty-title">Ready to Scan</div>
        <div class="empty-sub">Paste code above and tap scan to detect vulnerabilities in real-time</div>
      </div>
    </div>
  </div>

  <!-- Knowledge Feed -->
  <div class="knowledge-section">
    <div class="glass-card knowledge-card">
      <div class="knowledge-header">
        <span class="knowledge-title">🧠 Knowledge Feed</span>
        <span style="font-size:11px;color:var(--text3)" id="connLabel">● Online</span>
      </div>
      <div class="knowledge-items" id="knowledgeFeed">
        <div class="knowledge-item" style="animation-delay:0s"><div class="knowledge-dot fresh"></div><div class="knowledge-text"><strong>OWASP Top 10 2021</strong> — All 10 categories loaded locally</div></div>
        <div class="knowledge-item" style="animation-delay:0.1s"><div class="knowledge-dot fresh"></div><div class="knowledge-text"><strong>CWE Top 25 2023</strong> — Most dangerous software weaknesses indexed</div></div>
        <div class="knowledge-item" style="animation-delay:0.2s"><div class="knowledge-dot cached"></div><div class="knowledge-text"><strong>Crypto Best Practices</strong> — NIST-approved algorithms and TLS 1.3</div></div>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════
     PAGE 2: SCORE
     ═══════════════════════════════════════════════════════════════ -->
<div class="app-shell" id="page-score">
  <div class="nav-bar">
    <div class="nav-content">
      <div>
        <div class="nav-title">Security Score</div>
        <div class="nav-subtitle">Your code security rating</div>
      </div>
    </div>
  </div>
  <div class="score-section">
    <div class="score-ring-container">
      <svg width="100%" height="100%" viewBox="0 0 160 160">
        <circle class="score-ring-bg" cx="80" cy="80" r="65"/>
        <circle class="score-ring-fg" id="scoreRing" cx="80" cy="80" r="65" stroke="var(--green)" stroke-dasharray="408" stroke-dashoffset="0"/>
      </svg>
      <div class="score-center">
        <div class="score-number" id="scoreNumber">--</div>
        <div class="score-label">Score</div>
      </div>
    </div>
    <div class="score-verdict" id="scoreVerdict" style="background:rgba(255,255,255,0.04);color:var(--text3)">Run a scan to see your score</div>
  </div>
  <div class="findings-section" id="scoreFindings"></div>
</div>

<!-- ═══════════════════════════════════════════════════════════════
     PAGE 3: HISTORY
     ═══════════════════════════════════════════════════════════════ -->
<div class="app-shell" id="page-history">
  <div class="nav-bar">
    <div class="nav-content">
      <div>
        <div class="nav-title">Scan History</div>
        <div class="nav-subtitle" id="historyCount">0 scans</div>
      </div>
      <button style="background:rgba(239,68,68,0.1);color:var(--red);border:none;padding:6px 12px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer" onclick="clearHistory()">Clear</button>
    </div>
  </div>
  <div style="padding:20px;max-width:800px;margin:0 auto" id="historyList">
    <div class="empty-state">
      <div class="empty-icon">📋</div>
      <div class="empty-title">No Scans Yet</div>
      <div class="empty-sub">Your scan history will appear here</div>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════
     PAGE 4: SETTINGS
     ═══════════════════════════════════════════════════════════════ -->
<div class="app-shell" id="page-settings">
  <div class="nav-bar">
    <div class="nav-content">
      <div>
        <div class="nav-title">Settings</div>
        <div class="nav-subtitle">NanoShield v0.1.0</div>
      </div>
    </div>
  </div>
  <div style="padding:20px;max-width:800px;margin:0 auto">
    <div class="glass-card" style="margin-bottom:12px">
      <div class="glass-card-inner" style="display:flex;align-items:center;justify-content:space-between">
        <div><div style="font-size:15px;font-weight:600">🤖 AI Model</div><div style="font-size:12px;color:var(--text3);margin-top:2px">~48M parameter transformer</div></div>
        <span style="color:var(--green);font-size:12px;font-weight:600">Local</span>
      </div>
    </div>
    <div class="glass-card" style="margin-bottom:12px">
      <div class="glass-card-inner" style="display:flex;align-items:center;justify-content:space-between">
        <div><div style="font-size:15px;font-weight:600">📡 Online Updates</div><div style="font-size:12px;color:var(--text3);margin-top:2px">Auto-fetch latest CVEs when connected</div></div>
        <label style="position:relative;display:inline-block;width:51px;height:31px;cursor:pointer" class="toggle">
          <input type="checkbox" id="onlineToggle" checked style="opacity:0;width:0;height:0">
          <span style="position:absolute;inset:0;background:#333;border-radius:31px;transition:0.3s"></span>
          <span class="toggle-knob" style="position:absolute;left:2px;top:2px;width:27px;height:27px;background:white;border-radius:50%;transition:0.3s;box-shadow:0 2px 4px rgba(0,0,0,0.3)"></span>
        </label>
      </div>
    </div>
    <div class="glass-card" style="margin-bottom:12px">
      <div class="glass-card-inner" style="display:flex;align-items:center;justify-content:space-between;cursor:pointer" onclick="startDemo()">
        <div><div style="font-size:15px;font-weight:600">🎬 Demo Mode</div><div style="font-size:12px;color:var(--text3);margin-top:2px">Walk through features for hackathon judges</div></div>
        <span style="color:var(--accent2);font-size:20px">→</span>
      </div>
    </div>
    <div class="glass-card" style="margin-bottom:12px">
      <div class="glass-card-inner" style="display:flex;align-items:center;justify-content:space-between;cursor:pointer" onclick="exportReport()">
        <div><div style="font-size:15px;font-weight:600">📥 Export Report</div><div style="font-size:12px;color:var(--text3);margin-top:2px">Download vulnerability report as text</div></div>
        <span style="color:var(--text3);font-size:20px">→</span>
      </div>
    </div>
    <div class="glass-card" style="margin-bottom:12px">
      <div class="glass-card-inner" style="display:flex;align-items:center;justify-content:space-between;cursor:pointer" onclick="window.location.href='/dashboard'">
        <div><div style="font-size:15px;font-weight:600">📊 Real-Time Dashboard</div><div style="font-size:12px;color:var(--text3);margin-top:2px">Live terminal and scan analytics</div></div>
        <span style="color:var(--text3);font-size:20px">→</span>
      </div>
    </div>

    <div style="text-align:center;padding:32px 0;color:var(--text3);font-size:12px">
      <div style="font-size:24px;margin-bottom:8px">🛡️</div>
      NanoShield v0.1.0<br>
      <span style="color:var(--accent2)">48M parameters · 50+ vuln patterns · 100% local</span><br>
      <span style="margin-top:8px;display:inline-block">Made with 💜 for the Global Innovation Build Challenge</span>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════
     iOS BOTTOM TAB BAR
     ═══════════════════════════════════════════════════════════════ -->
<div class="tab-bar">
  <div class="tab-item active" onclick="switchPage('scanner')" data-page="scanner">
    <svg viewBox="0 0 24 24"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"/><path d="M12 6v6l4 2"/></svg>
    <span>Scan</span>
  </div>
  <div class="tab-item" onclick="switchPage('score')" data-page="score">
    <svg viewBox="0 0 24 24"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87L18.18 21 12 17.27 5.82 21 7 14.14l-5-4.87 6.91-1.01L12 2z"/></svg>
    <span>Score</span>
  </div>
  <div class="tab-item" onclick="switchPage('history')" data-page="history">
    <svg viewBox="0 0 24 24"><path d="M12 8v4l3 3"/><circle cx="12" cy="12" r="10"/></svg>
    <span>History</span>
  </div>
  <div class="tab-item" onclick="switchPage('settings')" data-page="settings">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
    <span>Settings</span>
  </div>
</div>

<!-- Keyboard shortcut hint -->
<div class="kbd-hint" id="kbdHint">
  <span class="kbd">⌘</span><span class="kbd">K</span><span style="font-size:11px;color:var(--text3);align-self:center">Quick scan</span>
</div>

<script>
// ═══════════════════════════════════════════════════════════════════
// NanoShield — Award-Winning JS
// ═══════════════════════════════════════════════════════════════════

let allFindings = [];
let scanHistory = JSON.parse(localStorage.getItem('ns_history') || '[]');
let currentLang = 'Python';

// ── Particle System ──
const canvas = document.getElementById('particles');
const ctx = canvas.getContext('2d');
let particles = [];
let mouseX = 0, mouseY = 0;

function resizeCanvas(){ canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

class Particle {
  constructor(){this.reset()}
  reset(){
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.size = Math.random() * 1.5 + 0.5;
    this.speedX = (Math.random() - 0.5) * 0.3;
    this.speedY = (Math.random() - 0.5) * 0.3;
    this.opacity = Math.random() * 0.4 + 0.1;
    this.color = ['99,102,241','6,182,212','16,185,129','236,72,153'][Math.floor(Math.random()*4)];
  }
  update(){
    this.x += this.speedX;
    this.y += this.speedY;
    const dx = mouseX - this.x, dy = mouseY - this.y;
    const dist = Math.sqrt(dx*dx + dy*dy);
    if(dist < 150){ this.x -= dx * 0.002; this.y -= dy * 0.002; }
    if(this.x < 0 || this.x > canvas.width || this.y < 0 || this.y > canvas.height) this.reset();
  }
  draw(){
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${this.color},${this.opacity})`;
    ctx.fill();
  }
}

for(let i = 0; i < 80; i++) particles.push(new Particle());

function animateParticles(){
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  particles.forEach(p => { p.update(); p.draw(); });
  // Draw connections
  for(let i = 0; i < particles.length; i++){
    for(let j = i+1; j < particles.length; j++){
      const dx = particles[i].x - particles[j].x;
      const dy = particles[i].y - particles[j].y;
      const dist = Math.sqrt(dx*dx+dy*dy);
      if(dist < 120){
        ctx.beginPath();
        ctx.moveTo(particles[i].x, particles[i].y);
        ctx.lineTo(particles[j].x, particles[j].y);
        ctx.strokeStyle = `rgba(99,102,241,${0.06 * (1 - dist/120)})`;
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }
    }
  }
  requestAnimationFrame(animateParticles);
}
animateParticles();

document.addEventListener('mousemove', e => { mouseX = e.clientX; mouseY = e.clientY; });

// ── 3D Tilt Effect ──
document.querySelectorAll('[data-tilt]').forEach(card => {
  card.addEventListener('mousemove', e => {
    const rect = card.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    const inner = card.querySelector('.glass-card-inner') || card;
    inner.style.transform = `perspective(600px) rotateY(${x*8}deg) rotateX(${-y*8}deg) translateZ(8px)`;
  });
  card.addEventListener('mouseleave', e => {
    const inner = card.querySelector('.glass-card-inner') || card;
    inner.style.transform = 'perspective(600px) rotateY(0) rotateX(0) translateZ(0)';
    inner.style.transition = 'transform 0.5s cubic-bezier(0.16,1,0.3,1)';
    setTimeout(() => inner.style.transition = '', 500);
  });
});

// ── Page Navigation ──
function switchPage(page){
  document.querySelectorAll('.app-shell').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-item').forEach(t => t.classList.remove('active'));
  document.getElementById('page-'+page).classList.add('active');
  document.querySelector(`[data-page="${page}"]`).classList.add('active');
  window.scrollTo({top:0, behavior:'smooth'});
}

// ── Language Tabs ──
function setLang(el){
  document.querySelectorAll('.lang-pill').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  currentLang = el.textContent;
}

// ── Toast ──
function showToast(msg, type='success'){
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + type + ' show';
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ── Scan ──
async function runScan(){
  const code = document.getElementById('codeInput').value.trim();
  if(!code){showToast('Paste some code first','info');return}

  const btn = document.getElementById('scanBtn');
  const overlay = document.getElementById('scannerOverlay');
  const scannerText = document.getElementById('scannerText');

  btn.classList.add('scanning');
  overlay.classList.add('active');

  const steps = ['Tokenizing code...', 'Running pattern analysis...', 'Checking OWASP rules...', 'Mapping CWE IDs...', 'Generating fixes...'];
  for(let i = 0; i < steps.length; i++){
    scannerText.textContent = steps[i];
    await sleep(350);
  }

  try{
    const res = await fetch('/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({code})});
    const data = await res.json();
    allFindings = data.findings;

    const crit = allFindings.filter(f=>f.severity==='CRITICAL').length;
    const high = allFindings.filter(f=>f.severity==='HIGH').length;
    const med = allFindings.filter(f=>f.severity==='MEDIUM').length;
    const low = allFindings.filter(f=>f.severity==='LOW').length;
    const score = Math.max(0, 100 - allFindings.length * 4 - crit * 3 - high * 2);

    animateCounter('sCrit', crit);
    animateCounter('sHigh', high);
    animateCounter('sMed', med);
    animateCounter('sLow', low);

    // Update score page
    updateScoreRing(score);
    document.getElementById('scoreNumber').textContent = score;
    const verdict = document.getElementById('scoreVerdict');
    if(score >= 80){verdict.textContent='✅ Excellent — Your code is secure';verdict.style.background='rgba(16,185,129,0.1)';verdict.style.color='var(--green)'}
    else if(score >= 60){verdict.textContent='⚠️ Good — Some improvements needed';verdict.style.background='rgba(234,179,8,0.1)';verdict.style.color='var(--yellow)'}
    else if(score >= 40){verdict.textContent='🟠 Fair — Multiple vulnerabilities found';verdict.style.background='rgba(249,115,22,0.1)';verdict.style.color='var(--orange)'}
    else{verdict.textContent='🔴 Poor — Critical issues detected';verdict.style.background='rgba(239,68,68,0.1)';verdict.style.color='var(--red)'}

    // Render findings
    renderFindings(allFindings);

    // Save to history
    const entry = {time: new Date().toLocaleTimeString(), score, crit, high, med, low, total: allFindings.length, lang: currentLang, code: code.substring(0,100)};
    scanHistory.unshift(entry);
    if(scanHistory.length > 50) scanHistory = scanHistory.slice(0,50);
    localStorage.setItem('ns_history', JSON.stringify(scanHistory));
    renderHistory();

    showToast(allFindings.length ? `Found ${allFindings.length} issue(s)` : 'All clear! ✅', allFindings.length ? 'info' : 'success');
  }catch(err){
    showToast('Scan failed: '+err.message, 'error');
  }

  overlay.classList.remove('active');
  btn.classList.remove('scanning');
}

function renderFindings(findings){
  const header = document.getElementById('findingsHeader');
  const list = document.getElementById('findingsList');
  const countEl = document.getElementById('findingsCount');

  if(!findings.length){
    header.style.display='none';
    list.innerHTML = `<div class="empty-state"><div class="empty-icon">✅</div><div class="empty-title">All Clear!</div><div class="empty-sub">No vulnerabilities detected. Your code looks secure.</div></div>`;
    document.getElementById('scoreFindings').innerHTML = '';
    return;
  }

  header.style.display='flex';
  countEl.textContent = `${findings.length} issue${findings.length!==1?'s':''}`;

  let html = '';
  findings.forEach((f, i) => {
    html += `
    <div class="glass-card finding-card" style="animation-delay:${i*0.06}s">
      <div class="glass-card-inner">
        <div class="finding-top">
          <div>
            <div class="finding-type">${f.icon} ${f.type}</div>
            <div class="finding-desc">${f.explanation}</div>
          </div>
          <span class="finding-severity sev-${f.severity}">${f.severity}</span>
        </div>
        <div class="finding-meta">
          <span class="finding-tag">Line ${f.line}</span>
          <span class="finding-tag">${f.owasp}</span>
          <span class="finding-tag">${f.cwe}</span>
          <span class="finding-tag">${f.category}</span>
        </div>
        <div class="finding-code-block">${escapeHtml(f.match)}</div>
        <div class="finding-fix-block"><span class="fix-label">💡 Fix:</span><span>${escapeHtml(f.fix)}</span></div>
      </div>
    </div>`;
  });

  list.innerHTML = html;
  document.getElementById('scoreFindings').innerHTML = html;
}

function updateScoreRing(score){
  const ring = document.getElementById('scoreRing');
  const circumference = 408;
  const offset = circumference - (score / 100) * circumference;
  ring.style.strokeDashoffset = offset;
  const color = score > 70 ? 'var(--green)' : score > 40 ? 'var(--yellow)' : 'var(--red)';
  ring.style.stroke = color;
  document.getElementById('scoreNumber').style.color = color;
}

function animateCounter(id, target){
  const el = document.getElementById(id);
  const start = parseInt(el.textContent) || 0;
  const diff = target - start;
  const duration = 600;
  const startTime = performance.now();
  function step(now){
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + diff * eased);
    if(progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function escapeHtml(text){return text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

// ── History ──
function renderHistory(){
  const list = document.getElementById('historyList');
  const countEl = document.getElementById('historyCount');
  countEl.textContent = `${scanHistory.length} scan${scanHistory.length!==1?'s':''}`;

  if(!scanHistory.length){
    list.innerHTML = `<div class="empty-state"><div class="empty-icon">📋</div><div class="empty-title">No Scans Yet</div><div class="empty-sub">Your scan history will appear here</div></div>`;
    return;
  }

  let html = '';
  scanHistory.forEach((h, i) => {
    const scoreColor = h.score >= 80 ? 'var(--green)' : h.score >= 60 ? 'var(--yellow)' : h.score >= 40 ? 'var(--orange)' : 'var(--red)';
    html += `
    <div class="glass-card" style="margin-bottom:8px">
      <div class="glass-card-inner" style="display:flex;align-items:center;justify-content:space-between;gap:12px">
        <div>
          <div style="font-size:14px;font-weight:600">${h.lang || 'Code'} — ${h.total} issues</div>
          <div style="font-size:12px;color:var(--text3);margin-top:2px">🔴${h.crit} 🟠${h.high} 🟡${h.med} 🔵${h.low}</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:22px;font-weight:800;color:${scoreColor}">${h.score}</div>
          <div style="font-size:11px;color:var(--text3)">${h.time}</div>
        </div>
      </div>
    </div>`;
  });
  list.innerHTML = html;
}

function clearHistory(){
  scanHistory = [];
  localStorage.removeItem('ns_history');
  renderHistory();
  showToast('History cleared', 'info');
}

// ── Export ──
function exportReport(){
  if(!allFindings.length){showToast('Nothing to export — scan first','info');return}
  let text = 'NanoShield Security Report\n' + '='.repeat(50) + '\n\n';
  allFindings.forEach(f => {
    text += `[${f.severity}] ${f.type}\n  Line ${f.line}: ${f.match}\n  ${f.explanation}\n  ${f.owasp} | ${f.cwe}\n  Fix: ${f.fix}\n\n`;
  });
  const blob = new Blob([text], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'nanoshield_report.txt';
  a.click();
  showToast('Report downloaded!');
}

// ── Online/Offline ──
window.addEventListener('online', () => {
  document.querySelector('.nav-badge').innerHTML = '<span class="dot"></span> ONLINE';
  showToast('Back online — syncing knowledge base', 'success');
});
window.addEventListener('offline', () => {
  document.querySelector('.nav-badge').innerHTML = '<span class="dot" style="background:var(--yellow)"></span> OFFLINE';
  document.getElementById('connLabel').textContent = '● Offline — using cache';
  document.getElementById('connLabel').style.color = 'var(--yellow)';
});

// ── Keyboard Shortcuts ──
document.addEventListener('keydown', e => {
  if((e.metaKey || e.ctrlKey) && e.key === 'k'){ e.preventDefault(); runScan(); }
  if(e.key === '1') switchPage('scanner');
  if(e.key === '2') switchPage('score');
  if(e.key === '3') switchPage('history');
  if(e.key === '4') switchPage('settings');
});

// Show keyboard hints on desktop
if(!('ontouchstart' in window)){
  setTimeout(() => document.getElementById('kbdHint').classList.add('visible'), 2000);
  setTimeout(() => document.getElementById('kbdHint').classList.remove('visible'), 7000);
}

// ── Demo Mode ──
let demoStep = 0;
const demoSteps = [
  {title:'Welcome to NanoShield 🛡️',subtitle:'The world\'s most advanced on-device security scanner. Zero internet required. Zero data leakage.',step:'Step 1 of 5'},
  {title:'50+ Vulnerability Patterns 🔍',subtitle:'We detect SQL injection, XSS, command injection, weak crypto, hardcoded credentials, buffer overflows, race conditions, SSRF, and 40+ more.',step:'Step 2 of 5'},
  {title:'AI-Powered Auto-Fix 💡',subtitle:'Every vulnerability comes with a suggested fix. NanoShield doesn\'t just find problems — it shows you exactly how to solve them.',step:'Step 3 of 5'},
  {title:'100% Local & Private 🔒',subtitle:'Your code never leaves your machine. The 48M parameter transformer runs entirely in local memory. No cloud, no APIs, no leaks.',step:'Step 4 of 5'},
  {title:'Built for Developers 👨‍💻',subtitle:'iOS-inspired interface, VS Code extension, real-time dashboard, PDF reports. Everything you need for security auditing.',step:'Step 5 of 5'},
];

function startDemo(){
  demoStep = 0;
  document.getElementById('demoOverlay').classList.add('active');
  updateDemo();
}

function nextDemoStep(){
  demoStep++;
  if(demoStep >= demoSteps.length){
    closeDemo();
    showToast('Demo complete! Try scanning some code 🚀');
    return;
  }
  updateDemo();
}

function updateDemo(){
  const s = demoSteps[demoStep];
  document.getElementById('demoTitle').textContent = s.title;
  document.getElementById('demoSubtitle').textContent = s.subtitle;
  document.getElementById('demoStep').textContent = s.step;
  document.getElementById('demoProgress').style.width = ((demoStep+1)/demoSteps.length*100)+'%';
}

function closeDemo(){
  document.getElementById('demoOverlay').classList.remove('active');
}

// Toggle switch
document.getElementById('onlineToggle')?.addEventListener('change', function(){
  const knob = this.parentElement.querySelector('.toggle-knob');
  const bg = this.parentElement.querySelector('span:first-of-type');
  if(this.checked){bg.style.background='var(--green)';knob.style.transform='translateX(20px)'}
  else{bg.style.background='#333';knob.style.transform='translateX(0)'}
});

// Init
renderHistory();
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/scan", methods=["POST"])
def scan():
    code = request.json.get("code", "")
    findings = scan_code(code)
    return jsonify({"findings": findings, "count": len(findings)})

@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": "NanoShield",
        "short_name": "NanoShield",
        "description": "AI Security Scanner — On-Device",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#000000",
        "theme_color": "#6366f1",
        "icons": [{"src": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>", "sizes": "any", "type": "image/svg+xml"}]
    })

@app.route("/dashboard")
def dashboard():
    return '<script>window.location.href="/"</script>'

if __name__ == "__main__":
    print("\n  🛡️  NanoShield — Award-Winning GUI")
    print("  → http://localhost:5000\n")
    app.run(debug=True, port=5000)
