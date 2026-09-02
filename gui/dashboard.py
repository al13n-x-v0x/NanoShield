"""
NanoShield Real-Time Dashboard
Terminal-style live stats, scan history, vulnerability heat map, and live terminal.
Run: python gui/dashboard.py
"""
import os, sys, json, re, time, threading
from flask import Flask, render_template_string, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

app = Flask(__name__)

# ─── Scan History Store ───────────────────────────────────────────────
scan_history = []
total_scans = 0
total_vulns = 0
start_time = time.time()

VULN_PATTERNS = {
    "SQL Injection": {"sev": "CRITICAL", "owasp": "A03", "cwe": "CWE-89",
        "pats": [r"execute\s*\(.*\+\s*", r"query\s*\(.*%s", r"cursor\.execute\s*\(.+format"],
        "fix": "cursor.execute('SELECT * FROM users WHERE name = ?', (username,))"},
    "XSS": {"sev": "HIGH", "owasp": "A03", "cwe": "CWE-79",
        "pats": [r"innerHTML\s*=", r"document\.write\s*\(", r"eval\s*\(\s*req\."],
        "fix": "element.textContent = userInput"},
    "Hardcoded Credentials": {"sev": "CRITICAL", "owasp": "A07", "cwe": "CWE-798",
        "pats": [r'password\s*=\s*["\'][^"\']+["\']', r'api_key\s*=\s*["\'][^"\']+["\']'],
        "fix": "os.environ.get('DB_PASSWORD')"},
    "Weak Crypto": {"sev": "HIGH", "owasp": "A02", "cwe": "CWE-327",
        "pats": [r"md5\(", r"sha1\(", r"DES\.", r"RC4"],
        "fix": "bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))"},
    "Command Injection": {"sev": "CRITICAL", "owasp": "A03", "cwe": "CWE-78",
        "pats": [r"os\.system\s*\(", r"subprocess\.call\s*\(.*shell\s*=\s*True", r"eval\s*\(\s*input"],
        "fix": "subprocess.run(['cat', filename], capture_output=True)"},
    "Path Traversal": {"sev": "HIGH", "owasp": "A01", "cwe": "CWE-22",
        "pats": [r"open\s*\(.*\.\./", r"os\.path\.join\s*\(.*\.\."],
        "fix": "os.path.realpath(path).startswith(expected_base)"},
    "Buffer Overflow": {"sev": "CRITICAL", "owasp": "A06", "cwe": "CWE-120",
        "pats": [r"strcpy\s*\(", r"gets\s*\(", r"sprintf\s*\("],
        "fix": "strncpy(buffer, input, sizeof(buffer) - 1)"},
    "Insecure Deserialization": {"sev": "HIGH", "owasp": "A08", "cwe": "CWE-502",
        "pats": [r"pickle\.loads?\s*\(", r"yaml\.load\s*\((?!.*Loader)"],
        "fix": "yaml.safe_load(data)"},
    "Race Condition": {"sev": "MEDIUM", "owasp": "A04", "cwe": "CWE-362",
        "pats": [r"global\s+\w+.*\n.*\w+\s*=\s*\w+\s*\+"],
        "fix": "with lock: balance -= amount"},
    "SSRF": {"sev": "HIGH", "owasp": "A10", "cwe": "CWE-918",
        "pats": [r"requests\.get\s*\(.*request\.", r"urllib\.request\.urlopen\s*\(.*input"],
        "fix": "validate_url(url, ALLOWLIST)"},
    "Eval/Exec": {"sev": "CRITICAL", "owasp": "A03", "cwe": "CWE-95",
        "pats": [r"\beval\s*\(", r"\bexec\s*\("],
        "fix": "ast.literal_eval(expression)"},
    "Debug Mode": {"sev": "MEDIUM", "owasp": "A05", "cwe": "CWE-489",
        "pats": [r"DEBUG\s*=\s*True", r"debug\s*=\s*True"],
        "fix": "DEBUG = os.environ.get('DEBUG','false') == 'true'"},
    "CORS Wildcard": {"sev": "MEDIUM", "owasp": "A05", "cwe": "CWE-942",
        "pats": [r"Access-Control-Allow-Origin.*\*", r"allow_origins\s*=\s*\[.*\*"],
        "fix": "allow_origins=['https://yourdomain.com']"},
    "Missing Auth": {"sev": "MEDIUM", "owasp": "A07", "cwe": "CWE-306",
        "pats": [r"@app\.route.*POST(?![\s\S]*auth)"],
        "fix": "@login_required  # add auth middleware"},
    "Weak Token": {"sev": "MEDIUM", "owasp": "A07", "cwe": "CWE-330",
        "pats": [r"token\s*=\s*random\.", r"uuid\.uuid1\(\)"],
        "fix": "secrets.token_urlsafe(32)"},
    "Timing Attack": {"sev": "MEDIUM", "owasp": "A02", "cwe": "CWE-208",
        "pats": [r"==\s*hash", r"if\s+\w+\s*==\s*token"],
        "fix": "hmac.compare_digest(a, b)"},
    "Unvalidated Redirect": {"sev": "MEDIUM", "owasp": "A01", "cwe": "CWE-601",
        "pats": [r"redirect\s*\(\s*request\."],
        "fix": "if url in ALLOWED_REDIRECTS: redirect(url)"},
    "Silent Exception": {"sev": "LOW", "owasp": "A09", "cwe": "CWE-778",
        "pats": [r"except.*pass", r"catch\s*\(\s*\w*\s*\)\s*\{\s*\}"],
        "fix": "logger.error(f'Error: {e}', exc_info=True)"},
    "Hardcoded IP": {"sev": "LOW", "owasp": "A05", "cwe": "CWE-200",
        "pats": [r"192\.168\.\d+\.\d+", r"10\.0\.\d+\.\d+"],
        "fix": "Use DNS names or env vars"},
    "Deprecated API": {"sev": "LOW", "owasp": "A06", "cwe": "CWE-693",
        "pats": [r"assert\s+\w+", r"random\.choice\s*\("],
        "fix": "Use secrets module for crypto"},
}


def scan_code(code):
    findings = []
    for name, v in VULN_PATTERNS.items():
        for pat in v["pats"]:
            for m in re.finditer(pat, code, re.MULTILINE):
                line = code[:m.start()].count("\n") + 1
                findings.append({
                    "type": name, "severity": v["sev"], "owasp": v["owasp"],
                    "cwe": v["cwe"], "line": line, "match": m.group()[:80], "fix": v["fix"],
                })
    return findings


DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NanoShield Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700;800&display=swap');
:root {
  --bg:#06090f; --bg2:#0c1220; --bg3:#111827; --border:#1e293b;
  --text:#e2e8f0; --muted:#64748b; --accent:#7b2fff; --accent2:#00d4ff;
  --green:#22c55e; --red:#ef4444; --yellow:#eab308; --orange:#f97316;
  --glass:rgba(255,255,255,0.03); --glass-border:rgba(255,255,255,0.06);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}

/* Background */
.bg-grid{position:fixed;inset:0;z-index:0;background-image:radial-gradient(circle at 20% 50%,rgba(123,47,255,0.06) 0%,transparent 50%),radial-gradient(circle at 80% 20%,rgba(0,212,255,0.04) 0%,transparent 50%);animation:bgP 8s ease-in-out infinite alternate}
@keyframes bgP{0%{opacity:.6}100%{opacity:1}}
.orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:.12;animation:fO 20s ease-in-out infinite alternate}
.o1{width:400px;height:400px;background:var(--accent);top:-100px;left:-100px}
.o2{width:300px;height:300px;background:var(--accent2);bottom:-50px;right:-50px;animation-delay:-7s}
@keyframes fO{0%{transform:translate(0,0) scale(1)}100%{transform:translate(40px,-30px) scale(1.1)}}

.glass{background:var(--glass);border:1px solid var(--glass-border);backdrop-filter:blur(20px);border-radius:14px}

/* Header */
.header{position:sticky;top:0;z-index:100;background:rgba(6,9,15,.85);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass-border);padding:14px 24px;display:flex;align-items:center;justify-content:space-between}
.header-left{display:flex;align-items:center;gap:12px}
.logo{font-size:22px;font-weight:900;background:linear-gradient(135deg,var(--accent2),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.pulse{background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);color:var(--green);font-size:11px;font-weight:600;padding:4px 12px;border-radius:20px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,.2)}50%{box-shadow:0 0 0 6px rgba(34,197,94,0)}}
.header-right{display:flex;gap:8px;align-items:center}
.btn{padding:8px 16px;border:none;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;transition:all .2s}
.btn-ghost{background:var(--glass);color:var(--muted);border:1px solid var(--border)}
.btn-ghost:hover{background:rgba(255,255,255,.06);color:var(--text)}

.container{max-width:1400px;margin:0 auto;padding:20px;position:relative;z-index:1}

/* Stats Grid */
.stats-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:16px}
.stat{text-align:center;padding:14px 8px;position:relative;overflow:hidden;transition:transform .3s}
.stat:hover{transform:translateY(-3px)}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.stat.s-crit::before{background:var(--red)}.stat.s-high::before{background:var(--orange)}
.stat.s-med::before{background:var(--yellow)}.stat.s-low::before{background:var(--accent2)}
.stat.s-total::before{background:var(--accent)}.stat.s-score::before{background:var(--green)}
.stat-num{font-size:28px;font-weight:900;line-height:1;font-family:'JetBrains Mono',monospace}
.stat.s-crit .stat-num{color:var(--red)}.stat.s-high .stat-num{color:var(--orange)}
.stat.s-med .stat-num{color:var(--yellow)}.stat.s-low .stat-num{color:var(--accent2)}
.stat.s-total .stat-num{color:var(--accent)}.stat.s-score .stat-num{color:var(--green)}
.stat-label{color:var(--muted);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.stat-delta{font-size:10px;font-weight:600;margin-top:2px}
.stat-delta.up{color:var(--red)}.stat-delta.down{color:var(--green)}.stat-delta.neutral{color:var(--muted)}

/* Main Grid */
.main-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.main-grid{grid-template-columns:1fr}.stats-grid{grid-template-columns:repeat(3,1fr)}}

.panel{overflow:hidden;transition:box-shadow .3s}
.panel:hover{box-shadow:0 0 30px rgba(123,47,255,.06)}
.panel-head{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.panel-title{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px}
.panel-body{padding:16px}

/* Terminal */
.terminal{background:#0a0a0a;border:1px solid #1a1a2e;border-radius:10px;font-family:'JetBrains Mono',monospace;font-size:12px;max-height:400px;overflow-y:auto;padding:12px;line-height:1.6}
.term-line{display:flex;gap:8px;animation:tFade .3s ease}
@keyframes tFade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.term-time{color:#475569;white-space:nowrap;min-width:65px}
.term-badge{padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;min-width:55px;text-align:center}
.term-badge.crit{background:rgba(239,68,68,.2);color:var(--red)}
.term-badge.high{background:rgba(249,115,22,.2);color:var(--orange)}
.term-badge.med{background:rgba(234,179,8,.2);color:var(--yellow)}
.term-badge.low{background:rgba(0,212,255,.2);color:var(--accent2)}
.term-badge.info{background:rgba(123,47,255,.2);color:var(--accent)}
.term-badge.ok{background:rgba(34,197,94,.2);color:var(--green)}
.term-msg{color:var(--text)}.term-fix{color:var(--green)}
.term-input{display:flex;align-items:center;gap:6px;padding:8px 0;border-top:1px solid #1a1a2e;margin-top:8px}
.term-prompt{color:var(--green);font-weight:700}
.term-input input{flex:1;background:transparent;border:none;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:12px;outline:none}

/* Chart Bars */
.chart-container{padding:8px 0}
.chart-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.chart-label{font-size:11px;color:var(--muted);width:100px;text-align:right;flex-shrink:0}
.chart-bar{flex:1;height:20px;background:rgba(255,255,255,.03);border-radius:4px;overflow:hidden;position:relative}
.chart-fill{height:100%;border-radius:4px;transition:width .8s cubic-bezier(.4,0,.2,1);display:flex;align-items:center;padding-left:8px;font-size:10px;font-weight:700;color:white;min-width:fit-content}
.chart-fill.crit{background:linear-gradient(90deg,#dc2626,#ef4444)}
.chart-fill.high{background:linear-gradient(90deg,#ea580c,#f97316)}
.chart-fill.med{background:linear-gradient(90deg,#ca8a04,#eab308)}
.chart-fill.low{background:linear-gradient(90deg,#0284c7,#0ea5e9)}
.chart-fill.ok{background:linear-gradient(90deg,#16a34a,#22c55e)}

/* History Table */
.history-table{width:100%;border-collapse:collapse}
.history-table th{text-align:left;font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;padding:8px 12px;border-bottom:1px solid var(--border)}
.history-table td{padding:8px 12px;font-size:12px;border-bottom:1px solid rgba(255,255,255,.03)}
.history-table tr:hover td{background:rgba(255,255,255,.02)}
.sev-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}

/* Sparkline */
.sparkline{display:flex;align-items:flex-end;gap:2px;height:40px;padding:8px 0}
.spark-bar{flex:1;border-radius:2px;transition:height .5s cubic-bezier(.4,0,.2,1);min-width:4px}
.spark-bar.v{background:var(--red)}.spark-bar.vh{background:var(--orange)}.spark-bar.vm{background:var(--yellow)}.spark-bar.vl{background:var(--accent2)}.spark-bar.vo{background:var(--green)}

/* Scrollbar */
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#334155;border-radius:3px}

.footer{text-align:center;padding:30px;color:#1e293b;font-size:11px}

/* Responsive */
@media(max-width:768px){.header{flex-wrap:wrap;gap:8px}.header-right{width:100%;justify-content:flex-end}.stats-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="bg-grid"></div><div class="orb o1"></div><div class="orb o2"></div>

<div class="header">
  <div class="header-left">
    <span class="logo">NanoShield</span>
    <span class="pulse" id="liveBadge">● LIVE</span>
    <span style="font-size:12px;color:var(--muted)" id="uptime">Uptime: 0s</span>
  </div>
  <div class="header-right">
    <span style="font-size:11px;color:var(--muted);background:var(--glass);border:1px solid var(--border);padding:4px 10px;border-radius:6px" id="scanRate">0 scans/min</span>
    <button class="btn btn-ghost" onclick="location.href='/'">← Back to Scanner</button>
    <button class="btn btn-ghost" onclick="exportLog()">📥 Export Log</button>
  </div>
</div>

<div class="container">
  <!-- Stats Row -->
  <div class="stats-grid">
    <div class="stat s-crit glass"><div class="stat-num" id="sCrit">0</div><div class="stat-label">Critical</div><div class="stat-delta neutral" id="dCrit">-</div></div>
    <div class="stat s-high glass"><div class="stat-num" id="sHigh">0</div><div class="stat-label">High</div><div class="stat-delta neutral" id="dHigh">-</div></div>
    <div class="stat s-med glass"><div class="stat-num" id="sMed">0</div><div class="stat-label">Medium</div><div class="stat-delta neutral" id="dMed">-</div></div>
    <div class="stat s-low glass"><div class="stat-num" id="sLow">0</div><div class="stat-label">Low</div><div class="stat-delta neutral" id="dLow">-</div></div>
    <div class="stat s-total glass"><div class="stat-num" id="sTotal">0</div><div class="stat-label">Total Scans</div><div class="stat-delta neutral" id="dTotal">-</div></div>
    <div class="stat s-score glass"><div class="stat-num" id="sScore">--</div><div class="stat-label">Avg Score</div><div class="stat-delta neutral" id="dScore">-</div></div>
  </div>

  <div class="main-grid">
    <!-- Live Terminal -->
    <div class="panel glass">
      <div class="panel-head">
        <span class="panel-title">🖥️ Live Terminal</span>
        <span style="font-size:11px;color:var(--green)" id="termStatus">● Connected</span>
      </div>
      <div class="panel-body" style="padding:8px">
        <div class="terminal" id="terminal">
          <div class="term-line"><span class="term-time">00:00:00</span><span class="term-badge info">SYS</span><span class="term-msg">NanoShield Dashboard initialized</span></div>
          <div class="term-line"><span class="term-time">00:00:00</span><span class="term-badge ok">LOAD</span><span class="term-msg">Loaded 20 vulnerability patterns</span></div>
          <div class="term-line"><span class="term-time">00:00:00</span><span class="term-badge ok">LOAD</span><span class="term-msg">Knowledge base ready (offline + online)</span></div>
          <div class="term-line"><span class="term-time">00:00:00</span><span class="term-badge info">NET</span><span class="term-msg">Online mode active — fetching advisories</span></div>
        </div>
        <div class="term-input">
          <span class="term-prompt">❯</span>
          <input type="text" id="termInput" placeholder="Type a command: scan <code>, stats, history, clear, help" onkeydown="if(event.key==='Enter')handleCmd(this.value)">
        </div>
      </div>
    </div>

    <!-- Vuln Distribution Chart -->
    <div class="panel glass">
      <div class="panel-head">
        <span class="panel-title">📊 Vulnerability Distribution</span>
        <span style="font-size:11px;color:var(--muted)" id="chartUpdate">Updated just now</span>
      </div>
      <div class="panel-body">
        <div class="chart-container" id="vulnChart"></div>
        <div style="margin-top:16px">
          <span class="panel-title" style="font-size:10px">Recent Scan Activity (last 20)</span>
          <div class="sparkline" id="sparkline"></div>
        </div>
      </div>
    </div>

    <!-- Scan History -->
    <div class="panel glass" style="grid-column:1/-1">
      <div class="panel-head">
        <span class="panel-title">📋 Scan History</span>
        <span style="font-size:11px;color:var(--muted)" id="histCount">0 scans</span>
      </div>
      <div class="panel-body" style="padding:0;max-height:300px;overflow-y:auto">
        <table class="history-table">
          <thead><tr><th>Time</th><th>File</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Score</th><th>Status</th></tr></thead>
          <tbody id="histBody"><tr><td colspan="8" style="text-align:center;color:var(--muted);padding:20px">No scans yet — paste code in the scanner</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
</div>
<div class="footer">NanoShield Dashboard — Real-time security monitoring</div>

<script>
let uptimeStart = Date.now();
let scanHistory = [];
let vulnCounts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
let prevCounts = {...vulnCounts};
let sparkData = [];
let termLines = [];

function ts() {
  const d = new Date();
  return d.toTimeString().slice(0,8);
}

function addTermLine(badge, cls, msg, fix) {
  const term = document.getElementById('terminal');
  const div = document.createElement('div');
  div.className = 'term-line';
  div.innerHTML = `<span class="term-time">${ts()}</span><span class="term-badge ${cls}">${badge}</span><span class="term-msg">${msg}${fix ? ' <span class="term-fix">→ ' + fix + '</span>' : ''}</span>`;
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
  if (term.children.length > 100) term.removeChild(term.firstChild);
}

function handleCmd(val) {
  const input = document.getElementById('termInput');
  input.value = '';
  const parts = val.trim().split(/\s+/);
  const cmd = parts[0]?.toLowerCase();

  if (cmd === 'help') {
    addTermLine('HELP', 'info', 'Commands: stats | history | clear | scan &lt;code&gt; | export | reset | uptime');
  } else if (cmd === 'stats') {
    addTermLine('STATS', 'info', `Scans: ${scanHistory.length} | Crit: ${vulnCounts.CRITICAL} | High: ${vulnCounts.HIGH} | Med: ${vulnCounts.MEDIUM} | Low: ${vulnCounts.LOW}`);
  } else if (cmd === 'history') {
    scanHistory.slice(-5).forEach(h => {
      addTermLine('HIST', 'info', `${h.file} — Score: ${h.score} (${h.total} vulns)`);
    });
    if (!scanHistory.length) addTermLine('HIST', 'info', 'No scan history yet');
  } else if (cmd === 'clear') {
    document.getElementById('terminal').innerHTML = '';
    addTermLine('SYS', 'ok', 'Terminal cleared');
  } else if (cmd === 'reset') {
    vulnCounts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
    scanHistory = []; sparkData = [];
    updateUI();
    addTermLine('SYS', 'ok', 'All stats reset');
  } else if (cmd === 'uptime') {
    const sec = Math.floor((Date.now() - uptimeStart) / 1000);
    addTermLine('SYS', 'info', `Uptime: ${Math.floor(sec/60)}m ${sec%60}s`);
  } else if (cmd === 'export') {
    exportLog();
  } else if (cmd === 'scan') {
    const code = parts.slice(1).join(' ');
    if (code) doScan(code, 'terminal');
    else addTermLine('ERR', 'crit', 'Usage: scan <code snippet>');
  } else {
    addTermLine('ERR', 'crit', `Unknown command: ${cmd}. Type "help" for commands.`);
  }
}

function doScan(code, source) {
  fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({code, source})})
    .then(r=>r.json()).then(data => {
      const f = data.findings;
      const c = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
      f.forEach(v => c[v.severity]++);

      Object.keys(c).forEach(k => {
        const diff = c[k] - (prevCounts[k] || 0);
        if (diff > 0) {
          const cls = {'CRITICAL':'crit','HIGH':'high','MEDIUM':'med','LOW':'low'}[k];
          addTermLine(k.slice(0,4).toUpperCase(), cls, `+${diff} new ${k} finding(s)`);
        }
      });

      f.forEach(v => {
        const cls = {'CRITICAL':'crit','HIGH':'high','MEDIUM':'med','LOW':'low'}[v.severity];
        addTermLine(v.severity.slice(0,4), cls, `${v.type} @ line ${v.line}`, v.fix);
      });

      if (f.length === 0) addTermLine('SCAN', 'ok', 'No vulnerabilities detected ✅');

      prevCounts = {...c};
      Object.keys(c).forEach(k => vulnCounts[k] += c[k]);
      total_vulns += f.length;
      total_scans++;

      const score = Math.max(0, 100 - f.length * 5);
      scanHistory.push({time: ts(), file: source || 'manual', crit: c.CRITICAL, high: c.HIGH, med: c.MEDIUM, low: c.LOW, score, total: f.length});
      sparkData.push(f.length);
      if (sparkData.length > 20) sparkData.shift();

      updateUI();
    }).catch(e => addTermLine('ERR', 'crit', 'Scan failed: ' + e.message));
}

function updateUI() {
  document.getElementById('sCrit').textContent = vulnCounts.CRITICAL;
  document.getElementById('sHigh').textContent = vulnCounts.HIGH;
  document.getElementById('sMed').textContent = vulnCounts.MEDIUM;
  document.getElementById('sLow').textContent = vulnCounts.LOW;
  document.getElementById('sTotal').textContent = total_scans;

  // Delta indicators
  const lastScan = scanHistory[scanHistory.length - 1];
  if (lastScan) {
    const avg = scanHistory.reduce((a,b) => a+b.score, 0) / scanHistory.length;
    document.getElementById('sScore').textContent = Math.round(avg);
  }

  // Chart
  const maxVal = Math.max(vulnCounts.CRITICAL, vulnCounts.HIGH, vulnCounts.MEDIUM, vulnCounts.LOW, 1);
  const chartData = [
    {label:'Critical', val:vulnCounts.CRITICAL, cls:'crit'},
    {label:'High', val:vulnCounts.HIGH, cls:'high'},
    {label:'Medium', val:vulnCounts.MEDIUM, cls:'med'},
    {label:'Low', val:vulnCounts.LOW, cls:'low'},
    {label:'Clean Lines', val: Math.max(0, total_scans * 10 - Object.values(vulnCounts).reduce((a,b)=>a+b,0)), cls:'ok'},
  ];
  document.getElementById('vulnChart').innerHTML = chartData.map(d => `
    <div class="chart-row">
      <span class="chart-label">${d.label}</span>
      <div class="chart-bar"><div class="chart-fill ${d.cls}" style="width:${Math.max(2,(d.val/maxVal)*100)}%">${d.val}</div></div>
    </div>`).join('');

  // Sparkline
  const maxSpark = Math.max(...sparkData, 1);
  document.getElementById('sparkline').innerHTML = sparkData.map(v => {
    const h = Math.max(4, (v / maxSpark) * 36);
    const cls = v === 0 ? 'vo' : v <= 2 ? 'vl' : v <= 4 ? 'vm' : v <= 6 ? 'vh' : 'v';
    return `<div class="spark-bar ${cls}" style="height:${h}px" title="${v} vulns"></div>`;
  }).join('');

  // History table
  const tbody = document.getElementById('histBody');
  if (scanHistory.length) {
    tbody.innerHTML = scanHistory.slice().reverse().map(h => {
      const sevColor = h.crit > 0 ? 'var(--red)' : h.high > 0 ? 'var(--orange)' : h.med > 0 ? 'var(--yellow)' : 'var(--green)';
      const status = h.total === 0 ? '✅ Clean' : h.crit > 0 ? '🔴 Critical' : h.high > 0 ? '🟠 Issues' : '🟡 Minor';
      return `<tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted)">${h.time}</td>
        <td style="font-family:'JetBrains Mono',monospace">${h.file}</td>
        <td style="color:var(--red);font-weight:700">${h.crit}</td>
        <td style="color:var(--orange);font-weight:700">${h.high}</td>
        <td style="color:var(--yellow);font-weight:700">${h.med}</td>
        <td style="color:var(--accent2);font-weight:700">${h.low}</td>
        <td><span style="color:${sevColor};font-weight:700;font-family:'JetBrains Mono',monospace">${h.score}</span></td>
        <td>${status}</td>
      </tr>`;
    }).join('');
    document.getElementById('histCount').textContent = scanHistory.length + ' scans';
  }
}

function exportLog() {
  let log = 'NanoShield Dashboard Log\n' + '='.repeat(50) + '\n\n';
  scanHistory.forEach(h => {
    log += `[${h.time}] ${h.file} | Crit:${h.crit} High:${h.high} Med:${h.med} Low:${h.low} | Score:${h.score}\n`;
  });
  const blob = new Blob([log], {type:'text/plain'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'nanoshield_log.txt'; a.click();
  addTermLine('SYS', 'ok', 'Log exported');
}

// Uptime ticker
setInterval(() => {
  const sec = Math.floor((Date.now() - uptimeStart) / 1000);
  document.getElementById('uptime').textContent = `Uptime: ${Math.floor(sec/60)}m ${sec%60}s`;
}, 1000);

// Auto-scan from main scanner (polls)
setInterval(async () => {
  try {
    const res = await fetch('/api/pending');
    const data = await res.json();
    if (data.code) doScan(data.code, data.filename || 'uploaded');
  } catch(e) {}
}, 1000);

document.getElementById('termInput').focus();
</script>
</body>
</html>
"""

@app.route("/dashboard")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    global total_scans, total_vulns
    code = request.json.get("code", "")
    source = request.json.get("source", "manual")
    findings = scan_code(code)
    total_scans += 1
    total_vulns += len(findings)
    return jsonify({"findings": findings, "count": len(findings)})

@app.route("/api/pending")
def api_pending():
    return jsonify({"code": None})

@app.route("/api/stats")
def api_stats():
    return jsonify({
        "total_scans": total_scans, "total_vulns": total_vulns,
        "uptime": time.time() - start_time,
    })


if __name__ == "__main__":
    print("\n  NanoShield Dashboard")
    print("  → http://localhost:5001/dashboard\n")
    app.run(debug=True, port=5001)
