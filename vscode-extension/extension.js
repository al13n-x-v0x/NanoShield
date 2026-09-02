/**
 * NanoShield VS Code Extension
 * Real-time code security vulnerability scanner
 * Works entirely offline — no data leaves your machine.
 */
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

// ─── Vulnerability Patterns ──────────────────────────────────────────
const VULN_PATTERNS = [
  { name: "SQL Injection", sev: "CRITICAL", owasp: "A03", cwe: "CWE-89",
    pats: [/execute\s*\(.*\+\s*/g, /query\s*\(.*%s/g, /cursor\.execute\s*\(.+format/g, /\.raw\s*\(.*\+/g],
    fix: 'Use parameterized query: cursor.execute("SELECT * FROM users WHERE name = ?", (username,))',
    regex: /execute\s*\(.*\+\s*|query\s*\(.*%s|cursor\.execute\s*\(.+format/ },
  { name: "XSS", sev: "HIGH", owasp: "A03", cwe: "CWE-79",
    pats: [/innerHTML\s*=/g, /document\.write\s*\(/g, /eval\s*\(\s*req\./g],
    fix: "Use element.textContent or DOMPurify.sanitize()",
    regex: /innerHTML\s*=|document\.write\s*\(|eval\s*\(\s*req\./ },
  { name: "Hardcoded Credentials", sev: "CRITICAL", owasp: "A07", cwe: "CWE-798",
    pats: [/password\s*=\s*["'][^"']+["']/g, /api_key\s*=\s*["'][^"']+["']/g, /secret\s*=\s*["'][^"']+["']/g],
    fix: 'Use os.environ.get("DB_PASSWORD") or a vault service',
    regex: /password\s*=\s*["'][^"']+["']|api_key\s*=\s*["'][^"']+["']|secret\s*=\s*["'][^"']+["']/ },
  { name: "Weak Crypto", sev: "HIGH", owasp: "A02", cwe: "CWE-327",
    pats: [/md5\s*\(/g, /sha1\s*\(/g, /DES\./g, /RC4/g],
    fix: "Use bcrypt/scrypt/Argon2 for passwords, SHA-256+ for hashing",
    regex: /md5\s*\(|sha1\s*\(|DES\.|RC4/ },
  { name: "Command Injection", sev: "CRITICAL", owasp: "A03", cwe: "CWE-78",
    pats: [/os\.system\s*\(/g, /subprocess\.call\s*\(.*shell\s*=\s*True/g, /eval\s*\(\s*input/g],
    fix: 'Use subprocess.run(["cmd", arg1, arg2]) with list args',
    regex: /os\.system\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True|eval\s*\(\s*input/ },
  { name: "Path Traversal", sev: "HIGH", owasp: "A01", cwe: "CWE-22",
    pats: [/open\s*\(.*\.\.\//g, /os\.path\.join\s*\(.*\.\./g],
    fix: "Validate with os.path.realpath().startswith(expected_base)",
    regex: /open\s*\(.*\.\.\// },
  { name: "Buffer Overflow", sev: "CRITICAL", owasp: "A06", cwe: "CWE-120",
    pats: [/strcpy\s*\(/g, /gets\s*\(/g, /sprintf\s*\(/g],
    fix: "Use strncpy/snprintf with bounds checking",
    regex: /strcpy\s*\(|gets\s*\(|sprintf\s*\(/ },
  { name: "Insecure Deserialization", sev: "HIGH", owasp: "A08", cwe: "CWE-502",
    pats: [/pickle\.loads?\s*\(/g, /yaml\.load\s*\((?!.*Loader)/g],
    fix: "Use yaml.safe_load() or json.loads()",
    regex: /pickle\.loads?\s*\(|yaml\.load\s*\(/ },
  { name: "Eval/Exec", sev: "CRITICAL", owasp: "A03", cwe: "CWE-95",
    pats: [/\beval\s*\(/g, /\bexec\s*\(/g],
    fix: "Use ast.literal_eval() for safe evaluation",
    regex: /\beval\s*\(|\bexec\s*\(/ },
  { name: "Race Condition", sev: "MEDIUM", owasp: "A04", cwe: "CWE-362",
    pats: [/thread\.start.*shared/g],
    fix: "Use threading.Lock() for shared state",
    regex: /thread\.start.*shared/ },
  { name: "Debug Mode", sev: "MEDIUM", owasp: "A05", cwe: "CWE-489",
    pats: [/DEBUG\s*=\s*True/g, /debug\s*=\s*True/g],
    fix: "Use environment variable: DEBUG = os.environ.get('DEBUG') == 'true'",
    regex: /DEBUG\s*=\s*True/ },
  { name: "CORS Wildcard", sev: "MEDIUM", owasp: "A05", cwe: "CWE-942",
    pats: [/allow_origins\s*=\s*\[.*\*/g],
    fix: "Restrict to specific allowed origins",
    regex: /allow_origins\s*=\s*\[.*\*/ },
  { name: "Weak Token", sev: "MEDIUM", owasp: "A07", cwe: "CWE-330",
    pats: [/token\s*=\s*random\./g, /uuid\.uuid1\(\)/g],
    fix: "Use secrets.token_urlsafe(32) for secure tokens",
    regex: /token\s*=\s*random\.|uuid\.uuid1\(\)/ },
  { name: "Silent Exception", sev: "LOW", owasp: "A09", cwe: "CWE-778",
    pats: [/except.*pass/g],
    fix: "Log errors: logger.error(f'Error: {e}', exc_info=True)",
    regex: /except\s+\w*:\s*pass|except:\s*pass/ },
  { name: "Timing Attack", sev: "MEDIUM", owasp: "A02", cwe: "CWE-208",
    pats: [/==\s*hash/g],
    fix: "Use hmac.compare_digest() for constant-time comparison",
    regex: /==\s*hash|==\s*token/ },
];

const SEVERITY_MAP = {
  CRITICAL: vscode.DiagnosticSeverity.Error,
  HIGH: vscode.DiagnosticSeverity.Warning,
  MEDIUM: vscode.DiagnosticSeverity.Information,
  LOW: vscode.DiagnosticSeverity.Hint,
};

const SEVERITY_COLORS = {
  CRITICAL: new vscode.ThemeColor('charts.red'),
  HIGH: new vscode.ThemeColor('charts.orange'),
  MEDIUM: new vscode.ThemeColor('charts.yellow'),
  LOW: new vscode.ThemeColor('charts.blue'),
};

let diagnosticCollection;
let liveScanEnabled = true;
let statusBarItem;
let outputChannel;

function activate(context) {
  outputChannel = vscode.window.createOutputChannel('NanoShield');
  diagnosticCollection = vscode.languages.createDiagnosticCollection('nanoshield');

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'nanoshield.toggleLiveScan';
  updateStatusBar();
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('nanoshield.scan', () => scanActiveEditor()),
    vscode.commands.registerCommand('nanoshield.scanSelection', () => scanSelection()),
    vscode.commands.registerCommand('nanoshield.scanProject', () => scanProject()),
    vscode.commands.registerCommand('nanoshield.toggleLiveScan', () => toggleLiveScan()),
    vscode.commands.registerCommand('nanoshield.showDashboard', () => showDashboard()),
    vscode.commands.registerCommand('nanoshield.exportReport', () => exportReport()),
  );

  // Quick fix provider
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider('*', new NanoShieldCodeActionProvider(), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    })
  );

  // Live scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (liveScanEnabled) scanDocument(doc);
    })
  );

  // Live scan on type (debounced)
  let debounceTimer;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(e => {
      if (!liveScanEnabled) return;
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => scanDocument(e.document), 2000);
    })
  );

  outputChannel.appendLine('NanoShield extension activated');
}

function updateStatusBar() {
  const icon = liveScanEnabled ? '🟢' : '🔴';
  const text = liveScanEnabled ? 'NanoShield: Live' : 'NanoShield: Off';
  statusBarItem.text = `${icon} ${text}`;
  statusBarItem.tooltip = 'Click to toggle live scanning';
}

function toggleLiveScan() {
  liveScanEnabled = !liveScanEnabled;
  updateStatusBar();
  if (!liveScanEnabled) diagnosticCollection.clear();
  vscode.window.showInformationMessage(`NanoShield live scanning ${liveScanEnabled ? 'enabled' : 'disabled'}`);
}

function scanDocument(doc) {
  if (!doc || doc.isClosed) return;
  const text = doc.getText();
  const diagnostics = [];

  for (const vuln of VULN_PATTERNS) {
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pat of vuln.pats) {
        pat.lastIndex = 0;
        let match;
        while ((match = pat.exec(line)) !== null) {
          const start = new vscode.Position(i, match.index);
          const end = new vscode.Position(i, match.index + match[0].length);
          const range = new vscode.Range(start, end);

          const diag = new vscode.Diagnostic(range, `${vuln.name}: ${vuln.fix}`, SEVERITY_MAP[vuln.sev]);
          diag.source = 'NanoShield';
          diag.code = vuln.cwe;
          diag.severity = SEVERITY_MAP[vuln.sev];

          const related = new vscode.DiagnosticRelatedInformation(
            new vscode.Location(doc.uri, range),
            `${vuln.owasp} | ${vuln.cwe} | Severity: ${vuln.sev}`
          );
          diag.relatedInformation = [related];

          diagnostics.push(diag);
        }
      }
    }
  }

  diagnosticCollection.set(doc.uri, diagnostics);

  // Update status bar with count
  const crit = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
  const high = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;
  const total = diagnostics.length;
  const icon = total === 0 ? '✅' : crit > 0 ? '🔴' : high > 0 ? '🟡' : '🔵';
  statusBarItem.text = `${icon} NanoShield: ${total} issues`;
  outputChannel.appendLine(`Scanned ${path.basename(doc.fileName)}: ${total} issues found`);
}

function scanActiveEditor() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) { vscode.window.showWarningMessage('No active editor'); return; }
  scanDocument(editor.document);
  const diags = diagnosticCollection.get(editor.document.uri);
  const count = diags ? diags.length : 0;
  vscode.window.showInformationMessage(`NanoShield: Found ${count} issue(s)`);
}

function scanSelection() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const text = editor.document.getText(editor.selection);
  let count = 0;
  for (const vuln of VULN_PATTERNS) {
    for (const pat of vuln.pats) {
      pat.lastIndex = 0;
      if (pat.test(text)) count++;
    }
  }
  vscode.window.showInformationMessage(`NanoShield: ${count} vulnerability pattern(s) in selection`);
}

async function scanProject() {
  const files = await vscode.workspace.findFiles('**/*.{py,js,ts,c,cpp,h,java,rb,go,rs}', '**/node_modules/**');
  let totalIssues = 0;
  for (const file of files) {
    const doc = await vscode.workspace.openTextDocument(file);
    scanDocument(doc);
    const diags = diagnosticCollection.get(file);
    if (diags) totalIssues += diags.length;
  }
  vscode.window.showInformationMessage(`NanoShield: Scanned ${files.length} files, found ${totalIssues} total issues`);
}

function showDashboard() {
  vscode.env.openExternal(vscode.Uri.parse('http://localhost:5001/dashboard'));
}

function exportReport() {
  const diags = vscode.languages.getDiagnostics();
  let report = 'NanoShield Security Report\n' + '='.repeat(50) + '\n\n';
  for (const [uri, issues] of diags) {
    if (issues.length === 0) continue;
    report += `File: ${uri.fsPath}\n`;
    report += '-'.repeat(40) + '\n';
    for (const d of issues) {
      const sev = Object.entries(SEVERITY_MAP).find(([,v]) => v === d.severity)?.[0] || 'UNKNOWN';
      report += `  [${sev}] ${d.message}\n`;
      report += `    Line ${d.range.start.line + 1}, Col ${d.range.start.character + 1}\n`;
      if (d.code) report += `    ${d.code}\n`;
      report += '\n';
    }
  }
  const wsPath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (wsPath) {
    const outPath = path.join(wsPath, 'nanoshield_report.txt');
    fs.writeFileSync(outPath, report);
    vscode.window.showInformationMessage(`Report saved to ${outPath}`);
  }
}

class NanoShieldCodeActionProvider {
  provideCodeActions(document, range, context) {
    const actions = [];
    for (const diag of context.diagnostics) {
      if (diag.source !== 'NanoShield') continue;
      const vuln = VULN_PATTERNS.find(v => v.cwe === diag.code);
      if (!vuln) continue;

      const fixAction = new vscode.CodeAction(`💡 ${vuln.fix}`, vscode.CodeActionKind.QuickFix);
      fixAction.diagnostics = [diag];
      fixAction.isPreferred = true;

      // Simple line replacement
      const line = document.lineAt(diag.range.start.line);
      const lineText = line.text;
      let newText = lineText;

      if (vuln.name === "Hardcoded Credentials") {
        const varMatch = lineText.match(/(\w+)\s*=\s*["'][^"']+["']/);
        if (varMatch) {
          const varName = varMatch[1];
          newText = lineText.replace(varMatch[0], `${varName} = os.environ.get("${varName.upper()}")`);
        }
      } else if (vuln.name === "Weak Crypto") {
        newText = lineText.replace(/md5\s*\(/, 'hashlib.sha256(');
      } else if (vuln.name === "Debug Mode") {
        newText = lineText.replace(/DEBUG\s*=\s*True/, 'DEBUG = os.environ.get("DEBUG", "false").lower() == "true"');
      }

      if (newText !== lineText) {
        const edit = new vscode.WorkspaceEdit();
        edit.replace(document.uri, line.range, newText);
        fixAction.edit = edit;
      }

      actions.push(fixAction);
    }
    return actions;
  }
}

function deactivate() {}

module.exports = { activate, deactivate };
