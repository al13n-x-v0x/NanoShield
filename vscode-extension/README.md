# NanoShield - VS Code Extension

Real-time code security vulnerability scanner for VS Code. **Works entirely offline**.

## Features

- 🔍 **Live Scanning** — Detects vulnerabilities as you type
- 💡 **Quick Fixes** — Click a fix suggestion to auto-repair code
- 🎨 **Inline Marks** — Red/yellow/blue squiggles under vulnerable code
- 📊 **Project Scan** — Scan entire project with one command
- 📥 **Export Report** — Generate text report of all findings
- ⚡ **16+ Patterns** — SQL injection, XSS, hardcoded creds, weak crypto, and more

## Commands

| Command | Shortcut | Description |
|---|---|---|
| `NanoShield: Scan Current File` | `Ctrl+Shift+S` | Scan the active editor |
| `NanoShield: Scan Selected Code` | Right-click → Scan | Scan only selected text |
| `NanoShield: Scan Entire Project` | Cmd Palette | Scan all source files |
| `NanoShield: Toggle Live Scanning` | `Ctrl+Shift+L` | Enable/disable auto-scan |
| `NanoShield: Open Dashboard` | Cmd Palette | Open web dashboard |
| `NanoShield: Export Report` | Cmd Palette | Save findings to file |

## Installation

### From Source
```bash
cd vscode-extension
npm install
npm run package
code --install-extension nanoshield-0.1.0.vsix
```

### How It Works
- Scans on **every save** (if live scanning is enabled)
- Scans on **typing** (debounced, 2s delay)
- Shows **inline diagnostics** with severity colors
- Offers **quick fixes** with one-click code repair
- **Zero network requests** — all logic runs locally

## Settings

| Setting | Default | Description |
|---|---|---|
| `nanoshield.liveScan.enabled` | `true` | Auto-scan on save |
| `nanoshield.severityThreshold` | `LOW` | Minimum severity for inline marks |
| `nanoshield.showInlineMarks` | `true` | Show squiggly underlines |
| `nanoshield.autoFix` | `true` | Show quick-fix code actions |
