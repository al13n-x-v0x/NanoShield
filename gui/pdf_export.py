"""
NanoShield PDF Report Generator
Creates styled vulnerability reports with severity charts, fix suggestions, and summaries.
No external dependencies — uses Python's built-in capabilities.
Run: python gui/pdf_export.py --findings findings.json --output report.pdf
"""
import json, sys, os, argparse
from datetime import datetime


HTML_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  @page { margin: 40px 50px; size: A4; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; color: #1a1a2e; background: white; }

  .cover { page-break-after: always; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 100vh; background: linear-gradient(135deg, #0a0e17, #1a1f35); color: white; text-align: center; padding: 60px; }
  .cover h1 { font-size: 48px; font-weight: 900; margin-bottom: 8px; background: linear-gradient(90deg, #00d4ff, #7b2fff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .cover .subtitle { font-size: 18px; color: #94a3b8; margin-bottom: 40px; }
  .cover .date { font-size: 14px; color: #64748b; }
  .cover .badge { display: inline-block; padding: 8px 20px; border-radius: 8px; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); margin: 4px; font-size: 13px; }

  .page { page-break-after: always; padding: 40px 50px; }
  .page:last-child { page-break-after: auto; }

  h2 { font-size: 24px; font-weight: 800; color: #0a0e17; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 3px solid #7b2fff; }
  h3 { font-size: 16px; font-weight: 700; color: #1a1f35; margin: 16px 0 8px; }

  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }
  .summary-card { padding: 20px; border-radius: 10px; text-align: center; }
  .summary-card.crit { background: #fef2f2; border: 2px solid #ef4444; }
  .summary-card.high { background: #fff7ed; border: 2px solid #f97316; }
  .summary-card.med { background: #fefce8; border: 2px solid #eab308; }
  .summary-card.low { background: #eff6ff; border: 2px solid #3b82f6; }
  .summary-card .num { font-size: 36px; font-weight: 900; }
  .summary-card.crit .num { color: #ef4444; }
  .summary-card.high .num { color: #f97316; }
  .summary-card.med .num { color: #eab308; }
  .summary-card.low .num { color: #3b82f6; }
  .summary-card .label { font-size: 12px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }

  .score-big { font-size: 72px; font-weight: 900; text-align: center; margin: 20px 0; }
  .score-big.good { color: #22c55e; }
  .score-big.warn { color: #eab308; }
  .score-big.bad { color: #ef4444; }

  .finding { border-radius: 8px; padding: 16px 20px; margin-bottom: 14px; border-left: 5px solid; page-break-inside: avoid; }
  .finding.crit { background: #fef2f2; border-color: #ef4444; }
  .finding.high { background: #fff7ed; border-color: #f97316; }
  .finding.med { background: #fefce8; border-color: #eab308; }
  .finding.low { background: #eff6ff; border-color: #3b82f6; }

  .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .finding-type { font-size: 16px; font-weight: 700; }
  .sev-badge { padding: 3px 10px; border-radius: 4px; font-size: 10px; font-weight: 800; text-transform: uppercase; color: white; }
  .finding.crit .sev-badge { background: #ef4444; }
  .finding.high .sev-badge { background: #f97316; }
  .finding.med .sev-badge { background: #eab308; color: #1a1a2e; }
  .finding.low .sev-badge { background: #3b82f6; }

  .finding-meta { font-size: 12px; color: #64748b; margin-bottom: 6px; }
  .finding-meta span { background: #f1f5f9; padding: 2px 8px; border-radius: 3px; margin-right: 6px; }

  .finding-code { background: #1a1a2e; color: #e2e8f0; padding: 8px 12px; border-radius: 6px; font-family: 'Consolas', monospace; font-size: 12px; margin: 8px 0; }
  .finding-fix { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 10px 14px; font-size: 13px; color: #166534; margin-top: 8px; }
  .finding-fix::before { content: '💡 Fix: '; font-weight: 700; }

  table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  th { background: #f1f5f9; text-align: left; padding: 10px 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; border-bottom: 2px solid #e2e8f0; }
  td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
  tr:hover td { background: #f8fafc; }

  .footer { text-align: center; padding: 20px; color: #94a3b8; font-size: 11px; border-top: 1px solid #e2e8f0; margin-top: 40px; }
</style>
</head>
<body>

<div class="cover">
  <h1>🛡️ NanoShield</h1>
  <div class="subtitle">Security Vulnerability Report</div>
  <div>
    <span class="badge">🔍 {{TOTAL_FINDINGS}} Findings</span>
    <span class="badge">📊 Score: {{SCORE}}/100</span>
    <span class="badge">📅 {{DATE}}</span>
  </div>
  <div class="date">Generated by NanoShield v0.1.0 — On-device security scanner</div>
</div>

<div class="page">
  <h2>Executive Summary</h2>

  <div class="summary-grid">
    <div class="summary-card crit"><div class="num">{{CRIT_COUNT}}</div><div class="label">Critical</div></div>
    <div class="summary-card high"><div class="num">{{HIGH_COUNT}}</div><div class="label">High</div></div>
    <div class="summary-card med"><div class="num">{{MED_COUNT}}</div><div class="label">Medium</div></div>
    <div class="summary-card low"><div class="num">{{LOW_COUNT}}</div><div class="label">Low</div></div>
  </div>

  <div class="score-big {{SCORE_CLASS}}">{{SCORE}}/100</div>
  <p style="text-align:center;color:#64748b;margin-top:-10px;">Overall Security Score</p>

  <h3>Findings by Type</h3>
  <table>
    <thead><tr><th>Vulnerability</th><th>Count</th><th>Severity</th><th>OWASP</th><th>CWE</th></tr></thead>
    <tbody>{{SUMMARY_TABLE}}</tbody>
  </table>
</div>

<div class="page">
  <h2>Detailed Findings</h2>
  {{FINDINGS_LIST}}
</div>

<div class="page">
  <h2>Recommendations</h2>
  <div style="background:#f8fafc;border-radius:10px;padding:24px;margin-bottom:20px;">
    <h3>🔴 Immediate Actions Required</h3>
    <p style="margin:8px 0;line-height:1.6;color:#475569;">
      {{CRIT_RECOMMENDATION}}
    </p>
  </div>
  <div style="background:#f8fafc;border-radius:10px;padding:24px;margin-bottom:20px;">
    <h3>🟠 Short-term Improvements</h3>
    <p style="margin:8px 0;line-height:1.6;color:#475569;">
      {{HIGH_RECOMMENDATION}}
    </p>
  </div>
  <div style="background:#f8fafc;border-radius:10px;padding:24px;">
    <h3>🟡 Best Practices</h3>
    <p style="margin:8px 0;line-height:1.6;color:#475569;">
      All findings should be addressed according to OWASP Top 10 2021 and CWE/SANS Top 25 guidelines.
      Implement automated security scanning in your CI/CD pipeline to catch vulnerabilities before deployment.
    </p>
  </div>

  <div class="footer">
    NanoShield Security Report — Generated {{DATE}} — Confidential<br>
    This report was generated entirely on-device. No data was sent to external servers.
  </div>
</div>

</body>
</html>
"""


def generate_html_report(findings, filename="scan_results"):
    """Generate styled HTML report from findings list."""
    crit = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    med = [f for f in findings if f.get("severity") == "MEDIUM"]
    low = [f for f in findings if f.get("severity") == "LOW"]
    total = len(findings)
    score = max(0, 100 - total * 5)
    score_cls = "good" if score > 70 else "warn" if score > 40 else "bad"

    # Group by type
    by_type = {}
    for f in findings:
        t = f.get("type", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1

    summary_rows = ""
    for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
        first = next(f for f in findings if f["type"] == t)
        sev = first.get("severity", "MEDIUM")
        summary_rows += f"<tr><td><strong>{t}</strong></td><td>{count}</td><td>{sev}</td><td>{first.get('owasp','')}</td><td>{first.get('cwe','')}</td></tr>\n"

    findings_html = ""
    for i, f in enumerate(findings):
        sev_cls = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}.get(f.get("severity", ""), "med")
        findings_html += f"""
        <div class="finding {sev_cls}">
          <div class="finding-header">
            <span class="finding-type">{f.get('type','Unknown')}</span>
            <span class="sev-badge">{f.get('severity','')}</span>
          </div>
          <div class="finding-meta">
            <span>Line {f.get('line','?')}</span>
            <span>{f.get('owasp','')}</span>
            <span>{f.get('cwe','')}</span>
          </div>
          <div class="finding-code">{f.get('match','')}</div>
          <div class="finding-fix">{f.get('fix','No fix suggestion available')}</div>
        </div>"""

    crit_rec = "Address all critical vulnerabilities immediately. These can lead to data breaches, remote code execution, or full system compromise."
    if not crit:
        crit_rec = "No critical vulnerabilities found. Continue monitoring and maintain secure coding practices."
    high_rec = "Review and fix high-severity findings within the current sprint. These represent significant security risks."
    if not high:
        high_rec = "No high-severity issues found. Maintain current security posture."

    html = HTML_REPORT_TEMPLATE
    html = html.replace("{{TOTAL_FINDINGS}}", str(total))
    html = html.replace("{{SCORE}}", str(score))
    html = html.replace("{{SCORE_CLASS}}", score_cls)
    html = html.replace("{{DATE}}", datetime.now().strftime("%Y-%m-%d %H:%M"))
    html = html.replace("{{CRIT_COUNT}}", str(len(crit)))
    html = html.replace("{{HIGH_COUNT}}", str(len(high)))
    html = html.replace("{{MED_COUNT}}", str(len(med)))
    html = html.replace("{{LOW_COUNT}}", str(len(low)))
    html = html.replace("{{SUMMARY_TABLE}}", summary_rows)
    html = html.replace("{{FINDINGS_LIST}}", findings_html)
    html = html.replace("{{CRIT_RECOMMENDATION}}", crit_rec)
    html = html.replace("{{HIGH_RECOMMENDATION}}", high_rec)

    output_path = f"{filename}_report.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"HTML report saved to {output_path}")
    return output_path


def generate_pdf(findings, output_path="nanoshield_report"):
    """Generate PDF report. Falls back to HTML if weasyprint not available."""
    html_path = generate_html_report(findings, output_path)
    try:
        from weasyprint import HTML
        pdf_path = f"{output_path}.pdf"
        HTML(filename=html_path).write_pdf(pdf_path)
        print(f"PDF report saved to {pdf_path}")
        return pdf_path
    except ImportError:
        print("weasyprint not installed — using HTML report instead.")
        print("Install with: pip install weasyprint")
        return html_path


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="NanoShield PDF Report Generator")
    p.add_argument("--findings", "-f", required=True, help="JSON file with findings array")
    p.add_argument("--output", "-o", default="nanoshield_report", help="Output filename (without extension)")
    p.add_argument("--format", choices=["html", "pdf"], default="html", help="Output format")
    args = p.parse_args()

    with open(args.findings) as f:
        data = json.load(f)

    findings = data if isinstance(data, list) else data.get("findings", [])

    if args.format == "pdf":
        generate_pdf(findings, args.output)
    else:
        generate_html_report(findings, args.output)
