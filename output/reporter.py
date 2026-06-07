"""
ShadowScan - HTML Report Generator
Generates a professional, self-contained HTML pentest report.
"""

import json
from datetime import datetime
from typing import Dict, List
from core.context import ScanContext, Finding, Severity


SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6",
    "INFO": "#6b7280",
}

SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH": "#fff7ed",
    "MEDIUM": "#fefce8",
    "LOW": "#eff6ff",
    "INFO": "#f9fafb",
}


def generate_html_report(ctx: ScanContext, exec_summary: str = "") -> str:
    summary = ctx.summary()
    findings = sorted(
        ctx.findings,
        key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f.severity.value),
    )

    severity_counts = summary["severity_counts"]
    total = summary["total_findings"]
    scan_date = ctx.start_time.strftime("%B %d, %Y %H:%M UTC")

    # Build findings HTML
    findings_html = ""
    for f in findings:
        color = SEVERITY_COLORS.get(f.severity.value, "#6b7280")
        bg = SEVERITY_BG.get(f.severity.value, "#f9fafb")
        chain_badge = (
            f'<span class="chain-badge">⛓ Chained from {f.chained_from}</span>'
            if f.chained_from else ""
        )
        evidence_html = f.evidence.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>") if f.evidence else "N/A"

        findings_html += f"""
        <div class="finding-card" style="border-left: 4px solid {color}; background: {bg};">
            <div class="finding-header">
                <span class="severity-badge" style="background: {color};">{f.severity.value}</span>
                <h3 class="finding-title">{f.title}</h3>
                {chain_badge}
            </div>
            <div class="finding-meta">
                <span>🔗 <a href="{f.url}" target="_blank">{f.url}</a></span>
                <span>📦 Module: <code>{f.module}</code></span>
                <span>🆔 ID: <code>{f.id}</code></span>
                <span>⏰ {f.timestamp[:19]}</span>
            </div>
            <p class="finding-desc">{f.description}</p>
            <details class="evidence-block">
                <summary>View Evidence</summary>
                <pre><code>{evidence_html}</code></pre>
            </details>
        </div>
        """

    # Donut chart data
    chart_data = json.dumps([
        {"label": s, "value": severity_counts.get(s, 0), "color": SEVERITY_COLORS.get(s, "#ccc")}
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if severity_counts.get(s, 0) > 0
    ])

    endpoints_html = "".join(
        f'<li><code>{ep}</code></li>'
        for ep in ctx.endpoints[:50]
    )

    tech_html = "".join(
        f'<span class="tech-tag">{tech}</span>'
        for tech in ctx.technologies
    ) or "<span class='tech-tag'>None detected</span>"

    flags_html = "".join(
        f'<div class="flag-item {"flag-on" if val else "flag-off"}">'
        f'{"✅" if val else "❌"} {key.replace("_", " ").title()}</div>'
        for key, val in ctx.flags.items()
    )

    exec_summary_html = exec_summary.replace("\n", "<br>") if exec_summary else (
        f"ShadowScan completed against <strong>{ctx.target}</strong>. "
        f"Total of <strong>{total}</strong> findings across "
        f"<strong>{len(summary['modules_run'])}</strong> modules."
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowScan Report — {ctx.target}</title>
<style>
  :root {{
    --bg: #0f0f13;
    --surface: #1a1a24;
    --surface2: #22222e;
    --border: #2d2d3d;
    --text: #e2e2f0;
    --text-dim: #888899;
    --accent: #7c3aed;
    --accent2: #06b6d4;
    --red: #ef4444;
    --orange: #f97316;
    --yellow: #eab308;
    --blue: #3b82f6;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
  }}

  .header {{
    background: linear-gradient(135deg, #1a0533 0%, #0f0f20 50%, #001a2e 100%);
    border-bottom: 1px solid var(--border);
    padding: 40px 60px;
  }}

  .header h1 {{
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(135deg, #a855f7, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}

  .header-meta {{
    margin-top: 12px;
    color: var(--text-dim);
    font-size: 0.9rem;
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
  }}

  .header-meta span {{ display: flex; align-items: center; gap: 6px; }}

  .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}

  .section {{ margin-bottom: 48px; }}

  .section-title {{
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--accent2);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 20px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }}

  /* Stat cards */
  .stat-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}

  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    transition: transform 0.2s;
  }}

  .stat-card:hover {{ transform: translateY(-2px); }}

  .stat-number {{
    font-size: 2rem;
    font-weight: 800;
    line-height: 1;
  }}

  .stat-label {{
    font-size: 0.75rem;
    color: var(--text-dim);
    margin-top: 6px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}

  /* Findings */
  .finding-card {{
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 16px;
    border: 1px solid rgba(255,255,255,0.05);
    background: var(--surface) !important;
    border-left-width: 5px !important;
  }}

  .finding-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
    flex-wrap: wrap;
  }}

  .severity-badge {{
    font-size: 0.7rem;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 20px;
    color: white;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex-shrink: 0;
  }}

  .finding-title {{
    font-size: 1rem;
    font-weight: 600;
    color: var(--text);
    flex: 1;
  }}

  .chain-badge {{
    font-size: 0.75rem;
    color: #a855f7;
    background: rgba(168,85,247,0.1);
    padding: 2px 8px;
    border-radius: 6px;
    border: 1px solid rgba(168,85,247,0.3);
  }}

  .finding-meta {{
    display: flex;
    gap: 20px;
    font-size: 0.8rem;
    color: var(--text-dim);
    margin-bottom: 10px;
    flex-wrap: wrap;
  }}

  .finding-meta a {{ color: var(--accent2); text-decoration: none; }}
  .finding-meta a:hover {{ text-decoration: underline; }}

  .finding-desc {{ font-size: 0.9rem; color: #ccc; margin-bottom: 12px; }}

  .evidence-block {{
    background: #0d0d18;
    border-radius: 6px;
    border: 1px solid var(--border);
    overflow: hidden;
  }}

  .evidence-block summary {{
    padding: 8px 14px;
    cursor: pointer;
    font-size: 0.8rem;
    color: var(--text-dim);
    user-select: none;
  }}

  .evidence-block pre {{
    padding: 12px 14px;
    font-size: 0.78rem;
    overflow-x: auto;
    color: #aaa;
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    white-space: pre-wrap;
    word-break: break-all;
  }}

  /* Executive summary */
  .exec-summary {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    font-size: 0.95rem;
    line-height: 1.8;
    color: #ccc;
  }}

  /* Tags */
  .tech-tag {{
    display: inline-block;
    background: rgba(124,58,237,0.15);
    color: #a78bfa;
    border: 1px solid rgba(124,58,237,0.3);
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.8rem;
    margin: 3px;
  }}

  /* Flags */
  .flags-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 8px;
  }}

  .flag-item {{
    padding: 8px 12px;
    border-radius: 8px;
    font-size: 0.85rem;
    background: var(--surface);
    border: 1px solid var(--border);
  }}

  .flag-on {{ color: #4ade80; }}
  .flag-off {{ color: #555; }}

  /* Endpoints */
  .endpoint-list {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    max-height: 300px;
    overflow-y: auto;
  }}

  .endpoint-list li {{
    list-style: none;
    padding: 4px 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.83rem;
  }}

  .endpoint-list li:last-child {{ border: none; }}
  .endpoint-list code {{ color: var(--accent2); }}

  /* Footer */
  .footer {{
    text-align: center;
    padding: 32px;
    color: var(--text-dim);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    margin-top: 60px;
  }}

  .footer strong {{ color: #a855f7; }}
</style>
</head>
<body>

<div class="header">
  <h1>🛡 ShadowScan Security Report</h1>
  <div class="header-meta">
    <span>🎯 <strong>{ctx.target}</strong></span>
    <span>📅 {scan_date}</span>
    <span>🆔 Scan ID: {ctx.scan_id}</span>
    <span>⏱ Duration: {summary['duration']}</span>
  </div>
</div>

<div class="container">

  <!-- Severity Summary -->
  <div class="section">
    <div class="stat-grid">
      <div class="stat-card" style="border-top: 3px solid {SEVERITY_COLORS['CRITICAL']}">
        <div class="stat-number" style="color:{SEVERITY_COLORS['CRITICAL']}">{severity_counts.get('CRITICAL',0)}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid {SEVERITY_COLORS['HIGH']}">
        <div class="stat-number" style="color:{SEVERITY_COLORS['HIGH']}">{severity_counts.get('HIGH',0)}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid {SEVERITY_COLORS['MEDIUM']}">
        <div class="stat-number" style="color:{SEVERITY_COLORS['MEDIUM']}">{severity_counts.get('MEDIUM',0)}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid {SEVERITY_COLORS['LOW']}">
        <div class="stat-number" style="color:{SEVERITY_COLORS['LOW']}">{severity_counts.get('LOW',0)}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid {SEVERITY_COLORS['INFO']}">
        <div class="stat-number" style="color:{SEVERITY_COLORS['INFO']}">{severity_counts.get('INFO',0)}</div>
        <div class="stat-label">Info</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid #7c3aed">
        <div class="stat-number" style="color:#a855f7">{summary['endpoints_discovered']}</div>
        <div class="stat-label">Endpoints</div>
      </div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="exec-summary">{exec_summary_html}</div>
  </div>

  <!-- Technologies -->
  <div class="section">
    <div class="section-title">Technologies Detected</div>
    <div>{tech_html}</div>
  </div>

  <!-- Attack Surface Flags -->
  <div class="section">
    <div class="section-title">Attack Surface Analysis</div>
    <div class="flags-grid">{flags_html}</div>
  </div>

  <!-- Findings -->
  <div class="section">
    <div class="section-title">Findings ({total})</div>
    {findings_html if findings_html else '<p style="color:var(--text-dim)">No findings recorded.</p>'}
  </div>

  <!-- Endpoints -->
  <div class="section">
    <div class="section-title">Discovered Endpoints ({len(ctx.endpoints)})</div>
    <ul class="endpoint-list">{endpoints_html}</ul>
  </div>

</div>

<div class="footer">
  Generated by <strong>ShadowScan v1.0</strong> — Intelligent Vulnerability Chaining Engine<br>
  Built by Akshat Singh | github.com/saksht<br>
  <em>For authorized security testing only.</em>
</div>

</body>
</html>"""


class Reporter:
    def __init__(self, ctx: ScanContext, output_path: str = "shadowscan_report.html"):
        self.ctx = ctx
        self.output_path = output_path

    def generate(self, exec_summary: str = "") -> str:
        html = generate_html_report(self.ctx, exec_summary)
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return self.output_path
