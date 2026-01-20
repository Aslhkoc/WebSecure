
import json
import html
from datetime import datetime

def render(report: dict) -> str:
    """
    Renders a legacy-style Pentest Report in HTML5 (Single File).
    Includes: Executive Summary, Severity Charts (CSS), Detailed Findings.
    """
    # 1. Prepare Data
    target = report.get("target", "Unknown Target")
    scan_time = report.get("timestamp", datetime.now().isoformat())
    findings = report.get("final", [])
    if not findings and "findings" in report:
        findings = report["findings"]
    
    # Severity Stats
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = str(f.get("severity", "Info")).capitalize()
        if "Kritik" in sev or "Critical" in sev: stats["Critical"] += 1
        elif "Yüksek" in sev or "High" in sev: stats["High"] += 1
        elif "Orta" in sev or "Medium" in sev: stats["Medium"] += 1
        elif "Düşük" in sev or "Low" in sev: stats["Low"] += 1
        else: stats["Info"] += 1

    total = sum(stats.values())
    
    # 2. CSS & Layout
    css = """
    :root {
        --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8;
        --crit: #ef4444; --high: #f97316; --med: #eab308; --low: #3b82f6; --info: #64748b;
    }
    body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 40px; }
    h1 { margin: 0; background: linear-gradient(90deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 40px; }
    .stat-card { background: var(--card); padding: 1.5rem; border-radius: 8px; text-align: center; border: 1px solid #334155; }
    .stat-val { font-size: 2.5rem; font-weight: 800; }
    .stat-label { color: var(--muted); text-transform: uppercase; font-size: 0.875rem; letter-spacing: 1px; }
    
    .finding-card { background: var(--card); border-radius: 8px; overflow: hidden; margin-bottom: 20px; border: 1px solid #334155; }
    .finding-header { padding: 1rem 1.5rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.03); }
    .finding-header:hover { background: rgba(255,255,255,0.05); }
    .badge { padding: 4px 12px; border-radius: 99px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
    
    .crit { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.5); }
    .high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.5); }
    .med  { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.5); }
    .low  { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.5); }
    .info { background: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid rgba(100, 116, 139, 0.5); }

    .finding-body { padding: 1.5rem; border-top: 1px solid #334155; display: none; }
    .finding-body.open { display: block; }
    
    code { font-family: 'Fira Code', monospace; background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }
    pre { background: #020617; padding: 1rem; border-radius: 6px; overflow-x: auto; border: 1px solid #1e293b; color: #a5f3fc; }
    
    .meta-grid { display: grid; grid-template-columns: 100px 1fr; gap: 10px; margin-bottom: 1rem; font-size: 0.9rem; }
    .meta-label { color: var(--muted); }
    
    details { margin-top: 1rem; }
    summary { cursor: pointer; color: #38bdf8; user-select: none; }
    """
    
    js = """
    function toggle(id) {
        document.getElementById(id).classList.toggle('open');
    }
    """

    # 3. HTML Structure
    html_parts = [
        f"<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>Pentest Report - {target}</title>",
        f"<style>{css}</style><script>{js}</script></head><body>",
        f"<div class='container'><header><h1>🛡️ WebSecure Pentest Report</h1>",
        f"<div style='color: var(--muted); margin-top: 10px;'>Target: <strong>{target}</strong> &bull; Date: {scan_time}</div></header>",
        
        # Stats
        "<div class='stats-grid'>",
        f"<div class='stat-card'><div class='stat-val' style='color:var(--crit)'>{stats['Critical']}</div><div class='stat-label'>Critical</div></div>",
        f"<div class='stat-card'><div class='stat-val' style='color:var(--high)'>{stats['High']}</div><div class='stat-label'>High</div></div>",
        f"<div class='stat-card'><div class='stat-val' style='color:var(--med)'>{stats['Medium']}</div><div class='stat-label'>Medium</div></div>",
        f"<div class='stat-card'><div class='stat-val' style='color:var(--low)'>{stats['Low']}</div><div class='stat-label'>Low</div></div>",
        f"<div class='stat-card'><div class='stat-val' style='color:var(--info)'>{stats['Info']}</div><div class='stat-label'>Info</div></div>",
        "</div>",
        
        "<h2>Detailed Findings</h2>"
    ]
    
    for i, f in enumerate(findings):
        fid = f"f{i}"
        sev = str(f.get("severity", "Info")).capitalize()
        sev_cls = "info"
        if "Kritik" in sev or "Critical" in sev: sev_cls = "crit"
        elif "Yüksek" in sev or "High" in sev: sev_cls = "high"
        elif "Orta" in sev or "Medium" in sev: sev_cls = "med"
        elif "Düşük" in sev or "Low" in sev: sev_cls = "low"
        
        title = html.escape(str(f.get("type", "Unknown Vulnerability")))
        url = html.escape(str(f.get("url", "")))
        desc = html.escape(str(f.get("description", f.get("message", "No description provided."))))
        payload = html.escape(str(f.get("payload", "")))
        
        html_parts.append(f"""
        <div class='finding-card'>
            <div class='finding-header' onclick='toggle("{fid}")'>
                <div style='display:flex; align-items:center; gap:10px;'>
                    <span class='badge {sev_cls}'>{sev}</span>
                    <span style='font-weight:600; font-size:1.1rem;'>{title}</span>
                </div>
                <div style='color:var(--muted); font-size:0.9rem;'>{url}</div>
            </div>
            <div id='{fid}' class='finding-body'>
                <div class='meta-grid'>
                    <div class='meta-label'>URL:</div><div><code>{url}</code></div>
                    <div class='meta-label'>Type:</div><div>{title}</div>
                    <div class='meta-label'>Severity:</div><div>{sev}</div>
                </div>
                <p>{desc}</p>
        """)
        
        if payload:
            html_parts.append(f"<div><strong>Payload Used:</strong><pre>{payload}</pre></div>")
            
        if "evidence" in f:
            evidence = json.dumps(f["evidence"], indent=2)
            html_parts.append(f"<details><summary>Forensic Evidence</summary><pre>{html.escape(evidence)}</pre></details>")
            
        html_parts.append("</div></div>")
        
    html_parts.append("</div></body></html>")
    return "\n".join(html_parts)
