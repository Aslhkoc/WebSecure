"""
websecure.reporters.pdf
------------------------
Professional PDF report generator.
Uses Jinja2 for HTML templating and WeasyPrint for HTML→PDF conversion.
"""
from __future__ import annotations
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    _JINJA2_AVAILABLE = True
except ImportError:
    _JINJA2_AVAILABLE = False

try:
    import weasyprint
    _WEASYPRINT_AVAILABLE = True
except (ImportError, OSError, Exception):
    # OSError on Windows when GTK/Pango native libraries are missing
    _WEASYPRINT_AVAILABLE = False

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _severity_color(severity: str) -> str:
    return {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#17a2b8",
        "Info": "#6c757d",
        "Informational": "#6c757d",
    }.get(severity, "#6c757d")


def _count_by_severity(findings: List[Dict]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = str(f.get("severity") or f.get("cvss_severity") or "Info")
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Info"] += 1
    return counts


def _flatten_findings(results: Dict) -> List[Dict]:
    """Extract all offensive/finding entries from the results bucket."""
    findings = []
    priority_buckets = ["offensive", "sqlmap", "xss", "ssrf", "idor", "ssti", "auth_matrix"]
    seen = set()
    for bucket in priority_buckets:
        for item in results.get(bucket, []):
            if not isinstance(item, dict):
                continue
            key = (item.get("type", ""), item.get("url", ""), item.get("parameter", ""))
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
    return findings


class PDFReporter:
    """Generates a professional penetration test PDF report."""

    def __init__(self, template_name: str = "report.html.j2"):
        self.template_name = template_name

    def generate(self, results: Dict, config: Dict, output_path: str) -> bool:
        """
        Generate PDF report.
        Returns True on success, False if WeasyPrint is unavailable (HTML fallback written instead).
        """
        html_content = self._render_html(results, config)
        if not html_content:
            return False

        # Always write HTML version
        html_path = output_path.replace(".pdf", ".html") if output_path.endswith(".pdf") else output_path + ".html"
        try:
            Path(html_path).write_text(html_content, encoding="utf-8")
            _logger.info(f"[PDF] HTML report written: {html_path}")
        except Exception as e:
            _logger.error(f"[PDF] HTML write failed: {e}")

        if not _WEASYPRINT_AVAILABLE:
            _logger.warning("[PDF] WeasyPrint not installed (pip install weasyprint). HTML report generated instead.")
            return False

        try:
            wp = weasyprint.HTML(string=html_content, base_url=str(_TEMPLATE_DIR))
            wp.write_pdf(output_path)
            _logger.info(f"[PDF] PDF report written: {output_path}")
            return True
        except Exception as e:
            _logger.error(f"[PDF] WeasyPrint error: {e}")
            return False

    def _render_html(self, results: Dict, config: Dict) -> Optional[str]:
        """Render the Jinja2 template with report data."""
        findings = _flatten_findings(results)
        severity_counts = _count_by_severity(findings)

        # Compute overall risk rating
        if severity_counts["Critical"] > 0:
            overall_risk = "Critical"
        elif severity_counts["High"] > 0:
            overall_risk = "High"
        elif severity_counts["Medium"] > 0:
            overall_risk = "Medium"
        elif severity_counts["Low"] > 0:
            overall_risk = "Low"
        else:
            overall_risk = "Informational"

        # Gather meta info
        target = config.get("target") or config.get("url", "Unknown Target")
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        tool_version = "WebSecure 3.0"
        scan_profile = (config.get("settings") or {}).get("scan_profile", "unknown")

        # WAF info
        waf_info = results.get("waf_detection", [{}])
        waf = waf_info[0] if waf_info else {}
        waf_vendor = waf.get("vendor", "None detected")
        waf_confidence = waf.get("confidence", 0.0)

        # Nmap/ports
        nmap_results = results.get("nmap", [])
        open_ports = [n for n in nmap_results if isinstance(n, dict) and n.get("state") == "open"]

        # TLS info
        tls_list = results.get("tls", [])
        tls_data = next((t for t in tls_list if isinstance(t, dict) and "certificate" in t), {})

        # Auth matrix
        matrix_data = results.get("auth_matrix", [{}])
        auth_matrix = matrix_data[0] if matrix_data else {}

        # JS analysis
        js_data = results.get("js_analysis", [{}])
        js_info = js_data[0] if js_data else {}

        # Discovered files
        discovered_files = results.get("files_discovered", [])

        template_data = {
            "target": target,
            "scan_date": scan_date,
            "tool_version": tool_version,
            "scan_profile": scan_profile,
            "overall_risk": overall_risk,
            "overall_risk_color": _severity_color(overall_risk),
            "findings": findings,
            "severity_counts": severity_counts,
            "total_findings": len(findings),
            "waf_vendor": waf_vendor,
            "waf_confidence": f"{waf_confidence:.0%}",
            "open_ports": open_ports,
            "tls_data": tls_data,
            "auth_matrix": auth_matrix,
            "js_info": js_info,
            "discovered_files": discovered_files,
            "severity_color": _severity_color,
        }

        # Try Jinja2 template
        if _JINJA2_AVAILABLE and (_TEMPLATE_DIR / self.template_name).exists():
            try:
                env = Environment(
                    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
                    autoescape=select_autoescape(["html", "xml"]),
                )
                env.globals["severity_color"] = _severity_color
                tmpl = env.get_template(self.template_name)
                return tmpl.render(**template_data)
            except Exception as e:
                _logger.warning(f"[PDF] Jinja2 render error: {e}, falling back to built-in template")

        # Built-in fallback HTML template (no external files needed)
        return self._builtin_template(template_data)

    def _builtin_template(self, d: Dict) -> str:
        """Minimal self-contained HTML report when Jinja2 template is unavailable."""
        findings_html = ""
        for f in d["findings"]:
            sev = f.get("severity") or f.get("cvss_severity") or "Info"
            color = _severity_color(sev)
            cvss = f.get("cvss_score", "")
            cvss_str = f" | CVSS: {cvss}" if cvss else ""
            remediation = f.get("remediation", "")
            findings_html += f"""
            <div style="border-left:4px solid {color};padding:12px;margin:12px 0;background:#fafafa">
              <div style="display:flex;justify-content:space-between">
                <strong>{f.get('type','Unknown')}</strong>
                <span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;font-size:0.85em">{sev}{cvss_str}</span>
              </div>
              <div style="margin-top:6px;color:#555;font-size:0.9em">
                <strong>URL:</strong> <code>{f.get('url','')}</code>
                {"<br><strong>Parameter:</strong> <code>"+f.get('parameter','')+"</code>" if f.get('parameter') else ""}
                {"<br><strong>Evidence:</strong> "+str(f.get('evidence',''))[:200] if f.get('evidence') else ""}
                {"<br><strong>Payload:</strong> <code>"+str(f.get('payload',''))[:100]+"</code>" if f.get('payload') else ""}
                {"<br><br><strong>Remediation:</strong> "+remediation if remediation else ""}
              </div>
            </div>"""

        ports_html = ""
        for p in d["open_ports"][:20]:
            ports_html += f"<tr><td>{p.get('port')}</td><td>{p.get('proto','tcp')}</td><td>{p.get('service','')}</td><td>{p.get('product','')} {p.get('version','')}</td></tr>"

        counts = d["severity_counts"]
        return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>WebSecure Report - {d['target']}</title>
<style>
  body{{font-family:Arial,sans-serif;margin:0;padding:20px;color:#333}}
  h1{{color:#1a1a2e}} h2{{color:#16213e;border-bottom:2px solid #0f3460;padding-bottom:6px}}
  .cover{{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;padding:60px 40px;margin:-20px -20px 30px}}
  .cover h1{{color:#e94560;font-size:2.5em;margin:0}} .cover p{{opacity:0.8}}
  .risk-badge{{display:inline-block;padding:8px 20px;border-radius:20px;font-weight:bold;color:#fff;background:{d['overall_risk_color']};font-size:1.3em}}
  .stat-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}}
  .stat{{padding:16px;border-radius:8px;text-align:center;color:#fff}}
  .stat .num{{font-size:2em;font-weight:bold}} .stat .lbl{{font-size:0.8em;opacity:0.9}}
  table{{width:100%;border-collapse:collapse;margin:10px 0}}
  th{{background:#16213e;color:#fff;padding:8px;text-align:left}}
  td{{padding:8px;border-bottom:1px solid #eee}} tr:hover{{background:#f8f9fa}}
  code{{background:#f1f3f4;padding:1px 4px;border-radius:3px;font-size:0.9em}}
  @media print{{.cover{{-webkit-print-color-adjust:exact}}}}
</style>
</head>
<body>
<div class="cover">
  <h1>WebSecure Penetration Test Report</h1>
  <p><strong>Target:</strong> {d['target']}</p>
  <p><strong>Date:</strong> {d['scan_date']}</p>
  <p><strong>Tool:</strong> {d['tool_version']} | Profile: {d['scan_profile']}</p>
  <br><div class="risk-badge">Overall Risk: {d['overall_risk']}</div>
</div>

<h2>Executive Summary</h2>
<div class="stat-grid">
  <div class="stat" style="background:#dc3545"><div class="num">{counts['Critical']}</div><div class="lbl">Critical</div></div>
  <div class="stat" style="background:#fd7e14"><div class="num">{counts['High']}</div><div class="lbl">High</div></div>
  <div class="stat" style="background:#ffc107;color:#333"><div class="num">{counts['Medium']}</div><div class="lbl">Medium</div></div>
  <div class="stat" style="background:#17a2b8"><div class="num">{counts['Low']}</div><div class="lbl">Low</div></div>
  <div class="stat" style="background:#6c757d"><div class="num">{counts['Info']}</div><div class="lbl">Info</div></div>
</div>
<p><strong>WAF Detected:</strong> {d['waf_vendor']} (confidence: {d['waf_confidence']})</p>
<p><strong>Total Findings:</strong> {d['total_findings']}</p>

<h2>Findings</h2>
{findings_html if findings_html else '<p style="color:#888">No findings recorded.</p>'}

{"<h2>Open Ports</h2><table><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th></tr>"+ports_html+"</table>" if ports_html else ""}

<hr>
<p style="color:#888;font-size:0.8em;text-align:center">
  Generated by {d['tool_version']} on {d['scan_date']}. This report is confidential.
</p>
</body></html>"""
