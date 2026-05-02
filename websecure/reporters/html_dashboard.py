"""
websecure.reporters.html_dashboard
------------------------------------
HTML dashboard renderer for WebSecure scan results.
Generates a modern, dark-mode, single-file HTML report.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone


def _escape(s):
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


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

    # Aggregate findings from ALL known buckets
    all_buckets = [
        "final", "offensive", "xss", "csrf", "jwt", "sqli", "nosqli",
        "ssrf", "xxe", "graphql", "file_upload", "auth", "auth_matrix",
        "headers", "security_headers", "rate_limit", "request_smuggling",
        "session_hunter", "mass_assignment", "ws_fuzz", "infrastructure",
        "sqlmap", "feroxbuster", "ffuf", "nuclei", "owasp",
        "discovery", "passive", "subdomains",
        "portscan", "nmap", "tls", "tls_findings", "js_analysis", "files_discovered",
    ]

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

            # Filter out Generic items without useful info
            f_type = item.get("type") or item.get("title") or "Generic"
            _raw_sev = (item.get("severity") or "Info").lower()
            _sev_map = {"critical": "Critical", "kritik": "Critical",
                        "high": "High", "yüksek": "High",
                        "medium": "Medium", "orta": "Medium",
                        "low": "Low", "düşük": "Low"}
            f_sev = _sev_map.get(_raw_sev, "Info")

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

            f = {
                "id": _id_counter,
                "severity": f_sev,
                "type": f"{f_type} ({bucket})", # Show tool source
                "url": item.get("url") or item.get("target") or "-",
                "method": item.get("method") or "GET",
                "param": item.get("param") or "-",
                "status": "Open",
                "detail": item
            }
            findings.append(f)
            _id_counter += 1

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

        secret_warning = f"<div style='background:rgba(218,54,51,0.1); border:1px solid var(--sev-critical); border-radius:4px; padding:0.75rem; margin-bottom:1rem; color:var(--sev-critical); font-weight:600;'>⚠️ {len(js_secrets)} hardcoded secret(s) detected in JavaScript files!</div>" if js_secrets else ""

        js_files_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">📜 JavaScript File Analysis</h3>
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
            {"<h4 style='margin-top:1rem; color:var(--sev-high);'>⚠️ Hardcoded Secrets</h4><div class='table-container'><table><thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Detail</th></tr></thead><tbody>" + rows_secrets + "</tbody></table></div>" if rows_secrets else ""}
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
            sen_warn = f"<div style='background:rgba(218,54,51,0.1); border:1px solid var(--sev-critical); border-radius:4px; padding:0.75rem; margin-bottom:1rem; color:var(--sev-critical); font-weight:600;'>⚠️ {len(sensitive_files)} sensitive file(s) exposed!</div>" if sensitive_files else ""
            files_html = f"""
            <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
                <h3 style="margin-top:0;">📁 Discovered Files ({len(file_items)} total, {len(sensitive_files)} sensitive)</h3>
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

    # Build type → {max_sev, count, advice, effort}
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
        _rem_rows_html += (
            f"<tr>"
            f"<td style='text-align:center; color:var(--text-muted); font-weight:600'>{rank}</td>"
            f"<td style='font-weight:500'>{_escape(vtype)}</td>"
            f"<td><span class='tag {_escape(sev_lbl)}'>{_escape(sev_lbl)}</span></td>"
            f"<td style='text-align:center; color:var(--accent); font-weight:600'>{info['count']}</td>"
            f"<td style='font-size:0.88rem; color:var(--text-muted)'>{_escape(info['advice'])}</td>"
            f"<td style='font-weight:600; color:{ec}'>{_escape(effort)}</td>"
            f"</tr>"
        )

    remediation_html = ""
    if _rem_rows_html:
        remediation_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">🎯 Remediation Priority Matrix</h3>
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
    findings_json = json.dumps(findings, default=str).replace("<", "\\u003c").replace(">", "\\u003e")

    # --- Ports Data Prep ---
    ports_html = ""
    nmap_data = results.get("nmap") or results.get("port_scan") or results.get("ports") or []
    if isinstance(nmap_data, list) and nmap_data:
        rows = []
        for p in nmap_data:
             if not isinstance(p, dict): continue
             # Normalize fields
             host = p.get("host") or p.get("ip") or "-"
             port = p.get("port") or p.get("dst_port") or "-"
             proto = p.get("proto") or "tcp"
             service = p.get("service") or p.get("name") or "-"
             state = p.get("state") or "open"

             # Accept "open" or "scanned" if we want to show them
             if "open" in str(state).lower():
                 rows.append(f"<tr><td>{_escape(host)}</td><td>{port}</td><td>{_escape(proto)}</td><td>{_escape(service)}</td><td><span class='tag Low'>{_escape(state)}</span></td></tr>")

        if rows:
             ports_html = f"""
             <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
                <h3 style="margin-top:0;">🌐 Open Ports (Nmap)</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>Service</th><th>State</th></tr></thead>
                        <tbody>{''.join(rows)}</tbody>
                    </table>
                </div>
             </div>
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
        <h3 style="margin-top:0;">🚦 Attack Traffic & Efficiency</h3>
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
            <h3 style="margin-top:0;">🌍 Discovered Subdomains ({len(subdomains)})</h3>
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
    if cert:
        valid_icon = "✅ Valid" if cert.get("valid") else "❌ Invalid"
        if cert.get("self_signed"):
            valid_icon = "⚠️ Self-Signed"

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

        hsts_icon = "✅" if (cert.get("hsts") or tls_data.get("hsts")) else "❌"

        ssl_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">🔒 SSL/TLS Certificate</h3>
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
            <h3 style="margin-top:0; color:var(--sev-high);">⚠️ Scan Phase Errors ({len(phase_errors)})</h3>
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
        <h1>🛡️ WebSecure Report</h1>
    </div>
    <div style="display:flex; gap:10px; align-items:center;">
        <button class="btn" onclick="showSessions()">🔑 Captured Sessions ({len(sessions)})</button>
        <div class="header-meta">
            <div>Target: <strong>{ _escape(target) }</strong> <span style="font-family:monospace; color:var(--accent)">[{_escape(target_ip)}]</span></div>
            <div>Date: { scan_date }</div>
        </div>
    </div>
</header>

<div class="container">

    <!-- Executive Summary -->
    <div class="stats-grid">
        <div class="stat-card">
            <span class="stat-value c-critical">{ stats["Critical"] }</span>
            <span class="stat-label">Critical</span>
        </div>
        <div class="stat-card">
            <span class="stat-value c-high">{ stats["High"] }</span>
            <span class="stat-label">High</span>
        </div>
        <div class="stat-card">
            <span class="stat-value c-medium">{ stats["Medium"] }</span>
            <span class="stat-label">Medium</span>
        </div>
        <div class="stat-card">
            <span class="stat-value c-low">{ stats["Low"] }</span>
            <span class="stat-label">Low</span>
        </div>
        <div class="stat-card">
             <span class="stat-value">{ total_issues }</span>
             <span class="stat-label">Total Findings</span>
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

    <!-- Remediation Priority Matrix -->
    { remediation_html }

    <!-- Phase Errors -->
    { phase_errors_html }

    <!-- Findings Table -->
    <h2>🔍 Findings ({total_issues} total)</h2>
    <div class="controls">
        <input type="text" id="searchInput" class="search" placeholder="Filter by URL, type, param, severity...">
        <select id="sevFilter" onchange="applyFilters()" style="background:var(--bg-header); border:1px solid var(--border); color:var(--text-main); padding:0.5rem 1rem; border-radius:6px;">
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
        </select>
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
            <h2>🔑 Captured Sessions</h2>
            <span class="close" onclick="closeModal('sessionsModal')">&times;</span>
        </div>
        <div class="modal-body" id="sessionsBody">
            <!-- Populated by JS -->
        </div>
    </div>
</div>

<script>
    const data = { findings_json };
    const sessions = { sessions_json };

    function renderTable(items) {{
        const tbody = document.getElementById('tableBody');
        tbody.innerHTML = '';
        if (items.length === 0) {{
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:2rem;">No findings match the current filter.</td></tr>';
            return;
        }}
        items.forEach(item => {{
            const tr = document.createElement('tr');
            tr.style.cursor = 'pointer';
            tr.onclick = () => showDetail(item.id);
            const sevClass = item.severity || 'Info';
            // Show param inline under URL for quick risk location view
            const paramBadge = item.param && item.param !== '-'
                ? `<br><span style="font-size:0.78rem; color:var(--text-muted);">param: <code style="color:var(--sev-high)">${{escapeHtml(item.param)}}</code></span>`
                : '';
            tr.innerHTML = `
                <td><span class="tag ${{sevClass}}">${{escapeHtml(sevClass)}}</span></td>
                <td style="font-weight:500">${{escapeHtml(item.type)}}</td>
                <td class="url">${{escapeHtml(item.url)}}${{paramBadge}}</td>
                <td class="method">${{escapeHtml(item.method)}}</td>
                <td><code style="font-size:0.85rem">${{escapeHtml(item.param)}}</code></td>
                <td><span class="tag Info">Open</span></td>
            `;
            tbody.appendChild(tr);
        }});
    }}

    function applyFilters() {{
        const term = document.getElementById('searchInput').value.toLowerCase();
        const sev = document.getElementById('sevFilter').value;
        const filtered = data.filter(item => {{
            const matchText = !term ||
                (item.url && item.url.toLowerCase().includes(term)) ||
                (item.type && item.type.toLowerCase().includes(term)) ||
                (item.param && item.param.toLowerCase().includes(term));
            const matchSev = !sev || item.severity === sev;
            return matchText && matchSev;
        }});
        renderTable(filtered);
    }}

    function showDetail(id) {{
        const item = data.find(i => i.id === id);
        if(!item) return;

        const d = item.detail;
        const modal = document.getElementById('detailModal');
        document.getElementById('modalTitle').innerText = item.type;

        let html = `
            <div class="kv-grid">
                <div class="label">URL</div> <div><a href="${{escapeHtml(item.url)}}" target="_blank" style="color:var(--accent)">${{escapeHtml(item.url)}}</a></div>
                <div class="label">Method</div> <div>${{item.method}}</div>
                <div class="label">Severity</div> <div><span class="tag ${{item.severity}}">${{item.severity}}</span></div>
                <div class="label">Location</div> <div>${{escapeHtml(d.location)}}</div>
                <div class="label">Param</div> <div><code>${{escapeHtml(item.param)}}</code></div>
            </div>
        `;

        if(d.reason) {{
             html += `<h3>Reason</h3><p>${{escapeHtml(d.reason)}}</p>`;
        }}

        if(d.poc || d.payload || d.evidence) {{
            const poc = d.poc || d.payload || d.evidence || "";
            if (typeof poc === 'object') {{
                html += `<h3>Evidence</h3><pre>${{escapeHtml(JSON.stringify(poc, null, 2))}}</pre>`;
            }} else {{
                html += `<h3>PoC / Payload</h3><pre>${{escapeHtml(poc)}}</pre>`;
            }}
        }}

        // [User Request] Render ALL keys in detail for Generic items to avoid "empty" look
        // If it's a generic info item, dump unknown keys as a table
        let knownKeys = ["url", "method", "severity", "location", "param", "reason", "poc", "payload", "evidence"];
        let extraKeys = Object.keys(d).filter(k => !knownKeys.includes(k) && !k.startsWith("_"));

        if (extraKeys.length > 0) {{
             html += `<h3>Additional Details</h3><div class="kv-grid">`;
             extraKeys.forEach(k => {{
                 let val = d[k];
                 if (typeof val === 'object') val = JSON.stringify(val, null, 2);
                 html += `<div class="label">${{escapeHtml(k)}}</div> <div><pre style="margin:0; padding:5px; font-size:0.85rem;">${{escapeHtml(val)}}</pre></div>`;
             }});
             html += `</div>`;
        }}


        // [WS3] Universal Forensic Panel (Evidence Locker)
        const ev = d.evidence || {{}};
        const hasEvidence = Object.keys(ev).length > 0;

        if (hasEvidence) {{
            html += `<div style="margin-top:20px; border:1px solid var(--accent); border-radius:6px; overflow:hidden;">`;
            html += `<div style="background:var(--accent); color:#000; padding:10px; font-weight:bold;">🔎 FACES OF EVIDENCE (FORENSICS)</div>`;
            html += `<div style="padding:15px; background:var(--bg-card);">`;

            // 1. Database Extraction (SQLMap)
            if (ev.database_banner || ev.extracted_data_type || ev.dumped_data) {{
                html += `<h4 style="color:var(--sev-high); margin-top:0;">🩸 Database Extraction Detected</h4>`;
                html += `<div class="kv-grid" style="margin-bottom:10px;">`;
                if(ev.database_banner) html += `<div class="label">DB Banner</div> <div><code>${{escapeHtml(ev.database_banner)}}</code></div>`;
                if(ev.extracted_data_type) html += `<div class="label">Extracted Type</div> <div>${{escapeHtml(ev.extracted_data_type)}}</div>`;
                html += `</div>`;

                if (ev.dumped_data && Array.isArray(ev.dumped_data)) {{
                    html += `<div><strong>Dumped Data Snippets:</strong></div>`;
                    html += `<pre style="color:var(--sev-high); border-color:var(--sev-high);">${{escapeHtml(ev.dumped_data.join("\\n"))}}</pre>`;
                }}
            }}

            // 2. XSS Alerts / Screenshots
            if (ev.alert_text || ev.screenshot_path) {{
                html += `<h4 style="color:var(--sev-med); margin-top:20px;">📸 DOM Exploitation Proof</h4>`;
                html += `<div class="kv-grid">`;
                if(ev.alert_text) html += `<div class="label">Alert Box</div> <div><code>${{escapeHtml(ev.alert_text)}}</code></div>`;
                if(ev.screenshot_path) html += `<div class="label">Screenshot</div> <div><a href="${{escapeHtml(ev.screenshot_path)}}" target="_blank">View File</a></div>`;
                html += `</div>`;
            }}

            // 3. Raw Response (Universal)
            if (ev.raw_response) {{
                html += `<h4 style="margin-top:20px;">📄 Raw Server Response</h4>`;
                html += `<pre style="max-height:200px; overflow:auto; font-size:0.8rem;">${{escapeHtml(ev.raw_response)}}</pre>`;
            }}

            html += `</div></div>`;
        }}

            // 2. XSS Proof (Alerts)
            if (ev.alert_text || ev.mechanism) {{
                html += `<h4 style="color:var(--sev-critical); margin-top:10px;">📸 Verified Payload Execution</h4>`;
                html += `<div style="background:rgba(218,54,51,0.1); border:1px solid var(--sev-critical); padding:10px; border-radius:4px;">`;
                html += `<div><strong>Mechanism:</strong> ${{escapeHtml(ev.mechanism || "Browser Event")}}</div>`;
                if(ev.alert_text) html += `<div><strong>Alert Content:</strong> <span style="font-family:monospace; background:#000; padding:2px 5px; color:#fff;">${{escapeHtml(ev.alert_text)}}</span></div>`;
                html += `</div>`;
            }}

            // 3. Raw Response (File Link or Snippet)
            if (ev.raw_response) {{
                 html += `<h4 style="margin-top:15px;">📜 Raw Server Response (Snapshot)</h4>`;
                 // Truncate if too long for modal
                 let raw = ev.raw_response;
                 if (raw.length > 2000) raw = raw.substring(0, 2000) + "... [truncated]";
                 html += `<pre>${{escapeHtml(raw)}}</pre>`;
            }}

            // 4. Screenshots
            if (ev.screenshot_path) {{
                 html += `<h4 style="margin-top:15px;">🖼️ Screen Capture</h4>`;
                 html += `<img src="${{escapeHtml(ev.screenshot_path)}}" style="max-width:100%; border:1px solid #555;">`;
            }}

            // 5. Generic KV dump for other evidence keys
            let usedKeys = ["database_banner", "extracted_data_type", "dumped_data", "alert_text", "mechanism", "raw_response", "screenshot_path"];
            let otherKeys = Object.keys(ev).filter(k => !usedKeys.includes(k));
            if(otherKeys.length > 0) {{
                 html += `<h4 style="margin-top:15px;">📂 Other Artifacts</h4><ul>`;
                 otherKeys.forEach(k => {{
                     let val = ev[k];
                     if(typeof val === 'object') val = JSON.stringify(val);
                     html += `<li><strong>${{escapeHtml(k)}}:</strong> ${{escapeHtml(val)}}</li>`;
                 }});
                 html += `</ul>`;
            }}

            html += `</div></div>`; // End of Forensic Card
        }}

        document.getElementById('modalBody').innerHTML = html;
        modal.style.display = 'block';
    }}

    function showSessions() {{
        const modal = document.getElementById('sessionsModal');
        const body = document.getElementById('sessionsBody');

        if (!sessions || sessions.length === 0) {{
            body.innerHTML = "<p>No sessions captured.</p>";
        }} else {{
            let html = "";
            sessions.forEach(s => {{
                const cookieJson = JSON.stringify(s.cookies || {{}});
                const exportCmd = `
// [WebSecure] One-Click Session Hijack
const cookies = ${{cookieJson}};
for (const [k, v] of Object.entries(cookies)) {{
    document.cookie = k + '=' + v + '; path=/';
}}
console.log('%c[+] Session Injected! Reloading...', 'color:lime; font-size:14px;');
setTimeout(() => location.reload(), 1000);
`.trim();

                // Escape for visual display but keep raw for copy
                const safeCmd = exportCmd.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
                const safeCmdAttr = escapeHtml(exportCmd).replace(/"/g, "&quot;");

                html += `<div class="card" style="margin-bottom:1rem; padding:1rem; background:var(--bg-body);">`;
                html += `<div style="display:flex; justify-content:space-between; align-items:flex-start;">`;
                html += `<div><strong>User:</strong> ${{escapeHtml(s.user)}} <span class="tag ${{s.verified ? 'Low' : 'Info'}}">${{s.verified ? 'Verified' : 'Unverified'}}</span></div>`;
                html += `<button class="btn" onclick="navigator.clipboard.writeText(this.getAttribute('data-cmd')).then(()=>alert('Copied! Paste into DevTools Console.'))" data-cmd="${{safeCmdAttr}}" style="font-size:0.8rem; padding:4px 8px;">📋 Copy Hijack Script</button>`;
                html += `</div>`;

                html += `<div><strong>Time:</strong> ${{s.timestamp}}</div>`;
                html += `<h4>Cookies</h4><pre>${{escapeHtml(JSON.stringify(s.cookies || {{}}, null, 2))}}</pre>`;
                html += `</div>`;
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

    // Search logic
    document.getElementById('searchInput').addEventListener('input', applyFilters);

    // Init
    renderTable(data);

</script>
</body>
</html>
"""
