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

        elif lower.startswith("sig_algo:") or lower.startswith("signature algorithm:"):
            cert["sig_algo"] = line.split(":", 1)[1].strip()

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

    # nmap çoğu zaman issuer/pubkey satırlarını boş bırakır ama PEM gömülüdür.
    # cryptography varsa PEM'i çözüp issuer (CA), imza algoritması ve anahtar
    # boyutunu doldur — "veriler tam gelsin" hedefi.
    if not cert.get("issuer_CN"):
        _pem_m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
        if _pem_m:
            try:
                from cryptography import x509 as _x509
                _c = _x509.load_pem_x509_certificate(_pem_m.group(0).encode())
                def _attr(name_obj, oid):
                    try:
                        vals = name_obj.get_attributes_for_oid(oid)
                        return vals[0].value if vals else ""
                    except Exception:
                        return ""
                from cryptography.x509.oid import NameOID as _NameOID
                _icn = _attr(_c.issuer, _NameOID.COMMON_NAME)
                _ion = _attr(_c.issuer, _NameOID.ORGANIZATION_NAME)
                if _icn:
                    cert["issuer_CN"] = _icn
                if _ion:
                    cert["issuer_O"] = _ion
                if not cert.get("subject_CN"):
                    _scn = _attr(_c.subject, _NameOID.COMMON_NAME)
                    if _scn:
                        cert["subject_CN"] = _scn
                if not cert.get("sig_algo") and getattr(_c, "signature_algorithm_oid", None):
                    cert["sig_algo"] = _c.signature_algorithm_oid._name
                try:
                    _ks = _c.public_key().key_size
                    if _ks:
                        cert["key_bits"] = int(_ks)
                except Exception:
                    pass
            except Exception as _pem_e:
                _logger.debug(f"[reporters.html_dashboard] PEM decode skipped: {_pem_e!r}")

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

            # ---------------------------------------------------------------
            # Gürültü filtresi — bulgu tablosunu kirleten kayıtları ele.
            # (a) Etiketi olmayan crawl/tech zenginleştirme artıfaktları:
            #     katana ile bulunan /static/chunks/*.js gibi URL'ler 'final'
            #     kovasına type'sız düşüp sahte CVSS 6.1/Medium damgası yiyor.
            #     Bunlar zafiyet değil — keşfedilen endpoint'ler (crawl bölümünde).
            # (b) Tarama-süreci olayları (phase_error vb.) ayrı tanı bölümünde.
            # ---------------------------------------------------------------
            _has_label = bool(item.get("type") or item.get("title") or item.get("message"))
            if not _has_label:
                continue
            _proc_noise = {
                "phase_error", "phase_timeout", "circuit_breaker_trip",
                "phase_metrics", "anti_block_event",
            }
            if str(item.get("type") or "").strip().lower() in _proc_noise:
                continue

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

    # Charts — artık statik Matplotlib PNG yerine canlı verilerden üretilen
    # gömülü SVG grafikler kullanıyoruz (aşağıda, stats + type_map hazır olunca).
    charts_html = ""

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

        secret_warning = f"<div style='background:rgba(218,54,51,0.1); border:1px solid var(--sev-critical); border-radius:4px; padding:0.75rem; margin-bottom:1rem; color:var(--sev-critical); font-weight:600;'>[!] JavaScript dosyalarında {len(js_secrets)} adet gömülü secret tespit edildi!</div>" if js_secrets else ""

        js_files_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">[scroll] JavaScript Dosya Analizi</h3>
            {secret_warning}
            <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:1rem; margin-bottom:1.5rem;">
                <div class="stat-card" style="padding:1rem; text-align:center;">
                    <span class="stat-value" style="font-size:1.5rem; color:var(--accent)">{len(js_files)}</span>
                    <span class="stat-label">Bulunan JS Dosyası</span>
                </div>
                <div class="stat-card" style="padding:1rem; text-align:center;">
                    <span class="stat-value" style="font-size:1.5rem; color:var(--sev-low)">{len(js_endpoints)}</span>
                    <span class="stat-label">Çıkarılan Endpoint</span>
                </div>
                <div class="stat-card" style="padding:1rem; text-align:center;">
                    <span class="stat-value" style="font-size:1.5rem; color:var(--sev-high)">{len(js_secrets)}</span>
                    <span class="stat-label">Tespit Edilen Secret</span>
                </div>
            </div>
            {"<h4>JS Dosyaları</h4><div class='table-container'><table><thead><tr><th>URL</th><th>Bilgi</th></tr></thead><tbody>" + rows_files + "</tbody></table></div>" if rows_files else ""}
            {"<h4 style='margin-top:1rem;'>Gizli Endpoint'ler / API Yolları</h4><div class='table-container'><table><thead><tr><th>Yol</th><th>Bulunduğu Yer</th></tr></thead><tbody>" + rows_endpoints + "</tbody></table></div>" if rows_endpoints else ""}
            {"<h4 style='margin-top:1rem; color:var(--sev-high);'>[!] Gömülü Secret'lar</h4><div class='table-container'><table><thead><tr><th>Severity</th><th>Tür</th><th>Dosya</th><th>Detay</th></tr></thead><tbody>" + rows_secrets + "</tbody></table></div>" if rows_secrets else ""}
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
                <h3 style="margin-top:0;">[signal] HTTP Probe Sonuçları — httpx ({len(_hx_rows)} host)</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>URL</th><th>Status</th><th>Başlık / Server</th><th>Teknolojiler</th><th>Content-Length</th></tr></thead>
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
                <h3 style="margin-top:0;">[globe] Taranan Endpoint'ler — katana ({len(_kat_eps)} bulundu{', ilk 200 gösteriliyor' if len(_kat_eps) > 200 else ''})</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>URL</th><th>Method</th><th>Kaynak</th></tr></thead>
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
            sen_warn = f"<div style='background:rgba(218,54,51,0.1); border:1px solid var(--sev-critical); border-radius:4px; padding:0.75rem; margin-bottom:1rem; color:var(--sev-critical); font-weight:600;'>[!] {len(sensitive_files)} adet hassas dosya dışarı açık!</div>" if sensitive_files else ""
            files_html = f"""
            <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
                <h3 style="margin-top:0;">[dir] Keşfedilen Dosyalar ({len(file_items)} toplam, {len(sensitive_files)} hassas)</h3>
                {sen_warn}
                <div class="table-container">
                    <table>
                        <thead><tr><th>Severity</th><th>URL</th><th>Tür / Detay</th></tr></thead>
                        <tbody>{all_file_rows}</tbody>
                    </table>
                </div>
            </div>
            """

    # --- Remediation Priority Matrix ---
    # Düzeltme önerileri — Türkçe açıklama, teknik terimler (CSP, JWT, SameSite…) korunur.
    _REMEDIATION_DB = {
        "sql injection": ("Parametreli sorgu / prepared statement kullan; girdi birleştirmeyi bırak", "Düşük"),
        "sqli": ("Parametreli sorgu / prepared statement kullan; girdi birleştirmeyi bırak", "Düşük"),
        "ssti": ("Kullanıcı kontrollü template render'ı kapat; statik template kullan", "Orta"),
        "template injection": ("Kullanıcı kontrollü template render'ı kapat; statik template kullan", "Orta"),
        "command injection": ("Shell çağrısından kaçın; shell=True yerine subprocess liste argümanı kullan", "Düşük"),
        "cmdi": ("Shell çağrısından kaçın; shell=True yerine subprocess liste argümanı kullan", "Düşük"),
        "xss": ("Tüm kullanıcı verisini output-encode et; sıkı CSP header'ı uygula", "Orta"),
        "cross-site scripting": ("Tüm kullanıcı verisini output-encode et; sıkı CSP header'ı uygula", "Orta"),
        "ssrf": ("Giden bağlantıları allowlist'le; iç metadata endpoint'lerine erişimi engelle", "Orta"),
        "xxe": ("XML parser'da external entity işlemeyi kapat (DTD devre dışı)", "Düşük"),
        "jwt": ("RS256/ES256 kullan; aud/iss/exp doğrula; imza anahtarlarını rotate et", "Orta"),
        "idor": ("Her kaynak erişiminde sunucu tarafı authorization zorla", "Orta"),
        "csrf": ("SameSite=Strict cookie + durum değiştiren her istekte CSRF token", "Düşük"),
        "open redirect": ("Yönlendirme hedeflerini allowlist'le; serbest URL'leri reddet", "Düşük"),
        "security header": ("HSTS, X-Content-Type-Options, X-Frame-Options, CSP header'larını ayarla", "Düşük"),
        "prototype pollution": ("Object.prototype'ı dondur; merge hedeflerinde null-prototype obje kullan", "Orta"),
        "file upload": ("MIME tipini sunucuda doğrula; web root dışında sakla; dosyaları yeniden adlandır", "Orta"),
        "mass assignment": ("Atanabilir alanlar için açık allow-list kullan; fazladan parametreyi reddet", "Düşük"),
        "nosql": ("Tipli sorgu builder kullan; kullanıcı girdisini sorguya asla interpolate etme", "Düşük"),
        "graphql": ("Production'da introspection'ı kapat; query depth/cost limiti uygula", "Düşük"),
        "request smuggling": ("HTTP/1.1 header'larını normalize et; mümkünse uçtan uca HTTP/2 kullan", "Yüksek"),
        "race condition": ("Kritik bölümlerde atomik işlem / advisory lock kullan", "Yüksek"),
        "tls": ("TLS 1.2+'ye yükselt; SSLv3/TLS 1.0'ı kapat; süresi dolan sertifikaları yenile", "Düşük"),
        "certificate": ("Sertifikayı yenile; güvenilir CA kullan; HSTS preloading etkinleştir", "Düşük"),
        "weak cipher": ("Zayıf/NULL cipher suite'leri kapat; sadece güçlü AEAD cipher'lara izin ver", "Düşük"),
        "clickjacking": ("X-Frame-Options: DENY veya CSP frame-ancestors 'none' uygula", "Düşük"),
        "cors": ("Origin'i allowlist'le; Access-Control-Allow-Origin'de wildcard + credentials kullanma", "Düşük"),
        "teknoloji": ("Sunucu/framework sürüm header'larını gizle; güncel yamalarda kal", "Düşük"),
        "web crawler": ("Keşfedilen endpoint'leri gözden geçir; gereksiz/eski olanları yetkilendir veya kaldır", "Düşük"),
        "api endpoint": ("Keşfedilen API endpoint'lerinde authentication/authorization doğrula", "Düşük"),
    }
    _SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    _EFFORT_COLOR = {"Düşük": "var(--sev-low)", "Orta": "var(--sev-medium)", "Yüksek": "var(--sev-high)"}

    # Build type -> {max_sev, count, advice, effort}
    type_map = {}
    for f in findings:
        raw_type = f["type"].split(" (")[0] if " (" in f["type"] else f["type"]
        entry = type_map.setdefault(raw_type, {"count": 0, "max_sev": 0, "sev_label": "Info", "examples": []})
        entry["count"] += 1
        sev_rank = _SEV_ORDER.get(f["severity"], 0)
        if sev_rank > entry["max_sev"]:
            entry["max_sev"] = sev_rank
            entry["sev_label"] = f["severity"]
        if len(entry["examples"]) < 8:
            entry["examples"].append({
                "url": f.get("url") or "-",
                "param": f.get("param") or "-",
                "severity": f.get("severity") or "Info",
                "method": f.get("method") or "GET",
            })
        # Lookup advice
        if "advice" not in entry:
            key_lower = raw_type.lower()
            for kw, (adv, eff) in _REMEDIATION_DB.items():
                if kw in key_lower:
                    entry["advice"] = adv
                    entry["effort"] = eff
                    break
        entry.setdefault("advice", "OWASP rehberine göre incele ve düzelt")
        entry.setdefault("effort", "Orta")

    priority_rows = sorted(type_map.items(), key=lambda x: (-x[1]["max_sev"], -x[1]["count"]))

    # -----------------------------------------------------------------------
    # Inline SVG charts — canlı veriden üretilir (statik Matplotlib PNG yerine).
    #   Sol: Risk Seviyesi Dağılımı (donut)
    #   Sağ: En Sık Görülen Bulgu Türleri (yatay bar) — "başarısız grafiği"nin
    #        yerine geçer; pentestçiye gerçek değer veren bir özet.
    # -----------------------------------------------------------------------
    import math as _math
    _SEV_COLORS = {
        "Critical": "#da3633", "High": "#d29922", "Medium": "#db6d28",
        "Low": "#3fb950", "Info": "#8b949e",
    }
    _sev_chart = [(s, stats.get(s, 0), _SEV_COLORS[s])
                  for s in ("Critical", "High", "Medium", "Low", "Info")]
    _sev_total = sum(c for _, c, _ in _sev_chart) or 1
    _R = 70.0
    _CIRC = 2 * _math.pi * _R
    _seg_svg = ""
    _legend_rows = ""
    _acc = 0.0
    for _name, _cnt, _col in _sev_chart:
        _frac = _cnt / _sev_total
        if _cnt > 0:
            _seg = _frac * _CIRC
            _seg_svg += (
                f'<circle cx="100" cy="100" r="{_R:.1f}" fill="none" stroke="{_col}" '
                f'stroke-width="26" stroke-dasharray="{_seg:.2f} {_CIRC - _seg:.2f}" '
                f'stroke-dashoffset="{-_acc:.2f}" transform="rotate(-90 100 100)">'
                f'<title>{_name}: {_cnt}</title></circle>'
            )
            _acc += _seg
        _legend_rows += (
            f'<div style="display:flex;align-items:center;gap:8px;font-size:0.85rem;margin:3px 0;">'
            f'<span style="width:11px;height:11px;border-radius:2px;background:{_col};display:inline-block;flex:0 0 auto;"></span>'
            f'<span style="color:var(--text-main);min-width:64px;">{_name}</span>'
            f'<span style="color:var(--text-muted);">{_cnt} ({100*_frac:.1f}%)</span>'
            f'</div>'
        )
    _donut = (
        f'<svg viewBox="0 0 200 200" width="200" height="200" style="display:block;margin:0 auto;">'
        f'<circle cx="100" cy="100" r="{_R:.1f}" fill="none" stroke="var(--bg-body)" stroke-width="26"></circle>'
        f'{_seg_svg}'
        f'<text x="100" y="94" text-anchor="middle" font-size="34" font-weight="700" fill="var(--text-main)">{total_issues}</text>'
        f'<text x="100" y="116" text-anchor="middle" font-size="12" fill="var(--text-muted)">BULGU</text>'
        f'</svg>'
    )

    # Top vulnerability types (by count) — yatay bar
    _by_count = sorted(type_map.items(), key=lambda x: -x[1]["count"])[:8]
    _max_cnt = max((info["count"] for _, info in _by_count), default=1) or 1
    _bars = ""
    if _by_count:
        for _vt, _info in _by_count:
            _w = max(4.0, 100.0 * _info["count"] / _max_cnt)
            _bc = _SEV_COLORS.get(_info["sev_label"], "#8b949e")
            _vt_short = _vt if len(_vt) <= 34 else _vt[:31] + "…"
            _bars += (
                f'<div style="margin:7px 0;cursor:pointer;" onclick="filterByType({json.dumps(_vt)})" '
                f'title="Bu türe göre filtrele: {_escape(_vt)}">'
                f'<div style="display:flex;justify-content:space-between;font-size:0.8rem;margin-bottom:2px;">'
                f'<span style="color:var(--text-main);">{_escape(_vt_short)}</span>'
                f'<span style="color:var(--text-muted);font-weight:600;">{_info["count"]}</span></div>'
                f'<div style="background:var(--bg-body);border-radius:4px;height:12px;overflow:hidden;">'
                f'<div style="width:{_w:.1f}%;height:100%;background:{_bc};border-radius:4px;"></div>'
                f'</div></div>'
            )
    else:
        _bars = '<p style="color:var(--text-muted);font-size:0.88rem;">Görüntülenecek bulgu türü yok.</p>'

    charts_html = f"""
    <div class="gallery">
        <div class="card chart-card" style="text-align:left;">
            <h3 style="margin-top:0;">Risk Seviyesi Dağılımı</h3>
            <div style="display:flex;flex-wrap:wrap;align-items:center;gap:1.5rem;justify-content:center;">
                <div>{_donut}</div>
                <div style="min-width:180px;">{_legend_rows}</div>
            </div>
        </div>
        <div class="card chart-card" style="text-align:left;">
            <h3 style="margin-top:0;">En Sık Görülen Bulgu Türleri</h3>
            <p style="color:var(--text-muted);font-size:0.82rem;margin:0 0 0.75rem;">Bir bara tıkla → tabloyu o türe göre filtreler.</p>
            {_bars}
        </div>
    </div>
    """

    _rem_rows_html = ""
    for rank, (vtype, info) in enumerate(priority_rows[:25], 1):
        sev_lbl = info["sev_label"]
        effort  = info["effort"]
        ec      = _EFFORT_COLOR.get(effort, "var(--text-muted)")
        # Safe JS string: use JSON encoding to avoid quote/special-char issues
        vtype_js = json.dumps(vtype)  # produces "\"...\""  — safe inside onclick attr
        sev_js   = json.dumps(sev_lbl)

        # Açılır detay satırı — etkilenen URL/parametre örnekleri ("oklara bilgi koy")
        _ex_rows = ""
        for _ex in info.get("examples", []):
            _ex_url = _ex.get("url") or "-"
            _ex_url_html = (
                f"<a href='{_escape(_ex_url)}' target='_blank' rel='noopener' style='color:var(--accent);text-decoration:none;'>{_escape(_ex_url)}</a>"
                if _ex_url and _ex_url != "-" else "-"
            )
            _ex_rows += (
                f"<tr>"
                f"<td><span class='tag {_escape(_ex.get('severity','Info'))}'>{_escape(_ex.get('severity','Info'))}</span></td>"
                f"<td class='method'>{_escape(_ex.get('method','GET'))}</td>"
                f"<td class='url' style='font-size:0.82rem'>{_ex_url_html}</td>"
                f"<td><code style='font-size:0.8rem;color:var(--sev-high)'>{_escape(_ex.get('param','-'))}</code></td>"
                f"</tr>"
            )
        _detail_block = (
            f"<div style='padding:0.5rem 0;'>"
            f"<div style='font-size:0.8rem;color:var(--text-muted);margin-bottom:6px;'>"
            f"Etkilenen yerler (ilk {len(info.get('examples', []))} örnek):</div>"
            f"<table style='width:100%;'><thead><tr>"
            f"<th width='90'>Severity</th><th width='70'>Method</th><th>URL</th><th width='130'>Parametre</th>"
            f"</tr></thead><tbody>{_ex_rows}</tbody></table>"
            f"<div style='margin-top:8px;'>"
            f"<button class='btn' style='font-size:0.78rem;padding:3px 10px;' onclick=\"filterByType({vtype_js})\">Tabloda hepsini filtrele &#8594;</button>"
            f"</div></div>"
        )

        _rem_rows_html += (
            f"<tr class='rem-main' onclick=\"toggleRemRow({rank})\" style='cursor:pointer;'>"
            f"<td style='text-align:center; color:var(--text-muted); font-weight:600'>{rank}</td>"
            f"<td style='font-weight:500;'>"
            f"  <span class='rem-caret' id='rem-caret-{rank}' style='display:inline-block;color:var(--accent);transition:transform 0.15s;font-size:0.8rem;'>&#9654;</span> "
            f"  {_escape(vtype)}"
            f"</td>"
            f"<td onclick=\"event.stopPropagation();filterBySeverity({sev_js})\" "
            f"    title='Sadece {_escape(sev_lbl)} bulguları filtrele' style='cursor:pointer;'>"
            f"  <span class='tag {_escape(sev_lbl)}'>{_escape(sev_lbl)}</span>"
            f"</td>"
            f"<td style='text-align:center; color:var(--accent); font-weight:600'>{info['count']}</td>"
            f"<td style='font-size:0.88rem; color:var(--text-muted)'>{_escape(info['advice'])}</td>"
            f"<td style='font-weight:600; color:{ec}'>{_escape(effort)}</td>"
            f"</tr>"
            f"<tr class='rem-detail' id='rem-detail-{rank}' style='display:none;'>"
            f"<td colspan='6' style='background:var(--bg-body);'>{_detail_block}</td>"
            f"</tr>"
        )

    remediation_html = ""
    if _rem_rows_html:
        remediation_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">[target] Öncelikli Düzeltme Matrisi</h3>
            <p style="color:var(--text-muted); font-size:0.88rem; margin:0 0 1rem;">
                Önem (severity) ve sıklığa göre sıralı — önce Critical/High olanları düzelt.
                <strong style="color:var(--text-main);">Satıra tıkla</strong> → etkilenen URL/parametreleri aç;
                <strong style="color:var(--text-main);">severity etiketine tıkla</strong> → tabloyu o seviyeye filtrele.
                <em>Çözüm Eforu</em> = düzeltmenin geliştirici maliyeti (severity ile aynı şey değildir).
            </p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th width="40">#</th>
                            <th>Zafiyet Türü</th>
                            <th width="100">Maks. Severity</th>
                            <th width="60">Adet</th>
                            <th>Önerilen Çözüm</th>
                            <th width="110">Çözüm Eforu</th>
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

                 def _first_line(text, *needles, limit=120):
                     for _l in str(text).split("\n"):
                         _ls = _l.strip()
                         if not _ls:
                             continue
                         if not needles or any(n.lower() in _ls.lower() for n in needles):
                             return _ls[:limit]
                     return ""

                 # Üst düzey servis bilgisi (CPE / OS guess)
                 _cpe = p.get("cpe")
                 if _cpe:
                     _cpe_s = ", ".join(_cpe) if isinstance(_cpe, list) else str(_cpe)
                     _detail_parts.append(f"<b>CPE:</b> {_escape(_cpe_s[:160])}")
                 if p.get("os_guess"):
                     _detail_parts.append(f"<b>OS Tahmini:</b> {_escape(str(p['os_guess'])[:120])}")

                 if "http-title" in _scripts:
                     _detail_parts.append(f"<b>Başlık:</b> {_escape(_scripts['http-title'][:120])}")

                 _srv = _scripts.get("http-server-header") or _first_line(_scripts.get("http-headers", ""), "Server:")
                 if _srv:
                     _detail_parts.append(f"<b>Server:</b> {_escape(str(_srv)[:120])}")

                 if "http-security-headers" in _scripts:
                     _sh = [l.strip() for l in str(_scripts["http-security-headers"]).split("\n") if l.strip()]
                     if _sh:
                         _detail_parts.append(
                             "<b>Güvenlik Header'ları:</b><br>" +
                             "<br>".join(_escape(l[:90]) for l in _sh[:8])
                         )

                 if "ssl-cert" in _scripts:
                     _cert_lines = [l.strip() for l in _scripts["ssl-cert"].split("\n")
                                    if any(k in l for k in ("commonName", "Not valid", "Subject:", "Issuer:", "Public Key", "bits"))]
                     if _cert_lines:
                         _detail_parts.append("<b>SSL Sertifikası:</b><br>" + "<br>".join(_escape(l[:110]) for l in _cert_lines[:7]))

                 if "ssl-enum-ciphers" in _scripts:
                     _ct = _scripts["ssl-enum-ciphers"]
                     _ls = _first_line(_ct, "least strength")
                     _tv = _first_line(_ct, "TLSv", "SSLv")
                     _cipher_summary = " | ".join(x for x in [_tv, _ls] if x)
                     if _cipher_summary:
                         _detail_parts.append(f"<b>TLS Cipher:</b> {_escape(_cipher_summary)}")

                 if "ssl-date" in _scripts:
                     _sd = _first_line(_scripts["ssl-date"])
                     if _sd:
                         _detail_parts.append(f"<b>Sunucu Saati (TLS):</b> {_escape(_sd)}")

                 _geo = _scripts.get("ip-geolocation-geoplugin") or _scripts.get("ip-geolocation-maxmind")
                 if _geo:
                     _geo_lines = [l.strip() for l in str(_geo).split("\n") if l.strip() and "coordinates" not in l.lower()]
                     if _geo_lines:
                         _detail_parts.append("<b>Coğrafi Konum:</b> " + _escape(" / ".join(_geo_lines[:3])[:160]))

                 _asn = _scripts.get("asn-query")
                 if _asn:
                     _asn_l = _first_line(_asn, "BGP", "Country", "Origin", "AS")
                     if _asn_l:
                         _detail_parts.append(f"<b>ASN:</b> {_escape(_asn_l[:160])}")

                 _whois = _scripts.get("whois-ip")
                 if _whois:
                     _wl = _first_line(_whois, "Organization", "OrgName", "netname", "descr", "inetnum")
                     if _wl:
                         _detail_parts.append(f"<b>WHOIS:</b> {_escape(_wl[:160])}")

                 for _sid in ("ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection"):
                     if _sid in _scripts and "VULNERABLE" in str(_scripts[_sid]).upper():
                         _detail_parts.append(f"<b style='color:var(--sev-critical)'>ZAFİYET: {_escape(_sid)}</b>")

                 # Geriye kalan, henüz gösterilmeyen script'leri de ham olarak ekle
                 _shown = {"http-title", "http-server-header", "http-headers", "http-security-headers",
                           "ssl-cert", "ssl-enum-ciphers", "ssl-date", "ip-geolocation-geoplugin",
                           "ip-geolocation-maxmind", "asn-query", "whois-ip", "ssl-heartbleed",
                           "ssl-poodle", "ssl-ccs-injection", "port-states", "fingerprint-strings"}
                 _extra = []
                 for _sk, _sv in _scripts.items():
                     if _sk in _shown:
                         continue
                     _line = _first_line(_sv)
                     if _line:
                         _extra.append(f"<b>{_escape(_sk)}:</b> {_escape(_line[:120])}")
                 if _extra:
                     _detail_parts.append("<br>".join(_extra[:6]))

                 _details_html = ""
                 if _detail_parts:
                     _inner = "<br><br>".join(_detail_parts)
                     _details_html = (
                         f"<details style='cursor:pointer'>"
                         f"<summary style='color:var(--accent);font-size:0.8rem;list-style:none'>&#9656; ayrıntılar</summary>"
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
                <h3 style="margin-top:0;">[web] Açık Portlar — Nmap ({len(rows)} bulundu)</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>Servis</th><th>Durum</th><th>Ayrıntılar</th></tr></thead>
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
    # Birincil kaynak: results["waf_detection"]; yedek: results["waf"] kovası (son kayıt).
    waf_raw = results.get("waf_detection") or {}
    if isinstance(waf_raw, list):
        waf_raw = next((x for x in waf_raw if isinstance(x, dict)), {})
    if not waf_raw:
        _waf_bucket = results.get("waf") or []
        if isinstance(_waf_bucket, list):
            # En yüksek confidence'lı / detected olan kaydı seç
            _cand = [x for x in _waf_bucket if isinstance(x, dict)]
            waf_raw = next((x for x in _cand if x.get("detected")),
                           (_cand[-1] if _cand else {}))
        elif isinstance(_waf_bucket, dict):
            waf_raw = _waf_bucket
    waf_detected = bool(waf_raw.get("detected"))
    _waf_vendor = waf_raw.get("vendor") or "Yok"
    if isinstance(_waf_vendor, str) and _waf_vendor.lower() in ("unknown", "none", ""):
        _waf_vendor = "Bilinmiyor" if waf_detected else "Yok"
    waf_confidence = waf_raw.get("confidence") or 0.0
    waf_badge_color = "var(--sev-critical)" if waf_detected else "var(--sev-low)"
    try:
        _wc = int(float(waf_confidence) * 100)
    except (TypeError, ValueError):
        _wc = 0
    waf_label = f"{_escape(_waf_vendor)} ({_wc}%)" if waf_detected else "Tespit Edilmedi"

    # --- Metrics / Traffic Data ---
    # results içinde "metrics" yoksa (çoğu zaman yok — ayrı metrics.json'a yazılır)
    # canlı HTTP sayaçlarına doğrudan başvur. Böylece pano her durumda dolar.
    _metrics_raw = results.get("metrics") or {}
    if isinstance(_metrics_raw, list):
        metrics = next((x for x in _metrics_raw if isinstance(x, dict)), {})
    elif isinstance(_metrics_raw, dict):
        metrics = _metrics_raw
    else:
        metrics = {}
    if not metrics.get("counters"):
        try:
            from websecure.core.http import get_http_metrics as _ghm
            _live = _ghm()
            if isinstance(_live, dict) and _live.get("counters"):
                metrics = _live
        except Exception as _mexc:
            _logger.debug(f"[html_dashboard] live metrics fallback failed: {_mexc!r}")
    _counters_raw = metrics.get("counters") or {}
    counters = _counters_raw if isinstance(_counters_raw, dict) else {}

    def _ci(*names):
        for n in names:
            v = counters.get(n)
            if v:
                return int(v)
        return 0
    total_req = _ci("total", "requests")
    ok_2xx    = _ci("2xx", "ok_2xx")
    block_403 = _ci("403", "ban_403")
    rate_429  = _ci("429", "throttle_429")
    err_4xx   = _ci("err_4xx")
    err_5xx   = _ci("err_5xx")
    redir_3xx = max(0, total_req - ok_2xx - err_4xx - err_5xx) if total_req else 0

    # Per-location status ("nereden 2xx/3xx/403/429 aldık")
    status_locations = metrics.get("status_locations") or {}
    # Yedek: anti_block_event kovasından blok konumları
    if not status_locations:
        for _abe in (results.get("anti_block_event") or []):
            if not isinstance(_abe, dict):
                continue
            _u = (_abe.get("url") or "").split("?", 1)[0]
            if not _u:
                continue
            _cls = {403: "403", 429: "429"}.get(int(_abe.get("status") or 0), "other")
            slot = status_locations.setdefault(_u, {})
            slot[_cls] = int(slot.get(_cls, 0)) + 1

    # Onaylı exploit = gerçekten doğrulanmış orta+ önemdeki bulgular
    exploit_count = stats["Critical"] + stats["High"] + stats["Medium"]

    # Response-code dağılım barı
    _dist = [
        ("2xx", ok_2xx, "var(--sev-low)"),
        ("3xx", redir_3xx, "var(--accent)"),
        ("403", block_403, "var(--sev-high)"),
        ("429", rate_429, "var(--sev-medium)"),
        ("4xx", max(0, err_4xx - block_403 - rate_429), "#b06a2c"),
        ("5xx", err_5xx, "var(--sev-critical)"),
    ]
    _dist_total = sum(v for _, v, _ in _dist) or 1
    _dist_bar = "".join(
        f'<div title="{lbl}: {val}" style="width:{100*val/_dist_total:.1f}%;background:{col};height:100%;"></div>'
        for lbl, val, col in _dist if val > 0
    )
    _dist_legend = " ".join(
        f'<span style="font-size:0.78rem;color:var(--text-muted);margin-right:10px;">'
        f'<span style="display:inline-block;width:9px;height:9px;background:{col};border-radius:2px;margin-right:3px;"></span>'
        f'{lbl}: <strong style="color:var(--text-main)">{val}</strong></span>'
        for lbl, val, col in _dist if val > 0
    )
    _dist_html = (
        f'<div style="margin-top:1rem;">'
        f'<div style="display:flex;height:14px;border-radius:4px;overflow:hidden;background:var(--bg-body);">{_dist_bar}</div>'
        f'<div style="margin-top:6px;">{_dist_legend}</div></div>'
    ) if total_req else (
        '<p style="color:var(--text-muted);font-size:0.86rem;margin-top:1rem;">'
        'Bu taramada HTTP sayaçları kaydedilmedi (istekler sayaç yolundan geçmemiş olabilir). '
        'Bir sonraki taramada bu pano otomatik dolacak.</p>'
    )

    # Konuma göre trafik tablosu
    _loc_html = ""
    if status_locations:
        def _loc_score(kv):
            s = kv[1]
            return (int(s.get("403", 0)) + int(s.get("429", 0)), sum(int(v) for k, v in s.items() if k != "last"))
        _loc_rows = ""
        for _path, _s in sorted(status_locations.items(), key=_loc_score, reverse=True)[:40]:
            def _cell(key, color):
                v = int(_s.get(key, 0))
                return f"<span style='color:{color};font-weight:600'>{v}</span>" if v else "<span style='color:var(--text-muted)'>0</span>"
            _blocked = int(_s.get("403", 0)) + int(_s.get("429", 0))
            _verdict = ("<span class='tag High'>WAF/Block</span>" if _blocked else "<span class='tag Low'>Geçti</span>")
            _loc_rows += (
                f"<tr>"
                f"<td class='url' style='font-size:0.8rem'>{_escape(_path)}</td>"
                f"<td style='text-align:center'>{_cell('2xx','var(--sev-low)')}</td>"
                f"<td style='text-align:center'>{_cell('3xx','var(--accent)')}</td>"
                f"<td style='text-align:center'>{_cell('403','var(--sev-high)')}</td>"
                f"<td style='text-align:center'>{_cell('429','var(--sev-medium)')}</td>"
                f"<td style='text-align:center'>{_cell('5xx','var(--sev-critical)')}</td>"
                f"<td style='text-align:center'>{_verdict}</td>"
                f"</tr>"
            )
        _loc_html = f"""
        <h4 style="margin:1.25rem 0 0.5rem;">Konuma Göre Trafik — nereden geçtik / nerede engellendik</h4>
        <div class="table-container">
            <table>
                <thead><tr>
                    <th>Yol (path)</th><th width="60">2xx</th><th width="60">3xx</th>
                    <th width="60">403</th><th width="60">429</th><th width="60">5xx</th><th width="110">Sonuç</th>
                </tr></thead>
                <tbody>{_loc_rows}</tbody>
            </table>
        </div>
        """

    traffic_html = f"""
    <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
        <h3 style="margin-top:0;">[signal] Saldırı Trafiği & Verimlilik</h3>
        <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); margin-bottom:0;">
            <div class="stat-card" style="padding:1rem;">
                <span class="stat-value" style="font-size:1.5rem; color:var(--text-main)">{total_req}</span>
                <span class="stat-label">Toplam İstek</span>
            </div>
            <div class="stat-card" style="padding:1rem;">
                <span class="stat-value" style="font-size:1.5rem; color:var(--sev-low)">{ok_2xx}</span>
                <span class="stat-label">2xx (Geçti)</span>
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
                <span class="stat-label">Onaylı Exploit</span>
            </div>
            <div class="stat-card" style="padding:1rem; border-color:{waf_badge_color};">
                <span class="stat-value" style="font-size:1rem; color:{waf_badge_color}; word-break:break-word">{waf_label}</span>
                <span class="stat-label">WAF Durumu</span>
            </div>
        </div>
        {_dist_html}
        {_loc_html}
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
            <h3 style="margin-top:0;">[globe] Keşfedilen Subdomain'ler ({len(subdomains)})</h3>
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
            # Augment with TLS versions + cipher sample from ssl-enum-ciphers
            _enum_text = _scripts.get("ssl-enum-ciphers") or ""
            _tls_versions = []
            _ciphers = []
            _least = ""
            for _el in _enum_text.splitlines():
                _els = _el.strip()
                _m = re.match(r"(TLSv[0-9.]+|SSLv[0-9]+)\s*:?\s*$", _els)
                if _m:
                    _tls_versions.append(_m.group(1))
                # cipher satırları genelde "TLS_..." içerir
                if "TLS_" in _els and len(_ciphers) < 6:
                    _ciphers.append(_els.split(" - ")[0].strip()[:70])
                if "least strength" in _els.lower():
                    _least = _els.split(":", 1)[-1].strip()
            if _tls_versions:
                cert["tls_version"] = ", ".join(dict.fromkeys(_tls_versions))
            if _ciphers:
                cert["ciphers"] = _ciphers
            if _least:
                cert["least_strength"] = _least
            # ssl-date'ten sunucu saati
            _sdt = _scripts.get("ssl-date") or ""
            if _sdt:
                cert.setdefault("server_time", _sdt.strip().split("\n")[0][:80])
            break  # use first port that has ssl-cert (usually 443)

    if cert:
        valid_icon = "[OK] Geçerli" if cert.get("valid") else "[X] Geçersiz"
        if cert.get("self_signed"):
            valid_icon = "[!] Self-Signed (kendinden imzalı)"

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
        days_label = f"{days} gün" if isinstance(days, int) else "-"

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
            san_html = f"<div class='label'>Alt Adlar (SAN)</div><div>{san_items}</div>"

        # Cipher listesi + en zayıf güç
        _ciphers = cert.get("ciphers") or []
        cipher_html = ""
        if _ciphers:
            _ch_items = "".join(
                f"<div style='font-family:monospace;font-size:0.8rem;color:var(--text-muted)'>{_escape(c)}</div>"
                for c in _ciphers
            )
            cipher_html = f"<div class='label'>Cipher Suite'ler</div><div>{_ch_items}</div>"
        least_html = ""
        if cert.get("least_strength"):
            least_html = (
                f"<div class='label'>En Zayıf Güç</div>"
                f"<div><span class='tag {'High' if str(cert.get('least_strength')).upper().startswith(('C','D','E','F')) else 'Low'}'>"
                f"{_escape(str(cert.get('least_strength')))}</span></div>"
            )
        servertime_html = ""
        if cert.get("server_time"):
            servertime_html = f"<div class='label'>Sunucu Saati (TLS)</div><div>{_escape(str(cert.get('server_time')))}</div>"

        hsts_on = bool(cert.get("hsts") or (isinstance(tls_data, dict) and tls_data.get("hsts")))
        hsts_icon = "[OK]" if hsts_on else "[X]"

        ssl_html = f"""
        <div class="card" style="background:var(--bg-card); border:1px solid var(--border); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0;">[lock] SSL/TLS Sertifikası</h3>
            <div class="kv-grid" style="grid-template-columns: 200px 1fr; gap:0.5rem; margin-bottom:0;">
                <div class="label">Durum</div>        <div>{valid_icon} {probs_html}{warnings_html}</div>
                <div class="label">HSTS</div>         <div>{hsts_icon} Strict-Transport-Security</div>
                <div class="label">Subject CN</div>   <div><code>{_escape(cert.get('subject_CN') or '-')}</code></div>
                <div class="label">Issuer (CA)</div>  <div>{_escape(cert.get('issuer_CN') or '-')}{(' (' + _escape(cert.get('issuer_O')) + ')') if cert.get('issuer_O') else ''}</div>
                <div class="label">Geçerlilik</div>   <div>{_escape(str(cert.get('not_before') or ''))} &mdash; {_escape(str(cert.get('not_after') or ''))}</div>
                <div class="label">Kalan Süre</div>   <div style="color:{expiry_color}"><strong>{days_label}</strong></div>
                <div class="label">Protokol</div>     <div>{_escape(cert.get('tls_version') or '-')}</div>
                {f'<div class="label">İmza Algoritması</div><div><code>{_escape(cert.get("sig_algo"))}</code></div>' if cert.get('sig_algo') else ''}
                {f'<div class="label">Anahtar Boyutu</div><div>{cert.get("key_bits")} bit</div>' if cert.get('key_bits') else ''}
                {least_html}
                {cipher_html}
                {servertime_html}
                <div class="label">Fingerprint</div>  <div style="font-family:monospace; font-size:0.82rem; word-break:break-all;">{_escape(cert.get('fingerprint') or '-')}</div>
                {san_html}
            </div>
        </div>
        """

    # --- Phase Errors Section ---
    # Faz hataları İKİ ayrı kovaya yazılıyordu ve rapor yalnızca birini okuyordu:
    #   • results["phase_error"]  → runner-seviyesi yakalanan hatalar (ssrf/idor/…)
    #   • results["errors"]       → watchdog timeout'ları (type="phase_timeout") ve
    #                                yakalanmamış thread çökmeleri (type="phase_error")
    # Eski kod sadece "phase_error" kovasını gösterdiği için sqlmap/waf_detect/ffuf
    # gibi TIMEOUT'a düşen ~18 faz raporda görünmüyordu (terminalde "exceeded …s —
    # skipped" yazsa da). Artık her iki kaynağı birleştir, normalize et, tekilleştir.
    def _norm_phase_errs(res):
        out = []
        seen = set()

        def _push(phase, exc_type, message):
            phase = (phase or "-").strip() or "-"
            exc_type = (exc_type or "").strip()
            message = (message or "").strip()
            key = (phase, exc_type, message)
            if key in seen:
                return
            seen.add(key)
            out.append({"phase": phase, "exc_type": exc_type, "message": message})

        # 1) Dedicated phase_error bucket (already in {meta:{phase,exc_type}, message})
        for e in (res.get("phase_error") or []):
            if not isinstance(e, dict):
                continue
            m = e.get("meta") if isinstance(e.get("meta"), dict) else {}
            _push(m.get("phase") or e.get("phase"), m.get("exc_type"), e.get("message"))

        # 2) errors bucket: surface phase_timeout + phase_error entries too
        for e in (res.get("errors") or []):
            if not isinstance(e, dict):
                continue
            etype = str(e.get("type") or "").strip().lower()
            if etype == "phase_timeout":
                secs = e.get("timeout_secs")
                _push(
                    e.get("phase"),
                    "PhaseTimeout",
                    f"phase exceeded {secs}s — skipped to prevent hang" if secs
                    else "phase timed out — skipped to prevent hang",
                )
            elif etype == "phase_error":
                m = e.get("meta") if isinstance(e.get("meta"), dict) else {}
                raw = str(e.get("error") or e.get("message") or "")
                exc = m.get("exc_type") or (raw.split(":", 1)[0] if ":" in raw else "")
                _push(e.get("phase") or m.get("phase"), exc, raw or e.get("message"))
            else:
                # 3) type'sız ama gerçek başarısızlık taşıyan kayıtlar — main.py'nin
                #    offensive bölümü hataları {stage:X, error:Y} (type YOK) olarak
                #    yazıyor (ör. ssrf_xxe "missing ctx", bizlogic "'str'.items()",
                #    "module_missing"). Eskiden bunlar HİÇBİR yerde görünmüyordu →
                #    "çalışmayan tarama" raporda gizli kalıyordu. error/message taşıyan
                #    her errors-kovası kaydını yüzeye çıkar (stage→phase).
                raw = e.get("error") or e.get("message")
                if not raw:
                    continue
                raw = str(raw)
                phase = e.get("phase") or e.get("stage")
                if not phase:
                    continue
                exc = raw.split(":", 1)[0].strip() if ":" in raw else "ScanError"
                # Çok uzun exc_type (aslında düz mesaj) → kısalt
                if len(exc) > 40 or " " in exc:
                    exc = "ScanError"
                _push(phase, exc, raw)
        return out

    phase_errors = _norm_phase_errs(results)
    phase_errors_html = ""
    if phase_errors:
        err_rows = "".join(
            f"<tr>"
            f"<td style='font-family:monospace; color:var(--sev-high)'>{_escape(e.get('phase', '-'))}</td>"
            f"<td style='color:var(--sev-medium)'>{_escape(e.get('exc_type', ''))}</td>"
            f"<td style='font-size:0.85rem; color:var(--text-muted)'>{_escape(e.get('message', ''))}</td>"
            f"</tr>"
            for e in phase_errors
        )
        phase_errors_html = f"""
        <div class="card" style="background:rgba(210,153,34,0.07); border:1px solid var(--sev-high); border-radius:6px; padding:1.5rem; margin-bottom:2rem;">
            <h3 style="margin-top:0; color:var(--sev-high);">[!] Tarama Faz Hataları ({len(phase_errors)})</h3>
            <p style="color:var(--text-muted); font-size:0.9rem; margin-bottom:1rem;">Bazı tarama fazları hata aldı veya zaman aşımına uğradı. Bu fazlardan gelen sonuçlar eksik olabilir.</p>
            <div class="table-container">
                <table>
                    <thead><tr><th>Faz</th><th>Hata Tipi</th><th>Mesaj</th></tr></thead>
                    <tbody>{err_rows}</tbody>
                </table>
            </div>
        </div>
        """

    # --- Sessions Data Prep ---
    sessions = results.get("sessions") or []
    sessions_json = json.dumps(sessions, default=str).replace("<", "\\u003c").replace(">", "\\u003e")

    return f"""<!DOCTYPE html>
<html lang="tr">
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
        <h1>[shield] WebSecure Raporu</h1>
    </div>
    <div style="display:flex; gap:10px; align-items:center;">
        <button class="btn" onclick="showSessions()">[key] Yakalanan Oturumlar ({len(sessions)})</button>
        <div class="header-meta">
            <div>Hedef: <strong>{ _escape(target) }</strong> <span style="font-family:monospace; color:var(--accent)">[{_escape(target_ip)}]</span></div>
            <div>Tarih: { scan_date }</div>
        </div>
    </div>
</header>

<div class="container">

    <!-- Yönetici Özeti — bir karta tıkla → bulgu tablosunu o severity'ye filtreler -->
    <div class="stats-grid">
        <div class="stat-card" id="card-Critical" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('Critical')" title="Sadece Critical bulguları göster">
            <span class="stat-value c-critical">{ stats["Critical"] }</span>
            <span class="stat-label">Critical</span>
        </div>
        <div class="stat-card" id="card-High" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('High')" title="Sadece High bulguları göster">
            <span class="stat-value c-high">{ stats["High"] }</span>
            <span class="stat-label">High</span>
        </div>
        <div class="stat-card" id="card-Medium" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('Medium')" title="Sadece Medium bulguları göster">
            <span class="stat-value c-medium">{ stats["Medium"] }</span>
            <span class="stat-label">Medium</span>
        </div>
        <div class="stat-card" id="card-Low" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('Low')" title="Sadece Low bulguları göster">
            <span class="stat-value c-low">{ stats["Low"] }</span>
            <span class="stat-label">Low</span>
        </div>
        <div class="stat-card" id="card-Info" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('Info')" title="Sadece Info (bilgilendirici) bulguları göster">
            <span class="stat-value c-info">{ stats["Info"] }</span>
            <span class="stat-label">Info</span>
        </div>
        <div class="stat-card" id="card-All" style="cursor:pointer; transition:border-color 0.15s;" onclick="filterBySeverity('')" title="Tüm bulguları göster">
             <span class="stat-value">{ total_issues }</span>
             <span class="stat-label">Tüm Bulgular</span>
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
    <h2>[search] Bulgular (<span id="findingCount">{total_issues}</span> / {total_issues})</h2>
    <p style="color:var(--text-muted); font-size:0.86rem; margin:-0.5rem 0 1rem;">
        Arama kutusu URL, tür, parametre, payload, severity ve açıklamada arar. Severity menüsü ile birlikte çalışır.
    </p>
    <div class="controls">
        <input type="text" id="searchInput" class="search" placeholder="URL, tür, parametre, payload veya severity ile filtrele..." oninput="applyFilters()">
        <select id="sevFilter" onchange="applyFilters()" style="background:var(--bg-header); border:1px solid var(--border); color:var(--text-main); padding:0.5rem 1rem; border-radius:6px;">
            <option value="">Tüm Severity'ler</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
        </select>
        <button class="btn" onclick="filterBySeverity('')" title="Tüm filtreleri temizle">&#x2715; Temizle</button>
    </div>

    <div class="table-container">
        <table id="findingsTable">
            <thead>
                <tr>
                    <th width="90">Severity</th>
                    <th width="180">Tür</th>
                    <th>URL / Risk Konumu</th>
                    <th width="80">Method</th>
                    <th width="120">Parametre</th>
                    <th width="80">Durum</th>
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
            <h2 id="modalTitle">Bulgu Detayı</h2>
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
            <h2>[key] Yakalanan Oturumlar</h2>
            <span class="close" onclick="closeModal('sessionsModal')">&times;</span>
        </div>
        <div class="modal-body" id="sessionsBody">
            <!-- Populated by JS -->
        </div>
    </div>
</div>

<!-- Veri, çalıştırılabilir script'ten AYRI tutulur. Böylece dev bir JSON içeriği
     asla fonksiyon tanımlarını bozamaz → search/filter/modal her zaman çalışır. -->
<script type="application/json" id="ws-findings-data">{ findings_json }</script>
<script type="application/json" id="ws-sessions-data">{ sessions_json }</script>

<script>
    // -----------------------------------------------------------------------
    // Data — application/json bloklarından güvenle parse edilir.
    // -----------------------------------------------------------------------
    var data = [];
    var sessions = [];
    try {{
        var _dEl = document.getElementById('ws-findings-data');
        data = JSON.parse((_dEl && _dEl.textContent) || '[]');
    }} catch(e) {{
        console.error('[WebSecure] Failed to parse findings data ({_data_size_kb} KB):', e);
        // Show a visible error so the user knows why the table is empty
        (function() {{
            var tb = document.getElementById('tableBody');
            if (tb) {{
                tb.innerHTML = '<tr><td colspan="6" style="color:var(--sev-critical);padding:1.5rem;text-align:center;">'
                    + '&#9888; Bulgu verisi okunamadı ({_data_size_kb} KB). '
                    + 'Tarayıcı konsolunu (F12 &rarr; Console) kontrol edin.</td></tr>';
            }}
        }})();
    }}
    try {{
        var _sEl = document.getElementById('ws-sessions-data');
        sessions = JSON.parse((_sEl && _sEl.textContent) || '[]');
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
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:2rem;">Bu filtreyle eşleşen bulgu yok.</td></tr>';
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
                    '<td><span class="tag Info">Açık</span></td>';
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

            // Canlı sayaç güncelle
            var fc = document.getElementById('findingCount');
            if (fc) fc.textContent = filtered.length;

            // Highlight active severity stat card
            var sevColors = {{
                'Critical': 'var(--sev-critical)',
                'High':     'var(--sev-high)',
                'Medium':   'var(--sev-medium)',
                'Low':      'var(--sev-low)',
                'Info':     'var(--sev-info)',
                '':         'var(--border)'
            }};
            ['Critical','High','Medium','Low','Info','All'].forEach(function(s) {{
                var card = document.getElementById('card-' + (s === 'All' ? 'All' : s));
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

    // Öncelikli Düzeltme Matrisi — satır aç/kapa
    function toggleRemRow(rank) {{
        try {{
            var det = document.getElementById('rem-detail-' + rank);
            var car = document.getElementById('rem-caret-' + rank);
            if (!det) return;
            var open = det.style.display !== 'none' && det.style.display !== '';
            det.style.display = open ? 'none' : 'table-row';
            if (car) car.style.transform = open ? 'rotate(0deg)' : 'rotate(90deg)';
        }} catch(e) {{ console.error('[WebSecure] toggleRemRow error:', e); }}
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

        const d = item.detail || {{}};
        const modal = document.getElementById('detailModal');
        document.getElementById('modalTitle').innerText = item.type;

        // --- 1. Temel bilgiler ---
        const verified = d.verified || d.confirmed;
        const confidence = d.confidence || d.score;
        const tool = d.tool || d.scanner || d.source;
        const verBadge = verified
            ? `<span style="background:rgba(63,185,80,0.15); border:1px solid var(--sev-low); color:var(--sev-low); border-radius:4px; padding:2px 8px; font-size:0.8rem; font-weight:600;">✓ Doğrulandı</span>`
            : `<span style="background:rgba(139,148,158,0.1); border:1px solid var(--text-muted); color:var(--text-muted); border-radius:4px; padding:2px 8px; font-size:0.8rem;">Doğrulanmadı</span>`;

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
                <div class="label">Hedef URL</div> <div><a href="${{escapeHtml(cleanUrl)}}" target="_blank" style="color:var(--accent)">${{escapeHtml(cleanUrl)}}</a></div>
                ${{testUrlHtml}}
                <div class="label">Method</div> <div><code>${{escapeHtml(item.method)}}</code></div>
                <div class="label">Severity</div> <div><span class="tag ${{item.severity}}">${{item.severity}}</span> ${{verBadge}}</div>
                ${{d.location ? `<div class="label">Konum</div> <div>${{escapeHtml(d.location)}}</div>` : ''}}
                ${{paramVal0 ? `<div class="label">Parametre</div> <div><code style="color:var(--sev-high)">${{escapeHtml(paramVal0)}}</code></div>` : ''}}
                ${{confidence ? `<div class="label">Güven</div> <div>${{escapeHtml(String(confidence))}}</div>` : ''}}
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
            html += `<div style="font-weight:600; color:var(--accent); margin-bottom:8px;">⚡ Saldırı Tekniği</div>`;
            html += `<div class="kv-grid" style="margin:0;">`;
            if(technique)   html += `<div class="label">Teknik</div><div><code style="color:var(--sev-high)">${{escapeHtml(technique)}}</code></div>`;
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
            html += `<div style="margin:12px 0;"><div style="font-weight:600; margin-bottom:4px;">📋 Açıklama</div><p style="color:var(--text-muted); margin:0;">${{escapeHtml(reasonVal)}}</p></div>`;
        }}

        // --- 5. HTTP İstek / Yanıt ---
        const reqVal  = d.request  || d.raw_request  || (typeof d.evidence === 'object' && d.evidence && d.evidence.request);
        const respVal = d.response || d.raw_response || (typeof d.evidence === 'object' && d.evidence && d.evidence.raw_response);
        if (reqVal || respVal) {{
            html += `<div style="margin:12px 0;">`;
            html += `<div style="font-weight:600; margin-bottom:8px;">🌐 HTTP Trafiği</div>`;
            if (reqVal) {{
                let rq = typeof reqVal === 'object' ? JSON.stringify(reqVal, null, 2) : String(reqVal);
                if (rq.length > 3000) rq = rq.substring(0, 3000) + "\\n... [kısaltıldı]";
                html += `<details style="margin-bottom:6px;"><summary style="cursor:pointer; color:var(--accent); font-size:0.88rem;">▶ İstek (Request)</summary><pre style="font-size:0.8rem; max-height:250px; overflow:auto; margin-top:4px;">${{escapeHtml(rq)}}</pre></details>`;
            }}
            if (respVal) {{
                let rs = typeof respVal === 'object' ? JSON.stringify(respVal, null, 2) : String(respVal);
                if (rs.length > 3000) rs = rs.substring(0, 3000) + "\\n... [kısaltıldı]";
                html += `<details><summary style="cursor:pointer; color:var(--accent); font-size:0.88rem;">▶ Yanıt (Response)</summary><pre style="font-size:0.8rem; max-height:250px; overflow:auto; margin-top:4px;">${{escapeHtml(rs)}}</pre></details>`;
            }}
            html += `</div>`;
        }}

        // --- 6. Evidence Forensics (object tipinde) ---
        const ev = (typeof d.evidence === 'object' && d.evidence && !Array.isArray(d.evidence)) ? d.evidence : {{}};
        const hasEvidence = Object.keys(ev).length > 0;
        if (hasEvidence) {{
            html += `<div style="margin-top:16px; border:1px solid var(--accent); border-radius:6px; overflow:hidden;">`;
            html += `<div style="background:var(--accent); color:#000; padding:8px 12px; font-weight:bold; font-size:0.9rem;">🔎 Kanıt Kasası</div>`;
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
            html += `<details style="margin-top:12px;"><summary style="cursor:pointer; color:var(--text-muted); font-size:0.85rem;">▶ Tüm Ham Alanlar (${{extraKeys.length}})</summary>`;
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
        // Önce modalı aç — render sırasında bir hata olsa bile pencere açılır.
        if (modal) modal.style.display = 'block';
        if (!body) return;

        try {{
            if (!sessions || sessions.length === 0) {{
                body.innerHTML = `
                  <div style="text-align:center; padding:2rem; color:var(--text-muted);">
                    <div style="font-size:2rem;">🔒</div>
                    <p>Yakalanmış oturum yok.</p>
                    <p style="font-size:0.85rem;">XSS DOM doğrulaması, credential recovery veya kimlik doğrulamalı tarama ile oturum/cookie verisi yakalanabilir.</p>
                  </div>`;
                return;
            }}

            // Oturum türü: XSS/credential ile kurban oturumu mu, yoksa tarama oturumu mu?
            const anyVictim = sessions.some(s => (s.source && /xss|credential/i.test(String(s.source))) || s.verified || s.xss_url);
            let html = anyVictim
                ? `<p style="color:var(--sev-critical); font-weight:bold; margin:0 0 1rem;">⚠️ ${{sessions.length}} oturum yakalandı — bunlar hedef kullanıcılara ait olabilir.</p>`
                : `<p style="color:var(--text-muted); margin:0 0 1rem;">ℹ️ Tarama sırasında elde edilen ${{sessions.length}} oturum/cookie kaydı. Aşağıdaki cookie'ler hedefe karşı oturum tekrarı (replay) için kullanılabilir.</p>`;

            sessions.forEach((s, idx) => {{
                s = s || {{}};
                const cookieObj  = (s.cookies && typeof s.cookies === 'object') ? s.cookies : {{}};
                const lsObj      = (s.local_storage && typeof s.local_storage === 'object') ? s.local_storage : {{}};
                const hdrObj     = (s.headers && typeof s.headers === 'object') ? s.headers : {{}};
                const drvList    = Array.isArray(s.driver_cookies) ? s.driver_cookies : [];
                const verified   = !!(s.verified || s.ato_verified);
                const authed     = !!s.authenticated;
                const source     = s.source || (authed ? 'auth_session' : 'scan_session');
                const userLbl    = s.user && s.user !== 'unknown' ? s.user : '';
                var _srcMap = {{
                    'xss_reflected':'🎯 XSS Reflected','xss_dom':'🎯 XSS DOM',
                    'xss_blind':'👁️ XSS Blind (OAST)','credential':'🔑 Credential Recovery',
                    'auth_session':'🔓 Kimlik Doğrulamalı Oturum','scan_session':'🧭 Tarama Oturumu'
                }};
                const sourceLabel = _srcMap[source] || source;

                // Replay/hijack script — DevTools konsoluna yapıştır
                const hijackScript = [
                    `// ═══ WebSecure Session Replay ═══`,
                    `// Kaynak: ${{source}} | Zaman: ${{s.timestamp || s.ts || ''}}`,
                    `(function() {{`,
                    `  var c = ${{JSON.stringify(cookieObj)}};`,
                    `  for (var k in c) document.cookie = k+'='+c[k]+'; path=/; SameSite=Lax';`,
                    `  var ls = ${{JSON.stringify(lsObj)}};`,
                    `  for (var k in ls) localStorage.setItem(k, ls[k]);`,
                    `  console.log('%c[WebSecure] Session injected!', 'color:lime;font-size:14px;font-weight:bold');`,
                    `  setTimeout(() => location.reload(), 800);`,
                    `}})();`,
                ].join('\\n');
                const curlCookies = Object.entries(cookieObj).map(([k,v]) => `${{k}}=${{String(v)}}`).join('; ');
                const curlCmd = `curl -s -b '${{curlCookies}}' '${{s.verification_url || s.origin_url || ''}}' -I`;
                const hijackAttr = escapeHtml(hijackScript).replace(/"/g, '&quot;');
                const curlAttr   = escapeHtml(curlCmd).replace(/"/g, '&quot;');

                html += `
                <div style="background:var(--bg-body); border:1px solid ${{verified ? 'var(--sev-critical)' : 'var(--border)'}}; border-radius:8px; padding:1rem; margin-bottom:1rem;">
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
                    <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                      <span style="font-size:1.1rem; font-weight:700; color:var(--accent);">#${{idx+1}}</span>
                      <span style="font-size:0.85rem; color:var(--accent);">${{sourceLabel}}</span>
                      <span class="tag ${{authed ? 'Low' : 'Info'}}" style="font-size:0.75rem;">${{authed ? '🔓 authenticated' : 'anonim'}}</span>
                      ${{verified ? `<span class="tag Critical" style="font-size:0.75rem;">✅ Doğrulandı${{s.verification_status ? ' (HTTP ' + escapeHtml(String(s.verification_status)) + ')' : ''}}</span>` : ''}}
                    </div>
                    <div style="display:flex; gap:6px; flex-wrap:wrap;">
                      <button class="btn" style="font-size:0.78rem; padding:3px 8px; background:rgba(248,81,73,0.15); border-color:var(--sev-high);"
                        onclick="navigator.clipboard.writeText(this.dataset.cmd).then(()=>{{this.textContent='✅ Kopyalandı!';setTimeout(()=>this.textContent='💉 JS Replay',1500)}})"
                        data-cmd="${{hijackAttr}}">💉 JS Replay</button>
                      <button class="btn" style="font-size:0.78rem; padding:3px 8px;"
                        onclick="navigator.clipboard.writeText(this.dataset.cmd).then(()=>{{this.textContent='✅ Kopyalandı!';setTimeout(()=>this.textContent='🖥️ cURL',1500)}})"
                        data-cmd="${{curlAttr}}">🖥️ cURL</button>
                    </div>
                  </div>

                  <div style="display:grid; grid-template-columns:130px 1fr; gap:4px 12px; font-size:0.83rem; margin-bottom:10px;">
                    <span style="color:var(--text-muted);">Zaman</span><span>${{escapeHtml(s.timestamp || s.ts || '-')}}</span>
                    ${{userLbl ? `<span style="color:var(--text-muted);">Kullanıcı</span><span><code style="color:var(--sev-high);">${{escapeHtml(userLbl)}}</code></span>` : ''}}
                    ${{s.xss_url ? `<span style="color:var(--text-muted);">XSS URL</span><span style="font-family:monospace; font-size:0.78rem; word-break:break-all;">${{escapeHtml(s.xss_url)}}</span>` : ''}}
                    ${{s.origin_url ? `<span style="color:var(--text-muted);">Origin</span><span style="font-size:0.78rem; word-break:break-all;">${{escapeHtml(s.origin_url)}}</span>` : ''}}
                  </div>

                  <details open>
                    <summary style="cursor:pointer; color:var(--accent); font-weight:600; font-size:0.85rem; margin-bottom:6px;">
                      🍪 Cookies (${{Object.keys(cookieObj).length}})
                    </summary>
                    ${{Object.keys(cookieObj).length ? `<div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:6px;">
                      ${{Object.entries(cookieObj).map(([k,v]) => {{
                        var vs = String(v == null ? '' : v);
                        return `<div style="background:rgba(0,0,0,0.3); border:1px solid var(--border); border-radius:4px; padding:4px 8px; font-size:0.78rem;">
                          <span style="color:var(--sev-medium); font-weight:600;">${{escapeHtml(k)}}</span>
                          <span style="color:var(--text-muted);">=</span>
                          <span style="color:var(--text-main); font-family:monospace; word-break:break-all;">${{escapeHtml(vs.length>72?vs.substring(0,72)+'…':vs)}}</span>
                        </div>`;
                      }}).join('')}}
                    </div>` : `<p style="color:var(--text-muted); font-size:0.8rem;">Cookie yok.</p>`}}
                  </details>

                  ${{Object.keys(hdrObj).length ? `
                  <details style="margin-top:6px;">
                    <summary style="cursor:pointer; color:var(--accent); font-weight:600; font-size:0.85rem;">📑 Header'lar (${{Object.keys(hdrObj).length}})</summary>
                    <pre style="font-size:0.76rem; max-height:140px; overflow:auto;">${{escapeHtml(JSON.stringify(hdrObj, null, 2))}}</pre>
                  </details>` : ''}}

                  ${{drvList.length ? `
                  <details style="margin-top:6px;">
                    <summary style="cursor:pointer; color:var(--accent); font-weight:600; font-size:0.85rem;">🌐 Driver Cookies (${{drvList.length}})</summary>
                    <pre style="font-size:0.76rem; max-height:140px; overflow:auto;">${{escapeHtml(JSON.stringify(drvList, null, 2))}}</pre>
                  </details>` : ''}}

                  ${{Object.keys(lsObj).length ? `
                  <details style="margin-top:6px;">
                    <summary style="cursor:pointer; color:var(--accent); font-weight:600; font-size:0.85rem;">💾 localStorage (${{Object.keys(lsObj).length}} key)</summary>
                    <pre style="font-size:0.78rem; max-height:120px; overflow:auto;">${{escapeHtml(JSON.stringify(lsObj, null, 2))}}</pre>
                  </details>` : ''}}
                </div>`;
            }});
            body.innerHTML = html;
        }} catch(e) {{
            console.error('[WebSecure] showSessions error:', e);
            body.innerHTML = '<p style="color:var(--sev-high); padding:1rem;">Oturumlar gösterilirken hata oluştu. Konsolu (F12) kontrol edin.</p>';
        }}
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
