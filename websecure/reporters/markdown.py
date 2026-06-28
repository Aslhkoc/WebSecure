from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from websecure.reporters import normalize_severity, severity_rank

# Logger
logger = logging.getLogger(__name__)

# --- Helper Functions (Copied from core/reporting) ---

def _short_poc(s: str) -> str:
    s = (s or "").strip()
    return (s[:4000] + " …") if len(s) > 4000 else s

_SEV_ICON: dict = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
    "Info":     "ℹ️",
    "Informational": "ℹ️",
}


# Severity normalize/rank tek kaynak: websecure.reporters (normalize_severity/severity_rank).
# _norm_sev_tr/_norm_sev_en eskiden ayrı ama ~aynı TR/EN normalizasyonuydu → tek kanona indi.
def _norm_sev_tr(s: str | None) -> str:
    return normalize_severity(s)


def _norm_sev_en(s: str | None) -> str:
    return normalize_severity(s)


def _sev_with_icon(s: str | None) -> str:
    """Return 'Critical 🔴' style label."""
    norm = normalize_severity(s)
    icon = _SEV_ICON.get(norm, "")
    return f"{norm} {icon}".strip()

def _sev_rank(s: str | None) -> int:
    # Tek kaynak: severity_rank (normalize-ederek-sıralar). Eski yerel kopya büyük-harf
    # etiketi küçük-harf haritada arayıp DAİMA 0 döndüren bir hata içeriyordu (dedup
    # severity escalation + severity sıralaması fiilen çalışmıyordu) — düzeltildi.
    return severity_rank(s)

def _dedupe_findings(items: List[Dict]) -> List[Dict]:
    """Deduplicates findings based on type, url, location, param."""
    bykey: Dict[tuple, Dict] = {}
    for it in (items or []):
        if not isinstance(it, dict):
            continue
        key = (it.get("type"), it.get("url"), it.get("location"), it.get("param"))
        cur = bykey.get(key)
        if cur is None:
            bykey[key] = dict(it)
            continue

        s_old = _sev_rank(cur.get("severity"))
        s_new = _sev_rank(it.get("severity"))
        if s_new > s_old:
            cur["severity"] = it.get("severity")

        cur_score = cur.get("score") or 0
        it_score = it.get("score") or 0
        if it_score > cur_score:
            cur["score"] = it_score

        if len(str(it.get("reason", ""))) > len(str(cur.get("reason", ""))):
            cur["reason"] = it.get("reason")
        
        # Merge lists
        for f in ("payloads", "similar_params"):
            if it.get(f):
                cur.setdefault(f, [])
                cur[f] = list(dict.fromkeys((cur.get(f) or []) + (it.get(f) or [])))

        _ev = it.get("evidence")
        if isinstance(_ev, dict) and _ev:
            cur.setdefault("evidence", {}).update(_ev)

        cur_poc_short = _short_poc(cur.get("poc") or "")
        it_poc_short = _short_poc(it.get("poc") or "")
        if len(str(it_poc_short)) > len(str(cur_poc_short)):
            cur["poc"] = it.get("poc")

    return list(bykey.values())


def _coerce_final(results: Dict) -> List[Dict]:
    fin = results.get("final")
    if isinstance(fin, list):
        return fin
    merged: List[Dict] = []
    for key, val in list(results.items()):
        if key.endswith("_summary"): continue
        if isinstance(val, list) and all(isinstance(x, dict) for x in val):
            for _it in val:
                it2 = dict(_it)
                if 'module' not in it2 and isinstance(key, str): it2['module'] = key
                merged.append(it2)
    return merged

def _render_ports_section(results: Dict) -> str:
    """Açık portları tam detayla render eder — Host | Port | Proto | Servis | Ürün/Versiyon | NSE | CPE"""
    cand_keys = ["nmap", "port_scan", "ports", "nmap_summary", "services"]
    rows = []

    def _as_int(val):
        s = str(val).strip()
        return int(s) if re.fullmatch(r"[+-]?\d+", s) else val

    def _script_highlights(scripts: dict) -> str:
        if not isinstance(scripts, dict):
            return ""
        parts = []
        for key in ("http-title", "banner", "ssl-cert", "http-server-header",
                    "ssh-hostkey", "ftp-anon", "ssl-heartbleed", "ssl-poodle"):
            val = scripts.get(key, "")
            if val:
                first = val.strip().split("\n")[0].strip()[:120]
                parts.append(f"{key}: {first}")
        for k, v in scripts.items():
            if v and any(w in v.lower() for w in ("vuln", "vulnerable", "cve-")):
                parts.append(f"[!] {k}: {v.strip().split(chr(10))[0][:120]}")
        return " // ".join(parts)

    for k in cand_keys:
        v = results.get(k)
        if not isinstance(v, list):
            continue
        for it in v:
            if not isinstance(it, dict):
                continue
            port = it.get("port") or it.get("dst_port")
            if port is None:
                continue
            product = str(it.get("product") or "")
            version = str(it.get("version") or "")
            pv = (product + " " + version).strip()
            cpe = it.get("cpe") or []
            rows.append({
                "host":    str(it.get("host") or it.get("ip") or ""),
                "port":    _as_int(port),
                "proto":   (str(it.get("proto") or it.get("protocol") or "tcp")).lower(),
                "service": str(it.get("service") or ""),
                "pv":      pv,
                "scripts": _script_highlights(it.get("scripts") or {}),
                "cpe":     ", ".join(cpe[:2]) if isinstance(cpe, list) else "",
                "os":      str(it.get("os_guess") or ""),
            })

    if not rows:
        return ""

    seen = {}
    for r in rows:
        key = (r["host"], r["port"], r["proto"])
        if key not in seen:
            seen[key] = r

    sorted_rows = sorted(seen.values(),
                         key=lambda r: (r["host"], r["port"] if isinstance(r["port"], int) else 99999))

    os_info = next((r["os"] for r in sorted_rows if r["os"]), "")
    out = ["## Açık Portlar", ""]
    if os_info:
        out.append(f"> **OS Tahmini:** {os_info}\n")
    out.append("| Host | Port | Proto | Servis | Ürün / Versiyon | NSE Script Çıktıları | CPE |")
    out.append("|-|-:|-|-|-|-|-|")
    for r in sorted_rows[:500]:
        out.append(
            f"| {r['host']} | **{r['port']}** | {r['proto']} "
            f"| {r['service']} | {r['pv']} | {r['scripts']} | {r['cpe']} |"
        )
    return "\n".join(out)


def _render_ssl_section(results: Dict) -> str:
    _tls_raw = results.get("tls") or results.get("ssl") or {}
    if isinstance(_tls_raw, list):
        tls = next((x for x in _tls_raw if isinstance(x, dict) and "certificate" in x), {})
    else:
        tls = _tls_raw if isinstance(_tls_raw, dict) else {}
    cert = tls.get("certificate") or {}
    if not cert: return ""
    
    out = ["## SSL/TLS Yapılandırma", "", "| Özellik | Değer |", "|-|-|"]
    out.append(f"| Geçerlilik | {'[OK] Geçerli' if cert.get('valid') else '[X] Geçersiz'} |")
    out.append(f"| Subject | `{cert.get('subject_CN') or '-'}` |")
    out.append(f"| Issuer | `{cert.get('issuer_CN') or '-'}` |")
    return "\n".join(out)

def render_risk_matrix(findings: List[Dict]) -> str:
    """Render a markdown remediation priority matrix from a list of finding dicts."""
    if not findings:
        return ""

    _REMEDIATION_DB = {
        "sql injection": ("Parameterized queries / prepared statements", "Low"),
        "sqli": ("Parameterized queries / prepared statements", "Low"),
        "ssti": ("Disable user-controlled template evaluation; use static templates", "Medium"),
        "template injection": ("Disable user-controlled template evaluation; use static templates", "Medium"),
        "command injection": ("Avoid shell calls; use subprocess list args", "Low"),
        "cmdi": ("Avoid shell calls; use subprocess list args", "Low"),
        "xss": ("Output-encode user data; enforce strict CSP header", "Medium"),
        "ssrf": ("Allowlist outbound destinations; block internal metadata endpoints", "Medium"),
        "xxe": ("Disable external entity processing in XML parser", "Low"),
        "jwt": ("Use RS256/ES256; validate aud/iss/exp claims", "Medium"),
        "idor": ("Enforce server-side authorization on every resource", "Medium"),
        "csrf": ("SameSite=Strict cookies + CSRF tokens on state-changing requests", "Low"),
        "open redirect": ("Allowlist redirect destinations", "Low"),
        "security header": ("Set HSTS, X-Content-Type-Options, X-Frame-Options, CSP", "Low"),
        "prototype pollution": ("Freeze Object.prototype; null-prototype objects for merges", "Medium"),
        "file upload": ("Validate MIME server-side; store outside web root; rename files", "Medium"),
        "mass assignment": ("Explicit field allow-lists; reject unexpected params", "Low"),
        "nosql": ("Use typed query builders; never interpolate input into queries", "Low"),
        "request smuggling": ("Normalize HTTP/1.1 headers; prefer HTTP/2 end-to-end", "High"),
        "tls": ("Upgrade to TLS 1.2+; disable weak protocols; renew certificates", "Low"),
    }

    type_map: Dict[str, dict] = {}
    for f in findings:
        t = str(f.get("type") or "Unknown")
        entry = type_map.setdefault(t, {"count": 0, "max_sev": 0, "sev_label": "Info", "advice": "", "effort": "Medium"})
        entry["count"] += 1
        sev_rank = severity_rank(f.get("severity"))  # tek kaynak (normalize+rank)
        if sev_rank > entry["max_sev"]:
            entry["max_sev"] = sev_rank
            entry["sev_label"] = normalize_severity(f.get("severity"))
        if not entry["advice"]:
            tl = t.lower()
            for kw, (adv, eff) in _REMEDIATION_DB.items():
                if kw in tl:
                    entry["advice"] = adv
                    entry["effort"] = eff
                    break
            if not entry["advice"]:
                entry["advice"] = "Review and remediate per OWASP guidance"

    rows = sorted(type_map.items(), key=lambda x: (-x[1]["max_sev"], -x[1]["count"]))

    lines = ["", "## Remediation Priority Matrix", "",
             "| # | Vulnerability Type | Max Severity | Count | Recommended Fix | Fix Effort |",
             "|:-:|---|:-:|:-:|---|:-:|"]
    for i, (vtype, info) in enumerate(rows[:20], 1):
        lines.append(
            f"| {i} | {_esc_md(vtype)} | {_esc_md(info['sev_label'])} | {info['count']} | {_esc_md(info['advice'])} | {_esc_md(info['effort'])} |"
        )
    return "\n".join(lines)

def _esc_md(s: str) -> str:
    """Escape pipe/backtick/asterisk characters that break Markdown tables."""
    return (str(s) or "").replace("|", "\\|").replace("`", "\\`").replace("*", "\\*")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

# --- Main Render Function ---

def render(results: Dict) -> str:
    """
    Renders the comprehensive Markdown report.
    Replaces logic previously in core/reporting.py
    """
    # Prep — SAYIM BİRLİĞİ: summary.json / report.html / SARIF / JUnit ile AYNI kanonik
    # bulgu kümesi. Eskiden yerel _coerce_final+_dedupe_findings kullanıp
    # _is_countable_finding filtresini ATLIYORDU → markdown raporu recon-çöpünü
    # (nmap port / discovery / subdomain / passive) sayıp diğer formatlarla çelişiyordu.
    try:
        from websecure.core.reporting import _canonical_report_findings as _canon
        items = list(_canon(results))
    except Exception:  # reporting import edilemezse eski davranışa düş (defansif)
        items = _dedupe_findings(_coerce_final(results))
    items.sort(key=lambda i: (-_sev_rank(i.get("severity")), -(i.get("score") or 0), str(i.get("type") or ""), str(i.get("url") or "")))

    meta = (results.get("meta") if isinstance(results, dict) else {})
    if isinstance(meta, list): meta = next((x for x in meta if isinstance(x, dict)), {})
    target = (meta.get("target") if isinstance(meta, dict) else "") or ""
    when = _now_iso()

    # Counts
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for i in items:
        counts[_norm_sev_tr(i.get("severity"))] = counts.get(_norm_sev_tr(i.get("severity")), 0) + 1

    lines = []
    lines.append("# WebSec Report")
    lines.append("")
    if target:
        lines.append(f"**Target:** `{_esc_md(target)}`  •  **Date:** `{when}`")
    lines.append("")

    # Summary Table
    lines.append("## Summary")
    lines.append("| Severity | Count |")
    lines.append("|-|-:|")
    for k in ("Critical", "High", "Medium", "Low", "Info"):
        icon = _SEV_ICON.get(k, "")
        lines.append(f"| {icon} {k} | {counts[k]} |")

    # Remediation Priority Matrix
    risk_matrix = render_risk_matrix(items)
    if risk_matrix:
        lines.append(risk_matrix)

    # Findings List
    lines.append("")
    lines.append("## Findings")
    lines.append("| # | Severity | Type | Target URL | Parameter | Confidence |")
    lines.append("|:-:|:-:|---|---|---|:-:|")
    for idx, i in enumerate(items, 1):
        sev = _sev_with_icon(i.get("severity"))
        vtype = _esc_md(i.get("type") or "Finding")
        # Show original (clean) target URL — strip injected payload if present
        url = _esc_md(i.get("url") or "")
        param = _esc_md(i.get("param") or i.get("parameter") or "")
        conf = _esc_md(i.get("confidence") or "—")
        lines.append(f"| {idx} | {sev} | {vtype} | {url} | {param} | {conf} |")

    # Details
    lines.append("")
    lines.append("## Details")
    for idx, it in enumerate(items, 1):
        lines.append("")
        t = it.get("type") or "GEN"
        sev = _sev_with_icon(it.get("severity"))
        lines.append(f"### {idx}. {t}")
        lines.append("")

        # Severity + confidence on one line
        conf = it.get("confidence") or "—"
        verified = it.get("verified") or it.get("oast_verified") or False
        verified_mark = " ✅ Doğrulandı" if verified else " ⚠️ Doğrulanmadı"
        lines.append(f"- **Severity**: {sev}  |  **Confidence**: `{conf}`{verified_mark}")

        # Target URL — original clean URL
        target_url = it.get("url") or ""
        lines.append(f"- **Target URL**: `{target_url}`")

        # Test URL — only show if payload was injected and URL changed
        payload = it.get("payload") or ""
        param = it.get("param") or it.get("parameter") or ""
        if payload and param and target_url:
            try:
                _p = urlparse(target_url)
                _params = dict(parse_qsl(_p.query))
                _params[param] = payload
                test_url = urlunparse(_p._replace(query=urlencode(_params)))
                if test_url != target_url:
                    lines.append(f"- **Test URL** *(payload enjekte edildi)*: `{test_url[:300]}`")
            except Exception as _fix_e:
                logger.debug(f"[reporters.markdown] {type(_fix_e).__name__}: {_fix_e!r}")

        lines.append(f"- **Parameter**: `{param}`")
        if payload:
            short_payload = payload[:200] + ("…" if len(payload) > 200 else "")
            lines.append(f"- **Payload**: `{short_payload}`")

        # Detection method + CVSS
        dm = it.get("detection_method") or it.get("method") or ""
        if dm:
            lines.append(f"- **Detection Method**: `{dm}`")
        cvss = it.get("cvss_score")
        if cvss:
            lines.append(f"- **CVSS Score**: `{cvss}`")

        if it.get("payloads"):
            lines.append(f"- **Payload Count**: `{len(it.get('payloads'))} adet`")

        # Remediation hint
        remediation = it.get("remediation") or ""
        if remediation:
            lines.append(f"- **Remediation**: {remediation}")

        # Evidence
        ev = it.get("evidence")
        if isinstance(ev, dict) and ev:
            lines.append("")
            lines.append("<details><summary>📋 Kanıtlar (Forensics)</summary>")
            lines.append("")
            lines.append("```json")
            ev_str = json.dumps(ev, indent=2, ensure_ascii=False)
            lines.append(ev_str[:2000] + ("…" if len(ev_str) > 2000 else ""))
            lines.append("```")
            lines.append("</details>")
        elif isinstance(ev, str) and ev:
            lines.append(f"- **Evidence**: {ev[:500]}")

    # Ports
    lines.append("")
    lines.append(_render_ports_section(results))
    
    # SSL
    lines.append("")
    lines.append(_render_ssl_section(results))

    return "\n".join(lines)
