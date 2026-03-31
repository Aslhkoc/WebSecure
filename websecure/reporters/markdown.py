from __future__ import annotations

import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Any

# Logger
logger = logging.getLogger(__name__)

# --- Helper Functions (Copied from core/reporting) ---

def _short_poc(s: str) -> str:
    s = (s or "").strip()
    return (s[:4000] + " …") if len(s) > 4000 else s

def _norm_sev_tr(s: str | None) -> str:
    """Normalize severity to English canonical."""
    s = (s or "Info").strip().lower()
    if s in ("kritik", "critical", "crit"): return "Critical"
    if s in ("yüksek", "high", "severe"): return "High"
    if s in ("orta", "medium", "med"): return "Medium"
    if s in ("düşük", "low"): return "Low"
    return "Info"

def _norm_sev_en(s: str | None) -> str:
    s = (s or "Info").strip().lower()
    if s in ("kritik", "critical", "crit"): return "Critical"
    if s in ("yüksek", "high", "severe"): return "High"
    if s in ("orta", "medium", "med"): return "Medium"
    if s in ("düşük", "low"): return "Low"
    return "Info"

def _sev_rank(s: str | None) -> int:
    """Rank via EN normalization: critical=4 > high=3 > medium=2 > low=1 > info=0."""
    m = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    try:
        return m.get(_norm_sev_en(s or ""), 0)
    except Exception as exc:
        return 0

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

        if it.get("evidence"):
            cur.setdefault("evidence", {}).update(it.get("evidence") or {})

        cur_poc_short = _short_poc(cur.get("poc") or "")
        it_poc_short = _short_poc(it.get("poc") or "")
        if len(str(it_poc_short)) > len(str(cur_poc_short)):
            cur["poc"] = it.get("poc")

    return list(bykey.values())


def _collect_http_proofs(results: Dict) -> Dict[str, Any]:
    # Placeholder for logic if needed, currently mostly unused in basic MD report
    # but kept for compatibility
    return {}

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
                parts.append(f"⚠️ {k}: {v.strip().split(chr(10))[0][:120]}")
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
    tls = results.get("tls") or results.get("ssl") or {}
    cert = tls.get("certificate") or {}
    if not cert: return ""
    
    out = ["## SSL/TLS Yapılandırma", "", "| Özellik | Değer |", "|-|-|"]
    out.append(f"| Geçerlilik | {'✅ Geçerli' if cert.get('valid') else '❌ Geçersiz'} |")
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

    _SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    type_map: Dict[str, dict] = {}
    for f in findings:
        t = str(f.get("type") or "Unknown")
        entry = type_map.setdefault(t, {"count": 0, "max_sev": 0, "sev_label": "Info", "advice": "", "effort": "Medium"})
        entry["count"] += 1
        sev_rank = _SEV_ORDER.get(_norm_sev_en(f.get("severity")).lower(), 0)
        if sev_rank > entry["max_sev"]:
            entry["max_sev"] = sev_rank
            entry["sev_label"] = _norm_sev_en(f.get("severity"))
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
            f"| {i} | {vtype} | {info['sev_label']} | {info['count']} | {info['advice']} | {info['effort']} |"
        )
    return "\n".join(lines)

def _now_iso() -> str:
    return datetime.now().replace(microsecond=0).isoformat()

# --- Main Render Function ---

def render(results: Dict) -> str:
    """
    Renders the comprehensive Markdown report.
    Replaces logic previously in core/reporting.py
    """
    # Prep
    items_raw = _coerce_final(results)
    items = _dedupe_findings(items_raw)
    items.sort(key=lambda i: (-_sev_rank(i.get("severity")), -(i.get("score") or 0), str(i.get("type") or ""), str(i.get("url") or "")))

    meta = (results.get("meta") if isinstance(results, dict) else {})
    if isinstance(meta, list): meta = next((x for x in meta if isinstance(x, dict)), {})
    target = (meta.get("target") if isinstance(meta, dict) else "") or ""
    when = _now_iso()

    def esc_md(s: str) -> str:
        return (str(s) or "").replace("|", "\\|").replace("`", "\\`").replace("*", "\\*")

    # Counts
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for i in items:
        counts[_norm_sev_tr(i.get("severity"))] = counts.get(_norm_sev_tr(i.get("severity")), 0) + 1

    lines = []
    lines.append("# WebSec Report")
    lines.append("")
    if target:
        lines.append(f"**Target:** `{esc_md(target)}`  •  **Date:** `{when}`")
    lines.append("")

    # Summary Table
    lines.append("## Summary")
    lines.append("| Severity | Count |")
    lines.append("|-|-:|")
    for k in ("Critical", "High", "Medium", "Low", "Info"):
        lines.append(f"| {k} | {counts[k]} |")

    # Remediation Priority Matrix
    risk_matrix = render_risk_matrix(items)
    if risk_matrix:
        lines.append(risk_matrix)

    # Findings List
    lines.append("")
    lines.append("## Findings")
    lines.append("| Severity | Type | URL | Param |")
    lines.append("|-|-|-|-|")
    for i in items:
        lines.append(f"| {_norm_sev_tr(i.get('severity'))} | {esc_md(i.get('type') or 'Finding')} | {esc_md(i.get('url') or '')} | {esc_md(i.get('param') or '')} |")

    # Details
    lines.append("")
    lines.append("## Details")
    for idx, it in enumerate(items, 1):
        lines.append("")
        t = it.get('type') or 'GEN'
        lines.append(f"### {idx}. {t}")
        lines.append(f"- **URL**: `{it.get('url') or ''}`")
        lines.append(f"- **Severity**: {_norm_sev_tr(it.get('severity'))}")
        lines.append(f"- **Param**: `{it.get('param') or ''}`")
        if it.get("payloads"):
            lines.append(f"- **Payloads**: `{len(it.get('payloads'))} adet`")
            
        # Forensic
        ev = it.get("evidence")
        if isinstance(ev, dict):
             lines.append("\n<details><summary>Kanıtlar (Forensics)</summary>\n")
             lines.append("```json")
             lines.append(json.dumps(ev, indent=2, ensure_ascii=False)[:2000] + ("..." if len(str(ev))>2000 else ""))
             lines.append("```\n</details>")

    # Ports
    lines.append("")
    lines.append(_render_ports_section(results))
    
    # SSL
    lines.append("")
    lines.append(_render_ssl_section(results))

    return "\n".join(lines)
