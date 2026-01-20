
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
    s = (s or "Bilgi").strip().lower()
    if s in ("kritik", "critical", "crit"): return "🔴 KRİTİK"
    if s in ("yüksek", "high", "severe"): return "🟠 YÜKSEK"
    if s in ("orta", "medium", "med"): return "🟡 ORTA"
    if s in ("düşük", "low"): return "🔵 DÜŞÜK"
    return "⚪ BİLGİ"

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
    except Exception:
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
    # Logic extracted from original code
    cand_keys = ["ports", "port_scan", "nmap", "nmap_summary", "services", "open_ports"]
    rows = []
    
    def _as_int(val):
        s = str(val).strip()
        return int(s) if re.fullmatch(r"[+-]?\d+", s) else val

    for k in cand_keys:
        v = results.get(k)
        if isinstance(v, list):
            for it in v:
                if not isinstance(it, dict): continue
                host = str(it.get("host") or it.get("ip") or it.get("address") or "")
                port = it.get("port") or it.get("dst_port") or it.get("service_port")
                if port is None: continue
                # Simple normalization
                rows.append({"host": host, "port": _as_int(port), "proto": str(it.get("proto") or "tcp"), 
                             "state": str(it.get("state") or "open"), "service": str(it.get("service") or "")})
        # Note: Additional dict key parsing omitted for brevity/focus on stability, 
        # normally nmap module output is a list of dicts.

    if not rows: return ""
    
    # Dedupe
    u_ports = {}
    for r in rows: u_ports[(r["host"], r["port"])] = r
    
    out = ["## Taranan/Açık Portlar", "", "| Host | Port | Protokol | Servis |", "|-|-|-|-|"]
    for (h, p), r in sorted(u_ports.items(), key=lambda x: (x[0][0], x[0][1] if isinstance(x[0][1], int) else 99999)):
         out.append(f"| {h} | {p} | {r.get('proto')} | {r.get('service')} |")
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
    # Placeholder for matrix logic
    return ""

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
    counts = {"Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Bilgi": 0}
    for i in items:
        counts[_norm_sev_tr(i.get("severity"))] = counts.get(_norm_sev_tr(i.get("severity")), 0) + 1

    lines = []
    lines.append("# WebSec Raporu")
    lines.append("")
    if target: 
        lines.append(f"**Hedef:** `{esc_md(target)}`  •  **Tarih:** `{when}`")
    lines.append("")
    
    # Summary Table
    lines.append("## Genel Özet")
    lines.append("| Seviye | Adet |")
    lines.append("|-|-:|")
    for k in ("Kritik", "Yüksek", "Orta", "Düşük", "Bilgi"):
        lines.append(f"| {k} | {counts[k]} |")
    
    # Findings List
    lines.append("")
    lines.append("## Bulgular Listesi")
    lines.append("| Seviye | Tür | URL | Param |")
    lines.append("|-|-|-|-|")
    for i in items:
        lines.append(f"| {_norm_sev_tr(i.get('severity'))} | {esc_md(i.get('type') or 'Bulgu')} | {esc_md(i.get('url') or '')} | {esc_md(i.get('param') or '')} |")

    # Details
    lines.append("")
    lines.append("## Detaylar")
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
