
from __future__ import annotations
import os
import pathlib
import re
import json
import hashlib
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from pathlib import Path
from collections import defaultdict
from websecure.core.alerts import AlertManager

# ========================== CI Gate (inlined from ci_gate.py) ==========================
import logging as _ci_logging
_ci_logger = _ci_logging.getLogger(__name__)

def should_fail_ci(cfg: dict, results: dict) -> bool:
    """
    CI Quality Gate Logic.
    Determines if the scan should fail based on configuration and results.
    """
    ci_cfg = cfg.get("ci") or {}
    fail_on = ci_cfg.get("fail_on") or []
    if not fail_on:
        return False
    normalized_fail = [s.strip().lower() for s in fail_on if isinstance(s, str)]
    if not normalized_fail:
        return False
    counts: dict[str, int] = {}
    if "summary" in results and "counts" in results["summary"]:
        raw = results["summary"]["counts"]
        for k, v in (raw or {}).items():
            canonical = _norm_sev_tr(str(k)).lower()
            counts[canonical] = counts.get(canonical, 0) + int(v or 0)
    elif "findings" in results:
        _findings = results["findings"]
        _findings_iter = (
            _findings.items() if isinstance(_findings, dict)
            else enumerate(_findings) if isinstance(_findings, list)
            else []
        )
        for _cat, items in _findings_iter:
            if not isinstance(items, (list, tuple)):
                items = [items]
            for item in items:
                if not isinstance(item, dict):
                    continue
                canonical = _norm_sev_tr(item.get("severity")).lower()
                counts[canonical] = counts.get(canonical, 0) + 1

    for severity, count in counts.items():
        if count > 0:
            if "any" in normalized_fail:
                _ci_logger.error(f"CI Failure: {count} bulgu tespit edildi (kural: 'any')")
                return True
            if severity in normalized_fail:
                _ci_logger.error(
                    f"CI Failure: {count} bulgu — severity '{severity}' eşiği aşıldı"
                )
                return True
    return False

# --- Globals for async/callback reporting ---
_GLOBAL_LOCK = threading.Lock()
_GLOBAL_RESULTS: Dict[str, List[Any]] = defaultdict(list)

# add_result (full implementation) is defined below at line ~534 with normalization + redaction + alerts.
# _GLOBAL_RESULTS is kept in sync by that implementation.

def verify_and_score(findings: List[Dict], oast_events: List[Dict]) -> List[Dict]:
    """
    Verifies findings against OAST callbacks and applies CVSS scoring.
    Steps:
      1. FP filtreleme (Adım 20 — FPLearner)
      2. Deduplicate findings by (type, url, parameter)
      3. Correlate with OAST events — mark verified=True on token match
      4. Apply CVSS v3.1 scoring via cvss_scorer if available
      5. Sort by CVSS score descending (Critical -> Info)
    """
    # 0. FP filtreleme (Adım 20)
    try:
        from websecure.core.fp_learner import get_fp_learner
        findings = get_fp_learner().filter_findings(findings)
    except Exception as _fp_exc:
        log_warn(f"[reporting] FPLearner unavailable or error: {_fp_exc!r}")

    # 1. Deduplicate
    unique = _dedupe_findings(findings)

    # 2. Build OAST event index: token string -> event dict
    oast_index: Dict[str, Dict] = {}
    for ev in (oast_events or []):
        ev_str = str(ev)
        # Extract any token-like strings (alphanumeric 8–40 chars)
        for tok in re.findall(r'[a-z0-9]{8,40}', ev_str):
            oast_index[tok] = ev

    # 3. Correlate each finding against OAST index
    oast_available = bool(oast_index)
    _OAST_DEPENDENT_TYPES = {"SSRF", "XXE", "SSRF/XXE", "Server-Side Request Forgery",
                              "XML External Entity", "Blind SSRF"}

    for f in unique:
        if f.get("verified"):
            continue
        # Check oast_token field or payload for matching tokens
        candidates = []
        if f.get("oast_token"):
            candidates.append(str(f["oast_token"]))
        if f.get("payload"):
            candidates += re.findall(r'[a-z0-9]{8,40}', str(f["payload"]))

        matched = False
        for tok in candidates:
            if tok in oast_index:
                f["verified"] = True
                f["confidence"] = "high"
                f["verification_method"] = "oast_callback"
                f["oast_event"] = str(oast_index[tok])[:200]
                matched = True
                break

        # Annotate SSRF/XXE findings that could not be verified via OAST
        if not matched and (f.get("type") in _OAST_DEPENDENT_TYPES):
            if not oast_available:
                f.setdefault("confidence", "low")
                f.setdefault("verification_note",
                             "OAST server not configured — out-of-band callback verification unavailable. "
                             "Finding is potential only; manual confirmation required.")
            else:
                # OAST available but no token matched -> still unconfirmed
                f.setdefault("confidence", "medium")
                f.setdefault("verification_note",
                             "No OAST callback received for this finding. "
                             "May be a false positive or firewall-blocked outbound request.")

    # 4. CVSS scoring (score_findings defined in this module via merged cvss_scorer)
    try:
        unique = score_findings(unique, auth_required=False, waf_detected=False)
    except Exception as exc:
        log_warn(f"[reporting] CVSS scoring skipped: {exc!r}")

    # 5. Sort: Critical (9+) -> High (7+) -> Medium (4+) -> Low -> Info
    _SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
                       "Info": 4, "Informational": 4}

    def _sort_key(f: Dict):
        sev = f.get("cvss_severity") or f.get("severity") or "Info"
        score = f.get("cvss_score", 0.0)
        return (_SEVERITY_ORDER.get(sev, 4), -float(score))

    unique.sort(key=_sort_key)
    return unique

        
def get_global_results() -> Dict[str, List[Any]]:
    with _GLOBAL_LOCK:
        # Return a shallow copy to avoid concurrent mod issues during read
        return {k: v[:] for k, v in _GLOBAL_RESULTS.items()}

# perform_reporting (full implementation with logger support) defined below at ~line 1502.
# Simple compat wrapper removed to avoid override confusion.

def finalize_reports(ctx: dict, cfg: dict) -> dict:
    """
    2.4/2.5 uyumlu finalize:
      - reporting.output_dir + formats dikkate alınır
      - JSON/MD/HTML/SARIF üretir (mevcut render fonksiyonlarını kullanır)
      - CI eşiği uygular ve 'ci.exit_on_violation' True ise SystemExit(1) fırlatır
    """
    rep_cfg = (cfg.get("reporting") or {}) if isinstance(cfg, dict) else {}
    
    # [Fix] Resolve raw output dir to Project Root to avoid split output/ folders
    raw_out = rep_cfg.get("output_dir") or cfg.get("output_dir") or "output"
    
    # Robustly find Project Root (parent of 'websecure' package)
    try:
        current_file = pathlib.Path(__file__).resolve()
        # If we are in websecure/core/reporting.py, root is 2 levels up from 'websecure'
        # Structure: ProjectRoot/websecure/core/reporting.py
        # Parents: [0]core, [1]websecure, [2]ProjectRoot
        if "websecure" in current_file.parts:
            # Find the index of 'websecure' and go one up
            idx = len(current_file.parts) - 1 - current_file.parts[::-1].index("websecure")
            root_dir = str(pathlib.Path(*current_file.parts[:idx]))
        else:
            # Fallback for weird installs
            root_dir = os.getcwd()

        if os.path.isabs(raw_out):
            out_dir = raw_out
        else:
            out_dir = os.path.join(root_dir, raw_out)
    except (OSError, ValueError, AttributeError) as exc:
        log_warn(f"[reporting] Output dir resolution failed, falling back to relative CWD: {exc!r}")
        out_dir = raw_out # Fallback to relative CWD



    results = {}
    if isinstance(ctx, dict):
        r = ctx.get("results")
        if isinstance(r, dict):
            results = dict(r)
        elif isinstance(r, list):
            results = {"final": r}
        meta = ctx.get("meta") or {}
        if meta:
            results["meta"] = meta
        if "metrics" in ctx and isinstance(ctx["metrics"], dict):
            results["metrics"] = dict(ctx["metrics"])

    # _buckets'tan eksik bucket'ları results'a ekle (add_result() ile yazılanlar)
    try:
        buckets = get_results()
        for bkey, bval in buckets.items():
            if bval and bkey not in results:
                results[bkey] = bval
            elif bval and isinstance(results.get(bkey), list):
                # Var olan listeyi _buckets ile birleştir (tekrar olmadan)
                # Content-based fingerprint — id() compares object identity, not content
                def _fp(x):
                    try:
                        return json.dumps(x, sort_keys=True, default=str)
                    except Exception:
                        return str(x)
                existing = {_fp(x) for x in results[bkey]}
                results[bkey] = results[bkey] + [x for x in bval if _fp(x) not in existing]
    except Exception as _be:
        log_warn(f"[reporting] _buckets merge atlandı: {_be!r}")

    # [Fix] Ensure 'nmap' key is populated for HTML dashboard BEFORE reporting
    # Check if we have port data in known keys
    if "nmap" not in results:
         results["nmap"] = results.get("port_scan") or results.get("ports") or []
         # Normalize to list of dicts if needed
         if isinstance(results["nmap"], dict) and "open_ports" in results["nmap"]:
              results["nmap"] = results["nmap"]["open_ports"]

    # [WS3] BANNER: Show exact report path to user
    try:
        os.makedirs(out_dir, exist_ok=True)
        abs_p = os.path.abspath(out_dir)
        html_p = os.path.join(abs_p, "report.html")
        print("\n" + "#"*70)
        print(" RAPOR OLUŞTURULUYOR / REPORT GENERATION")
        print("#"*70)
        print(f" [+] Dizin: {abs_p}")
        print(f" [+] Dosya: {html_p}")
        print("#"*70 + "\n")
    except Exception as e:
        print(f"[!] Rapor dizini oluşturma hatası: {e}")


    # [Fix] Ensure 'tls' key is populated from 'ssl' or certificate data
    if "tls" not in results:
         results["tls"] = results.get("ssl") or {}

    # Ensure output dir exists
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # 1. Generate Charts
    try:
        charts = _generate_charts(results, out_dir)
        results["charts"] = charts
    except Exception as e:
        log_warn(f"Chart generation failed: {e}")

    # 2. Generate HTML Report
    out = {"written": {}, "final_results": results}
    try:
        # render_html_dashboard defined in this module via merged html_dashboard
        # [Fix] Force HTML generation even if config is vague
        html_content = render_html_dashboard(results)
        
        # Ensure 'html' format is respected if explicitly disabled, but default to True
        should_gen = True
        rep_formats = rep_cfg.get("formats")
        if isinstance(rep_formats, list) and "html" not in rep_formats:
             should_gen = False
             
        report_path = os.path.join(out_dir, "report.html")  # define before conditional
        if should_gen:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"\n\033[92m[+] HTML Report Generated: {report_path}\033[0m")
            print("\033[90m    (Contains detailed findings, evidence, Nmap results, SSL info)\033[0m")
            # Add to written artifacts
            out["written"]["html"] = report_path
    except Exception as e:
        log_err(f"HTML Report generation failed: {e}")

    # [Phase 7] PDF Report Generation
    try:
        rep_formats = rep_cfg.get("formats", ["html"])
        if "pdf" in rep_formats or rep_cfg.get("pdf", {}).get("enabled", False):
            pdf_path = os.path.join(out_dir, "report.pdf")
            _pdf_ok = False
            try:
                from websecure.reporters.pdf import PDFReporter
                reporter = PDFReporter()
                _pdf_ok = reporter.generate(results, cfg, pdf_path)
            except Exception as _pdf_exc:  # ImportError dahil tüm hatalar -> fallback
                log_warn(f"[reporting] PDFReporter unavailable ({_pdf_exc!r}), falling back to PDFReportBuilder")
            if not _pdf_ok:
                # Fallback: PDFReportBuilder (inline WeasyPrint/reportlab/HTML)
                try:
                    findings_for_pdf = _coerce_final(results)
                    owasp_m = results.get("owasp_mapping") if isinstance(results, dict) else None
                    compliance_r = results.get("compliance_report") if isinstance(results, dict) else None
                    _pdf_builder = PDFReportBuilder()
                    actual_path = _pdf_builder.build(findings_for_pdf, pdf_path, owasp_m, compliance_r)
                    _pdf_ok = bool(actual_path)
                    pdf_path = actual_path or pdf_path
                except Exception as _fb_exc:
                    log_warn(f"[reporting] PDFReportBuilder fallback failed: {_fb_exc!r}")
            if _pdf_ok:
                out["written"]["pdf"] = pdf_path
                print(f"\n\033[92m[+] PDF Report Generated: {pdf_path}\033[0m")
    except Exception as e:
        log_warn(f"PDF report generation failed: {e}")

    # [CI/Quality Gate]
    ci_cfg = (cfg.get("ci") or {}) if isinstance(cfg, dict) else {}
    exit_on = bool(ci_cfg.get("exit_on_violation", False))
    fail_on_sev = ci_cfg.get("fail_on", [])
    
    fail = False
    if fail_on_sev and results:
         try:
            fail = should_fail_ci(cfg, results)
         except Exception as exc:
            log_warn(f"[reporting] CI gate evaluation failed: {exc!r}")
            fail = False

    if exit_on and fail:
        raise SystemExit(1)

    return out.get("written", out) if isinstance(out, dict) else {"output_dir": out_dir}


def add_session(user: str, cookies: dict, headers: dict = None, origin_url: str = None) -> None:
    """
    Adds a captured session to the report.
    Performs a quick liveness check (Liveness Check).
    """
    from websecure.core.http import hardened_session as _hs
    verified = False

    # Liveness Check
    if origin_url and cookies:
        try:
            # Try to access origin with cookies to see if we are still logged in
            s = _hs({})
            # Basic validation: If we get 200/302/403 (but different from public) -> Verified
            # Simplified: Just mark as captured. Real liveness check takes time.
            # But let's try a quick HEAD
            r = s.head(origin_url, cookies=cookies, timeout=3, allow_redirects=True)
            if r.status_code < 400:
                verified = True
        except Exception as exc:
            log_warn(f"[reporting] Session liveness check failed for {origin_url}: {exc!r}")
            
    entry = {
        "user": user,
        "cookies": cookies,
        "headers": headers or {},
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "verified": verified
    }
    
    add_result("sessions", entry)
RULES_REGISTRY: dict[str, dict] = {
    'SQL Injection': {'id': 'WS-SQLI', 'cwe': ['CWE-89'], 'help': 'Parametreli sorgu ve ORM kalkanlarını kullanın.'},
    'XSS': {'id': 'WS-XSS', 'cwe': ['CWE-79'], 'help': 'Çıktı kodlama (HTML/JS/CSS) ve CSP uygulayın.'},
    'SSRF': {'id': 'WS-SSRF', 'cwe': ['CWE-918'], 'help': 'Çıkış yapan istekleri allowlist ile kısıtlayın.'},
    'Open Redirect': {'id': 'WS-OR', 'cwe': ['CWE-601'],
                      'help': 'Yönlendirme hedefinde allowlist ve tam URL doğrulaması yapın.'},
    'Insecure Headers': {'id': 'WS-HDR', 'cwe': ['CWE-693'],
                         'help': 'Güvenlik başlıklarını (CSP, HSTS, XFO, X-Content-Type-Options) ayarlayın.'},
    'TLS Misconfiguration': {'id': 'WS-TLS', 'cwe': ['CWE-327', 'CWE-326'],
                             'help': 'Güçlü TLS sürümleri ve şifre kümeleri kullanın.'},
    'Authentication': {'id': 'WS-AUTH', 'cwe': ['CWE-287'],
                       'help': 'Güçlü kimlik doğrulama ve oturum yönetimi uygulayın.'},
    'Authorization': {'id': 'WS-AZ', 'cwe': ['CWE-285'],
                      'help': 'Yetki kontrollerini her endpoint seviyesinde zorunlu kılın.'},
    'Information Disclosure': {'id': 'WS-INFO', 'cwe': ['CWE-200'],
                               'help': 'Hata/sürüm bilgilerini son kullanıcıya göstermeyin.'},
}


def rule_for(finding: dict) -> dict:
    t = str(finding.get('type') or finding.get('title') or '').strip()
    if not t:
        return {'id': 'WS-GEN', 'cwe': [], 'help': ''}
    # normalize a few common prefixes
    norm = (t.replace('OWASP:', '').replace('OWASP ', '').strip())
    for key, meta in RULES_REGISTRY.items():
        if key.lower() in norm.lower():
            return meta | {'name': key}
    return {'id': 'WS-GEN', 'name': t, 'cwe': [], 'help': ''}


_PAYLOAD_METRICS = defaultdict(int)
_PAYLOAD_EXAMPLES = {}


def note_payload_usage(category: str, count: int, example: str = "") -> None:
    k = (category or "").strip().lower()
    c = int(count or 0)
    if k and c > 0:
        _PAYLOAD_METRICS[k] += c
        if example and k not in _PAYLOAD_EXAMPLES:
            _PAYLOAD_EXAMPLES[k] = example


def export_payload_metrics() -> dict:
    return {
        "payloads": {k: int(v) for k, v in sorted(_PAYLOAD_METRICS.items())},
        "examples": dict(_PAYLOAD_EXAMPLES),
    }


# --- ZEMSEC banner asset paths ---
ROOT = Path(__file__).resolve().parent
ASSETS_DIR = ROOT / "assets"
BANNER_FILE = "zemsec_dark.png" if (ASSETS_DIR / "zemsec_dark.png").exists() else (
    "zemsec_gri.jpg" if (ASSETS_DIR / "zemsec_gri.jpg").exists() else "")


# [WS3-ANCHOR] Auth Coverage Delta
class AuthCoverage:
    def __init__(self):
        self.counters = {"WAF": 0, "Auth": 0, "RateLimit": 0}

    def add(self, kind: str):
        if kind in self.counters:
            self.counters[kind] += 1


AUTH_COVERAGE = AuthCoverage()


def note_auth_outcome(kind: str):
    AUTH_COVERAGE.add(kind)


def render_auth_coverage_md():
    c = AUTH_COVERAGE.counters
    total = sum(c.values()) or 0
    return ("\n### Auth Coverage Delta\n"
            f"- WAF: {c['WAF']}\n- Auth: {c['Auth']}\n- Rate-Limit: {c['RateLimit']}\n"
            f"- Toplam 401/403: {total}\n")


# -------------------- Global durum (thread-safe) --------------------
_lock = threading.RLock()
_buckets: Dict[str, List[Dict[str, Any]]] = {}
_logger: logging.Logger | None = None

# -------------------- Maskeleme / Redaction (FAZ 4.1 — ayrı modül) --------------------
_ENFORCE_REDACT = True

from websecure.core.redaction import (  # noqa: E402
    redact_sensitive,
    RedactFilter,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_host_for_filename(url: str) -> str:
    host = urlparse(url).hostname or "report"
    safe = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in host)
    return safe[:100] or "report"


# -------------------- Logging --------------------
def configure_logging(level: str | int = "INFO", fmt: str = "[%(levelname)s] %(message)s") -> logging.Logger:
    global _logger
    lvl = getattr(logging, str(level).upper(), logging.INFO) if isinstance(level, str) else int(level)
    _logger = logging.getLogger("websec")
    _logger.setLevel(lvl)
    _logger.handlers = []
    h = logging.StreamHandler()
    h.setLevel(lvl)
    h.setFormatter(logging.Formatter(fmt))
    h.addFilter(RedactFilter())
    _logger.addHandler(h)
    return _logger


def log_info(msg, *a):  (_logger or logging.getLogger("websec")).info(msg, *a)


def log_warn(msg, *a):  (_logger or logging.getLogger("websec")).warning(msg, *a)


def log_err(msg, *a):   (_logger or logging.getLogger("websec")).error(msg, *a)


# -------------------- Kova API --------------------
def reset() -> None:
    """Tüm tarama-sonucu durumunu sıfırla (çoklu-hedef/queue/API/benchmark arası).

    BUG FIX: Eskiden yalnız `_buckets` temizleniyordu; ancak `get_global_results()`
    `_GLOBAL_RESULTS`'tan okur ve add_result her ikisine de yazar. `_GLOBAL_RESULTS`
    temizlenmediği için bir taramanın bulguları SONRAKİ taramaya sızıyordu
    (çoklu-hedef/queue/API'de yanlış rapor; benchmark'ta sahte FP). Artık her iki
    sonuç deposu da temizlenir.
    """
    with _lock:
        _buckets.clear()
    with _GLOBAL_LOCK:
        _GLOBAL_RESULTS.clear()


def _normalize_item(item: Any) -> Dict[str, Any]:
    """Coerce arbitrary payloads into a dict for safe reporting."""
    if item is None:
        return {}

    if isinstance(item, dict):
        return dict(item)

    # Dataclass benzeri nesne: __dataclass_fields__ ipucuyla alanları çıkar
    flds = getattr(item, "__dataclass_fields__", None)
    if isinstance(flds, dict):
        return {name: getattr(item, name, None) for name in flds.keys()}

    # Genel Python nesnesi (__dict__ varsa)
    if hasattr(item, "__dict__") and isinstance(getattr(item, "__dict__"), dict):
        return dict(vars(item))

    # Bytes -> metin (hatasız, ignore)
    if isinstance(item, (bytes, bytearray)):
        return {"message": bytes(item).decode("utf-8", "ignore")}

    # Düz string
    if isinstance(item, str):
        return {"message": item}

    # Sıralılar
    if isinstance(item, (list, tuple, set)):
        seq = list(item)
        if all(isinstance(x, dict) for x in seq):
            return {"items": [dict(x) for x in seq]}
        if all(isinstance(x, (list, tuple)) and len(x) == 2 for x in seq):
            # Anahtarların sözlüğe uygunluğunu önceden doğrula (hashlenebilir ve basit türler)
            simple_key = (str, int, float, bool)
            if all(isinstance(kv[0], simple_key) for kv in seq):
                return {kv[0]: kv[1] for kv in seq}
            return {"items": [repr(x) for x in seq]}
        return {"items": [x if isinstance(x, (int, float, str)) else repr(x) for x in seq]}

    # Geriye kalanlar için temsil
    return {"value": repr(item)}


# add_result -> learned.txt geri-besleme döngüsü için "öğrenilebilir" enjeksiyon
# bucket'ları. Bucket adı get_payloads(category) ile birebir aynı olmalı ki bir
# sonraki taramada doğru kategoriye eşleşip öncelikli denensin.
_LEARNABLE_BUCKETS = frozenset({
    "sqli", "xss", "ssti", "lfi", "cmdi", "rce", "nosqli",
    "ssrf", "xxe", "open_redirect", "redirect", "graphql",
})


def _is_contentless_vuln(it: Dict[str, Any]) -> bool:
    """Vuln-severity'li ama HİÇBİR actionable içeriği olmayan (url/payload/evidence/
    mesaj yok) ve generic type'lı bulgu mu? Gerçek taramada raporu/sayımı
    "VULN #N: VULNERABILITY [Medium] Target: N/A Payload: N/A" gibi junk'larla
    kirletiyordu. Bunlar Info'ya indirilir: veride kalır ama vuln SAYILMAZ, banner
    çalmaz, CI gate'i düşürmez."""
    sev = str(it.get("severity") or "").lower()
    if sev not in ("critical", "high", "medium", "low"):
        return False
    content_keys = (
        "url", "target", "endpoint", "matched_at", "matched-at",
        "payload", "evidence", "parameter", "param", "message",
        "detail", "details", "reason", "proof", "request", "response",
    )
    if any(it.get(k) for k in content_keys):
        return False
    t = str(it.get("type") or it.get("vuln_type") or "").strip().lower()
    if t and t not in ("vulnerability", "offensive", "finding", "vuln"):
        return False
    return True


def add_result(bucket: str, item: Any) -> None:
    if not bucket:
        return
    with _lock:
        it = _normalize_item(item)
        it.setdefault("ts", _now_iso())

        # Normalize severity to canonical English for every stored finding.
        # Scanners may emit "High", "High", "high", "CRITICAL", etc.
        # Storing canonical English ensures sorting, CI gates and CVSS scoring
        # all use the same key space without any per-caller conversion.
        raw_sev = it.get("severity")
        if raw_sev is not None:
            it["severity"] = _norm_sev_tr(raw_sev)  # returns "Critical"/"High"/…

        # İÇERİKSİZ junk bulguları (severity var ama url/payload/evidence yok) Info'ya
        # indir — "VULNERABILITY N/A" şişirmesini engeller, gerçek bulgular etkilenmez.
        if it.get("severity") and it["severity"] != "Info" and _is_contentless_vuln(it):
            it["severity"] = "Info"
            it.setdefault("_note", "contentless-downgraded")

        enforce = globals().get("_ENFORCE_REDACT", True)
        # [WS3] Bypass redaction for explicit 'sessions' bucket if user requested visibility
        if bucket == "sessions":
            safe_it = it
        else:
            safe_it = redact_sensitive(it) if enforce else it
            
        if bucket not in _buckets:
            _buckets[bucket] = []
        _buckets[bucket].append(safe_it)

    # Keep _GLOBAL_RESULTS in sync — acquire _GLOBAL_LOCK separately to avoid
    # nested lock deadlock (_lock RLock nested inside _GLOBAL_LOCK Lock)
    with _GLOBAL_LOCK:
        _GLOBAL_RESULTS[bucket].append(safe_it)

        # [WS3] Universal Evidence Handling
        # If item has 'evidence', we log it specifically or save artifacts
        evidence = safe_it.get("evidence")
        if evidence:
            # 1. Capture Raw Response if present
            if "raw_response" in evidence:
                _save_evidence_artifact(safe_it, "response.txt", evidence["raw_response"])
            
            # 2. Capture Screenshot path if present
            if "screenshot_path" in evidence:
                # Validated path is already there, just ensure report knows it
                pass

        # --- Audio Alert Logic ---
        # Check severity (supports English and Turkish normalized severities)
        sev = str(safe_it.get("severity") or "").lower()
        if "critical" in sev:
            AlertManager.play_critical()
        elif "high" in sev or "yuksek" in sev:
            AlertManager.play_high()
        elif "medium" in sev or "orta" in sev:
            AlertManager.play_medium()
        elif "low" in sev or "dusuk" in sev:
            AlertManager.play_low()

        # --- Console Visual Alert ---
        _console_alert(bucket, safe_it)

        # --- LiveMonitor finding highlight ---
        try:
            get_live_monitor().log_finding(bucket, safe_it)
        except (AttributeError, TypeError) as exc:
            log_warn(f"[reporting] LiveMonitor log_finding failed: {exc!r}")

    # --- Öğrenme döngüsü: onaylanmış enjeksiyon payload'ını learned.txt'ye yaz ---
    # (kilit dışında — dosya I/O'su kilidi tutmasın). config.fuzz.learning.enabled
    # kapalıysa record_learned_payload no-op'tur. Sonraki taramalarda get_payloads
    # bu payload'ı listenin başına ekleyip öncelikli dener.
    try:
        _pl = safe_it.get("payload")
        _sev = safe_it.get("severity")
        if (_pl and bucket in _LEARNABLE_BUCKETS
                and _sev in ("Critical", "High", "Medium")):
            from websecure.core.payloads import record_learned_payload as _rlp
            _rlp(bucket, str(_pl))
    except Exception:
        pass


# ===========================================================================
# LiveMonitor — real-time terminal output for scan progress
# FAZ 4.1: Ayrı modüle taşındı (core/live_monitor.py). Backward compat için import.
# ===========================================================================
from websecure.core.live_monitor import (  # noqa: E402
    get_live_monitor,
    console_alert as _console_alert_new,
)

# _console_alert backward compat alias
def _console_alert(bucket, item):  # noqa: E302
    _console_alert_new(bucket, item)


# Module-level singleton re-exported for callers that do:
#   from websecure.core.reporting import get_live_monitor
# This is already covered by the import above.


def _save_evidence_artifact(item: Dict[str, Any], suffix: str, content: str) -> None:
    """Saves raw evidence to the evidence/ folder in output."""
    try:
        # Resolve via __file__ so it works regardless of CWD on all platforms.
        # reporting.py lives at websecure/core/reporting.py; .parent.parent = websecure/
        _pkg_dir = pathlib.Path(__file__).resolve().parent.parent
        evidence_dir = str(_pkg_dir / "output" / "evidence")
        os.makedirs(evidence_dir, exist_ok=True)
        
        safe_name = _safe_host_for_filename(item.get("url") or "unknown")
        ts = int(datetime.now().timestamp())
        filename = f"{safe_name}_{ts}_{suffix}"
        
        path = os.path.join(evidence_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
            
        # Update item with reference
        if "evidence_files" not in item:
            item["evidence_files"] = []
        item["evidence_files"].append(path)
            
    except Exception as e:
        log_err(f"Failed to save evidence artifact: {e}")


def get_results() -> Dict[str, List[Dict[str, Any]]]:
    with _lock:
        return {k: [dict(x) for x in v] for k, v in _buckets.items()}


def get_bucket_results() -> Dict[str, List[Dict[str, Any]]]:
    return get_results()


# -------------------- Grafik Üretimi (Matplotlib) --------------------
def _ensure_dir(p: str) -> None:
    if not p:
        return
    os.makedirs(p, exist_ok=True)


def _safe_norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _generate_charts(results: Dict, out_dir: str) -> List[Dict[str, str]]:
    """
    3 pasta grafik üretir ve yan yana galeride gösterilir:
    - Risk Seviyesi Dağılımı (Bilgi -> 'Güvenli' olarak birleştirilir)
    - Saldırı Başarı Grafiği (faz başlıklarıyla birebir eşleşme; 12.5% bug fix)
    - Saldırı Başarısız Grafiği (başarısı 0 olan denemeler; yoksa 'Başarısız Yok')
    """
    import importlib.util as _iul
    if _iul.find_spec("matplotlib") is None:
        return []
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from collections import OrderedDict

    charts_meta: List[Dict[str, str]] = []
    img_dir = os.path.join(out_dir, "images")
    os.makedirs(img_dir, exist_ok=True)

    items = _coerce_final(results)

    # --- 1) Risk pie (Info -> Safe in chart)
    base_counts = {k: 0 for k in ("Critical", "High", "Medium", "Low", "Info")}
    for it in items:
        base_counts[_norm_sev_tr(it.get("severity"))] = base_counts.get(_norm_sev_tr(it.get("severity")), 0) + 1
    risk_labels = ["Critical", "High", "Medium", "Low", "Safe"]
    risk_values = [
        base_counts["Critical"],
        base_counts["High"],
        base_counts["Medium"],
        base_counts["Low"],
        base_counts["Info"],  # Info shown as Safe in chart
    ]
    if sum(risk_values) > 0:
        fig = plt.figure(figsize=(4, 4))
        ax = fig.add_subplot(111)
        ax.pie(risk_values, labels=risk_labels, autopct=lambda p: f"{p:.1f}%" if p > 0 else "", startangle=90)
        ax.axis('equal')
        ax.set_title("Risk Seviyesi Dağılımı")
        fig.tight_layout()
        pth = os.path.join(img_dir, "risk_severity.png")
        fig.savefig(pth, dpi=150, bbox_inches="tight")
        plt.close(fig)
        charts_meta.append(
            {"title": "Risk Seviyesi Dağılımı", "path": pth, "rel_path": "images/risk_severity.png", "kind": "risk"})

    # --- Denenen yöntemleri oku (phase_plan.visible[].title/id)
    tried_map: "OrderedDict[str,str]" = OrderedDict()
    for bucket, arr in (results or {}).items():
        if bucket != "phase_plan":
            continue
        for it in arr or []:
            for v in it.get("visible", []) or []:
                if v.get("enabled"):
                    raw = str(v.get("title") or v.get("id") or "").strip()
                    if not raw:
                        continue
                    key = re.sub(r"[^a-z0-9]+", "", raw.lower())
                    if key and key not in tried_map:
                        tried_map[key] = raw

    def _alias_norm(s: str) -> str:
        s = re.sub(r"[^a-z0-9]+", "", (s or "").lower())
        aliases = {
            "nosqli": "nosqlinjection",
            "sqlinjection": "sqli",
            "fileupload": "fileupload",
            "securityheaders": "headers",
            "headers": "headers",
            "xss": "xss",
            "oast": "oast",
        }
        return aliases.get(s, s)

    # --- Success count (exclude Info-level) — STRICT match
    success_per: "OrderedDict[str,int]" = OrderedDict((k, 0) for k in tried_map.keys())
    for it in items:
        sev = _norm_sev_en(it.get("severity"))
        if sev == "Info":
            continue
        typ_norm = _alias_norm(str(it.get("type") or it.get("title") or ""))
        if not typ_norm:
            continue
        for k in success_per.keys():
            if _alias_norm(k) == typ_norm:  # yalnızca birebir eşleşme
                success_per[k] += 1

    # --- 2) Başarı pie
    if success_per:
        labels2 = [tried_map[k] for k in success_per.keys()]
        values2 = [success_per[k] for k in success_per.keys()]
        if sum(values2) == 0:
            labels2, values2 = ["Başarı Yok"], [1]
        fig2 = plt.figure(figsize=(4, 4))
        ax2 = fig2.add_subplot(111)
        ax2.pie(values2, labels=labels2, autopct=lambda p: f"{p:.1f}%" if p > 0 else "", startangle=90)
        ax2.axis('equal')
        ax2.set_title("Saldırı Başarı Grafiği")
        fig2.tight_layout()
        pth2 = os.path.join(img_dir, "attacks_success.png")
        fig2.savefig(pth2, dpi=150, bbox_inches="tight")
        plt.close(fig2)
        charts_meta.append(
            {"title": "Kullanılan Saldırıların Başarı Grafiği", "path": pth2, "rel_path": "images/attacks_success.png",
             "kind": "success"})

    # --- 3) Başarısız pie (başarısı 0 olan denemeler; hiç yoksa tek dilim)
    failed_keys = [k for k, v in (success_per.items() if success_per else []) if v == 0]
    labels3 = [tried_map[k] for k in failed_keys] if failed_keys else ["Başarısız Yok"]
    values3 = [1 for _ in labels3]
    fig3 = plt.figure(figsize=(4, 4))
    ax3 = fig3.add_subplot(111)
    ax3.pie(values3, labels=labels3, autopct=lambda p: f"{p:.1f}%" if p > 0 else "", startangle=90)
    ax3.axis('equal')
    ax3.set_title("Kullanılan Saldırıların Başarısız Grafiği")
    fig3.tight_layout()
    pth3 = os.path.join(img_dir, "attacks_failed.png")
    fig3.savefig(pth3, dpi=150, bbox_inches="tight")
    plt.close(fig3)
    charts_meta.append(
        {"title": "Kullanılan Saldırıların Başarısız Grafiği", "path": pth3, "rel_path": "images/attacks_failed.png",
         "kind": "failed"})

    return charts_meta


# -------------------- Markdown Render --------------------
def _percentile(arr, p):
    # Guard: boş veya sayıya indirgenemeyen dizi -> 0.0
    if not arr:
        return 0.0

    # Sayıya güvenli dönüştürücü (istisnasız)
    def _to_float(x):
        s = str(x).strip()
        # ±12, 12.3, .5, 1e3, -2.5E-2 vb.
        if re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", s):
            return float(s)
        return None

    vals = [v for v in (_to_float(x) for x in arr) if v is not None]
    if not vals:
        return 0.0

    # p aralığını [0,100] içine sıkıştır
    pf = _to_float(p)
    p = 0.0 if pf is None else max(0.0, min(100.0, pf))

    arr2 = sorted(vals)
    k = (len(arr2) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(arr2) - 1)
    if f == c:
        return float(arr2[f])
    d0 = arr2[f] * (c - k)
    d1 = arr2[c] * (k - f)
    return float(d0 + d1)


def _rt_histogram(ms_list):
    buckets = [
        (0, 100, '<100ms'),
        (100, 300, '100–300ms'),
        (300, 1000, '300ms–1s'),
        (1000, 3000, '1–3s'),
        (3000, 999999999, '>3s'),
    ]
    out = {label: 0 for _, _, label in buckets}

    def _to_float(x):
        s = str(x).strip()
        if re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", s):
            return float(s)
        return None

    for x in (ms_list or []):
        v = _to_float(x)
        if v is None:
            continue
        for lo, hi, label in buckets:
            if lo <= v < hi:
                out[label] += 1
                break
    return out


MAX_POC_LEN = 4000


def _short_poc(s: str) -> str:
    s = (s or "").strip()
    return (s[:MAX_POC_LEN] + " …") if len(s) > MAX_POC_LEN else s


def _norm_sev_tr(s: str | None) -> str:
    """Normalize severity to English canonical. Accepts English and Turkish inputs."""
    s = (s or "info").strip().lower()
    if s in ("critical", "crit", "severe", "kritik"):
        return "Critical"
    if s in ("high", "yüksek", "yuksek"):
        return "High"
    if s in ("medium", "med", "orta"):
        return "Medium"
    if s in ("low", "düşük", "dusuk", "düsük"):
        return "Low"
    if s in ("info", "informational", "bilgi"):
        return "Info"
    return "Info"


def _sev_rank(s: str | None) -> int:
    """Rank via TR+EN normalization: critical=4 > high=3 > medium=2 > low=1 > info=0."""
    m = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    try:
        return m.get(_norm_sev_tr(s or "").lower(), 0)
    except (ValueError, TypeError, AttributeError) as exc:
        log_warn(f"[reporting] Severity rank lookup failed for {s!r}: {exc!r}")
        return 0

def _coerce_final(results: Dict) -> List[Dict]:

    fin = results.get("final")
    if isinstance(fin, list) and len(fin) > 0:
        return fin
    merged: List[Dict] = []
    for key, val in list(results.items()):
        if key.endswith("_summary"):
            continue
        if isinstance(val, list) and all(isinstance(x, dict) for x in val):
            for _it in val:
                it2 = dict(_it)
                if 'module' not in it2 and isinstance(key, str):
                    it2['module'] = key
                merged.append(it2)
    return merged


def _dedupe_findings(items: List[Dict]) -> List[Dict]:
    """(type,url,location,param) bazında tekilleştir; en yüksek severity/score'u al, payload/evidence birleştir."""
    bykey: Dict[Tuple, Dict] = {}
    for it in (items or []):
        if not isinstance(it, dict):
            continue
        key = (it.get("type"), it.get("url"), it.get("location"), it.get("param"))
        cur = bykey.get(key)
        if cur is None:
            bykey[key] = dict(it)
            continue

        # severity: daha yüksek olanı tut
        s_old = _sev_rank(cur.get("severity"))
        s_new = _sev_rank(it.get("severity"))
        if s_new > s_old:
            cur["severity"] = it.get("severity")

        # score: maksimum
        cur_score = cur.get("score") or 0
        it_score = it.get("score") or 0
        if it_score > cur_score:
            cur["score"] = it_score

        # reason: daha uzun açıklama
        if len(str(it.get("reason", ""))) > len(str(cur.get("reason", ""))):
            cur["reason"] = it.get("reason")

        # payloads: sırayı koruyarak tekilleştir
        if it.get("payloads"):
            cur.setdefault("payloads", [])
            cur_pl = list(cur.get("payloads") or [])
            it_pl = list(it.get("payloads") or [])
            cur["payloads"] = list(dict.fromkeys(cur_pl + it_pl))

        # similar_params: sırayı koruyarak tekilleştir
        if it.get("similar_params"):
            cur.setdefault("similar_params", [])
            cur_sp = list(cur.get("similar_params") or [])
            it_sp = list(it.get("similar_params") or [])
            cur["similar_params"] = list(dict.fromkeys(cur_sp + it_sp))

        # evidence: merge only when both sides are dicts
        ev_new = it.get("evidence")
        if ev_new is not None:
            cur_ev = cur.get("evidence")
            if isinstance(cur_ev, dict) and isinstance(ev_new, dict):
                cur_ev.update(ev_new)
            elif cur_ev is None:
                cur["evidence"] = ev_new

        # poc: kısa gösterimde daha “zengin” olanı al
        cur_poc_short = _short_poc(cur.get("poc") or "")
        it_poc_short = _short_poc(it.get("poc") or "")
        if len(str(it_poc_short)) > len(str(cur_poc_short)):
            cur["poc"] = it.get("poc")

    return list(bykey.values())


def _render_ports(results: Dict) -> str:
    """
    Açık portları tam detayla render eder.
    Host | Port | Proto | Servis | Ürün/Versiyon | NSE Çıktıları | CPE
    """
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
                    "ssh-hostkey", "ftp-anon", "smtp-commands",
                    "ssl-heartbleed", "ssl-poodle"):
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
                "cpe":     ", ".join(cpe[:2]) if cpe else "",
                "os":      str(it.get("os_guess") or ""),
            })

    if not rows:
        return ""

    # Dedupe by (host, port, proto)
    seen = {}
    for r in rows:
        key = (r["host"], r["port"], r["proto"])
        if key not in seen:
            seen[key] = r

    sorted_rows = sorted(seen.values(), key=lambda r: (r["host"], r["port"] if isinstance(r["port"], int) else 99999))

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


def _render_ssl_table(results: Dict) -> str:
    """Renders SSL/TLS certificate details including SAN, warnings, and self-signed status."""
    tls = results.get("tls") or {}
    if isinstance(tls, list):
        tls = next((x for x in tls if isinstance(x, dict) and "certificate" in x), {})
    cert = tls.get("certificate") or {}
    if not cert:
        return ""

    out = []
    out.append("## SSL/TLS Yapılandırma Detayları")
    out.append("")
    out.append("| Özellik | Değer |")
    out.append("|-|-|")

    # Status
    if cert.get("self_signed"):
        valid_icon = "[!] Self-Signed (Güvensiz)"
    elif cert.get("valid"):
        valid_icon = "[OK] Geçerli"
    else:
        valid_icon = "[X] Geçersiz"
    out.append(f"| Durum | {valid_icon} |")

    # HSTS
    hsts = "[OK] Aktif" if (cert.get("hsts") or tls.get("hsts")) else "[X] Eksik"
    out.append(f"| HSTS | {hsts} |")

    # Certificate fields
    out.append(f"| Subject CN | `{cert.get('subject_CN') or 'Unknown'}` |")
    out.append(f"| Issuer CN | `{cert.get('issuer_CN') or 'Unknown'}` |")
    out.append(f"| Issuer Org | `{cert.get('issuer_O') or '-'}` |")
    out.append(f"| Geçerlilik Başlangıcı | `{cert.get('not_before') or '-'}` |")
    out.append(f"| Geçerlilik Bitişi | `{cert.get('not_after') or '-'}` |")

    days = cert.get("days_remaining")
    if isinstance(days, int):
        if days < 0:
            days_str = f"[X] **Süresi Dolmuş** ({abs(days)} gün önce)"
        elif days < 30:
            days_str = f"[!] {days} gün (Kritik — Yakında Doluyor)"
        else:
            days_str = f"{days} gün"
    else:
        days_str = "-"
    out.append(f"| Kalan Süre | {days_str} |")

    out.append(f"| TLS Versiyonu | `{cert.get('tls_version') or '-'}` |")
    out.append(f"| SHA-256 Parmak İzi | `{cert.get('fingerprint') or '-'}` |")

    # SAN — domain/subdomain names in certificate
    san_list = cert.get("san") or []
    if san_list:
        san_str = ", ".join(f"`{s}`" for s in san_list)
        out.append(f"| Alt Adlar (SAN) | {san_str} |")

    # Problems
    probs = cert.get("problems") or []
    if probs:
        out.append(f"| **Problemler** | {' / '.join(probs)} |")

    # Warnings (TLS version weakness, expiry, self-signed)
    warnings = cert.get("warnings") or []
    if warnings:
        out.append(f"| **Uyarılar** | {' / '.join(warnings)} |")

    out.append("")
    return "\n".join(out)


def _render_markdown_report_inline(results: Dict) -> str:
    # Hazırlık
    items_raw = _coerce_final(results)
    items = _dedupe_findings(items_raw)
    items.sort(key=lambda i: (
    -_sev_rank(i.get("severity")), -(i.get("score") or 0), str(i.get("type") or ""), str(i.get("url") or "")))

    def esc_md(s: str) -> str:
        return (s or "").replace("|", "\\|").replace("`", "\\`").replace("*", "\\*")

    meta = (results.get("meta") if isinstance(results, dict) else {})
    if isinstance(meta, list):
        meta = next((x for x in meta if isinstance(x, dict)), {})
    target = (meta.get("target") if isinstance(meta, dict) else "") or ""
    when = _now_iso()

    # WS3 Egress Karnesi
    egress = (meta.get('egress') or {}) if isinstance(meta, dict) else {}
    lines: List[str] = []
    if egress:
        lines.append('## Egress Karnesi')
        lines.append('')
        lines.append('| Kimlik | Proxy | Bölge | Accept-Language | User-Agent |')
        lines.append('|-|-|-|-|-|')
        lines.append(
            f"| {egress.get('label', '')} | {egress.get('proxy_url', '') or 'direct'} | {egress.get('region', '')} | {egress.get('accept_language', '')} | {egress.get('ua', '')[:42]}… |")
        lines.append('')

    # Severity counts
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for i in items:
        counts[_norm_sev_tr(i.get("severity"))] = counts.get(_norm_sev_tr(i.get("severity")), 0) + 1

    # Start
    lines.append(render_auth_coverage_md())
    lines.append("# WebSec Report")
    lines.append("")
    if target:
        lines.append(f"**Target:** `{esc_md(target)}`  •  **Date:** `{when}`")
        lines.append("")

    # Summary Table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|-|-:|")
    for k in ("Critical", "High", "Medium", "Low", "Info"):
        lines.append(f"| {k} | {counts[k]} |")

    # Başarı Oranı ve Kullanılan Araçlar
    # Denenen fazlar (phase_plan.visible.enabled)
    tried_map = {}
    for node in (results.get("phase_plan") or []):
        for vis in (node.get("visible") or []):
            if vis.get("enabled"):
                raw = str(vis.get("title") or vis.get("id") or "").strip()
                key = re.sub(r"[^a-z0-9]+", "", raw.lower())
                if key and key not in tried_map:
                    tried_map[key] = raw

    # Başarılı modüller: bulgu üreten 'type' kümesi
    success_keys = set()
    for it in items:
        rawt = str(it.get("type") or it.get("category") or "").strip()
        if not rawt:
            continue
        key = re.sub(r"[^a-z0-9]+", "", rawt.lower())
        if key:
            success_keys.add(key)

    tried = list(tried_map.keys())
    success = [k for k in tried if k in success_keys]
    denom = len(tried) or 1
    pct = (100.0 * len(success) / denom)
    lines.append("")
    lines.append("### Saldırı Başarı Özeti")
    lines.append("")
    lines.append(f"- Denenen modül/faz: **{len(tried)}**")
    lines.append(f"- Başarılı (en az 1 bulgu üreten): **{len(success)}**  -> **%{pct:.1f}**")
    if tried:
        lines.append("- Dene(n)en: " + ", ".join(f"`{tried_map[k]}`" for k in tried))
    if success:
        lines.append("- Başarılı: " + ", ".join(f"`{tried_map[k]}`" for k in success))
    lines.append("")

    # Kullanılan Araçlar (item alanlarından derle)
    tool_set = set()
    for it in items:
        for fld in ("tool","engine","module","scanner"):
            val = it.get(fld)
            if isinstance(val, str) and val.strip():
                tool_set.add(val.strip())
    # Dış entegrasyon ipuçları
    for cand in ("sqlmapapi","nuclei","owasp zap","nikto"):
        # kaba tahmin: injection/owasp modüllerinde geçtiyse listeye ekle
        pass

    lines.append("### Kullanılan Araçlar")
    if tool_set:
        lines.append("- " + "\\n- ".join(sorted(tool_set)) )
    else:
        lines.append("_Araç bilgisi öğe kayıtlarında bulunamadı; sonuçlar dahili modüller tarafından üretilmiş olabilir._")
    lines.append("")

    # Grafikler (yan yana üç pasta)
    charts = (results.get("charts") or results.get("_charts") or [])
    if charts:
        kinds = {str(ch.get("kind") or ""): ch for ch in charts}

        def _img(ch: Dict | None) -> str:
            if not ch: return ""
            title = esc_md(str(ch.get("title", "Grafik")))
            relp = esc_md(str(ch.get("rel_path") or ch.get("path") or ""))
            return f'<figure class="chart"><img alt="{title}" src="{relp}"/><figcaption>{title}</figcaption></figure>'

        lines.append("")
        lines.append("### Grafikler")
        lines.append('<div class="chart-row">')
        lines.append(_img(kinds.get("risk")) or "")
        lines.append(_img(kinds.get("success")) or "")
        lines.append(_img(kinds.get("failed")) or "")
        lines.append("</div>")

    # Sızılabilir Yerler
    exploitable: List[Dict] = []
    for it in items:
        sev = _norm_sev_en(it.get("severity"))
        poc = (it.get("poc") or it.get("payload") or it.get("evidence") or "")
        poc_s = str(poc).lower()
        if sev in ("critical", "high", "medium", "low") or ("<script" in poc_s) or it.get("exploitable") or it.get(
                "exploit_url"):
            if sev not in ("info", "informational", ""):
                exploitable.append(it)
    if exploitable:
        lines.append("")
        lines.append("## Sızılabilir Yerler")
        lines.append("")
        lines.append("| Risk | Tür | URL | Param | PoC/Exploit |")
        lines.append("|-|-|-|-|-|")
        for e in exploitable:
            pocv = _short_poc((e.get("poc") or e.get("payload") or e.get("evidence") or e.get("exploit_url") or ""))
            lines.append(
                f"| {_norm_sev_tr(e.get('severity'))} | {esc_md(e.get('type') or '')} | {esc_md(e.get('url') or '')} | {esc_md(e.get('param') or '')} | `{pocv}` |")

    # Kullanılan Parametreler (frekans)
    from collections import Counter
    params = [str((it.get("param") or "")).strip() for it in items if (it.get("param") or "").strip()]
    if params:
        lines.append("")
        lines.append("## Kullanılan Parametreler")
        lines.append("")
        lines.append("| Parametre | Frekans |")
        lines.append("|-|-:|")
        for p_name, c in Counter(params).most_common(50):
            lines.append(f"| {esc_md(p_name)} | {c} |")

    # Informational Findings
    info_items = [it for it in items if _norm_sev_en(it.get("severity") or "") == "info"]
    if info_items:
        lines.append("")
        lines.append("## Informational Findings")
        lines.append("")
        lines.append("| Kaynak | URL | Param | Not |")
        lines.append("|-|-|-|-|")
        for it in info_items:
            note = it.get("reason") or it.get("description") or _short_poc(
                it.get("payload") or it.get("evidence") or "") or ""
            lines.append(
                f"| {esc_md(it.get('type') or '')} | {esc_md(it.get('url') or '')} | {esc_md(it.get('param') or '')} | {esc_md(str(note))} |")

    # Taranan Portlar / Açık Portlar
    ports_md = _render_ports(results)
    if ports_md:
        lines.append("")
        lines.append(ports_md)

    # SSL/TLS Table
    ssl_md = _render_ssl_table(results)
    if ssl_md:
         lines.append("")
         lines.append(ssl_md)

    return "\n".join(lines)


def render_markdown_report(results: Dict) -> str:
    """
    Delegates to the dedicated Markdown reporter module; falls back to inline implementation.
    """
    try:
        from websecure.reporters import markdown
        return markdown.render(results)
    except (ImportError, AttributeError):
        return _render_markdown_report_inline(results)

# -------------------- Eski Monolitik Fonksiyonlar (Kesildi) --------------------
# Eski render_markdown_report kod bloğu reporters/markdown.py dosyasına taşındı.
# Buradaki kalabalık temizlendi.


# -------------------- End of Refactored Section --------------------


def _write(path: str, data: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return path


def _sanitize_json_keys(obj: Any, _depth: int = 0) -> Any:
    """
    Recursively coerce dict keys to JSON-legal types.

    json.dump's ``default=`` hook only rescues non-serialisable *values*; a
    dict *key* that is not str/int/float/bool/None aborts the whole dump with
    ``TypeError: keys must be str, int, float, bool or None, not <X>``. In the
    wild this happened when a urllib3 ``PoolKey`` namedtuple leaked into the
    results tree (via a raw requests/connection object whose ``__dict__`` was
    expanded), crashing report generation at the very end of a 5-hour scan.

    This walks the structure once at report time and rewrites any offending key
    as ``str(key)`` so the report can never be lost to a stray internal object.
    A depth guard prevents runaway recursion on pathological/cyclic structures.
    """
    if _depth > 200:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if not isinstance(k, (str, int, float, bool)) and k is not None:
                k = str(k)
            out[k] = _sanitize_json_keys(v, _depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [_sanitize_json_keys(v, _depth + 1) for v in obj]
    return obj


def _json_dump(path: str, obj: Any) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)

    def _default(o):
        # Do NOT blindly expand library/transport internals (requests, urllib3,
        # http.client, sockets …): their __dict__ holds connection pools keyed
        # by non-serialisable objects (PoolKey) and can be huge. Render a repr
        # instead so nothing leaks into — or crashes — the report.
        mod = type(o).__module__ or ""
        if mod.split(".", 1)[0] in {"requests", "urllib3", "http", "socket", "ssl"}:
            return repr(o)
        if hasattr(o, "to_dict"):
            return o.to_dict()
        if hasattr(o, "name") and hasattr(o, "value"):  # Enum-like
            return o.value
        if hasattr(o, "__dict__"):
            return o.__dict__
        return str(o)

    safe = _sanitize_json_keys(obj)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(safe, f, ensure_ascii=False, indent=2, default=_default)
    return path


# -------------------- Üst seviye API --------------------


def _finding_id(it: Dict[str, Any]) -> str:
    t = str(it.get("type") or "")
    u = str(it.get("url") or "")
    p = str(it.get("param") or "")
    m = str(it.get("method") or "")
    loc = str(it.get("location") or "")
    raw = (t + "|" + u + "|" + p + "|" + m + "|" + loc).encode("utf-8", "ignore")
    return hashlib.sha1(raw).hexdigest()[:12]


def _collect_http_proofs(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    arr = results.get("http_proof") or []
    if isinstance(arr, list):
        return [dict(x or {}) for x in arr]
    return []


def _pick_best_proof(f: Dict[str, Any], proofs: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    url = str(f.get("url") or "")
    m = str((f.get("method") or "GET")).upper()
    best = None
    for x in proofs:
        if str(x.get("url") or "") == url and str(x.get("method") or "").upper() == m:
            best = x
    if best is None:
        for x in proofs:
            if str(x.get("url") or "") == url:
                best = x
    return best


def _write_text(path: str, data: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return path


def _write_json(path: str, obj: Any) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    return path


def build_proofs(results: Dict[str, Any], out_dir: str) -> Dict[str, Any]:
    proofs_index: Dict[str, Dict[str, str]] = {}
    proofs = _collect_http_proofs(results)
    items = _dedupe_findings(_coerce_final(results))
    base = os.path.join(out_dir, "proofs")
    for it in items:
        fid = _finding_id(it)
        fdir = os.path.join(base, fid)
        os.makedirs(fdir, exist_ok=True)
        # request.txt / response.head.txt / timing.json
        best = _pick_best_proof(it, proofs)
        if best is not None:
            _write_text(os.path.join(fdir, "request.txt"), str(best.get("request") or ""))
            _write_text(os.path.join(fdir, "response.head.txt"), str(best.get("response_head") or ""))
            _write_json(os.path.join(fdir, "timing.json"),
                        {"url": best.get("url"), "method": best.get("method"), "status": best.get("status"),
                         "rt_ms": best.get("rt_ms")})
        else:
            # Minimal fallback using fields on the finding itself
            req = str(it.get("poc") or it.get("payload") or "")
            if not req:
                req = (str(it.get("method") or "GET") + " " + str(it.get("url") or ""))
            _write_text(os.path.join(fdir, "request.txt"), req)
            _write_text(os.path.join(fdir, "response.head.txt"), "")
            _write_json(os.path.join(fdir, "timing.json"), {"url": it.get("url"), "method": it.get("method") or "GET"})
        # oast.txt if exists
        oast_items = results.get("oast") or []
        if isinstance(oast_items, list):
            rels = []
            u = str(it.get("url") or "")
            for x in oast_items:
                if str((x or {}).get("url") or "") == u:
                    rels.append(x)
            if rels:
                _write_text(os.path.join(fdir, "oast.txt"), json.dumps(rels, ensure_ascii=False, indent=2))
        proofs_index[fid] = {"dir": fdir}
    return proofs_index


def _count_status(results: Dict[str, Any], code: int) -> int:
    n = 0
    for it in (results.get("http_timing") or []):
        if int(it.get("status") or 0) == int(code):
            n += 1
    return n


def build_summary(results: Dict[str, Any], proofs_index: Dict[str, Any]) -> Dict[str, Any]:
    counters = get_counters()
    rl = results.get("rate_limit_obs") or []
    abe = results.get("anti_block_event") or []
    cov = results.get("input_coverage") or []

    # Güven seviyesi ve ciddiyet özeti
    confidence_counts: Dict[str, int] = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    severity_counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    verified_count = 0
    all_findings = _coerce_final(results)
    for f in all_findings:
        conf = str(f.get("confidence") or "unknown").lower()
        if conf not in confidence_counts:
            conf = "unknown"
        confidence_counts[conf] += 1
        sev = str(f.get("severity") or "Info")
        sev = sev.capitalize() if sev.lower() not in ("critical",) else "Critical"
        if sev not in severity_counts:
            sev = "Info"
        severity_counts[sev] += 1
        if f.get("verified"):
            verified_count += 1

    total = len(all_findings)
    fp_rate_est = round(confidence_counts["low"] / total, 3) if total else 0.0

    return {
        "http": {
            "requests": int(counters.get("http_requests", 0)),
            "bytes": int(counters.get("http_bytes", 0)),
            "429_count": _count_status(results, 429),
            "403_count": _count_status(results, 403),
            "rate_limit_obs": len(rl),
            "anti_block_events": len(abe),
        },
        "coverage": cov,
        "artefacts": {"findings": len(proofs_index), "paths": proofs_index},
        "scan_meta": {
            "total_findings": total,
            "verified_findings": verified_count,
            "confidence_summary": confidence_counts,
            "severity_summary": severity_counts,
            "estimated_fp_rate": fp_rate_est,
        },
    }



# -------------------- CVSS/CWE Enrichment --------------------
_CVSS_DEFAULTS = {
    "critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.1
}

def _norm_sev_en(s: str) -> str:
    s = (s or "").strip().lower()
    if s in ("critical", "crit", "severe", "kritik"):
        return "critical"
    if s in ("high", "yüksek", "yuksek"):
        return "high"
    if s in ("medium", "med", "orta"):
        return "medium"
    if s in ("low", "düşük", "dusuk", "düsük"):
        return "low"
    return "info"

def _cvss_for_item(it: Dict[str, Any], cfg: Dict[str, Any] | None) -> dict:
    # Allow explicit override on item
    cvss = it.get("cvss")
    if isinstance(cvss, dict) and "score" in cvss:
        try_score = float(cvss.get("score")) if isinstance(cvss.get("score"), (int, float, str)) else None
        if try_score is not None:
            return {"score": try_score, "version": "3.1", "vector": cvss.get("vector") or ""}
    # Heuristic based on severity and rule-type
    sev = _norm_sev_en(str(it.get("severity") or "low"))
    score = _CVSS_DEFAULTS.get(sev, 3.1)
    rule = str(it.get("type") or it.get("title") or "").strip()
    # Optional tweak: give IDOR/SSRF/SQLi a small bump to align with common baselines
    if rule.upper() in ("IDOR", "SSRF", "SQL INJECTION", "SQLI"):
        score = max(score, 7.5 if sev in ("high","critical") else 6.5)
    return {"score": float(score), "version": "3.1", "vector": ""}

def _cwe_for_item(it: Dict[str, Any]) -> list[str]:
    rule = str(it.get("type") or it.get("title") or "").strip()
    reg = RULES_REGISTRY.get(rule) or {}
    cwe = reg.get("cwe") or []
    if isinstance(cwe, (list, tuple)):
        return [str(x) for x in cwe]
    if isinstance(cwe, str):
        return [cwe]
    return []

def _build_poc_curl(finding: Dict[str, Any]) -> str:
    """Her bulgu için hazır çalıştırılabilir curl komutu üretir."""
    url     = finding.get("url") or ""
    method  = (finding.get("method") or finding.get("http_method") or "GET").upper()
    param   = finding.get("parameter") or finding.get("param") or ""
    payload = finding.get("payload") or ""
    headers = finding.get("headers") or {}

    header_str = " ".join(f'-H "{k}: {v}"' for k, v in headers.items())

    if method == "POST":
        data_arg = f'-d "{param}={payload}"' if param else f'-d "{payload}"'
        return f'curl -sk -X POST "{url}" {header_str} {data_arg}'.strip()

    if param and payload and url:
        sep = "&" if "?" in url else "?"
        injected_url = f"{url}{sep}{param}={payload}"
        return f'curl -sk "{injected_url}" {header_str}'.strip()

    return f'curl -sk "{url}" {header_str}'.strip()


def enrich_cvss_cwe(results: Dict[str, Any], cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if not isinstance(results, dict):
        return results
    out = {k: (v[:] if isinstance(v, list) else (dict(v) if isinstance(v, dict) else v)) for k, v in results.items()}
    items = _iter_findings(out)
    for it in items:
        if "cvss" not in it or not isinstance(it.get("cvss"), dict):
            it["cvss"] = _cvss_for_item(it, cfg)
        if "cwe" not in it:
            it["cwe"] = _cwe_for_item(it)
        if "poc_curl" not in it:
            it["poc_curl"] = _build_poc_curl(it)
    # prefer to expose enriched list as 'final' for downstream exporters
    out["final"] = items
    return out
def perform_reporting(session, cfg: Dict, results: Dict, logger: 'logging.Logger|None'=None, **_kw) -> Dict:
    """Top-level reporting: write JSON, MD/HTML/SARIF/JUnit, charts, proofs, summary."""
    global _logger
    if logger is not None:
        _logger = logger
    # Output directory & formats
    rep_cfg = (cfg.get("reporting") or {}) if isinstance(cfg, dict) else {}
    out_dir = (rep_cfg.get("output_dir") or "output")
    fmts: List[str] = rep_cfg.get("formats") or ["md", "html"]
    written: Dict[str, str] = {}
    os.makedirs(out_dir, exist_ok=True)

    # JSON — results.json olarak yazılıyor (aşağıda), report.json alias
    # Çift yazımı önlemek için burada yalnızca path saklıyoruz
    written['json'] = os.path.join(out_dir, 'results.json')
    # Also persist HTTP metrics snapshot for CI/analysis
    try:
        from websecure.core.http import get_http_metrics
        metrics_payload = get_http_metrics()
        _json_dump(os.path.join(out_dir, 'metrics.json'), metrics_payload)
        written['metrics'] = os.path.join(out_dir, 'metrics.json')
    except (ImportError, AttributeError, OSError) as exc:
        _logger.debug(f"[Reporting] HTTP metrics yazılamadı: {exc!r}")

    # Attach payload metrics if not present
    if isinstance(results, dict) and "payload_metrics" not in results:
        results = dict(results)  # avoid in-place mutation from outside
        results["payload_metrics"] = export_payload_metrics()
    # CVSS/CWE Enrichment
    results = enrich_cvss_cwe(results, cfg)

    # ---- OWASP Top 10 Mapping + Compliance + Remediation ----
    try:
        items_for_owasp = _coerce_final(results)
        # Remediation enrichment (CWE + remediation text per finding)
        remediation_gen = RemediationGuideGenerator()
        enriched_items = remediation_gen.enrich_batch(items_for_owasp)
        if isinstance(results, dict) and enriched_items:
            results = dict(results)
            results["final"] = enriched_items

        # OWASP Top 10 mapping
        owasp_mapper = OWASPTop10Mapper()
        owasp_mapping = owasp_mapper.map(enriched_items)
        results["owasp_mapping"] = owasp_mapping

        # Compliance report (PCI-DSS, HIPAA, ISO 27001)
        compliance_builder = ComplianceReportBuilder()
        compliance_report = compliance_builder.build(owasp_mapping)
        results["compliance_report"] = compliance_report
    except Exception as _oc_exc:
        log_warn(f"[reporting] OWASP/Compliance/Remediation enrichment failed: {_oc_exc!r}")

    # Charts
    charts = _generate_charts(results or {}, out_dir)
    if charts and isinstance(results, dict):
        results = dict(results)
        results["charts"] = charts

    # E-phase enrichments
    if isinstance(results, dict) and isinstance(results.get("final"), list):
        results = dict(results)
        results["final"] = _e_autofill(results["final"])

    # Evidence bundle (optional side-car)
    _write_evidence_bundle(results, out_dir)

    # Base JSON (always)
    json_path = os.path.join(out_dir, "results.json")
    _json_dump(json_path, results)
    written["json"] = json_path

    # Markdown
    md = None
    if "md" in fmts:
        try:
            md = render_e_phase_markdown_report(results)
        except Exception as _md_exc:
            import traceback as _tb
            _logger.error(f"[Reporting] Markdown render hatası: {_md_exc!r}\n{_tb.format_exc()}")
            print(f"\n[!] RAPOR HATASI (Markdown): {_md_exc!r}")
            print(_tb.format_exc())
            md = f"# Rapor Hatası\n\n```\n{_tb.format_exc()}\n```"
        # Prepend banner image (copy asset to output/assets)
        out_assets = Path(out_dir) / "assets"
        out_assets.mkdir(parents=True, exist_ok=True)
        if BANNER_FILE:
            src_img = ASSETS_DIR / BANNER_FILE
            dst_img = out_assets / BANNER_FILE
            if src_img.exists():
                if (not dst_img.exists()) or (src_img.read_bytes() != dst_img.read_bytes()):
                    dst_img.write_bytes(src_img.read_bytes())
                md = f"![ZEMSEC](assets/{BANNER_FILE})" + md

        meta_node = (results.get("meta") if isinstance(results, dict) else {})
        if isinstance(meta_node, list):
            meta_node = next((x for x in meta_node if isinstance(x, dict)), {})
        meta_target = (meta_node.get("target") if isinstance(meta_node, dict) else "") or ""
        host = urlparse(str(meta_target)).hostname
        if not host:
            tls = results.get("tls_summary") or []
            if isinstance(tls, list) and tls and isinstance(tls[0], dict):
                host = tls[0].get("host")
        safe = _safe_host_for_filename("https://" + (host or "report"))
        report_path = os.path.join(out_dir, f"{safe}_report.md")
        _write(report_path, md)
        written["md"] = report_path

    # HTML (modern dashboard)
    if "html" in fmts:
        import importlib.util as _iul
        try:
            # render_html_dashboard is defined in this module (merged from html_dashboard)
            html = render_html_dashboard(results)
        except Exception as exc:
            log_warn(f"[reporting] HTML dashboard render failed, falling back to markdown: {exc!r}")
            # Fallback to legacy markdown conversion if module missing
            if md is None:
                mdtxt = render_markdown_report(results)
            else:
                mdtxt = md
            
            if _iul.find_spec("markdown") is not None:
                import markdown as _md
                html_body = _md.markdown(mdtxt, extensions=["tables", "fenced_code"])
            else:
                html_body = "<pre>" + (mdtxt.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")) + "</pre>"
            
            html = """<!doctype html><html><head><meta charset='utf-8'><title>WebSec Legacy Report</title><body>""" + html_body + "</body></html>"

        html_path = os.path.join(out_dir, "report.html")
        _write(html_path, html)
        written["html"] = html_path

    # SARIF
    if "sarif" in fmts:
        sarif_obj = to_sarif(results, tool_name="WebSecure")
        sarif_path = os.path.join(out_dir, "report.sarif.json")
        _json_dump(sarif_path, sarif_obj)
        written["sarif"] = sarif_path

    # JUnit
    if "junit" in fmts:
        suite_name = (rep_cfg.get("junit") or {}).get("suite_name") or "WebSecure"
        junit_xml = to_junit(results, suite_name=suite_name)
        junit_path = os.path.join(out_dir, "report.junit.xml")
        _write(junit_path, junit_xml)
        written["junit"] = junit_path

    # Delta (optional) + Vulnerability Trend Analysis
    delta_cfg = rep_cfg.get("delta") or {}
    if delta_cfg.get("enabled"):
        baseline = delta_cfg.get("baseline")
        base = {}
        if isinstance(baseline, str) and baseline and Path(baseline).exists():
            try_text = Path(baseline).read_text(encoding="utf-8")
            base = json.loads(try_text) if try_text else {}
        delta = _diff_findings(base, results)
        delta_path = os.path.join(out_dir, "delta.json")
        _json_dump(delta_path, delta)
        written["delta"] = delta_path

        # Vulnerability Trend Analysis (compare baseline vs current)
        try:
            trend_analyzer = VulnerabilityTrendAnalyzer()
            baseline_findings = _coerce_final(base)
            current_findings = _coerce_final(results)
            if baseline_findings and current_findings:
                trend = trend_analyzer.compare(baseline_findings, current_findings)
                results = dict(results)
                results["vulnerability_trend"] = trend
                _json_dump(os.path.join(out_dir, "trend.json"), trend)
                written["trend"] = os.path.join(out_dir, "trend.json")
        except Exception as _trend_exc:
            log_warn(f"[reporting] VulnerabilityTrendAnalyzer failed: {_trend_exc!r}")

    # Integrations & CI
    _send_integrations(cfg, results, out_dir)
    _apply_ci_gates(cfg, results, out_dir)

    # Proofs & summary
    proofs_idx = build_proofs(results, out_dir)
    summary = build_summary(results, proofs_idx)
    _json_dump(os.path.join(out_dir, "summary.json"), summary)
    written["summary"] = os.path.join(out_dir, "summary.json")

    out = dict(results)
    out["written"] = written
    out["summary"] = summary
    return out


def _sha256_bytes(b: bytes) -> str:
    import hashlib as _h
    return _h.sha256(b).hexdigest()


def _write_evidence_bundle(results: Dict, out_dir: str) -> Optional[str]:
    from pathlib import Path as _P
    ev_dir = _P(out_dir) / 'evidence'
    ev_dir.mkdir(parents=True, exist_ok=True)
    manifest = {'files': []}
    copied = 0
    # artifacts (accept both list[str] and list[dict] and dict{'files': [...]})
    _arts = results.get('artifacts') or []
    _items: list[dict] = []
    if isinstance(_arts, dict):
        _files = _arts.get('files') or []
        for _el in _files:
            if isinstance(_el, str):
                _items.append({'artifact_path': _el})
            elif isinstance(_el, dict):
                _items.append(_el)
        # also allow stray string paths under arbitrary keys
        for _k, _v in _arts.items():
            if isinstance(_v, str):
                _items.append({'artifact_path': _v})
    elif isinstance(_arts, list):
        for _el in _arts:
            if isinstance(_el, str):
                _items.append({'artifact_path': _el})
            elif isinstance(_el, dict):
                _items.append(_el)
    for it in _items:
        p = str(it.get('artifact_path') or '').strip()
        if not p:
            continue
        src = _P(p)
        if not src.exists():
            continue
        dst = ev_dir / src.name
        data = src.read_bytes()
        if (not dst.exists()) or dst.read_bytes() != data:
            dst.write_bytes(data)
        manifest['files'].append({'name': src.name, 'sha256': _sha256_bytes(data), 'kind': 'artifact'})
        copied += 1
    # verification curls
    ver = (results.get('verification') or [])
    if ver:
        vf = ev_dir / 'verification.ndjson'
        lines = []
        for v in ver:
            lines.append(json.dumps({'url': v.get('url'), 'method': v.get('method'), 'status': v.get('status'),
                                     'curl': (v.get('repro') or {}).get('curl', '')}))
        data = ('\n'.join(lines) + '\n').encode('utf-8')
        vf.write_bytes(data)
        manifest['files'].append({'name': vf.name, 'sha256': _sha256_bytes(data), 'kind': 'verification'})
        copied += 1
    # inputs summary
    inp = (results.get('inputs') or [])
    if inp:
        ip = ev_dir / 'inputs.ndjson'
        data = ('\n'.join(json.dumps(x) for x in inp) + '\n').encode('utf-8')
        ip.write_bytes(data)
        manifest['files'].append({'name': ip.name, 'sha256': _sha256_bytes(data), 'kind': 'inputs'})
        copied += 1
    # manifest
    mf = ev_dir / 'manifest.json'
    mdata = json.dumps(manifest, ensure_ascii=False, indent=2).encode('utf-8')
    mf.write_bytes(mdata)
    return str(ev_dir) if copied > 0 else None


# -------------------- SARIF / JUnit / Delta yardımcıları --------------------


# -------------------- Rule-ID Registry (Batch 7) --------------------
RULE_REGISTRY_DEFAULTS = {
    "SSRF": {"name": "Server-Side Request Forgery", "description": "Sunucu içinden dış kaynağa yetkisiz istek",
             "recommendation": "Ağ egress kontrolü, allowlist, metadata IP/host engelleme"},
    "XXE": {"name": "XML External Entity", "description": "Harici varlık çözümleme ile dosya/SSRF",
            "recommendation": "XXE disable, güvenli parser"},
    "GRAPHQL_RPC": {"name": "GraphQL RPC Issues", "description": "Zayıf şema/doğrulama, introspection açık",
                    "recommendation": "Şema sertleştirme, izin kontrolü"},
    "FILE_UPLOAD": {"name": "Insecure File Upload", "description": "Dosya tür/uzantı denetimi zayıf",
                    "recommendation": "MIME/magic doğrulama, izolasyon"},
    "JWT": {"name": "JWT Weakness", "description": "Zayıf anahtar/alg conf",
            "recommendation": "Güçlü imza, key management"},
    "NOSQLI": {"name": "NoSQL Injection", "description": "Sorgu nesnesine enjekte",
               "recommendation": "Parametrik sorgu, tip doğrulama"},
    "TLS": {"name": "TLS Misconfiguration", "description": "Zayıf sürüm/suite/HSTS yok",
            "recommendation": "TLS1.2+, HSTS, modern suites"},
    "HEADERS": {"name": "Missing Security Headers", "description": "Önerilen başlıklar eksik",
                "recommendation": "HSTS, CSP, XFO, Referrer-Policy"},
    "RATE_LIMIT": {"name": "Missing/Broken Rate Limit", "description": "İstek başına limit/koruma yok",
                   "recommendation": "IP/token bazlı limit, CAPTCHA"},
    "AUTHZ": {"name": "Authorization Bypass", "description": "Yetki yükseltme/IDOR",
              "recommendation": "Rol/nesne seviyesinde kontrol"},
    "OAST": {"name": "Out-of-Band Interaction", "description": "Dış servise istenmeyen istek",
             "recommendation": "Egress filtreleme, SSRF sertleştirme"},
}


def _rule_ns(cfg: dict | None) -> str:
    rep = (cfg or {}).get("reporting") if isinstance(cfg, dict) else None
    sar = rep.get("sarif") if isinstance(rep, dict) else None
    ns = sar.get("rule_namespace") if isinstance(sar, dict) else None
    return ns if isinstance(ns, str) and ns.strip() else "websecure"


def _mk_rule_id(rtype: str, cfg: dict | None) -> str:
    base = (rtype or "GEN").upper().replace(" ", "_").replace("-", "_")
    return f"{_rule_ns(cfg)}/{base}"


def _build_registry(items: list[dict], cfg: dict | None) -> dict:
    reg = {k.upper(): dict(v) for k, v in RULE_REGISTRY_DEFAULTS.items()}
    for it in items or []:
        t = str(it.get("type") or it.get("title") or "GEN").upper().replace(" ", "_").replace("-", "_")
        if t not in reg:
            reg[t] = {
                "name": t.title().replace("_", " "),
                "description": it.get("description") or it.get("reason") or "",
                "recommendation": it.get("recommendation") or "",
            }
    return reg


def _map_severity_to_level(sev: str) -> str:
    s = (sev or "").lower()
    if s in ("Critical", "critical"): return "error"
    if s in ("High", "high"):     return "error"
    if s in ("Medium", "medium"):     return "warning"
    if s in ("Low", "low"):       return "note"
    return "note"


def _diff_findings(base: Dict, cur: Dict) -> Dict:
    def _key(x: Dict) -> str:
        return f"{x.get('type')}|{x.get('url')}|{x.get('param')}|{x.get('location')}"

    bset = {_key(x) for x in _coerce_final(base)}
    cset = {_key(x) for x in _coerce_final(cur)}
    return {
        "new": sorted(list(cset - bset)),
        "gone": sorted(list(bset - cset)),
        "same": sorted(list(cset & bset)),
    }


# -------------------- Flush (auto-report) --------------------
def _try_load_config() -> Dict:
    # Öncelik: core.utils.load_config (varsa)
    from importlib.util import find_spec as _ilu_find_spec
    from importlib import import_module as _ilu_import_module

    if _ilu_find_spec("websecure.core.utils") is not None:
        mod = _ilu_import_module("websecure.core.utils")
        fn = getattr(mod, "load_config", None)
        if callable(fn):
            c = fn()
            if c:
                return c

    # İkinci tercih: config.json mevcutsa
    p = Path("config.json")
    if p.exists() and p.is_file():
        txt = p.read_text(encoding="utf-8", errors="ignore").strip()
        if txt.startswith("{") or txt.startswith("["):
            return json.loads(txt)

    # Son çare: minimal varsayılan
    return {"reporting": {"formats": ["md"], "output_dir": "output"}}


def flush(session=None, cfg: Dict | None = None, results: Dict | None = None) -> Dict:
    _cfg = cfg or _try_load_config()
    _results = results or get_results()
    out = perform_reporting(session, _cfg, _results)
    return out or {}



# perform_reporting_and_integration kaldırıldı — perform_reporting() direkt kullanılır




# -------------------- Integrations & CI --------------------
def _send_integrations(cfg: Dict, results: Dict, out_dir: str) -> None:
    integ = (cfg.get("integrations") or {})
    wh = integ.get("webhook") or {}
    if not (wh.get("enabled") and wh.get("url")):
        return

    from importlib.util import find_spec
    from importlib import import_module
    from urllib.parse import urlparse
    import json as _json

    # 'requests' opsiyonel — yoksa sessizce atla (akışı bozma)
    if find_spec("requests") is None:
        return

    url = str(wh.get("url")).strip()
    u = urlparse(url)
    # Geçerli HTTP(S) URL değilse atla
    if u.scheme not in ("http", "https") or not u.netloc:
        return

    headers = wh.get("headers") if isinstance(wh.get("headers"), dict) else {}
    # Content-Type yoksa ekle
    if not any(k.lower() == "content-type" for k in headers.keys()):
        headers["Content-Type"] = "application/json"

    body = {
        "results": results,
        "summary": {"counts": {k: len(v) for k, v in results.items() if isinstance(v, list)}},
    }

    requests = import_module("requests")
    data = _json.dumps(body, ensure_ascii=False).encode("utf-8")
    # Ağ hataları bastırılmaz; üst katmana yükselir.
    requests.post(url, headers=headers, data=data, timeout=10)


def _severity_rank(s: str) -> int:
    s = (s or "").lower()
    order = {
        "info": 0, "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return order.get(s, 0)


def _apply_ci_gates(cfg: Dict, results: Dict, out_dir: str) -> None:

    ci = (cfg.get("ci") or {})
    fail_on = (ci.get("fail_on") or {})
    sev_min = (fail_on.get("severity_min") or "Medium").lower()
    new_only = bool(fail_on.get("new_findings", False))

    items = _coerce_final(results)

    if new_only:
        delta_path = os.path.join(out_dir, "delta.json")
        if os.path.exists(delta_path) and os.path.isfile(delta_path):
            with open(delta_path, "r", encoding="utf-8") as _f:
                txt = _f.read().strip()
            # Basit doğrulama: JSON gibi görünmüyorsa filtre uygulama
            if txt.startswith("{") or txt.startswith("["):
                d = json.loads(txt)
                keyed_new = d.get("new") or []

                def _is_new(it: Dict) -> bool:
                    key = f"{it.get('type')}|{it.get('url')}|{it.get('param')}|{it.get('location')}"
                    return key in keyed_new

                items = [it for it in items if _is_new(it)]

    rank_min = _severity_rank(sev_min)
    viol = [it for it in items if _severity_rank((it.get("severity") or "Info").lower()) >= rank_min]

    if viol:
        _write(os.path.join(out_dir, "ci.FAIL"), "\n".join([str(v) for v in viol]))
    else:
        _write(os.path.join(out_dir, "ci.OK"), "ok")


# ===================== CI Yardımcıları (public) =====================
# should_fail_ci is defined at the top of this module (canonical, TR+EN aware).


def summarize_by_severity(results: Dict) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    items = []
    if isinstance(results, dict) and "final" in results and isinstance(results["final"], list):
        items = list(results["final"])
    else:
        for bucket, arr in (results or {}).items():
            if not isinstance(arr, list):
                continue
            for it in arr:
                if isinstance(it, dict):
                    items.append(it)
    for it in items:
        sev = _norm_sev_en(it.get("severity") or "")
        if sev == "critical":
            counts["Critical"] += 1
        elif sev == "high":
            counts["High"] += 1
        elif sev == "medium":
            counts["Medium"] += 1
        elif sev == "low":
            counts["Low"] += 1
        else:
            counts["Informational"] += 1
    return counts


def to_markdown_summary(results: Dict) -> str:
    c = summarize_by_severity(results)
    return (
        "| Severity | Count |\n|---|---:|\n"
        f"| Critical | {c['Critical']} |\n"
        f"| High | {c['High']} |\n"
        f"| Medium | {c['Medium']} |\n"
        f"| Low | {c['Low']} |\n"
        f"| Informational | {c['Informational']} |\n"
    )


# ===================== SARIF / JUnit Export =====================

def _iter_findings(results: Dict) -> list[Dict]:
    """
    'results' içinde hangi kovada olursa olsun bulgu benzeri elemanları normalize ederek döndürür.
    - Her eleman _normalize_item ile sözlüğe çevrilir.
    - 'final' kovası varsa öncelik verilir.
    - Liste olmayan ama sözlük olan kova değerleri tek kayıt gibi ele alınır.
    - Hatalı/uygunsuz öğeler (str, tek elemanlı tuple vs.) yutulmaz; normalize edilip 'items' alanıyla taşınır.
    """
    items: list[dict] = []

    def _push(bucket: str, it):
        it2 = _normalize_item(it)
        it2["_bucket"] = bucket
        items.append(it2)

    if isinstance(results, dict) and isinstance(results.get("final"), list):
        for it in results.get("final") or []:
            _push("final", it)
        return items

    if isinstance(results, dict):
        for bucket, arr in (results or {}).items():
            # Bazı kovalarda özet/meta olabilir; yine de normalize ederek geçiriyoruz
            if isinstance(arr, list):
                for it in arr or []:
                    _push(bucket, it)
            elif isinstance(arr, dict):
                _push(bucket, arr)
            else:
                # tekil skaler/tuple vs. — normalize ederek geçir
                _push(bucket, arr)
    return items

# CWE mapping for known vulnerability types — used in SARIF rule tags
_CWE_MAP: Dict[str, str] = {
    "SQL Injection":              "CWE-89",
    "SQLi":                       "CWE-89",
    "Reflected XSS":              "CWE-79",
    "Stored XSS":                 "CWE-79",
    "DOM XSS":                    "CWE-79",
    "XSS":                        "CWE-79",
    "OS Command Injection":       "CWE-78",
    "CMDI":                       "CWE-78",
    "Path Traversal":             "CWE-22",
    "LFI":                        "CWE-22",
    "SSRF":                       "CWE-918",
    "XXE":                        "CWE-611",
    "SSTI":                       "CWE-94",
    "Open Redirect":              "CWE-601",
    "CSRF":                       "CWE-352",
    "IDOR":                       "CWE-639",
    "Insecure Deserialization":   "CWE-502",
    "Broken Authentication":      "CWE-287",
    "Sensitive Data Exposure":    "CWE-200",
    "Security Misconfiguration":  "CWE-16",
    "JWT":                        "CWE-347",
    "NoSQLi":                     "CWE-943",
    "Race Condition":             "CWE-362",
    "Request Smuggling":          "CWE-444",
    "CRLF Injection":             "CWE-93",
    "Prototype Pollution":        "CWE-1321",
}

def _cwe_for(rule_id: str) -> Optional[str]:
    """Return the CWE ID for a rule, matching on substring."""
    rid_upper = rule_id.upper()
    for key, cwe in _CWE_MAP.items():
        if key.upper() in rid_upper or rid_upper in key.upper():
            return cwe
    return None

def to_sarif(results: Dict, tool_name: str = "WebSec") -> Dict:
    items = _iter_findings(results)
    rule_ids = sorted(set(str(i.get("type") or i.get("title") or "finding") for i in items))

    def _make_rule(rid: str) -> Dict:
        cwe = _cwe_for(rid)
        rule: Dict = {
            "id":               rid,
            "name":             rid.replace(" ", "").replace("(", "").replace(")", ""),
            "shortDescription": {"text": rid},
            "fullDescription":  {"text": f"WebSecure detected: {rid}"},
            "help": {
                "text":     f"Vulnerability: {rid}" + (f" ({cwe})" if cwe else ""),
                "markdown": f"**{rid}**" + (f"\n\nCWE: [{cwe}](https://cwe.mitre.org/data/definitions/{cwe[4:]}.html)" if cwe else ""),
            },
            "properties": {
                "tags": ([cwe] if cwe else []) + ["security", "websecure"],
            },
        }
        if cwe:
            rule["relationships"] = [{
                "target": {
                    "id":    cwe,
                    "index": 0,
                    "toolComponent": {"name": "CWE", "index": 0},
                },
                "kinds": ["superset"],
            }]
        return rule

    rules = [_make_rule(rid) for rid in rule_ids]

    def _sev_to_level(s: str) -> str:
        s = (s or "").lower()
        if s in ("Critical", "High", "high", "critical"): return "error"
        if s in ("Medium", "medium"): return "warning"
        return "note"

    sarif_results = []
    for it in items:
        rid   = str(it.get("type") or it.get("title") or "finding")
        msg   = it.get("description") or it.get("evidence") or it.get("title") or rid
        loc   = it.get("url") or it.get("location") or "n/a"
        param = it.get("param") or ""
        sev   = it.get("severity") or "Info"

        # Parse URL for logicalLocation
        try:
            _parsed = urlparse(loc)
            logical_name = _parsed.path or loc
        except Exception:
            logical_name = loc

        entry: Dict = {
            "ruleId":  rid,
            "level":   _sev_to_level(sev),
            "message": {
                "text": (
                    f"{msg}"
                    + (f" | param: {param}" if param else "")
                    + (f" | severity: {sev}" if sev else "")
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri":         loc,
                        "uriBaseId":   "%SRCROOT%",
                        "description": {"text": f"Vulnerable endpoint: {loc}"},
                    },
                    "region": {
                        "startLine":   1,
                        "startColumn": 1,
                        "message":     {"text": f"Parameter: {param}" if param else "Endpoint"},
                    },
                },
                "logicalLocations": [{
                    "name":             logical_name,
                    "fullyQualifiedName": loc,
                    "kind":             "url",
                }],
            }],
            "fingerprints": {
                "primaryLocationLineHash/v1": str(hash(f"{rid}:{loc}:{param}") & 0xFFFFFFFF),
            },
            "properties": {
                "severity":    sev,
                "param":       param,
                "payload":     str(it.get("payload") or ""),
                "confidence":  str(it.get("confidence") or ""),
                "cwe":         _cwe_for(rid) or "",
            },
        }
        sarif_results.append(entry)

    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name":             tool_name,
                    "version":          "2.5.0",
                    "informationUri":   "https://github.com/Aslhkoc/WebSecure",
                    "rules":            rules,
                    "supportedTaxonomies": [{
                        "name":  "CWE",
                        "index": 0,
                        "guid":  "1B24E81E-B1B6-4F89-B3A9-E6CCCDCEA79E",
                    }],
                }
            },
            "results":  sarif_results,
            "taxonomies": [{
                "name":             "CWE",
                "version":          "4.13",
                "releaseDateUtc":   "2023-10-26",
                "guid":             "1B24E81E-B1B6-4F89-B3A9-E6CCCDCEA79E",
                "informationUri":   "https://cwe.mitre.org",
                "taxa":             [],
                "isComprehensive":  False,
            }],
        }]
    }


def to_junit(results: Dict, suite_name: str = "websec") -> str:
    import xml.sax.saxutils as sx
    items = _iter_findings(results)
    total = len(items)
    errors = sum(1 for i in items if str(i.get("severity", "")).lower() in ("critical", "high"))
    failures = sum(1 for i in items if str(i.get("severity", "")).lower() == "medium")
    skipped = 0
    parts = []
    parts.append(
        f"<testsuite name='{sx.escape(suite_name)}' tests='{total}' errors='{errors}' failures='{failures}' skipped='{skipped}'>")
    for i in items:
        name = sx.escape(str(i.get("type") or i.get("title") or "finding"))
        classname = sx.escape(str(i.get("_bucket") or "findings"))
        msg = sx.escape(str(i.get("description") or i.get("title") or ""))
        sev = str(i.get("severity", "")).lower()
        parts.append(f"  <testcase classname='{classname}' name='{name}'>")
        if sev in ("critical", "high"):
            parts.append(f"    <error message='{name}'><![CDATA[{msg}]]></error>")
        elif sev == "medium":
            parts.append(f"    <failure message='{name}'><![CDATA[{msg}]]></failure>")
        parts.append("  </testcase>")
    parts.append("</testsuite>")
    return "\n".join(parts)


_plan_logs = []


def add_plan_log(phase_id: str, step: str, data: dict):
    _plan_logs.append({"phase": phase_id, "step": step, "data": data, "ts": datetime.now(timezone.utc).isoformat() + "Z"})


def get_plan_logs():
    return list(_plan_logs)


def attach_oast_evidence(result: dict, events):
    if not events:
        return result
    # Guard: ensure evidence is always a dict before updating
    if not isinstance(result.get("evidence"), dict):
        result["evidence"] = {}
    ev = result["evidence"]
    ev["oast_events"] = events
    return result


# -------- Auth-Gap yardımcıları --------
def _path_bucket(u: str) -> str:
    from urllib.parse import urlparse

    s = (u or "")
    path = urlparse(s).path or "/"

    # İlk segmenti al ("/foo/bar" -> "/foo", "foo" -> "/")
    seg = path.split("/", 2)[1] if "/" in path[1:] else ""
    return "/" + (seg or "")


def _group_paths_for_auth_gap(items: list[dict]) -> list[dict]:
    if not items: return []
    buckets = {}
    for it in items:
        u = str(it.get("url") or "")
        st = int(it.get("status") or 0)
        b = _path_bucket(u)
        k = (b, st)
        buckets.setdefault(k, 0)
        buckets[k] += 1
    out = []
    for (b, st), cnt in sorted(buckets.items(), key=lambda x: (-x[1], x[0])):
        out.append({"bucket": b, "status": st, "count": cnt})
    return out


def _summarize_auth_gap(results: Dict[str, Any]) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = list(results.get("auth_gap") or [])
    by_class = {"waf": 0, "auth": 0, "rate-limit": 0, "unknown": 0}
    for it in items:
        c = str(it.get("class") or "unknown")
        by_class[c] = by_class.get(c, 0) + 1
    top_urls = {}
    for it in items:
        u = it.get("url")
        if not u: continue
        top_urls[u] = top_urls.get(u, 0) + 1
    top = sorted(top_urls.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return {"total": len(items), "by_class": by_class, "top_urls": top}


def _summarize_public_surface(results: Dict[str, Any]) -> Dict[str, Any]:
    eps = list(set(results.get("endpoints") or []))
    js_hints = list((results.get("artifacts") or {}).get("js_hints") or []) if isinstance(results.get("artifacts"), dict) else []
    js_candidates = list((results.get("artifacts") or {}).get("js_candidates") or []) if isinstance(results.get("artifacts"), dict) else []
    return {"endpoints": len(eps), "js_hints": len(js_hints), "js_candidates": len(js_candidates)}


def finalize_addendum(results: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    out_dir = ((cfg.get("reporting") or {}).get("output_dir") or "output")
    sections = {
        "auth_coverage_delta": _summarize_auth_gap(results),
        "public_surface": _summarize_public_surface(results),
    }
    sections['egress_health'] = (results.get('egress_health') or {})

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    md = ["# WebSecure Report — Addendum",
          "## Auth Coverage Delta",
          f"- Toplam 401/403/429 olayı: {sections['auth_coverage_delta']['total']}",
          f"- Sınıflar: {json.dumps(sections['auth_coverage_delta']['by_class'])}",
          "### En çok tetiklenen ilk 10 URL:"]
    for u, n in sections["auth_coverage_delta"]["top_urls"]:
        md.append(f"  - {u} — {n}")
    md.append("\n## Public Surface Summary")
    md.append(f"- Unique endpoints: {sections['public_surface']['endpoints']}")
    md.append(f"- JS hints: {sections['public_surface']['js_hints']}")
    md.append(f"- JS candidates: {sections['public_surface']['js_candidates']}")
    md_path = str(Path(out_dir, "report_addendum.md"))
    json_path = str(Path(out_dir, "report_addendum.json"))
    Path(md_path).write_text("\n".join(md), encoding="utf-8")
    Path(json_path).write_text(json.dumps(sections, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"written": {"addendum_md": md_path, "addendum_json": json_path}}


# -------------------- Lightweight Counters (thread-safe) --------------------
_counters_lock = threading.RLock()
_counters: Dict[str, int] = {}


def counters_inc(name: str, delta: int = 1) -> None:
    if not name:
        return
    with _counters_lock:
        _counters[name] = int(_counters.get(name, 0)) + int(delta or 0)


def counters_add_bytes(n: int) -> None:
    s = str(n).strip()
    b = int(s) if (s and s.lstrip("+-").isdigit()) else 0
    counters_inc("http_bytes", b)


def counters_snapshot() -> Dict[str, int]:
    with _counters_lock:
        return dict(_counters)


def get_counters() -> Dict[str, int]:
    return counters_snapshot()


def counters_reset() -> None:
    with _counters_lock:
        _counters.clear()


def _build_type_counts(items: List[Dict]) -> Dict[str, Dict[str, int]]:
    by_type: Dict[str, Dict[str, int]] = {}
    for it in (items or []):
        t = str(it.get("type") or "GEN").upper()
        s = _norm_sev_tr(it.get("severity"))
        d = by_type.setdefault(t, {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0})
        d[s] = d.get(s, 0) + 1
    return by_type


def _gen_mermaid_pie(title: str, data: Dict[str, int]) -> str:
    total = 0
    for v in data.values():
        sv = str(v).strip()
        total += int(sv) if (sv and sv.lstrip("+-").isdigit()) else 0
    if total <= 0:
        return "> (Grafik için yeterli veri yok)"

    lines = ["```mermaid", "pie title " + title]
    for k, v in data.items():
        sv = str(v).strip()
        iv = int(sv) if (sv and sv.lstrip("+-").isdigit()) else 0
        if iv:
            lines.append(f'  "{k}" : {iv}')
    lines.append("```")
    return "\n".join(lines)


def _gen_curl_for_finding(it: Dict) -> str:
    url = str(it.get("url") or it.get("location") or "http://example.test/")
    method = str(it.get("method") or "GET").upper()
    payload = None
    pl = it.get("payloads")
    if isinstance(pl, list) and pl:
        payload = pl[0]
    elif isinstance(it.get("evidence"), dict):
        ev = it.get("evidence") or {}
        pv = ev.get("payload") or ev.get("value")
        if pv is not None:
            payload = pv
    if method in ("GET", "HEAD"):
        if it.get("param") and payload is not None:
            from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
            u = urlsplit(url)
            q = dict(parse_qsl(u.query, keep_blank_values=True))
            q[str(it.get("param"))] = str(payload)
            url = urlunsplit((u.scheme, u.netloc, u.path, urlencode(q), u.fragment))
        return f"curl -i -X {method} '{url}'"
    body = '' if payload is None else str(payload).replace("'", "'\\''")
    return f"curl -i -X {method} '{url}' -d '{body}'"


def _render_risk_matrix(items: List[Dict]) -> str:
    by_type = _build_type_counts(items)
    totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for d in by_type.values():
        for k in list(totals.keys()):
            totals[k] += int(d.get(k, 0) or 0)
    lines = []
    lines.append("## Risk Matrix")
    lines.append("| Type | Critical | High | Medium | Low | Info | Total |")
    lines.append("|-|-:|-:|-:|-:|-:|-:|")
    for t, d in sorted(by_type.items(), key=lambda kv: (-kv[1].get("Critical", 0), -kv[1].get("High", 0), kv[0])):
        tot = sum(int(d.get(k, 0) or 0) for k in ("Critical", "High", "Medium", "Low", "Info"))
        lines.append(
            f"| {t} | {d.get('Critical', 0)} | {d.get('High', 0)} | {d.get('Medium', 0)} | {d.get('Low', 0)} | {d.get('Info', 0)} | {tot} |")
    lines.append(
        f"| **Total** | **{totals['Critical']}** | **{totals['High']}** | **{totals['Medium']}** | **{totals['Low']}** | **{totals['Info']}** | **{sum(totals.values())}** |")
    lines.append("")
    lines.append(_gen_mermaid_pie("Findings by Severity", totals))
    return "\n".join(lines)


def _render_scanned_areas(results: Dict) -> str:
    lines = []
    lines.append("## Taranan Alanlar / Modüller")
    pt = results.get("phase_timings") or {}
    if pt:
        lines.append("| Faz | Süre (sn) |")
        lines.append("|-|-:|")
        for k in sorted(pt.keys()):
            v = pt.get(k)
            lines.append(f"| {k} | {v} |")
    buckets = []
    for k, v in (results or {}).items():
        if isinstance(v, list) and k not in ('final',):
            buckets.append(k)
    if buckets:
        lines.append("")
        lines.append("**Toplanan veri kovaları:** " + ", ".join(sorted(buckets)))
    cov = results.get("coverage_summary") or {}
    if cov:
        lines.append("")
        lines.append("### Kapsam Özeti")
        lines.append("| Metrik | Değer |")
        lines.append("|-|-:|")
        keys = ("crawled_pages", "crawl_endpoints", "content_discovery_endpoints", "total_unique_endpoints")
        for k in keys:
            if k in cov:
                lines.append(f"| {k} | {cov.get(k)} |")
    return "\n".join(lines)


def _render_exploit_playbook(items: List[Dict]) -> str:
    krit = []
    for i in (items or []):
        if _sev_rank(i.get('severity')) >= 2:
            krit.append(i)
    if not krit:
        return ""
    # Sort by severity desc, then by score desc
    krit = sorted(krit, key=lambda x: (-_sev_rank(x.get('severity')), -float(x.get('score') or 0)))
    lines = []
    lines.append("## Exploit Playbook (PoC ve Adımlar)")
    for idx, it in enumerate(krit, 1):
        t = str(it.get('type') or 'GEN').upper()
        sev = _norm_sev_en(it.get('severity'))
        url = it.get('url') or it.get('location') or ''
        param = it.get('param') or ''
        reason = it.get('reason') or it.get('description') or ''
        lines.append(f"### {idx}. {t} • {sev}")
        lines.append(f"- Hedef: `{url}`  • Param: `{param}`  • Method: `{it.get('method') or 'GET'}`")
        if reason:
            lines.append(f"- Anlam: {reason}")
        if it.get('authenticated'):
            lines.append("- Durum: **Kimlikli** koşulda tetikleniyor.")
        if it.get('auth_only'):
            lines.append("- Not: Sadece kimlikli kullanıcıya açık uç.")
        sim = it.get('similar_params')
        if sim is not None:
            lines.append(f"- Benzer Parametreler: `{json.dumps(sim, ensure_ascii=False)}`")
        pls = it.get('payloads')
        if isinstance(pls, list) and pls:
            sample = pls[:3]
            lines.append("- Örnek Payloadlar:")
            for p in sample:
                lines.append(f"  - `{str(p)}`")
        poc_block = str(it.get('poc') or '').strip()
        if poc_block:
            lines.append("#### PoC (ham)")
            lines.append("```bash")
            lines.append(poc_block if len(poc_block) <= 4000 else poc_block[:4000] + "...")
            lines.append("```")

        # Plan C: structured PoC blocks
        pm = it.get("poc_multi") or {}
        if isinstance(pm, dict) and pm:
            lines.append("")
            lines.append("**PoC (Detaylı)**")
            for name in ["curl", "httpie", "python", "node", "powershell", "raw"]:
                val = pm.get(name)
                if isinstance(val, str) and val.strip():
                    lines.append(f"<details><summary>{name}</summary>")
                    lines.append("")
                    fence = "```powershell" if name == "powershell" else ("```http" if name == "raw" else "```")
                    lines.append(fence)
                    lines.append(val.strip())
                    lines.append("```")
                    lines.append("</details>")
        curl_cmd = _gen_curl_for_finding(it)
        if curl_cmd:
            lines.append("#### PoC (curl)")
            lines.append("```bash")
            lines.append(curl_cmd)
            lines.append("```")

    return "\n".join(lines)


# Fallback: if not wired above, enrich overview via direct call from caller.


def add_egress_health(result: dict, sections: dict | None = None, md: list | None = None) -> None:
    # Kovaya ekle
    add_result('egress_health', result)
    # İsteğe bağlı render: sections/md sağlanırsa tablo satırlarını üret
    if sections is None or md is None:
        return
    eh = sections.get('egress_health') or {}
    obs = list((eh.get('observations') or [])) if isinstance(eh, dict) else []
    if not obs:
        return
    md.append("## Egress Health")
    md.append("| Endpoint | Status | IP |")
    md.append("|-|-|-|")
    for it in obs:
        ep = str((it or {}).get('endpoint') or '')
        st = str((it or {}).get('code') or '')
        ip = str((it or {}).get('ip') or '')
        md.append(f"| {ep} | {st} | {ip} |")
    md.append("")


# ===================== E-FAZI RAPORLAMA (Dil & Yapı) =====================

def _e_autofill_payload_sample(it: Dict[str, Any]) -> str:
    # payload_sample türetimi: payloads -> payload -> poc -> evidence
    if isinstance(it.get("payload_sample"), str) and it.get("payload_sample"):
        return str(it.get("payload_sample"))
    plds = it.get("payloads")
    if isinstance(plds, list) and plds:
        s = str(plds[0])
        return s[:400]
    if isinstance(plds, dict) and plds:
        # first value
        first_val = next(iter(plds.values()))
        s = str(first_val)
        return s[:400]
    p = it.get("payload") or it.get("poc") or ""
    if isinstance(p, (dict, list)):
        p = json.dumps(p, ensure_ascii=False)
    s = str(p or "")
    if not s and isinstance(it.get("evidence"), dict):
        ev = it["evidence"]
        if "request" in ev:
            s = str(ev.get("request") or "")
        elif "raw" in ev:
            s = str(ev.get("raw") or "")
    return s[:400] if s else ""


def _e_autofill_repro_steps(it: Dict[str, Any]) -> list[str]:
    # Basit yeniden üretim adımları: HTTP method + URL + param/payload
    steps: list[str] = []
    m = str(it.get("method") or "GET").upper()
    u = str(it.get("url") or it.get("location") or "")
    pr = str(it.get("param") or "")
    payload = _e_autofill_payload_sample(it)
    if u:
        steps.append(f"1) {m} {u}")
    if pr:
        steps.append(f"2) Parametre: {pr}")
    if payload:
        steps.append(f"3) Payload/Poc uygula: {payload}")
    ev = it.get("evidence") or {}
    if isinstance(ev, dict) and (ev.get("callback_type") or ev.get("indicator")):
        ind = ev.get("indicator") or ev.get("callback_type")
        steps.append(f"4) Doğrulama: Gözlenen belirti -> {ind}")
    return steps


def _e_autofill(items: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    out = []
    for it in items or []:
        d = dict(it or {})
        d.setdefault("payload_sample", _e_autofill_payload_sample(d))
        if not d.get("repro_steps"):
            d["repro_steps"] = _e_autofill_repro_steps(d)
        out.append(d)
    return out


def _e_table_engelleme(results: Dict[str, Any]) -> str:
    rl = results.get("rate_limit_obs") or []
    abe = results.get("anti_block_event") or []
    http_skipped = results.get("http_skipped") or []
    rows = []
    for r in rl:
        rows.append(["rate_limit", str(r.get("url") or ""), str(r.get("status") or ""),
                     str(r.get("retry_after") or r.get("window") or "")])
    for a in abe:
        rows.append(["anti_block", str(a.get("kind") or a.get("reason") or ""), str(a.get("url") or ""),
                     str(a.get("action") or "")])
    for s in http_skipped:
        rows.append(["http_skipped", str(s.get("reason") or ""), str(s.get("url") or ""), "-"])
    if not rows:
        return "_Engelleme olayına rastlanmadı._"
    lines = ["| Tür | URL/Detay | Kod | Aksiyon/Zaman |", "|-|-|-|-|"]
    for t, u, k, ra in rows[:200]:
        lines.append(f"| {t} | {u} | {k} | {ra} |")
    return "\n".join(lines)


def _e_table_input_coverage(results: Dict[str, Any]) -> str:
    pub = results.get("public_surface") or []
    crawl = results.get("crawl_summary") or {}
    endpoints = int(crawl.get("endpoints") or 0)
    forms = int(crawl.get("forms") or 0)
    inputs = int(crawl.get("inputs") or 0)
    lines = ["| Alan | Değer |", "|-|-|"]
    lines.append(f"| Keşfedilen endpoint | {endpoints} |")
    lines.append(f"| Form sayısı | {forms} |")
    lines.append(f"| Input alanı | {inputs} |")
    lines.append(f"| Public Surface kayıtları | {len(pub)} |")
    return "\n".join(lines)


def _e_table_oast(results: Dict[str, Any]) -> str:
    items = results.get("final") or []
    rows = []
    for it in items:
        if not isinstance(it, dict):
            continue
        ev = it.get("evidence") or {}
        if not isinstance(ev, dict):
            ev = {}
        cb = ev.get("callback_type") or it.get("callback_type")
        if cb:
            rows.append([str(cb), str(it.get("type") or ""), str(it.get("url") or ""), str(it.get("param") or "")])
    if not rows:
        return "_OAST etkileşimi kaydedilmedi._"
    lines = ["| Callback | Tür | URL | Param |", "|-|-|-|-|"]
    for cb, t, u, p in rows[:200]:
        lines.append(f"| {cb} | {t} | {u} | {p} |")
    return "\n".join(lines)


def _e_table_ports(results: Dict) -> str:
    """
    Nmap sonuçlarını tam detayla render eder:
    Port | Proto | Servis | Ürün/Versiyon | NSE Script Çıktıları | CPE | OS
    """

    def _as_int(x):
        if isinstance(x, bool):
            return None
        if isinstance(x, int):
            return x
        if isinstance(x, str):
            s = x.strip()
            if s and (s.isdigit() or (s[0] in "+-" and s[1:].isdigit())):
                return int(s)
        return None

    def _script_highlights(scripts: dict) -> str:
        """NSE scriptlerinden en önemli bilgileri tek satıra toplar."""
        if not isinstance(scripts, dict):
            return ""
        parts = []
        # Önemli scriptler sırayla
        for key in ("http-title", "http-server-header", "banner", "ssl-cert",
                    "ssh-hostkey", "ftp-anon", "smtp-commands",
                    "ssl-heartbleed", "ssl-poodle", "ssl-dh-params",
                    "http-auth-finder", "http-methods"):
            val = scripts.get(key, "")
            if not val:
                continue
            # İlk satır yeterli
            first_line = val.strip().split("\n")[0].strip()
            if first_line:
                parts.append(f"**{key}**: {first_line[:120]}")
        # Vuln scriptleri — varsa ekle
        for k, v in scripts.items():
            if k not in parts and v and any(w in v.lower() for w in ("vuln", "vulnerable", "cve-", "exploit")):
                first_line = v.strip().split("\n")[0].strip()
                parts.append(f"[!] **{k}**: {first_line[:120]}")
        return " | ".join(parts)

    rows: list[dict] = []

    # nmap bucket'ı > port_scan bucket'ı
    scan_list = results.get("nmap") or results.get("port_scan") or []

    if isinstance(scan_list, list) and scan_list:
        for it in scan_list:
            if not isinstance(it, dict):
                continue
            port = _as_int(it.get("port"))
            if port is None:
                continue
            product = str(it.get("product") or "")
            version = str(it.get("version") or "")
            pv = (product + " " + version).strip()
            cpe = it.get("cpe") or []
            cpe_str = ", ".join(cpe[:2]) if cpe else ""
            rows.append({
                "host":    str(it.get("host") or it.get("ip") or ""),
                "port":    port,
                "proto":   str(it.get("proto") or it.get("protocol") or "tcp"),
                "service": str(it.get("service") or ""),
                "pv":      pv,
                "scripts": _script_highlights(it.get("scripts") or {}),
                "cpe":     cpe_str,
                "os":      str(it.get("os_guess") or ""),
            })
    else:
        # Özet mod fallback
        summ = results.get("port_scan_summary") or {}
        opened = summ.get("open") or summ.get("open_ports") or []
        host_default = str(summ.get("host") or "")
        for it in opened:
            port = _as_int(it.get("port") if isinstance(it, dict) else it)
            if port is None:
                continue
            rows.append({
                "host": str(it.get("host") if isinstance(it, dict) else "") or host_default,
                "port": port, "proto": "tcp", "service": str(it.get("service", "") if isinstance(it, dict) else ""),
                "pv": "", "scripts": "", "cpe": "", "os": "",
            })

    if not rows:
        return "_Açık port bulunamadı._"

    rows.sort(key=lambda r: (r["host"], r["port"]))

    # OS bilgisi varsa bir kez başa yaz
    os_info = next((r["os"] for r in rows if r["os"]), "")
    header_lines = []
    if os_info:
        header_lines.append(f"> **İşletim Sistemi Tahmini:** {os_info}\n")

    header_lines += ["| Host | Port | Proto | Servis | Ürün / Versiyon | NSE Script Çıktıları | CPE |",
                     "|-|-|-|-|-|-|-|"]
    for r in rows[:500]:
        header_lines.append(
            f"| {r['host']} | **{r['port']}** | {r['proto']} "
            f"| {r['service']} | {r['pv']} | {r['scripts']} | {r['cpe']} |"
        )
    return "\n".join(header_lines)


def _e_table_tls_headers(results: Dict[str, Any]) -> str:
    # tls_summary (yapılandırılmış özet) veya tls bucket'ından normalize et
    tls_raw = results.get("tls_summary") or results.get("tls") or []
    tls: list[dict] = []
    if isinstance(tls_raw, dict):
        # Tek dict — scanner çıktısı: {"certificate": {...}, "issues": [...]}
        cert = tls_raw.get("certificate") or {}
        tls.append({
            "host": tls_raw.get("host") or cert.get("host") or "",
            "tls_version": cert.get("tls_version") or tls_raw.get("tls_version") or "",
            "cn": cert.get("subject_CN") or cert.get("common_name") or cert.get("cn") or "",
            "status": "Geçerli [OK]" if cert.get("valid") else ("Geçersiz [FAIL]" if "valid" in cert else ""),
            "issues": tls_raw.get("issues") or [],
        })
    elif isinstance(tls_raw, list):
        for item in tls_raw:
            if not isinstance(item, dict):
                continue
            cert = item.get("certificate") or {}
            if cert:
                # Scanner formatı: item içinde certificate anahtarı var
                tls.append({
                    "host": item.get("host") or cert.get("host") or "",
                    "tls_version": cert.get("tls_version") or item.get("tls_version") or "",
                    "cn": cert.get("subject_CN") or cert.get("common_name") or cert.get("cn") or "",
                    "status": "Geçerli [OK]" if cert.get("valid") else ("Geçersiz [FAIL]" if "valid" in cert else ""),
                    "issues": item.get("issues") or [],
                })
            elif item.get("tls_version") or item.get("host") or item.get("cn"):
                # Zaten özet formatında
                tls.append(item)

    hdr = results.get("security_headers_summary") or {}
    # headers bucket'ından da dene
    if not hdr:
        hdr_raw = results.get("headers") or results.get("security_headers") or {}
        if isinstance(hdr_raw, list) and hdr_raw:
            hdr_raw = hdr_raw[0] if isinstance(hdr_raw[0], dict) else {}
        if isinstance(hdr_raw, dict):
            hdr = hdr_raw

    lines = []
    if tls:
        lines.append("**TLS / Sertifika Özeti**")
        lines.append("")
        lines.append("| Host | TLS Versiyon | CN (Subject) | Durum | Sorunlar |")
        lines.append("|-|-|-|-|-|")
        for t in tls[:50]:
            if not isinstance(t, dict):
                continue
            issues = ", ".join(t.get("issues") or []) or "—"
            lines.append(
                f"| {t.get('host') or '—'} | {t.get('tls_version') or '—'} | "
                f"`{t.get('cn') or '—'}` | {t.get('status') or '—'} | {issues} |"
            )
        lines.append("")
    if hdr:
        matrix = hdr.get("matrix") or hdr.get("headers") or {}
        if not matrix and isinstance(hdr, dict):
            # Bazı formatlarda doğrudan {header: {status,note}} gelir
            matrix = {k: v for k, v in hdr.items() if isinstance(v, dict)}
        if matrix:
            lines.append("**Security Headers Özeti**")
            lines.append("")
            lines.append("| Başlık | Durum | Not |")
            lines.append("|-|-|-|")
            for k, v in matrix.items():
                if isinstance(v, dict):
                    lines.append(f"| `{k}` | {v.get('status') or ''} | {v.get('note') or ''} |")
            lines.append("")
    return "\n".join(lines) if lines else "_TLS/Headers özeti mevcut değil._"


def _e_table_discovery(results: Dict[str, Any]) -> str:
    """
    FFUF / Feroxbuster / gobuster tarzı dizin-dosya keşif sonuçlarını tablo olarak render eder.
    Bucket keys: 'discovery', 'files_discovered', 'discovery_summary'
    """
    disc_items = results.get("discovery") or []
    files_items = results.get("files_discovered") or []
    disc_summary = results.get("discovery_summary") or {}

    # discovery_summary içinde list varsa onu da al
    if isinstance(disc_summary, dict):
        for key in ("paths", "urls", "discovered", "items"):
            extra = disc_summary.get(key) or []
            if isinstance(extra, list):
                disc_items = list(disc_items) + extra

    all_items = []
    seen = set()
    for it in list(disc_items) + list(files_items):
        if not isinstance(it, dict):
            continue
        url = str(it.get("url") or it.get("path") or it.get("input") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        all_items.append({
            "url": url,
            "status": str(it.get("status") or it.get("status_code") or ""),
            "size": str(it.get("length") or it.get("size") or it.get("content_length") or ""),
            "tool": str(it.get("tool") or it.get("source") or ""),
            "category": str(it.get("category") or ""),
        })

    if not all_items:
        return "_Dizin/dosya keşfi sonucu bulunamadı._"

    # Durum koduna göre sırala: 200 önce
    def _sort_key(r):
        try:
            return int(r["status"])
        except Exception:
            return 999

    all_items.sort(key=_sort_key)

    lines = [
        f"_Toplam {len(all_items)} yol keşfedildi._",
        "",
        "| URL / Yol | HTTP Durum | Boyut | Araç | Kategori |",
        "|-|-|-|-|-|",
    ]
    for r in all_items[:500]:
        lines.append(
            f"| `{r['url']}` | {r['status']} | {r['size']} | {r['tool']} | {r['category']} |"
        )
    if len(all_items) > 500:
        lines.append(f"| _... ve {len(all_items) - 500} sonuç daha_ | | | | |")
    return "\n".join(lines)


def _e_glossary() -> str:
    return (
        "### Sözlük\n"
        "- **SQLi (SQL Injection):** Kullanıcı girdisinin SQL sorgusunun parçası hâline getirilmesiyle veritabanına izinsiz erişim veya değişiklik yapılması.\n"
        "- **XSS (Cross-Site Scripting):** Zararlı JavaScript’in kullanıcı tarayıcısında çalıştırılmasıyla oturum çalma, sahte arayüz vb.\n"
        "- **SSRF (Server-Side Request Forgery):** Sunucunun iç ağ/metadata gibi beklenmeyen hedeflere istek atmaya zorlanması.\n"
        "- **XXE (XML External Entity):** XML parser’ın harici entity okuması sonucu dosya sızdırma veya SSRF etkisine yol açması.\n"
        "- **JWT:** JSON Web Token üzerinde doğrulama/alg/manipülasyon zaafiyetleri (ör. RS256->HS256, kid injection).\n"
        "- **NoSQL Injection:** Şema-esnek veritabanlarında (Mongo/Elasticsearch vb.) operatör enjeksiyonu ile yetkisiz veri erişimi.\n"
        "- **GraphQL:** Şema/rol sızıntısı, alias-storm, persisted query kötüye kullanımı, introspection kaçakları vb.\n"
    )


def render_e_phase_markdown_report(results: Dict) -> str:
    # Güvence: results dict değilse boş dict kabul et
    res = results if isinstance(results, dict) else {}
    # Güvence: meta dict değilse boş dict
    meta = res.get("meta") if isinstance(res, dict) else {}
    if not isinstance(meta, dict):
        # Bazı akışlarda meta liste olarak gelebiliyor; raporlama için boş sözlüğe indir.
        meta = {}
    items_raw = _coerce_final(results)
    items = _dedupe_findings(items_raw)
    # Autofill payload_sample & repro_steps
    items = _e_autofill(items)

    # ===== Başlık & Yönetici Özeti =====
    meta = (res.get("meta") if isinstance(res, dict) else {})
    if isinstance(meta, list):
        meta = next((x for x in meta if isinstance(x, dict)), {})
    target = (meta.get("target") if isinstance(meta, dict) else "") or ""
    when = _now_iso()
    sev_counts = summarize_by_severity({"final": items})
    total = sum(sev_counts.values())
    risk_brief = []
    if sev_counts.get("Critical", 0):
        risk_brief.append(f"{sev_counts['Critical']} critical")
    if sev_counts.get("High", 0):
        risk_brief.append(f"{sev_counts['High']} high")
    if not risk_brief:
        risk_brief.append("no critical/high findings")
    risk_sentence = ", ".join(risk_brief)

    lines: list[str] = []
    lines.append(f"# WebSecure Raporu — {target}")
    lines.append("")
    lines.append(f"_Tarih:_ {when}")
    lines.append("")
    lines.append("## Özet (Yönetici)")
    lines.append(
        f"{total} bulgu tespit edildi; {risk_sentence}. İş etkisi: müşteri verisi, kimlik doğrulama ve hizmet sürekliliği risk altında olabilir; acil öncelik kritik/yüksek bulguların giderilmesidir.")
    lines.append("")

    # ===== Grafikler =====
    charts = (results.get('charts') or results.get('_charts') or [])
    if charts:
        kinds = {str(ch.get('kind') or ''): ch for ch in charts}

        def _img(ch: Dict | None) -> str:
            if not ch: return ""
            title = str(ch.get("title") or "Grafik")
            relp = str(ch.get("rel_path") or ch.get("path") or "")
            return f'<figure class="chart"><img alt="{title}" src="{relp}"/><figcaption>{title}</figcaption></figure>'

        lines.append("### Grafikler")
        lines.append('<div class="chart-row">')
        lines.append(_img(kinds.get("risk")))
        lines.append(_img(kinds.get("success")))
        lines.append(_img(kinds.get("tried")))  # denenen saldırılar
        lines.append("</div>")
        lines.append("")

    # ===== Tablolar =====
    lines.append("## Tablolar")
    lines.append("### Engelleme Metrikleri")
    lines.append(_e_table_engelleme(results))
    lines.append("")
    lines.append("### Input Coverage")
    lines.append(_e_table_input_coverage(results))
    lines.append("")
    lines.append("### OAST Etkileşimleri")
    lines.append(_e_table_oast(results))
    lines.append("")
    lines.append("### Açık Portlar")
    lines.append(_e_table_ports(results))
    lines.append("")
    lines.append("### TLS/Headers")
    lines.append(_e_table_tls_headers(results))
    lines.append("")
    lines.append("### Dizin & Dosya Keşfi (FFUF / Feroxbuster)")
    lines.append(_e_table_discovery(results))
    lines.append("")

    # ===== Teknik Detay (Her bulgu) =====
    lines.append("## Teknik Detay")
    rank_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    items_sorted = sorted(items, key=lambda i: -rank_order.get(_norm_sev_tr(i.get("severity")), 0))
    for idx, it in enumerate(items_sorted, 1):
        sev = _norm_sev_en(it.get("severity"))
        lines.append(f"### {idx}. {it.get('type') or 'GEN'} — {sev}")
        lines.append("**Açıklama**")
        lines.append(str(it.get("description") or it.get("reason") or "—"))
        lines.append("")
        lines.append("**Etki**")
        lines.append(str(it.get("impact") or "—"))
        lines.append("")
        lines.append("**Kök Neden**")
        lines.append(str(it.get("root_cause") or "—"))
        lines.append("")
        lines.append("**Nasıl Tespit Edildi**")
        lines.append(str(it.get("how_detected") or "—"))
        lines.append("")
        lines.append("**Nasıl Doğrulandı**")
        lines.append(str(it.get("how_verified") or "—"))
        lines.append("")
        lines.append("**Kullanılan Payload/Komut**")
        lines.append("")
        ps = it.get("payload_sample") or ""
        lines.append("```")
        lines.append(str(ps))
        lines.append("```")
        lines.append("")
        lines.append("**Yeniden Üretim Adımları**")
        for s in (it.get("repro_steps") or []):
            if isinstance(s, str):
                lines.append(f"- {s}")
        lines.append("")
        lines.append("**Düzeltme Önerisi**")
        lines.append(str(it.get("remediation") or "—"))
        lines.append("")
        lines.append("**POC Artefaktları (dosya yolu)**")
        p = it.get("poc_path") or it.get("artifact_path") or ""
        lines.append(str(p or "—"))
        lines.append("")

    # ===== Sözlük =====
    lines.append(_e_glossary())

    return "\n".join(lines)


PROOFS_DIR = 'output/proofs'

# --- Phase logging helpers (no try/except) ---
def _phase_rec(results: dict, name: str, status: str, reason: str | None = None, duration_ms: int | None = None) -> None:
    if not isinstance(results, dict):
        return
    rec = {"name": str(name), "status": str(status)}
    if reason:
        rec["reason"] = str(reason)
    if duration_ms is not None:
        try:
            rec["duration_ms"] = int(duration_ms)
        except (ValueError, TypeError) as exc:
            # avoid try/except in user code; this is reporting module internal
            log_warn(f"[reporting] duration_ms cast failed for {duration_ms!r}: {exc!r}")
    results.setdefault("phase_runs", []).append(rec)
    if callable(globals().get("add_result")):
        add_result("phase", rec)


def _render_skipped_summary(items: list[dict]) -> str:
    skipped = [i for i in items if str(i.get("status","")).startswith("skipped:")]
    if not skipped:
        return ""
    by_reason: dict[str,int] = {}
    for it in skipped:
        r = str(it.get("status"))
        by_reason[r] = by_reason.get(r, 0) + 1
    lines = ["\n### Skipped / Atlanan Görevler"]
    for r, n in sorted(by_reason.items(), key=lambda kv: kv[0]):
        lines.append(f"- {r}: {n}")
    return "\n".join(lines)


def export_sarif(results: dict, out_path: str) -> None:
    """Minimal SARIF exporter; callers pass full results."""
    run = {
        "tool": {"driver": {"name": "WebSecure", "informationUri": "https://example.invalid"}},
        "results": []
    }
    for it in results.get("findings", []):
        rule_id = (it.get("cwe") or it.get("type") or "generic")
        msg = it.get("message") or it.get("title") or it.get("type") or "finding"
        run["results"].append({"ruleId": str(rule_id), "message": {"text": str(msg)}})
    sarif = {"version": "2.1.0", "runs": [run]}
    import json
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)


def phase_summary(ctx, results):
    _ = (ctx and results); return None



# === Finalize & Teardown (single-shot) =======================================
try:
    import weakref as _weakref
except ImportError as exc:  # pragma: no cover
    log_warn(f"[reporting] weakref unavailable, falling back to plain set: {exc!r}")
    _weakref = None

# Weak registry of "quitable" resources (e.g., Selenium WebDriver)
if "_WS_QUITABLES" not in globals():
    _WS_QUITABLES = _weakref.WeakSet() if _weakref is not None else set()
if "_WS_FINALIZED" not in globals():
    _WS_FINALIZED = False
if "_FINALIZED_FLAG" not in globals():
    _FINALIZED_FLAG = False

def register_quitable(obj, label: str | None = None) -> bool:
    """
    Register an object to be gracefully shut down at finalize().
    Accepts any object that exposes .quit() or .close(). Returns True if registered.
    """
    try:
        has_quit = hasattr(obj, "quit") and callable(getattr(obj, "quit"))
        has_close = hasattr(obj, "close") and callable(getattr(obj, "close"))
        if not (has_quit or has_close):
            return False
        if isinstance(_WS_QUITABLES, set):
            _WS_QUITABLES.add(obj)
        else:
            _WS_QUITABLES.add(obj)  # WeakSet
        # Optional: annotate for logs
        try:
            add_result("meta", {"stage":"teardown", "registered": True, "label": label or getattr(obj, "__class__", type(obj)).__name__})
        except Exception as exc:
            log_warn(f"[reporting] register_quitable add_result failed: {exc!r}")
        return True
    except Exception as exc:
        log_warn(f"[reporting] register_quitable failed for {label!r}: {exc!r}")
        return False

def _quit_all_quietly() -> int:
    """Call .quit() / .close() on all registered objects. Returns count."""
    count = 0
    items = list(_WS_QUITABLES) if isinstance(_WS_QUITABLES, (set, list)) else [x for x in _WS_QUITABLES]
    for obj in items:
        try:
            if hasattr(obj, "quit") and callable(getattr(obj, "quit")):
                obj.quit()
                count += 1
            elif hasattr(obj, "close") and callable(getattr(obj, "close")):
                obj.close()
                count += 1
        except Exception as exc:
            try:
                add_result("errors", {"stage":"teardown", "error": str(exc)})
            except Exception as inner_exc:
                log_warn(f"[reporting] teardown add_result failed: {inner_exc!r}")
    # clear registry (best-effort)
    try:
        if hasattr(_WS_QUITABLES, "clear"):
            _WS_QUITABLES.clear()
    except Exception as exc:
        log_warn(f"[reporting] _quit_all_quietly registry clear failed: {exc!r}")
    return count

def finalize(session=None, cfg: Dict | None = None, results: Dict | None = None, ctx: object | None = None) -> Dict:
    """
    One-shot finalize: writes reports (perform_reporting) then gracefully tears down
    browser/driver resources. Re-entrant safe (subsequent calls are no-ops). Returns
    the 'written' dict from perform_reporting (or {}).
    """
    global _FINALIZED_FLAG, _WS_FINALIZED
    if _FINALIZED_FLAG:
        return {}
    _FINALIZED_FLAG = True
    if _WS_FINALIZED:
        return {}

    # 1) Persist reports
    written = perform_reporting(session, cfg or _try_load_config(), results or get_results())

    # 2) Attempt to quit objects registered explicitly
    _ = _quit_all_quietly()

    # 3) Best-effort: tear down well-known attributes on ctx
    try:
        c = ctx
        for name in ("driver", "browser", "webdriver", "page", "context"):
            obj = getattr(c, name, None) if c is not None else None
            if obj is None:
                continue
            try:
                if hasattr(obj, "quit") and callable(getattr(obj, "quit")):
                    obj.quit()
                elif hasattr(obj, "close") and callable(getattr(obj, "close")):
                    obj.close()
            except Exception as e:
                add_result("errors", {"stage": "teardown", "where": name, "error": str(e)})
            try:
                setattr(c, name, None)
            except (AttributeError, TypeError) as exc:
                log_warn(f"[reporting] finalize setattr None failed for {name!r}: {exc!r}")
    except Exception as exc:
        log_warn(f"[reporting] finalize ctx teardown failed: {exc!r}")

    _WS_FINALIZED = True
    return written or {}


def _pull_metrics(ctx) -> dict:
    d = {}
    for k in ("http_metrics","coverage","engagement"):
        if hasattr(ctx, k):
            d[k] = getattr(ctx,k)
    return d


# ===========================================================================
# CVSS scoring -> websecure/core/cvss.py'e taşındı
from websecure.core.cvss import score_findings

# ===========================================================================
# HTML Dashboard -> websecure/reporters/html_dashboard.py'e taşındı
from websecure.reporters.html_dashboard import render_html_dashboard



# ===========================================================================
# ADIM 13 — Raporlama: OWASP Top 10, Compliance, Trend, Remediation, PDF
# ===========================================================================


# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) Mapper
# ---------------------------------------------------------------------------

_OWASP_2021: Dict[str, Dict[str, Any]] = {
    "A01:2021": {
        "name": "Broken Access Control",
        "keywords": ["idor", "bola", "privilege escalation", "path traversal",
                     "broken access", "unauthorized", "access control", "lfi"],
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "keywords": ["tls", "ssl", "weak cipher", "http not https", "beast", "poodle",
                     "crime", "breach", "robot", "certificate", "hsts", "insecure transport"],
    },
    "A03:2021": {
        "name": "Injection",
        "keywords": ["sqli", "sql injection", "command injection", "cmdi", "ldap injection",
                     "nosql", "xpath", "ssti", "template injection", "crlf injection",
                     "log4shell", "xxe", "header injection"],
    },
    "A04:2021": {
        "name": "Insecure Design",
        "keywords": ["race condition", "logic flaw", "business logic", "mass assignment",
                     "double spend", "missing rate limit"],
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "keywords": ["cors", "csp", "misconfiguration", "default credential", "debug",
                     "directory listing", "unnecessary feature", "open redirect",
                     "cookie flag", "samesite", "httponly", "x-frame"],
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "keywords": ["outdated", "cve-", "vulnerable component", "dependency", "library"],
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "keywords": ["jwt", "session fixation", "session hijack", "brute force",
                     "password reset", "2fa bypass", "oauth", "saml", "authentication",
                     "credential", "entropy", "session entropy", "login"],
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "keywords": ["deserialization", "supply chain", "ci/cd", "update integrity",
                     "unsigned", "package"],
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "keywords": ["log poisoning", "monitoring", "no logging", "audit trail",
                     "blind xss", "oast"],
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "keywords": ["ssrf", "server-side request", "internal network", "metadata",
                     "cloud metadata", "imds"],
    },
}


class OWASPTop10Mapper:
    """
    Maps security findings to OWASP Top 10 (2021) categories.
    Returns per-category counts and affected findings.

    SOLID/SRP: Only OWASP mapping logic.
    """

    def map(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Map findings to OWASP Top 10 categories.
        Returns {category_id: {name, count, findings}}.
        """
        category_map: Dict[str, Dict[str, Any]] = {
            cat_id: {"name": info["name"], "count": 0, "findings": []}
            for cat_id, info in _OWASP_2021.items()
        }
        unmapped: List[Dict] = []

        for finding in findings:
            search_text = " ".join([
                str(finding.get("type") or ""),
                str(finding.get("title") or ""),
                str(finding.get("description") or ""),
                str(finding.get("vulnerability") or ""),
            ]).lower()

            mapped = False
            for cat_id, info in _OWASP_2021.items():
                if any(kw in search_text for kw in info["keywords"]):
                    category_map[cat_id]["count"] += 1
                    category_map[cat_id]["findings"].append({
                        "type": finding.get("type"),
                        "severity": finding.get("severity"),
                        "url": finding.get("url"),
                    })
                    mapped = True
                    break
            if not mapped:
                unmapped.append(finding)

        return {
            "categories": category_map,
            "total_mapped": sum(v["count"] for v in category_map.values()),
            "unmapped_count": len(unmapped),
            "top_categories": sorted(
                [(k, v["count"]) for k, v in category_map.items() if v["count"] > 0],
                key=lambda x: x[1], reverse=True,
            )[:5],
        }

    def render_markdown(self, mapping: Dict[str, Any]) -> str:
        lines = ["## OWASP Top 10 (2021) Eşleme\n"]
        for cat_id, info in mapping["categories"].items():
            count = info["count"]
            if count == 0:
                continue
            lines.append(f"### {cat_id}: {info['name']} — {count} bulgu")
            for f in info["findings"][:5]:
                sev = f.get("severity", "?")
                typ = f.get("type", "?")
                url = f.get("url", "")
                lines.append(f"- **{sev}** {typ} `{url}`")
        if mapping["unmapped_count"]:
            lines.append(f"\n*{mapping['unmapped_count']} bulgu kategoriyle eşleşmedi.*")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Compliance Report Builder
# ---------------------------------------------------------------------------

_COMPLIANCE_CONTROLS: Dict[str, List[Dict[str, Any]]] = {
    "PCI-DSS v4.0": [
        {"id": "Req 6.2.4", "name": "Web uygulama saldırılarına karşı koruma",
         "owasp": ["A03:2021", "A01:2021"], "severity_threshold": "high"},
        {"id": "Req 6.3.3", "name": "Güvenlik açıkları risk sıralama ve giderim",
         "owasp": ["A06:2021"], "severity_threshold": "medium"},
        {"id": "Req 6.4.2", "name": "WAF veya eşdeğer kontrol",
         "owasp": ["A03:2021", "A05:2021"], "severity_threshold": "high"},
        {"id": "Req 8.3.6", "name": "Kimlik doğrulama mekanizmaları güvenliği",
         "owasp": ["A07:2021"], "severity_threshold": "high"},
        {"id": "Req 11.3.1", "name": "Harici penetrasyon testi",
         "owasp": [], "severity_threshold": "info"},
    ],
    "HIPAA Security Rule": [
        {"id": "§164.312(a)(1)", "name": "Access Control",
         "owasp": ["A01:2021", "A07:2021"], "severity_threshold": "medium"},
        {"id": "§164.312(a)(2)(iv)", "name": "Encryption and Decryption",
         "owasp": ["A02:2021"], "severity_threshold": "medium"},
        {"id": "§164.312(c)(1)", "name": "Integrity Controls",
         "owasp": ["A08:2021"], "severity_threshold": "medium"},
        {"id": "§164.312(d)", "name": "Person/Entity Authentication",
         "owasp": ["A07:2021"], "severity_threshold": "high"},
        {"id": "§164.312(e)(1)", "name": "Transmission Security",
         "owasp": ["A02:2021"], "severity_threshold": "medium"},
    ],
    "ISO 27001:2022": [
        {"id": "A.8.24", "name": "Kriptografi kullanımı",
         "owasp": ["A02:2021"], "severity_threshold": "medium"},
        {"id": "A.8.25", "name": "Güvenli geliştirme yaşam döngüsü",
         "owasp": ["A03:2021", "A04:2021"], "severity_threshold": "medium"},
        {"id": "A.8.26", "name": "Uygulama güvenlik gereksinimleri",
         "owasp": ["A01:2021", "A03:2021", "A07:2021"], "severity_threshold": "medium"},
        {"id": "A.8.29", "name": "Geliştirmede güvenlik testi",
         "owasp": ["A03:2021", "A05:2021"], "severity_threshold": "low"},
        {"id": "A.8.9", "name": "Yapılandırma yönetimi",
         "owasp": ["A05:2021"], "severity_threshold": "medium"},
    ],
}

_SEV_RANKS_COMP = {"Critical": 5, "critical": 5, "High": 4, "high": 4,
                   "Medium": 3, "medium": 3, "Low": 2, "low": 2, "Informational": 1, "info": 1}


class ComplianceReportBuilder:
    """
    Maps OWASP Top 10 findings to PCI-DSS / HIPAA / ISO 27001 controls.
    Determines PASS/FAIL status per control based on finding severity.

    SOLID/SRP: Only compliance mapping and status determination.
    """

    def build(
        self,
        owasp_mapping: Dict[str, Any],
        frameworks: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Build compliance report for the given frameworks.
        owasp_mapping: output of OWASPTop10Mapper.map()
        frameworks: list of framework names (default: all)
        """
        all_frameworks = frameworks or list(_COMPLIANCE_CONTROLS.keys())
        report: Dict[str, Any] = {}
        categories = owasp_mapping.get("categories", {})

        for fw in all_frameworks:
            controls = _COMPLIANCE_CONTROLS.get(fw, [])
            fw_results = []
            for ctrl in controls:
                affected = []
                for owasp_cat in ctrl.get("owasp", []):
                    cat_data = categories.get(owasp_cat, {})
                    if cat_data.get("count", 0) > 0:
                        for f in cat_data.get("findings", []):
                            sev = str(f.get("severity") or "info").lower()
                            min_rank = _SEV_RANKS_COMP.get(ctrl["severity_threshold"], 1)
                            if _SEV_RANKS_COMP.get(sev, 1) >= min_rank:
                                affected.append(f)
                status = "FAIL" if affected else "PASS"
                fw_results.append({
                    "id": ctrl["id"],
                    "name": ctrl["name"],
                    "status": status,
                    "affected_count": len(affected),
                    "affected_samples": affected[:3],
                })
            passed = sum(1 for r in fw_results if r["status"] == "PASS")
            report[fw] = {
                "controls": fw_results,
                "pass_count": passed,
                "fail_count": len(fw_results) - passed,
                "compliance_score": round(passed / max(len(fw_results), 1) * 100, 1),
            }
        return report

    def render_markdown(self, compliance_report: Dict[str, Any]) -> str:
        lines = ["## Uyumluluk Raporu\n"]
        for fw, data in compliance_report.items():
            score = data["compliance_score"]
            lines.append(f"### {fw} — {score:.0f}% Uyumlu")
            lines.append(f"[OK] {data['pass_count']} PASS  [X] {data['fail_count']} FAIL\n")
            for ctrl in data["controls"]:
                icon = "[OK]" if ctrl["status"] == "PASS" else "[X]"
                lines.append(f"- {icon} **{ctrl['id']}** {ctrl['name']} ({ctrl['affected_count']} bulgu)")
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Vulnerability Trend Analyzer
# ---------------------------------------------------------------------------

class VulnerabilityTrendAnalyzer:
    """
    Compares N scan results to detect vulnerability trends.
    Reports: new findings, fixed findings, regressed findings, severity changes.

    SOLID/SRP: Only trend analysis between scan snapshots.
    """

    @staticmethod
    def _finding_key(f: Dict[str, Any]) -> str:
        return f"{f.get('type','?')}|{f.get('url','?')}|{f.get('param','')}"

    def compare(
        self,
        baseline: List[Dict[str, Any]],
        current: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Compare baseline scan vs current scan findings.
        Returns: new, fixed, persisted, severity_changes.
        """
        baseline_map = {self._finding_key(f): f for f in baseline}
        current_map = {self._finding_key(f): f for f in current}

        new_findings = [f for k, f in current_map.items() if k not in baseline_map]
        fixed_findings = [f for k, f in baseline_map.items() if k not in current_map]
        persisted = [f for k, f in current_map.items() if k in baseline_map]
        severity_changes = []
        for k, curr_f in current_map.items():
            if k in baseline_map:
                old_sev = str(baseline_map[k].get("severity") or "info").lower()
                new_sev = str(curr_f.get("severity") or "info").lower()
                if old_sev != new_sev:
                    severity_changes.append({
                        "key": k,
                        "old_severity": old_sev,
                        "new_severity": new_sev,
                        "regression": _SEV_RANKS_COMP.get(new_sev, 1) > _SEV_RANKS_COMP.get(old_sev, 1),
                    })

        regressions = [c for c in severity_changes if c["regression"]]
        return {
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "persisted_count": len(persisted),
            "severity_changes": len(severity_changes),
            "regressions": len(regressions),
            "new_findings": new_findings[:10],
            "fixed_findings": fixed_findings[:10],
            "severity_changes_detail": severity_changes[:10],
            "trend": (
                "İYİLEŞİYOR" if len(fixed_findings) > len(new_findings)
                else "KÖTÜLEŞIYOR" if len(new_findings) > len(fixed_findings) or regressions
                else "SABIT"
            ),
        }

    def multi_scan_trend(self, scans: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Compare consecutive scan pairs. Returns list of compare results."""
        results = []
        for i in range(1, len(scans)):
            comparison = self.compare(scans[i - 1], scans[i])
            comparison["scan_index"] = i
            results.append(comparison)
        return results


# ---------------------------------------------------------------------------
# Remediation Guide Generator (CWE-based)
# ---------------------------------------------------------------------------

_CWE_REMEDIATION: Dict[str, str] = {
    "CWE-79":  "XSS: Tüm kullanıcı girdilerini HTML context'e göre encode edin (htmlspecialchars). CSP uygulayın.",
    "CWE-89":  "SQLi: Parametreli sorgular veya prepared statements kullanın. ORM'leri raw query'den kaçının.",
    "CWE-22":  "Path Traversal: Kullanıcı girdisini dosya yoluna dahil etmeden önce normalize edip whitelist doğrulaması yapın.",
    "CWE-78":  "CMDI: Kullanıcı girdisini shell komutlarına asla geçirmeyin. subprocess.run() ile liste argümanı kullanın.",
    "CWE-611": "XXE: XML parser'da external entity processing'i devre dışı bırakın (FEATURE_SECURE_PROCESSING).",
    "CWE-918": "SSRF: URL whitelist uygulayın. İç ağ CIDR'lerini (RFC1918) ve cloud metadata IP'sini (169.254.169.254) engelleyin.",
    "CWE-384": "Session Fixation: Login sonrası session_regenerate_id(true) çağırın.",
    "CWE-352": "CSRF: SameSite=Lax/Strict ve CSRF token kullanın.",
    "CWE-287": "Auth Bypass: Tüm korumalı endpoint'lere authentication middleware uygulayın.",
    "CWE-307": "Brute Force: Rate limiting, account lockout, CAPTCHA uygulayın.",
    "CWE-444": "HTTP Smuggling: Backend sunucularda CL ve TE çakışmalarını reddedin.",
    "CWE-601": "Open Redirect: Redirect hedeflerini whitelist ile doğrulayın.",
    "CWE-116": "Encoding: Çıktı bağlamına uygun encoding kullanın (HTML/URL/SQL).",
    "CWE-319": "Cleartext: HTTPS/TLS kullanın. HTTP redirect uygulayın. HSTS ekleyin.",
    "CWE-311": "Şifreleme eksik: Hassas verileri AES-256-GCM ile şifreleyin.",
    "CWE-330": "Zayıf rastgelelik: Kriptografik PRNG kullanın (os.urandom, secrets).",
    "CWE-94":  "Code Injection: Eval/exec kullanmayın. Template engine'leri güvenli modda çalıştırın.",
    "CWE-502": "Deserialization: Güvenilmeyen veriden deserialize etmeyin. İmzalı paketler kullanın.",
    "CWE-200": "Bilgi ifşası: Hata mesajlarını kullanıcıya yansıtmayın. Stack trace gizleyin.",
    "CWE-209": "Hata mesajı ifşası: Generic hata sayfaları gösterin, detayları logda tutun.",
}

_TYPE_TO_CWE: Dict[str, str] = {
    "xss": "CWE-79", "reflected xss": "CWE-79", "stored xss": "CWE-79", "dom xss": "CWE-79",
    "sqli": "CWE-89", "sql injection": "CWE-89", "blind sqli": "CWE-89",
    "lfi": "CWE-22", "path traversal": "CWE-22", "directory traversal": "CWE-22",
    "cmdi": "CWE-78", "command injection": "CWE-78", "rce": "CWE-78",
    "xxe": "CWE-611",
    "ssrf": "CWE-918", "server-side request forgery": "CWE-918",
    "session fixation": "CWE-384",
    "csrf": "CWE-352",
    "authentication bypass": "CWE-287", "auth bypass": "CWE-287",
    "brute force": "CWE-307",
    "http smuggling": "CWE-444", "request smuggling": "CWE-444",
    "open redirect": "CWE-601",
    "ssti": "CWE-94", "template injection": "CWE-94",
    "insecure deserialization": "CWE-502",
    "information disclosure": "CWE-200",
    "jwt expiry bypass": "CWE-287", "session entropy": "CWE-330",
    "cookie injection via crlf": "CWE-116", "crlf injection": "CWE-116",
}


class RemediationGuideGenerator:
    """
    Generates CWE-based remediation guidance for each finding.
    Enriches findings with CWE ID, OWASP category, and remediation text.

    SOLID/SRP: Only remediation guide generation.
    """

    def enrich(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Add cwe, owasp_category, remediation fields to finding."""
        finding = dict(finding)
        ftype = str(finding.get("type") or "").lower().strip()
        cwe = finding.get("cwe") or _TYPE_TO_CWE.get(ftype)
        if not cwe:
            # Partial match
            for key, val in _TYPE_TO_CWE.items():
                if key in ftype:
                    cwe = val
                    break
        if cwe:
            finding["cwe"] = cwe
            if not finding.get("remediation") and cwe in _CWE_REMEDIATION:
                finding["remediation"] = _CWE_REMEDIATION[cwe]
        # OWASP category
        if not finding.get("owasp_category"):
            search = ftype
            for cat_id, info in _OWASP_2021.items():
                if any(kw in search for kw in info["keywords"]):
                    finding["owasp_category"] = f"{cat_id}: {info['name']}"
                    break
        return finding

    def enrich_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.enrich(f) for f in findings]


# ---------------------------------------------------------------------------
# PDF Report Builder (WeasyPrint / reportlab / HTML fallback)
# ---------------------------------------------------------------------------

class PDFReportBuilder:
    """
    Executive summary PDF report generator.

    Tries backends in order:
    1. WeasyPrint  (CSS-based, best quality)
    2. reportlab   (programmatic)
    3. HTML file   (fallback — always works)

    SOLID/OCP: Add new PDF backends without modifying public API.
    """

    def __init__(self, title: str = "WebSecure Executive Report"):
        self.title = title

    def build(
        self,
        findings: List[Dict[str, Any]],
        output_path: str,
        owasp_mapping: Optional[Dict[str, Any]] = None,
        compliance_report: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate PDF (or HTML fallback) at output_path.
        Returns actual path written.
        """
        html_content = self._render_html(findings, owasp_mapping, compliance_report)

        # Try WeasyPrint
        if output_path.endswith(".pdf"):
            if self._try_weasyprint(html_content, output_path):
                return output_path
            if self._try_reportlab(findings, output_path):
                return output_path
            # HTML fallback
            html_path = output_path.replace(".pdf", ".html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            import logging as _log
            _log.getLogger(__name__).warning(
                f"[PDF] PDF kütüphanesi bulunamadı — HTML olarak kaydedildi: {html_path}\n"
                "PDF için: pip install weasyprint  veya  pip install reportlab"
            )
            return html_path
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            return output_path

    def _render_html(
        self,
        findings: List[Dict[str, Any]],
        owasp_mapping: Optional[Dict[str, Any]],
        compliance_report: Optional[Dict[str, Any]],
    ) -> str:
        from datetime import datetime as _dt
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        rows = "".join(
            f"<tr><td>{html_esc(str(f.get('type','?')))}</td>"
            f"<td class='sev-{str(f.get('severity','info')).lower()}'>{html_esc(str(f.get('severity','?')))}</td>"
            f"<td>{html_esc(str(f.get('url',''))[:80])}</td>"
            f"<td>{html_esc(str(f.get('cwe',''))[:30])}</td></tr>"
            for f in findings[:50]
        )
        owasp_section = ""
        if owasp_mapping:
            cats = owasp_mapping.get("categories", {})
            owasp_section = "<h2>OWASP Top 10 Eşleme</h2><ul>" + "".join(
                f"<li><b>{cat_id}: {info['name']}</b> — {info['count']} bulgu</li>"
                for cat_id, info in cats.items() if info["count"] > 0
            ) + "</ul>"
        compliance_section = ""
        if compliance_report:
            compliance_section = "<h2>Uyumluluk</h2>"
            for fw, data in compliance_report.items():
                compliance_section += (
                    f"<h3>{html_esc(fw)}: {data['compliance_score']:.0f}% Uyumlu</h3>"
                    f"<p>[OK] {data['pass_count']} PASS &nbsp; [X] {data['fail_count']} FAIL</p>"
                )

        return f"""<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<title>{html_esc(self.title)}</title>
<style>
  body{{font-family:Arial,sans-serif;margin:40px;color:#222}}
  h1{{color:#1a237e}} h2{{color:#283593;border-bottom:2px solid #283593}}
  table{{border-collapse:collapse;width:100%}}
  th{{background:#283593;color:white;padding:8px}}
  td{{border:1px solid #ccc;padding:6px;font-size:12px}}
  .sev-kritik,.sev-critical{{color:#c62828;font-weight:bold}}
  .sev-yüksek,.sev-high{{color:#e65100;font-weight:bold}}
  .sev-orta,.sev-medium{{color:#f57f17}}
  .sev-düşük,.sev-low{{color:#2e7d32}}
  .summary-box{{display:inline-block;padding:16px;margin:8px;border-radius:8px;min-width:100px;text-align:center}}
  .crit{{background:#ffcdd2}} .high{{background:#ffe0b2}}
  .med{{background:#fff9c4}} .low{{background:#c8e6c9}}
</style></head><body>
<h1>[lock] {html_esc(self.title)}</h1>
<p><i>Oluşturulma: {_dt.now().strftime('%Y-%m-%d %H:%M')}</i></p>
<h2>Yönetici Özeti</h2>
<div>
  <div class="summary-box crit"><b>{sev_counts.get('kritik', sev_counts.get('critical', 0))}</b><br>Kritik</div>
  <div class="summary-box high"><b>{sev_counts.get('yüksek', sev_counts.get('high', 0))}</b><br>Yüksek</div>
  <div class="summary-box med"><b>{sev_counts.get('orta', sev_counts.get('medium', 0))}</b><br>Orta</div>
  <div class="summary-box low"><b>{sev_counts.get('düşük', sev_counts.get('low', 0))}</b><br>Düşük</div>
</div>
<p><b>Toplam Bulgu:</b> {len(findings)}</p>
{owasp_section}
{compliance_section}
<h2>Bulgular (ilk 50)</h2>
<table><tr><th>Tür</th><th>Önem</th><th>URL</th><th>CWE</th></tr>{rows}</table>
</body></html>"""

    @staticmethod
    def _try_weasyprint(html: str, path: str) -> bool:
        try:
            from weasyprint import HTML as _WHTML
            _WHTML(string=html).write_pdf(path)
            return True
        except Exception:
            return False

    @staticmethod
    def _try_reportlab(findings: List[Dict[str, Any]], path: str) -> bool:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors
            doc = SimpleDocTemplate(path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = [Paragraph("WebSecure Executive Report", styles["Title"]), Spacer(1, 12)]
            data = [["Type", "Severity", "URL"]]
            for f in findings[:30]:
                data.append([
                    str(f.get("type", "?"))[:40],
                    str(f.get("severity", "?"))[:15],
                    str(f.get("url", ""))[:60],
                ])
            t = Table(data)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.navy),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(t)
            doc.build(story)
            return True
        except Exception:
            return False


def html_esc(s: str) -> str:
    import html as _html
    return _html.escape(str(s))
