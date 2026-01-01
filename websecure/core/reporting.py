
from __future__ import annotations
from urllib.parse import urlsplit, urlunsplit
import logging
import os, re, json, logging, threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Iterable, Tuple
from urllib.parse import urlparse
from pathlib import Path
from collections import defaultdict
import os, json, html
from typing import Any, Dict, List
from websecure.core.ci_gate import should_fail_ci

# [AUTO-CLEANUP] removed duplicate def '_ensure_dir' defined at lines 14-15

# [AUTO-CLEANUP] removed duplicate def 'add_result' defined at lines 17-18

def _sarif_from_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Minimal SARIF 2.1.0 skeleton
    runs = [{
        "tool": {"driver": {"name": "WebSecure", "informationUri": "https://example.invalid"}},
        "results": [],
    }]
    sarif = {"version": "2.1.0", "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json", "runs": runs}
    for r in results:
        runs[0]["results"].append({
            "ruleId": str(r.get("id", r.get("type", "finding"))),
            "level": r.get("severity", "note"),
            "message": {"text": r.get("message", "")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": r.get("url", "")}}
            }]
        })
    return sarif


def finalize_reports(ctx: dict, cfg: dict) -> dict:
    """
    2.4/2.5 uyumlu finalize:
      - reporting.output_dir + formats dikkate alınır
      - JSON/MD/HTML/SARIF üretir (mevcut render fonksiyonlarını kullanır)
      - CI eşiği uygular ve 'ci.exit_on_violation' True ise SystemExit(1) fırlatır
    """
    rep_cfg = (cfg.get("reporting") or {}) if isinstance(cfg, dict) else {}
    out_dir = rep_cfg.get("output_dir") or cfg.get("output_dir") or "output"

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

    out = perform_reporting(session=None, cfg=cfg, results=results, logger=None)


    results = out.get("written") if isinstance(out, dict) and "written" in out else {}
    
    ci_cfg = (cfg.get("ci") or {}) if isinstance(cfg, dict) else {}
    exit_on = bool(ci_cfg.get("exit_on_violation", False))
    fail_on_sev = ci_cfg.get("fail_on", [])
    
    fail = False
    
    # Check Quality Gate
    if fail_on_sev and results:
         # Statleri sonuclardan çıkar
         # Not: perform_reporting 'metrics' veya 'summary' döndürmeli
         # Basitçe results içindeki severitylere bak
         # Bu kisim biraz karmasik cunku 'out' yapisi fonksiyondan fonksiyona degisebilir
         # En temizi 'should_fail_ci' fonksiyonunu kullanmak
         try:
            fail = should_fail_ci(cfg, results)
         except Exception:
            fail = False

    if exit_on and fail:
        raise SystemExit(1)

    return out.get("written", out) if isinstance(out, dict) else {"output_dir": out_dir}
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
            f"- WAF: {c['WAF']}\n- Auth: {c['Auth']}\n- Rate‑Limit: {c['RateLimit']}\n"
            f"- Toplam 401/403: {total}\n")


# -------------------- Global durum (thread-safe) --------------------
_lock = threading.RLock()
_buckets: Dict[str, List[Dict[str, Any]]] = {}
_logger: logging.Logger | None = None

# -------------------- Maskeleme / Redaction --------------------
_ENFORCE_REDACT = True
_MASK = "<redacted>"

REDACT_KEYS = {
    "password", "passwd", "token", "authorization", "auth", "secret",
    "api_key", "apikey", "access_token", "refresh_token", "session",
    "cookie", "set-cookie", "csrf", "csrf_token", "xsrf"
}

_JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b")
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b", re.I)
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_EMAIL_RE = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")
_RE_COOKIE = re.compile(r"(?i)(?:^|;\s*)([A-Za-z0-9_\-]{1,64})=([^;]+)")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_host_for_filename(url: str) -> str:
    host = urlparse(url).hostname or "report"
    safe = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in host)
    return safe[:100] or "report"


def _redact_str(s: str) -> str:
    if not s: return s
    t = s
    t = _JWT_RE.sub(_MASK, t)
    t = _BEARER_RE.sub("Bearer " + _MASK, t)
    t = _HEX_RE.sub(_MASK, t)
    t = _EMAIL_RE.sub(_MASK, t)
    t = _RE_COOKIE.sub(lambda m: f"{m.group(1)}={_MASK}", t)
    for k in REDACT_KEYS:
        t = re.sub(fr'("{k}"\s*:\s*")([^"]+)"', fr'\1{_MASK}"', t, flags=re.IGNORECASE)
        t = re.sub(fr'({k})=([^\s;&]+)', fr'\1=' + _MASK, t, flags=re.IGNORECASE)
    return t


def redact_sensitive(val: Any, _depth: int = 0, _max: int = 6) -> Any:
    if _depth > _max:
        return _MASK
    if isinstance(val, dict):
        out: Dict[str, Any] = {}
        for k, v in val.items():
            if str(k).lower() in REDACT_KEYS:
                out[k] = _MASK
            else:
                out[k] = redact_sensitive(v, _depth + 1, _max)
        return out
    if isinstance(val, (list, tuple, set)):
        typ = type(val)
        return typ(redact_sensitive(x, _depth + 1, _max) for x in val)
    if isinstance(val, (bytes, str)):
        s = val.decode("utf-8", "ignore") if isinstance(val, bytes) else val
        return _redact_str(s)
    return val


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and record.args:
            record.args = tuple(redact_sensitive(a) for a in record.args)
        if isinstance(record.msg, str):
            record.msg = _redact_str(record.msg)
        return True


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
    with _lock:
        _buckets.clear()


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

    # Bytes → metin (hatasız, ignore)
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


def add_result(bucket: str, item: Any) -> None:
    if not bucket:
        return
    with _lock:
        it = _normalize_item(item)
        it.setdefault("ts", _now_iso())
        enforce = globals().get("_ENFORCE_REDACT", True)
        safe_it = redact_sensitive(it) if enforce else it
        if bucket not in _buckets:
            _buckets[bucket] = []
        _buckets[bucket].append(safe_it)


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

    # --- 1) Risk pie (Bilgi -> Güvenli, diğerleri ayrı dilim)
    base_counts = {k: 0 for k in ("Kritik","Yüksek","Orta","Düşük","Bilgi")}
    for it in items:
        base_counts[_norm_sev_tr(it.get("severity"))] = base_counts.get(_norm_sev_tr(it.get("severity")), 0) + 1
    risk_labels = ["Kritik", "Yüksek", "Orta", "Düşük", "Güvenli"]
    risk_values = [
        base_counts["Kritik"],
        base_counts["Yüksek"],
        base_counts["Orta"],
        base_counts["Düşük"],
        base_counts["Bilgi"],  # 'Bilgi' grafikte 'Güvenli' etiketiyle gösterilecek
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

    # --- Başarı sayımı (sadece Bilgi dışı bulgular) — STRICT eşleşme (12,5% bug fix)
    success_per: "OrderedDict[str,int]" = OrderedDict((k, 0) for k in tried_map.keys())
    for it in items:
        sev = _norm_sev_en(it.get("severity"))
        if sev == "Bilgi":
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
    # Guard: boş veya sayıya indirgenemeyen dizi → 0.0
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
    s = (s or "Bilgi").strip().lower()
    if s in ("kritik",): return "Kritik"
    if s in ("yüksek", "high", "severe"): return "Yüksek"
    if s in ("orta", "medium"): return "Orta"
    if s in ("düşük", "low"): return "Düşük"
    return "Bilgi"


def _sev_rank(s: str | None) -> int:
    """Rank via EN normalization: critical=4 > high=3 > medium=2 > low=1 > info=0."""
    m = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    # Use EN-normalization for consistent ordering
    try:
        return m.get(_norm_sev_en(s or ""), 0)
    except Exception:
        return 0

def _coerce_final(results: Dict) -> List[Dict]:

    fin = results.get("final")
    if isinstance(fin, list):
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

        # evidence: sözlük birleştirme
        if it.get("evidence"):
            cur.setdefault("evidence", {}).update(it.get("evidence") or {})

        # poc: kısa gösterimde daha “zengin” olanı al
        cur_poc_short = _short_poc(cur.get("poc") or "")
        it_poc_short = _short_poc(it.get("poc") or "")
        if len(str(it_poc_short)) > len(str(cur_poc_short)):
            cur["poc"] = it.get("poc")

    return list(bykey.values())


def _render_ports(results: Dict) -> str:
    """
    Taranan/Açık portları tablo halinde basar.
    Beklenen kaynaklar: results['ports'] veya results['port_scan'] veya results['nmap'] / ['nmap_summary']
    Her kayıt: {"host":..., "port":..., "proto":..., "state": "open/closed/filtered", "service":...}
    """
    cand_keys = ["ports", "port_scan", "nmap", "nmap_summary", "services", "open_ports"]
    rows = []

    def _as_int(val):
        s = str(val).strip()
        return int(s) if re.fullmatch(r"[+-]?\d+", s) else val

    for k in cand_keys:
        v = results.get(k)
        if isinstance(v, list):
            for it in v:
                if not isinstance(it, dict):
                    continue
                host = str(it.get("host") or it.get("ip") or it.get("address") or "")
                port = it.get("port") or it.get("dst_port") or it.get("service_port")
                if port is None:
                    continue
                port = _as_int(port)
                proto = (str(it.get("proto") or it.get("protocol") or "") or "tcp").lower()
                state = str(it.get("state") or it.get("status") or "")
                svc = str(it.get("service") or it.get("name") or it.get("product") or "")
                rows.append({"host": host, "port": port, "proto": proto, "state": state or "open", "service": svc})
        elif isinstance(v, dict):
            scanned = v.get("scanned") or []
            opened = v.get("open") or v.get("open_ports") or []
            for it in scanned:
                if isinstance(it, dict) and "port" in it:
                    rows.append({
                        "host": str(it.get("host") or ""),
                        "port": _as_int(it.get("port")),
                        "proto": str(it.get("proto") or "tcp"),
                        "state": str(it.get("state") or "scanned"),
                        "service": str(it.get("service") or "")
                    })
            for it in opened:
                if isinstance(it, dict) and "port" in it:
                    rows.append({
                        "host": str(it.get("host") or ""),
                        "port": _as_int(it.get("port")),
                        "proto": str(it.get("proto") or "tcp"),
                        "state": "open",
                        "service": str(it.get("service") or "")
                    })

    if not rows:
        return ""

    scanned_ports = {}
    open_ports = {}
    for r in rows:
        key = (r["host"], r["proto"], r["port"])
        scanned_ports[key] = r
        if str(r.get("state", "")).lower().startswith("open"):
            open_ports[key] = r

    out = []
    out.append("## Taranan Portlar")
    out.append("")
    out.append("| Host | Proto | Port | Servis | Durum |")
    out.append("|-|-|-:|-|-|")

    def _sort_key(kv):
        h, pr, po = kv[0]
        if isinstance(po, int):
            return (h, pr, po)
        # int değilse string karşılaştırma
        return (h, pr, str(po))

    for (h, pr, po), rr in sorted(scanned_ports.items(), key=_sort_key):
        out.append(f"| {h} | {pr} | {po} | {rr.get('service') or ''} | {rr.get('state') or ''} |")

    out.append("")
    out.append("## Açık Portlar")
    out.append("")
    out.append("| Host | Proto | Port | Servis |")
    out.append("|-|-|-:|-|")
    if open_ports:
        for (h, pr, po), rr in sorted(open_ports.items(), key=_sort_key):
            out.append(f"| {h} | {pr} | {po} | {rr.get('service') or ''} |")
    else:
        out.append("| - | - | - | - |")
    return "\n".join(out)


def render_markdown_report(results: Dict) -> str:
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
    lines: list[str] = []
    if egress:
        lines.append('## Egress Karnesi')
        lines.append('')
        lines.append('| Kimlik | Proxy | Bölge | Accept-Language | User-Agent |')
        lines.append('|-|-|-|-|-|')
        lines.append(
            f"| {egress.get('label', '')} | {egress.get('proxy_url', '') or 'direct'} | {egress.get('region', '')} | {egress.get('accept_language', '')} | {egress.get('ua', '')[:42]}… |")
        lines.append('')

    # Şiddet sayımları
    counts = {"Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Bilgi": 0}
    for i in items:
        counts[_norm_sev_tr(i.get("severity"))] = counts.get(_norm_sev_tr(i.get("severity")), 0) + 1

    # Başlangıç
    lines: List[str] = []
    lines.append(render_auth_coverage_md())
    lines.append("# WebSec Raporu")
    lines.append("")
    if target:
        lines.append(f"**Hedef:** `{esc_md(target)}`  •  **Tarih:** `{when}`")
        lines.append("")

    # Genel Özet (tablolaştırılmış)
    lines.append("## Genel Özet")
    lines.append("")
    lines.append("| Seviye | Adet |")
    lines.append("|-|-:|")
    for k in ("Kritik", "Yüksek", "Orta", "Düşük", "Bilgi"):
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
    lines.append(f"- Başarılı (en az 1 bulgu üreten): **{len(success)}**  → **%{pct:.1f}**")
    if tried:
        lines.append(f"- Dene(n)en: " + ", ".join(f"`{tried_map[k]}`" for k in tried))
    if success:
        lines.append(f"- Başarılı: " + ", ".join(f"`{tried_map[k]}`" for k in success))
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
        if sev in ("Kritik", "Yüksek", "Orta", "Düşük") or ("<script" in poc_s) or it.get("exploitable") or it.get(
                "exploit_url"):
            if sev != "Bilgi":
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

    # Edinilen Bilgiler (Bilgi seviyesi)
    info_items = [it for it in items if _norm_sev_tr(it.get("severity")) == "Bilgi"]
    if info_items:
        lines.append("")
        lines.append("## Edinilen Bilgiler")
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

    # Risk Matrisi
    lines.append("")
    lines.append(_render_risk_matrix(items))

    # Bulgular Listesi
    lines.append("")
    lines.append("## Bulgular Listesi")
    lines.append("| Seviye | Puan | Tür | URL | Lokasyon | Param | PoC |")
    lines.append("|-|-:|-|-|-|-|-|")
    for i in items:
        poc = _short_poc((i.get("poc") or i.get("payload") or i.get("evidence") or "")).strip()
        score = i.get("score")
        score_str = str(score) if score is not None else "-"
        t = i.get("type") or "GEN"
        if i.get("authenticated"):
            t += " [AUTH]"
            if i.get("auth_only"): t += " [AUTH-ONLY]"
        lines.append(
            f"| {_norm_sev_tr(i.get('severity'))} | {score_str} | {esc_md(t)} | {esc_md(i.get('url') or '')} | {esc_md(i.get('location') or '')} | {esc_md(i.get('param') or '')} | `{poc}` |")

    # Detaylar (her bulgu için KV tablo + PoC blokları)
    lines.append("")
    lines.append("## Detaylar")
    for idx, it in enumerate(items, 1):
        t = it.get('type') or 'GEN'
        if it.get("authenticated"):
            t += " [AUTH]"
            if it.get("auth_only"): t += " [AUTH-ONLY]"
        score = it.get('score') if it.get('score') is not None else '-'
        lines.append("")
        lines.append(f"### {idx}. {t} • ({score})")
        lines.append("| Alan | Değer |")
        lines.append("|-|-|")
        lines.append(f"| URL | `{it.get('url') or ''}` |")
        lines.append(f"| Lokasyon | `{it.get('location') or ''}` |")
        lines.append(f"| Param | `{it.get('param') or ''}` |")
        if (it.get('tool') or it.get('engine') or it.get('module')):
            lines.append(f"| Araç | `{it.get('tool') or it.get('engine') or it.get('module')}` |")
        lines.append(f"| Method | `{it.get('method') or ''}` |")
        if it.get("severity"):
            lines.append(f"| Seviye | `{_norm_sev_tr(it.get('severity'))}` |")
        if it.get("reason"):
            lines.append(f"| Neden | `{esc_md(str(it['reason']))}` |")
        if it.get("payloads"):
            lines.append(f"| Payloads | `{esc_md(json.dumps(it['payloads'], ensure_ascii=False))}` |")
        if it.get("similar_params"):
            lines.append(f"| Benzer Paramlar | `{esc_md(json.dumps(it['similar_params'], ensure_ascii=False))}` |")
        if (it.get("evidence") or {}).get("callback_type"):
            lines.append(f"| Callback | `{esc_md(it['evidence']['callback_type'])}` |")

        poc_block = ((it.get("poc") or it.get("payload") or it.get("evidence") or "")).strip()
        if poc_block:
            lines.append("**PoC / Payload**")
            lines.append("")
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
            lines.append(str(poc_block))
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
            lines.append("**PoC (curl)**")
            lines.append("")
            lines.append("```bash")
            lines.append(curl_cmd)
            lines.append("```")
            # Repro Steps (genel)
            lines.append("")
            lines.append("**Yeniden Üretim Adımları**")
            lines.append("1) Aşağıdaki PoC komutunu çalıştırın veya eşdeğer HTTP isteğini gönderin.")
            lines.append("2) Başlıklar/Parametreler farklıysa tablo üstündeki alanlardan uyarlayın.")

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

    return "\n".join(lines)


def _write(path: str, data: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return path


def _json_dump(path: str, obj: Any) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    def _default(o):
        if hasattr(o, "to_dict"):
            return o.to_dict()
        if hasattr(o, "__dict__"):
            return o.__dict__
        if hasattr(o, "name") and hasattr(o, "value"): # Enum-like
            return o.value
        return str(o)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, default=_default)
    return path


# -------------------- Üst seviye API --------------------


import hashlib


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
    }



# -------------------- CVSS/CWE Enrichment --------------------
_CVSS_DEFAULTS = {
    "critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.1
}

def _norm_sev_en(s: str) -> str:
    s = (s or "").strip().lower()
    if s in ("kritik", "critical", "crit"): return "critical"
    if s in ("yüksek", "high"): return "high"
    if s in ("orta", "medium", "med"): return "medium"
    if s in ("düşük", "low"): return "low"
    return "low"

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
    reg = RULES_REGISTRY.get(rule) or {}
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
    fmts: List[str] = rep_cfg.get("formats") or ["md"]
    written: Dict[str, str] = {}
    os.makedirs(out_dir, exist_ok=True)

    # Always write JSON for CI consumption
    _json_dump(os.path.join(out_dir, 'report.json'), results)
    written['json'] = os.path.join(out_dir, 'report.json')
    # Also persist HTTP metrics snapshot for CI/analysis
    try:
        from websecure.core.http import get_http_metrics
        metrics_payload = get_http_metrics()
        _json_dump(os.path.join(out_dir, 'metrics.json'), metrics_payload)
        written['metrics'] = os.path.join(out_dir, 'metrics.json')
    except Exception:
        pass

    # Attach payload metrics if not present
    if isinstance(results, dict) and "payload_metrics" not in results:
        results = dict(results)  # avoid in-place mutation from outside
        results["payload_metrics"] = export_payload_metrics()
    # CVSS/CWE Enrichment
    results = enrich_cvss_cwe(results, cfg)



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
        md = render_e_phase_markdown_report(results)
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
            if isinstance(tls, list) and tls:
                host = tls[0].get("host")
        safe = _safe_host_for_filename("https://" + (host or "report"))
        report_path = os.path.join(out_dir, f"{safe}_report.md")
        _write(report_path, md)
        written["md"] = report_path

    # HTML (convert MD when possible; safe fallback otherwise)
    if "html" in fmts:
        import importlib.util as _iul
        if md is None:
            mdtxt = render_markdown_report(results)
        else:
            mdtxt = md
        if _iul.find_spec("markdown") is not None:
            import markdown as _md
            html_body = _md.markdown(mdtxt, extensions=["tables", "fenced_code"])
        else:
            # Minimal <pre> fallback
            html_body = "<pre>" + (mdtxt.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")) + "</pre>"
        html = """<!doctype html><html><head><meta charset='utf-8'><title>WebSec Raporu</title>
<style>
:root{--bg:#0e1117;--card:#161b22;--text:#e6edf3;--muted:#a0aab8;--accent:#2f81f7;--b:#2d333b;}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;background:var(--bg);color:var(--text);line-height:1.5}
h1,h2,h3{color:var(--text);border-bottom:1px solid var(--b);padding-bottom:4px;margin-top:24px}
h1{font-size:28px} h2{font-size:22px} h3{font-size:18px}
table{border-collapse:collapse;width:100%;background:var(--card);margin:12px 0;border:1px solid var(--b)}
th,td{border:1px solid var(--b);padding:8px;vertical-align:top}
thead th{background:#0f1623}
tbody tr:nth-child(even){background:#0d1420}
code, pre{background:#0b1220;border:1px solid var(--b);border-radius:6px;color:#dde6f7}
pre{white-space:pre-wrap;padding:10px}
.chart-row{display:flex;gap:12px;align-items:stretch;margin:12px 0}
.chart-row .chart{flex:1;background:var(--card);border:1px solid var(--b);border-radius:10px;padding:8px}
.chart-row img{display:block;width:100%;height:auto;border-radius:6px;border:1px solid var(--b)}
.chart-row figcaption{margin-top:6px;color:var(--muted);font-size:13px;text-align:center}
.small{font-size:12px;color:var(--muted)}
</style>
</head><body>""" + html_body + "</body></html>"
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

    # Delta (optional)
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

    """
    Çok-format raporlama + grafik üretimi.
    'written' altında üretilen dosya yollarını döndürür.
    """


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
    if s in ("kritik", "critical"): return "error"
    if s in ("yüksek", "high"):     return "error"
    if s in ("orta", "medium"):     return "warning"
    if s in ("düşük", "low"):       return "note"
    return "note"


def _to_sarif(results: Dict) -> Dict:
    runs = [{
        "tool": {"driver": {"name": "WebSecure", "semanticVersion": "2.2.0"}},
        "results": []
    }]
    items = _coerce_final(results)
    for it in items:
        runs[0]["results"].append({
            "level": _map_severity_to_level(it.get("severity") or ""),
            "message": {"text": it.get("reason") or (it.get("type") or "Finding")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": it.get("url") or ""}}
            }]
        })
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": runs}


def _to_junit(results: Dict, suite_name: str = "WebSecure") -> str:
    items = _coerce_final(results)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="{suite_name}" tests="{len(items)}">'
    ]
    for idx, it in enumerate(items, 1):
        sev = (it.get("severity") or "Bilgi")
        name = f"{sev}:{it.get('type') or 'GEN'}"
        lines.append(f'  <testcase classname="websecure" name="{_xml_escape(name)}">')
        if _map_severity_to_level(sev) in ("warning", "error"):
            lines.append(f'    <failure message="{_xml_escape(it.get("reason") or name)}"/>')
        lines.append('  </testcase>')
    lines.append('</testsuite>')
    return "\n".join(lines)


def _xml_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") \
        .replace('"', "&quot;").replace("'", "&apos;")


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
    from importlib.machinery import ModuleSpec as _ilu_ModuleSpec
    from pathlib import Path
    import json as _json

    def _spec_origin(spec: _ilu_ModuleSpec) -> Optional[str]:
        return spec.origin

    def _is_local_path(path: str) -> bool:
        return Path(path).is_absolute() and Path(path).exists()

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
            return _json.loads(txt)

    # Son çare: minimal varsayılan
    return {"reporting": {"formats": ["md"], "output_dir": "output"}}


def flush(session=None, cfg: Dict | None = None, results: Dict | None = None) -> Dict:
    _cfg = cfg or _try_load_config()
    _results = results or get_results()
    out = perform_reporting(session, _cfg, _results)
    return out or {}



def perform_reporting_and_integration(session, cfg: dict, results: dict, logger: 'logging.Logger|None'=None, **_kw) -> dict:
    """
    global _logger
    if logger is not None:
        _logger = logger
    Birleşik giriş noktası: raporu üretir ve entegrasyonları tetikler.
    scan_modes/_resolve_reporter bu fonksiyonu arar.
    """
    return perform_reporting(session, cfg, results) or {}




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
    order = {"bilgi": 0, "düşük": 1, "orta": 2, "yüksek": 3, "kritik": 4}
    return order.get(s, 0)


def _apply_ci_gates(cfg: Dict, results: Dict, out_dir: str) -> None:
    import os, json

    ci = (cfg.get("ci") or {})
    fail_on = (ci.get("fail_on") or {})
    sev_min = (fail_on.get("severity_min") or "Orta").lower()
    new_only = bool(fail_on.get("new_findings", False))

    items = _coerce_final(results)

    if new_only:
        delta_path = os.path.join(out_dir, "delta.json")
        if os.path.exists(delta_path) and os.path.isfile(delta_path):
            txt = open(delta_path, "r", encoding="utf-8").read().strip()
            # Basit doğrulama: JSON gibi görünmüyorsa filtre uygulama
            if txt.startswith("{") or txt.startswith("["):
                d = json.loads(txt)
                keyed_new = d.get("new") or []

                def _is_new(it: Dict) -> bool:
                    key = f"{it.get('type')}|{it.get('url')}|{it.get('param')}|{it.get('location')}"
                    return key in keyed_new

                items = [it for it in items if _is_new(it)]

    rank_min = _severity_rank(sev_min)
    viol = [it for it in items if _severity_rank((it.get("severity") or "Bilgi").lower()) >= rank_min]

    if viol:
        _write(os.path.join(out_dir, "ci.FAIL"), "\n".join([str(v) for v in viol]))
    else:
        _write(os.path.join(out_dir, "ci.OK"), "ok")


# ===================== CI Yardımcıları (public) =====================
def should_fail_ci(cfg: Dict, results: Dict) -> bool:
    def _rank(s: str) -> int:
        s = (s or "").lower()
        order = {"bilgi": 0, "düşük": 1, "orta": 2, "yüksek": 3, "kritik": 4}
        return order.get(s, 0)

    ci = (cfg.get("ci") or {})
    fail_on = (ci.get("fail_on") or {})
    sev_min = (fail_on.get("severity_min") or "Orta").lower()
    new_only = bool(fail_on.get("new_findings", False))
    items = []
    if isinstance(results, dict) and "final" in results and isinstance(results["final"], list):
        items = list(results["final"])
    else:
        for bucket, arr in (results or {}).items():
            for it in arr or []:
                items.append(it)
    if new_only:
        keyed_new = set()
        for it in items:
            if it.get("_is_new"):
                key = f"{it.get('type')}|{it.get('url')}|{it.get('param')}|{it.get('location')}"
                keyed_new.add(key)

        def _is_new(it: Dict) -> bool:
            key = f"{it.get('type')}|{it.get('url')}|{it.get('param')}|{it.get('location')}"
            return key in keyed_new

        items = [it for it in items if _is_new(it)]
    rank_min = _rank(sev_min)
    viol = [it for it in items if _rank((it.get("severity") or "Bilgi")) >= rank_min]
    return bool(viol)


def summarize_by_severity(results: Dict) -> Dict[str, int]:
    counts = {"Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Bilgi": 0}
    items = []
    if isinstance(results, dict) and "final" in results and isinstance(results["final"], list):
        items = list(results["final"])
    else:
        for bucket, arr in (results or {}).items():
            for it in arr or []:
                items.append(it)
    for it in items:
        sev = str(it.get("severity") or "Bilgi").title()
        if sev.lower() == "kritik":
            counts["Kritik"] += 1
        elif sev.lower() == "yüksek":
            counts["Yüksek"] += 1
        elif sev.lower() == "orta":
            counts["Orta"] += 1
        elif sev.lower() == "düşük":
            counts["Düşük"] += 1
        else:
            counts["Bilgi"] += 1
    return counts


def to_markdown_summary(results: Dict) -> str:
    c = summarize_by_severity(results)
    return (
        "| Severity | Adet |\n|---|---:|\n"
        f"| Kritik | {c['Kritik']} |\n"
        f"| Yüksek | {c['Yüksek']} |\n"
        f"| Orta | {c['Orta']} |\n"
        f"| Düşük | {c['Düşük']} |\n"
        f"| Bilgi | {c['Bilgi']} |\n"
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

def to_sarif(results: Dict, tool_name: str = "WebSec") -> Dict:
    items = _iter_findings(results)
    rule_ids = sorted(set(str(i.get("type") or i.get("title") or "finding") for i in items))
    rules = [{
        "id": rid,
        "name": rid,
        "shortDescription": {"text": rid},
        "help": {"text": ""}
    } for rid in rule_ids]

    def _sev_to_level(s: str) -> str:
        s = (s or "").lower()
        if s in ("kritik", "yüksek", "high", "critical"): return "error"
        if s in ("orta", "medium"): return "warning"
        return "note"

    sarif_results = []
    for it in items:
        rid = str(it.get("type") or it.get("title") or "finding")
        msg = it.get("description") or it.get("title") or rid
        loc = it.get("url") or it.get("location") or "n/a"
        sarif_results.append({
            "ruleId": rid,
            "level": _sev_to_level(it.get("severity") or "Bilgi"),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc}
                }
            }]
        })
    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "rules": rules}},
            "results": sarif_results
        }]
    }


def to_junit(results: Dict, suite_name: str = "websec") -> str:
    import xml.sax.saxutils as sx
    items = _iter_findings(results)
    total = len(items)
    errors = sum(1 for i in items if str(i.get("severity", "")).lower() in ("kritik", "yüksek", "critical", "high"))
    failures = sum(1 for i in items if str(i.get("severity", "")).lower() in ("orta", "medium"))
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
        if sev in ("kritik", "yüksek", "critical", "high"):
            parts.append(f"    <error message='{name}'><![CDATA[{msg}]]></error>")
        elif sev in ("orta", "medium"):
            parts.append(f"    <failure message='{name}'><![CDATA[{msg}]]></failure>")
        parts.append("  </testcase>")
    parts.append("</testsuite>")
    return "\n".join(parts)


_plan_logs = []


def add_plan_log(phase_id: str, step: str, data: dict):
    _plan_logs.append({"phase": phase_id, "step": step, "data": data, "ts": datetime.utcnow().isoformat() + "Z"})


def get_plan_logs():
    return list(_plan_logs)


def attach_oast_evidence(result: dict, events):
    if not events:
        return result
    ev = result.setdefault("evidence", {})
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
    md.append("\\n## Public Surface Summary")
    md.append(f"- Unique endpoints: {sections['public_surface']['endpoints']}")
    md.append(f"- JS hints: {sections['public_surface']['js_hints']}")
    md.append(f"- JS candidates: {sections['public_surface']['js_candidates']}")
    md_path = str(Path(out_dir, "report_addendum.md"))
    json_path = str(Path(out_dir, "report_addendum.json"))
    Path(md_path).write_text("\\n".join(md), encoding="utf-8")
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
        d = by_type.setdefault(t, {"Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Bilgi": 0})
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
    totals = {"Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Bilgi": 0}
    for d in by_type.values():
        for k in list(totals.keys()):
            totals[k] += int(d.get(k, 0) or 0)
    lines = []
    lines.append("## Risk Matrisi")
    lines.append("| Tür | Kritik | Yüksek | Orta | Düşük | Bilgi | Toplam |")
    lines.append("|-|-:|-:|-:|-:|-:|-:|")
    for t, d in sorted(by_type.items(), key=lambda kv: (-kv[1].get("Kritik", 0), -kv[1].get("Yüksek", 0), kv[0])):
        tot = int(d.get('Kritik', 0) or 0) + int(d.get('Yüksek', 0) or 0) + int(d.get('Orta', 0) or 0) + int(
            d.get('Düşük', 0) or 0) + int(d.get('Bilgi', 0) or 0)
        lines.append(
            f"| {t} | {d.get('Kritik', 0)} | {d.get('Yüksek', 0)} | {d.get('Orta', 0)} | {d.get('Düşük', 0)} | {d.get('Bilgi', 0)} | {tot} |")
    lines.append(
        f"| **Toplam** | **{totals['Kritik']}** | **{totals['Yüksek']}** | **{totals['Orta']}** | **{totals['Düşük']}** | **{totals['Bilgi']}** | **{sum(totals.values())}** |")
    lines.append("")
    lines.append(_gen_mermaid_pie("Bulgu Dağılımı (Şiddet)", totals))
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
    import json as _json  # safe use
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
            lines.append(f"- Benzer Parametreler: `{_json.dumps(sim, ensure_ascii=False)}`")
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
        steps.append(f"4) Doğrulama: Gözlenen belirti → {ind}")
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
        ev = it.get("evidence") or {}
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
    Hem ayrıntılı 'port_scan' listesi (dict) hem de özet 'port_scan_summary.open' (int listesi)
    ile çalışır.
    """

    def _as_int(x):
        # bool -> dışla, int -> al, str sayısal -> al, aksi halde None
        if isinstance(x, bool):
            return None
        if isinstance(x, int):
            return x
        if isinstance(x, str):
            s = x.strip()
            if s and (s.isdigit() or (s[0] in "+-" and s[1:].isdigit())):
                return int(s)
        return None

    rows: list[dict] = []

    # 1) Ayrıntı varsa onu kullan (daha zengin veri)
    scan_list = results.get("port_scan") or []
    if isinstance(scan_list, list) and any(isinstance(it, dict) for it in scan_list):
        for it in scan_list:
            if not isinstance(it, dict):
                continue
            st = str(it.get("state") or "").lower()
            if st == "open" or st.startswith("open"):
                port = _as_int(it.get("port"))
                if port is None:
                    continue
                rows.append({
                    "host": str(it.get("host") or ""),
                    "port": port,
                    "service": str(it.get("service") or ""),
                    "banner": str(it.get("banner") or ""),
                })
    else:
        # 2) Özet mod: int listesi -> satıra dönüştür
        summ = results.get("port_scan_summary") or {}
        opened = (summ.get("open") or summ.get("open_ports") or [])
        host_default = str(summ.get("host") or "")
        if not host_default:
            meta = (results.get("meta") if isinstance(results, dict) else {})
            if isinstance(meta, list):
                meta = next((x for x in meta if isinstance(x, dict)), {})
            target = str((meta.get("target") if isinstance(meta, dict) else "") or "")
            if target:
                host_default = urlparse(target).hostname or ""
        for it in opened:
            if isinstance(it, dict):
                port = _as_int(it.get("port"))
                if port is None:
                    continue
                rows.append({
                    "host": str(it.get("host") or host_default),
                    "port": port,
                    "service": str(it.get("service") or ""),
                    "banner": str(it.get("banner") or ""),
                })
            else:
                port = _as_int(it)
                if port is None:
                    continue
                rows.append({"host": host_default, "port": port, "service": "", "banner": ""})

    if not rows:
        return "_Açık port bulunamadı._"

    # Stabil sıralama: host, port
    rows.sort(key=lambda r: (r["host"], r["port"]))

    lines = ["| Host | Port | Servis | Banner |", "|-|-|-|-|"]
    for r in rows[:200]:
        lines.append(f"| {r['host']} | {r['port']} | {r['service']} | {r['banner']} |")
    return "\n".join(lines)


def _e_table_tls_headers(results: Dict[str, Any]) -> str:
    tls = results.get("tls_summary") or []
    hdr = results.get("security_headers_summary") or {}
    lines = []
    # TLS
    if tls:
        lines.append("**TLS Özeti**")
        lines.append("")
        lines.append("| Host | Versiyon | CN | Durum | HSTS | Geçerlilik | Sorunlar |")
        lines.append("|-|-|-|-|-|")
        for t in tls[:50]:
            valid = ""
            issues = ",".join(t.get("issues") or [])
            lines.append(
                f"| {t.get('host') or ''} | {t.get('tls_version') or ''} | {t.get('cn') or ''} | {t.get('status') or ''} | {issues} |")
        lines.append("")
    # Headers
    if hdr:
        lines.append("**Security Headers Özeti**")
        lines.append("")
        lines.append("| Başlık | Durum | Not |")
        lines.append("|-|-|-|")
        for k, v in (hdr.get("matrix") or {}).items():
            lines.append(f"| {k} | {v.get('status') or ''} | {v.get('note') or ''} |")
        lines.append("")
    return "\n".join(lines) if lines else "_TLS/Headers özeti mevcut değil._"


def _e_glossary() -> str:
    return (
        "### Sözlük\n"
        "- **SQLi (SQL Injection):** Kullanıcı girdisinin SQL sorgusunun parçası hâline getirilmesiyle veritabanına izinsiz erişim veya değişiklik yapılması.\n"
        "- **XSS (Cross-Site Scripting):** Zararlı JavaScript’in kullanıcı tarayıcısında çalıştırılmasıyla oturum çalma, sahte arayüz vb.\n"
        "- **SSRF (Server-Side Request Forgery):** Sunucunun iç ağ/metadata gibi beklenmeyen hedeflere istek atmaya zorlanması.\n"
        "- **XXE (XML External Entity):** XML parser’ın harici entity okuması sonucu dosya sızdırma veya SSRF etkisine yol açması.\n"
        "- **JWT:** JSON Web Token üzerinde doğrulama/alg/manipülasyon zaafiyetleri (ör. RS256→HS256, kid injection).\n"
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
    if sev_counts.get("Kritik", 0):
        risk_brief.append(f"{sev_counts['Kritik']} kritik")
    if sev_counts.get("Yüksek", 0):
        risk_brief.append(f"{sev_counts['Yüksek']} yüksek")
    if not risk_brief:
        risk_brief.append("kritik/yüksek bulgu yok")
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

    # ===== Teknik Detay (Her bulgu) =====
    lines.append("## Teknik Detay")
    rank_order = {"Kritik": 4, "Yüksek": 3, "Orta": 2, "Düşük": 1, "Bilgi": 0}
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
        for s in it.get("repro_steps") or []:
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
        except Exception:
            # avoid try/except in user code; this is reporting module internal
            pass
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
except Exception:  # pragma: no cover
    _weakref = None

# Weak registry of "quitable" resources (e.g., Selenium WebDriver)
if "_WS_QUITABLES" not in globals():
    _WS_QUITABLES = _weakref.WeakSet() if _weakref is not None else set()
if "_WS_FINALIZED" not in globals():
    _WS_FINALIZED = False

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
        except Exception:
            pass
        return True
    except Exception:
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
        except Exception as e:
            try:
                add_result("errors", {"stage":"teardown", "error": str(e)})
            except Exception:
                pass
    # clear registry (best-effort)
    try:
        if hasattr(_WS_QUITABLES, "clear"):
            _WS_QUITABLES.clear()
    except Exception:
        pass
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
            except Exception:
                pass
    except Exception:
        pass

    _WS_FINALIZED = True
    return written or {}


def _pull_metrics(ctx) -> dict:
    d = {}
    for k in ("http_metrics","coverage","engagement"):
        if hasattr(ctx, k):
            d[k] = getattr(ctx,k)
    return d
