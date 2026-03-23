"""
websecure.core.analysis
-----------------------
Consolidated module for:
- Regex Safety (formerly safe_regex.py)
- Endpoint Storage (formerly endpoint_store.py)
- Anomaly Detection (formerly detect.py)
- WAF Detection & Evasion (formerly waf.py)
- Captcha Solving (formerly captcha.py)
- Login Dicovery (formerly login_discovery.py)
"""
from __future__ import annotations
import os
import re
import time
import json
import math
import random
import secrets
import string
import logging
import base64
import io
import statistics
import threading
import contextlib
import importlib.util
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, TypedDict, Callable, Iterable, Protocol, runtime_checkable
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin, parse_qsl, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry

# Optional Dependencies
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    from rapidfuzz import fuzz as rapidfuzz_fuzz
except ImportError:
    rapidfuzz_fuzz = None

try:
    import Levenshtein
except ImportError:
    Levenshtein = None

try:
    from sentence_transformers import SentenceTransformer, util as st_util
except ImportError:
    SentenceTransformer = None
    st_util = None

try:
    import pytesseract
    from PIL import Image
except ImportError:
    pytesseract = None
    Image = None

# WebSecure Imports
from websecure.core.utils import normalize_url, resolve_canonical_base, hardened_session, verify_for_phase
from websecure.core.reporting import add_result, log_warn

_logger = logging.getLogger(__name__)

# ============================================================================
# SECTION 1: SAFE REGEX (formerly safe_regex.py)
# ============================================================================

_DEFAULT_TIMEOUT_MS = 200
_current_timeout_ms = _DEFAULT_TIMEOUT_MS

def get_default_timeout_ms() -> int:
    return int(_current_timeout_ms)

def set_default_timeout_ms(ms: int) -> None:
    global _current_timeout_ms
    _current_timeout_ms = max(1, int(ms)) if ms > 0 else _DEFAULT_TIMEOUT_MS

def _run_with_timeout(fn, timeout_ms: Optional[int] = None):
    ms = timeout_ms if timeout_ms is not None else _current_timeout_ms
    ms = int(ms) if ms else _DEFAULT_TIMEOUT_MS
    
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(fn)
        if ms > 0:
            deadline = time.time() + (ms / 1000.0)
            sleep_step = max(0.005, min(0.05, ms / 1000.0 / 10.0))
            while True:
                if fut.done():
                    return fut.result()
                if time.time() >= deadline:
                    fut.cancel()
                    _logger.warning(f"Regex timed out after {ms}ms")
                    raise TimeoutError(f"Regex timed out ({ms} ms)")
                time.sleep(sleep_step)
        else:
            return fut.result()

def safe_compile(pattern: str, flags: int = 0) -> re.Pattern:
    # Basic linting
    if re.search(r"\.\{10,}", pattern):
        _logger.warning("Potential ReDoS pattern detected: large repetition")
    return re.compile(pattern, flags)

def safe_search(pattern: str, string: str, flags: int = 0, timeout_ms: int = None):
    return _run_with_timeout(lambda: re.search(pattern, string, flags), timeout_ms)

# ============================================================================
# SECTION 2: ENDPOINT STORE (formerly endpoint_store.py)
# ============================================================================

@dataclass
class EndpointStore:
    items: Set[str] = field(default_factory=set)

    def add_many(self, urls: Iterable[str]) -> None:
        for u in urls:
            if isinstance(u, str) and u.strip():
                self.items.add(u.strip())

    def to_list(self) -> List[str]:
        return sorted(self.items)

# ============================================================================
# SECTION 3: ANOMALY DETECTION (formerly detect.py)
# ============================================================================

class BaselineMeta(TypedDict, total=False):
    len: int
    time_samples: List[float]
    body: str

class CurrentMeta(TypedDict, total=False):
    len: int
    time_ms: float
    body: str

def size_delta(baseline_len: int, current_len: int) -> int:
    return abs(int(current_len) - int(baseline_len))

def levenshtein_ratio(a: str, b: str) -> float:
    if a is None or b is None: return 0.0
    a, b = str(a), str(b)
    if rapidfuzz_fuzz: return float(rapidfuzz_fuzz.ratio(a, b)) / 100.0
    if Levenshtein: return float(Levenshtein.ratio(a, b))
    from difflib import SequenceMatcher
    return float(SequenceMatcher(None, a, b).ratio())

def time_stddev(samples_ms: List[float]) -> float:
    n = max(1, len(samples_ms))
    if n < 2: return 0.0
    mean = sum(samples_ms) / n
    var = sum((x - mean) ** 2 for x in samples_ms) / (n - 1)
    return math.sqrt(var)

_sem_model = None
def _get_semantic_model():
    global _sem_model
    if _sem_model: return _sem_model
    if SentenceTransformer:
        _sem_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _sem_model

def semantic_ratio(a: str, b: str, html_aware: bool = True) -> float:
    if not (a and b): return 0.0
    if html_aware and BeautifulSoup:
        a = BeautifulSoup(a, "html.parser").get_text(" ")
        b = BeautifulSoup(b, "html.parser").get_text(" ")
    
    model = _get_semantic_model()
    if model and st_util:
        emb = model.encode([a, b], convert_to_tensor=True, show_progress_bar=False)
        score = float(st_util.cos_sim(emb[0], emb[1]).cpu().numpy())
        return (score + 1.0) / 2.0
    return levenshtein_ratio(a, b)

def anomaly_score(baseline: BaselineMeta, current: CurrentMeta, thresholds: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    th = {"size_delta": 1024.0, "time_stddev": 250.0, "lev_ratio": 0.85, "semantic_ratio": 0.80}
    if thresholds: th.update(thresholds)

    sd = size_delta(baseline.get("len", 0), current.get("len", 0))
    tsamples = list(baseline.get("time_samples", []))
    if "time_ms" in current: tsamples.append(float(current["time_ms"]))
    tsd = time_stddev(tsamples) if tsamples else 0.0
    
    a_body, b_body = str(baseline.get("body", "")), str(current.get("body", ""))
    lev = levenshtein_ratio(a_body, b_body)
    sem = semantic_ratio(a_body, b_body)
    
    sig_size = sd >= float(th["size_delta"])
    sig_time = tsd >= float(th["time_stddev"])
    sig_diff = lev <= float(th["lev_ratio"])
    sig_sem = sem <= float(th["semantic_ratio"])
    
    score = (int(sig_size) + int(sig_time) + int(sig_diff) + int(sig_sem)) / 4.0
    
    return {
        "score": score,
        "signals": {"size": sig_size, "time": sig_time, "diff": sig_diff, "semantic": sig_sem},
        "metrics": {"size_delta": sd, "time_stddev": tsd, "lev_ratio": lev, "semantic_ratio": sem}
    }

def detect_get_parameters_and_forms(url: str, driver=None, debug: bool = False, *, fetcher: Optional[callable] = None) -> Tuple[str, List[str], List[Dict[str, Any]]]:
    # Canonicalize
    url = normalize_url(url)
    parsed = urlparse(url)
    get_params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    
    html = ""
    if callable(fetcher): html = fetcher(url) or ""
    elif driver:
        driver.get(url)
        html = getattr(driver, "page_source", "")
        
    forms = []
    if html and BeautifulSoup:
        soup = BeautifulSoup(html, "html.parser")
        for idx, form in enumerate(soup.find_all("form")):
            inputs_meta = []
            for inp in form.find_all(["input", "textarea", "select", "button"]):
                inputs_meta.append({
                    "tag": inp.name,
                    "name": inp.get("name"),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", "")
                })
            forms.append({
                "index": idx,
                "action": form.get("action") or url,
                "method": (form.get("method") or "GET").upper(),
                "inputs": inputs_meta
            })
            
    return url, get_params, forms

def detect_graphql(url: str, body: str | bytes) -> bool:
    t = (body if isinstance(body, str) else body.decode("utf-8", "ignore")).lower()
    return "__schema" in t or "graphql" in t or url.lower().endswith("/graphql")

def cloud_hints(headers: Dict[str, Any]) -> List[str]:
    hints = []
    for v in headers.values():
        val = str(v).lower()
        if any(x in val for x in ["amazon", "s3", "cloudfront"]): hints.append("aws")
        if any(x in val for x in ["google", "gcp", "appengine"]): hints.append("gcp")
        if "azure" in val or "microsoft" in val: hints.append("azure")
    return sorted(set(hints))

def classify_401_403(resp) -> Optional[str]:
    status = getattr(resp, "status_code", None)
    if status not in (401, 403): return None
    text = (getattr(resp, "text", "") or "").lower()
    headers = {str(k).lower(): str(v).lower() for k, v in (getattr(resp, "headers", {}) or {}).items()}
    
    waf_keys = ("cf-ray", "cloudflare", "akamai", "imperva", "incapsula", "mod_security")
    if any(k in headers.get("server", "") for k in waf_keys) or "waf" in text:
        return "WAF"
    if headers.get("retry-after") or "rate limit" in text:
        return "RateLimit"
    return "Auth"

# ============================================================================
# SECTION 4: WAF DETECTION & EVASION (formerly waf.py)
# ============================================================================

_WAF_SIGNS = [
    ("cloudflare", ["cloudflare", "cf-ray", "cf-cache-status"]),
    ("akamai", ["akamai", "akamai-ghost"]),
    ("imperva", ["incapsula", "visid_incap"]),
    ("modsecurity", ["mod_security", "modsecurity"]),
]

_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
]

def _load_cfg() -> Dict[str, Any]:
    env = os.getenv("WEBSECURE_CONFIG") or os.getenv("WEBSEC_CONFIG")
    path = Path(env) if env else Path("config.json")
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def get_waf_cfg() -> Dict[str, Any]:
    cfg = _load_cfg()
    wc = (cfg.get("waf") or {}) if isinstance(cfg, dict) else {}
    # Defaults
    wc.setdefault("enabled", False)
    wc.setdefault("header_tactics", ["random_ua", "x_forwarded", "cache_bust"])
    wc.setdefault("strategies", ["encode", "caseflip", "comments", "space", "xsshex"])
    wc.setdefault("blocked_statuses", [406, 409, 429, 503])
    return wc

# --- Mutation Helpers ---
_SQLI_KEYWORDS = ["select","union","from","where","and","or","sleep","updatexml"]
def _flip_case_sql(s: str) -> str:
    return re.sub(r"(?i)\b(" + "|".join(_SQLI_KEYWORDS) + r")\b", 
                  lambda m: "".join(c.upper() if random.random()<0.5 else c.lower() for c in m.group(0)), s)

def _insert_comments_sql(s: str) -> str:
    return re.sub(r"(?i)\b(" + "|".join(_SQLI_KEYWORDS) + r")\b", 
                  lambda m: m.group(0)[:len(m.group(0))//2] + "/**/" + m.group(0)[len(m.group(0))//2:], s)

def _url_encode_chunks(s: str) -> str:
    return "".join(c if c.isalnum() else f"%{ord(c):02X}" for c in s)

def _double_url_encode(s: str) -> str:
    # Encode once, then encode the % signs
    base = "".join(c if c.isalnum() else f"%{ord(c):02X}" for c in s)
    return base.replace("%", "%25")

def _sql_hex_encode(s: str) -> str:
    # Convert string literals 'text' to 0x74657874 if possible
    # Detects quoted strings and converts them
    def _hex_repl(m):
        content = m.group(1)
        return "0x" + content.encode("utf-8").hex()
    return re.sub(r"'([^']{2,})'", _hex_repl, s)

def _whitespace_bypass(s: str) -> str:
    # Replace spaces with tabs, newlines, or comments
    replacements = ["%09", "%0A", "%0D", "/**/", "+"]
    return s.replace(" ", random.choice(replacements))

def _nullbyte_bypass(s: str) -> str:
    # Inject null byte before payload to confuse WAF parsers (e.g. ModSecurity old versions)
    return "%00" + s

def _unicode_bypass(s: str) -> str:
    # Replace some characters with unicode lookalikes
    # e.g. < -> \uff1c (Fullwidth Less-Than Sign)
    # Simple map for demonstration
    mapping = {
        "<": "\uff1c",
        ">": "\uff1e",
        "'": "\u02b9",
        '"': "\u02ba"
    }
    return "".join(mapping.get(c, c) for c in s)

def _cmd_obfuscate(s: str) -> str:
    # Basic command obfuscation for Linux/Unix
    # cat /etc/passwd -> c'at' /e'tc'/p'asswd'
    def _quote_char(m):
        c = m.group(0)
        return f"'{c}'" if random.random() < 0.3 else c
    
    # Don't quote special shell chars heavily
    specials = "|&; $`\\\"'"
    out = ""
    for char in s:
        if char in specials:
             out += char
        elif char.isalnum():
             out += f"'{char}'" if random.random() < 0.2 else char
        else:
             out += char
    return out.replace("''", "")


def mutate_payload(category: str, payload: str, cfg: Dict[str, Any] | None) -> List[str]:
    if not payload: return []
    if not cfg or not cfg.get("enabled", False): return [payload]
    
    strategies = set((cfg.get("strategies") or []))
    # Eğer strateji listesi boşsa varsayılanları doldur (aggressive mod için)
    if not strategies:
        strategies = {"encode", "caseflip", "comments", "double_encode", "nullbyte", "unicode", "cmd_quote"}
        
    variants = [payload]
    
    if "encode" in strategies:
        variants.append(_url_encode_chunks(payload))
    
    if "double_encode" in strategies:
        variants.append(_double_url_encode(payload))

    if category == "sqli":
        if "caseflip" in strategies:
            variants.append(_flip_case_sql(payload))
        if "comments" in strategies:
            variants.append(_insert_comments_sql(payload))
        if "sql_hex" in strategies:
            variants.append(_sql_hex_encode(payload))
        if "whitespace" in strategies:
            variants.append(_whitespace_bypass(payload))
        if "nullbyte" in strategies:
            variants.append(_nullbyte_bypass(payload))
        if "unicode" in strategies:
            variants.append(_unicode_bypass(payload))
    
    if category in ("rce", "exploit", "cmdi"):
        if "cmd_quote" in strategies:
            variants.append(_cmd_obfuscate(payload))
        if "nullbyte" in strategies:
             variants.append(_nullbyte_bypass(payload))
            
    if category == "xss" and "html_entity" in strategies:
         # Basic HTML entity encoding
         variants.append("".join(f"&#x{ord(c):x};" for c in payload))

    return list(dict.fromkeys(variants))[:int(cfg.get("max_variants_per_payload", 10))]

def mutate_payloads(category: str, payloads: Iterable[str], cfg: Dict[str, Any] | None) -> List[str]:
    out = []
    seen = set()
    for p in payloads:
        for v in mutate_payload(category, p, cfg):
            if v not in seen:
                seen.add(v); out.append(v)
    return out

# --- WAF Detection ---

@dataclass
class WAFDetection:
    vendor: Optional[str]
    blocked: bool
    reasons: List[str]

    def __bool__(self):
        return self.blocked

def detect_waf_from_response(resp: requests.Response, cfg: Dict[str, Any] | None = None) -> WAFDetection:
    cfg = cfg or get_waf_cfg()
    reasons = []
    vendor = None
    
    # 1. Status
    if resp.status_code in set(cfg.get("blocked_statuses", [])):
        reasons.append(f"status={resp.status_code}")
        
    # 2. Headers
    h_str = str(resp.headers).lower()
    for name, signs in _WAF_SIGNS:
        if any(s in h_str for s in signs):
            vendor = name
            reasons.append(f"header_sign={name}")
            
    # 3. Body
    text = (resp.text or "").lower()
    if "blocked" in text or "waf" in text or "denied" in text:
        reasons.append("body_block_marker")
        
    return WAFDetection(vendor=vendor, blocked=bool(reasons), reasons=reasons)

def next_user_agent() -> str:
    return random.choice(_UA_LIST)

def build_waf_headers(existing: Dict[str,str] = None, cfg: Dict[str,Any] = None) -> Dict[str,str]:
    h = dict(existing or {})
    cfg = cfg or get_waf_cfg()
    if not cfg.get("enabled"): return h
    
    tactics = set(cfg.get("header_tactics") or [])
    if "random_ua" in tactics:
        h["User-Agent"] = next_user_agent()
    if "x_forwarded" in tactics:
        h["X-Forwarded-For"] = f"127.0.{random.randint(1,255)}.{random.randint(1,255)}"
    if "cache_bust" in tactics:
        h["Cache-Control"] = "no-cache"
    return h

def request_with_waf(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    cfg = kwargs.get("cfg") or get_waf_cfg()
    if "cfg" in kwargs: del kwargs["cfg"]
    
    kwargs["headers"] = build_waf_headers(kwargs.get("headers"), cfg)
    resp = session.request(method, url, **kwargs)
    
    # Simple retry logic could go here if blocked
    return resp

# ============================================================================
# SECTION 5: CAPTCHA (formerly captcha.py)
# ============================================================================

@dataclass
class CaptchaConfig:
    provider: str = "none"
    api_key: Optional[str] = None
    site_key: Optional[str] = None
    site_url: Optional[str] = None
    tesseract_lang: str = "eng"
    timeout_sec: int = 120
    poll_interval_sec: int = 5
    two_captcha_base: str = "https://2captcha.com"
    anti_captcha_base: str = "https://api.anti-captcha.com"
    # CapSolver / gelişmiş ayarlar
    capsolver_base: str = "https://api.capsolver.com"
    recaptcha_type: str = "RecaptchaV2TaskProxyless"  # V3 için: RecaptchaV3TaskProxyless
    recaptcha_action: str = ""           # reCAPTCHA v3 action adı
    min_score: float = 0.5               # reCAPTCHA v3 minimum skor
    hcaptcha_enterprise_payload: Optional[Dict[str, Any]] = None


def read_captcha_config(config: Dict[str, Any]) -> CaptchaConfig:
    sec = (config or {}).get("settings", {}).get("security", {}) if config else {}
    c = sec.get("captcha", {}) if isinstance(sec, dict) else {}
    return CaptchaConfig(
        provider=c.get("provider", "none"),
        api_key=c.get("api_key"),
        site_key=c.get("site_key"),
        site_url=c.get("site_url"),
        tesseract_lang=c.get("tesseract_lang", "eng"),
        timeout_sec=int(c.get("timeout_sec", 120)),
        poll_interval_sec=int(c.get("poll_interval_sec", 5)),
        two_captcha_base=c.get("two_captcha_base", "https://2captcha.com"),
        anti_captcha_base=c.get("anti_captcha_base", "https://api.anti-captcha.com"),
        capsolver_base=c.get("capsolver_base", "https://api.capsolver.com"),
        recaptcha_type=c.get("recaptcha_type", "RecaptchaV2TaskProxyless"),
        recaptcha_action=c.get("recaptcha_action", ""),
        min_score=float(c.get("min_score", 0.5)),
        hcaptcha_enterprise_payload=c.get("hcaptcha_enterprise_payload"),
    )


@runtime_checkable
class ImageCaptchaSolver(Protocol):
    def solve(self, img_bytes: bytes, cfg: CaptchaConfig) -> Optional[str]: ...

@runtime_checkable
class RecaptchaV2Solver(Protocol):
    def solve(self, site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]: ...


class NoneProvider(ImageCaptchaSolver, RecaptchaV2Solver):
    def solve(self, *a, **k) -> Optional[str]:
        return None


class OCRProvider(ImageCaptchaSolver):
    def solve(self, img_bytes: bytes, cfg: CaptchaConfig) -> Optional[str]:
        if not (Image and pytesseract):
            return None
        img = Image.open(io.BytesIO(img_bytes))
        return pytesseract.image_to_string(img, lang=cfg.tesseract_lang).strip() or None


# ---------------------------------------------------------------------------
# 2captcha Provider (resim + reCAPTCHA v2/v3 + hCaptcha + Turnstile)
# ---------------------------------------------------------------------------

class TwoCaptchaProvider(ImageCaptchaSolver):
    """
    2captcha.com API entegrasyonu.

    Desteklenen tipler:
      - Resim CAPTCHA  → solve(img_bytes, cfg)
      - reCAPTCHA v2   → solve_recaptcha(site_key, site_url, cfg)
      - reCAPTCHA v3   → solve_recaptcha_v3(site_key, site_url, cfg)
      - hCaptcha       → solve_hcaptcha(site_key, site_url, cfg)
      - Turnstile      → solve_turnstile(site_key, site_url, cfg)
    """

    # --- Ortak polling yardımcısı ---
    @staticmethod
    def _poll_result(api_key: str, req_id: str, cfg: CaptchaConfig, base: str) -> Optional[str]:
        start = time.time()
        while time.time() - start < cfg.timeout_sec:
            time.sleep(cfg.poll_interval_sec)
            try:
                r = requests.get(
                    f"{base}/res.php",
                    params={"key": api_key, "action": "get", "id": req_id, "json": 1},
                    timeout=30,
                )
                d = r.json()
                if d.get("status") == 1:
                    return d.get("request")
                if d.get("request") == "ERROR_CAPTCHA_UNSOLVABLE":
                    return None
            except Exception:
                pass
        return None

    def solve(self, img_bytes: bytes, cfg: CaptchaConfig) -> Optional[str]:
        """Resim CAPTCHA çözme."""
        if not cfg.api_key:
            return None
        try:
            r = requests.post(
                f"{cfg.two_captcha_base}/in.php",
                data={
                    "key": cfg.api_key,
                    "method": "base64",
                    "body": base64.b64encode(img_bytes).decode("ascii"),
                    "json": 1,
                },
                timeout=30,
            )
            d = r.json()
            if d.get("status") != 1:
                return None
            return self._poll_result(cfg.api_key, str(d["request"]), cfg, cfg.two_captcha_base)
        except Exception:
            return None

    def solve_recaptcha(self, site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
        """reCAPTCHA v2 token çözme."""
        if not cfg.api_key:
            return None
        try:
            r = requests.post(
                f"{cfg.two_captcha_base}/in.php",
                data={
                    "key": cfg.api_key,
                    "method": "userrecaptcha",
                    "googlekey": site_key,
                    "pageurl": site_url,
                    "json": 1,
                },
                timeout=30,
            )
            d = r.json()
            if d.get("status") != 1:
                return None
            return self._poll_result(cfg.api_key, str(d["request"]), cfg, cfg.two_captcha_base)
        except Exception:
            return None

    def solve_recaptcha_v3(self, site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
        """reCAPTCHA v3 token çözme."""
        if not cfg.api_key:
            return None
        try:
            data: Dict[str, Any] = {
                "key": cfg.api_key,
                "method": "userrecaptcha",
                "version": "v3",
                "googlekey": site_key,
                "pageurl": site_url,
                "min_score": cfg.min_score,
                "json": 1,
            }
            if cfg.recaptcha_action:
                data["action"] = cfg.recaptcha_action
            r = requests.post(f"{cfg.two_captcha_base}/in.php", data=data, timeout=30)
            d = r.json()
            if d.get("status") != 1:
                return None
            return self._poll_result(cfg.api_key, str(d["request"]), cfg, cfg.two_captcha_base)
        except Exception:
            return None

    def solve_hcaptcha(self, site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
        """hCaptcha token çözme."""
        if not cfg.api_key:
            return None
        try:
            data: Dict[str, Any] = {
                "key": cfg.api_key,
                "method": "hcaptcha",
                "sitekey": site_key,
                "pageurl": site_url,
                "json": 1,
            }
            r = requests.post(f"{cfg.two_captcha_base}/in.php", data=data, timeout=30)
            d = r.json()
            if d.get("status") != 1:
                return None
            return self._poll_result(cfg.api_key, str(d["request"]), cfg, cfg.two_captcha_base)
        except Exception:
            return None

    def solve_turnstile(self, site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
        """Cloudflare Turnstile token çözme."""
        if not cfg.api_key:
            return None
        try:
            data: Dict[str, Any] = {
                "key": cfg.api_key,
                "method": "turnstile",
                "sitekey": site_key,
                "pageurl": site_url,
                "json": 1,
            }
            r = requests.post(f"{cfg.two_captcha_base}/in.php", data=data, timeout=30)
            d = r.json()
            if d.get("status") != 1:
                return None
            return self._poll_result(cfg.api_key, str(d["request"]), cfg, cfg.two_captcha_base)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# CapSolver Provider (resim + reCAPTCHA v2/v3 + hCaptcha + Turnstile + Funcaptcha)
# ---------------------------------------------------------------------------

class CapSolverProvider(ImageCaptchaSolver):
    """
    CapSolver API entegrasyonu (api.capsolver.com).

    CapSolver, 2captcha'dan farklı bir REST yapısı kullanır:
      POST /createTask  → {"taskId": "..."}
      POST /getTaskResult → {"status": "ready", "solution": {...}}

    Desteklenen tipler:
      - Resim CAPTCHA       → ImageToTextTask
      - reCAPTCHA v2        → ReCaptchaV2TaskProxyless
      - reCAPTCHA v3        → ReCaptchaV3TaskProxyless
      - hCaptcha            → HCaptchaTaskProxyless
      - Cloudflare Turnstile→ AntiCloudflareTask
      - Funcaptcha          → FunCaptchaTaskProxyless
    """

    def _create_task(self, cfg: CaptchaConfig, task: Dict[str, Any]) -> Optional[str]:
        """Görev oluştur, taskId döner."""
        try:
            r = requests.post(
                f"{cfg.capsolver_base}/createTask",
                json={"clientKey": cfg.api_key, "task": task},
                timeout=30,
            )
            d = r.json()
            if d.get("errorId", 1) != 0:
                return None
            return str(d.get("taskId", ""))
        except Exception:
            return None

    def _get_result(self, cfg: CaptchaConfig, task_id: str) -> Optional[Dict[str, Any]]:
        """Sonuç gelene kadar polling yap."""
        start = time.time()
        while time.time() - start < cfg.timeout_sec:
            time.sleep(cfg.poll_interval_sec)
            try:
                r = requests.post(
                    f"{cfg.capsolver_base}/getTaskResult",
                    json={"clientKey": cfg.api_key, "taskId": task_id},
                    timeout=30,
                )
                d = r.json()
                if d.get("errorId", 1) != 0:
                    return None
                if d.get("status") == "ready":
                    return d.get("solution") or {}
            except Exception:
                pass
        return None

    def solve(self, img_bytes: bytes, cfg: CaptchaConfig) -> Optional[str]:
        """Resim CAPTCHA çözme."""
        if not cfg.api_key:
            return None
        task_id = self._create_task(cfg, {
            "type": "ImageToTextTask",
            "body": base64.b64encode(img_bytes).decode("ascii"),
        })
        if not task_id:
            return None
        sol = self._get_result(cfg, task_id)
        return sol.get("text") if sol else None

    def solve_recaptcha(self, site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
        """reCAPTCHA v2 token çözme."""
        if not cfg.api_key:
            return None
        task_type = cfg.recaptcha_type or "ReCaptchaV2TaskProxyless"
        task_id = self._create_task(cfg, {
            "type": task_type,
            "websiteURL": site_url,
            "websiteKey": site_key,
        })
        if not task_id:
            return None
        sol = self._get_result(cfg, task_id)
        return sol.get("gRecaptchaResponse") if sol else None

    def solve_recaptcha_v3(self, site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
        """reCAPTCHA v3 token çözme."""
        if not cfg.api_key:
            return None
        task: Dict[str, Any] = {
            "type": "ReCaptchaV3TaskProxyless",
            "websiteURL": site_url,
            "websiteKey": site_key,
            "minScore": cfg.min_score,
        }
        if cfg.recaptcha_action:
            task["pageAction"] = cfg.recaptcha_action
        task_id = self._create_task(cfg, task)
        if not task_id:
            return None
        sol = self._get_result(cfg, task_id)
        return sol.get("gRecaptchaResponse") if sol else None

    def solve_hcaptcha(self, site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
        """hCaptcha token çözme."""
        if not cfg.api_key:
            return None
        task: Dict[str, Any] = {
            "type": "HCaptchaTaskProxyless",
            "websiteURL": site_url,
            "websiteKey": site_key,
        }
        if cfg.hcaptcha_enterprise_payload:
            task["enterprisePayload"] = cfg.hcaptcha_enterprise_payload
        task_id = self._create_task(cfg, task)
        if not task_id:
            return None
        sol = self._get_result(cfg, task_id)
        return sol.get("gRecaptchaResponse") or sol.get("token") if sol else None

    def solve_turnstile(self, site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
        """Cloudflare Turnstile token çözme."""
        if not cfg.api_key:
            return None
        task_id = self._create_task(cfg, {
            "type": "AntiCloudflareTask",
            "websiteURL": site_url,
            "websiteKey": site_key,
        })
        if not task_id:
            return None
        sol = self._get_result(cfg, task_id)
        return sol.get("token") if sol else None


# ---------------------------------------------------------------------------
# Provider seçici ve yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _select_solver(cfg: CaptchaConfig):
    if cfg.provider == "ocr":
        return OCRProvider()
    if cfg.provider == "2captcha":
        return TwoCaptchaProvider()
    if cfg.provider == "capsolver":
        return CapSolverProvider()
    return NoneProvider()


def solve_image_captcha_png_bytes(img_bytes: bytes, cfg: CaptchaConfig) -> Optional[str]:
    return _select_solver(cfg).solve(img_bytes, cfg)


def solve_recaptcha_v2_token(site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
    s = _select_solver(cfg)
    if hasattr(s, "solve_recaptcha"):
        return s.solve_recaptcha(site_key, site_url, cfg)  # type: ignore
    return None


def solve_recaptcha_v3_token(site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
    s = _select_solver(cfg)
    if hasattr(s, "solve_recaptcha_v3"):
        return s.solve_recaptcha_v3(site_key, site_url, cfg)  # type: ignore
    return None


def solve_hcaptcha_token(site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
    s = _select_solver(cfg)
    if hasattr(s, "solve_hcaptcha"):
        return s.solve_hcaptcha(site_key, site_url, cfg)  # type: ignore
    return None


def solve_turnstile_token(site_key: str, site_url: str, cfg: CaptchaConfig) -> Optional[str]:
    s = _select_solver(cfg)
    if hasattr(s, "solve_turnstile"):
        return s.solve_turnstile(site_key, site_url, cfg)  # type: ignore
    return None

# ============================================================================
# SECTION 6: LOGIN DISCOVERY (formerly login_discovery.py)
# ============================================================================

COMMON_LOGIN_PATHS = (
    "/login", "/signin", "/account/login", "/auth/login", "/admin", "/wp-login.php"
)

TECH_LOGIN_HINTS = {
    "WordPress": ["/wp-login.php", "/wp-admin/"],
    "Joomla": ["/administrator/"],
    "Drupal": ["/user/login"],
    "Django": ["/admin/login", "/accounts/login/"]
}

class LoginDiscovery:
    def __init__(self, session: requests.Session):
        self.session = session
        
    def score_page(self, html: str, url: str) -> int:
        score = 0
        html_lower = html.lower()
        if "password" in html_lower and "type=" in html_lower: score += 5
        if "user" in html_lower or "email" in html_lower: score += 2
        if "login" in url.lower() or "signin" in url.lower(): score += 3
        if "csrf" in html_lower or "token" in html_lower: score += 1
        return score

    def discover(self, base_url: str, seeds: List[str] = None) -> List[Tuple[str, int]]:
        candidates = set(seeds or [])
        # 1. Common paths
        for p in COMMON_LOGIN_PATHS:
            candidates.add(urljoin(base_url, p))
            
        # 2. Check each
        results = []
        for url in candidates:
            try:
                r = self.session.get(url, timeout=5, allow_redirects=True)
                if r.ok:
                    sc = self.score_page(r.text, url)
                    if sc > 0:
                        results.append((url, sc))
            except Exception:
                pass
                
        # 3. Report
        add_result("login_discovery", {
            "base": base_url,
            "candidates": [{"url": u, "score": s} for u, s in results[:10]]
        })
        return sorted(results, key=lambda x: x[1], reverse=True)

    def extract_csrf(self, html_text: str) -> Optional[str]:
        m = re.search(
            r'(?:name|id)\s*=\s*["\'](?:csrf|_csrf|_token|authenticity_token)["\']\s+value\s*=\s*["\']([^"\']+)["\']',
            html_text, re.I
        )
        return m.group(1) if m else None

def discover_login_urls_with_config(session, base_url, cfg=None) -> List[Tuple[str, int]]:
    ld = LoginDiscovery(session)
    seeds = (cfg or {}).get("login_discovery", {}).get("extra_paths", []) if cfg else []
    return ld.discover(base_url, seeds=seeds)

def extract_csrf(html_text: str) -> Optional[str]:
    return LoginDiscovery(None).extract_csrf(html_text)


# ===========================================================================
# MERGED FROM: websecure/core/input_analyzer.py
# Smart Input Context Analyzer — context-aware payload category detection
# ===========================================================================
# -*- coding: utf-8 -*-
"""
Smart Input Context Analyzer for WebSecure (Phase 2)

Bu modül input alanlarının bağlamını analiz eder ve uygun payload kategorilerini belirler.
Phase 2 Özellikleri:
- Derin Değer Analizi (Base64, JSON, JWT tespiti)
- Teknoloji Farkındalığı (Tech-Stack filtering)
"""

from __future__ import annotations
import re
import json
import base64
import binascii
from enum import Enum, auto
from typing import List, Set, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field


class InputContext(Enum):
    """Input alanı bağlam türleri"""
    # Authentication
    USERNAME = auto()       # Kullanıcı adı
    PASSWORD = auto()       # Şifre (skip)
    EMAIL = auto()          # Email
    
    # Data identifiers
    NUMERIC_ID = auto()     # id, user_id (SQLi, IDOR)
    UUID = auto()           # GUID/UUID (SQLi - blind mostly)
    
    # Search & Content
    SEARCH = auto()         # Arama
    TEXT_CONTENT = auto()   # Comment, body
    
    # Navigation & Files
    URL_REDIRECT = auto()   # Redirect
    FILE_PATH = auto()      # LFI
    
    # Structured / Encoded Data (Phase 2 NEW)
    JSON_BODY = auto()      # JSON object
    JSON_STRING = auto()    # JSON in string param
    XML_BODY = auto()       # XML input
    JWT = auto()            # JWT Token
    SERIALIZED = auto()     # PHP/Java Serialization
    BASE64_ENCODED = auto() # Generic Base64 (decode & re-analyze?)
    
    # Sorting & Pagination
    SORT_ORDER = auto()     # order by
    PAGINATION = auto()     # limit, offset
    FILTER = auto()         # category
    
    # Time & Date
    DATE_TIME = auto()
    
    # Special
    HIDDEN = auto()         # hidden
    HEADER = auto()         # header
    COOKIE = auto()         # cookie
    
    # Tokens (Skip)
    CSRF_TOKEN = auto()
    CAPTCHA = auto()
    SESSION = auto()
    
    # Default
    GENERIC = auto()        # Fallback


@dataclass
class ContextAnalysisResult:
    """Bağlam analizi sonucu"""
    context: InputContext
    confidence: float  # 0.0 - 1.0
    applicable_attacks: List[str]
    skip_reason: Optional[str] = None
    decoded_value: Any = None  # Base64 decode sonucu vs.


# =============================================================================
# TECH AWARENESS MAPPING
# =============================================================================

# Saldırı tiplerinin gerektirdiği teknolojiler (varsa)
# Eğer hedef sistemin teknolojileri biliniyorsa ve bu gereksinimlerle ÇAKIŞIYORSA skip edilir.
# Boş liste = Her yerde çalışır veya bağımsız.
_ATTACK_TECH_REQ: Dict[str, Set[str]] = {
    "sqli": {"sql", "mysql", "postgresql", "postgres", "mssql", "oracle", "sqlite", "mariadb"},
    "nosqli": {"nosql", "mongodb", "couchdb", "dynamodb", "redis"},
    "ssti": {"java", "python", "ruby", "nodejs", "php", "go"}, # Hepsi olabilir ama spesifik
    "php_injection": {"php"},
    "asp_net_injection": {"asp", "aspx", "iis", "windows"},
    "iis_shortname": {"iis", "windows"},
    "jsp_injection": {"java", "jsp", "tomcat", "jetty"},
}

# =============================================================================
# CONTEXT PATTERNS & ATTACKS
# =============================================================================

_CONTEXT_PATTERNS: Dict[InputContext, List[str]] = {
    InputContext.USERNAME: [r'^(user|username|login|uname|usr|account|nick)$', r'(user|login)[-_]?(name|id)$'],
    InputContext.PASSWORD: [r'^(pass|password|pwd|secret)$', r'(pass|pwd)[-_]?(word)?$'],
    InputContext.EMAIL: [r'^(email|mail)$', r'(email|mail)[-_]?(address)?$'],
    InputContext.NUMERIC_ID: [r'^id$', r'[-_]?id$', r'^(uid|pid|cid|oid)$'],
    InputContext.SEARCH: [r'^(q|query|search|s|keyword|term)$'],
    InputContext.URL_REDIRECT: [r'^(redirect|next|return|url|goto|dest)$'],
    InputContext.FILE_PATH: [r'^(file|path|doc|template|include|src)$'],
    InputContext.CSRF_TOKEN: [r'^(csrf|xsrf|token)$', r'[-_]?(csrf|xsrf)[-_]?'],
    InputContext.SESSION: [r'^(session|sess|jsessionid|phpsessid)$'],
}

_CONTEXT_ATTACKS: Dict[InputContext, List[str]] = {
    InputContext.NUMERIC_ID: ["sqli", "nosqli", "idor"],
    InputContext.USERNAME: ["sqli", "nosqli", "xss"],
    InputContext.PASSWORD: ["sqli", "nosqli", "auth_bypass"], # User explicitly requested testing keys
    InputContext.EMAIL: ["sqli", "nosqli", "header_injection", "xss"],

    InputContext.SEARCH: ["xss", "sqli", "ssti"],
    InputContext.TEXT_CONTENT: ["xss", "ssti", "sqli"],
    InputContext.URL_REDIRECT: ["open_redirect", "ssrf"],
    InputContext.FILE_PATH: ["lfi", "path_traversal", "rce"],
    
    # Phase 2 Added
    InputContext.JWT: ["jwt_attack", "auth_bypass"],
    InputContext.JSON_BODY: ["nosqli", "sqli", "xxe", "json_injection"],
    InputContext.JSON_STRING: ["nosqli", "sqli", "xxe"],
    InputContext.XML_BODY: ["xxe", "xpath_injection"],
    InputContext.SERIALIZED: ["deserialization", "rce"],
    InputContext.BASE64_ENCODED: ["deserialization", "sqli", "xss"], # Decode edip bakılmalı ama genelde bunlar
    
    InputContext.CSRF_TOKEN: [],
    InputContext.GENERIC: [
        "xss", "sqli", "nosqli", "ssti", "rce", "lfi", 
        "ssrf", "open_redirect", "xxe", "idor",
        "deserialization", "jwt_attack"
    ],
}

_SKIP_CONTEXTS: Dict[InputContext, str] = {
    InputContext.CSRF_TOKEN: "Validation token",
    InputContext.SESSION: "Session managment test (skipped here)",
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _is_json(s: str) -> bool:
    s = s.strip()
    if not (s.startswith('{') and s.endswith('}')) and not (s.startswith('[') and s.endswith(']')):
        return False
    try:
        json.loads(s)
        return True
    except:
        return False

def _is_xml(s: str) -> bool:
    s = s.strip()
    return s.startswith('<') and s.endswith('>') and ('<?xml' in s[:20] or '<root' in s or '<data' in s)

def _is_jwt(s: str) -> bool:
    # eyJ... . eyJ... . ...
    parts = s.split('.')
    if len(parts) != 3:
        return False
    if not s.startswith('eyJ'): # header {"alg":...} usually
        return False
    return True

def _is_base64(s: str) -> bool:
    # Minimal length heuristic + pattern
    if len(s) < 4 or len(s) % 4 != 0:
        return False
    if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', s):
        return False
    # Try decode
    try:
        base64.b64decode(s, validate=True)
        return True
    except:
        return False

# =============================================================================
# PUBLIC API
# =============================================================================

def analyze_input_context(
    name: str,
    input_type: Optional[str] = None,
    value: Optional[str] = None,
    url_path: Optional[str] = None,
    source: Optional[str] = None,
    tech_stack: Optional[Set[str]] = None
) -> ContextAnalysisResult:
    """
    Enhanced Context Analyzer Phase 2
    
    Args:
        tech_stack: Detected technologies (e.g. {'php', 'mysql', 'linux'})
    """
    name_lower = (name or "").lower().strip()
    value_str = str(value) if value else ""
    
    # 1. Deep Value Heuristics (High Confidence)
    if value_str:
        if _is_jwt(value_str):
            return ContextAnalysisResult(InputContext.JWT, 1.0, _CONTEXT_ATTACKS[InputContext.JWT])
        
        if _is_json(value_str):
            if source == "json":
               ctx = InputContext.JSON_BODY 
            else:
               ctx = InputContext.JSON_STRING
            return ContextAnalysisResult(ctx, 0.95, _CONTEXT_ATTACKS[ctx])
            
        if _is_xml(value_str):
            return ContextAnalysisResult(InputContext.XML_BODY, 0.95, _CONTEXT_ATTACKS[InputContext.XML_BODY])
            
        # Serialized check (PHP "O:..." or Java magic bytes hex?)
        if value_str.startswith('O:') and len(value_str) > 4: # Simple PHP object heuristic
            return ContextAnalysisResult(InputContext.SERIALIZED, 0.9, _CONTEXT_ATTACKS[InputContext.SERIALIZED])

    # 2. Source/Type Detection
    if source == "json":
         return ContextAnalysisResult(InputContext.JSON_BODY, 0.9, _CONTEXT_ATTACKS[InputContext.JSON_BODY])
         
    # 3. Name Pattern Matching
    for ctx, patterns in _CONTEXT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return ContextAnalysisResult(
                    ctx, 0.9, _CONTEXT_ATTACKS.get(ctx, []), 
                    skip_reason=_SKIP_CONTEXTS.get(ctx)
                )

    # 4. Fallback Value Heuristics
    if value_str:
         if re.match(r'^https?://', value_str):
             return ContextAnalysisResult(InputContext.URL_REDIRECT, 0.8, _CONTEXT_ATTACKS[InputContext.URL_REDIRECT])
         if re.match(r'^\d+$', value_str):
             return ContextAnalysisResult(InputContext.NUMERIC_ID, 0.7, _CONTEXT_ATTACKS[InputContext.NUMERIC_ID])

    # 5. Generic
    return ContextAnalysisResult(InputContext.GENERIC, 0.5, _CONTEXT_ATTACKS[InputContext.GENERIC])


def should_skip_payload_category(context: InputContext, category: str, tech_stack: Optional[Set[str]] = None) -> bool:
    """
    Decide whether to skip a payload category based on Context AND Technology.
    """
    # 1. Context Check
    applicable = _CONTEXT_ATTACKS.get(context, [])
    # If explicitly empty list (PASSWORD), we skip everything
    if context in _CONTEXT_ATTACKS and not applicable:
        return True
        
    # If category not in applicable list (and context is not GENERIC/Empty), skip.
    if applicable and category.lower() not in [a.lower() for a in applicable]:
        return True
        
    # 2. Technology Check (Phase 2)
    if tech_stack:
        req_techs = _ATTACK_TECH_REQ.get(category.lower())
        if req_techs:
            # Logic: If we REQUIRE sql, and tech_stack has NO sql, should we skip?
            # Problem: Tech stack implies "What is present".
            # If tech_stack = {'mongodb', 'nodejs'}, does it mean NO mysql? Usually yes in modern single-db apps.
            # But maybe not.
            # Safer Logic:
            # If tech_stack contains a CONFLICTING db type?
            # Example: If we are doing 'sqli' (needs generic sql)
            # If tech_stack has 'mongodb' and NO 'sql' variants...
            
            # Let's check overlap.
            # If tech_stack contains ANY known DB technology:
            known_dbs = {"mysql", "postgresql", "postgres", "mssql", "oracle", "sqlite", "mariadb", "mongodb", "couchdb", "dynamodb", "redis"}
            present_dbs = tech_stack.intersection(known_dbs)
            
            if present_dbs:
                # If DBs are detected, check if at least one satisfies the requirement.
                # 'sqli' reqs: {mysql, postgres...}
                # present: {mongodb}
                # overlap: Empty -> SKIP SQLi.
                # present: {mysql, mongodb} -> overlap: {mysql} -> ALLOW SQLi.
                
                reqs_for_cat = _ATTACK_TECH_REQ.get(category.lower())
                if reqs_for_cat:
                     # Calculate overlap
                     overlap = present_dbs.intersection(reqs_for_cat)
                     # If the requirement set consists of DBs (is a DB attack)
                     if reqs_for_cat.intersection(known_dbs): 
                         if not overlap:
                             return True # DB Mismatch! Skip.

            # Language checks
            # If category requires PHP, and tech_stack has Python/Node but NO PHP -> Skip
            known_langs = {"php", "python", "java", "ruby", "go", "nodejs", "asp", "aspx", "c#"}
            present_langs = tech_stack.intersection(known_langs)
            
            if present_langs:
                 req_langs = req_techs.intersection(known_langs)
                 if req_langs and not present_langs.intersection(req_langs):
                     return True # Language Mismatch! Skip.

    return False

def get_applicable_attacks(context: InputContext) -> List[str]:
    return list(_CONTEXT_ATTACKS.get(context, _CONTEXT_ATTACKS[InputContext.GENERIC]))

def format_analysis_log(name: str, result: ContextAnalysisResult) -> str:
    attacks = ", ".join(result.applicable_attacks) if result.applicable_attacks else "SKIP"
    info = f"[Context] {name} → {result.context.name}"
    if result.confidence > 0.8:
        info += " 🔥"
    info += f" → {attacks}"
    if result.skip_reason:
        info += f" ({result.skip_reason})"
    return info

# Compatibility Wrappers for existing scanners
def analyze_form_inputs(inputs: List[Dict[str, Any]]) -> Dict[str, ContextAnalysisResult]:
    # ... Same as before ...
    results = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            results[name] = analyze_input_context(name, input_type=inp.get("type"), value=inp.get("value"), source="form")
    return results

def get_context_stats(results: Dict[str, ContextAnalysisResult]) -> Dict[str, int]:
    stats: Dict[str, int] = {}
    for r in results.values():
        stats[r.context.name] = stats.get(r.context.name, 0) + 1
    return stats
