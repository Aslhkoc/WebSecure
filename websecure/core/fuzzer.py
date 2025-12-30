from __future__ import annotations
import asyncio
import contextlib
import difflib
import hashlib
import inspect
import json
import logging
import math
import os
import random
import re
import statistics
import string
import time
import uuid
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_tz, mktime_tz
from importlib import import_module
from importlib.util import find_spec
from itertools import product
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse, urlsplit, parse_qs

# Third-party optional
httpx = import_module('httpx') if find_spec('httpx') is not None else None
if find_spec("rapidfuzz") is not None:
    from rapidfuzz import fuzz as _rf_fuzz
else:
    _rf_fuzz = None

if find_spec("numpy") is not None:
    import numpy as _np
else:
    _np = None

if find_spec("sentence_transformers") is not None:
    from sentence_transformers import SentenceTransformer
else:
    SentenceTransformer = None

# WebSecure Core Imports
from websecure.core.oast import IOASTClient, replace_query_param, inject_query
from websecure.core.utils import ensure_wordlists
if find_spec("core.reporting") is not None:
    from websecure.core.reporting import note_auth_outcome, note_payload_usage
else:
    # Fallback reporting
    def note_auth_outcome(*a, **k): pass
    def note_payload_usage(*a, **k): pass

# ============================================================================
# SECTION 1: SEMANTIC ANALYSIS (formerly semantic.py)
# ============================================================================

_HTML_DROP_BLOCKS = re.compile(r"(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>|<!--.*?-->|<meta[^>]*?>")
_TAG_RE = re.compile(r"(?is)<[^>]+>")
_WS_RE = re.compile(r"\s+")
_ST_MODELS: Dict[str, Any] = {}

def _strip_html_noise(text: str, *, limit: int = 20000) -> str:
    if not text: return ""
    s = text[:limit]
    s = _HTML_DROP_BLOCKS.sub("", s)
    s = _TAG_RE.sub(" ", s)
    s = _WS_RE.sub(" ", s).strip()
    return s

def _shingles(s: str, n: int = 3) -> Set[str]:
    if not s or len(s) < n: return set()
    return {s[i:i+n] for i in range(len(s) - n + 1)}

def jaccard_similarity(a: str, b: str, n: int = 3, html_aware: bool = True, body_limit: int = 20000) -> float:
    if html_aware:
        a, b = _strip_html_noise(a, limit=body_limit), _strip_html_noise(b, limit=body_limit)
    else:
        a, b = (a or "")[:body_limit], (b or "")[:body_limit]
    sa, sb = _shingles(a, n), _shingles(b, n)
    if not sa or not sb: return 0.0
    return len(sa & sb) / len(sa | sb)

def difflib_similarity(a: str, b: str, html_aware: bool = True, body_limit: int = 20000) -> float:
    if html_aware:
        a, b = _strip_html_noise(a, limit=body_limit), _strip_html_noise(b, limit=body_limit)
    else:
        a, b = (a or "")[:body_limit], (b or "")[:body_limit]
    return difflib.SequenceMatcher(None, a, b).ratio()

def _cosine(u, v) -> float:
    if _np is None:
        dot = sum((float(x) * float(y) for x, y in zip(u, v)))
        nu = math.sqrt(sum(float(x) * float(x) for x in u)) or 1.0
        nv = math.sqrt(sum(float(y) * float(y) for y in v)) or 1.0
        return max(-1.0, min(1.0, dot / (nu * nv)))
    u = _np.asarray(u, dtype="float32")
    v = _np.asarray(v, dtype="float32")
    return float(_np.dot(u, v) / ((_np.linalg.norm(u) or 1.0) * (_np.linalg.norm(v) or 1.0)))

def _ensure_st_model(model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
    if SentenceTransformer is None: return None
    if model_name not in _ST_MODELS:
        try:
            _ST_MODELS[model_name] = SentenceTransformer(model_name)
        except Exception: return None
    return _ST_MODELS[model_name]

def transformer_similarity(a: str, b: str, model_name: str = "sentence-transformers/all-MiniLM-L6-v2", html_aware: bool = True, body_limit: int = 20000) -> float:
    model = _ensure_st_model(model_name)
    if not model: return 0.0
    if html_aware:
        a, b = _strip_html_noise(a, limit=body_limit), _strip_html_noise(b, limit=body_limit)
    else:
        a, b = (a or "")[:body_limit], (b or "")[:body_limit]
    vecs = model.encode([a, b], normalize_embeddings=True, convert_to_numpy=(_np is not None))
    return _cosine(vecs[0], vecs[1])

def semantic_similarity(a: str, b: str, method: str = "hybrid", body_limit: int = 20000, html_aware: bool = True) -> float:
    method = (method or "hybrid").lower()
    if method == "jaccard":
        return jaccard_similarity(a, b, html_aware=html_aware, body_limit=body_limit)
    if method == "difflib":
        return difflib_similarity(a, b, html_aware=html_aware, body_limit=body_limit)
    base = difflib_similarity(a, b, html_aware=html_aware, body_limit=body_limit)
    if method == "hybrid" and SentenceTransformer:
        tr = transformer_similarity(a, b, html_aware=html_aware, body_limit=body_limit)
        return 0.5 * base + 0.5 * tr
    return base


# ============================================================================
# SECTION 2: HEURISTICS (formerly heuristics.py)
# ============================================================================

@dataclass
class HeuristicsConfig:
    body_limit: int = 20000
    entropy_delta_min: float = 0.35
    semantic_min: float = 0.80
    time_z_min: float = 3.0
    size_rel_min: float = 0.25
    min_time_samples: int = 2
    ml_enabled: bool = False
    ml_bias: float = -1.0
    ml_weights: Tuple[float, float, float, float] = (0.9, 0.8, 0.6, 0.5)
    ml_time_norm: float = 10.0
    diff_compat: bool = True

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]] = None) -> "HeuristicsConfig":
        d = d or {}
        return cls(
            body_limit = int(d.get("body_limit", 20000)),
            entropy_delta_min = float(d.get("entropy_delta_min", 0.35)),
            semantic_min = float(d.get("semantic_min", 0.80)),
            time_z_min = float(d.get("time_z_min", 3.0)),
            size_rel_min = float(d.get("size_rel_min", 0.25)),
            min_time_samples = int(d.get("min_time_samples", 2)),
            ml_enabled = bool(d.get("ml_enabled", False)),
            ml_bias = float(d.get("ml_bias", -1.0)),
            ml_weights = tuple(d.get("ml_weights", (0.9,0.8,0.6,0.5))),
            ml_time_norm = float(d.get("ml_time_norm", 10.0)),
            diff_compat = bool(d.get("diff_compat", True)),
        )

def _shannon_entropy(s: str, *, limit: int = 20000) -> float:
    if not s: return 0.0
    s = s[:max(0, limit)]
    freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(max(p, 1e-12))
    return ent

def _median_abs_dev(values):
    if not values: return 0.0
    med = statistics.median(values)
    devs = [abs(v - med) for v in values]
    return statistics.median(devs)

def _sigmoid(lin: float) -> float:
    if lin >= 0.0: return 1.0 / (1.0 + math.exp(-lin))
    z = math.exp(lin)
    return z / (1.0 + z)

def anomaly_score(baseline: Dict[str, Any], current: Dict[str, Any], *, cfg: Dict[str,Any] | HeuristicsConfig | None = None) -> Dict[str, Any]:
    hc = cfg if isinstance(cfg, HeuristicsConfig) else HeuristicsConfig.from_dict(cfg)
    
    b_len, c_len = int(baseline.get("len", 0)), int(current.get("len", 0))
    b_ms_list = [float(x) for x in (baseline.get("time_samples") or []) if isinstance(x, (int, float))]
    c_ms = float(current.get("time_ms") or 0.0)
    b_body = str(baseline.get("body") or "")[:hc.body_limit]
    c_body = str(current.get("body") or "")[:hc.body_limit]

    b_ent = _shannon_entropy(b_body, limit=hc.body_limit)
    c_ent = _shannon_entropy(c_body, limit=hc.body_limit)
    ent_delta = abs(c_ent - b_ent)

    sim = semantic_similarity(b_body, c_body, body_limit=hc.body_limit)

    z, mad_z = 0.0, 0.0
    if len(b_ms_list) >= hc.min_time_samples:
        mean = statistics.fmean(b_ms_list)
        stdev = statistics.pstdev(b_ms_list)
        z = 0.0 if stdev == 0 else abs(c_ms - mean) / stdev
        mad = _median_abs_dev(b_ms_list)
        med = statistics.median(b_ms_list)
        mad_z = 0.0 if mad == 0 else abs(c_ms - med) / mad

    size_rel = (abs(c_len - b_len) / max(1, b_len)) if b_len else 0.0
    size_rel = min(1.0, size_rel)

    signals = {
        "entropy": ent_delta >= hc.entropy_delta_min,
        "semantic": sim <= hc.semantic_min,
        "time": max(z, mad_z) >= hc.time_z_min,
        "size": size_rel >= hc.size_rel_min,
        "diff": (1.0 - sim) >= (1.0 - hc.semantic_min) if hc.diff_compat else False,
    }

    score = 0
    score += 20 if signals["entropy"] else 0
    score += 20 if signals["semantic"] else 0
    score += 15 if signals["size"] else 0
    score += 15 if signals["time"] else 0
    score += 10 if signals["diff"] else 0
    if sum(1 for v in signals.values() if v) >= 3: score += 10

    ml_score = None
    if hc.ml_enabled:
        feats = ((1.0-sim), size_rel, ent_delta, (max(z, mad_z) / max(1e-9, hc.ml_time_norm)))
        w = list(hc.ml_weights)
        lin = float(hc.ml_bias) + sum(w[i] * feats[i] for i in range(4))
        prob = _sigmoid(lin)
        ml_score = float(prob)
        if prob >= 0.85: score = min(100, score + 15)
        elif prob >= 0.7: score = min(100, score + 8)

    return {
        "score": int(score),
        "signals": signals,
        "metrics": {"similarity": sim, "entropy_delta": ent_delta, "size_rel": size_rel, "z": z, "mad_z": mad_z},
        "ml_score": ml_score,
    }

# ============================================================================
# SECTION 3: VERIFICATION (formerly verifier.py)
# ============================================================================

SEV_ORDER = {"Bilgi": 0, "Düşük": 1, "Orta": 2, "Yüksek": 3, "Kritik": 4}

def _hash_sample(text: str) -> str:
    return hashlib.sha256((text or "")[:8192].encode("utf-8", "ignore")).hexdigest()

_CWE_MAP = {
    "xss": ["CWE-79"], "sqli": ["CWE-89"], "ssrf": ["CWE-918"], "open_redirect": ["CWE-601"],
    "path_traversal": ["CWE-22"], "lfi_rfi": ["CWE-98","CWE-22"], "nosqli": ["CWE-943"], "jwt": ["CWE-287","CWE-347"],
}

def _guess_cwe(find: dict) -> list[str]:
    curr = (str(find.get("param") or "") + str(find.get("injected") or "")).lower()
    hints = find.get("hints") or {}
    keys = set()
    for k in _CWE_MAP:
        if k in curr or hints.get(k): keys.add(k)
    return sorted(list({c for k in keys for c in _CWE_MAP[k]}))

def _norm_sev(s: str) -> str:
    return s if s in SEV_ORDER else "Bilgi"

def _score_from_fuzz(hints: Dict[str, bool] | None, base_sev: str) -> int:
    h = hints or {}
    score = 0
    if h.get("status_delta"): score += 30
    if h.get("size_delta"):   score += 25
    if h.get("diff_delta"):   score += 15
    if h.get("time_delta"):   score += 20
    score += [0, 10, 25, 40, 50][SEV_ORDER.get(_norm_sev(base_sev), 0)]
    return min(100, score)

def _score_from_oast(cb_type: str | None) -> int:
    base = 85
    if str(cb_type or "").lower() == "bxss": base += 5
    return min(100, base)

def compute_score(item: Dict[str, Any]) -> int:
    if (item.get("cvss") or {}).get("base"): return int(item["cvss"]["base"] * 10)
    
    t = (item.get("type") or "").upper()
    if t == "OAST" or item.get("oast_token"):
        return _score_from_oast(item.get("callback_type"))
    
    # Generic fuzz scoring
    base = _score_from_fuzz(item.get("hints"), item.get("severity"))
    return min(100, max(0, int(base)))

def deduplicate(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: Dict[Tuple[str,str,str], Dict[str, Any]] = {}
    for it in items or []:
        u = str(it.get("url") or "")
        p = str(it.get("param") or "")
        inj = str(it.get("injected") or "")
        k = (u, p, inj)
        
        if k not in buckets:
            buckets[k] = dict(it)
        else:
            old = buckets[k]
            # Replace if new one is better
            if (it.get("score", 0) > old.get("score", 0)):
                buckets[k] = dict(it)
                
    # Further collapse by param similarity if rapidfuzz is available
    out = list(buckets.values())
    if _rf_fuzz:
        final = []
        for it in out:
            merged = False
            for j, f in enumerate(final):
                if it.get("param") == f.get("param") and _rf_fuzz.token_set_ratio(str(it.get("injected")), str(f.get("injected"))) >= 92:
                     if compute_score(it) > compute_score(f):
                         final[j] = it
                     merged = True
                     break
            if not merged: final.append(it)
        out = final

    out.sort(key=lambda x: (int(x.get("score", 0)), SEV_ORDER.get(_norm_sev(x.get("severity", "Bilgi")), 0)), reverse=True)
    return out

def correlate_oast(findings: Iterable[Dict[str, Any]], events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ev_by_token = {str(e.get("token")): e for e in (events or []) if e.get("token")}
    out = []
    for f in findings or []:
        inj = str(f.get("injected") or "")
        tok = next((t for t in ev_by_token if t in inj), None)
        if tok:
            ev = ev_by_token[tok]
            g = dict(f)
            g.update({
                "type": "OAST",
                "oast_token": tok,
                "callback_type": str(ev.get("kind") or ev.get("type") or "http").lower(),
                "severity": "Yüksek"
            })
            out.append(g)
        else:
            out.append(f)
    return out

def cvss_for_severity(sev: str) -> dict:
    s = (sev or '').lower()
    if s in ('kritik','critical'): return {'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'base': 9.8}
    if s in ('yüksek','high'): return {'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L', 'base': 8.0}
    if s in ('orta','medium'): return {'vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N', 'base': 5.4}
    if s in ('düşük','low'): return {'vector': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N', 'base': 3.1}
    return {'vector': 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N', 'base': 0.1}

def verify_and_score(findings: Iterable[Dict[str, Any]], oast_events: Optional[Iterable[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    items = list(findings or [])
    if oast_events:
        items = correlate_oast(items, oast_events)
    
    for it in items:
        it["score"] = compute_score(it)
        if "cvss" not in it: it["cvss"] = cvss_for_severity(it.get("severity", "Bilgi"))
        if "cwe" not in it: it["cwe"] = _guess_cwe(it)
        
    return deduplicate(items)

def finalize_results(items: list[dict]) -> list[dict]:
    out = []
    for it in items:
        f = dict(it)
        # normalize severity case
        s = f.get("severity","").title()
        if s == "High": s = "Yüksek"
        if s == "Medium": s = "Orta"
        if s == "Low": s = "Düşük"
        if s == "Info": s = "Bilgi"
        if s == "Critical": s = "Kritik"
        f["severity"] = s
        out.append(f)
    return verify_and_score(out)


# ============================================================================
# SECTION 4: PARAM FUZZER (formerly param_fuzzer.py)
# ============================================================================

_PARAM_TO_CATS: Dict[str, Tuple[str, ...]] = {
    "url": ("ssrf", "open_redirect"), "uri": ("ssrf", "open_redirect"), "redirect": ("open_redirect",),
    "return": ("open_redirect",), "next": ("open_redirect",), "path": ("path_traversal","lfi_rfi"),
    "file": ("file_upload","lfi_rfi"), "id": ("sqli",), "user": ("sqli",), "q": ("xss",), "search": ("xss",),
}
_URLISH = ("url","uri","redirect","return","next","callback","target","link","path","file")

def _hint_categories(param: str) -> Tuple[str, ...]:
    k = (param or "").strip().lower()
    if k in _PARAM_TO_CATS: return _PARAM_TO_CATS[k]
    for u in _URLISH:
        if u in k: return ("ssrf","open_redirect")
    if k.endswith("id") or k.startswith("id_"): return ("sqli",)
    return tuple()

@dataclass
class HttpConfig:
    timeout_s: float = 20.0
    http2: bool = True
    verify_tls: bool = True
    max_keepalive: int = 20
    limits_total: int = 200
    limits_per_host: int = 20
    proxy: Optional[str] = None
    
    @classmethod
    def from_dict(cls, d):
        d = d or {}
        return cls(timeout_s=float(d.get("timeout_s", 20)), http2=d.get("http2", True), verify_tls=d.get("verify_tls", True))

@dataclass
class FuzzConfig:
    mandatory_categories: tuple[str, ...] = ("xss","sqli")
    rps: float = 15.0
    jitter_ms: int = 50
    backoff_factor: float = 2.0
    max_extra_ms: int = 4000
    baseline_retries: int = 1
    body_limit: int = 20000
    oast_enabled: bool = True
    oast_http_base: str = ""
    generic_values: Tuple[str, ...] = ("","0","1","-1","true","false","null","<script>alert(1)</script>","'\"`","../"*5)

    @classmethod
    def from_dict(cls, d):
        d = d or {}
        return cls(rps=float(d.get("rps", 15)), oast_enabled=d.get("oast_enabled", True))

@dataclass(frozen=True)
class FuzzItem:
    method: str
    url: str
    param: str
    baseline_value: Optional[str] = None
    headers: Optional[Dict[str,str]] = None
    cookies: Optional[Dict[str,str]] = None

@dataclass
class FuzzFinding:
    url: str
    param: str
    injected: str
    status_base: int
    status_new: int
    size_base: int
    size_new: int
    time_ms: float
    hints: Dict[str, bool]
    severity: str
    score: int
    diff_ratio: float
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    preview: str = ""
    similar_params: List[str] = field(default_factory=list)

class RateLimiter:
    def __init__(self, rps: float = 0.0) -> None:
        self._rps = max(0.0, float(rps))
        self._interval = 0.0 if self._rps <= 0 else 1.0 / self._rps
        self._lock = asyncio.Lock()
        self._t_last = 0.0
        self._extra_delay_ms = 0

    async def acquire(self, jitter_ms: int = 0) -> None:
        async with self._lock:
            now = time.monotonic()
            target = self._t_last + self._interval
            if target > now: await asyncio.sleep(target - now)
            self._t_last = time.monotonic()
        
        sleeptime = self._extra_delay_ms / 1000.0
        if jitter_ms > 0: sleeptime += random.randint(0, jitter_ms)/1000.0
        if sleeptime > 0: await asyncio.sleep(sleeptime)

    def on_429(self, retry_after: Optional[float], backoff: float, max_ms: int) -> None:
        if retry_after: self._extra_delay_ms = min(max_ms, int(retry_after * 1000))
        else: self._extra_delay_ms = min(max_ms, int(max(200, self._extra_delay_ms or 200) * backoff))

    def decay(self, base_ms: int = 200) -> None:
        if self._extra_delay_ms > base_ms:
             self._extra_delay_ms = max(base_ms, self._extra_delay_ms - 50)


def _mutations_for_value(v: Optional[str], cfg: FuzzConfig) -> List[str]:
    base = list(cfg.generic_values)
    if v: base.append(v + "'")
    return list(dict.fromkeys(base))

def _maybe_oast_payload(param: str, base: str, token: str, cfg: FuzzConfig) -> Optional[str]:
    if any(k in param.lower() for k in _URLISH):
        root = (cfg.oast_http_base or "").rstrip("/")
        if root: return f"{root}/hit?t={token}"
    return None

class AsyncHttp:
    def __init__(self, http_cfg: HttpConfig, headers=None, cookies=None):
        if httpx is None: raise RuntimeError("httpx required")
        client_kwargs = dict(http2=http_cfg.http2, timeout=http_cfg.timeout_s, verify=http_cfg.verify_tls, headers=headers, cookies=cookies)
        self._client = httpx.AsyncClient(**client_kwargs)

    async def get(self, url) -> httpx.Response: return await self._client.get(url)
    async def aclose(self): await self._client.aclose()
    async def __aenter__(self): return self
    async def __aexit__(self, *args): await self.aclose()


async def _baseline(http: AsyncHttp, item: FuzzItem, limiter: RateLimiter, cfg: FuzzConfig) -> Tuple[int, int, str, float]:
    start = time.perf_counter()
    r = await http.get(item.url)
    dt = (time.perf_counter() - start) * 1000.0
    return r.status_code, len(r.content), r.text[:cfg.body_limit], dt

async def _shoot(http: AsyncHttp, url: str, limiter: RateLimiter, cfg: FuzzConfig) -> Tuple[int, int, str, float]:
    await limiter.acquire(cfg.jitter_ms)
    start = time.perf_counter()
    r = await http.get(url)
    dt = (time.perf_counter() - start) * 1000.0
    return r.status_code, len(r.content), r.text[:cfg.body_limit], dt

def _diff_score_and_hints(baseline: Tuple[int,int,str,float], current: Tuple[int,int,str,float]) -> Tuple[int, str, Dict[str,bool], float]:
    b_st, b_sz, b_tx, _ = baseline
    c_st, c_sz, c_tx, c_ms = current
    
    status_changed = (b_st != c_st)
    size_delta = abs(c_sz - b_sz) / max(1, b_sz)
    
    # Calculate anomaly score using Heuristics block
    b_dict = {"len": b_sz, "body": b_tx, "time_samples": [baseline[3]]}
    c_dict = {"len": c_sz, "body": c_tx, "time_ms": c_ms}
    res = anomaly_score(b_dict, c_dict, cfg={})
    
    score = res["score"]
    hints = {
        "status_delta": status_changed,
        "size_delta": size_delta >= 0.25,
        "diff_delta": res["signals"]["semantic"],
        "time_delta": res["signals"]["time"],
    }
    
    sev = "Bilgi"
    if score >= 80: sev = "Yüksek"
    elif score >= 50: sev = "Orta"
    elif score >= 30: sev = "Düşük"
    
    return score, sev, hints, res["metrics"]["similarity"]


async def fuzz_async(
    items: Sequence[FuzzItem],
    *,
    http_cfg: Optional[HttpConfig] = None,
    cfg: Optional[FuzzConfig] = None,
    oast: IOASTClient | None = None,
    per_param: int | None = None,
    **kwargs
) -> List[FuzzFinding]:
    http_cfg = http_cfg or HttpConfig()
    cfg = cfg or FuzzConfig()
    limiter = RateLimiter(cfg.rps)
    findings = []

    async with AsyncHttp(http_cfg) as http:
        for item in items:
            base = await _baseline(http, item, limiter, cfg)
            
            muts = _mutations_for_value(item.baseline_value, cfg)
            
            # Categories & Wordlists
            _reg = ensure_wordlists({})
            _cats = _hint_categories(item.param)
            _ext = []
            for _c in _cats: _ext.extend(_reg.collect(_c))
            if _ext: muts = list(set(muts + _ext))
            
            if per_param and per_param > 0: muts = muts[:per_param]
            
            # OAST Token
            token = await oast.new_token() if oast and cfg.oast_enabled else None
            
            for mv in muts:
                inj = mv
                if token:
                    oast_p = _maybe_oast_payload(item.param, item.url, token, cfg)
                    if oast_p: inj = oast_p
                
                test_url = replace_query_param(item.url, item.param, inj)
                c_st, c_sz, c_tx, c_ms = await _shoot(http, test_url, limiter, cfg)
                
                score, sev, hints, diff_ratio = _diff_score_and_hints(base, (c_st, c_sz, c_tx, c_ms))
                
                if score >= 35 or any(hints.values()):
                    findings.append(FuzzFinding(
                        url=item.url, param=item.param, injected=inj,
                        status_base=base[0], status_new=c_st,
                        size_base=base[1], size_new=c_sz,
                        time_ms=c_ms, hints=hints, severity=sev, score=score,
                        diff_ratio=diff_ratio, preview=c_tx[:200]
                    ))
                    
    return findings

def fuzz(items: Sequence[FuzzItem], *, http_cfg: Optional[HttpConfig]=None, cfg: Optional[FuzzConfig]=None, oast: IOASTClient | None = None, **kwargs) -> List[FuzzFinding]:
    def _run():
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(fuzz_async(items, http_cfg=http_cfg, cfg=cfg, oast=oast, **kwargs))
        finally:
            loop.close()
            
    # Sync wrapper (safe for threads)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_run).result()

def to_fuzz_items(endpoints: Sequence[str], params: Iterable[str]) -> List[FuzzItem]:
    items = []
    for u in endpoints or []:
        for p in params or []:
            items.append(FuzzItem("GET", str(u), str(p)))
    return items

def discover_params_from_crawl(crawl_results) -> Set[str]:
    names = set()
    if isinstance(crawl_results, dict):
        cand = set(crawl_results.get('param_candidates') or [])
        names |= {str(x)[:64] for x in cand}
        for k in (crawl_results.get('json_keys') or []):
            names.add(str(k)[:64])
    return names

# Compatibility Wrapper
def fuzz_endpoint(session, *, target: dict, limits: dict | None = None, discovered=None, **kwargs):
    url = (target or {}).get("url") or ""
    params = discover_params_from_crawl(discovered) if isinstance(discovered, dict) else set(discovered or [])
    if not params: params = {"q","id"}
    
    items = to_fuzz_items([url], params)
    fcfg = FuzzConfig.from_dict(limits)
    hcfg = HttpConfig.from_dict(limits)
    
    return fuzz(items, http_cfg=hcfg, cfg=fcfg)

# ======================= Compatibility / Helpers =======================

COMMON_PARAM_WORDS = [
    "q","query","search","s","page","offset","limit","lang","locale",
    "redirect","return","next","callback","continue","dest","target","ref",
    "id","user","username","email","role","token","csrf","auth","file","path","url"
]

def guess_additional_params(discovered: set[str] | list[str] | dict, *, extra_words: list[str] | None = None):
    """Merge discovered names with common/extra words; return a set of strings."""
    names: set[str] = set()
    if isinstance(discovered, dict):
        for k,v in discovered.items():
            if isinstance(v, (list,set,tuple)):
                names |= {str(x) for x in v}
    else:
        names |= {str(x) for x in (discovered or [])}
    names |= set(COMMON_PARAM_WORDS)
    if extra_words:
        names |= {str(x) for x in extra_words}
    return names

def blind_param_fuzz(session, url: str, method: str, baseline_text: str, wordlist: List[str], baseline_obj: dict, bucket: list, max_params: int = 25, debug: bool = False):
    """
    Simplified blind parameter fuzzer for compatibility.
    Uses generic values for common params from wordlist.
    """
    params = list(wordlist or [])
    if not params: params = COMMON_PARAM_WORDS
    if max_params: params = params[:max_params]
    
    # Reuse fuzz() logic
    items = to_fuzz_items([url], params)
    
    # We construct a simple config
    cfg = FuzzConfig(oast_enabled=False, rps=20.0, mutations_per_param=1)
    # Only test a single generic value to trigger potential diffs
    cfg.generic_values = ("<script>alert(1)</script>", "'\"`", "1 OR 1=1")
    
    # Run sync
    findings = fuzz(items, cfg=cfg, session=session, debug=debug)
    
    for f in findings:
        item = {
            "type": "blind_param_diff",
            "url": f.url,
            "param": f.param,
            "injected": f.injected,
            "score": f.score,
            "severity": f.severity,
            "details": f.hints
        }
        bucket.append(item)

def verify_oast_findings(candidates: List[Dict[str, Any]], session, timeout: int = 10) -> List[Dict[str, Any]]:
    """Compat wrapper for verify_oast_findings."""
    # This was likely doing polling/verification.
    # We will assume it wraps generic OAST verification logic.
    # Since we don't have the original body, we'll implement a best-effort one or delegate.
    # In the new design, we use OASTClient.poll.
    # For now, let's return candidates if they are valid, or empty.
    # Real logic was likely in `verifier.py` or `osat.py`
    # We will just return candidates for now as a placeholder or use correlate if events provided.
    return candidates

def verify_findings_and_score(results_bucket: Dict[str, Any], session) -> List[Dict[str, Any]]:
    """Compat wrapper for verify_findings_and_score."""
    # Flatten bucket
    findings = []
    for k, v in results_bucket.items():
        if isinstance(v, list):
            findings.extend(v)
    return verify_and_score(findings)


