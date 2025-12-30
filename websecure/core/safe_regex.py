from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor
import os
import json
import re
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional, Iterable, Dict
from websecure.core.reporting import log_warn

__all__ = [
    # safe ops
    "compile", "search", "match", "fullmatch", "findall", "finditer", "split", "sub", "subn",
    # config / control
    "get_default_timeout_ms", "set_default_timeout_ms", "configure_from_config",
    "with_timeout", "patch_stdlib", "unpatch_stdlib",
    # convenience
    "enable_global", "disable_global",
]



# ---------------------------------------------------------------------------
# Defaults & config
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT_MS = 200  # hard default (ms)
_current_timeout_ms = _DEFAULT_TIMEOUT_MS

def get_default_timeout_ms() -> int:
    return int(_current_timeout_ms)

def _parse_int_ms(val) -> Optional[int]:
    """Pozitif tamsayıya güvenli dönüşüm (istisnasız)."""
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if val > 0 else None
    if isinstance(val, float):
        iv = int(val)
        return iv if iv > 0 else None
    if isinstance(val, str):
        s = val.strip()
        sign = 1
        if s.startswith(("+", "-")):
            if s[0] == "-":
                sign = -1
            s = s[1:].strip()
        if s.isdigit():
            iv = int(s) * sign
            return iv if iv > 0 else None
    return None


# ------------------------------------------------------------
# Zaman aşımı ayarı
# ------------------------------------------------------------

def set_default_timeout_ms(ms: int) -> None:
    global _current_timeout_ms
    parsed = _parse_int_ms(ms)
    if parsed is None:
        log_warn(f"Geçersiz timeout değeri: {ms!r}. Varsayılan kullanılacak: {_DEFAULT_TIMEOUT_MS} ms")
        _current_timeout_ms = _DEFAULT_TIMEOUT_MS
        return
    _current_timeout_ms = max(1, int(parsed))


# ------------------------------------------------------------
# Config yolu & okuma (sessiz yutma yok)
# ------------------------------------------------------------

def _load_config_path() -> Optional[Path]:
    # Öncelik: env, local config.json, ebeveynler (2 seviye)
    env = os.getenv("WEBSECURE_CONFIG") or os.getenv("WEBSEC_CONFIG")
    if env:
        p = Path(env)
        if p.exists():
            return p
    local = Path("config.json")
    if local.exists():
        return local
    here = Path(".").resolve()
    for up in [here, *list(here.parents)[:2]]:
        p = up / "config.json"
        if p.exists():
            return p
    return None


def _deep_get(d: Dict, path: str, default=None):
    cur = d
    for key in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def configure_from_config(cfg: Optional[Dict[str, Any]] = None) -> None:
    """
    Aşağıdaki anahtarlardan ilk bulunan kullanılır (ms):
      - env: WEBSEC_REGEX_TIMEOUT_MS
      - cfg["regex"]["timeout_ms"]
      - cfg["safe_regex"]["timeout_ms"]
      - cfg["extractors"]["regex_timeout_ms"]
      - cfg["settings"]["regex_timeout_ms"]
      - yoksa _DEFAULT_TIMEOUT_MS
    Not: JSON dosyası bozuksa hata **yükselir** (saklama yok).
    """
    # 1) ENV en baskın
    env = os.getenv("WEBSEC_REGEX_TIMEOUT_MS")
    if env is not None:
        pv = _parse_int_ms(env)
        if pv is not None:
            set_default_timeout_ms(pv)
            return
        log_warn(f"Geçersiz ENV WEBSEC_REGEX_TIMEOUT_MS: {env!r}")

    # 2) cfg verilmemişse dosyadan yüklemeyi dene (hata saklama yok)
    local_cfg: Dict[str, Any] = {}
    if cfg is None:
        p = _load_config_path()
        if p and p.exists():
            text = p.read_text(encoding="utf-8")          # bozuksa burada yükselir
            loaded = json.loads(text)                     # bozuksa burada yükselir
            if isinstance(loaded, dict):
                local_cfg = loaded
        cfg = local_cfg

    # 3) Bilinen yol anahtarları
    for key in (
        "regex.timeout_ms",
        "safe_regex.timeout_ms",
        "extractors.regex_timeout_ms",
        "settings.regex_timeout_ms",
    ):
        v = _deep_get(cfg, key, None) if isinstance(cfg, dict) else None
        if v is None:
            continue
        pv = _parse_int_ms(v)
        if pv is not None:
            set_default_timeout_ms(pv)
            return
        log_warn(f"Geçersiz config değeri '{key}': {v!r}")

    # 4) Fallback
    set_default_timeout_ms(_DEFAULT_TIMEOUT_MS)


# ------------------------------------------------------------
# İlk importta opsiyonel otomatik konfig
# (İstersen main’de çağır; burada saklama yok, bozuk JSON yükselir.)
# ------------------------------------------------------------
# configure_from_config()


# ------------------------------------------------------------
# Timeout ile çalıştırma (istisnasız)
# ------------------------------------------------------------

def _run_with_timeout(fn, timeout_ms: Optional[int] = None):
    ms = _parse_int_ms(timeout_ms if timeout_ms is not None else _current_timeout_ms)
    ms = ms if ms is not None else _DEFAULT_TIMEOUT_MS

    # İş parçacığı havuzu ile çalıştır; tamamlanana kadar bekle, süre aşımında iptal + yerel TimeoutError
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(fn)

        if ms > 0:
            deadline = time.time() + (ms / 1000.0)
            # Basit polling; gereksiz CPU tüketmemek için kısa uyku
            sleep_step = max(0.005, min(0.05, ms / 1000.0 / 10.0))
            while True:
                if fut.done():
                    # fn içi istisnalar burada **doğrudan** yükselir; saklama yok
                    return fut.result()
                if time.time() >= deadline:
                    fut.cancel()
                    raise TimeoutError(f"Regex timed out ({ms} ms)")
                time.sleep(sleep_step)
        else:
            return fut.result()


# ------------------------------------------------------------
# Context API (try/finally kullanmadan)
# ------------------------------------------------------------

class _TimeoutContext:
    def __init__(self, timeout_ms: int):
        self._new = int(_parse_int_ms(timeout_ms) or _DEFAULT_TIMEOUT_MS)
        self._prev = None

    def __enter__(self):
        # get_default_timeout_ms dışarıda tanımlı (mevcut projede var)
        self._prev = get_default_timeout_ms()
        set_default_timeout_ms(self._new)
        return self

    def __exit__(self, exc_type, exc, tb):
        set_default_timeout_ms(self._prev if self._prev is not None else _DEFAULT_TIMEOUT_MS)
        # False → istisnaları bastırma
        return False


def with_timeout(timeout_ms: int):
    """Bu context içinde geçici varsayılan timeout'u değiştirir."""
    return _TimeoutContext(timeout_ms)
# ---------------------------------------------------------------------------
# Safe API
# ---------------------------------------------------------------------------

def compile(pattern: str, flags: int = 0, *, timeout_ms: Optional[int] = None):
    """
    Not: compile için timeout uygulanmaz; timeout çağrı bazında (search/match/None) kullanılır.
    """
    if not isinstance(pattern, str):
        raise TypeError("pattern must be str")
    return re.compile(pattern, flags)

def _wrap_call(op_name: str):
    def _inner(pattern, string, flags: int = 0, *, timeout_ms: Optional[int] = None, **kwargs):
        rx = pattern if hasattr(pattern, "search") else re.compile(pattern, flags)
        def _do():
            op = getattr(rx, op_name)
            return op(string, **kwargs)
        return _run_with_timeout(_do, timeout_ms)
    return _inner

search    = _wrap_call("search")
match     = _wrap_call("match")
fullmatch = _wrap_call("fullmatch")
findall   = _wrap_call("findall")
finditer  = _wrap_call("finditer")
split     = _wrap_call("split")
sub       = _wrap_call("sub")
# subn ayrı döner (result, count)
def subn(pattern, repl, string, flags: int = 0, *, timeout_ms: Optional[int] = None, **kwargs):
    rx = pattern if hasattr(pattern, "subn") else re.compile(pattern, flags)
    def _do():
        return rx.subn(repl, string, **kwargs)
    return _run_with_timeout(_do, timeout_ms)

# ---------------------------------------------------------------------------
# Optional: patch stdlib re.* with safe wrappers
# ---------------------------------------------------------------------------

_orig_re_api = {}

def patch_stdlib(timeout_ms: Optional[int] = None):
    """
    Tüm re.* çağrılarını güvenli sarmalayıcılara yönlendirir.
    Bu işlem yalnızca aynı süreç içinde çalışan kodu etkiler.
    """
    global _orig_re_api, _current_timeout_ms
    if _orig_re_api:
        return
    if timeout_ms is not None:
        set_default_timeout_ms(timeout_ms)
    _orig_re_api = {
        "search": re.search, "match": re.match, "fullmatch": re.fullmatch, "findall": re.findall,
        "finditer": re.finditer, "split": re.split, "sub": re.sub, "subn": getattr(re, "subn", None),
        "compile": re.compile
    }
    def _mk(func):
        # capture at call time for up-to-date default
        return lambda *a, **k: globals()[func](*a, **k, timeout_ms=get_default_timeout_ms())
    re.search    = _mk("search")
    re.match     = _mk("match")
    re.fullmatch = _mk("fullmatch")
    re.findall   = _mk("findall")
    re.finditer  = _mk("finditer")
    re.split     = _mk("split")
    re.sub       = _mk("sub")
    if _orig_re_api["subn"] is not None:
        re.subn  = _mk("subn")
    # compile'i patch'lemiyoruz (istenirse _orig_re_api["compile"] tutuluyor)

def unpatch_stdlib():
    global _orig_re_api
    if not _orig_re_api:
        return
    re.search    = _orig_re_api["search"]
    re.match     = _orig_re_api["match"]
    re.fullmatch = _orig_re_api["fullmatch"]
    re.findall   = _orig_re_api["findall"]
    re.finditer  = _orig_re_api["finditer"]
    re.split     = _orig_re_api["split"]
    re.sub       = _orig_re_api["sub"]
    if _orig_re_api.get("subn") is not None:
        re.subn  = _orig_re_api["subn"]
    re.compile   = _orig_re_api["compile"]
    _orig_re_api = {}

# Convenience toggles for project‑wide adoption
def enable_global(timeout_ms: Optional[int] = None) -> None:
    """Tüm extractor/analizlerde patch'i açmak için pratik fonksiyon."""
    patch_stdlib(timeout_ms=timeout_ms)

def disable_global() -> None:
    unpatch_stdlib()

# === PATCH: WebSecure Upgrade (auto-applied) @ 2025-09-07T16:53:43.705200 ===

# Ek: Basit regex lint (ReDoS-kolik kalıpları yakalamak için)
def lint_pattern(pattern) -> list[str]:
    """
    Tehlikeli olabilecek regex kalıplarını işaretler (heuristic).
    Dönen liste boş değilse uyarı mesajları içerir.
    """
    warns: list[str] = []

    # Güvenli stringleştirme (istisnasız)
    if isinstance(pattern, str):
        s = pattern
    elif isinstance(pattern, (bytes, bytearray, memoryview)):
        s = bytes(pattern).decode("utf-8", "ignore")
        warns.append("pattern bytes olarak geldi; UTF-8 varsayılarak dönüştürüldü")
    else:
        return ["pattern str değil"]

    # 1) Nested quantifier (katastrofik backtracking riski)
    if re.search(r"\([^\)]*[\+\*][^\)]*\)[\+\*\{]", s):
        warns.append("Olası nested quantifier (katastrofik backtracking riski)")

    # 2) Geniş aralıklarla greedy tekrar
    if re.search(r"\.\{10,}", s):
        warns.append("Geniş aralıklı greedy tekrar (.{10,}) tespit edildi")

    # 3) Uzun lookbehind (çoğu motor için ağır)
    if re.search(r"\(\?<=.{5,}\)", s):
        warns.append("Uzun lookbehind tespit edildi")

    return warns

def guard_compile(pattern: str, flags: int = 0):
    warns = lint_pattern(pattern)
    if warns:
        # Derlemeye izin veriyoruz ama uyarıları raise etmek isteyenler için yardımcı
        pass
    return re.compile(pattern, flags)
