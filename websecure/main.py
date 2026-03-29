#bismillahirrahmanirrahim
from __future__ import annotations
import sys
import pathlib
import os

# [CRITICAL] Path patching MUST happen before local imports
# This ensures running from 'websecure/' subdirectory works in PyCharm/CLI
_p = pathlib.Path(__file__).resolve()
_pkg_root = str(_p.parent.parent)
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

from websecure.core.http import verify_for_phase
import inspect
from websecure.core.auth_flow import run_auto_signup, run_device_code_flow, smart_login
from importlib.util import find_spec as _find_spec
from importlib import import_module as _import_module
# run_business_logic_flows and run_race_conditions are loaded dynamically below (line ~884)
import re as _re_urlnorm
from urllib.parse import urlsplit as _urlsplit, urlunsplit as _urlunsplit, SplitResult as _SplitResult
import argparse, json, time, socket, ssl

def _opt_import(mod, func):
    try:
        from importlib import import_module
        m = import_module(mod)
        return getattr(m, func, None)
    except (ImportError, AttributeError, ModuleNotFoundError):
        return None

from websecure.core.phases import build_plan, run_plan_if_needed
from websecure.crawler import discovery_enrich
from websecure.core.alerts import AlertManager
from websecure.core.reporting import (
    verify_and_score, 
    configure_logging, 
    perform_reporting, 
    add_session
)



import logging as _logging
from urllib.parse import urlparse, urldefrag
from time import sleep
import asyncio
import shutil
import subprocess
from pathlib import Path as _P
import importlib as _im
import importlib.util as _iul
from websecure.core.utils import ensure_wordlists as _ensure_wl
from concurrent.futures import ThreadPoolExecutor
import time as _t
import sys as _sys, os as _os

_logger = _logging.getLogger(__name__)

_req_mod = _im.import_module('requests') if _iul.find_spec('requests') is not None else None
requests = _req_mod  # alias; may be None

# [UI] MSF-Style Banner (inlined from banner.py)
import random as _banner_random, platform as _banner_platform
_BANNER_VERSION = "2.0.4-dev"
_BANNER_CODENAME = "GhostProtocol"
_BANNERS = [r"""
  ██████  ███████ ███    ██ ███████ ███████ ██████  ██      ██████  ██ ████████
 ██  ████ ██      ████   ██ ██      ██      ██   ██ ██     ██    ██ ██    ██
 ██   ███ █████   ██ ██  ██ ███████ █████   ██████  ██     ██    ██ ██    ██
 ██  ████ ██      ██  ██ ██      ██ ██      ██      ██     ██    ██ ██    ██
  ██████  ███████ ██   ████ ███████ ███████ ██      ██████  ██████  ██    ██

                      [ SYSTEM: COMPROMISED ]
               [ TARGET: ACQUIRED | VECTOR: LETHAL ]
"""]

def print_banner(modules_count: int = 0) -> None:
    print(_banner_random.choice(_BANNERS))
    print(f"       =[ WebSecure v{_BANNER_VERSION} [{_BANNER_CODENAME}]")
    print(f"       =[ Modules: {modules_count} loaded")
    print(f"       =[ OS: {_banner_platform.system()} {_banner_platform.release()}")
    print("")
    
    # [WS3] Dynamic Wordlist Report
try:
    from websecure.core.utils import collect_all_wordlists
    _wd = collect_all_wordlists()
except (ImportError, AttributeError, OSError) as exc:
    _logger.debug(f"[main] Wordlist yüklenemedi: {exc!r}")

# [WS3-ANCHOR] New Module Imports
try:
    from websecure.core import chain_reactor
    from websecure.scanners import csrf, mass_assignment
except ImportError:
    chain_reactor = None
    csrf = None
    mass_assignment = None
    _logger.warning("[Main] Failed to import one or more extra scanner modules.")




try:
    from websecure.scanners import request_smuggling, jwt, nosqli
except ImportError:
    request_smuggling = None
    jwt = None
    nosqli = None
    _logger.warning("[Main] Failed to import request_smuggling, jwt, or nosqli.")


# [WS3] Offensive Scanner Wrappers (Bridge)
def offensive_request_smuggling(url, session, **kwargs):
    if request_smuggling:
        try:
            request_smuggling.run(url, session=session)
        except Exception as e:
            _logger.error(f"Request Smuggling failed: {e}")

def offensive_mass_assignment(url, session, **kwargs):
    if mass_assignment:
        try:
            res = mass_assignment.run(url, session=session)
            if res and isinstance(res, list):
                if callable(globals().get("add_result")):
                    for r in res:
                         add_result("mass_assignment", r)
        except Exception as e:
            _logger.error(f"Mass Assignment failed: {e}")

def offensive_jwt(url, session, **kwargs):
    if jwt:
        try:
            jwt.run(url, session=session)
        except Exception as e:
            _logger.error(f"JWT Scan failed: {e}")

def offensive_nosqli(url, session, **kwargs):
    if nosqli:
        try:
            nosqli.run(url, session=session)
        except Exception as e:
            _logger.error(f"NoSQLi Scan failed: {e}")




_BOUNDARY_EXC = tuple([
    (_req_mod.exceptions.RequestException if (_req_mod and hasattr(_req_mod, "exceptions")) else Exception),
    TimeoutError,
    ssl.SSLError,
    socket.gaierror,
    OSError,
    json.JSONDecodeError,
    ImportError,
    ValueError,
])
# Alias for compatibility
_ws_imp_util = _iul

def _report_phase_error(_phase: str, _where: str, _err: BaseException) -> None:
    _rmod = None
    if _iul.find_spec('websecure.core.reporting') is not None:
        _rmod = _im.import_module('websecure.core.reporting')
    if _rmod is not None and hasattr(_rmod, 'add_result'):
        _rmod.add_result(
            "errors",
            {
                "type": "phase_error",
                "severity": "error",
                "message": str(_err),
                "meta": {
                    "phase": _phase,
                    "where": _where,
                    "exc_type": _err.__class__.__name__,
                },
            }
        )
# --- end auto-injected header ---


def _ws_import_any(*names: str):
    """
    Belirtilen modül adlarını sırayla dener ve ilkini import eder.
    Sadece bu yardımcı içinde find_spec kullanılır (1.2 gereği).
    Çalışma sırasında modül çevirmez; deterministik ve tek-yön.
    """
    for n in names:
        if not isinstance(n, str) or not n.strip():
            continue
        try:
            if _ws_imp_util.find_spec(n) is not None:
                return _im.import_module(n)
        except _BOUNDARY_EXC as e:
            _logger.error('phase error [main]', exc_info=True)
            _report_phase_error('main', 'main.py', e)
            continue
    return None

def _ws_import_attr(names, attr: str, default=None):
    m = _ws_import_any(*names) if isinstance(names, (list, tuple)) else _ws_import_any(names)
    if m is None:
        return default
    return getattr(m, attr, default)

def _ws_spec(name: str):
    try:
        return _ws_imp_util.find_spec(name)
    except (ImportError, ModuleNotFoundError, AttributeError, ValueError):
        return None
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [main]', exc_info=True)
        return None

def _ws_has(*names: str) -> bool:
    return _ws_import_any(*names) is not None



if __package__ is None or __package__ == "":
    _pkg_dir = _os.path.dirname(_os.path.abspath(__file__))
    _parent = _os.path.dirname(_pkg_dir)
    if _parent not in _sys.path:
        _sys.path.insert(0, _parent)
    __package__ = "websecure"
def _load_config(p: str) -> dict:
    if not p or not os.path.exists(p):
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)



# FAZ-EK: URL normalizasyon → core/url_utils.py'e taşındı
from websecure.core.url_utils import (
    _ws3_is_ipv6_literal,
    _ws3_looks_like_host,
    _ws3_fix_scheme_and_netloc,
    _ws3_normalize_input_url,
    _ws3_curl_effective_url,
    _detect_final_url_and_scheme_robust,
)


def _session_priming(session, base_url, cfg):
    # Kimliksiz mod priming kapalıysa geç
    if not (((cfg or {}).get("kimliksiz_mod") or {}).get("priming") or {}).get("enabled"):
        return

    url = (base_url or "").strip() or "http://localhost"


    p = _urlsplit(url if "://" in url else "http://" + url)
    host = p.hostname or (p.netloc or "").split("/")[0]

    https_open = False
    if host:
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(5)
        code = s.connect_ex((host, 443))
        s.close()
        https_open = (code == 0)

    http_cfg = dict((cfg or {}).get("http") or {})
    tls_cfg = dict((cfg or {}).get("tls") or {})
    verify_flag = getattr(session, "verify", True)

    u = url if "://" in url else ("http://" + url)

    if bool(http_cfg.get("insecure_skip_verify", False)):
        verify_flag = False
    elif https_open and bool(tls_cfg.get("soft_fail", True)):

        verify_flag = False

    r = session.get(u, timeout=6, allow_redirects=True,
                    verify=verify_for_phase(cfg, 'egress', u))

    hdr_token = r.headers.get("x-csrf-token") or r.headers.get("x-xsrf-token")
    if hdr_token:
        session.headers.update({"X-CSRF-Token": hdr_token})


if _ws_spec('doctest') is not None:
    from doctest import debug  # optional
else:
    debug = None

if _ws_spec('discovered') is not None:
    import discovered  # optional
else:
    discovered = None
if _ws_spec('starlette') is not None:
    from starlette import endpoints  # optional
else:
    endpoints = None
if _ws_spec('urllib3.util') is not None:
    from urllib3.util import url  # optional
else:
    url = None

_discover_func = None

if _find_spec("websecure.crawler") is not None:
    _mod = _import_module("websecure.crawler")
    _discover_func = getattr(_mod, "discover_dynamic_endpoints", None)
elif _find_spec("crawler") is not None:
    _mod = _import_module("crawler")
    _discover_func = getattr(_mod, "discover_dynamic_endpoints", None)

if callable(_discover_func):
    discover_dynamic_endpoints = _discover_func  # dış API korunur
    DISCOVER_DYNAMIC_ENDPOINTS_SOURCE = _mod.__name__
else:
    DISCOVER_DYNAMIC_ENDPOINTS_SOURCE = "fallback"

    # Basit, sağlam ve bağımsız dinamik keşif (Selenium tabanlı)
    # Not: try/except yok; hata yakalama Future.exception() ile üst katmanda yapılır.
    def discover_dynamic_endpoints(start_url: str,
                                   headless: bool = True,
                                   timeout_ms: int = 15000,
                                   max_pages: int = 200,
                                   record_dir: str | None = None,
                                   prefer: str = "selenium",
                                   return_artifacts: bool = True) -> tuple[list[str], dict]:

        # İç iş: browser işi (istisna atmadan bırakılır, Future.exception ile gözlemlenir)
        def _job() -> tuple[list[str], dict]:
            # WebDriver ayağa kaldır
            from websecure.core.utils import setup_webdriver  # mevcut modülden kullan
            
            # [Fix] Respect headless parameter passed from caller (which comes from config)
            drv = setup_webdriver(headless=headless)
            if drv is None:
                return ([], {"reason": "webdriver_unavailable"} if return_artifacts else {})
            # Zaman aşımı ve başlangıç parametreleri
            pl_timeout = max(1, int(timeout_ms / 1000))
            if hasattr(drv, "set_page_load_timeout"):
                drv.set_page_load_timeout(pl_timeout)
            parsed = urlparse(start_url)
            origin = (parsed.scheme, parsed.netloc)
            q: list[str] = [start_url]
            seen: set[str] = set()
            found: list[str] = []
            steps = 0
            while q and len(seen) < int(max_pages):
                u = q.pop(0)
                if u in seen:
                    continue
                seen.add(u)
                try:
                    drv.get(u)
                    # Bağlantıları DOM'dan topla
                    hrefs = drv.execute_script("return Array.from(document.querySelectorAll('a[href]')).map(a => a.href);")
                    if isinstance(hrefs, list):
                        for h in hrefs:
                            if not isinstance(h, str):
                                continue
                            p = urlparse(h)
                            if (p.scheme, p.netloc) != origin:
                                continue
                            h2, _ = urldefrag(h)
                            if h2 not in found:
                                found.append(h2)
                            if h2 not in seen and h2 not in q and len(q) < (max_pages * 2):
                                q.append(h2)
                except Exception as exc:
                    _logger.debug(f"[main] WebDriver link extract hatası: {exc!r}")
                steps += 1
                if steps % 5 == 0:
                    sleep(0.05)  
            # Kapat
            if hasattr(drv, "quit"):
                drv.quit()
            art = {"visited": len(seen), "found": len(found), "source": "selenium_fallback"} if return_artifacts else {}
            return (found, art)

        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_job)
            hard_timeout = max(5, int((timeout_ms / 1000) * 2 + 10))
            end = None
            t0 = __import__("time").time()
            res: tuple[list[str], dict] | None = None
            while end is None and (__import__("time").time() - t0) < hard_timeout:
                exc = fut.exception(timeout=0.1)
                if exc is None and fut.done():
                    res = fut.result()
                    end = True
                elif exc is not None:
                    end = True
            if res is None:
                return ([], {"reason": "timeout"} if return_artifacts else {})
            return res



# ensure_session imported below alongside other session_factory symbols (line ~897)




if _ws_spec("websecure.core.utils") is not None:
    from websecure.core.utils import (
        current_identity,
        apply_detected_scheme,
        load_config,
        apply_active_profile,
        run_content_discovery,
        setup_logging,
        setup_webdriver,
        silence_insecure_request_warnings,
        validate_url,
    )
elif _ws_spec("utils") is not None:
    from utils import (
        current_identity,
        apply_detected_scheme,
        load_config,
        run_content_discovery,
        setup_logging,
        setup_webdriver,
        silence_insecure_request_warnings,
        validate_url,
    )
else:
    raise ImportError("Neither 'core.utils' nor 'utils' is importable")

_det_spec = _ws_spec("websecure.core.detect")
if _det_spec is not None:
    _det = _im.import_module('websecure.core.detect')
    _classify_cb = getattr(_det, 'classify_access_block', None)
    if callable(_classify_cb):
        classify_access_block = _classify_cb  # re-export locally
    else:
        def classify_access_block(status: int, headers: dict, body: str) -> str:
            hdrs = headers or {}
            ua = (hdrs.get('server', '') + ' ' + hdrs.get('via', '')).lower()
            text = (body or '').lower()
            if status == 429:
                return 'rate_limit'
            if 'cloudflare' in ua or 'attention required' in text:
                return 'waf_challenge'
            if status in (401, 403):
                if 'captcha' in text or 'recaptcha' in text:
                    return 'captcha_block'
                return 'auth_required'
            return 'unknown'
    _prime = getattr(_det, 'prime_session', None)
    if callable(_prime):
        prime_session = _prime  # mevcut (core.http)’teki varsa üzerine yazar
else:
    def classify_access_block(status: int, headers: dict, body: str) -> str:  # minimal heuristic, istisnasız
        get_hdr = headers.get if isinstance(headers, dict) or hasattr(headers, "get") else (lambda k, d=None: d)

        server_raw = get_hdr("server", "")
        via_raw = get_hdr("via", "")

        server = server_raw.lower() if isinstance(server_raw, str) else str(server_raw).lower()
        via = via_raw.lower() if isinstance(via_raw, str) else str(via_raw).lower()
        ua = (server + " " + via).strip()

        text = body.lower() if isinstance(body, str) else str(body or "").lower()
        sc = status if isinstance(status, int) else -1

        if sc == 429:
            return "rate_limit"
        if "cloudflare" in ua or "attention required" in text:
            return "waf_challenge"
        if sc in (401, 403):
            if "captcha" in text or "recaptcha" in text:
                return "captcha_block"
            return "auth_required"
        return "unknown"


_plan_spec = _ws_spec("websecure.core.phases")
if _plan_spec is not None:
    _phases = _im.import_module("websecure.core.phases")
    build_plan = getattr(_phases, "build_plan", None)
else:
    build_plan = None


# === Dinamik kanonik çözümleyici (core.utils.resolve_canonical_base) ===
def _get_resolve_canonical_base():
    # Öncelik: core.utils, sonra kök utils
    mod_name = None
    if _ws_spec("websecure.core.utils") is not None:
        mod_name = "websecure.core.utils"
    elif _ws_spec("utils") is not None:
        mod_name = "utils"

    if mod_name is not None:
        mod = _im.import_module(mod_name)
        func = getattr(mod, "resolve_canonical_base", None)
        if callable(func):
            return func

    # Minimal fallback (modül bulunamazsa en azından erişim deneyelim)
    import subprocess
    import shutil
    def _fallback(target, session, timeout=6, try_www=True):
        t = (target or "").strip()
        if not t:
            return None

        if "://" in t:
            candidates = [t]
        else:
            host = t.strip("/")
            if try_www:
                candidates = [
                    f"https://{host}",
                    f"https://www.{host}",
                    f"http://{host}",
                    f"http://www.{host}",
                ]
            else:
                candidates = [f"https://{host}", f"http://{host}"]

        ua = "Mozilla/5.0"
        sess_headers = getattr(session, "headers", None)
        if isinstance(sess_headers, dict):
            ua = (sess_headers.get("User-Agent") or ua) or "Mozilla/5.0"
        verify = getattr(session, "verify", True)

        curl_bin = shutil.which("curl")

        if curl_bin:
            def _probe_with_curl(url: str) -> str | None:
                args = [curl_bin, "-I", "-L", "-sS", "--max-time", str(float(timeout)), "-A", ua, url,
                        "-w", "%{url_effective} %{http_code}\n", "-o", "/dev/null"]
                if isinstance(verify, bool) and verify is False:
                    args.insert(1, "--insecure")
                elif isinstance(verify, str) and verify:
                    args[1:1] = ["--cacert", verify]

                cp = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                if cp.returncode == 0:
                    out = (cp.stdout or "").strip()
                    if out:
                        parts = out.split()
                        if len(parts) >= 2 and parts[-1].isdigit():
                            code = int(parts[-1])
                            final = " ".join(parts[:-1])
                            if 200 <= code < 600:
                                return final.split("#", 1)[0].rstrip("/")
                return None

            for url in candidates:
                ok = _probe_with_curl(url)
                if ok:
                    return ok
            return None

        # curl yoksa, sessiyonla ilerle (istisna yakalama YOK; hata olursa bastırılmaz)
        get = getattr(session, "get", None)
        if not callable(get):
            return None

        req_headers = {"User-Agent": ua}
        for url in candidates:
            r = get(url, headers=req_headers, timeout=timeout, allow_redirects=True, verify=verify)
            sc = getattr(r, "status_code", 0)
            if 200 <= sc < 600:
                return r.url.split("#", 1)[0].rstrip("/")

        return None

    return _fallback


_scan_spec = _ws_spec("websecure.core.phases")
if _scan_spec is not None:
    _scan_mod = _im.import_module("websecure.core.phases")
    ScanContext = getattr(_scan_mod, "ScanContext", None)
    ScanMode = getattr(_scan_mod, "ScanMode", None)
    run_mode = getattr(_scan_mod, "run_mode", None)
else:
    ScanContext = None
    ScanMode = None


    def run_mode(*_a, **_k):
        return None

# --- Faz Planı / Orkestrasyon ---


# --- TLS ---
_tls_spec = _ws_spec("websecure.scanners.tls")
if _tls_spec is not None:
    _tls_mod = _im.import_module('websecure.scanners.tls')
    _check = getattr(_tls_mod, "check_ssl_certificate", None)
    if callable(_check):
        check_ssl_certificate = _check
    else:
        def check_ssl_certificate(*a, **k):
            return {
                "host": None,
                "subject_CN": None,
                "not_before": None,
                "not_after": None,
                "days_remaining": None,
                "tls_version": None,
                "problems": ["tls_module_missing"],
            }
else:
    def check_ssl_certificate(*a, **k):
        return {
            "host": None,
            "subject_CN": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "tls_version": None,
            "problems": ["tls_module_missing"],
        }

    # [WS3] Fallback check_ssl_certificate is defined here
    pass

# --- Raporlama / sonuç kovaları ---
_reporting_mod = None
_ROOT = __file__

_spec_core = _ws_spec("websecure.core.reporting")
if _spec_core is not None:
    try:
        _reporting_mod = _im.import_module("websecure.core.reporting")
    except ImportError:
        _reporting_mod = None

# İkinci şans: düz 'reporting' ama sadece proje kökündense
if _reporting_mod is None:
    _spec_plain = _ws_spec("reporting")
    if _spec_plain is not None:
        _org = getattr(_spec_plain, "origin", None)
        if isinstance(_org, str):
            _org_p = str(_P(_org).resolve())
            _root_p = str(_P(__file__).resolve().parent)
            _is_local = _org_p.startswith(_root_p)
            _is_site = ("site-packages" in _org_p.lower()) or ("dist-packages" in _org_p.lower())
            if _is_local and not _is_site:
                _reporting_mod = _im.import_module("reporting")

if _reporting_mod is None:
    def add_result(*_a, **_k):
        return None


    # Debug konfigürasyonu - fixed: moved to main or removed as it relies on unparsed args
    # if args.debug:
    #    cfg['debug'] = True
    #    _logging.getLogger().setLevel(_logging.DEBUG)
    #    _logging.info("[CLI] Debug modu aktifleştirildi.")
    def configure_logging(*_a, **_k):
        return None


    def perform_reporting(*_a, **_k):
        return {"written": {}}


    def redact_sensitive(x):
        return x


    def get_bucket_results():
        return {}


    def note_auth_outcome(*_a, **_k):
        return None
else:
    add_result = getattr(_reporting_mod, "add_result", lambda *_a, **_k: None)
    configure_logging = getattr(_reporting_mod, "configure_logging", lambda *_a, **_k: None)
    _pri = getattr(_reporting_mod, "perform_reporting", None)
    if _pri is None:
        def perform_reporting(*_a, **_k):
            _flush = getattr(_reporting_mod, "flush", None)
            if callable(_flush):
                _flush()
            return {"written": {}}
    else:
        perform_reporting = _pri
    redact_sensitive = getattr(_reporting_mod, "redact_sensitive", lambda x: x)
    get_bucket_results = getattr(_reporting_mod, "get_bucket_results", lambda: {})
    note_auth_outcome = getattr(_reporting_mod, "note_auth_outcome", lambda *_a, **_k: None)


# --- Skorlama & entegrasyon ---

# --- Port tarama: phases.py:phase_portscan() kullanılır, bu wrapper'lar kaldırıldı ---


# --- Port Scanner ---
    # Auto-binded orphan modules (plugin imports) — DO NOT REMOVE
    for _m in [
        'websecure.core.injection',
        'websecure.core.phases',
        'websecure.core.safe_regex',
        'websecure.core.auth.auth_flow' if _ws_has('websecure.core.auth.auth_flow') else None,
        'websecure.crawler',
    ]:
        if _m and _ws_spec(_m) is not None:
            _im.import_module(_m)


# --- Crawler ---
# --- Crawler ---
_crawl_mod = _im.import_module('websecure.crawler') if _ws_spec('websecure.crawler') is not None else None
if _crawl_mod is None:
    # Fallback: try relative from core or root if simple import fails
    try:
         import websecure.crawler as _wc
         _crawl_mod = _wc
    except ImportError:
         print("[!] UYARI: Crawler modülü (websecure.crawler) yüklenemedi!")

crawl_website = getattr(_crawl_mod, 'crawl_website', None) if _crawl_mod else None
WebCrawler = getattr(_crawl_mod, 'WebCrawler', None) if _crawl_mod else None
CrawlerConfig = getattr(_crawl_mod, 'CrawlerConfig', None) if _crawl_mod else None

if crawl_website is None:
    def crawl_website(*a, **k):
        return None

# --- Güvenlik başlıkları ---
_infra_mod = _im.import_module('websecure.scanners.infrastructure') if _ws_spec('websecure.scanners.infrastructure') is not None else None
scan_security_headers = getattr(_infra_mod, 'get_security_headers', None) if _infra_mod else None

# --- GraphQL ---
_gql_mod = _im.import_module('websecure.scanners.graphql') if _ws_spec('websecure.scanners.graphql') is not None else None
GraphQLScanner = getattr(_gql_mod, 'GraphQLScanner', None) if _gql_mod else None
# --- SSRF/XXE ---
_ssrf_mod = _im.import_module('websecure.scanners.ssrf_xxe') if _ws_spec('websecure.scanners.ssrf_xxe') is not None else None
ssrf_xxe_scan = getattr(_ssrf_mod, 'scan', None) if _ssrf_mod else None
if ssrf_xxe_scan is None:
    def ssrf_xxe_scan(*a, **k):
        return None

# --- OWASP / Nuclei (yeni entegrasyon) ---
_owasp_mod = None
if _ws_spec("websecure.scanners.owasp") is not None:
    _owasp_mod = _im.import_module("websecure.scanners.owasp")
elif _ws_spec('owasp') is not None:
    _owasp_mod = _im.import_module('owasp')

run_owasp_and_nuclei = getattr(_owasp_mod, 'run_owasp_and_nuclei', None) if _owasp_mod else None
if run_owasp_and_nuclei is None:
    def run_owasp_and_nuclei(*a, **k):
        return {}


# FAZ 4.2: _call_scanner_if_available ve _bind_offensive core/scan_runner.py'e taşındı.
# Geriye dönük uyumluluk için buradan re-export edilir.
from websecure.core.scan_runner import (
    _call_scanner_if_available,
    _bind_offensive,
)


offensive_request_smuggling = _bind_offensive("websecure.scanners.request_smuggling", "offensive_request_smuggling")
offensive_mass_assignment = _bind_offensive("websecure.scanners.mass_assignment", "offensive_mass_assignment")
offensive_jwt = _bind_offensive("websecure.scanners.jwt", "offensive_jwt")
offensive_nosqli = _bind_offensive("websecure.scanners.nosqli", "offensive_nosqli")
offensive_ws_fuzz = _bind_offensive("websecure.scanners.ws_fuzz", "offensive_ws_fuzz")

# ws_fuzz modülü yoksa, ek saldırı taramalarını tetikleyen anlamlı bir fallback sağla
if _ws_spec("websecure.scanners.ws_fuzz") is None:
    def offensive_ws_fuzz(url, session=None, debug=False, auth_ctx=None):
        _call_scanner_if_available("websecure.scanners.authorization", url, session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.file_upload", url, session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.graphql_attacks", url, session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.ssrf_xxe", url, session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.tls", url, session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.owasp", url, session=session, debug=debug, auth_ctx=auth_ctx)
        return None

# --- Authorization ---
# --- Authorization ---
_authz = _im.import_module("websecure.scanners.auth_scanners") if _ws_spec(
    "websecure.scanners.auth_scanners") is not None else None
RoleContext = getattr(_authz, 'RoleContext', None) if _authz else None
RoleProfile = getattr(_authz, 'RoleProfile', None) if _authz else None
# In auth.py, the function is check_idor or compare_roles? 
# Wait, main expects 'run'. But auth.py has 'compare_roles' and 'check_idor'.
# I need to verify what 'authorization_run' is expected to do.
# Looking at auth.py again, it has no 'run' function exposed at top level?
# Line 106 says "formerly authorization.py". 
# Usually scanners have a 'run' entry point. 
# I will bind 'authorization_run' to a wrapper that calls compare_roles + check_idor.
def _auth_wrapper(url, session, debug=False, auth_ctx=None):
    findings = []
    if not auth_ctx or not hasattr(auth_ctx, "build_sessions"):
        return findings
    sessions = auth_ctx.build_sessions()
    if sys.modules.get("websecure.scanners.auth_scanners"):
        m = sys.modules["websecure.scanners.auth_scanners"]
        _comp = getattr(m, "compare_roles", None)
        _idor = getattr(m, "check_idor", None)
        if callable(_comp):
             findings.extend(_comp(url, sessions))
        if callable(_idor):
             findings.extend(_idor(sessions, url))
    return findings

authorization_run = _auth_wrapper

# --- Authenticated helpers (auth-only probe) ---
# auth.py has probe_auth_only
probe_auth_only = getattr(_authz, 'probe_auth_only', None) if _authz else None
if probe_auth_only is None:
    def probe_auth_only(*a, **k):
        return None

# --- Fuzzing / OAST ---
_pf = _im.import_module("websecure.core.fuzzer") if _ws_spec("websecure.core.fuzzer") is not None else None
discover_params_from_crawl = getattr(_pf, 'discover_params_from_crawl', None) if _pf else None
fuzz_endpoint = getattr(_pf, 'fuzz_endpoint', None) if _pf else None
guess_additional_params = getattr(_pf, 'guess_additional_params', None) if _pf else None

if discover_params_from_crawl is None:
    def discover_params_from_crawl(*a, **k):
        return {"query": [], "body": [], "json": []}
if guess_additional_params is None:
    def guess_additional_params(d, *a, **k):
        return d
if fuzz_endpoint is None:
    def fuzz_endpoint(*a, **k):
        return None

_oast = _im.import_module("websecure.core.oast") if _ws_spec("websecure.core.oast") is not None else None
OASTClient = getattr(_oast, 'OASTClient', None) if _oast else None
run_oast_on_target = getattr(_oast, 'run_oast_on_target', None) if _oast else None

if OASTClient is None:
    class OASTClient:
        def __init__(self, *a, **k):
            pass
if run_oast_on_target is None:
    def run_oast_on_target(*a, **k):
        return []

# --- Business Logic & Advanced Scanners ---
_flows_mod = _im.import_module("websecure.core.flows") if _ws_spec("websecure.core.flows") is not None else None
run_business_logic_flows = getattr(_flows_mod, "run_business_logic_flows", None) if _flows_mod else None

_bl_mod = _im.import_module("websecure.core.bl_concurrency") if _ws_spec("websecure.core.bl_concurrency") is not None else None
run_race_conditions = getattr(_bl_mod, "run_race_conditions", None) if _bl_mod else None

_gqa_mod = _im.import_module("websecure.scanners.graphql_attacks") if _ws_spec("websecure.scanners.graphql_attacks") is not None else None
graphql_attack_scan = getattr(_gqa_mod, "run", None) if _gqa_mod else None

_fu_mod = _im.import_module("websecure.scanners.file_upload") if _ws_spec("websecure.scanners.file_upload") is not None else None
file_upload_scan = getattr(_fu_mod, "run", None) if _fu_mod else None


# ------------------ Yardımcılar ------------------

# ------------------ Tarama yoğunluğu (Agresif/Normal) teklifi ------------------
# FAZ-EK: Profil seçme/uygulama helpers → core/scan_profile.py'e taşındı
from websecure.core.scan_profile import (
    _estimate_minutes,
    _apply_normal_profile,
    _offer_scan_profile_and_confirm,
    _pick_from_config,
    _choose_mode_from_config,
)


# FAZ-EK: Proxy/session helpers + ensure_session → core/session_factory.py'e taşındı
from websecure.core.session_factory import (
    ensure_session,
    _parse_host_port_from_proxy,
    _tcp_port_open,
    _proxy_alive,
    _setup_session_from_config,
)


def _build_auth_ctx(session: requests.Session, cfg: dict) -> dict | None:
    """
    Config + session'dan kimlik bağlamını (headers/cookies) üretir.

    """
    config = cfg if isinstance(cfg, dict) else {}
    auth = config.get("auth")
    auth = auth if isinstance(auth, dict) else {}

    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}

    # Bearer / Token
    tok = auth.get("bearer") or auth.get("bearer_token") or auth.get("token")
    if isinstance(tok, (str, bytes)):
        token_s = tok.decode() if isinstance(tok, bytes) else tok
        if token_s.strip():
            headers["Authorization"] = f"Bearer {token_s.strip()}"

    # API key header
    api_hdr = auth.get("api_key_header")
    api_val = auth.get("api_key")
    if isinstance(api_hdr, (str, bytes)) and isinstance(api_val, (str, bytes)):
        h = api_hdr.decode() if isinstance(api_hdr, bytes) else api_hdr
        v = api_val.decode() if isinstance(api_val, bytes) else api_val
        if h.strip() and v.strip():
            headers[h.strip()] = v

    # Extra auth headers
    extra_hdrs = auth.get("headers")
    if isinstance(extra_hdrs, dict):
        for k, v in extra_hdrs.items():
            ks = str(k)
            vs = str(v)
            if ks:
                headers[ks] = vs

    # Cookies from config
    ck = auth.get("cookie") or auth.get("cookies")
    if isinstance(ck, dict):
        for k, v in ck.items():
            cookies[str(k)] = str(v)

    if isinstance(auth.get("cookie_name"), (str, bytes)) and isinstance(auth.get("cookie_value"), (str, bytes)):
        cn = auth["cookie_name"].decode() if isinstance(auth["cookie_name"], bytes) else auth["cookie_name"]
        cv = auth["cookie_value"].decode() if isinstance(auth["cookie_value"], bytes) else auth["cookie_value"]
        if cn:
            cookies[str(cn)] = str(cv)

    # Session-derived Authorization (override only if not already set)
    sess_headers = getattr(session, "headers", None)
    if isinstance(sess_headers, dict) or hasattr(sess_headers, "get"):
        auth_in_sess = sess_headers.get("Authorization") if hasattr(sess_headers,
                                                                    "get") else None  # type: ignore[func-returns-value]
        if ("Authorization" not in headers) and isinstance(auth_in_sess, (str, bytes)):
            headers["Authorization"] = auth_in_sess.decode() if isinstance(auth_in_sess, bytes) else auth_in_sess

    # Session cookies
    sess_cj = getattr(session, "cookies", None)
    if sess_cj is not None:
        get_dict = getattr(sess_cj, "get_dict", None)
        if callable(get_dict):
            for k, v in get_dict().items():
                cookies[str(k)] = str(v)

    if not headers and not cookies:
        return None
    return {"headers": headers, "cookies": cookies}


def _off_enabled(cfg: dict, key: str) -> bool:
    """config.offensive.<key>.enabled -> bool (istisnasız parse)"""

    def _to_bool(x, default: bool = False) -> bool:
        if isinstance(x, bool):
            return x
        if isinstance(x, (int, float)):
            return x != 0
        if isinstance(x, str):
            s = x.strip().lower()
            if s in ("1", "true", "yes", "on", "enable", "enabled"):
                return True
            if s in ("0", "false", "no", "off", "disable", "disabled"):
                return False
        return default

    if not isinstance(cfg, dict):
        return False
    off = cfg.get("offensive")
    if not isinstance(off, dict):
        return False
    node = off.get(key)
    if not isinstance(node, dict):
        return False
    return _to_bool(node.get("enabled"), False)


def _off_profile_allows(cfg: dict, key: str) -> bool:
    """
    Offensive profil kapısı. 'stealth' az gürültülü; 'deep' hepsi.
    Varsayılan: 'stealth'.
    """
    prof = (((cfg.get("offensive") or {}).get("profile")) or "stealth").strip().lower()
    stealth = {"jwt_attacks", "nosql_injection"}
    deep = {"request_smuggling", "mass_assignment", "jwt_attacks", "nosql_injection", "websocket_fuzz"}
    allowed_set = deep if prof == "deep" else stealth
    return key in allowed_set


def _has_hsts(results: dict) -> bool:
    """security_headers çıktısından HSTS var mı? (istisnasız, bastırmasız)"""

    def _norm(x) -> str:
        return (str(x).strip().lower()) if x is not None else ""

    POSITIVE = {"mevcut", "present", "enabled", "ok", "yes", "true", "var", "on"}

    if not isinstance(results, dict):
        return False

    sh = results.get("security_headers")
    if sh is None:
        return False

    # Liste biçimi: [{"header": "...", "status": "..."}]
    if isinstance(sh, (list, tuple)):
        for it in sh:
            if isinstance(it, dict):
                h = _norm(it.get("header"))
                st_raw = it.get("status")
                st = _norm(st_raw)
                if h == "strict-transport-security" and (st in POSITIVE or (isinstance(st_raw, bool) and st_raw)):
                    return True
            elif isinstance(it, (list, tuple)) and len(it) >= 2:
                h = _norm(it[0])
                st_raw = it[1]
                st = _norm(st_raw)
                if h == "strict-transport-security" and (st in POSITIVE or (isinstance(st_raw, bool) and st_raw)):
                    return True
        return False

    # Sözlük biçimi: {"Strict-Transport-Security": "Mevcut"/True/...}
    if isinstance(sh, dict):
        h = _norm("Strict-Transport-Security")
        val = sh.get("Strict-Transport-Security") or sh.get("strict-transport-security")
        if val is not None:
            st = _norm(val)
            if st in POSITIVE or (isinstance(val, bool) and val):
                return True
        # Bazı raporlarda {"header": {"status": ...}} şeklinde olabilir
        node = sh.get("header") if isinstance(sh.get("header"), dict) else None
        if node and _norm(node.get("name")) == "strict-transport-security":
            v = node.get("status")
            return (isinstance(v, bool) and v) or (_norm(v) in POSITIVE)
        return False

    return False


def _auth_cov_note(kind: str) -> None:
    k = (kind or "").lower()
    if "waf" in k:
        note_auth_outcome("WAF");
        return
    if "rate" in k:
        note_auth_outcome("RateLimit");
        return
    note_auth_outcome("Auth")


def _public_surface_seeds(base_url: str) -> list[str]:
    base = base_url.rstrip("/")
    candidates = [
        "/robots.txt", "/sitemap.xml",
        "/api/public", "/api/health", "/api/status",
        "/guest", "/login", "/auth/login", "/auth/status",
        "/_next/data/index.json", "/static/app.js",
    ]
    return [base + p for p in candidates]

# --- Raporlama Entegrasyonu ---
if _iul.find_spec("websecure.core.reporting") is not None:
    _rmod = _im.import_module("websecure.core.reporting")
    _phase_rec = getattr(_rmod, "_phase_rec", None)
elif _iul.find_spec('reporting') is not None:
    from websecure.core.reporting import (
    configure_logging,
    perform_reporting,
    add_session,
    verify_and_score
)
else:
    _phase_rec = None


# --- Parametre imza filtresi yardımcıları — websecure.core.utils'ten al ---
try:
    from websecure.core.utils import sig_params as _sig_params_util, kw_filter as _kw_filter_util, guess_host_from_url as _guess_host_from_url

    def _sig_params(fn):
        return _sig_params_util(fn)

    def _kw_filter(fn, **kw):
        return _kw_filter_util(fn, **kw)

except (ImportError, AttributeError):
    def _sig_params(fn) -> set:
        return set(inspect.signature(fn).parameters.keys()) if callable(fn) else set()

    def _kw_filter(fn, **kw):
        ps = _sig_params(fn)
        return {k: v for k, v in kw.items() if k in ps}

    def _guess_host_from_url(url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).hostname or ""
        except (ValueError, AttributeError):
            return ""


def _passive_js_analyze(session: requests.Session, js_urls: list[str], results: dict) -> None:
    """Hafif JS pasif analiz: potansiyel anahtar izleri toplar (best-effort, istisnasız)."""
    keys: list[dict] = []
    curl_bin = shutil.which("curl")

    if not isinstance(js_urls, (list, tuple)) or not js_urls:
        return

    if curl_bin:
        # curl ile istisnasız içerik alma
        for u in js_urls:
            if not isinstance(u, str) or not u.strip():
                continue
            # yalnızca http/https şemaları
            pr = urlparse(u)
            if pr.scheme not in ("http", "https"):
                continue

            # -L (redirect), --max-time 5s, -sS sessiz, -w kodu yaz, içerik stdout'a düşer
            # not: check=False → istisna yok; returncode üzerinden karar
            cp = subprocess.run(
                [curl_bin, "-L", "--max-time", "5", "-sS", u, "-w", "\n%{http_code}\n"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if cp.returncode != 0:
                continue
            out = cp.stdout or ""
            if not out:
                continue
            *body_lines, last = out.splitlines()
            # Son satır HTTP kodu; geri kalanı gövde
            try_code = last.strip()
            http_code = int(try_code) if try_code.isdigit() else 0
            body = "\n".join(body_lines)
            if 200 <= http_code < 400 and body:
                lbody = body.lower()
                # Basit anahtar ipuçları
                if ("apikey" in lbody) or ("mapbox" in lbody) or ("google_maps" in lbody) or ("AIza" in body):
                    keys.append({"url": u, "hint": "key_like"})
    else:
        # curl yoksa sessizce atlamayalım: sonuçlara nedenini yazalım
        results.setdefault("artifacts", {}).setdefault("notes", []).append(
            {"component": "js_passive", "note": "curl_missing; js anahtar taraması atlandı"}
        )

    if keys:
        results.setdefault("artifacts", {}).setdefault("js_keys", []).extend(keys)


# ------------------ Faz Planı Çalıştırıcı (YENİ) ------------------
def _run_phase_plan(ctx, *, skip_legacy_offensive=True):

    results = getattr(ctx, "results", {})
    if not isinstance(results, dict):
        results = {}
        setattr(ctx, "results", results)

    plan = build_plan(ctx)  # hata olursa yükselir; bastırma yok

    ran = 0
    enabled = 0
    visible_meta = []
    results.setdefault("phase_timings", {})

    print(f"[DEBUG] Phase Plan Built ({len(plan)} items): {[p.get('id') for p in plan if isinstance(p, dict)]}")

    if not isinstance(plan, (list, tuple)):

        # Protokol: plan beklenen formatta değilse koşma
        add_result("phase_plan", {"visible": [], "enabled_total": 0, "ran": 0, "error": "invalid_plan_format"})
        if skip_legacy_offensive:
            results["_skip_legacy_offensive"] = True
        return {"ran": 0, "enabled": 0}

    for item in plan:
        if not isinstance(item, dict):
            continue
        rid = item.get("id")
        visible_meta.append({
            "id": rid,
            "title": item.get("title"),
            "enabled": bool(item.get("enabled")),
            "reason": item.get("reason"),
            "tags": item.get("tags", []),
        })

        runner = item.get("runner")
        if item.get("enabled") and callable(runner):
            enabled += 1
            t0 = time.time()
            runner(ctx)  # hata olursa yükselir; bastırma yok
            ran += 1
            results["phase_timings"][rid] = round(time.time() - t0, 2)

    add_result("phase_plan", {"visible": visible_meta, "enabled_total": enabled, "ran": ran})

    if skip_legacy_offensive:
        results["_skip_legacy_offensive"] = True

    return {"ran": ran, "enabled": enabled}

# ------------------ Ana akış ------------------
# FAZ-EK: Egress policy helpers → core/egress.py'e taşındı
from websecure.core.egress import (
    _enforce_egress_policy,
    _egress_health_check,
)

def _safe_call(func, *args, call_timeout: float | None = None, **kwargs):


    if not callable(func):
        return False, "not_callable"
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(func, *args, **kwargs)
        if call_timeout is None or call_timeout <= 0:
            while not fut.done():
                _t.sleep(0.01)
        else:
            t0 = _t.time()
            while not fut.done():
                if (_t.time() - t0) > call_timeout:
                    fut.cancel()
                    return False, "timeout"
                _t.sleep(0.01)
        exc = fut.exception()
        if exc is not None:
            return False, str(exc)
        return True, fut.result()


def _normalize_webdriver_cfg(cfg: dict) -> dict:

    def _to_bool(x, default=None):
        if isinstance(x, bool): return x
        if isinstance(x, (int, float)): return x != 0
        if isinstance(x, str):
            s = x.strip().lower()
            if s in ("1","true","yes","on"): return True
            if s in ("0","false","no","off"): return False
        return default

    out = {"webdriver": {}}
    c = cfg if isinstance(cfg, dict) else {}

    headless = None
    tls_wd = ((c.get("tls") or {}).get("webdriver") or {}) if isinstance(c.get("tls"), dict) else {}
    if isinstance(tls_wd, dict) and "headless" in tls_wd:
        headless = _to_bool(tls_wd.get("headless"), None)
    if headless is None and isinstance((c.get("crawl") or {}), dict) and "headless" in c.get("crawl", {}):
        headless = _to_bool(c.get("crawl", {}).get("headless"), None)
    if headless is None and isinstance((c.get("crawler") or {}), dict) and "headless" in c.get("crawler", {}):
        headless = _to_bool(c.get("crawler", {}).get("headless"), None)
    if headless is None and isinstance(((c.get("crawl") or {}).get("browser") or {}), dict):
        headless = _to_bool((c.get("crawl") or {}).get("browser", {}).get("headless"), None)
    if headless is None and isinstance(((c.get("crawler") or {}).get("browser") or {}), dict):
        headless = _to_bool((c.get("crawler") or {}).get("browser", {}).get("headless"), None)

    # [FEATURE] Allow CLI override for visibility
    # Öncelik sırası:
    # 1. --visible (Zorla AÇ)
    # 2. --headless (Zorla GİZLE)
    # 3. Varsayılan: AÇIK (False)
    
    if "--visible" in sys.argv:
        headless = False
    elif "--headless" in sys.argv:
        headless = True
    
    if headless is None:
        headless = False  # varsayılan: görünür tarayıcı

    out["webdriver"]["headless"] = bool(headless)

    bin_path = None
    if isinstance(tls_wd, dict) and isinstance(tls_wd.get("binary"), str) and tls_wd.get("binary").strip():
        bin_path = tls_wd.get("binary").strip()
        out["webdriver"]["binary"] = bin_path


    out["webdriver"]["allow_bad_tls"] = False


    return out


def main():
    print("=== Bu program Zemheri tarafından web sitesi ve web uygulamaları zaafiyet keşfi için oluşturuldu ===\n")

    print(r"""
  ______  ______  __  __   _____  ______   _____ 
 |___  / |  ____||  \/  | / ____||  ____| / ____|
O====|_______________________________________________________>  1   1 0
  / /__  | |____ | |  | | ____) || |____ | |____               0 0 1 1
 /_____| |______||_|  |_||_____/ |______| \_____|               011 0 0
                                                               0 1 1
                                                                1 0
                                                                 1
    """)
    print("[!] UYARI / ETHICS: Bu aracı yalnızca yazılı izinli ortamlarda ve yasal çerçevede kullanın.")
    print("    Tarama, hedef sistemlerde kayıt bırakabilir. Gizlilik/uyumluluk ve hız sınırlarını gözetin.")
    print("")
    cfg = load_config()

    # Install Ctrl+C handler — sets cancel event instead of crashing mid-scan
    try:
        from websecure.core.phases import _install_sigint_handler
        _install_sigint_handler()
    except (ImportError, Exception):
        pass

    try_prime = True

    _ = _ensure_wl(cfg)

    # port_scan anti-blocking kaldırıldı — Nmap rate control kendi içinde yönetiliyor

    # === Sonuç kovası (yerel ve global bağ) ===
    results: dict = {"phase_timings": {}, "sections": []}
    globals()['results'] = results
    globals()['cfg'] = cfg

    # Profil çözümleme (settings.profiles → _resolved_profile)
    # Profil çözümleme (settings.profiles → _resolved_profile)
    _profiles = (cfg.get("settings") or {}).get("profiles") or {}
    _active = (cfg.get("settings") or {}).get("scan_profile") or "stealth"
    cfg.setdefault("_resolved_profile", _profiles.get(_active, {}))

    # Raporlama modülüne tüm config’i ver
    configure_logging(level=str(((cfg or {}).get("settings") or {}).get("logging", {}).get("level", "INFO")))

    # --- Tool Manager Integration (Early Prompt) ---
    from websecure.core.tool_manager import ToolManager
    tm = ToolManager(cfg)
    # Interactive Prompt
    # CLI argümanlarından bağımsız çalışması için burada çağırıyoruz.
    # Ancak --help veya versiyon sorgusunda çalışmasın diye basit bir kontrol eklenebilir ama
    # argparse henüz parse edilmediği için sys.argv kontrolü gerekebilir.
    is_dry_run_pre = "--dry-run" in sys.argv
    is_wizard = "--wizard" in sys.argv

    if is_wizard:
        # Import dynamically to avoid overhead if not used
        try:
           from websecure.core.wizard import run_wizard
           should_run = run_wizard()
           if not should_run:
               sys.exit(0)
           # If user said YES to run immediately, reload config and proceed
           cfg = load_config() 
        except ImportError:
            print("[!] Wizard module not found.")
            sys.exit(1)
    is_batch_pre = "--batch" in sys.argv
    if "--help" not in sys.argv and "-h" not in sys.argv and not is_dry_run_pre and not is_batch_pre:
        tool_choices = tm.ask_user_interactive()

        # Apply choices
        if tool_choices.get("sqlmap"):
            tm.start_sqlmap_api()

        if "ffuf" in tool_choices:
            if cfg.get("content_discovery"):
                cfg["content_discovery"]["enabled"] = tool_choices["ffuf"]
            cfg.setdefault("offensive", {}).setdefault("ffuf", {})["enabled"] = tool_choices["ffuf"]

        if "feroxbuster" in tool_choices:
            cfg.setdefault("offensive", {}).setdefault("feroxbuster", {})["enabled"] = tool_choices["feroxbuster"]

        if "nmap" in tool_choices:
            cfg.setdefault("nmap", {})["enabled"] = tool_choices["nmap"]

        import atexit
        atexit.register(tm.stop_all)
    # ---------------------------------------------

    # InsecureRequestWarning sustur
    silence_insecure_request_warnings()

    # --- Tor Integration ---
    # Check if active profile config has Tor settings
    # _resolved_profile is populated above
    _prof = cfg.get("_resolved_profile") or {}
    _tor_interval = _prof.get("tor_rotation_interval")
    _tor_port = _prof.get("tor_control_port")
    
    # If proxy is a socks proxy pointing to local tor (9050, 9150), also might want to enable
    # But explicit config is safer.
    
    # [FIX] Tor Global Initialization (Acil Durum Onarımı)
    # Bu, tüm modüllerin (özellikle http.py) tek bir Tor kontrolcüsüne erişmesini sağlar.
    if _tor_interval and _tor_port:
         try:
             print(f"[+] Tor Entegrasyonu Aktif: Her {_tor_interval} saniyede IP değişecek.")
             from websecure.core.waf_bypass import init_tor_control, start_auto_rotation, rotate_tor_identity
             
             # Global kontrolcüyü başlat
             init_tor_control({"enabled": True, "control_port": int(_tor_port)})
             
             # İlk yenileme denemesi
             if rotate_tor_identity():
                 pass # Sessiz başarılı
             else:
                 print("[!] UYARI: Tor Control Port'a bağlanılamadı. (Tor çalışıyor mu?)")
                 
             # Otomatik döngüyü başlat
             start_auto_rotation(interval=int(_tor_interval))
             
         except ImportError:
             pass
         except Exception as e:
             print(f"[!] Tor hatası: {e}")
             
    # Cleanup (Daemon threadler otomatik kapanır, manuel stop gerekmez)

    # CLI argümanları
    parser = argparse.ArgumentParser(description="WebSecure hedef seçimi")
    parser.add_argument("--waf", action="store_true", help="WAF bypass modunu etkinleştir")
    parser.add_argument("--fuzz-ml", action="store_true", help="Heuristik tabanlı anomali tespiti")
    parser.add_argument("--target", "-t", help="Hedef domain veya URL")
    parser.add_argument("--attack", action="store_true", help="Offensive D-fazını etkinleştir (güvenli mod)")
    parser.add_argument("--attack-unsafe", action="store_true",
                        help="Offensive fazı güvenli olmayan modda çalıştır (dikkat!)")
    parser.add_argument("--verify-only", action="store_true", help="Yalnız bulguları doğrula & skorla")
    parser.add_argument("--oast-domain", help="OAST için kök domain (DNS tabanlı callback)")
    parser.add_argument("--oast-url", help="OAST HTTP callback tabanı (örn. https://oast.example)")
    parser.add_argument("--dry-run", action="store_true", help="Etkileşimli soruları atla ve sadece yapılandırmayı doğrula")
    parser.add_argument("--batch", action="store_true", help="Etkileşimli soruları atla ve varsayılanlarla devam et (Non-interactive)")
    parser.add_argument("--profile", help="Tarama profili (stealth, normal, aggressive, deep)")
    parser.add_argument("--debug", action="store_true", help="Detaylı hata ayıklama çıktılarını (DEBUG logs) göster")
    parser.add_argument("--visible", action="store_true", help="Tarayıcıyı AÇ (Varsayılan)")
    parser.add_argument("--headless", action="store_true", help="Tarayıcıyı GİZLE (Arka planda çalıştır)")
    args = parser.parse_args()

    # --headless VARSA gizle, --visible VARSA göster (çakışırsa visible kazanır, yukarıda sys.argv ile işledik ama burada config'e basıyoruz)
    # _normalize_webdriver_cfg zaten sys.argv kontrolü yaptı ve config yüklendiğinde headless set edildi.
    # Ancak burada son bir override yapalım:
    
    if args.headless and not args.visible:
        # Config'deki her yere işle
        cfg.setdefault("crawler", {})["headless"] = True
        cfg.setdefault("crawl", {})["headless"] = True
        if "webdriver" not in cfg: cfg["webdriver"] = {}
        cfg["webdriver"]["headless"] = True
        if "settings" not in cfg: cfg["settings"] = {}
        if "webdriver" not in cfg["settings"]: cfg["settings"]["webdriver"] = {}
        cfg["settings"]["webdriver"]["headless"] = True
        print("[*] Headless Mod Etkinleştirildi (Tarayıcı GİZLİ).")

    # VISIBLE MODE: Force all headless settings to False if requested OR default
    # Eğer --headless YOKSA, varsayılan olarak görünür olsun (veya --visible varsa)
    if args.visible or (not args.headless):
        if args.visible:
             print("[*] Live View (Visible Browser) Modu Etkinleştirildi.")
        # Config'deki her yere işle (Görünür yap)
        cfg.setdefault("crawler", {})["headless"] = False
        cfg.setdefault("crawl", {})["headless"] = False
        if "webdriver" not in cfg: cfg["webdriver"] = {}
        cfg["webdriver"]["headless"] = False
        if "settings" not in cfg: cfg["settings"] = {}
        if "webdriver" not in cfg["settings"]: cfg["settings"]["webdriver"] = {}
        cfg["settings"]["webdriver"]["headless"] = False

    off = (cfg.setdefault('offensive', {}) if isinstance(cfg, dict) else {})
    if args.attack or args.attack_unsafe or (off.get('enabled') is True):
        off['enabled'] = True
        off.setdefault('safe', True)
        if args.attack_unsafe:
            off['safe'] = False
    if args.verify_only:
        off['enabled'] = True
        off['verify'] = {'enabled': True}
    # OAST ayarları
    if args.oast_domain or args.oast_url:
        oast = cfg.setdefault('oast', {})
        if args.oast_domain:
            oast['dns_domain'] = args.oast_domain
        if args.oast_url:
            oast['http_base'] = args.oast_url

    if args.fuzz_ml:
        cfg.setdefault('fuzz', {}).setdefault('heuristics', {})
        cfg['fuzz']['heuristics']['enabled'] = True

    if args.waf:
        cfg.setdefault('waf', {})
        cfg['waf']['enabled'] = True

    def _readline_default(prompt: str, default: str) -> str:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        si = getattr(sys, "stdin", None)
        # TTY olmasa da oku
        if si is not None and hasattr(si, "readline"):
            line = si.readline()
            if isinstance(line, str):
                line = line.rstrip("\r\n")
            if line:
                return line.strip()
        return default

    def _detect_final_url_and_scheme_safe(raw: str, timeout_s: float = 6.0) -> tuple[str | None, str | None]:
        if not isinstance(raw, str) or not raw.strip():
            return None, None

        t = raw.strip()
        if "://" in t:
            candidates = [t]
        else:
            host = t.strip("/")
            candidates = [
                f"https://{host}",
                f"https://www.{host}",
                f"http://{host}",
                f"http://www.{host}",
            ]

        curl_bin = shutil.which("curl")
        if not curl_bin:
            # curl yoksa, ilk adayı normalize edip dön (erişilebilirlik doğrulaması yapmadan)
            u0 = candidates[0]
            sch = urlparse(u0).scheme or "http"
            return u0, sch

        for u in candidates:
            # -I başlık isteği, -L yönlendirme, --max-time süre, -sS sessiz, -o /dev/null gövdeyi at
            cp = subprocess.run(
                [curl_bin, "-I", "-L", "-sS", "--max-time", str(float(timeout_s)), u, "-w",
                 "%{url_effective} %{http_code}\n", "-o", "/dev/null"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if cp.returncode != 0:
                continue
            out = (cp.stdout or "").strip()
            if not out:
                continue
            parts = out.split()
            if len(parts) >= 2 and parts[-1].isdigit():
                code = int(parts[-1])
                final = " ".join(parts[:-1])
                if 200 <= code < 600:
                    eff = final.split("#", 1)[0].rstrip("/")
                    sch = urlparse(eff).scheme or "http"
                    return eff, sch
        return None, None

    # ---------------- snippet replacement (istisnasız) ----------------

    if args.target:
        raw_input_url = args.target.strip()
    else:
        try:
            raw_input_url = input("Hedef (domain veya URL) gir: ").strip()
        except EOFError:
            raw_input_url = ""
        raw_input_url = (raw_input_url if isinstance(raw_input_url, str) else "").strip() or str(
            cfg.get("base_url") or "")

    # Keşif için geçici session (config'ten bağımsız, sadece ulaşılabilirliği bulmak için)
    temp_session = ensure_session({})
    temp_session.verify = True

    final_url, scheme = _detect_final_url_and_scheme_robust(raw_input_url, timeout_s=6.0)
    if final_url:
        ok, valid_url, scheme_checked = validate_url(final_url)
    else:
        ok, valid_url, scheme_checked = (False, None, None)

    if ok and valid_url:
        url = valid_url
        scheme = scheme_checked or scheme or "https"
    else:
        if final_url:
            print("[WARN] validate_url başarısız; normalize edilmiş URL ile devam ediliyor.")
            url = final_url
            scheme = scheme or "https"
        else:
            print(f"[HATA] URL çözümlenemedi; http ile devam deneniyor. Girdi: {raw_input_url!r}")
            _close = getattr(temp_session, "close", None)
            if callable(_close):
                _close()
            # Fallback: şema yoksa http ile deneriz, varsa olduğu gibi bırakırız
            host = (raw_input_url or "").strip()
            if "://" not in host and host:
                url = "http://" + host
            else:
                url = host or "http://localhost"
            scheme = ("http" if url.lower().startswith("http://") else
                      "https" if url.lower().startswith("https://") else
                      (url.split(':', 1)[0].lower() if ':' in url else "http"))

    # >>> RUN-TIME OVERRIDE: Kullanıcıdan gelen (kanonik/valid edilmiş) URL'i config'e uygula
    cfg["target"] = url
    cfg["base_url"] = url
    # <<< OVERRIDE

    print(f"[URL] Kanonik erişim: {url}  (Mod: {scheme.upper()})")

    _close = getattr(temp_session, "close", None)
    if callable(_close):
        _close()

    # --- Tor (SOCKS) Seçimi ---
    if not args.dry_run and not args.batch:
        print("Tor (SOCKS) kullanılsın mı? (E/h)")
        use_tor = (input("> ").strip().lower() or "h")
    else:
        use_tor = "h"
        if args.dry_run:
            print("[Dry-Run] Tor sorusu atlandı (varsayılan: hayır).")
        # Batch modunda sessiz geç
    if use_tor.startswith("e"):
        host = (input("SOCKS host [127.0.0.1]: ").strip() or "127.0.0.1")
        port = (input("SOCKS port [9150]: ").strip() or "9150")
        scheme = "socks5h"  # DNS de tünelden geçsin
        socks_url = f"{scheme}://{host}:{port}"
        http_cfg = cfg.setdefault("http", {})
        _cur = http_cfg.get("proxies")
        if isinstance(_cur, dict):
            proxies = _cur
        else:
            proxies = {}
            http_cfg["proxies"] = proxies
        # Liveness check (connect_ex)
        if _proxy_alive(socks_url):
            proxies["http"] = socks_url
            proxies["https"] = socks_url
            # Egress sağlık kontrolüne Tor kontrol uç noktasını öne ekle
            privacy = cfg.setdefault("privacy", {})
            egress = privacy.setdefault("egress", {})
            endpoints = egress.setdefault("ip_echo_endpoints", [])
            if "https://check.torproject.org/api/ip" not in endpoints:
                endpoints.insert(0, "https://check.torproject.org/api/ip")
            print(f"[TOR] Proxy etkin: {socks_url}")
        else:
            print(f"[TOR] Uyarı: {host}:{port} erişilemiyor, proxy uygulanmadı.")
    else:
        print("[Egress] Tor devre dışı.")


    _read = globals().get("_readline_default")
    if not callable(_read):

        def _read(prompt: str, default: str) -> str:
            try:
                val = input(prompt)
                s = (val if isinstance(val, str) else "").strip()
                return s if s != "" else default
            except EOFError:
                return default

    print("")
    if not args.dry_run and not args.batch:
        print("Kimlikli tarama (oturum/cookie/token ile) yapmak ister misiniz? (E/h)")
        ans = (_read("> ", "h") or "h").strip().lower()
    else:
        ans = "h"
        if args.dry_run:
            print("[Dry-Run] Kimlik sorusu atlandı (varsayılan: hayır).")

    if ans.startswith("e"):
        cfg.setdefault("auth", {}).update({"enabled": True})
        print("")
        print("Yöntem seçin:")
        print("  [1] Cookie (ör. sessionid=...; diğerleri noktalı virgülle)")
        print("  [2] Bearer Token (sadece değer, 'Bearer' yazmayın)")
        print("  [3] API Key (Header adı + anahtar)")
        print("  [4] Form Login (login URL + kullanıcı + parola)")
        sel = (_read("Seçim (1-4): ", "0") or "0").strip()
        m = int(sel) if sel.isdigit() else 0

        if m == 1:
            raw = _read("Cookie girin (ör. sessionid=abc123; csrftoken=xyz): ", "").strip()
            cookies = {}
            for part in raw.split(";"):
                part = part.strip()
                if not part or "=" not in part:
                    continue
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
            cfg["auth"]["cookie"] = cookies
            cfg["mode"] = "authenticated"
        elif m == 2:
            tok = _read("Bearer token değerini girin: ", "").strip()
            cfg["auth"]["bearer"] = tok
            cfg["mode"] = "authenticated"
        elif m == 3:
            hdr = (_read("API Key header adı (örn: X-API-Key): ", "X-API-Key") or "X-API-Key").strip()
            key = _read("API key değeri: ", "").strip()
            cfg["auth"]["api_key_header"] = hdr
            cfg["auth"]["api_key"] = key
            cfg["mode"] = "authenticated"
        elif m == 4:
            lu = _read("Login URL: ", "").strip()
            un = _read("Kullanıcı adı/E-posta: ", "").strip()
            pw = _read("Parola: ", "").strip()
            cfg["auth"].update({
                "login_url": lu,
                "username_field": cfg.get("auth", {}).get("username_field", "username"),
                "password_field": cfg.get("auth", {}).get("password_field", "password"),
                "creds": {"username": un, "password": pw},
                "enabled": True
            })
            cfg["mode"] = "authenticated"
        else:
            print("[i] Geçersiz seçim; kimliksiz taramaya geçiliyor.")
            cfg["mode"] = "unauthenticated"
            cfg.setdefault("kimliksiz_mod", {}).setdefault("idempotent_only", True)
            cfg["kimliksiz_mod"].setdefault("priming", {})["enabled"] = True
    else:
        # Kimliksiz tarama
        cfg["mode"] = "unauthenticated"
        cfg.setdefault("kimliksiz_mod", {}).setdefault("idempotent_only", True)
        cfg["kimliksiz_mod"].setdefault("priming", {})["enabled"] = True

    # Opsiyonel: kurumsal proxy/VPN gibi bir çıkış kullanmak ister misiniz?
    # Proxy tercihi (istisnasız)
    _read = globals().get("_readline_default") or globals().get("_read")
    if not callable(_read):
        def _read(prompt: str, default: str) -> str:
            try:
                val = input(prompt)
                s = (val if isinstance(val, str) else "").strip()
                return s if s != "" else default
            except EOFError:
                return default
    if not args.dry_run and not args.batch:
        use_proxy = (_read("Çıkış trafiği için bir HTTPS proxy kullanmak ister misiniz? (E/h): ",
                           "h") or "h").strip().lower()
    else:
        use_proxy = "h"
        if args.dry_run:
            print("[Dry-Run] Proxy sorusu atlandı (varsayılan: hayır).")
    if use_proxy.startswith("e"):
        purl = (_read("Proxy URL (örn: http://127.0.0.1:8080 veya http://user:pass@host:port): ", "").strip())
        http_cfg = cfg.setdefault("http", {})
        proxies = http_cfg.setdefault("proxies", {})
        if purl:
            proxies["http"] = purl
            proxies["https"] = purl
            print("[i] Proxy ayarlandı.")


    if not args.dry_run and not args.batch and not args.profile:
        profile, cfg = _offer_scan_profile_and_confirm(cfg)
    else:
        # Öncelik: CLI --profile > Config > Varsayılan Deep
        profile = args.profile or (cfg.get("settings") or {}).get("scan_profile") or "deep"
        # Profil ayarlarına göre config güncelle (normalde _offer... fonksiyonu bunu yapar)
        # Burada basitçe profili set ediyoruz, detaylı config ayarı için _apply_profile benzeri bir mantık gerekebilir
        # Ancak mevcut yapıda profili settings'e yazmak yeterli olabilir, runner bunu okuyup karar veriyorsa.
        # Bir kontrol yapalım: _offer_scan_profile_and_confirm fonksiyonu cfg'yi güncelliyor mu?
        # Fonksiyonu çağırmadığımız için manuel güncelleme yapmamız gerekebilir.
        # Basitlik adına settings'e yazalım.
        cfg.setdefault("settings", {})["scan_profile"] = profile

        if args.dry_run:
            print(f"[Dry-Run] Profil seçimi atlandı (seçilen: {profile}).")
        elif args.batch:
            print(f"[Batch] Profil otomatik seçildi: {profile}")

    # [Fix] Force Aggressive if attack mode is requested via CLI
    if args.attack or args.attack_unsafe:
        if profile not in ("aggressive", "deep"):
            print(f"[WARN] Saldırı modu seçildi ancak profil '{profile}'. 'AGGRESSIVE' olarak zorlanıyor.")
            profile = "aggressive"
            # Re-fetch profile config
            _profiles = (cfg.get("settings") or {}).get("profiles") or {}
            cfg["_resolved_profile"] = _profiles.get("aggressive", {})
            cfg["settings"]["scan_profile"] = "aggressive"

    mode = _choose_mode_from_config(cfg)
    detailed = (mode == ScanMode.DETAILED) or bool((cfg.get("settings") or {}).get("detailed", False))
    print(f"[MOD] {mode.upper()}  |  Detay: {'EVET' if detailed else 'HAYIR'}  |  Profil: {profile.upper()}")
    print(f"[DEBUG] Active Config Profile: {cfg.get('settings', {}).get('scan_profile')} (Resolved: {bool(cfg.get('_resolved_profile'))})")


    debug = str((cfg.get("settings") or {}).get("logging", {}).get("level", "")).upper() == "DEBUG"
    logger = setup_logging(level='DEBUG' if debug else 'INFO')


    driver = None
    if True:  # FIX: block alignment; always run pipeline
        _wd_c = _normalize_webdriver_cfg(cfg)
        driver = setup_webdriver(headless=_wd_c["webdriver"]["headless"])
        if not driver:
            print("[i] WebDriver açılamadı; dinamik gezinme olmadan devam edilecek.")

        session = _setup_session_from_config(cfg)
        # --- Ön tanımlar: daha sonra kullanılan bağlamlar (lint/akış güvenliği) ---
        auth_ctx = _build_auth_ctx(session, cfg) if (mode == ScanMode.AUTHENTICATED) else None
        oast_cfg = (cfg.get('oast') or {})
        _enforce_egress_policy(cfg)
        _egress_health_check(session, cfg, results)

        if callable(globals().get("prime_session")):
            _ = prime_session(session, url, cfg, logger=logger)

        _install = globals().get("install_auth_retry_adapter")
        if callable(_install):
            _install(session, cfg)

        results.setdefault("phase_timings", {})

        meta = results.setdefault("meta", {})
        ci = current_identity(cfg)
        meta["egress"] = ci if isinstance(ci, (dict, list, str)) else str(ci)

        meta["scan_profile"] = profile
        if callable(globals().get("add_result")):
            add_result("meta", {"scan_profile": profile})

        auth_ok = False
        _run_auth_flow = globals().get("run_auth_flow")
        if callable(_run_auth_flow):
            auth_ok = bool(_run_auth_flow(session, cfg, driver=driver, base_url=url, debug=debug))

        def _auth_is_configured(_cfg: dict) -> bool:
            a = (_cfg.get('auth') or {}) if isinstance(_cfg, dict) else {}
            if a.get('bearer') or a.get('bearer_token') or a.get('token'):
                return True
            if a.get('api_key_header') and a.get('api_key'):
                return True
            if a.get('headers'):
                return True
            if a.get('cookie') or a.get('cookies'):
                return True
            if a.get('login_url') and (a.get('creds') or {}).get('username') and (a.get('creds') or {}).get('password'):
                return True
            return False

        _auth_node = (cfg.get('auth') or {}) if isinstance(cfg, dict) else {}
        if _auth_node.get('enabled') and _auth_node.get('strict_required'):
            if _auth_is_configured(cfg) and not auth_ok:
                raise RuntimeError(
                    'Kimlikli tarama başarısız (strict_required). Kimlik bilgileri var ama login kalıcı olmadı.')
            if not _auth_is_configured(cfg):
                raise RuntimeError(
                    'strict_required=true fakat kullanılabilir kimlik yöntemi yapılandırılmamış (bearer/api_key/cookie veya login_url+creds eksik).')


        # [Defensive] Ensure url is defined (e.g. if curl failed or logic skipped)
        if 'url' not in locals() or url is None:
            print("[WARN] 'url' variable resolved to None. Recovering from args...")
            url = (args.target or "").strip()
            if not url and isinstance(cfg, dict):
                 url = str(cfg.get("target") or "")
            if not url:
                 url = "http://localhost"
            scheme = "https" if url.startswith("https") else "http"

        def _build_ctx():
            required = {"url", "scheme", "config", "driver", "session", "results", "detailed", "save_report", "debug",
                        "logger"}
            if callable(ScanContext):
                sig = inspect.signature(ScanContext)  # Python sınıfıysa bu güvenli; C-extension değilse istisna atmaz
                params = set(sig.parameters.keys())
                if required.issubset(params):
                    return ScanContext(
                        url=url, scheme=scheme, config=cfg, driver=driver,
                        session=session, results=results, detailed=detailed,
                        save_report=True, debug=debug, logger=logger
                    )

            class _Ctx:
                __slots__ = (
                    "url", "scheme", "config", "driver", "session", "results", "detailed", "save_report", "debug",
                    "logger", "base_plan")

                @property
                def endpoints(self):
                    return self.results.get("endpoints", [])

                def get(self, key, default=None):
                    if hasattr(self, key):
                        return getattr(self, key)
                    if isinstance(self.config, dict):
                        return self.config.get(key, default)
                    return default


            ctx = _Ctx()
            ctx.url, ctx.scheme, ctx.config, ctx.driver = url, scheme, cfg, driver
            
            ctx.session, ctx.results, ctx.detailed = session, results, detailed
            ctx.save_report, ctx.debug, ctx.logger = True, debug, logger
            
            # [WS3] Inject manual phases for correct reporting
            manual_plan = [
                {"id": "discovery", "title": "Keşif", "enabled": True, "visible": True},
                {"id": "portscan", "title": "Port Taraması", "enabled": True, "visible": True},
                {"id": "tls", "title": "TLS Analizi", "enabled": True, "visible": True},
                {"id": "headers", "title": "Güvenlik Başlıkları", "enabled": True, "visible": True},
                {"id": "crawl", "title": "Gezinme (Crawl)", "enabled": True, "visible": True},
            ]
            
            # [WS3] INJECT FIX: Do NOT set base_plan manually. 
            # phases.py provides a complete default plan with functioning runners.
            # Setting manual_plan without runners caused Discovery to be skipped.
            # try:
            #     ctx.base_plan = manual_plan
            # except Exception:
            #     pass

            if callable(build_plan):
                # Get the plan (which might be just offensive if base_plan failed)
                raw_plan = build_plan(ctx)
                
                # [WS3] ANTI-GHOST PROTOCOL: Never allow empty plan
                if not raw_plan:
                    print("\n[!] UYARI: Otomatik plan oluşturulamadı, acil plan devreye giriyor...")
                    from websecure.core.phases import (
                        phase_waf_detect,
                        phase_discovery,
                        phase_portscan,
                        run_reporting_and_integration,
                    )
                    raw_plan = [
                        {"id": "waf_detect",  "title": "WAF Tespiti",    "runner": phase_waf_detect,              "enabled": True},
                        {"id": "discovery",   "title": "Keşif",          "runner": phase_discovery,               "enabled": True},
                        {"id": "port_scan",   "title": "Port Taraması",  "runner": phase_portscan,                "enabled": True},
                        {"id": "reporting",   "title": "Raporlama",      "runner": run_reporting_and_integration, "enabled": True},
                    ]

                # Merge manually if needed
                plan_map = {p["id"]: p for p in manual_plan}
                for p in raw_plan:
                    plan_map[p["id"]] = p
                
                results["phase_plan"] = list(plan_map.values())
            else:
                 results["phase_plan"] = manual_plan
            
            return ctx

        ctx = _build_ctx()

        # [WS3] SAFETY CHECK: Localhost Warning
        _turl = (url or "").lower()
        if "localhost" in _turl or "127.0.0.1" in _turl:
            print("\n" + "!"*60)
            print(" [DİKKAT] HEDEF LOCALHOST (KENDİ BİLGİSAYARINIZ)")
            print(" Bu tarama güvenlidir çünkü sadece çalışan servise istek atar.")
            print(" DOSYA SİSTEMİNİZE VEYA DİĞER PROGRAMLARA ZARAR VERMEZ.")
            print("!"*60 + "\n")

        if callable(globals().get("_session_priming")):
            _session_priming(session, url, cfg)

        # [WS3] ROBUST AUTHENTICATION & SESSION CAPTURE
        def _on_auth_event(evt: str, data: dict):
            if not data.get("ok", True) and "final" not in evt: return
            
            if evt == "auth.webdriver_login" and data.get("ok"):
                print("\n" + "="*65)
                print(" [KILL CAM] SESSION CAPTURED (BROWSER) ")
                print("="*65)
                print(f" [+] Strategy: WebDriver Injection")
                print(f" [+] Origin:   {url}")
                print(f" [+] Cookies:  Synced to Session")
                print("="*65 + "\n")
            elif evt == "auth.requests_login" and data.get("ok"):
                print("\n" + "="*65)
                print(" [KILL CAM] SESSION CAPTURED (API) ")
                print("="*65)
                print(f" [+] Strategy: API/Form Login")
                print(f" [+] Status:   Authorized")
                print("="*65 + "\n")
            elif evt == "auth.final":
                 if data.get("authenticated"):
                     print(f"[+] Auth Flow Complete: Authenticated = TRUE")
                 else:
                     pass # Silent failure to allow fallback

        # Invoke Smart Login with Event Callback
        if callable(smart_login):
            print("[*] Akıllı Oturum Yönetimi başlatılıyor (Smart Auth)...")
            smart_login(session, cfg, driver=driver, base_url=url, debug=debug, event_cb=_on_auth_event)


        # [WS3] SESSION HUNTER (User Code #1 Integration)
        # If Profile is Aggressive or user demands deep check, try hijacking/prediction
        # Check if auth failed OR if we just want to test robustness
        _prof = (cfg.get("settings") or {}).get("scan_profile")
        if _prof in ["aggressive", "safe_full"]: 
             # Import locally to avoid circle if TopLevel
             try:
                 from websecure.scanners.session_hunter import run_session_hunter
                 print("\n[*] Session Hunter Başlatılıyor (Tahmin & Brute Force)...")
                 hunter_res = run_session_hunter(url, session, threads=20) # 20 threads safe default
                 if hunter_res:
                     print(f"[!] DİKKAT: {len(hunter_res)} adet zayıf/tahmin edilebilir oturum bulundu!")
                     # Add to results?
                     if callable(globals().get("add_result")):
                         add_result("auth_weakness", {"hunter_findings": hunter_res})
             except ImportError:
                 print("[!] Session Hunter modülü yüklenemedi.")
             except Exception as e:
                 print(f"[!] Session Hunter hatası: {e}")

        _auth = (cfg.get('auth') or {}) if isinstance(cfg, dict) else {}
        _auto = (_auth.get('auto_signup') or {}) if isinstance(_auth, dict) else {}
        _assi = (_auth.get('assisted') or {}) if isinstance(_auth, dict) else {}

        if bool(_auto.get('enabled')) and callable(globals().get("run_auto_signup")):
            if run_auto_signup(session, cfg):
                print('[Auth] Auto-Signup başarılı.')
        if bool(_assi.get('enabled')) and callable(globals().get("run_device_code_flow")):
            if run_device_code_flow(session, cfg):
                print('[Auth] Device Code ile token alındı.')

        def mark(phase_name, start_t=None):
            if 'phase_timings' not in results or not isinstance(results.get('phase_timings'), dict):
                results['phase_timings'] = {}
            if start_t is None:
                return time.time()
            results["phase_timings"][phase_name] = round(time.time() - start_t, 2)

        if mode == ScanMode.AUTHENTICATED:
            print("[*] Kimlikli tarama başlatılıyor…")
            snap = dict(results)
            run_mode(ctx, ScanMode.AUTHENTICATED)
            meta = ctx.results.get("meta", {})
            auth_failed = (ctx.results == snap) or meta.get("auth_fallback") or meta.get("auth_error")
            if auth_failed:
                print("[!] Kimlikli tarama başarısız/atlandı; standart taramaya düşülüyor.")
        else:
            print("[*] Standart tarama başlatılıyor…")

        # [FIX] Legacy manual block replaced with Unified Plan Runner to ensure all
        # configured scanners (SSRF, NoSQLi, JWT, etc.) are executed.
        if callable(run_plan_if_needed):
            print("[*] Gelismis tarama plani calistiriliyor (Unified Framework)...")
            run_plan_if_needed(ctx)
        else:
            print("[!] CRITICAL: run_plan_if_needed fonksiyonu bulunamadi, manuel yedek calistiriliyor...")
            # Fallback: phases.py:phase_portscan() doğrudan çağrılır
            print("[•] Port taraması (TCP)…")
            t = mark("ports")
            try:
                from websecure.core.phases import phase_portscan as _pp
                _pp(ctx)
            except Exception as _pe:
                print(f"[PortScan] Fallback hata: {_pe}")
            mark("ports", t)
            
            discovery_enrich(url, results, open_ports=results.get("open_ports"), detailed=detailed, debug=debug)
            
            # ... (minified fallback)
            if callable(globals().get("run_owasp_and_nuclei")):
                 _safe_call(run_owasp_and_nuclei, url, results, session, config=cfg, debug=debug, auth_ctx=None, call_timeout=900.0)


        # --- Coverage / Keşif Özeti ---
        crawled_pages = _as_int(((results.get("crawl_summary") or {}).get("pages") or 0), 0)
        cd_count = _as_int(results.pop("_content_discovery_count", 0) or 0, 0)
        total_endpoints = len(set(results.get("endpoints", []) or []))
        cov = {
            "crawled_pages": crawled_pages,
            "crawl_endpoints": _as_int(((results.get("crawl_summary") or {}).get("endpoints") or total_endpoints),
                                       total_endpoints),
            "content_discovery_endpoints": cd_count,
            "total_unique_endpoints": total_endpoints,
        }
        results["coverage_summary"] = cov
        if callable(globals().get("add_result")):
            add_result("coverage_summary", cov)

        endpoints = list(results.get("endpoints", [])) or [url]
        crawled_pf_items = [{"url": u, "method": "GET", "params": {"query": {}, "body": {}, "json": {}}} for u in
                            endpoints]
        discovered = discover_params_from_crawl(crawled_pf_items) if callable(
            globals().get("discover_params_from_crawl")) else {"query": [], "body": [], "json": []}

        def _normalize_discovered(x):
            keys = ("query", "body", "json", "headers", "cookies", "path")
            out = {k: [] for k in keys}
            if isinstance(x, dict):
                for k in keys:
                    v = x.get(k, [])
                    if isinstance(v, (list, tuple)):
                        out[k] = list(v)
                    elif isinstance(v, set):
                        out[k] = list(v)
                    elif v is None:
                        out[k] = []
                    else:
                        out[k] = [v]
                return out
            if isinstance(x, (set, list, tuple)):
                out["query"] = list(x)
                return out
            return out

        discovered_map = _normalize_discovered(discovered)
        discovered = discovered_map
        extra_names = set()
        if callable(globals().get("guess_additional_params")):
            extra_names = set(guess_additional_params(discovered_map, extra_words=list(
                ((cfg.get("fuzz") or {}).get("extra_words") or []))))

        _names = []
        for _k in ("query", "body", "json", "headers", "cookies", "path"):
            _v = discovered_map.get(_k, []) if isinstance(discovered_map, dict) else []
            if isinstance(_v, (list, tuple, set)):
                _names.extend(list(_v))
        discovered_names_for_fuzz = set(str(x) for x in _names) | set(extra_names)
        fuzz_cfg = (cfg.get("fuzz") or {})
        fuzz_limits = {
            "per_param": _as_int(fuzz_cfg.get("per_param", 6), 6),
            "max_total": _as_int(fuzz_cfg.get("max_total", 250), 250),
            "rate_ms": _as_int(fuzz_cfg.get("rate_ms", 0), 0),
            "stop_on_high": bool(fuzz_cfg.get("stop_on_high", False)),
            "backoff_factor": float((fuzz_cfg.get("rate_limit") or {}).get("backoff_factor", 2.0)) if isinstance(
                fuzz_cfg.get("rate_limit"), dict) else 2.0,
            "max_rate_ms": _as_int((fuzz_cfg.get("rate_limit") or {}).get("max_rate_ms", 2000), 2000) if isinstance(
                fuzz_cfg.get("rate_limit"), dict) else 2000,
            "max_consecutive_429": _as_int((fuzz_cfg.get("rate_limit") or {}).get("max_consecutive_429", 6),
                                           6) if isinstance(fuzz_cfg.get("rate_limit"), dict) else 6,
            "jitter_ms": _as_int((fuzz_cfg.get("rate_limit") or {}).get("jitter_ms", 0), 0) if isinstance(
                fuzz_cfg.get("rate_limit"), dict) else 0,
            "proxy": (current_identity(cfg).get("proxy_url") if callable(
                globals().get("current_identity")) and current_identity(cfg) else None),
        }

        crawl_cfg = (cfg.get("crawler") or {}) if isinstance(cfg, dict) else {}

        # Static crawler via WebCrawler if available
        if 'WebCrawler' in globals() and callable(globals().get("WebCrawler")) and callable(
                globals().get("CrawlerConfig")):
            wc = WebCrawler(
                session,
                url,
                driver=driver,
                config=CrawlerConfig(
                    max_depth=_as_int(crawl_cfg.get("max_depth", 4), 4),
                    max_pages=_as_int(crawl_cfg.get("max_pages", 1000), 1000),
                    timeout_http=_as_int(crawl_cfg.get("timeout_http", 12), 12),
                    strict_same_origin=bool(crawl_cfg.get("strict_same_origin", True)),
                    ignore_robots=bool(crawl_cfg.get("ignore_robots", False)),
                ),
                debug=debug,
            )
            ok_wc, cout = _safe_call(wc.start, call_timeout=600.0)
            if ok_wc and isinstance(cout, dict):
                new_eps = list(set((cout.get("endpoints") or [])))
                endpoints.extend([u for u in new_eps if u not in endpoints])
                if callable(globals().get("add_result")):
                    add_result("crawl", {"static": {"new": len(new_eps)}})
            elif not ok_wc and callable(globals().get("add_result")):
                add_result("errors", {"stage": "crawl_static", "error": str(cout)})


        if bool(crawl_cfg.get("browser_js_discovery", True)) and callable(globals().get("discover_dynamic_endpoints")):
            ok_dyn, res = _safe_call(
                discover_dynamic_endpoints,
                url,
                headless=bool(crawl_cfg.get("headless", True)),
                timeout_ms=_as_int(crawl_cfg.get("browser_timeout_ms", 15000), 15000),
                max_pages=_as_int(crawl_cfg.get("browser_max_pages", 200), 200),
                record_dir=crawl_cfg.get("record_dir"),
                prefer=str(crawl_cfg.get("browser_prefer", "playwright")),
                return_artifacts=True,
                call_timeout=900.0,
            )
            if ok_dyn:
                eps, artifacts = (res or ([], []))
                if eps:
                    new_eps = [e.get("url") if isinstance(e, dict) else e for e in (eps or [])]
                    new_eps = [u for u in new_eps if isinstance(u, str)]
                    endpoints.extend([u for u in new_eps if u not in endpoints])
                    if callable(globals().get("add_result")):
                        add_result("crawl", {"browser": {"new": len(new_eps)}})
                if artifacts and callable(globals().get("add_result")):
                    add_result("artifacts", {"browser": artifacts})
            else:
                if callable(globals().get("add_result")):
                    add_result("errors", {"stage": "crawl_browser", "error": str(res)})

                    print("[•] SSRF/XXE sezgisel kontroller…")
                    t = mark("ssrf_xxe")
                    if callable(globals().get("ssrf_xxe_scan")):
                        kw = dict(session=session, endpoints=endpoints[:40], oast_cfg=oast_cfg, results=results,
                                  debug=debug,
                                  auth_ctx=auth_ctx)
                        # imza uyumu için anahtar adlarını fonskiyon imzasına göre filtrele
                        fk = _kw_filter(ssrf_xxe_scan, **kw)
                        # bazı sürümlerde 'endpoints' yerine yalnızca pozisyonel kullanılıyor olabilir:
                        if not fk:
                            # minimum pozisyonel: (session, endpoints, oast_cfg, results)
                            ok_ssrf, res_ssrf = _safe_call(ssrf_xxe_scan, session, endpoints[:40], oast_cfg, results,
                                                           call_timeout=900.0)
                        else:
                            ok_ssrf, res_ssrf = _safe_call(ssrf_xxe_scan, **fk, call_timeout=900.0)
                        if not ok_ssrf and callable(globals().get("add_result")):
                            add_result("errors", {"stage": "ssrf_xxe", "error": str(res_ssrf)})
                    else:
                        if callable(globals().get("add_result")):
                            add_result("errors", {"stage": "ssrf_xxe", "error": "module_missing"})
                    mark("ssrf_xxe", t)

        gql_eps = [u for u in endpoints if isinstance(u, str) and ("/graphql" in u.lower())]
        gql_cfg = (cfg.get("graphql") or {})
        cfg_eps = list(gql_cfg.get("endpoints") or [])
        all_gql_eps = list(dict.fromkeys((gql_eps or []) + cfg_eps))

        if all_gql_eps:
            print("[•] GraphQL RPC testleri…")
            t = mark("graphql")
            _gql_func = globals().get("graphql_scan")
            if callable(_gql_func):
                base_kw = dict(
                    session=session,
                    endpoints=all_gql_eps[:10],
                    results=results,
                    debug=debug,
                    base_url=url,
                    verify=bool(cfg.get('tls_verify', True)),
                    timeout=int((cfg.get('graphql') or {}).get('timeout', 20)),
                )
                fkw = _kw_filter(_gql_func, **base_kw)

                ok_gql, err_or_none = _safe_call(_gql_func, **fkw,
                                                 call_timeout=900.0) if fkw else _safe_call(
                    _gql_func, session, all_gql_eps[:10], results, call_timeout=900.0
                )
                if not ok_gql and callable(globals().get("add_result")):
                    add_result("errors", {"stage": "graphql", "error": str(err_or_none)})
            else:
                if callable(globals().get("add_result")):
                    add_result("errors", {"stage": "graphql", "error": "module_missing"})
            mark("graphql", t)

            if bool(gql_cfg.get("deep", True)):
                print("[•] GraphQL derin saldırı testleri…")
                t = mark("graphql_deep")
                _gql_att_func = globals().get("graphql_attack_scan")
                if callable(_gql_att_func):
                    deep_kw = dict(session=session, endpoints=all_gql_eps[:10], results=results, debug=debug,
                                   config=cfg)
                    fkw = _kw_filter(_gql_att_func, **deep_kw)
                    ok_gqa, err_or_none = _safe_call(_gql_att_func, **fkw,
                                                     call_timeout=900.0) if fkw else _safe_call(
                        _gql_att_func, session, all_gql_eps[:10], results, call_timeout=900.0
                    )
                    if not ok_gqa and callable(globals().get("add_result")):
                        add_result("errors", {"stage": "graphql_deep", "error": str(err_or_none)})
                else:
                    if callable(globals().get("add_result")):
                        add_result("errors", {"stage": "graphql_deep", "error": "module_missing"})
                mark("graphql_deep", t)

        upload_eps = []
        for fm in results.get("forms_meta", []):
            if any(inp.get("type") == "file" for inp in (fm.get("inputs") or [])):
                upload_eps.append(fm.get("action") or fm.get("page"))
        upload_eps = list(dict.fromkeys([u for u in upload_eps if u]))
        # File-Upload
        if upload_eps and callable(globals().get("file_upload_scan")):
            print("[•] Dosya yükleme testleri…")
            t = mark("file_upload")
            ok_fu, err_or_none = _safe_call(
                file_upload_scan,
                session, upload_eps[:15], results,
                debug=debug, base_url=url,
                call_timeout=900.0
            )
            if not ok_fu and callable(globals().get("add_result")):
                add_result("errors", {"stage": "file_upload", "error": str(err_or_none)})
            mark("file_upload", t)

        # [Fix] Fallback: If no endpoints found, force base URL to ensure offensive phase runs
        if not results.get("endpoints"):
            print("[WARN] Keşif başarısız (0 endpoints). Base URL ile saldırı zorlanıyor.")
            results.setdefault("endpoints", []).append(url)

        # Construct Context for flow_runner compatibility
        class Context:
            pass
        ctx = Context()
        ctx.config = cfg
        ctx.session = session
        ctx.results = (locals().get("results") or {}) # Capture local results
        # Sync results from discovery
        if "discovery" not in ctx.results and "discovered" in locals():
             ctx.results["discovery"] = locals().get("discovered")
        ctx.debug = debug
        ctx.target = url  # Use 'url' variable which represents the verified target
        ctx.url = url

        # [Fix] Direct Phase Execution
        # from websecure.core.phases import run_plan_if_needed

        print("[•] Faz planı çalıştırılıyor…")
        t = mark("phase_plan")
        _safe_call(run_plan_if_needed, ctx, call_timeout=None) # No timeout for full plan
        mark("phase_plan", t)

        # 6) OFFENSIVE 3A
        print("[•] Offensive modüller…")
        if results.get("_skip_legacy_offensive"):
            print("    [i] Faz planı etkin: legacy offensive bloğu atlanıyor.")
        else:
            def _profile_allows(key: str) -> bool:
                fn = globals().get("_off_profile_allows")
                return bool(fn(cfg, key)) if callable(fn) else True

            def _run_offensive(fn, **kw):
                if not callable(fn):
                    return
                fkw = _kw_filter(fn, **kw) if callable(globals().get("_kw_filter")) else kw
                ok_off, err_or_none = _safe_call(fn, **fkw, call_timeout=900.0)
                if not ok_off and callable(globals().get("add_result")):
                    add_result("errors",
                               {"stage": "offensive", "error": str(err_or_none),
                                "fn": getattr(fn, "__name__", "unknown")})

            t = mark("offensive")
            off_root = (cfg.get("offensive") or {}) if isinstance(cfg, dict) else {}
            if bool(off_root.get("enabled", False)):
                # Request Smuggling
                if _off_enabled(cfg, "request_smuggling") and _profile_allows("request_smuggling"):
                    _run_offensive(offensive_request_smuggling, url=url, session=session, debug=debug,
                                   auth_ctx=auth_ctx)

                # Mass Assignment
                if _off_enabled(cfg, "mass_assignment") and _profile_allows("mass_assignment"):
                    fields = ((off_root.get("mass_assignment") or {}).get("fields"))
                    _run_offensive(offensive_mass_assignment, url=url, session=session, debug=debug,
                                   fields=fields,
                                   auth_ctx=auth_ctx)

                # JWT
                if _off_enabled(cfg, "jwt_attacks") and _profile_allows("jwt_attacks"):
                    _run_offensive(offensive_jwt, url=url, session=session, debug=debug, auth_ctx=auth_ctx)

                # NoSQLi
                if _off_enabled(cfg, "nosql_injection") and _profile_allows("nosql_injection"):
                    _run_offensive(offensive_nosqli, url=url, session=session, debug=debug, auth_ctx=auth_ctx)

                # WebSocket Fuzz
                if _off_enabled(cfg, "websocket_fuzz") and _profile_allows("websocket_fuzz"):
                    _run_offensive(offensive_ws_fuzz, url=url, session=session, debug=debug, auth_ctx=auth_ctx)

            mark("offensive", t)

        print("[•] Skorlama/Doğrulama (MD)…")
        t = mark("reporting")
        buckets = get_bucket_results()

        all_findings = []
        for _k, _lst in (buckets or {}).items():
            if isinstance(_lst, list):
                for _it in _lst:
                    if isinstance(_it, dict):
                        all_findings.append(_it)

        oast_events = []
        for _it in all_findings:
            evs = _it.get("events")
            if isinstance(evs, list):
                for _ev in evs:
                    if isinstance(_ev, dict):
                        oast_events.append(_ev)

        final = verify_and_score(all_findings, oast_events)

        report_payload = dict(results)
        report_payload.update(get_bucket_results())
        report_payload.update(buckets)
        report_payload.update({
            "meta": {
                "target": url,
                "mode": mode,
                "detailed": detailed,
            },
            "final": final,
            "phase_timings": results.get("phase_timings", {}),
            "crawl_summary": results.get("crawl_summary"),
            "security_headers_summary": results.get("security_headers_summary"),
            "port_scan_summary": results.get("port_scan_summary"),
            "discovery_summary": results.get("discovery_summary"),
            # --- TLS Özet Tablosu 2.5 ---
            "tls_summary": results.get("tls_summary", []),
        })

        out = perform_reporting(session, cfg, report_payload)
        written = (out or {}).get("written", {})
        ok = written.get("md") or written.get("json")

        if driver is not None:
            getattr(driver, 'quit', lambda: None)()
        s = session
        if s is not None:
            getattr(s, 'close', lambda: None)()
        print("\n[i] Tamamlandı.")
        print(
            f"[i] Üretilen dosyalar: {json.dumps(written, ensure_ascii=False)}")  # yazılan dosyalar ve webhook sonucunu içerir

        print("fuzzing başlıyor…")
        t = mark("fuzzing")

        auth_ctx = _build_auth_ctx(session, cfg) if (mode == ScanMode.AUTHENTICATED) else None

        fuzz_fn = fuzz_endpoint if callable(globals().get("fuzz_endpoint")) else None
        sig_params = set(inspect.signature(fuzz_fn).parameters.keys()) if callable(fuzz_fn) else set()

        t_fz = mark("fuzzing")
        for u in endpoints[:50]:  # güvenli üst sınır
            if not callable(fuzz_fn):
                if callable(globals().get("add_result")):
                    add_result("errors", {"stage": "fuzz", "url": u, "error": "fuzz_endpoint_missing"})
                continue

            kwargs = dict(
                session=session,
                target={"url": u, "method": "GET"},
                method="GET",
                base_headers=(fuzz_cfg.get("base_headers") or {}),
                base_cookies=(fuzz_cfg.get("base_cookies") or {}),
                discovered=discovered_names_for_fuzz,
                limits=fuzz_limits,
                report_cb=lambda f: add_result("fuzz", redact_sensitive(f)) if callable(
                    globals().get("add_result")) else None,
                debug=debug,
                heuristics_cfg=(cfg.get('fuzz') or {}).get('heuristics'),
            )
            if "auth_ctx" in sig_params:
                kwargs["auth_ctx"] = auth_ctx

            ok_fz, err_or_none = _safe_call(fuzz_fn, **kwargs, call_timeout=900.0)
            if not ok_fz and callable(globals().get("add_result")):
                add_result("errors", {"stage": "fuzz", "url": u, "error": str(err_or_none)})

        mark("fuzzing", t_fz)

        mark("fuzzing", t_fz)

        # --- Offensive Scans (NoSQLi, SSRF, etc.) ---


        # 1. NoSQL Injection
        _nosqli_fn = getattr(nosqli, "run_nosqli_scan", None) if nosqli else None
        if callable(_nosqli_fn) and (cfg.get("scanners") or {}).get("nosqli"):
            print("[•] NoSQL Enjeksiyon taraması…")
            _safe_call(_nosqli_fn, ctx=ctx)

        # 2. SSRF / XXE
        _ssrf_fn = getattr(_ssrf_mod, "run_ssrf_xxe_scan", None) if _ssrf_mod else None
        if callable(_ssrf_fn) and (cfg.get("scanners") or {}).get("ssrf_xxe"):
            print("[•] SSRF & XXE taraması…")
            _safe_call(_ssrf_fn, ctx=ctx)

        merged_eps = list(set(endpoints + (ctx.results.get("discovery", {}).get("query") or [])))
        # Filter valid URLs
        merged_eps = [u for u in merged_eps if isinstance(u, str) and "://" in u]

        # 3. SQL Injection (New Robust Module)
        # Import dynamically to handle 'shim' modules
        _run_sqli = _opt_import('websecure.scanners.sqli', 'run')
        if callable(_run_sqli) and (cfg.get("scanners") or {}).get("sqli"):
            print(f"[•] SQL Enjeksiyon taraması (Robust) - {len(merged_eps)} hedefe...")
            # Note: sqli.run takes (url, session, debug) where url can be a list
            _safe_call(_run_sqli, merged_eps, session=session, debug=debug)

        # 4. Reflected XSS (New Robust Module)
        _run_xss = _opt_import('websecure.scanners.xss', 'run')
        if callable(_run_xss) and (cfg.get("scanners") or {}).get("xss"):
            print(f"[•] XSS taraması (Reflected) - {len(merged_eps)} hedefe...")
            _safe_call(_run_xss, merged_eps, session=session, debug=debug)


        # 5. CSRF (New Module)
        if csrf and (cfg.get("scanners") or {}).get("csrf"):
             print("[•] CSRF taraması…")
             try:
                 csrf.run_scan(ctx.url, session, results)
             except Exception as e:
                 _logger.error(f"CSRF failed: {e}")

        # 7. Chain Reactor (Correlation)
        if chain_reactor and isinstance(results, dict):
             print("[•] Zincirleme Analizi (Chain Reactor)…")
             try:
                 chain_reactor.analyze_chains(results)
             except Exception as e:
                 _logger.error(f"Chain Reactor failed: {e}")

        # Authorization / IDOR benzerlik kontrolleri (opsiyonel, bastırmasız)
        auth_cfg = (cfg.get("authorization") or {}) if isinstance(cfg, dict) else {}
        if RoleContext and bool(auth_cfg.get("enabled", False)) and callable(
                globals().get("authorization_run")):
            roles_cfg = auth_cfg.get("roles") or [{"name": "user", "headers": {}, "cookies": {}}]
            roles = []
            for rc in roles_cfg:
                roles.append(
                    RoleProfile(name=rc.get("name", "user"), headers=rc.get("headers", {}),
                                cookies=rc.get("cookies", {})))
            rctx = RoleContext(base=session, roles=roles)
            ok_authz, auth_findings = _safe_call(authorization_run, rctx, endpoints[:30], call_timeout=600.0)
            if ok_authz and isinstance(auth_findings, (list, tuple)):
                for f in auth_findings:
                    if callable(globals().get("add_result")):
                        add_result("authorization", f)
            elif not ok_authz and callable(globals().get("add_result")):
                add_result("errors", {"stage": "authorization", "error": str(auth_findings)})

        # Auth-only kaynak işaretleme (kimlikli akış varsa) — bastırmasız
        if callable(globals().get("_build_auth_ctx")) and callable(globals().get("probe_auth_only")):
            if mode == ScanMode.AUTHENTICATED and _build_auth_ctx(session, cfg):
                for u in endpoints[:20]:
                    ok_probe, f = _safe_call(probe_auth_only, session, "GET", u, call_timeout=60.0)
                    if ok_probe and f and callable(globals().get("add_result")):
                        add_result("auth_only", f)
                    elif not ok_probe and callable(globals().get("add_result")):
                        add_result("errors", {"stage": "auth_only_probe", "url": u, "error": str(f)})

        bl_cfg = (cfg.get("business_logic") or {}) if isinstance(cfg, dict) else {}
        if bl_cfg.get("enabled", True):
            print("[•] İş mantığı akış testleri…")
            t = mark("bizlogic_flows")
            if callable(globals().get("run_business_logic_flows")):
                ok_bl, err_or_none = _safe_call(run_business_logic_flows, session, url, cfg, results,
                                                debug=debug,
                                                call_timeout=900.0)
                if not ok_bl and callable(globals().get("add_result")):
                    add_result("errors", {"stage": "bizlogic_flows", "error": str(err_or_none)})
            else:
                if callable(globals().get("add_result")):
                    add_result("errors", {"stage": "bizlogic_flows", "error": "module_missing"})
            mark("bizlogic_flows", t)

            print("[•] Race/Concurrency testleri…")
            t = mark("bizlogic_race")
            if callable(globals().get("run_race_conditions")):
                ok_rc, err_or_none = _safe_call(run_race_conditions, session, url, cfg, results, debug=debug,
                                                call_timeout=900.0)
                if not ok_rc and callable(globals().get("add_result")):
                    add_result("errors", {"stage": "bizlogic_race", "error": str(err_or_none)})
            else:
                if callable(globals().get("add_result")):
                    add_result("errors", {"stage": "bizlogic_race", "error": "module_missing"})
            mark("bizlogic_race", t)


        oast_cfg = (cfg.get("oast") or {})
        if bool(oast_cfg.get("enabled")) and callable(globals().get("OASTClient")) and callable(
                globals().get("run_oast_on_target")):
            print("[•] OAST (out-of-band) testleri…")
            t = mark("oast")
            ok_client, client = _safe_call(OASTClient, session, oast_cfg, call_timeout=30.0)
            if ok_client:
                for u in endpoints[:20]:
                    disc = {"query": discovered.get("query", []), "body": [], "json": [], "headers": [],
                            "cookies": []}
                    limits = {"max_injections_per_loc": int(oast_cfg.get("max_injections_per_loc", 3))}
                    kw = dict(
                        session=session,
                        target={"url": u, "method": "GET"},
                        oast_client=client,
                        discovered=disc,
                        report_cb=(lambda f: add_result("oast", redact_sensitive(f)) if callable(
                            globals().get("add_result")) else None),
                        limits=limits,
                        auth_ctx=auth_ctx,
                    )
                    fkw = _kw_filter(run_oast_on_target, **kw)
                    ok_oast, findings = _safe_call(run_oast_on_target, **fkw, call_timeout=900.0)
                    if ok_oast and findings:
                        for f in findings:
                            if callable(globals().get("add_result")):
                                add_result("oast", redact_sensitive(f))
                    elif not ok_oast and callable(globals().get("add_result")):
                        add_result("errors", {"stage": "oast", "url": u, "error": str(findings)})
            else:
                if callable(globals().get("add_result")):
                    add_result("errors", {"stage": "oast", "error": f"client_init_failed:{client}"})
            mark("oast", t)


def _as_int(x, default: int = 0) -> int:
    if isinstance(x, int):
        return x
    if isinstance(x, float) and x.is_integer():
        return int(x)
    if isinstance(x, str):
        s = x.strip()
        if s.lstrip("+-").isdigit():
            return int(s)
    return default


if __name__ == "__main__":
    # from websecure.core.scan_modes import hpm_bootstrap_from_file
    # hpm_bootstrap_from_file('config.json')

    # [WS3] Interactive Mode (Wizard)
    if len(_sys.argv) < 2:
        try:
            from websecure.core.wizard import run_wizard
            # Run wizard and if it returns True (Run Now selected)
            if run_wizard():
                # We need to simulate CLI args for main() to be happy
                # Load the config we just saved to get the target
                try:
                    import json
                    with open("config.json", "r", encoding="utf-8") as _f:
                        _wiz_cfg = json.load(_f)
                        _wiz_tgt = _wiz_cfg.get("target")
                        if _wiz_tgt:
                            # Inject target into argv so main() parses it
                            _sys.argv.append(_wiz_tgt)
                            print(f"[Wizard] Hedef yüklendi: {_wiz_tgt}")
                            print(f"[Wizard] Otomatik başlatılıyor...")
                            time.sleep(1.5)
                except Exception as _e:
                    print(f"[!] Config okuma hatası: {_e}")
                    _sys.exit(1)
            else:
                # User cancelled or chose not to run immediately
                _sys.exit(0)
        except ImportError:
            pass
            
    # [WS3] External Tool Management
    try:
        from websecure.core.tool_manager import ToolManager
        # Load temporary config just for this decision
        import json
        _tm_cfg = {}
        if os.path.exists("config.json"):
            with open("config.json", "r") as f: _tm_cfg = json.load(f)
            
        tm = ToolManager(_tm_cfg)
        # Only ask if interactive and not configured
        if "--interactive" in sys.argv:
            updates = tm.ask_user_interactive()
            # If changed, we might want to update config, but for now just pass environment?
            # Actually, main() loads config again. 
            pass
            
        # Ensure SQLMap API is started if enabled in config
        if (_tm_cfg.get("offensive", {}).get("sqlmap", {}).get("enabled")) or \
           (_tm_cfg.get("tools", {}).get("sqlmap", {}).get("enabled")):
             tm.start_sqlmap_api()
             
    except Exception as e:
        print(f"[!] Tool Manager Error: {e}")

    # Wordlists sync removed per user request
    try:
        _ret = main()
        if inspect.iscoroutine(_ret):
            asyncio.run(_ret)
    except KeyboardInterrupt:
        print("\n[!] Kullanıcı tarafından iptal edildi (Ctrl+C).")
    except Exception as e:
        print(f"\n[!] Kritik Hata: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Emergency Report Save — works even on Ctrl+C or mid-scan crash
        print("\n[!] Raporlama süreci (Safety Net)...")
        _res = globals().get("results")
        _cfg = globals().get("cfg")
        if _res and _cfg:
            try:
                import websecure.core.reporting as _rep_safe
                # Merge bucket results (findings added during scan) into the payload
                try:
                    from websecure.core.reporting import get_bucket_results
                    _bucket_data = get_bucket_results()
                except Exception:
                    _bucket_data = {}
                _payload = dict(_res)
                if _bucket_data:
                    _payload.update(_bucket_data)
                # "meta" may be a list (from add_result("meta", {...}) calls) — coerce to dict
                _meta = _payload.get("meta")
                if isinstance(_meta, list):
                    _meta_dict: dict = {}
                    for _m in _meta:
                        if isinstance(_m, dict):
                            _meta_dict.update(_m)
                    _meta_dict["interrupted"] = True
                    _payload["meta"] = _meta_dict
                elif isinstance(_meta, dict):
                    _meta["interrupted"] = True
                else:
                    _payload["meta"] = {"interrupted": True}
                _rep_safe.perform_reporting(None, _cfg, _payload)
                print("[+] Raporlar başarıyla kaydedildi.")
            except Exception as _re:
                print(f"[!] Rapor kaydetme hatası: {_re}")
    
    # Success Alert
    try:
        AlertManager.play_success()
    except (AttributeError, OSError, Exception) as exc:
        _logger.debug(f"[main] AlertManager.play_success hatası: {exc!r}")

    # Keep window open

    try:
        input("\n[i] Çıkmak için Enter'a basın...")
    except (EOFError, KeyboardInterrupt):
        pass





