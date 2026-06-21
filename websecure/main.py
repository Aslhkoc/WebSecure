# Bismillahirrahmanirrahim
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
from websecure.core.auth_flow import (
    run_auto_signup, run_device_code_flow, smart_login,
    run_auth_flow, install_auth_retry_adapter,
)
from importlib.util import find_spec as _find_spec
from importlib import import_module as _import_module
# run_business_logic_flows and run_race_conditions are loaded dynamically below (line ~884)
import argparse
import json
import time
import socket
import ssl


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
# Not: configure_logging/perform_reporting/add_result/redact_sensitive/get_bucket_results/
# note_auth_outcome aşağıdaki _reporting_mod bloğunda (getattr + fallback) bağlanır.
# Burada sadece orada yeniden-bağlanmayan verify_and_score import edilir.
from websecure.core.reporting import verify_and_score

# Plan B — Nessus-style response behaviour analysis components
try:
    from websecure.core.tech_fingerprint import TechFingerprinter as _TechFingerprinter
    from websecure.core.endpoint_prioritizer import EndpointPrioritizer as _EndpointPrioritizer
    from websecure.core.fp_reducer import FalsePositiveReducer as _FalsePositiveReducer
    from websecure.core.rate_controller import AdaptiveRateController as _AdaptiveRateController
    from websecure.core.evidence_chain import EvidenceChainBuilder as _EvidenceChainBuilder
    _PLAN_B_AVAILABLE = True
except ImportError:
    _PLAN_B_AVAILABLE = False
    _TechFingerprinter = None
    _EndpointPrioritizer = None
    _FalsePositiveReducer = None
    _AdaptiveRateController = None
    _EvidenceChainBuilder = None


import logging as _logging
from urllib.parse import urlparse, urldefrag, parse_qsl
from time import sleep
import shutil
import subprocess


from pathlib import Path as _P
import importlib as _im
import importlib.util as _iul

# Startup dependency helpers — implementation lives in core/startup.py
from websecure.core.startup import (
    ensure_playwright_chromium as _ensure_playwright_chromium,
    ensure_curl_cffi as _ensure_curl_cffi,
    ensure_nuclei as _ensure_nuclei,
    ensure_interactsh as _ensure_interactsh,
)


from websecure.core.utils import ensure_wordlists as _ensure_wl
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FuturesTimeout
import sys as _sys
import os as _os

_logger = _logging.getLogger(__name__)

_req_mod = _im.import_module('requests') if _iul.find_spec('requests') is not None else None
requests = _req_mod  # alias; may be None

# [WS3] Dynamic Wordlist Report (asıl banner _print_banner() içinde basılır)
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


# [WS3] Offensive Scanner Wrappers — aşağıda (_bind_offensive ile) tanımlanır.
# Buradaki eski wrapper tanımları kaldırıldı: ileride
# offensive_request_smuggling/mass_assignment/jwt/nosqli sembolleri
# _bind_offensive() ile modülün run() fonksiyonuna yeniden bağlanıyordu;
# bu blok ölü koddu (hiç çağrılmadan üzerine yazılıyordu).


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
    except _BOUNDARY_EXC:
        _logger.error('phase error [main]', exc_info=True)
        return None


def _ws_has(*names: str) -> bool:
    return _ws_import_any(*names) is not None


if not globals().get("__package__"):
    _pkg_dir = _os.path.dirname(_os.path.abspath(__file__))
    _parent = _os.path.dirname(_pkg_dir)
    if _parent not in _sys.path:
        _sys.path.insert(0, _parent)
    __package__ = "websecure"
# _load_config kaldırıldı — load_config (core/utils) kullanılıyor


# FAZ-EK: URL normalizasyon -> core/url_utils.py'e taşındı
# noinspection PyProtectedMember
from websecure.core.url_utils import _detect_final_url_and_scheme_robust


def _session_priming(session, base_url, cfg):
    # Kimliksiz mod priming kapalıysa geç
    if not (((cfg or {}).get("kimliksiz_mod") or {}).get("priming") or {}).get("enabled"):
        return

    url = (base_url or "").strip() or "http://localhost"

    u = url if "://" in url else ("http://" + url)

    # Priming EN İYİ-ÇABA bir optimizasyondur: hedefin CSRF token'ını önceden
    # yakalamak içindir. Hedef erişilemezse (Tor yavaş/timeout, DNS, bağlantı
    # reddi, hedefin Tor exit node'larını engellemesi) TÜM taramayı çökertmemeli.
    # Tor üzerinden gecikme yüksek olduğundan timeout'u genişlet.
    _proxies = getattr(session, "proxies", {}) or {}
    _via_tor = "socks" in str(_proxies.get("https") or _proxies.get("http") or "").lower()
    _timeout = 30 if _via_tor else 8

    # Doğrulama kararı merkezî verify_for_phase() ile verilir.
    try:
        r = session.get(u, timeout=_timeout, allow_redirects=True,
                        verify=verify_for_phase(cfg, 'egress', u))
    except Exception as exc:
        _logger.warning(
            f"[Priming] Hedef ön-istek başarısız ({type(exc).__name__}: "
            f"{str(exc)[:140]}) — atlanıyor, tarama devam ediyor."
        )
        if _via_tor:
            _logger.warning(
                "[Priming] İpucu: Tor aktif. Hedef Tor exit node'larını engelliyor "
                "veya çok yavaş olabilir. Tor'suz deneyin ya da timeout'u artırın."
            )
        return

    hdr_token = r.headers.get("x-csrf-token") or r.headers.get("x-xsrf-token")
    if hdr_token:
        session.headers.update({"X-CSRF-Token": hdr_token})


_discover_func = None
_mod = None  # if/elif'lerin ikisi de çalışmazsa _mod tanımlı kalsın (PyCharm undefined uyarısı)

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
    # record_dir/prefer: gerçek (crawler) imzasıyla uyum için var; bu fallback kullanmaz.
    # noinspection PyUnusedLocal
    def discover_dynamic_endpoints(start_url: str,
                                   headless: bool = True,
                                   timeout_ms: int = 15000,
                                   max_pages: int = 200,
                                   record_dir: str | None = None,
                                   prefer: str = "selenium",
                                   return_artifacts: bool = True) -> tuple[list[str], dict]:

        # İç iş: browser işi (istisna atmadan bırakılır, Future.exception ile gözlemlenir)
        def _job() -> tuple[list[str], dict]:
            # WebDriver ayağa kaldır (setup_webdriver modül seviyesinde import edili)

            # [Fix] Respect headless parameter passed from caller (which comes from config)
            drv = setup_webdriver(headless=headless)
            if drv is None:
                return ([], {"reason": "webdriver_unavailable"} if return_artifacts else {})
            # GARANTİ kapanış: aşağıdaki gezinme sırasında (drv.get/execute_script
            # ya da timeout) bir exception olursa happy-path quit atlanır ve Chrome
            # öksüz kalırdı. quit'i finally'ye al → her durumda kapanır.
            try:
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
                        hrefs = drv.execute_script(
                            "return Array.from(document.querySelectorAll('a[href]')).map(a => a.href);")
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
                art = {"visited": len(seen), "found": len(found), "source": "selenium_fallback"} if return_artifacts else {}
                return (found, art)
            finally:
                quit_driver(drv)

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


if _ws_spec("websecure.core.utils") is None:
    raise ImportError("Zorunlu modül 'websecure.core.utils' import edilemiyor")
from websecure.core.utils import (
    current_identity,
    load_config,
    apply_active_profile,
    setup_logging,
    setup_webdriver,
    quit_driver,
    silence_insecure_request_warnings,
    validate_url,
    is_static_asset,
)

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
    # Not: 'prime_session' detect modülünden alınmaya çalışılıyordu ama detect.py yok
    # ve hiçbir yerde tanımlı değil; ölü atama kaldırıldı.
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


# build_plan üstte (satır 34) websecure.core.phases'ten hard-import edildi;
# eski koşullu yeniden-fetch bloğu redundant'tı (kaldırıldı).


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
    # subprocess/shutil modül seviyesinde zaten import edili (üst blok); lokal
    # redundant importlar kaldırıldı.
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
                        "-w", "%{url_effective} %{http_code}\n", "-o", os.devnull]
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
# TLS sertifika/protokol analizi faz planında (phase_tls -> scanners.tls) yapılır.
# Eski main seviyesi check_ssl_certificate wrapper'ı ölü koddu (hiç çağrılmıyordu), kaldırıldı.

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


# --- Plugin / bağımlı modül ön yüklemesi ---
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
_crawl_mod = _im.import_module('websecure.crawler') if _ws_spec('websecure.crawler') is not None else None
if _crawl_mod is None:
    # Fallback: doğrudan import dene (ara _wc değişkeni kaldırıldı)
    try:
        import websecure.crawler as _crawl_mod
    except ImportError:
        print("[!] UYARI: Crawler modülü (websecure.crawler) yüklenemedi!")

WebCrawler = getattr(_crawl_mod, 'WebCrawler', None) if _crawl_mod else None
CrawlerConfig = getattr(_crawl_mod, 'CrawlerConfig', None) if _crawl_mod else None
# crawl_website kaldırıldı: websecure.crawler bu sembolü export etmiyor ve main'de
# hiç çağrılmıyordu (statik crawl WebCrawler.start(), dinamik discover_dynamic_endpoints ile yapılır).

# --- Güvenlik başlıkları ---
# Güvenlik başlıkları faz planında (phase_sec_headers -> scanners.infrastructure) işlenir.
# Eski scan_security_headers binding'i main'de hiç kullanılmıyordu (ölü), kaldırıldı.

# --- GraphQL ---
_gql_mod = _im.import_module('websecure.scanners.graphql') if _ws_spec(
    'websecure.scanners.graphql') is not None else None
_gql_run = getattr(_gql_mod, 'run', None) if _gql_mod else None
# graphql_scan: legacy main-seviyesi GraphQL bloğu (aşağıda ~2160) bu global'i bekliyordu
# ama hiçbir yerde tanımlı değildi (kopuk wiring). scanners.graphql.run(target, ...) tek
# hedef alır; endpoint listesi üzerinde dönen ince bir adaptöre bağlandı.
if callable(_gql_run):
    def graphql_scan(session=None, endpoints=None, results=None, debug=False, **_k):
        for _ep in list(endpoints or [])[:10]:
            if isinstance(_ep, str):
                _gql_run(_ep, session=session, results=results, debug=debug)
        return None
# --- SSRF/XXE ---
_ssrf_mod = _im.import_module('websecure.scanners.ssrf_xxe') if _ws_spec(
    'websecure.scanners.ssrf_xxe') is not None else None
ssrf_xxe_scan = getattr(_ssrf_mod, 'scan', None) if _ssrf_mod else None
if ssrf_xxe_scan is None:
    def ssrf_xxe_scan(*_a, **_k):
        return None

# --- OWASP / Nuclei (yeni entegrasyon) ---
_owasp_mod = None
if _ws_spec("websecure.scanners.owasp") is not None:
    _owasp_mod = _im.import_module("websecure.scanners.owasp")
elif _ws_spec('owasp') is not None:
    _owasp_mod = _im.import_module('owasp')

run_owasp_and_nuclei = getattr(_owasp_mod, 'run_owasp_and_nuclei', None) if _owasp_mod else None
if run_owasp_and_nuclei is None:
    def run_owasp_and_nuclei(*_a, **_k):
        return {}


# FAZ 4.2: _call_scanner_if_available ve _bind_offensive core/scan_runner.py'e taşındı.
# Geriye dönük uyumluluk için buradan re-export edilir.
# noinspection PyProtectedMember
from websecure.core.scan_runner import (
    _call_scanner_if_available,
    _bind_offensive,
)


offensive_request_smuggling = _bind_offensive("websecure.scanners.request_smuggling", "offensive_request_smuggling")
offensive_mass_assignment = _bind_offensive("websecure.scanners.mass_assignment", "offensive_mass_assignment")
offensive_jwt = _bind_offensive("websecure.scanners.jwt", "offensive_jwt")
offensive_nosqli = _bind_offensive("websecure.scanners.nosqli", "offensive_nosqli")
# ws_fuzz modülü varsa run()'a bağla; yoksa ek saldırı taramalarını tetikleyen
# anlamlı bir fallback sağla (if/else: tek bağlama, redefinition yok).
if _ws_spec("websecure.scanners.ws_fuzz") is not None:
    offensive_ws_fuzz = _bind_offensive("websecure.scanners.ws_fuzz", "offensive_ws_fuzz")
else:
    def offensive_ws_fuzz(url, session=None, debug=False, auth_ctx=None):
        _call_scanner_if_available("websecure.scanners.authorization", url,
                                   session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.file_upload", url,
                                   session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.graphql_attacks", url,
                                   session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.ssrf_xxe", url, session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.tls", url, session=session, debug=debug, auth_ctx=auth_ctx)
        _call_scanner_if_available("websecure.scanners.owasp", url, session=session, debug=debug, auth_ctx=auth_ctx)
        return None

# --- Authorization ---
_authz = _im.import_module("websecure.scanners.auth_scanners") if _ws_spec(
    "websecure.scanners.auth_scanners") is not None else None
RoleContext = getattr(_authz, 'RoleContext', None) if _authz else None
RoleProfile = getattr(_authz, 'RoleProfile', None) if _authz else None
# auth_scanners.py top-level 'run' yerine compare_roles() + check_idor() sunar.
# authorization_run, ikisini auth_ctx.build_sessions() çoklu-oturum çıktısı üzerinde
# çağıran bir köprü wrapper'a bağlanır.


# noinspection PyUnusedLocal
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
    def probe_auth_only(*_a, **_k):
        return None

# --- Fuzzing / OAST ---
_pf = _im.import_module("websecure.core.fuzzer") if _ws_spec("websecure.core.fuzzer") is not None else None
discover_params_from_crawl = getattr(_pf, 'discover_params_from_crawl', None) if _pf else None
fuzz_endpoint = getattr(_pf, 'fuzz_endpoint', None) if _pf else None
guess_additional_params = getattr(_pf, 'guess_additional_params', None) if _pf else None

if discover_params_from_crawl is None:
    def discover_params_from_crawl(*_a, **_k):
        return {"query": [], "body": [], "json": []}
if guess_additional_params is None:
    def guess_additional_params(d, *_a, **_k):
        return d
if fuzz_endpoint is None:
    def fuzz_endpoint(*_a, **_k):
        return None

_oast = _im.import_module("websecure.core.oast") if _ws_spec("websecure.core.oast") is not None else None
OASTClient = getattr(_oast, 'OASTClient', None) if _oast else None
run_oast_on_target = getattr(_oast, 'run_oast_on_target', None) if _oast else None

if OASTClient is None:
    class OASTClient:
        def __init__(self, *_a, **_k):
            pass
if run_oast_on_target is None:
    def run_oast_on_target(*_a, **_k):
        return []

# --- Business Logic & Advanced Scanners ---
_flows_mod = _im.import_module("websecure.core.flows") if _ws_spec("websecure.core.flows") is not None else None
run_business_logic_flows = getattr(_flows_mod, "run_business_logic_flows", None) if _flows_mod else None

_bl_mod = _im.import_module("websecure.core.bl_concurrency") if _ws_spec(
    "websecure.core.bl_concurrency") is not None else None
run_race_conditions = getattr(_bl_mod, "run_race_conditions", None) if _bl_mod else None

_gqa_mod = _im.import_module("websecure.scanners.graphql_attacks") if _ws_spec(
    "websecure.scanners.graphql_attacks") is not None else None
graphql_attack_scan = getattr(_gqa_mod, "run", None) if _gqa_mod else None

_fu_mod = _im.import_module("websecure.scanners.file_upload") if _ws_spec(
    "websecure.scanners.file_upload") is not None else None
file_upload_scan = getattr(_fu_mod, "run", None) if _fu_mod else None


# ------------------ Yardımcılar ------------------

# ------------------ Tarama yoğunluğu (Agresif/Normal) teklifi ------------------
# FAZ-EK: Profil seçme/uygulama helpers -> core/scan_profile.py'e taşındı
# noinspection PyProtectedMember
from websecure.core.scan_profile import (
    _offer_scan_profile_and_confirm,
    _choose_mode_from_config,
)


# FAZ-EK: Proxy/session helpers + ensure_session -> core/session_factory.py'e taşındı
# noinspection PyProtectedMember
from websecure.core.session_factory import (
    ensure_session,
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

    positive = {"mevcut", "present", "enabled", "ok", "yes", "true", "var", "on"}

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
                if h == "strict-transport-security" and (st in positive or (isinstance(st_raw, bool) and st_raw)):
                    return True
            elif isinstance(it, (list, tuple)) and len(it) >= 2:
                h = _norm(it[0])
                st_raw = it[1]
                st = _norm(st_raw)
                if h == "strict-transport-security" and (st in positive or (isinstance(st_raw, bool) and st_raw)):
                    return True
        return False

    # Sözlük biçimi: {"Strict-Transport-Security": "Mevcut"/True/...}
    if isinstance(sh, dict):
        val = sh.get("Strict-Transport-Security") or sh.get("strict-transport-security")
        if val is not None:
            st = _norm(val)
            if st in positive or (isinstance(val, bool) and val):
                return True
        # Bazı raporlarda {"header": {"status": ...}} şeklinde olabilir
        node = sh.get("header") if isinstance(sh.get("header"), dict) else None
        if node and _norm(node.get("name")) == "strict-transport-security":
            v = node.get("status")
            return (isinstance(v, bool) and v) or (_norm(v) in positive)
        return False

    return False


# Not: _auth_cov_note ve _public_surface_seeds kaldırıldı — ikisi de hiç çağrılmayan
# ölü yardımcılardı. (Eski _phase_rec köprü bloğu da kaldırıldı: _phase_rec main içinde
# hiç okunmuyordu ve elif dalı 'reporting' kontrol edip yanlışlıkla websecure.core.reporting'i
# import ediyordu — kopuk mantık.)


# --- Parametre imza filtresi yardımcıları — websecure.core.utils'ten al ---
try:
    from websecure.core.utils import (
        sig_params as _sig_params_util,
        kw_filter as _kw_filter_util,
        guess_host_from_url as _guess_host_from_url,
    )

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
            return urlparse(url).hostname or ""
        except (ValueError, AttributeError):
            return ""


# Not: _passive_js_analyze kaldırıldı — hiç çağrılmayan ölü yardımcıydı.
# JS anahtar/secret taraması crawler.harvest_js_keys() ve passive_recon/js_analyzer
# scanner'ları tarafından yapılır.


# ------------------ Ana akış ------------------
# FAZ-EK: Egress policy helpers -> core/egress.py'e taşındı
# noinspection PyProtectedMember
from websecure.core.egress import (
    _enforce_egress_policy,
    _egress_health_check,
)


def _safe_call(func, *args, call_timeout: float | None = None, **kwargs):
    """Bir fonksiyonu ayrı bir thread'de, isteğe bağlı zaman aşımıyla çalıştırır.

    Dönüş: (ok: bool, result_or_error). Zaman aşımında ("timeout") veya istisnada
    (hata mesajı) ok=False döner.

    Not: Eskiden `with ThreadPoolExecutor() as ex:` kullanılıyordu; context manager
    çıkışta shutdown(wait=True) çağırdığı için zaman aşımı dönüşü bile takılan görev
    bitene kadar BLOKLANIYORDU — yani call_timeout fiilen etkisizdi. Artık executor
    elle yönetiliyor ve zaman aşımında shutdown(wait=False) ile çağıran serbest bırakılıyor
    (yetim thread arka planda en iyi çabayla biter).
    """
    if not callable(func):
        return False, "not_callable"

    ex = ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(func, *args, **kwargs)
    try:
        if call_timeout is None or call_timeout <= 0:
            exc = fut.exception()  # görev bitene kadar bloklar
        else:
            try:
                exc = fut.exception(timeout=call_timeout)
            except _FuturesTimeout:
                fut.cancel()
                ex.shutdown(wait=False)  # çağırana bloklamadan dön
                return False, "timeout"
        if exc is not None:
            return False, str(exc)
        return True, fut.result()
    finally:
        # Görev bittiyse temiz kapat; bitmediyse (timeout dışı erken dönüşlerde)
        # yine bloklamadan kapat.
        ex.shutdown(wait=False)


def _normalize_webdriver_cfg(cfg: dict) -> dict:

    def _to_bool(x, default=None):
        if isinstance(x, bool):
            return x
        if isinstance(x, (int, float)):
            return x != 0
        if isinstance(x, str):
            s = x.strip().lower()
            if s in ("1", "true", "yes", "on"):
                return True
            if s in ("0", "false", "no", "off"):
                return False
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

    if isinstance(tls_wd, dict) and isinstance(tls_wd.get("binary"), str) and tls_wd.get("binary").strip():
        out["webdriver"]["binary"] = tls_wd.get("binary").strip()

    out["webdriver"]["allow_bad_tls"] = False

    return out


def _build_arg_parser() -> argparse.ArgumentParser:
    """CLI argüman tanımları — main()'den bağımsız, test edilebilir."""
    p = argparse.ArgumentParser(description="WebSecure hedef seçimi")
    p.add_argument("--waf", action="store_true", help="WAF bypass modunu etkinleştir")
    p.add_argument("--fuzz-ml", action="store_true", help="Heuristik tabanlı anomali tespiti")
    p.add_argument("--target", "-t", help="Hedef domain veya URL")
    p.add_argument("--attack", action="store_true", help="Offensive D-fazını etkinleştir (güvenli mod)")
    p.add_argument("--attack-unsafe", action="store_true",
                   help="Offensive fazı güvenli olmayan modda çalıştır (dikkat!)")
    p.add_argument("--verify-only", action="store_true", help="Yalnız bulguları doğrula & skorla")
    p.add_argument("--oast-domain", help="OAST için kök domain (DNS tabanlı callback)")
    p.add_argument("--oast-url", help="OAST HTTP callback tabanı (örn. https://oast.example)")
    p.add_argument("--dry-run", action="store_true",
                   help="Etkileşimli soruları atla ve sadece yapılandırmayı doğrula")
    p.add_argument("--batch", action="store_true",
                   help="Etkileşimli soruları atla ve varsayılanlarla devam et (Non-interactive)")
    p.add_argument("--profile", help="Tarama profili (aggressive, stealth)")
    p.add_argument("--debug", action="store_true",
                   help="Detaylı hata ayıklama çıktılarını (DEBUG logs) göster")
    p.add_argument("--visible", action="store_true", help="Tarayıcıyı AÇ (Varsayılan)")
    p.add_argument("--headless", action="store_true", help="Tarayıcıyı GİZLE (Arka planda çalıştır)")
    p.add_argument("--wizard", action="store_true", help="Kurulum sihirbazını çalıştır")
    return p


# --- Phase helper functions (extracted from main()) --------------------------

def _print_banner() -> None:
    """Print the WebSecure ASCII art startup banner."""
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


def _startup_phase(cfg: dict) -> None:
    """
    Run all pre-scan startup tasks:
      - profile resolution and logging config
      - dependency checks (playwright, curl_cffi, nuclei, interactsh, OAST poller)
      - optional interactive tool manager prompts
      - profile-based Tor rotation init
    """
    # Resolve scan profile
    _profiles = (cfg.get("settings") or {}).get("profiles") or {}
    _active = (cfg.get("settings") or {}).get("scan_profile") or "stealth"
    cfg.setdefault("_resolved_profile", _profiles.get(_active, {}))
    configure_logging(level=str(((cfg or {}).get("settings") or {}).get("logging", {}).get("level", "INFO")))

    # HTTP politika + CAPTCHA config'ini config.json'dan HTTP katmanına uygula.
    # ÖNEMLİ: Bu iki fonksiyon tanımlıydı ama HİÇBİR YERDEN ÇAĞRILMIYORDU —
    # bu yüzden config.http.identity_pools (UA/Accept-Language rotasyonu),
    # http.rate_limit, http.idempotent_first, http.phase_profiles ve
    # settings.captcha ayarları okunmuyordu. Artık startup'ta uygulanıyor.
    try:
        from websecure.core.http import (
            install_http_phase_policies as _ihpp,
            install_captcha_config as _icc,
        )
        _ihpp(cfg)
        _icc(cfg)
    except Exception as _httpcfg_e:
        _logger.debug(f"[startup] HTTP policy/captcha install başarısız: {_httpcfg_e!r}")

    # Dependency checks
    _ensure_playwright_chromium()
    _ensure_curl_cffi()
    _ensure_nuclei(cfg)

    # OAST / interactsh
    print("\n" + "=" * 60)
    print("  [*] OAST / interactsh kurulumu kontrol ediliyor...")
    _ensure_interactsh(cfg)
    _oast_cfg2 = cfg.get("oast", {}) or {}
    _ic2 = _oast_cfg2.get("interactsh", {}) or {}
    if (_oast_cfg2.get("enabled") and _ic2.get("enabled")
            and _ic2.get("token") and "BURAYA" not in _ic2.get("token", "")):
        print("  [+] OAST / interactsh aktif.")
        try:
            from websecure.core.oast import start_global_oast_poller, stop_global_oast_poller
            import atexit as _atexit_oast
            start_global_oast_poller(cfg)
            print("  [+] OAST global poller baslatildi (arka plan dogrulama aktif).")
            _atexit_oast.register(stop_global_oast_poller)
        except Exception as _oast_ex:
            print(f"  [!] OAST poller baslanamadi: {_oast_ex}")
    else:
        print("  [i] OAST kullanilamiyor. SSRF/XXE bulgulari dogrulanamayacak.")
    print("=" * 60 + "\n")

    # Interactive tool manager (skipped in --dry-run / --batch / --help)
    is_dry_run_pre = "--dry-run" in sys.argv
    is_wizard = "--wizard" in sys.argv
    if is_wizard:
        try:
            from websecure.cli.wizard import run_wizard  # noqa: PLC0415
            if not run_wizard():
                sys.exit(0)
        except ImportError:
            print("[!] Wizard module not found.")
            sys.exit(1)

    is_batch_pre = "--batch" in sys.argv
    if "--help" not in sys.argv and "-h" not in sys.argv and not is_dry_run_pre and not is_batch_pre:
        from websecure.core.tool_manager import ToolManager  # noqa: PLC0415
        tm = ToolManager(cfg)
        tool_choices = tm.ask_user_interactive()
        if tool_choices.get("sqlmap"):
            tm.prepare_sqlmap()
        if "ffuf" in tool_choices:
            if cfg.get("content_discovery"):
                cfg["content_discovery"]["enabled"] = tool_choices["ffuf"]
            cfg.setdefault("offensive", {}).setdefault("ffuf", {})["enabled"] = tool_choices["ffuf"]
        if "feroxbuster" in tool_choices:
            cfg.setdefault("offensive", {}).setdefault("feroxbuster", {})["enabled"] = tool_choices["feroxbuster"]
        if "nmap" in tool_choices:
            cfg.setdefault("nmap", {})["enabled"] = tool_choices["nmap"]
        import atexit  # noqa: PLC0415
        atexit.register(tm.stop_all)

    # Profile-based Tor rotation (from config, non-interactive)
    silence_insecure_request_warnings()
    _prof = cfg.get("_resolved_profile") or {}
    _tor_interval = _prof.get("tor_rotation_interval")
    _tor_ctrl_port = _prof.get("tor_control_port")
    if _tor_interval and _tor_ctrl_port:
        try:
            print(f"[+] Tor Entegrasyonu Aktif: Her {_tor_interval} saniyede IP değişecek.")
            from websecure.core.waf_bypass import init_tor_control, start_auto_rotation, rotate_tor_identity  # noqa: PLC0415
            init_tor_control({"enabled": True, "control_port": int(_tor_ctrl_port)})
            if not rotate_tor_identity():
                print("[!] UYARI: Tor Control Port’a bağlanılamadı. (Tor çalışıyor mu?)")
            start_auto_rotation(interval=int(_tor_interval))
        except ImportError:
            pass
        except Exception as _e:
            print(f"[!] Tor hatası: {_e}")


def _apply_cli_args(cfg: dict, args) -> None:
    """Apply parsed CLI flags to the config dict (headless, attack mode, OAST, etc.)."""
    # Browser visibility
    if args.headless and not args.visible:
        cfg.setdefault("crawler", {})["headless"] = True
        cfg.setdefault("crawl", {})["headless"] = True
        cfg.setdefault("webdriver", {})["headless"] = True
        cfg.setdefault("settings", {}).setdefault("webdriver", {})["headless"] = True
        print("[*] Headless Mod Etkinleştirildi (Tarayıcı GİZLİ).")
    if args.visible or not args.headless:
        if args.visible:
            print("[*] Live View (Visible Browser) Modu Etkinleştirildi.")
        cfg.setdefault("crawler", {})["headless"] = False
        cfg.setdefault("crawl", {})["headless"] = False
        cfg.setdefault("webdriver", {})["headless"] = False
        cfg.setdefault("settings", {}).setdefault("webdriver", {})["headless"] = False

    # Offensive mode
    off = cfg.setdefault("offensive", {}) if isinstance(cfg, dict) else {}
    if args.attack or args.attack_unsafe or off.get("enabled") is True:
        off["enabled"] = True
        off.setdefault("safe", True)
        if args.attack_unsafe:
            off["safe"] = False
    if args.verify_only:
        off["enabled"] = True
        off["verify"] = {"enabled": True}

    # OAST overrides
    if args.oast_domain or args.oast_url:
        oast = cfg.setdefault("oast", {})
        if args.oast_domain:
            oast["dns_domain"] = args.oast_domain
        if args.oast_url:
            oast["http_base"] = args.oast_url

    # Misc flags
    if args.fuzz_ml:
        cfg.setdefault("fuzz", {}).setdefault("heuristics", {})["enabled"] = True
    if args.waf:
        cfg.setdefault("waf", {})["enabled"] = True


def _resolve_target_url(cfg: dict, args) -> tuple[str, str]:
    """
    Prompt for or read the target URL from args, then validate and normalise it.
    Returns (canonical_url, scheme).
    """
    if args.target:
        raw_input_url = args.target.strip()
    else:
        try:
            raw_input_url = input("Hedef (domain veya URL) gir: ").strip()
        except EOFError:
            raw_input_url = ""
        raw_input_url = (raw_input_url if isinstance(raw_input_url, str) else "").strip() or str(
            cfg.get("base_url") or "")

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
    elif final_url:
        print("[WARN] validate_url başarısız; normalize edilmiş URL ile devam ediliyor.")
        url = final_url
        scheme = scheme or "https"
    else:
        print(f"[HATA] URL çözümlenemedi; http ile devam deneniyor. Girdi: {raw_input_url!r}")
        host = (raw_input_url or "").strip()
        if "://" not in host and host:
            url = "http://" + host
        else:
            url = host or "http://localhost"
        scheme = ("http" if url.lower().startswith("http://") else
                  "https" if url.lower().startswith("https://") else
                  (url.split(":", 1)[0].lower() if ":" in url else "http"))

    _close = getattr(temp_session, "close", None)
    if callable(_close):
        _close()

    print(f"[URL] Kanonik erişim: {url}  (Mod: {scheme.upper()})")
    return url, scheme


def _select_profile(cfg: dict, args) -> tuple[str, dict]:
    """
    Interactively (or automatically) choose and apply the scan profile.
    Returns (profile_name, updated_cfg).
    """
    if not args.dry_run and not args.batch and not args.profile:
        profile, cfg = _offer_scan_profile_and_confirm(cfg)
    else:
        profile = args.profile or (cfg.get("settings") or {}).get("scan_profile") or "aggressive"
        # noinspection PyProtectedMember
        from websecure.core.scan_profile import _apply_aggressive_profile, _apply_stealth_profile  # noqa: PLC0415
        if profile in ("stealth",):
            cfg = _apply_stealth_profile(cfg)
        else:
            cfg = _apply_aggressive_profile(cfg)
            profile = "aggressive"
        cfg = apply_active_profile(cfg)
        if args.dry_run:
            print(f"[Dry-Run] Profil uygulandı: {profile}.")
        elif args.batch:
            print(f"[Batch] Profil otomatik uygulandı: {profile}")

    # Attack mode forces aggressive profile
    if args.attack or args.attack_unsafe:
        if profile not in ("aggressive", "deep"):
            print(f"[WARN] Saldırı modu seçildi ancak profil ‘{profile}’. ‘AGGRESSIVE’ olarak zorlanıyor.")
        profile = "aggressive"
        # noinspection PyProtectedMember
        from websecure.core.scan_profile import _apply_aggressive_profile  # noqa: PLC0415
        cfg = _apply_aggressive_profile(cfg)
        cfg = apply_active_profile(cfg)

    return profile, cfg


# --- Slim main entry point ----------------------------------------------------

def main() -> None:
    """
    WebSecure entry point — intentionally slim.
    Each phase is delegated to a focused helper function.
    """
    # Windows konsolu (cp1252) Unicode çıktıda (↓ ✓ ✗ … ş) UnicodeEncodeError
    # fırlatıp araç indirmeyi/çıktıyı çökertebilir. `python -m websecure` ile
    # çalıştırıldığında frozen entry point'in (run_websecure.py) reconfigure'ı
    # devreye girmez; bu yüzden burada da UTF-8 + errors=replace uygula.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass

    _print_banner()
    cfg = load_config()

    # Ctrl+C handler
    try:
        # noinspection PyProtectedMember
        from websecure.core.phases import _install_sigint_handler  # noqa: PLC0415
        _install_sigint_handler()
    except Exception as _fix_e:
        _logger.debug(f"[main] {type(_fix_e).__name__}: {_fix_e!r}")

    _ = _ensure_wl(cfg)
    results: dict = {"phase_timings": {}, "sections": []}

    # CLI argümanlarını AĞIR startup'tan ÖNCE ayrıştır: argparse `--help`/`-h` (ve
    # geçersiz argüman) burada sys.exit eder → araç indirme, OAST/interactsh ağ
    # çağrısı ve Tor rotasyonu TETİKLENMEZ. Yeni kullanıcı 'python -m websecure
    # --help' yazınca ağa çıkılmaz/araç kurulmaz. Argümanlar yine _startup_phase'den
    # SONRA uygulanır → normal koşuda davranış birebir korunur.
    args = _build_arg_parser().parse_args()

    # Phase 1 — startup checks + tool manager + Tor rotation
    _startup_phase(cfg)

    # Phase 2 — CLI argument config override
    _apply_cli_args(cfg, args)

    # Phase 3 — target URL resolution
    url, scheme = _resolve_target_url(cfg, args)
    cfg["target"] = url
    cfg["base_url"] = url

    # Phase 4 — interactive wizard (Tor / auth / görünür-tarayıcı enjeksiyon / proxy)
    from websecure.core.cli.interactive import (  # noqa: PLC0415
        setup_tor, setup_auth, setup_show_browser, setup_proxy,
    )
    setup_tor(cfg, args)
    setup_auth(cfg, args)
    setup_show_browser(cfg, args)
    setup_proxy(cfg, args)

    # Phase 5 — profile selection
    profile, cfg = _select_profile(cfg, args)

    # Phase 5b — stealth + görünür enjeksiyon çelişkisi: uyar ve yeniden sor
    from websecure.core.cli.interactive import confirm_stealth_browser_injection  # noqa: PLC0415
    confirm_stealth_browser_injection(cfg, args, profile)

    # Phase 6 — full scan execution
    _run_scan_phases(cfg, args, url, scheme, profile, results)


# --- Scan execution (extracted from main) ------------------------------------

def _run_scan_phases(
    cfg: dict,
    args,
    url: str,
    scheme: str,
    profile: str,
    results: dict,
) -> None:
    """
    Execute all scan phases in order:
      session setup -> auth flow -> context -> unified plan -> reporting -> fuzzing.

    All scanner module globals are accessible because this function lives in
    the same module where they are dynamically loaded at import time.
    """
    mode = _choose_mode_from_config(cfg)
    detailed = (ScanMode is not None and mode == ScanMode.DETAILED) or bool(
        (cfg.get("settings") or {}).get("detailed", False))
    print(f"[MOD] {mode.upper()}  |  Detay: {'EVET' if detailed else 'HAYIR'}  |  Profil: {profile.upper()}")

    debug = str((cfg.get("settings") or {}).get("logging", {}).get("level", "")).upper() == "DEBUG"
    logger = setup_logging(level='DEBUG' if debug else 'INFO')

    driver = None
    if True:  # FIX: block alignment; always run pipeline
        _wd_c = _normalize_webdriver_cfg(cfg)
        driver = setup_webdriver(headless=_wd_c["webdriver"]["headless"])
        if not driver:
            print("[i] WebDriver açılamadı; dinamik gezinme olmadan devam edilecek.")

        session = _setup_session_from_config(cfg)

        # --- HumanLike session adapter (stealth/evasion modu) ---
        _human_adapter_inst = None
        try:
            from websecure.core.human_adapter import make_human_session as _make_human_sess  # noqa: PLC0415
            _scan_profile_name = str((cfg.get("settings") or {}).get("scan_profile", "stealth")).lower()
            if _scan_profile_name in ("stealth", "paranoid", "casual"):
                _human_adapter_inst = _make_human_sess(profile=_scan_profile_name)
                _logger.info(f"[HumanAdapter] Aktif: profil={_scan_profile_name}")
                print(f"[+] HumanLike Adapter etkin (profil: {_scan_profile_name})")
        except Exception as _ha_exc:
            _logger.debug(f"[HumanAdapter] Yüklenemedi: {_ha_exc}")

        # --- Otomatik Playwright login (auth_profiles yapılandırılmışsa) ---
        # config.json varsayılan olarak PLACEHOLDER auth_profile içerir
        # (KULLANICI_ADI / SIFRE / https://hedef-site.com/login). Eski koşul yalnız
        # "username ve password dolu mu" diye baktığından, kullanıcı interaktif
        # olarak auth'u reddetse bile placeholder'lar dolu sayılıp Playwright login
        # SAHTE 'hedef-site.com' domain'ine bağlanmaya çalışıyor, zaman kaybediyor
        # ve "Mevcut URL: https://hedef-site.com/login" gibi yanıltıcı log basıyordu.
        # Çözüm: placeholder değerleri (ve hedefle alakasız login_url'i) ele.
        _PLACEHOLDER_AUTH = {
            "KULLANICI_ADI", "SIFRE", "KULLANICI", "PAROLA",
            "USERNAME", "PASSWORD", "user", "pass", "", None,
        }
        _run_auth_profiles = ((cfg.get("authenticated") or {}).get("auth_profiles") or [])
        _ap0 = _run_auth_profiles[0] if _run_auth_profiles else {}
        _ap_user = (_ap0.get("username") or "").strip()
        _ap_pass = (_ap0.get("password") or "").strip()
        _ap_login = (_ap0.get("login_url") or "").strip().lower()
        _auth_is_real = (
            _ap_user and _ap_pass
            and _ap_user not in _PLACEHOLDER_AUTH
            and _ap_pass not in _PLACEHOLDER_AUTH
            and "hedef-site.com" not in _ap_login  # placeholder domain
        )
        if _auth_is_real:
            try:
                from websecure.core.auth_flow import playwright_login as _pw_login
                print("[*] Playwright ile otomatik giris yapiliyor...")
                _pw_result = _pw_login(cfg, session_path="session.json")
                if _pw_result and _pw_result.get("login_successful"):
                    for _cn, _cv in (_pw_result.get("cookies") or {}).items():
                        session.cookies.set(_cn, _cv)
                    cfg.setdefault("browser", {})["auth_storage_state"] = \
                        _pw_result.get("storage_state_path", "session.json")
                    print("[+] Giris basarili. Oturum hazir.")
                elif _pw_result:
                    print("[!] Giris basarisiz olabilir. Scan devam ediyor.")
            except Exception as _pw_exc:
                print(f"[!] Otomatik login hatasi: {_pw_exc}. Scan devam ediyor.")

        # --- Ön tanımlar: daha sonra kullanılan bağlamlar (lint/akış güvenliği) ---
        auth_ctx = None
        oast_cfg = (cfg.get('oast') or {})
        _enforce_egress_policy(cfg)
        _egress_health_check(session, cfg, results)

        # Not: eski 'prime_session' çağrısı kaldırıldı — bu sembol hiçbir yerde
        # tanımlanmıyordu (detect.py yok, core.http'de de yok) → globals().get hep None,
        # blok hiç çalışmıyordu. Aktif oturum priming'i _session_priming() (aşağıda) yapar.

        if callable(install_auth_retry_adapter):
            install_auth_retry_adapter(session, cfg)

        results.setdefault("phase_timings", {})

        meta = results.setdefault("meta", {})
        ci = current_identity(cfg)
        meta["egress"] = ci if isinstance(ci, (dict, list, str)) else str(ci)

        meta["scan_profile"] = profile
        # Hedefi meta'ya YAZ — kesintiye uğrayan (Ctrl+C) taramalarda emergency rapor
        # yolu yalnız bu meta'yı görüyordu; target yoksa rapor "Unknown Target" basıyordu.
        if url:
            meta["target"] = url
        if callable(globals().get("add_result")):
            add_result("meta", {"scan_profile": profile, **({"target": url} if url else {})})

        auth_ok = False
        if callable(run_auth_flow):
            auth_ok = bool(run_auth_flow(session, cfg, driver=driver, base_url=url, debug=debug))

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
                    'strict_required=true fakat kullanılabilir kimlik yöntemi yapılandırılmamış '
                    '(bearer/api_key/cookie veya login_url+creds eksik).')

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
                    "url", "scheme", "config", "driver", "session", "results", "detailed",
                    "save_report", "debug", "logger", "base_plan",
                    # Faz 19 fix: faz runner'ların ihtiyaç duyduğu ek alanlar
                    "human_adapter", "_plan_ran", "target", "waf_profile",
                    "bypass_session", "technologies", "authenticated",
                    "base_url",
                    "auth_ctx", "auth",
                )

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
            ctx.target = url  # Faz 19 fix: faz runner'larının beklediği .target alanı
            ctx.base_url = url  # Fix: base_url olmadan ffuf/feroxbuster/sqlmap/js_analysis atlıyordu
            ctx.session, ctx.results, ctx.detailed = session, results, detailed
            ctx.save_report, ctx.debug, ctx.logger = True, debug, logger
            # Faz 19 fix: human_adapter'ı plan çalışmadan ÖNCE inject et
            try:
                ctx.human_adapter = _human_adapter_inst  # None olabilir, sorun değil
            except (AttributeError, TypeError) as _fix_e:
                _logger.debug(f"[main] {type(_fix_e).__name__}: {_fix_e!r}")

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
                        {"id": "waf_detect", "title": "WAF Tespiti", "runner": phase_waf_detect, "enabled": True},
                        {"id": "discovery", "title": "Keşif", "runner": phase_discovery, "enabled": True},
                        {"id": "port_scan", "title": "Port Taraması", "runner": phase_portscan, "enabled": True},
                        {"id": "reporting", "title": "Raporlama",
                         "runner": run_reporting_and_integration, "enabled": True},
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
            print("\n" + "!" * 60)
            print(" [DİKKAT] HEDEF LOCALHOST (KENDİ BİLGİSAYARINIZ)")
            print(" Bu tarama güvenlidir çünkü sadece çalışan servise istek atar.")
            print(" DOSYA SİSTEMİNİZE VEYA DİĞER PROGRAMLARA ZARAR VERMEZ.")
            print("!" * 60 + "\n")

        if callable(globals().get("_session_priming")):
            _session_priming(session, url, cfg)

        # Plan B: Reset false-positive reducer for this scan session
        if _PLAN_B_AVAILABLE and _FalsePositiveReducer is not None:
            try:
                _FalsePositiveReducer.reset_session()
                _logger.info("[PlanB] FalsePositiveReducer session reset.")
            except Exception as _fpr_exc:
                _logger.debug(f"[PlanB] FPR reset error: {_fpr_exc!r}")

        # Soft-404/catch-all baseline cache is per-origin and MUST be cleared per
        # scan (queue/API/multi-target mode reuses the process) — otherwise a stale
        # baseline from a previous target would gate the next one.
        try:
            from websecure.core.fp_reducer import SoftNotFoundBaseline as _SNFB
            _SNFB.reset()
        except Exception as _snfb_exc:
            _logger.debug(f"[PlanB] SoftNotFoundBaseline reset error: {_snfb_exc!r}")

        # Plan B: Wire AdaptiveRateController into results so scanners can use it
        if _PLAN_B_AVAILABLE and _AdaptiveRateController is not None:
            try:
                _scan_rps = float((cfg.get("settings") or {}).get("rate_limit_rps", 10.0))
                _rate_ctrl = _AdaptiveRateController(
                    initial_rps=_scan_rps, min_rps=0.5, max_rps=50.0
                )
                results["_rate_controller"] = _rate_ctrl
                _logger.info(f"[PlanB] AdaptiveRateController init @ {_scan_rps:.1f} rps")
            except Exception as _rc_exc:
                _logger.debug(f"[PlanB] RateController init error: {_rc_exc!r}")

        # [WS3] ROBUST AUTHENTICATION & SESSION CAPTURE
        def _on_auth_event(evt: str, data: dict):
            if not data.get("ok", True) and "final" not in evt:
                return

            if evt == "auth.webdriver_login" and data.get("ok"):
                print("\n" + "=" * 65)
                print(" [KILL CAM] SESSION CAPTURED (BROWSER) ")
                print("=" * 65)
                print(" [+] Strategy: WebDriver Injection")
                print(f" [+] Origin:   {url}")
                print(" [+] Cookies:  Synced to Session")
                print("=" * 65 + "\n")
            elif evt == "auth.requests_login" and data.get("ok"):
                print("\n" + "=" * 65)
                print(" [KILL CAM] SESSION CAPTURED (API) ")
                print("=" * 65)
                print(" [+] Strategy: API/Form Login")
                print(" [+] Status:   Authorized")
                print("=" * 65 + "\n")
            elif evt == "auth.final":
                if data.get("authenticated"):
                    print("[+] Auth Flow Complete: Authenticated = TRUE")
                else:
                    pass  # Silent failure to allow fallback

        # Invoke Smart Login with Event Callback
        if callable(smart_login):
            print("[*] Akıllı Oturum Yönetimi başlatılıyor (Smart Auth)...")
            smart_login(session, cfg, driver=driver, base_url=url, debug=debug, event_cb=_on_auth_event)

        # [WS3] SESSION SCANNER — weak session brute-force + timestamp prediction
        # Runs on aggressive/safe_full profiles (already wired into phases runner;
        # this block provides a direct call path for standalone main.py invocations)
        _prof = (cfg.get("settings") or {}).get("scan_profile")
        if _prof in ["aggressive", "safe_full"]:
            try:
                from websecure.scanners.session_scanner import run
                print("\n[*] Session Scanner Başlatılıyor (Brute Force + Tahmin)...")
                hunter_res = run(url, session=session, threads=20)
                if hunter_res:
                    print(f"[!] DİKKAT: {len(hunter_res)} adet oturum güvenlik bulgusu!")
                    if callable(globals().get("add_result")):
                        add_result("vulnerability", {"session_findings": hunter_res})
            except ImportError:
                print("[!] Session Scanner modülü yüklenemedi.")
            except Exception as e:
                print(f"[!] Session Scanner hatası: {e}")

        _auth = (cfg.get('auth') or {}) if isinstance(cfg, dict) else {}
        _auto = (_auth.get('auto_signup') or {}) if isinstance(_auth, dict) else {}
        _assi = (_auth.get('assisted') or {}) if isinstance(_auth, dict) else {}

        if bool(_auto.get('enabled')) and callable(globals().get("run_auto_signup")):
            if run_auto_signup(session, cfg):
                print('[Auth] Auto-Signup başarılı.')
        if bool(_assi.get('enabled')) and callable(globals().get("run_device_code_flow")):
            if run_device_code_flow(session, cfg):
                print('[Auth] Device Code ile token alındı.')

        auth_ctx = _build_auth_ctx(session, cfg)
        try:
            ctx.auth_ctx = auth_ctx
            ctx.auth = (cfg.get('auth') or {}) if isinstance(cfg, dict) else {}
        except (AttributeError, TypeError):
            pass

        def mark(phase_name, start_t=None):
            if 'phase_timings' not in results or not isinstance(results.get('phase_timings'), dict):
                results['phase_timings'] = {}
            if start_t is None:
                return time.time()
            results["phase_timings"][phase_name] = round(time.time() - start_t, 2)

        print("[*] Standart tarama başlatılıyor…")

        # [FIX] Legacy manual block replaced with Unified Plan Runner to ensure all
        # configured scanners (SSRF, NoSQLi, JWT, etc.) are executed.
        if callable(run_plan_if_needed):
            print("[*] Gelismis tarama plani calistiriliyor (Unified Framework)...")
            run_plan_if_needed(ctx)
            # Faz 19 fix: _plan_ran'ı ctx'e değil results dict'e yaz
            # ctx'e de yaz (slot varsa), ancak results dict her zaman paylaşılan referanstır.
            results["_plan_ran"] = True
            try:
                ctx._plan_ran = True
            except (AttributeError, TypeError) as _fix_e:
                _logger.debug(f"[main] {type(_fix_e).__name__}: {_fix_e!r}")
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
                _safe_call(run_owasp_and_nuclei, url, results, session, config=cfg,
                           debug=debug, auth_ctx=None, call_timeout=900.0)

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

        # Plan B (B5): Technology fingerprinting — runs once on base URL before offensive scanning
        if _PLAN_B_AVAILABLE and _TechFingerprinter is not None:
            try:
                _fp = _TechFingerprinter(session)
                _tech_profile = _fp.fingerprint(url, timeout=10)
                results["tech_profile"] = {
                    "url": _tech_profile.url,
                    "technologies": _tech_profile.technologies,
                    "cms": _tech_profile.cms,
                    "language": _tech_profile.language,
                    "framework": _tech_profile.framework,
                    "database": _tech_profile.database,
                    "server": _tech_profile.server,
                    "waf": _tech_profile.waf,
                    "sqli_dialects": _tech_profile.sqli_dialects,
                    "ssti_engines": _tech_profile.ssti_engines,
                }
                if callable(globals().get("add_result")):
                    add_result("tech_profile", results["tech_profile"])
                _logger.info(
                    f"[PlanB/B5] Tech: {_tech_profile.top_technologies(3)} | "
                    f"SQLi: {_tech_profile.sqli_dialects} | "
                    f"SSTI: {_tech_profile.ssti_engines}"
                )
                print(
                    f"[B5] Tech fingerprint: {', '.join(_tech_profile.top_technologies(3))}"
                    + (f" | WAF: {_tech_profile.waf}" if _tech_profile.waf else "")
                )
            except Exception as _fp_exc:
                _logger.debug(f"[PlanB] TechFingerprinter error: {_fp_exc!r}")

        endpoints = list(results.get("endpoints", [])) or [url]

        # Defense-in-depth: crawler artefaktı çöp URL'leri (özyinelemeli urljoin,
        # /[pagePath] route-şablonları, %5c kaçışları) enjeksiyon havuzuna sokma —
        # ingestion'da elenmiş olmalı ama burada da süz ki Tor üzerinde boşa
        # istek/zaman harcanmasın. Hepsi çöpse url'e düş (boş bırakma).
        try:
            from websecure.core.utils import is_junk_url as _is_junk, is_streaming_endpoint as _is_stream
            # Çöp (crawler-artefaktı) + socket.io/SSE/long-poll transport uçları
            # enjeksiyon havuzundan çıkar: ikincisi payload yansıtmaz, Tor'da ~45s
            # asılı kalır (verim sıfır). ws_fuzz socket.io'yu kendi keşfedip test eder.
            _clean_eps = [e for e in endpoints if not _is_junk(e) and not _is_stream(e)]
            if _clean_eps:
                if len(_clean_eps) != len(endpoints):
                    _logger.info(
                        "[main] %d çöp/stream endpoint enjeksiyon havuzundan elendi (%d→%d)",
                        len(endpoints) - len(_clean_eps), len(endpoints), len(_clean_eps)
                    )
                endpoints = _clean_eps
        except Exception as _je:
            _logger.debug(f"[main] is_junk_url/stream filtresi atlandı: {_je!r}")

        # Plan B (B8): Smart endpoint prioritization — re-rank after crawl
        if _PLAN_B_AVAILABLE and _EndpointPrioritizer is not None and len(endpoints) > 1:
            try:
                # Fix 5: Build method_map from forms_meta so POST endpoints score higher
                _method_map: dict[str, list] = {}
                for _fm in results.get("forms_meta", []) or []:
                    _fm_action = _fm.get("action") or ""
                    _fm_method = (_fm.get("method") or "GET").upper()
                    if _fm_action and _fm_method != "GET":
                        _method_map.setdefault(_fm_action, []).append(_fm_method)

                _prioritizer = _EndpointPrioritizer()
                _ranked = _prioritizer.rank(endpoints, method_map=_method_map)
                # Re-order endpoints: critical/high first
                _grouped = _prioritizer.group_by_priority(_ranked)
                _ordered_eps = (
                    [e.url for e in _grouped["critical"]]
                    + [e.url for e in _grouped["high"]]
                    + [e.url for e in _grouped["medium"]]
                    + [e.url for e in _grouped["low"]]
                )
                # Preserve any endpoints not ranked (e.g. no params)
                _seen_set = set(_ordered_eps)
                _ordered_eps += [u for u in endpoints if u not in _seen_set]
                endpoints = _ordered_eps
                results["endpoint_priority_summary"] = {
                    "critical": len(_grouped["critical"]),
                    "high": len(_grouped["high"]),
                    "medium": len(_grouped["medium"]),
                    "low": len(_grouped["low"]),
                    "total": len(_ranked),
                }
                _logger.info(
                    f"[PlanB/B8] Prioritized {len(_ranked)} endpoints: "
                    f"critical={len(_grouped['critical'])} high={len(_grouped['high'])}"
                )
                print(
                    f"[B8] Endpoint priority: critical={len(_grouped['critical'])} "
                    f"high={len(_grouped['high'])} medium={len(_grouped['medium'])}"
                )
            except Exception as _ep_exc:
                _logger.debug(f"[PlanB] EndpointPrioritizer error: {_ep_exc!r}")

        # Enjeksiyon/fuzz hedef listesi: STATIK asset'leri (.js/.css/.png/.woff…)
        # ele. Static chunk dosyaları query param işlemez; bunları SQLi/XSS/OAST/
        # SSRF/fuzz'a sokmak yalnız zaman kaybı (logda ~7 dk boşa static .js
        # fuzzing: 962-…js?q=, .js?redirect= …). Keşif/coverage için tam 'endpoints'
        # korunur; YALNIZ enjeksiyon döngüleri _inj_endpoints kullanır.
        _inj_endpoints = [u for u in endpoints
                          if isinstance(u, str) and not is_static_asset(u)]
        if not _inj_endpoints:
            _inj_endpoints = list(endpoints)  # tümü static ise enjeksiyonu boş bırakma
        _n_static = len(endpoints) - len(_inj_endpoints)
        if _n_static > 0:
            _logger.info(f"[fuzz] {_n_static} statik asset enjeksiyon listesinden elendi "
                         f"({len(_inj_endpoints)} enjekte edilebilir hedef)")

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
            # B1 FIX: ssrf_xxe_scan = run_ssrf_xxe_scan(ctx, oast_cfg=None, **kwargs).
            # `ctx` ZORUNLU positional ve scanner session/endpoints/results/config'i
            # ctx'ten okur. Eskiden kw'de ctx YOKTU → _kw_filter yalnız `oast_cfg`'yi
            # eşliyor, çağrı run_ssrf_xxe_scan(oast_cfg=...) oluyordu → her seferinde
            # "missing 1 required positional argument: 'ctx'" ile çöküyordu (ssrf_xxe
            # fazı 0.0s — hiç çalışmadı). ctx'i kw'ye ekle; eski imza için pozisyonel
            # ctx fallback'i de düzeltildi (önceki fallback session'ı ctx sanıyordu).
            kw = dict(ctx=ctx, session=session, endpoints=_inj_endpoints[:40], oast_cfg=oast_cfg,
                      results=results, debug=debug, auth_ctx=auth_ctx)
            fk = _kw_filter(ssrf_xxe_scan, **kw)
            if "ctx" not in fk:
                ok_ssrf, res_ssrf = _safe_call(ssrf_xxe_scan, ctx, oast_cfg, call_timeout=900.0)
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
        ctx.results = (locals().get("results") or {})  # Capture local results
        # Sync results from discovery
        if "discovery" not in ctx.results and "discovered" in locals():
            ctx.results["discovery"] = locals().get("discovered")
        ctx.debug = debug
        ctx.target = url  # Use 'url' variable which represents the verified target
        ctx.base_url = url  # Fix: base_url olmadan ffuf/feroxbuster/sqlmap/js_analysis atlıyordu
        ctx.url = url

        # Faz 19 fix: human_adapter'ı ikinci ctx'e de plan öncesi inject et
        if _human_adapter_inst is not None:
            try:
                ctx.human_adapter = _human_adapter_inst
            except (AttributeError, TypeError) as _fix_e:
                _logger.debug(f"[main] {type(_fix_e).__name__}: {_fix_e!r}")

        # [Fix] Direct Phase Execution — only runs if first call at line ~1911 did NOT execute
        # Faz 19 fix: _plan_ran kontrolü results dict üzerinden yapılır (ctx nesne değiştiğinden)
        if not results.get("_plan_ran", False) and not getattr(ctx, "_plan_ran", False):
            print("[•] Faz planı çalıştırılıyor…")
            t = mark("phase_plan")
            _safe_call(run_plan_if_needed, ctx, call_timeout=None)  # No timeout for full plan
            mark("phase_plan", t)
            results["_plan_ran"] = True
            try:
                ctx._plan_ran = True
            except (AttributeError, TypeError) as _fix_e:
                _logger.debug(f"[main] {type(_fix_e).__name__}: {_fix_e!r}")
        else:
            _logger.debug("[main] Faz planı zaten çalıştırıldı, ikinci çağrı atlandı.")

        # --- Exploit Orchestrator (exploitation.enabled=true ise) ---
        _exploit_cfg = (cfg.get("exploitation") or {}) if isinstance(cfg, dict) else {}
        if _exploit_cfg.get("enabled", True) is not False:
            print("[•] Exploit Orchestrator: bulgular zincire alınıyor…")
            try:
                from websecure.core.exploit_orchestrator import exploit_from_results as _exploit_fr  # noqa: PLC0415
                _exp_findings: list = []
                for _k, _lst in get_bucket_results().items():
                    if isinstance(_lst, list):
                        _exp_findings.extend([i for i in _lst if isinstance(i, dict)])
                if _exp_findings:
                    t_ex = mark("exploit_orchestrator")
                    _exp_res = _exploit_fr(
                        scan_results={"findings": _exp_findings, "target": url},
                        cfg=cfg,
                        lhost=_exploit_cfg.get("lhost", ""),
                        lport=int(_exploit_cfg.get("lport", 4444)),
                    )
                    mark("exploit_orchestrator", t_ex)
                    if _exp_res and callable(globals().get("add_result")):
                        _exp_summary = _exp_res.get("exploit_summary", {})
                        add_result("exploitation", {"results": _exp_res,
                                   "total": _exp_summary.get("total_exploited", 0)})
                    _n_ex = _exp_res.get("exploit_summary", {}).get(
                        "total_exploited", 0) if isinstance(_exp_res, dict) else 0
                    print(f"[+] Exploit Orchestrator tamamlandı: {_n_ex} senaryo")
            except ImportError:
                _logger.debug("[ExploitOrchestrator] Modül bulunamadı, atlandı.")
            except Exception as _ex_exc:
                _logger.warning(f"[ExploitOrchestrator] Hata: {_ex_exc}")

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
            # KONSOLİDASYON: faz planı (run_plan_if_needed) bu offensive scanner'ların
            # HEPSİNİ zaten çalıştırdı (_runner_request_smuggling/mass_assignment/jwt/
            # nosqli/ws_fuzz). Plan çalıştıysa legacy tekrarı atlanır → ~2x süre tasarrufu,
            # sıfır kapsam kaybı. (chain_reactor/authorization/business_logic faz planında
            # YOK → aşağıda koşulsuz çalışmaya devam eder.)
            if bool(off_root.get("enabled", False)) and not results.get("_plan_ran"):
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

        # NOT (akış düzeltmesi): Skorlama + raporlama bloğu ESKİDEN burada,
        # fuzzing/offensive taramalarından ÖNCE çalışıyordu. Sonuç:
        #   (1) fuzzing/NoSQLi/SSRF/SQLi/XSS/CSRF/ChainReactor/bizlogic/OAST
        #       bulguları resmî rapora GİRMİYORDU (rapor erken üretiliyordu),
        #   (2) program "Tamamlandı" deyip fuzzing'e devam ediyordu (kullanıcıya
        #       "bitti ama hâlâ çalışıyor" görünüyordu),
        #   (3) session.close() fuzzing session'ı KULLANMADAN önce çağrılıyordu,
        #   (4) en sonda finally safety-net İKİNCİ bir rapor basıyordu.
        # Çözüm: skorlama+raporlama+temizlik artık tüm taramalardan SONRA, bu
        # fonksiyonun en altında (_finalize_reporting) tek seferde yapılıyor.
        print("fuzzing başlıyor…")
        t = mark("fuzzing")

        # Akış düzeltmesi: auth_ctx burada None'a sıfırlanıyordu; bu, 1891'de kurulan
        # ve offensive taramalarda kullanılan kimlik bağlamını fuzzing ve (aşağıdaki) OAST
        # için kaybettiriyordu. Kimlikli taramalarda fuzz/OAST'ın da auth bağlamını
        # taşıması için sıfırlama kaldırıldı.

        fuzz_fn = fuzz_endpoint if callable(globals().get("fuzz_endpoint")) else None
        sig_params = set(inspect.signature(fuzz_fn).parameters.keys()) if callable(fuzz_fn) else set()

        t_fz = mark("fuzzing")
        for u in _inj_endpoints[:50]:  # güvenli üst sınır (static asset'ler elendi)
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
                report_cb=lambda f: add_result("vulnerability", {**redact_sensitive(f), "source": "fuzz"}) if callable(
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

        # --- Offensive Scans (NoSQLi, SSRF, etc.) ---

        # 1. NoSQL Injection
        _nosqli_fn = getattr(nosqli, "run_nosqli_scan", None) if nosqli else None
        if callable(_nosqli_fn) and (cfg.get("scanners") or {}).get("nosqli") and not results.get("_plan_ran"):
            print("[•] NoSQL Enjeksiyon taraması…")
            _safe_call(_nosqli_fn, ctx=ctx)

        # 2. SSRF / XXE
        _ssrf_fn = getattr(_ssrf_mod, "run_ssrf_xxe_scan", None) if _ssrf_mod else None
        if callable(_ssrf_fn) and (cfg.get("scanners") or {}).get("ssrf_xxe") and not results.get("_plan_ran"):
            print("[•] SSRF & XXE taraması…")
            _safe_call(_ssrf_fn, ctx=ctx)

        merged_eps = list(set(_inj_endpoints + (ctx.results.get("discovery", {}).get("query") or [])))
        # Filter valid URLs + static asset'leri ele (discovery query'si de içerebilir)
        merged_eps = [u for u in merged_eps
                      if isinstance(u, str) and "://" in u and not is_static_asset(u)]

        # Saldırı-yüzeyi dedup: birebir-string set() yetmez. WordPress/WooCommerce
        # gibi sitelerde `?add_to_wishlist=<id>&_wpnonce=<nonce>` linki HER ürün/
        # kategori/sayfalama varyantında tekrarlanır → aynı handler binlerce ayrı
        # "hedef" olarak fuzz'lanır (neuneon: 6207 wishlist URL'i, 2385 hedef,
        # ~5 saat). İmza = (host, sayısal-segmentleri normalize edilmiş path,
        # param-İSİM seti). Aynı imzadan tek temsilci tutulur: param DEĞERLERİ
        # fuzzing için önemsizdir (parametrenin kendisini test ederiz), volatil
        # nonce/id/pagination yüzünden kombinasyon patlaması engellenir.
        def _ep_signature(u: str):
            pr = urlparse(u)
            segs = tuple("#" if s.isdigit() else s for s in pr.path.split("/"))
            names = tuple(sorted(n for n, _ in parse_qsl(pr.query, keep_blank_values=True)))
            return (pr.netloc, segs, names)

        _seen_sig: set = set()
        _deduped_eps = []
        for u in merged_eps:
            sig = _ep_signature(u)
            if sig in _seen_sig:
                continue
            _seen_sig.add(sig)
            _deduped_eps.append(u)
        if len(_deduped_eps) < len(merged_eps):
            print(f"[•] Saldırı yüzeyi dedup: {len(merged_eps)} → {len(_deduped_eps)} "
                  f"hedef (volatil nonce/id/pagination varyantları birleştirildi)")
        merged_eps = _deduped_eps

        # 3. SQL Injection (New Robust Module)
        # Import dynamically to handle 'shim' modules
        _run_sqli = _opt_import('websecure.scanners.sqli', 'run')
        if callable(_run_sqli) and (cfg.get("scanners") or {}).get("sqli") and not results.get("_plan_ran"):
            print(f"[•] SQL Enjeksiyon taraması (Robust) - {len(merged_eps)} hedefe...")
            # Note: sqli.run takes (url, session, results, debug) where url can be a list.
            # results MUST be passed so the scanner can read forms_meta and fuzz the
            # discovered login/register/payment FORM fields (name/email/password/card)
            # via POST/JSON — without it self.results is empty and scan_forms is a no-op
            # (only URL-query params got tested → the "input fields untested" gap).
            _safe_call(_run_sqli, merged_eps, session=session, results=results, debug=debug)

        # 4. Reflected XSS (New Robust Module)
        _run_xss = _opt_import('websecure.scanners.xss', 'run')
        if callable(_run_xss) and (cfg.get("scanners") or {}).get("xss") and not results.get("_plan_ran"):
            print(f"[•] XSS taraması (Reflected) - {len(merged_eps)} hedefe...")
            # results MUST be passed (forms_meta) so XSS also fuzzes form fields, not
            # just URL-query params (see SQLi note above).
            _safe_call(_run_xss, merged_eps, session=session, results=results, debug=debug)

        # 5. CSRF (New Module)
        if csrf and (cfg.get("scanners") or {}).get("csrf") and not results.get("_plan_ran"):
            print("[•] CSRF taraması…")
            try:
                csrf.run_scan(ctx.url, session, results)
            except Exception as e:
                _logger.error(f"CSRF failed: {e}")

        # 7. Chain Reactor (Detection + Exploitation)
        if chain_reactor and isinstance(results, dict):
            _logger.info("[ChainReactor] Zincirleme analizi + exploit başlatılıyor…")
            try:
                # phase_chain_reactor: detection VE exploitation (credential dump, ATO, RCE)
                # analyze_chains sadece detection yapıyor — exploit pipeline çalışmıyordu (P3/P8)
                chain_reactor.phase_chain_reactor({"results": results, "session": session})
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
            ok_authz, auth_findings = _safe_call(authorization_run, rctx, _inj_endpoints[:30], call_timeout=600.0)
            if ok_authz and isinstance(auth_findings, (list, tuple)):
                for f in auth_findings:
                    if callable(globals().get("add_result")):
                        add_result("vulnerability", f)
            elif not ok_authz and callable(globals().get("add_result")):
                add_result("errors", {"stage": "authorization", "error": str(auth_findings)})

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
            # B4 FIX (süre anomalisi): OAST döngüsünün TOPLAM duvar-saati bütçesi yoktu
            # ve her hedef için call_timeout=900s (15 dk!) veriliyordu. Tor gibi yavaş
            # taşımalarda her OAST isteği ~50-70s sürünce, 20 hedef × ~6 param × 3 varyant
            # tek bir taramada OAST fazını 67 DAKİKAYA (4018s) çıkardı — üstelik 0 bulgu.
            # Artık: (1) faz için toplam bütçe (varsayılan 300s, config'ten ayarlanır),
            # (2) hedef başına bütçe-farkındalıklı makul timeout. Bütçe dolunca kalan
            # hedefler atlanır ve durum meta'ya yazılır.
            _oast_budget = float(oast_cfg.get("phase_budget_secs", 300) or 300)
            _oast_per_call = float(oast_cfg.get("per_target_timeout_secs", 120) or 120)
            # Max-power: OAST faz bütçesini ve 20-hedef sınırını kaldır — tüm enjeksiyon
            # endpoint'lerinde OOB testi yapılır, hiçbiri "kalanlar atlandı" ile geçilmez.
            _oast_unlimited = False
            try:
                from websecure.core.http import no_timeout_enabled as _nt
                _oast_unlimited = bool(_nt())
            except Exception:
                _oast_unlimited = False
            if _oast_unlimited:
                # B4 FIX (2026-06-20): no_timeout'ta bile FİRM tavan. Eskiden
                # _oast_budget=inf idi → kayıt-ölü/Tor'da OAST fazı 91 DAKİKA boşa
                # koştu (0 bulgu). Tam güç korunur ama mutlak tavanla (Tor 1800s /
                # doğrudan 1200s). per-call Tor'da uzun olabilir.
                _tor_active = False
                try:
                    import os as _os
                    _tor_active = (_os.environ.get("TOR_ACTIVE", "").lower() in ("1", "true", "yes"))
                except Exception:
                    _tor_active = False
                _oast_budget = float(oast_cfg.get("phase_budget_secs_max", 1800 if _tor_active else 1200))
                _oast_per_call = max(_oast_per_call, 180.0)
            ok_client, client = _safe_call(OASTClient, session, oast_cfg, call_timeout=30.0)
            # FIX-3 (2026-06-20): OOB kanalı GERÇEKTEN canlı mı? interactsh kaydı
            # TypeError/ağ ile başarısızsa (bu taramada olduğu gibi) her hedefe
            # asla doğrulanamayacak OOB payload atıp timeout'a düşmek anlamsız —
            # 91 dk israf. Kayıt-ölüyse TÜM fazı atla, durumu dürüstçe yaz.
            _oob_live = True
            _oast_skipped = False
            if ok_client and hasattr(client, "is_oob_live"):
                try:
                    _oob_live = bool(client.is_oob_live(timeout=30.0))
                except Exception as _live_exc:
                    _oob_live = False
                    _logger.debug(f"[OAST] is_oob_live check failed: {_live_exc!r}")
            if ok_client and not _oob_live:
                print("[i] OAST atlandı: OOB/interactsh kaydı başarısız "
                      "(OOB doğrulama bu tarama için kullanılamıyor).")
                if callable(globals().get("add_result")):
                    add_result("meta", {"stage": "oast",
                                        "status": "skipped:oob_registration_failed"})
                _oast_skipped = True  # döngüyü atla (ama init-fail DEĞİL)
            if ok_client and not _oast_skipped:
                _oast_done = 0
                for u in (_inj_endpoints if _oast_unlimited else _inj_endpoints[:20]):
                    _elapsed = time.time() - t
                    if _elapsed >= _oast_budget:
                        print(f"[i] OAST bütçesi ({int(_oast_budget)}s) doldu — "
                              f"{_oast_done} hedef tarandı, kalanlar atlandı.")
                        if callable(globals().get("add_result")):
                            add_result("meta", {"stage": "oast",
                                                "status": f"budget_exceeded:{int(_oast_budget)}s",
                                                "targets_scanned": _oast_done})
                        break
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
                    # Hedef başına timeout: per-call tavanı ile kalan bütçenin küçüğü.
                    _call_to = max(15.0, min(_oast_per_call, _oast_budget - _elapsed))
                    ok_oast, findings = _safe_call(run_oast_on_target, **fkw, call_timeout=_call_to)
                    _oast_done += 1
                    if ok_oast and findings:
                        for f in findings:
                            if callable(globals().get("add_result")):
                                add_result("oast", redact_sensitive(f))
                    elif not ok_oast and callable(globals().get("add_result")):
                        add_result("errors", {"stage": "oast", "url": u, "error": str(findings)})
            elif not ok_client:
                if callable(globals().get("add_result")):
                    add_result("errors", {"stage": "oast", "error": f"client_init_failed:{client}"})
            mark("oast", t)

        # ===================== SKORLAMA + RAPORLAMA (EN SON) =====================
        # Tüm taramalar (pasif/aktif/offensive/fuzz/OAST) bittikten SONRA tek
        # seferde skorla + raporla. Böylece rapor HER bulguyu kapsar ve program
        # "Tamamlandı" dediğinde gerçekten bitmiş olur.
        print("[•] Skorlama/Doğrulama (MD)…")
        t = mark("reporting")
        buckets = get_bucket_results()

        all_dicts = []
        for _k, _lst in (buckets or {}).items():
            if isinstance(_lst, list):
                for _it in _lst:
                    if isinstance(_it, dict):
                        all_dicts.append(_it)

        # OAST event'lerini TÜM kayıtlardan topla (filtrelemeden önce — event
        # taşıyan kayıt elensin istemeyiz).
        oast_events = []
        for _it in all_dicts:
            evs = _it.get("events")
            if isinstance(evs, list):
                for _ev in evs:
                    if isinstance(_ev, dict):
                        oast_events.append(_ev)

        # B3 FIX (saçmalayan kayıt): get_bucket_results() TÜM kovaları döndürür —
        # "errors", "meta", "oast" timeout kayıtları dahil. Eskiden bunların hepsi
        # skorlanıp `final`'e (ve SARIF/JUnit/results.json'a) sahte CVSS 6.1/Medium
        # ile giriyordu: 142 adet type'sız/severity'siz hayalet "bulgu" (ör.
        # {stage:oast, error:timeout}). HTML rapor bunları _has_label ile zaten
        # eliyordu ama makine-okur çıktılar kirleniyordu. Gerçek bulgu en az bir
        # kimlik alanı taşır (type/title/severity/name/vuln); taşımayan saf hata/
        # meta/timeout kayıtlarını skorlamadan önce ele.
        # Tutma kümesi HTML raporun _has_label filtresiyle (type/title/message)
        # hizalı — artı severity/name/vuln. Böylece rapor ile final/SARIF tutarlı:
        # raporun göstereceği hiçbir bulgu elenmez, kimliksiz hata/meta/timeout
        # kayıtları (message dahil hiçbir kimlik alanı yok) ise elenir.
        def _is_real_finding(it: dict) -> bool:
            return any(it.get(k) for k in ("type", "title", "message", "severity", "name", "vuln"))

        all_findings = [_it for _it in all_dicts if _is_real_finding(_it)]
        _n_dropped = len(all_dicts) - len(all_findings)
        if _n_dropped:
            _logger.debug(
                "[main] %d bulgu-olmayan kayıt (errors/meta/timeout) skorlamadan elendi",
                _n_dropped,
            )

        final = verify_and_score(all_findings, oast_events)

        # Plan B (B9): Evidence chain builder — correlate findings into attack chains
        if _PLAN_B_AVAILABLE and _EvidenceChainBuilder is not None and all_findings:
            try:
                _chain_builder = _EvidenceChainBuilder()
                _chain_builder.annotate_results(results)
                chains = results.get("attack_chains", [])
                if chains:
                    _logger.info(f"[PlanB/B9] Built {len(chains)} attack chains")
                    print(f"[B9] Attack chains: {len(chains)} correlation(s) found")
                    critical_chains = [c for c in chains if c.get("chain_severity") == "Critical"]
                    if critical_chains:
                        print(f"  [!!] Critical chains: {len(critical_chains)}")
                        for c in critical_chains[:3]:
                            print(f"      - {c['title']} (score={c['chain_score']})")
            except Exception as _cb_exc:
                _logger.debug(f"[PlanB] EvidenceChainBuilder error: {_cb_exc!r}")

        report_payload = dict(results)
        report_payload.update(get_bucket_results())
        report_payload.update(buckets)
        # Bucket'lardan nmap/tls/discovery verilerini açıkça al
        _bkts = get_bucket_results()
        report_payload.update({
            "meta": {
                "target": url,
                "mode": mode,
                "detailed": detailed,
            },
            "final": final,
            # 'final' burada verify_and_score'un ürettiği TAM konsolide listedir →
            # otoriter işaretle ki rapor katmanı (html_dashboard/_iter_findings) onu
            # tek-kaynak kabul edip ham kovalarla yeniden agregasyona gitmesin.
            "_final_authoritative": True,
            "phase_timings": results.get("phase_timings", {}),
            "crawl_summary": results.get("crawl_summary"),
            "security_headers_summary": results.get("security_headers_summary"),
            "port_scan_summary": results.get("port_scan_summary"),
            "discovery_summary": results.get("discovery_summary"),
            # Nmap: bucket veya results'tan
            "nmap": _bkts.get("nmap") or results.get("nmap") or results.get("port_scan") or [],
            # TLS: bucket veya results'tan; _e_table_tls_headers normalize eder
            "tls": _bkts.get("tls") or results.get("tls") or [],
            "tls_summary": results.get("tls_summary") or [],
            # Discovery: bucket'lardan
            "discovery": _bkts.get("discovery") or results.get("discovery") or [],
            "files_discovered": _bkts.get("files_discovered") or results.get("files_discovered") or [],
            # Plan B data
            "attack_chains": results.get("attack_chains") or [],
            "tech_profile": results.get("tech_profile") or {},
            "endpoint_priority_summary": results.get("endpoint_priority_summary") or {},
        })

        out = perform_reporting(session, cfg, report_payload)
        written = (out or {}).get("written", {})
        mark("reporting", t)

        # Rapor başarıyla üretildi → finally safety-net'in İKİNCİ kez raporlamasını
        # engelle (çift "Raporlama süreci" çıktısını önler).
        globals()["_REPORTING_DONE"] = True

        if driver is not None:
            quit_driver(driver)  # kapat + reaper kaydından düş
        s = session
        if s is not None:
            getattr(s, 'close', lambda: None)()
        print("\n[i] Tamamlandı.")
        print(
            # yazılan dosyalar ve webhook sonucunu içerir
            f"[i] Üretilen dosyalar: {json.dumps(written, ensure_ascii=False)}")


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
    # scan_modes modülü kaldırıldı — işlevsellik scan_runner.py içinde
    # hpm_bootstrap_from_file('config.json')

    # NOT: Eskiden burada bir config sihirbazı (cli.wizard.ConfigWizard, 10 adımlı
    # "ayar formu") ve ikinci/yinelenen bir ToolManager bloğu vardı. Banner'dan ÖNCE
    # çalışıp başlangıcı karıştırıyordu. Kaldırıldı — tüm başlangıç akışı (banner →
    # harici araç seçimi → Tor/proxy/auth) artık tek yerde, main() içinde:
    #   _print_banner() → _startup_phase() [ToolManager.ask_user_interactive] →
    #   setup_tor() / setup_auth() / setup_proxy().
    # Sihirbaza hâlâ `--wizard` flag'i ile erişilebilir (main() içinde, opt-in).
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Kullanıcı tarafından iptal edildi (Ctrl+C).")
    except Exception as e:
        print(f"\n[!] Kritik Hata: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Emergency Report Save — SADECE normal raporlama yapılmadıysa (Ctrl+C /
        # tarama ortası çökme). Normal akışta _run_scan_phases sonunda rapor zaten
        # üretildi (_REPORTING_DONE=True) → burada İKİNCİ kez raporlama yapma;
        # aksi halde kullanıcı "Tamamlandı" sonrası tekrar "Raporlama süreci" görür.
        _res = globals().get("results")
        _cfg = globals().get("cfg")
        if globals().get("_REPORTING_DONE"):
            pass  # rapor zaten kaydedildi, sessizce geç
        elif _res and _cfg:
            print("\n[!] Raporlama süreci (Safety Net)...")
            try:
                import websecure.core.reporting as _rep_safe
                # Merge bucket results (findings added during scan) into the payload
                # noinspection PyBroadException
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
    except Exception as exc:
        _logger.debug(f"[main] AlertManager.play_success hatası: {exc!r}")

    # Keep window open

    try:
        sys.stdout.write("\n[i] Cikmak icin Enter'a basin...\n")
        sys.stdout.flush()
        sys.stdin.readline()
    except (EOFError, KeyboardInterrupt, UnicodeDecodeError, OSError) as _fix_e:
        _logger.debug(f"[main] {type(_fix_e).__name__}: {_fix_e!r}")
