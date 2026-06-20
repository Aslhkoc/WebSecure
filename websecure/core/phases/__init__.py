from __future__ import annotations

# Sub-module re-exports (extracted from this monolith for future incremental splitting)
from websecure.core.phases._context import ScanMode, ScanContext  # noqa: F401
from websecure.core.phases._hprofile import (  # noqa: F401
    HProfilePolicy, HProfileManager,
    hpm, hpm_init_from_config, hpm_bootstrap_from_file,
    hpm_record_status, hpm_current_policy,
)

from websecure.core.utils import _ws_import_any, _ws_maybe_import_any
import concurrent.futures as _cf
import logging
import logging as _logging
import importlib
import importlib.util as _iul
import inspect
import json
import os
import socket
import ssl
import signal
import threading
import time as _t
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse
try:
    from websecure.core.reporting import _phase_rec
except ImportError:
    def _phase_rec(*_a, **_k): pass

# Global cancel event — set by SIGINT handler or external callers to stop the scan
_SCAN_CANCEL = threading.Event()

# Kayıtlı alt süreçler — (proc, phase_id) çiftleri olarak tutulur.
#   • Ctrl+C → _kill_all_children: HEPSİ öldürülür.
#   • Faz watchdog'la terk edildiğinde → kill_phase_children(phase): YALNIZ o
#     fazın hâlâ canlı süreçleri öldürülür. Böylece dalfox/ffuf/katana gibi
#     araçlar fazları bittikten sonra arka planda sızıp koşmaya devam etmez
#     ("araç görevini bitirip ölmeli; fazı aşan artık temizlenir"). Tam güç
#     KORUNUR: öldürme yalnız faz GERÇEKTEN bütçesini aştığında/iptalde olur.
_CHILD_PROCS: list = []          # list[tuple[proc, str]]
_CHILD_PROCS_LOCK = threading.Lock()


def _current_phase_tag() -> str:
    """Kayıt anındaki aktif faz id'si (alt süreci açan faz). Wrapper'lar faz
    thread'i içinde çalıştığından ACTIVE_PHASE doğru fazı verir."""
    try:
        from websecure.core.http import ACTIVE_PHASE
        return ACTIVE_PHASE.get() or ""
    except Exception:
        return ""


def register_child_proc(proc, phase: str = None) -> None:
    """Subprocess'i registry'e kaydet. phase verilmezse aktif fazdan alınır →
    faz terk edilince yalnız o fazın çocukları hedeflenebilsin."""
    tag = phase if phase is not None else _current_phase_tag()
    with _CHILD_PROCS_LOCK:
        _CHILD_PROCS.append((proc, tag))


def unregister_child_proc(proc) -> None:
    with _CHILD_PROCS_LOCK:
        _CHILD_PROCS[:] = [(p, t) for (p, t) in _CHILD_PROCS if p is not proc]


def _terminate_procs(procs) -> int:
    """Süreçleri nazikçe (terminate) sonra zorla (kill) sonlandır. Canlı olanı sayar."""
    procs = [p for p in procs if p is not None]
    killed = 0
    for p in procs:
        try:
            if p.poll() is None:
                p.terminate()
                killed += 1
        except Exception:
            pass
    if procs:
        import time as _time
        _time.sleep(0.5)
        for p in procs:
            try:
                if p.poll() is None:
                    p.kill()
            except Exception:
                pass
    return killed


def kill_phase_children(phase: str) -> int:
    """YALNIZ belirtilen fazın kayıtlı, hâlâ canlı alt süreçlerini öldür.
    Faz watchdog tarafından terk edildiğinde (veya iptalde) çağrılır →
    dalfox/ffuf/katana/httpx arka planda sızmaya devam etmez."""
    with _CHILD_PROCS_LOCK:
        procs = [p for (p, t) in _CHILD_PROCS if t == phase]
        _CHILD_PROCS[:] = [(p, t) for (p, t) in _CHILD_PROCS if t != phase]
    n = _terminate_procs(procs)
    if n:
        _logger.info("[phases] '%s' fazı terk edildi — %d artık alt süreç öldürüldü", phase, n)
    return n


def _kill_all_children() -> None:
    """Tüm kayıtlı alt süreçleri sonlandır (Ctrl+C)."""
    with _CHILD_PROCS_LOCK:
        procs = [p for (p, _t) in _CHILD_PROCS]
        _CHILD_PROCS.clear()
    _terminate_procs(procs)


def _install_sigint_handler():
    """Install SIGINT handler: 1. Ctrl+C → graceful stop + 5s force exit.
    2. Ctrl+C × 2 → anında çıkış."""
    if threading.current_thread() is not threading.main_thread():
        return
    try:
        def _handler(signum, frame):
            if _SCAN_CANCEL.is_set():
                # İkinci Ctrl+C → anında çık
                print("\n[!] Zorla çıkılıyor (os._exit)...")
                _kill_all_children()
                os._exit(1)

            print("\n[!] Ctrl+C — tarama durduruluyor... (tekrar basarsan anında çıkar)")
            _SCAN_CANCEL.set()
            _kill_all_children()

            # 8 saniye içinde program kendisi çıkmazsa zorla çık
            def _force_exit():
                import time as _t
                _t.sleep(8)
                if not _SCAN_CANCEL.is_set():
                    return
                print("\n[!] Zaman aşımı — program zorla kapatılıyor.")
                os._exit(0)

            _fe = threading.Thread(target=_force_exit, daemon=True)
            _fe.start()

        signal.signal(signal.SIGINT, _handler)
    except (OSError, ValueError) as _fix_e:
        _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")
from websecure.core.http import hardened_session
from websecure.core.reporting import add_result, redact_sensitive
# Safe imports for optional scanners
_rs = _ma = _jwt = _nq = _ws = _sx = _gql = _fu = None

try:
    from websecure.scanners import request_smuggling as _rs
except ImportError:
    pass

try:
    from websecure.scanners import mass_assignment as _ma
except ImportError:
    pass

try:
    from websecure.scanners import jwt as _jwt
except ImportError:
    pass

try:
    from websecure.scanners import nosqli as _nq
except ImportError:
    pass

try:
    from websecure.scanners import ws_fuzz as _ws
except ImportError:
    pass

try:
    from websecure.scanners import ssrf_xxe as _sx
except ImportError:
    pass


try:
    from websecure.scanners import graphql as _gql
except ImportError:
    pass


try:
    from websecure.scanners import file_upload as _fu
except ImportError:
    pass

# --- Yeni tarayıcı modülleri ---
_cmdi = _lfi = _cors = _st = _ss = _crlf = _wfp = None

try:
    from websecure.scanners import cmdi as _cmdi
except ImportError:
    pass

try:
    from websecure.scanners import lfi as _lfi
except ImportError:
    pass

try:
    from websecure.scanners import cors as _cors
except ImportError:
    pass

try:
    from websecure.scanners import subdomain_takeover as _st
except ImportError:
    pass

try:
    from websecure.scanners import session_scanner as _ss
except ImportError:
    pass

try:
    from websecure.scanners import crlf_injection as _crlf
except ImportError:
    pass

try:
    from websecure.core import waf_fingerprint as _wfp
except ImportError:
    pass

try:
    from websecure.crawler import WebCrawler
except ImportError:
    WebCrawler = None
_logger = _logging.getLogger(__name__)
_req_mod = importlib.import_module('requests') if _iul.find_spec('requests') is not None else None
requests = _req_mod  # alias; may be None

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

def _report_phase_error(_phase: str, _where: str, _err: BaseException) -> None:
    _rmod = None
    if _iul.find_spec('websecure.core.reporting') is not None:
        _rmod = importlib.import_module('websecure.core.reporting')
    elif _iul.find_spec('reporting') is not None:
        _rmod = importlib.import_module('reporting')
    if _rmod is not None and hasattr(_rmod, 'add_result'):
        _rmod.add_result("phase_error", {
            "type": "phase_error",
            "severity": "error",
            "message": str(_err),
            "target": _where or "",
            "meta": {
                "phase": _phase,
                "where": _where,
                "exc_type": _err.__class__.__name__,
            },
        })



def _importable(mod: str):
    try:
        import importlib.util as _iul
        return _iul.find_spec(mod) is not None
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [phases]', exc_info=True)
        _report_phase_error('phases', 'phases.py', e)
        return False


# =============================================================================
# TECH DETECTION ENGINE
# Detects CMS/framework/language/DB from HTTP headers, cookies, and body.
# Called BEFORE phase selection so tech_trigger logic fires correctly.
# =============================================================================

def _detect_technologies(resp) -> set:
    """
    Detect technologies from an HTTP response object.
    Returns a set of lowercase technology identifiers.
    """
    techs = set()
    if resp is None:
        return techs

    headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    body = ""
    try:
        body = (resp.text or "").lower()
    except (AttributeError, UnicodeDecodeError) as exc:
        _logger.debug(f"[phases] Response body decode skipped: {exc!r}")
    cookies_str = " ".join(headers.get("set-cookie", "").lower().split())

    # --- Server header ---
    server = headers.get("server", "")
    if "apache" in server:       techs.add("apache")
    if "nginx" in server:        techs.add("nginx")
    if "iis" in server:          techs.add("iis"); techs.add("windows")
    if "cloudflare" in server:   techs.add("cloudflare")
    if "lighttpd" in server:     techs.add("lighttpd")
    if "caddy" in server:        techs.add("caddy")
    if "tomcat" in server:       techs.add("tomcat"); techs.add("java")
    if "jetty" in server:        techs.add("jetty"); techs.add("java")

    # --- X-Powered-By ---
    xpb = headers.get("x-powered-by", "")
    if "php" in xpb:             techs.add("php")
    if "asp.net" in xpb.lower(): techs.add("aspnet"); techs.add("iis")
    if "express" in xpb.lower(): techs.add("nodejs"); techs.add("express")

    # --- Cookies ---
    if "phpsessid" in cookies_str:        techs.add("php")
    if "jsessionid" in cookies_str:       techs.add("java"); techs.add("tomcat")
    if "asp.net_sessionid" in cookies_str: techs.add("aspnet")
    if "laravel_session" in cookies_str:  techs.add("php"); techs.add("laravel")
    if "django" in cookies_str or "csrftoken" in cookies_str: techs.add("python"); techs.add("django")
    if "flask" in cookies_str or "session=" in cookies_str:   techs.add("python"); techs.add("flask")

    # --- CMS/Framework specific headers ---
    if "x-drupal-cache" in headers or "x-drupal-dynamic-cache" in headers:
        techs.add("drupal"); techs.add("php")
    if "x-pingback" in headers:
        techs.add("wordpress"); techs.add("php")
    xgen = headers.get("x-generator", "")
    if "wordpress" in xgen.lower(): techs.add("wordpress"); techs.add("php")
    if "drupal" in xgen.lower():    techs.add("drupal"); techs.add("php")
    if "joomla" in xgen.lower():    techs.add("joomla"); techs.add("php")

    # --- Body patterns ---
    if "wp-content" in body or "wp-includes" in body or "/wp-json/" in body:
        techs.add("wordpress"); techs.add("php")
    if "joomla" in body and ("option=com_" in body or "mosConfig" in body):
        techs.add("joomla"); techs.add("php")
    if "drupal" in body and ("drupal.settings" in body or "drupal.behaviors" in body):
        techs.add("drupal"); techs.add("php")
    if "laravel" in body or "_token" in body:
        if "php" not in techs and "laravel" in body:
            techs.add("laravel"); techs.add("php")
    if "react" in body and ("__reactfiber" in body or "react.development" in body or "_next" in body):
        techs.add("react")
    if "_next/static" in body or "next.js" in body:
        techs.add("nextjs"); techs.add("nodejs")
    if "nuxt" in body:             techs.add("nuxtjs"); techs.add("nodejs")
    if "angular" in body and ("ng-version" in body or "ng-app" in body):
        techs.add("angular")
    if "vue.js" in body or "vue.min.js" in body:
        techs.add("vue")
    if "django" in body:           techs.add("python"); techs.add("django")
    if "flask" in body and "werkzeug" in body: techs.add("python"); techs.add("flask")
    if "graphql" in body or "/graphql" in body or "graphiql" in body:
        techs.add("graphql")
    if "apollo" in body or "__apollo_client" in body or "relaystore" in body:
        techs.add("graphql")
    if "swagger" in body or "openapi" in body:
        techs.add("rest_api")
    if "/api/v" in body or "/api/" in body:
        techs.add("rest_api")
    # --- WebSocket / realtime signals ---
    if ("socket.io" in body or "ws://" in body or "wss://" in body
            or "new websocket(" in body or "websocket(" in body or "sockjs" in body):
        techs.add("websocket")

    # --- Content-type based ---
    ct = headers.get("content-type", "")
    if "application/json" in ct:   techs.add("rest_api")
    if "application/graphql" in ct: techs.add("graphql")
    # WebSocket upgrade advertised on the base response
    if "upgrade" in headers.get("connection", "").lower() and "websocket" in headers.get("upgrade", "").lower():
        techs.add("websocket")

    return techs


def _probe_attack_surface(sess, base_url: str) -> set:
    """
    Active attack-surface fingerprint — the part a single homepage GET CANNOT see.

    A REST API, a GraphQL endpoint or a WebSocket rarely link themselves from the
    landing page, so the homepage-only probe used to miss them and the Smart-Tactics
    tech-triggers (rest_api / graphql / websocket) never fired → tech-gated
    escalation (CMS/CVE payloads, NoSQL/JWT/GraphQL/WS suites) stayed generic. We
    now actively knock on a handful of high-signal endpoints. Bounded (short
    timeouts, all failures swallowed) so it stays a *quick* probe.
    """
    found: set = set()
    try:
        from urllib.parse import urljoin
    except Exception:
        return found

    # --- REST / OpenAPI ---
    for path in ("/api", "/api/v1", "/api/v2", "/swagger.json", "/openapi.json",
                 "/v2/api-docs", "/api/swagger.json", "/api-docs", "/rest"):
        try:
            r = sess.get(urljoin(base_url, path), timeout=6, allow_redirects=True)
            if int(getattr(r, "status_code", 0) or 0) >= 500:
                continue
            ct = (r.headers.get("content-type", "") or "").lower()
            snippet = (r.text[:2000] or "").lower()
            if "json" in ct or "swagger" in snippet or "openapi" in snippet or '"paths"' in snippet:
                found.add("rest_api")
                break
        except Exception as exc:
            _logger.debug(f"[TechProbe] api probe {path}: {exc!r}")

    # --- GraphQL: POST a tiny introspection query, look for a real GraphQL reply ---
    for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"):
        try:
            r = sess.post(urljoin(base_url, path),
                          json={"query": "{__typename}"}, timeout=6, allow_redirects=True)
            body = (r.text[:2000] or "").lower()
            # A GraphQL server answers __typename or returns a GraphQL-style errors array
            if "__typename" in body or ('"errors"' in body and "graphql" in body) \
                    or '"data"' in body and "__typename" in body:
                found.add("graphql")
                break
        except Exception as exc:
            _logger.debug(f"[TechProbe] graphql probe {path}: {exc!r}")

    return found


def _quick_tech_probe(ctx) -> set:
    """
    Makes a fast GET to the target + active attack-surface probes and populates
    ctx.technologies. Called at build_plan() time so _flag(tech_trigger=...) works.
    """
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return set()
    existing = getattr(ctx, "technologies", None)
    if existing:
        return set(existing)
    try:
        sess = getattr(ctx, "session", None) or hardened_session({})
        resp = sess.get(url, timeout=8, allow_redirects=True)
        techs = _detect_technologies(resp)
        # Active surface probing — makes rest_api/graphql/websocket triggers real.
        try:
            techs |= _probe_attack_surface(sess, url)
        except Exception as exc:
            _logger.debug(f"[TechProbe] attack-surface probe failed: {exc!r}")
        ctx.technologies = list(techs)
        if techs:
            _logger.info(f"[TechProbe] Detected: {', '.join(sorted(techs))}")
            add_result("meta", {"stage": "tech_probe", "technologies": list(techs), "url": url, "message": f"Tespit edilen teknolojiler: {', '.join(sorted(techs))}"})
        return techs
    except Exception as e:
        _logger.debug(f"[TechProbe] Quick probe failed: {e}")
        return set()

def _call_if_exists(modname: str, cand_funcs=("run","scan","main","execute"), *args, **kwargs) -> bool:
    try:
        mod = importlib.import_module(modname)
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [phases]', exc_info=True)
        _report_phase_error('phases', 'phases.py', e)
        return False
    fn = None
    for n in cand_funcs:
        fn = getattr(mod, n, None)
        if callable(fn):
            break
    if not callable(fn):
        return False
    fn(*args, **kwargs) if args or kwargs else fn()
    return True



def phase_waf_detect(ctx: dict):
    """
    Detect WAF before offensive scanning to choose bypass strategies.

    İki katmanlı tespit:
    1. WAFDetector (waf_bypass) — aktif prob + imza tabanlı tespit
    2. detect_waf_from_response() (analysis) — HTTP yanıtı analizi (fallback)
    """
    _ctx_get = ctx.get if hasattr(ctx, "get") else lambda k, d=None: getattr(ctx, k, d)
    target = _ctx_get("target") or _ctx_get("url") or ""
    if not target:
        return

    _waf_bypass_succeeded = False

    # --- Katman 1: WAFDetector (waf_bypass modülü) -----------------------
    try:
        from websecure.core.waf_bypass import WAFDetector
        session = _ctx_get("session") or hardened_session()
        detector = WAFDetector()
        profile = detector.detect(target, session=session)
        # Profile'ı ctx'e kaydet
        try:
            if isinstance(ctx, dict):
                ctx["waf_profile"] = profile
            else:
                ctx.waf_profile = profile
        except Exception as _fix_e:
            _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")
        # Bypass session oluştur
        try:
            from websecure.core.waf_bypass import build_bypass_session
            _bypass_sess = build_bypass_session(profile)
            try:
                if isinstance(ctx, dict):
                    ctx["bypass_session"] = _bypass_sess
                else:
                    ctx.bypass_session = _bypass_sess
            except Exception as _fix_e:
                _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")
        except (ImportError, AttributeError) as exc:
            _logger.debug(f"[phases] WAF bypass session unavailable: {exc!r}")
        add_result("waf", {
            "url": target,
            "target": target,
            "vendor": profile.vendor,
            "confidence": profile.confidence,
            "detected": profile.detected,
            "bypass_strategies": profile.bypass_strategies,
            "message": (
                f"WAF: {profile.vendor} (güven: {profile.confidence:.0%})"
                if profile.detected else "WAF tespit edilmedi"
            ),
        })
        if profile.detected:
            _logger.info(f"[phases] WAF detected: {profile.vendor} ({profile.confidence:.0%})")
        _waf_bypass_succeeded = True
    except Exception as _e1:
        _logger.debug(f"[phases] WAF detection (waf_bypass) skipped: {_e1}")

    # --- Katman 2: detect_waf_from_response() fallback (analysis.py) -----
    # waf_bypass başarısız veya WAF tespit edemediyse HTTP yanıtını analiz et
    if not _waf_bypass_succeeded:
        try:
            from websecure.core.analysis import detect_waf_from_response as _dwfr
            _sess = _ctx_get("session") or hardened_session()
            _resp = _sess.get(target, timeout=8, allow_redirects=True, verify=False)
            _waf = _dwfr(_resp)
            _conf = 0.75 if _waf.blocked else 0.0
            add_result("waf", {
                "url": target,
                "target": target,
                "vendor": _waf.vendor or ("Unknown" if _waf.blocked else "None"),
                "confidence": _conf,
                "detected": _waf.blocked,
                "bypass_strategies": [],
                "reasons": _waf.reasons,
                "message": (
                    f"WAF (response analysis): {_waf.vendor} — {', '.join(_waf.reasons)}"
                    if _waf.blocked else "WAF tespit edilmedi (response analysis)"
                ),
            })
            if _waf.blocked:
                _logger.info(
                    f"[phases] WAF detected via response analysis: "
                    f"{_waf.vendor} reasons={_waf.reasons}"
                )
                try:
                    if isinstance(ctx, dict):
                        ctx["waf_profile"] = _waf
                    else:
                        ctx.waf_profile = _waf
                except Exception as _fix_e:
                    _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")
        except Exception as _e2:
            _logger.debug(f"[phases] detect_waf_from_response fallback skipped: {_e2}")


def phase_discovery(ctx: dict):
    s = hardened_session()
    target = ctx.get("target") or ""
    if not target:
        return
    # trivial probe to ensure session works
    try:
        r = s.get(target, timeout=6, allow_redirects=True)
        add_result("discovery", {"severity":"info","message":f"Discovery touched: {target} ({r.status_code})","url":target})
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [phases]', exc_info=True)
        _report_phase_error('phases', 'phases.py', e)
        add_result("discovery", {"severity":"warning","message":f"Discovery failed: {e}","url":target})
    
    # [WS3] External Discovery Tools
    try:
        # FFUF
        if _get(ctx.get("config",{}), "offensive.ffuf.enabled", True):
             _runner_ffuf(ctx)
        
        # Feroxbuster
        if _get(ctx.get("config",{}), "offensive.feroxbuster.enabled", True):
             _runner_feroxbuster(ctx)
    except Exception as e:
        _logger.warning(f"External discovery tool failed: {e}")


def _phase_httpx_port_fallback(ctx, host: str) -> None:
    """
    Nmap yokken devreye giren Python-native port scanner.
    Top-1000 TCP portu tarar, banner grabbing + servis tespiti yapar.
    """
    import socket as _socket
    import concurrent.futures as _cf
    import ssl as _ssl

    # Top-1000 en yaygın TCP portları
    _TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443, 8888, 8000, 8008, 8081, 8082,
        8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8443, 8888, 9090,
        9200, 9300, 4443, 4080, 3000, 4000, 5000, 5001, 5432, 5984, 6379,
        6443, 7001, 7002, 7080, 7443, 9000, 9001, 9002, 9003, 9080, 9443,
        10000, 10443, 11211, 27017, 27018, 28017, 50000, 50070,
        # SSH/FTP/Telnet/SMTP
        20, 69, 79, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        102, 104, 109, 119, 123, 137, 138, 161, 162, 179, 194,
        389, 427, 465, 512, 513, 514, 515, 543, 544, 548, 554,
        587, 631, 636, 646, 873, 990, 992, 1080, 1194, 1433, 1434,
        1521, 1723, 2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
        2181, 2375, 2376, 2377, 2379, 2380, 3128, 3268, 3269, 3306,
        4040, 4848, 5000, 5006, 5007, 5044, 5060, 5061, 5601, 5672,
        5900, 5985, 5986, 6000, 6001, 6080, 6443, 6514, 7077, 7474,
        8161, 8888, 9042, 9060, 9092, 9418, 9999, 10250, 10255, 15672,
        18080, 18081, 25672, 32400, 49152, 49153, 49154, 49155,
    ]

    # Servis tahmin tablosu (port → isim)
    _SVC = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
        139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
        445: "microsoft-ds", 587: "smtp", 993: "imaps", 995: "pop3s",
        1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
        2375: "docker", 2376: "docker-tls", 3000: "http-alt",
        3306: "mysql", 3389: "rdp", 4443: "https-alt", 4848: "glassfish",
        5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc",
        5984: "couchdb", 5985: "winrm", 5986: "winrm-tls",
        6379: "redis", 7001: "weblogic", 8080: "http-proxy",
        8161: "activemq", 8443: "https-alt", 8888: "http-alt",
        9000: "http-alt", 9042: "cassandra", 9092: "kafka",
        9200: "elasticsearch", 9300: "elasticsearch-node",
        9418: "git", 11211: "memcached", 15672: "rabbitmq-mgmt",
        27017: "mongodb", 27018: "mongodb", 28017: "mongodb-http",
        50070: "hadoop-namenode",
    }

    _HTTPS_PORTS = {443, 8443, 4443, 9443, 7443, 6443, 2083, 2087, 2096, 5986}

    def _grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
        """TCP banner grabbing."""
        try:
            with _socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                try:
                    data = s.recv(1024)
                    return data.decode("utf-8", errors="replace")[:200].strip()
                except Exception:
                    return ""
        except Exception:
            return ""

    def _probe_port(port: int):
        """Tek portu tara, açıksa bulgu döndür."""
        try:
            with _socket.create_connection((host, port), timeout=1.5):
                pass
        except (ConnectionRefusedError, _socket.timeout, OSError):
            return None
        except Exception:
            return None

        svc = _SVC.get(port, "unknown")
        is_https = port in _HTTPS_PORTS
        banner = ""

        # Banner grabbing (sadece bazı servisler için)
        if svc not in ("http", "https", "https-alt", "http-proxy", "http-alt"):
            banner = _grab_banner(host, port)

        # HTTP/HTTPS probe
        http_info = {}
        if svc in ("http", "https", "http-alt", "https-alt", "http-proxy") or port in _HTTPS_PORTS or port == 80:
            session = hardened_session({})
            scheme = "https" if is_https else "http"
            try:
                r = session.get(f"{scheme}://{host}:{port}/", timeout=4,
                                allow_redirects=False, verify=False)
                http_info = {
                    "status": r.status_code,
                    "server": r.headers.get("Server", ""),
                    "title": "",
                }
                from bs4 import BeautifulSoup as _BS
                try:
                    soup = _BS(r.text[:4096], "html.parser")
                    t = soup.find("title")
                    if t:
                        http_info["title"] = t.get_text(strip=True)[:100]
                except Exception as _fix_e:
                    _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")
                if svc == "unknown":
                    svc = scheme
            except Exception as _fix_e:
                _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")

        severity = "info"
        # Kritik servisler için severity yükselt
        if svc in ("ssh", "ftp", "telnet", "rdp", "vnc", "redis",
                   "mongodb", "memcached", "elasticsearch", "docker"):
            severity = "medium"

        detail = banner or (f"HTTP {http_info.get('status','')} — {http_info.get('server','')} — {http_info.get('title','')}" if http_info else "")
        return {
            "severity": severity,
            "message": f"Açık port: {port}/tcp ({svc})" + (f" — {detail[:120]}" if detail.strip() else ""),
            "host": host,
            "port": port,
            "proto": "tcp",
            "service": svc,
            "state": "open",
            "banner": banner[:200],
            "http_info": http_info,
            "scripts": {},
            "source": "python-portscan",
        }

    print(f"[PortScan/Python] {host} — {len(_TOP_PORTS)} port taranıyor…")
    open_ports = []
    with _cf.ThreadPoolExecutor(max_workers=150) as ex:
        futures = {ex.submit(_probe_port, p): p for p in _TOP_PORTS}
        for fut in _cf.as_completed(futures):
            result = fut.result()
            if result:
                open_ports.append(result)
                add_result("nmap", result)

    print(f"[PortScan/Python] Tamamlandı — {len(open_ports)} açık port bulundu.")


def phase_portscan(ctx: dict):
    """
    Nmap port taraması.
    Tarama modu config'deki scan_profile'a göre otomatik seçilir:
      STEALTH  -> stealth mod (SYN -T2)
      NORMAL   -> standard (servis+script)
      AGGRESSIVE -> deep (OS+script+aggressive)
    """
    nmap_cfg = ctx.get("config", {}).get("nmap", {}) or {}
    if not nmap_cfg.get("enabled", True):
        add_result("meta", {"stage": "portscan", "severity": "note", "message": "nmap disabled"})
        return

    from websecure.integrations.nmap import NmapWrapper
    host = ctx.get("host")
    if not host:
        u = ctx.get("url") or ctx.get("target") or ""
        if u:
            host = _host_from_url(u)
    if not host:
        return

    nmap = NmapWrapper()
    if not nmap.is_available():
        add_result("meta", {"stage": "portscan", "severity": "warning", "message": "Nmap binary bulunamadı — httpx fallback ile HTTP portları taranıyor."})
        _phase_httpx_port_fallback(ctx, host)
        return

    # Mode selection: _nmap config > scan_profile
    _cfg_top = ctx.get("config") or {}
    _nmap_profile = _cfg_top.get("_nmap", {})
    nmap_mode = nmap_cfg.get("mode") or _nmap_profile.get("mode")
    if not nmap_mode:
        scan_profile = str(_cfg_top.get("scan_profile", "NORMAL")).upper()
        nmap_mode = {"STEALTH": "stealth", "NORMAL": "standard", "AGGRESSIVE": "deep"}.get(scan_profile, "standard")

    # Port override
    ports_cfg = nmap_cfg.get("ports", [])
    ports_arg = ",".join(map(str, ports_cfg)) if ports_cfg else None

    # Extra args: config + profil ek argümanları
    extra_args = list(nmap_cfg.get("arguments", []))
    extra_args += _nmap_profile.get("extra_args", [])

    # Vuln script mode if explicitly configured
    vuln_mode = nmap_cfg.get("vuln_scripts", False)
    if vuln_mode:
        extra_args = extra_args + ["--script", "vuln,auth,default", "--script-timeout", "30s"]

    # Akıllı port tarama stratejisi: hedefe göre mod seç
    import socket as _socket
    try:
        resolved_ip = _socket.gethostbyname(host)
        # RFC-1918 private ranges: 10.x.x.x, 172.16–31.x.x, 192.168.x.x
        _parts = resolved_ip.split(".")
        _second = int(_parts[1]) if len(_parts) >= 2 else 0
        _private = (
            resolved_ip.startswith("10.") or
            resolved_ip.startswith("192.168.") or
            (resolved_ip.startswith("172.") and 16 <= _second <= 31)
        )
        if _private and nmap_mode == "aggressive":
            nmap_mode = "deep"  # iç ağda aggressive çok gürültülü
    except Exception:
        resolved_ip = None

    _nmap_proxy = _cfg_top.get("_tor_proxy")

    # [CDN/origin] CDN/WAF arkasındaysa nmap edge'i tarar → origin'i keşfetmeye
    # çalış; bulunursa origin'i tam güç tara, bulunamazsa port taramasını
    # 80/443 ile sınırla (tüm port taraması CDN üzerinde anlamsızdır).
    _scan_target = host
    try:
        from websecure.integrations.nmap import assess_cdn_origin
        _do_origin = bool(nmap_cfg.get("origin_discovery", True))
        _cdn = assess_cdn_origin(host, url=ctx.get("url") or ctx.get("target"),
                                 do_origin_discovery=_do_origin)
        add_result("nmap_recon", _cdn)
        if _cdn.get("is_cdn"):
            add_result("meta", {"stage": "portscan", "severity": "note",
                                "message": _cdn.get("note", "")})
            if _cdn.get("origin_ip") and _cdn.get("origin_verified"):
                _scan_target = _cdn["origin_ip"]
                _logger.info(f"[Nmap] CDN bypass — gerçek origin taranıyor: {_scan_target}")
            elif _cdn.get("limit_ports") and nmap_cfg.get("cdn_limit_to_web", True):
                ports_arg = _cdn["limit_ports"]
                _logger.info(f"[Nmap] CDN edge — port taraması {ports_arg} ile sınırlandı")
    except Exception as _ce:
        _logger.debug(f"[Nmap] CDN/origin değerlendirmesi atlandı: {_ce!r}")

    _logger.info(f"[Nmap] Tarama modu: {nmap_mode}, hedef: {_scan_target}")
    res = nmap.scan(_scan_target, ports=ports_arg, mode=nmap_mode, extra_args=extra_args or None, proxy=_nmap_proxy)

    # Store OS guess in ctx for use by other phases
    os_guesses = list({item["os_guess"] for item in res if item.get("os_guess")})
    if os_guesses and isinstance(ctx, dict):
        ctx.setdefault("os_guess", os_guesses[0])

    for item in res:
        p = item.get("port")
        if not p:
            continue
        svc = item.get("service", "?")
        product = item.get("product", "")
        version = item.get("version", "")
        scripts = item.get("scripts", {})
        add_result("nmap", {
            "severity": "info",
            "message": f"Açık port: {p}/{item.get('protocol', 'tcp')} ({svc} {product} {version})".strip(),
            "host": item.get("ip") or item.get("hostname") or host,
            "port": p,
            "proto": item.get("protocol", "tcp"),
            "service": svc,
            "product": product,
            "version": version,
            "cpe": item.get("cpe", []),
            "os_guess": item.get("os_guess", ""),
            "scripts": scripts,
            "state": "open",
        })
        # Flag interesting services for deeper scanning
        if svc in ("http", "https", "http-alt", "http-proxy"):
            ctx_techs = getattr(ctx, "technologies", None)
            if isinstance(ctx_techs, list) and "web" not in ctx_techs:
                ctx_techs.append("web")
        # Flag script findings as separate results
        for script_id, script_out in scripts.items():
            if script_out and any(kw in script_out.lower() for kw in ("vuln", "vulnerable", "cve-", "exploit")):
                add_result("vulnerability", {
                    "severity": "high",
                    "tool": "nmap-nse",
                    "script": script_id,
                    "host": host,
                    "port": p,
                    "evidence": script_out[:500],
                })

    # ctx["results"] ile de senkronize et (finalize_reports okuyabilsin)
    port_records = []
    for item in res:
        p = item.get("port")
        if not p:
            continue
        port_records.append({
            "host": item.get("ip") or item.get("hostname") or host,
            "port": p,
            "proto": item.get("protocol", "tcp"),
            "service": item.get("service", ""),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
            "state": "open",
            "scripts": item.get("scripts", {}),
            "cpe": item.get("cpe", []),
            "os_guess": item.get("os_guess", ""),
        })
    if isinstance(ctx, dict) and port_records:
        ctx_results = ctx.setdefault("results", {})
        ctx_results["nmap"] = port_records
        ctx_results["port_scan"] = port_records

    if not res:
        add_result("meta", {"stage": "portscan", "severity": "note", "message": "Açık port bulunamadı (Nmap)."})

def phase_tls(ctx: dict):
    url = ctx.get("url") or ctx.get("target", "")
    try:
        from websecure.scanners.tls import scan_tls
        tls_result = scan_tls(url, session=ctx.get("session"), config=ctx.get("config", {}))
        if tls_result:
            # Store certificate details under "tls" bucket for the dashboard
            add_result("tls", tls_result)
            # Also push any TLS findings (weak protocols/ciphers) to "offensive"
            for finding in tls_result.get("new_findings", []):
                add_result("offensive", finding)
    except ImportError:
        add_result("tls", {"severity": "note", "message": "tls scanner not present; skipped"})
    except Exception as e:
        add_result("tls", {"severity": "warning", "message": f"TLS scan error: {e}"})

def phase_sec_headers(ctx: dict):
    url = ctx.get("url") or ctx.get("target") or ""
    session = ctx.get("session") or hardened_session({})
    if not _call_if_exists("websecure.scanners.infrastructure", ("run", "scan_tls", "scan"),
                           url, session=session, results=ctx.get("results", {})):
        add_result("security_headers", {"severity": "note", "message": "security_headers scanner not present; skipped"})

def phase_offensive(ctx: dict):
    add_result('offensive', {'severity': 'note', 'message': 'offensive_gate_applied'})
    cfg = ctx.get("config", {}) if isinstance(ctx, dict) else getattr(ctx, "config", {}) or {}
    if not (cfg.get("offensive", {}) or {}).get("enabled", True):
        add_result("offensive", {"severity": "note", "message": "offensive disabled"})
        return

    url = ctx.get("url") or ctx.get("target") or ""
    session = ctx.get("session") or hardened_session({})
    results = ctx.get("results") or {}

    hit = 0

    def _safe_run(label: str, fn):
        nonlocal hit
        try:
            fn()
            hit += 1
        except Exception as _e:
            _logger.warning(f"[phases] {label} error: {_e}")
            _report_phase_error("offensive", label, _e)

    # --- Faz 7: httpx probe before scanners (enriches ctx.technologies) ---
    _safe_run("httpx_probe", lambda: _runner_httpx_probe(ctx))

    # --- Scanners with standard (url, session=, results=, ...) signature ---
    _url_first = [
        "websecure.scanners.request_smuggling",
        "websecure.scanners.mass_assignment",
        "websecure.scanners.jwt",
        "websecure.scanners.ws_fuzz",
        "websecure.scanners.graphql",
        "websecure.scanners.csrf",
        "websecure.scanners.passive_recon",
        "websecure.scanners.sqli",
        "websecure.scanners.xss",
        "websecure.scanners.auth_scanners",
        "websecure.scanners.ssti",
        "websecure.scanners.idor",
        "websecure.scanners.js_analyzer",
        # Yeni entegre edilen tarayıcılar
        "websecure.scanners.cmdi",
        "websecure.scanners.lfi",
        "websecure.scanners.cors",
        "websecure.scanners.subdomain_takeover",
        "websecure.scanners.crlf_injection",
        "websecure.scanners.session_scanner",
        # Faz 3 — bağlı olmayan scanner'lar
        "websecure.scanners.prototype_pollution",
        "websecure.scanners.headers",
        "websecure.scanners.race_condition",
        # Faz 20 — yeni eklenen kapsamlı tarayıcılar
        "websecure.scanners.clickjacking",
        "websecure.scanners.param_pollution",
        "websecure.scanners.bypass_403",
        "websecure.scanners.business_logic",
    ]
    for m in _url_first:
        label = m.rsplit(".", 1)[-1]
        _safe_run(label, lambda _m=m: _call_if_exists(
            _m, ("run", "scan", "main", "execute"), url,
            session=session, results=results, cfg=cfg))

    # --- ctx-first scanners (nosqli, ssrf_xxe already have run(ctx)) ---
    for m in ("websecure.scanners.nosqli", "websecure.scanners.ssrf_xxe"):
        label = m.rsplit(".", 1)[-1]
        _safe_run(label, lambda _m=m: _call_if_exists(
            _m, ("run", "scan", "main", "execute"), ctx))

    # --- owasp: run(session, base_url, config, ...) ---
    _safe_run("owasp", lambda: __import__(
        "websecure.scanners.owasp", fromlist=["run"]
    ).run(session, url, config=cfg, debug=False))

    # --- file_upload: run(session, endpoints, results, ...) ---
    if _fu:
        _safe_run("file_upload", lambda: _fu.run(
            session,
            list(results.get("endpoints") or [url]) or [url],
            results,
            base_url=url,
        ))

    # --- open_redirect: run(target, cfg, session, urls, results) ---
    _safe_run("open_redirect", lambda: _call_if_exists(
        "websecure.scanners.open_redirect",
        ("run", "scan"),
        url, cfg, session, [], results))

    # --- waf_fingerprint: WAFFingerprinter class interface ---
    if _wfp:
        def _waf_fp_call():
            fp_cls = getattr(_wfp, "WAFFingerprinter", None)
            if callable(fp_cls):
                report = fp_cls().fingerprint(url, session=session)
                if report:
                    add_result("waf", {
                        "url": url,
                        "vendor": getattr(report, "vendor", "unknown"),
                        "confidence": getattr(report, "confidence", 0.0),
                        "detected": getattr(report, "detected", False),
                    })
        _safe_run("waf_fingerprint", _waf_fp_call)

    if not hit:
        add_result("offensive", {"severity": "note", "message": "no offensive modules found"})

    # [WS3] External Tools Execution (Sqlmap)
    try:
        if (cfg.get("offensive", {}).get("sqlmap", {}).get("enabled", True)):
            _runner_sqlmap(ctx)
    except Exception as _e:
        _logger.warning(f"[phases] sqlmap runner error: {_e}")
        _report_phase_error("sqlmap", "phases.phase_offensive.sqlmap", _e)

    # --- Faz 7: dalfox verify after all XSS scanners ---
    _safe_run("dalfox_verify", lambda: _runner_dalfox_verify(ctx))


"""
Koşul bazlı AMA görünür (visible) fazlar:
 - SSRF/XXE
 - HTTP Request Smuggling
 - Mass Assignment
 - NoSQL Injection
 - File Upload abuse
 - JWT manipülasyonları
 - WebSocket fuzz
 - GraphQL saldırı seti

Notlar
------
* Bu dosya build_plan(ctx) içinde fazları, config'e göre `enabled`/`disabled` kararını
  vererek ama her durumda **görünür** şekilde plana ekler.
* Her fazın `runner`'ı aynı imzaya sahiptir: runner(ctx) -> None
  (Hataları kendisi raporlar; plan akışını bozmaz. İstisnalar yutulmaz.)
* `ctx` için beklenen minimal alanlar:
    - ctx.url            (str)  : hedef temel URL
    - ctx.session        (requests.Session) : ortak oturum
    - ctx.config         (dict) : yapılandırma
    - ctx.results        (dict) : (opsiyonel) sonuç kovası
    - ctx.debug          (bool) : (opsiyonel) hata ayıklama
"""
_reporting_mod = None  # module-level sentinel — resolved lazily by get_results()


def get_results() -> dict:
    """Return the central results bucket if available, else an empty dict.
    Prefers core.reporting.get_results when present.
    """
    global _reporting_mod
    mod = _reporting_mod
    if mod is None:
        try:
            if _iul.find_spec("websecure.core.reporting") is not None:
                import importlib as _im
                mod = _im.import_module("websecure.core.reporting")
                _reporting_mod = mod
            elif _iul.find_spec("reporting") is not None:
                import importlib as _im
                mod = _im.import_module("reporting")
                _reporting_mod = mod
        except Exception as _fix_e:
            _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")
    fn = getattr(mod, "get_results", None) if mod is not None else None
    if callable(fn):
        try:
            val = fn()
            return val if isinstance(val, dict) else {}
        except Exception:
            return {}
    # Fallback: no global results provider
    return {}

# ----------------------------- Yardımcılar (no try/except) -----------------------------


def _opt_import(module: str, attr: Optional[str] = None):
    fulls = []
    if isinstance(module, str) and module:
        if '.' in module:
            fulls.append(module)
        else:
            fulls.extend((f'websecure.core.{module}', module))
    mod = _ws_maybe_import_any(*fulls) if fulls else None
    if not mod:
        return None
    return getattr(mod, attr) if isinstance(attr, str) and attr else mod

def _resolve_module(primary: str, fallbacks: List[str] | None = None):
    """Önce tam paket adı, sonra fallbackler, en sonda düz modül ismi."""
    cands = [primary] + list(fallbacks or []) + [primary.rsplit(".", 1)[-1]]
    for m in cands:
        mod = _opt_import(m)
        if mod:
            return mod
    _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return_none')

    return None
def _get(cfg: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = cfg
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur

def _deep_get(d: object, path: str, default=None):
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur

def _filter_kwargs(fn: Callable, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """fn imzasına göre kwargs filtrele (TypeError yakalamadan uyum)."""
    params = inspect.signature(fn).parameters
    return {k: v for k, v in kwargs.items() if k in params}

def _ensure_results_bucket(ctx: Any) -> Dict[str, Any]:
    bucket = getattr(ctx, "results", None)
    if not isinstance(bucket, dict):
        setattr(ctx, "results", {})
        bucket = ctx.results
    return bucket


def _merge_results(ctx: Any, res: Any) -> None:
    """Merge a scanner result dict into ctx.results (safe, no-op on bad input)."""
    if not isinstance(res, dict):
        return
    ctx_results = getattr(ctx, "results", None)
    if not isinstance(ctx_results, dict):
        return
    for key, val in res.items():
        if isinstance(val, list):
            ctx_results.setdefault(key, []).extend(val)
        elif isinstance(val, dict):
            existing = ctx_results.get(key)
            if isinstance(existing, dict):
                existing.update(val)
            else:
                ctx_results[key] = val
        else:
            ctx_results[key] = val

def _host_from_url(u: str) -> str:
    try_netloc = urlparse(u or "").netloc
    return (try_netloc.split(":")[0] or "").lower()

# ----------------------------- Kritik hata işaretleme (no try/except) -----------------------------

def set_critical_error(ctx: Any, reason: str) -> None:
    if not hasattr(ctx, "shared") or not isinstance(ctx.shared, dict):
        setattr(ctx, "shared", {})
    ctx.shared["critical_error"] = reason or True
    add_result("errors", {"stage": "critical", "reason": reason})

def clear_critical_error(ctx: Any) -> None:
    if hasattr(ctx, "shared") and isinstance(ctx.shared, dict):
        ctx.shared.pop("critical_error", None)

# ----------------------------- Faz çalıştırma izolasyonu (no try/except) -----------------------------

# Per-phase timeout overrides. Phases not listed here use _DEFAULT_PHASE_TIMEOUT.
# Timeouts are intentionally tight — aggressive mode must finish in a reasonable time.
_PHASE_TIMEOUTS: Dict[str, int] = {
    # ── Heavy external tools ───────────────────────────────────────────────
    "port_scan":         2700,   # nmap two-stage aggressive=25min, stealth T1=45min
    "portscan":          2700,
    "sqlmap":             600,   # time-based blind SQL injection
    "passive_recon":      600,   # OSINT APIs + DNS + cert lookups
    "amass":              600,
    "nuclei":             480,   # many templates
    "subdomain":          480,
    "owasp_and_nuclei":   480,
    "feroxbuster":        420,   # recursive dir brute-force
    "ffuf":               480,   # content + file fuzzing (stealth'te _safe() 3x uygular)
    # ── Crawlers / probers ─────────────────────────────────────────────────
    "discovery":          240,
    "katana":             180,
    "browser_crawler":    180,
    "js_analysis":        150,
    "httpx_probe":        120,
    # ── Active injection scanners (have their own internal budgets) ────────
    "ssti":               260,   # internal _SCAN_BUDGET_S = 240s
    "xss":                240,
    "dalfox_verify":      180,
    "nosqli":              90,   # internal JS_PHASE_BUDGET = 25s
    "idor":                90,
    "sqli":               120,
    # ── Medium active scanners ─────────────────────────────────────────────
    "csrf":               120,
    "lfi":                120,
    "cmdi":               120,
    "xxe":                120,
    "ssrf":               120,
    "jwt":                120,
    "dom_xss":            120,
    "races":              120,
    "race_condition":     120,
    "mass_assignment":    120,
    "polyglot_probe":     120,   # values.txt polyglot surface triage
    "auth_matrix":        120,
    "prototype_pollution": 90,
    "scanners.ssrf_xxe":  120,
    "scanners.request_smuggling": 120,
    "scanners.graphql":    90,
    "scanners.graphql_attacks": 90,
    "scanners.ws_fuzz":    90,
    "scanners.file_upload": 90,
    "scanners.tls":        90,
    # ── Fast / light scanners ──────────────────────────────────────────────
    "waf_detect":          60,
    "waf_fingerprint":     60,
    "headers_scanner":     90,
    "session_scanner":     90,
    "cors":                90,
    "crlf_injection":      90,
    "open_redirect":       90,
    "subdomain_takeover":  90,
    "session_analysis":    60,
    "human_adapter":       30,
    "verify_and_score":    60,
    "reporting":           60,
    "exploit_orchestrator": 120,
}
_DEFAULT_PHASE_TIMEOUT = 120  # 2 min default (was 5 min — too long for light scanners)

# Phases whose watchdog stays UNLIMITED under no_timeout. These are legitimately
# long recon/offensive tools that may run a long time but make steady progress;
# abandoning them mid-work would defeat the user's "full power" intent (nmap
# özellikle: anonimlik/zaman için kısıtlanmaz). Their subprocesses are still
# bounded by effective_timeout (generous-finite), so even these cannot hang the
# scan forever — we only avoid prematurely abandoning a phase that IS progressing.
# Every OTHER phase gets a generous-but-finite watchdog under no_timeout so a hung
# in-process await auto-advances instead of freezing until the user hits Ctrl+C.
_NO_TIMEOUT_UNBOUNDED_PHASES: set = {
    "port_scan", "portscan",          # nmap — full-power priority
    # NOT: "sqlmap" KASITLI ÇIKARILDI (kullanıcı talebi 2026-06-15) — sqlmap artık
    # FİRM zaman bütçesiyle sınırlı (_resolve_sqlmap_budget); no_timeout modunda bile
    # sınırsız koşmaz. Gücü kısılmaz (level/risk/threads/tamper aynen), yalnız toplam
    # süresi tavanlanır → tarama her zaman biter ve raporunu yazar.
    "nuclei", "owasp_and_nuclei",
    "amass", "subdomain", "passive_recon",
}
# Watchdog failsafe = configured × this (min 600s) for non-unbounded phases when
# no_timeout is on. Large on purpose: only a genuine hang trips it.
_NO_TIMEOUT_WATCHDOG_FACTOR = 6

# ---------------------------------------------------------------------------
# STAGED + BACKGROUND execution model (Madde 4 — Adım B)
# ---------------------------------------------------------------------------
# Eski katı `_PARALLEL_GROUPS` (gruplar SIRALI; bağımsız-yavaş iş tüm taramayı
# serileştiriyordu — amass en başta crawl'ı, sqlmap/port en sonda offensive'i
# bekletiyordu) yerine bağımlılık-farkında model:
#
#   • DEPENDENT ZİNCİR aşamalı koşar (sıra korunur):
#       Aşama 0: waf_detect (profil)  →  Aşama 1: keşif/crawl (forms_meta+endpoint)
#       →  Aşama 2: saldırı (offensive — keşif sonuçlarını TÜKETİR)
#       →  Aşama 3: finalizer'lar (exploit/oast/skorlama/rapor — TÜM bulguları okur)
#   • BACKGROUND (bağımsız) fazlar EN BAŞTA başlar ve TÜM aşamalarla ÖRTÜŞÜR;
#     finalizer'lardan ÖNCE join edilir. Ana duvar-saati kazancı buradan gelir.
#
# Birleşik istek hacmi global AIMD admission gate (Adım A, core/http.py) ile
# sağlıklı tutulur → bağımsız fazları erkenden başlatmak hedefi dövmez.
#
# Sınıflandırılmamış HER etkin faz güvenli varsayılan olarak Aşama 2'ye düşer
# (catch-all) → hiçbir faz sessizce atlanmaz.

# Aşama 0 — WAF tespiti (hızlı, profili kurar; offensive payload seçimini etkiler)
_STAGE_WAF: List[str] = ["waf_detect"]

# Aşama 1 — keşif/crawl: offensive'in tükettiği endpoint + forms_meta yüzeyini üretir
_STAGE_DISCOVERY: List[str] = [
    "katana", "browser_crawler", "discovery", "http_crawler_orchestrator",
    "session_analysis", "js_analysis", "httpx_probe", "fuzz_param_discovery",
]

# BACKGROUND — dependent zincirden BAĞIMSIZ; baştan başlar, her aşamayla örtüşür,
# finalizer'lardan önce join edilir. (amass subdomain.py içinden çağrılır.)
_BACKGROUND_PHASES: List[str] = [
    "subdomain", "passive_recon", "port_scan", "sqlmap",
    "nuclei", "ffuf", "feroxbuster",
]

# Aşama 3 — finalizer'lar: TÜM bulgular (background dahil) tamamlandıktan SONRA,
# SIRAYLA koşar (exploit found-vuln'leri sömürür → oast OOB doğrular → skorla → rapor).
_FINALIZER_PHASES: List[str] = [
    "exploit_orchestrator", "oast_verification", "verify_and_score", "reporting",
]

# Aşama 2 (saldırı) = bu sınıflara girmeyen TÜM etkin fazlar (catch-all).
_NON_OFFENSIVE_PHASES: set = (
    set(_STAGE_WAF) | set(_STAGE_DISCOVERY) | set(_BACKGROUND_PHASES) | set(_FINALIZER_PHASES)
)

# Aşama-içi ve background havuz genişlikleri (gerçek istek throttle'ı AIMD gate'tir;
# bunlar yalnız thread/bellek baskısını sınırlar).
_STAGE_MAX_WORKERS = 8
_BACKGROUND_MAX_WORKERS = 6

# Faz ÖNCELİĞİ (Madde 4 — Adım D). Bir aşama içindeki fazlar bu ağırlığa göre
# (YÜKSEK önce) gönderilir → yüksek-değerli/yüksek-severity scanner'lar havuz
# slotlarını ilk kapar. Tarama erken kesilirse (global deadline / Ctrl+C) en
# değerli bulgular ÖNCE elde edilmiş olur. Sıralama yalnız gönderim sırasını
# etkiler (eşzamanlı koşum + AIMD throttle aynı); doğruluk etkisi yoktur.
_PHASE_PRIORITY: Dict[str, int] = {
    # RCE / kritik etki sınıfı
    "cmdi": 95, "ssti": 95, "lfi": 92, "ssrf": 92, "xxe": 90,
    "scanners.ssrf_xxe": 92, "scanners.file_upload": 90,
    "scanners.request_smuggling": 88,
    # Yüksek-etki enjeksiyon / erişim kontrolü
    "xss": 85, "nosqli": 85, "jwt": 84, "idor": 84, "auth_matrix": 84,
    "authorization_matrix": 84, "mass_assignment": 82, "open_redirect": 80,
    "crlf_injection": 80, "prototype_pollution": 80, "cors": 78,
    "scanners.graphql": 78, "scanners.graphql_attacks": 78,
    "races": 76, "race_condition": 76, "dom_xss": 75,
    # Orta
    "scanners.tls": 55, "scanners.ws_fuzz": 55, "param_pollution": 55,
    "business_logic": 55, "clickjacking": 50, "waf_bypass_validate": 50,
    "human_adapter": 50, "subdomain_takeover": 50,
    # Düşük / en son (pasif veya türev)
    "headers_scanner": 35, "session_scanner": 35, "waf_fingerprint": 35,
    "polyglot_probe": 30, "dalfox_verify": 25,
}
_DEFAULT_PHASE_PRIORITY = 50


def _resolve_sqlmap_budget(ctx) -> int:
    """sqlmap subprocess'inin TAMAMI için FİRM duvar-saati tavanı (saniye).

    Kullanıcı talebi (2026-06-15): sqlmap max-power/no_timeout modunda bile
    SINIRSIZ koşmasın. Bütçe FİRM'dir — gerçek tavandır ve no_timeout çarpanıyla
    (WEBSECURE_NOTIMEOUT_FACTOR) ŞİŞİRİLMEZ. sqlmap bu bütçe İÇİNDE tam güçte
    kalır (level/risk/threads/tamper/crawl değişmez); yalnız toplam süre
    sınırlanır → tarama her zaman biter ve raporunu yazar.

    Çözünürlük sırası: offensive.sqlmap.budget_seconds → sqlmap.budget_seconds →
    _sqlmap.timeout (profil per-run süresi, ör. stealth=1800) → 1800 varsayılan.
    Tor/proxy aktifken istek başına ~10-30x yavaş olduğundan tavana sonlu
    headroom verilir (yine kesinlikle sonlu).
    """
    cfg = getattr(ctx, "config", {}) or {}
    if not isinstance(cfg, dict):
        return 1800
    # Açıkça yapılandırılmış değer (herhangi bir kaynaktan) MUTLAK saygı görür —
    # kullanıcının/profilin verdiği sayı aynen kullanılır. Tor headroom YALNIZ
    # hiçbir değer verilmediğinde devreye giren hardcoded varsayılana uygulanır.
    _explicit = ((cfg.get("offensive") or {}).get("sqlmap") or {}).get("budget_seconds")
    if _explicit is None:
        _explicit = (cfg.get("sqlmap") or {}).get("budget_seconds")
    if _explicit is None:
        _explicit = (cfg.get("_sqlmap") or {}).get("timeout")
    if _explicit is not None:
        try:
            return max(300, int(_explicit))
        except (TypeError, ValueError):
            pass
    # Hiç değer verilmemiş → varsayılan. Tor/proxy'de istek-başı gecikme çok büyük
    # olduğundan sqlmap tavan içinde onaya ulaşabilsin diye headroom (yine sonlu).
    _proxied = bool(
        cfg.get("_tor_proxy")
        or (cfg.get("proxy") or {}).get("url")
        or ((cfg.get("proxy") or {}).get("tor_control") or {}).get("enabled")
    )
    return 2700 if _proxied else 1800


def _safe(ctx, fn: Callable[[], None], phase_id: str) -> None:
    """
    Her fazı ayrı bir thread'de çalıştırır. İstisnalar main thread'i bozmaz.

    Hata yakalama, fazın çalıştığı worker thread'in İÇİNDE try/except ile yapılır;
    process-global ``threading.excepthook`` KULLANILMAZ. Sebep: fazlar paralel
    gruplar halinde (bkz. _PARALLEL_GROUPS) eşzamanlı çalışır ve tek bir global
    excepthook'u her _safe çağrısı ezerdi — böylece bir fazın thread'inde oluşan
    hata YANLIŞ faza atfedilirdi (gerçek örnek: run_ffuf_scan'in 'os'
    UnboundLocalError'u 'owasp_and_nuclei' altına kaydedilmişti). Closure içindeki
    ``err`` dict'i thread'e özeldir; yarış (race) ve restore-sırası tehlikesi yok.
    """
    err: Dict[str, str] = {}

    phase_timeout = _PHASE_TIMEOUTS.get(phase_id, _DEFAULT_PHASE_TIMEOUT)

    # Stealth profilinde harici araçlara (ffuf, feroxbuster, sqlmap) 3x zaman ver —
    # çünkü -rate 1-2 ile çalışıyorlar ve aynı iş çok daha uzun sürüyor.
    _ctx_cfg = getattr(ctx, "config", {}) or {}
    _scan_profile = str((_ctx_cfg.get("settings") or {}).get("scan_profile", "normal")).lower()
    if _scan_profile == "stealth" and phase_id in (
        "ffuf", "feroxbuster", "sqlmap", "nuclei", "amass", "subdomain", "passive_recon"
    ):
        phase_timeout = int(phase_timeout * 3)

    # Max-power / timeout-free mode. Previously this set phase_timeout to
    # float("inf") for EVERY phase — but then any phase that blocks forever
    # (browser_crawler'ın sayfa-içi fetch'i, Tor üzerinde asılı ffuf) tüm taramayı
    # sonsuza kilitler ve TEK çıkış Ctrl+C olur (kullanıcının yaşadığı donma).
    # Çözüm: ağır recon/ofansif fazlar SINIRSIZ kalır (ilerleyen bir fazı terk
    # etmeyiz); diğer her faz cömert-ama-SONLU bir watchdog alır → asılı bir faz
    # Ctrl+C beklemeden otomatik bir sonrakine ilerler. Araç subprocess'leri zaten
    # effective_timeout ile sınırlı olduğundan (cömert-sonlu) bu watchdog yalnızca
    # gerçek bir donmada (in-process await) devreye girer.
    try:
        from websecure.core.http import no_timeout_enabled as _nt_enabled
        if _nt_enabled():
            if phase_id in _NO_TIMEOUT_UNBOUNDED_PHASES:
                phase_timeout = float("inf")
            else:
                phase_timeout = max(phase_timeout * _NO_TIMEOUT_WATCHDOG_FACTOR, 600)
    except Exception:
        pass

    # sqlmap: süre artık FİRM bütçeyle sınırlı (kullanıcı talebi 2026-06-15, bkz
    # _resolve_sqlmap_budget). ASIL tavan subprocess'tedir (wrapper.scan run_timeout);
    # buradaki watchdog yalnız subprocess kill'i de asılırsa devreye giren failsafe →
    # bütçenin hemen üstüne sabitle (no_timeout çarpanını sqlmap için bilinçli ez ki
    # 'tam güç' başka fazları kilitlemesin). Temiz kısmi-sonuç ayrıştırması (wrapper'ın
    # TimeoutExpired dalı) bu watchdog'dan ÖNCE çalışır.
    if phase_id == "sqlmap":
        try:
            phase_timeout = _resolve_sqlmap_budget(ctx) + 300
        except Exception:
            pass

    def _phase_fn():
        # Each phase thread sets its own active-phase context so that http.py's
        # idempotent-first policy uses the correct phase name (not a stale one
        # from a previously executed phase, e.g. "discovery").
        try:
            from websecure.core.http import set_active_phase as _set_ap
            _set_ap(phase_id)
        except Exception:
            pass
        # Hata yakalama bu thread'in içinde yapılır → thread-local, race-free.
        # BaseException (KeyboardInterrupt/SystemExit dahil) yakalanır ki main
        # thread'e sızıp taramayı bozmasın; yalnızca err dict'ine yazılır.
        try:
            fn()
        except BaseException as e:  # noqa: BLE001 — kasıtlı: faz hatasını izole et
            err["type"] = type(e).__name__
            err["error"] = str(e)
            err["trace"] = "".join(
                traceback.format_exception(type(e), e, e.__traceback__)
            )[-2000:]

    t = threading.Thread(target=_phase_fn, name=f"phase::{phase_id}", daemon=True)
    t.start()

    # Poll in 1s increments so Ctrl+C (_SCAN_CANCEL) is checked frequently
    elapsed = 0.0
    while t.is_alive() and elapsed < phase_timeout:
        t.join(timeout=1.0)
        elapsed += 1.0
        if _SCAN_CANCEL.is_set():
            break

    if t.is_alive():
        # Faz hâlâ canlı (daemon thread zorla öldürülemez). İKİ ZORUNLU temizlik
        # — aksi halde araç (dalfox/ffuf/katana/sqlmap...) arka planda sızıp
        # koşmaya devam eder, sonraki fazlardan zaman/Tor bandı çalar:
        #   (1) mark_phase_abandoned → http.py istekleri PhaseAbandoned ile kesilir
        #       + loop tabanlı wrapper'lar (dalfox verify) is_phase_abandoned()
        #       görüp yeni süreç açmayı bırakır;
        #   (2) kill_phase_children → bu fazın AÇIK BIRAKTIĞI alt süreçler gerçekten
        #       öldürülür. Yalnız bu faz hedeflenir; eşzamanlı diğer fazlar bozulmaz.
        # Tam güç korunur: buraya yalnız faz GERÇEKTEN bütçesini aştığında veya
        # Ctrl+C'de gelinir — sağlıklı biten faz çocuklarını finally'de unregister eder.
        try:
            from websecure.core.http import mark_phase_abandoned as _mark_abandoned
            _mark_abandoned(phase_id)
        except Exception:
            pass
        try:
            kill_phase_children(phase_id)
        except Exception:
            pass
        if _SCAN_CANCEL.is_set():
            _logger.info("[phases] Phase '%s' cancelled by user (Ctrl+C)", phase_id)
        else:
            _logger.warning(
                "[phases] Phase '%s' exceeded %ds — skipped to prevent hang", phase_id, phase_timeout
            )
            add_result("errors", {
                "type": "phase_timeout",
                "phase": phase_id,
                "timeout_secs": phase_timeout,
            })

    if err:
        add_result("errors", {
            "type": "phase_error",
            "phase": phase_id,
            "error": f"{err.get('type')}: {err.get('error')}",
            "trace": err.get("trace", "")[-2000:]
        })

# ----------------------------- Faz nesnesi -----------------------------

@dataclass
class Phase:
    id: str
    title: str
    enabled: bool
    reason: Optional[str] = None
    runner: Optional[Callable[[Any], None]] = None
    tags: List[str] = field(default_factory=list)
    visible: bool = True

def is_blocked(ctx) -> bool:
    """Tarama bloke mi? cancelled veya critical_error bayraklarını kontrol eder."""
    if ctx is None:
        return False
    if bool(getattr(ctx, "cancelled", False)):
        return True
    shared = getattr(ctx, "shared", None)
    if isinstance(shared, dict) and bool(shared.get("critical_error", False)):
        return True
    return False


def adjust_scan_mode(results: dict, cfg: dict) -> str:
    """HTTP metriklerine göre scan profilini dinamik ayarlar."""
    current = str((cfg or {}).get("scan_profile", "NORMAL")).upper()
    four = int(results.get("403", 0)) + int(results.get("429", 0))
    ok = int(results.get("2xx", 0))
    if four >= 5:
        if current == "AGGRESSIVE":
            return "NORMAL"
        if current == "NORMAL":
            return "STEALTH"
    if ok >= 20 and four == 0:
        if current == "STEALTH":
            return "NORMAL"
        if current == "NORMAL":
            return "AGGRESSIVE"
    return current


def flush(ctx=None):
    """Raporlama tamponunu diske yazar."""
    try:
        from websecure.core.reporting import flush as _rf
        return _rf()
    except (ImportError, OSError) as exc:
        _logger.debug(f"[phases] flush skipped: {exc!r}")


def _runner_katana(ctx) -> None:
    """katana web crawler — keşif fazı öncesi JS-aware endpoint tarama."""
    try:
        from websecure.integrations.katana import KatanaWrapper
        wrapper = KatanaWrapper()
        if not wrapper.is_available():
            add_result("meta", {"stage": "katana", "status": "skipped:not-installed"})
            return
        url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
        if not url:
            return
        # Ensure URL has protocol prefix before passing to katana
        if url and not url.startswith(("http://", "https://")):
            url = "https://" + url
        # Config'den derinlik, süre ve JS tarama seçeneklerini al
        cfg = getattr(ctx, "config", {}) or {}
        katana_cfg = cfg.get("katana") or {}
        # max_depth default 2 — agresif 3 her zaman timeout sebebidir
        depth = int(katana_cfg.get("depth") or (cfg.get("discovery") or {}).get("max_depth") or 2)
        js_crawl = bool(katana_cfg.get("js_crawl", True))
        # crawl_duration_s config'den alınabilir; default 120s
        crawl_duration_s = int(katana_cfg.get("crawl_duration_s") or 120)
        rate_limit = int(katana_cfg.get("rate_limit") or 50)
        wrapper.depth = depth
        wrapper.crawl_duration_s = crawl_duration_s
        wrapper.rate_limit = rate_limit
        # Proxy'i geç — Tor aktifse gerçek IP sızmasın
        _katana_proxy = _resolve_proxy(ctx)
        result = wrapper.run(url, depth=depth, js_crawl=js_crawl, proxy=_katana_proxy)
        unique_urls = result.extra.get("unique_urls", [])
        endpoints_data = result.extra.get("endpoints", [])
        timed_out = result.extra.get("timed_out", False)
        # Katana, Next.js/GitBook gibi SPA'larda relative-urljoin özyinelemesi ve
        # /[pagePath] gibi route-şablonlarından çöp URL üretebilir (docs.kick.com
        # taramasında görüldü). Havuza girmeden ele — yoksa Tor üzerinde boşa
        # istek harcanır ve rapor şişer.
        try:
            from websecure.core.utils import is_junk_url as _is_junk, is_streaming_endpoint as _is_stream
        except Exception:
            _is_junk = lambda _u: False  # noqa: E731 — import güvenliği
            _is_stream = lambda _u: False  # noqa: E731
        # ctx.results["endpoints"] 'a katana URL'lerini ekle. socket.io/SSE/long-poll
        # uçlarını enjeksiyon havuzuna SOKMA (XSS/SQLi onlara payload atıp Tor'da
        # ~45s asılı kalıyor, yansıma imkânsız = verimsiz). ws_fuzz bunları kendi
        # keşfedip test eder → kapsam kaybı yok.
        if unique_urls:
            ctx_results = getattr(ctx, "results", None)
            if ctx_results is None:
                ctx_results = {}
                try:
                    ctx.results = ctx_results
                except AttributeError:
                    pass
            existing = set(ctx_results.get("endpoints", []))
            existing.update(u for u in unique_urls if not _is_junk(u) and not _is_stream(u))
            ctx_results["endpoints"] = list(existing)
        # endpoints bucket'a yaz
        for ep_dict in endpoints_data:
            ep_url = ep_dict.get("url", "")
            if ep_url and not _is_junk(ep_url):
                add_result("endpoints", {
                    "url": ep_url,
                    "method": ep_dict.get("method", "GET"),
                    "source": f"katana:{ep_dict.get('source', '')}",
                    "params": ep_dict.get("params", []),
                })
        # ToolFinding'leri meta'ya yaz
        for f in result.findings:
            add_result("meta", f.to_dict())
        add_result("meta", {
            "stage": "katana",
            "status": "partial" if timed_out else "ok",
            "endpoints": len(unique_urls),
            "duration_s": round(result.duration_s, 1),
            "timed_out": timed_out,
        })
        _logger.info(
            f"[phases] katana: {len(unique_urls)} URL keşfedildi"
            f"{'  [kısmi-timeout]' if timed_out else ''}"
        )
    except Exception as e:
        _logger.warning(f"[phases] katana runner error: {e}")
        _report_phase_error("katana", "phases._runner_katana", e)


def _runner_browser_crawler(ctx) -> None:
    """
    Playwright tabanlı BrowserCrawler — JS-heavy SPA'lar için.
    should_use_browser_crawler() heuristic'i True dönerse devreye girer.
    Playwright yoksa veya site JS-heavy değilse sessizce atlar.
    """
    try:
        from websecure.core.browser_crawler import (
            BrowserCrawler, BrowserCrawlConfig, should_use_browser_crawler,
        )
        existing_results = getattr(ctx, "results", {}) or {}
        http_result = {
            "endpoints": list(existing_results.get("endpoints", [])),
            "tech_stack": list(getattr(ctx, "technologies", []) or []),
            # Statik parse hiç form bulamadıysa (SPA'da JS-render formlar) tarayıcıyla
            # render edip keşfet → input alanları fuzz'lanabilsin.
            "forms_found": sum(
                len(p.get("forms", []) or [])
                for p in (existing_results.get("forms_meta", []) or [])
                if isinstance(p, dict)
            ),
        }
        if not should_use_browser_crawler(http_result):
            add_result("meta", {"stage": "browser_crawler", "status": "skipped:not-needed"})
            return

        url = (getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
               or getattr(ctx, "target", ""))
        if not url:
            return

        cfg = getattr(ctx, "config", {}) or {}
        # Config yolları: üst seviye browser_crawler/browser VEYA crawl.browser
        # (kullanıcının config.json'da headless ayarı crawl.browser altında).
        bc_cfg = (cfg.get("browser_crawler") or cfg.get("browser")
                  or (cfg.get("crawl") or {}).get("browser") or {})
        _headless = bool(bc_cfg.get("headless", True))
        config = BrowserCrawlConfig(
            headless=_headless,
            # headless=False zaten görünür Chrome açar; show_browser onu garanti eder
            show_browser=bool(bc_cfg.get("show_browser", not _headless)),
            slow_mo_ms=int(bc_cfg.get("slow_mo_ms") or 0),
            max_pages=int(bc_cfg.get("max_pages") or 50),
            timeout_ms=int(bc_cfg.get("timeout_ms") or 15000),
            # Tor/proxy üzerinden geçir ki tarayıcı da gerçek IP'yi gizlesin
            proxy_url=_resolve_proxy(ctx),
        )

        crawler = BrowserCrawler(config)
        import asyncio as _asyncio

        def _run(coro):
            # Python 3.10+ deprecates get_event_loop() outside async context.
            # get_event_loop_policy().get_event_loop() degrades gracefully; if it
            # raises or the loop is closed, build a fresh loop.
            try:
                loop = _asyncio.get_event_loop_policy().get_event_loop()
                if loop.is_closed():
                    raise RuntimeError("event loop is closed")
            except RuntimeError:
                loop = _asyncio.new_event_loop()
                _asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)

        # Son kalkan: crawl içindeki bütçe normalde önce devreye girip KISMİ sonuç
        # döndürür; bu sert tavan (bütçe + 120sn) crawl'ın HER DURUMDA geri
        # dönmesini garanti eder — no_timeout faz-watchdog'unu kapattığı için tek
        # bir donmuş await aksi halde tüm taramayı sonsuza dek kilitler.
        _hard_cap = crawler.overall_budget_seconds() + 120
        try:
            result = _run(_asyncio.wait_for(crawler.crawl(url), timeout=_hard_cap))
        except _asyncio.TimeoutError:
            _logger.warning(
                "[phases] BrowserCrawler sert süre tavanını (%ss) aştı — "
                "faz sonlandırıldı, tarama devam ediyor", int(_hard_cap)
            )
            add_result("meta", {"stage": "browser_crawler", "status": "skipped:timeout",
                                 "hard_cap_secs": int(_hard_cap)})
            return

        # Endpoint'leri ctx.results'a ekle.
        # Defense-in-depth: browser_crawler kapsam dışı host'ları zaten elemeli,
        # ama burada da same-site süzgeci uygula — üçüncü-parti analytics/ads
        # beacon URL'lerinin (analytics.google.com vb.) fuzz havuzuna sızıp
        # taramayı şişirmesini ikinci kez engeller.
        try:
            from websecure.core.utils import (
                same_site as _same_site, is_junk_url as _is_junk,
                is_streaming_endpoint as _is_stream,
            )
            # socket.io/SSE/long-poll uçları enjeksiyon havuzuna girmesin (verimsiz
            # asılı kalma); ws_fuzz onları kendi keşfedip test eder → kapsam kaybı yok.
            new_urls = {
                u for u in (result.endpoints + result.api_endpoints + result.spa_routes)
                if _same_site(u, url) and not _is_junk(u) and not _is_stream(u)
            }
        except Exception:
            new_urls = set(result.endpoints + result.api_endpoints + result.spa_routes)
        ctx_results = getattr(ctx, "results", None)
        if ctx_results is None:
            ctx_results = {}
            try:
                ctx.results = ctx_results
            except AttributeError:
                pass
        existing_eps = set(ctx_results.get("endpoints", []))
        existing_eps.update(new_urls)
        ctx_results["endpoints"] = list(existing_eps)

        # Keşfedilen FORM'ları (SPA login/register/ödeme alanları) scanner'lara
        # ulaştır. BU MERGE EKSİKTİ: browser_crawler formları buluyor
        # (result.forms_meta) ama xss/sqli/nosqli/csrf `results["forms_meta"]`'dan
        # okuyor → forms_meta hiç dolmuyordu → input alanları (name/email/password/
        # kart) HİÇ fuzz'lanmıyor, yalnızca URL query'si test ediliyordu. SPA'da
        # formlar JS ile render edildiğinden statik HTML parse (form_parser) onları
        # GÖREMEZ → tek kaynak browser_crawler'dır.
        bc_forms = getattr(result, "forms_meta", None) or []
        _bc_forms_added = 0
        if bc_forms:
            fm = ctx_results.get("forms_meta", [])
            if not isinstance(fm, list):
                fm = []
            _by_url = {p.get("url"): p for p in fm
                       if isinstance(p, dict) and p.get("url")}
            for page in bc_forms:
                if not isinstance(page, dict):
                    continue
                p_url = page.get("url") or url
                p_forms = page.get("forms") or []
                if not p_forms:
                    continue
                if p_url in _by_url:
                    _by_url[p_url].setdefault("forms", []).extend(p_forms)
                else:
                    entry = {"url": p_url, "forms": list(p_forms)}
                    fm.append(entry)
                    _by_url[p_url] = entry
                _bc_forms_added += len(p_forms)
            ctx_results["forms_meta"] = fm
            _logger.info(
                "[phases] BrowserCrawler: %d form (SPA dahil) forms_meta'ya eklendi "
                "→ input alanları (name/email/password/kart) artık POST/JSON ile "
                "fuzz'lanacak", _bc_forms_added,
            )

        # Tech stack güncelle
        if result.tech_stack:
            existing_tech = list(getattr(ctx, "technologies", []) or [])
            for t in result.tech_stack:
                if t not in existing_tech:
                    existing_tech.append(t)
            try:
                ctx.technologies = existing_tech
            except AttributeError:
                pass

        # Exposed secret'ler bulgu olarak kaydet
        for secret in result.secrets_found:
            add_result("offensive", {
                "type": "SecretExposed",
                "severity": secret.get("severity", "High"),
                "title": f"Exposed Secret: {secret.get('type', 'Unknown')}",
                "url": secret.get("url", url),
                "evidence": secret.get("value_preview", ""),
                "tool": "browser_crawler",
                "verified": False,
            })

        add_result("meta", {
            "stage": "browser_crawler",
            "status": "completed",
            "endpoints_found": len(result.endpoints),
            "api_endpoints": len(result.api_endpoints),
            "spa_routes": len(result.spa_routes),
            "secrets_found": len(result.secrets_found),
            "forms_found": _bc_forms_added,
            "tech_stack": result.tech_stack,
        })
        _logger.info(
            f"[phases] BrowserCrawler: {len(new_urls)} URL, "
            f"{len(result.secrets_found)} secret, {result.tech_stack}"
        )
    except Exception as e:
        _logger.debug(f"[phases] BrowserCrawler error (Playwright not available?): {e}")
        add_result("meta", {"stage": "browser_crawler", "status": "skipped:error",
                             "error": str(e)[:200]})


def _runner_browser_inject(ctx) -> None:
    """
    Görünür-tarayıcı FORM ENJEKSİYONU — yalnızca kullanıcı başlangıçta 'E' dediyse
    (cfg['browser_injection']['enabled']). Gerçek Chrome penceresinde login/kayıt/
    yorum/ödeme formlarındaki alanlara (kullanıcı adı/e-posta/şifre/kart/CVV/yorum)
    SQLi+XSS payload'larını TEK TEK yazar, gönderir, sonucu (alert/SQL hata) gözler.
    Kapalıyken (varsayılan) sessizce atlar — HTTP-katmanı form taraması zaten çalışır.
    """
    cfg = getattr(ctx, "config", {}) or {}
    if not bool((cfg.get("browser_injection") or {}).get("enabled")):
        return
    if is_blocked(ctx):
        add_result("meta", {"stage": "browser_inject", "status": "skipped:blocked"})
        return
    try:
        from websecure.core.browser_crawler import (
            run_browser_form_injection, BrowserCrawlConfig,
        )

        url = (getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
               or getattr(ctx, "target", ""))
        if not url:
            return

        results = getattr(ctx, "results", {}) or {}

        # 1) Form İÇEREN sayfa URL'leri (forms_meta tarayıcı/statik keşiften gelir)
        page_urls: List[str] = []
        for p in (results.get("forms_meta", []) or []):
            if isinstance(p, dict) and p.get("url") and (p.get("forms")):
                _u = str(p["url"]).split("#")[0]
                if _u and _u not in page_urls:
                    page_urls.append(_u)

        # 2) Form ihtimali yüksek endpoint'ler (login/kayıt/yorum/ödeme/arama/iletişim)
        _form_hint = re.compile(
            r"(login|signin|sign-in|log-in|register|signup|sign-up|auth|account|"
            r"comment|review|feedback|contact|checkout|payment|odeme|sepet|cart|"
            r"search|ara|profile|settings|password|reset)",
            re.I,
        )
        for ep in (results.get("endpoints", []) or []):
            try:
                if _form_hint.search(str(ep)) and str(ep) not in page_urls:
                    page_urls.append(str(ep))
            except Exception:
                continue

        bc_cfg = (cfg.get("browser_crawler") or cfg.get("browser")
                  or (cfg.get("crawl") or {}).get("browser") or {})
        config = BrowserCrawlConfig(
            headless=bool(bc_cfg.get("headless", False)),
            show_browser=bool(bc_cfg.get("show_browser", True)),
            slow_mo_ms=int(bc_cfg.get("slow_mo_ms") or 120),
            timeout_ms=int(bc_cfg.get("timeout_ms") or 15000),
            proxy_url=_resolve_proxy(ctx),
        )

        try:
            from websecure.core.http import no_timeout_enabled as _nt_enabled
            _budget = 600 if _nt_enabled() else 300
        except Exception:
            _budget = 300

        _logger.info(
            "[phases] Görünür form enjeksiyonu başlıyor — %d sayfa hedefleniyor.",
            len(page_urls) + 1,
        )
        findings = run_browser_form_injection(
            url, page_urls, config, max_total_seconds=_budget,
        )

        for f in (findings or []):
            add_result("offensive", f)

        add_result("meta", {
            "stage": "browser_inject",
            "status": "completed",
            "pages": len(page_urls) + 1,
            "findings": len(findings or []),
        })
        _logger.info(
            "[phases] Görünür form enjeksiyonu bitti — %d onaylı bulgu.",
            len(findings or []),
        )
    except Exception as exc:
        _logger.debug("[phases] browser_inject error: %r", exc)
        add_result("meta", {"stage": "browser_inject", "status": "skipped:error",
                            "error": str(exc)[:200]})


def _runner_http_crawler_orchestrator(ctx) -> None:
    """
    CrawlerOrchestrator — HTTP + OpenAPI + GraphQL + gRPC + ParameterMiner + Sitemap.
    Core crawler pipeline for endpoint discovery beyond Katana.
    """
    try:
        from websecure.core.crawler import CrawlerOrchestrator
        url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or ""
        if not url:
            return
        session = getattr(ctx, "session", None) or hardened_session()
        cfg = getattr(ctx, "config", {}) or {}
        disc_cfg = cfg.get("discovery") or {}
        orchestrator = CrawlerOrchestrator(
            max_pages=int(disc_cfg.get("max_pages", 200)),
            enable_openapi=bool(disc_cfg.get("enable_openapi", True)),
            enable_graphql=bool(disc_cfg.get("enable_graphql", True)),
            enable_grpc=bool(disc_cfg.get("enable_grpc", False)),
            enable_version_scan=bool(disc_cfg.get("enable_version_scan", True)),
            enable_param_mining=bool(disc_cfg.get("enable_param_mining", True)),
            param_mine_limit=int(disc_cfg.get("param_mine_limit", 20)),
        )
        result = orchestrator.run(url, session)
        # Merge discovered endpoints into ctx.results
        ctx_results = getattr(ctx, "results", None)
        if ctx_results is None:
            ctx_results = {}
            try:
                ctx.results = ctx_results
            except AttributeError:
                pass
        # B1 FIX: CrawlResult.api_endpoints = List[EndpointMeta] (hashable DEĞİL —
        # plain @dataclass + mutable `params: List` → __hash__ = None). Eskiden bu
        # nesneler doğrudan set'e ekleniyordu:
        #   (a) `existing.update(result.api_endpoints)` → TypeError: unhashable type:
        #       'EndpointMeta' → TÜM http_crawler fazı çöküyordu (API/OpenAPI/GraphQL
        #       endpoint keşfi KAYBOLUYORDU — kimlikli taramada enjeksiyon hedefleri
        #       eksik kalıyordu),
        #   (b) çökmese bile `endpoints` (URL-string havuzu) içine nesne karışıp
        #       downstream urlparse/is_static_asset'i bozardı.
        # Çözüm: EndpointMeta'dan .url çıkar; api_endpoints'i url-string olarak
        # (url'e göre tekilleştirilmiş) sakla.
        def _ep_url(e):
            if hasattr(e, "url"):
                return e.url
            if isinstance(e, dict):
                return e.get("url")
            return str(e)

        existing = set(ctx_results.get("endpoints", []))
        existing.update(result.endpoints)
        existing.update(_ep_url(e) for e in result.api_endpoints if _ep_url(e))
        ctx_results["endpoints"] = list(existing)
        if result.discovered_params:
            ctx_results.setdefault("discovered_params", {}).update(result.discovered_params)
        if result.sitemap:
            ctx_results["sitemap"] = result.sitemap
        if result.api_endpoints:
            ctx_results.setdefault("api_endpoints", [])
            _api_seen = {_ep_url(e) for e in ctx_results["api_endpoints"]}
            for _e in result.api_endpoints:
                _u = _ep_url(_e)
                if _u and _u not in _api_seen:
                    _api_seen.add(_u)
                    ctx_results["api_endpoints"].append(_u)
        add_result("meta", {
            "stage": "http_crawler",
            "status": "ok",
            "endpoints": len(result.endpoints),
            "api_endpoints": len(result.api_endpoints),
            "grpc_services": len(result.grpc_services),
        })
        _logger.info(
            "[phases] CrawlerOrchestrator: %d endpoints, %d API, %d gRPC",
            len(result.endpoints), len(result.api_endpoints), len(result.grpc_services),
        )
    except Exception as exc:
        _logger.debug(f"[phases] CrawlerOrchestrator error: {exc!r}")
        _report_phase_error("http_crawler", "phases._runner_http_crawler_orchestrator", exc)


def _runner_discovery(ctx) -> None:
    if is_blocked(ctx):
        add_result('meta', {'stage': 'discovery', 'status': 'skipped:blocked'})
        return
    # Katana kuruluysa keşif öncesi çalıştır — endpoint havuzunu zenginleştirir
    _runner_katana(ctx)
    # CrawlerOrchestrator: HTTP + OpenAPI + GraphQL + gRPC + ParameterMiner + Sitemap
    _runner_http_crawler_orchestrator(ctx)
    run_discovery_extended(ctx)
    # BrowserCrawler: HTTP crawler az endpoint bulduysa veya JS-heavy SPA ise devreye girer
    _runner_browser_crawler(ctx)
    # Görünür-tarayıcı form enjeksiyonu (yalnız kullanıcı 'E' dediyse) — forms_meta
    # browser_crawler tarafından doldurulduktan SONRA çalışır ki login/yorum/ödeme
    # alanları görünür Chrome'da payload'larla denensin.
    _runner_browser_inject(ctx)

def _runner_fuzz_and_param_discovery(ctx) -> None:
    run_fuzz_and_param_discovery(ctx)

def _runner_oast_verification(ctx) -> None:
    run_oast_verification(ctx)

def _runner_reporting_and_integration(ctx) -> None:
    run_reporting_and_integration(ctx)

def _runner_authorization_matrix(ctx) -> None:
    run_authorization_matrix(ctx)

def _runner_feroxbuster(ctx):
    run_feroxbuster_scan(ctx)
    return _mk_result("feroxbuster", "finished", {})

def _runner_nuclei(ctx):
    run_nuclei_scan(ctx)
    return _mk_result("nuclei", "finished", {})

def _runner_js_analysis(ctx) -> None:
    run_js_analysis(ctx)

def _runner_sqlmap(ctx):
    run_sqlmap_scan(ctx)
    return _mk_result("sqlmap", "finished", {})

def _runner_business_logic_races(ctx) -> None:
    run_business_logic_races(ctx)

def _runner_ffuf(ctx) -> None:
    run_ffuf_scan(ctx)

def _runner_xss(ctx) -> None:
    run_xss_scan(ctx)

def _runner_subdomain(ctx) -> None:
    """Subdomain enumeration: DNS brute + subfinder + amass + crt.sh"""
    try:
        from websecure.scanners.subdomain import run as _sub_run
        target = getattr(ctx, "target", None) or getattr(ctx, "base_url", None) or ""
        if not target:
            return
        cfg = getattr(ctx, "config", {}) or {}
        results = _sub_run(target, cfg=cfg)
        for r in results:
            # KANONİK KOVA = 'subdomains' (ÇOĞUL). Rapor (html_dashboard
            # FINDING_BUCKETS + dedike "Keşfedilen Subdomain'ler" bölümü),
            # pdf reporter ve subdomain.py docstring'i HEPSİ çoğul okur.
            # Eski 'subdomain' (tekil) hiçbir tüketicinin okumadığı öksüz
            # kovaydı → tarama subdomain buluyor ama rapora HİÇ düşmüyordu.
            add_result("subdomains", r)
        _logger.info(f"[phases] Subdomain tarama tamamlandı: {len(results)} bulgu")
    except Exception as e:
        _logger.warning(f"[phases] Subdomain tarama hatası: {e}")
        _report_phase_error("subdomain", "phases._runner_subdomain", e)

def _runner_open_redirect(ctx) -> None:
    """Open redirect taraması."""
    try:
        from websecure.scanners.open_redirect import run as _or_run
        target = getattr(ctx, "target", None) or getattr(ctx, "base_url", None) or ""
        if not target:
            return
        cfg = getattr(ctx, "config", {}) or {}
        session = getattr(ctx, "session", None)
        # Crawler'dan gelen URL listesini de gönder
        urls = list(getattr(ctx, "endpoints", None) or [])
        results = _or_run(target, cfg=cfg, session=session, urls=urls)
        for r in results:
            add_result("offensive", r)
        _logger.info(f"[phases] Open redirect tarama tamamlandı: {len(results)} bulgu")
    except Exception as e:
        _logger.warning(f"[phases] Open redirect tarama hatası: {e}")
        _report_phase_error("open_redirect", "phases._runner_open_redirect", e)
# ----------------------------- Runner sargıları -----------------------------

def _runner_scanners_ssrf_xxe(ctx) -> None:
    """scanners.ssrf_xxe.scan(...) çağrısı için imza-uyumlu sargı."""
    mod = _opt_import("websecure.scanners.ssrf_xxe")
    if not mod or not hasattr(mod, "scan") or not callable(getattr(mod, "scan")):
        add_result("offensive", {
            "type": "SSRF/XXE",
            "severity": "Informational",
            "reason": "Modül bulunamadı ya da `scan` yok."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return

    base_url = (getattr(ctx, "url", None)
                or getattr(ctx, "base_url", None)
                or getattr(ctx, "target", None)
                or "")
    if not base_url:
        add_result("meta", {"stage": "ssrf_xxe", "status": "skipped:no-url"})
        return

    # OAST taraması başlamadan interactsh'e kayıt ol -> subdomain al
    oast_domain = _setup_oast_domain(ctx)

    scan = getattr(mod, "scan")
    cfg = getattr(ctx, "config", {}) or {}
    oast_cfg = dict(cfg.get("oast", {}) or {})

    # interactsh subdomain'i scanner'a geçir
    if oast_domain:
        oast_cfg["dns_domain"] = oast_domain
    endpoints = getattr(ctx, "endpoints", None) or ([base_url] if base_url else [])

    results_bucket = _ensure_results_bucket(ctx)
    auth_ctx = getattr(ctx, "auth", None) or getattr(ctx, "auth_ctx", None)

    # olası param adlarını birlikte sun ve filtrele
    kw_all = {
        "session": getattr(ctx, "session", None),
        "endpoints": endpoints,
        "oast_cfg": oast_cfg,
        "oast": oast_cfg,
        "results": results_bucket,
        "debug": bool(getattr(ctx, "debug", False)),
        "auth_ctx": auth_ctx,
    }
    scan(ctx, **_filter_kwargs(scan, kw_all))

def _runner_scanners_request_smuggling(ctx) -> None:
    """HTTP Request Smuggling (CL.TE / TE.CL / TE.TE / H2.CL / H2.TE / differential)."""
    # B2/P3 FIX: eski runner `probe_te_cl` vb. metotları arıyordu — bunlar mevcut
    # RequestSmugglingScanner'da YOK (BaseScanner'dan türer, sadece run() var).
    # hasattr guard nedeniyle sessizce hiçbir prob çalışmıyordu.
    # Düzeltme: modül-düzeyi run() kullan (tüm CL.TE/TE.CL/differential/H2 probu yapar).
    mod = _opt_import("websecure.scanners.request_smuggling")
    if not mod:
        add_result("meta", {"stage": "request_smuggling", "status": "skipped:module-not-found"})
        return
    base_url = (getattr(ctx, "url", None)
                or getattr(ctx, "base_url", None)
                or getattr(ctx, "target", None)
                or "")
    if not base_url:
        add_result("meta", {"stage": "request_smuggling", "status": "skipped:no-url"})
        return
    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))
    try:
        run_fn = getattr(mod, "run", None)
        if callable(run_fn):
            findings = run_fn(base_url, session=sess, debug=debug) or []
            for f in findings:
                add_result("request_smuggling", f)
                if (f.get("severity") or "") in ("Critical", "High", "Medium"):
                    add_result("offensive", f)
            add_result("meta", {"stage": "request_smuggling", "findings": len(findings)})
    except Exception as e:
        _logger.warning(f"[phases] Request Smuggling runner error: {e}")
        _report_phase_error("request_smuggling", "phases._runner_scanners_request_smuggling", e)

def _runner_mass_assignment(ctx) -> None:
    mod = _opt_import("websecure.scanners.mass_assignment")
    if not mod:
        add_result("offensive", {"type": "Mass Assignment", "severity": "Informational", "reason": "Modül bulunamadı."})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    base_url = (getattr(ctx, "url", None) or getattr(ctx, "target", None) or "")
    if not base_url:
        add_result("meta", {"stage": "mass_assignment", "status": "skipped:no-url"})
        return
    sess = getattr(ctx, "session", None)
    timeout = float(_get(getattr(ctx, "config", {}) or {}, "timeouts.mass_assignment", 10.0))
    endpoints = _get(getattr(ctx, "config", {}) or {}, "mass_assignment.endpoints", None)
    params = _get(getattr(ctx, "config", {}) or {}, "mass_assignment.params", None)

    # run imzasını keşfet
    run = getattr(mod, "run", None)
    if callable(run):
        kw = _filter_kwargs(run, dict(url=base_url, base_url=base_url, session=sess, debug=bool(getattr(ctx, "debug", False)),
                                      timeout=timeout, endpoints=endpoints, params=params))
        run(**kw)

def _runner_nosqli(ctx) -> None:
    mod = _opt_import("websecure.scanners.nosqli")
    if not mod:
        add_result("offensive", {"type": "NoSQLi", "severity": "Informational", "reason": "Modül bulunamadı."})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    base_url = (getattr(ctx, "url", None) or getattr(ctx, "target", None) or "")
    if not base_url:
        add_result("meta", {"stage": "nosqli", "status": "skipped:no-url"})
        return
    sess = getattr(ctx, "session", None)
    timeout = float(_get(getattr(ctx, "config", {}) or {}, "timeouts.nosqli", 8.0))
    endpoints = _get(getattr(ctx, "config", {}) or {}, "nosqli.endpoints", None)
    params = _get(getattr(ctx, "config", {}) or {}, "nosqli.params", None)
    results = _ensure_results_bucket(ctx)

    # Extract HTML forms discovered during the discovery phase
    forms_meta = (getattr(ctx, "results", {}) or {}).get("forms_meta", [])
    all_forms: list = []
    for page in forms_meta:
        if isinstance(page, dict):
            all_forms.extend(page.get("forms", []))

    run = getattr(mod, "run", None)
    if callable(run):
        kw = _filter_kwargs(run, dict(url=base_url, base_url=base_url, session=sess,
                                      debug=bool(getattr(ctx, "debug", False)),
                                      timeout=timeout, endpoints=endpoints,
                                      params=params, results=results, forms=all_forms))
        run(**kw)

def _runner_scanners_file_upload(ctx) -> None:
    """
    scanners.file_upload.{run|scan} için sargı.
    - İmza keşfi ile uyum (TypeError yakalamadan)
    """
    mod = _opt_import("websecure.scanners.file_upload")
    if not mod:
        add_result("offensive", {
            "type": "File Upload",
            "severity": "Informational",
            "reason": "Modül bulunamadı."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    run = getattr(mod, "run", None) or getattr(mod, "scan", None)
    if not callable(run):
        add_result("offensive", {
            "type": "File Upload",
            "severity": "Informational",
            "reason": "`run`/`scan` bulunamadı."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    base_url = (getattr(ctx, "url", None)
                or getattr(ctx, "base_url", None)
                or getattr(ctx, "target", None)
                or "")
    if not base_url:
        add_result("meta", {"stage": "file_upload", "status": "skipped:no-url"})
        return
    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))
    cfg = getattr(ctx, "config", {}) or {}

    endpoints_cfg = _deep_get(cfg, "file_upload.endpoints", None)
    if endpoints_cfg and not isinstance(endpoints_cfg, list):
        endpoints_cfg = [endpoints_cfg]

    disc = (getattr(ctx, "results", {}) or {}).get("discovery", {}) or {}
    endpoints_disc = disc.get("upload") or []

    endpoints = endpoints_cfg or endpoints_disc or ([base_url] if base_url else [])
    results_bucket = _ensure_results_bucket(ctx)

    kw_all = dict(session=sess, endpoints=endpoints, results=results_bucket,
                  base_url=base_url, debug=debug)
    run(**_filter_kwargs(run, kw_all))

    # Olası bulguları rapora yaz
    fb = results_bucket.get("file_upload") if isinstance(results_bucket, dict) else None
    if isinstance(fb, list):
        for item in fb:
            if isinstance(item, dict):
                add_result("vulnerability", {**item, "source": "file_upload"})
    add_result("meta", {"stage": "file_upload", "tested": len(endpoints)})

def _runner_jwt(ctx) -> None:
    mod = _opt_import("websecure.scanners.jwt")
    if not mod or not hasattr(mod, "JWTScanner"):
        add_result("offensive", {"type": "JWT", "severity": "Informational", "reason": "Modül/Sınıf bulunamadı."})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return

    base_url = (getattr(ctx, "url", None) or getattr(ctx, "target", None) or "")
    if not base_url:
        add_result("meta", {"stage": "jwt", "status": "skipped:no-url"})
        return

    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))

    try:
        scanner = mod.JWTScanner(session=sess, debug=debug)
        vulns = scanner.run(base_url)

        # Merge results
        for bucket, findings in scanner.results.items():
             if bucket.endswith("_summary"): 
                 continue
             if isinstance(findings, list):
                 for item in findings:
                     add_result("jwt", item)
        
        add_result("meta", {"stage": "jwt", "vulns": vulns})
    except Exception as e:
        add_result("errors", {"stage": "jwt", "error": str(e)})

def _runner_scanners_ws_fuzz(ctx) -> None:
    """
    scanners.ws_fuzz.{run|scan} için sargı.
    - İmza keşfi
    - Sonuçları normalize ederek raporla
    """
    mod = _opt_import("websecure.scanners.ws_fuzz")
    if not mod:
        add_result("offensive", {
            "type": "WebSocket",
            "severity": "Informational",
            "reason": "Modül bulunamadı."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    run = getattr(mod, "run", None) or getattr(mod, "scan", None)
    if not callable(run):
        add_result("offensive", {
            "type": "WebSocket",
            "severity": "Informational",
            "reason": "`run`/`scan` bulunamadı."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    base_url = (getattr(ctx, "url", None)
                or getattr(ctx, "base_url", None)
                or getattr(ctx, "target", None)
                or "")
    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))
    cfg = getattr(ctx, "config", {}) or {}

    endpoints_cfg = _deep_get(cfg, "ws.endpoints", None)
    if endpoints_cfg and not isinstance(endpoints_cfg, list):
        endpoints_cfg = [endpoints_cfg]

    disc = (getattr(ctx, "results", {}) or {}).get("discovery", {}) or {}
    endpoints_disc = disc.get("ws") or disc.get("websocket") or []
    endpoints = endpoints_cfg or endpoints_disc or ([base_url] if base_url else [])

    results_bucket = _ensure_results_bucket(ctx)

    # B2 FIX: ws_fuzz.run(url, ...) `url`'i ZORUNLU positional alır; runner sadece
    # `base_url` veriyordu → _filter_kwargs `url`'i bulamayıp düşürüyor, her çağrı
    # `TypeError: run() missing 1 required positional argument: 'url'` ile çöküyordu
    # (scanner hiç çalışmıyordu). Hem `url` hem `base_url` sun — imzaya göre filtrele.
    kw_all = dict(session=sess, endpoints=endpoints, results=results_bucket,
                  url=base_url, base_url=base_url, debug=debug)
    run(**_filter_kwargs(run, kw_all))

    # normalize & rapor
    for key in ("ws_fuzz", "websocket", "ws"):
        val = results_bucket.get(key) if isinstance(results_bucket, dict) else None
        if not val:
            continue
        items: List[Dict[str, Any]] = []
        if isinstance(val, dict):
            items = [val]
        elif isinstance(val, (list, tuple)):
            for x in val:
                if isinstance(x, dict):
                    items.append(x)
                elif isinstance(x, str):
                    items.append({"message": x})
                else:
                    items.append({"value": repr(x)})
        elif isinstance(val, str):
            items = [{"message": val}]
        else:
            items = [{"value": repr(val)}]
        for item in items:
            add_result(key, item)
    add_result("meta", {"stage": "ws_fuzz", "tested": len(endpoints)})

def _runner_graphql(ctx) -> None:
    att_mod = _opt_import("websecure.scanners.graphql_attacks")
    rpc_mod = _opt_import("websecure.scanners.graphql_rpc")
    
    # [WS3] Fallback to robust scanner if 'attacks' module missing
    if not att_mod:
        mod_base = _opt_import("websecure.scanners.graphql")
        if mod_base and hasattr(mod_base, "GraphQLScanner"):
             add_result("offensive", {"type": "GraphQL Attacks", "severity": "Note", "reason": "Attack module missing, running standard GraphQL Scanner"})
             _runner_scanners_graphql(ctx)
             return
        
        add_result("offensive", {"type": "GraphQL", "severity": "Info", "reason": "Modüller bulunamadı."})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return

    gql_url = _get(getattr(ctx, "config", {}) or {}, "graphql.url", None)
    if not gql_url:
        base = (getattr(ctx, "url", "") or "").rstrip("/")
        gql_url = base + "/graphql"

    if rpc_mod and hasattr(rpc_mod, "GraphQLClient") and callable(getattr(rpc_mod, "GraphQLClient")):
        client = rpc_mod.GraphQLClient(getattr(ctx, "session", None),
                                       timeout=float(_get(getattr(ctx, "config", {}) or {}, "timeouts.graphql", 20.0)),
                                       verify_tls=True)
    else:
        # Check if att_mod has Client, if not use base
        client_cls = getattr(att_mod, "GraphQLClient", None)
        if not client_cls:
             # Try base scanner's client if available? Or fail gracefully
             return
        client = client_cls(getattr(ctx, "session", None),
                            timeout=float(_get(getattr(ctx, "config", {}) or {}, "timeouts.graphql", 20.0)))

    probes: List[Tuple[str, Callable]] = []
    if hasattr(att_mod, "probe_persisted_query_bypass") and callable(getattr(att_mod, "probe_persisted_query_bypass")):
        probes.append(("PersistedQuery", getattr(att_mod, "probe_persisted_query_bypass")))
    if hasattr(att_mod, "probe_batch_alias_storm") and callable(getattr(att_mod, "probe_batch_alias_storm")):
        probes.append(("AliasStorm", getattr(att_mod, "probe_batch_alias_storm")))
    if hasattr(att_mod, "probe_introspection_bypass") and callable(getattr(att_mod, "probe_introspection_bypass")):
        probes.append(("IntrospectionBypass", getattr(att_mod, "probe_introspection_bypass")))

    # Hata yakalama her probe thread'inin İÇİNDE yapılır; process-global
    # threading.excepthook KULLANILMAZ (bu fonksiyonun kendisi de offensive
    # paralel grubunda bir _safe thread'inde koşar — global hook'u ezmek
    # kardeş fazların hatalarını yanlış faza atfederdi). list.append CPython'da
    # GIL altında atomiktir, findings_acc gibi errors da kilitsiz toplanır.
    errors: List[Dict[str, Any]] = []
    ts: List[threading.Thread] = []
    findings_acc: List[Dict[str, Any]] = []

    for name, func in probes:
        def _runner(call: Callable = func, label: str = name):
            try:
                # İmza-keşfi ile kwargs filtrele
                kw = _filter_kwargs(call, dict(client=client, url=gql_url, endpoint=gql_url,
                                               session=getattr(ctx, "session", None),
                                               debug=bool(getattr(ctx, "debug", False))))
                out = call(**kw)
                for f in list(out or []):
                    findings_acc.append({
                        "type": f"GraphQL {label}",
                        "severity": f.get("severity", "Informational"),
                        "url": f.get("endpoint", gql_url),
                        "reason": f.get("issue"),
                        "proof": redact_sensitive({
                            "payload": f.get("payload"),
                            "extra": f.get("extra", {}),
                            "body_hint": f.get("body_hint")
                        })
                    })
            except BaseException as e:  # noqa: BLE001 — kasıtlı: probe hatasını izole et
                errors.append({
                    "name": f"graphql::{label}",
                    "error": f"{type(e).__name__}: {e}",
                    "trace": "".join(
                        traceback.format_exception(type(e), e, e.__traceback__)
                    )[-1000:]
                })

        t = threading.Thread(target=_runner, name=f"graphql::{name}", daemon=True)
        t.start()
        ts.append(t)

    for t in ts:
        t.join()

    for it in findings_acc:
        add_result("offensive", it)
    if errors:
        add_result("errors", {"type": "graphql_probes", "errors": errors})

def _runner_passive_recon(ctx) -> None:
    mod = _opt_import("websecure.scanners.passive_recon")
    if not mod:
        add_result("discovery", {"type": "Passive Recon", "severity": "Info", "reason": "Module not found"})
        return

    base_url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)

    # 1. Content Discovery (Robots, Sitemap, Common Files)
    if hasattr(mod, "ContentDiscoveryScanner"):
        cds = mod.ContentDiscoveryScanner(sess)
        findings = cds.scan(base_url)
        for f in findings:
            add_result("discovery", f)

    # 2. Passive JS Analysis
    if hasattr(mod, "PassiveJSScanner"):
        pjs = mod.PassiveJSScanner(sess)
        # Get endpoints from discovery results
        endpoints = results.get("endpoints", [])
        # Also include base_url
        if base_url not in endpoints:
            endpoints.append(base_url)
        
        # Filter for likely JS files or pages that might contain JS
        # For simplicity, we scan explicitly .js files found
        js_urls = [u for u in endpoints if u.split('?')[0].endswith(".js")]
        
        if js_urls:
            js_findings = pjs.scan(js_urls)
            for f in js_findings:
                add_result("offensive", f) # JS secrets are offensive/vulnerability findings

def _runner_owasp_nuclei(ctx) -> None:
    mod = _opt_import("websecure.scanners.owasp")
    if not mod:
         add_result("offensive", {"type": "OWASP", "severity": "Info", "reason": "Module not found"})
         return
    run_func = getattr(mod, "run_owasp_and_nuclei", None)
    if not callable(run_func):
         add_result("offensive", {"type": "OWASP", "severity": "Info", "reason": "run function not found"})
         return

    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
    session = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    cfg = getattr(ctx, "config", {}) or {}
    debug = bool(getattr(ctx, "debug", False))
    auth_ctx = getattr(ctx, "auth_ctx", None)

    # Madde 3: nuclei'yi BURADA yalnız dedike `nuclei` fazı koşmuyorsa çalıştır.
    # `nuclei` fazı _flag("nuclei", default=True) ile varsayılan açık → kullanıcı
    # offensive.nuclei.enabled=False yapmadıkça bu OWASP fazı nuclei'yi ATLAR
    # (aksi halde nuclei aynı taramada iki kez koşardı, aynı paralel grupta).
    _off_cfg = (cfg.get("offensive") or {}) if isinstance(cfg, dict) else {}
    _nuclei_phase_enabled = ((_off_cfg.get("nuclei") or {}).get("enabled")) is not False

    # Run — populates results dict with a01_, a02_, etc. OWASP buckets
    run_func(url, results, session, config=cfg, debug=debug, auth_ctx=auth_ctx,
             run_nuclei=not _nuclei_phase_enabled)

    # Flush OWASP bucket findings into the global reporting system.
    # owasp.py writes to results["a01_broken_access_control"] etc. but never calls
    # add_result() directly, so findings would otherwise be invisible to the reporter.
    _owasp_bucket_keys = [k for k in results if isinstance(k, str) and k.startswith("a0")]
    for _bk in _owasp_bucket_keys:
        for _item in (results.get(_bk) or []):
            if not isinstance(_item, dict):
                continue
            _item.setdefault("source", "owasp")
            _item.setdefault("owasp_bucket", _bk)
            add_result("vulnerability", _item)
            if _item.get("severity") in ("Critical", "High", "Medium"):
                add_result("offensive", _item)

    add_result("meta", {"stage": "owasp_nuclei", "status": "completed"})




def _runner_scanners_graphql(ctx) -> None:
    mod = _opt_import("websecure.scanners.graphql")
    if not mod or not hasattr(mod, "GraphQLScanner"):
        return
    base_url = (getattr(ctx, "url", None) or getattr(ctx, "base_url", None) or "")
    sess = getattr(ctx, "session", None)
    scanner = mod.GraphQLScanner(sess, debug=bool(getattr(ctx, "debug", False)))
    # It updates ctx.results internally if it inherits keys
    # But checks return.
    res = scanner.run(base_url)
    _merge_results(ctx, res)

def _runner_scanners_tls(ctx) -> None:
    # Use scanners.tls if available
    mod = _opt_import("websecure.scanners.tls")
    if not mod or not hasattr(mod, "scan_tls"):
        return
    base_url = (getattr(ctx, "url", None) or getattr(ctx, "base_url", None) or "")
    # scanners.tls.scan_tls(url, results=...)
    mod.scan_tls(base_url, results=getattr(ctx, "results", {}))

# ----------------------------- Plan oluşturucu -----------------------------


# ----------------------------- CSRF Runner (NEW) -----------------------------
def _runner_csrf(ctx) -> None:
    mod = _opt_import("websecure.scanners.csrf")
    if not mod:
        add_result("offensive", {"type": "CSRF", "severity": "Info", "reason": "Module not found"})
        return
    
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
    session = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    debug = bool(getattr(ctx, "debug", False))
    
    # Run scan
    if hasattr(mod, "run_scan"):
        # run_scan internally adds findings or info notes
        mod.run_scan(url, session, results, debug=debug)
    elif hasattr(mod, "run"):
         mod.run(url, session=session, results=results, debug=debug)
    else:
        add_result("offensive", {"type": "CSRF", "severity": "Info", "reason": "run_scan/run not found"})


# ----------------------------- Phase 4 Runner Functions ---------------------------

def _runner_ssti(ctx) -> None:
    mod = _opt_import("websecure.scanners.ssti")
    if not mod:
        add_result("meta", {"stage": "ssti", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    endpoints = results.get("endpoints", [url]) if results else [url]
    run_fn = getattr(mod, "run", None) or getattr(mod, "SSTIScanner", None)
    if callable(run_fn):
        try:
            scanner_cls = getattr(mod, "SSTIScanner", None)
            if scanner_cls:
                forms = results.get("forms_meta", []) if results else []
                all_forms = []
                for page in forms:
                    if isinstance(page, dict):
                        all_forms.extend(page.get("forms", []))
                scanner_cls(session=sess, results=results).run(
                    url, endpoints=endpoints, forms=all_forms
                )
            else:
                run_fn(url, session=sess, results=results)
        except Exception as e:
            _logger.warning(f"[phases] SSTI runner error: {e}")
            _report_phase_error("ssti", "phases._runner_ssti", e)


def _runner_idor(ctx) -> None:
    mod = _opt_import("websecure.scanners.idor")
    if not mod:
        add_result("meta", {"stage": "idor", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    endpoints = results.get("endpoints", [url]) if results else [url]
    role_sessions = getattr(ctx, "role_sessions", {}) or {}
    try:
        scanner_cls = getattr(mod, "IDORScanner", None)
        if scanner_cls:
            scanner_cls(session=sess, results=results).run(url, endpoints=endpoints, role_sessions=role_sessions)
        elif hasattr(mod, "run"):
            mod.run(url, session=sess, results=results)
    except Exception as e:
        _logger.warning(f"[phases] IDOR runner error: {e}")
        _report_phase_error("idor", "phases._runner_idor", e)


def _runner_auth_matrix(ctx) -> None:
    mod = _opt_import("websecure.scanners.auth_scanners")
    if not mod:
        add_result("meta", {"stage": "auth_matrix", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    endpoints = results.get("endpoints", [url]) if results else [url]
    role_sessions = getattr(ctx, "role_sessions", {}) or {}

    try:
        # Multi-role auth matrix (sadece role_sessions varsa)
        if role_sessions:
            scanner_cls = getattr(mod, "AuthMatrixScanner", None)
            if scanner_cls:
                scanner_cls(session=sess, results=results, role_sessions=role_sessions).run(
                    url, endpoints=endpoints, role_sessions=role_sessions
                )
        else:
            # role_sessions yoksa: module-level run() çağır — OAuth2, SAML, 2FA bypass, PasswordReset tarar
            _logger.info("[phases] auth_matrix: role_sessions yok, temel auth taraması başlatılıyor")
            if hasattr(mod, "run"):
                mod.run(url, session=sess, results=results)
    except Exception as e:
        _logger.warning(f"[phases] AuthMatrix runner error: {e}")
        _report_phase_error("auth_matrix", "phases._runner_auth_matrix", e)


def _runner_bypass_403(ctx) -> None:
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    try:
        _call_if_exists("websecure.scanners.bypass_403", ("run", "scan"), url,
                        session=sess, results=results, cfg=getattr(ctx, "config", {}))
    except Exception as e:
        _logger.warning(f"[phases] bypass_403 runner error: {e}")
        _report_phase_error("bypass_403", "phases._runner_bypass_403", e)


def _runner_clickjacking(ctx) -> None:
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    try:
        _call_if_exists("websecure.scanners.clickjacking", ("run", "scan"), url,
                        session=sess, results=results)
    except Exception as e:
        _logger.warning(f"[phases] clickjacking runner error: {e}")
        _report_phase_error("clickjacking", "phases._runner_clickjacking", e)


def _runner_param_pollution(ctx) -> None:
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    try:
        _call_if_exists("websecure.scanners.param_pollution", ("run", "scan"), url,
                        session=sess, results=results)
    except Exception as e:
        _logger.warning(f"[phases] param_pollution runner error: {e}")
        _report_phase_error("param_pollution", "phases._runner_param_pollution", e)


def _runner_business_logic(ctx) -> None:
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    try:
        _call_if_exists("websecure.scanners.business_logic", ("run", "scan"), url,
                        session=sess, results=results)
    except Exception as e:
        _logger.warning(f"[phases] business_logic runner error: {e}")
        _report_phase_error("business_logic", "phases._runner_business_logic", e)


_DOM_XSS_SKIP_EXT = (
    ".js", ".mjs", ".cjs", ".css", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".otf", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico",
    ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".wasm", ".zip", ".gz",
)
_DOM_XSS_SKIP_PATH = (
    "/_next/static/", "/static/chunks/", "/static/media/", "/_next/static",
    "/static/js/", "/static/css/", "/assets/", "/dist/", "/build/static/",
)


def _is_static_asset(u: str) -> bool:
    """Statik varlık mı (DOM XSS testine UYGUN DEĞİL)?

    DOM XSS yalnız uygulama DOM'u olan HTML sayfalarında anlamlıdır. Statik
    .js/.css/medya dosyaları tarayıcıda düz metin gösterilir; bunlara DOM XSS
    testi yapmak yüzlerce SAHTE bulgu üretiyordu (Next.js chunk'ları: her
    /_next/static/chunks/*.js için fragment/window.name/localStorage/postMessage
    = 4 sahte High/Critical). Bu yüzden DOM XSS hedeflerinden elenir.
    """
    try:
        from urllib.parse import urlparse as _up
        p = _up(u).path.lower()
    except Exception:
        return False
    if any(p.endswith(ext) for ext in _DOM_XSS_SKIP_EXT):
        return True
    if any(seg in p for seg in _DOM_XSS_SKIP_PATH):
        return True
    return False


def _runner_dom_xss(ctx) -> None:
    mod = _opt_import("websecure.scanners.dom_xss")
    if not mod:
        add_result("meta", {"stage": "dom_xss", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    _raw_eps = results.get("endpoints", [url]) if results else [url]
    # Statik asset'leri (JS/CSS/medya/Next.js chunk'ları) ele — DOM XSS yalnız
    # HTML sayfalarına uygulanır. Eşlenik gerçek bir HTML hedef kalmazsa ana url'e düş.
    endpoints = [e for e in _raw_eps if e and not _is_static_asset(e)] or [url]
    _skipped = len(_raw_eps) - len(endpoints)
    if _skipped > 0:
        _logger.info(f"[dom_xss] {_skipped} statik asset (JS/CSS/medya) DOM XSS hedefinden elendi")
    try:
        scanner_cls = getattr(mod, "DOMXSSScanner", None)
        if scanner_cls:
            scanner_cls(session=sess, results=results).run(url, endpoints=endpoints)
        elif hasattr(mod, "run"):
            mod.run(url, session=sess, results=results)
    except Exception as e:
        _logger.warning(f"[phases] DOMXSSScanner runner error: {e}")
        _report_phase_error("dom_xss", "phases._runner_dom_xss", e)


def _runner_cmdi(ctx) -> None:
    """Command Injection (CMDi) taraması."""
    mod = _opt_import("websecure.scanners.cmdi")
    if not mod:
        add_result("meta", {"stage": "cmdi", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    # CMDi önceden YALNIZ base url'yi alıyordu — ne keşfedilen endpoint'ler ne de
    # formlar geçiliyordu. Artık prioritize edilmiş endpoint listesi + form alanları
    # (login/feedback/search) da test edilir.
    _eps = results.get("endpoints", [url]) if results else [url]
    try:
        _eps = _prioritize_urls(_eps)[:40] or [url]
    except Exception:
        _eps = list(_eps)[:40] or [url]
    _forms = []
    for _page in (results.get("forms_meta", []) if results else []):
        if isinstance(_page, dict):
            _forms.extend(_page.get("forms", []))
    try:
        run_fn = getattr(mod, "run", None)
        if callable(run_fn):
            run_fn(url, session=sess, results=results, debug=False, urls=_eps, forms=_forms)
    except Exception as e:
        _logger.warning(f"[phases] CMDi runner error: {e}")
        _report_phase_error("cmdi", "phases._runner_cmdi", e)


def _runner_lfi(ctx) -> None:
    """LFI / Directory Traversal taraması."""
    mod = _opt_import("websecure.scanners.lfi")
    if not mod:
        add_result("meta", {"stage": "lfi", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    try:
        run_fn = getattr(mod, "run", None)
        if callable(run_fn):
            run_fn(url, session=sess, results=results, debug=False)
    except Exception as e:
        _logger.warning(f"[phases] LFI runner error: {e}")
        _report_phase_error("lfi", "phases._runner_lfi", e)


def _runner_cors(ctx) -> None:
    """CORS Misconfiguration taraması."""
    mod = _opt_import("websecure.scanners.cors")
    if not mod:
        add_result("meta", {"stage": "cors", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    try:
        run_fn = getattr(mod, "run", None)
        if callable(run_fn):
            run_fn(url, session=sess, results=results, debug=False)
    except Exception as e:
        _logger.warning(f"[phases] CORS runner error: {e}")
        _report_phase_error("cors", "phases._runner_cors", e)


def _runner_subdomain_takeover(ctx) -> None:
    """Subdomain Takeover taraması."""
    mod = _opt_import("websecure.scanners.subdomain_takeover")
    if not mod:
        add_result("meta", {"stage": "subdomain_takeover", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    try:
        run_fn = getattr(mod, "run", None)
        if callable(run_fn):
            run_fn(url, session=sess, results=results, debug=False)
    except Exception as e:
        _logger.warning(f"[phases] Subdomain Takeover runner error: {e}")
        _report_phase_error("subdomain_takeover", "phases._runner_subdomain_takeover", e)


def _runner_session_scanner(ctx) -> None:
    """Session & Cookie güvenlik taraması."""
    mod = _opt_import("websecure.scanners.session_scanner")
    if not mod:
        add_result("meta", {"stage": "session_scanner", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    try:
        scanner_cls = getattr(mod, "SessionScanner", None)
        if scanner_cls:
            scanner_cls(session=sess, results=results, debug=False).run(url)
        else:
            run_fn = getattr(mod, "run", None)
            if callable(run_fn):
                run_fn(url, session=sess, results=results)
    except Exception as e:
        _logger.warning(f"[phases] Session scanner error: {e}")
        _report_phase_error("session_scanner", "phases._runner_session_scanner", e)


def _runner_crlf_injection(ctx) -> None:
    """CRLF Injection ve header injection taraması."""
    mod = _opt_import("websecure.scanners.crlf_injection")
    if not mod:
        add_result("meta", {"stage": "crlf_injection", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    auth_ctx = getattr(ctx, "auth_ctx", None)
    try:
        run_fn = getattr(mod, "run", None)
        if callable(run_fn):
            run_fn(url, session=sess, debug=False, auth_ctx=auth_ctx)
    except Exception as e:
        _logger.warning(f"[phases] CRLF Injection runner error: {e}")
        _report_phase_error("crlf_injection", "phases._runner_crlf_injection", e)


def _runner_waf_bypass_validate(ctx) -> None:
    """WAFBypassScanner — WAF bypass doğrulama ve bypass mümkünlüğü testi."""
    try:
        from websecure.core.waf_bypass import WAFBypassScanner as _WAFBypassScanner
    except ImportError:
        add_result("meta", {"stage": "waf_bypass_validate", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    if not url:
        return
    sess = getattr(ctx, "session", None) or hardened_session({})
    results = _ensure_results_bucket(ctx)
    debug = getattr(ctx, "debug", False)
    try:
        scanner = _WAFBypassScanner(session=sess, results=results, debug=debug)
        scanner.run(url)
    except Exception as e:
        _logger.warning(f"[phases] WAF bypass validate runner error: {e}")
        _report_phase_error("waf_bypass_validate", "phases._runner_waf_bypass_validate", e)


def _runner_waf_fingerprint(ctx) -> None:
    """WAF davranış parmak izi analizi (waf_fingerprint modülü)."""
    mod = _opt_import("websecure.core.waf_fingerprint") or _opt_import("core.waf_fingerprint")
    if not mod:
        add_result("meta", {"stage": "waf_fingerprint", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None) or hardened_session({})
    try:
        fingerprinter_cls = getattr(mod, "WAFFingerprinter", None)
        if fingerprinter_cls:
            fp = fingerprinter_cls()
            report = fp.fingerprint(url, session=sess)
            if report:
                add_result("waf", {
                    "url": url,
                    "vendor": getattr(report, "vendor", "unknown"),
                    "confidence": getattr(report, "confidence", 0.0),
                    "bypass_hints": getattr(report, "bypass_strategies", []),
                    "rate_limit": getattr(report, "rate_limit", {}),
                    "detected": getattr(report, "detected", False),
                    "message": f"WAF parmak izi: {getattr(report, 'vendor', 'unknown')}",
                })
    except Exception as e:
        _logger.warning(f"[phases] WAF fingerprint runner error: {e}")
        _report_phase_error("waf_fingerprint", "phases._runner_waf_fingerprint", e)


def _runner_exploit_orchestrator(ctx) -> None:
    """Exploit Orchestrator — zafiyet bulgularını zincirleyerek gerçek saldırı dener."""
    try:
        from websecure.core.exploit_orchestrator import exploit_from_results  # noqa: PLC0415
        results = _ensure_results_bucket(ctx)
        cfg = getattr(ctx, "config", {}) or {}
        exploit_cfg = (cfg.get("exploitation") or {})
        if exploit_cfg.get("enabled", True) is False:
            add_result("meta", {"stage": "exploit_orchestrator", "status": "skipped:disabled"})
            return
        url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
        # Bulguları tüm saldırı kovalarından topla
        all_findings: list = []
        for bucket in ("offensive", "sqli", "xss", "ssrf", "idor", "ssti", "cmdi", "lfi", "final"):
            bucket_items = results.get(bucket, [])
            if isinstance(bucket_items, list):
                all_findings.extend([i for i in bucket_items if isinstance(i, dict)])
        if not all_findings:
            add_result("meta", {"stage": "exploit_orchestrator", "status": "skipped:no-findings"})
            return
        exploit_results = exploit_from_results(
            scan_results={"findings": all_findings, "target": url},
            cfg=cfg,
        )
        if exploit_results:
            n = len(exploit_results) if isinstance(exploit_results, list) else 1
            add_result("exploitation", {"results": exploit_results, "total": n, "target": url})
            _logger.info(f"[phases] Exploit orchestrator: {n} exploit tamamlandı")
    except ImportError:
        add_result("meta", {"stage": "exploit_orchestrator", "status": "skipped:module-not-found"})
    except Exception as e:
        _logger.warning(f"[phases] Exploit orchestrator runner error: {e}")
        _report_phase_error("exploit_orchestrator", "phases._runner_exploit_orchestrator", e)


def _runner_human_adapter(ctx) -> None:
    """HumanLike Adapter — tarama oturumunu insan benzeri davranışla sarar."""
    try:
        from websecure.core.human_adapter import make_human_session  # noqa: PLC0415
        cfg = getattr(ctx, "config", {}) or {}
        _scan_profile = str((cfg.get("settings") or {}).get("scan_profile", "stealth")).lower()
        human_sess = make_human_session(profile=_scan_profile)
        # ctx'e human_adapter nesnesini ekle; diğer fazlar isteğe bağlı kullanabilir
        if hasattr(ctx, "__dict__") or hasattr(ctx, "__slots__"):
            try:
                setattr(ctx, "human_adapter", human_sess)
            except (AttributeError, TypeError) as _fix_e:
                _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")
        add_result("meta", {"stage": "human_adapter", "status": "active", "profile": _scan_profile})
        _logger.info(f"[phases] HumanLike adapter aktif: {_scan_profile}")
    except ImportError:
        add_result("meta", {"stage": "human_adapter", "status": "skipped:module-not-found"})
    except Exception as e:
        _logger.warning(f"[phases] HumanLike adapter error: {e}")
        _report_phase_error("human_adapter", "phases._runner_human_adapter", e)


_VERIFY_BUCKETS = {
    "offensive", "sqlmap", "xss", "ssrf", "idor", "ssti", "auth_matrix",
    "nosqli", "csrf", "jwt", "lfi", "cmdi", "cors", "crlf_injection",
    "session_scanner", "prototype_pollution", "xxe", "race_condition",
    "headers", "tls", "subdomain_takeover", "dom_xss",
}


def _runner_verify_and_score(ctx) -> None:
    """Run verification + CVSS scoring + correlation on all accumulated findings."""
    try:
        from websecure.core.reporting import get_global_results, verify_and_score
        g_res = get_global_results()
        all_findings = []
        for bucket, items in g_res.items():
            if bucket in _VERIFY_BUCKETS:
                all_findings.extend([i for i in items if isinstance(i, dict)])
        oast_events = g_res.get("oast_callbacks", [])
        # CVSS scoring runs ONCE inside verify_and_score with the real auth/WAF
        # context (Madde 3 — önceki çift score_findings çağrısı kaldırıldı).
        waf_profile = getattr(ctx, "waf_profile", None)
        waf_detected = bool(getattr(waf_profile, "detected", False)) if waf_profile else False
        auth_required = bool(getattr(ctx, "authenticated", False))
        scored = verify_and_score(all_findings, oast_events,
                                  auth_required=auth_required, waf_detected=waf_detected)
        add_result("final", {"findings": scored, "total": len(scored)})
        _logger.info(f"[phases] Verified & scored {len(scored)} findings")

        # Warn if OAST-dependent findings exist but OAST was not configured
        if not oast_events:
            _OAST_TYPES = {"SSRF", "XXE", "SSRF/XXE", "Server-Side Request Forgery",
                           "XML External Entity", "Blind SSRF"}
            unverified_oast = [f for f in scored if f.get("type") in _OAST_TYPES]
            if unverified_oast:
                _logger.warning(
                    f"[phases] {len(unverified_oast)} SSRF/XXE finding(s) could not be verified: "
                    "no OAST server configured. Configure 'oast.interactsh_url' in config.json "
                    "to enable out-of-band confirmation."
                )
    except Exception as e:
        _logger.warning(f"[phases] verify_and_score error: {e}")

    # --- Correlation Engine: exploit zinciri + tekrar eden bulgular ---
    try:
        from websecure.core.reporting import get_global_results as _get_global_results
        from websecure.core.correlation_engine import get_correlation_engine, ChainCorrelation
        g_res = _get_global_results()

        # Tüm anlamlı bulgular
        corr_findings: list = []
        for bucket, items in g_res.items():
            if isinstance(items, list) and bucket not in ("meta", "errors", "final", "oast_callbacks"):
                corr_findings.extend([i for i in items if isinstance(i, dict) and i.get("type")])

        if len(corr_findings) >= 2:
            scan_id = str(getattr(ctx, "scan_id", "current"))

            # Within-scan: sadece ChainCorrelation — FingerprintCorrelation/Escalation aynı liste için anlamsız
            # P12 fix: mutating _strategies on the global singleton stripped all other
            # strategies for every subsequent caller (e.g. api/server.py). Use fork()
            # to get a scoped copy instead of polluting the singleton.
            chain_engine = get_correlation_engine().fork(strategies=[ChainCorrelation()])
            matches = chain_engine.correlate(
                corr_findings, corr_findings,
                scan1_id=scan_id, scan2_id=scan_id,
                min_confidence=0.5,
            )

            if matches:
                report = chain_engine.report(matches)
                add_result("correlation", report)
                _logger.info(
                    f"[phases] Korelasyon: {len(matches)} zincir tespit edildi — "
                    + ", ".join(report.get("chains", []))
                )
                # Kritik zincirleri offensive bucket'a da ekle.
                # B3 FIX: url alanı yoktu → raporda `url=-` hayalet/placeholder bulgu
                # gibi görünüyordu. Korelasyon hedefin kendisiyle ilgili olduğundan
                # taban URL'i ekle (boşsa zincirdeki bulgu URL'lerinden ilkini kullan).
                _chain_url = (getattr(ctx, "url", None) or getattr(ctx, "base_url", None)
                              or getattr(ctx, "target", None) or "")
                for m in matches:
                    _m_url = _chain_url or getattr(m, "url", "") or ""
                    add_result("offensive", {
                        "type": "Exploit Chain",
                        "severity": "High",
                        "url": _m_url,
                        "chain": m.chain_name,
                        "confidence": m.confidence,
                        "description": m.description,
                        "finding1_id": m.finding1_id,
                        "finding2_id": m.finding2_id,
                    })
    except Exception as e:
        _logger.warning(f"[phases] correlation_engine error: {e}")

    # Faz 6: PayloadScorer feedback — başarılı bulgular Bayesian scorer'a kaydet
    try:
        from websecure.core.payload_engine import get_engine as _get_payload_engine
        from websecure.core.reporting import get_global_results as _get_global_results_ps
        _pe_scorer = _get_payload_engine()
        _g_ps = _get_global_results_ps()
        _bucket_cat_map = {
            "offensive": "generic", "sqli": "sqli", "xss": "xss",
            "rce": "rce", "lfi": "lfi", "ssrf": "ssrf", "ssti": "ssti",
            "nosqli": "nosql", "cmdi": "rce",
        }
        for _bucket_ps, _cat_ps in _bucket_cat_map.items():
            for _f_ps in _g_ps.get(_bucket_ps, []):
                if not isinstance(_f_ps, dict):
                    continue
                if _f_ps.get("severity") in ("Critical", "High"):
                    _payload_ps = _f_ps.get("payload") or _f_ps.get("evidence") or ""
                    if _payload_ps and isinstance(_payload_ps, str) and len(_payload_ps) < 512:
                        _pe_scorer.record_result(_payload_ps, _cat_ps, success=True)
        _pe_scorer.save_scores()
        _logger.debug("[phases] PayloadScorer güncellendi.")
    except Exception as _ps_exc:
        _logger.debug(f"[phases] PayloadScorer feedback error: {_ps_exc}")


# ----------------------------- Faz 3 — Yeni Runner'lar ---------------------------

def _runner_prototype_pollution(ctx) -> None:
    """Prototype Pollution taraması (JSON body / query string / constructor)."""
    mod = _opt_import("websecure.scanners.prototype_pollution")
    if not mod:
        add_result("meta", {"stage": "prototype_pollution", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))
    auth_ctx = getattr(ctx, "auth_ctx", None)
    try:
        findings = mod.run(url, session=sess, debug=debug, auth_ctx=auth_ctx) or []
        for f in findings:
            add_result("prototype_pollution", f)
            if f.get("severity") in ("Critical", "High", "Medium"):
                add_result("offensive", f)
        add_result("meta", {"stage": "prototype_pollution", "findings": len(findings)})
    except Exception as e:
        _logger.warning(f"[phases] Prototype Pollution runner error: {e}")
        _report_phase_error("prototype_pollution", "phases._runner_prototype_pollution", e)


def _runner_headers_scanner(ctx) -> None:
    """Security headers tam analizi (CSP, HSTS, email security, DNS CAA, vb.)."""
    mod = _opt_import("websecure.scanners.headers")
    if not mod:
        add_result("meta", {"stage": "headers_scanner", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))
    try:
        findings = mod.run(url, session=sess, debug=debug) or []
        if isinstance(findings, list):
            for f in findings:
                add_result("security_headers", f)
        elif isinstance(findings, dict):
            add_result("security_headers", findings)
        add_result("meta", {"stage": "headers_scanner", "status": "completed"})
    except Exception as e:
        _logger.warning(f"[phases] Headers Scanner runner error: {e}")
        _report_phase_error("headers_scanner", "phases._runner_headers_scanner", e)


def _runner_race_condition(ctx) -> None:
    """Race Condition taraması — RaceConditionScanner orchestrator kullanır."""
    mod = _opt_import("websecure.scanners.race_condition")
    if not mod:
        add_result("meta", {"stage": "race_condition", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))
    results = _ensure_results_bucket(ctx)
    try:
        scanner_cls = getattr(mod, "RaceConditionScanner", None)
        if scanner_cls:
            findings = scanner_cls(session=sess, results=results, debug=debug).run(url) or []
        else:
            findings = mod.run(url, session=sess, debug=debug) or []
        for f in findings:
            add_result("race_condition", f)
            if f.get("severity") in ("Critical", "High", "Medium"):
                add_result("offensive", f)
        add_result("meta", {"stage": "race_condition", "findings": len(findings)})
    except Exception as e:
        _logger.warning(f"[phases] Race Condition runner error: {e}")
        _report_phase_error("race_condition", "phases._runner_race_condition", e)


# ---- Faz 7: httpx probe + dalfox verify runners -------------------------

def _runner_httpx_probe(ctx) -> None:
    """httpx ile hızlı HTTP prob — teknoloji tespiti, HTTP/2, TLS, status kodu."""
    try:
        from websecure.integrations.httpx_runner import HttpxWrapper
        wrapper = HttpxWrapper()
        if not wrapper.is_available():
            add_result("meta", {"stage": "httpx_probe", "status": "skipped:not-installed"})
            return
        url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
        if not url:
            return
        result = wrapper.probe_bulk([url], tech_detect=True, tls_probe=True)
        # Teknoloji zenginleştirme: httpx tespitlerini ctx.technologies'e ekle
        all_techs = set(getattr(ctx, "technologies", []) or [])
        for pr_dict in result.extra.get("probe_results", []):
            for t in (pr_dict.get("tech") or []):
                if t:
                    all_techs.add(t)
        if all_techs:
            ctx.technologies = sorted(all_techs)
        # Probe host verisini 'httpx' kovasına yaz → rapordaki "HTTP Probe Sonuçları
        # — httpx" tablosu YALNIZ results['httpx']/'http_probe'i okur. Eskiden bu
        # veri HİÇBİR kovaya yazılmıyordu (yalnız meta'ya status özeti) → tablo HİÇ
        # render edilmiyordu (kullanıcı "httpx görmedim" şikâyeti). probe_results
        # dict'leri url/status_code/title/tech/content_length taşır = renderer'ın
        # beklediği şekil. 'httpx' recon kovasıdır (bkz reporting._NON_FINDING_BUCKETS)
        # → bulgu/severity sayısını şişirmez; html zaten type'sız öğeyi bulgudan eler.
        for _pr in result.extra.get("probe_results", []):
            if isinstance(_pr, dict) and (_pr.get("url") or _pr.get("input")):
                add_result("httpx", _pr)
        for f in result.findings:
            add_result("meta", f.to_dict())
        add_result("meta", {
            "stage": "httpx_probe",
            "status": "ok",
            "probed": len(result.extra.get("probe_results", [])),
            "findings": result.finding_count,
        })
        _logger.info(f"[phases] httpx_probe: {result.finding_count} bulgu, techs={len(all_techs)}")
    except Exception as e:
        _logger.warning(f"[phases] httpx_probe runner error: {e}")
        _report_phase_error("httpx_probe", "phases._runner_httpx_probe", e)


def _runner_dalfox_verify(ctx) -> None:
    """Dalfox ile XSS bulgularını doğrula — yalnızca dalfox kuruluysa çalışır."""
    try:
        from websecure.integrations.dalfox import DalfoxWrapper
        wrapper = DalfoxWrapper()
        if not wrapper.is_available():
            add_result("meta", {"stage": "dalfox_verify", "status": "skipped:not-installed"})
            return
        from websecure.core.reporting import get_global_results as _get_gr_df
        g_res = _get_gr_df()
        # XSS bulgularını topla
        xss_findings: list = []
        for bucket in ("xss", "dom_xss", "offensive"):
            for f in g_res.get(bucket, []):
                if not isinstance(f, dict) or not f.get("url"):
                    continue
                t = (f.get("type") or "").lower()
                if "xss" in t or bucket == "xss":
                    xss_findings.append(f)
        # Tekrarları url+type bazında deduplicate et
        seen_keys: set = set()
        unique_xss: list = []
        for f in xss_findings:
            k = f"{f.get('url', '')}|{f.get('type', '')}"
            if k not in seen_keys:
                seen_keys.add(k)
                unique_xss.append(f)
        if not unique_xss:
            add_result("meta", {"stage": "dalfox_verify", "status": "skipped:no-xss-findings"})
            return
        # Cookie + blind callback al
        cookie = ""
        auth_ctx = getattr(ctx, "auth_ctx", None)
        if isinstance(auth_ctx, dict):
            cookie = auth_ctx.get("cookie") or auth_ctx.get("session_cookie") or ""
        blind_callback = ""
        cfg = getattr(ctx, "config", {}) or {}
        oast_cfg = (cfg.get("oast") or {}) if isinstance(cfg, dict) else {}
        if isinstance(oast_cfg, dict):
            blind_callback = oast_cfg.get("interactsh_url") or oast_cfg.get("blind_callback") or ""
        wrapper.blind_callback = blind_callback
        result = wrapper.verify_xss_findings(unique_xss, cookie=cookie)
        for f in result.findings:
            d = f.to_dict()
            add_result("xss", d)
            add_result("offensive", d)
        add_result("meta", {
            "stage": "dalfox_verify",
            "status": "ok",
            "input_findings": len(unique_xss),
            "confirmed": result.finding_count,
        })
        _logger.info(
            f"[phases] dalfox_verify: {len(unique_xss)} XSS → "
            f"{result.finding_count} doğrulandı"
        )
    except Exception as e:
        _logger.warning(f"[phases] dalfox_verify runner error: {e}")
        _report_phase_error("dalfox_verify", "phases._runner_dalfox_verify", e)


def _runner_xxe(ctx) -> None:
    """XXE (XML External Entity) taraması — XXEScanner sınıfını doğrudan kullanır.
    OAST domain kurulursa XXEScanner'a geçirilir; out-of-band konfirmasyonu sağlar.
    """
    mod = _opt_import("websecure.scanners.ssrf_xxe")
    if not mod:
        add_result("meta", {"stage": "xxe", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    if not url:
        add_result("meta", {"stage": "xxe", "status": "skipped:no-url"})
        return
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    debug = bool(getattr(ctx, "debug", False))
    # OAST domain for out-of-band detection
    oast_domain = _setup_oast_domain(ctx)
    try:
        xxe_cls = getattr(mod, "XXEScanner", None)
        if xxe_cls:
            cfg = getattr(ctx, "config", {}) or {}
            oast_cfg = dict(cfg.get("oast", {}) or {})
            if oast_domain:
                oast_cfg["dns_domain"] = oast_domain
            init_kw = dict(session=sess, results=results, debug=debug)
            kw = _filter_kwargs(xxe_cls.__init__, init_kw)
            scanner = xxe_cls(**kw)
            endpoints = results.get("endpoints", [url]) or [url]
            run_fn = getattr(scanner, "run", None) or getattr(scanner, "scan", None)
            if callable(run_fn):
                run_kw = dict(url=url, endpoints=endpoints, oast_cfg=oast_cfg)
                run_fn(**_filter_kwargs(run_fn, run_kw))
            # Flush findings
            for item in (results.get("xxe") or []):
                if isinstance(item, dict):
                    add_result("xxe", item)
                    if item.get("severity") in ("Critical", "High"):
                        add_result("offensive", item)
        else:
            # Fallback: delegate to combined ssrf_xxe runner
            _runner_scanners_ssrf_xxe(ctx)
    except Exception as e:
        _logger.warning(f"[phases] XXE runner error: {e}")
        _report_phase_error("xxe", "phases._runner_xxe", e)


def _runner_ssrf(ctx) -> None:
    """SSRF (Server-Side Request Forgery) taraması — SSRFScanner sınıfını doğrudan kullanır.
    OAST domain kurulursa out-of-band SSRF tespiti sağlanır.
    """
    mod = _opt_import("websecure.scanners.ssrf_xxe")
    if not mod:
        add_result("meta", {"stage": "ssrf", "status": "skipped:module-not-found"})
        return
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or getattr(ctx, "target", "")
    if not url:
        add_result("meta", {"stage": "ssrf", "status": "skipped:no-url"})
        return
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    debug = bool(getattr(ctx, "debug", False))
    # OAST domain for out-of-band detection
    oast_domain = _setup_oast_domain(ctx)
    try:
        ssrf_cls = getattr(mod, "SSRFScanner", None)
        if ssrf_cls:
            endpoints = results.get("endpoints", [url]) or [url]
            cfg = getattr(ctx, "config", {}) or {}
            oast_cfg = dict(cfg.get("oast", {}) or {})
            if oast_domain:
                oast_cfg["dns_domain"] = oast_domain
            # SSRFScanner(session, endpoints) — imzaya uyum
            try:
                scanner = ssrf_cls(sess, endpoints)
            except TypeError:
                init_kw = dict(session=sess, results=results, debug=debug)
                scanner = ssrf_cls(**_filter_kwargs(ssrf_cls.__init__, init_kw))
            if results is not None and not hasattr(scanner, "results"):
                scanner.results = results
            elif results is not None:
                scanner.results = results
            run_fn = getattr(scanner, "run", None)
            if callable(run_fn):
                # SSRFScanner.run(self, url, **kwargs) — `url` ZORUNLU.
                # Eskiden run_kw'de url yoktu → "missing 1 required positional
                # argument: 'url'" ile SSRF taraması tamamen çöküyordu (XXE runner
                # ise url'i doğru geçiyordu). endpoints/oast_cfg run imzasında
                # **kwargs altında olduğundan _filter_kwargs onları eler; url ise
                # adlandırılmış parametre olduğu için korunur.
                run_kw = dict(url=url, endpoints=endpoints, oast_cfg=oast_cfg)
                try:
                    run_fn(**_filter_kwargs(run_fn, run_kw))
                except TypeError:
                    run_fn(url)
            # Flush findings from scanner.results
            for bucket_key in ("ssrf", "offensive"):
                for item in (getattr(scanner, "results", {}) or {}).get(bucket_key) or []:
                    if isinstance(item, dict):
                        add_result(bucket_key, item)
        else:
            # Fallback: combined ssrf_xxe runner
            _runner_scanners_ssrf_xxe(ctx)
    except Exception as e:
        _logger.warning(f"[phases] SSRF runner error: {e}")
        _report_phase_error("ssrf", "phases._runner_ssrf", e)


def _runner_session_analysis(ctx) -> None:
    """
    CookieSecurityAnalyzer + SessionLifecycleProber ile oturum güvenliğini denetler.
    Zayıf/HTTPOnly eksik/SameSite eksik cookie'leri bulgu olarak kaydeder.
    """
    try:
        from websecure.core.session_manager import CookieSecurityAnalyzer
        url = (getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
               or getattr(ctx, "target", ""))
        if not url:
            add_result("meta", {"stage": "session_analysis", "status": "skipped:no-url"})
            return
        session = getattr(ctx, "session", None)
        if session is None:
            add_result("meta", {"stage": "session_analysis", "status": "skipped:no-session"})
            return

        analyzer = CookieSecurityAnalyzer(session=session)
        audit_results = analyzer.audit(url)

        finding_count = 0
        for audit in (audit_results if isinstance(audit_results, list) else [audit_results]):
            if not isinstance(audit, dict):
                try:
                    # CookieAuditResult dataclass
                    audit = vars(audit)
                except Exception:
                    continue
            issues = audit.get("issues") or []
            if issues:
                add_result("offensive", {
                    "type": "WeakCookieSecurity",
                    "severity": audit.get("severity", "Medium"),
                    "title": f"Cookie Güvenlik Sorunu: {audit.get('name', 'unknown')}",
                    "url": url,
                    "evidence": "; ".join(str(i) for i in issues),
                    "tool": "session_manager",
                    "verified": True,
                })
                finding_count += 1

        add_result("meta", {
            "stage": "session_analysis",
            "status": "completed",
            "findings": finding_count,
        })
        _logger.info(f"[phases] session_analysis: {finding_count} cookie sorun")
    except Exception as e:
        _logger.debug(f"[phases] session_analysis error: {e}")
        add_result("meta", {"stage": "session_analysis", "status": "skipped:error",
                             "error": str(e)[:200]})


# ----------------------------- Plan Builder End ---------------------------

def _offensive_phases(ctx) -> List[Phase]:
    cfg = getattr(ctx, "config", {}) or {}
    off = cfg.get("offensive", {}) if isinstance(cfg, dict) else {}

    base_enabled = bool(_get(off, "enabled", True))
    # aggressive override: ctx.mode AGGRESSIVE => always evaluate offensive set
    mode = str(getattr(ctx, "mode", getattr(getattr(ctx, "config", {}), "mode", "")).upper())
    if mode in ("AGGRESSIVE","DEEP"):
        base_enabled = True
    # Max-power / no_timeout (default ON): the smart scan must run the FULL
    # offensive suite — never silently downgrade to a recon-only pass. An explicit
    # offensive.enabled=False in config is still honored (handled per-phase by the
    # user_val check inside _flag), so this only lifts the *implicit* gate.
    if base_enabled is not True and _get(off, "enabled") is not False:
        try:
            from websecure.core.http import no_timeout_enabled as _nt_full
            if _nt_full():
                base_enabled = True
        except Exception:
            pass
    # [Smart Tactics] "Avcı" Modu ve Derinlemesine Analiz
    detected_techs = getattr(ctx, "technologies", []) or []
    
    def _flag(key: str, default: bool = False, tech_trigger: str = None) -> bool:
        """
        Phase etkinleştirme mantığı:
        1. Config'de AÇIK ise -> True
        2. Config'de KAPALI ise -> False (Kullanıcı explicit olarak kapattıysa saygı duy)
        3. Config'de BELİRSİZ ise:
           a. İlgili teknoloji tespit edildiyse -> TRUE (Smart Activation)
           b. Profil Aggressive/Deep ise -> TRUE
           c. Varsayılan (default) -> ...
        """
        
        # 1. Config Check (Explicit)
        user_val = _get(off, f"{key}.enabled")
        if user_val is False:
             return False # Kullanıcı ısrarla kapatmış
        if user_val is True:
             return True # Kullanıcı ısrarla açmış
             
        # 2. Smart Tech Trigger
        if tech_trigger and tech_trigger in detected_techs:
             print(f"[Smart Tactics] '{key}' modülü, '{tech_trigger}' algoritması tespit edildiği için OTOMATİK etkinleştirildi.")
             return True
             
        # 3. Profile/Default Fallback
        return base_enabled and default

    phases: List[Phase] = [
        Phase(id="waf_detect", title="WAF Tespiti", enabled=True, runner=lambda c: _safe(c, lambda: phase_waf_detect(c), "waf_detect"), tags=["waf","recon"]),
        Phase(id="subdomain", title="Subdomain Enumeration", enabled=_flag("subdomain", default=True), runner=lambda c: _safe(c, lambda: _runner_subdomain(c), "subdomain"), tags=["recon","dns","passive"]),
        Phase(
            id="katana",
            title="Katana JS-Aware Web Crawler",
            enabled=_flag("katana", default=True),
            runner=lambda c: _safe(c, lambda: _runner_katana(c), "katana"),
            tags=["recon", "crawler", "js", "endpoints"],
        ),
        Phase(
            id="browser_crawler",
            title="Browser Crawler (Playwright/SPA)",
            enabled=_flag("browser_crawler", default=True),
            runner=lambda c: _safe(c, lambda: _runner_browser_crawler(c), "browser_crawler"),
            tags=["recon", "crawler", "js", "spa", "playwright"],
        ),
        Phase(
            id="session_analysis",
            title="Session / Cookie Güvenlik Analizi",
            enabled=_flag("session_analysis", default=True),
            runner=lambda c: _safe(c, lambda: _runner_session_analysis(c), "session_analysis"),
            tags=["session", "cookie", "passive", "auth"],
        ),
        Phase(id="discovery", title="Keşif", enabled=True, runner=lambda c: _safe(c, lambda: _runner_discovery(c), "discovery"), tags=["crawl","map"]),
        Phase(
            id="http_crawler_orchestrator",
            title="HTTP Crawler Orchestrator (OpenAPI/GraphQL/gRPC/Param)",
            enabled=_flag("http_crawler_orchestrator", default=True),
            runner=lambda c: _safe(c, lambda: _runner_http_crawler_orchestrator(c), "http_crawler_orchestrator"),
            tags=["crawl", "recon", "endpoints", "openapi", "graphql"],
        ),
        Phase(id="passive_recon", title="Pasif Keşif", enabled=True, runner=lambda c: _safe(c, lambda: _runner_passive_recon(c), "passive_recon"), tags=["passive"]),
        Phase(
            id="httpx_probe",
            title="httpx HTTP/2 Prob & Teknoloji Tespiti",
            enabled=_flag("httpx_probe", default=True),
            runner=lambda c: _safe(c, lambda: _runner_httpx_probe(c), "httpx_probe"),
            tags=["recon", "tech-detect", "http2"],
        ),
        Phase(id="js_analysis", title="JS Dosya & Endpoint Analizi", enabled=True, runner=lambda c: _safe(c, lambda: _runner_js_analysis(c), "js_analysis"), tags=["js","recon","secrets"]),
        Phase(id="ffuf", title="FFUF Content & File Fuzzing", enabled=True, runner=lambda c: _safe(c, lambda: _runner_ffuf(c), "ffuf"), tags=["fuzz","content","files"]),
        Phase(id="feroxbuster", title="Feroxbuster Recursive Discovery", enabled=True, runner=lambda c: _safe(c, lambda: _runner_feroxbuster(c), "feroxbuster"), tags=["fuzz","content"]),
        Phase(id="nuclei", title="Nuclei Vulnerability Scanner", enabled=_flag("nuclei", default=True), runner=lambda c: _safe(c, lambda: _runner_nuclei(c), "nuclei"), tags=["vuln","cve","nuclei"]),
        Phase(id="port_scan", title="Port Taraması", enabled=True, runner=lambda c: _safe(c, lambda: run_portscan(c), "portscan"), tags=["infra","port"]),
        Phase(id="xss", title="XSS Scan (Nuclei/Dalfox)", enabled=_flag("xss", default=True), runner=lambda c: _safe(c, lambda: _runner_xss(c), "xss"), tags=["xss","active"]),
        Phase(
            id="dalfox_verify",
            title="Dalfox XSS Doğrulama",
            enabled=_flag("dalfox_verify", default=True),
            runner=lambda c: _safe(c, lambda: _runner_dalfox_verify(c), "dalfox_verify"),
            tags=["xss", "verify", "dalfox"],
        ),
        Phase(id="csrf", title="CSRF Scanner", enabled=_flag("csrf", default=True), runner=lambda c: _safe(c, lambda: _runner_csrf(c), "csrf"), tags=["csrf","active"]),
        Phase(
            id="scanners.ssrf_xxe",
            title="SSRF/XXE",
            enabled=_flag("scanners.ssrf_xxe", default=True), # Deep profilde varsayılan açık olsun
            runner=lambda c: _safe(c, lambda: _runner_scanners_ssrf_xxe(c), "scanners.ssrf_xxe"),
            tags=["active", "oast"],
        ),
        Phase(
            id="scanners.request_smuggling",
            title="HTTP Request Smuggling",
            enabled=_flag("scanners.request_smuggling", default=True),
            runner=lambda c: _safe(c, lambda: _runner_scanners_request_smuggling(c), "scanners.request_smuggling"),
            tags=["active", "http"],
        ),
        Phase(
            id="mass_assignment",
            title="Mass Assignment",
            enabled=_flag("mass_assignment", default=True, tech_trigger="rest_api"),
            runner=lambda c: _safe(c, lambda: _runner_mass_assignment(c), "mass_assignment"),
            tags=["api", "json"],
        ),
        Phase(
            id="nosqli",
            title="NoSQL Injection",
            enabled=_flag("nosqli", default=True, tech_trigger="rest_api"), # API varsa NoSQL riski yüksek
            runner=lambda c: _safe(c, lambda: _runner_nosqli(c), "nosqli"),
            tags=["api", "query"],
        ),
        Phase(
            id="polyglot_probe",
            title="Polyglot Injection-Surface Probe",
            enabled=_flag("polyglot_probe", default=True),
            runner=lambda c: _safe(c, lambda: run_polyglot_probe(c), "polyglot_probe"),
            tags=["active", "triage", "fuzz"],
        ),
        Phase(
            id="scanners.file_upload",
            title="File Upload Abuse",
            enabled=_flag("scanners.file_upload", default=True),
            runner=lambda c: _safe(c, lambda: _runner_scanners_file_upload(c), "scanners.file_upload"),
            tags=["active", "upload"],
        ),
        Phase(
            id="scanners.graphql",
            title="GraphQL Scanner",
            enabled=_flag("scanners.graphql", default=True, tech_trigger="graphql"),
            runner=lambda c: _safe(c, lambda: _runner_scanners_graphql(c), "scanners.graphql"),
            tags=["active", "graphql"],
        ),
        Phase(
            id="scanners.ws_fuzz",
            title="WebSocket Fuzzer",
            enabled=_flag("scanners.ws_fuzz", default=True, tech_trigger="websocket"),
            runner=lambda c: _safe(c, lambda: _runner_scanners_ws_fuzz(c), "scanners.ws_fuzz"),
            tags=["active", "websocket"],
        ),
        Phase(
            id="scanners.tls",
            title="TLS/SSL Analysis",
            enabled=_flag("scanners.tls", default=True),
            runner=lambda c: _safe(c, lambda: _runner_scanners_tls(c), "scanners.tls"),
            tags=["ssl", "config"],
        ),
        Phase(
            id="sqlmap",
            title="SQLMap Scan",
            enabled=_flag("sqlmap", default=True),
            runner=lambda c: _safe(c, lambda: _runner_sqlmap(c), "sqlmap"),
            tags=["sqli", "active"],
        ),
        Phase(
            id="jwt",
            title="JWT Manipülasyonları",
            enabled=_flag("jwt", default=True, tech_trigger="rest_api"),
            runner=lambda c: _safe(c, lambda: _runner_jwt(c), "jwt"),
            tags=["auth", "token"],
        ),
        Phase(id="races", title="Race/Concurrency", enabled=_flag("races", default=True), runner=lambda c: _safe(c, lambda: _runner_business_logic_races(c), "races"), tags=["race","concurrency"]),
        Phase(
            id="scanners.graphql_attacks",
            title="GraphQL Saldırı Seti",
            enabled=_flag("graphql_attacks", default=True, tech_trigger="graphql"),
            runner=lambda c: _safe(c, lambda: _runner_graphql(c), "scanners.graphql_attacks"),
            tags=["graphql", "api"],
        ),
        Phase(
            id="owasp_and_nuclei",
            title="OWASP & Nuclei",
            enabled=_flag("owasp_nuclei", default=True),
            runner=lambda c: _safe(c, lambda: _runner_owasp_nuclei(c), "owasp_and_nuclei"),
            tags=["active", "signatures"],
        ),
        # Phase 4 new scanners
        Phase(
            id="ssti",
            title="SSTI (Template Injection)",
            enabled=_flag("ssti", default=True),
            runner=lambda c: _safe(c, lambda: _runner_ssti(c), "ssti"),
            tags=["active", "injection", "rce"],
        ),
        Phase(
            id="idor",
            title="IDOR / Object Access Control",
            enabled=_flag("idor", default=True),
            runner=lambda c: _safe(c, lambda: _runner_idor(c), "idor"),
            tags=["active", "access_control"],
        ),
        Phase(
            id="auth_matrix",
            title="Authorization Matrix",
            enabled=_flag("auth_matrix", default=True),
            runner=lambda c: _safe(c, lambda: _runner_auth_matrix(c), "auth_matrix"),
            tags=["auth", "access_control"],
        ),
        Phase(
            id="dom_xss",
            title="DOM XSS (Browser-based)",
            enabled=_flag("dom_xss", default=True),
            runner=lambda c: _safe(c, lambda: _runner_dom_xss(c), "dom_xss"),
            tags=["xss", "browser", "dom"],
        ),
        Phase(
            id="open_redirect",
            title="Open Redirect",
            enabled=_flag("open_redirect", default=True),
            runner=lambda c: _safe(c, lambda: _runner_open_redirect(c), "open_redirect"),
            tags=["active", "redirect", "a01"],
        ),
        # ── Yeni tarayıcı fazları ──────────────────────────────────────────
        Phase(
            id="cmdi",
            title="Command Injection (CMDi)",
            enabled=_flag("cmdi", default=True),
            runner=lambda c: _safe(c, lambda: _runner_cmdi(c), "cmdi"),
            tags=["active", "injection", "rce"],
        ),
        Phase(
            id="lfi",
            title="LFI / Directory Traversal",
            enabled=_flag("lfi", default=True),
            runner=lambda c: _safe(c, lambda: _runner_lfi(c), "lfi"),
            tags=["active", "lfi", "traversal", "rce"],
        ),
        Phase(
            id="cors",
            title="CORS Misconfiguration",
            enabled=_flag("cors", default=True),
            runner=lambda c: _safe(c, lambda: _runner_cors(c), "cors"),
            tags=["active", "cors", "config", "a05"],
        ),
        Phase(
            id="subdomain_takeover",
            title="Subdomain Takeover",
            enabled=_flag("subdomain_takeover", default=True),
            runner=lambda c: _safe(c, lambda: _runner_subdomain_takeover(c), "subdomain_takeover"),
            tags=["active", "dns", "takeover", "recon"],
        ),
        Phase(
            id="session_scanner",
            title="Session & Cookie Güvenliği",
            enabled=_flag("session_scanner", default=True),
            runner=lambda c: _safe(c, lambda: _runner_session_scanner(c), "session_scanner"),
            tags=["active", "auth", "session", "cookie"],
        ),
        Phase(
            id="crlf_injection",
            title="CRLF Injection / Header Injection",
            enabled=_flag("crlf_injection", default=True),
            runner=lambda c: _safe(c, lambda: _runner_crlf_injection(c), "crlf_injection"),
            tags=["active", "injection", "header", "a03"],
        ),
        # ── Faz 20 — phase_offensive'de var ama plan'da eksikti ─────────────
        Phase(
            id="bypass_403",
            title="403 Bypass (Path/Verb/Header)",
            enabled=_flag("bypass_403", default=True),
            runner=lambda c: _safe(c, lambda: _runner_bypass_403(c), "bypass_403"),
            tags=["active", "access_control", "bypass"],
        ),
        Phase(
            id="clickjacking",
            title="Clickjacking / Double-Click Jacking",
            enabled=_flag("clickjacking", default=True),
            runner=lambda c: _safe(c, lambda: _runner_clickjacking(c), "clickjacking"),
            tags=["active", "ui", "clickjacking"],
        ),
        Phase(
            id="param_pollution",
            title="HTTP Parameter Pollution (HPP)",
            enabled=_flag("param_pollution", default=True),
            runner=lambda c: _safe(c, lambda: _runner_param_pollution(c), "param_pollution"),
            tags=["active", "injection", "waf_bypass"],
        ),
        Phase(
            id="business_logic",
            title="Business Logic Flaws",
            enabled=_flag("business_logic", default=True),
            runner=lambda c: _safe(c, lambda: _runner_business_logic(c), "business_logic"),
            tags=["active", "logic", "a04"],
        ),
        # ── Faz 3 — Yeni bağlanan scanner'lar ────────────────────────────────
        Phase(
            id="prototype_pollution",
            title="Prototype Pollution",
            enabled=_flag("prototype_pollution", default=True),
            runner=lambda c: _safe(c, lambda: _runner_prototype_pollution(c), "prototype_pollution"),
            tags=["active", "injection", "js", "api"],
        ),
        Phase(
            id="xxe",
            title="XXE (XML External Entity)",
            enabled=_flag("xxe", default=True),
            runner=lambda c: _safe(c, lambda: _runner_xxe(c), "xxe"),
            tags=["active", "injection", "xml", "oast"],
        ),
        Phase(
            id="ssrf",
            title="SSRF (Server-Side Request Forgery)",
            enabled=_flag("ssrf", default=True),
            runner=lambda c: _safe(c, lambda: _runner_ssrf(c), "ssrf"),
            tags=["active", "ssrf", "oast"],
        ),
        Phase(
            id="headers_scanner",
            title="Security Headers Analizi (Tam)",
            enabled=_flag("headers_scanner", default=True),
            runner=lambda c: _safe(c, lambda: _runner_headers_scanner(c), "headers_scanner"),
            tags=["passive", "headers", "config", "a05"],
        ),
        Phase(
            id="race_condition",
            title="Race Condition (Tam Orchestrator)",
            enabled=_flag("race_condition", default=True),
            runner=lambda c: _safe(c, lambda: _runner_race_condition(c), "race_condition"),
            tags=["active", "race", "concurrency", "logic"],
        ),
        Phase(
            id="waf_fingerprint",
            title="WAF Davranış Parmak İzi",
            enabled=_flag("waf_fingerprint", default=True),
            runner=lambda c: _safe(c, lambda: _runner_waf_fingerprint(c), "waf_fingerprint"),
            tags=["waf", "recon", "fingerprint"],
        ),
        Phase(
            id="waf_bypass_validate",
            title="WAF Bypass Doğrulama",
            enabled=_flag("waf_bypass_validate", default=True),
            runner=lambda c: _safe(c, lambda: _runner_waf_bypass_validate(c), "waf_bypass_validate"),
            tags=["waf", "bypass", "offensive"],
        ),
        Phase(
            id="human_adapter",
            title="HumanLike Session Adapter",
            enabled=_flag("human_adapter", default=True),
            runner=lambda c: _safe(c, lambda: _runner_human_adapter(c), "human_adapter"),
            tags=["stealth", "evasion", "session"],
        ),
        Phase(
            id="exploit_orchestrator",
            title="Exploit Orchestrator (Zincir Saldırı)",
            enabled=_flag("exploit_orchestrator", default=True),
            runner=lambda c: _safe(c, lambda: _runner_exploit_orchestrator(c), "exploit_orchestrator"),
            tags=["exploitation", "rce", "post_exploit", "chain"],
        ),
        Phase(
            id="oast_verification",
            title="OAST Callback Doğrulama (Interactsh)",
            enabled=_flag("oast_verification", default=True),
            runner=lambda c: _safe(c, lambda: _runner_oast_verification(c), "oast_verification"),
            tags=["oast", "verify", "blind", "ssrf", "xxe"],
        ),
        Phase(
            id="fuzz_param_discovery",
            title="Fuzz & Parametre Keşfi",
            enabled=_flag("fuzz_param_discovery", default=True),
            runner=lambda c: _safe(c, lambda: _runner_fuzz_and_param_discovery(c), "fuzz_param_discovery"),
            tags=["fuzz", "param", "discovery", "active"],
        ),
        Phase(
            id="authorization_matrix",
            title="Authorization Matrix (IDOR/PrivEsc)",
            enabled=_flag("authorization_matrix", default=True),
            runner=lambda c: _safe(c, lambda: _runner_authorization_matrix(c), "authorization_matrix"),
            tags=["auth", "idor", "access_control", "active"],
        ),
        # ── Doğrulama & Raporlama ─────────────────────────────────────────
        Phase(id="verify_and_score", title="Doğrulama & Skorlama", enabled=True, runner=lambda c: _safe(c, lambda: _runner_verify_and_score(c), "verify_and_score"), tags=["verify","score"]),
        Phase(id="reporting", title="Raporlama", enabled=True, runner=lambda c: _safe(c, lambda: _runner_reporting_and_integration(c), "reporting"), tags=["report"])
    ]

    # Görünürlüklerini koru; devre dışı olanlar için reason ekle
    for ph in phases:
        if not ph.enabled and not ph.reason:
            ph.reason = "config.offensive.{}.enabled = false".format(
                ph.id if ph.id != "scanners.graphql_attacks" else "graphql_attacks"
            )
    return phases

def build_plan(ctx) -> List[Dict[str, Any]]:
    """
    Tüm planı döndürür. Mevcut (varsa) `ctx.base_plan` üzerinden genişletme yapar.
    Eğer ctx.base_plan yoksa yalnızca `offensive` fazları döndürür.
    Dönen yapı sade dict'lere dönüştürülür; runner callables korunur.
    """
    # Faz 17: Plugin registry — built-in scanner'ları kaydet + entry point plugin'lerini yükle
    try:
        from websecure.core.plugin_registry import get_registry as _get_registry
        _reg = _get_registry()
        _reg.register_builtins()
        _reg.discover_entry_points()
        _logger.debug(f"[phases] Plugin registry: {len(_reg.list_all())} plugin yüklendi")
    except Exception as _preg_exc:
        _logger.debug(f"[phases] Plugin registry başlatılamadı: {_preg_exc!r}")

    # Quick tech probe before phase selection so tech_trigger flags work correctly
    if not getattr(ctx, "technologies", None):
        try:
            _quick_tech_probe(ctx)
        except Exception as exc:
            _logger.debug(f"[phases] Quick tech probe failed: {exc!r}")

    # Faz 18: LoginDiscovery — giriş sayfalarını bul ve ctx'e kaydet
    try:
        from websecure.core.analysis import discover_login_urls_with_config
        url = (getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
               or getattr(ctx, "target", ""))
        if url and not getattr(ctx, "login_urls", None):
            cfg = getattr(ctx, "config", {}) or {}
            session = getattr(ctx, "session", None)
            login_urls = discover_login_urls_with_config(url, cfg=cfg, session=session)
            if login_urls:
                try:
                    ctx.login_urls = login_urls
                except AttributeError:
                    pass
                add_result("meta", {"stage": "login_discovery",
                                    "login_urls": login_urls[:10]})
                _logger.info(f"[phases] LoginDiscovery: {len(login_urls)} giriş URL'si bulundu")
    except Exception as _ld_exc:
        _logger.debug(f"[phases] LoginDiscovery hatası: {_ld_exc!r}")

    # Faz 6: PayloadEngine — CMS-aware payload pre-computation after tech probe
    try:
        from websecure.core.payload_engine import get_engine as _get_payload_engine
        _pe = _get_payload_engine()
        _techs = list(getattr(ctx, "technologies", []) or [])
        if _techs:
            _cms_name = _pe.fingerprinter.detect(_techs)
            if _cms_name and not getattr(ctx, "detected_cms", None):
                ctx.detected_cms = _cms_name
                _logger.info(f"[phases] PayloadEngine CMS tespit: {_cms_name}")
            _cms_paths = _pe.get_cms_paths(_techs)
            if _cms_paths and not getattr(ctx, "cms_extra_paths", None):
                ctx.cms_extra_paths = _cms_paths
            _ctx_payloads: dict = {}
            for _cat in ("sqli", "xss", "rce", "lfi"):
                _ctx_payloads[_cat] = _pe.get(category=_cat, tech_tags=_techs, limit=100)
            ctx.cms_payloads = _ctx_payloads
            add_result("meta", {
                "stage": "cms_payload_init",
                "cms": _cms_name,
                "techs": _techs,
                "cms_paths_count": len(_cms_paths),
            })
    except Exception as _pe_exc:
        _logger.debug(f"[phases] PayloadEngine init error: {_pe_exc}")

    base: List[Phase] = []
    existing = getattr(ctx, "base_plan", None)
    if isinstance(existing, list):
    # Plan: discovery -> headers -> tls -> offensive -> finalize
        for item in existing:
            if isinstance(item, Phase):
                base.append(item)
            elif isinstance(item, dict):
                base.append(Phase(
                    id=item.get("id") or item.get("name") or "phase",
                    title=item.get("title") or item.get("name") or item.get("id") or "Phase",
                    enabled=bool(item.get("enabled", True)),
                    reason=item.get("reason"),
                    runner=item.get("runner"),
                    tags=list(item.get("tags", [])),
                    visible=bool(item.get("visible", True))
                ))

    out: List[Dict[str, Any]] = []
    for ph in base + _offensive_phases(ctx):
        out.append({
            "id": ph.id,
            "title": ph.title,
            "enabled": ph.enabled,
            "reason": ph.reason,
            "visible": ph.visible,
            "tags": ph.tags,
            "runner": ph.runner,
        })
        # Akış düzeltmesi: raporlama fazı plan dışı tutulur; final rapor flush_reporting ile yapılır.
    out = [p for p in out if str(p.get('id') or '').lower() not in ('report','reporting') and 'report' not in (p.get('tags') or [])]
    return out

def plan_visible(plan: Dict) -> Dict:
    out = {"visible": []}
    for name, entry in (plan or {}).items():
        if isinstance(entry, dict) and entry.get("enabled"):
            out["visible"].append({
                "id": entry.get("id") or name,
                "title": entry.get("title") or name,
                "enabled": True
            })
    return out

def _mk_result(name, status, metrics=None, errors=None):
    return {
        "name": name,
        "status": status,
        "started_at": None,
        "ended_at": None,
        "metrics": metrics or {},
        "errors": errors or [],
    }


def run_discovery(ctx):

    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)

    if not isinstance(getattr(ctx, "results", None), dict):
        setattr(ctx, "results", {})
    results = ctx.results  # type: ignore[attr-defined]  # ctx shape varies (dict or ScanContext)

    if url:
        from websecure.crawler import WebCrawler
        try:
            _wc = WebCrawler(getattr(ctx, "session", None), url, debug=bool(getattr(ctx, "debug", False)))
            _res = _wc.start()
            if isinstance(_res, dict):
                results.update(_res)
        except Exception as e:
            add_result("errors", {"stage": "discovery_fallback", "error": str(e)})

    # --- Smart Tactics Analysis: header + body + endpoint-based detection ---
    if isinstance(results, dict):
        techs = set(getattr(ctx, "technologies", []) or [])
        endpoints = results.get("endpoints", []) or []

        # Endpoint URL pattern detection
        if any("graphql" in u or "/gql" in u for u in endpoints):
            techs.add("graphql")
        if any("/api/" in u for u in endpoints) or any(u.endswith(".json") for u in endpoints):
            techs.add("rest_api")
        if any("wp-content" in u or "wp-json" in u or "wp-admin" in u for u in endpoints):
            techs.add("wordpress"); techs.add("php")
        if any(".jsp" in u or ".do" in u for u in endpoints):
            techs.add("java")
        if any(".php" in u for u in endpoints):
            techs.add("php")
        if any(".aspx" in u or ".ashx" in u for u in endpoints):
            techs.add("aspnet")
        if any("websocket" in u or "/ws/" in u for u in endpoints):
            techs.add("websocket")
        if any("socket.io" in u for u in endpoints):
            techs.add("websocket"); techs.add("nodejs")

        # Also do a fresh header probe if we haven't done it yet
        if url and not getattr(ctx, "_tech_probe_done", False):
            try:
                from websecure.core.http import hardened_session as _hs
                _resp = _hs({}).get(url, timeout=8, allow_redirects=True)
                techs |= _detect_technologies(_resp)
                ctx._tech_probe_done = True
            except Exception as exc:
                _logger.debug(f"[phases] Header tech probe failed for {url}: {exc!r}")

        ctx.technologies = list(techs)
        if techs:
            add_result("meta", {"stage": "smart_analysis", "detected_technologies": list(techs)})
            _logger.info(f"[SmartTactics] Teknolojiler: {', '.join(sorted(techs))}")

    eps = len((results.get("endpoints") or [])) if isinstance(results, dict) else 0
    add_result("phase_event", {"phase": "discovery", "checked": eps})
    return _mk_result("discovery", "ok", {"endpoints": eps})


def run_portscan(ctx):
    """Port taraması: Nmap entegrasyonu — profile göre maksimum güç."""
    from websecure.integrations.nmap import NmapWrapper
    from urllib.parse import urlparse

    cfg = getattr(ctx, "config", {}) or {}
    nmap_cfg = cfg.get("nmap", {}) or {}
    # results: ctx.results referansına bağlı kalmalı — yeni dict oluşturma (falsy boş dict'e dikkat)
    _ctx_results = getattr(ctx, "results", None)
    if not isinstance(_ctx_results, dict):
        _ctx_results = {}
        try:
            ctx.results = _ctx_results
        except (AttributeError, TypeError) as _fix_e:
            _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")
    results = _ctx_results

    # Nmap disabled ise atla
    if not nmap_cfg.get("enabled", True):
        add_result("meta", {"stage": "portscan", "severity": "note", "message": "Nmap devre dışı (config)."})
        return _mk_result("portscan", "skipped", {"reason": "disabled"})

    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return _mk_result("portscan", "failed", {"error": "no_url"})

    # Host adını ayıkla
    if "://" in url:
        host = urlparse(url).hostname or url
    else:
        host = url.split(":")[0]

    nmap = NmapWrapper()
    if not nmap.is_available():
        add_result("meta", {"stage": "portscan", "severity": "warning", "message": "Nmap binary bulunamadı — sudo apt install nmap"})
        return _mk_result("portscan", "failed", {"error": "nmap_missing"})

    # --- Mod seçimi: scan_profile'a göre —
    # Config portları veya arguments YOK SAYILIR — en güçlü tarama yapılır
    scan_profile = str(
        cfg.get("scan_profile") or
        (cfg.get("settings") or {}).get("scan_profile") or "aggressive"
    ).upper()
    nmap_mode = {
        "STEALTH":    "stealth",    # -sT -T2 (root gerektirmez, gizli)
        "AGGRESSIVE": "aggressive", # -sV -sC --top-ports 10000 + vuln + root'ta -A
        "NORMAL":     "normal",     # -sV top-1000 ports (deep/65535 çok yavaş)
    }.get(scan_profile, "aggressive")

    # Akıllı port tarama stratejisi: hedefe göre mod seç
    import socket as _socket
    try:
        resolved_ip = _socket.gethostbyname(host)
        # RFC-1918 private ranges: 10.x.x.x, 172.16–31.x.x, 192.168.x.x
        _parts = resolved_ip.split(".")
        _second = int(_parts[1]) if len(_parts) >= 2 else 0
        _private = (
            resolved_ip.startswith("10.") or
            resolved_ip.startswith("192.168.") or
            (resolved_ip.startswith("172.") and 16 <= _second <= 31)
        )
        if _private and nmap_mode == "aggressive":
            nmap_mode = "deep"  # iç ağda aggressive çok gürültülü
    except Exception:
        resolved_ip = None

    _tor_proxy = cfg.get("_tor_proxy")
    # Config'deki port listesi ve ekstra argümanlar
    _cfg_ports = nmap_cfg.get("ports", [])
    ports_arg = ",".join(map(str, _cfg_ports)) if _cfg_ports else None
    extra_args = list(nmap_cfg.get("arguments", []) or []) or None

    # [CDN/origin] CDN/WAF arkasındaysa origin'i keşfet; bulunamazsa 80/443'e
    # sınırla — tüm port taraması CDN edge'i üzerinde anlamsızdır.
    _scan_target = host
    try:
        from websecure.integrations.nmap import assess_cdn_origin
        _do_origin = bool(nmap_cfg.get("origin_discovery", True))
        _cdn = assess_cdn_origin(host, url=url, do_origin_discovery=_do_origin)
        add_result("nmap_recon", _cdn)
        if _cdn.get("is_cdn"):
            add_result("meta", {"stage": "portscan", "severity": "note",
                                "message": _cdn.get("note", "")})
            if _cdn.get("origin_ip") and _cdn.get("origin_verified"):
                _scan_target = _cdn["origin_ip"]
                _logger.info(f"[Nmap] CDN bypass — gerçek origin taranıyor: {_scan_target}")
            elif _cdn.get("limit_ports") and nmap_cfg.get("cdn_limit_to_web", True):
                ports_arg = _cdn["limit_ports"]
                _logger.info(f"[Nmap] CDN edge — port taraması {ports_arg} ile sınırlandı")
    except Exception as _ce:
        _logger.debug(f"[Nmap] CDN/origin değerlendirmesi atlandı: {_ce!r}")

    _logger.info(f"[Nmap] Başlıyor — host={_scan_target}, mod={nmap_mode} (profil={scan_profile}), ports={ports_arg or 'default'}")

    try:
        scan_res = nmap.scan(_scan_target, mode=nmap_mode, ports=ports_arg, extra_args=extra_args, proxy=_tor_proxy)
    except Exception as e:
        return _mk_result("portscan", "failed", {"error": str(e)})

    port_records = []
    open_ports = []

    for item in scan_res:
        p = item.get("port")
        if not p:
            continue
        open_ports.append(p)
        svc = item.get("service", "unknown")
        product = item.get("product", "")
        version = item.get("version", "")
        scripts = item.get("scripts", {})
        _h = item.get("ip") or host
        record = {
            "severity": "info",
            "message": f"Açık port: {p}/{item.get('protocol','tcp')} ({svc} {product} {version})".strip(),
            "url": f"{_h}:{p}",
            "target": _h,
            "host": _h,
            "port": p,
            "proto": item.get("protocol", "tcp"),
            "service": svc,
            "product": product,
            "version": version,
            "cpe": item.get("cpe", []),
            "os_guess": item.get("os_guess", ""),
            "scripts": scripts,
            "state": "open",
        }
        port_records.append(record)
        # Rapor bucket'ına ekle
        add_result("nmap", record)

        # NSE script çıktılarından yapılandırılmış finding'ler üret
        _scheme = "https" if svc in ("https", "ssl", "tls") or p in (443, 8443, 4443) else "http"
        _base_url = f"{_scheme}://{_h}:{p}"

        if "ssl-cert" in scripts:
            add_result("tls", {
                "severity": "Info", "type": "SSL Certificate",
                "url": _base_url, "host": _h, "port": p,
                "message": f"SSL Certificate on {_h}:{p}",
                "detail": {"raw": scripts["ssl-cert"][:1500]},
            })

        if "ssl-enum-ciphers" in scripts:
            _ct = scripts["ssl-enum-ciphers"]
            _cs = "Info"; _ctype = "TLS Cipher Suites"
            if any(f" - {g}" in _ct for g in ("C", "D", "F")):
                _cs = "High"; _ctype = "Weak TLS Cipher Suite"
            elif " - B" in _ct:
                _cs = "Medium"; _ctype = "Moderate TLS Cipher Suite"
            add_result("tls", {
                "severity": _cs, "type": _ctype,
                "url": _base_url, "host": _h, "port": p,
                "message": f"TLS Cipher Suites on {_h}:{p}",
                "detail": {"raw": _ct[:1500]},
            })

        if "ssl-heartbleed" in scripts and "VULNERABLE" in scripts["ssl-heartbleed"].upper():
            add_result("tls", {
                "severity": "Critical", "type": "SSL Heartbleed (CVE-2014-0160)",
                "url": _base_url, "host": _h, "port": p,
                "message": f"Heartbleed vulnerability on {_h}:{p}",
                "detail": {"raw": scripts["ssl-heartbleed"][:500]},
            })

        if "ssl-poodle" in scripts and "VULNERABLE" in scripts["ssl-poodle"].upper():
            add_result("tls", {
                "severity": "High", "type": "SSL POODLE (CVE-2014-3566)",
                "url": _base_url, "host": _h, "port": p,
                "message": f"POODLE vulnerability on {_h}:{p}",
                "detail": {"raw": scripts["ssl-poodle"][:500]},
            })

        if "ssl-dh-params" in scripts:
            _dh = scripts["ssl-dh-params"]
            if any(kw in _dh.lower() for kw in ("logjam", "weak", "anonymous")):
                add_result("tls", {
                    "severity": "Medium", "type": "Weak DH Parameters",
                    "url": _base_url, "host": _h, "port": p,
                    "message": f"Weak DH parameters on {_h}:{p}",
                    "detail": {"raw": _dh[:500]},
                })

        if "http-title" in scripts:
            add_result("tls", {
                "severity": "Info", "type": "HTTP Title",
                "url": _base_url, "host": _h, "port": p,
                "message": scripts["http-title"][:150],
                "detail": {"raw": scripts["http-title"]},
            })

        if "http-server-header" in scripts:
            add_result("tls", {
                "severity": "Info", "type": "HTTP Server Header",
                "url": _base_url, "host": _h, "port": p,
                "message": f"Server: {scripts['http-server-header'][:100]}",
                "detail": {"raw": scripts["http-server-header"]},
            })

        # NSE script çıktısında GERÇEK zafiyet sinyali taşıyanları vulnerability'e ekle.
        # B1/B3 FIX (FP): eski kod "vuln" SUBSTRING'ini arıyordu → http-xssed'in benign
        # çıktısı "No previously reported XSS vuln." içinde "vuln" geçtiği için HIGH
        # false-positive üretiyordu (kanıt "zafiyet YOK" diyor, severity HIGH diyordu).
        # Artık: (a) negatif/benign çıktıları ele, (b) yalnız nmap'in standart vuln
        # state'i olan TAM KELİME "vulnerable" (NOT VULNERABLE hariç) ya da gerçek bir
        # CVE-id (cve-YYYY-NNNN) sinyalini zafiyet say. Bilgilendirici scriptler
        # (http-xssed/http-title/...) artık yanlış alarm üretmez.
        _NSE_BENIGN = (
            "not vulnerable", "no previously reported", "couldn't find",
            "could not find", "no relevant", "no findings", "no cve",
            "none found", "no xss", "0 vulnerabilities",
        )
        for script_id, script_out in scripts.items():
            if not script_out:
                continue
            _low = script_out.lower()
            if any(_neg in _low for _neg in _NSE_BENIGN):
                continue
            _is_vuln = bool(
                (re.search(r"\bvulnerable\b", _low) and "not vulnerable" not in _low)
                or re.search(r"cve-\d{4}-\d{3,}", _low)
            )
            if _is_vuln:
                add_result("vulnerability", {
                    "severity": "High", "type": f"NSE: {script_id}",
                    "tool": "nmap-nse", "script": script_id,
                    "url": _base_url, "host": _h, "port": p,
                    "evidence": script_out[:500],
                })

        # Web servisleri teknoloji listesine ekle
        if svc in ("http", "https", "http-alt", "http-proxy"):
            ctx_techs = getattr(ctx, "technologies", None)
            if isinstance(ctx_techs, list) and "web" not in ctx_techs:
                ctx_techs.append("web")

    # OS tahmini results'a yaz (ctx.__slots__ kısıtı için güvenli)
    os_guesses = list({item["os_guess"] for item in scan_res if item.get("os_guess")})
    if os_guesses:
        results["os_guess"] = os_guesses[0]
        try:
            ctx.os_guess = os_guesses[0]
        except (AttributeError, TypeError) as _fix_e:
            _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")

    # Reporting uyumluluğu için results dict'e de yaz
    results["port_scan"] = port_records
    results["nmap"] = port_records
    results["open_ports"] = open_ports

    if not port_records:
        add_result("meta", {"stage": "portscan", "severity": "note", "message": "Açık port bulunamadı (Nmap)."})

    return _mk_result("portscan", "ok", {"scanned": nmap_mode, "open": len(open_ports)})


def run_tls(ctx):
    """TLS taraması: scan_tls_quick(url|[url])"""
    from websecure.scanners.tls import scan_tls_quick as _scan_tls_quick
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return _mk_result("tls", "skipped:no-url")
    _scan_tls_quick(url)
    return _mk_result("tls", "ok")


def run_security_headers(ctx):
    """Güvenlik başlıkları taraması."""
    from websecure.scanners.infrastructure import get_security_headers as _scan_headers
    session = getattr(ctx, "session", None)
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return _mk_result("security_headers", "skipped:no-url")
    results = getattr(ctx, "results", None) or {}
    _scan_headers(url, results, session=session, debug=False)
    return _mk_result("security_headers", "ok")


def run_offensive(ctx):
    """Offensive umbrella: discovery çıktısını tüm modüllere geçir.
    Boşsa bile modüller 'checked_none' kanıtı üretmeli.
    """
    results = getattr(ctx, "results", {}) or {}
    endpoints = list(dict.fromkeys((results.get("endpoints") or [])))

    metrics = {}

    if endpoints:
        add_result("offensive", {"type": "discovery_feed", "count": len(endpoints)})
    else:
        add_result("offensive", {"type": "discovery_feed", "count": 0, "note": "checked_none"})

    # Consolidated Offensive Phase
    from websecure.scanners.jwt import JWTScanner
    from websecure.scanners.graphql import GraphQLScanner
    from websecure.scanners.ssrf_xxe import SSRFScanner
    
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return _mk_result("offensive", "skipped:no-url")

    # Run JWT
    jwt_s = JWTScanner(ctx.session, getattr(ctx, "results", None))
    jwt_s.run(url) 
    metrics["jwt"] = 1

    # Run GraphQL
    gql_s = GraphQLScanner(ctx.session, getattr(ctx, "results", None))
    gql_s.run(url)
    metrics["graphql"] = 1

    # Run SSRF
    # SSRFScanner expects endpoints in init and run() takes no args
    ssrf_s = SSRFScanner(ctx.session, [url])
    # Manually inject results dict because SSRFScanner creates its own if not passed (and it doesn't take it in init)
    if getattr(ctx, "results", None) is not None:
        ssrf_s.results = ctx.results
    ssrf_s.run(url)
    metrics["ssrf"] = 1

    return _mk_result("offensive", "ok", metrics)
def run_finalize(ctx):
    # Final aggregation/report generation, if any
    return _mk_result("finalize", "ok")


def run_security_headers_basic(ctx, *, event_cb=None):
    from websecure.scanners.infrastructure import get_security_headers as _scan_headers
    from websecure.core.reporting import add_result
    sess = getattr(ctx, "session", None)
    base_url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None) or getattr(ctx, "target", None)
    results = getattr(ctx, "results", {})
    _scan_headers(base_url, results, session=sess, debug=bool(getattr(ctx, "debug", False)))
    add_result("meta", {"stage": "headers_checked", "base_url": base_url})
    return results.get("headers", {})


def run_tls_basic(ctx, *, event_cb=None):
    from websecure.scanners.tls import scan_tls as _scan_tls
    from websecure.core.reporting import add_result

    base_url = getattr(ctx, "base_url", None) or ""
    results = getattr(ctx, "results", {}) or {}
    session = getattr(ctx, "session", None)
    config = getattr(ctx, "config", {}) or {}

    _scan_tls(
        base_url,
        results=results,
        session=session,
        config=config,
        debug=bool(getattr(ctx, "debug", False)),
    )
    add_result("meta", {"stage": "tls_checked", "base_url": base_url})
    return results.get("tls", {})

def run_plan_if_needed(ctx: dict):
    """
    Executes the unified scan plan if not already executed.
    Orchestrates discovery, portscan, tls, offensive phases based on config.
    """
    # Reset circuit breaker at scan start so previous scan's OPEN state doesn't bleed in
    try:
        from websecure.core.circuit_breaker import reset_circuit_breaker as _reset_cb
        _reset_cb()
    except Exception as _fix_e:
        _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")

    # Inject AsyncScanRunner into ctx so individual scanners can use parallel HTTP probes
    try:
        from websecure.core.async_runner import AsyncScanRunner as _AsyncScanRunner
        cfg = ctx.get("config", {}) if isinstance(ctx, dict) else getattr(ctx, "config", {}) or {}
        max_concurrent = int((cfg.get("async", {}) or {}).get("max_concurrent", 30))
        timeout_s = float((cfg.get("async", {}) or {}).get("timeout_s", 10.0))
        _ar = _AsyncScanRunner(max_concurrent=max_concurrent, timeout_s=timeout_s)
        if isinstance(ctx, dict):
            ctx["async_runner"] = _ar
        else:
            setattr(ctx, "async_runner", _ar)
    except Exception as _fix_e:
        _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")

    plan = build_plan(ctx)
    if not plan:
        add_result("meta", {"stage": "plan", "status": "empty_plan"})
        return

    _logger.info(f"[Phases] Executing plan with {len(plan)} steps.")

    results = _ensure_results_bucket(ctx)
    # Mark start
    results.setdefault("meta", {})["scan_start"] = _t.time()

    # ------------------------------------------------------------------
    # Global scan deadline — stops the entire scan after N minutes so
    # aggressive mode never runs for 4+ hours.  Configurable via
    # config.global_timeout_s (default: 90 minutes).
    # ------------------------------------------------------------------
    cfg_obj = (ctx if isinstance(ctx, dict) else vars(ctx) if hasattr(ctx, "__dict__") else {})
    _global_cfg = (cfg_obj.get("config") or {}) if isinstance(cfg_obj, dict) else {}
    if not isinstance(_global_cfg, dict):
        _global_cfg = {}
    _global_timeout_s = int(_global_cfg.get("global_timeout_s", 90 * 60))  # 90 min default
    # Max-power / timeout-free mode: no global deadline — the scan runs every phase
    # to completion. Ctrl+C (_SCAN_CANCEL) remains the single cooperative stop.
    _no_timeout_mode = False
    try:
        from websecure.core.http import no_timeout_enabled as _nt_enabled
        _no_timeout_mode = bool(_nt_enabled())
    except Exception:
        _no_timeout_mode = False
    if _no_timeout_mode:
        _global_deadline = float("inf")
        _logger.info("[phases] Global scan budget: SINIRSIZ (no_timeout aktif — hicbir faz atlanmaz)")
    else:
        _global_deadline = _t.monotonic() + _global_timeout_s
        _logger.info("[phases] Global scan budget: %d min", _global_timeout_s // 60)

    _is_debug = ctx.get("debug") if isinstance(ctx, dict) else getattr(ctx, "debug", False)

    # ------------------------------------------------------------------
    # Helper: run one plan item, used by both serial and parallel paths
    # ------------------------------------------------------------------
    def _run_phase_item(item: Dict[str, Any]) -> None:
        pid     = item.get("id")
        runner  = item.get("runner")
        enabled = item.get("enabled", False)
        if not (enabled and callable(runner)):
            if _is_debug:
                _logger.debug("Skipping phase %s (enabled=%s)", pid, enabled)
            return
        if item.get("visible", True):
            phase_title = item.get("title", pid)
            print(f"[•] Faz: {phase_title}")
            try:
                from websecure.core.reporting import get_live_monitor
                get_live_monitor().log_phase(phase_title)
            except (ImportError, AttributeError) as exc:
                _logger.debug("[phases] LiveMonitor log_phase unavailable: %r", exc)
        start_t = _t.time()
        # ÇİFT _safe SARMASI BUG FIX: her Phase.runner zaten kendini _safe ile
        # sarıyor (runner=lambda c: _safe(c, lambda: _runner_X(c), "X")). Burada
        # tekrar _safe(ctx, lambda: runner(ctx), pid) çağırmak fazı İKİ watchdog
        # thread'iyle iç içe çalıştırıyordu → eşzamanlı timeout'ta ÇİFT "Phase X
        # exceeded ... skipped" logu (logda subdomain_takeover/dom_xss/sqlmap 2x)
        # + gereksiz thread/kaynak. runner'ı doğrudan çağır — koruma iç _safe'te.
        runner(ctx)
        if _is_debug:
            print(f"    -> {pid} finished in {_t.time() - start_t:.2f}s")

    # ------------------------------------------------------------------
    # Build lookup: phase_id -> plan item
    # ------------------------------------------------------------------
    _phase_map: Dict[str, Dict[str, Any]] = {
        item.get("id"): item for item in plan if item.get("id")
    }
    _executed: set = set()  # tracks ids already dispatched

    # ------------------------------------------------------------------
    # STAGED + BACKGROUND execution (Madde 4 — Adım B). Dependent chain runs in
    # ordered stages (waf → discovery → offensive → finalizers); independent
    # work runs in a background lane that overlaps every stage and is joined
    # before the finalizers. Request volume is throttled by the global AIMD gate.
    # ------------------------------------------------------------------
    def _deadline_or_cancel() -> bool:
        if _SCAN_CANCEL.is_set():
            _logger.info("[phases] Scan cancelled — stopping plan execution")
            return True
        if _t.monotonic() > _global_deadline:
            _logger.warning(
                "[phases] Global scan timeout (%d min) — stopping early", _global_timeout_s // 60
            )
            add_result("errors", {
                "type": "global_scan_timeout",
                "timeout_secs": _global_timeout_s,
                "message": f"Scan exceeded {_global_timeout_s // 60}min global deadline",
            })
            return True
        return False

    def _enabled(ids):
        """Plan-ordered, enabled, not-yet-dispatched items for the given ids."""
        idset = set(ids)
        return [
            it for it in plan
            if it.get("id") in idset and it.get("id") not in _executed
            and it.get("enabled", False) and callable(it.get("runner"))
        ]

    def _run_stage(items, label: str) -> None:
        items = [it for it in items if it.get("id") not in _executed]
        for it in items:
            _executed.add(it.get("id"))
        if not items:
            return
        # Madde 4 — Adım D: yüksek-öncelikli (yüksek-değer/severity) fazlar havuz
        # slotlarını ÖNCE kapsın. Stable sort → eşit öncelikte plan sırası korunur.
        items.sort(key=lambda it: -_PHASE_PRIORITY.get(it.get("id"), _DEFAULT_PHASE_PRIORITY))
        if len(items) == 1:
            _run_phase_item(items[0])
            return
        _logger.info("[phases] %s (%d faz): %s", label, len(items),
                     [it.get("id") for it in items])
        with _cf.ThreadPoolExecutor(max_workers=min(len(items), _STAGE_MAX_WORKERS)) as pool:
            futs = {pool.submit(_run_phase_item, it): it.get("id") for it in items}
            for fut in _cf.as_completed(futs):
                try:
                    fut.result()
                except Exception as exc:
                    _logger.error("[phases] Stage phase error (id=%s): %s", futs[fut], exc)

    # --- Background lane: independent slow work, started up front (overlaps all stages) ---
    _bg_items = _enabled(_BACKGROUND_PHASES)
    for it in _bg_items:
        _executed.add(it.get("id"))
    _bg_pool = None
    _bg_futs: Dict[Any, str] = {}
    if _bg_items:
        _bg_pool = _cf.ThreadPoolExecutor(
            max_workers=min(len(_bg_items), _BACKGROUND_MAX_WORKERS),
            thread_name_prefix="bg",
        )
        _bg_futs = {_bg_pool.submit(_run_phase_item, it): it.get("id") for it in _bg_items}
        _logger.info("[phases] Arka plan (bağımsız) fazlar başlatıldı: %s",
                     [it.get("id") for it in _bg_items])

    try:
        # Aşama 0 — WAF tespit (profil)
        if not _deadline_or_cancel():
            _run_stage(_enabled(_STAGE_WAF), "Aşama 0 — WAF tespit")
        # Aşama 1 — keşif/crawl (endpoint + forms_meta)
        if not _deadline_or_cancel():
            _run_stage(_enabled(_STAGE_DISCOVERY), "Aşama 1 — Keşif/Crawl")
        # Aşama 2 — saldırı (catch-all: sınıflandırılmamış HER etkin faz)
        if not _deadline_or_cancel():
            _mid_items = [
                it for it in plan
                if it.get("id") not in _NON_OFFENSIVE_PHASES
                and it.get("id") not in _executed
                and it.get("enabled", False) and callable(it.get("runner"))
            ]
            _run_stage(_mid_items, "Aşama 2 — Saldırı")
    finally:
        # Background'ı finalizer'lardan ÖNCE join et (bulgular tam olmalı).
        if _bg_pool is not None:
            for fut in _cf.as_completed(list(_bg_futs.keys())):
                try:
                    fut.result()
                except Exception as exc:
                    _logger.error("[phases] Background phase error (id=%s): %s",
                                  _bg_futs.get(fut), exc)
            _bg_pool.shutdown(wait=True)

    # Aşama 3 — finalizer'lar: SIRAYLA (exploit → oast → skorla → rapor).
    for pid in _FINALIZER_PHASES:
        if _SCAN_CANCEL.is_set():
            _logger.info("[phases] Scan cancelled — finalizer'lar atlanıyor")
            break
        it = _phase_map.get(pid)
        if (it and it.get("id") not in _executed
                and it.get("enabled", False) and callable(it.get("runner"))):
            _executed.add(pid)
            _run_phase_item(it)

    results["meta"]["scan_end"] = _t.time()
    try:
        from websecure.core.reporting import get_live_monitor
        get_live_monitor().summary()
    except (ImportError, AttributeError) as exc:
        _logger.debug(f"[phases] LiveMonitor summary unavailable: {exc!r}")

    # Raporlama fazı plan'dan filtrelendi; burada eksiz çalıştır (SARIF/JUnit/bildirim)
    try:
        run_reporting_and_integration(ctx)
    except Exception as _rep_exc:
        _logger.debug(f"[phases] run_reporting_and_integration hatası: {_rep_exc!r}")


# ===========================================================================
# MERGED FROM: websecure/core/flow_runner.py
# Phase execution functions: run_discovery_extended, run_xss_scan, run_sqlmap_scan,
# run_ffuf_scan, adjust_scan_mode, flush, is_blocked
# ===========================================================================
import logging
import os
import shutil
import time

try:
    from websecure.core.reporting import add_result
except ImportError:
    def add_result(*_a, **_k): pass  # type: ignore[assignment]

try:
    from websecure.core.http import hardened_session
except ImportError:
    hardened_session = None  # type: ignore[assignment]

try:
    from websecure.crawler import WebCrawler, CrawlerConfig
except ImportError:
    pass  # WebCrawler already guarded above

# Integration Wrappers
try:
    from websecure.integrations.sqlmap import SQLMapWrapper
except ImportError:
    SQLMapWrapper = None

try:
    from websecure.integrations.ffuf import FFUFWrapper
except ImportError:
    FFUFWrapper = None

try:
    from websecure.integrations.nuclei import NucleiWrapper
except ImportError:
    NucleiWrapper = None

try:
    from websecure.integrations.ffuf import FeroxbusterWrapper
except ImportError:
    FeroxbusterWrapper = None

try:
    from websecure.core.oast import IOSATClient
except ImportError:
    IOSATClient = None

# Fallback/Nuclei for XSS if external tools preferred
try:
    from websecure.scanners.owasp import run_owasp_and_nuclei
except ImportError:
    run_owasp_and_nuclei = None

# [WS3] Robust Local Scanners (Always Available)
try:
    from websecure.scanners.xss import run as run_local_xss
except ImportError:
    run_local_xss = None

try:
    from websecure.scanners.sqli import run as run_local_sqli
except ImportError:
    run_local_sqli = None

_logger = logging.getLogger(__name__)


def _get_config(ctx, key: str, default: Any = None) -> Any:
    cfg = getattr(ctx, "config", {}) or {}
    if not isinstance(cfg, dict):
        return default
    
    parts = key.split(".")
    curr = cfg
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        else:
            return default
    return curr

def _resolve_proxy(ctx) -> str | None:
    """Helper to get proxy string from config (Tor/Rotation)."""
    # 0. Check _tor_proxy set by main.py Tor auto-start
    _tor_proxy = (getattr(ctx, "config", {}) or {}).get("_tor_proxy")
    if _tor_proxy:
        return _tor_proxy

    # 1. Check if Tor is active via proxy_manager
    # CRITICAL: socks5h:// routes DNS through Tor too — prevents DNS leak to ISP
    tor = _get_config(ctx, "proxy.tor_control.enabled", False)
    if tor:
        return "socks5h://127.0.0.1:9050"

    # 2. Check explicit proxy
    proxy_url = _get_config(ctx, "proxy.url")
    if proxy_url:
        return proxy_url

    return None

def run_discovery_extended(ctx) -> None:
    """
    Runs the advanced crawler discovery phase.
    Supports Visibility and Proxy.
    """
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return

    _logger.info(f"Starting Extended Discovery on {url}")
    session = getattr(ctx, "session", None) or hardened_session()
    
    # Configure Crawler
    c_cfg = CrawlerConfig()
    c_cfg.max_depth = int(_get_config(ctx, "crawl.max_depth", 3))
    c_cfg.max_pages = int(_get_config(ctx, "crawl.max_pages", 50))
    
    # [Check 1] Visibility — crawl.browser.headless=false veya ctx.visible -> görünür Chrome
    is_visible = bool(getattr(ctx, "visible", False) or _get_config(ctx, "crawl.browser.headless") is False)
    # is_visible'ı gerçekten crawler'a bağla (önceden hesaplanıp kullanılmıyordu)
    c_cfg.headless = not is_visible
    # Tarayıcı tabanlı JS keşfini config'ten etkinleştir (crawl.use_browser).
    # Aksi halde _run_browser_discovery() hiç çağrılmaz ve Chrome açılmaz.
    c_cfg.browser_js_discovery = bool(
        _get_config(ctx, "crawl.use_browser", c_cfg.browser_js_discovery)
    )
    c_cfg.browser_max_pages = int(
        _get_config(ctx, "crawl.browser.max_pages", c_cfg.browser_max_pages)
    )
    if is_visible:
        _logger.info(
            "[Crawler] Görünür mod aktif (crawl.browser.headless=false) — "
            "Chrome penceresi açılacak, tarama adımlarını izleyebilirsiniz."
        )

    # [Check 5] Proxy/Evasion
    proxy_server = _resolve_proxy(ctx)
    if proxy_server:
        _logger.info(f"[Evasion] Crawler using proxy: {proxy_server}")
        c_cfg.proxy_url = proxy_server

    # headless / browser_js_discovery / proxy artık c_cfg üzerinden WebCrawler'a geçiyor
    crawler = WebCrawler(
        session,
        start_url=url,
        config=c_cfg,
        debug=bool(getattr(ctx, "debug", False)),
        driver=None
    )
    
    res = crawler.start()
    
    # Update Context Results
    if isinstance(res, dict):
        current_res = getattr(ctx, "results", {}) or {}
        # Merge carefully
        found_endpoints = res.get("endpoints", [])
        
        # [WS3] Fallback: If no endpoints found, use base URL to ensure offensive scanners have a target.
        if not found_endpoints and url:
             _logger.info("Discovery yielded no endpoints. Forcing base URL as target for offensive phases.")
             found_endpoints = [url]
        
        # [WS3] Enhanced Form Parsing (User Logic Integration)
        # Force a fetch of base URL to parse dynamic inputs/forms if not done
        try:
             from websecure.core.form_parser import extract_all_inputs
             t_html = ""
             t_cookie = ""
             # Try to get HTML from crawler results if available, else fetch
             if isinstance(res, dict) and res.get("html"):
                  t_html = res.get("html")
             elif ctx.session:
                  # Quick fetch
                  try:
                       rr = ctx.session.get(url, timeout=10)
                       t_html = rr.text
                       t_cookie = "; ".join(
                           f"{c.name}={c.value}" for c in getattr(rr, "cookies", [])
                       )
                  except Exception as exc:
                      import logging as _lg
                      _lg.getLogger(__name__).debug(f"[Phases] Form fetch failed for {url}: {exc!r}")

             if t_html:
                  all_inputs = extract_all_inputs(t_html, url, cookie_header=t_cookie)
                  new_forms = all_inputs.get("forms", [])
                  existing_forms = current_res.get("forms_meta", [])
                  if new_forms:
                        _logger.info(f"[FormParser] Extracted {len(new_forms)} forms (including dynamic script inputs).")
                        existing_forms.append({
                             "url": url,
                             "forms": new_forms
                        })
                        current_res["forms_meta"] = existing_forms
                  # Store additional extracted input vectors for scanners
                  for _key in ("url_params", "json_fields", "cookies", "headers"):
                        _vals = all_inputs.get(_key, [])
                        if _vals:
                             current_res.setdefault(_key, []).extend(_vals)
        except ImportError:
             _logger.warning("Could not import form_parser.")
        except Exception as e:
             _logger.error(f"Form parsing failed: {e}")

        existing = set(current_res.get("endpoints", []))
        existing.update(found_endpoints)
        current_res["endpoints"] = list(existing)
        
        # Merge other keys
        for k, v in res.items():
            if k != "endpoints":
                current_res[k] = v
        
        ctx.results = current_res

    # -- Endpoint Seeding: probe parameterized paths when crawler found few --
    _seed_parameterized_endpoints(ctx)

    add_result("meta", {"stage": "discovery_extended", "count": len(getattr(ctx, "results", {}).get("endpoints", []))})


# ---------------------------------------------------------------------------
# Universal Endpoint Seeder
# Covers ALL major web frameworks, CMS systems, REST/GraphQL APIs worldwide.
# Technology-specific paths are selected dynamically based on detected stack.
# ---------------------------------------------------------------------------

# -- Generic (works on any web app) ------------------------------------------
_GENERIC_PARAM_TEMPLATES: List[str] = [
    # Root-level search / query params — ubiquitous SQLi/XSS surface
    "/?q={val}",
    "/?s={val}",
    "/?search={val}",
    "/?query={val}",
    "/?keyword={val}",
    "/?term={val}",
    "/?text={val}",
    # ID-based object access — ubiquitous IDOR/SQLi surface
    "/?id=1",
    "/?id=2",
    "/?pid=1",
    "/?uid=1",
    "/?user_id=1",
    "/?product_id=1",
    "/?item_id=1",
    "/?record_id=1",
    "/?object_id=1",
    # Pagination / ordering — SQLi surface
    "/?page=1",
    "/?page=1&per_page=10",
    "/?offset=0&limit=10",
    "/?sort=id&order=asc",
    "/?start=0&count=10",
    # Category / filter — SQLi/XSS surface
    "/?category=1",
    "/?cat=1",
    "/?type=1",
    "/?filter={val}",
    "/?tag={val}",
    # Redirect / return URL — Open Redirect surface
    "/login?redirect=/",
    "/login?next=/",
    "/login?return=/",
    "/login?return_to=/",
    "/logout?redirect=/",
    "/logout?next=/",
    "/signin?redirect=/",
    "/auth/login?next=/",
    "/redirect?url=/",
    "/go?url=/",
    "/out?url=/",
    "/link?url=/",
    "/jump?url=/",
    "/?url=/",
    "/?next=/",
    # File / resource — Path traversal / LFI surface
    "/download?file=test",
    "/download?filename=test.txt",
    "/file?name=test.txt",
    "/file?path=test",
    "/image?src=test.jpg",
    "/img?url=test.jpg",
    "/view?page=index",
    "/include?file=index",
    "/load?template=main",
    "/render?view=index",
    # Language / locale — sometimes XSS
    "/?lang=en",
    "/?locale=en",
    "/?language=en",
    # Callback / JSONP — XSS surface
    "/?callback={val}",
    "/?jsonp={val}",
    # Debug / format toggles
    "/?debug=1",
    "/?format=json",
    "/?output=json",
    "/?_format=json",
]

# -- REST API (version-agnostic) ----------------------------------------------
_REST_API_TEMPLATES: List[str] = [
    # Core CRUD resources — IDOR/SQLi/Mass Assignment surface
    "/api/users?id=1",
    "/api/users/1",
    "/api/user?id=1",
    "/api/products?id=1",
    "/api/products/1",
    "/api/product?id=1",
    "/api/items?id=1",
    "/api/items/1",
    "/api/orders?id=1",
    "/api/orders/1",
    "/api/posts?id=1",
    "/api/posts/1",
    "/api/comments?id=1",
    "/api/categories?id=1",
    "/api/search?q={val}",
    "/api/search?query={val}",
    # Versioned APIs
    "/api/v1/users?id=1",
    "/api/v1/users/1",
    "/api/v1/products?id=1",
    "/api/v1/search?q={val}",
    "/api/v2/users?id=1",
    "/api/v2/users/1",
    "/api/v2/products?id=1",
    "/api/v2/search?q={val}",
    "/api/v3/users?id=1",
    # Auth endpoints
    "/api/login",
    "/api/auth/login",
    "/api/auth/token",
    "/api/register",
    "/api/me",
    "/api/profile?id=1",
    # Admin / management
    "/api/admin/users?id=1",
    "/api/admin/dashboard",
    # Schema discovery
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api/docs",
]

# -- GraphQL ------------------------------------------------------------------
_GRAPHQL_TEMPLATES: List[str] = [
    "/graphql?query={val}",
    "/graphql/v1?query={val}",
    "/api/graphql?query={val}",
    "/gql?query={val}",
    "/query?query={val}",
]

# -- WordPress ----------------------------------------------------------------
_WORDPRESS_TEMPLATES: List[str] = [
    "/?p=1",
    "/?page_id=1",
    "/?cat=1",
    "/?tag={val}",
    "/?s={val}",
    "/?author=1",
    "/?attachment_id=1",
    "/wp-json/wp/v2/posts?id=1",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/pages?id=1",
    "/wp-json/wp/v2/media?id=1",
    "/?feed=rss2",
    "/xmlrpc.php",
    "/wp-login.php?redirect_to=/",
    "/wp-admin/admin-ajax.php?action=test",
]

# -- Laravel / PHP frameworks --------------------------------------------------
_LARAVEL_TEMPLATES: List[str] = [
    "/api/user?id=1",
    "/api/posts?id=1",
    "/api/products?id=1",
    "/api/orders?id=1",
    "/storage/app/public/test",
    "/telescope/requests",
    "/horizon/dashboard",
    "/nova/api/users?page=1",
]

# -- Django / Python frameworks ------------------------------------------------
_DJANGO_TEMPLATES: List[str] = [
    "/api/?format=json",
    "/api/users/?format=json",
    "/api/users/1/?format=json",
    "/api/products/?format=json",
    "/api/posts/?format=json",
    "/admin/",
    "/__debug__/",
    "/silk/requests/",
]

# -- Ruby on Rails -------------------------------------------------------------
_RAILS_TEMPLATES: List[str] = [
    "/users/1",
    "/users/1.json",
    "/products/1",
    "/products/1.json",
    "/posts/1",
    "/posts/1.json",
    "/orders/1",
    "/articles/1",
    "/comments/1",
    "/search?q={val}",
    "/rails/info/properties",
]

# -- ASP.NET / .NET Core -------------------------------------------------------
_ASPNET_TEMPLATES: List[str] = [
    "/api/values?id=1",
    "/api/product/1",
    "/api/user/1",
    "/api/order/1",
    "/swagger/index.html",
    "/healthz",
    "/health",
    "/.well-known/health",
    "/elmah.axd",
    "/trace.axd",
]

# -- Spring Boot / Java --------------------------------------------------------
_SPRING_TEMPLATES: List[str] = [
    "/api/v1/users?id=1",
    "/api/v1/products?id=1",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/metrics",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
]

# -- Node.js / Express ---------------------------------------------------------
_NODE_TEMPLATES: List[str] = [
    "/api/users?id=1",
    "/api/posts?id=1",
    "/api/products?id=1",
    "/graphql",
    "/socket.io/",
    "/.well-known/security.txt",
]

# -- Generic CMS / eCommerce ---------------------------------------------------
_CMS_TEMPLATES: List[str] = [
    # Magento
    "/index.php/catalog/product/view/id/1",
    "/rest/V1/products/1",
    # Drupal
    "/node/1",
    "/node/1?_format=json",
    "/user/1",
    "/jsonapi/node/article?filter[id]=1",
    # Joomla
    "/index.php?option=com_content&view=article&id=1",
    "/index.php?option=com_users&view=login&return={val}",
    # PrestaShop
    "/index.php?id_product=1&controller=product",
    "/api/products/1?ws_key=",
    # OpenCart
    "/index.php?route=product/product&product_id=1",
    "/index.php?route=account/login&redirect={val}",
    # Shopify apps
    "/products/test?variant=1",
    "/collections/all?sort_by=best-selling",
    # WooCommerce
    "/?product=test",
    "/?add-to-cart=1",
]

# Technology -> additional template list mapping
_TECH_TEMPLATE_MAP: Dict[str, List[str]] = {
    "wordpress":   _WORDPRESS_TEMPLATES,
    "drupal":      _CMS_TEMPLATES,
    "joomla":      _CMS_TEMPLATES,
    "laravel":     _LARAVEL_TEMPLATES,
    "php":         _LARAVEL_TEMPLATES,
    "django":      _DJANGO_TEMPLATES,
    "python":      _DJANGO_TEMPLATES,
    "rails":       _RAILS_TEMPLATES,
    "ruby":        _RAILS_TEMPLATES,
    "aspnet":      _ASPNET_TEMPLATES,
    "dotnet":      _ASPNET_TEMPLATES,
    "spring":      _SPRING_TEMPLATES,
    "java":        _SPRING_TEMPLATES,
    "node":        _NODE_TEMPLATES,
    "express":     _NODE_TEMPLATES,
    "graphql":     _GRAPHQL_TEMPLATES,
    "rest_api":    _REST_API_TEMPLATES,
    "magento":     _CMS_TEMPLATES,
    "prestashop":  _CMS_TEMPLATES,
    "opencart":    _CMS_TEMPLATES,
    "shopify":     _CMS_TEMPLATES,
}

_PARAM_CANARY = "wstest"


def _seed_parameterized_endpoints(ctx) -> None:
    """
    Universal endpoint seeder — works on any web application worldwide.

    Strategy:
    1. Always probe the generic parameter templates (search, id, redirect, file, etc.)
    2. Detect technology stack from ctx.technologies and add tech-specific paths
    3. Always add REST API paths (most modern apps have /api/...)
    4. Probe with HEAD then GET to minimize bandwidth
    5. Add all non-404 responses to ctx.results["endpoints"]

    This ensures XSS, SQLi, CMDI, Open Redirect, IDOR, Path Traversal scanners
    all receive real parameterized URLs to test — not just the base URL.
    """
    base_url = (getattr(ctx, "base_url", None)
                or getattr(ctx, "url", None)
                or getattr(ctx, "target", None) or "")
    if not base_url:
        return

    current_res = getattr(ctx, "results", {}) or {}
    existing_eps = current_res.get("endpoints", [])
    param_eps = [u for u in existing_eps if "?" in u]

    # Only seed if we have fewer than 15 parameterized URLs
    if len(param_eps) >= 15:
        _logger.info(f"[seed] {len(param_eps)} parameterized endpoints already present — skip")
        return

    sess = getattr(ctx, "session", None)
    if sess is None:
        try:
            import requests as _r
            sess = _r.Session()
            sess.verify = False
            sess.headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            )
        except ImportError:
            return

    from urllib.parse import urlparse as _up
    parsed = _up(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Build template list: generic + tech-specific + REST API (always)
    techs = set(t.lower() for t in (getattr(ctx, "technologies", []) or []))
    templates: List[str] = list(_GENERIC_PARAM_TEMPLATES) + list(_REST_API_TEMPLATES)

    for tech, extra in _TECH_TEMPLATE_MAP.items():
        if tech in techs:
            _logger.info(f"[seed] Tech '{tech}' detected — adding {len(extra)} specific templates")
            templates.extend(extra)

    # Deduplicate templates
    templates = list(dict.fromkeys(templates))
    _logger.info(f"[seed] Probing {len(templates)} endpoint templates on {origin} ...")

    from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _asc
    try:
        import urllib3 as _u3
        _u3.disable_warnings()
    except ImportError as exc:
        _logger.debug(f"[phases] urllib3 not available, warnings not suppressed: {exc!r}")

    _SKIP_CODES = {404, 405, 410, 501, 502, 503, 504}

    def _probe(template: str):
        path = (template
                .replace("{val}", _PARAM_CANARY)
                .replace("{id}", "1"))
        full_url = origin + path
        try:
            # HEAD first (faster), fallback to GET
            try:
                r = sess.head(full_url, timeout=4, allow_redirects=True)
            except Exception as exc:
                _logger.debug(f"[seed] HEAD failed for {full_url}, falling back to GET: {exc!r}")
                r = sess.get(full_url, timeout=4, allow_redirects=True)
            if r.status_code not in _SKIP_CODES:
                return full_url
        except Exception as exc:
            _logger.debug(f"[seed] Probe failed for {full_url}: {exc!r}")
        return None

    new_eps: List[str] = []
    existing_set = set(existing_eps)

    with _TPE(max_workers=15) as pool:
        futs = {pool.submit(_probe, t): t for t in templates}
        try:
            for f in _asc(futs, timeout=45):
                result = f.result()
                if result and result not in existing_set and result not in new_eps:
                    new_eps.append(result)
        except Exception as exc:
            _logger.debug(f"[seed] Probe phase timed out — partial results collected: {exc!r}")

    if new_eps:
        _logger.info(f"[seed] Added {len(new_eps)} endpoint(s) to offensive scan list")
        existing_set.update(new_eps)
        current_res["endpoints"] = list(existing_set)
        ctx.results = current_res
        add_result("meta", {
            "stage": "endpoint_seeding",
            "new_endpoints": len(new_eps),
            "tech_templates_used": sorted(techs & set(_TECH_TEMPLATE_MAP)),
            "sample": new_eps[:8],
        })
    else:
        _logger.info("[seed] No additional endpoints found via probing")


def _prioritize_urls(urls: List[str]) -> List[str]:
    """
    Sorts URLs by 'interest' level for offensive scanning.
    High Priority: Login, Admin, Payment, Parameters
    Low Priority: Deep nesting, Static-looking, Logout
    """
    if not urls: return []
    
    def _score(u: str) -> int:
        s = 0
        ul = u.lower()
        if "?" in ul: s += 20
        if any(k in ul for k in ("login", "signin", "auth", "admin", "account", "register", "signup")): s += 50
        if any(k in ul for k in ("pay", "checkout", "cart", "buy", "order")): s += 40
        if "password" in ul or "reset" in ul: s += 30
        
        # Penalize deep nesting (often irrelevant content)
        s -= (ul.count("/") * 2)
        
        # Avoid destructive/logout
        if "logout" in ul or "signout" in ul: s -= 500
        
        return s
        
    return sorted(list(set(urls)), key=_score, reverse=True)



def _detect_csrf_token_name(results: dict) -> str | None:
    """
    Keşfedilen formlardan CSRF token alan adını çıkar.

    sqlmap'e --csrf-token=<ad> verebilmek için kullanılır; aksi halde token
    korumalı formlarda her istek reddedilir ve sessiz false-negative oluşur.
    """
    if not isinstance(results, dict):
        return None
    _pat = re.compile(r"csrf|xsrf|_token|authenticity_token|nonce|verif", re.I)
    pages = results.get("forms_meta") or []
    for page in pages:
        if not isinstance(page, dict):
            continue
        for form in (page.get("forms") or []):
            if not isinstance(form, dict):
                continue
            for inp in (form.get("inputs") or form.get("fields") or []):
                name = inp.get("name") if isinstance(inp, dict) else None
                if name and _pat.search(str(name)):
                    return str(name)
    return None


def run_sqlmap_scan(ctx) -> None:
    """
    sqlmap'i bağımsız bir SQLi keşif + sömürü motoru olarak çalıştırır.

    Artık "doğrulayıcı" değil: kendi crawl'ını yapabilir, tüm parametreleri
    yüksek level/risk ile dener, CSRF token'ı yönetir ve onaylanan injection'ları
    SQLiExploiter ile sömürür (şema/kimlik bilgisi/dosya/RCE).
    [Check 1, 2, 5] Tools working, Payload/Exploit, Proxy support.
    """
    if SQLMapWrapper is None:
        add_result("meta", {"stage": "sqlmap", "status": "skipped", "reason": "Integration module missing"})
        return

    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None) or getattr(ctx, "target", None)
    if not url:
        return

    # Check config
    if not _get_config(ctx, "sqlmap.enabled", True):
        return

    _logger.info("Launching SQLMap scan...")
    wrapper = SQLMapWrapper()
    if not wrapper.is_available():
        add_result("meta", {"stage": "sqlmap", "status": "skipped", "reason": "Binary not found in PATH"})
        return

    # [budget] FİRM zaman tavanı — sqlmap no_timeout modunda bile sınırsız koşmaz
    # (kullanıcı talebi). Gücü kısılmaz; yalnız toplam süre tavanlanır. Bütçe
    # subprocess'e run_timeout olarak geçer (effective_timeout çarpanı uygulanmaz).
    _sqlmap_budget = _resolve_sqlmap_budget(ctx)
    _logger.info("[SQLMap] Firm zaman bütçesi: %ds (tam güç bu süre içinde)", _sqlmap_budget)
    add_result("meta", {"stage": "sqlmap", "status": "budgeted", "budget_seconds": _sqlmap_budget})

    # [beast] Saldırı gücü: floor yüksek tutulur — sqlmap artık doğrulayıcı
    # değil, bağımsız bir keşif+sömürü motoru. level 5 = cookie/header/referer
    # injection da denenir; risk 3 = OR-based + zaman tabanlı ağır testler.
    level = max(3, int(_get_config(ctx, "sqlmap.level", 5)))
    risk = max(2, int(_get_config(ctx, "sqlmap.risk", 3)))

    # [Check 5] Proxy
    extra_args = list(_get_config(ctx, "sqlmap.extra_args", []) or [])
    proxy = _resolve_proxy(ctx)
    if proxy:
        _logger.info(f"[Evasion] SQLMap using proxy: {proxy}")

    if _get_config(ctx, "sqlmap.random_agent", True):
        extra_args.append("--random-agent")

    # [beast] Ucuz DBMS parmak izi — yalnızca zafiyetli parametrelerde çalışır,
    # genel yük getirmez ama bulgulara DBMS/banner/kullanıcı bağlamı ekler.
    if _get_config(ctx, "sqlmap.fingerprint", True):
        for _fp in ("--banner", "--current-user", "--current-db", "--hostname", "--is-dba"):
            if _fp not in extra_args:
                extra_args.append(_fp)

    # [beast] CSRF korumalı formlarda token'ı otomatik yönet — aksi halde
    # sqlmap her istekte reddedilir → sessiz false-negative.
    _csrf_token = _detect_csrf_token_name(getattr(ctx, "results", {}))
    if _csrf_token and not any(str(a).startswith("--csrf-token") for a in extra_args):
        extra_args.append(f"--csrf-token={_csrf_token}")
        _logger.info(f"[SQLMap] CSRF token parametresi yönetiliyor: {_csrf_token}")


    # [Smart] Tech-aware extension hints from detected technologies
    techs = set(getattr(ctx, "technologies", []) or [])
    if "php" in techs:
        _logger.info("[Smart-SQLi] PHP detected — prioritizing PHP endpoints")
    if "java" in techs:
        _logger.info("[Smart-SQLi] Java detected — prioritizing JSP/servlet endpoints")
    if "aspnet" in techs:
        _logger.info("[Smart-SQLi] ASP.NET detected — prioritizing ASPX endpoints")

    # [FIX] Iterate over ALL discovered endpoints, not just base URL
    raw_endpoints = getattr(ctx, "results", {}).get("endpoints", [])
    # [WS3] Priority Sort: Attack Login/Payment/Param-heavy first!
    endpoints = _prioritize_urls(raw_endpoints)

    if not endpoints:
        endpoints = [url]

    # [FIX] Get discovered params to hint SQLMap
    params = getattr(ctx, "results", {}).get("param_candidates", [])

    # Smart param prioritization: numeric IDs and search params are high-value for SQLi
    high_value_params = []
    _sqli_hint_patterns = ("id", "uid", "user_id", "item", "product", "cat", "page", "search", "q", "query", "order", "sort")
    for p in params:
        if any(h in p.lower() for h in _sqli_hint_patterns):
            high_value_params.append(p)
            _logger.info(f"[Smart-SQLi] High-priority parameter: {p}")

    param_str = ",".join(params) if params else None

    _sqlmap_profile = (getattr(ctx, "config", {}) or {}).get("_sqlmap", {})
    findings = []

    # SQLMap TEK ÇALIŞTIRILIR — endpoint başına döngü yok.
    # Önce parametre içeren URL'leri önceliklendir; hepsini -m dosyasıyla tek
    # sqlmap invocation'ına ver. Bu şekilde sqlmap kendi iç concurrency'siyle
    # yönetir ve 1800s bir kez harcanır, N kez değil.
    _param_eps  = [u for u in endpoints if "?" in u]
    _other_eps  = [u for u in endpoints if "?" not in u]
    # Önce param'lılar, sonra diğerleri; statik varlıkları atla
    _static_ext = (".png", ".jpg", ".css", ".js", ".woff", ".ttf", ".svg", ".ico", ".gif", ".webp")
    _all_eps    = [u for u in (_param_eps + _other_eps)
                   if not any(u.lower().endswith(e) for e in _static_ext)]

    if not _all_eps:
        _all_eps = [url]

    # Tek hedef varsa -u, birden fazlaysa -m ile URL listesi dosyası geç
    import tempfile as _tmpfile, os as _os

    # [beast] Parametreli yüzey azsa sqlmap KENDİ crawl'ını yapsın — böylece
    # bizim crawler'ın kaçırdığı endpoint'leri de keşfeder. Discovery aracı
    # olarak bağımsız çalışmasının anahtarı budur.
    _crawl_depth = int(_get_config(ctx, "sqlmap.crawl_depth", 3))
    _self_discover = len(_param_eps) < 3 and _crawl_depth > 0

    if _self_discover:
        # Self-crawl modunda -p verme: sqlmap kendi bulduğu tüm parametreleri test etsin
        cmd_args = list(extra_args)
        if not any(str(a).startswith("--crawl") for a in cmd_args):
            cmd_args.extend(["--crawl", str(_crawl_depth)])
        if "--forms" not in cmd_args:
            cmd_args.append("--forms")
        _logger.info(
            "[SQLMap] Az parametreli yüzey (%d) — sqlmap self-crawl (depth=%d) ile bağımsız keşif yapıyor",
            len(_param_eps), _crawl_depth,
        )
        findings = wrapper.scan(
            url, batch=True, level=level, risk=risk,
            extra_args=cmd_args, proxy=proxy, profile_cfg=_sqlmap_profile,
            run_timeout=_sqlmap_budget,
        )
    else:
        cmd_args = list(extra_args)
        if param_str:
            cmd_args.extend(["-p", param_str])

        if len(_all_eps) == 1:
            _logger.info("[SQLMap] Tek endpoint — sqlmap bir kez çalışıyor: %s", _all_eps[0])
            findings = wrapper.scan(
                _all_eps[0], batch=True, level=level, risk=risk,
                extra_args=cmd_args, proxy=proxy, profile_cfg=_sqlmap_profile,
                run_timeout=_sqlmap_budget,
            )
        else:
            # -m: sqlmap URL listesi dosyasından okur, tek process içinde iter eder
            _url_fd, _url_file = _tmpfile.mkstemp(suffix=".txt", prefix="ws_sqlmap_urls_")
            try:
                with _os.fdopen(_url_fd, "w") as _fh:
                    _fh.write("\n".join(_all_eps))
                _logger.info(
                    "[SQLMap] %d endpoint — tek sqlmap çalışması (-m): %s",
                    len(_all_eps), _url_file,
                )
                # -m flag'ini extra_args olarak geçir; wrapper.scan() birincil URL'yi
                # sadece raporlama için kullanır, asıl hedefler dosyadan okunur
                _m_args = cmd_args + ["-m", _url_file]
                findings = wrapper.scan(
                    _all_eps[0], batch=True, level=level, risk=risk,
                    extra_args=_m_args, proxy=proxy, profile_cfg=_sqlmap_profile,
                    run_timeout=_sqlmap_budget,
                )
            finally:
                try:
                    _os.unlink(_url_file)
                except Exception:
                    pass

    # Report
    if findings:
        for f in findings:
            # [Check 2] Validating exploits
            # [WS3] Merge finding data to expose 'evidence' key to reporting
            entry = {
                "severity": "high",
                "type": "SQL Injection",
                "tool": "sqlmap"
            }
            if isinstance(f, dict):
                entry.update(f) # Merges raw_finding and EVIDENCE
            else:
                entry["detail"] = f

            add_result("sqlmap", entry)
            # SQLi is always offensive — route Critical/High to offensive bucket too
            if str(entry.get("severity", "")).lower() in ("critical", "high"):
                add_result("offensive", entry)

    # [Fix] sqlmap'in NE YAPTIĞINI HER ZAMAN raporla — yalnız findings>0 değil.
    # Eskiden 0 bulguda yalnız {"status":"finished","findings":0} yazılıyordu;
    # kullanıcı sqlmap'in çalışıp çalışmadığını/neyi test ettiğini göremiyordu.
    # Artık: kaç hedef/parametre denendi, DBMS, süre, ve 0 ise NEDEN (WAF/403 mu,
    # injectable parametre mi yok). Hem terminale hem rapora.
    _meta = getattr(wrapper, "last_run_meta", {}) or {}
    _tested_targets = len(_all_eps)
    _tested_params = len(params) if params else 0
    _dbms = _meta.get("dbms") or "—"
    _elapsed = _meta.get("elapsed_s")
    if not findings:
        # 0 bulgu nedenini biriken çıktıdan/durumdan çıkar (dürüst teşhis)
        _reason = "injectable parametre bulunamadı"
        try:
            _res_obj = getattr(ctx, "results", {}) or {}
            _cb = _res_obj.get("circuit_breaker") or []
            _waf = _res_obj.get("waf") or []
            if _meta.get("timed_out"):
                _reason = "zaman bütçesi doldu (kısmi)"
            elif any(isinstance(w, dict) and w.get("detected") for w in (_waf if isinstance(_waf, list) else [])):
                _reason = "hedef WAF/403 ile blokluyor — enjeksiyon yüzeyi erişilemedi"
            elif _self_discover and _tested_params == 0:
                _reason = "test edilebilir parametre/form yok (statik/parametresiz yüzey)"
        except Exception:
            pass
        _summary_msg = (
            f"sqlmap bitti: {_tested_targets} hedef, {_tested_params} parametre denendi, "
            f"DBMS={_dbms}, süre={_elapsed}s — 0 onaylı SQLi ({_reason})"
        )
        add_result("sqlmap", {
            "status": "finished",
            "findings": 0,
            "tested_targets": _tested_targets,
            "tested_params": _tested_params,
            "dbms": _meta.get("dbms") or "",
            "elapsed_s": _elapsed,
            "timed_out": bool(_meta.get("timed_out")),
            "reason": _reason,
            "message": _summary_msg,
        })
    else:
        _summary_msg = (
            f"sqlmap bitti: {len(findings)} SQLi bulgusu, {_tested_targets} hedef denendi, "
            f"DBMS={_dbms}, süre={_elapsed}s"
        )
        add_result("meta", {
            "stage": "sqlmap", "status": "findings",
            "count": len(findings), "tested_targets": _tested_targets,
            "dbms": _meta.get("dbms") or "", "elapsed_s": _elapsed,
            "message": _summary_msg,
        })
    print(f"  [sqlmap] {_summary_msg}")
    _logger.info("[SQLMap] %s", _summary_msg)

    # [beast] Onaylanan her injection için tam sömürü hattı — şema dökümü,
    # kimlik bilgisi çıkarımı, dosya okuma/yazma, RCE. sqlmap artık yalnızca
    # tespit değil sömürü de yapan bir motor.
    if findings and _get_config(ctx, "exploitation.enabled", True):
        try:
            from websecure.scanners.sqli import SQLiExploiter as _SQLiExploiter
        except Exception as _ie:
            _logger.debug(f"[SQLMap] SQLiExploiter import edilemedi: {_ie!r}")
            _SQLiExploiter = None
        if _SQLiExploiter is not None:
            _seen_pp: set = set()
            for f in findings:
                if not isinstance(f, dict):
                    continue
                _u = f.get("url") or url
                _pm = f.get("parameter") or f.get("param")
                if not _pm:
                    continue
                _key = (_u, _pm)
                if _key in _seen_pp:
                    continue
                _seen_pp.add(_key)
                _db_hint = "mysql"
                _ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
                if _ev.get("dbms"):
                    _db_hint = str(_ev["dbms"]).split()[0].lower()
                try:
                    _exp = _SQLiExploiter(session=getattr(ctx, "session", None))
                    _rep = _exp.full_exploitation_pipeline(_u, _pm, db_hint=_db_hint)
                except Exception as _ee:
                    _logger.debug(f"[SQLMap] sömürü başarısız {_u} ({_pm}): {_ee!r}")
                    continue
                if _rep.get("credentials"):
                    add_result("offensive", {
                        "severity": "critical",
                        "type": "SQL Injection — Credentials Extracted",
                        "tool": "sqlmap",
                        "url": _u, "parameter": _pm,
                        "evidence": {
                            "credentials": _rep["credentials"][:5],
                            "count": len(_rep["credentials"]),
                        },
                        "verified": True,
                    })
                    _logger.warning(
                        "[SQLMap] %d kimlik bilgisi çıkarıldı: %s (%s)",
                        len(_rep["credentials"]), _u, _pm,
                    )
                if _rep.get("web_shell"):
                    add_result("offensive", {
                        "severity": "critical",
                        "type": "SQL Injection → Web Shell (RCE)",
                        "tool": "sqlmap",
                        "url": _u, "parameter": _pm,
                        "evidence": {"web_shell": _rep["web_shell"]},
                        "verified": True,
                    })
                    _logger.warning("[SQLMap] Web shell yerleştirildi: %s", _rep["web_shell"])
                if _rep.get("file_reads"):
                    add_result("offensive", {
                        "severity": "high",
                        "type": "SQL Injection — Sensitive File Read",
                        "tool": "sqlmap",
                        "url": _u, "parameter": _pm,
                        "evidence": {"files": list(_rep["file_reads"].keys())[:10]},
                        "verified": True,
                    })

    # [WS3] Python-based SQLi (Robust Fallback/Companion)
    if run_local_sqli:
        _logger.info("[SQLi] Running internal robust SQLi scanner (Python)...")
        # Ensure discovered params are passed via results if needed, but scanner reads forms_meta itself
        run_local_sqli(
            endpoints,
            getattr(ctx, "session", None),
            results=getattr(ctx, "results", {}), 
            debug=bool(getattr(ctx, "debug", False))
        )


def run_xss_scan(ctx) -> None:
    """
    [Check 2] XSS Payload/Exploit trials.
    [WS3] UPDATED: Uses Robust Local XSS Scanner (xss.py) + Nuclei/OWASP as secondary.
    """
    _logger.info("Launching XSS Scan...")

    # Inject detected tech_stack into results so get_smart_payloads() can filter correctly
    _results = getattr(ctx, "results", {}) or {}
    _tech = list(getattr(ctx, "technologies", []) or [])
    if _tech and "tech_stack" not in _results:
        _results["tech_stack"] = _tech

    # 1. Local Python Scanner (Robust)
    if run_local_xss:
        _logger.info("[XSS] Running internal XSS scanner (Python/Canary)...")
        _raw_eps = _results.get("endpoints", [])
        # [WS3] Smart Prioritization
        _eps = _prioritize_urls(_raw_eps)
        if not _eps:
             _eps = [getattr(ctx, "base_url", "")]

        _cfg = getattr(ctx, "config", {}) or {}
        _oast_domain = (_cfg.get("oast") or {}).get("dns_domain") or None
        run_local_xss(
            _eps,
            getattr(ctx, "session", None),
            results=_results,
            debug=bool(getattr(ctx, "debug", False)),
            oast_domain=_oast_domain,
        )
    else:
        _logger.warning("[XSS] Internal scanner missing (xss.py).")
        add_result("xss", {"status": "skipped", "reason": "XSS module (xss.py) missing"})

    # 2. (Madde 3) İkincil OWASP/Nuclei çağrısı KALDIRILDI — saf redundans:
    #    nuclei'nin XSS şablonları zaten dedike `nuclei` fazında, OWASP kontrolleri
    #    de `owasp_and_nuclei` fazında koşuyor. Buradaki çağrı yüzünden nuclei tarama
    #    başına 3×, tüm OWASP suite 2× koşuyordu. Kapsam kaybı yok (aynı şablonlar
    #    dedike fazda çalışır), yalnız tekrar eden iş elendi.


# ffuf DİZİN/DOSYA keşfine UYGUN OLMAYAN wordlist ad-ipuçları. Bunlar başka
# tarayıcıların PAYLOAD listeleri (sqli/xss/lfi/ssrf…) ya da param/parola/subdomain
# listeleridir; bir dizin adı olarak denenince hep 404 döner → bütçeyi boşa harcar.
# (SecLists kurulu DEĞİLSE collect_all_wordlists tüm paketli payload listelerini
#  döndürür; süzmezsek ffuf'un ~%80'i çöp olur.) Path-keşfi havuzundan ele.
_FFUF_NON_DISCOVERY_HINTS = (
    "sqli", "xss", "lfi", "rfi", "cmdi", "command", "ssrf", "ssti", "xxe",
    "nosqli", "payload", "deserial", "smuggl", "prototype", "jwt", "secret",
    "redirect", "passwd", "password", "cred", "param", "subdomain", "graphql",
    "values", "special-char", "special_char", "fuzz",
)


def _is_ffuf_discovery_wordlist(path: str) -> bool:
    """
    ffuf dizin/dosya keşfi için UYGUN bir wordlist mi? Payload/param/parola/subdomain
    listelerini (path-keşfinde hep 404) basit dosya-adı sezgisiyle eler. Gerçek path
    listeleri (dirs/files/api_paths/common/raft/directory-list…) korunur.
    """
    base = os.path.basename(path or "").lower()
    return not any(h in base for h in _FFUF_NON_DISCOVERY_HINTS)


def _ffuf_budgeted_wordlist(sources, tor_active: bool, max_words_override: int = 0):
    """
    ffuf'a verilecek wordlist'i BÜTÇEYE + TAŞIMAYA göre boyutlandırır: dedup eder ve
    bir üst sınıra kadar yazar. Kaynakları öncelik sırasıyla okur (en iyi curated
    discovery listesi önce), bir temp dosyaya yazar.

    SEBEP: collect_all_wordlists() tüm SecLists/PATT/DirBuster listelerini döndürür
    (milyonlarca satır). Eski kod hepsini cap'siz birleştiriyordu → ffuf bunu Tor'da
    (~2-3 req/s) veya 600s bütçede ASLA bitiremiyor → kill → ffuf'un `-o` JSON dosyası
    boş/yarım kalıyor → 'FFUF output was not valid JSON', sıfır sonuç. Cap'lersek ffuf
    listeyi BİTİRİR ve sonuçları yazar.

    Üst sınır = bütçe(sn) × gerçekçi hız(req/s) × 0.7; Tor'da hız düşük → liste küçük.
    Dönen: temp dosya yolu (çağıran finally'de silmeli) veya None.
    """
    try:
        # Tor-farkında bütçeyle HİZALA: -maxtime Tor'da ~7dk'ya sabitlendiği için
        # (content_discovery_timeout) wordlist de o süreye sığacak boyutta olmalı —
        # aksi halde ffuf 2400s'lik liste alıp 420s'de -maxtime'a takılır (kısmi).
        # Direkt bağlantıda content_discovery_timeout == effective_timeout (tam güç).
        from websecure.integrations.base import content_discovery_timeout as _cdt
        budget = int(_cdt(600) or 600)
    except Exception:
        budget = 600
    rate = 2.5 if tor_active else 40.0
    max_words = int(budget * rate * 0.7)
    if max_words_override and max_words_override > 0:
        max_words = max_words_override
    max_words = max(500, min(max_words, 100000))

    import tempfile as _tf
    seen: set = set()
    written = 0
    out_path = None
    try:
        fd, out_path = _tf.mkstemp(prefix="ws_ffuf_wl_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8", errors="ignore") as out:
            for src in sources:
                if written >= max_words:
                    break
                if not src or not os.path.isfile(src):
                    continue
                try:
                    with open(src, "r", encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            w = line.strip()
                            if not w or w.startswith("#"):
                                continue
                            if w in seen:
                                continue
                            seen.add(w)
                            out.write(w + "\n")
                            written += 1
                            if written >= max_words:
                                break
                except Exception:
                    continue
    except Exception:
        return None
    if written == 0:
        try:
            if out_path and os.path.exists(out_path):
                os.remove(out_path)
        except OSError:
            pass
        return None
    _logger.info(
        f"[FFUF] Wordlist bütçelendi: {written} kelime "
        f"(cap={max_words}, tor={tor_active}, kaynak={len(sources)} liste)"
    )
    return out_path


def _ffuf_realistic_rate(session, url: str, threads: int, tor_active: bool) -> float:
    """ffuf'un GERÇEK isabet hızını (req/s) hedefin gecikmesinden tahmin eder.

    SEBEP: wordlist'i `bütçe × hız` ile boyutluyoruz; eski kod hızı SABİT 40 req/s
    (direkt) / 2.5 (Tor) varsayıyordu. Yavaş hedefte gerçek hız çok daha düşük →
    liste bütçeye sığmaz → ffuf timeout/kill → boş sonuç. Birkaç istek zamanlayıp
    `eşzamanlı thread / ortalama gecikme` ile gerçekçi tavan üretiriz; başarısız
    olursa eski sabit varsayıma düşer. Sonuç makul aralığa sıkıştırılır.
    """
    lat: list = []
    try:
        base = url.split("FUZZ")[0] if "FUZZ" in url else url
        for _ in range(3):
            _t0 = _t.monotonic()
            session.get(base, timeout=15, allow_redirects=False)
            lat.append(max(0.02, _t.monotonic() - _t0))
    except Exception:
        pass
    if lat:
        avg = sum(lat) / len(lat)
    else:
        avg = 4.0 if tor_active else 1.0
    rate = max(1, threads) / avg
    lo, hi = (0.5, 8.0) if tor_active else (3.0, 120.0)
    return max(lo, min(rate, hi))


_ALLOWED_HTTP = (200, 201, 202, 203, 204, 206, 301, 302, 307, 308)
_BLOCKED_HTTP = (401, 403, 407, 451)


def _header_fuzz_baseline(session, url: str) -> tuple:
    """Un-fuzzed (header'sız) baseline yanıtı: (status, body_len). Hata → (0, -1)."""
    try:
        r = session.get(url, timeout=15, allow_redirects=False)
        return int(getattr(r, "status_code", 0) or 0), len(getattr(r, "text", "") or "")
    except Exception:
        return 0, -1


def _is_real_header_bypass(base_status: int, base_len: int, hf: dict) -> bool:
    """Bir header enjeksiyonu YALNIZ baseline'a göre erişim durumunu değiştirdiğinde
    gerçek bir bypass'tır. Hedefe özel DEĞİL — her site için geçerli mantık:
      • baseline bloklu (401/403/407) + fuzzed erişilebilir (2xx/3xx) → klasik bypass;
      • ikisi de erişilebilir ama içerik BELİRGİN farklı (IP/host'a göre farklı sayfa)
        → içerik-bazlı bypass. Eşik yüksek (catch-all jitter FP üretmesin).
    Public/catch-all sayfa zaten 200 + aynı boyut → bypass edilecek bir şey yok → False."""
    try:
        hf_status = int(hf.get("status", 0) or 0)
    except (TypeError, ValueError):
        hf_status = 0
    if hf_status == 0:
        return False
    if base_status in _BLOCKED_HTTP and hf_status in _ALLOWED_HTTP:
        return True
    try:
        hf_len = int(hf.get("length", -1))
    except (TypeError, ValueError):
        hf_len = -1
    if (base_status in _ALLOWED_HTTP and hf_status in _ALLOWED_HTTP
            and base_len >= 0 and hf_len >= 0):
        if abs(hf_len - base_len) > max(2048, int(base_len * 0.30)):
            return True
    return False


def _sensitive_file_is_genuine(session, url: str, baseline) -> bool:
    """Keşfedilen 'hassas dosya' adayını yeniden çekip GERÇEKTEN o dosya mı doğrular.
    Catch-all SPA her .bak/.config yoluna 200 + HTML index döndürür → bu FP'dir.
    Genel kural (hedefe özel değil): genuine-hit (soft-404/catch-all değil) VE yanıt
    HTML uygulama kabuğu DEĞİL. Gerçek açık config/yedek (gerçek içerik) KORUNUR."""
    try:
        r = session.get(url, timeout=15, allow_redirects=False)
    except Exception:
        return False
    try:
        if baseline is not None and not baseline.is_genuine_hit(r):
            return False
    except Exception:
        pass
    try:
        ct = (r.headers.get("Content-Type", "") or "").lower()
    except Exception:
        ct = ""
    body = (getattr(r, "text", "") or "")[:2048].lower()
    if "text/html" in ct or "application/xhtml" in ct:
        return False
    if any(m in body for m in ("<!doctype html", "<html", "<app-root", "ng-version", "<script")):
        return False
    return True


def run_ffuf_scan(ctx) -> None:
    """
    Runs FFUF fuzzing.
    [Check 6] Wordlists usage.
    """
    if FFUFWrapper is None:
        add_result("ffuf", {"status": "skipped", "reason": "Integration module missing"})
        return

    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None) or getattr(ctx, "target", None)
    if not url:
        return

    if not _get_config(ctx, "offensive.ffuf.enabled", True):
        return

    # [WS3] Dynamic Wordlist Collection + SecLists/PATT kurulum tespiti
    from websecure.core.utils import collect_all_wordlists
    from websecure.core.utils.wordlists import get_tech_extensions

    _logger.info("Dinamik wordlist taraması başlatılıyor...")
    wl_data = collect_all_wordlists()
    all_wls = wl_data.get("all", [])
    count = wl_data.get("count", 0)
    est_lines = wl_data.get("total_lines_est", 0)
    curated = wl_data.get("curated", {})
    seclists_root = wl_data.get("seclists_root", "")

    _logger.info(f"[Wordlists] {count} wordlist bulundu | SecLists: {'VAR' if seclists_root else 'YOK'} | ~{est_lines} satır")

    if count == 0:
        add_result("ffuf", {"status": "skipped", "reason": "No wordlists found in dynamic search"})
        return

    # Merge into a single temp file
    # ... code for merging wordlists ...
    
    # [WS3] Smart Login Audit
    # We run this if discovery found forms, or if we want to probe the login page specifically
    if _get_config(ctx, "login_discovery.enabled", True):
        try:
            from websecure.core.auth_flow import LoginAuditor
            
            # Identify forms from crawler results
            forms_meta = getattr(ctx, "results", {}).get("forms_meta", [])
            
            # If no forms meta, maybe we can try the base URL if it looks like login?
            # For now, rely on crawler output.
            
            if forms_meta:
                _logger.info(f"[Login-Audit] Found {len(forms_meta)} potential login forms. Starting Smart Audit (1000+ words)...")
                
                # Resolve wordlist path
                # NOT: burada `import os` YAPMA. Modül seviyesinde zaten import edildi
                # (satır 19). Fonksiyon-içi koşullu `import os`, `os`'u TÜM fonksiyon
                # için local değişken yapıyordu; forms_meta boşsa (SPA/login formu statik
                # HTML'de yoksa) bu satır hiç çalışmaz ve aşağıdaki `os.path.join` (API
                # wordlist dalı) `UnboundLocalError: 'os'` ile çökerdi → ffuf fazı komple
                # düşüyordu. Modül-düzeyi import'a güven.
                wl_path = os.path.join(os.getcwd(), "websecure/wordlists/passwords_top1000.txt")
                if not os.path.exists(wl_path):
                     _logger.warning("[Login-Audit] Wordlist not found, generating default...")
                     # write basic if missing (failsafe)
                     with open(wl_path, "w", encoding="utf-8") as f: f.write("admin\n123456\npassword\n")
                
                auditor = LoginAuditor(getattr(ctx, "session"), url, wl_path)
                
                # Re-feed forms into auditor (since auditor heuristic runs on HTML, 
                # but we already have form meta, we might need to adapt or just let auditor re-check URLs)
                # Simpler: Let auditor Scan the LOGIN urls found
                
                login_urls = [f['url'] for f in forms_meta]
                
                # Fetch content again to parse inputs accurately
                for l_url in login_urls:
                    try:
                        resp = getattr(ctx, "session").get(l_url, timeout=10)
                        auditor.discover_forms(resp.text, l_url)
                    except Exception as exc:
                        _logger.debug(f"[Login-Audit] Form discovery failed for {l_url}: {exc!r}")
                        
                results = auditor.run_audit()
                for res in results:
                    add_result("vulnerability", res)
                    
        except Exception as e:
            _logger.error(f"[Login-Audit] Failed: {e}")

    # Return or continue...

    # This is safer than multiple -w flags for a single FUZZ keyword
    merged_wl_path = "merged_wordlist_temp.txt"  # placeholder (finally temizler)
    _api_wl_built = None   # bütçeli API listesi (finally temizler)
    _ext_wl_built = None   # bütçeli uzantı listesi (finally temizler)
    try:
        _tor_active = bool(_resolve_proxy(ctx)) or os.environ.get("WEBSECURE_TOR_ACTIVE") == "1"
        _ffuf_max_words = int(_get_config(ctx, "offensive.ffuf.max_words", 0) or 0)

        wrapper = FFUFWrapper()
        if not wrapper.is_available():
            add_result("ffuf", {"status": "skipped", "reason": "Binary not found"})
            return

        custom_args = []
        # [Check 5] Proxy
        proxy = _resolve_proxy(ctx)
        if proxy:
            _logger.info(f"[Evasion] FFUF using proxy: {proxy}")
        _ffuf_profile = (getattr(ctx, "config", {}) or {}).get("_ffuf", {})

        # --- ffuf'u BÜTÇE İÇİNDE BİTİRECEK şekilde boyutla ---------------------
        # Her ffuf çağrısı kill-bütçesi (effective_timeout) İÇİNDE bitmeli; aksi
        # halde -maxtime/kill devreye girer ve eski kod boş JSON üretirdi. Gerçek
        # hızı hedefin gecikmesinden ölç, kelime tavanını ona göre seç. (Bu,
        # "ffuf farklı yerlerde timeout yiyor" şikâyetinin sayısal köküdür.)
        from websecure.integrations.base import effective_timeout as _eff_to_fn
        _eff_threads = int(_ffuf_profile.get("threads", 40))
        if proxy:
            _eff_threads = min(_eff_threads, 10)
        _ffuf_rate = _ffuf_realistic_rate(getattr(ctx, "session", None), url, _eff_threads, _tor_active)
        _call_budget = int(_eff_to_fn(600) or 600)
        # Uzantısız tek çağrıda sığacak kelime tavanı: bütçenin YARISINDA bitsin
        # (kalan yarı = boyutlama hatası payı + ffuf'un kendi -maxtime marjı).
        _base_word_cap = max(500, min(int(_call_budget * 0.5 * _ffuf_rate), 100000))
        if _ffuf_max_words > 0:
            _base_word_cap = _ffuf_max_words
        _logger.info(
            f"[FFUF] hız≈{_ffuf_rate:.1f} req/s | bütçe={_call_budget}s | "
            f"kelime-tavanı={_base_word_cap} (threads={_eff_threads}, tor={_tor_active})"
        )

        # Öncelik: curated discovery listeleri ÖNCE (targeted), sonra paketli/dış
        # listelerin YALNIZ path-keşfine uygun olanları (payload/param/parola/subdomain
        # listeleri elenir — yoksa ffuf'un çoğu çöp denemeye gider, özellikle SecLists
        # kurulu değilken). Curated zaten vetted, doğrudan; all_wls süzülür.
        _disc_from_all = [w for w in all_wls if _is_ffuf_discovery_wordlist(w)]
        _wl_sources = list(curated.get("discovery", [])) + _disc_from_all
        _built_wl = _ffuf_budgeted_wordlist(_wl_sources, _tor_active, _base_word_cap)
        if not _built_wl:
            add_result("ffuf", {"status": "skipped", "reason": "wordlist build failed"})
            return
        merged_wl_path = _built_wl

        # --- Directory/path discovery ---
        _logger.info("Launching FFUF scan with MERGED wordlist...")
        findings = wrapper.run_scan(url, wordlist=merged_wl_path, custom_args=custom_args, proxy=proxy, profile_cfg=_ffuf_profile)
        for f in findings:
            add_result("discovery", {"tool": "ffuf", **f})

        # --- API endpoint discovery ---
        # Ham curated[0]'ı (220k-1.2M satır) doğrudan KULLANMA — onu da bütçele,
        # yoksa SecLists kuruluyken API taraması da timeout yer (eski bug: bu dal
        # cap'siz curated[0] veriyordu, kodun kendi yorumu "kullanma" diyordu ama
        # API dalı yine de kullanıyordu).
        curated_api = curated.get("api", [])
        _api_sources = list(curated_api)
        if not _api_sources:
            _api_wl_path = os.path.normpath(os.path.join(
                os.path.dirname(__file__), "..", "..", "wordlists", "api_paths.txt"))
            if os.path.isfile(_api_wl_path):
                _api_sources = [_api_wl_path]
        if _api_sources:
            _api_wl_built = _ffuf_budgeted_wordlist(_api_sources, _tor_active, _base_word_cap)
            if _api_wl_built:
                _logger.info("[FFUF] API endpoint scan (bütçeli liste)")
                api_findings = wrapper.run_scan(url, wordlist=_api_wl_built, custom_args=custom_args, proxy=proxy, profile_cfg=_ffuf_profile)
                for f in api_findings:
                    add_result("discovery", {"tool": "ffuf", "category": "api", **f})

        # --- File extension discovery: tech-aware via get_tech_extensions() ---
        _ff_techs = list(getattr(ctx, "technologies", []) or [])
        sensitive_exts = get_tech_extensions(_ff_techs)
        # KRİTİK: -e ile her kelime (1 + uzantı_sayısı) kez denenir. Uzantı listesi
        # DAİMA ≥8 (varsayılan yedek/config seti), çoğu 14-20+. Wordlist'i bölmezsek
        # istek sayısı 9-21x patlar → garantili timeout/kill (uzantı taramasının
        # her seferinde boş dönmesinin sebebi buydu). Tavanı (1+uzantı) ile böl ki
        # toplam istek dizin taramasıyla aynı bütçede kalsın.
        _ext_count = (sensitive_exts.count(",") + 1) if sensitive_exts else 0
        _ext_cap = max(200, _base_word_cap // (1 + _ext_count)) if _ext_count else _base_word_cap
        _ext_wl_built = _ffuf_budgeted_wordlist(_wl_sources, _tor_active, _ext_cap)
        if _ext_wl_built:
            _logger.info(
                f"[FFUF] Extension scan (techs: {_ff_techs or 'generic'}): {sensitive_exts} "
                f"| kelime≤{_ext_cap}×(1+{_ext_count})"
            )
            ext_findings = wrapper.run_scan(
                url,
                wordlist=_ext_wl_built,
                extensions=sensitive_exts,
                custom_args=custom_args,
                proxy=proxy,
                profile_cfg=_ffuf_profile,
            )
            try:
                from websecure.scanners.js_analyzer import classify_discovered_file
                # FP GUARD: classify_discovered_file YALNIZ URL uzantısına bakar (.bak/
                # .config → "exposed"). Catch-all SPA her yola 200 + HTML index döndürür
                # → her uzantı sahte "High" olur (juice-shop'ta 71 FP). Adayı yeniden
                # çekip GERÇEK dosya mı doğrula (genuine-hit + HTML-shell değil). Gerçek
                # açık .bak/config (gerçek içerik) High kalır; catch-all Info'ya düşer.
                # Bütçeli: doğrulama isteği Tor'da pahalı → en çok _SF_VERIFY_CAP aday.
                _sf_session = getattr(ctx, "session", None) or hardened_session({})
                try:
                    from websecure.core.fp_reducer import SoftNotFoundBaseline as _SNB
                    _sf_baseline = _SNB.for_target(_sf_session, url)
                except Exception:
                    _sf_baseline = None
                _SF_VERIFY_CAP = 80
                _sf_checked = 0
                for f in ext_findings:
                    f_url = f.get("url", "")
                    f_status = f.get("status", 200)
                    classified = classify_discovered_file(f_url, f_status)
                    if not classified:
                        add_result("files_discovered", {"tool": "ffuf", "severity": "Info", **f})
                        continue
                    _genuine = False
                    if _sf_checked < _SF_VERIFY_CAP:
                        _sf_checked += 1
                        _genuine = _sensitive_file_is_genuine(_sf_session, f_url, _sf_baseline)
                    if _genuine:
                        add_result("files_discovered", classified)
                        if classified.get("severity") in ("Critical", "High"):
                            add_result("offensive", classified)
                    else:
                        # Doğrulanamadı (catch-all/HTML shell ya da bütçe doldu) →
                        # High/offensive'e YÜKSELTME, bilgi olarak tut.
                        add_result("files_discovered", {
                            "tool": "ffuf", "severity": "Info",
                            "type": classified.get("type", "Discovered Path"),
                            "url": f_url, "status": f_status,
                            "note": "doğrulanmadı (catch-all/HTML shell olabilir)",
                        })
            except ImportError:
                for f in ext_findings:
                    add_result("files_discovered", {"tool": "ffuf", "severity": "Info", **f})

        # --- Header fuzzing: IP spoofing / auth bypass / WAF bypass ---
        _hdr_fuzz_enabled = _get_config(ctx, "ffuf.header_fuzzing", True)
        if _hdr_fuzz_enabled:
            try:
                hdr_findings = wrapper.fuzz_headers(
                    url=url,
                    proxy=proxy,
                    threads=min(int(_ffuf_profile.get("threads", 20)), 20),
                )
                # FP GUARD: bir header "bypass"ı yalnız baseline'a (header'sız istek)
                # GÖRE erişim durumu değiştiğinde gerçektir. Eskiden ffuf -mc ile dönen
                # HER 200 işaretleniyordu → catch-all/public sayfada 326 sahte "Auth
                # Bypass [Medium]" (aynı URL, payload=N/A). Gerçek bypass (403→200) ve
                # içerik-bazlı bypass korunur; baseline ile aynı yanıtlar elenir.
                _hf_session = getattr(ctx, "session", None) or hardened_session({})
                _hf_base_status, _hf_base_len = _header_fuzz_baseline(_hf_session, url)
                _hf_kept = [hf for hf in hdr_findings
                            if _is_real_header_bypass(_hf_base_status, _hf_base_len, hf)]
                for hf in _hf_kept:
                    hdr_name = hf.get("fuzzed_header", "unknown")
                    hdr_val = hf.get("input", "")
                    hdr_status = hf.get("status", 0)
                    add_result("offensive", {
                        "type": "Header Fuzzing — Potential Auth/IP Bypass",
                        "severity": "Medium",
                        "url": url,
                        "tool": "ffuf",
                        "fuzz_mode": "header_value",
                        "fuzzed_header": hdr_name,
                        "fuzzed_value": hdr_val,
                        "status": hdr_status,
                        "baseline_status": _hf_base_status,
                        "message": (
                            f"Header '{hdr_name}: {hdr_val}' → HTTP {hdr_status} "
                            f"(baseline header'sız: HTTP {_hf_base_status}) — erişim durumu "
                            "değişti, olası auth/IP bypass"
                        ),
                    })
                if _hf_kept:
                    _logger.info(
                        f"[FFUF] Header fuzzing: {len(_hf_kept)} gerçek bypass "
                        f"({len(hdr_findings)} aday, {len(hdr_findings) - len(_hf_kept)} "
                        f"baseline-eşi elendi; baseline=HTTP {_hf_base_status})"
                    )
                elif hdr_findings:
                    _logger.info(
                        f"[FFUF] Header fuzzing: {len(hdr_findings)} aday baseline ile aynı "
                        f"(HTTP {_hf_base_status}) → bypass değil, hepsi elendi"
                    )
            except Exception as _hdr_exc:
                _logger.debug(f"[FFUF] Header fuzzing skipped: {_hdr_exc!r}")

    finally:
        # Cleanup — dizin + API + uzantı bütçeli temp listelerinin hepsi silinmeli.
        for _tmp in (merged_wl_path, _api_wl_built, _ext_wl_built):
            if _tmp and os.path.exists(_tmp):
                try:
                    os.remove(_tmp)
                except OSError:
                    pass
        _logger.debug("FFUF temp wordlists deleted.")


def run_feroxbuster_scan(ctx) -> None:
    """
    Runs Feroxbuster for content discovery.
    """
    if FeroxbusterWrapper is None:
        add_result("feroxbuster", {"status": "skipped", "reason": "Integration module missing"})
        return
        
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None) or getattr(ctx, "target", None)
    if not url:
        return

    if not _get_config(ctx, "feroxbuster.enabled", True):
        return

    wrapper = FeroxbusterWrapper()
    if not wrapper.is_available():
        add_result("feroxbuster", {"status": "skipped", "reason": "Binary not found"})
        return

    _logger.info("Launching Feroxbuster scan...")
    # Correct config paths: feroxbuster.depth takes priority over discovery.feroxbuster.depth
    depth = int(_get_config(ctx, "feroxbuster.depth",
                _get_config(ctx, "discovery.feroxbuster.depth", 3)))
    wordlist = _get_config(ctx, "feroxbuster.wordlist", "")

    extra_args = []
    # [Check 5] Proxy
    proxy = _resolve_proxy(ctx)
    if proxy:
        extra_args.extend(["--proxy", proxy])

    findings = wrapper.scan(url, wordlist=wordlist or None, depth=depth, extra_args=extra_args)
    
    new_eps = []
    for f in findings:
        f_url = f.get("url")
        if f_url:
             new_eps.append(f_url)
        add_result("discovery", {"tool": "feroxbuster", **f})

    # [WS3] FEEDBACK LOOP: Add to endpoints for offensive tools
    if new_eps:
        current_res = getattr(ctx, "results", {}) or {}
        existing = set(current_res.get("endpoints", []))
        before_count = len(existing)
        existing.update(new_eps)
        current_res["endpoints"] = list(existing)
        if len(existing) > before_count:
             _logger.info(f"[Feroxbuster] Added {len(existing) - before_count} new endpoints to offensive context.")
        ctx.results = current_res


def run_polyglot_probe(ctx) -> None:
    """
    Generic Polyglot Injection-Surface Probe — paketli wordlists/values.txt'yi (polyglot
    saldırı-değerleri: SSRF metadata, XXE, sleep, traversal, JWT…) keşfedilen HER query
    parametresine püskürtür ve REAKTİF parametreleri bir TRİYAJ sinyali olarak işaretler:
      • saldırı-şekilli girdide sunucu HATASI (5xx, baseline 5xx değilken)  -> Low
      • payload'ın HAM (escape'siz) YANSIMASI (<...> içeren payload aynen dönerse) -> Info
    Dedike tarayıcılarla (sqli/xss/lfi…) YARIŞMAZ — onaylı zafiyet iddia etmez, yalnız
    "şu parametre saldırı girdisine tepkili, derinlemesine bakılmalı" der. Tor-farkında
    cap'ler ile istek sayısı sınırlı. (Eskiden orphan olan values.txt'nin evi.)
    """
    try:
        url = (getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
               or getattr(ctx, "target", None))
        if not url:
            return
        if not _get_config(ctx, "offensive.polyglot_probe.enabled", True):
            return
        session = getattr(ctx, "session", None)
        if session is None:
            import requests as _rq
            session = _rq.Session()

        from websecure.core.payloads import load_external_payloads
        polyglots = [p.strip() for p in (load_external_payloads("values") or [])
                     if p and p.strip() and not p.strip().startswith("#")]
        if not polyglots:
            add_result("meta", {"stage": "polyglot_probe", "status": "skipped:no-values"})
            return

        tor = bool(_resolve_proxy(ctx)) or os.environ.get("WEBSECURE_TOR_ACTIVE") == "1"
        max_params = 15 if tor else 40
        max_vals = 8 if tor else 15
        polyglots = polyglots[:max_vals]

        from urllib.parse import urlparse, parse_qsl, urlencode

        results = getattr(ctx, "results", {}) or {}
        endpoints = list(results.get("endpoints", []) or [])
        if url not in endpoints:
            endpoints.insert(0, url)

        # Aday (endpoint, param) çiftleri — yalnız query parametresi olanlar
        candidates = []
        seen_pairs = set()
        for ep in endpoints:
            try:
                pr = urlparse(ep)
                for (k, _v) in parse_qsl(pr.query, keep_blank_values=True):
                    key = (pr.scheme, pr.netloc, pr.path, k)
                    if key in seen_pairs:
                        continue
                    seen_pairs.add(key)
                    candidates.append((ep, k))
                    if len(candidates) >= max_params:
                        break
            except Exception:
                continue
            if len(candidates) >= max_params:
                break
        if not candidates:
            add_result("meta", {"stage": "polyglot_probe", "status": "completed",
                                "params_probed": 0, "flagged": 0})
            return

        _to = 12
        flagged = 0
        for ep, param in candidates:
            try:
                pr = urlparse(ep)
                base_q = dict(parse_qsl(pr.query, keep_blank_values=True))
                # baseline (benign deger)
                bq = dict(base_q); bq[param] = "wsbenign1"
                try:
                    b_resp = session.get(pr._replace(query=urlencode(bq)).geturl(),
                                         timeout=_to, allow_redirects=False)
                    base_status = b_resp.status_code
                except Exception:
                    base_status = None

                hit = None
                for v in polyglots:
                    q = dict(base_q); q[param] = v
                    try:
                        r = session.get(pr._replace(query=urlencode(q)).geturl(),
                                        timeout=_to, allow_redirects=False)
                    except Exception:
                        continue
                    # 1) error-reactive (en guclu sinyal)
                    if r.status_code >= 500 and (base_status is None or base_status < 500):
                        hit = ("error", v, r.status_code); break
                    # 2) HAM (escape'siz) yansima: <...> iceren payload aynen donduyse
                    if ("<" in v and ">" in v) and v in (r.text or ""):
                        hit = ("reflect", v, r.status_code)
                        # error daha guclu — taramaya devam, error bulunca ustune yaz
                        continue
                if hit:
                    kind, v, code = hit
                    sev = "Low" if kind == "error" else "Info"
                    signal = ("saldırı girdisinde sunucu hatası (5xx)" if kind == "error"
                              else "payload ham/escape'siz yansıdı (olası enjeksiyon yüzeyi)")
                    add_result("offensive", {
                        "type": "Injection Surface (Polyglot Probe)",
                        "severity": sev,
                        "url": ep,
                        "param": param,
                        "tool": "polyglot_probe",
                        "verified": False,
                        "evidence": {
                            "signal": signal,
                            "payload": v[:120],
                            "status": code,
                            "baseline_status": base_status,
                        },
                        "message": (
                            f"Parametre '{param}' polyglot saldırı girdisine tepki verdi: {signal}. "
                            "TRİYAJ sinyali — onaylı zafiyet DEĞİL; dedike tarayıcı doğrulamalı."
                        ),
                    })
                    flagged += 1
            except Exception as exc:
                _logger.debug(f"[polyglot_probe] {ep} [{param}]: {exc!r}")

        add_result("meta", {"stage": "polyglot_probe", "status": "completed",
                            "params_probed": len(candidates), "flagged": flagged})
        _logger.info(f"[polyglot_probe] {len(candidates)} parametre tarandı, {flagged} reaktif")
    except Exception as e:
        _logger.debug(f"[polyglot_probe] error: {e!r}")
        add_result("meta", {"stage": "polyglot_probe", "status": "skipped:error",
                            "error": str(e)[:200]})


def run_nuclei_scan(ctx) -> None:
    """
    Nuclei vulnerability scanner — tam entegrasyon.

    Özellikler:
      - Tech-aware template seçimi (ctx.technologies)
      - Stealth / Agresif profil (rate-limit + concurrency)
      - OAST/interactsh entegrasyonu (ctx.oast_domain → -iserver/-interactsh-url)
      - Mevcut WebSecure bulgularıyla deduplication (fingerprint bazlı)
      - Tespit edilen yeni teknolojileri ctx.technologies'e ekler
      - Şablon güncelleme (stealth'te atlanır)
    """
    if NucleiWrapper is None:
        add_result("nuclei", {"status": "skipped", "reason": "NucleiWrapper not importable"})
        return

    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return

    if not _get_config(ctx, "nuclei.enabled", True):
        add_result("nuclei", {"status": "skipped", "reason": "Disabled in config"})
        return

    wrapper = NucleiWrapper()
    if not wrapper.is_available():
        add_result("nuclei", {"status": "skipped", "reason": "nuclei binary not found"})
        _logger.warning(
            "[Nuclei] Binary bulunamadı. "
            "tools/nuclei/nuclei (Linux/macOS) veya tools/nuclei/nuclei.exe (Windows) "
            "yoluna koyun ya da PATH'e ekleyin."
        )
        return

    # ------------------------------------------------------------------
    # Profil tespiti: stealth / aggressive / normal
    # ------------------------------------------------------------------
    cfg = getattr(ctx, "config", {}) or {}
    _scan_profile = str(
        (cfg.get("settings") or {}).get("scan_profile", "normal")
    ).lower()
    if _scan_profile not in ("stealth", "aggressive", "normal"):
        _scan_profile = "normal"

    # ------------------------------------------------------------------
    # Parametre toplama
    # ------------------------------------------------------------------
    tech_stack   = list(getattr(ctx, "technologies", []) or [])
    proxy        = _resolve_proxy(ctx)
    severity     = _get_config(ctx, "nuclei.severity", "low,medium,high,critical")
    extra_tags   = _get_config(ctx, "nuclei.tags", "") or ""
    auto_update  = bool(_get_config(ctx, "nuclei.auto_update", True))
    tags         = extra_tags.strip() if extra_tags.strip() else None
    nuclei_cfg   = cfg.get("_nuclei", {}) or {}

    # OAST domain (interactsh subdomain — kör SSRF/RCE tespiti)
    interactsh_url: Optional[str] = None
    oast_domain = getattr(ctx, "oast_domain", None)
    if oast_domain:
        # Tam URL formatı: https://xyz.oast.pro veya dns://xyz.oast.pro
        interactsh_url = oast_domain if "://" in oast_domain else f"https://{oast_domain}"
        _logger.info(f"[Nuclei] OAST callback URL: {interactsh_url}")

    # ------------------------------------------------------------------
    # Deduplication: mevcut WebSecure fingerprint'leri topla
    # ------------------------------------------------------------------
    existing_fps: set = set()
    try:
        results_dict = getattr(ctx, "results", {}) or {}
        for bucket in ("offensive", "xss", "sqli", "ssrf", "nuclei"):
            for item in (results_dict.get(bucket) or []):
                if isinstance(item, dict):
                    key = f"{item.get('template_id','')}{item.get('url','')}"
                    if key:
                        import hashlib as _h
                        existing_fps.add(
                            _h.md5(key.encode(), usedforsecurity=False).hexdigest()
                        )
    except Exception as _dedup_exc:
        _logger.debug(f"[Nuclei] Dedup fingerprint toplama hatası: {_dedup_exc!r}")

    # ------------------------------------------------------------------
    # Şablon güncelleme (stealth'te atla)
    # ------------------------------------------------------------------
    if auto_update and _scan_profile != "stealth":
        _logger.info("[Nuclei] Şablon güncelliği kontrol ediliyor...")
        try:
            wrapper.update_templates(force=False, timeout=60)
            ver = wrapper.get_template_version()
            if ver:
                _logger.info(f"[Nuclei] Şablonlar hazır: {ver}")
        except Exception as _nu_exc:
            _logger.debug(f"[Nuclei] Şablon güncelleme kontrolü başarısız: {_nu_exc!r}")

    # ------------------------------------------------------------------
    # Tarama
    # ------------------------------------------------------------------
    _logger.info(
        f"[Nuclei] Tarama başlıyor → {url} "
        f"(profil={_scan_profile}, tech={tech_stack or 'auto'}, "
        f"oast={'evet' if interactsh_url else 'hayır'})"
    )

    findings = wrapper.scan(
        target=url,
        tags=tags,
        severity=severity,
        proxy=proxy,
        tech_stack=tech_stack,
        profile_cfg=nuclei_cfg,
        profile=_scan_profile,
        interactsh_url=interactsh_url,
        auto_update=False,           # Yukarıda zaten ele alındı
        deduplicate_fps=existing_fps,
    )

    # ------------------------------------------------------------------
    # Sonuçları dağıt
    # ------------------------------------------------------------------
    crit_high_count = 0
    new_techs: list = []

    for finding in findings:
        sev = finding.get("severity", "Info")
        add_result("nuclei", finding)

        # Critical / High / Medium → offensive bucket'a da ekle
        if sev in ("Critical", "High", "Medium"):
            add_result("offensive", finding)
            crit_high_count += 1

        # Tech detection bulguları CVE değil — technologies listesine ekle
        if finding.get("is_tech_detection"):
            new_techs.append(finding.get("vuln_type", "").lower())

    # Yeni teknolojileri ctx.technologies'e ekle
    if new_techs:
        existing_techs = list(getattr(ctx, "technologies", []) or [])
        merged = list(set(existing_techs + new_techs))
        try:
            ctx.technologies = merged
        except AttributeError:
            pass
        _logger.info(f"[Nuclei] Yeni teknoloji tespiti: {new_techs}")

    # CVE özeti meta'ya
    cve_list = [
        cve
        for f in findings
        for cve in (f.get("cve_ids") or [])
        if cve
    ]

    add_result("meta", {
        "stage":        "nuclei",
        "findings":     len(findings),
        "crit_high":    crit_high_count,
        "cve_count":    len(cve_list),
        "cve_ids":      sorted(set(cve_list))[:20],  # ilk 20 CVE
        "profile":      _scan_profile,
        "oast_enabled": bool(interactsh_url),
        "template_ver": wrapper.get_template_version() or "unknown",
    })

    _logger.info(
        f"[Nuclei] Tamamlandı: {len(findings)} bulgu "
        f"({crit_high_count} Kritik/Yüksek, {len(cve_list)} CVE)"
    )


def run_js_analysis(ctx) -> None:
    """
    Discovers and analyses JavaScript files on the target:
    - Extracts hidden API endpoints / internal paths
    - Detects hardcoded secrets, tokens, API keys
    """
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None) or getattr(ctx, "target", None)
    if not url:
        return

    if not _get_config(ctx, "offensive.scanners.js_analysis.enabled", True):
        add_result("js", {"status": "skipped", "reason": "Disabled in config"})
        return

    try:
        from websecure.scanners.js_analyzer import JSAnalyzer
    except ImportError:
        add_result("js", {"status": "skipped", "reason": "js_analyzer module missing"})
        return

    _logger.info("[JSAnalyzer] Starting JavaScript file analysis...")
    results_bucket = getattr(ctx, "results", {}) or {}
    session = getattr(ctx, "session", None)

    analyzer = JSAnalyzer(session=session, results=results_bucket, debug=False)
    findings = analyzer.run(url)

    for f in findings:
        add_result("js", f)
        if f.get("severity") in ("High", "Critical"):
            add_result("offensive", f)

    _logger.info(f"[JSAnalyzer] Done. {len(findings)} finding(s) recorded.")


def run_reporting_and_integration(ctx) -> None:
    from websecure.core.reporting import perform_reporting

    results = getattr(ctx, "results", {}) or {}
    cfg = getattr(ctx, "config", {}) or {}
    session = getattr(ctx, "session", None)

    _logger.info("Generating Final Reports...")
    perform_reporting(session, cfg, results)

    # Always-on SARIF + JUnit — CI/CD pipeline'ı için yapılandırmadan bağımsız üret
    _rep_cfg = (cfg.get("reporting") or {}) if isinstance(cfg, dict) else {}
    _formats = list(_rep_cfg.get("formats") or [])
    try:
        from websecure.core import paths as _ws_paths
        _default_out = str(_ws_paths.output_dir()) if _ws_paths.is_frozen() else "output"
    except Exception:
        _default_out = "output"
    _out_dir = str(_rep_cfg.get("output_dir") or cfg.get("output_dir") or _default_out)
    try:
        import os as _os
        _os.makedirs(_out_dir, exist_ok=True)
    except Exception as _fix_e:
        _logger.debug(f"[core.phases.__init__] {type(_fix_e).__name__}: {_fix_e!r}")

    if "sarif" not in _formats:
        try:
            from websecure.core.report_generator import export_sarif as _export_sarif
            from websecure.core.reporting import get_global_results as _get_gr
            _all_findings: List[Dict] = []
            for _bucket in _get_gr().values():
                if isinstance(_bucket, list):
                    _all_findings.extend(_bucket)
            import os as _os2
            _sarif_path = _os2.path.join(_out_dir, "websecure.sarif")
            _export_sarif({"findings": _all_findings}, _sarif_path)
            _logger.info(f"[run_reporting] SARIF always-on yazıldı: {_sarif_path}")
        except Exception as _sarif_exc:
            _logger.debug(f"[run_reporting] SARIF always-on hatası: {_sarif_exc!r}")

    if "junit" not in _formats:
        try:
            from websecure.core.report_generator import export_junit as _export_junit
            from websecure.core.reporting import get_global_results as _get_gr2
            _all_findings2: List[Dict] = []
            for _bucket2 in _get_gr2().values():
                if isinstance(_bucket2, list):
                    _all_findings2.extend(_bucket2)
            import os as _os3
            _junit_path = _os3.path.join(_out_dir, "websecure.junit.xml")
            _export_junit({"findings": _all_findings2}, _junit_path)
            _logger.info(f"[run_reporting] JUnit always-on yazıldı: {_junit_path}")
        except Exception as _junit_exc:
            _logger.debug(f"[run_reporting] JUnit always-on hatası: {_junit_exc!r}")

    # Faz 12: NotificationDispatcher — scan tamamlandığında webhook/email/Slack bildir
    try:
        from websecure.core.notification import NotificationDispatcher, NotificationConfig
        # Notifications config varsa dispatcher kur
        _notif_cfg_raw = (cfg.get("notifications") or cfg.get("notification") or {})
        if _notif_cfg_raw and isinstance(_notif_cfg_raw, dict):
            _notif_cfg = NotificationConfig.from_dict(_notif_cfg_raw)
            dispatcher = NotificationDispatcher(config=_notif_cfg)
            # Sadece notifier konfigürasyonu varsa gönder
            if dispatcher._notifiers:
                from websecure.core.reporting import get_global_results as _get_gr3
                _all_f3: List[Dict] = []
                for _b3 in _get_gr3().values():
                    if isinstance(_b3, list):
                        _all_f3.extend(
                            [i for i in _b3 if isinstance(i, dict)
                             and i.get("severity") in ("Critical", "High", "Medium", "Low", "Info")]
                        )
                totals = dispatcher.notify_batch(_all_f3, deduplicate=True)
                _logger.info(f"[run_reporting] Bildirim: {totals}")
    except Exception as _notif_exc:
        _logger.debug(f"[run_reporting] Bildirim hatası: {_notif_exc!r}")


def _setup_oast_domain(ctx) -> Optional[str]:
    """
    SSRF/XXE taraması başlamadan önce interactsh'e kayıt olur,
    dönen subdomain'i ctx.oast_domain olarak kaydeder.
    Döndürülen subdomain SSRF scanner'ın dns_domain alanına geçirilir.
    """
    cfg = getattr(ctx, "config", {}) or {}
    oast_cfg = cfg.get("oast", {}) or {}
    if not oast_cfg.get("enabled", False):
        return None

    interactsh_cfg = oast_cfg.get("interactsh", {}) or {}
    server = (interactsh_cfg.get("server") or "").rstrip("/")
    token  = interactsh_cfg.get("token", "")
    if not server or not token:
        return None

    try:
        import requests as _requests
        reg_resp = _requests.post(
            f"{server}/register",
            json={"public-key": "", "secret-key": token, "correlation-id": "websecure"},
            timeout=10,
        )
        data = reg_resp.json()
        # interactsh yanıtı: {"correlation-id": "...", "domain": "abc123.oast.pro"}
        domain = data.get("domain") or data.get("correlation-id", "")
        if domain:
            setattr(ctx, "oast_domain", domain)
            setattr(ctx, "oast_correlation_id", data.get("correlation-id", ""))
            _logger.info(f"[OAST] interactsh subdomain alındı: {domain}")
            return domain
    except Exception as exc:
        _logger.debug(f"[OAST] Subdomain alma hatası: {exc!r}")
    return None


def run_oast_verification(ctx) -> None:
    """interactsh'e poll ederek DNS/HTTP callback'lerini toplar ve eşleşen bulguları verified=True yapar."""
    cfg = getattr(ctx, "config", {}) or {}
    oast_cfg = cfg.get("oast", {}) or {}
    if not oast_cfg.get("enabled", False):
        add_result("meta", {"stage": "oast", "status": "disabled"})
        return

    interactsh_cfg = oast_cfg.get("interactsh", {}) or {}
    server = (interactsh_cfg.get("server") or "").rstrip("/")
    token  = interactsh_cfg.get("token", "")
    poll_interval = float(oast_cfg.get("poll_interval", 5.0))
    wait_seconds  = float(oast_cfg.get("wait_seconds", 45))

    if not server or not token:
        add_result("meta", {"stage": "oast", "status": "no_server_or_token"})
        _logger.warning("[OAST] interactsh server/token yapılandırılmamış. oast.interactsh.server ve .token ayarlayın.")
        return

    import time as _time
    import requests as _requests

    # interactsh'e kayıt ol -> benzersiz correlation ID al
    try:
        reg_resp = _requests.post(
            f"{server}/register",
            json={"public-key": "", "secret-key": token, "correlation-id": "websecure"},
            timeout=10,
        )
        reg_data = reg_resp.json()
        correlation_id = reg_data.get("correlation-id", "")
        _logger.info(f"[OAST] interactsh kaydı tamam, correlation-id: {correlation_id}")
    except Exception as exc:
        _logger.warning(f"[OAST] interactsh kayıt hatası: {exc!r}")
        add_result("meta", {"stage": "oast", "status": f"registration_failed: {exc}"})
        return

    # wait_seconds süresince poll et
    deadline = _time.time() + wait_seconds
    all_events = []
    _logger.info(f"[OAST] {wait_seconds}s boyunca callback bekleniyor (her {poll_interval}s)...")
    while _time.time() < deadline:
        try:
            poll_resp = _requests.get(
                f"{server}/poll",
                params={"id": correlation_id, "secret": token},
                timeout=10,
            )
            data = poll_resp.json()
            interactions = data.get("data") or []
            if interactions:
                all_events.extend(interactions)
                _logger.info(f"[OAST] {len(interactions)} callback alındı!")
        except Exception as exc:
            _logger.debug(f"[OAST] Poll hatası: {exc!r}")
        _time.sleep(poll_interval)

    for ev in all_events:
        add_result("oast_callbacks", ev)

    add_result("meta", {
        "stage": "oast",
        "status": "ok",
        "callbacks_received": len(all_events),
    })
    _logger.info(f"[OAST] Tamamlandı. Toplam {len(all_events)} callback.")



def run_fuzz_and_param_discovery(ctx) -> None:
    """
    Parametre keşfi ve fuzzing fazı.
    ParamDiscoveryPipeline (ffuf-based) ile parametre mining yapar.
    """
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "") or ""
    if not url:
        add_result("meta", {"stage": "fuzz_param_discovery", "status": "skipped:no-url"})
        return
    try:
        from websecure.integrations.ffuf import ParamDiscoveryPipeline
        # Oturum cookie'lerini ffuf'a aktar; aksi halde kimlik-doğrulamalı
        # hedeflerde parametre keşfi anonim çalışıp auth-arkası parametreleri
        # kaçırıyordu (session alınıyor ama discover'a HİÇ geçilmiyordu — kopuk).
        session = getattr(ctx, "session", None)
        cookie_str = ""
        _cookies = getattr(session, "cookies", None)
        if _cookies:
            try:
                cookie_str = "; ".join(f"{c.name}={c.value}" for c in _cookies)
            except Exception as _ck_exc:
                _logger.debug("[phases] cookie serialize failed: %r", _ck_exc)
        pipeline = ParamDiscoveryPipeline()
        result = pipeline.discover(url, method="GET", cookie=cookie_str)
        if result and result.params:
            add_result("discovery", {
                "url": url,
                "params_found": result.params,
                "total": len(result.params),
                "source": "ParamDiscoveryPipeline",
            })
            # Inject discovered params into ctx for downstream scanners
            existing = getattr(ctx, "discovered_params", []) or []
            ctx.discovered_params = list(dict.fromkeys(existing + result.params))
            _logger.info(
                "[phases] ParamDiscoveryPipeline: %d params discovered at %s",
                len(result.params), url,
            )
        else:
            add_result("meta", {"stage": "fuzz_param_discovery", "status": "no_params_found"})
    except Exception as exc:
        _logger.debug("[phases] ParamDiscoveryPipeline error: %r", exc)
        add_result("meta", {"stage": "fuzz_param_discovery", "status": "delegated_to_main_loop"})

def run_authorization_matrix(ctx) -> None:
    """
    Yetkilendirme matrisi (IDOR/PrivEsc) testi.
    scanners.auth modülünü kullanır.
    """
    mod = _opt_import("websecure.scanners.auth_scanners")
    if not mod:
        add_result("auth_matrix", {"status": "skipped", "reason": "Module not found"})
        return

    # run(session, base_url, users=[...]) imzasına uyum sağla
    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        add_result("auth_matrix", {"status": "skipped", "reason": "run() function missing"})
        return

    # Config'den kullanıcıları al
    cfg = getattr(ctx, "config", {}) or {}
    auth_cfg = cfg.get("auth", {}) or {}
    if not auth_cfg.get("matrix_enabled", True):
        return

    users = auth_cfg.get("users", []) # [{"user": "admin", "pass": "123"}, ...]
    
    _logger.info("Launching Authorization Matrix Scan...")
    
    # Session ve URL
    sess = getattr(ctx, "session", None) or hardened_session()
    url = getattr(ctx, "base_url", "")
    
    try:
        # Modülün run fonksiyonunu çağır.
        # BUG FIX ("run() missing 1 required positional argument: 'target'"):
        # auth_scanners.run imzası (target, session, results, debug) — ilk ZORUNLU
        # param 'target'. Eski kod yalnız url/base_url veriyordu, _filter_kwargs
        # 'target'ı eşleştiremeyip düşürünce çağrı patlıyordu. 'target' anahtarını
        # ekle (url/base_url da uyumlu imzalar için kalsın).
        kw = _filter_kwargs(run_fn, {
            "target": url, "url": url, "base_url": url,
            "session": sess, "config": cfg, "users": users,
        })
        findings = run_fn(**kw)
        
        if findings:
            for f in findings:
                add_result("auth_matrix", f)
        add_result("meta", {"stage": "auth_matrix", "findings": len(findings) if findings else 0})

    except Exception as e:
        _logger.error(f"Auth Matrix Error: {e}")
        add_result("errors", {"stage": "auth_matrix", "error": str(e)})


def run_business_logic_races(ctx) -> None:
    """
    Business Logic Race Condition testlerini çalıştırır.
    websecure.core.bl_concurrency modülünü kullanır.
    """
    try:
        from websecure.core.bl_concurrency import run_race_conditions
    except ImportError:
        add_result("meta", {"stage": "races", "status": "skipped:missing_core_module"})
        return

    sess = getattr(ctx, "session", None) or hardened_session()
    url = getattr(ctx, "base_url", "")
    cfg = getattr(ctx, "config", {}) or {}
    results_bucket = getattr(ctx, "results", {}) or {}
    debug = bool(getattr(ctx, "debug", False))

    if not _get_config(ctx, "business_logic.enabled", True):
        return

    _logger.info("Launching Business Logic Race Conditions Scan...")
    
    # Raporlama callback
    def _cb(evt, data):
        if debug:
            _logger.debug(f"[Race] {evt}: {data}")

    try:
        stats = run_race_conditions(sess, url, cfg, results_bucket, debug=debug, event_cb=_cb)
        _logger.info(f"Race Scan Finished: {stats}")
    except Exception as e:
        _logger.error(f"Race Scan Failed: {e}")
        add_result("errors", {"stage": "races", "error": str(e)})



# ===========================================================================
# MERGED FROM: websecure/core/scan_modes.py
# ScanContext, ScanMode, run_mode, run, run_many, build_plan delegates
# ===========================================================================
from websecure.core.utils import _ws_import_any, _ws_maybe_import_any
from importlib import import_module
from websecure.core.http import hardened_session
import re
import logging
from importlib.util import find_spec
import asyncio
import importlib
from dataclasses import dataclass
from pathlib import Path
import sys
import importlib.util as _ilu
from websecure.core.http import hardened_session as _hardened_session
# --- scan_modes merge: duplicate definitions removed, using originals defined above ---


def __ensure_triple_plan(plan):
    out = []
    for item in list(plan or []):
        if isinstance(item, (list, tuple)):
            if len(item) == 3:
                out.append(tuple(item))
            elif len(item) == 2:
                name, fn = item
                est = 90 if str(name).lower() not in ("discovery","portscan","tls","security_headers") else {"discovery":60,"portscan":60,"tls":45,"security_headers":45}.get(str(name).lower(),90)
                out.append((name, est, fn))
        else:
            # pass through (unknown)
            out.append(item)
    return out

def __run_plan_adapt(run_plan_fn, plan, ctx, cfg):
    try:
        params = list(_ins.signature(run_plan_fn).parameters.keys())
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [scan_modes]', exc_info=True)
        _report_phase_error('scan_modes', 'scan_modes.py', e)
        params = ["plan", "ctx"]
    if len(params) >= 3:
        return run_plan_fn(plan, ctx, cfg)
    return run_plan_fn(plan, ctx)

# --- Safe signature-aware call helper (prevents TypeError for unexpected kwargs) ---
import inspect as _ins

def _safe_call_runner(_fn, session=None, base_url=None, config=None, logger=None, context=None):
    """
    Signature-aware caller:
      - If _fn(ctx, phases) is expected, synthesize ctx and phases.
      - Else call with filtered kwargs: (session, base_url|url|base, config|cfg, logger)
    """
    import inspect as _ins_local
    try:
        params = list(_ins_local.signature(_fn).parameters.keys())
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [scan_modes]', exc_info=True)
        _report_phase_error('scan_modes', 'scan_modes.py', e)
        params = []

    # If runner expects (ctx, phases): build minimal ctx + phases
    if (len(params) >= 2 and params[0] == "ctx" and params[1] == "phases") or {"ctx","phases"}.issubset(params):
        # Build a minimal ScanContext if not provided
        if context is None:
            try:
                # ScanContext, modül tepesinde _context'ten import edilir; gerçek
                # bağlamı kur (eski 'try: pass' içi-boştu → _SC tanımsız kalıp NameError atıyordu).
                context = ScanContext(url=base_url, session=session, config=(config or {}), logger=logger)
            except _BOUNDARY_EXC as e:
                _logger.error('phase error [scan_modes]', exc_info=True)
                _report_phase_error('scan_modes', 'scan_modes.py', e)
                # Fallback tiny context (ScanContext protokolüyle birebir değil)
                class _SC:  # type: ignore[no-untyped-def]  # inline fallback, does not match ScanContext protocol
                    def __init__(self, url, session, config, logger):
                        self.url, self.session, self.config, self.logger = url, session, (config or {}), logger
                        self.results = {}
                        self.detailed = False
                        self.save_report = False
                        self.debug = False
                context = _SC(url=base_url, session=session, config=(config or {}), logger=logger)

        try:
            from websecure.core.phases import build_plan as _build_plan
        except _BOUNDARY_EXC as e:
            _logger.error('phase error [scan_modes]', exc_info=True)
            _report_phase_error('scan_modes', 'scan_modes.py', e)
            # ultimate fallback: empty plan
            def _build_plan(_ctx): return []  # type: ignore[misc]  # emergency fallback stub

        phases = getattr(context, "phases", None) or _build_plan(context)
        # normalize phases if they are dicts from build_plan
        if phases and isinstance(phases, (list, tuple)) and phases and isinstance(phases[0], dict):
            phases = [(str(p.get('id') or p.get('name') or 'phase'), p.get('runner')) for p in phases if callable(p.get('runner'))]
        return _fn(context, phases)

    # Otherwise: filter kwargs to expected names
    try:
        params = _ins_local.signature(_fn).parameters
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [scan_modes]', exc_info=True)
        _report_phase_error('scan_modes', 'scan_modes.py', e)
        params = {}

    kwargs = {}
    if "context" in params:
        kwargs["context"] = context
    elif "ctx" in params:
        kwargs["ctx"] = context
    
    # Pass raw results if requested (and context not used or redundant)
    if "results" in params:
        if context and context.results:
            kwargs["results"] = context.results
        else:
            kwargs["results"] = {}

    if "session" in params:
        kwargs["session"] = session
    if "base_url" in params:
        kwargs["base_url"] = base_url
    elif "url" in params:
        kwargs["url"] = base_url
    elif "base" in params:
        kwargs["base"] = base_url
    if "config" in params:
        kwargs["config"] = config
    elif "cfg" in params:
        kwargs["cfg"] = config
    if "logger" in params:
        kwargs["logger"] = logger
    return _fn(**kwargs) if kwargs else _fn()


# --- Qualified import helpers (no try/except, no lazy hacks) ---
_PKG_ROOT = (__package__.split('.')[0] if __package__ else 'websecure')  # expected 'websecure'

def _qualify(name: str) -> str:
    # Map 'core.xxx' to 'websecure.core.xxx' inside the package
    if name.startswith(f"{_PKG_ROOT}."):
        return name
    if name.startswith("core."):
        return f"{_PKG_ROOT}.{name}"
    return name

# _opt_import ve _resolve_module yukarıda tanımlı (satır 367 ve 379) — duplicate kaldırıldı
_PROJECT_ROOT = Path(__file__).resolve().parents[1]  # .../<root>
_SITEPK_SUBSTR = ("site-packages", "dist-packages")


_reporting = _opt_import("websecure.core.reporting")
_requests = _opt_import("requests")


# ScanMode + ScanContext -> extracted to websecure.core.phases._context (imported at top)

# ------------------------- Raporlama köprüleri -------------------------
def _report(bucket: str, item: Dict[str, Any]) -> None:
    if _reporting and hasattr(_reporting, "add_result"):
        _reporting.add_result(bucket, item)


def _flush_report() -> None:
    if _reporting and hasattr(_reporting, "flush"):
        _reporting.flush()


def _get_or_create_session(sess: Any):
    """session nesnesi varsa döner, yoksa hardened_session oluşturur."""
    if sess is not None:
        return sess
    if _requests is None:
        raise RuntimeError("requests modülü bulunamadı; oturum gerekli.")
    return _hardened_session({})


# ---------------------- Authenticated akışı arayıcı ----------------------
def _resolve_auth_runner():
    """
    authenticated_scan veya varyantlarını bulur; None dönebilir.

    """
    # Birincil adaylar
    for m in ("core.authenticated_scan", "authenticated_scan"):
        mod = _opt_import(m)
        if not mod:
            continue

        fn = getattr(mod, "run", None)
        if callable(fn):
            return lambda session, base_url, config, logger: _safe_call_runner(fn, session, base_url, config, logger)

        cls = getattr(mod, "AuthenticatedScanner", None)
        if cls is not None:
            def _call(session, base_url, config, logger):
                scanner = cls(session=session, base_url=base_url, config=config, logger=logger)
                run_all = getattr(scanner, "run_all", None)
                return run_all() if callable(run_all) else scanner.run()

            return _call

    # Geriye dönük (zorunlu değil)
    for m in ("core.flow_runner", "flow_runner"):
        mod = _opt_import(m)
        if not mod:
            continue
        for cand in ("run_authenticated", "run", "main"):
            fn = getattr(mod, cand, None)
            if callable(fn):
                return lambda session, base_url, config, logger: _safe_call_runner(fn, session, base_url, config, logger)
    return None


def incremental_targets(all_links: list[str], previous: list[str] | None = None) -> list[str]:
    prev = set(previous or [])
    return [u for u in (all_links or []) if u not in prev]


# HProfilePolicy + HProfileManager + hpm_* -> extracted to websecure.core.phases._hprofile (imported at top)

def run_mode(context: 'ScanContext', mode: str) -> 'Optional[Dict[str, Any]]':
    """
    NORMAL/DETAILED/DEEP: core.phases.build_plan + core.runner.run_plan (signature-aware).
    AUTHENTICATED: dış köprü + raporlama.
    """
    mode = (mode or "").strip().lower()
    if mode == "stealth":
        mode = ScanMode.NORMAL
    elif mode == "aggressive":
        mode = ScanMode.DEEP

    # Ensure session and target
    context.session = _ensure_session(getattr(context, "session", None))
    cfg = context.config or {}
    base_url = (getattr(context, "url", None) or cfg.get("base_url") or cfg.get("target") or "")
    if not base_url:
        _report("errors", {"stage": "run_mode", "error": "Target/base_url eksik"})
        _flush_report()
        return context.results

    # Non-authenticated modes
    if mode in (ScanMode.NORMAL, ScanMode.DETAILED, ScanMode.DEEP):
        context.detailed = (mode != ScanMode.NORMAL)

        # build_plan ve run_plan bu modülde tanımlı (merged from phases + runner)
        import sys as _sys
        _self_mod = _sys.modules.get(__name__) or _sys.modules.get("websecure.core.phases")
        build_plan_fn = globals().get("build_plan") or (getattr(_self_mod, "build_plan", None) if _self_mod else None)
        run_plan_fn = globals().get("run_plan") or (getattr(_self_mod, "run_plan", None) if _self_mod else None)

        if not callable(build_plan_fn) or not callable(run_plan_fn):
            _report("errors", {"stage": "run_mode", "error": "Flow runner çözümlemesi başarısız (build_plan/run_plan yok)"})
            _flush_report()
            return context.results

        plan = build_plan_fn(context)
        plan = __ensure_triple_plan(plan)

        loop = asyncio.get_event_loop_policy().get_event_loop()
        if loop.is_running():
            asyncio.create_task(__run_plan_adapt(run_plan_fn, plan, context, cfg))
        else:
            asyncio.run(__run_plan_adapt(run_plan_fn, plan, context, cfg))

        _flush_report()
        return context.results

    # Authenticated mode
    if mode == ScanMode.AUTHENTICATED:
        auth_runner = _resolve_auth_runner()
        if not callable(auth_runner):
            _report("errors", {"stage": "run_mode", "error": "Authenticated runner bulunamadı"})
            _flush_report()
            return context.results
        logger = logging.getLogger(__name__)
        auth_runner(context.session, base_url, cfg, logger=logger)
        _flush_report()
        return context.results

    _report("errors", {"stage": "run_mode", "error": f"desteklenmeyen mod: {mode}"})
    _flush_report()
    return context.results


# ===========================================================================
# MERGED FROM: websecure/core/runner.py
# RunnerConfig, run_plan, run, run_many, _build_ctx, _ensure_session
# ===========================================================================
# adjust_scan_mode defined in this module (merged from flow_runner.py)
from websecure.core.reporting import get_bucket_results
import asyncio
from dataclasses import dataclass
from typing import List, Tuple, Awaitable, Callable, Optional, Dict, Any
import sys
import time
import asyncio
# ScanContext defined in this module (merged from scan_modes.py)
from websecure.core.reporting import log_info, log_warn, add_result, flush as _report_flush
# flush defined in this module (merged from flow_runner.py)
from importlib.util import find_spec
from types import SimpleNamespace
from types import SimpleNamespace
import importlib

from typing import TYPE_CHECKING, Callable
# run_plan is defined in this module (merged from runner.py)
# --------------------------- Dinamik import yardımcıları ---------------------------
def _missing_guard(symbol: str, where: str):
    def _raise(*_args, **_kwargs):
        raise RuntimeError(f"{symbol} kullanılabilir değil: {where} modülü/öğesi bulunamadı.")
    return _raise

def _import_first_available(module_names: list[str]):
    """İlk mevcut modül adını döndürür; hiçbiri yoksa None."""
    for name in module_names:
        try:
            if name and find_spec(name) is not None:
                return importlib.import_module(name)
        except (ModuleNotFoundError, ValueError):
            continue
    return None

_pkg = (__package__ or "").strip()

# --------------------------- flow_runner fonksiyonları ---------------------------
# Varsayılan: çağrılırsa NET hata versin (susturma yok)
_run_all = _missing_guard("run_all_extended", "flow_runner")
_run_plan_if_needed = _missing_guard("run_plan_if_needed", "flow_runner")
_flush_reporting = _missing_guard("flush_reporting", "flow_runner")

_flow_mod_candidates = []
if _pkg:
    _flow_mod_candidates.append(f"{_pkg}.flow_runner")
_flow_mod_candidates.append("core.flow_runner")

_flow_mod = _import_first_available(_flow_mod_candidates)
if _flow_mod is not None:
    if hasattr(_flow_mod, "run_all_extended"):
        _run_all = getattr(_flow_mod, "run_all_extended")
    if hasattr(_flow_mod, "run_plan_if_needed"):
        _run_plan_if_needed = getattr(_flow_mod, "run_plan_if_needed")
    if hasattr(_flow_mod, "flush_reporting"):
        _flush_reporting = getattr(_flow_mod, "flush_reporting")

# --------------------------- http.hardened_session ---------------------------
# Not: hardened oturum opsiyonel ise None bırakılabilir; zorunlu ise guard kullan.
_hardened_session = None

_http_mod_candidates = []
if _pkg:
    _http_mod_candidates.append(f"{_pkg}.http")
_http_mod_candidates.append("core.http")

_http_mod = _import_first_available(_http_mod_candidates)
if _http_mod is not None and hasattr(_http_mod, "hardened_session"):
    _hardened_session = getattr(_http_mod, "hardened_session")

# --------------------------- İptal/Kritik kontrol ---------------------------
def _is_cancelled(ctx: 'ScanContext') -> bool:
    # Global Ctrl+C bayrağını köprüle: threaded runner _SCAN_CANCEL'i doğrudan
    # poll'lar, ama async run_plan yolu YALNIZ _is_cancelled'a bakar. Buraya
    # eklenmezse o yolda Ctrl+C fazlar-arası iptali görmez (sadece 8s force-exit
    # durdurur, in-process fazlar o ana dek sürer). Set yalnız Ctrl+C handler'ında
    # yapılır → sahte iptal riski yok, yalnız iptali daha duyarlı kılar.
    if _SCAN_CANCEL.is_set():
        return True
    if ctx is None:
        return False
    if bool(getattr(ctx, "cancelled", False)):
        return True
    shared = getattr(ctx, "shared", None)
    if isinstance(shared, dict) and bool(shared.get("critical_error", False)):
        return True
    return False

# --------------------------- Tipler ---------------------------
PhaseFn = Callable[[ScanContext], Awaitable[None]]
Plan = List[Tuple[str, int, PhaseFn]]  # (ad, tahmini_saniye, faz_fn)

@dataclass
class RunnerConfig:
    interactive: bool = False               # True ise 'ask' seçeneği input() ile sorulur
    on_timeout: str = "extend"              # "extend" | "retry" | "skip" | "ask"
    extend_factor: float = 1.5              # zaman aşımında yeni timeout = eski * faktor
    max_timeout_sec: int = 30 * 60          # tek faz için üst sınır
    max_retries: int = 1                    # zaman aşımı sonrası tekrar sayısı
    progress_cb: Optional[Callable[[str, str, Dict[str, Any]], None]] = None
    confirm_cb: Optional[Callable[[str, int, int, ScanContext], bool]] = None  # (faz_adı, deneme, timeout, ctx) -> extend?

# --------------------------- Yardımcılar ---------------------------
def _cfg_from_ctx(ctx: ScanContext) -> RunnerConfig:
    rcfg = ((getattr(ctx, "config", {}) or {}).get("runner") or {})
    return RunnerConfig(
        interactive=bool(rcfg.get("interactive", False)),
        on_timeout=str(rcfg.get("on_timeout", "extend")).lower(),
        extend_factor=float(rcfg.get("extend_factor", 1.5)),
        max_timeout_sec=int(rcfg.get("max_timeout_sec", 30*60)),
        max_retries=int(rcfg.get("max_retries", 1)),
        progress_cb=rcfg.get("progress_cb"),
        confirm_cb=rcfg.get("confirm_cb"),
    )
def _dynamic_estimate(name: str, base_est: int, ctx: ScanContext) -> int:
    est = int(base_est)
    lname = name.lower()
    if "injection" in lname:
        p = len((ctx.results or {}).get("detected_get_params") or [])
        f = len((ctx.results or {}).get("detected_forms") or [])
        est = base_est + 30 * (p if p > 0 else 1) + 20 * (1 if f > 0 else 0)
    elif "owasp" in lname:
        open_ports = (ctx.results or {}).get("open_ports") or []
        est = base_est + 10 * len(open_ports)
    # 60s–20m aralığına kelepçe
    return max(60, min(est, 20 * 60))

def _should_extend(name: str, attempt: int, timeout_sec: int, cfg: 'RunnerConfig', ctx: 'ScanContext') -> bool:
    # DIP: confirm_cb varsa karar oradan gelir (sorumluluk çağıranda; hata saklanmaz)
    if callable(getattr(cfg, "confirm_cb", None)):
        return bool(cfg.confirm_cb(name, attempt, timeout_sec, ctx))

    decision = getattr(cfg, "on_timeout", None)
    if decision == "ask" and getattr(cfg, "interactive", False):
        # Yalnızca gerçekten etkileşimli uçta sor
        if hasattr(sys, "stdin") and sys.stdin is not None and sys.stdin.isatty():
            ans = (input(f"[?] '{name}' zaman aşımına uğradı. Süreyi uzatalım mı? (E/h): ").strip().lower() or "")
            return not ans.startswith("h")
        # TTY yoksa “ask” mümkün değil -> uzatma yok
        return False

    return decision in ("extend", "retry")


async def _run_phase_with_policy(name: str, base_est: int, phase: 'PhaseFn', ctx: 'ScanContext', cfg: 'RunnerConfig') -> None:
    est = _dynamic_estimate(name, base_est, ctx)
    attempts = 0

    # progress: start
    if callable(getattr(cfg, "progress_cb", None)):
        cfg.progress_cb("start", name, {"estimate_sec": est})

    t_phase_start = time.time()

    while True:
        # kritik/iptal kontrolü
        if _is_cancelled(ctx):
            add_result("meta", {"stage": "phase", "name": name, "status": "cancelled"})
            return

        log_info(f"\n[i] Aşama: {name}  (~{max(1, est // 60)} dk)")

        task = asyncio.create_task(phase(ctx))
        done, pending = await asyncio.wait({task}, timeout=est)

        # Zaman aşımı
        if pending:
            for t in pending:
                t.cancel()
            log_warn(f"Aşama '{name}' tahmini sürede bitmedi (timeout={est}s).")

            if attempts >= getattr(cfg, "max_retries", 0) or not _should_extend(name, attempts + 1, est, cfg, ctx):
                # progress: skipped
                if callable(getattr(cfg, "progress_cb", None)):
                    cfg.progress_cb("skipped", name, {"attempts": attempts, "reason": "timeout"})
                add_result("meta", {
                    "stage": "phase",
                    "name": name,
                    "status": "skipped_timeout",
                    "duration_sec": round(time.time() - t_phase_start, 2)
                })
                return

            # yeniden dene: deneme sayısını artır, süreyi yeniden değerlendir
            attempts += 1
            est = _dynamic_estimate(name, base_est, ctx)
            continue

        # Tamamlandı: sonucu değerlendir (hata saklama yok)
        finished = next(iter(done))
        exc = finished.exception()
        if exc is not None:
            # Hata durumunu rapora yaz ve yükselt (susturma yok)
            add_result("meta", {
                "stage": "phase",
                "name": name,
                "status": "error",
                "error": str(exc),
                "duration_sec": round(time.time() - t_phase_start, 2)
            })
            raise exc

        # Başarılı
        if callable(getattr(cfg, "progress_cb", None)):
            cfg.progress_cb("done", name, {"attempts": attempts})

        add_result("meta", {
            "stage": "phase",
            "name": name,
            "status": "done",
            "duration_sec": round(time.time() - t_phase_start, 2)
        })
        return

async def run_plan(plan: 'Plan', ctx: 'ScanContext', cfg: 'Dict'):
    """
    Planı sıralı ve politikaya bağlı timeout yönetimiyle çalıştırır.
    Hata saklama yok: faz içi hatalar 'meta: error' olarak rapora yazılır ve faz biter;
    run_plan try/except kullanmaz, böylece kontrol akışı sade ve deterministiktir.
    """
    # Plan G hook: profil ayarı (rapor metriklerine göre)
    _ = adjust_scan_mode(get_bucket_results(), cfg)

    cfg_local = _cfg_from_ctx(ctx)
    for (name, base_est, phase) in plan:
        if _is_cancelled(ctx):
            add_result("meta", {"stage": "phase", "name": name, "status": "cancelled"})
            _report_flush() # sonuç kovalarını/phase izini kayda geç
            return
        # Fazın kendi içinde timeout/hata durumları rapora işlenir;
        await _run_phase_with_policy(name, base_est, phase, ctx, cfg_local)



# === PATCH: WebSecure Upgrade (auto-applied) @ 2025-09-07T16:53:43.705200 ===

# Politikalar: hata yönetimi + iptal
from typing import Literal, cast
import signal

ErrorPolicy = Literal["continue","skip","stop","ask"]

@dataclass
class _ExtendedRunnerConfig(RunnerConfig):
    on_error: ErrorPolicy = "continue"   # continue | skip | stop | ask
    cancel_on_sigint: bool = True

def _cfg_extend(cfg: RunnerConfig, ctx: ScanContext) -> _ExtendedRunnerConfig:
    rcfg = ((getattr(ctx, "config", {}) or {}).get("runner") or {})
    return _ExtendedRunnerConfig(
        **cfg.__dict__,
        on_error=str(rcfg.get("on_error","continue")).lower(),
        cancel_on_sigint=bool(rcfg.get("cancel_on_sigint", True)),
    )
import sys
import time
import asyncio
import signal
import threading

def _install_cancel_hook(enabled: bool):
    if not enabled:
        return lambda: None

    # Sadece ana thread ve SIGINT mevcutsa kanca kur.
    is_main_thread = threading.current_thread() is threading.main_thread()
    has_sigint = hasattr(signal, "SIGINT") and callable(getattr(signal, "signal", None))
    if not (is_main_thread and has_sigint):
        return lambda: None

    cancelled = {"val": False}

    def _mark(_signum, _frame):
        cancelled["val"] = True  # Yerel bayrak; iptal kontrolünüz ctx tarafında ilerliyor.

    old = signal.getsignal(signal.SIGINT) if hasattr(signal, "getsignal") else None
    signal.signal(signal.SIGINT, _mark)

    def _restore():
        if old is not None and is_main_thread and has_sigint:
            signal.signal(signal.SIGINT, old)

    return _restore


_EXPORTS = ("run", "run_many", "run_plan")
__all__ = [name for name in _EXPORTS if name in globals()]



# Yardımcı: bir fonksiyonun beklenen modülden gelip gelmediğini doğrula
def _is_from_modules(fn, *expected_modules: str) -> bool:
    if fn is None:
        return False
    modname = getattr(fn, "__module__", "") or ""
    # hem "core.flow_runner" gibi tam ad hem de ".flow_runner" soneki desteklenir
    return any(modname == m or modname.endswith(f".{m.split('.')[-1]}") for m in expected_modules)

# --------------------------- Context Kurulumu ---------------------------
def _resolve_url_from_target(target, cfg) -> str | None:
    # target içinden url çıkar
    if isinstance(target, str):
        return target
    if isinstance(target, dict):
        return target.get("url") or target.get("base_url") or target.get("target")
    # nesne benzeri
    url = getattr(target, "url", None) or getattr(target, "base_url", None) or getattr(target, "target", None)
    if url:
        return url
    # cfg içinden yedek
    if isinstance(cfg, dict):
        return cfg.get("base_url") or cfg.get("target")
    return getattr(cfg, "base_url", None) or getattr(cfg, "target", None)

def _build_ctx(target, cfg, session=None, debug=False):
    url = _resolve_url_from_target(target, cfg)
    if not url:
        log_warn("hedef URL çıkarılamadı: target/cfg içinde 'url' ya da 'base_url' yok")
    # mevcut session yoksa ve gerçek hardened_session varsa kur
    sess = session
    if sess is None and callable(_hardened_session) and _is_from_modules(_hardened_session, "core.http", "http"):
        sess = _hardened_session(cfg)
    ctx = SimpleNamespace(url=url, base_url=url, session=sess, config=(cfg or {}), results={}, debug=bool(debug))
    return ctx

# --------------------------- Koşucu Köprüleri ---------------------------
def _flow_runner_available() -> bool:
    # Tekrar import etmeden, fonksiyonun gerçekten flow_runner modülünden gelip gelmediğini kontrol et
    return (
        _is_from_modules(_run_plan_if_needed, "core.flow_runner", "flow_runner")
        or _is_from_modules(_run_all, "core.flow_runner", "flow_runner")
        or _is_from_modules(_flush_reporting, "core.flow_runner", "flow_runner")
    )

def run(target, cfg, *, session=None, debug=False, event_cb=None):
    """Sadece faz planını çalıştırır; mükerrer tarama yok."""
    # Önce bağlamı kur, sonra oturumu garanti altına al
    ctx = _build_ctx(target, cfg, session=session, debug=debug)
    _ensure_session(ctx)

    # Authenticated scan: config["auth"] varsa oturum aç
    try:
        from websecure.core.auth_manager import AuthManager as _AM
        _AM.authenticate(ctx)
    except Exception as _auth_err:
        _logger.debug(f"[run] AuthManager skip: {_auth_err}")

    # Plan çalıştırma (tüm fazlar + rapor)
    # run_plan_if_needed bu modülde tanımlı (satır ~3551); _missing_guard kullanma
    run_plan_if_needed(ctx)

    # Raporu diske yazdır
    try:
        run_reporting_and_integration(ctx)
    except Exception as _rep_e:
        _logger.debug(f"[run] reporting error: {_rep_e!r}")
    return getattr(ctx, "results", None)



def run_many(targets, cfg, *, session=None, debug=False, event_cb=None, progress_cb=None):
    """Birden çok hedefi sırayla koşturur (seri); hata yutma yok."""
    results = []
    for idx, t in enumerate(list(targets or [])):
        if callable(progress_cb):
            progress_cb("start", {"index": idx, "target": t})
        res = run(t, cfg, session=session, debug=debug, event_cb=event_cb)
        results.append({"target": t, "results": res})
        if callable(progress_cb):
            progress_cb("end", {"index": idx, "target": t})
    return results

def _dyn_profile_update(stats: dict, current: str) -> str:
    p = (current or "NORMAL").upper()
    four = int(stats.get("403",0)) + int(stats.get("429",0))
    ok = int(stats.get("2xx",0))
    if four >= 5:
        if p == "AGGRESSIVE": return "NORMAL"
        if p == "NORMAL": return "STEALTH"
    if ok >= 20 and four == 0:
        if p == "STEALTH": return "NORMAL"
        if p == "NORMAL": return "AGGRESSIVE"
    return p


def _maybe_adjust_profile(current: str) -> str:
    pkg = (__package__ or "").strip()
    candidates = []
    if pkg:
        candidates.append(f"{pkg}.http")   # yerel paket
    candidates.append("core.http")         # proje içi çekirdek
    candidates.append("http")              # düz ad (legacy)

    http_mod = None
    for name in candidates:
        if find_spec(name) is not None:
            http_mod = importlib.import_module(name)
            break

    if http_mod is None or not hasattr(http_mod, "get_http_metrics"):
        log_warn("get_http_metrics yok; profil ayarı değiştirilmedi.")
        return current

    stats = http_mod.get_http_metrics()    # hata varsa yükselir; saklama yok
    return _dyn_profile_update(stats, current)



# -- Compatibility wrapper: accept (plan, ctx) or (plan, ctx, cfg) --
def run_plan_adapt(*args, _run_plan=None, **kwargs):

    import inspect

    # 1) run_plan hedefini çağrı anında çöz
    rp = _run_plan if _run_plan is not None else globals().get("run_plan")
    if rp is None or not callable(rp):
        raise RuntimeError("run_plan not available in current module scope")

    # 2) Argümanları tek noktadan çıkar
    plan = kwargs.get("plan", args[0] if len(args) > 0 else None)
    ctx  = kwargs.get("ctx",  args[1] if len(args) > 1 else None)
    cfg  = kwargs.get("cfg",  args[2] if len(args) > 2 else getattr(ctx, "config", None))

    # 3) İmzaya göre çağır
    params = list(inspect.signature(rp).parameters.values())
    if len(params) >= 3:
        return rp(plan, ctx, cfg)
    elif len(params) == 2:
        return rp(plan, ctx)
    else:
        # Olağandışı durum: beklenmeyen imza
        return rp()

def _ensure_session(ctx):
    from websecure.core.http import build_session
    if getattr(ctx, "session", None) is None:
        cfg = getattr(ctx, "config", {}) or {}
        ctx.session = build_session(cfg)
    return ctx.session
