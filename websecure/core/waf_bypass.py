import random
import time
import logging
import string
from typing import Dict, Optional
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest

logger = logging.getLogger(__name__)

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
            sess._req_counter += 1
            rotate_every = getattr(sess, "_rotate_every", 10)
            if sess._req_counter % max(1, rotate_every) == 0:
                try:
                    from websecure.core.waf_bypass import get_tor_proxy
                    new_proxy = get_tor_proxy()
                    if new_proxy:
                        sess.proxies.update(new_proxy)
                        proxy_str = list(new_proxy.values())[0]
                        logger.debug(
                            "[WAFBypass] Continuous rotation: proxy → %s (req#%d)",
                            proxy_str, sess._req_counter,
                        )
                        try:
                            from websecure.core.reporting import get_live_monitor
                            get_live_monitor().log_rotation(sess._req_counter, proxy_str)
                        except Exception:
                            pass
                except Exception:
                    pass

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

            # 3a. Double URL encoding (e.g. %27 → %2527)
            if self._get_flag("_bypass_double_encode"):
                path = _double_encode_path(path)

            # 3b. Unicode char substitution
            elif self._get_flag("_bypass_unicode"):
                path = _unicode_encode_path(path)

            # 3c. Case randomization for case-insensitive WAF rules
            elif self._get_flag("_bypass_case"):
                path = _case_randomize_path(path)

            # 3d. Random structural obfuscation (always active, low probability)
            elif random.random() < 0.2 and path.startswith("/"):
                tactic = random.choice(["double_slash", "current_dir", "semicolon", "null_byte_ext"])
                if tactic == "double_slash":
                    path = "//" + path.lstrip("/")
                elif tactic == "current_dir":
                    path = "/./" + path.lstrip("/")
                elif tactic == "semicolon":
                    path = path + ";.css"
                elif tactic == "null_byte_ext":
                    path = path + "%00.html"

            # Apply suffix if set (e.g. from random_path_suffix strategy)
            suffix = getattr(self._session_ref, "_bypass_path_suffix", None) if self._session_ref else None
            if suffix and not path.endswith(suffix):
                path = path.rstrip("/") + suffix

            request.url = urlunparse((
                parsed.scheme, parsed.netloc, path,
                parsed.params, parsed.query, parsed.fragment
            ))
        except Exception:
            pass

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
            except Exception:
                pass

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
            except Exception:
                pass

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
            except Exception:
                pass

        # 9. Overlong UTF-8 path encoding (_evasion_overlong flag)
        if self._get_flag("_evasion_overlong"):
            try:
                from websecure.core.evasion import OverlongUTF8Encoder
                from urllib.parse import urlsplit, urlunsplit
                parts    = urlsplit(request.url)
                new_path = OverlongUTF8Encoder().partial_encode(parts.path, "/<>\"'()")
                request.url = urlunsplit(parts._replace(path=new_path))
            except Exception:
                pass

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
            except Exception:
                pass

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
            except Exception:
                pass

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
        # Add Jitter/Delay
        if self.jitter_range:
            sleep_time = random.uniform(*self.jitter_range)
            time.sleep(sleep_time)
        return super().request(method, url, *args, **kwargs)


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
        """Apply all listed strategies to the session. Returns modified session."""
        for name in strategies:
            fn = self._STRATEGIES.get(name)
            if fn:
                try:
                    fn(session)
                except Exception as e:
                    logger.debug(f"[BypassEngine] Strategy '{name}' error: {e}")
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
    except Exception:
        pass

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
    Sets a flag so curl_cffi / httpx drivers send pseudo-headers in a
    non-standard order that some WAFs do not expect.
    """
    session._evasion_http2_pseudo = True
    # If curl_cffi is available, prefer it as it exposes header-order control
    try:
        if _CURL_CFFI_AVAILABLE:
            session._use_curl_cffi     = True
            session._curl_cffi_profile = _resolve_profile("chrome_124")
    except Exception:
        pass


def build_bypass_session(waf_profile=None) -> WAFBypassSession:
    """
    Build a WAFBypassSession with strategies applied for the detected WAF.
    If waf_profile is None or no WAF detected, returns a plain WAFBypassSession.
    """
    session = WAFBypassSession()
    if waf_profile and getattr(waf_profile, 'detected', False):
        strategies = waf_profile.bypass_strategies or []
        _engine.apply(session, strategies)
        logger.info(f"[BypassEngine] Applied {len(strategies)} strategies for {waf_profile.vendor}")
    return session


# ===========================================================================
# MERGED FROM: websecure/core/tls_driver.py
# curl_cffi tabanlı JA3/JA4 TLS parmak izi taklidi
# ===========================================================================
"""
tls_driver.py — curl_cffi tabanlı TLS parmak izi sahteciliği.

Cloudflare, Akamai, Imperva gibi JA3/JA4 tabanlı WAF'lar Python
requests/httpx kütüphanelerinin standart TLS imzasını tanır ve engeller.
Bu modül curl_cffi kullanarak gerçek tarayıcı TLS握手taklidini sağlar.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

_logger = logging.getLogger(__name__)

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
# Profil Haritası  (websecure profil adı → curl_cffi impersonate değeri)
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
        except Exception:
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
                f"[TLSDriver] {method.upper()} {url} → {raw.status_code} ({elapsed*1000:.0f}ms)"
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
            except Exception:
                pass
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
  - Başarısızlık sayacı → otomatik devre dışı bırakma
  - Çoklu strateji: round_robin, weighted_random, sticky, lru
  - Ülke bazlı hedefleme
  - Vendor'a özel URL oluşturucu
"""
from __future__ import annotations

import hashlib
import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence
from urllib.parse import urlparse

_logger = logging.getLogger(__name__)

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
        e = pool[self._rr_idx % len(pool)]
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
                except Exception:
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
from typing import Any  # noqa: E402 — döngüsel import önlemi için altta


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
        except Exception:
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
            # Tor başarısızlığı → yeni kimlik iste
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
        except Exception:
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
    # Fallback: bare Tor SOCKS5 if port 9050 is open
    try:
        import socket as _sock
        with _sock.create_connection(("127.0.0.1", 9050), timeout=0.5):
            tor_url = "socks5h://127.0.0.1:9050"
            return {"http": tor_url, "https": tor_url}
    except Exception:
        pass
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
from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)

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
