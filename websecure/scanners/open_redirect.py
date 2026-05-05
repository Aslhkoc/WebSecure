"""
websecure.scanners.open_redirect
---------------------------------
Open Redirect zafiyet taraması.

Strateji:
  1. Crawler çıktısından redirect parametrelerini topla
  2. Her parametreye 30+ bypass payload'ı dene
  3. Yanıt Location header'ı veya JS redirect'i kontrol et
  4. WAF bypass: çeşitli encoding ve protocol tricks

Performans:
  - BaseScanner.run_parallel_probes() ile paralel HTTP istekleri (MAX_WORKERS=8)
  - Timeout: 4 saniye per-request
  - MAX_PROBE_REQUESTS: sonsuz döngü koruması
  - Per-path early exit: ilk bulgu sonrası o path atlanır
"""
from __future__ import annotations

import logging
import re
from concurrent.futures import TimeoutError as _FuturesTimeout
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

import requests as _requests

from websecure.scanners.base import BaseScanner
from websecure.core.payloads import load_external_payloads

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------
MAX_WORKERS        = 8    # paralel thread sayısı
REQUEST_TIMEOUT    = 4    # saniye per-request
MAX_PROBE_REQUESTS = 120  # probe fazında maksimum istek
PROBE_PHASE_TIMEOUT = 45  # saniye — toplam probe fazı için deadline

_CANARY = "evil.websecure.internal"

# Redirect parametresi isimleri (yaygın)
_REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "redirectUrl", "redirectUri",
    "return", "return_url", "returnUrl", "returnTo", "return_to",
    "next", "next_url", "nextUrl",
    "url", "goto", "go", "link", "target",
    "dest", "destination",
    "forward", "forward_url",
    "location", "loc",
    "callback", "callback_url", "callbackUrl",
    "out", "out_url",
    "jump", "jump_url",
    "continue", "continue_url",
    "redir", "rdr",
    "ref", "referer", "referrer",
    "from", "from_url",
    "path", "page",
    "site", "view",
]

_PAYLOADS = [
    # Temel
    f"https://{_CANARY}",
    f"http://{_CANARY}",
    f"//{_CANARY}",
    f"//{_CANARY}/path",
    f"//{_CANARY}@target.com",
    # Çift slash
    f"///{_CANARY}",
    f"////{_CANARY}",
    # Backslash bypass
    f"/\\{_CANARY}",
    f"\\\\{_CANARY}",
    # URL encode
    f"https%3A%2F%2F{_CANARY}",
    f"%2F%2F{_CANARY}",
    f"%5C%5C{_CANARY}",
    # Double encode
    f"https%253A%252F%252F{_CANARY}",
    f"%252F%252F{_CANARY}",
    # @ bypass
    f"https://target.com@{_CANARY}",
    f"https://{_CANARY}%40target.com",
    # Subdomain bypass
    f"https://target.com.{_CANARY}",
    f"https://{_CANARY}?target.com",
    f"https://{_CANARY}#target.com",
    # Newline
    f"https://{_CANARY}%0d%0alocation:https://{_CANARY}",
    # Tab/space
    f"https://{_CANARY}%09",
    f" https://{_CANARY}",
    # Fragment bypass
    f"https://{_CANARY}#",
    # Null byte
    f"https://{_CANARY}%00",
]

def _load_redirect_payloads() -> List[str]:
    """open_redirect.txt'i yükle — attacker.com ve benzerlerini _CANARY ile değiştir."""
    seen = set(_PAYLOADS)
    _PLACEHOLDER_DOMAINS = ("attacker.com", "evil.com", "x.com", "burpcollaborator.net", "oastify.com")
    extra: List[str] = []
    for line in load_external_payloads("open_redirect"):
        if not line:
            continue
        for ph in _PLACEHOLDER_DOMAINS:
            if ph in line:
                line = line.replace(ph, _CANARY)
                break
        if line not in seen:
            seen.add(line)
            extra.append(line)
    return extra

_PAYLOADS = _PAYLOADS + _load_redirect_payloads()

# Probe edilecek endpoint path'leri
_PROBE_PATHS = [
    "/login", "/logout", "/signin", "/signout",
    "/redirect", "/go", "/out", "/link",
    "/oauth/callback", "/sso/callback",
    "/", "",
]

_PROBE_PARAMS   = _REDIRECT_PARAMS[:15]  # ilk 15 (en yaygın)
_PROBE_PAYLOADS = _PAYLOADS[:20]         # ilk 20 (tüm temel bypass varyantları)


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _is_open_redirect(response, payload: str) -> bool:
    location = response.headers.get("Location", "") or response.headers.get("location", "")
    if location and _CANARY in location:
        return True

    refresh = response.headers.get("Refresh", "") or response.headers.get("refresh", "")
    if refresh and _CANARY in refresh:
        return True

    try:
        body = response.text[:6000]
    except (AttributeError, UnicodeDecodeError) as exc:
        logger.debug(f"[OpenRedirect] Body decode failed: {exc!r}")
        return False

    if _CANARY in body:
        patterns = [
            rf'location\s*=\s*["\']?[^"\']*{re.escape(_CANARY)}',
            rf'location\.href\s*=\s*["\'][^"\']*{re.escape(_CANARY)}',
            rf'window\.location\s*=\s*["\'][^"\']*{re.escape(_CANARY)}',
            rf'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+{re.escape(_CANARY)}',
            rf'url\s*=\s*["\'][^"\']*{re.escape(_CANARY)}',
        ]
        for pat in patterns:
            if re.search(pat, body, re.IGNORECASE):
                return True

    return False


def _find_redirect_params(url: str) -> List[str]:
    parsed = urlparse(url)
    if not parsed.query:
        return []
    params = parse_qs(parsed.query, keep_blank_values=True)
    return [p for p in params if p.lower() in _REDIRECT_PARAMS]


# ---------------------------------------------------------------------------
# Ana scanner — BaseScanner'dan türetildi (FAZ 3.2)
# ---------------------------------------------------------------------------

class OpenRedirectScanner(BaseScanner):
    """
    Open Redirect taraması.
    - Crawler URL'lerinde redirect parametresi arar
    - Yaygın probe endpoint'lerini paralel test eder
    - BaseScanner.run_parallel_probes() ile hızlı, sonsuz döngü korumalı
    - BaseScanner.report_finding() ile merkezi raporlama
    """

    name = "open_redirect"
    phase = "offensive"

    def __init__(self, session=None, results: Dict = None, debug: bool = False,
                 timeout: int = REQUEST_TIMEOUT):
        super().__init__(session, results, debug)
        self.timeout = timeout

    def run(self, target: str, **kwargs) -> None:
        """BaseScanner interface — delegates to scan()."""
        urls = kwargs.get("urls") or kwargs.get("endpoints") or []
        self.scan(target, urls=urls)

    def _probe_task(self, task: Tuple) -> Optional[Dict[str, Any]]:
        """Tek bir (test_url, param, payload, origin_url) kombinasyonunu test eder."""
        test_url, param, payload, origin_url = task
        try:
            resp = self.session.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
            if _is_open_redirect(resp, payload):
                return {
                    "vuln_type": "Open Redirect",
                    "url": origin_url,
                    "param": param,
                    "payload": payload,
                    "severity": "High",
                    "evidence": f"Param '{param}' ile '{payload}' redirect tetikledi",
                    "extra": {
                        "test_url": test_url,
                        "status_code": resp.status_code,
                        "location": resp.headers.get("Location", ""),
                        "cwe": "CWE-601",
                        "owasp": "A01:2021",
                    },
                }
        except _requests.exceptions.Timeout as exc:
            logger.debug(f"[OpenRedirect] Probe timed out for {test_url}: {exc!r}")
        except _requests.exceptions.ConnectionError as exc:
            logger.debug(f"[OpenRedirect] Probe connection error for {test_url}: {exc!r}")
        except _requests.exceptions.RequestException as exc:
            logger.warning(f"[OpenRedirect] Probe request failed for {test_url}: {exc!r}")
        return None

    def scan(self, base_url: str, urls: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Tam Open Redirect taraması. BaseScanner.run() tarafından çağrılır.
        Bulgular hem merkezi raporlamaya (self.report_finding) hem de dönüş değerine eklenir.
        """
        try:
            import urllib3
            urllib3.disable_warnings()
        except ImportError:
            pass

        findings: List[Dict[str, Any]] = []
        tested: Set[str] = set()
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        # ── 1. Crawler URL'lerindeki redirect parametrelerini paralel test et ──
        crawler_tasks: List[Tuple] = []
        for url in (urls or []):
            for param in _find_redirect_params(url):
                for payload in _PAYLOADS:
                    key = f"{url}|{param}|{payload}"
                    if key not in tested:
                        tested.add(key)
                        test_url = self.inject_param(url, param, payload)
                        crawler_tasks.append((test_url, param, payload, url))

        if crawler_tasks:
            hits = self.run_parallel_probes(
                self._probe_task, crawler_tasks,
                max_workers=MAX_WORKERS, stop_on_first=False,
            )
            for hit in hits:
                extra = hit.pop("extra", None)
                self.report_finding(**hit, extra=extra)
                findings.append(hit)
                logger.info(f"[OpenRedirect] BULUNDU: {hit['url']} param={hit['param']}")

        # ── 2. Probe endpoint'leri paralel test et (MAX_PROBE_REQUESTS ile kısıtlı) ──
        probe_tasks: List[Tuple] = []
        for path in _PROBE_PATHS:
            probe_url = origin + path
            for param in _PROBE_PARAMS:
                for payload in _PROBE_PAYLOADS:
                    key = f"{probe_url}|{param}|{payload}"
                    if key not in tested:
                        tested.add(key)
                        test_url = f"{probe_url}?{param}={quote(payload)}"
                        probe_tasks.append((test_url, param, payload, probe_url))
                    if len(probe_tasks) >= MAX_PROBE_REQUESTS:
                        break
                if len(probe_tasks) >= MAX_PROBE_REQUESTS:
                    break
            if len(probe_tasks) >= MAX_PROBE_REQUESTS:
                break

        logger.info(
            f"[OpenRedirect] {len(probe_tasks)} probe isteği paralel gönderiliyor "
            f"(timeout={PROBE_PHASE_TIMEOUT}s)..."
        )

        # Probe fazı: ThreadPoolExecutor directly (PROBE_PHASE_TIMEOUT gerektiriyor)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(self._probe_task, task): task
                for task in probe_tasks
            }
            try:
                for f in as_completed(futures, timeout=PROBE_PHASE_TIMEOUT):
                    result = f.result()
                    if result:
                        extra = result.pop("extra", None)
                        self.report_finding(**result, extra=extra)
                        findings.append(result)
                        logger.info(
                            f"[OpenRedirect] BULUNDU (probe): "
                            f"{result['url']} param={result['param']}"
                        )
            except _FuturesTimeout:
                logger.info(
                    "[OpenRedirect] Probe fazı zaman aşımı — mevcut bulgularla devam ediliyor"
                )

        logger.info(f"[OpenRedirect] Tamamlandı: {len(findings)} bulgu")
        return findings


# ---------------------------------------------------------------------------
# Plugin API
# ---------------------------------------------------------------------------

def run(target: str, cfg: Optional[Dict[str, Any]] = None, session=None,
        urls: Optional[List[str]] = None, results=None, **kwargs) -> List[Dict[str, Any]]:
    cfg = cfg or {}
    or_cfg = cfg.get("open_redirect", {}) if isinstance(cfg, dict) else {}
    timeout = int(or_cfg.get("timeout", REQUEST_TIMEOUT))
    scanner = OpenRedirectScanner(session=session, results=results, timeout=timeout)
    return scanner.scan(target, urls=urls)

# ============================================================================
# ADIM 8 — Open Redirect Zincirleri (SOLID Siniflar)
# OpenRedirectOAuthTheftChain, OpenRedirectSSRFChain, OpenRedirectAdim8Scanner
# ============================================================================
from __future__ import annotations
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional
from websecure.scanners.base import BaseScanner

_or_logger = logging.getLogger(__name__ + ".adim8")

_EVIL_HOST  = "evil-wsp.invalid"
_OOB_HOST   = "oob-wsp.invalid"

_OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
    "/connect/authorize", "/openid/authorize",
]

_SSRF_INTERNAL = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/",
    "http://localhost/",
]

_REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "url", "goto", "dest", "destination", "forward", "target",
    "callback", "ref", "from", "location",
]

_OAUTH_THEFT_PAYLOADS = [
    "https://{evil}",
    "https://{evil}/callback",
    "//{evil}",
    "https://{legit}@{evil}",
    "https://{legit}.{evil}",
    "https://{evil}?client_id=legit",
    "\thttps://{evil}",
]


# ===========================================================================
# OpenRedirectOAuthTheftChain
# ===========================================================================
class OpenRedirectOAuthTheftChain(BaseScanner):
    """
    Open Redirect → OAuth token theft zinciri:
    1. OAuth authorization endpoint'te redirect_uri bypass
    2. Auth code / access_token Location header'a inject edilirse hedef → attacker
    3. State CSRF ile birlikte exploit zinciri
    """
    name = "open_redirect_oauth"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed  = urllib.parse.urlparse(target)
        legit   = parsed.netloc or "app.example.com"

        # 1. Discover OAuth endpoints
        oauth_eps = self._find_oauth_endpoints(target)

        # 2. Test redirect_uri bypass on each
        for ep_url in oauth_eps:
            for tpl in _OAUTH_THEFT_PAYLOADS:
                evil_uri = tpl.format(evil=_EVIL_HOST, legit=legit)
                test_url = self._inject_redirect_uri(ep_url, evil_uri)
                try:
                    resp = self.session.get(test_url, timeout=8, allow_redirects=False)
                    loc  = resp.headers.get("location", "")
                    # If redirect sends us to evil host with code/token
                    if _EVIL_HOST in loc:
                        code  = re.search(r"[?&]code=([^&]+)", loc)
                        token = re.search(r"[?&](access_token|token)=([^&]+)", loc)
                        results.append({
                            "vuln_type": "Open Redirect → OAuth Token Theft",
                            "url": test_url, "severity": "Critical",
                            "description": (
                                f"OAuth redirect_uri bypass accepted: {evil_uri!r}. "
                                f"Authorization redirected to attacker host. "
                                + (f"Auth code: {code.group(1)[:8]}..." if code else "")
                                + (f"Token leaked." if token else "")
                            ),
                            "evidence": {
                                "evil_uri": evil_uri,
                                "redirect_location": loc,
                                "auth_code_present": bool(code),
                                "token_present": bool(token),
                                "status": resp.status_code,
                            },
                        })
                        self.report_finding(**results[-1])
                        return results
                    # Partial bypass: redirected without rejecting evil host
                    if resp.status_code in (301, 302, 303, 307) and "error" not in loc.lower():
                        results.append({
                            "vuln_type": "Open Redirect → OAuth redirect_uri Bypass (Probable)",
                            "url": test_url, "severity": "High",
                            "description": (
                                f"OAuth endpoint accepted redirect_uri={evil_uri!r} "
                                "without error. Code/token may be sent to attacker on full exploit."
                            ),
                            "evidence": {"evil_uri": evil_uri, "location": loc, "status": resp.status_code},
                        })
                        self.report_finding(**results[-1])
                        break
                except Exception as exc:
                    _or_logger.debug("[OAuthTheft] %s", exc)

        # 3. Test regular redirect params on main app
        for param in _REDIRECT_PARAMS[:6]:
            for tpl in _OAUTH_THEFT_PAYLOADS[:3]:
                evil = tpl.format(evil=_EVIL_HOST, legit=legit)
                url  = target + ("&" if "?" in target else "?") + f"{param}={urllib.parse.quote(evil, safe=':/')}"
                try:
                    resp = self.session.get(url, timeout=8, allow_redirects=False)
                    loc  = resp.headers.get("location", "")
                    if _EVIL_HOST in loc:
                        results.append({
                            "vuln_type": "Open Redirect — Token Leakage via Param",
                            "url": url, "severity": "High",
                            "description": (
                                f"Open redirect via '{param}' param leads to {_EVIL_HOST}. "
                                "If used in OAuth/SAML flow, tokens may leak."
                            ),
                            "evidence": {"param": param, "evil": evil, "location": loc},
                        })
                        self.report_finding(**results[-1])
                        return results
                except Exception as exc:
                    _or_logger.debug("[OAuthParam] %s", exc)

        return results

    def _find_oauth_endpoints(self, base: str) -> List[str]:
        found = []
        for path in _OAUTH_PATHS:
            url = urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code not in (404, 410):
                    found.append(url)
            except Exception:
                pass
        return found or [base]

    def _inject_redirect_uri(self, endpoint: str, value: str) -> str:
        parsed = urllib.parse.urlparse(endpoint)
        pairs  = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        found  = False
        new    = []
        for k, v in pairs:
            if k.lower() in ("redirect_uri", "redirect_url", "callback"):
                new.append((k, value))
                found = True
            else:
                new.append((k, v))
        if not found:
            new += [("redirect_uri", value), ("response_type", "code"), ("client_id", "test")]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new)))


# ===========================================================================
# OpenRedirectSSRFChain
# ===========================================================================
class OpenRedirectSSRFChain(BaseScanner):
    """
    Open Redirect → SSRF gecis testi:
    Server-side redirect takibi yapan endpoint'lerde
    open redirect → internal SSRF'e donusebilir.
    """
    name = "open_redirect_ssrf"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed  = urllib.parse.urlparse(target)

        # Find server-side fetching endpoints (url/src/fetch params)
        fetch_params = ["url", "src", "fetch", "proxy", "resource", "remote", "load"]

        for ssrf_target in _SSRF_INTERNAL[:4]:
            for param in fetch_params:
                # Direct SSRF via redirect param
                url = target + ("&" if "?" in target else "?") + f"{param}={urllib.parse.quote(ssrf_target, safe=':/')}"
                try:
                    resp = self.session.get(url, timeout=10, allow_redirects=True)
                    body = getattr(resp, "text", "")[:2000]
                    if resp.status_code == 200 and re.search(
                        r"ami-|instanceId|accountId|iam|169\.254|metadata", body, re.I
                    ):
                        results.append({
                            "vuln_type": "Open Redirect → SSRF (Cloud Metadata)",
                            "url": url, "severity": "Critical",
                            "description": (
                                f"Open redirect param '{param}' followed as SSRF to {ssrf_target}. "
                                "Cloud metadata accessible via server-side redirect follow."
                            ),
                            "evidence": {
                                "param": param, "ssrf_target": ssrf_target,
                                "status": resp.status_code, "body_snippet": body[:300],
                            },
                        })
                        self.report_finding(**results[-1])
                        return results
                    # Internal service response
                    if resp.status_code == 200 and len(body) > 30 and \
                       not re.search(r"<html|<!doctype", body[:100], re.I):
                        results.append({
                            "vuln_type": "Open Redirect → SSRF (Internal Service)",
                            "url": url, "severity": "High",
                            "description": (
                                f"Param '{param}' caused server to fetch {ssrf_target}. "
                                "Internal service response received."
                            ),
                            "evidence": {"param": param, "ssrf_target": ssrf_target,
                                         "status": resp.status_code, "body_len": len(body)},
                        })
                        self.report_finding(**results[-1])
                except Exception as exc:
                    _or_logger.debug("[ORSSRF] %s: %s", ssrf_target, exc)

        return results


# ===========================================================================
# OpenRedirectAdim8Scanner — Orchestrator
# ===========================================================================
class OpenRedirectAdim8Scanner(BaseScanner):
    """
    Adim 8 Open Redirect orchestrator:
    OAuthTheftChain + SSRFChain (orijinal OpenRedirectScanner ile birlikte calisir)
    """
    name = "open_redirect_adim8"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        chains = [
            OpenRedirectOAuthTheftChain(session=self.session, results=self.results),
            OpenRedirectSSRFChain(session=self.session, results=self.results),
        ]
        for chain in chains:
            try:
                chain.target = target
                res = chain.run(target, **kwargs)
                all_results.extend(res)
            except Exception as exc:
                _or_logger.warning("[ORAdim8] %s failed: %s", chain.name, exc)
        return all_results
