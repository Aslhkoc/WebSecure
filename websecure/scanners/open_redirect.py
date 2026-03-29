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
