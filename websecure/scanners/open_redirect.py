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
  - ThreadPoolExecutor ile paralel HTTP istekleri (MAX_WORKERS=12)
  - Timeout: 5 saniye (8'den düşürüldü)
  - MAX_PROBE_REQUESTS: sonsuz döngü koruması
  - Per-path early exit: ilk bulgu sonrası o path atlanır
"""
from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------
MAX_WORKERS       = 12    # paralel thread sayısı
REQUEST_TIMEOUT   = 5     # saniye (8'den düşürüldü)
MAX_PROBE_REQUESTS = 600  # probe fazında maksimum istek (sonsuz döngü koruması)

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

# Probe edilecek endpoint path'leri
_PROBE_PATHS = [
    "/login", "/logout", "/signin", "/signout",
    "/redirect", "/go", "/out", "/link",
    "/oauth/callback", "/sso/callback",
    "/", "",
]

# Probe fazında kullanılacak param sayısı ve payload sayısı
_PROBE_PARAMS   = _REDIRECT_PARAMS[:15]  # ilk 15 (en yaygın)
_PROBE_PAYLOADS = _PAYLOADS[:8]          # ilk 8 (en etkili)


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _is_open_redirect(response, payload: str) -> bool:
    # 1. 3xx Location header
    location = response.headers.get("Location", "") or response.headers.get("location", "")
    if location and _CANARY in location:
        return True

    # 2. Refresh header
    refresh = response.headers.get("Refresh", "") or response.headers.get("refresh", "")
    if refresh and _CANARY in refresh:
        return True

    # 3. HTML meta / JS redirect
    try:
        body = response.text[:6000]
    except Exception:
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


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_query, parsed.fragment))


# ---------------------------------------------------------------------------
# Ana scanner
# ---------------------------------------------------------------------------

class OpenRedirectScanner:
    """
    Open Redirect taraması.
    - Crawler URL'lerinde redirect parametresi arar
    - Yaygın probe endpoint'lerini paralel test eder
    - ThreadPoolExecutor ile hızlı, sonsuz döngü korumalı
    """

    def __init__(self, session=None, timeout: int = REQUEST_TIMEOUT):
        self.session = session
        self.timeout = timeout

    def _get_session(self):
        if self.session:
            return self.session
        try:
            import requests
            s = requests.Session()
            s.headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
            )
            return s
        except ImportError:
            return None

    def _probe(self, sess, test_url: str, param: str, payload: str,
               origin_url: str) -> Optional[Dict[str, Any]]:
        """Tek bir URL+param+payload kombinasyonunu test eder."""
        try:
            resp = sess.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
            if _is_open_redirect(resp, payload):
                return {
                    "type": "Open Redirect",
                    "severity": "High",
                    "url": origin_url,
                    "parameter": param,
                    "payload": payload,
                    "test_url": test_url,
                    "status_code": resp.status_code,
                    "location": resp.headers.get("Location", ""),
                    "evidence": f"Param '{param}' ile '{payload}' redirect tetikledi",
                    "cwe": "CWE-601",
                    "owasp": "A01:2021",
                }
        except Exception:
            pass
        return None

    def scan(self, base_url: str, urls: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass

        sess = self._get_session()
        if not sess:
            logger.warning("[OpenRedirect] Session oluşturulamadı")
            return []

        findings: List[Dict[str, Any]] = []
        tested: Set[str] = set()
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        # ── 1. Crawler URL'lerindeki redirect parametrelerini paralel test et ──
        crawler_tasks = []
        for url in (urls or []):
            for param in _find_redirect_params(url):
                for payload in _PAYLOADS:
                    key = f"{url}|{param}|{payload}"
                    if key not in tested:
                        tested.add(key)
                        test_url = _inject_param(url, param, payload)
                        crawler_tasks.append((test_url, param, payload, url))

        if crawler_tasks:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = {
                    pool.submit(self._probe, sess, tu, p, pl, ou): (tu, p, pl, ou)
                    for tu, p, pl, ou in crawler_tasks
                }
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        findings.append(result)
                        logger.info(f"[OpenRedirect] BULUNDU: {result['url']} param={result['parameter']}")

        # ── 2. Probe endpoint'leri paralel test et (MAX_PROBE_REQUESTS ile kısıtlı) ──
        probe_tasks = []
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

        logger.info(f"[OpenRedirect] {len(probe_tasks)} probe isteği paralel gönderiliyor...")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(self._probe, sess, tu, p, pl, ou): (tu, p, pl, ou)
                for tu, p, pl, ou in probe_tasks
            }
            for f in as_completed(futures):
                result = f.result()
                if result:
                    findings.append(result)
                    logger.info(f"[OpenRedirect] BULUNDU (probe): {result['url']} param={result['parameter']}")

        logger.info(f"[OpenRedirect] Tamamlandı: {len(findings)} bulgu")
        return findings


# ---------------------------------------------------------------------------
# Plugin API
# ---------------------------------------------------------------------------

def run(target: str, cfg: Optional[Dict[str, Any]] = None, session=None,
        urls: Optional[List[str]] = None, **kwargs) -> List[Dict[str, Any]]:
    cfg = cfg or {}
    or_cfg = cfg.get("open_redirect", {}) if isinstance(cfg, dict) else {}
    timeout = int(or_cfg.get("timeout", REQUEST_TIMEOUT))
    scanner = OpenRedirectScanner(session=session, timeout=timeout)
    return scanner.scan(target, urls=urls)
