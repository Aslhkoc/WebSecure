"""
websecure.scanners.open_redirect
---------------------------------
Open Redirect zafiyet taraması.

Strateji:
  1. Crawler çıktısından redirect parametrelerini topla
  2. Her parametreye 30+ bypass payload'ı dene
  3. Yanıt Location header'ı veya JS redirect'i kontrol et
  4. WAF bypass: çeşitli encoding ve protocol tricks
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlencode, urlparse, urlunparse, urljoin, quote

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redirect parametresi isimleri (yaygın)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Payload listesi — WAF bypass teknikleri dahil
# ---------------------------------------------------------------------------
_CANARY = "evil.websecure.internal"

_PAYLOADS = [
    # Temel
    f"https://{_CANARY}",
    f"http://{_CANARY}",
    f"//{_CANARY}",
    # Protocol-relative + path
    f"//{_CANARY}/path",
    f"//{_CANARY}@target.com",
    # Çift slash
    f"///{_CANARY}",
    f"////{_CANARY}",
    # Backslash bypass (IIS, Windows)
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
    # Newline injection
    f"https://{_CANARY}%0d%0alocation:https://{_CANARY}",
    # Tab / space
    f"https://{_CANARY}%09",
    f" https://{_CANARY}",
    # Unicode bypass
    f"https://ⓔⓥⓘⓛ.websecure.internal",
    f"https://{_CANARY.replace('.', '\u3002')}",
    # Fragment bypass
    f"https://{_CANARY}#",
    # Null byte
    f"https://{_CANARY}%00",
    # IP bypass
    "https://0x45.0x58.0x41.0x4d",   # hex IP
    "https://1113982819",             # decimal IP örneği
    # Data URI (bazı uygulamalar JS redirect yapıyor)
    f"data:text/html,<script>window.location='https://{_CANARY}'</script>",
    # javascript: URI
    f"javascript://comment%0aalert(document.domain)",
]


def _is_open_redirect(response, payload: str) -> bool:
    """
    Yanıtın gerçek bir open redirect içerip içermediğini kontrol eder.
    """
    # 1. 3xx Location header
    location = response.headers.get("Location", "") or response.headers.get("location", "")
    if location and _CANARY in location:
        return True

    # 2. Refresh header
    refresh = response.headers.get("Refresh", "") or response.headers.get("refresh", "")
    if refresh and _CANARY in refresh:
        return True

    # 3. HTML meta refresh veya JS redirect
    body = ""
    try:
        body = response.text[:8000]
    except Exception:
        pass

    if _CANARY in body:
        # Daha spesifik kontrol: sadece body'de canary geçmesi yetmez,
        # redirect context içinde olmalı
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


# ---------------------------------------------------------------------------
# URL içindeki redirect parametrelerini çıkar
# ---------------------------------------------------------------------------

def _find_redirect_params(url: str) -> List[str]:
    """URL query string'inde redirect parametresi var mı?"""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    from urllib.parse import parse_qs
    params = parse_qs(parsed.query, keep_blank_values=True)
    found = []
    for p in params:
        if p.lower() in _REDIRECT_PARAMS:
            found.append(p)
    return found


def _inject_payload(url: str, param: str, payload: str) -> str:
    """URL'deki belirtilen parametreyi payload ile değiştirir."""
    from urllib.parse import parse_qs, urlencode
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))


# ---------------------------------------------------------------------------
# Ana scanner sınıfı
# ---------------------------------------------------------------------------

class OpenRedirectScanner:
    """
    Open redirect taraması.
    Hem crawler tarafından bulunan URL'leri hem de base URL üzerindeki
    yaygın endpoint'leri tarar.
    """

    # Redirect parametresi enjekte edilecek yaygın endpoint'ler
    _PROBE_PATHS = [
        "/login", "/logout", "/signin", "/signout", "/auth",
        "/redirect", "/go", "/out", "/link",
        "/oauth/authorize", "/oauth/callback",
        "/sso/login", "/sso/callback",
        "/", "",
    ]

    def __init__(self, session=None, timeout: int = 8):
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

    def _test_url(self, sess, url: str, param: str) -> Optional[Dict[str, Any]]:
        """Bir URL + parametre kombinasyonunu tüm payload'larla test eder."""
        for payload in _PAYLOADS:
            test_url = _inject_payload(url, param, payload)
            try:
                resp = sess.get(
                    test_url,
                    timeout=self.timeout,
                    allow_redirects=False,  # kendi redirect'imizi kontrol etmeliyiz
                    verify=False,
                )
                if _is_open_redirect(resp, payload):
                    return {
                        "severity": "high",
                        "title": "Open Redirect",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "test_url": test_url,
                        "status_code": resp.status_code,
                        "location": resp.headers.get("Location", ""),
                        "evidence": f"Param '{param}' ile '{payload}' yükü redirect tetikledi",
                        "cwe": "CWE-601",
                        "owasp": "A01:2021",
                    }
            except Exception:
                pass
        return None

    def scan(self, base_url: str, urls: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        base_url: hedef sitenin kök URL'si
        urls: crawler'dan gelen URL listesi (opsiyonel)
        """
        import warnings
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass

        sess = self._get_session()
        if not sess:
            logger.warning("[OpenRedirect] HTTP session oluşturulamadı")
            return []

        findings: List[Dict[str, Any]] = []
        tested: Set[str] = set()
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        # 1. Crawler'dan gelen URL'lerde redirect param ara
        for url in (urls or []):
            for param in _find_redirect_params(url):
                key = f"{url}|{param}"
                if key in tested:
                    continue
                tested.add(key)
                result = self._test_url(sess, url, param)
                if result:
                    findings.append(result)
                    logger.info(f"[OpenRedirect] BULUNDU: {url} param={param}")

        # 2. Probe endpoint'lere tüm redirect param isimlerini enjekte et
        for path in self._PROBE_PATHS:
            probe_url = origin + path
            for param in _REDIRECT_PARAMS[:20]:  # top 20 parametre yeterli
                for payload in _PAYLOADS[:10]:   # hızlı: ilk 10 payload
                    test_url = f"{probe_url}?{param}={quote(payload)}"
                    key = f"{test_url}|{param}"
                    if key in tested:
                        continue
                    tested.add(key)
                    try:
                        resp = sess.get(
                            test_url,
                            timeout=self.timeout,
                            allow_redirects=False,
                            verify=False,
                        )
                        if _is_open_redirect(resp, payload):
                            findings.append({
                                "severity": "high",
                                "title": "Open Redirect",
                                "url": probe_url,
                                "param": param,
                                "payload": payload,
                                "test_url": test_url,
                                "status_code": resp.status_code,
                                "location": resp.headers.get("Location", ""),
                                "evidence": f"Probe endpoint'te open redirect tespit edildi",
                                "cwe": "CWE-601",
                                "owasp": "A01:2021",
                            })
                            logger.info(f"[OpenRedirect] BULUNDU (probe): {probe_url} param={param}")
                    except Exception:
                        pass

        logger.info(f"[OpenRedirect] Tamamlandı: {len(findings)} bulgu")
        return findings


# ---------------------------------------------------------------------------
# Plugin API
# ---------------------------------------------------------------------------

def run(target: str, cfg: Optional[Dict[str, Any]] = None, session=None,
        urls: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Plugin entry point.
    cfg anahtarları:
      open_redirect.timeout  — istek timeout süresi (varsayılan: 8)
    """
    cfg = cfg or {}
    or_cfg = cfg.get("open_redirect", {}) if isinstance(cfg, dict) else {}
    timeout = int(or_cfg.get("timeout", 8))

    scanner = OpenRedirectScanner(session=session, timeout=timeout)
    return scanner.scan(target, urls=urls)
