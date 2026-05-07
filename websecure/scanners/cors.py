"""
websecure.scanners.cors
------------------------
CORS (Cross-Origin Resource Sharing) tam exploit analizi.

Adim 9 - Siniflar:
  CORSScanner(BaseScanner)           -- orchestrator
  CORSWildcardProber                 -- Access-Control-Allow-Origin: * + credentials
  CORSOriginReflectionProber         -- arbitrary origin reflect + credentials:true
  CORSNullOriginProber               -- null origin bypass (iframe sandbox trick)
  CORSSubdomainTrustProber           -- *.domain.com trust + subdomain as pivot
  CORSPreflightBypassProber          -- OPTIONS preflight bypass teknikleri
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

_EVIL_ORIGIN = "https://evil-wsp.invalid"

_ORIGIN_BYPASS_VARIANTS = [
    "https://evil-wsp.invalid",
    "null",
    "https://evil-wsp.invalid.target.example.com",
    "https://target.example.com.evil-wsp.invalid",
    "https://target.example.com%60.evil-wsp.invalid",
    "https://evil-wsp.invalid\ttarget",
    "https://\r\nevil-wsp.invalid",
]

_SENSITIVE_ENDPOINTS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/v1/user", "/api/v1/me", "/api/admin", "/dashboard",
    "/api/keys", "/api/tokens", "/api/settings",
]


def _cors_vulnerable(resp, origin: str) -> Tuple[bool, bool]:
    """Returns (origin_reflected, credentials_allowed)."""
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    reflected  = acao == origin or (origin == "null" and acao == "null")
    with_creds = acac == "true"
    return reflected, with_creds


# ===========================================================================
# 1. CORSWildcardProber
# ===========================================================================
class CORSWildcardProber(BaseScanner):
    """
    Wildcard CORS + credentials:true kombinasyonu:
    ACAO: * ile birlikte ACAC: true = kritik (tarayicilar bloklasa da sunucu yanlisi)
    """
    name = "cors_wildcard"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        endpoints = self._find_endpoints(target)
        for url in endpoints:
            try:
                resp = self.session.get(url, headers={"Origin": _EVIL_ORIGIN}, timeout=8)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                if acao == "*":
                    sev = "Critical" if acac == "true" else "Medium"
                    results.append({
                        "vuln_type": "CORS Wildcard Origin" + (" + credentials" if acac == "true" else ""),
                        "url": url, "severity": sev,
                        "description": (
                            f"CORS ACAO: * detected. "
                            + ("ACAC: true with wildcard is a critical misconfiguration — "
                               "credentials cannot actually be sent (browser blocks), "
                               "but indicates a poorly configured CORS policy." if acac == "true"
                               else "Wildcard allows any site to read responses.")
                        ),
                        "evidence": {
                            "ACAO": acao, "ACAC": acac, "status": resp.status_code,
                        },
                    })
                    self.report_finding(**results[-1])
            except Exception as exc:
                logger.debug("[CORSWild] %s: %s", url, exc)
        return results

    def _find_endpoints(self, base: str) -> List[str]:
        found = [base]
        for path in _SENSITIVE_ENDPOINTS:
            url = urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=4)
                if r.status_code not in (404, 410):
                    found.append(url)
            except Exception:
                pass
        return found[:6]


# ===========================================================================
# 2. CORSOriginReflectionProber
# ===========================================================================
class CORSOriginReflectionProber(BaseScanner):
    """
    Arbitrary origin reflection + credentials:true — en tehlikeli CORS konfigurasyonu.
    Tam hesap devralma zinciri: cookie + CORS + XHR.
    """
    name = "cors_reflection"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc or parsed.hostname or "target.example.com"
        endpoints = _SENSITIVE_ENDPOINTS[:5]

        for path in endpoints:
            url = urllib.parse.urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            for evil_origin in [_EVIL_ORIGIN, f"https://evil.{domain}", f"https://{domain}.evil-wsp.invalid"]:
                try:
                    resp = self.session.get(url, headers={"Origin": evil_origin}, timeout=8)
                    reflected, with_creds = _cors_vulnerable(resp, evil_origin)
                    if reflected and with_creds:
                        results.append({
                            "vuln_type": "CORS Origin Reflection + credentials:true (ATO Risk)",
                            "url": url, "severity": "Critical",
                            "description": (
                                f"Server reflects arbitrary origin '{evil_origin}' with "
                                "Access-Control-Allow-Credentials: true. "
                                "Attacker can read authenticated responses from any origin — "
                                "Account Takeover via CORS."
                            ),
                            "evidence": {
                                "evil_origin": evil_origin,
                                "ACAO": resp.headers.get("Access-Control-Allow-Origin"),
                                "ACAC": resp.headers.get("Access-Control-Allow-Credentials"),
                                "status": resp.status_code,
                            },
                        })
                        self.report_finding(**results[-1])
                        return results
                    elif reflected:
                        results.append({
                            "vuln_type": "CORS Origin Reflection (No Credentials)",
                            "url": url, "severity": "Medium",
                            "description": (
                                f"Server reflects arbitrary origin '{evil_origin}' "
                                "but without credentials flag. Limited impact for non-credentialed requests."
                            ),
                            "evidence": {
                                "evil_origin": evil_origin,
                                "ACAO": resp.headers.get("Access-Control-Allow-Origin"),
                            },
                        })
                        self.report_finding(**results[-1])
                except Exception as exc:
                    logger.debug("[CORSRefl] %s: %s", url, exc)
        return results


# ===========================================================================
# 3. CORSNullOriginProber
# ===========================================================================
class CORSNullOriginProber(BaseScanner):
    """
    Null origin bypass:
    iframe sandbox, data: URI, file: URI'dan gelen istekler 'null' origin gonder.
    Bazi sunucular 'null' origini whitelist'e alir.
    """
    name = "cors_null_origin"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        endpoints = _SENSITIVE_ENDPOINTS[:4]

        for path in endpoints:
            url = urllib.parse.urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = self.session.get(url, headers={"Origin": "null"}, timeout=8)
                reflected, with_creds = _cors_vulnerable(resp, "null")
                if reflected:
                    sev = "Critical" if with_creds else "High"
                    results.append({
                        "vuln_type": "CORS Null Origin Bypass" + (" + credentials" if with_creds else ""),
                        "url": url, "severity": sev,
                        "description": (
                            "Server allows 'null' origin in CORS. "
                            "Attacker can embed a sandboxed iframe (Origin: null) to read "
                            "authenticated responses. " +
                            ("With credentials=true: full ATO possible." if with_creds else "")
                        ),
                        "evidence": {
                            "ACAO": resp.headers.get("Access-Control-Allow-Origin"),
                            "ACAC": resp.headers.get("Access-Control-Allow-Credentials"),
                            "status": resp.status_code,
                        },
                    })
                    self.report_finding(**results[-1])
                    return results
            except Exception as exc:
                logger.debug("[CORSNull] %s: %s", url, exc)
        return results


# ===========================================================================
# 4. CORSSubdomainTrustProber
# ===========================================================================
class CORSSubdomainTrustProber(BaseScanner):
    """
    Subdomain-trust CORS:
    ACAO: *.target.com — Subdomain Takeover ile birlesince ATO zinciri.
    """
    name = "cors_subdomain_trust"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc or "target.example.com"
        domain = domain.split(":")[0]

        # Test common subdomain trust patterns
        test_origins = [
            f"https://evil.{domain}",
            f"https://attacker.{domain}",
            f"https://xss.{domain}",
            f"https://not{domain}",
            f"https://{domain}.evil-wsp.invalid",
        ]

        for path in _SENSITIVE_ENDPOINTS[:4]:
            url = urllib.parse.urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            for origin in test_origins:
                try:
                    resp = self.session.get(url, headers={"Origin": origin}, timeout=8)
                    reflected, with_creds = _cors_vulnerable(resp, origin)
                    if reflected:
                        results.append({
                            "vuln_type": "CORS Subdomain Trust" + (" + ATO" if with_creds else ""),
                            "url": url, "severity": "High" if with_creds else "Medium",
                            "description": (
                                f"CORS trusts subdomain pattern — '{origin}' reflected. "
                                + ("Combined with Subdomain Takeover -> full ATO." if with_creds else
                                   "Subdomain XSS + CORS = potential data theft.")
                            ),
                            "evidence": {
                                "trusted_origin": origin,
                                "ACAO": resp.headers.get("Access-Control-Allow-Origin"),
                                "ACAC": resp.headers.get("Access-Control-Allow-Credentials"),
                            },
                        })
                        self.report_finding(**results[-1])
                        return results
                except Exception as exc:
                    logger.debug("[CORSSub] %s: %s", url, exc)
        return results


# ===========================================================================
# 5. CORSPreflightBypassProber
# ===========================================================================
class CORSPreflightBypassProber(BaseScanner):
    """
    Preflight (OPTIONS) bypass teknikleri:
    - Custom method yerine standart (GET/POST) ile credentialled istek
    - Content-Type: text/plain ile preflight atlama
    - Simple headers ile non-simple istek bypass
    """
    name = "cors_preflight_bypass"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        for path in _SENSITIVE_ENDPOINTS[:3]:
            url = urllib.parse.urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            # Preflight OPTIONS request
            try:
                opts = self.session.options(url, headers={
                    "Origin": _EVIL_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization, X-Custom-Header",
                }, timeout=8)
                acam = opts.headers.get("Access-Control-Allow-Methods", "")
                acah = opts.headers.get("Access-Control-Allow-Headers", "")
                acao = opts.headers.get("Access-Control-Allow-Origin", "")
                if _EVIL_ORIGIN in acao or acao == "*":
                    if "authorization" in acah.lower() or "*" in acah:
                        results.append({
                            "vuln_type": "CORS Preflight Allows Credentialed Headers",
                            "url": url, "severity": "High",
                            "description": (
                                "OPTIONS preflight allows Authorization header from evil origin. "
                                "Authenticated cross-origin requests may be permitted."
                            ),
                            "evidence": {
                                "ACAO": acao, "ACAM": acam, "ACAH": acah,
                                "status": opts.status_code,
                            },
                        })
                        self.report_finding(**results[-1])
            except Exception as exc:
                logger.debug("[CORSPreflight] %s: %s", url, exc)
        return results


# ===========================================================================
# CORSScanner — Orchestrator
# ===========================================================================
class CORSScanner(BaseScanner):
    """
    Adim 9 CORS orchestrator:
    WildcardProber + OriginReflectionProber + NullOriginProber
    + SubdomainTrustProber + PreflightBypassProber
    """
    name = "cors"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        probers = [
            CORSWildcardProber(session=self.session, results=self.results),
            CORSOriginReflectionProber(session=self.session, results=self.results),
            CORSNullOriginProber(session=self.session, results=self.results),
            CORSSubdomainTrustProber(session=self.session, results=self.results),
            CORSPreflightBypassProber(session=self.session, results=self.results),
        ]
        for prober in probers:
            try:
                prober.target = target
                all_results.extend(prober.run(target, **kwargs))
            except Exception as exc:
                logger.warning("[CORSScanner] %s: %s", prober.name, exc)
        return all_results


def run(url: str, session=None, debug: bool = False, **kwargs) -> List[Dict]:
    scanner = CORSScanner(session=session, debug=debug)
    return scanner.run(url, **kwargs)
