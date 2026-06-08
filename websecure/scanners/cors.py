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
import urllib.parse
from typing import Dict, List, Optional, Tuple

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

_EVIL_ORIGIN = "https://evil-wsp.invalid"

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
                            "CORS ACAO: * detected. "
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
                # path_exists: soft-404/catch-all farkındalı varlık kontrolü
                # (normal sunucuda eski `status_code not in (404,410)` ile aynı).
                if self.path_exists(r):
                    found.append(url)
            except Exception as _fix_e:
                logger.debug(f"[scanners.cors] {type(_fix_e).__name__}: {_fix_e!r}")
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
# 6. OriginReflectionProber
# ===========================================================================
class OriginReflectionProber(BaseScanner):
    """
    Dedicated origin reflection prober:
    Tests whether the server reflects any arbitrary Origin back as
    Access-Control-Allow-Origin (all-origin permissiveness).
    Test origins: https://evil.com, https://attacker.com, null.
    """
    name = "cors_origin_reflection"

    _TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        endpoints = [target] + [
            urllib.parse.urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            for p in _SENSITIVE_ENDPOINTS[:4]
        ]
        for url in endpoints[:5]:
            for origin in self._TEST_ORIGINS:
                try:
                    resp = self.session.get(url, headers={"Origin": origin}, timeout=8)
                    reflected, with_creds = _cors_vulnerable(resp, origin)
                    if reflected:
                        sev = "Critical" if with_creds else "High"
                        finding = {
                            "vuln_type": "CORS — Server Reflects Arbitrary Origin" + (" + credentials" if with_creds else ""),
                            "url": url,
                            "severity": sev,
                            "description": (
                                f"Server reflects origin '{origin}' in Access-Control-Allow-Origin header — "
                                "the server allows any origin to read its responses. "
                                + ("With ACAC: true, attacker can read credentialed responses (ATO risk)."
                                   if with_creds else "")
                            ),
                            "evidence": {
                                "sent_origin": origin,
                                "ACAO": resp.headers.get("Access-Control-Allow-Origin"),
                                "ACAC": resp.headers.get("Access-Control-Allow-Credentials"),
                                "status": resp.status_code,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        return results
                except Exception as exc:
                    logger.debug("[OriginReflectionProber] %s %s: %s", url, origin, exc)
        return results


# ===========================================================================
# 7. NullOriginProber
# ===========================================================================
class NullOriginProber(BaseScanner):
    """
    Null origin bypass prober (dedicated):
    Sends Origin: null to detect iframe sandbox bypass misconfiguration.
    If server returns Access-Control-Allow-Origin: null -> High severity.
    """
    name = "cors_null_origin_prober"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        endpoints = [target] + [
            urllib.parse.urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            for p in _SENSITIVE_ENDPOINTS[:4]
        ]
        for url in endpoints[:5]:
            try:
                resp = self.session.get(url, headers={"Origin": "null"}, timeout=8)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                if acao == "null":
                    sev = "Critical" if acac == "true" else "High"
                    finding = {
                        "vuln_type": "CORS — Null Origin Allowed (iframe sandbox bypass)",
                        "url": url,
                        "severity": sev,
                        "description": (
                            "Server responds with Access-Control-Allow-Origin: null. "
                            "Attacker can use a sandboxed iframe (<iframe sandbox>) to send "
                            "requests with Origin: null and read responses, bypassing SOP. "
                            + ("With credentials=true: full account takeover possible." if acac == "true" else "")
                        ),
                        "evidence": {
                            "sent_origin": "null",
                            "ACAO": acao,
                            "ACAC": acac,
                            "status": resp.status_code,
                        },
                    }
                    results.append(finding)
                    self.report_finding(**finding)
                    return results
            except Exception as exc:
                logger.debug("[NullOriginProber] %s: %s", url, exc)
        return results


# ===========================================================================
# 8. SubdomainWildcardProber
# ===========================================================================
class SubdomainWildcardProber(BaseScanner):
    """
    Subdomain wildcard / suffix trick prober:
    - evil.TARGET_DOMAIN.com  (target domain as suffix of attacker subdomain)
    - TARGET_DOMAINevil.com   (target domain as prefix in attacker domain)
    If Access-Control-Allow-Origin reflects evil domain -> Critical.
    """
    name = "cors_subdomain_wildcard"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        domain = (parsed.netloc or parsed.hostname or "target.example.com").split(":")[0]

        evil_origins = [
            f"https://evil.{domain}.com",       # subdomain of attacker, contains target domain
            f"https://{domain}evil.com",         # suffix trick
            f"https://attacker.{domain}",        # subdomain of target (requires subdomain takeover)
            f"https://www.{domain}.attacker.com",
        ]

        endpoints = [target] + [
            urllib.parse.urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            for p in _SENSITIVE_ENDPOINTS[:3]
        ]
        for url in endpoints[:4]:
            for evil_origin in evil_origins:
                try:
                    resp = self.session.get(url, headers={"Origin": evil_origin}, timeout=8)
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                    if acao == evil_origin or evil_origin in acao:
                        sev = "Critical" if acac == "true" else "High"
                        finding = {
                            "vuln_type": "CORS — Subdomain Wildcard / Suffix Trick",
                            "url": url,
                            "severity": sev,
                            "description": (
                                f"Server reflects evil origin '{evil_origin}' — "
                                f"the CORS origin-validation logic can be bypassed by using the target "
                                f"domain as part of an attacker-controlled domain. "
                                + ("ACAC: true — attacker can steal credentialed responses." if acac == "true" else "")
                            ),
                            "evidence": {
                                "evil_origin": evil_origin,
                                "ACAO": acao,
                                "ACAC": acac,
                                "status": resp.status_code,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        return results
                except Exception as exc:
                    logger.debug("[SubdomainWildcardProber] %s %s: %s", url, evil_origin, exc)
        return results


# ===========================================================================
# 9. CredentialedCORSProber
# ===========================================================================
class CredentialedCORSProber(BaseScanner):
    """
    Credentialed CORS prober:
    Sends Origin: https://evil.com + Access-Control-Request-Headers: Authorization.
    If response has both ACAO: evil.com AND ACAC: true -> Critical (credential leak).
    """
    name = "cors_credentialed"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        evil_origin = "https://evil.com"
        endpoints = [target] + [
            urllib.parse.urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            for p in _SENSITIVE_ENDPOINTS[:5]
        ]
        for url in endpoints[:6]:
            try:
                resp = self.session.get(url, headers={
                    "Origin": evil_origin,
                    "Access-Control-Request-Headers": "Authorization",
                }, timeout=8)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                if (acao == evil_origin or evil_origin in acao) and acac == "true":
                    finding = {
                        "vuln_type": "CORS — Credentialed Request with Evil Origin (Credential Leak)",
                        "url": url,
                        "severity": "Critical",
                        "description": (
                            f"Server returns ACAO: {acao!r} + ACAC: true for origin '{evil_origin}'. "
                            "Attacker can issue credentialed cross-origin requests (with cookies/Authorization) "
                            "and read the authenticated responses — credential / session exfiltration."
                        ),
                        "evidence": {
                            "sent_origin": evil_origin,
                            "ACAO": acao,
                            "ACAC": acac,
                            "request_header": "Authorization",
                            "status": resp.status_code,
                        },
                    }
                    results.append(finding)
                    self.report_finding(**finding)
                    return results
            except Exception as exc:
                logger.debug("[CredentialedCORSProber] %s: %s", url, exc)
        return results


# ===========================================================================
# 10. CORSXSSChainDetector
# ===========================================================================
class CORSXSSChainDetector(BaseScanner):
    """
    CORS + XSS chain detector:
    If CORS misconfiguration AND XSS indicators are found together,
    reports them as a combined exploit chain with higher severity.
    XSS indicators: CSP absence, X-XSS-Protection: 0, reflected script tags in body.
    """
    name = "cors_xss_chain"

    _XSS_PROBE_PAYLOADS = [
        "<script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        evil_origin = "https://evil.com"

        # 1. Check for CORS misconfiguration
        cors_evidence: Optional[Dict] = None
        try:
            resp = self.session.get(target, headers={"Origin": evil_origin}, timeout=8)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == evil_origin or acao == "*":
                cors_evidence = {
                    "ACAO": acao,
                    "ACAC": acac,
                    "with_credentials": acac == "true",
                }
        except Exception as exc:
            logger.debug("[CORSXSSChain] CORS check: %s", exc)

        if not cors_evidence:
            return results

        # 2. Check for XSS indicators
        xss_evidence: Optional[Dict] = None
        for payload in self._XSS_PROBE_PAYLOADS:
            xss_url = target + ("&" if "?" in target else "?") + f"q={urllib.parse.quote(payload)}"
            try:
                xss_resp = self.session.get(xss_url, timeout=8)
                xss_body = getattr(xss_resp, "text", "")[:5000]
                csp_header = xss_resp.headers.get("Content-Security-Policy", "")
                # Reflected XSS: raw payload appears in response body
                if payload in xss_body or payload.lower() in xss_body.lower():
                    xss_evidence = {
                        "payload": payload,
                        "xss_url": xss_url,
                        "reflected": True,
                        "csp_present": bool(csp_header),
                    }
                    break
                # No CSP + X-XSS-Protection: 0 is also suspicious
                xss_protection = xss_resp.headers.get("X-XSS-Protection", "")
                if not csp_header and xss_protection == "0":
                    xss_evidence = {
                        "payload": payload,
                        "xss_url": xss_url,
                        "reflected": False,
                        "csp_present": False,
                        "note": "No CSP + X-XSS-Protection: 0 detected",
                    }
            except Exception as exc:
                logger.debug("[CORSXSSChain] XSS probe: %s", exc)

        # 3. If both exist, report as chained exploit
        if cors_evidence and xss_evidence:
            finding = {
                "vuln_type": "CORS + XSS Exploit Chain",
                "url": target,
                "severity": "Critical",
                "description": (
                    "CORS misconfiguration and XSS indicator detected together. "
                    "An attacker can chain XSS to steal CORS-allowed authenticated responses: "
                    "inject script via XSS -> issue CORS cross-origin request -> read victim's data. "
                    f"CORS: ACAO={cors_evidence['ACAO']!r}, ACAC={cors_evidence['ACAC']!r}. "
                    f"XSS: payload={xss_evidence['payload']!r} reflected={xss_evidence['reflected']}."
                ),
                "evidence": {
                    "cors": cors_evidence,
                    "xss": xss_evidence,
                    "chain_impact": "Session hijack / account takeover via XSS+CORS chain",
                },
            }
            results.append(finding)
            self.report_finding(**finding)

        return results


# ===========================================================================
# CORSScanner — Orchestrator
# ===========================================================================
class CORSScanner(BaseScanner):
    """
    CORS orchestrator:
    WildcardProber + OriginReflectionProber + NullOriginProber
    + SubdomainTrustProber + PreflightBypassProber
    + OriginReflectionProber(dedicated) + NullOriginProber(dedicated)
    + SubdomainWildcardProber + CredentialedCORSProber + CORSXSSChainDetector
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
            OriginReflectionProber(session=self.session, results=self.results),
            NullOriginProber(session=self.session, results=self.results),
            SubdomainWildcardProber(session=self.session, results=self.results),
            CredentialedCORSProber(session=self.session, results=self.results),
            CORSXSSChainDetector(session=self.session, results=self.results),
        ]
        for prober in probers:
            try:
                all_results.extend(prober.run(target, **kwargs))
            except Exception as exc:
                logger.warning("[CORSScanner] %s: %s", prober.name, exc)
        return all_results


def run(url: str, session=None, results: dict = None, debug: bool = False, **kwargs) -> List[Dict]:
    scanner = CORSScanner(session=session, results=results or {}, debug=debug)
    return scanner.run(url, **kwargs)
