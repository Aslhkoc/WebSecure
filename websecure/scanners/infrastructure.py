"""
websecure.scanners.infrastructure
---------------------------------
Consolidated module for:
- Security Headers Analysis (formerly headers.py)
- TLS/SSL Configuration & Policy Analysis (formerly tls.py)
"""
from __future__ import annotations
import re
import socket
import hashlib
import ssl as pyssl
import typing as t
import logging
import concurrent.futures as _fut
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urlsplit, urljoin
from importlib.util import find_spec
from importlib import import_module

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding as _CryptoEncoding
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
    _CryptoEncoding = None

import requests
from websecure.core.http import hardened_session, verify_for_phase, classify_access_block
from websecure.core.reporting import add_result
from websecure.scanners.base import BaseScanner

_logger = logging.getLogger(__name__)

# optional httpx support
httpx = None
_HAS_HTTPX = False
if find_spec("httpx") is not None:
    try:
        httpx = import_module("httpx")
        _HAS_HTTPX = True
    except ImportError:
        pass

# ============================================================================
# SECTION 1: HEADER SCANNER (formerly headers.py)
# ============================================================================

@dataclass
class HeaderFinding:
    title: str
    severity: str  # Info | Low | Medium | High
    description: str
    evidence: t.Dict[str, t.Any] = field(default_factory=dict)
    recommendation: str = ""
    tags: t.List[str] = field(default_factory=list)

@dataclass
class HeaderCoverage:
    # PASS/WARN/FAIL
    csp: str = "FAIL"
    hsts: str = "FAIL"
    xfo: str = "FAIL"   # SX
    xcto: str = "FAIL"  # XXO
    coop: str = "FAIL"
    corp: str = "FAIL"
    perm_policy: str = "WARN"
    referrer_policy: str = "WARN"
    notes: t.Dict[str, str] = field(default_factory=dict)

def _norm_header_key(k: str) -> str:
    return "-".join([p.capitalize() for p in k.split("-")])

def _header(resp, name: str) -> str:
    if resp is None: return ""
    raw = getattr(resp, "headers", None)
    if not raw: return ""
    
    key = str(name)
    alt = _norm_header_key(key)
    wanted = {key.lower()}
    if alt and alt != key: wanted.add(alt.lower())
    
    # Try dict-like access
    if hasattr(raw, "get"):
        for k in (key, alt):
            if k:
                v = raw.get(k)
                if v: return v
        # Case insensitive scan
        if hasattr(raw, "keys"):
            for k in raw.keys():
                if isinstance(k, str) and k.lower() in wanted:
                    return raw.get(k) or ""
                    
    # Try list-of-tuples access
    if hasattr(raw, "__iter__") and not isinstance(raw, (str, bytes, dict)):
        for item in raw:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                k, v = item
                if isinstance(k, str) and k.lower() in wanted:
                    return v or ""
    return ""

def _bool(v: t.Optional[str]) -> bool:
    return bool(v and str(v).strip())

def _split_directives(v: str) -> t.Dict[str, str]:
    out = {}
    if not v: return out
    for part in re.split(r"\s*;\s*", v.strip()):
        if not part: continue
        if " " in part:
            k, vv = part.split(" ", 1)
        else:
            k, vv = part, ""
        out[k.strip().lower()] = vv.strip().lower()
    return out

def _csp_findings(csp: str) -> t.Tuple[str, t.List[HeaderFinding], t.List[str]]:
    notes = []
    findings = []
    pocs = []
    
    d = _split_directives(csp)
    has_default = "default-src" in d
    vv = csp.lower()
    
    weak_tokens = []
    for bad in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "blob:"):
        if bad in vv: weak_tokens.append(bad)
        
    if not has_default: notes.append("default-src missing")
    if d.get("object-src", "") != "'none'": notes.append("object-src 'none' recommended")
    if d.get("base-uri", "*") in ("*", ""): notes.append("base-uri loose")
    if "frame-ancestors" not in d: notes.append("frame-ancestors missing")
    
    img_src = d.get("img-src", d.get("default-src", ""))
    img_tokens = set((img_src or "").split())
    if (not img_src) or "*" in img_tokens or "data:" in img_tokens:
        pocs.append("<img src='https://COLLAB/bxss.gif' />")
        pocs.append("new Image().src='https://COLLAB/bxss.gif';")
        
    status = "PASS"
    if weak_tokens:
        status = "WARN"
        findings.append(HeaderFinding(
            title="CSP Weak Directives",
            severity="Medium",
            description="CSP contains risky keywords.",
            evidence={"CSP": csp, "weak": weak_tokens},
            recommendation="Avoid unsafe-inline/eval.",
            tags=["CSP", "Headers"]
        ))
        
    if not has_default: status = "WARN"
    return status, findings, pocs

def analyze_response_headers(resp, origin_for_cors: t.Optional[str] = None) -> t.Tuple[HeaderCoverage, t.List[HeaderFinding], t.List[str]]:
    cov = HeaderCoverage()
    findings = []
    pocs = []
    
    # CSP
    csp = _header(resp, "Content-Security-Policy")
    if _bool(csp):
        cov.csp, fnds, csppocs = _csp_findings(csp)
        findings += fnds
        pocs += csppocs
        cov.notes["csp"] = "strict" if cov.csp == "PASS" else "can-improve"
    else:
        cov.csp = "FAIL"; cov.notes["csp"] = "missing"
        findings.append(HeaderFinding("Missing CSP", "High", "No CSP found.", recommendation="Implement CSP.", tags=["CSP", "Headers"]))
        
    # HSTS
    hsts = _header(resp, "Strict-Transport-Security")
    if _bool(hsts):
        cov.hsts = "PASS"; cov.notes["hsts"] = hsts
        if "max-age" not in hsts.lower():
             findings.append(HeaderFinding("HSTS Invalid", "Low", "Missing max-age.", evidence={"HSTS": hsts}, tags=["HSTS"]))
    else:
        cov.hsts = "FAIL"; cov.notes["hsts"] = "missing"
        findings.append(HeaderFinding("Missing HSTS", "Medium", "HSTS required for HTTPS.", tags=["HSTS"]))
        
    # XFO
    xfo = _header(resp, "X-Frame-Options")
    if not _bool(xfo):
        cov.xfo = "FAIL"; cov.notes["xfo"] = "missing"
    elif xfo.upper() in ("DENY", "SAMEORIGIN"):
        cov.xfo = "PASS"; cov.notes["xfo"] = xfo
    else:
        cov.xfo = "WARN"; cov.notes["xfo"] = xfo
        findings.append(HeaderFinding("Weak XFO", "Low", "Unexpected XFO value.", evidence={"XFO": xfo}, tags=["Clickjacking"]))

    # XXO
    xcto = _header(resp, "X-Content-Type-Options")
    cov.xcto = "PASS" if (xcto or "").strip().lower() == "nosniff" else "FAIL"
    if cov.xcto == "FAIL":
        findings.append(HeaderFinding("Missing/Weak XXO", "Medium", "nosniff required.", evidence={"XXO": xcto}, tags=["MIME"]))
        
    # COOP/CORP/Permissions
    cov.coop = "PASS" if "same-origin" in (getattr(resp, "headers", {}).get("Cross-Origin-Opener-Policy") or "") else "WARN"
    cov.corp = "PASS" if "same-origin" in (getattr(resp, "headers", {}).get("Cross-Origin-Resource-Policy") or "") else "WARN"
    
    perm = _header(resp, "Permissions-Policy")
    cov.perm_policy = "PASS" if perm else "WARN"

    # -- CORS Analysis ------------------------------------------------------
    acao = _header(resp, "Access-Control-Allow-Origin")
    acac = _header(resp, "Access-Control-Allow-Credentials")
    acao_methods = _header(resp, "Access-Control-Allow-Methods")

    if acao == "*":
        if acac and acac.lower() == "true":
            findings.append(HeaderFinding(
                "CORS Wildcard + Credentials",
                "Critical",
                "Access-Control-Allow-Origin: * combined with Allow-Credentials: true — "
                "browsers block this but some frameworks strip the restriction silently.",
                evidence={"ACAO": acao, "ACAC": acac},
                recommendation="Never combine wildcard ACAO with credentials.",
                tags=["CORS"],
            ))
        else:
            findings.append(HeaderFinding(
                "CORS Wildcard Origin",
                "Medium",
                "Any origin can read responses from this endpoint.",
                evidence={"ACAO": acao},
                recommendation="Restrict ACAO to trusted origins.",
                tags=["CORS"],
            ))
    elif acao and acao.lower() == "null":
        findings.append(HeaderFinding(
            "CORS Null Origin Allowed",
            "High",
            "ACAO: null allows sandboxed iframes and file:// origins — exploitable via sandboxed iframes.",
            evidence={"ACAO": acao},
            tags=["CORS"],
        ))
    elif acao and origin_for_cors and acao == origin_for_cors:
        findings.append(HeaderFinding(
            "CORS Origin Reflection",
            "High",
            "Server dynamically reflects the request Origin header — "
            "any origin can read authenticated responses.",
            evidence={"ACAO": acao, "reflected_origin": origin_for_cors},
            recommendation="Maintain an explicit allowlist of trusted origins.",
            tags=["CORS"],
        ))

    # -- Cookie Security Analysis --------------------------------------------
    set_cookie_headers = []
    raw_headers = getattr(resp, "headers", {})
    if hasattr(raw_headers, "getlist"):
        set_cookie_headers = raw_headers.getlist("Set-Cookie")
    elif hasattr(raw_headers, "items"):
        set_cookie_headers = [v for k, v in raw_headers.items() if k.lower() == "set-cookie"]

    for cookie_str in set_cookie_headers:
        cookie_lower = cookie_str.lower()
        cookie_name = cookie_str.split("=")[0].strip()

        if "httponly" not in cookie_lower:
            findings.append(HeaderFinding(
                "Cookie Missing HttpOnly Flag",
                "Medium",
                f"Cookie '{cookie_name}' is accessible via JavaScript — XSS can steal it.",
                evidence={"cookie": cookie_str[:120]},
                recommendation="Add HttpOnly flag to all session cookies.",
                tags=["Cookie", "XSS"],
            ))
        if "secure" not in cookie_lower:
            findings.append(HeaderFinding(
                "Cookie Missing Secure Flag",
                "Medium",
                f"Cookie '{cookie_name}' is transmitted over HTTP — susceptible to interception.",
                evidence={"cookie": cookie_str[:120]},
                recommendation="Add Secure flag to all session cookies.",
                tags=["Cookie", "TLS"],
            ))
        samesite_match = re.search(r"samesite\s*=\s*(strict|lax|none)", cookie_lower)
        if not samesite_match:
            findings.append(HeaderFinding(
                "Cookie Missing SameSite Attribute",
                "Low",
                f"Cookie '{cookie_name}' has no SameSite — vulnerable to CSRF in some contexts.",
                evidence={"cookie": cookie_str[:120]},
                recommendation="Set SameSite=Lax or SameSite=Strict.",
                tags=["Cookie", "CSRF"],
            ))
        elif samesite_match.group(1) == "none" and "secure" not in cookie_lower:
            findings.append(HeaderFinding(
                "Cookie SameSite=None Without Secure",
                "High",
                f"Cookie '{cookie_name}' SameSite=None requires Secure flag.",
                evidence={"cookie": cookie_str[:120]},
                tags=["Cookie"],
            ))

    # -- Referrer-Policy Analysis --------------------------------------------
    referrer = _header(resp, "Referrer-Policy")
    if referrer:
        if referrer.lower() in ("unsafe-url", "no-referrer-when-downgrade", ""):
            findings.append(HeaderFinding(
                "Weak Referrer-Policy",
                "Low",
                f"Referrer-Policy '{referrer}' may leak full URL to third parties.",
                evidence={"Referrer-Policy": referrer},
                recommendation="Use 'strict-origin-when-cross-origin' or stricter.",
                tags=["Privacy", "Headers"],
            ))
    else:
        findings.append(HeaderFinding(
            "Missing Referrer-Policy",
            "Low",
            "No Referrer-Policy — browser defaults may leak origin to cross-origin requests.",
            recommendation="Set Referrer-Policy: strict-origin-when-cross-origin.",
            tags=["Privacy", "Headers"],
        ))

    return cov, findings, pocs

class HeaderScanner(BaseScanner):
    name: str = "headers"

    def __init__(self, session=None, results=None, debug=False, timeout=15.0, verify_tls=True):
        super().__init__(session=session, results=results, debug=debug)
        self.timeout = timeout
        self.verify_tls = verify_tls

    def run(self, target: str, **kwargs) -> t.Dict[str, t.Any]:
        """BaseScanner interface — delegates to scan_url."""
        return self.scan_url(target, **kwargs)

    def _do_get(self, url: str, headers: t.Optional[t.Dict] = None) -> t.Any:
        h = headers or {}
        if self.session:
            return self.session.get(url, headers=h, timeout=self.timeout)
        elif _HAS_HTTPX and httpx:
            with httpx.Client(verify=self.verify_tls) as c:
                return c.get(url, headers=h, timeout=self.timeout)
        else:
            _fallback = hardened_session({})
            return _fallback.get(url, headers=h, timeout=self.timeout, verify=self.verify_tls)

    def scan_url(self, url: str, origin_for_cors: str = None, do_preflight: bool = False) -> t.Dict[str, t.Any]:
        h = {"Origin": origin_for_cors} if origin_for_cors else None
        resp = self._do_get(url, h)

        cov, fnds, pocs = analyze_response_headers(resp, origin_for_cors)

        # Host Header Injection
        fnds.extend(self._test_host_header_injection(url))

        # Cache Poisoning / Forwarded-Host reflection
        fnds.extend(self._test_cache_poisoning(url))

        return {
            "url": url,
            "status": getattr(resp, "status_code", 0),
            "headers": dict(getattr(resp, "headers", {})),
            "coverage": cov,
            "findings": [f.__dict__ for f in fnds],
            "pocs": pocs
        }

    # ------------------------------------------------------------------
    # Host Header Injection — deep variant (password reset, routing, ambiguous)
    # ------------------------------------------------------------------
    _EVIL_HOST = "evil.websecure.internal"

    # Password reset / forgot-password paths commonly vulnerable to host poisoning
    _RESET_PATHS = [
        "/forgot-password", "/reset-password", "/password-reset",
        "/account/password/reset", "/auth/forgot", "/user/forgot-password",
        "/api/auth/forgot-password", "/api/password-reset",
    ]

    def _test_host_header_injection(self, url: str) -> t.List[HeaderFinding]:
        findings = []
        parsed = urlparse(url)
        real_host = parsed.netloc
        base = f"{parsed.scheme}://{real_host}"

        # --- Variant set: (header_dict, technique_name) ---
        inject_variants = [
            # Classic reflection tests
            ({"Host": self._EVIL_HOST},                                          "Host override"),
            ({"Host": f"{real_host}.{self._EVIL_HOST}"},                         "Host subdomain append"),
            ({"Host": real_host, "X-Forwarded-Host": self._EVIL_HOST},          "X-Forwarded-Host"),
            ({"Host": real_host, "X-Host": self._EVIL_HOST},                    "X-Host"),
            ({"Host": real_host, "X-Original-Host": self._EVIL_HOST},           "X-Original-Host"),
            ({"Host": real_host, "X-Forwarded-Server": self._EVIL_HOST},        "X-Forwarded-Server"),
            # Port injection: trick app into building URLs with evil port
            ({"Host": f"{real_host}:1337"},                                      "Host port injection"),
            # Absolute-URL routing bypass (some proxies forward the absolute URL)
            ({"Host": self._EVIL_HOST, "X-Forwarded-Proto": "https"},           "Host+Proto override"),
            # Duplicate Host (first vs last server behavior)
            ({"Host": real_host, "X-Real-Host": self._EVIL_HOST},               "X-Real-Host"),
        ]

        for inject_headers, technique in inject_variants:
            try:
                resp = self._do_get(url, inject_headers)
                body = (getattr(resp, "text", "") or "")[:8000]
                resp_headers = dict(getattr(resp, "headers", {}))
                location = resp_headers.get("Location", "")
                set_cookie = resp_headers.get("Set-Cookie", "")

                if self._EVIL_HOST in body or self._EVIL_HOST in location or self._EVIL_HOST in set_cookie:
                    injected_val = next(
                        (v for v in inject_headers.values() if self._EVIL_HOST in v), self._EVIL_HOST
                    )
                    injected_key = next(
                        (k for k, v in inject_headers.items() if self._EVIL_HOST in v), "Host"
                    )
                    findings.append(HeaderFinding(
                        title="Host Header Injection",
                        severity="High",
                        description=(
                            f"[{technique}] Server reflects injected Host value into response. "
                            "Enables: password-reset link hijacking, web cache poisoning, SSRF routing."
                        ),
                        evidence={
                            "technique": technique,
                            "injected_header": injected_key,
                            "injected_value": injected_val,
                            "location": location[:200],
                            "body_snippet": body[:300],
                        },
                        recommendation=(
                            "Validate the Host header against a strict server-side whitelist. "
                            "Never use the Host header to construct URLs in responses or emails."
                        ),
                        tags=["Host-Header", "Cache-Poisoning", "SSRF"],
                    ))
                    add_result("offensive", {
                        "type": "Host Header Injection",
                        "severity": "High",
                        "url": url,
                        "technique": technique,
                        "parameter": injected_key,
                        "payload": injected_val,
                        "evidence": body[:300],
                        "cwe": "CWE-20",
                        "owasp": "A03:2021",
                    })
                    break
            except Exception:
                continue

        # --- Password reset link poisoning ---
        findings.extend(self._test_password_reset_poisoning(base))
        return findings

    def _test_password_reset_poisoning(self, base: str) -> t.List[HeaderFinding]:
        """
        Test password reset endpoints for Host header poisoning.
        A vulnerable server will embed the injected host in the reset email link.
        We detect this by checking if the injected value appears in the response body.
        """
        findings = []
        for path in self._RESET_PATHS:
            url = base.rstrip("/") + path
            try:
                # First probe: GET to check if endpoint exists
                r_check = self.session.get(url, timeout=5, verify=False, allow_redirects=True)
                if r_check.status_code in (404, 410):
                    continue

                # Poison probe: POST with injected Host + dummy email
                poison_headers = {
                    "Host": self._EVIL_HOST,
                    "X-Forwarded-Host": self._EVIL_HOST,
                }
                r_poison = self.session.post(
                    url,
                    data={"email": "test@example.com", "username": "test"},
                    headers=poison_headers,
                    timeout=8,
                    verify=False,
                    allow_redirects=True,
                )
                body = (r_poison.text or "")[:5000]
                if self._EVIL_HOST in body:
                    findings.append(HeaderFinding(
                        title="Password Reset Poisoning via Host Header",
                        severity="Critical",
                        description=(
                            f"Password reset endpoint {path} reflects injected Host header in response. "
                            "An attacker can poison reset emails to point to an evil server, "
                            "stealing victim reset tokens."
                        ),
                        evidence={
                            "path": path,
                            "injected_host": self._EVIL_HOST,
                            "body_snippet": body[:300],
                        },
                        recommendation=(
                            "Build password reset URLs from a server-side configured base URL, "
                            "never from the request's Host header."
                        ),
                        tags=["Host-Header", "Password-Reset", "Account-Takeover"],
                    ))
                    add_result("offensive", {
                        "type": "Password Reset Poisoning via Host Header",
                        "severity": "Critical",
                        "url": url,
                        "payload": self._EVIL_HOST,
                        "evidence": body[:300],
                        "cwe": "CWE-640",
                        "owasp": "A07:2021",
                    })
                    break
            except Exception:
                continue
        return findings

    # ------------------------------------------------------------------
    # Cache Poisoning — deep variant (unkeyed headers, fat GET, param cloaking,
    #                                 cache deception, DoS-via-cache)
    # ------------------------------------------------------------------
    _CACHE_POISON_HEADERS = [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Forwarded-Proto",
        "X-Forwarded-For",
        # Additional unkeyed headers often present in CDN/reverse proxy stacks
        "X-Host",
        "X-Forwarded-Server",
        "X-HTTP-Host-Override",
        "Forwarded",
        "X-Original-Forwarded-For",
        "True-Client-IP",
    ]

    def _test_cache_poisoning(self, url: str) -> t.List[HeaderFinding]:
        findings = []
        import random
        import string
        # Use a unique canary per scan run to avoid cross-test pollution
        canary = "wscache" + "".join(random.choices(string.ascii_lowercase, k=6)) + ".internal"
        parsed = urlparse(url)

        # --- 1. Unkeyed header reflection ---
        for header_name in self._CACHE_POISON_HEADERS:
            header_val = canary if "For" not in header_name else f"1.2.3.4, {canary}"
            try:
                # Add a cache-buster query param to avoid polluting live cache
                bust_url = url + ("&" if parsed.query else "?") + f"cb={canary[:8]}"
                resp = self._do_get(bust_url, {header_name: header_val})
                body = (getattr(resp, "text", "") or "")[:8000]
                resp_h = dict(getattr(resp, "headers", {}))
                location = resp_h.get("Location", "")

                if canary in body or canary in location:
                    cache_control = resp_h.get("Cache-Control", "")
                    age = resp_h.get("Age", "")
                    cacheable = "no-store" not in cache_control and "private" not in cache_control

                    severity = "Critical" if cacheable else "High"
                    findings.append(HeaderFinding(
                        title="Web Cache Poisoning — Unkeyed Header Reflection",
                        severity=severity,
                        description=(
                            f"Header '{header_name}' is reflected into the response and is NOT "
                            f"part of the cache key. Cache-Control: {cache_control or 'not set'}. "
                            f"{'Response is cacheable — full poisoning possible.' if cacheable else 'Response marked non-cacheable — limited impact.'}"
                        ),
                        evidence={
                            "header": header_name,
                            "canary": canary,
                            "cache_control": cache_control,
                            "age_header": age,
                            "cacheable": cacheable,
                            "body_snippet": body[:300],
                            "location": location[:200],
                        },
                        recommendation=(
                            "Configure the CDN/cache layer to include all response-influencing headers "
                            "in the cache key, or strip them at the edge before they reach the origin."
                        ),
                        tags=["Cache-Poisoning", "Unkeyed-Header"],
                    ))
                    add_result("offensive", {
                        "type": "Web Cache Poisoning",
                        "severity": severity,
                        "url": url,
                        "technique": "unkeyed_header",
                        "parameter": header_name,
                        "payload": header_val,
                        "evidence": body[:300],
                        "cwe": "CWE-444",
                        "owasp": "A05:2021",
                    })
                    break
            except Exception:
                continue

        # --- 2. Fat GET attack (body parameter overrides query string) ---
        findings.extend(self._test_fat_get(url, canary))

        # --- 3. Parameter cloaking (semicolon delimiter) ---
        findings.extend(self._test_param_cloaking(url, canary))

        # --- 4. Web cache deception ---
        findings.extend(self._test_cache_deception(url))

        return findings

    def _test_fat_get(self, url: str, canary: str) -> t.List[HeaderFinding]:
        """
        Fat GET: send a GET request with a body parameter that may override
        the URL query string on the origin, but the cache key only uses the URL.
        """
        findings = []
        parsed = urlparse(url)
        qs_params = dict(parse_qsl(parsed.query))
        if not qs_params:
            return findings  # Need query params to test

        for param_name in list(qs_params.keys())[:3]:
            try:
                # Baseline
                base_resp = self.session.get(url, timeout=6, verify=False)
                base_body = (base_resp.text or "")[:5000]

                # Fat GET: same URL, but body overrides param
                fat_resp = self.session.request(
                    "GET", url,
                    data={param_name: canary},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=6, verify=False,
                )
                fat_body = (fat_resp.text or "")[:5000]
                if canary in fat_body and canary not in base_body:
                    findings.append(HeaderFinding(
                        title="Web Cache Poisoning — Fat GET Body Override",
                        severity="High",
                        description=(
                            f"Parameter '{param_name}' in GET request body overrides the URL query "
                            "string value on the origin. If the cache keys only on the URL, "
                            "an attacker can poison the cache with a body-injected value."
                        ),
                        evidence={
                            "param": param_name,
                            "canary": canary,
                            "body_snippet": fat_body[:300],
                        },
                        recommendation=(
                            "Configure cache to treat GET-with-body as non-cacheable, "
                            "or normalize requests before caching."
                        ),
                        tags=["Cache-Poisoning", "Fat-GET"],
                    ))
                    add_result("offensive", {
                        "type": "Web Cache Poisoning — Fat GET",
                        "severity": "High",
                        "url": url,
                        "technique": "fat_get",
                        "parameter": param_name,
                        "evidence": fat_body[:300],
                        "cwe": "CWE-444",
                    })
            except Exception:
                continue
        return findings

    def _test_param_cloaking(self, url: str, canary: str) -> t.List[HeaderFinding]:
        """
        Parameter cloaking: use semicolon as separator to inject a hidden parameter
        that the origin sees but the cache ignores.
        e.g. /search?q=legit;evil=<canary>
        """
        findings = []
        parsed = urlparse(url)
        if not parsed.query:
            return findings

        try:
            # Inject via semicolon after existing query
            cloak_url = url + f";wscachecloak={canary}"
            resp = self.session.get(cloak_url, timeout=6, verify=False)
            body = (resp.text or "")[:5000]
            if canary in body:
                findings.append(HeaderFinding(
                    title="Web Cache Poisoning — Parameter Cloaking",
                    severity="High",
                    description=(
                        "Semicolon-delimited parameter is reflected in response but may be "
                        "invisible to the cache key parser. Allows cache key normalization bypass."
                    ),
                    evidence={"canary": canary, "cloak_url": cloak_url, "body_snippet": body[:300]},
                    recommendation=(
                        "Ensure the cache normalizes all URL parameter delimiters consistently "
                        "with the origin server."
                    ),
                    tags=["Cache-Poisoning", "Param-Cloaking"],
                ))
                add_result("offensive", {
                    "type": "Web Cache Poisoning — Parameter Cloaking",
                    "severity": "High",
                    "url": url,
                    "technique": "param_cloaking",
                    "evidence": body[:300],
                    "cwe": "CWE-444",
                })
        except Exception as _fix_e:
            _logger.debug(f"[scanners.infrastructure] {type(_fix_e).__name__}: {_fix_e!r}")
        return findings

    def _test_cache_deception(self, url: str) -> t.List[HeaderFinding]:
        """
        Web Cache Deception: append a static-looking path extension to a dynamic
        authenticated page to trick the cache into storing authenticated content.
        e.g. /account → /account/nonexistent.css
        """
        findings = []
        parsed = urlparse(url)
        base_path = parsed.path.rstrip("/") or "/"
        deception_suffixes = [
            f"{base_path}/ws_cache_test.css",
            f"{base_path}/ws_cache_test.js",
            f"{base_path}/ws_cache_test.jpg",
            f"{base_path}/ws_cache_test.png",
        ]
        try:
            # Baseline: original URL
            base_resp = self.session.get(url, timeout=6, verify=False)
            base_status = base_resp.status_code
            base_body = (base_resp.text or "")[:3000]
            if base_status not in (200,):
                return findings
            # Check if baseline contains any sensitive markers
            sensitive_markers = ["email", "username", "account", "profile", "password", "token"]
            has_sensitive = any(m in base_body.lower() for m in sensitive_markers)
            if not has_sensitive:
                return findings

            for suffix_url in deception_suffixes[:2]:
                deception_url_full = f"{parsed.scheme}://{parsed.netloc}{suffix_url}"
                try:
                    dec_resp = self.session.get(deception_url_full, timeout=6, verify=False)
                    dec_body = (dec_resp.text or "")[:3000]
                    if dec_resp.status_code == 200 and any(m in dec_body.lower() for m in sensitive_markers):
                        cache_ctrl = dec_resp.headers.get("Cache-Control", "")
                        if "no-store" not in cache_ctrl and "private" not in cache_ctrl:
                            findings.append(HeaderFinding(
                                title="Web Cache Deception",
                                severity="High",
                                description=(
                                    f"Authenticated page content served at {suffix_url} with a "
                                    "static file extension. If cached, any user requesting this URL "
                                    "will receive the victim's authenticated response."
                                ),
                                evidence={
                                    "deception_url": deception_url_full,
                                    "cache_control": cache_ctrl,
                                    "body_snippet": dec_body[:300],
                                },
                                recommendation=(
                                    "Configure the cache to never store responses for authenticated pages. "
                                    "Use Cache-Control: no-store, private on all authenticated endpoints."
                                ),
                                tags=["Cache-Deception", "Auth-Bypass"],
                            ))
                            add_result("offensive", {
                                "type": "Web Cache Deception",
                                "severity": "High",
                                "url": deception_url_full,
                                "technique": "cache_deception",
                                "evidence": dec_body[:300],
                                "cwe": "CWE-525",
                            })
                            break
                except Exception:
                    continue
        except Exception as _fix_e:
            _logger.debug(f"[scanners.infrastructure] {type(_fix_e).__name__}: {_fix_e!r}")
        return findings

# ============================================================================
# SECTION 2: TLS SCANNER (formerly tls.py)
# ============================================================================

@dataclass
class CertificateReport:
    host: str
    port: int
    scheme: str
    subject_CN: t.Optional[str]
    issuer_CN: t.Optional[str]
    issuer_O: t.Optional[str]
    not_before: str
    not_after: str
    days_remaining: int
    san: list[str]
    problems: list[str]
    valid: bool
    tls_version: t.Optional[str] = None
    alpn: t.Optional[str] = None
    fingerprint_sha256: t.Optional[str] = None
    self_signed: t.Optional[bool] = None

def _extract_cert_details_from_obj(cert) -> dict:
    """Extract certificate details from a cryptography cert object."""
    if not _HAS_CRYPTO or cert is None:
        return {}
    try:
        def _get_name(name, oid):
            att = name.get_attributes_for_oid(oid)
            return att[0].value if att else None

        sub_cn = _get_name(cert.subject, x509.NameOID.COMMON_NAME)
        iss_cn = _get_name(cert.issuer, x509.NameOID.COMMON_NAME)
        iss_o  = _get_name(cert.issuer, x509.NameOID.ORGANIZATION_NAME)

        nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
        na = cert.not_valid_after_utc  if hasattr(cert, "not_valid_after_utc")  else cert.not_valid_after

        fp = cert.fingerprint(hashlib.sha256()).hex()

        # Subject Alternative Names
        san_list: t.List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound as _fix_e:
            _logger.debug(f"[scanners.infrastructure] {type(_fix_e).__name__}: {_fix_e!r}")

        return {
            "subject_CN":  sub_cn,
            "issuer_CN":   iss_cn,
            "issuer_O":    iss_o,
            "not_before":  nb.isoformat(),
            "not_after":   na.isoformat(),
            "serial":      str(cert.serial_number),
            "fingerprint": fp,
            "san":         list(san_list),
        }
    except Exception as e:
        _logger.warning(f"Cert parsing error: {e}")
        return {}


def _extract_cert_details(der_data: bytes) -> dict:
    """Parses DER bytes using cryptography library to extract detailed info."""
    if not _HAS_CRYPTO or not der_data:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der_data, default_backend())
        return _extract_cert_details_from_obj(cert)
    except Exception as e:
        _logger.warning(f"DER cert parsing error: {e}")
        return {}

def _normalize_host(url: str) -> t.Tuple[str, int, str]:
    if "://" not in url: url = "https://" + url
    p = urlparse(url)
    h = p.hostname or url
    sch = p.scheme or "https"
    pt = p.port or (443 if sch == "https" else 80)
    return h, pt, sch

def _parse_dt_openssl(s: str) -> datetime:
    s = " ".join(s.split())
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")

def _host_matches_san(host: str, san: t.Iterable[str]) -> bool:
    host = (host or "").lower()
    for name in (san or []):
        n = (name or "").lower()
        if n.startswith("*."):
            if host.endswith(n[1:]) and host.count(".") >= n[1:].count("."): return True
        elif host == n: return True
    return False

class PySSLCertChecker:
    def __init__(self, session=None):
        self._session = session  # optional SmartSession for SSL validation probe

    def check(self, url: str, *, timeout: int = 10) -> CertificateReport:
        host, port, scheme = _normalize_host(url)
        if scheme == "http":
            return CertificateReport(host, port, scheme, None, None, None, "", "", 0, [], ["no_tls"], False)

        ctx = pyssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = pyssl.CERT_NONE  # Verify yoksa binary form almaya çalışacağız veya opsiyonel yapacağız

        der = None
        ver = None
        alpn = None
        problems = []
        
        # 1. Deneme: Düşük seviye socket ile binary sertifika alma (cryptography için)
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    try:
                        der = ss.getpeercert(binary_form=True)
                    except ValueError:
                         # Bazen verify_mode=CERT_NONE iken binary_form desteklenmez, tekrar deneriz
                         pass
                        
                    ver = ss.version()
                    alpn = ss.selected_alpn_protocol()
        except Exception as e:
            # Hata durumunda hemen pes etme, alternatif yöntemi dene
            problems.append(f"Socket connection error: {e}")

        # 2. Fallback: ssl.get_server_certificate returns PEM string
        if not der:
            try:
                pem = pyssl.get_server_certificate((host, port), timeout=timeout)
                if pem and _HAS_CRYPTO:
                    try:
                        _pem_cert = x509.load_pem_x509_certificate(
                            pem.encode("utf-8"), default_backend()
                        )
                        # Convert PEM cert to DER bytes for _extract_cert_details
                        der = _pem_cert.public_bytes(_CryptoEncoding.DER)
                    except Exception as ex:
                        problems.append(f"PEM parsing error: {ex}")
            except Exception as e:
                problems.append(f"Alternative cert fetch failed: {e}")

        # Detayları çıkar
        details = {}
        if der:
            details = _extract_cert_details(der)
            # Validasyon başarılı varsayımı (detay alabildik)
            if not problems: 
                # Sorun listesi boş değilse bile sertifika aldıysak validasyonu ayrıca kontrol edelim
                pass 
        else:
             problems.append("Could not retrieve certificate details.")

        # Eğer cryptography yoksa veya detaylar boşsa, standart yöntem (CERT_OPTIONAL/REQUIRED) ile text almak deneyebiliriz
        # Ancak verify=NONE iken text dict boş döner. O yüzden verify gerektirir ama self-signed ise patlar.
        # Şimdilik cryptography varsa detayları alıyoruz, yoksa sınırlı bilgi dönüyoruz.
       
        valid = False
        try:
            # Basit doğrulama kontrolü — verify=True (default) to check cert validity
            _getter = (self._session.get if self._session is not None else hardened_session({}).get)
            _getter(url, timeout=timeout)
            valid = True
        except requests.exceptions.SSLError:
            valid = False
            problems.append("Certificate validation failed (Self-signed or expired).")
        except Exception as exc:
            valid = False
            
        nb = details.get("not_before", "")
        na = details.get("not_after", "")

        days = 0
        if na:
            try:
                from datetime import timezone
                dt_na = datetime.fromisoformat(na)
                if dt_na.tzinfo is None:
                    dt_na = dt_na.replace(tzinfo=timezone.utc)
                days = (dt_na - datetime.now(timezone.utc)).days
            except Exception as exc:
                _logger.debug(f"[scanners.infrastructure] {type(exc).__name__}: {exc!r}")

        return CertificateReport(
            host=host, port=port, scheme=scheme,
            subject_CN=details.get("subject_CN"),
            issuer_CN=details.get("issuer_CN"),
            issuer_O=details.get("issuer_O"),
            not_before=nb,
            not_after=na,
            days_remaining=days,
            san=details.get("san", []),      # extracted from SAN extension
            problems=problems,
            valid=valid,
            tls_version=ver,
            alpn=alpn,
            fingerprint_sha256=details.get("fingerprint"),
            self_signed=not valid,
        )

# ============================================================================
# SECTION 3: UNIFIED PUBLIC API
# ============================================================================

def get_security_headers(url: str, results: dict, session=None, debug=False, origin_for_cors=None, do_preflight=False):
    scanner = HeaderScanner(session=session, timeout=15.0)
    out = scanner.scan_url(url, origin_for_cors=origin_for_cors, do_preflight=do_preflight)
    
    if isinstance(results, dict):
        results.setdefault("security_headers", []).append(out)
        
    return out

def check_ssl_certificate(url: str, *, timeout=10, config=None, session=None, hsts_header=None):
    # Retrieve cert report
    host, port, sch = _normalize_host(url)
    checker = PySSLCertChecker()
    rep = checker.check(url, timeout=timeout)
    
    # Analyze
    problems = list(rep.problems)
    
    # HSTS check
    hsts_on = bool(hsts_header)
    if hsts_header is None:
        # Probe HEAD
        try:
            s = session or hardened_session({})
            r = s.head("https://" + host, timeout=5, verify=False)
            hsts_on = "strict-transport-security" in r.headers.keys() or "Strict-Transport-Security" in r.headers
        except Exception as exc:
            _logger.debug(f"[scanners.infrastructure] {type(exc).__name__}: {exc!r}")
            
    # TLS version weakness
    tls_warnings: t.List[str] = []
    if rep.tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        tls_warnings.append(f"Weak TLS version negotiated: {rep.tls_version} — upgrade to TLS 1.2+")
        problems.append(f"Weak TLS: {rep.tls_version}")

    # Certificate expiry warning
    if rep.days_remaining < 0:
        problems.append("Certificate is EXPIRED")
    elif rep.days_remaining < 30:
        tls_warnings.append(f"Certificate expires in {rep.days_remaining} days")

    # Self-signed
    if rep.self_signed:
        tls_warnings.append("Certificate appears self-signed — browser will show security warning")

    return {
        "host": host, "port": port, "scheme": sch,
        "valid": rep.valid and not problems,
        "problems": problems,
        "warnings": tls_warnings,
        "hsts": hsts_on,
        "tls_version": rep.tls_version,
        "fingerprint": rep.fingerprint_sha256,
        "subject_CN": rep.subject_CN,
        "issuer_CN": rep.issuer_CN,
        "issuer_O": rep.issuer_O,
        "not_before": rep.not_before,
        "not_after": rep.not_after,
        "days_remaining": rep.days_remaining,
        "san": rep.san,
        "self_signed": rep.self_signed,
    }

def scan_tls(url: str, *, results=None, session=None, config=None, debug=False) -> t.Dict[str, t.Any]:
    if not results: results = {}
    
    # Headers
    h_info = get_security_headers(url, results, session, debug)
    hsts_on = bool((h_info.get("headers") or {}).get("Strict-Transport-Security"))
    
    # Cert
    c_info = check_ssl_certificate(url, session=session, config=config, hsts_header=hsts_on)
    
    results.setdefault("tls", {})["certificate"] = c_info
    results.setdefault("tls", {})["headers"] = h_info
    
    return {"headers": h_info, "certificate": c_info}

# Plugin registry compat alias
run = scan_tls
