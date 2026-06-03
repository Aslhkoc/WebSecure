"""
websecure.scanners.bypass_403
------------------------------
HTTP 403 / Forbidden Bypass scanner.

Classes:
  PathNormalizationBypass  — Path manipulation techniques
  HeaderInjectionBypass    — Custom headers to spoof trusted origins
  VerbTamperingBypass      — HTTP method tampering
  EncodingBypass           — URL encoding / double-encoding tricks
  APIVersionBypass         — API version / path variant bypass
  ContentTypeBypass        — Content-Type header switching bypass
  AcceptHeaderBypass       — Accept / Accept-Language / Accept-Encoding bypass
  FourOhThreeScanner       — Orchestrator
"""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitive paths probed for initial 403/401 discovery
# ---------------------------------------------------------------------------
_SENSITIVE_PATHS: List[str] = [
    "/admin",
    "/admin/",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/.git/HEAD",
    "/config",
    "/backup",
    "/api/admin",
    "/api/v1/admin",
    "/console",
    "/actuator",
    "/actuator/env",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/web.config",
]

_BLOCKED_STATUSES = {401, 403}


def _body_length_diff_pct(a: Optional[str], b: Optional[str]) -> float:
    """Return the relative difference between two response bodies as a fraction [0..1]."""
    if not a and not b:
        return 0.0
    la = len(a or "")
    lb = len(b or "")
    mx = max(la, lb, 1)
    return abs(la - lb) / mx


def _join_url(base: str, path: str) -> str:
    """Join base URL and path segment safely."""
    return base.rstrip("/") + "/" + path.lstrip("/")


def _path_variants(path: str) -> List[str]:
    """
    Generate path normalisation bypass variants for *path*.
    e.g. /admin -> /admin/., /admin/./, //admin/, etc.
    """
    # Determine the last segment (e.g. "admin") and whether it ends with /
    p = path.rstrip("/")
    seg = p.lstrip("/") or "admin"

    variants: List[str] = [
        # dot-segment
        f"/{seg}/.",
        f"/{seg}/./",
        f"/{seg}//",
        f"//{seg}/",
        f"/./{seg}/",
        # case variants
        f"/{seg.upper()}/",
        f"/{seg.capitalize()}/",
        f"/{seg[:2].upper()}{seg[2:]}/",
        # trailing slash difference
        f"/{seg}",
        f"/{seg}/",
        f"/{seg}?/",
        # path parameters
        f"/{seg};bypass",
        f"/{seg};.bypass",
        f"/{seg}/;/",
        # null byte
        f"/{seg}%00",
        f"/{seg}%00.html",
        # dot-segment overlong
        f"/{seg}/../{seg}/",
        f"/{seg}/%2e/",
        f"/{seg}/..;/",
        # Unicode / percent a = \x61
        f"/%61{'dmin' if seg == 'admin' else seg[1:]}/",
        # double-slash
        f"//{seg}//",
        # overlong encoding
        f"/%c0%ae%c0%ae/{seg}",
        # self-reference
        f"/{seg}/./",
        # tab / space
        f"/{seg}%09/",
        f"/{seg}%20",
    ]
    # Augment with PathMutator variants from evasion module
    try:
        from websecure.core.evasion import path_variants as _pv
        variants.extend(_pv(path))
    except (ImportError, Exception) as _fix_e:
        logger.debug(f"[scanners.bypass_403] {type(_fix_e).__name__}: {_fix_e!r}")

    # deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for v in variants:
        if v not in seen and v != path:
            seen.add(v)
            unique.append(v)
    return unique


# ===========================================================================
# 1. PathNormalizationBypass
# ===========================================================================
class PathNormalizationBypass(BaseScanner):
    """
    Path manipulation bypass techniques.

    For each blocked (403/401) path, generate normalisation variants and
    compare the response status/body against the baseline.  A status change
    to 200/301/302 is a confirmed bypass; a significant body-length
    difference (> 20 %) is flagged as a potential bypass.
    """

    name = "bypass_path"

    def run(self, target: str, blocked_paths: Optional[List[Tuple[str, int]]] = None, **kwargs) -> List[Dict]:
        """
        Parameters
        ----------
        target:
            Base URL (scheme + host), e.g. ``https://example.com``.
        blocked_paths:
            Pre-discovered list of (path, baseline_status) tuples.
            If not provided, ``_SENSITIVE_PATHS`` is probed internally.
        """
        results: List[Dict] = []
        if blocked_paths is None:
            blocked_paths = self._discover_blocked(target)

        for path, baseline_status in blocked_paths:
            baseline_body = self._fetch_body(target, path)
            variants = _path_variants(path)
            for variant in variants:
                try:
                    url = _join_url(target, variant.lstrip("/"))
                    resp = self.session.get(url, timeout=7, verify=False, allow_redirects=False)
                    status = resp.status_code
                    body = resp.text

                    if status in (200, 301, 302):
                        if status in (301, 302):
                            location = resp.headers.get("Location", "").lower()
                            _auth_paths = ("/login", "/auth", "/sign", "/error",
                                           "/403", "/401", "/forbidden", "/access-denied")
                            if any(p in location for p in _auth_paths):
                                continue  # redirect to auth page — not a bypass
                        finding = {
                            "vuln_type": "403 Bypass — Path Normalisation (Confirmed)",
                            "url": url,
                            "severity": "Critical",
                            "description": (
                                f"Path normalisation variant bypassed {baseline_status} on "
                                f"'{path}'. Variant '{variant}' returned HTTP {status}."
                            ),
                            "evidence": {
                                "original_path": path,
                                "bypass_variant": variant,
                                "baseline_status": baseline_status,
                                "bypass_status": status,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                    elif _body_length_diff_pct(baseline_body, body) > 0.20 and status not in _BLOCKED_STATUSES:
                        finding = {
                            "vuln_type": "403 Bypass — Path Normalisation (Potential)",
                            "url": url,
                            "severity": "High",
                            "description": (
                                f"Path variant '{variant}' for '{path}' returned HTTP {status} "
                                f"with significantly different body (>{20}% length diff). "
                                "Possible partial bypass."
                            ),
                            "evidence": {
                                "original_path": path,
                                "bypass_variant": variant,
                                "baseline_status": baseline_status,
                                "probe_status": status,
                                "body_diff_pct": round(_body_length_diff_pct(baseline_body, body) * 100, 1),
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                except Exception as exc:
                    logger.debug("[bypass_path] %s variant=%s: %s", path, variant, exc)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover_blocked(self, target: str) -> List[Tuple[str, int]]:
        """Probe ``_SENSITIVE_PATHS`` and return those returning 401/403."""
        blocked: List[Tuple[str, int]] = []
        for path in _SENSITIVE_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=6, verify=False, allow_redirects=False)
                if resp.status_code in _BLOCKED_STATUSES:
                    blocked.append((path, resp.status_code))
                    logger.debug("[bypass_path] Blocked (%d): %s", resp.status_code, url)
            except Exception as exc:
                logger.debug("[bypass_path] discover %s: %s", url, exc)
        return blocked

    def _fetch_body(self, target: str, path: str) -> str:
        """Fetch the body of the baseline blocked request (empty string on error)."""
        url = _join_url(target, path.lstrip("/"))
        try:
            resp = self.session.get(url, timeout=6, verify=False, allow_redirects=False)
            return resp.text
        except Exception as exc:
            logger.debug("[bypass_path] fetch_body %s: %s", url, exc)
            return ""


# ===========================================================================
# 2. HeaderInjectionBypass
# ===========================================================================
class HeaderInjectionBypass(BaseScanner):
    """
    Custom header injection to spoof trusted internal/proxy origins.

    Tests headers that server-side middleware may use to allow access from
    trusted networks (load balancers, CDNs, internal proxies).
    """

    name = "bypass_headers"

    _HEADER_SETS: List[Dict[str, str]] = [
        {"X-Original-URL": "{path}"},
        {"X-Rewrite-URL": "{path}"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "localhost"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"Referer": "{base}/internal"},
    ]

    def run(self, target: str, blocked_paths: Optional[List[Tuple[str, int]]] = None, **kwargs) -> List[Dict]:
        """
        Parameters
        ----------
        target:
            Base URL.
        blocked_paths:
            Pre-discovered blocked paths with their baseline status codes.
        """
        results: List[Dict] = []
        if blocked_paths is None:
            blocked_paths = self._discover_blocked(target)

        parsed = urllib.parse.urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path, baseline_status in blocked_paths:
            full_url = _join_url(target, path.lstrip("/"))
            # Also test: sending request to / with path injected via X-Original-URL
            root_url = base_url + "/"

            for header_template in self._HEADER_SETS:
                headers: Dict[str, str] = {}
                is_path_header = False
                for k, v in header_template.items():
                    resolved = v.replace("{path}", path).replace("{base}", base_url)
                    headers[k] = resolved
                    if "{path}" in v:
                        is_path_header = True

                probe_url = root_url if is_path_header else full_url
                try:
                    resp = self.session.get(
                        probe_url, headers=headers,
                        timeout=7, verify=False, allow_redirects=False,
                    )
                    status = resp.status_code
                    if status in (200, 301, 302):
                        finding = {
                            "vuln_type": "403 Bypass — Header Injection (Confirmed)",
                            "url": full_url,
                            "severity": "Critical",
                            "description": (
                                f"Header injection bypassed {baseline_status} on '{path}'. "
                                f"Header(s) {list(headers.keys())} returned HTTP {status}."
                            ),
                            "evidence": {
                                "original_path": path,
                                "injected_headers": headers,
                                "probe_url": probe_url,
                                "baseline_status": baseline_status,
                                "bypass_status": status,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                except Exception as exc:
                    logger.debug("[bypass_headers] %s headers=%s: %s", path, list(headers.keys()), exc)
        return results

    def _discover_blocked(self, target: str) -> List[Tuple[str, int]]:
        blocked: List[Tuple[str, int]] = []
        for path in _SENSITIVE_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=6, verify=False, allow_redirects=False)
                if resp.status_code in _BLOCKED_STATUSES:
                    blocked.append((path, resp.status_code))
            except Exception as exc:
                logger.debug("[bypass_headers] discover %s: %s", url, exc)
        return blocked


# ===========================================================================
# 3. VerbTamperingBypass
# ===========================================================================
class VerbTamperingBypass(BaseScanner):
    """
    HTTP method / verb tampering bypass.

    Some access control middleware only checks GET/POST, leaving other methods
    (HEAD, OPTIONS, TRACE, PUT, etc.) unprotected.  Also tests override headers
    (X-HTTP-Method-Override, _method) which some frameworks honour.
    """

    name = "bypass_verb"

    # (method, extra_headers_or_body)
    _VERBS: List[Tuple[str, Dict[str, Any]]] = [
        ("HEAD", {}),
        ("OPTIONS", {}),
        ("TRACE", {}),
        ("TRACK", {}),
        ("PUT", {}),
        ("PATCH", {}),
        ("DELETE", {}),
        ("CONNECT", {}),
        # POST with method-override headers
        ("POST", {"headers": {"X-HTTP-Method-Override": "GET"}}),
        ("POST", {"headers": {"X-Method-Override": "GET"}}),
        ("POST", {"headers": {"X-HTTP-Method": "PUT"}}),
        # POST with _method body param
        ("POST", {"data": {"_method": "GET"}}),
        # GET with X-HTTP-Method override
        ("GET",  {"headers": {"X-HTTP-Method": "PUT"}}),
    ]

    def run(self, target: str, blocked_paths: Optional[List[Tuple[str, int]]] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        if blocked_paths is None:
            blocked_paths = self._discover_blocked(target)

        for path, baseline_status in blocked_paths:
            url = _join_url(target, path.lstrip("/"))
            for method, extras in self._VERBS:
                req_headers = extras.get("headers", {})
                req_data = extras.get("data", None)
                try:
                    resp = self.session.request(
                        method, url,
                        headers=req_headers,
                        data=req_data,
                        timeout=7,
                        verify=False,
                        allow_redirects=False,
                    )
                    status = resp.status_code

                    # HEAD 200 on a 403 GET is particularly interesting
                    is_interesting = (
                        status not in _BLOCKED_STATUSES
                        and status != 405  # Method Not Allowed — expected
                        and status not in (0, 400, 404, 410)
                    )
                    if is_interesting:
                        note = ""
                        if method == "HEAD" and status == 200:
                            note = " HEAD 200 on a blocked GET path — auth check may be skipped for HEAD."
                        finding = {
                            "vuln_type": "403 Bypass — Verb Tampering",
                            "url": url,
                            "severity": "High",
                            "description": (
                                f"HTTP method '{method}' returned {status} on path '{path}' "
                                f"that blocked GET with {baseline_status}.{note}"
                            ),
                            "evidence": {
                                "original_path": path,
                                "tampered_method": method,
                                "extra_headers": req_headers,
                                "baseline_status": baseline_status,
                                "bypass_status": status,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                except Exception as exc:
                    logger.debug("[bypass_verb] %s %s: %s", method, url, exc)
        return results

    def _discover_blocked(self, target: str) -> List[Tuple[str, int]]:
        blocked: List[Tuple[str, int]] = []
        for path in _SENSITIVE_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=6, verify=False, allow_redirects=False)
                if resp.status_code in _BLOCKED_STATUSES:
                    blocked.append((path, resp.status_code))
            except Exception as exc:
                logger.debug("[bypass_verb] discover %s: %s", url, exc)
        return blocked


# ===========================================================================
# 4. EncodingBypass
# ===========================================================================
class EncodingBypass(BaseScanner):
    """
    URL encoding and Unicode variant bypass techniques.

    Generates encoding variants of each blocked path and checks whether any
    returns a non-403 response, indicating a parser discrepancy.
    """

    name = "bypass_encoding"

    def run(self, target: str, blocked_paths: Optional[List[Tuple[str, int]]] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        if blocked_paths is None:
            blocked_paths = self._discover_blocked(target)

        for path, baseline_status in blocked_paths:
            for enc_path in self._encoding_variants(path):
                url = _join_url(target, enc_path.lstrip("/"))
                try:
                    resp = self.session.get(url, timeout=7, verify=False, allow_redirects=False)
                    status = resp.status_code
                    if status not in _BLOCKED_STATUSES and status not in (0, 400, 404, 410):
                        finding = {
                            "vuln_type": "403 Bypass — Encoding Variant",
                            "url": url,
                            "severity": "High",
                            "description": (
                                f"Encoding variant '{enc_path}' of '{path}' returned HTTP {status} "
                                f"(baseline was {baseline_status}). Parser discrepancy detected."
                            ),
                            "evidence": {
                                "original_path": path,
                                "encoded_variant": enc_path,
                                "baseline_status": baseline_status,
                                "bypass_status": status,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                except Exception as exc:
                    logger.debug("[bypass_encoding] %s -> %s: %s", path, enc_path, exc)
        return results

    # ------------------------------------------------------------------

    @staticmethod
    def _encoding_variants(path: str) -> List[str]:
        """
        Return encoding / Unicode variants of *path*.
        Covers: single-encode, double-encode, Unicode full-width,
        HTML entity-style, hex case variants.
        Also includes EncodingChain variants from evasion module.
        """
        p = path.rstrip("/")
        seg = p.lstrip("/") or "admin"

        variants: List[str] = [
            # Single-encode slash
            f"/%2f{seg}",
            f"/{seg}%2f",
            # Single-encode dot
            f"/%2e{seg}",
            # Double-encode slash
            f"/%252f{seg}",
            f"/{seg}%252f",
            # Double-encode dot
            f"/%252e{seg}",
            # Unicode full-width slash (U+FF0F)  ／
            f"/／{seg}",
            # Unicode full-width asterisk (U+FF0A) ＊
            f"/＊{seg}",
            # HTML entity style (broken parsers)
            f"/&#x2f;{seg}",
            # Hex lowercase
            "/%2fadmin" if seg == "admin" else f"/%2f{seg}",
            # Hex uppercase
            "/%2Fadmin" if seg == "admin" else f"/%2F{seg}",
            # Leading double encode
            f"/%2F{seg}%2F",
        ]

        # Augment with EncodingChain multi-layer variants from evasion module
        try:
            from websecure.core.evasion import encoding_variants as _ev
            variants.extend(_ev(path, depth=2))
        except (ImportError, Exception) as _fix_e:
            logger.debug(f"[scanners.bypass_403] {type(_fix_e).__name__}: {_fix_e!r}")

        # deduplicate
        seen: set = set()
        unique: List[str] = []
        for v in variants:
            if v not in seen and v != path:
                seen.add(v)
                unique.append(v)
        return unique

    def _discover_blocked(self, target: str) -> List[Tuple[str, int]]:
        blocked: List[Tuple[str, int]] = []
        for path in _SENSITIVE_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=6, verify=False, allow_redirects=False)
                if resp.status_code in _BLOCKED_STATUSES:
                    blocked.append((path, resp.status_code))
            except Exception as exc:
                logger.debug("[bypass_encoding] discover %s: %s", url, exc)
        return blocked


# ===========================================================================
# 5. APIVersionBypass
# ===========================================================================
class APIVersionBypass(BaseScanner):
    """
    Attempt to bypass 403 on a path by trying API version prefixes,
    REST alternatives, trailing slashes, extensions, and case variants.

    For each blocked path, generates:
      - Version variants: /v1/PATH, /v2/PATH, /v3/PATH, /api/PATH, /api/v1/PATH, /api/v2/PATH, /rest/PATH, /graphql
      - Trailing slash:   /admin → /admin/
      - Extensions:       /admin → /admin.json, /admin.xml, /admin.html, /admin.php
      - Case variants:    /Admin, /ADMIN, /aDmIn
    """

    name = "bypass_api_version"

    def run(self, target: str, blocked_paths: Optional[List[Tuple[str, int]]] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        if blocked_paths is None:
            blocked_paths = self._discover_blocked(target)

        for path, baseline_status in blocked_paths:
            for variant in self._api_variants(path):
                url = _join_url(target, variant.lstrip("/"))
                try:
                    resp = self.session.get(url, timeout=7, verify=False, allow_redirects=False)
                    status = resp.status_code
                    if status in (200, 301, 302):
                        finding = {
                            "vuln_type": "403 Bypass — API Version / Path Variant (Confirmed)",
                            "url": url,
                            "severity": "Critical",
                            "description": (
                                f"API/path variant '{variant}' bypassed {baseline_status} on "
                                f"'{path}'. Returned HTTP {status}."
                            ),
                            "evidence": {
                                "original_path": path,
                                "bypass_variant": variant,
                                "baseline_status": baseline_status,
                                "bypass_status": status,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                except Exception as exc:
                    logger.debug("[bypass_api_version] %s variant=%s: %s", path, variant, exc)
        return results

    @staticmethod
    def _api_variants(path: str) -> List[str]:
        """Generate API version/path variants for *path*."""
        p = path.rstrip("/")
        seg = p.lstrip("/")

        variants: List[str] = []

        # Version prefix variants
        for prefix in ("/v1", "/v2", "/v3", "/api", "/api/v1", "/api/v2", "/rest"):
            variants.append(f"{prefix}/{seg}")

        # GraphQL as alternative API surface
        variants.append("/graphql")

        # Trailing slash
        if not p.endswith("/"):
            variants.append(f"/{seg}/")

        # Extension variants
        for ext in (".json", ".xml", ".html", ".php"):
            if not seg.endswith(ext):
                variants.append(f"/{seg}{ext}")

        # Case variants
        variants.append(f"/{seg.upper()}/")
        variants.append(f"/{seg.capitalize()}/")
        if len(seg) >= 3:
            variants.append(f"/{seg[:1].upper()}{seg[1:3].lower()}{seg[3:].upper()}/")

        # Deduplicate
        seen: set = set()
        unique: List[str] = []
        for v in variants:
            if v not in seen and v != path:
                seen.add(v)
                unique.append(v)
        return unique

    def _discover_blocked(self, target: str) -> List[Tuple[str, int]]:
        blocked: List[Tuple[str, int]] = []
        for path in _SENSITIVE_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=6, verify=False, allow_redirects=False)
                if resp.status_code in _BLOCKED_STATUSES:
                    blocked.append((path, resp.status_code))
            except Exception as exc:
                logger.debug("[bypass_api_version] discover %s: %s", url, exc)
        return blocked


# ===========================================================================
# 6. ContentTypeBypass
# ===========================================================================
class ContentTypeBypass(BaseScanner):
    """
    Attempt to bypass 403 by sending different Content-Type headers.

    Some WAF/middleware rules are Content-Type specific. Sending an unexpected
    Content-Type may bypass the rule matching and allow access.
    """

    name = "bypass_content_type"

    _CONTENT_TYPES: List[str] = [
        "application/json",
        "application/xml",
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/xml",
        "application/javascript",
    ]

    def run(self, target: str, blocked_paths: Optional[List[Tuple[str, int]]] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        if blocked_paths is None:
            blocked_paths = self._discover_blocked(target)

        for path, baseline_status in blocked_paths:
            url = _join_url(target, path.lstrip("/"))
            for content_type in self._CONTENT_TYPES:
                try:
                    resp = self.session.get(
                        url,
                        headers={"Content-Type": content_type},
                        timeout=7,
                        verify=False,
                        allow_redirects=False,
                    )
                    status = resp.status_code
                    if status in (200, 301, 302):
                        finding = {
                            "vuln_type": "403 Bypass — Content-Type Switching (Confirmed)",
                            "url": url,
                            "severity": "Critical",
                            "description": (
                                f"Content-Type '{content_type}' bypassed {baseline_status} on "
                                f"'{path}'. Returned HTTP {status}. "
                                "The access control rule appears to be Content-Type specific."
                            ),
                            "evidence": {
                                "original_path": path,
                                "content_type": content_type,
                                "baseline_status": baseline_status,
                                "bypass_status": status,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                except Exception as exc:
                    logger.debug("[bypass_content_type] %s ct=%s: %s", path, content_type, exc)
        return results

    def _discover_blocked(self, target: str) -> List[Tuple[str, int]]:
        blocked: List[Tuple[str, int]] = []
        for path in _SENSITIVE_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=6, verify=False, allow_redirects=False)
                if resp.status_code in _BLOCKED_STATUSES:
                    blocked.append((path, resp.status_code))
            except Exception as exc:
                logger.debug("[bypass_content_type] discover %s: %s", url, exc)
        return blocked


# ===========================================================================
# 7. AcceptHeaderBypass
# ===========================================================================
class AcceptHeaderBypass(BaseScanner):
    """
    Attempt to bypass 403 by varying Accept, Accept-Language, and Accept-Encoding headers.

    Some access control implementations check Accept headers for API vs browser
    traffic and apply different rules. Varying these headers may circumvent WAF rules.
    """

    name = "bypass_accept"

    _ACCEPT_SETS: List[Dict[str, str]] = [
        {"Accept": "*/*"},
        {"Accept": "application/json"},
        {"Accept": "text/html"},
        {"Accept": "application/xml"},
        {
            "Accept": "text/html",
            "Accept-Language": "en-US,en;q=0.9",
        },
        {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        },
        {
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        },
    ]

    def run(self, target: str, blocked_paths: Optional[List[Tuple[str, int]]] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        if blocked_paths is None:
            blocked_paths = self._discover_blocked(target)

        for path, baseline_status in blocked_paths:
            url = _join_url(target, path.lstrip("/"))
            for accept_headers in self._ACCEPT_SETS:
                try:
                    resp = self.session.get(
                        url,
                        headers=accept_headers,
                        timeout=7,
                        verify=False,
                        allow_redirects=False,
                    )
                    status = resp.status_code
                    if status in (200, 301, 302):
                        finding = {
                            "vuln_type": "403 Bypass — Accept Header Variation (Confirmed)",
                            "url": url,
                            "severity": "High",
                            "description": (
                                f"Accept header set {list(accept_headers.keys())} bypassed "
                                f"{baseline_status} on '{path}'. Returned HTTP {status}. "
                                "The server responds differently based on Accept headers."
                            ),
                            "evidence": {
                                "original_path": path,
                                "accept_headers": accept_headers,
                                "baseline_status": baseline_status,
                                "bypass_status": status,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                except Exception as exc:
                    logger.debug("[bypass_accept] %s headers=%s: %s", path, list(accept_headers.keys()), exc)
        return results

    def _discover_blocked(self, target: str) -> List[Tuple[str, int]]:
        blocked: List[Tuple[str, int]] = []
        for path in _SENSITIVE_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=6, verify=False, allow_redirects=False)
                if resp.status_code in _BLOCKED_STATUSES:
                    blocked.append((path, resp.status_code))
            except Exception as exc:
                logger.debug("[bypass_accept] discover %s: %s", url, exc)
        return blocked


# ===========================================================================
# FourOhThreeScanner — Orchestrator
# ===========================================================================
class FourOhThreeScanner(BaseScanner):
    """
    Orchestrator for all 403/Forbidden bypass techniques.

    Step 1: Discover 403/401 pages by probing common sensitive paths.
    Step 2: Run all bypass sub-scanners against each blocked path:
            PathNormalizationBypass, HeaderInjectionBypass, VerbTamperingBypass,
            EncodingBypass, APIVersionBypass, ContentTypeBypass, AcceptHeaderBypass.
    Step 3: Report confirmed bypasses as Critical, potential bypasses as High.
    """

    name = "bypass_403"

    def run(self, target: str, **kwargs) -> List[Dict]:  # type: ignore[override]
        all_results: List[Dict] = []

        # Step 1: discover blocked paths once (shared across sub-scanners)
        blocked_paths: List[Tuple[str, int]] = []
        logger.debug("[bypass_403] Step 1 — discovering blocked paths on %s", target)
        for path in _SENSITIVE_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=6, verify=False, allow_redirects=False)
                if resp.status_code in _BLOCKED_STATUSES:
                    blocked_paths.append((path, resp.status_code))
                    logger.debug("[bypass_403] Blocked (%d): %s", resp.status_code, url)
            except Exception as exc:
                logger.debug("[bypass_403] probe %s: %s", url, exc)

        if not blocked_paths:
            logger.debug("[bypass_403] No blocked paths found on %s", target)
            return all_results

        logger.debug("[bypass_403] Found %d blocked path(s), running bypass modules.", len(blocked_paths))

        # Step 2: run sub-scanners
        sub_scanners = [
            PathNormalizationBypass(session=self.session, results=self.results, debug=self.debug),
            HeaderInjectionBypass(session=self.session, results=self.results, debug=self.debug),
            VerbTamperingBypass(session=self.session, results=self.results, debug=self.debug),
            EncodingBypass(session=self.session, results=self.results, debug=self.debug),
            APIVersionBypass(session=self.session, results=self.results, debug=self.debug),
            ContentTypeBypass(session=self.session, results=self.results, debug=self.debug),
            AcceptHeaderBypass(session=self.session, results=self.results, debug=self.debug),
        ]

        for scanner in sub_scanners:
            try:
                found = scanner.run(target, blocked_paths=blocked_paths, **kwargs)
                all_results.extend(found)
            except Exception as exc:
                logger.debug("[bypass_403] sub-scanner %s failed: %s", scanner.name, exc)

        return all_results


# ---------------------------------------------------------------------------
# Module-level entry point
# ---------------------------------------------------------------------------

def run(url: str, session=None, results: dict = None, debug: bool = False, **kwargs) -> list:
    """Entry point for the FourOhThreeScanner."""
    scanner = FourOhThreeScanner(session=session, results=results or {}, debug=debug)
    return scanner.run(url, **kwargs)
