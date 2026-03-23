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
        except Exception:
            return False

        data = {"username": username, "password": password}
        if csrf_selector and r.ok:
            m = re.search(csrf_selector, r.text or "")
            if m:
                pass  # CSRF token extraction — key name needed for injection

        try:
            r2 = self.session.post(r.url, data=data, timeout=20)
        except Exception:
            return False

        if r2.status_code < 400:
            self.ctx.is_authenticated = True
            self.ctx.last_login_ts = time.time()
            tok = None
            if "json" in r2.headers.get("content-type", ""):
                try:
                    j = r2.json()
                    tok = j.get("token") or j.get("access_token")
                except Exception:
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
        except Exception:
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
    except Exception:
        pass

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
    except Exception:
        pass
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
    Produces an authorization matrix: endpoint × role → HTTP status.
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
            add_result("offensive", finding)
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
            add_result("offensive", finding)
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
