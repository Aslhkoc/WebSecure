"""
websecure.scanners.auth_matrix
--------------------------------
Authorization matrix scanner.
Tests every discovered endpoint with each role session.
Flags privilege escalation when lower-privilege roles access restricted resources.
"""
from __future__ import annotations
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from websecure.core.reporting import add_result
from websecure.scanners.base import BaseScanner

_logger = logging.getLogger(__name__)

# HTTP methods to test for each endpoint
_TEST_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

# Response status interpretations
_STATUS_MEANING = {
    200: "allowed",
    201: "allowed",
    204: "allowed",
    301: "redirect",
    302: "redirect",
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    500: "server_error",
}

# Admin-only path indicators
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

        # Determine which roles are privileged vs unprivileged
        role_names = list(role_sessions.keys())
        privileged_roles = [r for r in role_names if any(
            kw in r.lower() for kw in ("admin", "superuser", "root", "manager", "staff")
        )]
        unprivileged_roles = [r for r in role_names if r not in privileged_roles]

        # Test each endpoint
        for endpoint in endpoints[:100]:  # Cap at 100 endpoints
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

            # Analyze for privilege escalation
            privilege_issues = self._analyze_access(
                endpoint, endpoint_results, privileged_roles, unprivileged_roles, is_admin_path
            )
            escalations.extend(privilege_issues)

            # Check for missing authentication (admin path accessible without auth)
            anon_result = endpoint_results.get("anonymous", {})
            if is_admin_path and anon_result.get("status") == 200:
                missing_auth.append({
                    "endpoint": endpoint,
                    "status": 200,
                    "reason": "Admin path accessible without authentication",
                })

        # Store matrix in results
        add_result("auth_matrix", {
            "matrix": matrix,
            "roles_tested": role_names,
            "endpoints_tested": len(matrix),
            "escalations_found": len(escalations),
        })

        # Store individual escalation findings
        for finding in escalations:
            add_result("offensive", finding)
            self.add("offensive", finding)

        # Store missing auth findings
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
        """Analyze role results for privilege escalation."""
        findings = []

        for unpriv in unprivileged_roles:
            unpriv_result = results.get(unpriv, {})
            unpriv_status = unpriv_result.get("status", 0)

            if unpriv_status not in (200, 201):
                continue

            # Check if privileged roles also get 200 (expected behavior - not IDOR)
            # But if the endpoint is admin-only AND unprivileged gets 200 → escalation
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

            # Horizontal escalation: unprivileged accesses something another user owns
            for priv in privileged_roles:
                priv_result = results.get(priv, {})
                priv_status = priv_result.get("status", 0)
                # If admin gets 200 and user also gets 200 with similar response length
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
        """Generate an HTML table for the authorization matrix."""
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
