"""
websecure.scanners.business_logic
-----------------------------------
Business Logic Vulnerability scanner.

Classes:
  NegativeValueProber      — Negative quantity/price/amount manipulation
  WorkflowSkipProber       — Multi-step workflow bypass
  PrivilegeEscalationProber — Role/permission parameter tampering
  LimitBypassProber        — Rate limit, coupon, quantity abuse
  BusinessLogicScanner     — Orchestrator
"""
from __future__ import annotations

import json
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from websecure.scanners.base import BaseScanner
from websecure.core.http import hardened_session as _hardened_session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# Common API paths for user/account update
_PROFILE_UPDATE_PATHS = [
    "/api/user/update",
    "/api/users/update",
    "/profile/update",
    "/account/settings",
    "/api/account/update",
    "/api/me/update",
    "/user/settings",
]

# Common login / auth paths for rate-limit tests
_LOGIN_PATHS = ["/login", "/api/login", "/auth/login", "/api/auth/login", "/signin", "/api/signin"]
_RESET_PATHS = [
    "/forgot-password", "/password-reset", "/api/forgot-password",
    "/api/password-reset", "/account/recover",
]

def _join_url(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _indicates_order_accepted(body: str, status: int) -> bool:
    """Heuristic: response suggests a cart/order was accepted."""
    if not _is_success(status):
        return False
    keywords = ["order", "cart", "checkout", "accepted", "success", "confirmed", "placed"]
    body_lower = body.lower()
    return any(kw in body_lower for kw in keywords)


def _value_reflected(body: str, value: str) -> bool:
    """Check whether a submitted value appears in the response body."""
    return str(value) in body


# ===========================================================================
# 1. NegativeValueProber
# ===========================================================================
class NegativeValueProber(BaseScanner):
    """
    Negative / boundary value injection into numeric fields.

    Finds forms and JSON API endpoints with numeric fields
    (quantity, amount, price, total, count, age, discount) and submits
    extreme values including negatives, INT_MIN, MAX_INT, NaN, Infinity.

    A confirmed finding is emitted when the server responds with a success
    status that includes order/cart acceptance language while the negative
    total is reflected in the response.
    """

    name = "neg_value"

    # Numeric boundary payloads as strings (sent as form data)
    _NUMERIC_PAYLOADS_STR: List[str] = [
        "-1",
        "-999",
        "-0.01",
        "-2147483648",  # INT_MIN
        "0",
        "0.001",
        "2147483647",   # INT_MAX
        "9999999",
        "4294967295",   # UINT_MAX
    ]

    # JSON-specific payloads (can include NaN, Infinity as JSON primitives
    # — note: standard JSON doesn't support NaN/Infinity, but many parsers
    # accept them anyway or treat them as null)
    _JSON_PAYLOADS: List[Any] = [
        -1,
        -999,
        -0.01,
        -2147483648,
        0,
        0.001,
        2147483647,
        9999999,
        4294967295,
        1e308,
        1.7976931348623157e+308,
        float("nan"),
        float("inf"),
        float("-inf"),
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        endpoints = self._discover_numeric_endpoints(target)
        for url, method, fields, is_json in endpoints:
            results.extend(self._probe_endpoint(url, method, fields, is_json))
        return results

    # ------------------------------------------------------------------

    def _discover_numeric_endpoints(
        self, target: str
    ) -> List[Tuple[str, str, List[str], bool]]:
        """
        Return list of (url, method, numeric_field_names, is_json_api).

        Probes common cart/order/checkout endpoints and inspects forms
        crawled from the target.
        """
        found: List[Tuple[str, str, List[str], bool]] = []
        candidate_paths = [
            "/api/cart",
            "/api/cart/add",
            "/api/order",
            "/api/order/create",
            "/api/checkout",
            "/cart/add",
            "/shop/cart",
            "/api/v1/cart",
            "/api/v1/order",
        ]
        for path in candidate_paths:
            url = _join_url(target, path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in (404, 410):
                    continue
                # Assume JSON API with standard numeric fields
                found.append((url, "POST", ["quantity", "amount", "price", "discount"], True))
                logger.debug("[neg_value] Candidate endpoint: %s", url)
            except Exception as exc:
                logger.debug("[neg_value] discover %s: %s", url, exc)
        return found

    def _probe_endpoint(
        self,
        url: str,
        method: str,
        fields: List[str],
        is_json: bool,
    ) -> List[Dict]:
        results: List[Dict] = []
        for field in fields:
            if is_json:
                for value in self._JSON_PAYLOADS:
                    results.extend(self._send_json_probe(url, field, value))
            else:
                for value in self._NUMERIC_PAYLOADS_STR:
                    results.extend(self._send_form_probe(url, method, field, value))
        return results

    def _send_json_probe(self, url: str, field: str, value: Any) -> List[Dict]:
        payload: Dict[str, Any] = {field: value, "quantity": value if field != "quantity" else 1}
        try:
            # json.dumps: float("nan") -> "NaN", float("inf") -> "Infinity"
            body = json.dumps(payload, allow_nan=True)
            resp = self.session.post(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                timeout=8,
                verify=False,
            )
            if _indicates_order_accepted(resp.text, resp.status_code) and _value_reflected(resp.text, str(value)):
                finding = {
                    "vuln_type": "Business Logic — Negative/Boundary Value Accepted",
                    "url": url,
                    "severity": "Critical",
                    "description": (
                        f"Field '{field}' accepted value '{value}' and the server responded "
                        f"with HTTP {resp.status_code} indicating order/cart acceptance. "
                        "Server may calculate a negative total or allow free items."
                    ),
                    "evidence": {
                        "field": field,
                        "injected_value": str(value),
                        "status": resp.status_code,
                        "body_excerpt": resp.text[:300],
                    },
                }
                self.report_finding(**finding)
                return [finding]
        except Exception as exc:
            logger.debug("[neg_value] JSON probe %s field=%s value=%s: %s", url, field, value, exc)
        return []

    def _send_form_probe(self, url: str, method: str, field: str, value: str) -> List[Dict]:
        payload = {field: value, "quantity": value if field != "quantity" else "1"}
        try:
            resp = self.session.request(method, url, data=payload, timeout=8, verify=False)
            if _indicates_order_accepted(resp.text, resp.status_code) and _value_reflected(resp.text, value):
                finding = {
                    "vuln_type": "Business Logic — Negative/Boundary Value Accepted (Form)",
                    "url": url,
                    "severity": "Critical",
                    "description": (
                        f"Form field '{field}' accepted value '{value}' and server indicated "
                        f"order/cart acceptance (HTTP {resp.status_code})."
                    ),
                    "evidence": {
                        "field": field,
                        "injected_value": value,
                        "status": resp.status_code,
                        "body_excerpt": resp.text[:300],
                    },
                }
                self.report_finding(**finding)
                return [finding]
        except Exception as exc:
            logger.debug("[neg_value] form probe %s field=%s value=%s: %s", url, field, value, exc)
        return []


# ===========================================================================
# 2. WorkflowSkipProber
# ===========================================================================
class WorkflowSkipProber(BaseScanner):
    """
    Multi-step workflow bypass.

    Detects checkout, registration, and password-reset flows and attempts to
    directly access later steps without completing earlier ones.  Also tests
    parameter-based step tracking (?step=N manipulation).
    """

    name = "workflow_skip"

    # Each tuple: (early_step_path, late_step_path, flow_name)
    _WORKFLOWS: List[Tuple[str, str, str]] = [
        ("/checkout/shipping",      "/checkout/confirm",        "Checkout"),
        ("/checkout/payment",       "/checkout/complete",       "Checkout"),
        ("/register/start",         "/register/verify",         "Registration"),
        ("/register/start",         "/register/complete",       "Registration"),
        ("/password-reset/request", "/password-reset/confirm",  "Password Reset"),
        ("/signup/start",           "/signup/verify",           "Signup"),
        ("/order/shipping",         "/order/confirm",           "Order"),
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []

        # 1. Direct step-access tests (fresh session per check)
        for early_path, late_path, flow in self._WORKFLOWS:
            result = self._probe_direct_skip(target, early_path, late_path, flow)
            if result:
                results.append(result)

        # 2. Parameter-based step manipulation
        results.extend(self._probe_param_step(target))

        return results

    # ------------------------------------------------------------------

    def _probe_direct_skip(
        self, target: str, early_path: str, late_path: str, flow: str
    ) -> Optional[Dict]:
        """
        Try to access *late_path* directly in a fresh session (without visiting
        *early_path* first).  Returns a finding dict if accessible (200).
        """
        late_url = _join_url(target, late_path.lstrip("/"))
        try:
            # Use a brand-new session (no cookies from prior steps)
            fresh_session = _hardened_session({})
            fresh_session.verify = False
            resp = fresh_session.get(late_url, timeout=7, allow_redirects=True)
            if _is_success(resp.status_code):
                finding = {
                    "vuln_type": f"Business Logic — Workflow Skip ({flow})",
                    "url": late_url,
                    "severity": "High",
                    "description": (
                        f"{flow} flow step '{late_path}' is accessible directly "
                        f"(HTTP {resp.status_code}) without completing '{early_path}'. "
                        "Server does not enforce step sequencing."
                    ),
                    "evidence": {
                        "flow": flow,
                        "skipped_step": early_path,
                        "accessed_step": late_path,
                        "status": resp.status_code,
                        "body_excerpt": resp.text[:200],
                    },
                }
                self.report_finding(**finding)
                return finding
        except Exception as exc:
            logger.debug("[workflow_skip] %s -> %s: %s", early_path, late_path, exc)
        return None

    def _probe_param_step(self, target: str) -> List[Dict]:
        """
        Find URLs with ?step=N parameter and attempt to jump to a later step.
        """
        results: List[Dict] = []
        candidate_urls = [
            _join_url(target, "checkout?step=1"),
            _join_url(target, "register?step=1"),
            _join_url(target, "wizard?step=1"),
            _join_url(target, "setup?step=1"),
        ]
        for base_url in candidate_urls:
            try:
                resp_step1 = self.session.get(base_url, timeout=6, verify=False)
                if resp_step1.status_code in (404, 410, 0):
                    continue

                # Jump to step 3 directly
                parsed = urllib.parse.urlparse(base_url)
                qs = dict(urllib.parse.parse_qsl(parsed.query))
                qs["step"] = "3"
                jump_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))
                fresh = _hardened_session({})
                fresh.verify = False
                resp_jump = fresh.get(jump_url, timeout=7)

                if _is_success(resp_jump.status_code):
                    # Compare bodies — if different from step 1, likely real step content
                    body1 = resp_step1.text
                    body3 = resp_jump.text
                    if len(body3) > 50 and body3 != body1:
                        finding = {
                            "vuln_type": "Business Logic — Parameter-Based Step Jump",
                            "url": jump_url,
                            "severity": "High",
                            "description": (
                                f"Directly accessing ?step=3 returned HTTP {resp_jump.status_code} "
                                "with different content than step=1. Workflow enforcement is missing."
                            ),
                            "evidence": {
                                "step1_url": base_url,
                                "jump_url": jump_url,
                                "step1_status": resp_step1.status_code,
                                "jump_status": resp_jump.status_code,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
            except Exception as exc:
                logger.debug("[workflow_skip] param_step %s: %s", base_url, exc)
        return results


# ===========================================================================
# 3. PrivilegeEscalationProber
# ===========================================================================
class PrivilegeEscalationProber(BaseScanner):
    """
    Role / permission parameter tampering and IDOR.

    Searches for privilege-indicating parameters (role, user_type, is_admin,
    etc.) in API responses and forms, then attempts to elevate them by
    submitting elevated values.  Also performs basic IDOR probing on
    sequential user-ID endpoints.
    """

    name = "priv_esc"

    _PRIV_PARAMS: List[str] = [
        "role", "user_type", "account_type", "is_admin", "is_staff",
        "level", "tier", "group", "permission", "access_level",
    ]

    _ELEVATED_VALUES: List[str] = [
        "admin", "true", "1", "superuser", "administrator",
        "staff", "root", "manager", "owner",
    ]

    # Responses that suggest privilege was granted
    _SUCCESS_KEYWORDS = [
        "welcome", "dashboard", "admin", "manage", "settings",
        "control", "privilege", "elevated", "granted",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []

        # 1. Parameter tampering on profile/update endpoints
        results.extend(self._probe_param_tampering(target))

        # 2. IDOR on user-ID endpoints
        results.extend(self._probe_idor(target))

        return results

    # ------------------------------------------------------------------

    def _probe_param_tampering(self, target: str) -> List[Dict]:
        results: List[Dict] = []
        for path in _PROFILE_UPDATE_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                check = self.session.get(url, timeout=5, verify=False)
                if check.status_code in (404, 410):
                    continue
            except Exception as exc:
                logger.debug("[priv_esc] path check %s: %s", url, exc)
                continue

            for param in self._PRIV_PARAMS:
                for value in self._ELEVATED_VALUES:
                    results.extend(
                        self._send_priv_probe(url, param, value)
                    )
        return results

    def _send_priv_probe(self, url: str, param: str, value: str) -> List[Dict]:
        """Try to POST the privilege parameter in multiple casing variants."""
        variants = [
            {param: value},
            {param.capitalize(): value.capitalize()},
            {param.upper(): value.upper()},
            {f"{param}[]": value},
        ]
        results: List[Dict] = []
        for payload in variants:
            try:
                # Try both form and JSON
                for send_json in (False, True):
                    if send_json:
                        resp = self.session.post(
                            url, json=payload, timeout=8, verify=False,
                        )
                    else:
                        resp = self.session.post(
                            url, data=payload, timeout=8, verify=False,
                        )
                    if _is_success(resp.status_code) and self._response_suggests_escalation(resp.text):
                        finding = {
                            "vuln_type": "Business Logic — Privilege Escalation via Parameter Tampering",
                            "url": url,
                            "severity": "Critical",
                            "description": (
                                f"Submitting {{{param}: {value}}} to '{url}' returned "
                                f"HTTP {resp.status_code} with admin/elevated content in body. "
                                "Server may have granted elevated privileges."
                            ),
                            "evidence": {
                                "param": param,
                                "value": value,
                                "payload": payload,
                                "status": resp.status_code,
                                "body_excerpt": resp.text[:300],
                            },
                        }
                        self.report_finding(**finding)
                        results.append(finding)
                        return results  # one confirmed finding per param is enough
            except Exception as exc:
                logger.debug("[priv_esc] tamper %s param=%s val=%s: %s", url, param, value, exc)
        return results

    def _probe_idor(self, target: str) -> List[Dict]:
        """
        Test IDOR: probe /api/users/123 with own session,
        then /api/users/124 (another user's record).
        """
        results: List[Dict] = []
        idor_paths = [
            "/api/users/{id}",
            "/api/user/{id}",
            "/api/accounts/{id}",
            "/api/profile/{id}",
            "/api/v1/users/{id}",
        ]
        for path_template in idor_paths:
            for base_id in (1, 100, 123):
                own_url = _join_url(target, path_template.replace("{id}", str(base_id)).lstrip("/"))
                other_url = _join_url(target, path_template.replace("{id}", str(base_id + 1)).lstrip("/"))
                try:
                    own_resp = self.session.get(own_url, timeout=6, verify=False)
                    if own_resp.status_code in (404, 410, 401, 403):
                        continue

                    other_resp = self.session.get(other_url, timeout=6, verify=False)
                    if _is_success(other_resp.status_code) and other_resp.text != own_resp.text:
                        finding = {
                            "vuln_type": "Business Logic — IDOR (Insecure Direct Object Reference)",
                            "url": other_url,
                            "severity": "High",
                            "description": (
                                f"Accessing '{other_url}' (ID {base_id + 1}) with the same session "
                                f"that owns ID {base_id} returned HTTP {other_resp.status_code}. "
                                "Different body content suggests cross-user data exposure."
                            ),
                            "evidence": {
                                "own_url": own_url,
                                "other_url": other_url,
                                "own_status": own_resp.status_code,
                                "other_status": other_resp.status_code,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        break  # one IDOR per template is enough
                except Exception as exc:
                    logger.debug("[priv_esc] IDOR %s: %s", own_url, exc)
        return results

    def _response_suggests_escalation(self, body: str) -> bool:
        body_lower = body.lower()
        return any(kw in body_lower for kw in self._SUCCESS_KEYWORDS)


# ===========================================================================
# 4. LimitBypassProber
# ===========================================================================
class LimitBypassProber(BaseScanner):
    """
    Rate-limit, coupon, and quantity abuse detection.

    Tests:
    - Coupon / discount applied multiple times in same request
    - Zero-quantity purchase
    - Stock overflow (request more than available)
    - Rate-limit bypass via header rotation (X-Forwarded-For, User-Agent)
    - Free trial abuse (account re-creation)
    """

    name = "limit_bypass"

    _USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/118.0",
        "curl/7.88.1",
        "python-requests/2.28.0",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
    ]

    _FORWARDED_IPS = [
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
        "192.168.1.100", "192.168.1.101", "172.16.0.1", "172.16.0.2",
        "1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16",
        "127.0.0.1", "127.0.0.2",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []

        # Coupon / discount abuse
        results.extend(self._probe_coupon_abuse(target))

        # Quantity manipulation
        results.extend(self._probe_quantity_abuse(target))

        # Rate-limit bypass
        results.extend(self._probe_rate_limit_bypass(target))

        return results

    # ------------------------------------------------------------------

    def _probe_coupon_abuse(self, target: str) -> List[Dict]:
        results: List[Dict] = []
        coupon_paths = [
            "/api/coupon/apply",
            "/api/discount/apply",
            "/api/promo/apply",
            "/cart/coupon",
            "/checkout/coupon",
            "/api/v1/coupon",
        ]
        for path in coupon_paths:
            url = _join_url(target, path.lstrip("/"))
            try:
                check = self.session.get(url, timeout=5, verify=False)
                if check.status_code in (404, 410):
                    continue
            except Exception as exc:
                logger.debug("[limit_bypass] coupon path check %s: %s", url, exc)
                continue

            # Apply same coupon twice in rapid succession
            for code in ["SAVE10", "DISCOUNT20", "FREE100", "TEST"]:
                successes = []
                for _ in range(2):
                    try:
                        resp = self.session.post(
                            url,
                            json={"code": code, "coupon": code, "promo": code},
                            timeout=7,
                            verify=False,
                        )
                        if _is_success(resp.status_code):
                            successes.append(resp.status_code)
                    except Exception as exc:
                        logger.debug("[limit_bypass] coupon probe %s code=%s: %s", url, code, exc)

                if len(successes) >= 2:
                    finding = {
                        "vuln_type": "Business Logic — Coupon Applied Multiple Times",
                        "url": url,
                        "severity": "High",
                        "description": (
                            f"Coupon code '{code}' was accepted {len(successes)} times on the "
                            "same endpoint. Server does not prevent coupon reuse."
                        ),
                        "evidence": {
                            "coupon_code": code,
                            "accepted_count": len(successes),
                            "statuses": successes,
                        },
                    }
                    results.append(finding)
                    self.report_finding(**finding)

            # Apply coupon with negative discount
            try:
                resp = self.session.post(
                    url,
                    json={"code": "SAVE10", "discount": -50},
                    timeout=7,
                    verify=False,
                )
                if _is_success(resp.status_code) and _value_reflected(resp.text, "-50"):
                    finding = {
                        "vuln_type": "Business Logic — Coupon with Negative Discount Accepted",
                        "url": url,
                        "severity": "Critical",
                        "description": (
                            "Server accepted a coupon payload with negative discount=-50. "
                            "This could allow attackers to increase the cart total unexpectedly "
                            "or exploit discount logic reversal."
                        ),
                        "evidence": {
                            "payload": {"code": "SAVE10", "discount": -50},
                            "status": resp.status_code,
                        },
                    }
                    results.append(finding)
                    self.report_finding(**finding)
            except Exception as exc:
                logger.debug("[limit_bypass] neg coupon %s: %s", url, exc)

        return results

    def _probe_quantity_abuse(self, target: str) -> List[Dict]:
        results: List[Dict] = []
        cart_paths = [
            "/api/cart/add",
            "/api/cart",
            "/cart/add",
            "/api/order/item",
            "/api/v1/cart/add",
        ]
        for path in cart_paths:
            url = _join_url(target, path.lstrip("/"))
            try:
                check = self.session.get(url, timeout=5, verify=False)
                if check.status_code in (404, 410):
                    continue
            except Exception as exc:
                logger.debug("[limit_bypass] cart path check %s: %s", url, exc)
                continue

            # Zero quantity
            try:
                resp = self.session.post(
                    url,
                    json={"quantity": 0, "product_id": 1, "item_id": 1},
                    timeout=8,
                    verify=False,
                )
                if _is_success(resp.status_code):
                    finding = {
                        "vuln_type": "Business Logic — Zero Quantity Accepted",
                        "url": url,
                        "severity": "Medium",
                        "description": (
                            f"Server accepted quantity=0 (HTTP {resp.status_code}). "
                            "This may allow adding free items or creating invalid orders."
                        ),
                        "evidence": {"quantity": 0, "status": resp.status_code},
                    }
                    results.append(finding)
                    self.report_finding(**finding)
            except Exception as exc:
                logger.debug("[limit_bypass] zero_qty %s: %s", url, exc)

            # Stock overflow
            try:
                resp = self.session.post(
                    url,
                    json={"quantity": 9999999, "product_id": 1, "item_id": 1},
                    timeout=8,
                    verify=False,
                )
                if _is_success(resp.status_code) and "9999999" in resp.text:
                    finding = {
                        "vuln_type": "Business Logic — Stock Overflow Not Validated",
                        "url": url,
                        "severity": "Medium",
                        "description": (
                            f"Server accepted quantity=9999999 (HTTP {resp.status_code}) and "
                            "reflected the value in the response. No stock limit enforced."
                        ),
                        "evidence": {"quantity": 9999999, "status": resp.status_code},
                    }
                    results.append(finding)
                    self.report_finding(**finding)
            except Exception as exc:
                logger.debug("[limit_bypass] overflow_qty %s: %s", url, exc)

        return results

    def _probe_rate_limit_bypass(self, target: str) -> List[Dict]:
        """
        Rotate User-Agent and X-Forwarded-For headers to test whether rate
        limits are enforced across 20 rapid requests to /login and
        /forgot-password.
        """
        results: List[Dict] = []
        test_endpoints: List[Tuple[str, str, Dict[str, Any]]] = []

        for path in _LOGIN_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=4, verify=False)
                if self.path_exists(r):
                    test_endpoints.append((url, "POST", {"username": "admin", "password": "wrong"}))
                    break
            except Exception as exc:
                logger.debug("[limit_bypass] login path check %s: %s", url, exc)

        for path in _RESET_PATHS:
            url = _join_url(target, path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=4, verify=False)
                if self.path_exists(r):
                    test_endpoints.append((url, "POST", {"email": "test@test.com"}))
                    break
            except Exception as exc:
                logger.debug("[limit_bypass] reset path check %s: %s", url, exc)

        for url, method, payload in test_endpoints:
            result = self._send_rotated_burst(url, method, payload, n=20)
            if result:
                results.append(result)
        return results

    def _send_rotated_burst(
        self,
        url: str,
        method: str,
        payload: Dict[str, Any],
        n: int = 20,
    ) -> Optional[Dict]:
        """
        Send *n* requests with rotating User-Agent and X-Forwarded-For.
        If fewer than 20% of requests are rate-limited (429), flag as bypass.
        """
        statuses: List[int] = []
        ip_pool = self._FORWARDED_IPS
        ua_pool = self._USER_AGENTS

        def _one(idx: int) -> int:
            headers = {
                "User-Agent": ua_pool[idx % len(ua_pool)],
                "X-Forwarded-For": ip_pool[idx % len(ip_pool)],
                "Accept-Language": f"en-US,{idx};q=0.9",
            }
            try:
                resp = self.session.request(
                    method, url, data=payload,
                    headers=headers, timeout=7, verify=False,
                )
                return resp.status_code
            except Exception as exc:
                logger.debug("[limit_bypass] rotated request %s idx=%d: %s", url, idx, exc)
                return 0

        with ThreadPoolExecutor(max_workers=min(n, 10)) as exe:
            futs = {exe.submit(_one, i): i for i in range(n)}
            for fut in as_completed(futs):
                try:
                    statuses.append(fut.result())
                except Exception as exc:
                    logger.debug("[limit_bypass] burst future: %s", exc)

        rate_limited = sum(1 for s in statuses if s == 429)
        non_limited = [s for s in statuses if s not in (429, 503, 0)]

        # If there are some rate-limited AND some non-limited, bypass is partial
        if rate_limited > 0 and len(non_limited) > 2:
            finding = {
                "vuln_type": "Business Logic — Rate-Limit Bypass via Header Rotation",
                "url": url,
                "severity": "High",
                "description": (
                    f"{len(non_limited)}/{n} requests bypassed rate limiting by rotating "
                    "User-Agent and X-Forwarded-For headers. "
                    f"{rate_limited} request(s) were limited — confirming rate limit exists "
                    "but can be partially evaded."
                ),
                "evidence": {
                    "total_requests": n,
                    "rate_limited_count": rate_limited,
                    "bypass_count": len(non_limited),
                    "sample_statuses": statuses[:10],
                },
            }
            self.report_finding(**finding)
            return finding

        # If NO rate limiting whatsoever after 20 requests
        if rate_limited == 0 and len(non_limited) >= int(n * 0.8):
            finding = {
                "vuln_type": "Business Logic — No Rate Limiting Detected",
                "url": url,
                "severity": "Medium",
                "description": (
                    f"{n} rapid requests to '{url}' were all accepted (no 429/503 returned). "
                    "Endpoint appears to have no rate limiting, enabling brute-force attacks."
                ),
                "evidence": {
                    "total_requests": n,
                    "rate_limited_count": 0,
                    "sample_statuses": statuses[:10],
                },
            }
            self.report_finding(**finding)
            return finding

        return None


# ===========================================================================
# BusinessLogicScanner — Orchestrator
# ===========================================================================
class BusinessLogicScanner(BaseScanner):
    """
    Orchestrator for all business logic vulnerability scanners.

    Runs:
    - NegativeValueProber
    - WorkflowSkipProber
    - PrivilegeEscalationProber
    - LimitBypassProber
    """

    name = "business_logic"

    def run(self, target: str, **kwargs) -> List[Dict]:  # type: ignore[override]
        all_results: List[Dict] = []
        probers = [
            NegativeValueProber(session=self.session, results=self.results, debug=self.debug),
            WorkflowSkipProber(session=self.session, results=self.results, debug=self.debug),
            PrivilegeEscalationProber(session=self.session, results=self.results, debug=self.debug),
            LimitBypassProber(session=self.session, results=self.results, debug=self.debug),
        ]
        for prober in probers:
            try:
                logger.debug("[business_logic] Running %s on %s", prober.name, target)
                found = prober.run(target, **kwargs)
                all_results.extend(found)
            except Exception as exc:
                logger.debug("[business_logic] sub-scanner %s failed: %s", prober.name, exc)

        return all_results


# ---------------------------------------------------------------------------
# Module-level entry point
# ---------------------------------------------------------------------------

def run(url: str, session=None, results: dict = None, debug: bool = False, **kwargs) -> list:
    """Entry point for the BusinessLogicScanner."""
    scanner = BusinessLogicScanner(session=session, results=results or {}, debug=debug)
    return scanner.run(url, **kwargs)
