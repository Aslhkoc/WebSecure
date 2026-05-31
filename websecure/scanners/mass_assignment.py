from __future__ import annotations
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseScanner
from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SENSITIVE_KEYS: List[str] = [
    # Privilege escalation
    "is_admin", "isAdmin", "admin", "role", "roles",
    "account_type", "accountType", "type", "is_superuser", "isSuperUser",
    "permissions", "perms", "group", "groups", "privilege", "privileges",
    "access_level", "accessLevel", "user_type", "userType", "staff",
    # Financial manipulation
    "balance", "credit", "credits", "discount", "price", "amount",
    # Account status bypass
    "is_verified", "verified", "is_active", "active", "status",
    "email_verified", "emailVerified", "phone_verified", "phoneVerified",
    # Security bypass fields
    "is_banned", "banned", "suspended", "is_locked", "locked",
    "two_factor_enabled", "twoFactorEnabled", "mfa_enabled", "mfaEnabled",
]

ESCALATION_VALUES: List[Any] = [
    True, 1, "admin", "administrator", "superuser", "root", "staff", "owner",
]

_NESTED_WRAPPERS = ["user", "profile", "account", "data", "payload"]
_NESTED_KEYS = ["role", "is_admin", "admin", "permissions", "type", "account_type"]

_COMMON_API_PATHS = [
    "/api/user", "/api/users/me", "/api/v1/user", "/api/v1/users/me",
    "/api/profile", "/api/account", "/api/me",
    "/user/update", "/users/update", "/profile/update",
    "/api/v2/user", "/api/v2/profile",
]


class MassAssignmentScanner(BaseScanner):
    """
    Mass Assignment / Over-Posting Vulnerability Scanner.

    Techniques:
    - Direct field injection in JSON body: {"is_admin": true}
    - Nested field injection: {"user": {"role": "admin"}}
    - Form-based (urlencoded) mass assignment
    - Field discovery via API endpoint probing
    - Two-phase verification: GET after injection to check persistence
    - Tests POST / PUT / PATCH methods
    - Parallel testing with ThreadPoolExecutor
    """

    name = "mass_assignment"
    MAX_WORKERS = 4

    def run(self, url: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])

        endpoints: List[str] = kwargs.get("endpoints") or []
        if not endpoints:
            endpoints = self._discover_api_endpoints(url)
        if url not in endpoints:
            endpoints.insert(0, url)

        logger.info(f"[MassAssign] Scanning {len(endpoints)} endpoints")

        for ep in endpoints:
            self._scan_endpoint(ep, bucket)

        return self.results

    # -------------------------------------------------------------------------
    # Endpoint discovery
    # -------------------------------------------------------------------------

    def _discover_api_endpoints(self, base_url: str) -> List[str]:
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found: List[str] = []
        for path in _COMMON_API_PATHS:
            target = base + path
            try:
                r = self.session.get(target, timeout=4)
                if r.status_code not in (404, 405, 501):
                    found.append(target)
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[MassAssign] Endpoint discovery probe failed for {target!r}: {exc!r}")
        return found

    # -------------------------------------------------------------------------
    # Per-endpoint scan
    # -------------------------------------------------------------------------

    def _scan_endpoint(self, url: str, bucket: str):
        working_methods = self._probe_methods(url)
        if not working_methods:
            return

        baseline = {"name": "test", "email": "test@test.com", "username": "testuser"}

        for method_fn, method_name in working_methods:
            self._probe_flat_injection(url, method_fn, method_name, baseline, bucket)
            self._probe_nested_injection(url, method_fn, method_name, baseline, bucket)
            self._probe_form_injection(url, method_name, baseline, bucket)

    def _probe_methods(self, url: str) -> List[Tuple]:
        working = []
        for method_name, method_fn in [
            ("POST",  self.session.post),
            ("PUT",   self.session.put),
            ("PATCH", self.session.patch),
        ]:
            try:
                r = method_fn(url, json={"__probe__": True}, timeout=4)
                if r.status_code not in (404, 405, 501):
                    working.append((method_fn, method_name))
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[MassAssign] Method probe {method_name} failed for {url!r}: {exc!r}")
        return working

    # -------------------------------------------------------------------------
    # Flat field injection: {"is_admin": true}
    # -------------------------------------------------------------------------

    def _probe_flat_injection(
        self, url: str, method_fn, method_name: str, baseline: Dict, bucket: str
    ):
        try:
            base_resp = method_fn(url, json=baseline, timeout=5)
        except requests.exceptions.RequestException as exc:
            logger.debug(f"[MassAssign] Flat injection baseline request failed for {url!r}: {exc!r}")
            return

        def test_one(key: str, val: Any) -> Optional[Dict]:
            attack = {**baseline, key: val}
            try:
                r = method_fn(url, json=attack, timeout=5)
                return self._analyze(url, method_name, key, val, base_resp, r, "flat")
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[MassAssign] Flat injection request failed for key={key!r}: {exc!r}")
                return None

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
            futures = {
                pool.submit(test_one, k, v): (k, v)
                for k in SENSITIVE_KEYS
                for v in ESCALATION_VALUES
            }
            for f in as_completed(futures):
                result = f.result()
                if result:
                    self.add(bucket, result)
                    add_result("offensive", result)
                    self._verify_persistence(url, result["field"], result["injected_value"], bucket)

    # -------------------------------------------------------------------------
    # Nested field injection: {"user": {"role": "admin"}}
    # -------------------------------------------------------------------------

    def _probe_nested_injection(
        self, url: str, method_fn, method_name: str, baseline: Dict, bucket: str
    ):
        try:
            base_resp = method_fn(url, json=baseline, timeout=5)
        except requests.exceptions.RequestException as exc:
            logger.debug(f"[MassAssign] Nested injection baseline request failed for {url!r}: {exc!r}")
            return

        for wrapper in _NESTED_WRAPPERS:
            for key in _NESTED_KEYS:
                for val in ESCALATION_VALUES[:4]:
                    attack = {**baseline, wrapper: {key: val}}
                    try:
                        r = method_fn(url, json=attack, timeout=5)
                        result = self._analyze(
                            url, method_name, f"{wrapper}.{key}", val, base_resp, r, "nested"
                        )
                        if result:
                            self.add(bucket, result)
                            add_result("offensive", result)
                    except requests.exceptions.RequestException as exc:
                        logger.debug(f"[MassAssign] Nested injection request failed for {wrapper}.{key!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # Form-based injection (urlencoded)
    # -------------------------------------------------------------------------

    def _probe_form_injection(
        self, url: str, method_name: str, baseline: Dict, bucket: str
    ):
        try:
            base_resp = self.session.request(method_name, url, data=baseline, timeout=5)
            if base_resp.status_code in (404, 405):
                return
        except requests.exceptions.RequestException as exc:
            logger.debug(f"[MassAssign] Form injection baseline request failed for {url!r}: {exc!r}")
            return

        for key in SENSITIVE_KEYS[:12]:       # top-priority fields only
            for val in ESCALATION_VALUES[:4]:
                attack = {**baseline, key: str(val)}
                try:
                    r = self.session.request(method_name, url, data=attack, timeout=5)
                    result = self._analyze(url, method_name, key, val, base_resp, r, "form_urlencoded")
                    if result:
                        self.add(bucket, result)
                        add_result("offensive", result)
                except requests.exceptions.RequestException as exc:
                    logger.debug(f"[MassAssign] Form injection request failed for key={key!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # Response comparison
    # -------------------------------------------------------------------------

    def _analyze(
        self,
        url: str, method: str, key: str, val: Any,
        base_resp, attack_resp,
        injection_type: str,
    ) -> Optional[Dict]:
        if attack_resp.status_code >= 500:
            return None

        try:
            base_json = base_resp.json()
        except (ValueError, TypeError, AttributeError):
            base_json = {}

        try:
            attack_json = attack_resp.json()
        except (ValueError, TypeError, AttributeError):
            attack_json = None

        str_val = str(val).lower()

        # -- Access control bypass ------------------------------------------
        if base_resp.status_code == 403 and attack_resp.status_code == 200:
            return {
                "type": "Mass Assignment — Access Control Bypass",
                "severity": "Critical",
                "url": url, "method": method,
                "injection_type": injection_type,
                "field": key, "injected_value": val,
                "details": f"Injecting '{key}={val}' changed response from 403 to 200",
            }

        # -- JSON key reflection --------------------------------------------
        if isinstance(attack_json, dict):
            # Check top-level and nested under "data", "user", "profile"
            for container in [attack_json,
                               attack_json.get("data") if isinstance(attack_json.get("data"), dict) else {},
                               attack_json.get("user") if isinstance(attack_json.get("user"), dict) else {}]:
                reflected = (container or {}).get(key)
                if reflected is not None and str(reflected).lower() == str_val:
                    baseline_val = base_json.get(key)
                    if baseline_val is None or str(baseline_val).lower() != str_val:
                        return {
                            "type": "Mass Assignment — Field Reflected in Response",
                            "severity": "High",
                            "url": url, "method": method,
                            "injection_type": injection_type,
                            "field": key, "injected_value": val,
                            "details": (
                                f"Field '{key}={val}' injected and reflected back — "
                                "verify if this persists in account state"
                            ),
                        }

        # -- Text-based reflection fallback --------------------------------
        elif (attack_resp.status_code == 200
              and key in (attack_resp.text or "")
              and str_val in (attack_resp.text or "").lower()
              and str_val not in (base_resp.text or "").lower()):
            return {
                "type": "Mass Assignment — Value Reflected (Text)",
                "severity": "Medium",
                "url": url, "method": method,
                "injection_type": injection_type,
                "field": key, "injected_value": val,
                "details": f"Injected value '{val}' appeared in response text",
            }

        return None

    # -------------------------------------------------------------------------
    # Persistence verification (GET after injection)
    # -------------------------------------------------------------------------

    def _verify_persistence(self, url: str, key: str, val: Any, bucket: str):
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code != 200:
                return
            try:
                data = r.json()
            except (ValueError, TypeError):
                return
            str_val = str(val).lower()
            for obj in [data,
                        data.get("data") if isinstance(data.get("data"), dict) else {},
                        data.get("user") if isinstance(data.get("user"), dict) else {},
                        data.get("profile") if isinstance(data.get("profile"), dict) else {}]:
                if isinstance(obj, dict) and obj.get(key) is not None:
                    if str(obj[key]).lower() == str_val:
                        self.add(bucket, {
                            "type": "Mass Assignment — Persisted (Confirmed RCE-Level)",
                            "severity": "Critical",
                            "url": url,
                            "field": key,
                            "persisted_value": val,
                            "details": (
                                f"Injected '{key}={val}' persisted in GET response — "
                                "mass assignment is confirmed, account state was modified"
                            ),
                        })
                        return
        except requests.exceptions.RequestException as exc:
            logger.debug(f"[MassAssign] Persistence verification request failed for {url!r}: {exc!r}")


# ---------------------------------------------------------------------------
# Module-level adapter (backward-compatible)
# ---------------------------------------------------------------------------

def run(url: str, session=None, results: dict = None, debug: bool = False, **kwargs) -> List[Dict]:
    if session is None:
        try:
            from websecure.core.http import hardened_session as _hs
            session = _hs({})
        except ImportError:
            import requests as _req
            session = _req.Session()
    scanner = MassAssignmentScanner(
        session=session,
        results=results if results is not None else {},
        debug=debug,
    )
    endpoints = kwargs.get("endpoints") or []
    scanner.run(url, endpoints=endpoints)
    return scanner.results.get("mass_assignment", [])
