"""
websecure.core.auth_manager
-----------------------------
Authenticated scan orchestrator.

Config (config.json → "auth" key):
    {
        "type": "form" | "basic" | "bearer" | "cookie" | "api_key" | "jwt",
        "username": "...",
        "password": "...",
        "token": "...",           # bearer / jwt / api_key value
        "login_url": "...",       # form login endpoint
        "success_indicator": "dashboard",  # text expected in response after login
        "cookie": {"name": "value"},       # for type=cookie
        "api_key_header": "X-API-Key",     # for type=api_key (default X-API-Key)
        "jwt_refresh_url": "...",          # optional JWT refresh endpoint
    }

Usage in phases/__init__.py:
    from websecure.core.auth_manager import AuthManager
    AuthManager.authenticate(ctx)
"""
from __future__ import annotations

import base64
import logging
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests import Session
    from websecure.core.http import hardened_session as _hardened_session
except ImportError:
    requests = None  # type: ignore
    Session = object  # type: ignore
    def _hardened_session(*args, **kwargs):  # type: ignore[misc]
        return None

_logger = logging.getLogger(__name__)

_CSRF_FIELD_NAMES = (
    "csrf_token", "_csrf", "csrf", "csrfmiddlewaretoken",
    "xsrf_token", "_xsrf", "authenticity_token", "__RequestVerificationToken",
)

_SUCCESS_HINTS = (
    re.compile(r"(?i)\b(?:logout|sign.?out|çıkış)\b"),
    re.compile(r"(?i)\b(?:dashboard|my.?account|profile|hesabım|profil|welcome)\b"),
)

_VERIFY_PATHS = ("/dashboard", "/profile", "/account", "/me", "/home", "/panel")


def _extract_csrf(html: str) -> Optional[str]:
    """Extract CSRF token from HTML form fields."""
    for name in _CSRF_FIELD_NAMES:
        m = re.search(
            rf'<input[^>]+name=["\']({re.escape(name)})["\'][^>]*value=["\']([^"\']+)["\']',
            html, re.I,
        )
        if m:
            return m.group(2)
        m = re.search(
            rf'<input[^>]+value=["\']([^"\']+)["\'][^>]*name=["\']({re.escape(name)})["\']',
            html, re.I,
        )
        if m:
            return m.group(1)
        # meta tag
        m = re.search(
            rf'<meta[^>]+name=["\']csrf[^"\']*["\'][^>]*content=["\']([^"\']+)["\']',
            html, re.I,
        )
        if m:
            return m.group(1)
    return None


def _detect_form_fields(html: str) -> Dict[str, str]:
    """Extract all input fields from the first form."""
    fields: Dict[str, str] = {}
    for m in re.finditer(
        r'<input([^>]*)>', html, re.I | re.S
    ):
        attrs_str = m.group(1)
        name_m = re.search(r'name=["\']([^"\']+)["\']', attrs_str, re.I)
        value_m = re.search(r'value=["\']([^"\']*)["\']', attrs_str, re.I)
        type_m = re.search(r'type=["\']([^"\']+)["\']', attrs_str, re.I)
        if not name_m:
            continue
        field_type = (type_m.group(1) if type_m else "text").lower()
        if field_type in ("submit", "button", "image", "reset"):
            continue
        fields[name_m.group(1)] = value_m.group(1) if value_m else ""
    return fields


def _looks_authenticated(text: str, indicator: Optional[str] = None) -> bool:
    if indicator and indicator.lower() in text.lower():
        return True
    for rx in _SUCCESS_HINTS:
        if rx.search(text):
            return True
    return False


class AuthManager:
    """
    Single-responsibility auth orchestrator.
    Call AuthManager.authenticate(ctx) at scan start.
    Injects auth into ctx.session and stores metadata in ctx.results["auth_meta"].
    """

    def __init__(self, cfg: Dict[str, Any], session: Session, base_url: str):
        self._cfg = cfg
        self._session = session
        self._base_url = base_url.rstrip("/")
        self._auth_type = (cfg.get("type") or "none").lower().strip()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def authenticate(cls, ctx) -> bool:
        """
        Read auth config from ctx.config["auth"], authenticate, inject session.
        Returns True if authentication succeeded (or no auth configured).
        """
        cfg = (getattr(ctx, "config", None) or {})
        auth_cfg = cfg.get("auth") or {}

        if not auth_cfg or auth_cfg.get("type", "none").lower() in ("none", ""):
            _logger.debug("[AuthManager] No auth config — unauthenticated scan.")
            return True

        session = getattr(ctx, "session", None)
        if session is None:
            if requests is None:
                _logger.warning("[AuthManager] requests not available, skipping auth.")
                return False
            session = _hardened_session({})
            ctx.session = session

        base_url = getattr(ctx, "url", "") or ""
        mgr = cls(auth_cfg, session, base_url)
        ok = mgr._run()

        if not hasattr(ctx, "results") or ctx.results is None:
            ctx.results = {}
        ctx.results.setdefault("auth_meta", {})
        ctx.results["auth_meta"]["type"] = mgr._auth_type
        ctx.results["auth_meta"]["success"] = ok
        ctx.results["auth_meta"]["authenticated"] = ok

        if ok:
            _logger.info(f"[AuthManager] Authentication succeeded (type={mgr._auth_type})")
        else:
            _logger.warning(f"[AuthManager] Authentication FAILED (type={mgr._auth_type})")

        return ok

    def refresh_csrf(self, url: Optional[str] = None) -> Optional[str]:
        """Fetch page and return current CSRF token."""
        target = url or self._base_url
        try:
            resp = self._session.get(target, timeout=10, allow_redirects=True)
            return _extract_csrf(resp.text or "")
        except Exception as e:
            _logger.debug(f"[AuthManager] refresh_csrf error: {e}")
            return None

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _run(self) -> bool:
        dispatch = {
            "form": self._form_login,
            "form_login": self._form_login,
            "basic": self._basic_auth,
            "bearer": self._bearer_token,
            "token": self._bearer_token,
            "cookie": self._cookie_inject,
            "api_key": self._api_key,
            "jwt": self._jwt_auth,
        }
        handler = dispatch.get(self._auth_type)
        if handler is None:
            _logger.warning(f"[AuthManager] Unknown auth type: {self._auth_type!r}")
            return False
        try:
            return handler()
        except Exception as e:
            _logger.error(f"[AuthManager] Auth error ({self._auth_type}): {e}", exc_info=True)
            return False

    # ------------------------------------------------------------------
    # Form login
    # ------------------------------------------------------------------

    def _form_login(self) -> bool:
        login_url = self._cfg.get("login_url") or ""
        if not login_url:
            login_url = self._base_url + "/login"
        if not login_url.startswith("http"):
            login_url = urljoin(self._base_url + "/", login_url.lstrip("/"))

        username = self._cfg.get("username") or self._cfg.get("user") or ""
        password = self._cfg.get("password") or self._cfg.get("pass") or ""
        indicator = self._cfg.get("success_indicator") or ""

        # Step 1: GET login page — discover form fields + CSRF
        try:
            resp = self._session.get(login_url, timeout=15, allow_redirects=True)
            html = resp.text or ""
        except Exception as e:
            _logger.warning(f"[AuthManager] GET {login_url} failed: {e}")
            return False

        fields = _detect_form_fields(html)
        csrf_token = _extract_csrf(html)

        # Fill credentials into detected fields
        user_key = self._detect_field_key(fields, ("username", "user", "email", "login", "name"))
        pass_key = self._detect_field_key(fields, ("password", "pass", "passwd", "pwd"))

        if user_key:
            fields[user_key] = username
        else:
            fields["username"] = username

        if pass_key:
            fields[pass_key] = password
        else:
            fields["password"] = password

        if csrf_token:
            csrf_key = self._find_csrf_key(fields) or "csrf_token"
            fields[csrf_key] = csrf_token

        # Step 2: POST login
        try:
            post_resp = self._session.post(
                login_url, data=fields,
                headers={"Referer": login_url},
                timeout=15, allow_redirects=True,
            )
        except Exception as e:
            _logger.warning(f"[AuthManager] POST {login_url} failed: {e}")
            return False

        body = post_resp.text or ""

        # Step 3: Verify authentication
        if _looks_authenticated(body, indicator):
            return True

        # Follow redirect and check again
        final_url = post_resp.url
        if final_url and final_url != login_url:
            try:
                verify_resp = self._session.get(final_url, timeout=10)
                if _looks_authenticated(verify_resp.text or "", indicator):
                    return True
            except Exception as _e:
                _logger.debug(f"[AuthManager] Auth verify request failed: {_e!r}")

        # Try common success paths
        for path in _VERIFY_PATHS:
            try:
                vr = self._session.get(
                    self._base_url + path, timeout=8, allow_redirects=True,
                )
                if vr.status_code == 200 and _looks_authenticated(vr.text or "", indicator):
                    return True
            except Exception:
                continue

        _logger.warning("[AuthManager] Form login: no success indicator found.")
        return False

    @staticmethod
    def _detect_field_key(fields: Dict[str, str], candidates) -> Optional[str]:
        for key in fields:
            kl = key.lower()
            for c in candidates:
                if c in kl:
                    return key
        return None

    @staticmethod
    def _find_csrf_key(fields: Dict[str, str]) -> Optional[str]:
        for key in fields:
            kl = key.lower()
            if any(c in kl for c in ("csrf", "xsrf", "token", "authenticity")):
                return key
        return None

    # ------------------------------------------------------------------
    # Basic auth
    # ------------------------------------------------------------------

    def _basic_auth(self) -> bool:
        username = self._cfg.get("username") or ""
        password = self._cfg.get("password") or ""
        self._session.auth = (username, password)
        return self._verify_auth()

    # ------------------------------------------------------------------
    # Bearer token
    # ------------------------------------------------------------------

    def _bearer_token(self) -> bool:
        token = self._cfg.get("token") or self._cfg.get("bearer") or ""
        if not token:
            _logger.warning("[AuthManager] Bearer token missing in config.")
            return False
        self._session.headers["Authorization"] = f"Bearer {token}"
        return self._verify_auth()

    # ------------------------------------------------------------------
    # Cookie injection
    # ------------------------------------------------------------------

    def _cookie_inject(self) -> bool:
        cookies = self._cfg.get("cookie") or self._cfg.get("cookies") or {}
        if isinstance(cookies, str):
            # "name=value; name2=value2" format
            for part in cookies.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    self._session.cookies.set(k.strip(), v.strip())
        elif isinstance(cookies, dict):
            for k, v in cookies.items():
                self._session.cookies.set(str(k), str(v))
        return self._verify_auth()

    # ------------------------------------------------------------------
    # API Key
    # ------------------------------------------------------------------

    def _api_key(self) -> bool:
        token = self._cfg.get("token") or self._cfg.get("api_key") or ""
        header = self._cfg.get("api_key_header") or "X-API-Key"
        if not token:
            _logger.warning("[AuthManager] API key token missing in config.")
            return False
        self._session.headers[header] = token
        # Also try common alternatives
        for alt in ("X-Auth-Token", "X-Access-Token"):
            if alt != header:
                self._session.headers.setdefault(alt, token)
        return self._verify_auth()

    # ------------------------------------------------------------------
    # JWT auth
    # ------------------------------------------------------------------

    def _jwt_auth(self) -> bool:
        token = self._cfg.get("token") or self._cfg.get("jwt_token") or ""
        username = self._cfg.get("username") or ""
        password = self._cfg.get("password") or ""
        login_url = self._cfg.get("login_url") or ""
        refresh_url = self._cfg.get("jwt_refresh_url") or ""

        if not token and login_url:
            # Obtain token via login endpoint
            try:
                resp = self._session.post(
                    login_url if login_url.startswith("http") else urljoin(self._base_url + "/", login_url.lstrip("/")),
                    json={"username": username, "password": password},
                    timeout=15,
                )
                data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                for key in ("token", "access_token", "accessToken", "jwt", "id_token"):
                    if key in data:
                        token = data[key]
                        break
                if not token and "data" in data:
                    for key in ("token", "access_token", "accessToken"):
                        if key in data["data"]:
                            token = data["data"][key]
                            break
            except Exception as e:
                _logger.warning(f"[AuthManager] JWT login failed: {e}")

        if not token:
            _logger.warning("[AuthManager] JWT token could not be obtained.")
            return False

        self._session.headers["Authorization"] = f"Bearer {token}"

        # Optional refresh
        if refresh_url:
            try:
                r_url = refresh_url if refresh_url.startswith("http") else urljoin(self._base_url + "/", refresh_url.lstrip("/"))
                rr = self._session.post(r_url, json={"token": token}, timeout=10)
                rdata = rr.json() if rr.ok else {}
                for key in ("token", "access_token", "accessToken"):
                    if key in rdata:
                        new_token = rdata[key]
                        self._session.headers["Authorization"] = f"Bearer {new_token}"
                        break
            except Exception as _fix_e:
                _logger.debug(f"[core.auth_manager] {type(_fix_e).__name__}: {_fix_e!r}")

        return self._verify_auth()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _verify_auth(self) -> bool:
        """Verify that current session is authenticated by hitting base URL."""
        indicator = self._cfg.get("success_indicator") or ""
        for path in ["", "/dashboard", "/profile", "/me", "/api/me", "/api/user"]:
            try:
                url = self._base_url + path if path else self._base_url
                resp = self._session.get(url, timeout=10, allow_redirects=True)
                if resp.status_code in (200, 201) and _looks_authenticated(resp.text or "", indicator):
                    return True
                if resp.status_code == 200 and indicator and indicator.lower() in (resp.text or "").lower():
                    return True
            except Exception:
                continue
        # Accept if any 200 received (non-form auth cannot easily detect auth success from body)
        try:
            resp = self._session.get(self._base_url, timeout=10)
            if resp.status_code not in (401, 403):
                return True
        except Exception as _fix_e:
            _logger.debug(f"[core.auth_manager] {type(_fix_e).__name__}: {_fix_e!r}")
        return False


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def authenticate(ctx) -> bool:
    """Shorthand: AuthManager.authenticate(ctx)."""
    return AuthManager.authenticate(ctx)


__all__ = ["AuthManager", "authenticate"]
