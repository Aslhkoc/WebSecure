"""
websecure.core.auth.oauth
--------------------------
OAuth 2.0 flow handler for authenticated scanning.
Supports:
- Authorization Code Flow (with PKCE)
- Implicit Flow
- Client Credentials
- Auto-approve consent screens via Playwright
"""
from __future__ import annotations
import base64
import hashlib
import logging
import os
import re
import secrets
import time
from typing import Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import requests

_logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


def _pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge."""
    verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge


class OAuthFlowHandler:
    """
    Handles OAuth 2.0 authentication flows for the scanner.
    Returns a requests.Session with the access token injected.
    """

    def __init__(self, config: Dict):
        self.config = config
        self.token_url: str = config.get("token_url", "")
        self.auth_url: str = config.get("auth_url", "")
        self.client_id: str = config.get("client_id", "")
        self.client_secret: str = config.get("client_secret", "")
        self.redirect_uri: str = config.get("redirect_uri", "http://localhost:9876/callback")
        self.scope: str = config.get("scope", "openid profile email")

    def get_session(self, flow: str = "authorization_code") -> Optional[requests.Session]:
        """
        Get an authenticated session using the specified OAuth flow.
        Returns a requests.Session with Authorization header set, or None on failure.
        """
        token = None

        if flow == "authorization_code":
            token = self._authorization_code_flow()
        elif flow == "implicit":
            token = self._implicit_flow()
        elif flow == "client_credentials":
            token = self._client_credentials_flow()
        else:
            _logger.warning(f"[OAuth] Unknown flow: {flow}")
            return None

        if not token:
            _logger.error(f"[OAuth] Failed to obtain token via {flow}")
            return None

        session = requests.Session()
        session.headers["Authorization"] = f"Bearer {token}"
        _logger.info(f"[OAuth] Authenticated via {flow}, token obtained")
        return session

    def _client_credentials_flow(self) -> Optional[str]:
        """OAuth 2.0 Client Credentials Grant."""
        if not self.token_url or not self.client_id:
            return None
        try:
            resp = requests.post(self.token_url, data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": self.scope,
            }, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            return data.get("access_token")
        except Exception as e:
            _logger.error(f"[OAuth] Client credentials error: {e}")
            return None

    def _authorization_code_flow(self) -> Optional[str]:
        """Authorization Code Flow with PKCE via Playwright."""
        if not _PLAYWRIGHT_AVAILABLE:
            _logger.warning("[OAuth] Playwright not available for authorization code flow")
            return None
        if not self.auth_url or not self.token_url:
            return None

        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(16)

        auth_params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        full_auth_url = self.auth_url + "?" + urlencode(auth_params)

        auth_code = None

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()

                # Intercept redirect to capture auth code
                redirect_codes = []

                def _on_request(request):
                    if self.redirect_uri in request.url:
                        parsed = urlparse(request.url)
                        qs = parse_qs(parsed.query)
                        code = qs.get("code", [None])[0]
                        if code:
                            redirect_codes.append(code)

                page.on("request", _on_request)
                page.goto(full_auth_url, timeout=15000)

                # Auto-fill login if credentials provided
                creds = self.config.get("credentials", {})
                if creds.get("username"):
                    try:
                        page.fill('input[type=email], input[name*=user], input[name*=login], input[id*=user]',
                                  creds["username"])
                        page.fill('input[type=password]', creds.get("password", ""))
                        page.click('button[type=submit], input[type=submit]')
                        page.wait_for_timeout(2000)
                    except Exception as e:
                        _logger.debug(f"[OAuth] Auto-fill error: {e}")

                # Auto-approve consent screen
                try:
                    approve_selectors = [
                        "button:has-text('Allow')",
                        "button:has-text('Authorize')",
                        "button:has-text('Accept')",
                        "button:has-text('Grant')",
                        "input[value='Allow']",
                    ]
                    for sel in approve_selectors:
                        btn = page.query_selector(sel)
                        if btn:
                            btn.click()
                            page.wait_for_timeout(1500)
                            break
                except Exception:
                    pass

                page.wait_for_timeout(2000)
                browser.close()

                if redirect_codes:
                    auth_code = redirect_codes[0]

        except Exception as e:
            _logger.error(f"[OAuth] Authorization code flow error: {e}")
            return None

        if not auth_code:
            _logger.warning("[OAuth] No auth code received")
            return None

        # Exchange code for token
        try:
            resp = requests.post(self.token_url, data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code_verifier": verifier,
            }, timeout=15)
            resp.raise_for_status()
            return resp.json().get("access_token")
        except Exception as e:
            _logger.error(f"[OAuth] Token exchange error: {e}")
            return None

    def _implicit_flow(self) -> Optional[str]:
        """Implicit Flow - captures token from URL fragment after redirect."""
        if not _PLAYWRIGHT_AVAILABLE:
            return None

        auth_params = {
            "response_type": "token",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": secrets.token_urlsafe(16),
        }
        full_auth_url = self.auth_url + "?" + urlencode(auth_params)
        captured_token = []

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()

                def _on_navigate(url):
                    if self.redirect_uri in url and "access_token=" in url:
                        fragment = urlparse(url).fragment
                        qs = parse_qs(fragment)
                        token = qs.get("access_token", [None])[0]
                        if token:
                            captured_token.append(token)

                page.on("framenavigated", lambda frame: _on_navigate(frame.url))
                page.goto(full_auth_url, timeout=15000)
                page.wait_for_timeout(3000)
                browser.close()
        except Exception as e:
            _logger.error(f"[OAuth] Implicit flow error: {e}")

        return captured_token[0] if captured_token else None
