"""
websecure.core.auth.session_manager
-------------------------------------
Session lifecycle manager for multi-role authenticated scanning.
Maintains named sessions (admin, user, anonymous), detects expiry,
and auto-re-authenticates during long scans.
"""
from __future__ import annotations
import logging
import threading
import time
from typing import Callable, Dict, Optional

import requests

_logger = logging.getLogger(__name__)

# Type alias
SessionFactory = Callable[[], requests.Session]


class ManagedSession:
    """A session with TTL and re-authentication capability."""

    def __init__(self, name: str, session: requests.Session,
                 factory: Optional[SessionFactory] = None,
                 keepalive_url: Optional[str] = None,
                 ttl: float = 1800.0):
        self.name = name
        self.session = session
        self.factory = factory
        self.keepalive_url = keepalive_url
        self.ttl = ttl
        self._created_at = time.monotonic()
        self._last_check = time.monotonic()

    @property
    def age(self) -> float:
        return time.monotonic() - self._created_at

    def is_alive(self) -> bool:
        """Check if session is still valid via keepalive URL."""
        if not self.keepalive_url:
            return self.age < self.ttl
        try:
            resp = self.session.get(self.keepalive_url, timeout=8, allow_redirects=False)
            # 200 or 2xx = alive; redirect to login = dead
            alive = 200 <= resp.status_code < 300
            self._last_check = time.monotonic()
            return alive
        except Exception:
            return False

    def refresh(self) -> bool:
        """Re-authenticate using the factory function."""
        if not self.factory:
            _logger.warning(f"[SessionManager] No factory for session '{self.name}', cannot refresh")
            return False
        try:
            new_session = self.factory()
            if new_session:
                self.session = new_session
                self._created_at = time.monotonic()
                _logger.info(f"[SessionManager] Session '{self.name}' refreshed")
                return True
        except Exception as e:
            _logger.error(f"[SessionManager] Refresh failed for '{self.name}': {e}")
        return False


class SessionManager:
    """
    Manages multiple named sessions for multi-role scanning.
    Provides auto-refresh and session synchronization between
    Playwright browser contexts and requests.Session objects.
    """

    def __init__(self, keepalive_url: Optional[str] = None, check_interval: float = 120.0):
        self._sessions: Dict[str, ManagedSession] = {}
        self._lock = threading.Lock()
        self._keepalive_url = keepalive_url
        self._check_interval = check_interval
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def add_session(self, name: str, session: requests.Session,
                    factory: Optional[SessionFactory] = None,
                    keepalive_url: Optional[str] = None,
                    ttl: float = 1800.0) -> None:
        """Register a named session."""
        with self._lock:
            self._sessions[name] = ManagedSession(
                name=name,
                session=session,
                factory=factory,
                keepalive_url=keepalive_url or self._keepalive_url,
                ttl=ttl,
            )
        _logger.info(f"[SessionManager] Registered session '{name}'")

    def get(self, name: str) -> Optional[requests.Session]:
        """Get a session by name, refreshing if expired."""
        with self._lock:
            managed = self._sessions.get(name)
        if not managed:
            return None
        if not managed.is_alive():
            _logger.info(f"[SessionManager] Session '{name}' expired, refreshing...")
            managed.refresh()
        return managed.session

    def get_all(self) -> Dict[str, requests.Session]:
        """Return all managed sessions as name -> requests.Session dict."""
        result = {}
        for name in list(self._sessions.keys()):
            s = self.get(name)
            if s:
                result[name] = s
        return result

    def has(self, name: str) -> bool:
        return name in self._sessions

    def role_count(self) -> int:
        return len(self._sessions)

    def start_monitor(self) -> None:
        """Start background thread that periodically checks session health."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="SessionMonitor"
        )
        self._monitor_thread.start()
        _logger.debug("[SessionManager] Monitor thread started")

    def stop_monitor(self) -> None:
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(self._check_interval)
            if self._stop_event.is_set():
                break
            with self._lock:
                names = list(self._sessions.keys())
            for name in names:
                with self._lock:
                    managed = self._sessions.get(name)
                if managed and not managed.is_alive():
                    _logger.info(f"[SessionMonitor] Session '{name}' dead, auto-refreshing")
                    managed.refresh()

    def sync_playwright_cookies(self, name: str, playwright_cookies: list) -> None:
        """
        Copy cookies from Playwright browser context into the named requests.Session.
        playwright_cookies: list of dicts with keys: name, value, domain, path, etc.
        """
        session = self.get(name)
        if not session:
            return
        for cookie in playwright_cookies:
            session.cookies.set(
                cookie.get("name", ""),
                cookie.get("value", ""),
                domain=cookie.get("domain", ""),
                path=cookie.get("path", "/"),
            )
        _logger.debug(f"[SessionManager] Synced {len(playwright_cookies)} cookies to '{name}'")


# Global singleton
_DEFAULT_MANAGER: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    global _DEFAULT_MANAGER
    if _DEFAULT_MANAGER is None:
        _DEFAULT_MANAGER = SessionManager()
    return _DEFAULT_MANAGER


def build_role_sessions_from_config(auth_cfg: dict,
                                     base_url: str = "") -> Dict[str, requests.Session]:
    """
    Build role sessions from config dict.
    auth_cfg["roles"] = [{"name": "admin", "username": "...", "password": "..."}, ...]
    Returns dict: role_name -> requests.Session
    """
    from websecure.core.auth_flow import smart_login

    manager = get_session_manager()
    result: Dict[str, requests.Session] = {}

    roles = auth_cfg.get("roles", [])
    if not roles:
        # Single role from top-level credentials
        creds = auth_cfg.get("credentials", {})
        if creds:
            roles = [{"name": "default", **creds}]

    for role in roles:
        name = role.get("name", "user")
        username = role.get("username", "")
        password = role.get("password", "")
        login_url = role.get("login_url") or auth_cfg.get("login_url") or base_url

        if not username or not login_url:
            continue

        def _factory(u=username, p=password, url=login_url):
            return smart_login(url, u, p)

        session = _factory()
        if session:
            manager.add_session(name, session, factory=_factory,
                                keepalive_url=base_url or None)
            result[name] = session
            _logger.info(f"[SessionManager] Built session for role '{name}'")

    # Always add anonymous session
    anon = requests.Session()
    anon.headers["User-Agent"] = "Mozilla/5.0 WebSecure/3.0"
    manager.add_session("anonymous", anon)
    result["anonymous"] = anon

    return result
