"""
websecure.scanners.session_hunter
----------------------------------
Session Security Scanner.

Techniques:
- Live cookie analysis: entropy measurement, format fingerprinting
- Session fixation: set-before-login persistence check
- Predictability detection: sequential IDs, timestamp-based hashes
- Weak/common value brute-force (dictionary attack)
- Token format detection: UUID, JWT, MD5, SHA256, Base64, sequential
- Cookie attribute audit: HttpOnly, Secure, SameSite
"""
from __future__ import annotations

import base64
import hashlib
import logging
import math
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as _FutureTimeoutError
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from .base import BaseScanner
from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)

try:
    from websecure.core.auth_flow import _looks_authenticated
except ImportError:
    def _looks_authenticated(text, resp=None, hints=None):
        text_lower = (text or "").lower()
        return any(k in text_lower for k in ("dashboard", "logout", "sign out", "my account", "welcome"))

# ---------------------------------------------------------------------------
# Token format patterns
# ---------------------------------------------------------------------------
_TOKEN_FORMATS = [
    ("JWT",         re.compile(r'^eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]*$')),
    ("UUID v4",     re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)),
    ("MD5 hex",     re.compile(r'^[0-9a-f]{32}$', re.I)),
    ("SHA1 hex",    re.compile(r'^[0-9a-f]{40}$', re.I)),
    ("SHA256 hex",  re.compile(r'^[0-9a-f]{64}$', re.I)),
    ("Hex",         re.compile(r'^[0-9a-f]{16,}$', re.I)),
    ("Base64",      re.compile(r'^[A-Za-z0-9+/\-_]{16,}=*$')),
    ("Sequential",  re.compile(r'^\d{1,10}$')),
]

# Session cookie names to analyze
_SESSION_NAMES = [
    "PHPSESSID", "JSESSIONID", "session", "sess", "sid",
    "connect.sid", "ASP.NET_SessionId", "ASPSESSIONID",
    "auth", "token", "access_token", "remember_me", "_session",
]

# Weak/common values to brute-force
_WEAK_VALUES = [
    "admin", "administrator", "user", "guest", "test", "demo",
    "root", "debug", "trace", "token", "auth", "session", "cookie",
    "abc123", "123456", "password", "qwerty", "0", "1", "true",
    "false", "", "null", "undefined",
]


# ---------------------------------------------------------------------------
# SessionHunter
# ---------------------------------------------------------------------------

class SessionHunter(BaseScanner):
    """
    Session Security Scanner — entropy, fixation, prediction, brute-force.
    Inherits BaseScanner for standardized reporting and session management.
    """

    name = "session_hunter"
    MAX_WORKERS = 8
    # Overall timeout (seconds) for each sub-phase — prevents infinite hangs on slow targets
    PHASE_TIMEOUT = 60

    def run(self, target: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])
        workers = int(kwargs.get("threads", self.MAX_WORKERS))
        phase_timeout = int(kwargs.get("op_timeout", self.PHASE_TIMEOUT))

        # 1. Analyze live cookies
        self._analyze_live_cookies(target, bucket)

        # 2. Session fixation
        self._check_session_fixation(target, bucket)

        # 3. Dictionary attack on common weak values
        self._brute_common(target, bucket, workers=workers, phase_timeout=phase_timeout)

        # 4. Timestamp-seed prediction
        self._predict_timestamp_sessions(target, bucket, workers=workers, phase_timeout=phase_timeout)

        return self.results

    # -------------------------------------------------------------------------
    # Live cookie analysis
    # -------------------------------------------------------------------------

    def _analyze_live_cookies(self, url: str, bucket: str):
        """Fetch the target and analyze all session cookies for weaknesses."""
        try:
            resp = self.session.get(url, timeout=8)
        except Exception as exc:
            return

        for cookie in resp.cookies:
            name = cookie.name
            value = cookie.value or ""

            # Only analyze session-like cookies
            is_session = (
                any(n.lower() in name.lower() for n in _SESSION_NAMES)
                or len(value) >= 8
            )
            if not is_session or not value:
                continue

            entropy = _shannon_entropy(value)
            fmt = _detect_token_format(value)
            issues: List[str] = []

            # Entropy check
            if entropy < 3.5 and len(value) >= 8:
                issues.append(f"Low entropy ({entropy:.2f} bits/char) — token may be guessable")

            # Sequential integer — trivially enumerable
            if re.match(r'^\d{1,8}$', value):
                issues.append("Sequential integer session ID — trivially enumerable (IDOR/session hijack risk)")

            # Timestamp-embedded
            ts_hint = _detect_timestamp(value)
            if ts_hint:
                issues.append(f"Session ID encodes a Unix timestamp ({ts_hint}) — predictable generation")

            # JWT with no signature
            if fmt == "JWT":
                parts = value.split(".")
                if len(parts) == 3 and parts[2] == "":
                    issues.append("JWT with empty signature — alg:none bypass risk")

            # Very short token
            if len(value) < 16:
                issues.append(f"Very short session token ({len(value)} chars) — small key space")

            # Cookie flags
            secure = getattr(cookie, "secure", False)
            rest = getattr(cookie, "_rest", {}) or {}
            http_only = "httponly" in {k.lower() for k in rest} or rest.get("HttpOnly") is not None

            if not http_only:
                issues.append("Missing HttpOnly — XSS can steal this cookie")
            if not secure and url.startswith("https://"):
                issues.append("Missing Secure flag — cookie transmitted over HTTP")
            if "SameSite" not in {k for k in rest}:
                issues.append("Missing SameSite — CSRF risk")

            if issues:
                sev = "High" if any("enumerable" in i or "JWT" in i or "entropy" in i for i in issues) else "Medium"
                finding = self.create_finding(
                    type="Session Token Weakness",
                    url=url,
                    severity=sev,
                    details="; ".join(issues),
                    evidence={
                        "cookie_name": name,
                        "format": fmt or "unknown",
                        "entropy_bits": round(entropy, 2),
                        "token_length": len(value),
                        "sample": value[:12] + "..." if len(value) > 12 else value,
                    },
                )
                self.add(bucket, finding)
                add_result("offensive", finding)

    # -------------------------------------------------------------------------
    # Session fixation
    # -------------------------------------------------------------------------

    def _check_session_fixation(self, url: str, bucket: str):
        """
        Send a known session ID to the login endpoint.
        If the server reuses it post-auth, session fixation is confirmed.
        """
        FIXED = "WEBSECURE_FIXED_9x7z3q"
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        candidates = [
            base + "/login", base + "/signin",
            base + "/auth/login", base + "/api/login",
            base + "/user/login",
        ]

        for login_url in candidates:
            try:
                resp = self.session.get(
                    login_url,
                    cookies={"PHPSESSID": FIXED, "session": FIXED, "sid": FIXED},
                    timeout=5,
                    allow_redirects=True,
                )
                if resp.status_code == 404:
                    continue

                # If server echoes our fixed value back in Set-Cookie
                for c in resp.cookies:
                    if c.value == FIXED:
                        finding = self.create_finding(
                            type="Session Fixation",
                            url=login_url,
                            severity="High",
                            details=(
                                f"Server preserved attacker-supplied session ID. "
                                f"Cookie '{c.name}' was set to the attacker-controlled value."
                            ),
                            evidence={"cookie": c.name, "fixed_value": FIXED},
                        )
                        self.add(bucket, finding)
                        add_result("offensive", finding)
                        return
            except Exception as exc:
                continue

    # -------------------------------------------------------------------------
    # Common value brute-force
    # -------------------------------------------------------------------------

    def _brute_common(self, url: str, bucket: str, workers: int = 8, phase_timeout: int = 60):
        """Dictionary attack: try well-known weak session ID values."""
        ua = self.session.headers.get("User-Agent", "Mozilla/5.0")

        def check_one(name: str, value: str) -> Optional[Dict]:
            try:
                resp = requests.get(
                    url,
                    headers={"Cookie": f"{name}={value}", "User-Agent": ua},
                    timeout=5,
                    verify=False,
                )
                if _looks_authenticated(resp.text, resp):
                    return self.create_finding(
                        type="Weak Session ID — Dictionary Attack",
                        url=url,
                        severity="Critical",
                        details=f"Access gained with trivial session: {name}={value!r}",
                        evidence={"cookie": f"{name}={value}", "status": resp.status_code},
                    )
            except Exception as exc:
                logger.debug("[SessionHunter] brute_common error: %s", exc)
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(check_one, name, val): (name, val)
                for name in _SESSION_NAMES[:6]
                for val in _WEAK_VALUES
            }
            try:
                for f in as_completed(futures, timeout=phase_timeout):
                    result = f.result()
                    if result:
                        self.add(bucket, result)
                        add_result("offensive", result)
            except _FutureTimeoutError:
                logger.warning("[SessionHunter] _brute_common timed out after %ds, cancelling remaining tasks", phase_timeout)
                for f in futures:
                    f.cancel()

    # -------------------------------------------------------------------------
    # Timestamp-seed prediction
    # -------------------------------------------------------------------------

    def _predict_timestamp_sessions(self, url: str, bucket: str, workers: int = 8, phase_timeout: int = 60):
        """
        Generate candidate session IDs from Unix timestamps (last 15 min).
        Covers MD5/SHA256/base64/uid-hash variants used by weak generators.
        """
        now = int(time.time())
        seeds = list(range(now - 900, now, 30))  # every 30s over 15 min -> ~30 seeds
        ua = self.session.headers.get("User-Agent", "Mozilla/5.0")

        logger.info("[SessionHunter] Testing %d timestamp seeds against %s", len(seeds), url)

        def test_seed(ts: int) -> Optional[Dict]:
            ts_str = str(ts)
            candidates = [
                hashlib.md5(ts_str.encode()).hexdigest(),
                hashlib.md5(ts_str.encode()).hexdigest()[:26],
                hashlib.sha256(f"session:{ts}".encode()).hexdigest()[:32],
                base64.urlsafe_b64encode(ts_str.encode()).decode().rstrip("="),
                hashlib.md5(f"user:1:{ts}".encode()).hexdigest(),
                hashlib.sha1(ts_str.encode()).hexdigest(),
            ]
            for val in candidates:
                for name in _SESSION_NAMES[:5]:
                    try:
                        resp = requests.get(
                            url,
                            headers={"Cookie": f"{name}={val}", "User-Agent": ua},
                            timeout=4,
                            verify=False,
                        )
                        if _looks_authenticated(resp.text, resp):
                            return self.create_finding(
                                type="Predictable Session ID — Timestamp Seed",
                                url=url,
                                severity="Critical",
                                details=(
                                    f"Session derived from Unix timestamp {ts} was accepted. "
                                    "Server uses time-based session generation — trivially brute-forceable."
                                ),
                                evidence={"seed_timestamp": ts, "cookie": f"{name}={val}"},
                            )
                    except Exception as exc:
                        logger.debug("[SessionHunter] test_seed error ts=%d: %s", ts, exc)
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(test_seed, ts): ts for ts in seeds}
            try:
                for f in as_completed(futures, timeout=phase_timeout):
                    result = f.result()
                    if result:
                        self.add(bucket, result)
                        add_result("offensive", result)
            except _FutureTimeoutError:
                logger.warning("[SessionHunter] _predict_timestamp_sessions timed out after %ds, cancelling remaining tasks", phase_timeout)
                for f in futures:
                    f.cancel()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _detect_token_format(value: str) -> Optional[str]:
    for name, pattern in _TOKEN_FORMATS:
        if pattern.match(value):
            return name
    return None


def _detect_timestamp(value: str) -> Optional[str]:
    """Return a hint string if value encodes a plausible Unix timestamp (2020–2030)."""
    if re.match(r'^\d{10}$', value):
        ts = int(value)
        if 1577836800 < ts < 1893456000:
            return value
    m = re.search(r'(\d{10})', value)
    if m:
        ts = int(m.group(1))
        if 1577836800 < ts < 1893456000:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Legacy entry points (backward compatible)
# ---------------------------------------------------------------------------

def run_session_hunter(url: str, session=None, results: Dict = None, **kwargs) -> List[Dict]:
    hunter = SessionHunter(
        session=session or requests.Session(),
        results=results or {},
    )
    hunter.run(url)
    return hunter.results.get("session_hunter", [])


run = run_session_hunter
