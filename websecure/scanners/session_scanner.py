"""
websecure.scanners.session_scanner
-----------------------------------
Session & Cookie güvenlik tarayıcıları.

Adim 12 — Siniflar:
  CookieFlagScanner            — HttpOnly/Secure/SameSite eksiklik tespiti
  SessionFixationExploiter     — session fixation tam exploit zinciri
  CookieInjectionProber        — CRLF -> Set-Cookie injection tespiti
  JWTExpiryBypassProber        — expired JWT token kabul kontrolü
  BrowserFingerprintBypassProber — UA/Accept değişikliği -> session bypass testi
  ConcurrentSessionBypassProber  — concurrent session limit bypass testi
  SessionScanner               — orchestrator (Adim 12)
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as _FutureTimeoutError
from typing import Dict, List, Optional

import requests

from websecure.core.http import hardened_session
from websecure.scanners.base import BaseScanner
from websecure.core.session_manager import (
    CookieSecurityAnalyzer,
    SessionEntropyAnalyzer,
    SessionLifecycleProber,
)
from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_SENSITIVE_NAMES = re.compile(
    r"(sess|token|auth|jwt|sid|csrftoken|xsrf|remember|login|uid|user|account)",
    re.I,
)

# Weak/common session ID values to brute-force (from session_hunter.py)
_WEAK_SESSION_VALUES = [
    "admin", "administrator", "user", "guest", "test", "demo",
    "root", "debug", "trace", "token", "auth", "session", "cookie",
    "abc123", "123456", "password", "qwerty", "0", "1", "true",
    "false", "", "null", "undefined",
]

# Session cookie names to test against
_SESSION_COOKIE_NAMES = [
    "PHPSESSID", "JSESSIONID", "session", "sess", "sid",
    "connect.sid", "ASP.NET_SessionId", "auth", "token",
]

try:
    from websecure.core.auth_flow import _looks_authenticated
except ImportError:
    def _looks_authenticated(text, resp=None, hints=None):
        text_lower = (text or "").lower()
        return any(k in text_lower for k in (
            "dashboard", "logout", "sign out", "my account", "welcome"
        ))


# ---------------------------------------------------------------------------
# CookieFlagScanner
# ---------------------------------------------------------------------------

class CookieFlagScanner(BaseScanner):
    """
    Crawls the target's main page and common endpoints to collect Set-Cookie
    headers. Analyzes each cookie for missing HttpOnly / Secure / SameSite flags.

    Reports:
    - Missing HttpOnly -> XSS cookie theft
    - Missing Secure   -> HTTP transmission, MITM risk
    - Missing SameSite -> CSRF risk
    - SameSite=None without Secure
    - Overly broad Domain

    SOLID/SRP: Only cookie flag analysis.
    """

    _PROBE_PATHS = [
        "/", "/login", "/register", "/api/", "/api/v1/",
        "/dashboard", "/profile", "/account", "/auth/login",
        "/signin", "/admin", "/user/session",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        analyzer = CookieSecurityAnalyzer()
        seen_cookies: set = set()
        base = target.rstrip("/")

        for path in self._PROBE_PATHS:
            url = base + path
            try:
                r = self.session.get(
                    url, timeout=_TIMEOUT, verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; CookieAudit/1.0)"},
                )
                results = analyzer.analyze_response(r)
                for res in results:
                    key = f"{res.name}:{path}"
                    if key in seen_cookies:
                        continue
                    if not res.issues:
                        continue  # Don't mark as seen — same cookie may have issues at another path
                    seen_cookies.add(key)
                    self.report_finding(
                        type="Cookie Security Flag",
                        severity=res.severity,
                        url=url,
                        cookie_name=res.name,
                        http_only=res.http_only,
                        secure=res.secure,
                        same_site=res.same_site,
                        issues=res.issues,
                        description="; ".join(res.issues),
                        remediation=(
                            "Set-Cookie başlığına HttpOnly; Secure; SameSite=Lax ekleyin. "
                            "Session token'ları için SameSite=Strict tercih edin."
                        ),
                    )
                    findings.append(res.to_dict())
            except Exception as e:
                logger.debug(f"[CookieFlagScanner] {url}: {e}")

        return findings


# ---------------------------------------------------------------------------
# SessionFixationExploiter
# ---------------------------------------------------------------------------

class SessionFixationExploiter(BaseScanner):
    """
    Tests session fixation vulnerability:
    1. GET /login -> record pre-auth session token
    2. POST credentials -> check if session token changed
    3. If same token -> session fixation confirmed

    Also tests forced session injection via URL (sid= parameter).

    SOLID/SRP: Only session fixation testing.
    """

    _SESSION_PARAMS = ["sid", "session_id", "PHPSESSID", "jsessionid", "sessid", "token"]

    def run(self, target: str, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        login_url = kwargs.get("login_url") or target.rstrip("/") + "/login"
        credentials = kwargs.get("credentials") or {"username": "test", "password": "test"}

        # --- Test 1: Pre/post-auth token comparison ---
        try:
            pre_session = hardened_session({})
            pre_session.verify = False
            # Response body is irrelevant here — we only need the Set-Cookie side
            # effect captured in the session jar.
            pre_session.get(login_url, timeout=_TIMEOUT, allow_redirects=True)
            pre_cookies = dict(pre_session.cookies)

            pre_tokens = {k: v for k, v in pre_cookies.items() if _SENSITIVE_NAMES.search(k)}
            if not pre_tokens:
                logger.debug("[SessionFixation] No session cookie found pre-auth")
            else:
                # Login with same session (we read the post-auth cookie jar, not
                # the response body).
                pre_session.post(
                    login_url, data=credentials, timeout=_TIMEOUT, allow_redirects=True
                )
                post_cookies = dict(pre_session.cookies)
                post_tokens = {k: v for k, v in post_cookies.items() if _SENSITIVE_NAMES.search(k)}

                for name, pre_val in pre_tokens.items():
                    post_val = post_tokens.get(name)
                    if post_val and pre_val == post_val:
                        self.report_finding(
                            type="Session Fixation",
                            severity="High",
                            url=login_url,
                            cookie_name=name,
                            pre_auth_value=pre_val[:16] + "...",
                            post_auth_value=post_val[:16] + "...",
                            description=(
                                f"'{name}' session token login sonrası değişmedi — "
                                "session fixation saldırısına karşı savunmasız"
                            ),
                            remediation=(
                                "Login sonrası session_regenerate_id(true) veya eşdeğeri çağrılmalı. "
                                "Eski session token geçersiz kılınmalı."
                            ),
                        )
                        findings.append({"cookie": name, "fixed": True})
        except Exception as e:
            logger.debug(f"[SessionFixation] Test 1 failed: {e}")

        # --- Test 2: URL-based session injection ---
        fixed_token = "WEBSECURE_FIXED_" + uuid.uuid4().hex[:8]
        for param in self._SESSION_PARAMS:
            test_url = f"{login_url}?{param}={fixed_token}"
            try:
                s = hardened_session({})
                s.verify = False
                s.get(test_url, timeout=_TIMEOUT, allow_redirects=True)
                jar = dict(s.cookies)
                if jar.get(param) == fixed_token or jar.get(param.upper()) == fixed_token:
                    self.report_finding(
                        type="Session Fixation (URL-based)",
                        severity="High",
                        url=test_url,
                        parameter=param,
                        injected_token=fixed_token,
                        description=(
                            f"URL parametresi '{param}' ile session token enjekte edildi — "
                            "sunucu URL'deki session ID'yi kabul ediyor"
                        ),
                        remediation=(
                            "Session token URL parametrelerinden alınmamalı. "
                            "Sadece HttpOnly cookie kullanın."
                        ),
                    )
                    findings.append({"param": param, "url_fixation": True})
            except Exception as e:
                logger.debug(f"[SessionFixation] URL test {param}: {e}")

        return findings


# ---------------------------------------------------------------------------
# CookieInjectionProber
# ---------------------------------------------------------------------------

class CookieInjectionProber(BaseScanner):
    """
    Tests CRLF injection that leads to Set-Cookie header injection.
    Injects CRLF sequences into URL parameters and HTTP headers.
    Looks for reflected Set-Cookie in response.

    SOLID/SRP: Only cookie injection via CRLF testing.
    """

    _CRLF_PAYLOADS = [
        "\r\nSet-Cookie: injected=1",
        "\r\nSet-Cookie: injected=1; HttpOnly",
        "%0d%0aSet-Cookie: injected=1",
        "%0aSet-Cookie: injected=1",
        "\r\n\t Set-Cookie: injected=1",
        "%0d%0a%09Set-Cookie: injected=1",
        "%E5%98%8D%E5%98%8ASet-Cookie: injected=1",  # Unicode CRLF
        "\\r\\nSet-Cookie: injected=1",
    ]

    _PROBE_PARAMS = ["next", "redirect", "url", "return", "path", "ref", "goto", "dest"]
    _PROBE_HEADERS = ["Referer", "X-Forwarded-Host", "Location", "Host"]

    def run(self, target: str, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.rstrip("/")

        for param in self._PROBE_PARAMS:
            for payload in self._CRLF_PAYLOADS[:4]:
                test_url = f"{base}/?{param}={payload}"
                try:
                    r = self.session.get(
                        test_url, timeout=_TIMEOUT, verify=False, allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    # Check if injected cookie appears in response
                    set_cookie_hdrs = [
                        v for k, v in r.headers.items() if k.lower() == "set-cookie"
                    ]
                    if any("injected=1" in h for h in set_cookie_hdrs):
                        self.report_finding(
                            type="Cookie Injection via CRLF",
                            severity="High",
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            reflected_header=set_cookie_hdrs,
                            description=(
                                f"CRLF enjeksiyonu '{param}' parametresinde — "
                                "keyfi Set-Cookie başlığı enjekte edildi"
                            ),
                            remediation=(
                                "Kullanıcı girdisini HTTP yanıt başlıklarına yansıtmadan önce "
                                "CRLF karakterlerini (\\r, \\n) filtreleyin."
                            ),
                        )
                        findings.append({"param": param, "payload": payload})
                        break
                except Exception as e:
                    logger.debug(f"[CookieInject] {param}: {e}")

        return findings


# ---------------------------------------------------------------------------
# JWTExpiryBypassProber
# ---------------------------------------------------------------------------

class JWTExpiryBypassProber(BaseScanner):
    """
    Tests whether expired JWT tokens are accepted by the server.

    Steps:
    1. Collect a valid JWT from the target (via cookie/header)
    2. Manually set exp claim to epoch 0 (past)
    3. Send the tampered JWT -> if 200 returned, vulnerability confirmed

    Also tests: exp claim removal entirely.

    SOLID/SRP: Only JWT expiry validation testing.
    """

    def _decode_jwt_parts(self, token: str):
        parts = token.split(".")
        if len(parts) != 3:
            return None, None, None

        def _b64_decode(s: str) -> dict:
            pad = s + "=" * (-len(s) % 4)
            try:
                return json.loads(base64.urlsafe_b64decode(pad))
            except Exception:
                return {}

        header = _b64_decode(parts[0])
        payload = _b64_decode(parts[1])
        return header, payload, parts[2]

    def _encode_jwt_parts(self, header: dict, payload: dict, sig: str = "") -> str:
        def _b64_encode(d: dict) -> str:
            return base64.urlsafe_b64encode(
                json.dumps(d, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
        return f"{_b64_encode(header)}.{_b64_encode(payload)}.{sig}"

    def _find_jwt_in_response(self, r: requests.Response) -> Optional[str]:
        """Try to extract a JWT from Set-Cookie or Authorization header."""
        for k, v in r.headers.items():
            if k.lower() == "set-cookie":
                m = re.search(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', v)
                if m:
                    return m.group(0)
        for k, v in r.headers.items():
            if k.lower() in ("authorization", "x-auth-token", "x-access-token"):
                m = re.search(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', v)
                if m:
                    return m.group(0)
        # Check cookies
        for k, v in r.cookies.items():
            m = re.search(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', v)
            if m:
                return m.group(0)
        return None

    def run(self, target: str, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        jwt_token = kwargs.get("jwt_token")
        protected_url = kwargs.get("protected_url") or target.rstrip("/") + "/api/me"
        auth_header = kwargs.get("auth_header", "Authorization")

        if not jwt_token:
            # Try to collect a JWT from login or protected page
            try:
                r = self.session.get(
                    protected_url, timeout=_TIMEOUT, verify=False,
                    headers={"Authorization": "Bearer invalid.token.here"},
                )
                jwt_token = self._find_jwt_in_response(r)
            except Exception as _fix_e:
                logger.debug(f"[scanners.session_scanner] {type(_fix_e).__name__}: {_fix_e!r}")

        if not jwt_token:
            logger.debug("[JWTExpiry] No JWT token found — skipping")
            return findings

        header, payload, sig = self._decode_jwt_parts(jwt_token)
        if not payload:
            return findings

        # --- Test 1: Set exp to 0 (past) ---
        tampered_payload = {**payload, "exp": 0}
        tampered_token = self._encode_jwt_parts(header or {}, tampered_payload, sig)

        for test_name, token in [
            ("expired_exp_0", tampered_token),
            ("exp_removed", self._encode_jwt_parts(
                header or {},
                {k: v for k, v in payload.items() if k != "exp"},
                sig,
            )),
        ]:
            try:
                r = self.session.get(
                    protected_url, timeout=_TIMEOUT, verify=False,
                    headers={auth_header: f"Bearer {token}"},
                )
                if r.status_code == 200:
                    self.report_finding(
                        type="JWT Expiry Bypass",
                        severity="Critical",
                        url=protected_url,
                        test=test_name,
                        tampered_token=token[:64] + "...",
                        response_status=r.status_code,
                        description=(
                            f"Süresi dolmuş/exp'siz JWT kabul edildi ({test_name}) — "
                            "token expiry doğrulaması eksik"
                        ),
                        remediation=(
                            "JWT doğrulama kütüphanesi her zaman exp alanını kontrol etmeli. "
                            "options.ignoreExpiration=false olduğundan emin olun."
                        ),
                    )
                    findings.append({"test": test_name, "status": r.status_code})
            except Exception as e:
                logger.debug(f"[JWTExpiry] {test_name}: {e}")

        return findings


# ---------------------------------------------------------------------------
# BrowserFingerprintBypassProber
# ---------------------------------------------------------------------------

class BrowserFingerprintBypassProber(BaseScanner):
    """
    Tests whether the server relies on browser fingerprinting to protect sessions.
    If session remains valid after UA/Accept header swap -> fingerprint not enforced.
    If session invalidated -> fingerprint-based protection detected (defensive behavior).

    Also tests session token reuse from a different IP (via X-Forwarded-For spoofing).

    SOLID/SRP: Only browser fingerprint bypass testing.
    """

    _ALT_AGENTS = [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "curl/7.88.1",
        "python-requests/2.28.2",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile/15E148",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        login_url = kwargs.get("login_url") or target.rstrip("/") + "/login"
        protected_url = kwargs.get("protected_url") or target.rstrip("/") + "/api/me"
        credentials = kwargs.get("credentials") or {"username": "test", "password": "test"}
        original_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"

        # Step 1: Establish session with original UA
        s = hardened_session({})
        s.verify = False
        s.headers["User-Agent"] = original_ua
        try:
            s.post(login_url, data=credentials, timeout=_TIMEOUT, allow_redirects=True)
            session_cookies = dict(s.cookies)
            if not session_cookies:
                return findings
        except Exception as e:
            logger.debug(f"[BrowserFP] Login failed: {e}")
            return findings

        # Step 2: Replay session with different UA / Accept headers
        for alt_ua in self._ALT_AGENTS[:2]:
            try:
                replay = hardened_session({})
                replay.verify = False
                replay.cookies.update(session_cookies)
                replay.headers["User-Agent"] = alt_ua
                r = replay.get(protected_url, timeout=_TIMEOUT, allow_redirects=True)

                if r.status_code == 200 and "login" not in r.url.lower():
                    self.report_finding(
                        type="Browser Fingerprint Session Bypass",
                        severity="Medium",
                        url=protected_url,
                        original_ua=original_ua[:60],
                        replay_ua=alt_ua,
                        response_status=r.status_code,
                        description=(
                            "Session token farklı User-Agent ile kabul edildi — "
                            "browser fingerprint koruması etkin değil"
                        ),
                        remediation=(
                            "Session oluşturulurken User-Agent, Accept ve diğer "
                            "fingerprint başlıkları bağlanmalı. Değişirse oturum sonlandırılmalı."
                        ),
                    )
                    findings.append({"alt_ua": alt_ua, "bypass": True})
                    break
            except Exception as e:
                logger.debug(f"[BrowserFP] replay with {alt_ua[:30]}: {e}")

        # Step 3: IP spoof replay
        try:
            spoof = hardened_session({})
            spoof.verify = False
            spoof.cookies.update(session_cookies)
            spoof.headers["X-Forwarded-For"] = "1.2.3.4"
            spoof.headers["X-Real-IP"] = "1.2.3.4"
            r_spoof = spoof.get(protected_url, timeout=_TIMEOUT, allow_redirects=True)
            if r_spoof.status_code == 200 and "login" not in r_spoof.url.lower():
                self.report_finding(
                    type="Session IP Binding Bypass",
                    severity="Medium",
                    url=protected_url,
                    spoofed_ip="1.2.3.4",
                    response_status=r_spoof.status_code,
                    description=(
                        "Session farklı IP adresinden (X-Forwarded-For spoofing) kabul edildi — "
                        "IP bazlı session binding etkin değil"
                    ),
                    remediation="Session'ı başlatılan IP ile ilişkilendirin; değişirse sona erdirin.",
                )
                findings.append({"ip_spoof_bypass": True})
        except Exception as e:
            logger.debug(f"[BrowserFP] IP spoof test: {e}")

        return findings


# ---------------------------------------------------------------------------
# ConcurrentSessionBypassProber
# ---------------------------------------------------------------------------

class ConcurrentSessionBypassProber(BaseScanner):
    """
    Tests concurrent session limits:
    - Creates N sessions for the same user
    - Verifies if older sessions remain valid (limit bypass)

    Also tests: session token replay from different geographic location
    (X-Country-Code header swap).

    SOLID/SRP: Only concurrent session testing.
    """

    def run(self, target: str, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        login_url = kwargs.get("login_url") or target.rstrip("/") + "/login"
        protected_url = kwargs.get("protected_url") or target.rstrip("/") + "/api/me"
        credentials = kwargs.get("credentials") or {"username": "test", "password": "test"}
        n = int(kwargs.get("n_sessions", 3))

        prober = SessionLifecycleProber(timeout=_TIMEOUT, session=self.session)
        result = prober.test_concurrent_sessions(
            login_url, protected_url, credentials, n_sessions=n
        )

        if result.get("tested") and result.get("first_session_still_valid"):
            self.report_finding(
                type="Concurrent Session Limit Bypass",
                severity=result.get("severity", "Medium"),
                url=login_url,
                sessions_created=result.get("sessions_created"),
                first_session_valid=result.get("first_session_still_valid"),
                description=result.get("description", ""),
                remediation=(
                    "Aynı hesap için maksimum aktif oturum sayısı sınırlandırılmalı. "
                    "Yeni oturum oluşturulduğunda en eski oturum geçersiz kılınmalı."
                ),
            )
            findings.append(result)

        return findings


# ---------------------------------------------------------------------------
# WeakSessionBruteForcer  (ported from session_hunter._brute_common)
# ---------------------------------------------------------------------------

class WeakSessionBruteForcer(BaseScanner):
    """
    Dictionary attack against well-known weak session ID values.
    Tries every combination of _SESSION_COOKIE_NAMES × _WEAK_SESSION_VALUES
    and checks whether the server treats the request as authenticated.

    SOLID/SRP: Only weak-value brute force testing.
    """

    MAX_WORKERS = 8
    PHASE_TIMEOUT = 60

    def run(self, target: str, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        workers = int(kwargs.get("threads", self.MAX_WORKERS))
        phase_timeout = int(kwargs.get("op_timeout", self.PHASE_TIMEOUT))
        ua = (self.session.headers.get("User-Agent") if self.session else None) or "Mozilla/5.0"

        def check_one(name: str, value: str) -> Optional[Dict]:
            try:
                resp = self.session.get(
                    target,
                    headers={"Cookie": f"{name}={value}", "User-Agent": ua},
                    timeout=5,
                    verify=False,
                )
                if _looks_authenticated(resp.text, resp):
                    return {
                        "type": "Weak Session ID — Dictionary Attack",
                        "severity": "Critical",
                        "url": target,
                        "cookie": f"{name}={value}",
                        "status": resp.status_code,
                        "description": (
                            f"Access gained with trivial session: {name}={value!r}. "
                            "Server accepts a well-known weak session identifier."
                        ),
                        "remediation": (
                            "Use cryptographically random session IDs (os.urandom(32)). "
                            "Never accept predictable or dictionary-word values."
                        ),
                    }
            except Exception as exc:
                logger.debug("[WeakSessionBruteForcer] %s=%s: %s", name, value, exc)
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(check_one, name, val): (name, val)
                for name in _SESSION_COOKIE_NAMES[:6]
                for val in _WEAK_SESSION_VALUES
            }
            try:
                for f in as_completed(futures, timeout=phase_timeout):
                    result = f.result()
                    if result:
                        self.report_finding(**result)
                        findings.append(result)
            except _FutureTimeoutError:
                logger.warning(
                    "[WeakSessionBruteForcer] Phase timed out after %ds", phase_timeout
                )
                for f in futures:
                    f.cancel()

        return findings


# ---------------------------------------------------------------------------
# TimestampSessionPredictor  (ported from session_hunter._predict_timestamp_sessions)
# ---------------------------------------------------------------------------

class TimestampSessionPredictor(BaseScanner):
    """
    Timestamp-seed prediction attack.
    Generates candidate session IDs derived from Unix timestamps over the last
    15 minutes (30-second intervals → ~30 seeds × 6 hash variants = 180 probes).

    Covers: MD5, SHA256, SHA1, base64, user-prefixed MD5 variants.

    SOLID/SRP: Only timestamp-based session prediction testing.
    """

    MAX_WORKERS = 8
    PHASE_TIMEOUT = 60

    def run(self, target: str, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        workers = int(kwargs.get("threads", self.MAX_WORKERS))
        phase_timeout = int(kwargs.get("op_timeout", self.PHASE_TIMEOUT))
        ua = (self.session.headers.get("User-Agent") if self.session else None) or "Mozilla/5.0"

        now = int(time.time())
        seeds = list(range(now - 900, now, 30))   # 15 min window, 30s intervals
        logger.info("[TimestampSessionPredictor] Testing %d timestamp seeds", len(seeds))

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
                for name in _SESSION_COOKIE_NAMES[:5]:
                    try:
                        resp = self.session.get(
                            target,
                            headers={"Cookie": f"{name}={val}", "User-Agent": ua},
                            timeout=4,
                            verify=False,
                        )
                        if _looks_authenticated(resp.text, resp):
                            return {
                                "type": "Predictable Session ID — Timestamp Seed",
                                "severity": "Critical",
                                "url": target,
                                "seed_timestamp": ts,
                                "cookie": f"{name}={val}",
                                "description": (
                                    f"Session derived from Unix timestamp {ts} was accepted. "
                                    "Server uses time-based session generation — "
                                    "trivially brute-forceable within a 15-minute window."
                                ),
                                "remediation": (
                                    "Session IDs must be generated from a CSPRNG (os.urandom). "
                                    "Never derive session tokens from predictable inputs like timestamps."
                                ),
                            }
                    except Exception as exc:
                        logger.debug(
                            "[TimestampSessionPredictor] ts=%d name=%s: %s", ts, name, exc
                        )
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(test_seed, ts): ts for ts in seeds}
            try:
                for f in as_completed(futures, timeout=phase_timeout):
                    result = f.result()
                    if result:
                        self.report_finding(**result)
                        findings.append(result)
            except _FutureTimeoutError:
                logger.warning(
                    "[TimestampSessionPredictor] Phase timed out after %ds", phase_timeout
                )
                for f in futures:
                    f.cancel()

        return findings


# ---------------------------------------------------------------------------
# SessionScanner (Adım 12 orchestrator)
# ---------------------------------------------------------------------------

class SessionScanner(BaseScanner):
    """
    Adim 12 orchestrator: Session & Cookie security full audit.

    Runs:
    1. CookieFlagScanner         — HttpOnly/Secure/SameSite flag audit
    2. SessionFixationExploiter  — Pre/post-auth token rotation test
    3. CookieInjectionProber     — CRLF -> Set-Cookie injection
    4. JWTExpiryBypassProber     — Expired JWT accepted?
    5. BrowserFingerprintBypassProber — UA/IP swap session bypass
    6. ConcurrentSessionBypassProber  — Concurrent session limit test
    7. SessionEntropyAnalyzer    — Session ID predictability score

    SOLID/LSP: All sub-scanners are interchangeable via BaseScanner interface.
    """

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_findings: List[Dict] = []

        sub_scanners = [
            ("CookieFlagScanner",             CookieFlagScanner),
            ("SessionFixationExploiter",       SessionFixationExploiter),
            ("CookieInjectionProber",          CookieInjectionProber),
            ("JWTExpiryBypassProber",          JWTExpiryBypassProber),
            ("BrowserFingerprintBypassProber", BrowserFingerprintBypassProber),
            ("ConcurrentSessionBypassProber",  ConcurrentSessionBypassProber),
            ("WeakSessionBruteForcer",         WeakSessionBruteForcer),
            ("TimestampSessionPredictor",      TimestampSessionPredictor),
        ]

        for name, ScannerClass in sub_scanners:
            try:
                scanner = ScannerClass(session=self.session, results=self.results, debug=self.debug)
                findings = scanner.run(target, **kwargs)
                for f in findings:
                    f.setdefault("scanner", name)
                all_findings.extend(findings)
                logger.debug(f"[SessionScanner] {name}: {len(findings)} bulgu")
            except Exception as e:
                logger.warning(f"[SessionScanner] {name} hatası: {e}")

        # Session entropy analysis (non-destructive, no credentials needed)
        try:
            entropy_analyzer = SessionEntropyAnalyzer(sample_count=6, session=self.session)
            entropy_result = entropy_analyzer.analyze(target)
            if entropy_result.get("severity") in ("Critical", "High", "Medium"):
                self.report_finding(
                    type="Session Entropy",
                    severity=entropy_result["severity"],
                    url=target,
                    entropy_bits=entropy_result.get("avg_entropy_bits"),
                    min_entropy_bits=entropy_result.get("min_entropy_bits"),
                    unique_ratio=entropy_result.get("unique_ratio"),
                    verdict=entropy_result.get("verdict"),
                    description=(
                        f"Session token entropisi: {entropy_result.get('avg_entropy_bits')} bit — "
                        f"{entropy_result.get('verdict')}"
                    ),
                    remediation=(
                        "Session ID en az 128-bit kriptografik rastgelelik içermeli. "
                        "os.urandom(32) veya secrets.token_hex(32) kullanın."
                    ),
                )
                all_findings.append({**entropy_result, "scanner": "SessionEntropyAnalyzer"})
        except Exception as e:
            logger.debug(f"[SessionScanner] Entropy analysis failed: {e}")

        for finding in all_findings:
            add_result("session", finding)

        logger.info(f"[SessionScanner] Toplam {len(all_findings)} bulgu — {target}")
        return all_findings


def run(url: str, session=None, results: dict = None, debug: bool = False, **kwargs) -> list:
    """Standard (url, session=, results=, ...) entry point for phase runner and _call_if_exists."""
    scanner = SessionScanner(session=session, results=results if results is not None else {}, debug=debug)
    return scanner.run(url, **kwargs)
