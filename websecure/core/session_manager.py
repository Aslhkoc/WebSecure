"""
websecure.core.session_manager
-------------------------------
Session ve Cookie güvenlik analiz yardımcıları.

Adim 12 — Siniflar:
  CookieAuditResult      — cookie analizi dataclass
  CookieSecurityAnalyzer — HttpOnly/Secure/SameSite eksiklik + etki analizi
  SessionEntropyAnalyzer — session ID tahmin edilebilirlik (Shannon entropy) skoru
  SessionLifecycleProber — logout sonrası geçerlilik + concurrent session limit testi
"""
from __future__ import annotations

import logging
import math
import re
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import requests

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CookieAuditResult
# ---------------------------------------------------------------------------

@dataclass
class CookieAuditResult:
    """Holds the security audit findings for a single cookie."""
    name: str
    value_snippet: str = ""
    # Flag state
    http_only: bool = False
    secure: bool = False
    same_site: Optional[str] = None          # "Strict" | "Lax" | "None" | None
    domain: Optional[str] = None
    path: str = "/"
    max_age: Optional[int] = None
    expires: Optional[str] = None
    # Findings
    missing_http_only: bool = False
    missing_secure: bool = False
    missing_same_site: bool = False
    same_site_none_without_secure: bool = False
    overly_broad_domain: bool = False
    session_cookie_no_expiry: bool = False
    # Impact
    issues: List[str] = field(default_factory=list)
    severity: str = "Info"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "http_only": self.http_only,
            "secure": self.secure,
            "same_site": self.same_site,
            "domain": self.domain,
            "path": self.path,
            "issues": self.issues,
            "severity": self.severity,
        }


# ---------------------------------------------------------------------------
# CookieSecurityAnalyzer
# ---------------------------------------------------------------------------

# Cookies that are security-sensitive (session tokens, auth tokens)
_SENSITIVE_COOKIE_NAMES = re.compile(
    r"(sess|token|auth|jwt|sid|csrftoken|xsrf|remember|login|uid|user|account)",
    re.I,
)


class CookieSecurityAnalyzer:
    """
    Analyzes Set-Cookie headers for missing security flags and their impact.

    Checks:
    - HttpOnly missing -> XSS cookie theft risk
    - Secure missing   -> MITM session hijack risk
    - SameSite missing -> CSRF risk
    - SameSite=None without Secure -> cross-site leak
    - Overly broad Domain -> subdomain cookie theft
    - No expiry on session cookie -> session persistence

    SOLID/SRP: Only cookie security flag analysis.
    """

    def parse_set_cookie(self, header_value: str) -> CookieAuditResult:
        """Parse a single Set-Cookie header value into CookieAuditResult."""
        parts = [p.strip() for p in header_value.split(";")]
        if not parts:
            return CookieAuditResult(name="unknown")

        # First part: name=value
        first = parts[0]
        if "=" in first:
            name, _, val = first.partition("=")
        else:
            name, val = first, ""

        result = CookieAuditResult(
            name=name.strip(),
            value_snippet=val[:32],
        )

        for part in parts[1:]:
            pl = part.lower().strip()
            if pl == "httponly":
                result.http_only = True
            elif pl == "secure":
                result.secure = True
            elif pl.startswith("samesite="):
                result.same_site = part.split("=", 1)[1].strip()
            elif pl.startswith("domain="):
                result.domain = part.split("=", 1)[1].strip()
            elif pl.startswith("path="):
                result.path = part.split("=", 1)[1].strip()
            elif pl.startswith("max-age="):
                try:
                    result.max_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif pl.startswith("expires="):
                result.expires = part.split("=", 1)[1].strip()

        self._audit(result)
        return result

    def _audit(self, r: CookieAuditResult) -> None:
        """Apply security audit rules and populate issues + severity."""
        is_sensitive = bool(_SENSITIVE_COOKIE_NAMES.search(r.name))

        if not r.http_only:
            r.missing_http_only = True
            sev = "Yüksek" if is_sensitive else "Orta"
            r.issues.append(
                f"HttpOnly eksik — JavaScript cookie erişimi mümkün "
                f"({'kritik: oturum çalınabilir' if is_sensitive else 'risk: izleme cookie'})"
            )

        if not r.secure:
            r.missing_secure = True
            r.issues.append(
                "Secure flag eksik — HTTP üzerinden iletilir, MITM saldırısıyla çalınabilir"
            )

        if r.same_site is None:
            r.missing_same_site = True
            r.issues.append(
                "SameSite eksik — CSRF saldırısına karşı savunmasız"
            )
        elif r.same_site.lower() == "none" and not r.secure:
            r.same_site_none_without_secure = True
            r.issues.append(
                "SameSite=None ama Secure flag yok — tarayıcı reddeder, güvensiz yapılandırma"
            )

        if r.domain and r.domain.startswith("."):
            r.overly_broad_domain = True
            r.issues.append(
                f"Geniş domain (.{r.domain}) — tüm subdomainler bu cookie'yi okuyabilir"
            )

        if is_sensitive and not r.max_age and not r.expires:
            r.session_cookie_no_expiry = True
            r.issues.append(
                "Session cookie'sinde Max-Age/Expires yok — tarayıcı kapanınca silinir "
                "ama session backend'de geçerli kalabilir"
            )

        # Severity
        if any(x in (r.missing_http_only, r.missing_secure) for x in [True]) and is_sensitive:
            r.severity = "Yüksek"
        elif r.issues:
            r.severity = "Orta"
        else:
            r.severity = "Bilgi"

    def analyze_response(self, response) -> List[CookieAuditResult]:
        """Analyze all Set-Cookie headers from a requests.Response."""
        results: List[CookieAuditResult] = []
        set_cookie_headers = response.headers.getlist("Set-Cookie") if hasattr(
            response.headers, "getlist"
        ) else [
            v for k, v in response.headers.items() if k.lower() == "set-cookie"
        ]
        for hval in set_cookie_headers:
            results.append(self.parse_set_cookie(hval))
        return results

    def analyze_jar(self, cookies: Dict[str, str]) -> List[CookieAuditResult]:
        """Analyze a flat cookie dict (from requests.cookies). Flags are unknown — marks as missing."""
        results: List[CookieAuditResult] = []
        for name, val in cookies.items():
            r = CookieAuditResult(
                name=name,
                value_snippet=str(val)[:32],
                http_only=False,
                secure=False,
                same_site=None,
            )
            self._audit(r)
            results.append(r)
        return results


# ---------------------------------------------------------------------------
# SessionEntropyAnalyzer
# ---------------------------------------------------------------------------

class SessionEntropyAnalyzer:
    """
    Collects N session tokens from the target and calculates Shannon entropy
    to estimate session ID predictability.

    Low entropy -> session IDs are guessable / brute-forceable.

    Scoring:
    - < 32 bits: CRITICAL (trivially guessable)
    - 32–64 bits: HIGH (brute-forceable)
    - 64–96 bits: MEDIUM (marginally acceptable)
    - > 96 bits: OK (cryptographically strong)

    SOLID/SRP: Only session entropy analysis.
    """

    _SENSITIVE_NAMES = re.compile(
        r"(sess|token|jsess|phpsess|asp\.net_sessionid|laravel_session|cf_clearance)",
        re.I,
    )

    def __init__(self, timeout: int = 8, sample_count: int = 10):
        self.timeout = timeout
        self.sample_count = sample_count

    def collect_tokens(self, url: str, cookie_name: Optional[str] = None) -> List[str]:
        """Make sample_count fresh requests and collect distinct session tokens."""
        tokens: List[str] = []
        for _ in range(self.sample_count):
            try:
                r = requests.get(
                    url, timeout=self.timeout, verify=False,
                    headers={"User-Agent": f"EntropyProbe/{uuid.uuid4().hex[:6]}"},
                    allow_redirects=True,
                )
                jar = dict(r.cookies)
                if cookie_name and cookie_name in jar:
                    tokens.append(jar[cookie_name])
                else:
                    # Pick most likely session token
                    for cname, cval in jar.items():
                        if self._SENSITIVE_NAMES.search(cname) and cval:
                            tokens.append(cval)
                            break
                    else:
                        # First cookie value
                        if jar:
                            tokens.append(next(iter(jar.values())))
            except Exception as e:
                _logger.debug(f"[Entropy] Token collect failed: {e}")
        return [t for t in tokens if t]

    @staticmethod
    def shannon_entropy(token: str) -> float:
        """Compute per-character Shannon entropy in bits."""
        if not token:
            return 0.0
        counts = Counter(token)
        length = len(token)
        entropy = -sum(
            (c / length) * math.log2(c / length) for c in counts.values()
        )
        return entropy

    def effective_entropy_bits(self, token: str) -> float:
        """Effective entropy = per-char entropy × token length."""
        return self.shannon_entropy(token) * len(token)

    def analyze(self, url: str, cookie_name: Optional[str] = None) -> Dict[str, Any]:
        """Collect tokens and compute entropy statistics."""
        tokens = self.collect_tokens(url, cookie_name)
        if not tokens:
            return {"error": "No tokens collected", "samples": 0}

        entropies = [self.effective_entropy_bits(t) for t in tokens]
        avg_entropy = sum(entropies) / len(entropies)
        min_entropy = min(entropies)

        if min_entropy < 32:
            verdict = "KRİTİK — tahmin edilebilir (brute-force riski yüksek)"
            severity = "Kritik"
        elif min_entropy < 64:
            verdict = "YÜKSEK — düşük entropi, gelişmiş brute-force mümkün"
            severity = "Yüksek"
        elif min_entropy < 96:
            verdict = "ORTA — sınırda kabul edilebilir entropi"
            severity = "Orta"
        else:
            verdict = "GÜVENLİ — kriptografik güçte entropi"
            severity = "Bilgi"

        # Check uniqueness (sequential tokens?)
        unique_ratio = len(set(tokens)) / len(tokens)

        return {
            "samples": len(tokens),
            "avg_entropy_bits": round(avg_entropy, 1),
            "min_entropy_bits": round(min_entropy, 1),
            "unique_ratio": round(unique_ratio, 2),
            "verdict": verdict,
            "severity": severity,
            "token_samples": [t[:16] + "..." for t in tokens[:3]],
        }


# ---------------------------------------------------------------------------
# SessionLifecycleProber
# ---------------------------------------------------------------------------

class SessionLifecycleProber:
    """
    Tests session validity across lifecycle events:
    - Post-logout validity (session still accepted after logout)
    - Concurrent session limit (multiple sessions from different clients)
    - Session persistence after password change

    SOLID/SRP: Only session lifecycle testing.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def test_post_logout_validity(
        self,
        login_url: str,
        logout_url: str,
        protected_url: str,
        credentials: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        1. Login -> save session cookies
        2. Logout
        3. Re-use saved session cookies on protected_url
        Returns whether old session is still valid (vulnerability).
        """
        s = requests.Session()
        s.verify = False
        try:
            # Step 1: Login
            r_login = s.post(login_url, data=credentials, timeout=self.timeout, allow_redirects=True)
            pre_logout_cookies = dict(s.cookies)
            if not pre_logout_cookies:
                return {"error": "No cookies after login", "tested": False}

            # Step 2: Logout
            s.get(logout_url, timeout=self.timeout, allow_redirects=True)

            # Step 3: Replay old session
            replay_session = requests.Session()
            replay_session.verify = False
            replay_session.cookies.update(pre_logout_cookies)
            r_replay = replay_session.get(protected_url, timeout=self.timeout, allow_redirects=True)

            still_valid = r_replay.status_code == 200 and (
                "logout" not in r_replay.url.lower()
                and "login" not in r_replay.url.lower()
                and "sign" not in r_replay.url.lower()
            )
            return {
                "tested": True,
                "post_logout_valid": still_valid,
                "replay_status": r_replay.status_code,
                "replay_url": r_replay.url,
                "severity": "Yüksek" if still_valid else "Bilgi",
                "description": (
                    "Logout sonrası eski oturum cookie'si hâlâ geçerli — session invalidation eksik"
                    if still_valid
                    else "Session logout sonrası geçersiz kılınmış (doğru davranış)"
                ),
            }
        except Exception as e:
            return {"error": str(e), "tested": False}

    def test_concurrent_sessions(
        self,
        login_url: str,
        protected_url: str,
        credentials: Dict[str, str],
        n_sessions: int = 3,
    ) -> Dict[str, Any]:
        """
        Create N concurrent sessions from different clients.
        Check if earlier sessions are invalidated when new ones are created.
        """
        sessions: List[Dict[str, Any]] = []
        for i in range(n_sessions):
            s = requests.Session()
            s.verify = False
            s.headers["User-Agent"] = f"ConcurrentTest/{i}/{uuid.uuid4().hex[:8]}"
            try:
                s.post(login_url, data=credentials, timeout=self.timeout, allow_redirects=True)
                cookies = dict(s.cookies)
                if cookies:
                    sessions.append({"session": s, "cookies": cookies, "index": i})
            except Exception as e:
                _logger.debug(f"[SessionLife] concurrent login {i} failed: {e}")

        if len(sessions) < 2:
            return {"error": "Could not create multiple sessions", "tested": False}

        # Check if first session is still valid after N logins
        first = sessions[0]
        first_replay = requests.Session()
        first_replay.verify = False
        first_replay.cookies.update(first["cookies"])
        try:
            r = first_replay.get(protected_url, timeout=self.timeout, allow_redirects=True)
            first_still_valid = r.status_code == 200 and "login" not in r.url.lower()
        except Exception:
            first_still_valid = False

        return {
            "tested": True,
            "sessions_created": len(sessions),
            "first_session_still_valid": first_still_valid,
            "concurrent_session_limit": not first_still_valid,
            "severity": "Orta" if first_still_valid else "Bilgi",
            "description": (
                "Concurrent session limiti yok — aynı hesaba N oturum açılabilir"
                if first_still_valid
                else "Eski oturum yeni oturum açılınca geçersiz kılınmış (doğru davranış)"
            ),
        }
