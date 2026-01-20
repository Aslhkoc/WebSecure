from typing import Dict, Any
from .base import BaseScanner
import requests

class RateLimitScanner(BaseScanner):
    name = "rate_limit"

    def run(self, target: str, **kwargs) -> Any:
        self.logger.info(f"Checking rate limits on {target}")
        
        # 1. Passive Check (Headers)
        try:
            resp = self.session.head(target, timeout=10)
            headers = resp.headers
            
            rl_headers = {k: v for k, v in headers.items() if "ratelimit" in k.lower()}
            
            if rl_headers:
                self.add("rate_limit", {
                    "severity": "Info",
                    "issue": "Rate Limit Headers Detected",
                    "description": "Server exposes rate limit information in headers.",
                    "details": rl_headers,
                    "url": target
                })
                self.logger.info(f"Found Rate Limit headers: {rl_headers}")
            else:
                self.logger.debug("No rate limit headers found passively.")

        except Exception as e:
            self.logger.error(f"Rate limit passive check failed: {e}")

        # 2. Active Check (Burst - Optional/Safe)
        # We verify if we can make a small burst of 5 requests without 429
        # This is a 'safety check' rather than a DoS attempt.
        try:
            for i in range(5):
                r = self.session.get(target, params={"t": i}, timeout=5)
                if r.status_code == 429:
                    self.add("rate_limit", {
                        "severity": "Low",
                        "issue": "Strict Rate Limiting Detected",
                        "description": "Server returned 429 Too Many Requests during low-volume burst test.",
                        "url": target
                    })
                    break
        except Exception:
            pass
            pass

def run(target: str, session=None, results=None, **kwargs):
    scanner = RateLimitScanner(session, results)
    scanner.run(target)
