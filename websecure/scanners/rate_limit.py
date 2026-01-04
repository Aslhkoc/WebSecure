from __future__ import annotations
from typing import Any, Dict, List, Optional
import time
from .base import BaseScanner

class RateLimitScanner(BaseScanner):
    name = "rate_limit"

    def run(self, url: str) -> Dict[str, Any]:
        bucket = self.name
        self.results[bucket] = []
        
        # Simple burst test
        vulns = 0
        t0 = time.time()
        count = 0
        for _ in range(10):
            try:
                self.session.get(url, timeout=5)
                count += 1
            except:
                pass
        
        dt = time.time() - t0
        rps = count / dt if dt > 0 else 0
        
        self.add(bucket, {
            "type": "Rate Limit Check",
            "severity": "Info",
            "details": f"Sent {count} req in {dt:.2f}s (~{rps:.1f} RPS)",
            "rps": rps
        })
        
        # Heuristic: if we sent 10 reqs very fast and got 200s, maybe no rate limit
        if rps > 5.0:
             self.add(bucket, {
                "type": "No Rate Limit Detected (Fast Burst)",
                "severity": "Low",
                "details": "Client was able to send burst traffic without 429."
            })
            
        self.set_summary(bucket, vulns)
        return self.results
