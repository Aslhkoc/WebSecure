"""
websecure.core.fp_reducer
~~~~~~~~~~~~~~~~~~~~~~~~~~~
False-positive reduction engine for WebSecure.

Implements:
  1. Reproducibility testing — re-verify findings N times before reporting
  2. Confidence scoring — aggregate signal strength across attempts
  3. Deduplication gate — cross-scanner global dedup to prevent double-reporting
  4. Stability filter — reject findings that appear intermittently

Why reproducibility matters:
  - Time-based SQLi spikes can be server hiccups
  - Error-based findings can be from flaky static content
  - XSS canary might appear coincidentally in ADS/analytics tags

This module is used by scanners to gate their report_finding() calls.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests as _requests

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Finding dataclass for verification
# ---------------------------------------------------------------------------

@dataclass
class FindingVerification:
    """Result of reproducibility testing for a single finding."""
    finding_key: str        # dedup key
    attempts: int           # total verification attempts
    successes: int          # how many re-confirmed
    confidence: float       # 0.0–1.0 aggregate
    is_confirmed: bool      # True when successes/attempts >= threshold
    evidence_chain: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Global cross-scanner deduplication registry
# ---------------------------------------------------------------------------

class _GlobalFindingRegistry:
    """
    Thread-safe global set of already-reported finding keys.
    Prevents duplicate findings from multiple scanners reporting the same issue.
    """
    _instance: Optional["_GlobalFindingRegistry"] = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._seen: set = set()
        self._lock = threading.Lock()
        self._stats: Dict[str, int] = {"registered": 0, "suppressed": 0}

    @classmethod
    def get(cls) -> "_GlobalFindingRegistry":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance

    def is_seen(self, key: str) -> bool:
        with self._lock:
            return key in self._seen

    def register(self, key: str) -> bool:
        """Register key. Returns False if already registered (suppress)."""
        with self._lock:
            if key in self._seen:
                self._stats["suppressed"] += 1
                return False
            self._seen.add(key)
            self._stats["registered"] += 1
            return True

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    @classmethod
    def reset(cls) -> None:
        """Reset for new scan session."""
        with cls._instance_lock:
            if cls._instance:
                with cls._instance._lock:
                    cls._instance._seen.clear()
                    cls._instance._stats = {"registered": 0, "suppressed": 0}


# ---------------------------------------------------------------------------
# Reproducibility Verifier
# ---------------------------------------------------------------------------

class ReproducibilityVerifier:
    """
    Verifies a candidate finding by re-running the probe N times.
    Returns FindingVerification with confidence score.

    Confirmation rules:
      - Error-based SQLi:  ≥2/3 re-confirmations (errors must be reproducible)
      - Time-based SQLi:   ≥3/3 re-confirmations (timing is noisy)
      - XSS reflection:    ≥2/2 re-confirmations (reflections should be stable)
      - Default:           ≥2/3 re-confirmations

    Confidence scoring:
      conf = (successes / attempts) * stability_factor
      where stability_factor = 1.0 if all hits consistent, < 1.0 if intermittent
    """

    # Required successes per detection method
    _CONFIRMATION_THRESHOLDS: Dict[str, Tuple[int, int]] = {
        "error_based":           (2, 3),   # 2/3
        "boolean_blind":         (2, 3),
        "time_based":            (3, 3),   # 3/3 — no false-positive budget
        "union_based":           (2, 2),   # 2/2 — union is usually stable
        "reflection":            (2, 2),   # 2/2
        "dom_playwright":        (1, 1),   # DOM confirmed = 1/1 enough
        "schema_extraction":     (1, 1),   # extraction = irrefutable
        "sqlmap_confirmed":      (1, 1),   # external tool confirmed
        "header_error":          (2, 3),
        "json_error":            (2, 3),
        "adaptive_waf_bypass":   (2, 3),
        "stacked_query":         (3, 3),
        "oob_dns":               (1, 1),   # async — accept on send
    }

    _DEFAULT_THRESHOLD = (2, 3)

    def __init__(self, session: Any, *, enable: bool = True) -> None:
        self.session = session
        self.enable = enable

    def verify(
        self,
        vuln_type: str,
        url: str,
        param: str,
        payload: str,
        probe_fn: Callable[[], bool],
        detection_method: str = "error_based",
    ) -> FindingVerification:
        """
        Run probe_fn() the required number of times.
        probe_fn() should return True if the vulnerability condition is met.

        Returns FindingVerification — caller decides whether to report.
        """
        key = self._make_key(vuln_type, url, param, payload)

        if not self.enable:
            # Verification disabled — pass through with medium confidence
            return FindingVerification(
                finding_key=key,
                attempts=1,
                successes=1,
                confidence=0.65,
                is_confirmed=True,
                evidence_chain=["verification_disabled"],
            )

        required, total = self._CONFIRMATION_THRESHOLDS.get(
            detection_method, self._DEFAULT_THRESHOLD
        )

        successes = 0
        evidence_chain: List[str] = []

        for i in range(total):
            t0 = time.time()
            try:
                ok = probe_fn()
                elapsed = time.time() - t0
                if ok:
                    successes += 1
                    evidence_chain.append(f"trial_{i+1}: confirmed ({elapsed:.2f}s)")
                else:
                    evidence_chain.append(f"trial_{i+1}: not_confirmed ({elapsed:.2f}s)")
            except Exception as exc:
                evidence_chain.append(f"trial_{i+1}: error ({exc!r})")

        hit_rate = successes / total
        # Stability penalty: if intermittent (some hit, some miss), reduce confidence
        stability = 1.0 if (successes == total or successes == 0) else max(0.70, hit_rate)
        confidence = round(hit_rate * stability, 3)

        is_confirmed = successes >= required

        return FindingVerification(
            finding_key=key,
            attempts=total,
            successes=successes,
            confidence=confidence,
            is_confirmed=is_confirmed,
            evidence_chain=evidence_chain,
        )

    @staticmethod
    def _make_key(vuln_type: str, url: str, param: str, payload: str) -> str:
        raw = f"{vuln_type}|{url}|{param}|{payload[:80]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# False Positive Reducer — main public API
# ---------------------------------------------------------------------------

class FalsePositiveReducer:
    """
    Orchestrates reproducibility verification and global dedup.

    Usage (from scanners):
        fpr = FalsePositiveReducer(session)

        verification = fpr.verify_and_gate(
            vuln_type="SQL Injection (Error)",
            url=url, param=param, payload=payload,
            probe_fn=lambda: error_check(url, param, payload),
            detection_method="error_based",
        )
        if verification.is_confirmed:
            self.report_finding(...)
    """

    def __init__(self, session: Any, *, verify_enabled: bool = True) -> None:
        self._verifier = ReproducibilityVerifier(session, enable=verify_enabled)
        self._registry = _GlobalFindingRegistry.get()

    def verify_and_gate(
        self,
        vuln_type: str,
        url: str,
        param: str,
        payload: str,
        probe_fn: Callable[[], bool],
        detection_method: str = "error_based",
    ) -> FindingVerification:
        """
        Full FP-reduction pipeline:
          1. Check global dedup (don't re-test already reported findings)
          2. Run reproducibility verification
          3. Register confirmed findings in global registry
        Returns FindingVerification with is_confirmed flag.
        """
        key = ReproducibilityVerifier._make_key(vuln_type, url, param, payload)

        if self._registry.is_seen(key):
            _logger.debug(f"[FPR] Global dedup suppressed: {vuln_type} @ {url} param={param}")
            return FindingVerification(
                finding_key=key,
                attempts=0,
                successes=0,
                confidence=0.0,
                is_confirmed=False,
                evidence_chain=["global_dedup_suppressed"],
            )

        verification = self._verifier.verify(
            vuln_type, url, param, payload, probe_fn, detection_method
        )

        if verification.is_confirmed:
            self._registry.register(key)

        return verification

    def is_globally_seen(self, vuln_type: str, url: str, param: str, payload: str) -> bool:
        key = ReproducibilityVerifier._make_key(vuln_type, url, param, payload)
        return self._registry.is_seen(key)

    def stats(self) -> Dict[str, Any]:
        return {
            "registry": self._registry.stats(),
        }

    @staticmethod
    def reset_session() -> None:
        """Call at start of each new scan to clear cross-scan state."""
        _GlobalFindingRegistry.reset()


__all__ = [
    "FindingVerification",
    "ReproducibilityVerifier",
    "FalsePositiveReducer",
]
