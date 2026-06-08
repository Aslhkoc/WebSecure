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
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

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
            # Verification disabled — pass through but mark as unverified.
            # confidence=0.50 signals single-shot finding (no reproducibility check).
            # Callers should treat this as tentative, not confirmed.
            return FindingVerification(
                finding_key=key,
                attempts=0,
                successes=0,
                confidence=0.50,
                is_confirmed=True,
                evidence_chain=["verification_disabled:unverified"],
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

        hit_rate = successes / total if total > 0 else 0.0
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
            self._registry.register(verification.finding_key)

        return verification

    def stats(self) -> Dict[str, Any]:
        return {
            "registry": self._registry.stats(),
        }

    @staticmethod
    def reset_session() -> None:
        """Call at start of each new scan to clear cross-scan state."""
        _GlobalFindingRegistry.reset()


# ---------------------------------------------------------------------------
# Soft-404 / catch-all baseline — shared across scanners
# ---------------------------------------------------------------------------

@dataclass
class _NotFoundSample:
    """One observed 'response for a path that cannot exist'."""
    status: int
    length: int
    prefix: str
    location: str = ""


class SoftNotFoundBaseline:
    """Per-target soft-404 / catch-all detector — compute ONCE, reuse everywhere.

    Many targets (Angular/React SPAs, parked domains, catch-all CDNs/load balancers)
    return HTTP 200 (or a 3xx redirect) with the SAME page for EVERY path — including
    paths that cannot exist. Scanners that infer "endpoint exists" from
    ``status_code not in (404, 410)`` then fire on hundreds of phantom paths
    (this is exactly what flooded the karekod.com parked-domain scan). This class
    probes a few random impossible paths ONCE per origin to learn what the server's
    "not found" answer looks like, then lets callers ask whether a real response is
    a GENUINE hit or just the catch-all page.

    Safety contract (so this is a strict no-op on normal servers and test stubs):
      * ``is_catch_all`` is True ONLY when random impossible paths come back as
        *non-trivial* successes — body >= ``_MIN_BODY`` bytes, or a redirect with a
        Location. Empty/short responses (e.g. unit-test mocks returning empty 200)
        never count → callers behave exactly like the old status check.
      * When not catch-all, ``is_genuine_hit`` returns True for any non-404 — i.e.
        identical to the legacy ``status_code not in (404, 410)`` behaviour.
      * Any probing failure leaves ``samples`` empty → not catch-all → no-op.

    Cached per origin (thread-safe) and cleared per scan session via ``reset()``.
    """

    _MIN_BODY = 50
    _PROBE_EXTS = (".env", ".txt", ".json", ".bak")

    _cache: Dict[str, "SoftNotFoundBaseline"] = {}
    _cache_lock = threading.Lock()
    _origin_locks: Dict[str, threading.Lock] = {}

    def __init__(self, session: Any = None, origin: str = "", *,
                 timeout: int = 5, _probe: bool = True) -> None:
        self.origin = origin
        self.samples: List[_NotFoundSample] = []
        if _probe and session is not None and origin:
            self._probe(session, timeout)

    def _probe(self, session: Any, timeout: int) -> None:
        for ext in self._PROBE_EXTS:
            rnd = "ws-nonexistent-" + os.urandom(8).hex() + ext
            try:
                r = session.get(urljoin(self.origin + "/", rnd),
                                timeout=timeout, allow_redirects=False)
            except Exception as exc:  # network error → just skip this probe
                _logger.debug("[SoftNotFound] probe failed (%s): %r", rnd, exc)
                continue
            try:
                st = int(getattr(r, "status_code", 0) or 0)
            except Exception:
                continue
            if st in (0, 404, 410):
                continue
            body = getattr(r, "text", "") or ""
            loc = ""
            try:
                loc = (getattr(r, "headers", {}) or {}).get("Location", "") or ""
            except Exception:
                loc = ""
            self.samples.append(_NotFoundSample(st, len(body), body[:512], loc))

    @property
    def is_catch_all(self) -> bool:
        return any(
            (s.length >= self._MIN_BODY) or (300 <= s.status < 400 and bool(s.location))
            for s in self.samples
        )

    def matches_baseline(self, resp: Any) -> bool:
        """True if ``resp`` is (near-)identical to the catch-all not-found page."""
        if not self.is_catch_all:
            return False
        try:
            st = int(getattr(resp, "status_code", 0) or 0)
        except Exception:
            return False
        body = getattr(resp, "text", "") or ""
        ln = len(body)
        prefix = body[:512]
        loc = ""
        try:
            loc = (getattr(resp, "headers", {}) or {}).get("Location", "") or ""
        except Exception:
            loc = ""
        for s in self.samples:
            if st != s.status:
                continue
            if 300 <= st < 400:
                if loc and s.location and loc == s.location:
                    return True
                continue
            tol = max(64, int(s.length * 0.05))
            if abs(ln - s.length) <= tol:
                return True
            if prefix and prefix == s.prefix:
                return True
        return False

    def is_genuine_hit(self, resp: Any) -> bool:
        """True if ``resp`` represents a real resource (not 404/soft-404/catch-all)."""
        try:
            st = int(getattr(resp, "status_code", 0) or 0)
        except Exception:
            return False
        if st in (0, 404, 410):
            return False
        if not self.is_catch_all:
            return True  # normal server → legacy behaviour (any non-404 = exists)
        return not self.matches_baseline(resp)

    @staticmethod
    def _origin(url: str) -> str:
        try:
            p = urlparse(url or "")
            if p.scheme and p.netloc:
                return f"{p.scheme}://{p.netloc}"
        except Exception:
            pass
        return ""

    @classmethod
    def for_target(cls, session: Any, url: str) -> "SoftNotFoundBaseline":
        """Return the cached baseline for ``url``'s origin, computing it once.

        Thread-safe; only same-origin computations serialise (different origins
        never block each other). On an unparseable URL returns an empty (no-op)
        baseline so callers can use the result unconditionally.
        """
        origin = cls._origin(url)
        if not origin:
            return cls(_probe=False)
        with cls._cache_lock:
            inst = cls._cache.get(origin)
            if inst is not None:
                return inst
            olock = cls._origin_locks.setdefault(origin, threading.Lock())
        with olock:
            with cls._cache_lock:
                inst = cls._cache.get(origin)
                if inst is not None:
                    return inst
            inst = cls(session, origin)
            with cls._cache_lock:
                cls._cache[origin] = inst
            return inst

    @classmethod
    def reset(cls) -> None:
        """Clear the per-origin cache (call at the start of every scan session)."""
        with cls._cache_lock:
            cls._cache.clear()
            cls._origin_locks.clear()


__all__ = [
    "FindingVerification",
    "ReproducibilityVerifier",
    "FalsePositiveReducer",
    "SoftNotFoundBaseline",
]
