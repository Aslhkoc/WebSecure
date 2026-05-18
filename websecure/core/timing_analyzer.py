"""
websecure.core.timing_analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Statistical timing analysis for blind injection detection.

Eliminates the two biggest sources of blind timing false-positives:
  1. Natural server jitter (high-stdev hosts)
  2. Single-spike network hiccups

Algorithm (per parameter):
  Phase 1 — Baseline sampling (n=5 benign requests)
             → computes mean + stdev of natural response time
  Phase 2 — Dynamic threshold = baseline_mean + k*baseline_stdev
             where k is auto-tuned from [3.0 … 5.0] based on stdev magnitude
  Phase 3 — First-pass probe: if probe_time ≥ threshold, enter cross-validation
  Phase 4 — Cross-validation: re-send N times, require M/N hits
             (default: 3/3 — all three must exceed threshold)
  Phase 5 — Non-injected interleave: send benign request between each timed probe
             to confirm server is not globally slow (network congestion check)

All results are wrapped in a TimingResult dataclass with full provenance.
"""
from __future__ import annotations

import logging
import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests as _requests

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TimingBaseline:
    """Statistical profile of baseline (non-injected) response times."""
    url: str
    param: str
    mean_s: float
    stdev_s: float
    min_s: float
    max_s: float
    samples: int
    dynamic_threshold: float   # mean + k * stdev, minimum 3.0 s
    k_factor: float            # auto-tuned sigma multiplier
    timestamp: float = field(default_factory=time.time)

    def is_jittery(self) -> bool:
        """High-stdev host — needs tighter cross-validation."""
        return self.stdev_s > 0.5

    def cv(self) -> float:
        """Coefficient of variation: stdev / mean."""
        return self.stdev_s / max(self.mean_s, 0.001)


@dataclass
class TimingResult:
    """Result of a timed injection probe with full provenance."""
    payload: str
    probe_times: List[float]          # raw elapsed seconds per trial
    benign_interleave_times: List[float]  # benign request times between trials
    threshold: float
    hits: int
    required_hits: int
    total_trials: int
    confirmed: bool
    confidence: float                 # 0.0 – 1.0
    evidence: str

    @property
    def mean_probe_time(self) -> float:
        return statistics.mean(self.probe_times) if self.probe_times else 0.0

    @property
    def mean_benign_time(self) -> float:
        return statistics.mean(self.benign_interleave_times) if self.benign_interleave_times else 0.0


# ---------------------------------------------------------------------------
# Main TimingAnalyzer
# ---------------------------------------------------------------------------

class TimingAnalyzer:
    """
    Statistical timing analysis engine for blind injection detection.

    Thread-safe: baseline cache is protected by a lock.
    One analyzer instance can be shared across scanner threads.
    """

    # Auto-tuning k-factor table: stdev → k
    # High-jitter hosts need higher k to suppress false positives
    _K_TABLE: List[Tuple[float, float]] = [
        (0.00, 3.0),   # stdev <0.1s → k=3.0 (stable host)
        (0.10, 3.5),
        (0.30, 4.0),
        (0.50, 4.5),
        (1.00, 5.0),   # stdev ≥1.0s → k=5.0 (very jittery)
    ]

    # Minimum absolute threshold regardless of baseline arithmetic
    _ABS_MIN_THRESHOLD: float = 3.0   # seconds

    # Cross-validation parameters
    _CV_TRIALS: int = 3
    _CV_REQUIRED: int = 3   # 3/3 — all must hit (no false-positive budget)

    # Baseline cache TTL — stale baselines cause false positives on changing servers
    _CACHE_TTL: float = 300.0  # seconds

    def __init__(self, session: Any, *, baseline_n: int = 5) -> None:
        self.session = session
        self.baseline_n = baseline_n
        self._cache: Dict[str, Tuple[TimingBaseline, float]] = {}  # (baseline, timestamp)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture_baseline(
        self,
        url: str,
        param: str,
        *,
        timeout: int = 15,
    ) -> Optional[TimingBaseline]:
        """
        Sample baseline_n clean requests and compute statistical profile.
        Caches per (url, param) key — subsequent calls return the cached value.
        """
        cache_key = f"{url}|{param}"
        with self._lock:
            if cache_key in self._cache:
                bl, ts = self._cache[cache_key]
                if time.monotonic() - ts < self._CACHE_TTL:
                    return bl
                del self._cache[cache_key]  # expired — remove stale entry

        times: List[float] = []
        for _ in range(self.baseline_n):
            t0 = time.time()
            try:
                self.session.get(url, timeout=timeout)
                times.append(time.time() - t0)
            except _requests.exceptions.Timeout:
                times.append(float(timeout))
            except Exception as exc:
                _logger.debug(f"[TA] Baseline sample failed {url}: {exc!r}")

        if len(times) < 2:
            _logger.warning(f"[TA] Could not capture reliable baseline for {url}")
            return None

        mean_s = statistics.mean(times)
        stdev_s = statistics.stdev(times)
        k = self._auto_k(stdev_s)
        threshold = max(mean_s + k * stdev_s, self._ABS_MIN_THRESHOLD)

        bl = TimingBaseline(
            url=url,
            param=param,
            mean_s=mean_s,
            stdev_s=stdev_s,
            min_s=min(times),
            max_s=max(times),
            samples=len(times),
            dynamic_threshold=threshold,
            k_factor=k,
        )
        with self._lock:
            self._cache[cache_key] = (bl, time.monotonic())

        _logger.debug(
            f"[TA] Baseline {url} param={param}: "
            f"mean={mean_s:.3f}s stdev={stdev_s:.3f}s k={k} threshold={threshold:.3f}s"
        )
        return bl

    def probe(
        self,
        url: str,
        param: str,
        payload: str,
        inject_fn: Callable[[str, str, str], str],
        *,
        baseline: Optional[TimingBaseline] = None,
        timeout: int = 20,
        expected_delay: float = 3.0,
    ) -> Optional[TimingResult]:
        """
        Execute a timed probe for the given payload.

        Phase 1: Capture baseline if not provided.
        Phase 2: First-pass probe — if below threshold, return None immediately.
        Phase 3: Cross-validation — 3 more trials, all must hit.
        Phase 4: Interleave benign request check.

        Returns TimingResult if confirmed, None if not.
        """
        if baseline is None:
            baseline = self.capture_baseline(url, param, timeout=timeout)
        if baseline is None:
            return None

        injected_url = inject_fn(url, param, payload)
        threshold = max(baseline.dynamic_threshold, expected_delay)

        # Phase 2: first-pass
        t0 = time.time()
        try:
            self.session.get(injected_url, timeout=threshold + expected_delay + 5)
            elapsed = time.time() - t0
        except _requests.exceptions.Timeout:
            elapsed = float(timeout)
        except Exception as exc:
            _logger.debug(f"[TA] First-pass probe error {injected_url}: {exc!r}")
            return None

        if elapsed < threshold:
            return None  # fast return — no timing signal at all

        # Phase 3: cross-validation
        probe_times: List[float] = [elapsed]
        benign_times: List[float] = []
        hits = 1 if elapsed >= threshold else 0

        for trial in range(self._CV_TRIALS - 1):
            # Interleave: benign request before each trial
            bt = self._time_benign(url, timeout=timeout)
            if bt is not None:
                benign_times.append(bt)
                # Safety valve: if the benign request itself is slow,
                # the server is globally degraded — abort timing check
                if bt > threshold:
                    _logger.debug(
                        f"[TA] Benign request slow ({bt:.2f}s >= threshold {threshold:.2f}s) "
                        f"— aborting timing probe for {url} param={param}"
                    )
                    return None

            # Timed trial
            t0 = time.time()
            try:
                self.session.get(injected_url, timeout=threshold + expected_delay + 5)
                t_elapsed = time.time() - t0
            except _requests.exceptions.Timeout:
                t_elapsed = float(timeout)
            except Exception:
                continue

            probe_times.append(t_elapsed)
            if t_elapsed >= threshold:
                hits += 1

        confirmed = hits >= self._CV_REQUIRED
        confidence = self._compute_confidence(
            hits, self._CV_TRIALS, probe_times, benign_times, threshold, baseline
        )

        mean_probe = statistics.mean(probe_times) if probe_times else elapsed
        evidence = (
            f"Time-based ({hits}/{self._CV_TRIALS} trials ≥ {threshold:.2f}s) | "
            f"probe_mean={mean_probe:.2f}s | baseline_mean={baseline.mean_s:.2f}s"
        )
        if benign_times:
            evidence += f" | benign_mean={statistics.mean(benign_times):.2f}s"

        return TimingResult(
            payload=payload,
            probe_times=probe_times,
            benign_interleave_times=benign_times,
            threshold=threshold,
            hits=hits,
            required_hits=self._CV_REQUIRED,
            total_trials=self._CV_TRIALS,
            confirmed=confirmed,
            confidence=confidence,
            evidence=evidence,
        )

    def probe_post(
        self,
        url: str,
        param: str,
        payload: str,
        form_data: Dict[str, str],
        *,
        baseline: Optional[TimingBaseline] = None,
        timeout: int = 20,
        expected_delay: float = 3.0,
    ) -> Optional[TimingResult]:
        """POST form variant — same algorithm, uses session.post()."""
        if baseline is None:
            baseline = self.capture_baseline(url, param, timeout=timeout)
        if baseline is None:
            return None

        threshold = max(baseline.dynamic_threshold, expected_delay)

        def _post_probe() -> float:
            t0 = time.time()
            try:
                data = dict(form_data)
                data[param] = payload
                self.session.post(url, data=data, timeout=threshold + expected_delay + 5)
                return time.time() - t0
            except _requests.exceptions.Timeout:
                return float(timeout)
            except Exception:
                return 0.0

        probe_times: List[float] = []
        benign_times: List[float] = []
        hits = 0

        for trial in range(self._CV_TRIALS):
            if trial > 0:
                bt = self._time_benign(url, timeout=timeout)
                if bt is not None:
                    benign_times.append(bt)
                    if bt > threshold:
                        return None

            t = _post_probe()
            probe_times.append(t)
            if t >= threshold:
                hits += 1

        if not probe_times:
            return None

        confirmed = hits >= self._CV_REQUIRED
        confidence = self._compute_confidence(
            hits, self._CV_TRIALS, probe_times, benign_times, threshold, baseline
        )

        mean_probe = statistics.mean(probe_times)
        evidence = (
            f"POST Time-based ({hits}/{self._CV_TRIALS} trials ≥ {threshold:.2f}s) | "
            f"probe_mean={mean_probe:.2f}s | baseline_mean={baseline.mean_s:.2f}s"
        )

        return TimingResult(
            payload=payload,
            probe_times=probe_times,
            benign_interleave_times=benign_times,
            threshold=threshold,
            hits=hits,
            required_hits=self._CV_REQUIRED,
            total_trials=self._CV_TRIALS,
            confirmed=confirmed,
            confidence=confidence,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auto_k(self, stdev: float) -> float:
        """Auto-tune sigma multiplier k from stdev magnitude."""
        k = self._K_TABLE[-1][1]
        for threshold, kval in self._K_TABLE:
            if stdev >= threshold:
                k = kval
        return k

    def _time_benign(self, url: str, *, timeout: int = 15) -> Optional[float]:
        """Time a benign (non-injected) GET request."""
        t0 = time.time()
        try:
            self.session.get(url, timeout=timeout)
            return time.time() - t0
        except Exception:
            return None

    def _compute_confidence(
        self,
        hits: int,
        trials: int,
        probe_times: List[float],
        benign_times: List[float],
        threshold: float,
        baseline: TimingBaseline,
    ) -> float:
        """
        Compute confidence score 0.0–1.0.
        Gates: hit ratio, probe vs benign gap, stability.
        """
        if not probe_times:
            return 0.0

        hit_ratio = hits / trials
        mean_probe = statistics.mean(probe_times)
        mean_benign = statistics.mean(benign_times) if benign_times else baseline.mean_s

        # Gap between probe mean and benign mean relative to threshold
        gap = (mean_probe - mean_benign) / max(threshold, 1.0)
        gap_score = min(gap, 1.0)

        # Consistency bonus: if all probes are consistently above threshold
        consistency = 1.0 if hits == trials else hit_ratio

        # Baseline stability bonus: stable baseline → higher confidence
        stability = 1.0 - min(baseline.cv(), 1.0)

        confidence = (
            hit_ratio * 0.50
            + gap_score * 0.30
            + consistency * 0.10
            + stability * 0.10
        )
        return round(min(confidence, 1.0), 3)


__all__ = [
    "TimingBaseline",
    "TimingResult",
    "TimingAnalyzer",
]
