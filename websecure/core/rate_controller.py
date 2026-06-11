"""
websecure.core.rate_controller
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Adaptive rate control engine for WebSecure.

Dynamically adjusts request rate based on:
  1. Server response times — slow responses → back off (avoid timeouts)
  2. HTTP 429 / 503 / WAF block codes → immediate throttle + backoff
  3. WAF signature detection in response bodies → gentle throttle
  4. Success rate — if >20% of requests fail, slow down

The controller runs as a token-bucket limiter combined with a
feedback loop from recent response metrics.

SOLID:
  RateMetrics       — collects response samples
  WafSignalDetector — identifies WAF block signals
  AdaptiveRateController — orchestrates both, exposes acquire()/release()
"""
from __future__ import annotations

import logging
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional, Tuple

_logger = logging.getLogger(__name__)

# HTTP status codes that indicate rate limiting or WAF blocking
_BLOCK_CODES = frozenset({429, 503, 403, 406, 418, 509})

# WAF block page signatures in response body
_WAF_BODY_PATTERNS = [
    "Access Denied",
    "Forbidden by Firewall",
    "cloudflare",
    "Security Check",
    "Request blocked",
    "Bot protection",
    "Rate limit exceeded",
    "Too many requests",
    "Sucuri CloudProxy",
    "Incapsula incident",
    "DDoS protection",
]


# ---------------------------------------------------------------------------
# Metrics collector
# ---------------------------------------------------------------------------

@dataclass
class ResponseSample:
    elapsed_s: float
    status_code: int
    timestamp: float = field(default_factory=time.time)
    waf_blocked: bool = False


class RateMetrics:
    """
    Sliding window of recent response samples.
    Computes real-time statistics for adaptive decisions.
    """

    def __init__(self, window_size: int = 20) -> None:
        self._samples: Deque[ResponseSample] = deque(maxlen=window_size)
        self._lock = threading.Lock()

    def record(self, elapsed_s: float, status_code: int, waf_blocked: bool = False) -> None:
        with self._lock:
            self._samples.append(ResponseSample(elapsed_s, status_code, waf_blocked=waf_blocked))

    def mean_elapsed(self) -> float:
        with self._lock:
            if not self._samples:
                return 0.0
            return statistics.mean(s.elapsed_s for s in self._samples)

    def p90_elapsed(self) -> float:
        with self._lock:
            if not self._samples:
                return 0.0
            times = sorted(s.elapsed_s for s in self._samples)
            # P7 fix: previous formula `int(len*0.90) - 1` undershot by one position.
            # For 10 samples: int(10*0.90)-1 = 8 → index 8 = 9th value (80th pct, not 90th).
            # Correct: clamp int(len*0.90) to [0, len-1].
            idx = min(int(len(times) * 0.90), len(times) - 1)
            return times[idx]

    def block_rate(self) -> float:
        with self._lock:
            if not self._samples:
                return 0.0
            blocked = sum(
                1 for s in self._samples
                if s.status_code in _BLOCK_CODES or s.waf_blocked
            )
            return blocked / len(self._samples)

    def error_rate(self) -> float:
        with self._lock:
            if not self._samples:
                return 0.0
            errors = sum(1 for s in self._samples if s.status_code >= 500 or s.status_code == 0)
            return errors / len(self._samples)

    def sample_count(self) -> int:
        with self._lock:
            return len(self._samples)


# ---------------------------------------------------------------------------
# WAF Signal Detector
# ---------------------------------------------------------------------------

class WafSignalDetector:
    """
    Identifies WAF block signals from HTTP responses.
    Returns a (is_blocked, reason) tuple.
    """

    @staticmethod
    def detect(status_code: int, body: str = "", headers: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
        if status_code in _BLOCK_CODES:
            return True, f"HTTP {status_code} block code"

        body_lower = (body or "").lower()
        for pat in _WAF_BODY_PATTERNS:
            if pat.lower() in body_lower:
                return True, f"WAF body pattern: {pat!r}"

        if headers:
            if "x-sucuri-id" in headers or "x-sucuri-cache" in headers:
                return True, "Sucuri WAF header detected"
            if "x-datadome" in headers:
                return True, "DataDome WAF header detected"

        return False, ""


# ---------------------------------------------------------------------------
# Token Bucket
# ---------------------------------------------------------------------------

class _TokenBucket:
    """
    Standard token-bucket rate limiter.
    Rate is tokens per second; burst is max accumulated tokens.
    """

    def __init__(self, rate: float, burst: int) -> None:
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def set_rate(self, rate: float) -> None:
        with self._lock:
            self._rate = max(rate, 0.05)  # floor: 1 request per 20 seconds

    def acquire(self, block: bool = True) -> bool:
        """
        Consume one token. If block=True, waits until a token is available.
        Returns True when a token was consumed.
        """
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(
                    self._burst,
                    self._tokens + elapsed * self._rate,
                )
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True

                if not block:
                    return False

                wait = (1.0 - self._tokens) / self._rate

            time.sleep(min(wait, 0.5))

    @property
    def current_rate(self) -> float:
        with self._lock:
            return self._rate


# Public alias: TEK-KAYNAK token bucket. http.RateLimiter bu sınıfa delege eder
# (eski kopyalanmış bucket algoritması kaldırıldı). AdaptiveRateController da _TokenBucket'i kullanır.
TokenBucket = _TokenBucket


# ---------------------------------------------------------------------------
# AdaptiveRateController — main public API
# ---------------------------------------------------------------------------

class AdaptiveRateController:
    """
    Adaptive token-bucket rate controller.

    Usage (from scanners):
        ctrl = AdaptiveRateController(initial_rps=10)
        ...
        ctrl.acquire()                     # blocks until a token is available
        resp = session.get(url, ...)
        ctrl.record(resp.elapsed.total_seconds(), resp.status_code, resp.text)

    The controller auto-adjusts the token bucket rate based on feedback:
      - If block_rate > 20% → halve rate
      - If p90 > 3s → reduce rate by 30%
      - If block_rate < 5% and p90 < 1s → increase rate by 20% (up to max)
      - If error_rate > 30% → reduce rate by 40%
    """

    def __init__(
        self,
        initial_rps: float = 10.0,
        min_rps: float = 0.2,
        max_rps: float = 50.0,
        adapt_interval: int = 10,   # adapt every N samples
    ) -> None:
        self._min_rps = min_rps
        self._max_rps = max_rps
        self._adapt_interval = adapt_interval

        self._bucket = _TokenBucket(rate=initial_rps, burst=max(int(initial_rps * 2), 5))
        self._metrics = RateMetrics(window_size=30)
        self._waf_detector = WafSignalDetector()

        self._sample_count = 0
        self._throttle_until: float = 0.0   # epoch time to enforce minimum wait
        self._lock = threading.Lock()

        self._stats: Dict[str, Any] = {
            "rate_adjustments": 0,
            "waf_blocks": 0,
            "throttle_events": 0,
        }

    def acquire(self) -> None:
        """Block until a request token is available."""
        # Honour any active throttle pause
        with self._lock:
            pause_until = self._throttle_until
        if pause_until > time.time():
            wait = pause_until - time.time()
            _logger.debug(f"[RateCtrl] Throttle pause: sleeping {wait:.1f}s")
            time.sleep(max(wait, 0))

        self._bucket.acquire(block=True)

    def record(
        self,
        elapsed_s: float,
        status_code: int,
        body: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Record a response sample and trigger adaptation if needed."""
        is_blocked, reason = self._waf_detector.detect(status_code, body, headers or {})

        if is_blocked:
            with self._lock:
                self._stats["waf_blocks"] += 1
            _logger.warning(f"[RateCtrl] WAF/block detected: {reason}")
            self._enforce_backoff(factor=0.50, pause_s=5.0)

        self._metrics.record(elapsed_s, status_code, waf_blocked=is_blocked)

        with self._lock:
            self._sample_count += 1
            should_adapt = (self._sample_count % self._adapt_interval == 0)

        if should_adapt and self._metrics.sample_count() >= self._adapt_interval:
            self._adapt()

    def _adapt(self) -> None:
        """Adjust rate based on current metrics."""
        block_rate = self._metrics.block_rate()
        error_rate = self._metrics.error_rate()
        p90 = self._metrics.p90_elapsed()
        current = self._bucket.current_rate

        new_rate = current

        if block_rate > 0.20:
            new_rate = current * 0.50
            _logger.info(f"[RateCtrl] High block rate ({block_rate:.0%}) → rate {current:.1f}→{new_rate:.1f} rps")
        elif error_rate > 0.30:
            new_rate = current * 0.60
            _logger.info(f"[RateCtrl] High error rate ({error_rate:.0%}) → rate {current:.1f}→{new_rate:.1f} rps")
        elif p90 > 3.0:
            new_rate = current * 0.70
            _logger.info(f"[RateCtrl] Slow p90 ({p90:.1f}s) → rate {current:.1f}→{new_rate:.1f} rps")
        elif block_rate < 0.05 and p90 < 1.0 and error_rate < 0.05:
            new_rate = current * 1.20
            _logger.debug(f"[RateCtrl] Good metrics → rate {current:.1f}→{new_rate:.1f} rps")

        new_rate = max(self._min_rps, min(self._max_rps, new_rate))
        if abs(new_rate - current) > 0.05:
            self._bucket.set_rate(new_rate)
            with self._lock:
                self._stats["rate_adjustments"] += 1

    def _enforce_backoff(self, factor: float = 0.50, pause_s: float = 5.0) -> None:
        """Immediately halve rate and enforce a pause."""
        current = self._bucket.current_rate
        new_rate = max(self._min_rps, current * factor)
        self._bucket.set_rate(new_rate)
        with self._lock:
            self._throttle_until = time.time() + pause_s
            self._stats["throttle_events"] += 1
        _logger.warning(
            f"[RateCtrl] Backoff enforced: rate {current:.1f}→{new_rate:.1f} rps, "
            f"pause {pause_s:.0f}s"
        )

    @property
    def current_rps(self) -> float:
        return self._bucket.current_rate

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            s = dict(self._stats)
        s["current_rps"] = self._bucket.current_rate
        s["block_rate"] = round(self._metrics.block_rate(), 3)
        s["error_rate"] = round(self._metrics.error_rate(), 3)
        s["p90_elapsed"] = round(self._metrics.p90_elapsed(), 3)
        return s


__all__ = [
    "RateMetrics",
    "WafSignalDetector",
    "AdaptiveRateController",
]
