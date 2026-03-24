"""
websecure.core.circuit_breaker
-------------------------------
Scan-level circuit breaker. Monitors HTTP response stream in real-time and
halts scanning when blocking thresholds are exceeded.

State machine
─────────────
  CLOSED    → normal scanning
  OPEN      → scanning halted; raises CircuitBreakerTripped on every request
  HALF_OPEN → recovery probe mode; limited requests allowed to test target

Thresholds that trip CLOSED → OPEN
────────────────────────────────────
  • 403 ratio ≥ 50 % over a sliding window of the last N responses
  • Consecutive 429s ≥ max_consecutive_429 (default 10)
  • Consecutive connection errors ≥ max_consecutive_errors (default 5)

Recovery path
─────────────
  OPEN → HALF_OPEN  after recovery_timeout seconds
  HALF_OPEN → CLOSED   on first 2xx probe response
  HALF_OPEN → OPEN     on any non-2xx probe response (timer reset)

Integration
───────────
  Call cb_check()       before every HTTP request (auto-wired in http._smart_request)
  Call cb_record(status) after every HTTP response
  Call cb_record_error() on ConnectionError / Timeout
  Call cb_reset()        after successful IP/identity rotation (Tor NEWNYM etc.)
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

_logger = logging.getLogger("websecure.circuit_breaker")


# ---------------------------------------------------------------------------
# State & Config
# ---------------------------------------------------------------------------

class CBState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


@dataclass
class CBConfig:
    # 403 ratio threshold — fraction of last `window_size` responses
    forbidden_ratio_threshold: float = 0.50
    # Sliding window depth for ratio calculation
    window_size: int = 20
    # Consecutive 429s before tripping
    max_consecutive_429: int = 10
    # Consecutive connection-level errors before tripping
    max_consecutive_errors: int = 5
    # Seconds to stay OPEN before attempting HALF_OPEN recovery
    recovery_timeout: float = 30.0
    # How many probe requests are allowed in HALF_OPEN before auto-re-open
    half_open_probe_limit: int = 3


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class CircuitBreakerTripped(Exception):
    """Raised when a request is attempted while the circuit is OPEN."""

    def __init__(self, state: CBState, reason: str, retry_in: float = 0.0) -> None:
        self.state    = state
        self.reason   = reason
        self.retry_in = retry_in
        super().__init__(
            f"[CircuitBreaker] {state.value.upper()}: {reason}"
            + (f" — retry in {retry_in:.0f}s" if retry_in > 0 else "")
        )


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class ScanCircuitBreaker:
    """
    Thread-safe circuit breaker scoped to one scan run.

    Typical usage (already wired via module-level helpers)::

        cb_check()          # before request — raises if OPEN
        cb_record(status)   # after response
        cb_record_error()   # on connection failure
        cb_reset()          # after successful identity rotation
    """

    def __init__(self, cfg: Optional[CBConfig] = None) -> None:
        self._cfg   = cfg or CBConfig()
        self._lock  = threading.Lock()

        self._state: CBState = CBState.CLOSED

        # Sliding window of raw status codes (positive int) or -1 for conn errors
        self._window: list[int] = []

        # Streak counters
        self._consecutive_429: int   = 0
        self._consecutive_errors: int = 0

        # HALF_OPEN probe tracking
        self._half_open_probes: int = 0

        # Timing
        self._opened_at: Optional[float] = None
        self._open_reason: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def state(self) -> CBState:
        return self._state

    @property
    def is_open(self) -> bool:
        return self._state == CBState.OPEN

    def check(self) -> None:
        """
        Called before every HTTP request.

        - CLOSED     → passes silently.
        - HALF_OPEN  → passes if probe budget not exhausted; increments probe counter.
        - OPEN       → transitions to HALF_OPEN if recovery timeout elapsed;
                       otherwise raises CircuitBreakerTripped.
        """
        with self._lock:
            if self._state == CBState.CLOSED:
                return

            if self._state == CBState.OPEN:
                elapsed    = time.time() - (self._opened_at or 0.0)
                remaining  = self._cfg.recovery_timeout - elapsed
                if elapsed >= self._cfg.recovery_timeout:
                    self._transition(CBState.HALF_OPEN, "recovery timeout elapsed")
                    self._half_open_probes = 1
                    return
                raise CircuitBreakerTripped(
                    CBState.OPEN, self._open_reason, retry_in=max(0.0, remaining)
                )

            if self._state == CBState.HALF_OPEN:
                if self._half_open_probes >= self._cfg.half_open_probe_limit:
                    raise CircuitBreakerTripped(
                        CBState.HALF_OPEN,
                        f"probe budget exhausted ({self._cfg.half_open_probe_limit}); waiting for probe results",
                    )
                self._half_open_probes += 1

    def record(self, status: int) -> None:
        """
        Called after every HTTP response with the status code.

        Special sentinel: status = -1 means connection error (use record_error() instead).
        """
        with self._lock:
            s = int(status)

            # --- Update sliding window ---
            self._window.append(s)
            if len(self._window) > self._cfg.window_size:
                self._window.pop(0)

            # --- Update streak counters ---
            if s == 429:
                self._consecutive_429   += 1
                self._consecutive_errors = 0
            elif s == -1:
                self._consecutive_errors += 1
                self._consecutive_429    = 0
            else:
                self._consecutive_429 = 0
                if s < 500:
                    self._consecutive_errors = 0

            # --- State-specific logic ---
            if self._state == CBState.HALF_OPEN:
                if 200 <= s < 300:
                    self._transition(CBState.CLOSED, f"probe succeeded ({s})")
                else:
                    self._transition(CBState.OPEN, f"probe failed ({s})")
                return

            if self._state == CBState.CLOSED:
                self._evaluate_thresholds()

    def record_error(self) -> None:
        """Convenience: record a connection-level error (timeout, refused, etc.)."""
        self.record(-1)

    def reset(self) -> None:
        """
        Force-reset to CLOSED (e.g. called after successful Tor NEWNYM rotation).
        Clears all counters and window so the new identity starts clean.
        """
        with self._lock:
            if self._state != CBState.CLOSED:
                self._transition(CBState.CLOSED, "manual reset after identity rotation")

    def status(self) -> dict:
        """Return a diagnostic snapshot (safe to call anytime)."""
        with self._lock:
            forbidden = sum(1 for s in self._window if s == 403)
            ratio     = (forbidden / len(self._window)) if self._window else 0.0
            remaining = 0.0
            if self._state == CBState.OPEN and self._opened_at:
                remaining = max(0.0, self._cfg.recovery_timeout - (time.time() - self._opened_at))
            return {
                "state":               self._state.value,
                "window_size":         len(self._window),
                "forbidden_ratio":     round(ratio, 3),
                "consecutive_429":     self._consecutive_429,
                "consecutive_errors":  self._consecutive_errors,
                "open_reason":         self._open_reason,
                "retry_in_s":          round(remaining, 1),
            }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _evaluate_thresholds(self) -> None:
        """Check all thresholds and trip if exceeded. Called with lock held."""
        cfg = self._cfg

        if self._consecutive_429 >= cfg.max_consecutive_429:
            self._transition(
                CBState.OPEN,
                f"consecutive 429s: {self._consecutive_429} >= {cfg.max_consecutive_429}",
            )
            return

        if self._consecutive_errors >= cfg.max_consecutive_errors:
            self._transition(
                CBState.OPEN,
                f"consecutive errors: {self._consecutive_errors} >= {cfg.max_consecutive_errors}",
            )
            return

        if len(self._window) >= cfg.window_size:
            forbidden = sum(1 for s in self._window if s == 403)
            ratio     = forbidden / len(self._window)
            if ratio >= cfg.forbidden_ratio_threshold:
                self._transition(
                    CBState.OPEN,
                    f"403 ratio {ratio:.0%} >= {cfg.forbidden_ratio_threshold:.0%} "
                    f"over last {cfg.window_size} requests",
                )

    def _transition(self, new_state: CBState, reason: str) -> None:
        """State transition. Called with lock held."""
        old = self._state
        self._state = new_state

        if new_state == CBState.OPEN:
            self._opened_at        = time.time()
            self._open_reason      = reason
            self._half_open_probes = 0
            _logger.warning(
                "[CircuitBreaker] %s → OPEN: %s", old.value.upper(), reason
            )
            print(f"[CircuitBreaker] ⛔ OPEN — {reason}")

        elif new_state == CBState.HALF_OPEN:
            self._half_open_probes = 0
            _logger.info("[CircuitBreaker] OPEN → HALF_OPEN: %s", reason)
            print(f"[CircuitBreaker] 🔶 HALF_OPEN — {reason}")

        elif new_state == CBState.CLOSED:
            self._consecutive_429    = 0
            self._consecutive_errors = 0
            self._window.clear()
            self._open_reason        = ""
            self._opened_at          = None
            _logger.info("[CircuitBreaker] → CLOSED: %s", reason)
            print(f"[CircuitBreaker] ✅ CLOSED — {reason}")


# ---------------------------------------------------------------------------
# Global singleton helpers
# ---------------------------------------------------------------------------

_GLOBAL_CB: Optional[ScanCircuitBreaker] = None
_CB_LOCK = threading.Lock()


def get_circuit_breaker(cfg: Optional[CBConfig] = None) -> ScanCircuitBreaker:
    """Return the process-global circuit breaker, creating it if needed."""
    global _GLOBAL_CB
    with _CB_LOCK:
        if _GLOBAL_CB is None:
            _GLOBAL_CB = ScanCircuitBreaker(cfg)
        return _GLOBAL_CB


def reset_circuit_breaker(cfg: Optional[CBConfig] = None) -> ScanCircuitBreaker:
    """
    (Re-)initialize the global circuit breaker.
    Call this at the start of each scan run so state from a previous run
    doesn't bleed into the new one.
    """
    global _GLOBAL_CB
    with _CB_LOCK:
        _GLOBAL_CB = ScanCircuitBreaker(cfg)
        return _GLOBAL_CB


def cb_check() -> None:
    """Check the global circuit breaker. Raises CircuitBreakerTripped if OPEN."""
    get_circuit_breaker().check()


def cb_record(status: int) -> None:
    """Record an HTTP status code into the global circuit breaker."""
    get_circuit_breaker().record(status)


def cb_record_error() -> None:
    """Record a connection-level error into the global circuit breaker."""
    get_circuit_breaker().record_error()


def cb_reset() -> None:
    """
    Reset the global circuit breaker to CLOSED.
    Call after a successful IP/identity rotation so the new identity
    starts with a clean slate.
    """
    get_circuit_breaker().reset()


def cb_status() -> dict:
    """Return a diagnostic snapshot of the global circuit breaker."""
    return get_circuit_breaker().status()
