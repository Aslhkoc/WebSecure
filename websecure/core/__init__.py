"""
websecure.core
~~~~~~~~~~~~~~~
WebSecure çekirdek bileşenleri.

Tüm Step 20 modülleri buradan erişilebilir.
"""
from __future__ import annotations
import logging as _logging

_logger = _logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exception hiyerarşisi — tüm core ve scanner modülleri buradan import eder
# ---------------------------------------------------------------------------
from websecure.core.exceptions import (  # noqa: E402
    WebSecureError,
    ScanError,
    ProbeError,
    BaselineError,
    PayloadError,
    NetworkError,
    ConnectionRefusedError,
    RequestTimeoutError,
    SSLHandshakeError,
    ParseError,
    ConfigError,
    wrap_requests_error,
)

# ---------------------------------------------------------------------------
# Step 20 — Kalıcılık & Analitik (lazy import)
# ---------------------------------------------------------------------------
try:
    from websecure.core.fp_learner import get_fp_learner, FPLearner, FPRule
except Exception as _e:
    _logger.debug(f"[core] fp_learner yüklenemedi (opsiyonel): {_e!r}")
    get_fp_learner = FPLearner = FPRule = None  # type: ignore[assignment,misc]

try:
    from websecure.core.score_tracker import get_score_tracker, ScoreTracker, ScoreCalculator
except Exception as _e:
    _logger.debug(f"[core] score_tracker yüklenemedi (opsiyonel): {_e!r}")
    get_score_tracker = ScoreTracker = ScoreCalculator = None  # type: ignore[assignment,misc]

try:
    from websecure.core.correlation_engine import get_correlation_engine, CorrelationEngine
except Exception as _e:
    _logger.debug(f"[core] correlation_engine yüklenemedi (opsiyonel): {_e!r}")
    get_correlation_engine = CorrelationEngine = None  # type: ignore[assignment,misc]

try:
    from websecure.core.plugin_marketplace import get_marketplace, PluginMarketplace, BasePlugin
except Exception as _e:
    _logger.debug(f"[core] plugin_marketplace yüklenemedi (opsiyonel): {_e!r}")
    get_marketplace = PluginMarketplace = BasePlugin = None  # type: ignore[assignment,misc]

try:
    from websecure.core.async_runner import AsyncScanRunner, AsyncScanTask
except Exception as _e:
    _logger.debug(f"[core] async_runner yüklenemedi (opsiyonel): {_e!r}")
    AsyncScanRunner = AsyncScanTask = None  # type: ignore[assignment,misc]

try:
    from websecure.core.scan_runner import post_scan_persist, filter_false_positives
except Exception as _e:
    _logger.debug(f"[core] scan_runner yüklenemedi (opsiyonel): {_e!r}")
    post_scan_persist = filter_false_positives = None  # type: ignore[assignment,misc]

__all__ = [
    # Exception hiyerarşisi
    "WebSecureError",
    "ScanError", "ProbeError", "BaselineError", "PayloadError",
    "NetworkError", "ConnectionRefusedError", "RequestTimeoutError", "SSLHandshakeError",
    "ParseError", "ConfigError",
    "wrap_requests_error",
    # FP Öğrenme
    "get_fp_learner", "FPLearner", "FPRule",
    # Skor Takibi
    "get_score_tracker", "ScoreTracker", "ScoreCalculator",
    # Korelasyon
    "get_correlation_engine", "CorrelationEngine",
    # Plugin
    "get_marketplace", "PluginMarketplace", "BasePlugin",
    # Async
    "AsyncScanRunner", "AsyncScanTask",
    # Yardımcılar
    "post_scan_persist", "filter_false_positives",
]
