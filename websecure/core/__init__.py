"""
websecure.core
~~~~~~~~~~~~~~~
WebSecure çekirdek bileşenleri.

Tüm Step 20 modülleri buradan erişilebilir.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Step 20 — Kalıcılık & Analitik (lazy import)
# ---------------------------------------------------------------------------
try:
    from websecure.core.fp_learner import get_fp_learner, FPLearner, FPRule
except Exception:
    pass

try:
    from websecure.core.score_tracker import get_score_tracker, ScoreTracker, ScoreCalculator
except Exception:
    pass

try:
    from websecure.core.correlation_engine import get_correlation_engine, CorrelationEngine
except Exception:
    pass

try:
    from websecure.core.plugin_marketplace import get_marketplace, PluginMarketplace, BasePlugin
except Exception:
    pass

try:
    from websecure.core.async_runner import AsyncScanRunner, AsyncScanTask
except Exception:
    pass

try:
    from websecure.core.scan_runner import post_scan_persist, filter_false_positives
except Exception:
    pass

__all__ = [
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
