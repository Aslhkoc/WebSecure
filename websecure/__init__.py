"""
WebSecure Analysis Framework — v20.0.0
Sektör lideri web güvenlik tarama motoru.
"""
from __future__ import annotations

__version__ = "20.0.0"

# ---------------------------------------------------------------------------
# Temel bileşenler
# ---------------------------------------------------------------------------
from websecure.core.utils import setup_logging
from websecure.scanners.base import BaseScanner

# ---------------------------------------------------------------------------
# Step 20 — Kalıcılık, Analitik, Mimari (lazy / graceful degradation)
# ---------------------------------------------------------------------------
try:
    from websecure.db import get_db, Database
    from websecure.db import (
        Scan, Finding, Tenant, Project, ScoreRecord,
        ScanRepository, FindingRepository, TenantRepository,
        ProjectRepository, ScoreRepository,
    )
    _HAS_DB = True
except Exception:
    _HAS_DB = False

try:
    from websecure.core.fp_learner import get_fp_learner, FPLearner, FPRule
    _HAS_FP = True
except Exception:
    _HAS_FP = False

try:
    from websecure.core.score_tracker import get_score_tracker, ScoreTracker, ScoreCalculator
    _HAS_SCORE = True
except Exception:
    _HAS_SCORE = False

try:
    from websecure.core.correlation_engine import get_correlation_engine, CorrelationEngine
    _HAS_CORR = True
except Exception:
    _HAS_CORR = False

try:
    from websecure.core.plugin_marketplace import get_marketplace, PluginMarketplace, BasePlugin
    _HAS_MARKETPLACE = True
except Exception:
    _HAS_MARKETPLACE = False

try:
    from websecure.core.async_runner import AsyncScanRunner, AsyncScanTask
    _HAS_ASYNC = True
except Exception:
    _HAS_ASYNC = False

try:
    from websecure.api import get_api_server, APIServer
    _HAS_API = True
except Exception:
    _HAS_API = False

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "__version__",
    "setup_logging",
    "BaseScanner",
    # DB
    "get_db", "Database",
    "Scan", "Finding", "Tenant", "Project", "ScoreRecord",
    "ScanRepository", "FindingRepository", "TenantRepository",
    "ProjectRepository", "ScoreRepository",
    # Analytics
    "get_fp_learner", "FPLearner", "FPRule",
    "get_score_tracker", "ScoreTracker", "ScoreCalculator",
    "get_correlation_engine", "CorrelationEngine",
    # Plugin
    "get_marketplace", "PluginMarketplace", "BasePlugin",
    # Async
    "AsyncScanRunner", "AsyncScanTask",
    # API
    "get_api_server", "APIServer",
]
