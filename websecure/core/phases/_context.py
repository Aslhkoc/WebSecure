"""
websecure.core.phases._context
-------------------------------
Scan mode constants and scan context dataclass.
These are pure data structures with no internal dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


class ScanMode:
    NORMAL = "normal"
    DETAILED = "detailed"
    AUTHENTICATED = "authenticated"
    DEEP = "deep"
    # Aliases
    STEALTH = NORMAL
    AGGRESSIVE = DEEP


@dataclass
class ScanContext:
    url: str = ""
    scheme: str = ""
    config: Dict[str, Any] | None = None
    driver: Any = None
    session: Any = None
    results: Dict[str, Any] | None = None
    detailed: bool = False
    save_report: bool = False
    debug: bool = False
    logger: Any = None

    def __post_init__(self):
        if self.config is None:
            self.config = {}
        if self.results is None:
            self.results = {}

    @property
    def endpoints(self):
        return self.results.get("endpoints", [])
