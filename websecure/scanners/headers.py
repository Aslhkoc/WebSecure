"""
websecure.scanners.headers
--------------------------
Legacy stub.
This functionality has been moved to websecure.scanners.infrastructure.
This file remains to support dynamic imports from config 'modules': ['headers'].
"""

from __future__ import annotations
from .infrastructure import get_security_headers


def scan(target: str, session=None, **kwargs):
    """
    Adapter for the main scanner engine.
    The engine expects a 'scan' or 'run' function.
    """
    results = {}
    get_security_headers(target, results, session=session, debug=kwargs.get("debug", False))
    return results.get("security_headers", [])


def run(target: str, session=None, **kwargs):
    return scan(target, session, **kwargs)
