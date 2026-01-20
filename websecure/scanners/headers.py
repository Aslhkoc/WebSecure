"""
websecure.scanners.headers
--------------------------
Legacy stub.
This functionality has been moved to websecure.scanners.infrastructure.
This file remains to support dynamic imports from config 'modules': ['headers'].
"""

from .infrastructure import get_security_headers, analyze_response_headers, HeaderScanner

def scan(target: str, session=None, **kwargs):
    """
    Adapter for the main scanner engine.
    The engine expects a 'scan' or 'run' function.
    """
    results = {}
    # Call the consolidated function
    # Note: 'get_security_headers' signature is (url, results, session, debug, ...)
    get_security_headers(target, results, session=session, debug=kwargs.get("debug", False))
    return results.get("security_headers", [])

def run(target: str, session=None, **kwargs):
    return scan(target, session, **kwargs)
