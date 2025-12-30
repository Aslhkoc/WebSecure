from .infrastructure import get_security_headers as _real_scan

def scan(session, endpoints, results, debug=False, config=None):
    """
    Shim for backward compatibility with phases.py
    """
    targets = [endpoints] if isinstance(endpoints, str) else (endpoints or [])
    for url in targets:
        _real_scan(url, results, session=session, debug=debug)

def get_security_headers(*args, **kwargs):
    return _real_scan(*args, **kwargs)
