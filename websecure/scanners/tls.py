from .infrastructure import scan_tls as _real_scan_tls
from .infrastructure import check_ssl_certificate as _real_check_ssl

def scan_tls(url, **kwargs):
    return _real_scan_tls(url, **kwargs)

def check_ssl_certificate(*args, **kwargs):
    return _real_check_ssl(*args, **kwargs)

def scan_tls_quick(url):
    # Compatibility wrapper for phases.py calls
    return scan_tls(url)
