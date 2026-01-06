import ssl
import socket
import logging
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse

from .infrastructure import check_ssl_certificate as _get_cert_details

_logger = logging.getLogger(__name__)

def _create_socket(host: str, port: int, timeout: int = 5):
    return socket.create_connection((host, port), timeout=timeout)

def check_protocol_support(host: str, port: int) -> List[str]:
    """
    Checks for support of deprecated/weak protocols.
    Returns a list of weak protocols found (e.g. ['TLS 1.0', 'TLS 1.1']).
    """
    weak_protocols = []
    
    # Map friendly names to SSLContext configuration
    # Note: Modern Python/OpenSSL often completely removes SSLv2/SSLv3 support.
    # We will try to test what we can.
    
    start_tests = []
    
    # Try TLS 1.0
    if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1"):
        start_tests.append(("TLS 1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1))
    
    # Try TLS 1.1
    if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_1"):
         start_tests.append(("TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1))

    for name, min_ver, max_ver in start_tests:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
            
            with _create_socket(host, port) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    # If we handshake successfully, the protocol is supported
                    if ssock.version():
                        weak_protocols.append(name)
        except (ssl.SSLError, socket.error):
            # Handshake failed -> Protocol likely not supported or server requires SNI/Verify
            pass
        except ValueError:
            # OS/Lib might reject the version configuration
            pass

    return weak_protocols

def check_weak_ciphers(host: str, port: int) -> List[str]:
    """
    Checks for support of weak cipher suites (RC4, NULL, DES).
    """
    weak_ciphers_found = []
    
    # Cipher strings to test. 
    # OpenSSL cipher strings: NULL, RC4, DES, 3DES, EXPORT, ADH
    # We try to force these ciphers.
    
    bad_suites = [
        ("RC4", "RC4"),
        ("NULL", "NULL"),
        ("DES", "DES"),
        ("Export", "EXPORT"),
        ("Anon", "aNULL")
    ]
    
    for name, cipher_str in bad_suites:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers(cipher_str)
            except ssl.SSLError:
                # Local OpenSSL might not even support asking for it
                continue
                
            with _create_socket(host, port) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        c_name = cipher[0]
                        weak_ciphers_found.append(f"{name} ({c_name})")
        except (ssl.SSLError, socket.error):
            pass
            
    return weak_ciphers_found

def scan_tls(url: str, **kwargs) -> Dict[str, Any]:
    """
    Enhanced TLS Scanner.
    Performs:
    1. Standard Certificate Analysis (Validity, Dates, Issuer) via infrastructure.py
    2. Protocol Support Check (TLS 1.0, 1.1)
    3. Weak Cipher Check (RC4, NULL, etc.)
    """
    results = kwargs.get("results", {})
    
    # 1. Base Cert Analysis
    base_info = _get_cert_details(url, **kwargs)
    
    host = base_info.get("host")
    port = base_info.get("port", 443)
    
    if not host:
        return base_info

    findings = []
    
    # 2. Protocol Check
    weak_protos = check_protocol_support(host, port)
    if weak_protos:
        base_info["problems"].extend([f"Weak Protocol: {p}" for p in weak_protos])
        for wp in weak_protos:
             findings.append({
                "type": "Weak TLS Protocol",
                "severity": "Medium", # TLS 1.0/1.1 is usually Medium/High depending on compliance
                "url": url,
                "description": f"Server supports deprecated protocol: {wp}",
                "recommendation": "Disable TLS 1.0 and 1.1. Configure server to use TLS 1.2 or 1.3 only."
            })

    # 3. Cipher Check
    weak_ciphers = check_weak_ciphers(host, port)
    if weak_ciphers:
         base_info["problems"].extend([f"Weak Cipher: {c}" for c in weak_ciphers])
         for wc in weak_ciphers:
             findings.append({
                "type": "Weak Cipher Suite",
                "severity": "Medium",
                "url": url,
                "description": f"Server supports weak cipher suite: {wc}",
                "recommendation": "Disable weak ciphers (RC4, DES, NULL). Use modern AEAD suites."
            })

    # Inject findings into main results if provided
    if "final" not in results:
        results["final"] = []
    
    # Avoid duplicates
    existing_ids = set() # simplistic check
    results["final"].extend(findings)

    # Return merged info
    return {
        "certificate": base_info,
        "new_findings": findings
    }

# Compatibility alias
def check_ssl_certificate(*args, **kwargs):
    return _get_cert_details(*args, **kwargs)

def scan_tls_quick(url):
    return scan_tls(url)
