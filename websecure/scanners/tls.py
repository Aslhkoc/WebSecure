from __future__ import annotations
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
    results = kwargs.get("results") or {}

    # 1. Base Cert Analysis — guarded: non-HTTPS hosts will fail gracefully
    try:
        base_info = _get_cert_details(url, config=kwargs.get("config"), session=kwargs.get("session"))
    except Exception as exc:
        _logger.warning(f"[TLS] Certificate analysis failed for {url}: {exc!r}")
        base_info = {}

    if not isinstance(base_info, dict):
        base_info = {}

    host = base_info.get("host")
    port = base_info.get("port", 443)

    if not host:
        from urllib.parse import urlparse as _up
        parsed = _up(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return {"certificate": base_info, "new_findings": []}

    # Ensure problems list exists
    if "problems" not in base_info:
        base_info["problems"] = []

    findings: List[Dict[str, Any]] = []

    # 2. Protocol Check
    try:
        weak_protos = check_protocol_support(host, port)
    except Exception as exc:
        _logger.debug(f"[TLS] Protocol check error for {host}:{port}: {exc!r}")
        weak_protos = []

    for wp in weak_protos:
        base_info["problems"].append(f"Weak Protocol: {wp}")
        findings.append({
            "type": "Weak TLS Protocol",
            "severity": "Medium",
            "url": url,
            "description": f"Server supports deprecated protocol: {wp}",
            "recommendation": "Disable TLS 1.0 and 1.1. Configure server to use TLS 1.2 or 1.3 only.",
        })

    # 3. Cipher Check
    try:
        weak_ciphers = check_weak_ciphers(host, port)
    except Exception as exc:
        _logger.debug(f"[TLS] Cipher check error for {host}:{port}: {exc!r}")
        weak_ciphers = []

    for wc in weak_ciphers:
        base_info["problems"].append(f"Weak Cipher: {wc}")
        findings.append({
            "type": "Weak Cipher Suite",
            "severity": "Medium",
            "url": url,
            "description": f"Server supports weak cipher suite: {wc}",
            "recommendation": "Disable weak ciphers (RC4, DES, NULL). Use modern AEAD suites.",
        })

    results.setdefault("final", []).extend(findings)

    return {
        "certificate": base_info,
        "new_findings": findings,
    }

# Compatibility alias
def check_ssl_certificate(*args, **kwargs):
    return _get_cert_details(*args, **kwargs)

def scan_tls_quick(url):
    return scan_tls(url)

# Plugin registry compat alias
run = scan_tls

# ============================================================================
# ADIM 9 — TLS Gelismis Siniflar
# TLSBEASTPoodleProber, TLSCRIMEBREACHProber, TLSROBOTProber,
# HTTP2HTTP3Checker, CDNMisconfigProber, TLSAdim9Scanner
# ============================================================================
import logging
import socket
import ssl
import time
import urllib.parse
from typing import Any, Dict, List, Optional
from websecure.scanners.base import BaseScanner

_tls_logger = logging.getLogger(__name__ + ".adim9")


def _tls_socket(host: str, port: int, timeout: int = 8) -> Optional[ssl.SSLSocket]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        return ctx.wrap_socket(raw, server_hostname=host)
    except Exception:
        return None


def _raw_socket(host: str, port: int, timeout: int = 8) -> Optional[socket.socket]:
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return None


# ===========================================================================
# TLSBEASTPoodleProber — BEAST + POODLE
# ===========================================================================
class TLSBEASTPoodleProber(BaseScanner):
    """
    BEAST (TLS 1.0 CBC) ve POODLE (SSLv3 / TLS CBC padding oracle) tespiti.
    """
    name = "tls_beast_poodle"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or 443

        # BEAST: TLS 1.0 destegi var mi?
        beast = self._probe_beast(host, port)
        if beast:
            results.append(beast)
            self.report_finding(**beast)

        # POODLE: SSLv3 destegi
        poodle = self._probe_poodle(host, port)
        if poodle:
            results.append(poodle)
            self.report_finding(**poodle)

        # TLS 1.1 (deprecated)
        tls11 = self._probe_tls11(host, port)
        if tls11:
            results.append(tls11)
            self.report_finding(**tls11)

        return results

    def _probe_beast(self, host: str, port: int) -> Optional[Dict]:
        if not (hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1")):
            return None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    ver = s.version()
                    cipher = s.cipher()
                    if ver == "TLSv1" and cipher and "CBC" in cipher[0]:
                        return {
                            "vuln_type": "TLS BEAST — TLS 1.0 CBC Cipher",
                            "url": f"https://{host}:{port}", "severity": "Medium",
                            "description": (
                                f"Server supports TLS 1.0 with CBC cipher {cipher[0]}. "
                                "Vulnerable to BEAST attack (Browser Exploit Against SSL/TLS). "
                                "Disable TLS 1.0 or prefer RC4 (deprecated) over CBC."
                            ),
                            "evidence": {"tls_version": ver, "cipher": cipher[0], "host": host},
                        }
        except Exception:
            pass
        return None

    def _probe_poodle(self, host: str, port: int) -> Optional[Dict]:
        """SSLv3 desteği — POODLE."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            if hasattr(ssl, "OP_NO_TLSv1") and hasattr(ssl, "OP_NO_TLSv1_1") and hasattr(ssl, "OP_NO_TLSv1_2"):
                ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    if "SSL" in (s.version() or ""):
                        return {
                            "vuln_type": "TLS POODLE — SSLv3 Supported",
                            "url": f"https://{host}:{port}", "severity": "High",
                            "description": "Server supports SSLv3. Vulnerable to POODLE attack.",
                            "evidence": {"version": s.version(), "host": host},
                        }
        except Exception:
            pass
        return None

    def _probe_tls11(self, host: str, port: int) -> Optional[Dict]:
        if not (hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_1")):
            return None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    if s.version() == "TLSv1.1":
                        return {
                            "vuln_type": "TLS 1.1 Supported (Deprecated)",
                            "url": f"https://{host}:{port}", "severity": "Low",
                            "description": "TLS 1.1 is deprecated (RFC 8996). Disable and use TLS 1.2/1.3 only.",
                            "evidence": {"version": "TLS 1.1", "host": host},
                        }
        except Exception:
            pass
        return None


# ===========================================================================
# TLSCRIMEBREACHProber — CRIME + BREACH
# ===========================================================================
class TLSCRIMEBREACHProber(BaseScanner):
    """
    CRIME: TLS compression aktif mi?
    BREACH: HTTP compression (gzip/deflate) + secret in response?
    """
    name = "tls_crime_breach"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or 443

        # CRIME
        crime = self._probe_crime(host, port)
        if crime:
            results.append(crime)
            self.report_finding(**crime)

        # BREACH
        breach = self._probe_breach(target)
        if breach:
            results.append(breach)
            self.report_finding(**breach)

        return results

    def _probe_crime(self, host: str, port: int) -> Optional[Dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    comp = s.compression()
                    if comp:
                        return {
                            "vuln_type": "TLS CRIME — TLS Compression Enabled",
                            "url": f"https://{host}:{port}", "severity": "High",
                            "description": (
                                f"TLS compression is enabled ({comp}). "
                                "Vulnerable to CRIME attack — attacker can decrypt HTTPS cookies."
                            ),
                            "evidence": {"compression": comp, "host": host},
                        }
        except Exception:
            pass
        return None

    def _probe_breach(self, url: str) -> Optional[Dict]:
        try:
            resp = self.session.get(url, headers={"Accept-Encoding": "gzip, deflate"}, timeout=10)
            enc  = resp.headers.get("Content-Encoding", "").lower()
            ct   = resp.headers.get("Content-Type", "").lower()
            if enc in ("gzip", "deflate", "br") and "text/html" in ct:
                # Heuristic: if page reflects a parameter in compressed body
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qsl(parsed.query)
                if qs:
                    canary = "wsp_breach_test"
                    test_pairs = [(k, canary) for k, v in qs[:1]]
                    test_url   = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_pairs)))
                    r2 = self.session.get(test_url, headers={"Accept-Encoding": "gzip, deflate"}, timeout=10)
                    if canary in (r2.text or ""):
                        return {
                            "vuln_type": "TLS BREACH — HTTP Compression + Secret Reflection",
                            "url": url, "severity": "High",
                            "description": (
                                f"HTTP response uses {enc} compression and reflects user input. "
                                "Vulnerable to BREACH: attacker can recover secrets (CSRF tokens, cookies) "
                                "via adaptive chosen-plaintext attack over HTTPS."
                            ),
                            "evidence": {"encoding": enc, "reflected_param": test_pairs[0][0]},
                        }
        except Exception as exc:
            _tls_logger.debug("[BREACH] %s", exc)
        return None


# ===========================================================================
# TLSROBOTProber — RSA PKCS#1 v1.5 Padding Oracle (ROBOT)
# ===========================================================================
class TLSROBOTProber(BaseScanner):
    """
    ROBOT (Return Of Bleichenbacher's Oracle Threat):
    RSA PKCS#1 v1.5 padding oracle — timing farki ile tespiti.
    """
    name = "tls_robot"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or 443

        timing = self._probe_timing(host, port)
        if timing:
            results.append(timing)
            self.report_finding(**timing)
        return results

    def _probe_timing(self, host: str, port: int) -> Optional[Dict]:
        """
        Simplified ROBOT timing probe:
        Send RSA-based ClientHello and measure handshake times.
        Large variance in timing suggests PKCS1.5 oracle.
        """
        times = []
        for i in range(5):
            t0 = time.time()
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                # Force RSA key exchange ciphers only
                try:
                    ctx.set_ciphers("RSA")
                except ssl.SSLError:
                    return None  # RSA ciphers not available locally
                with socket.create_connection((host, port), timeout=6) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as s:
                        times.append(time.time() - t0)
            except Exception:
                times.append(time.time() - t0)
        if len(times) < 3:
            return None
        avg = sum(times) / len(times)
        variance = max(times) - min(times)
        if variance > avg * 0.5 and avg < 2.0:
            return {
                "vuln_type": "TLS ROBOT — RSA Padding Oracle (Timing)",
                "url": f"https://{host}:{port}", "severity": "Critical",
                "description": (
                    "High timing variance in RSA TLS handshakes detected. "
                    "Possible ROBOT (Bleichenbacher) padding oracle. "
                    "An attacker may decrypt TLS sessions or forge RSA signatures."
                ),
                "evidence": {
                    "avg_ms": round(avg * 1000, 1),
                    "variance_ms": round(variance * 1000, 1),
                    "samples": [round(t * 1000, 1) for t in times],
                },
            }
        return None


# ===========================================================================
# HTTP2HTTP3Checker
# ===========================================================================
class HTTP2HTTP3Checker(BaseScanner):
    """
    HTTP/2 ve HTTP/3 (QUIC) destek kontrolu.
    Alpn negotiation + Alt-Svc header analizi.
    """
    name = "http2_http3_checker"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or 443

        # HTTP/2 check via ALPN
        h2 = self._check_h2(host, port)
        if h2:
            results.append(h2)

        # HTTP/3 check via Alt-Svc header
        h3 = self._check_h3(target)
        if h3:
            results.append(h3)

        return results

    def _check_h2(self, host: str, port: int) -> Optional[Dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    proto = s.selected_alpn_protocol()
                    if proto == "h2":
                        return {
                            "vuln_type": "HTTP/2 Supported",
                            "url": f"https://{host}:{port}", "severity": "Info",
                            "description": "Server supports HTTP/2 (ALPN negotiated h2). Modern protocol.",
                            "evidence": {"alpn": proto},
                        }
        except Exception:
            pass
        return None

    def _check_h3(self, url: str) -> Optional[Dict]:
        try:
            resp = self.session.get(url, timeout=8)
            alt  = resp.headers.get("Alt-Svc", "")
            if "h3" in alt or "quic" in alt.lower():
                return {
                    "vuln_type": "HTTP/3 (QUIC) Advertised",
                    "url": url, "severity": "Info",
                    "description": f"Server advertises HTTP/3/QUIC via Alt-Svc: {alt[:100]}",
                    "evidence": {"alt_svc": alt},
                }
        except Exception:
            pass
        return None


# ===========================================================================
# CDNMisconfigProber
# ===========================================================================
class CDNMisconfigProber(BaseScanner):
    """
    CDN misconfiguration tespiti:
    - Cache deception (path suffix tricks)
    - Cache poisoning via headers
    - X-Forwarded-Host reflection
    - Via/X-Cache header bilgi ifşası
    """
    name = "cdn_misconfig"

    _CACHE_DECEPTION_SUFFIXES = [
        "/profile%2F..%2Fstatic%2Fwsp.css",
        "/account%2F..%2Fimg%2Fwsp.png",
        "/dashboard%2F..%2Fjs%2Fwsp.js",
        "/api/user/wsp.css",
        "/api/me/wsp.jpg",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []

        # 1. Cache deception
        for suffix in self._CACHE_DECEPTION_SUFFIXES:
            url = target.rstrip("/") + suffix
            try:
                resp = self.session.get(url, timeout=8)
                age  = resp.headers.get("Age", "")
                cache_ctrl = resp.headers.get("Cache-Control", "")
                x_cache    = resp.headers.get("X-Cache", "")
                if resp.status_code == 200 and (age or "HIT" in x_cache.upper()):
                    results.append({
                        "vuln_type": "CDN Cache Deception",
                        "url": url, "severity": "High",
                        "description": (
                            f"CDN cached authenticated response at path '{suffix}'. "
                            "Cache deception: attacker tricks victim to visit URL -> "
                            "CDN caches their private page -> attacker retrieves it."
                        ),
                        "evidence": {"suffix": suffix, "age": age,
                                     "x_cache": x_cache, "status": resp.status_code},
                    })
                    self.report_finding(**results[-1])
                    break
            except Exception as exc:
                _tls_logger.debug("[CDN] %s", exc)

        # 2. X-Forwarded-Host reflection / cache poisoning
        canary = "wsp-poison.invalid"
        try:
            resp = self.session.get(target, headers={"X-Forwarded-Host": canary}, timeout=8)
            if canary in (resp.text or "")[:3000] or canary in str(resp.headers):
                results.append({
                    "vuln_type": "CDN Cache Poisoning via X-Forwarded-Host",
                    "url": target, "severity": "High",
                    "description": (
                        f"X-Forwarded-Host: {canary} reflected in response. "
                        "If CDN caches this response, all users receive poisoned content."
                    ),
                    "evidence": {"injected_host": canary, "reflected": True},
                })
                self.report_finding(**results[-1])
        except Exception as exc:
            _tls_logger.debug("[CDNPoison] %s", exc)

        # 3. Info disclosure via Via / X-Cache
        try:
            resp = self.session.get(target, timeout=8)
            via  = resp.headers.get("Via", "")
            srv  = resp.headers.get("Server", "")
            xcache = resp.headers.get("X-Cache", "")
            if via or xcache:
                results.append({
                    "vuln_type": "CDN Header Information Disclosure",
                    "url": target, "severity": "Info",
                    "description": f"CDN/proxy headers exposed: Via={via!r}, X-Cache={xcache!r}, Server={srv!r}",
                    "evidence": {"via": via, "x_cache": xcache, "server": srv},
                })
        except Exception:
            pass

        return results


# ===========================================================================
# TLSAdim9Scanner — Orchestrator
# ===========================================================================
class TLSAdim9Scanner(BaseScanner):
    """
    Adim 9 TLS/Network orchestrator:
    BEASTPoodle + CRIMEBREACH + ROBOT + HTTP2HTTP3 + CDNMisconfig
    """
    name = "tls_adim9"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        probers = [
            TLSBEASTPoodleProber(session=self.session, results=self.results),
            TLSCRIMEBREACHProber(session=self.session, results=self.results),
            TLSROBOTProber(session=self.session, results=self.results),
            HTTP2HTTP3Checker(session=self.session, results=self.results),
            CDNMisconfigProber(session=self.session, results=self.results),
        ]
        for prober in probers:
            try:
                prober.target = target
                all_results.extend(prober.run(target, **kwargs))
            except Exception as exc:
                _tls_logger.warning("[TLSAdim9] %s: %s", prober.name, exc)
        return all_results


# ============================================================================
# DEEP CIPHER + PROTOCOL ATTACK CLASSES
# WeakCipherSuiteProber, HSTSMissingProber, TLSProtocolDowngradeProber,
# CertificateValidationProber, TLSCompressionProber, TLSDeepScanner
# ============================================================================
import datetime
import re
import subprocess


_deep_logger = logging.getLogger(__name__ + ".deep")


# ===========================================================================
# WeakCipherSuiteProber — RC4, DES, NULL, EXPORT cipher detection
# ===========================================================================
class WeakCipherSuiteProber(BaseScanner):
    """
    Test server for weak cipher suite acceptance: RC4, DES/3DES, NULL, EXPORT.
    Falls back to openssl subprocess if local OpenSSL can't negotiate the cipher.
    """
    name = "tls_weak_cipher"

    _CIPHER_TESTS = [
        ("RC4",    "RC4-SHA:RC4-MD5",            "Critical"),
        ("3DES",   "DES-CBC3-SHA",                "High"),
        ("DES",    "DES-CBC-SHA",                 "Critical"),
        ("NULL",   "NULL-MD5:NULL-SHA",           "Critical"),
        ("EXPORT", "EXP-RC4-MD5:EXP-DES-CBC-SHA","Critical"),
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or 443

        for cipher_name, cipher_str, severity in self._CIPHER_TESTS:
            finding = self._probe_cipher(host, port, cipher_name, cipher_str, severity)
            if finding:
                results.append(finding)
                self.report_finding(**finding)

        return results

    def _probe_cipher(self, host: str, port: int,
                      cipher_name: str, cipher_str: str, severity: str) -> Optional[Dict]:
        # Attempt 1: via ssl module
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            try:
                ctx.set_ciphers(cipher_str)
            except ssl.SSLError:
                # Local OpenSSL does not know this cipher — try subprocess fallback
                return self._probe_cipher_subprocess(host, port, cipher_name, cipher_str, severity)

            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    negotiated = s.cipher()
                    if negotiated:
                        return {
                            "vuln_type": f"Weak Cipher Suite — {cipher_name}",
                            "url": f"https://{host}:{port}",
                            "severity": severity,
                            "description": (
                                f"Server accepted weak cipher suite '{negotiated[0]}' "
                                f"(category: {cipher_name}). This cipher is considered "
                                "cryptographically broken and should be disabled immediately."
                            ),
                            "evidence": {
                                "cipher_name": cipher_name,
                                "negotiated_cipher": negotiated[0],
                                "protocol": negotiated[1],
                                "host": host,
                            },
                        }
        except (ssl.SSLError, socket.error, OSError):
            pass
        except AttributeError:
            pass
        except Exception as exc:
            _deep_logger.debug("[WeakCipher] %s probe error: %s", cipher_name, exc)

        return self._probe_cipher_subprocess(host, port, cipher_name, cipher_str, severity)

    def _probe_cipher_subprocess(self, host: str, port: int,
                                  cipher_name: str, cipher_str: str, severity: str) -> Optional[Dict]:
        """Fallback: use openssl s_client subprocess to test cipher."""
        try:
            result = subprocess.run(
                ["openssl", "s_client", "-cipher", cipher_str,
                 "-connect", f"{host}:{port}", "-no_tls1_3"],
                input=b"",
                capture_output=True,
                timeout=8,
            )
            output = result.stdout.decode("utf-8", errors="replace") + \
                     result.stderr.decode("utf-8", errors="replace")
            # Successful handshake marker
            if "Cipher    :" in output and "NONE" not in output:
                # Extract cipher name from output
                for line in output.splitlines():
                    if "Cipher    :" in line:
                        negotiated_name = line.split(":")[-1].strip()
                        return {
                            "vuln_type": f"Weak Cipher Suite — {cipher_name}",
                            "url": f"https://{host}:{port}",
                            "severity": severity,
                            "description": (
                                f"Server accepted weak cipher suite '{negotiated_name}' "
                                f"(category: {cipher_name}) via openssl s_client probe. "
                                "This cipher is considered cryptographically broken."
                            ),
                            "evidence": {
                                "cipher_name": cipher_name,
                                "negotiated_cipher": negotiated_name,
                                "method": "openssl_subprocess",
                                "host": host,
                            },
                        }
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        except Exception as exc:
            _deep_logger.debug("[WeakCipher] subprocess fallback error: %s", exc)

        return None


# ===========================================================================
# HSTSMissingProber — HSTS header analysis + HTTP redirect + mixed content
# ===========================================================================
class HSTSMissingProber(BaseScanner):
    """
    Check HSTS configuration, HTTP→HTTPS redirect, and mixed content.
    """
    name = "tls_hsts"

    _ONE_YEAR = 31536000  # seconds

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or 443
        https_url = f"https://{host}" + (f":{port}" if port != 443 else "")

        # 1. HSTS header check
        hsts_findings = self._check_hsts(https_url)
        for f in hsts_findings:
            results.append(f)
            self.report_finding(**f)

        # 2. HTTP → HTTPS redirect check
        redirect_finding = self._check_http_redirect(host, parsed.port or 80)
        if redirect_finding:
            results.append(redirect_finding)
            self.report_finding(**redirect_finding)

        # 3. Mixed content check
        mixed_finding = self._check_mixed_content(https_url)
        if mixed_finding:
            results.append(mixed_finding)
            self.report_finding(**mixed_finding)

        return results

    def _check_hsts(self, https_url: str) -> List[Dict]:
        findings = []
        try:
            resp = self.session.get(https_url, timeout=10, allow_redirects=True)
            hsts = resp.headers.get("Strict-Transport-Security", "")

            if not hsts:
                findings.append({
                    "vuln_type": "HSTS Missing",
                    "url": https_url,
                    "severity": "High",
                    "description": (
                        "The server does not send a Strict-Transport-Security (HSTS) header. "
                        "Without HSTS, users are vulnerable to SSL stripping attacks."
                    ),
                    "evidence": {"header": "Strict-Transport-Security", "value": None},
                })
                return findings

            # Parse max-age
            max_age = 0
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))

            if max_age < self._ONE_YEAR:
                findings.append({
                    "vuln_type": "HSTS max-age Too Short",
                    "url": https_url,
                    "severity": "Medium",
                    "description": (
                        f"HSTS max-age is {max_age} seconds (< {self._ONE_YEAR} / 1 year). "
                        "A short max-age reduces protection against SSL stripping."
                    ),
                    "evidence": {"hsts_header": hsts, "max_age": max_age},
                })

            if "includesubdomains" not in hsts.lower():
                findings.append({
                    "vuln_type": "HSTS Missing includeSubDomains",
                    "url": https_url,
                    "severity": "Low",
                    "description": (
                        "HSTS header is missing the 'includeSubDomains' directive. "
                        "Subdomains are not protected against SSL stripping."
                    ),
                    "evidence": {"hsts_header": hsts},
                })

            if "preload" not in hsts.lower():
                findings.append({
                    "vuln_type": "HSTS Missing preload",
                    "url": https_url,
                    "severity": "Informational",
                    "description": (
                        "HSTS header is missing the 'preload' directive. "
                        "Without preload, users are unprotected on their first visit."
                    ),
                    "evidence": {"hsts_header": hsts},
                })

        except Exception as exc:
            _deep_logger.debug("[HSTS] check failed: %s", exc)

        return findings

    def _check_http_redirect(self, host: str, port: int) -> Optional[Dict]:
        """Check that HTTP redirects to HTTPS."""
        http_url = f"http://{host}" + (f":{port}" if port not in (80, 443) else "")
        try:
            resp = self.session.get(http_url, timeout=8, allow_redirects=False)
            location = resp.headers.get("Location", "")
            if resp.status_code not in (301, 302, 307, 308) or not location.startswith("https://"):
                return {
                    "vuln_type": "HTTP to HTTPS Redirect Missing",
                    "url": http_url,
                    "severity": "High",
                    "description": (
                        f"HTTP request to {http_url} does not redirect to HTTPS "
                        f"(status={resp.status_code}, Location={location!r}). "
                        "Users accessing via HTTP are not automatically upgraded."
                    ),
                    "evidence": {
                        "status_code": resp.status_code,
                        "location": location,
                    },
                }
        except Exception as exc:
            _deep_logger.debug("[HSTS] HTTP redirect check failed: %s", exc)
        return None

    def _check_mixed_content(self, https_url: str) -> Optional[Dict]:
        """Scan HTTPS page HTML for http:// src/href references."""
        try:
            resp = self.session.get(https_url, timeout=10)
            html = resp.text or ""
            # Find http:// in src= or href= attributes
            mixed = re.findall(
                r'(?:src|href|action)\s*=\s*["\']?(http://[^\s"\'<>]+)',
                html, re.IGNORECASE
            )
            if mixed:
                return {
                    "vuln_type": "Mixed Content on HTTPS Page",
                    "url": https_url,
                    "severity": "Medium",
                    "description": (
                        f"HTTPS page loads {len(mixed)} resource(s) over insecure HTTP. "
                        "Mixed content allows network attackers to tamper with page resources."
                    ),
                    "evidence": {
                        "mixed_urls": mixed[:5],
                        "total_count": len(mixed),
                    },
                }
        except Exception as exc:
            _deep_logger.debug("[HSTS] Mixed content check failed: %s", exc)
        return None


# ===========================================================================
# TLSProtocolDowngradeProber — SSLv2/v3/TLS1.0/1.1 downgrade testing
# ===========================================================================
class TLSProtocolDowngradeProber(BaseScanner):
    """
    Test for dangerous legacy protocol support:
    SSLv2 (DROWN), SSLv3 (POODLE), TLSv1.0 (BEAST), TLSv1.1 (deprecated).
    """
    name = "tls_downgrade"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or 443

        tests = [
            ("SSLv2",   self._probe_sslv2,  host, port),
            ("SSLv3",   self._probe_sslv3,  host, port),
            ("TLSv1.0", self._probe_tlsv10, host, port),
            ("TLSv1.1", self._probe_tlsv11, host, port),
        ]

        for proto_name, probe_fn, h, p in tests:
            try:
                finding = probe_fn(h, p)
                if finding:
                    results.append(finding)
                    self.report_finding(**finding)
            except Exception as exc:
                _deep_logger.debug("[Downgrade] %s probe error: %s", proto_name, exc)

        return results

    def _probe_sslv2(self, host: str, port: int) -> Optional[Dict]:
        """DROWN: SSLv2 support check."""
        try:
            proto = getattr(ssl, "PROTOCOL_SSLv2", None)
            if proto is None:
                raise AttributeError("PROTOCOL_SSLv2 not available")
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    ver = s.version()
                    if ver:
                        return {
                            "vuln_type": "SSLv2 Supported (DROWN)",
                            "url": f"https://{host}:{port}",
                            "severity": "Critical",
                            "description": (
                                f"Server supports SSLv2 (negotiated: {ver}). "
                                "Vulnerable to DROWN attack — allows decryption of RSA TLS sessions. "
                                "Disable SSLv2 immediately."
                            ),
                            "evidence": {"protocol": "SSLv2", "negotiated": ver, "host": host},
                        }
        except AttributeError:
            pass  # Python/OpenSSL removed SSLv2 — server almost certainly doesn't support it
        except ssl.SSLError:
            pass  # Handshake failed — server correctly rejects SSLv2
        except (socket.error, OSError):
            pass
        except Exception as exc:
            _deep_logger.debug("[Downgrade] SSLv2 probe error: %s", exc)
        return None

    def _probe_sslv3(self, host: str, port: int) -> Optional[Dict]:
        """POODLE: SSLv3 support check."""
        try:
            proto = getattr(ssl, "PROTOCOL_SSLv3", None)
            if proto is None:
                raise AttributeError("PROTOCOL_SSLv3 not available")
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    ver = s.version()
                    if ver:
                        return {
                            "vuln_type": "SSLv3 Supported (POODLE)",
                            "url": f"https://{host}:{port}",
                            "severity": "Critical",
                            "description": (
                                f"Server supports SSLv3 (negotiated: {ver}). "
                                "Vulnerable to POODLE attack — allows CBC padding oracle decryption. "
                                "Disable SSLv3 immediately."
                            ),
                            "evidence": {"protocol": "SSLv3", "negotiated": ver, "host": host},
                        }
        except AttributeError:
            pass  # SSLv3 constant unavailable in this Python/OpenSSL build
        except ssl.SSLError:
            pass  # Handshake failed — server correctly rejects SSLv3
        except (socket.error, OSError):
            pass
        except Exception as exc:
            _deep_logger.debug("[Downgrade] SSLv3 probe error: %s", exc)
        return None

    def _probe_tlsv10(self, host: str, port: int) -> Optional[Dict]:
        """BEAST: TLS 1.0 support check."""
        try:
            if not (hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1")):
                raise AttributeError("TLSv1 constant not available")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    ver = s.version()
                    if ver:
                        return {
                            "vuln_type": "TLS 1.0 Supported (BEAST)",
                            "url": f"https://{host}:{port}",
                            "severity": "High",
                            "description": (
                                f"Server supports TLS 1.0 (negotiated: {ver}). "
                                "Vulnerable to BEAST attack and deprecated per RFC 8996. "
                                "Disable TLS 1.0 and use TLS 1.2/1.3 only."
                            ),
                            "evidence": {"protocol": "TLSv1.0", "negotiated": ver, "host": host},
                        }
        except AttributeError:
            pass
        except ssl.SSLError:
            pass
        except (socket.error, OSError):
            pass
        except Exception as exc:
            _deep_logger.debug("[Downgrade] TLSv1.0 probe error: %s", exc)
        return None

    def _probe_tlsv11(self, host: str, port: int) -> Optional[Dict]:
        """TLS 1.1 deprecation check."""
        try:
            if not (hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_1")):
                raise AttributeError("TLSv1_1 constant not available")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((host, port), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    ver = s.version()
                    if ver:
                        return {
                            "vuln_type": "TLS 1.1 Supported (Deprecated)",
                            "url": f"https://{host}:{port}",
                            "severity": "Medium",
                            "description": (
                                f"Server supports TLS 1.1 (negotiated: {ver}). "
                                "TLS 1.1 is deprecated per RFC 8996. "
                                "Upgrade to TLS 1.2/1.3."
                            ),
                            "evidence": {"protocol": "TLSv1.1", "negotiated": ver, "host": host},
                        }
        except AttributeError:
            pass
        except ssl.SSLError:
            pass
        except (socket.error, OSError):
            pass
        except Exception as exc:
            _deep_logger.debug("[Downgrade] TLSv1.1 probe error: %s", exc)
        return None


# ===========================================================================
# CertificateValidationProber — expiry, hostname, self-signed, issuer
# ===========================================================================
class CertificateValidationProber(BaseScanner):
    """
    Full certificate validation: expiry, hostname match, self-signed detection,
    and near-expiry warnings.
    """
    name = "tls_cert"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or 443

        findings = self._probe_cert(host, port)
        for f in findings:
            results.append(f)
            self.report_finding(**f)

        return results

    def _probe_cert(self, host: str, port: int) -> List[Dict]:
        findings = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cert = s.getpeercert()

            if not cert:
                findings.append({
                    "vuln_type": "Certificate Not Retrieved",
                    "url": f"https://{host}:{port}",
                    "severity": "High",
                    "description": "Could not retrieve TLS certificate from server.",
                    "evidence": {"host": host},
                })
                return findings

            # Expiry check
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                try:
                    not_after = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    delta = not_after - now

                    if delta.total_seconds() < 0:
                        findings.append({
                            "vuln_type": "Certificate Expired",
                            "url": f"https://{host}:{port}",
                            "severity": "High",
                            "description": (
                                f"TLS certificate expired on {not_after_str}. "
                                "Browsers will reject this certificate."
                            ),
                            "evidence": {"not_after": not_after_str, "host": host},
                        })
                    elif delta.days < 30:
                        findings.append({
                            "vuln_type": "Certificate Expiring Soon",
                            "url": f"https://{host}:{port}",
                            "severity": "Medium",
                            "description": (
                                f"TLS certificate expires in {delta.days} days ({not_after_str}). "
                                "Renew the certificate before expiry to avoid service disruption."
                            ),
                            "evidence": {
                                "not_after": not_after_str,
                                "days_remaining": delta.days,
                                "host": host,
                            },
                        })
                    else:
                        findings.append({
                            "vuln_type": "Certificate Valid",
                            "url": f"https://{host}:{port}",
                            "severity": "Informational",
                            "description": (
                                f"TLS certificate is valid and expires in {delta.days} days."
                            ),
                            "evidence": {
                                "not_after": not_after_str,
                                "days_remaining": delta.days,
                                "host": host,
                            },
                        })
                except (ValueError, OSError) as exc:
                    _deep_logger.debug("[Cert] Date parse error: %s", exc)

            # Self-signed check: subject == issuer
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            if subject and issuer and subject == issuer:
                findings.append({
                    "vuln_type": "Self-Signed Certificate",
                    "url": f"https://{host}:{port}",
                    "severity": "High",
                    "description": (
                        "TLS certificate is self-signed (issuer == subject). "
                        "Browsers will show security warnings; MITM attacks are trivial."
                    ),
                    "evidence": {
                        "subject": subject,
                        "issuer": issuer,
                        "host": host,
                    },
                })

            # Hostname match check
            common_name = subject.get("commonName", "")
            san_list = [
                name for _, name in cert.get("subjectAltName", [])
                if _ == "DNS"
            ]
            all_names = san_list or ([common_name] if common_name else [])
            hostname_ok = any(
                self._hostname_matches(host, n) for n in all_names
            )
            if not hostname_ok and all_names:
                findings.append({
                    "vuln_type": "Certificate Hostname Mismatch",
                    "url": f"https://{host}:{port}",
                    "severity": "High",
                    "description": (
                        f"TLS certificate CN/SAN does not match hostname '{host}'. "
                        f"Certificate covers: {all_names[:5]}. "
                        "Vulnerable to MITM — browsers will warn users."
                    ),
                    "evidence": {
                        "host": host,
                        "cert_names": all_names[:5],
                        "common_name": common_name,
                    },
                })

        except ssl.SSLError as exc:
            if "certificate has expired" in str(exc).lower():
                findings.append({
                    "vuln_type": "Certificate Expired",
                    "url": f"https://{host}:{port}",
                    "severity": "High",
                    "description": f"TLS handshake failed due to expired certificate: {exc}",
                    "evidence": {"ssl_error": str(exc), "host": host},
                })
        except (socket.error, OSError) as exc:
            _deep_logger.debug("[Cert] Connection error: %s", exc)
        except Exception as exc:
            _deep_logger.debug("[Cert] Unexpected error: %s", exc)

        return findings

    @staticmethod
    def _hostname_matches(hostname: str, pattern: str) -> bool:
        """Simple wildcard hostname matching."""
        if pattern.startswith("*."):
            suffix = pattern[2:]
            parts  = hostname.split(".", 1)
            return len(parts) == 2 and parts[1].lower() == suffix.lower()
        return hostname.lower() == pattern.lower()


# ===========================================================================
# TLSCompressionProber — CRIME attack via TLS compression detection
# ===========================================================================
class TLSCompressionProber(BaseScanner):
    """
    Detect CRIME vulnerability: TLS compression enabled on server.
    Primary method: ssl.SSLSocket.compression() after handshake.
    Fallback: openssl s_client -comp subprocess.
    """
    name = "tls_compression"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or 443

        finding = self._probe_compression(host, port)
        if finding:
            results.append(finding)
            self.report_finding(**finding)

        return results

    def _probe_compression(self, host: str, port: int) -> Optional[Dict]:
        # Primary: ssl module check
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=8) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    comp = s.compression()
                    if comp:
                        return {
                            "vuln_type": "TLS Compression Enabled (CRIME)",
                            "url": f"https://{host}:{port}",
                            "severity": "High",
                            "description": (
                                f"TLS compression is enabled (algorithm: {comp}). "
                                "Vulnerable to CRIME attack: an attacker with network access "
                                "can decrypt HTTPS cookies and session tokens via adaptive "
                                "chosen-plaintext attack."
                            ),
                            "evidence": {"compression_algorithm": comp, "host": host},
                        }
                    # comp is None → no compression → not vulnerable (check subprocess too)
        except (ssl.SSLError, socket.error, OSError) as exc:
            _deep_logger.debug("[Compression] SSL connect error: %s", exc)
        except Exception as exc:
            _deep_logger.debug("[Compression] Unexpected error: %s", exc)

        # Fallback: openssl s_client -comp
        return self._probe_compression_subprocess(host, port)

    def _probe_compression_subprocess(self, host: str, port: int) -> Optional[Dict]:
        """Use openssl s_client -comp to check for TLS compression."""
        try:
            result = subprocess.run(
                ["openssl", "s_client", "-comp", "-connect", f"{host}:{port}"],
                input=b"",
                capture_output=True,
                timeout=10,
            )
            output = result.stdout.decode("utf-8", errors="replace") + \
                     result.stderr.decode("utf-8", errors="replace")

            # openssl reports "Compression: zlib compression" when enabled
            if "Compression: zlib compression" in output:
                return {
                    "vuln_type": "TLS Compression Enabled (CRIME)",
                    "url": f"https://{host}:{port}",
                    "severity": "High",
                    "description": (
                        "TLS compression (zlib) detected via openssl s_client -comp. "
                        "Vulnerable to CRIME attack — disable TLS compression on the server."
                    ),
                    "evidence": {
                        "detection_method": "openssl_subprocess",
                        "compression_algorithm": "zlib",
                        "host": host,
                    },
                }
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        except Exception as exc:
            _deep_logger.debug("[Compression] subprocess error: %s", exc)

        return None


# ===========================================================================
# TLSDeepScanner — Orchestrator for all 5 deep cipher/protocol probers
# ===========================================================================
class TLSDeepScanner(BaseScanner):
    """
    Deep TLS attack orchestrator:
    WeakCipherSuiteProber + HSTSMissingProber + TLSProtocolDowngradeProber +
    CertificateValidationProber + TLSCompressionProber
    """
    name = "tls_deep"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        probers = [
            WeakCipherSuiteProber(session=self.session, results=self.results),
            HSTSMissingProber(session=self.session, results=self.results),
            TLSProtocolDowngradeProber(session=self.session, results=self.results),
            CertificateValidationProber(session=self.session, results=self.results),
            TLSCompressionProber(session=self.session, results=self.results),
        ]
        for prober in probers:
            try:
                prober.target = target
                all_results.extend(prober.run(target, **kwargs))
            except Exception as exc:
                _deep_logger.warning("[TLSDeep] %s failed: %s", prober.name, exc)

        # sslyze entegrasyonu — kuruluysa derin analiz yap
        try:
            sslyze_results = _run_sslyze(target)
            all_results.extend(sslyze_results)
        except Exception as exc:
            _deep_logger.debug("[TLSDeep] sslyze skipped: %s", exc)

        return all_results


# ===========================================================================
# SSlyze entegrasyon fonksiyonu — Heartbleed, ROBOT, OCSP, cipher enum
# ===========================================================================

def _run_sslyze(target: str) -> List[Dict]:
    """
    sslyze ile tam TLS analizi:
    - Heartbleed, ROBOT, OpenSSL CCS Injection
    - Session renegotiation
    - OCSP stapling
    - Certificate bilgileri (issuer, expiry, SAN)
    - Zayıf cipher suite enumeration
    """
    try:
        from sslyze import (
            Scanner, ServerNetworkLocation, ServerScanRequest,
            ScanCommand,
        )
        from sslyze.errors import ServerRejectedTlsHandshake, ConnectionToServerFailed
    except ImportError:
        return []

    import urllib.parse as _up
    parsed = _up.urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port == 80:
        return []  # HTTP — TLS analizi gerekmez

    findings: List[Dict] = []

    try:
        location = ServerNetworkLocation(hostname=host, port=port)
        request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.SESSION_RENEGOTIATION,
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
            },
        )
        scanner = Scanner()
        scanner.queue_scans([request])

        for result in scanner.get_results():
            if result.scan_result is None:
                continue
            r = result.scan_result

            # Heartbleed
            try:
                hb = r.heartbleed
                if hb and hb.is_vulnerable_to_heartbleed:
                    findings.append({
                        "vuln_type": "Heartbleed (CVE-2014-0160)",
                        "url": f"https://{host}:{port}",
                        "severity": "Critical",
                        "description": (
                            "Server is vulnerable to Heartbleed! An attacker can read "
                            "64KB of server memory per request, leaking private keys, "
                            "session tokens, and plaintext data."
                        ),
                        "evidence": {"host": host, "port": port, "detection": "sslyze"},
                        "cvss": 9.8,
                    })
            except Exception:
                pass

            # ROBOT
            try:
                robot = r.robot
                if robot and "VULNERABLE" in str(robot.robot_result).upper():
                    findings.append({
                        "vuln_type": "ROBOT Attack — RSA Padding Oracle",
                        "url": f"https://{host}:{port}",
                        "severity": "High",
                        "description": (
                            "Server is vulnerable to ROBOT (Return Of Bleichenbacher's "
                            "Oracle Threat). Attacker can decrypt RSA ciphertext or "
                            "forge RSA signatures."
                        ),
                        "evidence": {"robot_result": str(robot.robot_result), "detection": "sslyze"},
                        "cvss": 7.5,
                    })
            except Exception:
                pass

            # OpenSSL CCS Injection
            try:
                ccs = r.openssl_ccs_injection
                if ccs and ccs.is_vulnerable_to_ccs_injection:
                    findings.append({
                        "vuln_type": "OpenSSL CCS Injection (CVE-2014-0224)",
                        "url": f"https://{host}:{port}",
                        "severity": "High",
                        "description": (
                            "Server is vulnerable to OpenSSL CCS Injection. "
                            "A MitM attacker can decrypt and modify encrypted traffic."
                        ),
                        "evidence": {"host": host, "detection": "sslyze"},
                        "cvss": 7.4,
                    })
            except Exception:
                pass

            # Session Renegotiation
            try:
                renego = r.session_renegotiation
                if renego:
                    if not renego.supports_secure_renegotiation:
                        findings.append({
                            "vuln_type": "Insecure TLS Renegotiation",
                            "url": f"https://{host}:{port}",
                            "severity": "Medium",
                            "description": (
                                "Server does not support secure TLS renegotiation (RFC 5746). "
                                "Vulnerable to renegotiation injection attacks."
                            ),
                            "evidence": {"host": host, "detection": "sslyze"},
                        })
                    if renego.is_vulnerable_to_client_renegotiation_dos:
                        findings.append({
                            "vuln_type": "Client-Initiated Renegotiation DoS",
                            "url": f"https://{host}:{port}",
                            "severity": "Medium",
                            "description": (
                                "Server allows unlimited client-initiated renegotiation. "
                                "Can be abused for CPU-exhaustion DoS."
                            ),
                            "evidence": {"host": host, "detection": "sslyze"},
                        })
            except Exception:
                pass

            # Certificate Info
            try:
                cert_info = r.certificate_info
                if cert_info and cert_info.certificate_deployments:
                    dep = cert_info.certificate_deployments[0]
                    leaf = dep.received_certificate_chain[0]
                    import datetime as _dt2
                    expiry = leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") else leaf.not_valid_after
                    now = _dt2.datetime.now(_dt2.timezone.utc)
                    days_left = (expiry.replace(tzinfo=_dt2.timezone.utc) - now).days if expiry.tzinfo is None else (expiry - now).days
                    if days_left < 0:
                        findings.append({
                            "vuln_type": "Expired SSL Certificate",
                            "url": f"https://{host}:{port}",
                            "severity": "Critical",
                            "description": f"SSL certificate expired {abs(days_left)} day(s) ago.",
                            "evidence": {"days_left": days_left, "detection": "sslyze"},
                        })
                    elif days_left < 30:
                        findings.append({
                            "vuln_type": "SSL Certificate Expiring Soon",
                            "url": f"https://{host}:{port}",
                            "severity": "High",
                            "description": f"SSL certificate expires in {days_left} day(s).",
                            "evidence": {"days_left": days_left, "detection": "sslyze"},
                        })
                    if not dep.leaf_certificate_subject_matches_hostname:
                        findings.append({
                            "vuln_type": "SSL Certificate Hostname Mismatch",
                            "url": f"https://{host}:{port}",
                            "severity": "High",
                            "description": f"Certificate subject does not match hostname '{host}'.",
                            "evidence": {"host": host, "detection": "sslyze"},
                        })
            except Exception:
                pass

            # Weak cipher suites (TLS 1.0 / 1.1 accepted ciphers)
            for suite_result in [getattr(r, "tls_1_0_cipher_suites", None),
                                  getattr(r, "tls_1_1_cipher_suites", None)]:
                try:
                    if suite_result and suite_result.accepted_cipher_suites:
                        proto = "TLS 1.0" if "tls_1_0" in str(suite_result) else "TLS 1.1"
                        names = [c.cipher_suite.name for c in suite_result.accepted_cipher_suites[:5]]
                        findings.append({
                            "vuln_type": f"Deprecated Protocol Accepted — {proto}",
                            "url": f"https://{host}:{port}",
                            "severity": "Medium",
                            "description": f"Server accepts {proto} connections. Accepted ciphers: {names}",
                            "evidence": {"protocol": proto, "ciphers": names, "detection": "sslyze"},
                        })
                except Exception:
                    pass

    except (ConnectionToServerFailed, ServerRejectedTlsHandshake, Exception) as exc:
        _deep_logger.debug("[sslyze] scan failed for %s: %s", host, exc)

    return findings
