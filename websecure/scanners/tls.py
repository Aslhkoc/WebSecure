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
    base_info = _get_cert_details(url, config=kwargs.get("config"), session=kwargs.get("session"))
    
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

# Plugin registry compat alias
run = scan_tls

# ============================================================================
# ADIM 9 — TLS Gelismis Siniflar
# TLSBEASTPoodleProber, TLSCRIMEBREACHProber, TLSROBOTProber,
# HTTP2HTTP3Checker, CDNMisconfigProber, TLSAdim9Scanner
# ============================================================================
from __future__ import annotations
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
                            "Cache deception: attacker tricks victim to visit URL → "
                            "CDN caches their private page → attacker retrieves it."
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
