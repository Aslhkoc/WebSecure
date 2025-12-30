from __future__ import annotations
import concurrent.futures as _fut
import time
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, urlsplit

from .base import BaseScanner
from websecure.core.reporting import add_result
from websecure.core.utils import random_string, ttl_cache_get, ttl_cache_set

# =============================================================================
#  Configurations
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
#  Helpers & Constants
# =============================================================================

COMMON_URL_PARAMS = [
    "url", "redirect", "next", "dest", "destination", "callback", "u", "return", "return_to",
    "continue", "target", "endpoint", "webhook", "feed", "link", "out", "source", "file", "path",
    "image", "img", "avatar", "download"
]

BODY_URL_KEYS = [
    "url", "webhook", "avatar", "image", "callback", "target", "endpoint", "feed", "source", "file", "path"
]

METADATA_BASES = ["http://169.254.169.254", "http://100.100.100.200"]
AWS_PATHS = [
    "/latest/meta-data/", "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/iam/security-credentials/role-name"
]
GCP_PATHS = ["/computeMetadata/v1/instance/service-accounts/default/token"]
AZURE_PATHS = ["/metadata/instance?api-version=2021-02-01"]

XXE_POC = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [ <!ENTITY ext SYSTEM "{U}"> ]>
<root><v>&ext;</v></root>"""

ERROR_FINGERPRINTS = [
    "connection refused", "timed out", "no route to host", "invalid host",
    "host is unreachable", "could not resolve", "failed to connect"
]

def _encode_ip_variants(ip: str) -> List[str]:
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
        return [
            ip,
            ".".join(f"{p:03o}" for p in (a, b, c, d)), # Octal
            ".".join(f"{p:02x}" for p in (a, b, c, d)), # Hex
            str(a * (256 ** 3) + b * (256 ** 2) + c * 256 + d), # Decimal
            "0x" + "".join(f"{p:02x}" for p in (a, b, c, d)) # Hex single
        ]
    except ValueError:
        return [ip]

def _metadata_urls() -> List[str]:
    urls = []
    for base in METADATA_BASES:
        try:
            ip = base.split("://", 1)[1]
            for enc in _encode_ip_variants(ip):
                host = f"http://{enc}"
                for p in AWS_PATHS + GCP_PATHS + AZURE_PATHS:
                    urls.append(host + p)
        except IndexError: 
            pass
    return list(dict.fromkeys(urls))

def _local_scheme_payloads(enable_local=True, enable_dict=False, enable_tftp=True) -> List[str]:
    if not enable_local: return []
    p = ["file:///etc/hosts", "file:///proc/self/environ"]
    if enable_dict: p.append("dict://127.0.0.1:2628/")
    if enable_tftp: p.append("tftp://127.0.0.1:69/boot")
    return p

def _inject_q(url: str, key: str, val: str) -> str:
    u = urlparse(url)
    qs = dict(parse_qsl(u.query, keep_blank_values=True))
    qs[key] = val
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(qs, doseq=True), u.fragment))

def _existing_query_keys(url: str) -> List[str]:
    if not url: return []
    u = urlsplit(url)
    if not u.query: return []
    return sorted({k for k, _ in parse_qsl(u.query, keep_blank_values=True)})

# =============================================================================
#  OAST Client (Simplified)
# =============================================================================

class OASTClient:
    def __init__(self, provider="generic", dns_domain=None):
        self.provider = provider
        self.dns_domain = (dns_domain or "").strip(".")

    def make_token(self, prefix="ws") -> str:
        return f"{prefix}{random_string(14)}"

    def token_dns(self, token: str) -> str:
        return f"{token}.{self.dns_domain}" if self.dns_domain else token

    def poll(self, tokens: List[str], timeout: int = 10) -> List[Dict]:
        return [] # Dummy implementation

# =============================================================================
#  Main Scanner Class
# =============================================================================

class SSRFXXEScanner(BaseScanner):
    name = "ssrf_xxe"

    def __init__(
        self,
        session,
        endpoints: List[str],
        cfg: Optional[SSRFXXEConfig] = None,
        debug: bool = False,
        auth_ctx: Optional[Dict] = None,
        oast_client: Optional[OASTClient] = None,
    ):
        super().__init__(session=session, debug=debug)
        self.endpoints = [e for e in (endpoints or []) if isinstance(e, str)]
        self.cfg = cfg or SSRFXXEConfig()
        self.auth_ctx = auth_ctx or {}
        self.oast_client = oast_client or OASTClient(
            self.cfg.oast.provider, self.cfg.oast.dns_domain
        )
        self.seen_keys = set()
        
        # Init results structure
        self.results["target_endpoints"] = self.endpoints

        # Set UA
        if self.cfg.tuning.user_agent:
            self.session.headers.update({"User-Agent": self.cfg.tuning.user_agent})

    def _record_safe(self, entry: Dict[str, Any], unique_key: Tuple) -> None:
        if unique_key in self.seen_keys:
            return
        self.seen_keys.add(unique_key)
        
        # Standardize for BaseScanner
        status_msg = "Error" if entry.get("error") else "OK"
        if entry.get("suspect"): status_msg = f"Suspect ({entry['suspect']})"
        
        entry.setdefault("status", status_msg)
        entry.setdefault("severity", "High" if entry.get("suspect") else "Info")
        
        self.add("ssrf_xxe", entry)

    def _request(self, method, url, **kwargs):
        """Resilient request wrapper."""
        retries = self.cfg.tuning.retries
        for _ in range(max(1, retries + 1)):
            try:
                return self.session.request(method, url, **kwargs)
            except Exception:
                pass
        return None

    def run(self) -> Dict[str, Any]:
        bucket = self.results.setdefault("ssrf_xxe", []) # BaseScanner will append here via add()
        suspect_count = 0
        
        o = self.cfg.oast
        t = self.cfg.tuning
        oast_enabled = bool(o.enabled and self.oast_client.dns_domain)
        token = self.oast_client.make_token(o.token_prefix)
        dns_host = self.oast_client.token_dns(token)
        
        cbs = {
            "http": f"http://{dns_host}/hit?t={token}",
            "https": f"https://{dns_host}/hit?t={token}",
            "dns": f"http://{dns_host}"
        }
        
        # Report OAST usage
        add_result("oast", {
            "module": self.name,
            "token": token,
            "dns": dns_host
        })
        
        TO = int(o.timeout)
        hdrs = o.base_headers.copy()
        cookies = o.base_cookies.copy()

        # Precompute payloads
        candidates = [
            (cbs["http"], "oast-http"),
            (cbs["https"], "oast-https"),
            (cbs["dns"], "oast-dns")
        ]
        if o.enable_metadata_probes:
            candidates.extend((m, "meta-ip") for m in _metadata_urls())
        candidates.extend((lp, "local-scheme") for lp in _local_scheme_payloads(
            o.enable_local_schemes, o.enable_dict_scheme, o.enable_tftp_scheme
        ))

        def process_query_injection(url, param, payload, tag):
            nonlocal suspect_count
            target = _inject_q(url, param, payload)
            t0 = time.time()
            resp = self._request("GET", target, timeout=TO, allow_redirects=t.respect_redirects, headers=hdrs, cookies=cookies)
            duration = time.time() - t0
            
            error = None if resp else "Connection Failed"
            status_code = resp.status_code if resp else None
            
            # Simple heuristics
            suspect = None
            if duration > o.timing_threshold:
                suspect = "timing"
            elif error and any(sig in str(error).lower() for sig in ERROR_FINGERPRINTS):
                suspect = "error-fingerprint"
                
            entry = {
                "endpoint": url,
                "param": param,
                "payload": payload,
                "tag": tag,
                "code": status_code,
                "elapsed": duration,
                "suspect": suspect,
                "error": error
            }
            if suspect: suspect_count += 1
            self._record_safe(entry, (url, param, "GET", tag))

        # Execution Loop
        if self.endpoints:
            with _fut.ThreadPoolExecutor(max_workers=t.concurrency) as ex:
                for url in self.endpoints:
                    keys = list(dict.fromkeys(_existing_query_keys(url) + COMMON_URL_PARAMS))[:30]
                    for param in keys:
                        for payload, tag in candidates:
                            ex.submit(process_query_injection, url, param, payload, tag)
                            
        # OAST Verification
        if oast_enabled:
            events = self.oast_client.poll([token])
            if events:
                self.results["ssrf_xxe_oast_events"] = events
                # Cross-reference
                for entry in self.results.get("ssrf_xxe", []):
                    # Basic correlation logic could go here
                    entry["confirmed"] = True

        self.set_summary("ssrf_xxe", suspect_count)
        return self.results
 
# Aliases for compatibility
SSRFScanner = SSRFXXEScanner
XXEScanner = SSRFXXEScanner

