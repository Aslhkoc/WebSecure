from __future__ import annotations
import hashlib
import time as _t
import json
import re
import contextlib
import logging
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Protocol, Tuple, Set

from .base import BaseScanner

logger = logging.getLogger(__name__)

# --- Constants ---
DEFAULT_HEADERS = {"Content-Type": "application/json"}
INTROSPECTION_MIN = {
    "query": (
        "query IntrospectionQuery { "
        "__schema { "
        "  queryType { name fields { name } } "
        "  mutationType { name fields { name } } "
        "  subscriptionType { name fields { name } } "
        "} }"
    )
}
INTROSPECTION_PING = {"query": "query { __schema { queryType { name } } }"}
FUZZ_QUERIES = [
    {"query": "query Q($n:Int!){ user(id:$n){ id name }}", "variables": {"n": 2147483647}},
    {"query": "query Q{ __typename }"},
    {"query": "mutation M($x:ID!){ updateUser(id:$x, name:\"A\"){ id }}", "variables": {"x": "not-an-id"}},
    {"query": "query Q{ nonExistingField }"},
]
COMMON_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graph", "/gql", "/api/gql", "/v1/graphql", "/v2/graphql"]

# --- Client ---
class GraphQLClient:
    def __init__(self, session, timeout: int = 20):
        self.session = session
        self.timeout = int(timeout)

    def _maybe_json(self, text: str, headers: Dict[str, Any]) -> Dict[str, Any]:
        ct = (headers.get("Content-Type") or "").lower()
        s = (text or "").lstrip()
        if "json" in ct or s.startswith("{") or s.startswith("["):
            try:
                return json.loads(text)
            except:
                pass
        return {}

    def post(self, url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, Any], str, float]:
        t0 = _t.time()
        try:
            r = self.session.post(
                url, json=payload, headers={**DEFAULT_HEADERS, **(headers or {})},
                timeout=self.timeout, allow_redirects=True
            )
            dt = _t.time() - t0
            return r.status_code, self._maybe_json(r.text, r.headers), r.text, dt
        except Exception:
            return 0, {}, "", 0.0

    def get(self, url: str, query: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, Any], str, float]:
        t0 = _t.time()
        try:
            r = self.session.get(
                url, params={"query": query}, headers={"Accept": "application/json", **(headers or {})},
                timeout=self.timeout, allow_redirects=True
            )
            dt = _t.time() - t0
            return r.status_code, self._maybe_json(r.text, r.headers), r.text, dt
        except Exception:
            return 0, {}, "", 0.0

@dataclass
class Finding:
    endpoint: str
    issue: str
    severity: str = "Medium"
    payload: Optional[Dict[str, Any]] = None
    code: Optional[int] = None
    latency: Optional[float] = None
    body_hint: Optional[str] = None

class GraphQLProbe(Protocol):
    def run(self, client: GraphQLClient, url: str) -> List[Finding]: ...

# --- Probes ---
class IntrospectionProbe:
    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        code, j, _, dt = client.post(url, INTROSPECTION_PING)
        if code == 200 and j.get("data", {}).get("__schema"):
            return [Finding(url, "Introspection Enabled", "Medium", INTROSPECTION_PING, code, dt)]
        # Check GET
        g_code, g_j, _, g_dt = client.get(url, INTROSPECTION_PING["query"])
        if g_code == 200 and g_j.get("data", {}).get("__schema"):
            return [Finding(url, "Introspection Enabled (GET)", "Medium", {"method": "GET"}, g_code, g_dt)]
        return []

class WeakValidationProbe:
    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        out = []
        for q in FUZZ_QUERIES:
            code, j, txt, dt = client.post(url, q)
            no_errors = "errors" not in (j or {})
            nonsensical_ok = bool(j.get("data")) and "nonExistingField" in q["query"]
            if code == 200 and (no_errors or nonsensical_ok):
                out.append(Finding(url, "Weak Validation", "Medium", q, code, dt))
        return out

class BatchProbe:
    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        arr_payload = [{"query": "query A { __typename }"}, {"query": "query B { __typename }"}]
        t0 = _t.time()
        try:
            r = client.session.post(url, json=arr_payload, headers=DEFAULT_HEADERS, timeout=client.timeout)
            dt = _t.time() - t0
            if r.status_code == 200 and (r.text or "").strip().startswith("["):
                return [Finding(url, "Batch Queries Supported", "Medium", {"len": len(arr_payload)}, r.status_code, dt)]
        except:
            pass
        return []

class AliasProbe:
    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        aliases = " ".join([f"a{i}:__typename" for i in range(50)])
        q = {"query": f"query A {{ {aliases} }}"}
        code, j, _, dt = client.post(url, q)
        if code == 200 and "errors" not in (j or {}) and dt > 1.0:
            return [Finding(url, "Excessive Alias processing (DoS risk)", "Medium", q, code, dt)]
        return []

# --- Main Scanner Class ---
class GraphQLScanner(BaseScanner):
    name = "graphql"

    def run(self, url: str) -> Dict[str, Any]:
        """
        Scans a single endpoint or discovers endpoints if url is a base URL.
        Note: The BaseScanner interface expects 'url' to be the target.
        """
        endpoints = self._discover_endpoints(url)
        if not endpoints:
            endpoints = [url] # Assume inputs are endpoints if discovery fails or if url looks like one

        bucket = self.name
        self.results[bucket] = []
        
        client = GraphQLClient(self.session)
        vulns = 0

        for ep in endpoints:
            probes = [IntrospectionProbe(), WeakValidationProbe(), BatchProbe(), AliasProbe()]
            for p in probes:
                for f in p.run(client, ep):
                    self.add(bucket, {
                        "endpoint": f.endpoint,
                        "issue": f.issue,
                        "severity": f.severity,
                        "details": f.body_hint or f.issue
                    })
                    vulns += 1
        
        self.set_summary(bucket, vulns)
        return self.results

    def _discover_endpoints(self, base: str) -> List[str]:
        found = []
        if "graphql" in base:
            return [base]
        
        for p in COMMON_GRAPHQL_PATHS:
            target = base.rstrip("/") + p
            try:
                r = self.session.get(target, params={"query": "{__typename}"}, timeout=5)
                if r.status_code == 200 and "data" in r.text:
                    found.append(target)
            except:
                pass
        return found
