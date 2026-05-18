"""
websecure.scanners.idor
------------------------
Insecure Direct Object Reference (IDOR) scanner.
Dual-role comparison (high confidence) + sequential enumeration (medium confidence).
"""
from __future__ import annotations

import hashlib as _hashlib
import logging
import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import requests as _requests

from websecure.scanners.base import BaseScanner

_logger = logging.getLogger(__name__)

# Patterns indicating sensitive data in response
_SENSITIVE_PATTERNS: Dict[str, str] = {
    "email":       r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "password":    r'"password"\s*:\s*"[^"]{4,}"',
    "ssn":         r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "phone":       r"\b[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}\b",
    "address":     r'"(?:address|street|city|zipcode)"\s*:\s*"[^"]{5,}"',
    "token":       r'"(?:token|secret|api_key|access_token)"\s*:\s*"[^"]{8,}"',
    "api_key":     r'[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s*[=:]\s*["\']?[A-Za-z0-9\-_]{16,}',
}


def _body_hash(text: str) -> str:
    """Boşlukları normalize ederek SHA-256 üretir — aynı içerik farklı whitespace ile eşleşir."""
    normalized = " ".join(text.split())
    return _hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _contains_sensitive(body: str) -> Optional[str]:
    for name, pattern in _SENSITIVE_PATTERNS.items():
        if re.search(pattern, body, re.I):
            return name
    return None


class IDORScanner(BaseScanner):
    """
    IDOR scanner with two detection modes:
    1. Dual-role: Compare response with session A vs session B for same resource ID
    2. Sequential: Enumerate adjacent IDs from discovered endpoints, look for data leakage
    """

    name = "idor"
    phase = "offensive"

    def __init__(self, session=None, results: Dict = None, debug: bool = False,
                 timeout: int = 10, session_b=None):
        super().__init__(session, results, debug)
        self.timeout = timeout
        self.session_b = session_b  # Second session for dual-role testing

    def run(self, target: str, **kwargs):
        endpoints = kwargs.get("endpoints") or [target]
        sessions = kwargs.get("role_sessions") or {}

        # Hard cap — prevent excessive runtime on large endpoint lists
        endpoints = endpoints[:15]

        if not self.session_b and sessions:
            sessions_list = list(sessions.values())
            if len(sessions_list) >= 2:
                self.session_b = sessions_list[1]

        for url in endpoints:
            if self.session_b:
                self._dual_role_test(url)
            self._sequential_enum(url)

    def _dual_role_test(self, url: str):
        """
        Compare responses: session A vs session B for same URL.
        If A sees more data -> IDOR.
        """
        body_a = self._fetch(url, self.session)
        body_b = self._fetch(url, self.session_b)

        if not body_a or not body_b:
            return

        sim = _similarity(body_a, body_b)

        if sim > 0.70 and body_a != body_b:
            sensitive = _contains_sensitive(body_b)
            # Only report if body_a also has sensitive data — confirms this is a protected
            # resource that Session B should not be able to access (prevents false positives
            # where both sessions legitimately see the same public data)
            if sensitive and _contains_sensitive(body_a):
                self.report_finding(
                    vuln_type="IDOR",
                    url=url,
                    param="",
                    payload="",
                    severity="High",
                    evidence=(
                        f"Session B sees sensitive data ({sensitive}) with "
                        f"{sim:.0%} response similarity to Session A"
                    ),
                    extra={"confidence": "high", "verified": True, "similarity_score": round(sim, 3)},
                )

    def _sequential_enum(self, url: str):
        """
        Extract numeric IDs from URL params/path, test adjacent IDs.
        Report if sensitive data leaks through other IDs.
        Pre-fetches the original body ONCE and reuses it across all loops.
        Parallelises test-ID fetches via ThreadPoolExecutor.
        """
        import concurrent.futures as _cf

        parsed = urlparse(url)
        params = parse_qsl(parsed.query)

        # Pre-fetch ONCE — reused across all param and path loops below
        original_body = self._fetch(url, self.session) or ""
        orig_hash = _body_hash(original_body)

        # --- Query parameter IDs ---
        for param_name, param_value in params:
            if not re.match(r"^\d+$", param_value):
                continue
            base_id = int(param_value)
            valid_test_ids = [
                tid for tid in set([base_id - 2, base_id - 1, base_id + 1, base_id + 2])
                if tid > 0
            ]

            def _check_param_id(
                test_id: int,
                _pname: str = param_name,
                _params: list = params,
                _orig: str = original_body,
                _orig_hash: str = orig_hash,
                _parsed=parsed,
                _base: int = base_id,
            ) -> None:
                new_params = dict(_params)
                new_params[_pname] = str(test_id)
                test_url = urlunparse(_parsed._replace(query=urlencode(new_params)))
                body = self._fetch(test_url, self.session)
                if not body:
                    return
                if _body_hash(body) == _orig_hash:
                    return
                sim = _similarity(_orig, body)
                if sim >= 0.90:
                    return
                sensitive = _contains_sensitive(body)
                if sensitive:
                    self.report_finding(
                        vuln_type="IDOR",
                        url=test_url,
                        param=_pname,
                        payload=str(test_id),
                        severity="Medium",
                        evidence=f"Sıralı numaralandırma {sensitive} içeren yanıt ortaya çıkardı",
                        extra={
                            "confidence": "medium",
                            "original_id": _base,
                            "tested_id": test_id,
                            "similarity_score": round(sim, 3),
                        },
                    )

            with _cf.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(_check_param_id, valid_test_ids))

        # --- Path-based IDs: /api/user/123 -> /api/user/124 ---
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            if not re.match(r"^\d+$", part):
                continue
            base_id = int(part)
            for test_id in [base_id - 1, base_id + 1]:
                if test_id <= 0:
                    continue
                new_parts = path_parts[:]
                new_parts[i] = str(test_id)
                test_url = urlunparse(parsed._replace(path="/".join(new_parts)))
                body = self._fetch(test_url, self.session)
                if not body:
                    continue
                if _body_hash(body) == orig_hash:
                    continue
                sim_score = _similarity(original_body, body)
                if sim_score >= 0.90:
                    continue
                sensitive = _contains_sensitive(body)
                if sensitive:
                    self.report_finding(
                        vuln_type="IDOR",
                        url=test_url,
                        param=f"path[{i}]",
                        payload=str(test_id),
                        severity="Medium",
                        evidence=f"Path tabanlı IDOR {sensitive} içeren yanıt ortaya çıkardı",
                        extra={
                            "confidence": "medium",
                            "original_id": base_id,
                            "tested_id": test_id,
                            "similarity_score": round(sim_score, 3),
                        },
                    )

    def _fetch(self, url: str, session) -> Optional[str]:
        try:
            if session:
                resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                resp = _requests.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code < 400:
                return resp.text
        except _requests.exceptions.Timeout as exc:
            _logger.warning(f"[IDOR] Fetch timed out for {url}: {exc!r}")
        except _requests.exceptions.ConnectionError as exc:
            _logger.warning(f"[IDOR] Fetch connection error for {url}: {exc!r}")
        except _requests.exceptions.RequestException as exc:
            _logger.error(f"[IDOR] Fetch failed for {url}: {exc!r}")
        return None


def run(target: str, session=None, results=None, debug=False, **kwargs):
    scanner = IDORScanner(session=session, results=results, debug=debug)
    scanner.run(target, **kwargs)
