"""
tests/integration/test_severity_pipeline.py
--------------------------------------------
Real integration tests — no mocks for the core data pipeline.
Tests verify that severity values flow correctly from scanner → add_result → CI gate.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

class TestSeverityNormalization:
    """_norm_sev_tr must return canonical English regardless of input language."""

    def setup_method(self):
        from websecure.core.reporting import _norm_sev_tr
        self.norm = _norm_sev_tr

    @pytest.mark.parametrize("raw,expected", [
        # English inputs
        ("Critical", "Critical"),
        ("critical", "Critical"),
        ("CRITICAL", "Critical"),
        ("crit", "Critical"),
        ("severe", "Critical"),
        ("High", "High"),
        ("high", "High"),
        ("Medium", "Medium"),
        ("medium", "Medium"),
        ("med", "Medium"),
        ("Low", "Low"),
        ("low", "Low"),
        ("Info", "Info"),
        ("info", "Info"),
        # Turkish inputs
        ("Kritik", "Critical"),
        ("kritik", "Critical"),
        ("Yüksek", "High"),
        ("yüksek", "High"),
        ("yuksek", "High"),
        ("Orta", "Medium"),
        ("orta", "Medium"),
        ("Düşük", "Low"),
        ("düşük", "Low"),
        ("Bilgi", "Info"),
        ("bilgi", "Info"),
        # Edge cases
        (None, "Info"),
        ("", "Info"),
        ("garbage", "Info"),
    ])
    def test_norm_accepts_tr_and_en(self, raw, expected):
        assert self.norm(raw) == expected


class TestRankOrderSort:
    """Items must be sorted Critical > High > Medium > Low > Info."""

    def test_sorting_with_mixed_language_severity(self):
        from websecure.core.reporting import _norm_sev_tr, _sev_rank

        items = [
            {"severity": "Low", "type": "A"},
            {"severity": "Kritik", "type": "B"},
            {"severity": "medium", "type": "C"},
            {"severity": "High", "type": "D"},
            {"severity": "Bilgi", "type": "E"},
        ]

        sorted_items = sorted(items, key=lambda i: -_sev_rank(i.get("severity")))
        types = [i["type"] for i in sorted_items]

        # B(Critical) > D(High) > C(Medium) > A(Low) > E(Info)
        assert types == ["B", "D", "C", "A", "E"]


# ---------------------------------------------------------------------------
# add_result severity normalization
# ---------------------------------------------------------------------------

class TestAddResultNormalizesSeverity:
    """add_result must store canonical English severity regardless of scanner input."""

    @pytest.mark.parametrize("raw_sev,canonical", [
        ("High",     "High"),
        ("high",     "High"),
        ("Yüksek",   "High"),
        ("CRITICAL", "Critical"),
        ("Kritik",   "Critical"),
        ("orta",     "Medium"),
        ("LOW",      "Low"),
        ("Düşük",    "Low"),
        ("Info",     "Info"),
        ("Bilgi",    "Info"),
    ])
    def test_canonical_english_stored(self, raw_sev, canonical):
        """add_result normalizes severity; verify via _norm_sev_tr (same logic)."""
        from websecure.core.reporting import add_result, get_bucket_results

        # Unique bucket per parametrize call avoids cross-test pollution
        safe_name = raw_sev.encode("ascii", "ignore").decode().lower()
        unique_bucket = f"_sev_norm_test_{safe_name}_{id(raw_sev)}"
        add_result(unique_bucket, {"type": "TEST", "severity": raw_sev, "url": "http://x"})

        all_buckets = get_bucket_results()
        stored = all_buckets.get(unique_bucket, [])
        assert stored, f"Nothing stored for severity input '{raw_sev}'"
        got = stored[-1].get("severity")
        assert got == canonical, (
            f"add_result stored '{got}' for input '{raw_sev}', expected '{canonical}'"
        )


# ---------------------------------------------------------------------------
# CI gate correctness
# ---------------------------------------------------------------------------

class TestCIGate:
    """CI gate must trip correctly for both English and Turkish severity values.

    should_fail_ci(cfg, results) signature:
      cfg     = {"ci": {"fail_on": ["high", ...]}}
      results = {"findings": {"bucket": [finding, ...]}}
    """

    def _gate(self, findings: list[dict], fail_on: list[str]) -> bool:
        from websecure.core.reporting import should_fail_ci
        cfg = {"ci": {"fail_on": fail_on}}
        results = {"findings": {"offensive": findings}}
        return should_fail_ci(cfg, results)

    def test_english_high_trips_gate(self):
        findings = [{"severity": "High", "type": "XSS", "url": "http://x"}]
        assert self._gate(findings, ["high"]) is True

    def test_turkish_yuksek_trips_gate(self):
        findings = [{"severity": "Yüksek", "type": "XSS", "url": "http://x"}]
        assert self._gate(findings, ["high"]) is True

    def test_low_does_not_trip_high_gate(self):
        findings = [{"severity": "Low", "type": "INFO", "url": "http://x"}]
        assert self._gate(findings, ["high"]) is False

    def test_any_trips_for_any_finding(self):
        findings = [{"severity": "Info", "type": "HDR", "url": "http://x"}]
        assert self._gate(findings, ["any"]) is True

    def test_empty_findings_no_trip(self):
        assert self._gate([], ["critical"]) is False

    def test_critical_trips_gate(self):
        findings = [{"severity": "Kritik", "type": "SQLI", "url": "http://x"}]
        assert self._gate(findings, ["critical"]) is True

    def test_mixed_severities_trips_on_highest(self):
        findings = [
            {"severity": "Low",     "type": "A", "url": "http://x"},
            {"severity": "Yüksek",  "type": "B", "url": "http://x"},
            {"severity": "Info",    "type": "C", "url": "http://x"},
        ]
        assert self._gate(findings, ["high"]) is True
        assert self._gate(findings, ["critical"]) is False


# ---------------------------------------------------------------------------
# Live HTTP server — BaseScanner against a real server
# ---------------------------------------------------------------------------

import threading
import http.server
import urllib.request
import time


class _XSSServer(http.server.BaseHTTPRequestHandler):
    """Tiny HTTP server that reflects the ?q= parameter back — simulates reflected XSS."""

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        q = (qs.get("q") or ["safe"])[0]
        body = f"<html><body>{q}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # silence server logs during tests


@pytest.fixture(scope="module")
def live_server():
    """Starts a real local HTTP server for integration tests."""
    server = http.server.HTTPServer(("127.0.0.1", 0), _XSSServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestBaseScannerAgainstRealServer:
    """BaseScanner.fetch_baseline() and inject_param() against a live server."""

    def test_fetch_baseline_returns_real_response(self, live_server):
        import requests
        from websecure.scanners.base import BaseScanner

        session = requests.Session()
        scanner = BaseScanner(session=session)
        resp = scanner.fetch_baseline(live_server)

        assert resp is not None
        assert resp.status_code == 200
        assert "safe" in resp.text

    def test_baseline_cache_returns_same_object(self, live_server):
        import requests
        from websecure.scanners.base import BaseScanner

        session = requests.Session()
        scanner = BaseScanner(session=session)
        r1 = scanner.fetch_baseline(live_server)
        r2 = scanner.fetch_baseline(live_server)
        assert r1 is r2, "Cache must return the exact same response object"

    def test_inject_param_reflects_in_server(self, live_server):
        import requests
        from websecure.scanners.base import BaseScanner

        session = requests.Session()
        scanner = BaseScanner(session=session)
        url = live_server + "/?q=hello"
        injected_url = scanner.inject_param(url, "q", "<MARKER>")
        resp = session.get(injected_url)
        assert "<MARKER>" in resp.text

    def test_run_parallel_probes_collects_hits(self, live_server):
        import requests
        from websecure.scanners.base import BaseScanner

        session = requests.Session()
        scanner = BaseScanner(session=session)
        base_url = live_server + "/?q="

        def probe(payload: str):
            url = base_url + payload
            resp = session.get(url, timeout=5)
            if payload in resp.text:
                return {"payload": payload, "reflected": True}
            return None

        hits = scanner.run_parallel_probes(probe, ["<script>", "safe", "xss"], stop_on_first=True)
        assert len(hits) >= 1
        assert hits[0]["reflected"] is True


# ---------------------------------------------------------------------------
# Circuit breaker integration
# ---------------------------------------------------------------------------

class TestCircuitBreakerTripLog:

    def test_trip_is_recorded_on_open(self):
        from websecure.core.circuit_breaker import ScanCircuitBreaker, CBConfig

        cb = ScanCircuitBreaker(CBConfig(max_consecutive_429=2))
        cb.record(429)
        cb.record(429)  # should trip OPEN

        assert cb.is_open
        log = cb.get_trip_log()
        assert len(log) == 1
        assert "reason" in log[0]
        assert "429" in log[0]["reason"]

    def test_reset_clears_state_but_not_trip_log(self):
        from websecure.core.circuit_breaker import ScanCircuitBreaker, CBConfig

        cb = ScanCircuitBreaker(CBConfig(max_consecutive_429=1))
        cb.record(429)
        assert cb.is_open
        cb.reset()
        assert not cb.is_open
        # Trip log is historical — must survive reset
        assert len(cb.get_trip_log()) == 1
