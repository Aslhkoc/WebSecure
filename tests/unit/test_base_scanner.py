"""
tests/unit/test_base_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
BaseScanner: inject_param, run_parallel_probes, fetch_baseline, report_finding, thread-safety.
"""
from __future__ import annotations

import threading
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import requests

from websecure.scanners.base import BaseScanner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner(mock_session):
    return BaseScanner(session=mock_session, results={}, debug=False)


# ---------------------------------------------------------------------------
# inject_param
# ---------------------------------------------------------------------------

class TestInjectParam:
    def test_replaces_existing_param(self, scanner):
        url = "http://target.test/search?q=hello&page=1"
        result = scanner.inject_param(url, "q", "PAYLOAD")
        assert "q=PAYLOAD" in result
        assert "page=1" in result

    def test_adds_new_param(self, scanner):
        url = "http://target.test/search"
        result = scanner.inject_param(url, "id", "42")
        assert "id=42" in result
        assert result.startswith("http://target.test/search")

    def test_preserves_scheme_and_host(self, scanner):
        url = "https://example.com/path?a=1"
        result = scanner.inject_param(url, "a", "X")
        assert result.startswith("https://example.com/path")

    def test_special_chars_encoded(self, scanner):
        url = "http://target.test/?q=normal"
        result = scanner.inject_param(url, "q", "<script>")
        assert "<script>" not in result or "%3C" in result or "q=%3Cscript%3E" in result


# ---------------------------------------------------------------------------
# run_parallel_probes
# ---------------------------------------------------------------------------

class TestRunParallelProbes:
    def test_returns_hits(self, scanner):
        def probe(p):
            return {"found": p} if p == "HIT" else None

        results = scanner.run_parallel_probes(probe, ["MISS", "HIT", "MISS"])
        assert len(results) == 1
        assert results[0]["found"] == "HIT"

    def test_stop_on_first_true(self, scanner):
        call_count = {"n": 0}

        def probe(p):
            call_count["n"] += 1
            return {"p": p} if p == "HIT" else None

        results = scanner.run_parallel_probes(
            probe, ["HIT", "ALSO_HIT", "ALSO_HIT2"], stop_on_first=True
        )
        assert len(results) >= 1

    def test_stop_on_first_false_collects_all(self, scanner):
        def probe(p):
            return {"p": p} if p.startswith("HIT") else None

        results = scanner.run_parallel_probes(
            probe, ["HIT1", "HIT2", "MISS"], stop_on_first=False
        )
        assert len(results) == 2

    def test_empty_payloads_returns_empty(self, scanner):
        def probe(p):
            return p
        results = scanner.run_parallel_probes(probe, [])
        assert results == []

    def test_probe_exception_logged_not_raised(self, scanner):
        def probe(p):
            raise requests.exceptions.ConnectionError("refused")

        # Should not raise — exception is swallowed after logging
        results = scanner.run_parallel_probes(probe, ["a", "b"])
        assert results == []


# ---------------------------------------------------------------------------
# fetch_baseline
# ---------------------------------------------------------------------------

class TestFetchBaseline:
    def test_returns_response_on_success(self, scanner, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "hello"
        mock_session.get.return_value = mock_resp

        resp = scanner.fetch_baseline("http://target.test/")
        assert resp is mock_resp

    def test_returns_none_on_timeout(self, scanner, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        resp = scanner.fetch_baseline("http://target.test/")
        assert resp is None

    def test_returns_none_on_connection_error(self, scanner, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        resp = scanner.fetch_baseline("http://target.test/")
        assert resp is None

    def test_post_method(self, scanner, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_session.post.return_value = mock_resp

        resp = scanner.fetch_baseline("http://target.test/api", method="POST", data={"k": "v"})
        assert resp is mock_resp
        mock_session.post.assert_called_once()


# ---------------------------------------------------------------------------
# report_finding
# ---------------------------------------------------------------------------

class TestReportFinding:
    def test_adds_to_offensive_bucket(self, scanner):
        with patch.object(scanner, "add") as mock_add:
            scanner.report_finding(
                vuln_type="XSS",
                url="http://target.test/?q=x",
                param="q",
                payload="<s>",
                severity="High",
                evidence="reflected",
            )
            mock_add.assert_called_once()
            bucket, entry = mock_add.call_args[0]
            assert bucket == "offensive"
            assert entry["type"] == "XSS"
            assert entry["severity"] == "High"

    def test_extra_dict_merged(self, scanner):
        with patch.object(scanner, "add") as mock_add:
            scanner.report_finding(
                vuln_type="SQLi",
                url="http://t.test/",
                severity="Critical",
                extra={"cwe": "CWE-89", "engine": "MySQL"},
            )
            _, entry = mock_add.call_args[0]
            assert entry.get("cwe") == "CWE-89"
            assert entry.get("engine") == "MySQL"

    def test_no_extra_ok(self, scanner):
        with patch.object(scanner, "add") as mock_add:
            scanner.report_finding(vuln_type="IDOR", url="http://t.test/", severity="Medium")
            mock_add.assert_called_once()


# ---------------------------------------------------------------------------
# Thread safety — concurrent add()
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_add_no_data_loss(self, scanner):
        """100 thread simultaneously adding to same bucket → no entry lost."""
        num_threads = 100
        barrier = threading.Barrier(num_threads)

        def worker(i):
            barrier.wait()
            scanner.add("xss", {"type": "XSS", "url": f"http://t.test/{i}", "severity": "High"})

        with patch("websecure.scanners.base.add_result"):
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert len(scanner.results.get("xss", [])) == num_threads
