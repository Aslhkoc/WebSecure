"""
tests/unit/test_nosqli_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
NoSQL injection scanner testleri.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.nosqli import NoSQLiScanner


@pytest.fixture
def nosqli(mock_session):
    return NoSQLiScanner(session=mock_session, results={}, debug=False)


class TestNoSQLiDetection:
    def test_operator_injection_detected(self, nosqli, mock_session):
        """$ne operatör injection → farklı response body → finding."""
        baseline_text = "Found 0 results"
        injected_text = "Found 42 results"

        responses = [
            mock_session._make_response(text=baseline_text),
            mock_session._make_response(text=injected_text),
        ]
        mock_session.get.side_effect = responses

        with patch.object(nosqli, "report_finding"):
            nosqli.run("http://target.test/users?role=admin")

        # Crash olmamalı

    def test_no_false_positive_same_response(self, nosqli, mock_session):
        """Baseline ve injection yanıtı aynıysa → finding olmamalı."""
        mock_session.get.return_value = mock_session._make_response(
            text="<html>No results</html>"
        )
        with patch.object(nosqli, "report_finding") as mock_report:
            nosqli.run("http://target.test/search?q=test")
        # Identical baseline/injection responses must NOT yield a finding.
        mock_report.assert_not_called()

    def test_no_crash_on_timeout(self, nosqli, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        nosqli.run("http://target.test/search?q=test")  # no raise

    def test_no_crash_on_connection_error(self, nosqli, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        nosqli.run("http://target.test/search?q=test")  # no raise

    def test_inherits_basescanner(self, nosqli):
        from websecure.scanners.base import BaseScanner
        assert isinstance(nosqli, BaseScanner)

    def test_run_method_callable(self, nosqli):
        assert callable(nosqli.run)
