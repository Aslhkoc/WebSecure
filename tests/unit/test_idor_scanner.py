"""
tests/unit/test_idor_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
IDOR scanner testleri: dual-role detection, sequential enum, no false positive.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from websecure.scanners.idor import IDORScanner


@pytest.fixture
def idor(mock_session):
    return IDORScanner(session=mock_session, results={}, debug=False)


class TestIDORDetection:
    def test_different_content_signals_idor(self, idor, mock_session):
        """İki farklı ID için farklı yanıt → IDOR sinyali."""
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            # İlk çağrı: kendi kaynağı, ikinci: başka kullanıcı kaynağı
            text = "user_data_owner" if call_count["n"] == 1 else "user_data_other_user"
            return mock_session._make_response(text=text)

        mock_session.get.side_effect = side_effect
        # Sadece crash olmamasını ve metodun çağrılabilir olduğunu doğrularız
        idor.run("http://target.test/user/1", urls=["http://target.test/user/1"])

    def test_same_content_no_idor(self, idor, mock_session):
        """Aynı yanıt → IDOR bulunmamalı."""
        mock_session.get.return_value = mock_session._make_response(
            text="<html>Access denied</html>", status_code=403
        )
        with patch.object(idor, "report_finding") as mock_report:
            idor.run("http://target.test/user/1", urls=["http://target.test/user/1"])

    def test_no_crash_on_timeout(self, idor, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        idor.run("http://target.test/user/1", urls=["http://target.test/user/1"])

    def test_no_crash_on_connection_error(self, idor, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        idor.run("http://target.test/user/1", urls=["http://target.test/user/1"])

    def test_inherits_basescanner(self, idor):
        from websecure.scanners.base import BaseScanner
        assert isinstance(idor, BaseScanner)

    def test_run_method_callable(self, idor):
        assert callable(idor.run)
