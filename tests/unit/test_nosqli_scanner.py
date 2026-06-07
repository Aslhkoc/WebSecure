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
        """Payload'lı istek baseline'dan anlamlı farklılaşınca (200->500) NoSQLi
        anomalisi RAPORLANMALI.

        REGRESYON: Önceki sürüm report_finding'i patch'leyip HİÇBİR ŞEY assert
        etmiyordu (yorum: 'Crash olmamalı'); detection tamamen bozulsa bile test
        geçiyordu. Artık baseline→anomali deterministik kurgulanıp bulgu doğrulanır.
        """
        import threading
        served_baseline = {"v": False}
        lock = threading.Lock()

        def _resp(url, *a, **kw):
            # _fuzz_url_params'taki İLK GET fetch_baseline'dir (payload'sız);
            # sonraki tüm prob'lar payload'lı → 500 anomali döndür (base 200->500).
            with lock:
                if not served_baseline["v"]:
                    served_baseline["v"] = True
                    return mock_session._make_response(text="Found 0 results", status_code=200)
            return mock_session._make_response(text="MongoError: $ne", status_code=500)

        mock_session.get.side_effect = _resp

        with patch.object(nosqli, "report_finding") as mock_report:
            # 'list' yolu _fuzz_json_body tetiklemez (api/user/... anahtarı yok),
            # böylece test yalnız URL-param anomali yolunu ölçer.
            nosqli.run("http://target.test/list?role=admin")

        assert mock_report.called, "NoSQLi anomalisi tespit edilemedi (detection kopuk)"
        vtypes = [str(c.kwargs.get("vuln_type", "")) for c in mock_report.call_args_list]
        assert any("NoSQL" in t for t in vtypes), f"NoSQL bulgusu beklenildi, gelen: {vtypes}"

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
