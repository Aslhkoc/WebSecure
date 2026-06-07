"""
tests/unit/test_owasp.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
OWASP yüzey kontrolleri scanner birim testleri.

owasp.run() fonksiyon-tabanlı bir orkestratördür; birden çok hafif check_*
çağırır ve sonuç dict'i döndürür. Ağ hatasında çökmemeli, dict döndürmeli.
"""
from __future__ import annotations

import requests

from websecure.scanners import owasp

_TARGET = "http://target.test/"


class TestOwaspRobustness:
    def test_run_returns_dict_when_unreachable(self, mock_session):
        """Tüm istekler ağ hatası verse de run() çökmemeli ve dict döndürmeli."""
        err = requests.exceptions.ConnectionError("refused")
        for m in (mock_session.get, mock_session.post, mock_session.head):
            m.side_effect = err
        out = owasp.run(_TARGET, session=mock_session, debug=False)
        assert isinstance(out, dict)
        assert out.get("target") == _TARGET

    def test_run_callable(self):
        assert callable(owasp.run)
