"""
tests/conftest.py
~~~~~~~~~~~~~~~~~
Paylaşımlı pytest fixture'ları.
"""
from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
import requests


# ---------------------------------------------------------------------------
# Mock HTTP session
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_session():
    """Gerçek HTTP isteği yapmayan mock requests.Session."""
    session = MagicMock(spec=requests.Session)

    def _make_response(
        status_code: int = 200,
        text: str = "",
        headers: Dict[str, str] = None,
    ) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.content = text.encode("utf-8")
        resp.headers = headers or {}
        resp.url = "http://mock.test/"
        resp.elapsed = MagicMock()
        resp.elapsed.total_seconds.return_value = 0.1
        return resp

    session._make_response = _make_response
    session.get.return_value = _make_response()
    session.post.return_value = _make_response()
    session.put.return_value = _make_response()
    session.delete.return_value = _make_response()
    session.head.return_value = _make_response()
    session.request.return_value = _make_response()
    return session


# ---------------------------------------------------------------------------
# BaseScanner fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def base_scanner(mock_session):
    """Temel BaseScanner örneği, gerçek session olmadan."""
    from websecure.scanners.base import BaseScanner
    scanner = BaseScanner(session=mock_session, results={}, debug=False)
    return scanner


# ---------------------------------------------------------------------------
# Sample finding dict
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_finding() -> Dict[str, Any]:
    """Geçerli bir bulgu dict'i."""
    return {
        "type": "XSS",
        "url": "http://target.test/search?q=test",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "severity": "High",
        "evidence": "Payload reflected in response",
    }


# ---------------------------------------------------------------------------
# Target URL helper
# ---------------------------------------------------------------------------

TARGET_URL = "http://target.test"
VULN_URL = "http://target.test/search?q=hello"
