"""
tests/unit/test_jwt.py
~~~~~~~~~~~~~~~~~~~~~~~~
JWT scanner birim testleri.

JWTScanner token keşfini session header/cookie üzerinden yapar (gerçek
requests.Session gerekir; saldırı fazları ağ ister, bunlar entegrasyon kapsamı).
Bu birim testler token keşfi + gating mantığını deterministik korur.
"""
from __future__ import annotations

import base64
import json

import requests

from websecure.scanners.jwt import JWTScanner


def _b64(d) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def _make_jwt(alg: str = "none") -> str:
    return f"{_b64({'alg': alg, 'typ': 'JWT'})}.{_b64({'sub': '1', 'role': 'user'})}.sig"


class TestTokenDiscovery:
    def test_find_tokens_from_bearer_header(self):
        """Authorization: Bearer <jwt> başlığından token keşfedilmeli."""
        tok = _make_jwt()
        s = requests.Session()
        s.headers["Authorization"] = f"Bearer {tok}"
        scanner = JWTScanner(session=s, results={})
        assert tok in scanner._find_tokens()

    def test_no_tokens_when_absent(self):
        """Hiç token yoksa keşif boş dönmeli (ve run 0)."""
        s = requests.Session()
        scanner = JWTScanner(session=s, results={})
        assert scanner._find_tokens() == []

    def test_run_returns_zero_without_tokens(self):
        """Token yokken run() ağ erişimi yapmadan 0 döndürmeli (gating)."""
        s = requests.Session()
        scanner = JWTScanner(session=s, results={})
        assert scanner.run("http://target.test/") == 0


class TestStructure:
    def test_inherits_basescanner(self):
        s = requests.Session()
        from websecure.scanners.base import BaseScanner
        assert isinstance(JWTScanner(session=s, results={}), BaseScanner)

    def test_run_callable(self):
        s = requests.Session()
        assert callable(JWTScanner(session=s, results={}).run)
