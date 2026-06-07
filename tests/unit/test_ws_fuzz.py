"""
tests/unit/test_ws_fuzz.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
WebSocket fuzzing scanner birim testleri (yapısal).

WebSocketFuzzer gerçek tespiti canlı WebSocket sunucusu gerektirir (entegrasyon
kapsamı); run() gerçek ws bağlantısı açar. WebSocketFuzzer.__init__ url alır
(session değil). Birim test import + sınıf sözleşmesini korur.
"""
from __future__ import annotations

from websecure.scanners.ws_fuzz import WebSocketFuzzer
from websecure.scanners.base import BaseScanner


def test_inherits_basescanner():
    assert isinstance(WebSocketFuzzer("ws://target.test/ws"), BaseScanner)


def test_run_callable():
    assert callable(WebSocketFuzzer("ws://target.test/ws").run)


def test_name_attribute():
    assert WebSocketFuzzer("ws://target.test/ws").name == "ws_fuzz"


def test_module_has_run():
    from websecure.scanners import ws_fuzz
    assert callable(ws_fuzz.run)
