"""
tests/unit/test_exceptions.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Exception hiyerarşisi doğrulama testleri.
"""
from __future__ import annotations

import requests
import pytest

from websecure.core.exceptions import (
    WebSecureError,
    ScanError,
    ProbeError,
    BaselineError,
    PayloadError,
    NetworkError,
    RequestTimeoutError,
    ConnectionRefusedError as WsConnectionRefusedError,
    SSLHandshakeError,
    ParseError,
    ConfigError,
    wrap_requests_error,
)


class TestHierarchy:
    def test_scan_error_is_websecure_error(self):
        assert issubclass(ScanError, WebSecureError)

    def test_probe_error_is_scan_error(self):
        assert issubclass(ProbeError, ScanError)

    def test_baseline_error_is_scan_error(self):
        assert issubclass(BaselineError, ScanError)

    def test_payload_error_is_scan_error(self):
        assert issubclass(PayloadError, ScanError)

    def test_network_error_is_websecure_error(self):
        assert issubclass(NetworkError, WebSecureError)

    def test_timeout_is_network_error(self):
        assert issubclass(RequestTimeoutError, NetworkError)

    def test_connection_refused_is_network_error(self):
        assert issubclass(WsConnectionRefusedError, NetworkError)

    def test_ssl_is_network_error(self):
        assert issubclass(SSLHandshakeError, NetworkError)

    def test_parse_error_is_websecure_error(self):
        assert issubclass(ParseError, WebSecureError)

    def test_config_error_is_websecure_error(self):
        assert issubclass(ConfigError, WebSecureError)


class TestFields:
    def test_fields_stored(self):
        exc = ProbeError(
            "probe failed",
            url="http://t.test/",
            param="q",
            payload="<s>",
            original_exc=ValueError("orig"),
        )
        assert exc.url == "http://t.test/"
        assert exc.param == "q"
        assert exc.payload == "<s>"
        assert isinstance(exc.original_exc, ValueError)

    def test_str_representation(self):
        exc = ScanError("something broke", url="http://t.test/")
        assert "something broke" in str(exc)

    def test_defaults_empty(self):
        exc = ConfigError("bad config")
        assert exc.url == ""
        assert exc.param == ""
        assert exc.payload == ""
        assert exc.original_exc is None


class TestWrapRequestsError:
    def test_timeout_maps_to_request_timeout_error(self):
        orig = requests.exceptions.Timeout("timed out")
        wrapped = wrap_requests_error(orig, url="http://t.test/")
        assert isinstance(wrapped, RequestTimeoutError)
        assert wrapped.original_exc is orig

    def test_connection_error_maps_to_connection_refused(self):
        orig = requests.exceptions.ConnectionError("refused")
        wrapped = wrap_requests_error(orig, url="http://t.test/")
        assert isinstance(wrapped, WsConnectionRefusedError)

    def test_ssl_error_maps_to_ssl_handshake_error(self):
        orig = requests.exceptions.SSLError("ssl")
        wrapped = wrap_requests_error(orig, url="http://t.test/")
        assert isinstance(wrapped, SSLHandshakeError)

    def test_generic_request_exception_maps_to_network_error(self):
        orig = requests.exceptions.RequestException("other")
        wrapped = wrap_requests_error(orig)
        assert isinstance(wrapped, NetworkError)

    def test_catch_chain(self):
        """Catching WebSecureError catches all custom exceptions."""
        try:
            raise ProbeError("p", url="http://t.test/")
        except WebSecureError:
            pass  # expected
        else:
            pytest.fail("WebSecureError should have caught ProbeError")
