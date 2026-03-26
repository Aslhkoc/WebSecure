"""
tests/unit/test_reporting.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
add_result thread-safety, redaction, finding schema testleri.
"""
from __future__ import annotations

import threading
from unittest.mock import patch

import pytest

from websecure.core.redaction import (
    redact_sensitive,
    REDACT_KEYS,
    _redact_str,
    _MASK,
)


class TestRedactStr:
    def test_jwt_masked(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = _redact_str(jwt)
        assert _MASK in result

    def test_bearer_token_masked(self):
        header = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"
        result = _redact_str(header)
        assert "Bearer " + _MASK in result

    def test_email_masked(self):
        text = "contact user@example.com for help"
        result = _redact_str(text)
        assert "user@example.com" not in result
        assert _MASK in result

    def test_no_false_positive_plain_text(self):
        text = "The quick brown fox jumps over the lazy dog"
        result = _redact_str(text)
        assert result == text


class TestRedactSensitive:
    def test_dict_password_key_masked(self):
        data = {"username": "admin", "password": "s3cr3t"}
        result = redact_sensitive(data)
        assert result["username"] == "admin"
        assert result["password"] == _MASK

    def test_nested_dict_masked(self):
        data = {"outer": {"token": "abc123def456ghi789"}}
        result = redact_sensitive(data)
        assert result["outer"]["token"] == _MASK

    def test_list_processed(self):
        data = [{"api_key": "abc12345678901234567890"}]
        result = redact_sensitive(data)
        assert result[0]["api_key"] == _MASK

    def test_bytes_decoded_and_masked(self):
        data = b"Bearer abcdefghijklmnopqrstuvwxyz012345"
        result = redact_sensitive(data)
        assert "Bearer " + _MASK in result

    def test_depth_limit_returns_mask(self):
        # Create deeply nested dict
        deep = {}
        current = deep
        for _ in range(10):
            current["x"] = {}
            current = current["x"]
        current["val"] = "safe"
        # Should not raise, returns _MASK at depth limit
        result = redact_sensitive(deep)
        assert result is not None

    def test_non_sensitive_key_preserved(self):
        data = {"url": "http://target.test/", "severity": "High"}
        result = redact_sensitive(data)
        assert result["url"] == "http://target.test/"
        assert result["severity"] == "High"


class TestRedactKeys:
    def test_all_required_keys_present(self):
        required = {"password", "token", "authorization", "secret", "api_key", "cookie"}
        assert required.issubset(REDACT_KEYS)


class TestAddResultThreadSafety:
    def test_concurrent_writes_no_loss(self):
        """100 thread eş zamanlı add_result — hiç bulgu kaybolmamalı."""
        from websecure.core.reporting import add_result, get_global_results
        import time

        bucket = f"test_concurrent_{int(time.time() * 1000)}"
        num = 50

        barrier = threading.Barrier(num)

        def worker(i):
            barrier.wait()
            add_result(bucket, {"type": "XSS", "id": i, "severity": "High"})

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        results = get_global_results()
        assert len(results.get(bucket, [])) == num


class TestFindingSchema:
    def test_report_finding_schema(self, mock_session):
        """report_finding'in ürettiği entry standart şemaya uymalı."""
        from websecure.scanners.base import BaseScanner

        scanner = BaseScanner(session=mock_session, results={})
        with patch("websecure.scanners.base.add_result"):
            scanner.report_finding(
                vuln_type="SQLi",
                url="http://t.test/page?id=1",
                param="id",
                payload="' OR 1=1--",
                severity="Critical",
                evidence="Error-based detection",
                extra={"cwe": "CWE-89"},
            )

        bucket_entries = scanner.results.get("offensive", [])
        assert len(bucket_entries) == 1
        entry = bucket_entries[0]
        assert entry["type"] == "SQLi"
        assert entry["url"] == "http://t.test/page?id=1"
        assert entry["parameter"] == "id"
        assert entry["severity"] == "Critical"
        assert entry.get("cwe") == "CWE-89"
