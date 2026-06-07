"""
tests/unit/test_reporting.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
add_result thread-safety, redaction, finding schema testleri.
"""
from __future__ import annotations

import os
import threading
from unittest.mock import patch


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


class TestResetClearsAllStores:
    """REGRESYON: reset() hem _buckets hem _GLOBAL_RESULTS'u temizlemeli.

    Eskiden yalnız _buckets temizleniyordu; _GLOBAL_RESULTS (get_global_results'un
    okuduğu depo) temizlenmediğinden bir taramanın bulguları SONRAKİ taramaya
    sızıyordu (çoklu-hedef/queue/API'de yanlış rapor; benchmark'ta sahte FP).
    """

    def test_reset_clears_global_and_bucket_stores(self):
        from websecure.core.reporting import (
            add_result, get_global_results, get_bucket_results, reset,
        )

        reset()
        add_result("_leak_probe", {"type": "X", "severity": "High", "url": "http://x"})
        # Yazıldığını doğrula (iki depoda da)
        assert get_global_results().get("_leak_probe"), "add_result _GLOBAL_RESULTS'a yazmadı"
        assert get_bucket_results().get("_leak_probe"), "add_result _buckets'a yazmadı"

        reset()
        # İki depo da temizlenmeli — sızıntı olmamalı
        assert not get_global_results().get("_leak_probe"), \
            "reset() _GLOBAL_RESULTS'u temizlemedi — bulgular sonraki taramaya sızar"
        assert not get_bucket_results().get("_leak_probe"), \
            "reset() _buckets'u temizlemedi"


class TestPDFReportBuilder:
    """REGRESYON: PDF üretimi her zaman bir çıktı üretmeli (gerçek PDF veya HTML
    fallback) ve sessizce kaybolmamalı. reportlab kuruluysa gerçek %PDF beklenir
    (Windows'ta weasyprint kurulamadığında çalışan tek backend)."""

    def test_build_always_produces_output(self, tmp_path):
        from websecure.core.reporting import PDFReportBuilder

        findings = [
            {"type": "SQL Injection", "severity": "Critical",
             "url": "http://t.test/x?id=1", "cwe": "CWE-89"},
            {"type": "XSS", "severity": "High", "url": "http://t.test/s?q=2"},
        ]
        out_pdf = str(tmp_path / "report.pdf")
        path = PDFReportBuilder().build(findings, out_pdf)

        assert path, "build() boş yol döndürdü"
        assert os.path.exists(path), f"Çıktı dosyası üretilmedi: {path}"
        assert os.path.getsize(path) > 0, "Çıktı dosyası boş"

        with open(path, "rb") as fh:
            head = fh.read(5)
        # Bir backend varsa gerçek PDF; yoksa HTML fallback — ikisi de kabul.
        assert head == b"%PDF-" or path.endswith(".html"), \
            f"Ne gerçek PDF ne HTML fallback üretildi (head={head!r}, path={path})"

    def test_reportlab_backend_makes_real_pdf_when_available(self, tmp_path):
        import importlib.util
        if importlib.util.find_spec("reportlab") is None:
            import pytest
            pytest.skip("reportlab kurulu değil — gerçek-PDF yolu doğrulanamaz")

        from websecure.core.reporting import PDFReportBuilder
        out_pdf = str(tmp_path / "real.pdf")
        # weasyprint genelde Windows'ta yok; _try_reportlab devreye girmeli.
        ok = PDFReportBuilder._try_reportlab(
            [{"type": "X", "severity": "High", "url": "http://t/x"}], out_pdf,
        )
        assert ok is True, "reportlab backend PDF üretemedi"
        assert os.path.exists(out_pdf)
        with open(out_pdf, "rb") as fh:
            assert fh.read(5) == b"%PDF-", "reportlab gerçek PDF üretmedi"


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
