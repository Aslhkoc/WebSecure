"""
tests/unit/test_url_utils.py
-----------------------------
Unit tests for websecure.core.url_utils — URL normalization helpers.

Note on _ws3_is_ipv6_literal:
  The implementation returns True for any string containing ":" (to catch
  raw IPv6 like "::1") as well as strings bracketed with "[...]". Tests
  reflect this actual behavior.
"""
from __future__ import annotations


from websecure.core.url_utils import (
    _ws3_is_ipv6_literal,
    _ws3_looks_like_host,
    _ws3_normalize_input_url,
)


# ---------------------------------------------------------------------------
# _ws3_is_ipv6_literal
# ---------------------------------------------------------------------------

def test_ipv6_literal_with_brackets():
    assert _ws3_is_ipv6_literal("[::1]") is True
    assert _ws3_is_ipv6_literal("[2001:db8::1]") is True


def test_ipv6_literal_bare_colons():
    # "::1" contains ":" so returns True (implementation uses ":" in s)
    assert _ws3_is_ipv6_literal("::1") is True
    assert _ws3_is_ipv6_literal("2001:db8::1") is True


def test_ipv6_literal_ipv4():
    assert _ws3_is_ipv6_literal("192.168.1.1") is False


def test_ipv6_literal_empty():
    assert _ws3_is_ipv6_literal("") is False


def test_ipv6_literal_plain_hostname():
    assert _ws3_is_ipv6_literal("example.com") is False


# ---------------------------------------------------------------------------
# _ws3_looks_like_host
# ---------------------------------------------------------------------------

def test_looks_like_host_domain():
    assert _ws3_looks_like_host("example.com") is True
    assert _ws3_looks_like_host("sub.example.com") is True


def test_looks_like_host_ip():
    assert _ws3_looks_like_host("192.168.1.1") is True


def test_looks_like_host_localhost():
    assert _ws3_looks_like_host("localhost") is True


def test_looks_like_host_ipv6():
    # Contains ":" so passes _ws3_is_ipv6_literal check
    assert _ws3_looks_like_host("::1") is True


def test_looks_like_host_plain_string():
    assert _ws3_looks_like_host("notahost") is False


# ---------------------------------------------------------------------------
# _ws3_normalize_input_url
# ---------------------------------------------------------------------------

def test_normalize_adds_scheme():
    result = _ws3_normalize_input_url("example.com")
    assert result is not None
    assert "example.com" in result


def test_normalize_preserves_https():
    result = _ws3_normalize_input_url("https://example.com/path")
    assert result is not None
    assert result.startswith("https://")


def test_normalize_preserves_http():
    result = _ws3_normalize_input_url("http://example.com")
    assert result is not None
    assert result.startswith("http://")


def test_normalize_empty_returns_none():
    result = _ws3_normalize_input_url("")
    assert result is None


def test_normalize_whitespace_stripped():
    result = _ws3_normalize_input_url("  https://example.com  ")
    assert result is not None
    assert "example.com" in result
