"""
tests/unit/test_utils_helpers.py
---------------------------------
Unit tests for websecure.core.utils.helpers — sig_params, kw_filter,
guess_host_from_url, redact_sensitive, ttl_cache.
"""
from __future__ import annotations

import time

import pytest

from websecure.core.utils.helpers import (
    guess_host_from_url,
    kw_filter,
    redact_sensitive,
    sig_params,
    ttl_cache_get,
    ttl_cache_set,
)


# ---------------------------------------------------------------------------
# sig_params
# ---------------------------------------------------------------------------

def test_sig_params_basic():
    def fn(a, b, c=3):
        pass
    assert sig_params(fn) == {"a", "b", "c"}


def test_sig_params_no_params():
    def fn():
        pass
    assert sig_params(fn) == set()


def test_sig_params_non_callable():
    assert sig_params(42) == set()
    assert sig_params(None) == set()


def test_sig_params_var_keyword():
    def fn(**kwargs):
        pass
    params = sig_params(fn)
    assert "kwargs" in params


# ---------------------------------------------------------------------------
# kw_filter
# ---------------------------------------------------------------------------

def test_kw_filter_keeps_accepted():
    def fn(x, y):
        pass
    result = kw_filter(fn, x=1, y=2, z=3)
    assert result == {"x": 1, "y": 2}


def test_kw_filter_empty_kwargs():
    def fn(x):
        pass
    assert kw_filter(fn) == {}


def test_kw_filter_no_overlap():
    def fn(a):
        pass
    assert kw_filter(fn, b=1, c=2) == {}


def test_kw_filter_var_kwargs_passes_everything():
    """When fn accepts **kwargs, all items should pass through."""
    def fn(**kwargs):
        pass
    result = kw_filter(fn, x=1, y=2)
    assert result == {"x": 1, "y": 2}


def test_kw_filter_non_callable():
    result = kw_filter(None, x=1)  # type: ignore
    assert result == {}


# ---------------------------------------------------------------------------
# guess_host_from_url
# ---------------------------------------------------------------------------

def test_guess_host_from_url_http():
    assert guess_host_from_url("http://example.com/path") == "example.com"


def test_guess_host_from_url_https():
    assert guess_host_from_url("https://api.example.com:8443/v1") == "api.example.com"


def test_guess_host_from_url_empty():
    assert guess_host_from_url("") == ""


def test_guess_host_from_url_ip():
    assert guess_host_from_url("http://192.168.1.1:8080/") == "192.168.1.1"


# ---------------------------------------------------------------------------
# redact_sensitive
# ---------------------------------------------------------------------------

def test_redact_sensitive_password():
    data = {"username": "admin", "password": "secret123"}
    result = redact_sensitive(data)
    assert result["password"] == "***REDACTED***"
    assert result["username"] == "admin"


def test_redact_sensitive_token_key():
    data = {"session_id": "xyz", "token": "eyJhbGc.xxx.yyy"}
    result = redact_sensitive(data)
    assert result["token"] == "***REDACTED***"
    assert result["session_id"] == "xyz"


def test_redact_sensitive_nested():
    # "auth" is itself a sensitive key, so wrap it under a non-sensitive parent
    data = {"credentials": {"token": "eyJhbGc.xxx.yyy", "user": "bob"}}
    result = redact_sensitive(data)
    # "credentials" is not sensitive — recurse into it
    assert result["credentials"]["token"] == "***REDACTED***"
    assert result["credentials"]["user"] == "bob"


def test_redact_sensitive_jwt_in_string():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi789"
    result = redact_sensitive(jwt)
    assert "[REDACTED]" in result


def test_redact_sensitive_list():
    data = [{"token": "abc"}, {"other": "value"}]
    result = redact_sensitive(data)
    assert result[0]["token"] == "***REDACTED***"
    assert result[1]["other"] == "value"


def test_redact_sensitive_plain_string():
    result = redact_sensitive("hello world")
    assert result == "hello world"


def test_redact_sensitive_non_sensitive_keys():
    data = {"url": "http://example.com", "status": 200}
    result = redact_sensitive(data)
    assert result == data


# ---------------------------------------------------------------------------
# TTL cache
# ---------------------------------------------------------------------------

def test_ttl_cache_set_and_get():
    ttl_cache_set("test_key_1", "test_value", ttl=60)
    assert ttl_cache_get("test_key_1") == "test_value"


def test_ttl_cache_missing_key():
    assert ttl_cache_get("nonexistent_key_xyz") is None


def test_ttl_cache_expired():
    ttl_cache_set("expiry_test_key", "value", ttl=1)
    time.sleep(1.1)
    assert ttl_cache_get("expiry_test_key") is None


def test_ttl_cache_overwrite():
    ttl_cache_set("overwrite_key", "first", ttl=60)
    ttl_cache_set("overwrite_key", "second", ttl=60)
    assert ttl_cache_get("overwrite_key") == "second"
