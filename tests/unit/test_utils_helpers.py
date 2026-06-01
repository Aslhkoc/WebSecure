"""
tests/unit/test_utils_helpers.py
---------------------------------
Unit tests for websecure.core.utils.helpers — sig_params, kw_filter,
guess_host_from_url.

Note: redact_sensitive was moved to websecure.core.redaction (covered by
tests/unit/test_reporting.py), and the ttl_cache_* helpers were removed from
the codebase; both are intentionally no longer tested here.
"""
from __future__ import annotations

from websecure.core.utils.helpers import (
    guess_host_from_url,
    kw_filter,
    sig_params,
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
