"""
websecure.core.url_utils
~~~~~~~~~~~~~~~~~~~~~~~~
URL normalizasyon ve scheme tespiti için yardımcı fonksiyonlar.
main.py'den FAZ-EK kapsamında buraya taşındı.
"""
from __future__ import annotations

import re as _re_urlnorm
import shutil
import subprocess
from urllib.parse import urlsplit as _urlsplit, urlunsplit as _urlunsplit, SplitResult as _SplitResult
import logging

_logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = ("https", "http")
_DOMAIN_RE__WS3 = _re_urlnorm.compile(r"^(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$")
_IPV4_RE__WS3 = _re_urlnorm.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _ws3_is_ipv6_literal(s: str) -> bool:
    return (s.startswith("[") and s.endswith("]")) or (":" in s)


def _ws3_looks_like_host(s: str) -> bool:
    return bool(
        _DOMAIN_RE__WS3.match(s) or _IPV4_RE__WS3.match(s) or _ws3_is_ipv6_literal(s) or s.lower() == "localhost")


def _ws3_fix_scheme_and_netloc(p: _SplitResult) -> _SplitResult:
    sch = (p.scheme or "").lower()
    netloc = p.netloc
    path = p.path
    if not netloc and path and _ws3_looks_like_host(path):
        netloc = path
        path = ""
    return _SplitResult(sch, netloc, path, p.query, p.fragment)


def _ws3_normalize_input_url(raw: str) -> str | None:
    s = (raw or "").strip()
    if not s:
        return None
    if "://" not in s and _ws3_looks_like_host(s):
        s = "https://" + s
    p = _urlsplit(s)
    p2 = _ws3_fix_scheme_and_netloc(p)
    if not p2.netloc:
        return None
    return _urlunsplit((p2.scheme, p2.netloc, p2.path, p2.query, p2.fragment))


def _ws3_curl_effective_url(url: str, timeout_s: float) -> str:
    curl_bin = shutil.which("curl")
    if not curl_bin:
        return url
    cp = subprocess.run(
        [curl_bin, "-I", "-L", "-m", str(int(timeout_s)), "-sS", "-o", "/dev/null", "-w", "%{url_effective}", url],
        capture_output=True, text=True, check=False,
    )
    eff = (cp.stdout or "").strip()
    return eff or url


def _detect_final_url_and_scheme_robust(raw_input_url: str, timeout_s: float = 6.0) -> tuple[str | None, str | None]:
    s = (raw_input_url or "").strip()
    if not s:
        return None, None

    if "://" in s:
        norm = _ws3_normalize_input_url(s)
        if not norm:
            return None, None
        eff = _ws3_curl_effective_url(norm, timeout_s)
        norm2 = _ws3_normalize_input_url(eff) or norm
        sch = (_urlsplit(norm2).scheme or "http").lower()
        return norm2, sch


    host = s.strip("/")
    candidates = [
        f"https://{host}",
        f"http://{host}",
        f"https://www.{host}",
        f"http://www.{host}",
    ]


    curl_bin = shutil.which("curl")
    if curl_bin:
        for u in candidates:
            cp = subprocess.run(
                [curl_bin, "-I", "-L", "-sS", "--max-time", str(float(timeout_s)), u, "-w",
                 "%{url_effective} %{http_code}", "-o", "/dev/null"],

                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
            )
            if cp.returncode != 0 or not cp.stdout:
                continue
            parts = (cp.stdout.strip()).split()
            if len(parts) >= 2 and parts[-1].isdigit():
                code = int(parts[-1])
                final = " ".join(parts[:-1])
                if 200 <= code < 600:
                    eff = final.split("#", 1)[0].rstrip("/")
                    sch = (_urlsplit(eff).scheme or "http").lower()
                    return eff, sch


    u0 = candidates[0]
    sch = (_urlsplit(u0).scheme or "http").lower()
    return u0, sch
