# -*- coding: utf-8 -*-
"""
Smart Input Context Analyzer for WebSecure (Phase 2)

Bu modül input alanlarının bağlamını analiz eder ve uygun payload kategorilerini belirler.
Phase 2 Özellikleri:
- Derin Değer Analizi (Base64, JSON, JWT tespiti)
- Teknoloji Farkındalığı (Tech-Stack filtering)
"""

from __future__ import annotations
import re
import json
import base64
import binascii
from enum import Enum, auto
from typing import List, Set, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field


class InputContext(Enum):
    """Input alanı bağlam türleri"""
    # Authentication
    USERNAME = auto()       # Kullanıcı adı
    PASSWORD = auto()       # Şifre (skip)
    EMAIL = auto()          # Email
    
    # Data identifiers
    NUMERIC_ID = auto()     # id, user_id (SQLi, IDOR)
    UUID = auto()           # GUID/UUID (SQLi - blind mostly)
    
    # Search & Content
    SEARCH = auto()         # Arama
    TEXT_CONTENT = auto()   # Comment, body
    
    # Navigation & Files
    URL_REDIRECT = auto()   # Redirect
    FILE_PATH = auto()      # LFI
    
    # Structured / Encoded Data (Phase 2 NEW)
    JSON_BODY = auto()      # JSON object
    JSON_STRING = auto()    # JSON in string param
    XML_BODY = auto()       # XML input
    JWT = auto()            # JWT Token
    SERIALIZED = auto()     # PHP/Java Serialization
    BASE64_ENCODED = auto() # Generic Base64 (decode & re-analyze?)
    
    # Sorting & Pagination
    SORT_ORDER = auto()     # order by
    PAGINATION = auto()     # limit, offset
    FILTER = auto()         # category
    
    # Time & Date
    DATE_TIME = auto()
    
    # Special
    HIDDEN = auto()         # hidden
    HEADER = auto()         # header
    COOKIE = auto()         # cookie
    
    # Tokens (Skip)
    CSRF_TOKEN = auto()
    CAPTCHA = auto()
    SESSION = auto()
    
    # Default
    GENERIC = auto()        # Fallback


@dataclass
class ContextAnalysisResult:
    """Bağlam analizi sonucu"""
    context: InputContext
    confidence: float  # 0.0 - 1.0
    applicable_attacks: List[str]
    skip_reason: Optional[str] = None
    decoded_value: Any = None  # Base64 decode sonucu vs.


# =============================================================================
# TECH AWARENESS MAPPING
# =============================================================================

# Saldırı tiplerinin gerektirdiği teknolojiler (varsa)
# Eğer hedef sistemin teknolojileri biliniyorsa ve bu gereksinimlerle ÇAKIŞIYORSA skip edilir.
# Boş liste = Her yerde çalışır veya bağımsız.
_ATTACK_TECH_REQ: Dict[str, Set[str]] = {
    "sqli": {"sql", "mysql", "postgresql", "postgres", "mssql", "oracle", "sqlite", "mariadb"},
    "nosqli": {"nosql", "mongodb", "couchdb", "dynamodb", "redis"},
    "ssti": {"java", "python", "ruby", "nodejs", "php", "go"}, # Hepsi olabilir ama spesifik
    "php_injection": {"php"},
    "asp_net_injection": {"asp", "aspx", "iis", "windows"},
    "iis_shortname": {"iis", "windows"},
    "jsp_injection": {"java", "jsp", "tomcat", "jetty"},
}

# =============================================================================
# CONTEXT PATTERNS & ATTACKS
# =============================================================================

_CONTEXT_PATTERNS: Dict[InputContext, List[str]] = {
    InputContext.USERNAME: [r'^(user|username|login|uname|usr|account|nick)$', r'(user|login)[-_]?(name|id)$'],
    InputContext.PASSWORD: [r'^(pass|password|pwd|secret)$', r'(pass|pwd)[-_]?(word)?$'],
    InputContext.EMAIL: [r'^(email|mail)$', r'(email|mail)[-_]?(address)?$'],
    InputContext.NUMERIC_ID: [r'^id$', r'[-_]?id$', r'^(uid|pid|cid|oid)$'],
    InputContext.SEARCH: [r'^(q|query|search|s|keyword|term)$'],
    InputContext.URL_REDIRECT: [r'^(redirect|next|return|url|goto|dest)$'],
    InputContext.FILE_PATH: [r'^(file|path|doc|template|include|src)$'],
    InputContext.CSRF_TOKEN: [r'^(csrf|xsrf|token)$', r'[-_]?(csrf|xsrf)[-_]?'],
    InputContext.SESSION: [r'^(session|sess|jsessionid|phpsessid)$'],
}

_CONTEXT_ATTACKS: Dict[InputContext, List[str]] = {
    InputContext.NUMERIC_ID: ["sqli", "nosqli", "idor"],
    InputContext.USERNAME: ["sqli", "nosqli", "xss"],
    InputContext.PASSWORD: ["sqli", "nosqli", "auth_bypass"], # User explicitly requested testing keys
    InputContext.EMAIL: ["sqli", "nosqli", "header_injection", "xss"],

    InputContext.SEARCH: ["xss", "sqli", "ssti"],
    InputContext.TEXT_CONTENT: ["xss", "ssti", "sqli"],
    InputContext.URL_REDIRECT: ["open_redirect", "ssrf"],
    InputContext.FILE_PATH: ["lfi", "path_traversal", "rce"],
    
    # Phase 2 Added
    InputContext.JWT: ["jwt_attack", "auth_bypass"],
    InputContext.JSON_BODY: ["nosqli", "sqli", "xxe", "json_injection"],
    InputContext.JSON_STRING: ["nosqli", "sqli", "xxe"],
    InputContext.XML_BODY: ["xxe", "xpath_injection"],
    InputContext.SERIALIZED: ["deserialization", "rce"],
    InputContext.BASE64_ENCODED: ["deserialization", "sqli", "xss"], # Decode edip bakılmalı ama genelde bunlar
    
    InputContext.CSRF_TOKEN: [],
    InputContext.GENERIC: [
        "xss", "sqli", "nosqli", "ssti", "rce", "lfi", 
        "ssrf", "open_redirect", "xxe", "idor",
        "deserialization", "jwt_attack"
    ],
}

_SKIP_CONTEXTS: Dict[InputContext, str] = {
    InputContext.CSRF_TOKEN: "Validation token",
    InputContext.SESSION: "Session managment test (skipped here)",
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _is_json(s: str) -> bool:
    s = s.strip()
    if not (s.startswith('{') and s.endswith('}')) and not (s.startswith('[') and s.endswith(']')):
        return False
    try:
        json.loads(s)
        return True
    except:
        return False

def _is_xml(s: str) -> bool:
    s = s.strip()
    return s.startswith('<') and s.endswith('>') and ('<?xml' in s[:20] or '<root' in s or '<data' in s)

def _is_jwt(s: str) -> bool:
    # eyJ... . eyJ... . ...
    parts = s.split('.')
    if len(parts) != 3:
        return False
    if not s.startswith('eyJ'): # header {"alg":...} usually
        return False
    return True

def _is_base64(s: str) -> bool:
    # Minimal length heuristic + pattern
    if len(s) < 4 or len(s) % 4 != 0:
        return False
    if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', s):
        return False
    # Try decode
    try:
        base64.b64decode(s, validate=True)
        return True
    except:
        return False

# =============================================================================
# PUBLIC API
# =============================================================================

def analyze_input_context(
    name: str,
    input_type: Optional[str] = None,
    value: Optional[str] = None,
    url_path: Optional[str] = None,
    source: Optional[str] = None,
    tech_stack: Optional[Set[str]] = None
) -> ContextAnalysisResult:
    """
    Enhanced Context Analyzer Phase 2
    
    Args:
        tech_stack: Detected technologies (e.g. {'php', 'mysql', 'linux'})
    """
    name_lower = (name or "").lower().strip()
    value_str = str(value) if value else ""
    
    # 1. Deep Value Heuristics (High Confidence)
    if value_str:
        if _is_jwt(value_str):
            return ContextAnalysisResult(InputContext.JWT, 1.0, _CONTEXT_ATTACKS[InputContext.JWT])
        
        if _is_json(value_str):
            if source == "json":
               ctx = InputContext.JSON_BODY 
            else:
               ctx = InputContext.JSON_STRING
            return ContextAnalysisResult(ctx, 0.95, _CONTEXT_ATTACKS[ctx])
            
        if _is_xml(value_str):
            return ContextAnalysisResult(InputContext.XML_BODY, 0.95, _CONTEXT_ATTACKS[InputContext.XML_BODY])
            
        # Serialized check (PHP "O:..." or Java magic bytes hex?)
        if value_str.startswith('O:') and len(value_str) > 4: # Simple PHP object heuristic
            return ContextAnalysisResult(InputContext.SERIALIZED, 0.9, _CONTEXT_ATTACKS[InputContext.SERIALIZED])

    # 2. Source/Type Detection
    if source == "json":
         return ContextAnalysisResult(InputContext.JSON_BODY, 0.9, _CONTEXT_ATTACKS[InputContext.JSON_BODY])
         
    # 3. Name Pattern Matching
    for ctx, patterns in _CONTEXT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return ContextAnalysisResult(
                    ctx, 0.9, _CONTEXT_ATTACKS.get(ctx, []), 
                    skip_reason=_SKIP_CONTEXTS.get(ctx)
                )

    # 4. Fallback Value Heuristics
    if value_str:
         if re.match(r'^https?://', value_str):
             return ContextAnalysisResult(InputContext.URL_REDIRECT, 0.8, _CONTEXT_ATTACKS[InputContext.URL_REDIRECT])
         if re.match(r'^\d+$', value_str):
             return ContextAnalysisResult(InputContext.NUMERIC_ID, 0.7, _CONTEXT_ATTACKS[InputContext.NUMERIC_ID])

    # 5. Generic
    return ContextAnalysisResult(InputContext.GENERIC, 0.5, _CONTEXT_ATTACKS[InputContext.GENERIC])


def should_skip_payload_category(context: InputContext, category: str, tech_stack: Optional[Set[str]] = None) -> bool:
    """
    Decide whether to skip a payload category based on Context AND Technology.
    """
    # 1. Context Check
    applicable = _CONTEXT_ATTACKS.get(context, [])
    # If explicitly empty list (PASSWORD), we skip everything
    if context in _CONTEXT_ATTACKS and not applicable:
        return True
        
    # If category not in applicable list (and context is not GENERIC/Empty), skip.
    if applicable and category.lower() not in [a.lower() for a in applicable]:
        return True
        
    # 2. Technology Check (Phase 2)
    if tech_stack:
        req_techs = _ATTACK_TECH_REQ.get(category.lower())
        if req_techs:
            # Logic: If we REQUIRE sql, and tech_stack has NO sql, should we skip?
            # Problem: Tech stack implies "What is present".
            # If tech_stack = {'mongodb', 'nodejs'}, does it mean NO mysql? Usually yes in modern single-db apps.
            # But maybe not.
            # Safer Logic:
            # If tech_stack contains a CONFLICTING db type?
            # Example: If we are doing 'sqli' (needs generic sql)
            # If tech_stack has 'mongodb' and NO 'sql' variants...
            
            # Let's check overlap.
            # If tech_stack contains ANY known DB technology:
            known_dbs = {"mysql", "postgresql", "postgres", "mssql", "oracle", "sqlite", "mariadb", "mongodb", "couchdb", "dynamodb", "redis"}
            present_dbs = tech_stack.intersection(known_dbs)
            
            if present_dbs:
                # If DBs are detected, check if at least one satisfies the requirement.
                # 'sqli' reqs: {mysql, postgres...}
                # present: {mongodb}
                # overlap: Empty -> SKIP SQLi.
                # present: {mysql, mongodb} -> overlap: {mysql} -> ALLOW SQLi.
                
                reqs_for_cat = _ATTACK_TECH_REQ.get(category.lower())
                if reqs_for_cat:
                     # Calculate overlap
                     overlap = present_dbs.intersection(reqs_for_cat)
                     # If the requirement set consists of DBs (is a DB attack)
                     if reqs_for_cat.intersection(known_dbs): 
                         if not overlap:
                             return True # DB Mismatch! Skip.

            # Language checks
            # If category requires PHP, and tech_stack has Python/Node but NO PHP -> Skip
            known_langs = {"php", "python", "java", "ruby", "go", "nodejs", "asp", "aspx", "c#"}
            present_langs = tech_stack.intersection(known_langs)
            
            if present_langs:
                 req_langs = req_techs.intersection(known_langs)
                 if req_langs and not present_langs.intersection(req_langs):
                     return True # Language Mismatch! Skip.

    return False

def get_applicable_attacks(context: InputContext) -> List[str]:
    return list(_CONTEXT_ATTACKS.get(context, _CONTEXT_ATTACKS[InputContext.GENERIC]))

def format_analysis_log(name: str, result: ContextAnalysisResult) -> str:
    attacks = ", ".join(result.applicable_attacks) if result.applicable_attacks else "SKIP"
    info = f"[Context] {name} → {result.context.name}"
    if result.confidence > 0.8:
        info += " 🔥"
    info += f" → {attacks}"
    if result.skip_reason:
        info += f" ({result.skip_reason})"
    return info

# Compatibility Wrappers for existing scanners
def analyze_form_inputs(inputs: List[Dict[str, Any]]) -> Dict[str, ContextAnalysisResult]:
    # ... Same as before ...
    results = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            results[name] = analyze_input_context(name, input_type=inp.get("type"), value=inp.get("value"), source="form")
    return results

def get_context_stats(results: Dict[str, ContextAnalysisResult]) -> Dict[str, int]:
    stats: Dict[str, int] = {}
    for r in results.values():
        stats[r.context.name] = stats.get(r.context.name, 0) + 1
    return stats
