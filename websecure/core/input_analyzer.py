"""
websecure.core.input_analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Heuristic input-context analysis for smart payload selection.
Classifies HTTP parameters/form fields so scanners can choose
the most relevant payloads and skip irrelevant categories.
"""
from __future__ import annotations
import re
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


# ---------------------------------------------------------------------------
# Context taxonomy
# ---------------------------------------------------------------------------

class ContextType(Enum):
    NUMERIC_ID   = auto()   # e.g. id=42, user_id=7
    EMAIL        = auto()   # e.g. email=foo@bar.com
    URL          = auto()   # e.g. redirect=https://...
    SEARCH       = auto()   # e.g. q=hello, search=foo
    USERNAME     = auto()   # e.g. username=admin
    PASSWORD     = auto()   # e.g. password=...  (skip most payloads)
    BOOLEAN      = auto()   # e.g. active=true/false/1/0
    FILE_PATH    = auto()   # e.g. file=../etc/passwd
    TOKEN        = auto()   # e.g. csrf_token, api_key
    GENERIC_TEXT = auto()   # catch-all


@dataclass
class InputContext:
    """Analysis result for a single parameter."""
    param_name: str
    context: ContextType
    sample_value: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    # Convenience accessor used in base.py: ctx_result.context.name
    # ContextType already has .name from Enum — no extra work needed.


# ---------------------------------------------------------------------------
# Name / value heuristics
# ---------------------------------------------------------------------------

_NAME_RULES: List[tuple] = [
    # (regex_on_name, ContextType)
    (re.compile(r"(^|_)(id|pk|key|num|no)$", re.I),          ContextType.NUMERIC_ID),
    (re.compile(r"email", re.I),                               ContextType.EMAIL),
    (re.compile(r"(url|redirect|return|next|dest|callback)", re.I), ContextType.URL),
    (re.compile(r"(search|query|q|keyword|term|find)", re.I), ContextType.SEARCH),
    (re.compile(r"(user(name)?|login|handle|nick)", re.I),    ContextType.USERNAME),
    (re.compile(r"(pass(word)?|secret|pin|pwd)", re.I),       ContextType.PASSWORD),
    (re.compile(r"(active|enable|flag|bool|toggle)", re.I),   ContextType.BOOLEAN),
    (re.compile(r"(file|path|dir|folder|location)", re.I),    ContextType.FILE_PATH),
    (re.compile(r"(token|csrf|nonce|state|api_?key)", re.I),  ContextType.TOKEN),
]

_VALUE_RULES: List[tuple] = [
    (re.compile(r"^\d+$"),                                     ContextType.NUMERIC_ID),
    (re.compile(r"^[^@]+@[^@]+\.[^@]+$"),                     ContextType.EMAIL),
    (re.compile(r"^https?://", re.I),                         ContextType.URL),
    (re.compile(r"^(true|false|1|0|yes|no)$", re.I),          ContextType.BOOLEAN),
    (re.compile(r"[/\\]"),                                     ContextType.FILE_PATH),
]


def analyze_input_context(
    param_name: str,
    value: Optional[str] = None,
) -> InputContext:
    """
    Classify a single HTTP parameter by name and optional sample value.

    Returns an :class:`InputContext` with the best-matching :class:`ContextType`.
    """
    notes: List[str] = []

    # 1. Name-based heuristics (highest priority)
    for pattern, ctx_type in _NAME_RULES:
        if pattern.search(param_name):
            notes.append(f"name matched /{pattern.pattern}/")
            return InputContext(param_name, ctx_type, value, notes)

    # 2. Value-based heuristics
    if value is not None:
        for pattern, ctx_type in _VALUE_RULES:
            if pattern.search(value):
                notes.append(f"value matched /{pattern.pattern}/")
                return InputContext(param_name, ctx_type, value, notes)

    # 3. Default
    notes.append("no specific pattern matched")
    return InputContext(param_name, ContextType.GENERIC_TEXT, value, notes)


# ---------------------------------------------------------------------------
# Skip-category logic
# ---------------------------------------------------------------------------

# Categories that make no sense for certain contexts
_SKIP_MAP: Dict[ContextType, List[str]] = {
    ContextType.PASSWORD: ["xss", "sqli", "nosqli", "ssti", "rce", "cmdi"],
    ContextType.BOOLEAN:  ["xss", "ssti", "rce", "cmdi", "lfi"],
    ContextType.TOKEN:    ["xss", "ssti", "rce", "cmdi"],
    ContextType.EMAIL:    ["lfi", "rce", "cmdi"],
    ContextType.NUMERIC_ID: ["xss"],
}


def should_skip_payload_category(context: InputContext, category: str) -> bool:
    """
    Return True if *category* payloads should be skipped for the given *context*.
    """
    skip_list = _SKIP_MAP.get(context.context, [])
    return category.lower() in skip_list


# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------

def format_analysis_log(context: InputContext) -> str:
    """Return a human-readable string describing the analysis result."""
    notes_str = "; ".join(context.notes) if context.notes else "—"
    return (
        f"[InputAnalyzer] '{context.param_name}' → {context.context.name} "
        f"(value={context.sample_value!r}, notes: {notes_str})"
    )


# ---------------------------------------------------------------------------
# Form-level bulk analysis (used by crawler)
# ---------------------------------------------------------------------------

def analyze_form_inputs(inputs: List[Dict[str, Any]]) -> Dict[str, InputContext]:
    """
    Analyse a list of form input dicts (each with 'name' and optionally 'value').
    Returns a mapping of param_name → InputContext.
    """
    result: Dict[str, InputContext] = {}
    for inp in inputs:
        name = inp.get("name") or inp.get("id") or ""
        if not name:
            continue
        value = inp.get("value") or inp.get("placeholder") or None
        result[name] = analyze_input_context(name, value)
    return result
