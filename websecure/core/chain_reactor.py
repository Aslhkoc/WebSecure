"""
websecure.core.chain_reactor
----------------------------
The "Brain" of the Senior Hacker.
This module analyzes the complete set of findings *after* all scanners have finished.
It looks for combinations of low/medium vulnerabilities that, when chained, create
a Critical or High impact scenario.

Supported Chains:
1. Self-XSS + CSRF -> Account Takeover (Critical)
2. Sensitive Information Disclosure + IDOR -> Critical Data Leak (High)
"""
from __future__ import annotations
import logging
from typing import Dict, Any, List

from websecure.core.reporting import add_result

_logger = logging.getLogger(__name__)

def _find_by_type(findings: List[Dict[str, Any]], type_keyword: str) -> List[Dict[str, Any]]:
    """Helper to fuzzy-find vulnerabilities by type."""
    matches = []
    kw = type_keyword.lower()
    for f in findings:
        if not isinstance(f, dict):
             continue
        t = str(f.get("type", "")).lower()
        if kw in t:
            matches.append(f)
    return matches

def analyze_chains(results: Dict[str, Any]) -> None:
    """
    Main entry point. Reads 'results' which contains all findings from all buckets.
    Injects new 'Chained' findings into a 'chain_reactor' bucket.
    """
    bucket = "chain_reactor"
    
    # Flatten all findings for easier searching
    all_findings = []
    for k, v in results.items():
        if isinstance(v, list):
            all_findings.extend(v)
            
    # -------------------------------------------------------------------------
    # CHAIN 1: Self-XSS + CSRF -> Account Takeover
    # -------------------------------------------------------------------------
    # Criteria:
    # A. An XSS finding exists (even stored/reflected low impact).
    # B. A CSRF finding exists on a sensitive action (password/email).
    
    xss_candidates = _find_by_type(all_findings, "xss")
    csrf_candidates = _find_by_type(all_findings, "csrf")
    
    # Filter for sensitive CSRF (heuristic from csrf scanner usually marks them Medium/High)
    sensitive_csrf = [c for c in csrf_candidates if c.get("severity") in ("High", "Medium")]
    
    if xss_candidates and sensitive_csrf:
        # We have a chain!
        # Pick the best examples for evidence
        best_xss = xss_candidates[0]
        best_csrf = sensitive_csrf[0]
        
        add_result(bucket, {
            "type": "Chained Vulnerability: Account Takeover",
            "title": "Account Takeover via CSRF + XSS Chain",
            "severity": "Critical",
            "confidence": "High",
            "url": best_csrf.get("url"),
            "description": (
                "Automatic analysis detected a Critical Kill Chain.\n\n"
                "1. **Self-XSS/XSS Found**: An attacker can execute script code (payload: `{}`).\n"
                "2. **CSRF Found**: A sensitive action (change password/email) lacks protection.\n\n"
                "**Impact**: An attacker can force a logged-in victim to execute the XSS payload. "
                "Since CSRF protection is missing, the XSS can then perform the sensitive action "
                "(e.g., change password) without user interaction, leading to full Account Takeover."
            ).format(best_xss.get("payload", "N/A")),
            "evidence": {
                "chain_link_1": best_xss,
                "chain_link_2": best_csrf
            }
        })
        _logger.info("CHAIN REACTOR: DETECTED CSRF+XSS CHAIN!")

    # -------------------------------------------------------------------------
    # CHAIN 2: Information Disclosure + IDOR
    # -------------------------------------------------------------------------
    # Criteria:
    # A. Leaked internal paths/IDs (Info Disclosure).
    # B. IDOR vulnerability detected.
    
    info_leaks = _find_by_type(all_findings, "disclosure") + _find_by_type(all_findings, "leak")
    idors = _find_by_type(all_findings, "idor")
    
    if info_leaks and idors:
        best_leak = info_leaks[0]
        best_idor = idors[0]
        
        add_result(bucket, {
            "type": "Chained Vulnerability: Informed IDOR",
            "title": "Mass Data Leakage via Info Disclosure + IDOR",
            "severity": "High",
            "confidence": "Medium",
            "url": best_idor.get("url"),
            "description": (
                "Automatic analysis detected a High severity chain.\n\n"
                "1. **Information Leak**: Valid internal IDs or paths are leaked.\n"
                "2. **IDOR**: Access control on these objects is broken.\n\n"
                "**Impact**: An attacker does not need to guess IDs (which is often a mitigation for IDOR). "
                "They can scrape leaked IDs and systematically exploit the IDOR to dump database records."
            ),
            "evidence": {
                "chain_link_1": best_leak,
                "chain_link_2": best_idor
            }
        })

    # Future Chains can be added here...
