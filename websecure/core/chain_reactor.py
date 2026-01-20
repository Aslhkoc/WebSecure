# -*- coding: utf-8 -*-
"""
websecure.core.chain_reactor
----------------------------
The "Brain" of the Senior Hacker.
This module analyzes the complete set of findings *after* all scanners have finished.
It looks for combinations of low/medium vulnerabilities that, when chained, create
a Critical or High impact scenario.

Supported Chains (v2.0):
1. Self-XSS + CSRF -> Account Takeover (Critical)
2. Sensitive Information Disclosure + IDOR -> Critical Data Leak (High)
3. SSRF + Cloud Metadata -> Cloud Infrastructure Compromise (Critical)
4. Open Redirect + XSS -> Advanced DOM-Based Phishing (High)
5. LFI + File Upload -> Remote Code Execution (Critical)
"""
from __future__ import annotations
import logging
from typing import Dict, Any, List

from websecure.core.reporting import add_result

_logger = logging.getLogger(__name__)

def _find_by_type(findings: List[Dict[str, Any]], type_keywords: List[str]) -> List[Dict[str, Any]]:
    """Helper to fuzzy-find vulnerabilities by type."""
    matches = []
    for f in findings:
        if not isinstance(f, dict):
             continue
        t = str(f.get("type", "")).lower()
        # If ANY keyword matches
        if any(k.lower() in t for k in type_keywords):
            matches.append(f)
    return matches

def _check_evidence_for_keywords(finding: Dict[str, Any], keywords: List[str]) -> bool:
    """Checks finding evidence/payload for specific keywords."""
    blob = str(finding.get("evidence", "")) + str(finding.get("payload", "")) + str(finding.get("description", ""))
    blob = blob.lower()
    return any(k.lower() in blob for k in keywords)

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
            
    # Pre-fetch categories
    xss_candidates = _find_by_type(all_findings, ["xss", "script"])
    csrf_candidates = _find_by_type(all_findings, ["csrf", "xsrf"])
    info_leaks = _find_by_type(all_findings, ["disclosure", "leak", "sensitive"])
    idors = _find_by_type(all_findings, ["idor", "insecure direct object"])
    ssrf_candidates = _find_by_type(all_findings, ["ssrf", "server side request"])
    redirect_candidates = _find_by_type(all_findings, ["open redirect", "unvalidated redirect"])
    lfi_candidates = _find_by_type(all_findings, ["lfi", "traversal", "local file"])
    upload_candidates = _find_by_type(all_findings, ["upload", "file write"])

    # -------------------------------------------------------------------------
    # CHAIN 1: Self-XSS + CSRF -> Account Takeover
    # -------------------------------------------------------------------------
    sensitive_csrf = [c for c in csrf_candidates if c.get("severity") in ("High", "Medium")]
    
    if xss_candidates and sensitive_csrf:
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
                "1. **Self-XSS/XSS Found**: An attacker can execute script code.\n"
                "2. **CSRF Found**: A sensitive action lacks protection.\n\n"
                "**Impact**: An attacker can force a logged-in victim to execute the XSS payload, "
                "bypassing CSRF protection to perform sensitive actions (Password Reset, etc.)."
            ),
            "evidence": {"xss": best_xss, "csrf": best_csrf}
        })
        _logger.info("CHAIN REACTOR: DETECTED CSRF+XSS CHAIN!")

    # -------------------------------------------------------------------------
    # CHAIN 2: Info Disclosure + IDOR -> Mass Data Leakage
    # -------------------------------------------------------------------------
    if info_leaks and idors:
        add_result(bucket, {
            "type": "Chained Vulnerability: Informed IDOR",
            "title": "Mass Data Leakage via Info Disclosure + IDOR",
            "severity": "High",
            "confidence": "Medium",
            "url": idors[0].get("url"),
            "description": (
                "1. **Information Leak**: Valid internal IDs/Paths leaked.\n"
                "2. **IDOR**: Access control broken on ID-based endpoints.\n\n"
                "**Impact**: Attacker can enumerate legitimate IDs from the leak and unrestricted IDOR to dump data."
            ),
            "evidence": {"leak": info_leaks[0], "idor": idors[0]}
        })

    # -------------------------------------------------------------------------
    # CHAIN 3: SSRF + Cloud Metadata -> Cloud Compromise (NEW)
    # -------------------------------------------------------------------------
    # Check if any SSRF specifically hit metadata IP or keywords
    cloud_ssrf = []
    for s in ssrf_candidates:
        if _check_evidence_for_keywords(s, ["169.254.169.254", "metadata", "aws", "iam", "compute", "instance-id"]):
            cloud_ssrf.append(s)
            
    if cloud_ssrf:
        add_result(bucket, {
            "type": "Chained Vulnerability: Cloud Infrastructure Compromise",
            "title": "Full Cloud Compromise via Metadata SSRF",
            "severity": "Critical",
            "confidence": "High",
            "url": cloud_ssrf[0].get("url"),
            "description": (
                "1. **SSRF Found**: Application sends requests to arbitrary URLs.\n"
                "2. **Cloud Detection**: Evidence shows successful access to Cloud Metadata (AWS/GCP/Azure).\n\n"
                "**Impact**: An attacker can extract temporary IAM credentials (AWS keys) from the metadata service "
                "and take control of the entire cloud infrastructure."
            ),
            "evidence": {"ssrf": cloud_ssrf[0]}
        })
        _logger.info("CHAIN REACTOR: DETECTED CLOUD SSRF CHAIN!")

    # -------------------------------------------------------------------------
    # CHAIN 4: Open Redirect + XSS -> Advanced Phishing (NEW)
    # -------------------------------------------------------------------------
    if redirect_candidates and xss_candidates:
        add_result(bucket, {
            "type": "Chained Vulnerability: Advanced Phishing",
            "title": "Trust-Based Phishing via Open Redirect + XSS",
            "severity": "High",
            "confidence": "Medium",
            "url": redirect_candidates[0].get("url"),
            "description": (
                "1. **Open Redirect**: Valid domain redirects to arbitrary targets.\n"
                "2. **XSS**: Javascript execution capability.\n\n"
                "**Impact**: An attacker can construct a link to the valid domain that redirects to a malicious site, "
                "OR use XSS to overlay a fake login form on the trusted redirect page."
            ),
            "evidence": {"redirect": redirect_candidates[0], "xss": xss_candidates[0]}
        })

    # -------------------------------------------------------------------------
    # CHAIN 5: LFI + File Upload/RCE Evidence -> RCE (NEW)
    # -------------------------------------------------------------------------
    # If we have LFI and either 'Upload' capability OR 'RCE' keywords in LFI evidence
    rce_lfi = []
    for l in lfi_candidates:
        # Check if we managed to access sensitive system files or exec code
        if _check_evidence_for_keywords(l, ["root:", "boot.ini", "win.ini", "system32"]):
             # Standard LFI, check for upload pairing
             if upload_candidates:
                 add_result(bucket, {
                    "type": "Chained Vulnerability: RCE via LFI+Upload",
                    "title": "Remote Code Execution via LFI and File Upload",
                    "severity": "Critical",
                    "confidence": "High",
                    "url": l.get("url"),
                    "description": (
                        "1. **LFI Found**: Arbitrary file read/inclusion.\n"
                        "2. **File Upload Found**: Capability to upload files (even non-executable ones).\n\n"
                        "**Impact**: An attacker can upload a file containing malicious code (webshell) masquerading as an image, "
                        "then use the LFI vulnerability to include and execute it, achieving RCE."
                    ),
                    "evidence": {"lfi": l, "upload": upload_candidates[0]}
                })
                 break

