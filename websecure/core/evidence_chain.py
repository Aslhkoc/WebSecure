"""
websecure.core.evidence_chain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Evidence chain builder for WebSecure scan results.

Correlates individual findings into attack chains:
  - SQLi on /login → credential dump → account takeover chain
  - XSS → Session hijack → ATO chain
  - IDOR + SQLi → data exfiltration chain
  - SSRF → Internal network access → lateral movement

Each chain includes:
  - Root vulnerability (the entry point)
  - Consequence chain (what an attacker can do from there)
  - Combined CVSS chain score (escalated from root)
  - Attack narrative (human-readable summary)

Also exposes `EvidenceChainBuilder.annotate_results()` which enriches the
results dict in-place with chain membership information.

SOLID: Single responsibility — correlation only (no scanning, no reporting).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity → numeric (for chain score computation)
# ---------------------------------------------------------------------------

_SEV_SCORES: Dict[str, float] = {
    "critical":      9.5,
    "high":          7.5,
    "medium":        5.0,
    "low":           3.0,
    "informational": 0.5,
    "info":          0.5,
}


def _sev_score(sev: str) -> float:
    return _SEV_SCORES.get((sev or "").lower(), 3.0)


def _score_to_sev(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 1.0:
        return "Low"
    # P10 fix: was "Informational" — system-wide convention is "Info"
    # (html_dashboard, diff.py, markdown.py all key on "Info").
    return "Info"


# ---------------------------------------------------------------------------
# Chain dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ChainStep:
    """One step in an attack chain."""
    vuln_type: str
    url: str
    param: str
    severity: str
    evidence: str
    finding_id: Optional[str] = None


@dataclass
class AttackChain:
    """
    A correlated multi-step attack chain.
    chain_score is the escalated combined severity.
    """
    chain_id: str
    chain_type: str              # "sqli_ato", "xss_ato", "idor_exfil", etc.
    title: str
    steps: List[ChainStep] = field(default_factory=list)
    chain_score: float = 0.0
    chain_severity: str = "High"
    narrative: str = ""

    def add_step(self, step: ChainStep) -> None:
        self.steps.append(step)
        # Escalate chain score: chain score = max(step scores) + 0.5 per additional step
        max_score = max(_sev_score(s.severity) for s in self.steps)
        bonus = min((len(self.steps) - 1) * 0.5, 1.5)
        self.chain_score = round(min(max_score + bonus, 10.0), 1)
        self.chain_severity = _score_to_sev(self.chain_score)


# ---------------------------------------------------------------------------
# Chain correlation rules
# ---------------------------------------------------------------------------

# Format: (vuln_type_pattern, consequence_type, chain_type, title_template, narrative_template)
_CHAIN_RULES: List[Tuple[str, str, str, str, str]] = [
    (
        "SQL Injection",
        "schema_extraction",
        "sqli_exfil",
        "SQL Injection → Database Exfiltration",
        "SQL injection at {url} allows direct extraction of the database schema and "
        "potentially all stored records, including credentials.",
    ),
    (
        "SQL Injection",
        "credential",
        "sqli_ato",
        "SQL Injection → Account Takeover",
        "SQL injection at {url} enables credential extraction, allowing an attacker "
        "to authenticate as any user, including administrators.",
    ),
    (
        "SQL Injection",
        "web_shell",
        "sqli_rce",
        "SQL Injection → Remote Code Execution (Web Shell)",
        "SQL injection at {url} combined with FILE write privileges allows deployment "
        "of a web shell, granting full server-side command execution.",
    ),
    (
        "Reflected XSS",
        "session",
        "xss_ato",
        "Cross-Site Scripting → Account Takeover",
        "Reflected XSS at {url} can be used to steal session cookies or tokens via "
        "a malicious link, enabling account takeover without credentials.",
    ),
    (
        "Stored XSS",
        "session",
        "stored_xss_ato",
        "Stored XSS → Persistent Account Takeover",
        "Stored XSS at {url} executes automatically for all users visiting the page, "
        "enabling mass session hijacking and account takeover.",
    ),
    (
        "IDOR",
        "SQL Injection",
        "idor_sqli_exfil",
        "IDOR + SQL Injection → Data Exfiltration Chain",
        "An IDOR vulnerability at {url} combined with SQL injection allows an attacker "
        "to access and extract arbitrary user records.",
    ),
    (
        "SSRF",
        "internal",
        "ssrf_pivot",
        "SSRF → Internal Network Pivot",
        "SSRF at {url} allows an attacker to probe and interact with internal services "
        "not accessible from the internet, enabling lateral movement.",
    ),
    (
        "File Upload",
        "web_shell",
        "upload_rce",
        "File Upload → Remote Code Execution",
        "Unrestricted file upload at {url} allows deployment of a web shell, "
        "granting full server-side command execution.",
    ),
    (
        "Open Redirect",
        "phishing",
        "redirect_phish",
        "Open Redirect → Phishing / Token Theft",
        "Open redirect at {url} can be exploited in phishing attacks to steal "
        "authentication tokens or credentials via a trusted-looking URL.",
    ),
    (
        "SSTI",
        "rce",
        "ssti_rce",
        "Server-Side Template Injection → Remote Code Execution",
        "SSTI at {url} allows template expression evaluation leading to arbitrary "
        "code execution on the server with the web application's privileges.",
    ),
]


# ---------------------------------------------------------------------------
# Evidence Chain Builder
# ---------------------------------------------------------------------------

class EvidenceChainBuilder:
    """
    Correlates scan findings into multi-step attack chains.

    Usage:
        builder = EvidenceChainBuilder()
        chains = builder.build_chains(results["offensive"])
        results["attack_chains"] = [c.__dict__ for c in chains]
    """

    def build_chains(self, findings: List[Dict[str, Any]]) -> List[AttackChain]:
        """
        Build attack chains from a list of finding dicts.
        Applies correlation rules to find linked vulnerabilities.
        """
        chains: List[AttackChain] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        for idx_a, finding_a in enumerate(findings):
            type_a = str(finding_a.get("type") or finding_a.get("vuln_type") or "")
            url_a  = str(finding_a.get("url") or "")
            sev_a  = str(finding_a.get("severity") or "Low")

            # Feedback-loop guard: do NOT build chains from *synthetic* chain /
            # playbook findings produced by other correlators (chain_reactor).
            # Their type text ("CHAIN: … SSTI → RCE …") contains both a root-vuln
            # keyword AND a consequence keyword, so a single synthetic finding
            # would fabricate a brand-new "SSTI → RCE" chain even when no real
            # SSTI was ever detected — and do so twice, producing the duplicate
            # critical chains seen in the wild. Only correlate primary findings.
            if finding_a.get("is_chain") or finding_a.get("chain_id") or \
               type_a.upper().startswith("CHAIN") or "ZINCIR" in type_a.upper():
                continue

            for rule_vuln, rule_consequence, chain_type, title_tpl, narrative_tpl in _CHAIN_RULES:
                if rule_vuln.lower() not in type_a.lower():
                    continue

                # P8 fix: consequence_evidence was a dead variable — assigned as
                # bool or dict but never read after the if-else. Removed and
                # replaced with a direct condition on the return value.
                _same_finding_consequence = self._find_consequence(
                    finding_a, rule_consequence
                )
                if not _same_finding_consequence:
                    # Look in other findings for the consequence
                    consequence_finding = self._find_consequence_finding(
                        findings, idx_a, rule_consequence
                    )
                    if consequence_finding is None:
                        continue
                else:
                    consequence_finding = finding_a

                pair_key = (f"{idx_a}:{type_a}", chain_type)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                title = title_tpl
                narrative = narrative_tpl.format(url=url_a)

                chain_id = f"{chain_type}_{idx_a}"
                chain = AttackChain(
                    chain_id=chain_id,
                    chain_type=chain_type,
                    title=title,
                    narrative=narrative,
                )

                # Step 1: root vulnerability
                chain.add_step(ChainStep(
                    vuln_type=type_a,
                    url=url_a,
                    param=str(finding_a.get("parameter") or finding_a.get("param") or ""),
                    severity=sev_a,
                    evidence=str(finding_a.get("evidence") or "")[:200],
                ))

                # Step 2: consequence
                if consequence_finding is not finding_a:
                    type_b = str(consequence_finding.get("type") or "")
                    chain.add_step(ChainStep(
                        vuln_type=type_b or rule_consequence,
                        url=str(consequence_finding.get("url") or url_a),
                        param=str(consequence_finding.get("parameter") or ""),
                        severity=str(consequence_finding.get("severity") or "High"),
                        evidence=str(consequence_finding.get("evidence") or "")[:200],
                    ))
                else:
                    # P7 fix: when the consequence was confirmed INSIDE the root
                    # finding (_same_finding_consequence=True), the original code
                    # skipped the second step entirely — chain_score received no
                    # escalation bonus. A finding that already proves exploitation
                    # is MORE dangerous, not less. Add a synthetic step so the
                    # chain escalation arithmetic applies.
                    chain.add_step(ChainStep(
                        vuln_type=rule_consequence,
                        url=url_a,
                        param="",
                        severity=sev_a,
                        evidence="[consequence confirmed within root finding]",
                    ))

                chains.append(chain)
                _logger.info(
                    f"[Chain] Built: {chain_type} @ {url_a} "
                    f"score={chain.chain_score} ({chain.chain_severity})"
                )

        # Final dedup: collapse chains that are identical in kind and root URL.
        # Two findings of the same type at the SAME url must not yield two copies
        # of the same chain (e.g. duplicate "SSTI → RCE @ /x"). Distinct URLs are
        # preserved as separate chains.
        deduped: List[AttackChain] = []
        seen_chain_keys: Set[Tuple[str, str]] = set()
        for c in chains:
            root_url = c.steps[0].url if getattr(c, "steps", None) else ""
            key = (c.chain_type, root_url)
            if key in seen_chain_keys:
                continue
            seen_chain_keys.add(key)
            deduped.append(c)

        # Sort by chain score descending
        deduped.sort(key=lambda c: c.chain_score, reverse=True)
        return deduped

    def annotate_results(self, results: Dict[str, Any]) -> None:
        """
        Enrich results dict in-place with attack chain information.
        Adds "attack_chains" key with serialisable chain data.
        """
        offensive = results.get("offensive") or []
        if not offensive:
            return

        chains = self.build_chains(offensive)
        if not chains:
            return

        results["attack_chains"] = [
            {
                "chain_id": c.chain_id,
                "chain_type": c.chain_type,
                "title": c.title,
                "chain_score": c.chain_score,
                "chain_severity": c.chain_severity,
                "narrative": c.narrative,
                "steps": [
                    {
                        "vuln_type": s.vuln_type,
                        "url": s.url,
                        "param": s.param,
                        "severity": s.severity,
                        "evidence": s.evidence[:200],
                    }
                    for s in c.steps
                ],
            }
            for c in chains
        ]

        # Escalate severity of root findings that participate in chains
        # Build url -> chain_severity map for critical chains (score >= 9.0)
        url_to_chain_sev: Dict[str, str] = {}
        for _chain in chains:
            if _chain.chain_score >= 9.0:
                for step in _chain.steps:
                    url_to_chain_sev[step.url] = _chain.chain_severity

        for finding in offensive:
            chain_sev = url_to_chain_sev.get(finding.get("url", ""))
            if chain_sev:
                current_sev = (finding.get("severity") or "Low").lower()
                if current_sev not in ("critical",):
                    finding["chain_escalated"] = True
                    finding["chain_severity"] = chain_sev

        _logger.info(
            f"[Chain] Annotated {len(chains)} attack chains into results. "
            f"Critical chains: {sum(1 for c in chains if c.chain_severity == 'Critical')}"
        )

    def _find_consequence(self, finding: Dict[str, Any], consequence_type: str) -> bool:
        """Check if this single finding itself contains consequence evidence."""
        extra = finding.get("extra") or {}
        vuln_type = (finding.get("type") or "").lower()
        consequence = consequence_type.lower()

        if consequence == "web_shell" and (extra.get("shell_url") or "web_shell" in vuln_type):
            return True
        if consequence == "credential" and (extra.get("credentials") or "credential" in vuln_type):
            return True
        if consequence == "schema_extraction" and (extra.get("schema") or "schema" in vuln_type):
            return True
        if consequence == "rce" and ("rce" in vuln_type or "shell" in vuln_type):
            return True
        if consequence == "session" and ("ato" in vuln_type or "session" in vuln_type):
            return True
        return False

    def _find_consequence_finding(
        self,
        findings: List[Dict[str, Any]],
        root_idx: int,
        consequence_type: str,
    ) -> Optional[Dict[str, Any]]:
        """Search other findings for one that represents the consequence."""
        consequence = consequence_type.lower()
        for idx, f in enumerate(findings):
            if idx == root_idx:
                continue
            ftype = (f.get("type") or "").lower()

            # Never satisfy a consequence from a *synthetic* chain/playbook finding
            # — otherwise a real root vuln would "chain" into another correlator's
            # output (e.g. SSTI → the pre-built "CHAIN: … RCE …" string), fabricating
            # escalations that no primary scanner actually confirmed.
            if f.get("is_chain") or f.get("chain_id") or \
               ftype.startswith("chain") or "zincir" in ftype:
                continue

            # P7 fix: the generic `consequence in ftype` check ran BEFORE the
            # specific keyword overrides. For "internal", ANY finding whose type
            # contains the word "internal" (e.g. "Internal Server Error") matched,
            # never reaching the SSRF-specific check below. Specific category
            # guards now run first and use `continue` to skip the generic path.
            if consequence == "internal":
                if "ssrf" in ftype:
                    return f
                continue  # "internal" must match via SSRF only — skip generic
            if consequence == "phishing":
                if "redirect" in ftype or "open redirect" in ftype:
                    return f
                continue  # "phishing" must match via redirect only — skip generic

            if consequence in ftype:
                return f
        return None


__all__ = [
    "ChainStep",
    "AttackChain",
    "EvidenceChainBuilder",
]
