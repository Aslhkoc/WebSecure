"""
websecure.scanners.clickjacking
--------------------------------
Clickjacking & UI Redressing full scanner.

Classes:
  FrameOptionsAnalyzer      — X-Frame-Options missing/misconfigured
  CSPFrameAncestorsAnalyzer — CSP frame-ancestors missing/weak
  ClickjackingExplorer      — Interactive clickjacking surface (drag-drop, double-click, forms)
  ClickjackingScanner       — Orchestrator
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from websecure.scanners.base import BaseScanner
from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS: List[Tuple[str, str]] = [
    ("/", "homepage"),
    ("/login", "login"),
    ("/admin", "admin"),
    ("/dashboard", "dashboard"),
    ("/account", "account"),
    ("/settings", "settings"),
    ("/transfer", "transfer"),
    ("/payment", "payment"),
    ("/checkout", "checkout"),
    ("/profile", "profile"),
]

_HIGH_RISK_PATHS: Set[str] = {
    "/login", "/admin", "/dashboard", "/account",
    "/settings", "/transfer", "/payment", "/checkout", "/profile",
}

_SENSITIVE_FIELD_RE = re.compile(
    r"(amount|transfer|payment|credit|debit|balance|account|auth|password|passwd|"
    r"email|username|card|cvv|token|secret|withdraw|send)",
    re.IGNORECASE,
)

_SOCIAL_WIDGET_RE = re.compile(
    r"(fb-like|facebook\.com/plugins|twitter\.com/widgets|"
    r"platform\.twitter\.com|apis\.google\.com/js/platform)",
    re.IGNORECASE,
)

_DRAGGABLE_RE = re.compile(
    r"draggable\s*=\s*[\"']?true[\"']?",
    re.IGNORECASE,
)

_DRAG_EVENT_RE = re.compile(
    r"on(dragstart|drop|dragend|dragover|dragenter)\s*=",
    re.IGNORECASE,
)

_DBLCLICK_RE = re.compile(
    r"on(dblclick)\s*=",
    re.IGNORECASE,
)

_META_XFO_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']?x-frame-options["\']?',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _build_url(base: str, path: str) -> str:
    """Join base URL and path safely."""
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _is_high_risk(path: str) -> bool:
    return any(path.rstrip("/").startswith(p) for p in _HIGH_RISK_PATHS)


def _get_xfo(resp) -> Optional[str]:
    """Return X-Frame-Options header value (upper-cased) or None."""
    val = resp.headers.get("X-Frame-Options", "")
    return val.strip().upper() if val else None


def _get_csp(resp) -> Optional[str]:
    """Return Content-Security-Policy header value or None."""
    return resp.headers.get("Content-Security-Policy") or None


def _get_csp_report_only(resp) -> Optional[str]:
    return resp.headers.get("Content-Security-Policy-Report-Only") or None


def _parse_frame_ancestors(csp: Optional[str]) -> Optional[str]:
    """
    Extract the frame-ancestors directive value from a CSP string.
    Returns the directive value (everything after 'frame-ancestors ') or None.
    """
    if not csp:
        return None
    for directive in csp.split(";"):
        directive = directive.strip()
        if directive.lower().startswith("frame-ancestors"):
            parts = directive.split(None, 1)
            return parts[1].strip() if len(parts) > 1 else ""
    return None


def _cookies_samesite_none(resp) -> bool:
    """Return True if any Set-Cookie header uses SameSite=None."""
    for value in resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") else []:
        if "samesite=none" in value.lower():
            return True
    # requests combines multiple Set-Cookie into one header sometimes
    sc = resp.headers.get("Set-Cookie", "")
    return "samesite=none" in sc.lower()


# ===========================================================================
# 1. FrameOptionsAnalyzer
# ===========================================================================

class FrameOptionsAnalyzer(BaseScanner):
    """
    Analyze X-Frame-Options (XFO) header across common sensitive paths.

    Decision matrix:
      - Missing header on high-risk path → High
      - Missing header on other path    → Medium
      - ALLOWALL                         → Critical
      - ALLOW-FROM (deprecated)          → High
      - SAMEORIGIN                       → Informational (partial protection)
      - DENY                             → safe, no finding
      - <meta http-equiv="X-Frame-Options"> → Medium (ineffective in browsers)
    """

    name = "frame_options"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Probe target and common sensitive paths for XFO issues."""
        findings: List[Dict] = []

        for path, label in _SENSITIVE_PATHS:
            url = _build_url(target, path)
            try:
                resp = self.session.get(
                    url, timeout=7, verify=False, allow_redirects=True
                )
            except Exception as exc:
                logger.debug("[FrameOptions] %s fetch failed: %r", url, exc)
                continue

            # Skip 404 / 410 — path doesn't exist
            if resp.status_code in (404, 410):
                continue

            xfo = _get_xfo(resp)
            high_risk = _is_high_risk(path)

            finding = self._evaluate_xfo(url, xfo, resp.text, high_risk, label)
            if finding:
                findings.append(finding)
                self.report_finding(**finding)

        return findings

    def _evaluate_xfo(
        self,
        url: str,
        xfo: Optional[str],
        body: str,
        high_risk: bool,
        label: str,
    ) -> Optional[Dict]:
        """Return a finding dict for this URL/XFO combination, or None if safe."""

        # Check for ineffective meta tag regardless of header presence
        if _META_XFO_RE.search(body):
            return {
                "vuln_type": "X-Frame-Options via Meta Tag (Ineffective)",
                "url": url,
                "severity": "Medium",
                "description": (
                    f"Page '{label}' sets X-Frame-Options via a <meta> tag. "
                    "Modern browsers ignore this — the header must be sent via HTTP. "
                    "The page may still be frameable."
                ),
                "evidence": {"xfo_header": xfo, "path_label": label},
            }

        if xfo is None:
            sev = "High" if high_risk else "Medium"
            return {
                "vuln_type": "Missing X-Frame-Options Header",
                "url": url,
                "severity": sev,
                "description": (
                    f"The {label} page does not send an X-Frame-Options header. "
                    "It can be embedded in an attacker-controlled iframe, enabling clickjacking."
                ),
                "evidence": {"xfo_header": None, "path_label": label},
                "remediation": (
                    "Set 'X-Frame-Options: DENY' (preferred) or 'SAMEORIGIN'. "
                    "Also add 'frame-ancestors' in Content-Security-Policy."
                ),
            }

        if xfo == "ALLOWALL":
            return {
                "vuln_type": "X-Frame-Options: ALLOWALL (Critical Misconfiguration)",
                "url": url,
                "severity": "Critical",
                "description": (
                    f"The {label} page sends 'X-Frame-Options: ALLOWALL', "
                    "explicitly permitting framing by any origin. "
                    "This is not a standard value and disables all framing protection."
                ),
                "evidence": {"xfo_header": xfo, "path_label": label},
                "remediation": "Replace with 'X-Frame-Options: DENY' and CSP frame-ancestors 'none'.",
            }

        if xfo.startswith("ALLOW-FROM"):
            return {
                "vuln_type": "X-Frame-Options: ALLOW-FROM (Deprecated, Bypassed by Modern Browsers)",
                "url": url,
                "severity": "High",
                "description": (
                    f"The {label} page uses 'ALLOW-FROM', which is not supported in "
                    "Chrome, Firefox, or Safari. Attackers can bypass it on those browsers."
                ),
                "evidence": {"xfo_header": xfo, "path_label": label},
                "remediation": (
                    "Replace ALLOW-FROM with CSP 'frame-ancestors <origin>' "
                    "which is universally supported."
                ),
            }

        if xfo == "SAMEORIGIN":
            # Informational — still protects against cross-origin framing
            return {
                "vuln_type": "X-Frame-Options: SAMEORIGIN (Partial Protection)",
                "url": url,
                "severity": "Informational",
                "description": (
                    f"The {label} page uses SAMEORIGIN. This protects against "
                    "cross-origin framing but same-origin attackers could still frame it. "
                    "Prefer DENY for sensitive pages or use CSP frame-ancestors 'none'."
                ),
                "evidence": {"xfo_header": xfo, "path_label": label},
            }

        # DENY — properly hardened, no finding
        return None


# ===========================================================================
# 2. CSPFrameAncestorsAnalyzer
# ===========================================================================

class CSPFrameAncestorsAnalyzer(BaseScanner):
    """
    Analyze Content-Security-Policy frame-ancestors directive.

    Decision matrix:
      - No CSP at all AND no XFO          → Critical (if sensitive path)
      - CSP present but no frame-ancestors → Medium (XFO may compensate)
      - frame-ancestors *                  → Critical
      - frame-ancestors http:              → Critical
      - frame-ancestors 'none'             → Informational (hardened)
      - frame-ancestors 'self'             → Informational (partial)
      - CSP-Report-Only mode               → Medium (no enforcement)
      - Both 'none' and XFO DENY          → Info (best practice confirmed)
    """

    name = "csp_frame_ancestors"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Check CSP frame-ancestors on target and sensitive paths."""
        findings: List[Dict] = []

        for path, label in _SENSITIVE_PATHS:
            url = _build_url(target, path)
            try:
                resp = self.session.get(
                    url, timeout=7, verify=False, allow_redirects=True
                )
            except Exception as exc:
                logger.debug("[CSPFrameAncestors] %s fetch failed: %r", url, exc)
                continue

            if resp.status_code in (404, 410):
                continue

            csp = _get_csp(resp)
            csp_ro = _get_csp_report_only(resp)
            xfo = _get_xfo(resp)
            high_risk = _is_high_risk(path)

            finding = self._evaluate_csp(url, csp, csp_ro, xfo, high_risk, label)
            if finding:
                findings.append(finding)
                self.report_finding(**finding)

        return findings

    def _evaluate_csp(
        self,
        url: str,
        csp: Optional[str],
        csp_ro: Optional[str],
        xfo: Optional[str],
        high_risk: bool,
        label: str,
    ) -> Optional[Dict]:
        """Evaluate frame-ancestors status and return a finding or None."""

        fa_value = _parse_frame_ancestors(csp)
        fa_ro_value = _parse_frame_ancestors(csp_ro)

        # CSP-Report-Only mode means no actual enforcement
        if csp_ro and fa_ro_value is not None and csp is None:
            return {
                "vuln_type": "CSP frame-ancestors in Report-Only Mode (Not Enforced)",
                "url": url,
                "severity": "Medium",
                "description": (
                    f"Page '{label}' sets frame-ancestors only in "
                    "Content-Security-Policy-Report-Only. This mode reports violations "
                    "but does NOT prevent the page from being framed."
                ),
                "evidence": {
                    "csp_ro_header": csp_ro,
                    "csp_header": None,
                    "xfo_header": xfo,
                },
                "remediation": "Move frame-ancestors to the enforced Content-Security-Policy header.",
            }

        # Both CSP and XFO are hardened — confirm best practice
        if fa_value is not None:
            fa_lower = fa_value.lower().strip()

            if fa_lower == "'none'" and xfo == "DENY":
                return {
                    "vuln_type": "Clickjacking Protection: Properly Hardened",
                    "url": url,
                    "severity": "Informational",
                    "description": (
                        f"Page '{label}' has both CSP frame-ancestors 'none' and "
                        "X-Frame-Options: DENY — fully protected against clickjacking."
                    ),
                    "evidence": {"csp_frame_ancestors": fa_value, "xfo": xfo},
                }

            if fa_lower in ("'none'", "'self'"):
                sev = "Informational"
                desc = (
                    f"Page '{label}' has CSP frame-ancestors {fa_value!r} — "
                    "partial clickjacking protection in place. "
                    "Consider also adding X-Frame-Options: DENY for legacy browser support."
                )
                return {
                    "vuln_type": f"CSP frame-ancestors {fa_value} (Partial Protection)",
                    "url": url,
                    "severity": sev,
                    "description": desc,
                    "evidence": {"csp_frame_ancestors": fa_value, "xfo": xfo},
                }

            # Wildcard or scheme-only — critical misconfiguration
            if fa_lower in ("*", "http:", "https:", "http: https:"):
                return {
                    "vuln_type": f"CSP frame-ancestors '{fa_value}' (Critical — Any Origin Allowed)",
                    "url": url,
                    "severity": "Critical",
                    "description": (
                        f"Page '{label}' sets frame-ancestors to '{fa_value}', "
                        "which allows any origin to embed this page in an iframe. "
                        "This completely negates clickjacking protection."
                    ),
                    "evidence": {"csp_frame_ancestors": fa_value, "xfo": xfo},
                    "remediation": "Set frame-ancestors 'none' or list only trusted origins.",
                }

            # Non-standard / specific origin — low severity note
            return {
                "vuln_type": "CSP frame-ancestors Allows Specific Origin",
                "url": url,
                "severity": "Low",
                "description": (
                    f"Page '{label}' restricts framing to: {fa_value}. "
                    "Verify that this origin is fully trusted and cannot be taken over."
                ),
                "evidence": {"csp_frame_ancestors": fa_value, "xfo": xfo},
            }

        # No frame-ancestors directive at all
        xfo_ok = xfo in ("DENY", "SAMEORIGIN")
        if not csp:
            # No CSP at all
            if not xfo_ok and high_risk:
                return {
                    "vuln_type": "No CSP frame-ancestors + No X-Frame-Options (Dual Missing)",
                    "url": url,
                    "severity": "Critical",
                    "description": (
                        f"Sensitive page '{label}' has neither a Content-Security-Policy "
                        "frame-ancestors directive nor an X-Frame-Options header. "
                        "Clickjacking attacks are fully viable."
                    ),
                    "evidence": {"csp_header": None, "xfo_header": xfo},
                    "remediation": (
                        "Add CSP: frame-ancestors 'none' and X-Frame-Options: DENY."
                    ),
                }
            elif not xfo_ok:
                return {
                    "vuln_type": "Missing CSP frame-ancestors Directive",
                    "url": url,
                    "severity": "Medium",
                    "description": (
                        f"Page '{label}' has no CSP frame-ancestors directive. "
                        "Modern browsers rely on CSP for framing controls; X-Frame-Options "
                        "is deprecated."
                    ),
                    "evidence": {"csp_header": None, "xfo_header": xfo},
                    "remediation": "Add 'frame-ancestors' to your Content-Security-Policy.",
                }
        else:
            # CSP exists but lacks frame-ancestors
            if not xfo_ok:
                return {
                    "vuln_type": "CSP Present But Missing frame-ancestors Directive",
                    "url": url,
                    "severity": "Medium",
                    "description": (
                        f"Page '{label}' has a Content-Security-Policy header but it does not "
                        "include a frame-ancestors directive, leaving clickjacking unaddressed."
                    ),
                    "evidence": {"csp_header": csp[:200], "xfo_header": xfo},
                    "remediation": "Append \"frame-ancestors 'none'\" to the CSP header.",
                }

        return None


# ===========================================================================
# 3. ClickjackingExplorer
# ===========================================================================

class ClickjackingExplorer(BaseScanner):
    """
    Probe for advanced clickjacking attack surfaces:
      - HTML5 drag-and-drop hijacking (draggable attributes, drag events)
      - Double-click jacking (dblclick handlers on sensitive actions)
      - Form-based clickjacking (POST forms with sensitive fields on frameable pages)
      - Social widget injection (fb-like / twitter-share on frameable pages)
      - Cookie SameSite=None amplifier cross-referencing
    """

    name = "clickjacking_surface"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Probe all clickjacking attack surfaces for the target."""
        findings: List[Dict] = []
        protected_urls: Set[str] = kwargs.get("protected_urls", set())

        for path, label in _SENSITIVE_PATHS:
            url = _build_url(target, path)
            if url in protected_urls:
                logger.debug("[ClickjackingExplorer] Skipping hardened URL: %s", url)
                continue

            try:
                resp = self.session.get(
                    url, timeout=7, verify=False, allow_redirects=True
                )
            except Exception as exc:
                logger.debug("[ClickjackingExplorer] %s fetch failed: %r", url, exc)
                continue

            if resp.status_code in (404, 410):
                continue

            body = resp.text
            iframeable = self._is_iframeable(resp)
            samesite_none = _cookies_samesite_none(resp)

            # --- Drag-and-drop hijacking ---
            if iframeable and _DRAGGABLE_RE.search(body):
                finding = {
                    "vuln_type": "Drag-and-Drop Clickjacking Surface",
                    "url": url,
                    "severity": "High",
                    "description": (
                        f"Page '{label}' is iframeable and contains HTML5 draggable elements. "
                        "An attacker can overlay a transparent iframe over a file-picker or "
                        "drag-target to steal drag-and-drop payloads (e.g., files, text selections)."
                    ),
                    "evidence": {
                        "iframeable": iframeable,
                        "draggable_found": True,
                        "samesite_none": samesite_none,
                    },
                    "remediation": "Prevent framing with X-Frame-Options: DENY and CSP frame-ancestors 'none'.",
                }
                findings.append(finding)
                self.report_finding(**finding)

            if iframeable and _DRAG_EVENT_RE.search(body):
                finding = {
                    "vuln_type": "Drag-and-Drop Event Handler Hijacking Surface",
                    "url": url,
                    "severity": "High",
                    "description": (
                        f"Page '{label}' is iframeable and registers drag event handlers "
                        "(ondragstart/ondrop). Transparent iframe overlay can intercept user "
                        "drag actions intended for legitimate content."
                    ),
                    "evidence": {
                        "iframeable": iframeable,
                        "drag_events_found": True,
                        "samesite_none": samesite_none,
                    },
                    "remediation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                }
                findings.append(finding)
                self.report_finding(**finding)

            # --- Double-click jacking ---
            if iframeable and _DBLCLICK_RE.search(body):
                finding = {
                    "vuln_type": "Double-Click Jacking Surface",
                    "url": url,
                    "severity": "High",
                    "description": (
                        f"Page '{label}' is iframeable and registers dblclick event handlers. "
                        "Attackers can trick users into double-clicking a UI element (e.g., "
                        "a CAPTCHA or game) while the second click fires a hidden sensitive action."
                    ),
                    "evidence": {
                        "iframeable": iframeable,
                        "dblclick_found": True,
                        "samesite_none": samesite_none,
                    },
                    "remediation": "Prevent framing and require explicit user confirmation for sensitive actions.",
                }
                findings.append(finding)
                self.report_finding(**finding)

            # --- Form-based clickjacking ---
            post_forms = self._find_sensitive_post_forms(body)
            if iframeable and post_forms:
                amplified = "Critical" if samesite_none else "High"
                finding = {
                    "vuln_type": "Form-Based Clickjacking (POST Form on Iframeable Page)",
                    "url": url,
                    "severity": amplified,
                    "description": (
                        f"Page '{label}' is iframeable and contains a POST form with sensitive "
                        f"fields ({', '.join(post_forms)}). An attacker can overlay a transparent "
                        "iframe to trick users into submitting the form."
                        + (" SameSite=None cookies amplify this to Critical." if samesite_none else "")
                    ),
                    "evidence": {
                        "iframeable": iframeable,
                        "sensitive_fields": post_forms,
                        "samesite_none": samesite_none,
                    },
                    "remediation": (
                        "Prevent framing. Add CSRF tokens. Set cookies SameSite=Strict or Lax."
                    ),
                }
                findings.append(finding)
                self.report_finding(**finding)

            # --- Social widget injection ---
            if iframeable and _SOCIAL_WIDGET_RE.search(body):
                finding = {
                    "vuln_type": "Social Widget Injection on Iframeable Page",
                    "url": url,
                    "severity": "Medium",
                    "description": (
                        f"Page '{label}' is iframeable and embeds social widgets (Facebook Like, "
                        "Twitter Share, etc.). Attackers can frame the page over their own site to "
                        "trigger social actions (like/share) without user intent."
                    ),
                    "evidence": {
                        "iframeable": iframeable,
                        "social_widgets_found": True,
                    },
                    "remediation": "Prevent framing of pages that embed social action widgets.",
                }
                findings.append(finding)
                self.report_finding(**finding)

            # --- SameSite=None amplifier (standalone) ---
            if iframeable and samesite_none and not post_forms:
                finding = {
                    "vuln_type": "Iframeable Page with SameSite=None Cookies (Clickjacking Amplifier)",
                    "url": url,
                    "severity": "High",
                    "description": (
                        f"Page '{label}' is iframeable and sets cookies with SameSite=None. "
                        "Cross-site framing will include session cookies, making clickjacking "
                        "attacks authenticated and significantly more dangerous."
                    ),
                    "evidence": {
                        "iframeable": iframeable,
                        "samesite_none": True,
                    },
                    "remediation": (
                        "Set X-Frame-Options: DENY. Change cookies to SameSite=Strict or Lax."
                    ),
                }
                findings.append(finding)
                self.report_finding(**finding)

        return findings

    def _is_iframeable(self, resp) -> bool:
        """Return True if this response does NOT properly prevent framing."""
        xfo = _get_xfo(resp)
        csp = _get_csp(resp)
        fa = _parse_frame_ancestors(csp)

        # Hardened by XFO
        if xfo == "DENY":
            return False

        # Hardened by CSP frame-ancestors
        if fa is not None:
            fa_lower = fa.lower().strip()
            if fa_lower == "'none'":
                return False
            # wildcard / broad → still iframeable
            if fa_lower in ("*", "http:", "https:"):
                return True
            # self or specific origin → partially frameable by same-origin, flag as iframeable
            return False

        # No protection at all
        return True

    def _find_sensitive_post_forms(self, body: str) -> List[str]:
        """Return list of sensitive field names found inside POST forms."""
        sensitive_fields: List[str] = []
        form_pattern = re.compile(
            r"<form[^>]*method\s*=\s*[\"']?post[\"']?[^>]*>(.*?)</form>",
            re.IGNORECASE | re.DOTALL,
        )
        input_name_pattern = re.compile(
            r"<input[^>]*name\s*=\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        )
        for form_match in form_pattern.finditer(body):
            form_body = form_match.group(1)
            for inp_match in input_name_pattern.finditer(form_body):
                name = inp_match.group(1)
                if _SENSITIVE_FIELD_RE.search(name):
                    sensitive_fields.append(name)
        return sensitive_fields


# ===========================================================================
# 4. ClickjackingScanner — Orchestrator
# ===========================================================================

class ClickjackingScanner(BaseScanner):
    """
    Orchestrates all three clickjacking sub-scanners:
      1. FrameOptionsAnalyzer      — XFO header checks
      2. CSPFrameAncestorsAnalyzer — CSP frame-ancestors checks
      3. ClickjackingExplorer      — surface/attack vector probing

    Deduplication: pages that are fully hardened (DENY + frame-ancestors 'none')
    are excluded from the surface scan to reduce noise.
    """

    name = "clickjacking"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Run all sub-scanners and aggregate results."""
        all_findings: List[Dict] = []

        # Step 1: XFO analysis
        xfo_analyzer = FrameOptionsAnalyzer(
            session=self.session, results=self.results, debug=self.debug
        )
        xfo_findings = []
        try:
            xfo_findings = xfo_analyzer.run(target, **kwargs)
            all_findings.extend(xfo_findings)
        except Exception as exc:
            logger.warning("[ClickjackingScanner] FrameOptionsAnalyzer failed: %r", exc)

        # Step 2: CSP frame-ancestors analysis
        csp_analyzer = CSPFrameAncestorsAnalyzer(
            session=self.session, results=self.results, debug=self.debug
        )
        csp_findings = []
        try:
            csp_findings = csp_analyzer.run(target, **kwargs)
            all_findings.extend(csp_findings)
        except Exception as exc:
            logger.warning("[ClickjackingScanner] CSPFrameAncestorsAnalyzer failed: %r", exc)

        # Determine which URLs are properly hardened (skip surface scan for those)
        protected_urls: Set[str] = self._find_hardened_urls(
            xfo_findings, csp_findings
        )

        # Step 3: Surface exploration (skip fully hardened pages)
        explorer = ClickjackingExplorer(
            session=self.session, results=self.results, debug=self.debug
        )
        try:
            surface_findings = explorer.run(
                target, protected_urls=protected_urls, **kwargs
            )
            all_findings.extend(surface_findings)
        except Exception as exc:
            logger.warning("[ClickjackingScanner] ClickjackingExplorer failed: %r", exc)

        # Summary
        frameable_sensitive = sum(
            1 for f in all_findings
            if f.get("evidence", {}).get("iframeable") is True
        )
        if frameable_sensitive:
            logger.info(
                "[ClickjackingScanner] %s sensitive frameable page(s) detected for %s",
                frameable_sensitive,
                target,
            )
        self.set_summary("clickjacking", len(all_findings))

        return all_findings

    def _find_hardened_urls(
        self,
        xfo_findings: List[Dict],
        csp_findings: List[Dict],
    ) -> Set[str]:
        """
        Identify URLs reported as properly hardened in both XFO and CSP analyses.
        A URL is considered hardened only when CSP reports it as 'Properly Hardened'.
        """
        hardened: Set[str] = set()
        for f in csp_findings:
            if "Properly Hardened" in f.get("vuln_type", ""):
                hardened.add(f["url"])
        return hardened


# ===========================================================================
# Module-level adapter
# ===========================================================================

def run(
    url: str,
    session=None,
    results: dict = None,
    debug: bool = False,
    **kwargs,
) -> list:
    """Module-level entry point for the scan engine."""
    scanner = ClickjackingScanner(
        session=session, results=results or {}, debug=debug
    )
    return scanner.run(url, **kwargs)
