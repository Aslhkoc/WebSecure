"""
websecure.scanners.clickjacking
--------------------------------
Clickjacking & UI Redressing full scanner.

Classes:
  FrameOptionsAnalyzer      — X-Frame-Options missing/misconfigured
  CSPFrameAncestorsAnalyzer — CSP frame-ancestors missing/weak
  ClickjackingExplorer      — Interactive clickjacking surface (drag-drop, double-click, forms)
  ClickjackingPoCGenerator  — Generate HTML PoC for frameable pages
  FrameBustingBypassProber  — Detect frame-busting JS and sandbox bypass
  DoubleClickJackingProber  — Detect ondblclick on sensitive actions
  ClickjackingScanner       — Orchestrator
"""
from __future__ import annotations

import base64
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

from websecure.scanners.base import BaseScanner

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

_FRAME_BUST_JS_RE = re.compile(
    r"(top\s*[!=]=\s*self|self\s*[!=]=\s*top|top\.location|parent\.location|"
    r"window\.top\s*[!=]=\s*window\.self|frameElement)",
    re.IGNORECASE,
)

_POC_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head><style>
iframe {{ opacity: 0.0; position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 2; }}
.decoy {{ position: absolute; top: 200px; left: 300px; z-index: 1; font-size: 20px; }}
</style></head>
<body>
<div class="decoy">Click here to win a prize!</div>
<iframe src="{target_url}"></iframe>
</body></html>
"""

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
    # urllib3 raw response exposes duplicate headers individually via getlist()
    # requests' CaseInsensitiveDict does not support getlist(), so use raw
    try:
        raw_cookies = resp.raw.headers.getlist("set-cookie")
        if raw_cookies:
            return any("samesite=none" in v.lower() for v in raw_cookies)
    except Exception:
        pass
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
            if not self.path_exists(resp):  # soft-404 baseline: catch-all hedefte hayalet-sayfa FP'sini önler
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

            if not self.path_exists(resp):  # soft-404 baseline: catch-all hedefte hayalet-sayfa FP'sini önler
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

            if not self.path_exists(resp):  # soft-404 baseline: catch-all hedefte hayalet-sayfa FP'sini önler
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
# 4. ClickjackingPoCGenerator
# ===========================================================================

class ClickjackingPoCGenerator(BaseScanner):
    """
    Generate a working HTML Proof-of-Concept for pages that are frameable
    (X-Frame-Options missing or weak).

    The PoC uses a transparent iframe overlay technique. The generated HTML
    is base64-encoded and attached to the finding evidence as ``poc_html``
    so the user can decode and open it in a browser.
    """

    name = "clickjacking_poc"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Generate PoC for vulnerable (frameable) paths."""
        findings: List[Dict] = []

        for path, label in _SENSITIVE_PATHS:
            url = _build_url(target, path)
            try:
                resp = self.session.get(
                    url, timeout=7, verify=False, allow_redirects=True
                )
            except Exception as exc:
                logger.debug("[PoCGenerator] %s fetch failed: %r", url, exc)
                continue

            if not self.path_exists(resp):  # soft-404 baseline: catch-all hedefte hayalet-sayfa FP'sini önler
                continue

            xfo = _get_xfo(resp)
            csp = _get_csp(resp)
            fa = _parse_frame_ancestors(csp)

            # Only generate PoC when the page is actually frameable
            is_frameable = self._is_frameable(xfo, fa)
            if not is_frameable:
                continue

            poc_html = _POC_TEMPLATE.format(target_url=url)
            poc_b64 = base64.b64encode(poc_html.encode("utf-8")).decode("ascii")

            severity = "High" if _is_high_risk(path) else "Medium"
            finding = {
                "vuln_type": "Clickjacking PoC Generated",
                "url": url,
                "severity": severity,
                "description": (
                    f"Page '{label}' is iframeable (XFO: {xfo or 'missing'}, "
                    f"CSP frame-ancestors: {fa or 'missing'}). "
                    "A Proof-of-Concept HTML file has been generated. "
                    "Decode the base64 'poc_html' field and open it in a browser to verify."
                ),
                "evidence": {
                    "xfo_header": xfo,
                    "csp_frame_ancestors": fa,
                    "path_label": label,
                    "poc_html": poc_b64,
                },
                "remediation": (
                    "Add 'X-Frame-Options: DENY' and CSP 'frame-ancestors: none' "
                    "to prevent this page from being embedded in an iframe."
                ),
            }
            findings.append(finding)
            self.report_finding(**finding)

        return findings

    @staticmethod
    def _is_frameable(xfo: Optional[str], fa: Optional[str]) -> bool:
        """Return True if neither XFO nor CSP frame-ancestors properly protects the page."""
        if xfo == "DENY":
            return False
        if fa is not None:
            fa_lower = fa.lower().strip()
            if fa_lower == "'none'":
                return False
            # wildcard / scheme-only → still frameable
            if fa_lower in ("*", "http:", "https:"):
                return True
            return False
        # No frame-ancestors directive
        if xfo in ("SAMEORIGIN",):
            # Partially protected — still frameable by same-origin, flag as frameable
            return True
        return True


# ===========================================================================
# 5. FrameBustingBypassProber
# ===========================================================================

class FrameBustingBypassProber(BaseScanner):
    """
    Detect frame-busting JavaScript and test whether it can be bypassed.

    Frame-busting JS (e.g. ``if (top !== self) { top.location = self.location; }``)
    can be defeated by framing the page with a sandboxed iframe that lacks the
    ``allow-top-navigation`` permission:

        <iframe sandbox="allow-forms allow-scripts" src="target">

    This prober:
      1. Fetches the page body and searches for frame-busting JS patterns.
      2. If found, verifies the page is actually frameable (XFO/CSP).
      3. Reports High if sandbox bypass is viable (frameable + frame-bust JS present).
    """

    name = "frame_busting_bypass"

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Probe for frame-busting bypass opportunities."""
        findings: List[Dict] = []

        for path, label in _SENSITIVE_PATHS:
            url = _build_url(target, path)
            try:
                resp = self.session.get(
                    url, timeout=7, verify=False, allow_redirects=True
                )
            except Exception as exc:
                logger.debug("[FrameBustBypass] %s fetch failed: %r", url, exc)
                continue

            if not self.path_exists(resp):  # soft-404 baseline: catch-all hedefte hayalet-sayfa FP'sini önler
                continue

            body = resp.text
            xfo = _get_xfo(resp)
            csp = _get_csp(resp)
            fa = _parse_frame_ancestors(csp)

            has_frame_bust = bool(_FRAME_BUST_JS_RE.search(body))
            if not has_frame_bust:
                continue

            # Even with frame-busting JS, check if framing is blocked at header level
            # If headers allow framing, sandbox bypass is viable
            framing_allowed_by_headers = ClickjackingPoCGenerator._is_frameable(xfo, fa)

            if framing_allowed_by_headers:
                # sandbox="allow-forms allow-scripts" blocks top.location reassignment
                # because allow-top-navigation is absent
                finding = {
                    "vuln_type": "Frame-Busting Bypass via Sandboxed iframe",
                    "url": url,
                    "severity": "High",
                    "description": (
                        f"Page '{label}' uses frame-busting JavaScript "
                        "(top !== self / top.location guard) but is still frameable "
                        "via HTTP headers (XFO: {xfo}, CSP frame-ancestors: {fa}). "
                        "An attacker can use:\n"
                        '  <iframe sandbox="allow-forms allow-scripts" src="{url}">\n'
                        "The 'sandbox' attribute without 'allow-top-navigation' prevents "
                        "the frame-busting script from navigating top.location, "
                        "nullifying the protection."
                    ).format(xfo=xfo or "missing", fa=fa or "missing", url=url),
                    "evidence": {
                        "frame_bust_js_detected": True,
                        "xfo_header": xfo,
                        "csp_frame_ancestors": fa,
                        "path_label": label,
                        "bypass_technique": (
                            'sandbox="allow-forms allow-scripts" (no allow-top-navigation)'
                        ),
                    },
                    "remediation": (
                        "Replace JavaScript frame-busting with server-side headers: "
                        "'X-Frame-Options: DENY' and CSP 'frame-ancestors: none'. "
                        "JS-based frame-busting is unreliable and bypassable."
                    ),
                }
                findings.append(finding)
                self.report_finding(**finding)
            else:
                # Headers protect framing but JS redundancy is noted
                finding = {
                    "vuln_type": "Frame-Busting JS Present (Headers Already Protect)",
                    "url": url,
                    "severity": "Informational",
                    "description": (
                        f"Page '{label}' uses frame-busting JS and is also protected "
                        "by HTTP headers (defense-in-depth). No bypass is viable."
                    ),
                    "evidence": {
                        "frame_bust_js_detected": True,
                        "xfo_header": xfo,
                        "csp_frame_ancestors": fa,
                        "path_label": label,
                    },
                }
                findings.append(finding)
                self.report_finding(**finding)

        return findings


# ===========================================================================
# 6. DoubleClickJackingProber
# ===========================================================================

class DoubleClickJackingProber(BaseScanner):
    """
    Detect double-click jacking attack surfaces.

    Pages with ``ondblclick`` event handlers on or near sensitive actions
    (payment, delete, admin, confirm) are vulnerable to double-click jacking:
    an attacker overlays a game/CAPTCHA so the first click positions the cursor
    and the second click triggers the hidden sensitive action.
    """

    name = "double_click_jacking"

    # Sensitive action keywords in ondblclick handler values
    _SENSITIVE_ACTION_RE = re.compile(
        r"ondblclick\s*=\s*[\"'][^\"']*"
        r"(?:pay|payment|delete|remove|transfer|send|admin|confirm|"
        r"submit|purchase|checkout|withdraw|approve|ban|reset)[^\"']*[\"']",
        re.IGNORECASE,
    )

    # Generic ondblclick on form/button/input elements
    _DBLCLICK_ELEMENT_RE = re.compile(
        r"<(?:button|input|a|form)[^>]*ondblclick\s*=",
        re.IGNORECASE,
    )

    def run(self, target: str, **kwargs) -> List[Dict]:
        """Probe all sensitive paths for double-click jacking surfaces."""
        findings: List[Dict] = []

        for path, label in _SENSITIVE_PATHS:
            url = _build_url(target, path)
            try:
                resp = self.session.get(
                    url, timeout=7, verify=False, allow_redirects=True
                )
            except Exception as exc:
                logger.debug("[DblClickJacking] %s fetch failed: %r", url, exc)
                continue

            if not self.path_exists(resp):  # soft-404 baseline: catch-all hedefte hayalet-sayfa FP'sini önler
                continue

            body = resp.text
            xfo = _get_xfo(resp)
            csp = _get_csp(resp)
            fa = _parse_frame_ancestors(csp)
            iframeable = ClickjackingPoCGenerator._is_frameable(xfo, fa)

            # Check for sensitive ondblclick handlers
            sensitive_match = self._SENSITIVE_ACTION_RE.search(body)
            generic_match = self._DBLCLICK_ELEMENT_RE.search(body)

            if sensitive_match:
                severity = "Critical" if iframeable else "High"
                finding = {
                    "vuln_type": "Double-Click Jacking — Sensitive Action via ondblclick",
                    "url": url,
                    "severity": severity,
                    "description": (
                        f"Page '{label}' has an ondblclick handler tied to a sensitive action "
                        f"(payment, delete, admin, confirm, etc.). "
                        + ("The page is also iframeable, enabling a complete double-click jacking attack. "
                           if iframeable else
                           "The page is framing-protected but the ondblclick handler is still a risk "
                           "if protection is ever weakened.")
                        + " An attacker overlays the iframe and tricks the user into double-clicking, "
                        "triggering the sensitive action."
                    ),
                    "evidence": {
                        "iframeable": iframeable,
                        "xfo_header": xfo,
                        "csp_frame_ancestors": fa,
                        "path_label": label,
                        "dblclick_snippet": sensitive_match.group(0)[:200],
                    },
                    "remediation": (
                        "Avoid ondblclick for sensitive actions. "
                        "Require explicit single-click confirmation dialogs. "
                        "Add X-Frame-Options: DENY and CSP frame-ancestors: none."
                    ),
                }
                findings.append(finding)
                self.report_finding(**finding)

            elif generic_match and iframeable:
                finding = {
                    "vuln_type": "Double-Click Jacking Surface — ondblclick on Interactive Element",
                    "url": url,
                    "severity": "Medium",
                    "description": (
                        f"Page '{label}' is iframeable and has ondblclick handlers on "
                        "interactive elements (button/input/a/form). "
                        "Verify whether these actions are sensitive; if so, this is exploitable."
                    ),
                    "evidence": {
                        "iframeable": iframeable,
                        "xfo_header": xfo,
                        "csp_frame_ancestors": fa,
                        "path_label": label,
                        "dblclick_snippet": generic_match.group(0)[:200],
                    },
                    "remediation": (
                        "Review all ondblclick-triggered actions for sensitivity. "
                        "Add framing protection headers."
                    ),
                }
                findings.append(finding)
                self.report_finding(**finding)

        return findings


# ===========================================================================
# 7. ClickjackingScanner — Orchestrator
# ===========================================================================

class ClickjackingScanner(BaseScanner):
    """
    Orchestrates all clickjacking sub-scanners:
      1. FrameOptionsAnalyzer       — XFO header checks
      2. CSPFrameAncestorsAnalyzer  — CSP frame-ancestors checks
      3. ClickjackingExplorer       — surface/attack vector probing
      4. ClickjackingPoCGenerator   — HTML PoC for frameable pages
      5. FrameBustingBypassProber   — JS frame-busting bypass detection
      6. DoubleClickJackingProber   — ondblclick sensitive action detection

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

        # Step 4: PoC generation for frameable pages
        poc_generator = ClickjackingPoCGenerator(
            session=self.session, results=self.results, debug=self.debug
        )
        try:
            poc_findings = poc_generator.run(target, **kwargs)
            all_findings.extend(poc_findings)
        except Exception as exc:
            logger.warning("[ClickjackingScanner] ClickjackingPoCGenerator failed: %r", exc)

        # Step 5: Frame-busting bypass detection
        fb_prober = FrameBustingBypassProber(
            session=self.session, results=self.results, debug=self.debug
        )
        try:
            fb_findings = fb_prober.run(target, **kwargs)
            all_findings.extend(fb_findings)
        except Exception as exc:
            logger.warning("[ClickjackingScanner] FrameBustingBypassProber failed: %r", exc)

        # Step 6: Double-click jacking detection
        dblclick_prober = DoubleClickJackingProber(
            session=self.session, results=self.results, debug=self.debug
        )
        try:
            dblclick_findings = dblclick_prober.run(target, **kwargs)
            all_findings.extend(dblclick_findings)
        except Exception as exc:
            logger.warning("[ClickjackingScanner] DoubleClickJackingProber failed: %r", exc)

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
