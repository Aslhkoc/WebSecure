"""
websecure.core.endpoint_prioritizer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Smart endpoint prioritizer for WebSecure scanners.

Ranks crawled endpoints and their parameters by attack surface value so
scanners test the most dangerous targets first — not just in crawl order.

Scoring factors:
  1. Auth endpoint bonus   — login/register/password-reset pages score highest
  2. Parameter richness    — endpoints with many parameters = broader surface
  3. Dynamic path segments — /api/v1/user/123 → higher than /about
  4. Sensitive path terms  — /admin, /api, /upload, /search, /account, /payment
  5. File extension hints  — .php, .asp, .jsp endpoints often more vulnerable
  6. Query parameter names — id, user, token, redirect, url → injection magnets
  7. HTTP method diversity — endpoints accepting POST/PUT/DELETE over GET-only

Returns a ranked list of (url, params, priority_score) for scanner consumption.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring term lists
# ---------------------------------------------------------------------------

# Path segments that indicate auth/sensitive endpoints (high priority)
_AUTH_PATH_TERMS = frozenset({
    "login", "signin", "sign-in", "logout", "signout", "sign-out",
    "register", "signup", "sign-up", "password", "passwd", "reset",
    "forgot", "verify", "confirm", "activate", "auth", "oauth",
    "token", "session", "sso", "saml", "openid", "callback",
})

# Path segments that indicate admin/management (high priority)
_ADMIN_PATH_TERMS = frozenset({
    "admin", "administrator", "manage", "management", "dashboard",
    "control", "panel", "console", "backoffice", "back-office",
    "superuser", "staff", "internal",
})

# Path segments for sensitive operations (medium-high priority)
_SENSITIVE_PATH_TERMS = frozenset({
    "api", "rest", "graphql", "json", "xml", "rpc", "service",
    "upload", "download", "export", "import", "file", "attachment",
    "search", "query", "filter", "find",
    "account", "profile", "user", "users", "member", "members",
    "payment", "billing", "checkout", "cart", "order", "invoice",
    "settings", "config", "configuration", "preferences",
    "report", "analytics", "stats", "statistics",
    "delete", "remove", "edit", "update", "create", "new",
    "redirect", "forward", "url", "link", "goto",
})

# Parameter names that are high-value injection targets
_HIGH_VALUE_PARAMS = frozenset({
    # SQL injection magnets
    "id", "user_id", "userid", "uid", "account_id", "record",
    "item", "page", "product", "category", "order", "search",
    "query", "q", "keyword", "filter", "sort", "limit", "offset",
    # Auth injection
    "username", "user", "login", "email", "password", "token",
    "session", "auth", "key", "secret", "api_key",
    # Open redirect / SSRF
    "redirect", "redirect_uri", "redirect_url", "url", "next",
    "return", "returnto", "return_to", "goto", "target", "dest",
    "destination", "ref", "referrer", "referer",
    # File inclusion
    "file", "path", "dir", "page", "template", "include",
    "module", "view", "document", "doc", "src",
    # SSTI
    "name", "title", "subject", "message", "body", "content",
    "text", "comment", "description",
})

# File extensions that typically indicate dynamic, injectable content
_HIGH_VALUE_EXTENSIONS = frozenset({
    ".php", ".php5", ".php7", ".phtml",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".jsp", ".jspx", ".do", ".action",
    ".cfm", ".cfc",
    ".rb", ".py",
    ".pl", ".cgi",
})

# Dynamic URL path segment pattern (IDs, hashes, slugs)
_DYNAMIC_SEGMENT_RE = re.compile(
    r"^\d+$"                             # pure numeric
    r"|^[0-9a-f]{8}-[0-9a-f]{4}"       # UUID
    r"|^[0-9a-f]{16,}$"                 # hex hash
    r"|^[a-z0-9][a-z0-9\-]{5,}[0-9]$", # slug with trailing digit
    re.I,
)


# ---------------------------------------------------------------------------
# Endpoint dataclass
# ---------------------------------------------------------------------------

@dataclass
class PrioritizedEndpoint:
    """A ranked endpoint with its parameters and priority score."""
    url: str
    params: List[Tuple[str, str]]    # (name, value) list
    priority_score: float            # 0.0–1.0+
    reasons: List[str] = field(default_factory=list)
    is_auth_endpoint: bool = False
    is_admin_endpoint: bool = False
    high_value_params: List[str] = field(default_factory=list)

    def param_names(self) -> List[str]:
        return [n for n, _ in self.params]


# ---------------------------------------------------------------------------
# Prioritizer
# ---------------------------------------------------------------------------

class EndpointPrioritizer:
    """
    Scores and ranks crawled endpoints for attack surface priority.

    Usage:
        ep = EndpointPrioritizer()
        ranked = ep.rank(endpoints)
        # ranked[0] = highest priority endpoint to scan first
    """

    def rank(
        self,
        endpoints: List[str],
        *,
        method_map: Optional[Dict[str, List[str]]] = None,
    ) -> List[PrioritizedEndpoint]:
        """
        Rank a list of URL strings.

        endpoints: list of full URL strings (with query params)
        method_map: optional dict url -> list of HTTP methods observed

        Returns list sorted by priority_score descending.
        """
        scored: List[PrioritizedEndpoint] = []
        for url in endpoints:
            pe = self._score(url, method_map or {})
            if pe is not None:
                scored.append(pe)

        scored.sort(key=lambda e: e.priority_score, reverse=True)
        return scored

    def _score(
        self,
        url: str,
        method_map: Dict[str, List[str]],
    ) -> Optional[PrioritizedEndpoint]:
        try:
            parsed = urlparse(url)
        except Exception:
            return None

        params = parse_qsl(parsed.query, keep_blank_values=True)
        path = (parsed.path or "").lower()
        path_segments = [s for s in path.split("/") if s]
        ext = ""
        if path_segments:
            last = path_segments[-1]
            dot_idx = last.rfind(".")
            if dot_idx != -1:
                ext = last[dot_idx:]

        score = 0.0
        reasons: List[str] = []
        is_auth = False
        is_admin = False
        high_val_params: List[str] = []

        # 1. Auth endpoint bonus (+0.50)
        if any(term in path_segments for term in _AUTH_PATH_TERMS):
            score += 0.50
            reasons.append("auth_endpoint")
            is_auth = True

        # 2. Admin endpoint bonus (+0.45)
        if any(term in path_segments for term in _ADMIN_PATH_TERMS):
            score += 0.45
            reasons.append("admin_endpoint")
            is_admin = True

        # 3. Sensitive path terms (+0.20 per term, max +0.40)
        sensitive_hits = [t for t in path_segments if t in _SENSITIVE_PATH_TERMS]
        if sensitive_hits:
            bonus = min(len(sensitive_hits) * 0.20, 0.40)
            score += bonus
            reasons.append(f"sensitive_path:{','.join(sensitive_hits[:3])}")

        # 4. Dynamic path segments (+0.15)
        dynamic_segs = [s for s in path_segments if _DYNAMIC_SEGMENT_RE.match(s)]
        if dynamic_segs:
            score += 0.15
            reasons.append(f"dynamic_segments:{len(dynamic_segs)}")

        # 5. File extension (+0.20 for PHP/ASP/JSP)
        if ext.lower() in _HIGH_VALUE_EXTENSIONS:
            score += 0.20
            reasons.append(f"extension:{ext}")

        # 6. High-value parameter names
        for pname, _ in params:
            pname_l = pname.lower()
            if pname_l in _HIGH_VALUE_PARAMS:
                score += 0.10
                if pname_l not in high_val_params:
                    high_val_params.append(pname_l)
                if len(high_val_params) == 1:
                    reasons.append(f"injection_param:{pname_l}")

        # 7. Parameter richness (+0.05 per extra param, max +0.20)
        if len(params) > 1:
            richness = min((len(params) - 1) * 0.05, 0.20)
            score += richness
            if richness > 0:
                reasons.append(f"param_count:{len(params)}")

        # 8. Non-GET methods (+0.10)
        methods = method_map.get(url, [])
        if any(m.upper() in ("POST", "PUT", "DELETE", "PATCH") for m in methods):
            score += 0.10
            reasons.append("non_get_method")

        # Minimum score for any endpoint with params
        if params and score == 0.0:
            score = 0.05

        return PrioritizedEndpoint(
            url=url,
            params=params,
            priority_score=round(score, 3),
            reasons=reasons,
            is_auth_endpoint=is_auth,
            is_admin_endpoint=is_admin,
            high_value_params=high_val_params,
        )

    def filter_high_priority(
        self,
        endpoints: List[PrioritizedEndpoint],
        *,
        min_score: float = 0.30,
    ) -> List[PrioritizedEndpoint]:
        """Return only endpoints above the minimum priority score."""
        return [e for e in endpoints if e.priority_score >= min_score]

    def group_by_priority(
        self,
        endpoints: List[PrioritizedEndpoint],
    ) -> Dict[str, List[PrioritizedEndpoint]]:
        """
        Group endpoints into priority tiers.
        Returns dict with keys: "critical", "high", "medium", "low"
        """
        groups: Dict[str, List[PrioritizedEndpoint]] = {
            "critical": [],  # score >= 0.80
            "high":     [],  # 0.50 <= score < 0.80
            "medium":   [],  # 0.25 <= score < 0.50
            "low":      [],  # score < 0.25
        }
        for ep in endpoints:
            if ep.priority_score >= 0.80:
                groups["critical"].append(ep)
            elif ep.priority_score >= 0.50:
                groups["high"].append(ep)
            elif ep.priority_score >= 0.25:
                groups["medium"].append(ep)
            else:
                groups["low"].append(ep)
        return groups


__all__ = [
    "PrioritizedEndpoint",
    "EndpointPrioritizer",
]
