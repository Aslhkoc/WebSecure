"""
websecure.core.tech_fingerprint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Pre-scan CMS/framework/tech-stack fingerprinting engine.

Identifies the technology stack before attack scanning so scanners can
select targeted payloads (e.g. Jinja2 SSTI for Flask, ORA- SQLi for Oracle)
instead of firing every possible payload blindly.

Detection sources (in priority order):
  1. HTTP response headers   (Server, X-Powered-By, X-Generator, Via)
  2. HTML body patterns      (<meta generator>, copyright strings, known paths)
  3. Cookie names            (PHPSESSID → PHP, JSESSIONID → Java/Tomcat)
  4. Response URL redirects  (wp-login.php → WordPress)
  5. Wappalyzer-style regex  (condensed version, no external deps)

Returns a TechProfile dataclass consumed by scanners to tune payload selection.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import requests as _requests

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------

# Format: (tech_label, confidence_increment, match_region)
# match_region: "headers" | "body" | "cookies" | "url"
_HEADER_SIGS: List[Tuple[str, float, str, str]] = [
    # (header_name_lower, pattern, tech_label, confidence)
    ("server",           r"Apache",              "Apache",      0.80),
    ("server",           r"nginx",               "Nginx",       0.80),
    ("server",           r"Microsoft-IIS",       "IIS",         0.90),
    ("server",           r"LiteSpeed",           "LiteSpeed",   0.80),
    ("server",           r"Caddy",               "Caddy",       0.80),
    ("x-powered-by",     r"PHP",                 "PHP",         0.90),
    ("x-powered-by",     r"ASP\.NET",            "ASP.NET",     0.90),
    ("x-powered-by",     r"Express",             "Node.js",     0.85),
    ("x-powered-by",     r"Next\.js",            "Next.js",     0.85),
    ("x-powered-by",     r"Phusion Passenger",   "Ruby",        0.75),
    ("x-generator",      r"WordPress",           "WordPress",   0.95),
    ("x-generator",      r"Drupal",              "Drupal",      0.95),
    ("x-generator",      r"Joomla",              "Joomla",      0.95),
    ("x-drupal-cache",   r"",                    "Drupal",      0.90),
    ("x-wp-total",       r"",                    "WordPress",   0.95),
    ("x-pingback",       r"",                    "WordPress",   0.80),
    ("x-aspnet-version", r"",                    "ASP.NET",     0.95),
    ("x-aspnetmvc-version", r"",                 "ASP.NET MVC", 0.95),
    ("via",              r"varnish",             "Varnish",     0.80),
    ("x-varnish",        r"",                    "Varnish",     0.90),
    ("cf-ray",           r"",                    "Cloudflare",  0.95),
    ("x-shopify-stage", r"",                     "Shopify",     0.95),
]

_BODY_SIGS: List[Tuple[str, str, float]] = [
    # (regex, tech_label, confidence)
    (r"<meta[^>]+content=['\"][^'\"]*WordPress",        "WordPress",   0.90),
    (r"/wp-content/",                                   "WordPress",   0.85),
    (r"/wp-includes/",                                  "WordPress",   0.90),
    (r"Powered by WordPress",                           "WordPress",   0.95),
    (r"<meta[^>]+content=['\"][^'\"]*Joomla",           "Joomla",      0.90),
    (r"/components/com_",                               "Joomla",      0.85),
    (r"<meta[^>]+name=['\"]generator['\"][^>]+Drupal",  "Drupal",      0.90),
    (r"Drupal\.settings",                               "Drupal",      0.85),
    (r"sites/default/files",                            "Drupal",      0.80),
    (r"__VIEWSTATE",                                    "ASP.NET",     0.90),
    (r"__EVENTVALIDATION",                              "ASP.NET",     0.90),
    (r"WebResource\.axd",                               "ASP.NET",     0.85),
    (r"<meta[^>]+generator[^>]+Magento",                "Magento",     0.90),
    (r"Mage\.Cookies",                                  "Magento",     0.85),
    (r"mage-messages",                                  "Magento",     0.80),
    (r"ng-version=",                                    "Angular",     0.90),
    (r"__NEXT_DATA__",                                  "Next.js",     0.90),
    (r"_nuxt/",                                         "Nuxt.js",     0.85),
    (r"<div id=['\"]app['\"]",                          "Vue.js",      0.60),
    (r"React\.createElement|reactroot",                 "React",       0.80),
    (r"django\.jQuery|csrfmiddlewaretoken",             "Django",      0.85),
    (r"<!--\s*Laravel\s*-->|laravel_session",           "Laravel",     0.85),
    (r"Powered by phpBB",                               "phpBB",       0.95),
    (r"vBulletin",                                      "vBulletin",   0.90),
    (r"SharePoint",                                     "SharePoint",  0.90),
    (r"<meta[^>]+generator[^>]+Shopify",                "Shopify",     0.90),
    (r"cdn\.shopify\.com",                              "Shopify",     0.90),
    (r"Powered by OpenCart",                            "OpenCart",    0.95),
    (r"PrestaShop",                                     "PrestaShop",  0.90),
    (r"WooCommerce",                                    "WooCommerce", 0.90),
]

_COOKIE_SIGS: List[Tuple[str, str, float]] = [
    # (cookie_name_pattern, tech_label, confidence)
    (r"^PHPSESSID$",         "PHP",          0.85),
    (r"^JSESSIONID$",        "Java",         0.85),
    (r"^ASP\.NET_SessionId", "ASP.NET",      0.90),
    (r"^wordpress_",         "WordPress",    0.90),
    (r"^wp-settings-",       "WordPress",    0.85),
    (r"^django_",            "Django",       0.80),
    (r"^laravel_session",    "Laravel",      0.85),
    (r"^XSRF-TOKEN$",        "Laravel/Angular", 0.65),
    (r"^rack\.session",      "Ruby/Rack",    0.80),
    (r"^_rails_",            "Rails",        0.85),
    (r"^CFID$|^CFTOKEN$",    "ColdFusion",   0.90),
    (r"^connect\.sid",       "Node.js",      0.80),
    (r"^magento",            "Magento",      0.85),
]

_DB_SIGS: List[Tuple[str, str, float]] = [
    (r"ORA-\d{4}",           "Oracle",       0.90),
    (r"MySQL",               "MySQL",        0.80),
    (r"PostgreSQL",          "PostgreSQL",   0.80),
    (r"MSSQL|SQL Server",    "MSSQL",        0.80),
    (r"SQLite",              "SQLite",       0.80),
    (r"MongoDB",             "MongoDB",      0.80),
]


# ---------------------------------------------------------------------------
# TechProfile dataclass
# ---------------------------------------------------------------------------

@dataclass
class TechProfile:
    """
    Detected technology stack for a target URL.
    Used by scanners to select targeted payloads.
    """
    url: str
    technologies: Dict[str, float] = field(default_factory=dict)  # tech -> confidence
    cms: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    database: Optional[str] = None
    server: Optional[str] = None
    waf: Optional[str] = None
    raw_headers: Dict[str, str] = field(default_factory=dict)

    # Recommended payload categories for this stack
    sqli_dialects: List[str] = field(default_factory=list)   # ["mysql", "mssql", ...]
    ssti_engines: List[str] = field(default_factory=list)     # ["jinja2", "twig", ...]
    xss_contexts: List[str] = field(default_factory=list)     # ["html", "attr", "script"]

    def has_tech(self, *techs: str) -> bool:
        for t in techs:
            if any(t.lower() in k.lower() for k in self.technologies):
                return True
        return False

    def top_technologies(self, n: int = 5) -> List[str]:
        return sorted(self.technologies, key=lambda t: self.technologies[t], reverse=True)[:n]

    def confidence(self, tech: str) -> float:
        for k, v in self.technologies.items():
            if tech.lower() in k.lower():
                return v
        return 0.0


# ---------------------------------------------------------------------------
# Fingerprinter
# ---------------------------------------------------------------------------

class TechFingerprinter:
    """
    CMS/framework/tech-stack fingerprinting engine.

    Usage:
        fp = TechFingerprinter(session)
        profile = fp.fingerprint(url)
        # profile.sqli_dialects → ["mysql", "mariadb"]
        # profile.ssti_engines  → ["jinja2"]
    """

    _CMS_TECH_MAP: Dict[str, str] = {
        "WordPress": "php",
        "Joomla": "php",
        "Drupal": "php",
        "Laravel": "php",
        "Magento": "php",
        "OpenCart": "php",
        "PrestaShop": "php",
        "WooCommerce": "php",
        "phpBB": "php",
        "vBulletin": "php",
        "Django": "python",
        "Flask": "python",
        "Next.js": "node",
        "Nuxt.js": "node",
        "Angular": "node",
        "Express": "node",
        "Rails": "ruby",
        "ASP.NET": "aspnet",
        "ASP.NET MVC": "aspnet",
        "SharePoint": "aspnet",
        "Shopify": "ruby",
    }

    # SQLi dialect recommendations by server/language
    _SQLI_DIALECT_MAP: Dict[str, List[str]] = {
        "php": ["mysql", "mariadb", "postgresql", "mssql"],
        "aspnet": ["mssql", "mysql"],
        "python": ["postgresql", "mysql", "sqlite"],
        "ruby": ["postgresql", "mysql", "sqlite"],
        "node": ["mysql", "postgresql", "mongodb"],
        "java": ["oracle", "mssql", "mysql", "postgresql"],
        "Oracle": ["oracle"],
        "MySQL": ["mysql", "mariadb"],
        "MSSQL": ["mssql"],
        "PostgreSQL": ["postgresql"],
        "MongoDB": ["mongodb"],
    }

    # SSTI engine recommendations by language/framework
    _SSTI_ENGINE_MAP: Dict[str, List[str]] = {
        "Django": ["django"],
        "Flask": ["jinja2"],
        "Laravel": ["twig", "blade"],
        "Joomla": ["twig"],
        "Drupal": ["twig"],
        "WordPress": ["smarty"],
        "python": ["jinja2", "mako"],
        "ruby": ["erb", "haml"],
        "java": ["freemarker", "velocity", "thymeleaf"],
        "aspnet": ["razor"],
        "node": ["nunjucks", "handlebars", "pug"],
        "php": ["twig", "smarty", "blade"],
    }

    # WAF detection
    _WAF_SIGS: List[Tuple[str, str, str]] = [
        ("server",               r"(?i)cloudflare",     "Cloudflare"),
        ("x-sucuri-id",          r"",                   "Sucuri"),
        ("x-sucuri-cache",       r"",                   "Sucuri"),
        ("server",               r"(?i)sucuri",         "Sucuri"),
        ("x-firewall-protection", r"",                  "Imperva"),
        ("x-powered-by",         r"(?i)imunify",        "Imunify360"),
        ("server",               r"(?i)akamai",         "Akamai"),
        ("x-akamai-transformed", r"",                   "Akamai"),
        ("server",               r"(?i)barracuda",      "Barracuda"),
        ("x-sqreen-",            r"",                   "Sqreen"),
        ("x-datadome",           r"",                   "DataDome"),
    ]

    def __init__(self, session: Any) -> None:
        self.session = session
        # Pre-compile body sigs
        self._body_compiled = [
            (re.compile(pat, re.I), label, conf)
            for pat, label, conf in _BODY_SIGS
        ]
        self._cookie_compiled = [
            (re.compile(pat, re.I), label, conf)
            for pat, label, conf in _COOKIE_SIGS
        ]
        self._db_compiled = [
            (re.compile(pat, re.I), label, conf)
            for pat, label, conf in _DB_SIGS
        ]

    def fingerprint(self, url: str, *, timeout: int = 10) -> TechProfile:
        """
        Fingerprint the target URL and return a TechProfile.
        Performs 1 HTTP GET; all detection is done on that single response.
        """
        profile = TechProfile(url=url)

        try:
            resp = self.session.get(url, timeout=timeout, allow_redirects=True)
        except Exception as exc:
            _logger.debug(f"[Fingerprint] Failed to fetch {url}: {exc!r}")
            return profile

        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text or ""
        cookies = {c.name: c.value for c in resp.cookies}
        profile.raw_headers = hdrs

        self._detect_headers(profile, hdrs)
        self._detect_body(profile, body)
        self._detect_cookies(profile, cookies)
        self._detect_db_from_body(profile, body)
        self._detect_waf(profile, hdrs)
        self._derive_stack(profile)

        _logger.info(
            f"[Fingerprint] {url} → "
            f"top={profile.top_technologies(3)} "
            f"sqli={profile.sqli_dialects} "
            f"ssti={profile.ssti_engines}"
        )
        return profile

    def _add_tech(self, profile: TechProfile, tech: str, conf: float) -> None:
        existing = profile.technologies.get(tech, 0.0)
        # Confidence merging: P(A or B) = 1 - (1-A)(1-B)
        merged = 1.0 - (1.0 - existing) * (1.0 - conf)
        profile.technologies[tech] = round(min(merged, 1.0), 3)

    def _detect_headers(self, profile: TechProfile, hdrs: Dict[str, str]) -> None:
        for hdr_name, pattern, tech, conf in _HEADER_SIGS:
            val = hdrs.get(hdr_name, "")
            if not val:
                continue
            if pattern == "" or re.search(pattern, val, re.I):
                self._add_tech(profile, tech, conf)
                if hdr_name == "server" and not profile.server:
                    profile.server = val[:60]

    def _detect_body(self, profile: TechProfile, body: str) -> None:
        for pat, tech, conf in self._body_compiled:
            if pat.search(body):
                self._add_tech(profile, tech, conf)

    def _detect_cookies(self, profile: TechProfile, cookies: Dict[str, str]) -> None:
        for cookie_name in cookies:
            for pat, tech, conf in self._cookie_compiled:
                if pat.search(cookie_name):
                    self._add_tech(profile, tech, conf)

    def _detect_db_from_body(self, profile: TechProfile, body: str) -> None:
        for pat, tech, conf in self._db_compiled:
            if pat.search(body):
                self._add_tech(profile, tech, conf)
                if not profile.database:
                    profile.database = tech

    def _detect_waf(self, profile: TechProfile, hdrs: Dict[str, str]) -> None:
        for hdr_name, pattern, waf in self._WAF_SIGS:
            val = hdrs.get(hdr_name, "")
            if not val and hdr_name in hdrs:
                val = hdrs[hdr_name]
            if pattern == "" and hdr_name in hdrs:
                profile.waf = waf
                self._add_tech(profile, f"WAF:{waf}", 0.90)
                return
            if val and pattern and re.search(pattern, val, re.I):
                profile.waf = waf
                self._add_tech(profile, f"WAF:{waf}", 0.90)
                return

    def _derive_stack(self, profile: TechProfile) -> None:
        """Derive higher-level attributes and payload recommendations from detected techs."""
        techs = profile.technologies

        # CMS
        for cms in ["WordPress", "Joomla", "Drupal", "Magento", "Shopify",
                    "OpenCart", "PrestaShop", "phpBB", "vBulletin", "SharePoint"]:
            if techs.get(cms, 0) >= 0.75:
                profile.cms = cms
                break

        # Language
        lang_order = [
            ("PHP", "php"), ("ASP.NET", "aspnet"), ("ASP.NET MVC", "aspnet"),
            ("Node.js", "node"), ("Python", "python"), ("Ruby", "ruby"), ("Java", "java"),
        ]
        for tech, lang in lang_order:
            if techs.get(tech, 0) >= 0.60:
                profile.language = lang
                break
        # Infer from CMS
        if not profile.language and profile.cms:
            profile.language = self._CMS_TECH_MAP.get(profile.cms)

        # Framework
        for fw in ["Django", "Flask", "Laravel", "Rails", "Angular", "React",
                   "Next.js", "Nuxt.js", "Express"]:
            if techs.get(fw, 0) >= 0.65:
                profile.framework = fw
                break

        # SQLi dialects
        dialects: List[str] = []
        if profile.database:
            dialects = self._SQLI_DIALECT_MAP.get(profile.database, [])
        if not dialects and profile.language:
            dialects = self._SQLI_DIALECT_MAP.get(profile.language, [])
        if not dialects:
            dialects = ["mysql", "mssql", "postgresql"]  # universal default
        profile.sqli_dialects = dialects

        # SSTI engines
        engines: List[str] = []
        for fw in [profile.framework, profile.cms, profile.language]:
            if fw and fw in self._SSTI_ENGINE_MAP:
                engines = self._SSTI_ENGINE_MAP[fw]
                break
        if not engines:
            engines = ["jinja2", "twig", "freemarker", "velocity"]
        profile.ssti_engines = engines

        # XSS contexts — always relevant
        profile.xss_contexts = ["html", "attr", "script", "comment", "style"]


__all__ = [
    "TechProfile",
    "TechFingerprinter",
]
