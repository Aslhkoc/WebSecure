# -*- coding: utf-8 -*-
"""
websecure.core.profiles
-----------------------
Tarama Profili Sistemi v2.0

Mimari (SOLID / OOP):
  ScanProfile (ABC)       : Tum profillerin soyut taban sinifi (Template Method)
  ProfileRegistry         : Singleton kayit + lookup (Registry Deseni)
  ProfileLoader           : YAML dosyalarindan ozel profil yukleme
  AdaptiveProfileEngine   : Hedef metriklerine gore profil parametrelerini canli ayarlar
  ProfileComposer         : Iki profili birlestirir (Decorator Deseni)
  ProfileValidator        : YAML sema dogrulama

Built-in Profiller:
  AggressiveProfile    : Tam kapsam, maksimum hiz
  StealthProfile       : Tam kapsam, yavas + WAF bypass
  CICDProfile          : CI/CD icin optimize (< 5 dk, kritik once)
  BugBountyProfile     : Minimum false positive, sadece Critical/High
  ComplianceProfile    : OWASP Top 10 odakli (PCI-DSS, HIPAA, ISO 27001)
  APIOnlyProfile       : Sadece REST/GraphQL/gRPC yuzey
  AuthenticatedProfile : Login -> token -> tam tarama sablonu
  CustomProfile        : YAML'dan yuklenen ozel profil
"""
from __future__ import annotations

import logging
import statistics
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

_ALL_MODULES = [
    "xss", "sqli", "ssrf", "xxe", "cmdi", "ssti", "csrf", "crlf_injection",
    "open_redirect", "idor", "race_condition", "file_upload", "dom_xss",
    "lfi", "request_smuggling", "mass_assignment", "jwt_attacks", "nosqli",
    "auth_scanners", "cors", "headers", "tls", "graphql", "websocket_fuzz",
    "prototype_pollution", "js_analyzer", "session_scanner", "subdomain_takeover",
    "waf_fingerprint", "oast", "nmap", "subdomain", "passive_recon",
    "infrastructure", "owasp",
]

_OWASP_TOP10_MODULES = [
    "sqli",          # A01 - Injection
    "auth_scanners", # A02 - Broken Authentication
    "xss",           # A03 - XSS
    "idor",          # A01 - Broken Access Control
    "ssrf",          # A10 - SSRF
    "xxe",           # A05 - Security Misconfiguration / XXE
    "file_upload",   # A08 - Insecure Deserialization / Upload
    "cors",          # A05 - Security Misconfiguration
    "headers",       # A05 - Security Misconfiguration
    "tls",           # A02 - Cryptographic Failures
    "jwt_attacks",   # A02 - Broken Authentication
    "csrf",          # A01 - Broken Access Control
]

_API_MODULES = [
    "sqli", "nosqli", "ssrf", "xxe", "idor", "auth_scanners",
    "jwt_attacks", "mass_assignment", "graphql", "cors", "race_condition",
    "cmdi", "ssti", "open_redirect", "oast",
]

_FAST_MODULES = [
    "sqli", "xss", "ssrf", "cmdi", "idor", "auth_scanners",
    "headers", "cors", "jwt_attacks",
]


# ---------------------------------------------------------------------------
# Veri Sinifi: Profil Metaveri
# ---------------------------------------------------------------------------

@dataclass
class ProfileMetadata:
    name:        str
    profile_id:  str
    description: str
    version:     str = "1.0"
    author:      str = "WebSecure"
    tags:        List[str] = field(default_factory=list)
    min_severity: str = "info"   # info / low / medium / high / critical
    estimated_duration_min: int = 0
    yaml_path:   Optional[str] = None


# ---------------------------------------------------------------------------
# Veri Sinifi: Adaptif Olcumler
# ---------------------------------------------------------------------------

@dataclass
class AdaptiveMetrics:
    avg_response_ms:  float = 0.0
    p95_response_ms:  float = 0.0
    error_rate:       float = 0.0   # 0.0 - 1.0
    block_rate:       float = 0.0   # 403/429 orani
    waf_detected:     bool  = False
    server_banner:    str   = ""
    recommended_rps:  float = 10.0
    recommended_concurrency: int = 5

    @property
    def is_slow_target(self) -> bool:
        return self.avg_response_ms > 2000

    @property
    def is_waf_protected(self) -> bool:
        return self.waf_detected or self.block_rate > 0.1


# ---------------------------------------------------------------------------
# ScanProfile — Soyut Taban Sinifi
# ---------------------------------------------------------------------------

class ScanProfile(ABC):
    """
    Tum tarama profillerinin soyut taban sinifi.

    Alt siniflar apply() metodunu implement eder:
      - cfg dict'ini alir, degistirir, geri doner
      - PRIORITY_MODULES: once calistirilacak moduller
      - EXCLUDED_MODULES: hicbir kosulda calistirilmayacak moduller
    """

    NAME:             str = "base"
    DESCRIPTION:      str = ""
    VERSION:          str = "1.0"
    PRIORITY_MODULES: List[str] = []
    EXCLUDED_MODULES: List[str] = []
    MIN_SEVERITY:     str = "info"
    TAGS:             List[str] = []
    ESTIMATED_MIN:    int = 0

    @abstractmethod
    def apply(self, cfg: dict) -> dict:
        """Profil ayarlarini cfg'ye uygula ve geri don."""
        ...

    def metadata(self) -> ProfileMetadata:
        return ProfileMetadata(
            name=self.NAME,
            profile_id=self.NAME.lower().replace(" ", "_"),
            description=self.DESCRIPTION,
            version=self.VERSION,
            tags=self.TAGS,
            min_severity=self.MIN_SEVERITY,
            estimated_duration_min=self.ESTIMATED_MIN,
        )

    # ── Paylasilmis yardimci metotlar ────────────────────────────────────

    def _enable_modules(self, cfg: dict, modules: List[str]) -> None:
        off = cfg.setdefault("offensive", {})
        off["enabled"] = True
        for mod in modules:
            off.setdefault(mod, {})["enabled"] = True

    def _disable_modules(self, cfg: dict, modules: List[str]) -> None:
        off = cfg.setdefault("offensive", {})
        for mod in modules:
            off.setdefault(mod, {})["enabled"] = False

    def _enable_all_modules(self, cfg: dict) -> None:
        self._enable_modules(cfg, _ALL_MODULES)

    def _set_fuzz(self, cfg: dict, *, rps: int, concurrency: int,
                  per_param: int, max_total: int) -> None:
        fz = cfg.setdefault("fuzz", {})
        fz["rps"] = rps
        fz["concurrency"] = concurrency
        fz["per_param"] = per_param
        fz["max_total"] = max_total

    def _set_http(self, cfg: dict, *, timeout: int = 15,
                  retries: int = 2, rps: float = 10.0) -> None:
        h = cfg.setdefault("http", {})
        h["timeout_seconds"] = timeout
        h["retries"] = retries
        ab = cfg.setdefault("anti_blocking", {}).setdefault("http", {})
        ab["rps"] = rps

    def _set_filter(self, cfg: dict, min_severity: str) -> None:
        cfg.setdefault("filter", {})["min_severity"] = min_severity

    def _set_tools(self, cfg: dict, *,
                   sqlmap: bool = True, nuclei: bool = True,
                   nmap: bool = True, ffuf: bool = True) -> None:
        for tool, enabled in [("_sqlmap", sqlmap), ("_nuclei", nuclei),
                               ("_nmap", nmap), ("_ffuf", ffuf)]:
            cfg.setdefault(tool, {})["enabled"] = enabled

    def _mark_profile(self, cfg: dict) -> None:
        cfg.setdefault("settings", {})["scan_profile"] = self.NAME
        cfg.setdefault("_profile", {})["selected"] = self.NAME
        cfg["_scan_mode"] = self.NAME

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.NAME!r}>"


# ---------------------------------------------------------------------------
# Built-in Profil: Aggressive
# ---------------------------------------------------------------------------

class AggressiveProfile(ScanProfile):
    """
    Tam kapsam, maksimum hiz.
    Tum modul + tum payload + tum wordlist. WAF bypass denese de hizdan odun vermez.
    """

    NAME          = "aggressive"
    DESCRIPTION   = "Tam kapsam, maksimum hiz. Tum moduller, tum payloadlar, yuksek RPS."
    PRIORITY_MODULES = ["sqli", "xss", "ssrf", "cmdi"]
    ESTIMATED_MIN = 30
    TAGS          = ["full-scope", "fast", "pentest"]

    def apply(self, cfg: dict) -> dict:
        self._mark_profile(cfg)
        self._enable_all_modules(cfg)

        self._set_fuzz(cfg, rps=15, concurrency=20, per_param=20, max_total=100_000)
        self._set_http(cfg, timeout=20, retries=2, rps=15.0)

        cfg.setdefault("_sqlmap", {}).update({
            "risk": 3, "level": 5, "threads": 10,
            "extra_args": ["--random-agent", "--batch", "--forms", "--crawl=3"],
        })
        cfg.setdefault("_ffuf", {}).update({
            "threads": 50,
            "extra_args": ["-rate", "200", "-recursion", "-recursion-depth", "3"],
        })
        cfg.setdefault("_nuclei", {}).update({
            "rate_limit": 200, "concurrency": 50, "bulk_size": 50,
            "extra_args": ["-severity", "critical,high,medium,low,info"],
        })
        cfg.setdefault("_nmap", {}).update({
            "mode": "deep", "extra_args": ["-T4", "--min-parallelism", "10"],
        })
        cfg.setdefault("nmap", {})["mode"] = "deep"
        cfg.setdefault("content_discovery", {}).update({
            "rate_limit": 200, "threads": 50, "recursive": True,
        })
        cfg.setdefault("waf_bypass", {}).update({
            "enabled": True, "rotate_headers": True, "max_variants_per_payload": 10,
        })
        cfg.setdefault("wordlists", {})["use_all"] = True
        cfg.setdefault("oast", {})["enabled"] = True
        return cfg


# ---------------------------------------------------------------------------
# Built-in Profil: Stealth
# ---------------------------------------------------------------------------

class StealthProfile(ScanProfile):
    """
    Tam kapsam, yavas + guclu WAF bypass.
    Ayni kapsam, dusuk RPS, insan benzeri gecikmeler.
    """

    NAME          = "stealth"
    DESCRIPTION   = "Tam kapsam, yavas & WAF bypass. Agirsabak tarama, rate limit asmaz."
    PRIORITY_MODULES = ["sqli", "ssrf", "auth_scanners"]
    ESTIMATED_MIN = 240
    TAGS          = ["full-scope", "slow", "waf-bypass", "pentest"]

    def apply(self, cfg: dict) -> dict:
        self._mark_profile(cfg)
        self._enable_all_modules(cfg)

        self._set_fuzz(cfg, rps=1, concurrency=2, per_param=20, max_total=100_000)
        self._set_http(cfg, timeout=30, retries=3, rps=1.0)

        ab = cfg.setdefault("anti_blocking", {}).setdefault("http", {})
        ab["jitter_ms"] = 2500
        ab["max_extra_delay_ms"] = 4000
        ab["human_like_delays"] = True
        ab["rotate_user_agent"] = True

        cfg.setdefault("_sqlmap", {}).update({
            "risk": 3, "level": 5, "threads": 1,
            "extra_args": [
                "--delay=5", "--random-agent", "--batch", "--forms", "--crawl=3",
                "--tamper=space2comment,between,randomcase,charencode",
            ],
        })
        cfg.setdefault("_ffuf", {}).update({
            "threads": 1,
            "extra_args": ["-rate", "2", "-p", "1.0-3.0", "-recursion", "-recursion-depth", "3"],
        })
        cfg.setdefault("_nuclei", {}).update({
            "rate_limit": 3, "concurrency": 5, "bulk_size": 5,
            "extra_args": ["-severity", "critical,high,medium,low,info"],
        })
        cfg.setdefault("_nmap", {}).update({
            "mode": "deep",
            "extra_args": ["-T1", "--scan-delay", "5s", "--max-parallelism", "1", "-sS"],
        })
        cfg.setdefault("nmap", {})["mode"] = "deep"
        cfg.setdefault("content_discovery", {}).update({
            "rate_limit": 5, "threads": 1, "recursive": True,
        })
        cfg.setdefault("waf_bypass", {}).update({
            "enabled": True, "rotate_headers": True, "max_variants_per_payload": 10,
            "encoding_variants": True, "case_variants": True, "comment_variants": True,
        })
        cfg.setdefault("wordlists", {})["use_all"] = True
        cfg.setdefault("oast", {})["enabled"] = True
        return cfg


# ---------------------------------------------------------------------------
# Built-in Profil: CI/CD
# ---------------------------------------------------------------------------

class CICDProfile(ScanProfile):
    """
    CI/CD boru hatti icin optimize edilmis profil.

    Hedef: < 5 dakikada kritik bulgulari bulmak.
      - Sadece kritik/high scanner'lar
      - Kisa timeout (10 sn)
      - Yuksek concurrency (hizli)
      - Nmap / subdomain / crawl devre disi
      - Nuclei sadece critical/high template'leri
      - SQLMap yok (cok yavas)
      - Fail-fast: ilk kritik bulguda dur (opsiyonel)
    """

    NAME          = "cicd"
    DESCRIPTION   = "CI/CD optimize: < 5 dk, sadece Critical/High, hizli timeout."
    PRIORITY_MODULES = ["sqli", "xss", "ssrf", "cmdi", "auth_scanners", "idor"]
    EXCLUDED_MODULES = ["nmap", "subdomain", "passive_recon", "waf_fingerprint",
                        "infrastructure", "js_analyzer", "websocket_fuzz",
                        "prototype_pollution", "race_condition"]
    MIN_SEVERITY  = "high"
    ESTIMATED_MIN = 5
    TAGS          = ["cicd", "fast", "critical-first", "pipeline"]

    def apply(self, cfg: dict) -> dict:
        self._mark_profile(cfg)

        # Sadece hizli modulleri ac
        self._enable_modules(cfg, _FAST_MODULES)
        self._disable_modules(cfg, self.EXCLUDED_MODULES)

        self._set_fuzz(cfg, rps=20, concurrency=15, per_param=5, max_total=5_000)
        self._set_http(cfg, timeout=10, retries=1, rps=20.0)
        self._set_filter(cfg, min_severity="high")

        # Oncelikli modul sirasini kaydet
        cfg.setdefault("scan", {})["priority_modules"] = self.PRIORITY_MODULES
        cfg.setdefault("scan", {})["timeout_seconds"] = 300   # 5 dakika hard limit
        cfg.setdefault("scan", {})["fail_fast"] = True        # ilk Critical'da dur

        # Araclar: hafif konfigurasyon
        cfg.setdefault("_sqlmap", {}).update({
            "enabled": False,  # cicd'de cok yavas
        })
        cfg.setdefault("_nuclei", {}).update({
            "rate_limit": 300, "concurrency": 100, "bulk_size": 100,
            "extra_args": ["-severity", "critical,high", "-timeout", "5"],
        })
        cfg.setdefault("_nmap", {})["enabled"] = False
        cfg.setdefault("_ffuf", {}).update({
            "threads": 30,
            "extra_args": ["-rate", "300", "-timeout", "5"],
        })
        cfg.setdefault("content_discovery", {}).update({
            "enabled": False,   # CI/CD'de crawler yok
        })
        cfg.setdefault("crawl", {}).update({
            "enabled": True, "deep": False, "max_pages": 50,
        })
        cfg.setdefault("waf_bypass", {}).update({
            "enabled": True, "max_variants_per_payload": 3,
        })
        cfg.setdefault("oast", {})["enabled"] = True

        _logger.info("[CICDProfile] CI/CD profili uygulandi: max 5 dk, sadece Critical/High.")
        return cfg


# ---------------------------------------------------------------------------
# Built-in Profil: Bug Bounty
# ---------------------------------------------------------------------------

class BugBountyProfile(ScanProfile):
    """
    Bug bounty programlari icin optimize edilmis profil.

    Hedef: Minimum false positive, maksimum gercek bulgu.
      - Sadece yuksek guvenlikli tespitler raporlanir
      - OOB/OAST her modulde aktif (blind tespitler icin)
      - WAF bypass maksimum (program'in WAF'u olabilir)
      - SQLMap dogrulama asama
      - Cok sayida payload varyanti (daha az, daha iyi)
      - Interactsh ile blind XSS/SSRF/XXE dogrulama
    """

    NAME          = "bug_bounty"
    DESCRIPTION   = "Bug bounty: min false positive, OOB/OAST, WAF bypass, sadece Critical/High."
    PRIORITY_MODULES = ["ssrf", "sqli", "xss", "xxe", "auth_scanners",
                        "idor", "file_upload", "cmdi", "ssti"]
    EXCLUDED_MODULES = ["infrastructure", "passive_recon"]
    MIN_SEVERITY  = "high"
    ESTIMATED_MIN = 90
    TAGS          = ["bug-bounty", "low-fp", "oast", "waf-bypass"]

    def apply(self, cfg: dict) -> dict:
        self._mark_profile(cfg)
        self._enable_all_modules(cfg)
        self._disable_modules(cfg, self.EXCLUDED_MODULES)

        self._set_fuzz(cfg, rps=8, concurrency=10, per_param=15, max_total=50_000)
        self._set_http(cfg, timeout=20, retries=3, rps=8.0)
        self._set_filter(cfg, min_severity="high")

        cfg.setdefault("scan", {})["priority_modules"] = self.PRIORITY_MODULES

        # OAST her yerde aktif — blind tespitler icin kritik
        cfg.setdefault("oast", {}).update({
            "enabled": True,
            "max_injections_per_loc": 5,
            "protocols": ["dns", "http", "smtp"],
        })

        # WAF bypass guclu
        cfg.setdefault("waf_bypass", {}).update({
            "enabled": True, "rotate_headers": True, "max_variants_per_payload": 8,
            "encoding_variants": True, "case_variants": True,
            "ml_scoring": True,
        })

        # SQLMap: dogrulama modunda (agresif degil)
        cfg.setdefault("_sqlmap", {}).update({
            "risk": 2, "level": 3, "threads": 5,
            "extra_args": ["--random-agent", "--batch", "--flush-session"],
        })

        cfg.setdefault("_nuclei", {}).update({
            "rate_limit": 100, "concurrency": 30, "bulk_size": 30,
            "extra_args": ["-severity", "critical,high"],
        })

        # Confirmation mode: bulgu dogrulanmadan raporlanmaz
        cfg.setdefault("scan", {})["confirm_findings"] = True
        cfg.setdefault("scan", {})["min_confidence"] = "high"

        # Rate limiting — hedefin rate limit'ini asma
        ab = cfg.setdefault("anti_blocking", {}).setdefault("http", {})
        ab["jitter_ms"] = 500
        ab["max_extra_delay_ms"] = 1000
        ab["rotate_user_agent"] = True

        _logger.info("[BugBountyProfile] Bug bounty profili uygulandi.")
        return cfg


# ---------------------------------------------------------------------------
# Built-in Profil: Compliance
# ---------------------------------------------------------------------------

class ComplianceProfile(ScanProfile):
    """
    Uyumluluk denetimi profili: OWASP Top 10 odakli.

    Desteklenen standartlar:
      PCI-DSS v4 / HIPAA / ISO 27001:2022 / NIST SP 800-53 / GDPR

    Hedef:
      - OWASP Top 10 kategorilerinin tamamini kapsama
      - Her bulgu icin CWE esleme
      - Remediation rehberi ile raporlama
      - Compliance raporu otomatik uret
    """

    NAME          = "compliance"
    DESCRIPTION   = "OWASP Top 10 + PCI-DSS/HIPAA/ISO27001 uyumluluk denetimi."
    PRIORITY_MODULES = _OWASP_TOP10_MODULES
    EXCLUDED_MODULES = ["passive_recon", "waf_fingerprint", "websocket_fuzz"]
    MIN_SEVERITY  = "medium"
    ESTIMATED_MIN = 60
    TAGS          = ["compliance", "owasp", "pci-dss", "hipaa", "iso27001"]

    # OWASP Top 10 (2021) modul esleme
    OWASP_MAP = {
        "A01:2021 - Broken Access Control":      ["idor", "csrf", "mass_assignment"],
        "A02:2021 - Cryptographic Failures":     ["tls", "headers"],
        "A03:2021 - Injection":                  ["sqli", "nosqli", "cmdi", "ssti", "xxe"],
        "A04:2021 - Insecure Design":            ["auth_scanners"],
        "A05:2021 - Security Misconfiguration":  ["cors", "headers", "xxe"],
        "A06:2021 - Vulnerable Components":      ["owasp"],
        "A07:2021 - Auth Failures":              ["auth_scanners", "jwt_attacks"],
        "A08:2021 - Software/Data Integrity":    ["file_upload"],
        "A09:2021 - Logging Failures":           ["headers"],
        "A10:2021 - SSRF":                       ["ssrf"],
    }

    def apply(self, cfg: dict) -> dict:
        self._mark_profile(cfg)
        self._enable_modules(cfg, _OWASP_TOP10_MODULES)
        self._disable_modules(cfg, self.EXCLUDED_MODULES)

        self._set_fuzz(cfg, rps=5, concurrency=8, per_param=10, max_total=20_000)
        self._set_http(cfg, timeout=20, retries=2, rps=5.0)
        self._set_filter(cfg, min_severity="medium")

        cfg.setdefault("scan", {}).update({
            "priority_modules": self.PRIORITY_MODULES,
            "owasp_mapping": True,
            "cwe_mapping": True,
            "generate_compliance_report": True,
            "compliance_standards": ["PCI-DSS", "HIPAA", "ISO27001"],
        })

        # Compliance raporlama zenginlestirme
        cfg.setdefault("reporting", {}).update({
            "include_remediation": True,
            "include_owasp_mapping": True,
            "include_cwe": True,
            "include_cvss": True,
            "compliance_standards": ["PCI-DSS v4", "HIPAA", "ISO 27001:2022"],
            "executive_summary": True,
        })

        # OWASP map'i cfg'ye ekle (raporlama icin)
        cfg["_owasp_coverage"] = self.OWASP_MAP

        cfg.setdefault("_nmap", {}).update({
            "mode": "normal", "extra_args": ["-T3"],
        })
        cfg.setdefault("_nuclei", {}).update({
            "rate_limit": 50, "concurrency": 20,
            "extra_args": ["-severity", "critical,high,medium"],
        })
        cfg.setdefault("waf_bypass", {}).update({
            "enabled": True, "max_variants_per_payload": 5,
        })
        cfg.setdefault("oast", {})["enabled"] = True

        _logger.info("[ComplianceProfile] Uyumluluk profili: OWASP Top 10 + PCI-DSS/HIPAA.")
        return cfg


# ---------------------------------------------------------------------------
# Built-in Profil: API-Only
# ---------------------------------------------------------------------------

class APIOnlyProfile(ScanProfile):
    """
    Sadece REST / GraphQL / gRPC API yuzeyini tarayan profil.

    Browser-based scanner'lar, Nmap, subdomain, DNS devre disi.
    API guvenligi: Auth, IDOR, SQLi, NoSQLi, SSRF, Mass Assignment, Rate Limit.
    """

    NAME          = "api_only"
    DESCRIPTION   = "Yalnizca REST/GraphQL/gRPC yuzey: Auth, IDOR, SQLi, SSRF, Mass Assignment."
    PRIORITY_MODULES = ["auth_scanners", "idor", "sqli", "nosqli", "ssrf",
                        "mass_assignment", "jwt_attacks", "cors", "graphql", "race_condition"]
    EXCLUDED_MODULES = ["nmap", "subdomain", "passive_recon", "infrastructure",
                        "dom_xss", "csrf", "clickjacking", "hsts",
                        "prototype_pollution", "websocket_fuzz",
                        "js_analyzer", "subdomain_takeover"]
    MIN_SEVERITY  = "medium"
    ESTIMATED_MIN = 25
    TAGS          = ["api", "rest", "graphql", "grpc", "idor", "auth"]

    def apply(self, cfg: dict) -> dict:
        self._mark_profile(cfg)
        self._enable_modules(cfg, self.PRIORITY_MODULES)
        self._disable_modules(cfg, self.EXCLUDED_MODULES)

        self._set_fuzz(cfg, rps=25, concurrency=20, per_param=15, max_total=30_000)
        self._set_http(cfg, timeout=15, retries=2, rps=25.0)
        self._set_filter(cfg, min_severity="medium")

        cfg.setdefault("scan", {}).update({
            "priority_modules": self.PRIORITY_MODULES,
            "api_mode": True,
            "follow_openapi": True,    # OpenAPI/Swagger otomatik import
            "follow_graphql": True,    # GraphQL schema introspection
        })

        # GraphQL derin tarama
        cfg.setdefault("graphql", {}).update({
            "enabled": True, "deep": True,
            "introspection": True, "mutation_fuzzing": True,
        })

        # Crawler: minimal (sadece API endpoint'leri)
        cfg.setdefault("crawl", {}).update({
            "enabled": True, "deep": False, "max_pages": 20,
            "api_only": True,
        })

        # Nmap / subdomain yok
        cfg.setdefault("nmap", {})["enabled"] = False
        cfg.setdefault("subdomain", {})["enabled"] = False
        cfg.setdefault("content_discovery", {})["enabled"] = False

        # SQLMap: API-uyumlu
        cfg.setdefault("_sqlmap", {}).update({
            "risk": 2, "level": 3, "threads": 8,
            "extra_args": ["--random-agent", "--batch", "--data", "{}",
                           "--headers", "Content-Type: application/json"],
        })

        cfg.setdefault("_nuclei", {}).update({
            "rate_limit": 150, "concurrency": 40,
            "extra_args": ["-severity", "critical,high,medium", "-tags", "api"],
        })

        cfg.setdefault("oast", {})["enabled"] = True
        cfg.setdefault("waf_bypass", {}).update({
            "enabled": True, "max_variants_per_payload": 5,
        })

        _logger.info("[APIOnlyProfile] API-only profili: REST/GraphQL/gRPC.")
        return cfg


# ---------------------------------------------------------------------------
# Built-in Profil: Authenticated
# ---------------------------------------------------------------------------

class AuthenticatedProfile(ScanProfile):
    """
    Login -> token -> tam tarama sablonu.

    Giris yapildiktan sonra oturumlu olarak tum yuzey taranir.
    Privilege escalation, IDOR, BOLA, session hijacking odakli.
    """

    NAME          = "authenticated"
    DESCRIPTION   = "Login -> token -> tam tarama. Auth bypass, PrivEsc, IDOR odakli."
    PRIORITY_MODULES = ["auth_scanners", "idor", "mass_assignment", "jwt_attacks",
                        "sqli", "xss", "ssrf", "csrf", "race_condition"]
    EXCLUDED_MODULES = ["passive_recon"]
    MIN_SEVERITY  = "medium"
    ESTIMATED_MIN = 60
    TAGS          = ["authenticated", "idor", "privesc", "session", "pentest"]

    def apply(self, cfg: dict) -> dict:
        self._mark_profile(cfg)
        self._enable_all_modules(cfg)
        self._disable_modules(cfg, self.EXCLUDED_MODULES)

        self._set_fuzz(cfg, rps=10, concurrency=12, per_param=15, max_total=60_000)
        self._set_http(cfg, timeout=20, retries=2, rps=10.0)
        self._set_filter(cfg, min_severity="medium")

        cfg.setdefault("scan", {}).update({
            "priority_modules": self.PRIORITY_MODULES,
            "authenticated": True,
            "test_privilege_escalation": True,
            "test_horizontal_privesc": True,   # diger kullanicilarin kaynaklari
            "test_vertical_privesc": True,     # admin yetkisi kazanma
            "multi_role_testing": True,
        })

        # Auth akisi yapilandirmasi
        auth_cfg = cfg.setdefault("auth", {})
        if not auth_cfg.get("type"):
            auth_cfg["type"] = "form"
            auth_cfg["_note"] = (
                "login_url, username_field, password_field, "
                "credentials degerlerini yapilandirin."
            )

        # Session guvenligi testleri
        cfg.setdefault("offensive", {}).setdefault("session_scanner", {}).update({
            "enabled": True,
            "test_fixation": True,
            "test_entropy": True,
            "test_concurrent": True,
        })

        # IDOR: birden fazla rol ile test
        cfg.setdefault("offensive", {}).setdefault("idor", {}).update({
            "enabled": True,
            "multi_role": True,
            "id_range": 200,
        })

        cfg.setdefault("_sqlmap", {}).update({
            "risk": 2, "level": 4, "threads": 6,
            "extra_args": ["--random-agent", "--batch", "--forms"],
        })
        cfg.setdefault("_nuclei", {}).update({
            "rate_limit": 80, "concurrency": 25,
            "extra_args": ["-severity", "critical,high,medium"],
        })
        cfg.setdefault("oast", {})["enabled"] = True
        cfg.setdefault("waf_bypass", {}).update({
            "enabled": True, "max_variants_per_payload": 6,
        })

        _logger.info("[AuthenticatedProfile] Kimlik dogrulumali tarama profili uygulandi.")
        return cfg


# ---------------------------------------------------------------------------
# CustomProfile — YAML'dan Yuklenen Profil
# ---------------------------------------------------------------------------

class CustomProfile(ScanProfile):
    """YAML dosyasindan yuklenen ozel profil."""

    def __init__(self, data: Dict[str, Any], source_path: Optional[str] = None) -> None:
        self._data = data
        self.NAME        = data.get("profile_id") or data.get("name", "custom")
        self.DESCRIPTION = data.get("description", "")
        self.VERSION     = str(data.get("version", "1.0"))
        self.TAGS        = data.get("tags", [])
        self.MIN_SEVERITY = data.get("filter", {}).get("min_severity", "info")
        self.ESTIMATED_MIN = int(data.get("estimated_duration_min", 0))
        self.PRIORITY_MODULES = data.get("scan", {}).get("priority_modules", [])
        self.EXCLUDED_MODULES = data.get("scan", {}).get("disabled_modules", [])
        self._source_path = source_path

    def metadata(self) -> ProfileMetadata:
        m = super().metadata()
        m.yaml_path = self._source_path
        return m

    def apply(self, cfg: dict) -> dict:
        self._mark_profile(cfg)

        # Modüller
        scan_cfg = self._data.get("scan", {})
        enabled_mods  = scan_cfg.get("enabled_modules", [])
        disabled_mods = scan_cfg.get("disabled_modules", [])

        if enabled_mods:
            self._enable_modules(cfg, enabled_mods)
        else:
            self._enable_all_modules(cfg)

        if disabled_mods:
            self._disable_modules(cfg, disabled_mods)

        # Fuzz
        if "concurrency" in scan_cfg or "rps" in scan_cfg:
            self._set_fuzz(
                cfg,
                rps=int(scan_cfg.get("rps", 10)),
                concurrency=int(scan_cfg.get("concurrency", 10)),
                per_param=int(scan_cfg.get("per_param", 15)),
                max_total=int(scan_cfg.get("max_total_requests", 50_000)),
            )

        # HTTP
        http_cfg = self._data.get("http", {})
        if http_cfg:
            self._set_http(
                cfg,
                timeout=int(http_cfg.get("timeout_seconds", 15)),
                retries=int(http_cfg.get("retries", 2)),
                rps=float(scan_cfg.get("rps", 10)),
            )

        # Filtre
        filter_cfg = self._data.get("filter", {})
        if filter_cfg.get("min_severity"):
            self._set_filter(cfg, filter_cfg["min_severity"])

        # Araçlar
        tools = self._data.get("tools", {})
        for tool in ("sqlmap", "nuclei", "nmap", "ffuf"):
            if tool in tools:
                t_cfg = tools[tool]
                if isinstance(t_cfg, dict):
                    cfg.setdefault(f"_{tool}", {}).update(t_cfg)

        # Auth
        auth_cfg = self._data.get("auth", {})
        if auth_cfg:
            cfg.setdefault("auth", {}).update(auth_cfg)

        # WAF bypass
        waf_cfg = self._data.get("waf_bypass", {})
        if waf_cfg:
            cfg.setdefault("waf_bypass", {}).update(waf_cfg)

        # OAST
        oast_cfg = self._data.get("oast", {})
        if oast_cfg:
            cfg.setdefault("oast", {}).update(oast_cfg)

        # Scan ayarlari
        scan_opts = {k: v for k, v in scan_cfg.items()
                     if k not in ("enabled_modules", "disabled_modules", "priority_modules",
                                  "rps", "concurrency", "per_param", "max_total_requests")}
        if scan_opts:
            cfg.setdefault("scan", {}).update(scan_opts)

        _logger.info(f"[CustomProfile] '{self.NAME}' profili uygulandi.")
        return cfg


# ---------------------------------------------------------------------------
# ProfileLoader — YAML Dosya Yukleyici
# ---------------------------------------------------------------------------

class ProfileLoader:
    """
    YAML profil dosyalarini yukler ve CustomProfile ornekleri doner.

    Arama yollari (oncelik sirasiyla):
      1. websecure/config/profiles/*.yml
      2. ~/.websecure/profiles/*.yml
      3. WEBSECURE_PROFILE_DIR ortam degiskeni
      4. extra_dirs constructor parametresi
    """

    # Zorunlu YAML alanlari
    REQUIRED_FIELDS = {"name", "profile_id"}

    def __init__(self, extra_dirs: Optional[List[str]] = None) -> None:
        self._extra_dirs = extra_dirs or []

    def load_all(self) -> List[CustomProfile]:
        profiles: List[CustomProfile] = []
        for path in self._find_profile_files():
            try:
                profile = self._load_file(path)
                if profile:
                    profiles.append(profile)
            except Exception as exc:
                _logger.warning(f"[ProfileLoader] {path.name} yuklenemedi: {exc!r}")
        return profiles

    def load_file(self, path: str) -> Optional[CustomProfile]:
        return self._load_file(Path(path))

    def _load_file(self, path: Path) -> Optional[CustomProfile]:
        try:
            import yaml  # noqa: PLC0415
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                _logger.warning(f"[ProfileLoader] {path.name} gecersiz format (dict bekleniyor).")
                return None
            missing = self.REQUIRED_FIELDS - data.keys()
            if missing:
                _logger.warning(f"[ProfileLoader] {path.name} eksik alan: {missing}")
                return None
            profile = CustomProfile(data, source_path=str(path))
            _logger.debug(f"[ProfileLoader] Yuklendi: {path.name} -> '{profile.NAME}'")
            return profile
        except ModuleNotFoundError:
            _logger.warning("[ProfileLoader] PyYAML yuklu degil. `pip install pyyaml`")
            return None

    def _find_profile_files(self):
        import os
        search_dirs: List[Path] = [
            Path(__file__).parent.parent / "config" / "profiles",
            Path.home() / ".websecure" / "profiles",
        ]
        if os.environ.get("WEBSECURE_PROFILE_DIR"):
            search_dirs.append(Path(os.environ["WEBSECURE_PROFILE_DIR"]))
        for d in self._extra_dirs:
            search_dirs.append(Path(d))

        for d in search_dirs:
            if d.is_dir():
                yield from d.glob("*.yml")
                yield from d.glob("*.yaml")


# ---------------------------------------------------------------------------
# ProfileValidator — YAML Sema Dogrulama
# ---------------------------------------------------------------------------

class ProfileValidator:
    """YAML profil verilerini dogrular ve uyari listesi doner."""

    VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
    VALID_AUTH_TYPES = {"none", "basic", "bearer", "cookie", "form", "oauth2", "apikey"}

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> List[str]:
        """Dogrulama uyarilarini liste olarak doner (bos = gecerli)."""
        warnings: List[str] = []

        if not data.get("name"):
            warnings.append("'name' alani bos olamaz.")
        if not data.get("profile_id"):
            warnings.append("'profile_id' alani bos olamaz.")

        scan = data.get("scan", {})
        if "rps" in scan and not isinstance(scan["rps"], (int, float)):
            warnings.append("scan.rps sayisal olmali.")
        if "concurrency" in scan and not isinstance(scan["concurrency"], int):
            warnings.append("scan.concurrency tam sayi olmali.")

        filt = data.get("filter", {})
        if filt.get("min_severity") and filt["min_severity"] not in cls.VALID_SEVERITIES:
            warnings.append(
                f"filter.min_severity gecersiz: {filt['min_severity']}. "
                f"Gecerli: {cls.VALID_SEVERITIES}"
            )

        auth = data.get("auth", {})
        if auth.get("type") and auth["type"] not in cls.VALID_AUTH_TYPES:
            warnings.append(
                f"auth.type gecersiz: {auth['type']}. "
                f"Gecerli: {cls.VALID_AUTH_TYPES}"
            )

        return warnings


# ---------------------------------------------------------------------------
# ProfileComposer — Iki Profili Birlestir (Decorator Deseni)
# ---------------------------------------------------------------------------

class ProfileComposer:
    """
    Iki profili siralayarak birlestiren dekorator.

    Kullanim: cicd + waf_bypass ayarlarini birlestirmek icin.
    Ikinci profilin ayarlari birincinin ustune yazar.
    """

    def __init__(self, base: ScanProfile, overlay: ScanProfile) -> None:
        self._base    = base
        self._overlay = overlay
        self.NAME = f"{base.NAME}+{overlay.NAME}"

    def apply(self, cfg: dict) -> dict:
        cfg = self._base.apply(cfg)
        cfg = self._overlay.apply(cfg)
        cfg["_composed_from"] = [self._base.NAME, self._overlay.NAME]
        return cfg

    def metadata(self) -> ProfileMetadata:
        return ProfileMetadata(
            name=self.NAME,
            profile_id=self.NAME.replace("+", "_"),
            description=f"{self._base.DESCRIPTION} + {self._overlay.DESCRIPTION}",
            tags=list(set(self._base.TAGS + self._overlay.TAGS)),
        )


# ---------------------------------------------------------------------------
# AdaptiveProfileEngine — Canli Profil Ayarlama
# ---------------------------------------------------------------------------

class AdaptiveProfileEngine:
    """
    Hedef metriklerini olcer ve profil parametrelerini canli olarak ayarlar.

    Olcumler:
      - Ortalama yanit suresi (baseline probe)
      - WAF tespiti (block rate, 403/429 orani)
      - Hata orani

    Ayarlama kurallari:
      - Yavas hedef (>2000ms) → RPS'i dusurkonsurrency'i azalt
      - WAF tespit edildi → WAF bypass etkinlestir, daha az RPS
      - Yuksek hata orani → retry artir, concurrency azalt
      - Hizli hedef (<200ms) → RPS artir
    """

    PROBE_COUNT       = 5    # kac probe isteği atilacak
    PROBE_TIMEOUT     = 10   # saniye

    def probe_target(
        self,
        url:     str,
        session: Any = None,
    ) -> AdaptiveMetrics:
        """Hedefe probe istekleri atarak temel metrikleri olcer."""
        import requests  # noqa: PLC0415

        timings:  List[float] = []
        errors:   int = 0
        blocks:   int = 0

        probe_session = session
        if probe_session is None:
            probe_session = requests.Session()
            probe_session.headers["User-Agent"] = (
                "Mozilla/5.0 (compatible; WebSecureProbe/1.0)"
            )

        for _ in range(self.PROBE_COUNT):
            try:
                t0 = time.monotonic()
                resp = probe_session.get(
                    url, timeout=self.PROBE_TIMEOUT,
                    allow_redirects=True
                )
                elapsed_ms = (time.monotonic() - t0) * 1000
                timings.append(elapsed_ms)
                if resp.status_code in (403, 429, 406, 503):
                    blocks += 1
            except Exception:
                errors += 1

        total = self.PROBE_COUNT
        block_rate = blocks / total
        error_rate = errors / total

        if not timings:
            avg_ms = 0.0
            p95_ms = 0.0
        else:
            avg_ms = statistics.mean(timings)
            p95_ms = (
                sorted(timings)[int(len(timings) * 0.95) - 1]
                if len(timings) >= 2
                else timings[-1]
            )

        # WAF tespiti (basit: block rate yuksekse WAF var)
        waf_detected = block_rate > 0.3

        # Onerilen RPS
        if avg_ms > 3000 or error_rate > 0.5:
            recommended_rps = 1.0
            recommended_concurrency = 2
        elif avg_ms > 1500:
            recommended_rps = 3.0
            recommended_concurrency = 5
        elif avg_ms > 500:
            recommended_rps = 8.0
            recommended_concurrency = 10
        elif waf_detected:
            recommended_rps = 2.0
            recommended_concurrency = 3
        else:
            recommended_rps = 15.0
            recommended_concurrency = 20

        metrics = AdaptiveMetrics(
            avg_response_ms=round(avg_ms, 1),
            p95_response_ms=round(p95_ms, 1),
            error_rate=round(error_rate, 3),
            block_rate=round(block_rate, 3),
            waf_detected=waf_detected,
            recommended_rps=recommended_rps,
            recommended_concurrency=recommended_concurrency,
        )

        _logger.info(
            f"[AdaptiveEngine] Probe tamamlandi: avg={avg_ms:.0f}ms, "
            f"waf={waf_detected}, block_rate={block_rate:.2f}, "
            f"onerildi: {recommended_rps} RPS / {recommended_concurrency} concurrency"
        )
        return metrics

    def adjust(self, cfg: dict, metrics: AdaptiveMetrics) -> dict:
        """Metriklere gore cfg parametrelerini canli guncelle."""
        fz = cfg.setdefault("fuzz", {})
        fz["rps"] = metrics.recommended_rps
        fz["concurrency"] = metrics.recommended_concurrency

        ab = cfg.setdefault("anti_blocking", {}).setdefault("http", {})
        ab["rps"] = metrics.recommended_rps

        if metrics.waf_detected:
            cfg.setdefault("waf_bypass", {}).update({
                "enabled": True,
                "rotate_headers": True,
                "max_variants_per_payload": 8,
                "encoding_variants": True,
            })
            _logger.info("[AdaptiveEngine] WAF tespit edildi → bypass etkinlestirildi.")

        if metrics.is_slow_target:
            cfg.setdefault("http", {})["timeout_seconds"] = 30
            _logger.info(
                f"[AdaptiveEngine] Yavas hedef ({metrics.avg_response_ms:.0f}ms) "
                f"→ timeout=30s, RPS={metrics.recommended_rps}"
            )

        cfg["_adaptive_metrics"] = {
            "avg_response_ms":    metrics.avg_response_ms,
            "p95_response_ms":    metrics.p95_response_ms,
            "waf_detected":       metrics.waf_detected,
            "block_rate":         metrics.block_rate,
            "recommended_rps":    metrics.recommended_rps,
            "recommended_concurrency": metrics.recommended_concurrency,
        }
        return cfg

    def recommend_profile(self, metrics: AdaptiveMetrics) -> str:
        """Metriklere gore en uygun profil adini oner."""
        if metrics.waf_detected and metrics.avg_response_ms > 1000:
            return "stealth"
        if metrics.waf_detected:
            return "bug_bounty"
        if metrics.avg_response_ms < 200 and not metrics.waf_detected:
            return "aggressive"
        return "stealth"


# ---------------------------------------------------------------------------
# ProfileRegistry — Singleton Kayit Defteri
# ---------------------------------------------------------------------------

class ProfileRegistry:
    """
    Tum profilleri kaydeden ve lookup saglayan singleton.

    Kullanim:
      registry = ProfileRegistry.instance()
      registry.register(CICDProfile())
      profile = registry.get("cicd")
      cfg = registry.apply("cicd", cfg)
    """

    _instance: Optional["ProfileRegistry"] = None
    _initialized: bool = False

    def __new__(cls) -> "ProfileRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._profiles: Dict[str, ScanProfile] = {}
        self._register_builtins()
        self._load_yaml_profiles()
        ProfileRegistry._initialized = True

    @classmethod
    def instance(cls) -> "ProfileRegistry":
        return cls()

    # ── Kayit yonetimi ────────────────────────────────────────────────────

    def register(self, profile: ScanProfile) -> None:
        self._profiles[profile.NAME] = profile
        _logger.debug(f"[ProfileRegistry] Kaydedildi: '{profile.NAME}'")

    def get(self, name: str) -> Optional[ScanProfile]:
        return self._profiles.get(name)

    def list(self) -> List[str]:
        return sorted(self._profiles.keys())

    def list_metadata(self) -> List[ProfileMetadata]:
        return [p.metadata() for p in self._profiles.values()]

    def apply(self, name: str, cfg: dict) -> dict:
        """Profil adina gore cfg'yi uygula. Profil bulunamazsa cfg degismez."""
        profile = self.get(name)
        if profile is None:
            _logger.warning(f"[ProfileRegistry] Profil bulunamadi: '{name}'")
            return cfg
        return profile.apply(cfg)

    # ── Dahili kayit ──────────────────────────────────────────────────────

    def _register_builtins(self) -> None:
        for profile_cls in [
            AggressiveProfile, StealthProfile, CICDProfile,
            BugBountyProfile, ComplianceProfile, APIOnlyProfile,
            AuthenticatedProfile,
        ]:
            self.register(profile_cls())

    def _load_yaml_profiles(self) -> None:
        loader = ProfileLoader()
        try:
            for custom_profile in loader.load_all():
                self.register(custom_profile)
        except Exception as exc:
            _logger.warning(f"[ProfileRegistry] YAML profil yukleme hatasi: {exc!r}")


# ---------------------------------------------------------------------------
# Module-level kolaylik fonksiyonlari (geri uyumluluk kopruleri)
# ---------------------------------------------------------------------------

def get_registry() -> ProfileRegistry:
    """Global ProfileRegistry singleton'ina erisim."""
    return ProfileRegistry.instance()


def apply_profile(name: str, cfg: dict) -> dict:
    """Profil adina gore cfg'ye profili uygula."""
    return get_registry().apply(name, cfg)


def list_profiles() -> List[str]:
    """Kayitli tum profil adlarini listele."""
    return get_registry().list()


def get_profile_metadata(name: str) -> Optional[ProfileMetadata]:
    """Profil metadata'sini getir."""
    p = get_registry().get(name)
    return p.metadata() if p else None


__all__ = [
    "ScanProfile",
    "ProfileMetadata",
    "AdaptiveMetrics",
    "ProfileRegistry",
    "ProfileLoader",
    "ProfileValidator",
    "ProfileComposer",
    "AdaptiveProfileEngine",
    "AggressiveProfile",
    "StealthProfile",
    "CICDProfile",
    "BugBountyProfile",
    "ComplianceProfile",
    "APIOnlyProfile",
    "AuthenticatedProfile",
    "CustomProfile",
    "get_registry",
    "apply_profile",
    "list_profiles",
    "get_profile_metadata",
]
