"""
websecure.core.scan_profile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Profil seçme/uygulama yardımcıları.

SADECE 2 MOD:
  - Agresif : Tam kapsam, maksimum hız, tüm araçlar/payload/wordlist/script aktif
  - Stealth : Tam kapsam, yavaş, WAF bypass, sakin adımlar — kapsam AYNI
"""
from __future__ import annotations

import os
import re
import logging

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sistemdeki tüm modüller — her iki profilde de TAM AÇIK
# ---------------------------------------------------------------------------
_ALL_OFFENSIVE_MODULES = [
    "request_smuggling", "mass_assignment", "jwt_attacks", "nosql_injection",
    "websocket_fuzz", "ssrf", "xxe", "graphql", "sqlmap",
    "xss", "sqli", "ssti", "cmdi", "csrf", "crlf_injection",
    "open_redirect", "idor", "race_condition", "prototype_pollution",
    "file_upload", "dom_xss", "headers", "tls",
    "auth_scanners", "owasp", "infrastructure", "passive_recon",
    "js_analyzer", "session_hunter", "cors", "clickjacking", "hsts",
]

def _enable_all_modules(cfg: dict) -> None:
    """Sistemdeki tüm modülleri tek tek aktif et."""
    off = cfg.setdefault("offensive", {})
    off["enabled"] = True
    off["profile"] = "deep"
    for mod in _ALL_OFFENSIVE_MODULES:
        node = off.setdefault(mod, {})
        if isinstance(node, dict):
            node["enabled"] = True

    # Keşif / tarama modülleri
    cfg.setdefault("content_discovery", {})["enabled"] = True
    cfg.setdefault("subdomain", {})["enabled"] = True
    cfg.setdefault("crawl", {})["enabled"] = True
    cfg.setdefault("crawl", {})["deep"] = True
    cfg.setdefault("waf_detect", {})["enabled"] = True
    cfg.setdefault("nmap", {})["enabled"] = True
    cfg.setdefault("nmap", {})["vuln_scripts"] = True
    cfg.setdefault("oast", {})["enabled"] = True
    cfg.setdefault("graphql", {})["enabled"] = True
    cfg.setdefault("graphql", {})["deep"] = True

    # Wordlist maksimum
    cfg.setdefault("wordlists", {})["use_all"] = True

    # OAST maksimum enjeksiyon
    cfg.setdefault("oast", {})["max_injections_per_loc"] = 10

    # Fuzz: maksimum payload
    os.environ["WS_PAYLOADS_MAX"] = "100000"


# ---------------------------------------------------------------------------
# Tahmin
# ---------------------------------------------------------------------------

def _estimate_minutes(config: dict, profile: str) -> tuple[int, int]:
    def _to_float(x, default: float) -> float:
        if isinstance(x, (int, float)):
            return float(x)
        if isinstance(x, str):
            s = x.strip()
            if re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)', s):
                return float(s)
        return default

    def _to_int(x, default: int) -> int:
        if isinstance(x, int):
            return x
        if isinstance(x, float) and x.is_integer():
            return int(x)
        if isinstance(x, str):
            s = x.strip()
            if re.fullmatch(r'[+-]?\d+', s):
                return int(s)
        return default

    cfg = config if isinstance(config, dict) else {}
    fz = cfg.get("fuzz") or {}
    rps = _to_float(fz.get("rps"), 0.0)
    if rps <= 0.0:
        rate_ms = _to_float(fz.get("rate_ms"), 0.0)
        rps = 1000.0 / rate_ms if rate_ms > 0.0 else 10.0
    max_total = _to_int(fz.get("max_total"), 2000)
    if max_total < 1:
        max_total = 2000
    base_sec = max_total / (rps if rps > 0.0 else 1.0)
    disc = cfg.get("content_discovery") or {}
    disc_over = 8 * 60 if bool(disc.get("enabled")) else 0
    off = cfg.get("offensive") or {}
    of_count = sum(1 for v in off.values() if isinstance(v, dict) and bool(v.get("enabled")))
    prof = profile.lower() if isinstance(profile, str) else ""
    off_over = of_count * (90 if prof == "aggressive" else 45)
    sec = base_sec + disc_over + off_over
    lo = int(max(1, round((sec / 60.0) * 0.8)))
    hi = int(max(1, round((sec / 60.0) * 1.4)))
    if hi < lo:
        hi = lo + 1
    return (lo, hi)


# ---------------------------------------------------------------------------
# AGRESİF PROFİL
# Tam kapsam + maksimum hız + WAF'tan kaçınmaya çalışır (ama hızdan ödün vermez)
# ---------------------------------------------------------------------------

def _apply_aggressive_profile(cfg: dict) -> dict:
    """Agresif profil: tüm modüller, tüm araçlar, tüm payloadlar — maksimum hız."""
    cfg.setdefault("settings", {})["scan_profile"] = "aggressive"
    cfg.setdefault("_profile", {})["selected"] = "aggressive"
    cfg["_scan_mode"] = "aggressive"

    # Tüm modülleri aç
    _enable_all_modules(cfg)

    # --- HTTP / Anti-blocking ---
    ab = cfg.setdefault("anti_blocking", {}).setdefault("http", {})
    ab["rps"] = 15
    ab["jitter_ms"] = 100
    ab["max_extra_delay_ms"] = 200
    ab["rotate_user_agent"] = True

    # --- Fuzz ---
    fz = cfg.setdefault("fuzz", {})
    fz["rps"] = 15
    fz["concurrency"] = 20
    fz["per_param"] = 20
    fz["max_total"] = 100000

    # --- SQLMap: tam güç ---
    cfg.setdefault("_sqlmap", {}).update({
        "risk": 3, "level": 5,
        "threads": 10,
        "extra_args": ["--random-agent", "--batch", "--forms", "--crawl=3"],
    })

    # --- FFUF: çok thread ---
    cfg.setdefault("_ffuf", {}).update({
        "threads": 50,
        "extra_args": ["-rate", "200", "-recursion", "-recursion-depth", "3"],
    })

    # --- Feroxbuster ---
    cfg.setdefault("_feroxbuster", {}).update({
        "threads": 50,
        "extra_args": ["--depth", "5", "--auto-tune"],
    })

    # --- Nuclei: tam rate ---
    cfg.setdefault("_nuclei", {}).update({
        "rate_limit": 200,
        "concurrency": 50,
        "bulk_size": 50,
        "extra_args": ["-severity", "critical,high,medium,low,info", "-tags", ""],
    })

    # --- Nmap: deep + hızlı ---
    cfg.setdefault("_nmap", {}).update({
        "mode": "deep",
        "extra_args": ["-T4", "--min-parallelism", "10"],
    })
    cfg.setdefault("nmap", {})["mode"] = "deep"

    # --- Content discovery ---
    cd = cfg.setdefault("content_discovery", {})
    cd["rate_limit"] = 200
    cd["threads"] = 50
    cd["recursive"] = True

    # --- WAF bypass headers (agresif ama dener) ---
    cfg.setdefault("waf_bypass", {}).update({
        "enabled": True,
        "rotate_headers": True,
        "max_variants_per_payload": 10,
    })

    return cfg


# ---------------------------------------------------------------------------
# STEALTH PROFİL
# Tam kapsam + yavaş + güçlü WAF bypass — kapsam Agresif ile AYNI
# ---------------------------------------------------------------------------

def _apply_stealth_profile(cfg: dict) -> dict:
    """Stealth profil: tüm modüller, tüm araçlar, tüm payloadlar — yavaş & WAF bypass."""
    cfg.setdefault("settings", {})["scan_profile"] = "stealth"
    cfg.setdefault("_profile", {})["selected"] = "stealth"
    cfg["_scan_mode"] = "stealth"

    # Tüm modülleri aç (kapsam agresifle aynı)
    _enable_all_modules(cfg)

    # --- HTTP / Anti-blocking: insan gibi davran ---
    ab = cfg.setdefault("anti_blocking", {}).setdefault("http", {})
    ab["rps"] = 1
    ab["jitter_ms"] = 2500
    ab["max_extra_delay_ms"] = 4000
    ab["rotate_user_agent"] = True
    ab["human_like_delays"] = True

    # --- Fuzz ---
    fz = cfg.setdefault("fuzz", {})
    fz["rps"] = 1
    fz["concurrency"] = 2
    fz["per_param"] = 20     # Payload sayısı aynı, tempo yavaş
    fz["max_total"] = 100000

    # --- SQLMap: tam güç + WAF tamper + gecikmeli ---
    cfg.setdefault("_sqlmap", {}).update({
        "risk": 3, "level": 5,
        "threads": 1,
        "extra_args": [
            "--delay=5", "--random-agent", "--batch", "--forms", "--crawl=3",
            "--tamper=space2comment,between,randomcase,charencode,equaltolike,greatest",
        ],
    })

    # --- FFUF: tek thread, çok yavaş ---
    cfg.setdefault("_ffuf", {}).update({
        "threads": 1,
        "extra_args": ["-rate", "2", "-p", "1.0-3.0", "-recursion", "-recursion-depth", "3"],
    })

    # --- Feroxbuster: yavaş ---
    cfg.setdefault("_feroxbuster", {}).update({
        "threads": 1,
        "extra_args": ["--depth", "5", "--rate-limit", "5"],
    })

    # --- Nuclei: çok düşük rate ---
    cfg.setdefault("_nuclei", {}).update({
        "rate_limit": 3,
        "concurrency": 5,
        "bulk_size": 5,
        "extra_args": ["-severity", "critical,high,medium,low,info", "-tags", ""],
    })

    # --- Nmap: deep + çok yavaş + stealth ---
    cfg.setdefault("_nmap", {}).update({
        "mode": "deep",
        "extra_args": [
            "-T1", "--scan-delay", "5s", "--max-parallelism", "1",
            "--randomize-hosts", "-sS",
        ],
    })
    cfg.setdefault("nmap", {})["mode"] = "deep"

    # --- Content discovery ---
    cd = cfg.setdefault("content_discovery", {})
    cd["rate_limit"] = 5
    cd["threads"] = 1
    cd["recursive"] = True

    # --- WAF bypass: güçlü ---
    cfg.setdefault("waf_bypass", {}).update({
        "enabled": True,
        "rotate_headers": True,
        "max_variants_per_payload": 10,
        "encoding_variants": True,
        "case_variants": True,
        "comment_variants": True,
    })

    return cfg


# ---------------------------------------------------------------------------
# Geriye dönük uyumluluk: _apply_normal_profile -> stealth'e yönlendir
# ---------------------------------------------------------------------------

def _apply_normal_profile(config: dict) -> tuple[dict, list[str]]:
    """Eski isim; stealth profiline yönlendirildi. Her iki mod da tam kapsamlı."""
    cfg = _apply_stealth_profile(config)
    return cfg, ["Normal profil kaldırıldı -> Stealth profili uygulandı (tam kapsam, yavaş)"]


# ---------------------------------------------------------------------------
# Kullanıcıya profil sor
# ---------------------------------------------------------------------------

def _offer_scan_profile_and_confirm(cfg: dict) -> tuple[str, dict]:
    """
    Kullaniciya tarama profilini sorar ve cfg'yi buna gore ayarlar.

    Profil sistemi v2.0: 7 yerlesik profil + YAML ozel profiller.
    """

    def _prompt(msg: str, default: str) -> str:
        try:
            val = input(msg)
            s = (val if isinstance(val, str) else "").strip()
            return s if s != "" else default
        except EOFError:
            return default

    def _get_apply_active_profile():
        try:
            from websecure.core.utils import apply_active_profile
            return apply_active_profile
        except Exception:
            return lambda c: c

    # Profil secenekleri: (numara, profil_id, etiket, aciklama)
    MENU_ENTRIES = [
        ("1", "aggressive",    "Agresif",           "Tam kapsam + maksimum hiz (~30 dk)"),
        ("2", "stealth",       "Stealth",            "Tam kapsam + yavas + WAF bypass (~4 saat)"),
        ("3", "cicd",          "CI/CD Pipeline",     "Hizli kritik tarama, < 5 dk"),
        ("4", "bug_bounty",    "Bug Bounty",         "Min. false positive, OOB/OAST, WAF bypass (~90 dk)"),
        ("5", "compliance",    "Uyumluluk Denetimi", "OWASP Top 10 + PCI-DSS/HIPAA/ISO27001 (~60 dk)"),
        ("6", "api_only",      "API-Only",           "Sadece REST/GraphQL/gRPC yuzey (~25 dk)"),
        ("7", "authenticated", "Kimlik Dogrulamali", "Login -> token -> tam tarama (~60 dk)"),
    ]

    # Ek YAML profilleri listele
    try:
        from websecure.core.profiles import get_registry
        registry = get_registry()
        builtin_ids = {e[1] for e in MENU_ENTRIES}
        extra_profiles = [
            name for name in registry.list() if name not in builtin_ids
        ]
    except Exception:
        extra_profiles = []

    while True:
        print("\n[?] Tarama Profili:")
        print("-" * 60)
        for num, pid, label, desc in MENU_ENTRIES:
            print(f"    {num}) {label:<22} - {desc}")

        if extra_profiles:
            print("    --- YAML Ozel Profiller ---")
            for i, name in enumerate(extra_profiles, start=len(MENU_ENTRIES) + 1):
                print(f"    {i}) {name}")

        print("-" * 60)
        valid_nums = {e[0] for e in MENU_ENTRIES} | {
            str(len(MENU_ENTRIES) + i + 1) for i in range(len(extra_profiles))
        }

        sel = (_prompt("Seciminiz [1-7, varsayilan=1]: ", "1") or "1").strip()

        # YAML profil secimi
        try:
            sel_int = int(sel)
            if sel_int > len(MENU_ENTRIES) and extra_profiles:
                extra_idx = sel_int - len(MENU_ENTRIES) - 1
                if 0 <= extra_idx < len(extra_profiles):
                    profile_id = extra_profiles[extra_idx]
                    try:
                        from websecure.core.profiles import apply_profile
                        cfg = apply_profile(profile_id, cfg)
                    except Exception:
                        pass
                    return profile_id, cfg
        except (ValueError, TypeError):
            pass

        # Yerlesik profil secimi
        matched = next((e for e in MENU_ENTRIES if e[0] == sel), None)
        if not matched:
            print("Gecersiz secim. Lutfen listeden bir numara secin.")
            continue

        _, profile_id, label, desc = matched

        # Profile-specific onay mesaji
        if profile_id == "aggressive":
            lo, hi = _estimate_minutes(cfg, "aggressive")
            print(f"\n[*] {label} secildi. Yaklasik {lo}-{hi} dakika surebilir.")
        elif profile_id == "stealth":
            lo, hi = _estimate_minutes(cfg, "stealth")
            print(f"\n[*] {label} secildi. Tam kapsam, yavas (~{lo * 4}-{hi * 6} dk).")
            print("    WAF bypass aktif, dusuk RPS, rastgele gecikmeler.")
        elif profile_id == "cicd":
            print(f"\n[*] {label} secildi. Hedef: < 5 dk, sadece Critical/High.")
            print("    SQLMap devre disi. Fail-fast mod aktif.")
        elif profile_id == "bug_bounty":
            print(f"\n[*] {label} secildi. Min. false positive, OAST aktif, WAF bypass.")
            print("    Sadece dogrulanmis Critical/High bulgular raporlanir.")
        elif profile_id == "compliance":
            print(f"\n[*] {label} secildi.")
            print("    OWASP Top 10 + PCI-DSS/HIPAA/ISO27001 uyumluluk raporu uretilecek.")
        elif profile_id == "api_only":
            print(f"\n[*] {label} secildi.")
            print("    Sadece REST/GraphQL/gRPC yuzey. Nmap/subdomain devre disi.")
        elif profile_id == "authenticated":
            print(f"\n[*] {label} secildi.")
            print("    Giris kimlik bilgilerini --auth-user / --auth-pass ile verin.")
        else:
            print(f"\n[*] {label} secildi.")

        ans = (_prompt("Devam? [D]evam / [B]asa don: ", "D") or "D").lower()
        if ans.startswith("b"):
            continue

        # Profili uygula
        try:
            from websecure.core.profiles import apply_profile
            cfg = apply_profile(profile_id, cfg)
        except Exception:
            # Fallback: eski uygulamalar
            if profile_id == "aggressive":
                cfg = _apply_aggressive_profile(cfg)
            else:
                cfg = _apply_stealth_profile(cfg)

        apply_active_profile = _get_apply_active_profile()
        cfg = apply_active_profile(cfg)
        return profile_id, cfg


def _pick_from_config(cfg: dict, key: str, default=None):
    v = cfg.get(key)
    return default if v is None else v


def _choose_mode_from_config(config: dict | None) -> str:
    """Mode seçimi."""
    try:
        from websecure.core.phases._context import ScanMode
    except ImportError:
        ScanMode = None

    def _normal():
        return ScanMode.NORMAL if ScanMode else "normal"

    def _detailed():
        return ScanMode.DETAILED if ScanMode else "detailed"

    def _deep():
        return ScanMode.DEEP if ScanMode else "deep"

    if not config:
        return _normal()

    m = str((config.get("mode") or "")).strip().lower()
    alias = {"auth": "authenticated", "kimlikli": "authenticated",
             "detaylı": "detailed", "detayli": "detailed", "derin": "deep"}
    if m in alias:
        m = alias[m]
    if ScanMode and m in (ScanMode.NORMAL, ScanMode.DETAILED, ScanMode.AUTHENTICATED, ScanMode.DEEP):
        return m

    prof = ((config.get("settings") or {}).get("scan_profile") or "").strip().lower()
    if prof == "detailed":
        return _detailed()
    if prof in ("deep", "aggressive"):
        return _deep()
    return _normal()


def apply_profile_by_name(name: str, cfg: dict) -> dict:
    """
    Profil adina gore cfg'yi uygular.
    Yeni ProfileRegistry sistemine kopru — geri uyumlu public API.

    Desteklenen profil adlari:
      aggressive, stealth, cicd, bug_bounty, compliance, api_only, authenticated
      + websecure/config/profiles/ altindaki YAML profiller
    """
    try:
        from websecure.core.profiles import apply_profile
        return apply_profile(name, cfg)
    except Exception as exc:
        _logger.warning(f"[scan_profile] ProfileRegistry hatasi: {exc!r}. Fallback.")
        if name == "aggressive":
            return _apply_aggressive_profile(cfg)
        return _apply_stealth_profile(cfg)


__all__ = [
    "_estimate_minutes",
    "_apply_normal_profile",
    "_apply_aggressive_profile",
    "_apply_stealth_profile",
    "_offer_scan_profile_and_confirm",
    "_pick_from_config",
    "_choose_mode_from_config",
    "apply_profile_by_name",
]
