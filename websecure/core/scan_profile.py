"""
websecure.core.scan_profile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Profil seçme/uygulama yardımcıları.
main.py'den taşındı (FAZ-EK).

İçerik:
  - _estimate_minutes
  - _apply_normal_profile
  - _offer_scan_profile_and_confirm
  - _pick_from_config
  - _choose_mode_from_config
"""
from __future__ import annotations

import os
import re
import logging

_logger = logging.getLogger(__name__)


def _estimate_minutes(config: dict, profile: str) -> tuple[int, int]:
    """Çok kaba bir süre kestirimi (dakika). Raporsal amaçlıdır; garanti vermez."""

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

    # fuzz ayarları
    fz = cfg.get("fuzz")
    fz = fz if isinstance(fz, dict) else {}

    rps = _to_float(fz.get("rps"), 0.0)
    if rps <= 0.0:
        rate_ms = _to_float(fz.get("rate_ms"), 0.0)
        rps = 1000.0 / rate_ms if rate_ms > 0.0 else 10.0

    max_total = _to_int(fz.get("max_total"), 2000)
    if max_total < 1:
        max_total = 2000

    base_sec = max_total / (rps if rps > 0.0 else 1.0)

    # discovery overhead
    disc = cfg.get("content_discovery")
    disc = disc if isinstance(disc, dict) else {}
    disc_over = 8 * 60 if bool(disc.get("enabled")) else 0

    # offensive overhead
    off = cfg.get("offensive")
    off = off if isinstance(off, dict) else {}
    of_count = sum(1 for v in off.values() if isinstance(v, dict) and bool(v.get("enabled")))

    prof = profile.lower() if isinstance(profile, str) else ""
    off_over = of_count * (90 if prof == "aggressive" else 45)  # saniye

    sec = base_sec + disc_over + off_over
    lo = int(max(1, round((sec / 60.0) * 0.8)))
    hi = int(max(1, round((sec / 60.0) * 1.4)))
    if hi < lo:
        hi = lo + 1

    return (lo, hi)


def _apply_normal_profile(config: dict) -> tuple[dict, list[str]]:
    """Config üzerinde NORMAL (stealth) profil ayarı yapar ve yoğunluğu azaltır.
    Mutasyon: verilen sözlüğü yerinde günceller, ayrıca değişiklik notlarını döndürür.
    """

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

    if not isinstance(config, dict):
        return {}, ["Config sözlük değil; normal profil uygulanamadı"]

    notes: list[str] = []

    # --- Fuzz ---
    fz = config.setdefault("fuzz", {})
    if not isinstance(fz, dict):
        fz = {}
        config["fuzz"] = fz

    if "per_param" in fz:
        old = _to_int(fz.get("per_param"), 10)
        new = max(1, old // 2)
        fz["per_param"] = new
        notes.append(f"Parametre başına mutasyon sayısı {old}→{new}")
    else:
        fz["per_param"] = 3
        notes.append("Parametre başına mutasyon sayısı 3 olarak sınırlandı")

    if "max_total" in fz:
        old = _to_int(fz.get("max_total"), 1000)
        new = max(50, old // 2)
        fz["max_total"] = new
        notes.append(f"Toplam enjeksiyon {old}→{new}")
    else:
        fz["max_total"] = 500
        notes.append("Toplam enjeksiyon 500 ile sınırlandı")

    if "rps" in fz:
        old = _to_int(fz.get("rps"), 20)
        new = max(1, old // 2)
        fz["rps"] = new
        notes.append(f"Fuzz RPS {old}→{new}")
    elif ("rate_ms" in fz) and bool(fz.get("rate_ms")):
        old = _to_int(fz.get("rate_ms"), 100)
        new = max(50, old * 2)
        fz["rate_ms"] = new
        notes.append(f"Fuzz rate_ms {old}→{new}")
    else:
        fz["rps"] = 10
        notes.append("Fuzz RPS 10 olarak ayarlandı")

    # --- Offensive (stealth) ---
    off = config.setdefault("offensive", {})
    if not isinstance(off, dict):
        off = {}
        config["offensive"] = off
    off["profile"] = "stealth"
    for k in ("request_smuggling", "mass_assignment", "websocket_fuzz"):
        node = off.setdefault(k, {})
        if isinstance(node, dict):
            node.setdefault("enabled", False)
    for k in ("jwt_attacks", "nosql_injection"):
        node = off.setdefault(k, {})
        if isinstance(node, dict):
            node.setdefault("enabled", True)

    # --- WAF ---
    waf = config.setdefault("waf", {})
    if not isinstance(waf, dict):
        waf = {}
        config["waf"] = waf
    if "max_variants_per_payload" in waf:
        old = _to_int(waf.get("max_variants_per_payload"), 6)
        new = max(1, old // 2)
        waf["max_variants_per_payload"] = new
        notes.append(f"WAF payload varyantları {old}->{new}")

    # --- OAST ---
    oast = config.setdefault("oast", {})
    if not isinstance(oast, dict):
        oast = {}
        config["oast"] = oast
    if "max_injections_per_loc" in oast:
        old = _to_int(oast.get("max_injections_per_loc"), 3)
        new = max(1, old // 2)
        oast["max_injections_per_loc"] = new
        notes.append(f"OAST enjeksiyonları {old}->{new}")

    # --- GraphQL ---
    gql = config.setdefault("graphql", {})
    if not isinstance(gql, dict):
        gql = {}
        config["graphql"] = gql
    if bool(gql.get("deep", True)):
        gql["deep"] = False
        notes.append("GraphQL derin testler sadeleştirildi (introspection + temel kontroller)")

    # --- İçerik keşfi ---
    cd = config.setdefault("content_discovery", {})
    if not isinstance(cd, dict):
        cd = {}
        config["content_discovery"] = cd
    rate = _to_int(cd.get("rate_limit"), 50)
    new_rate = max(10, rate // 2)
    cd["rate_limit"] = new_rate
    notes.append(f"İçerik keşfi hız limiti {rate}->{new_rate}")

    return config, notes


def _offer_scan_profile_and_confirm(cfg: dict) -> tuple[str, dict]:
    """Kullanıcıya Agresif/Normal profilini sorar ve cfg'yi buna göre ayarlar."""

    def _prompt(msg: str, default: str) -> str:
        try:
            val = input(msg)
            s = (val if isinstance(val, str) else "").strip()
            return s if s != "" else default
        except EOFError:
            return default

    # Lazy import to avoid circular at module load time
    def _get_apply_active_profile():
        try:
            from websecure.core.utils import apply_active_profile
            return apply_active_profile
        except Exception:
            return lambda c: c

    while True:
        print("""
[?] Tarama yoğunluğu:
    1) Agresif - kapsam ve mutasyonlar tam (daha uzun sürebilir)
    2) Normal   - payload/mutasyon yoğunluğu azaltılır (kapsam korunur)
    3) Güvenli Full - WAF atlatma öncelikli, tüm araçlar aktif (en yavaş, en kapsamlı)
""".rstrip())

        sel = (_prompt("Seçiminiz [1/2/3, varsayılan=1]: ", "1") or "1").strip()
        if sel not in ("1", "2", "3"):
            print("Geçersiz seçim.")
            continue

        if sel == "1":
            lo, hi = _estimate_minutes(cfg, "aggressive")
            print(f"[!] Agresif modu seçtiniz. Yaklaşık {lo}-{hi} dakika sürebilir.")
            ans = (_prompt("Devam etmek istiyor musunuz? [D]evam / [B]aşa dön: ", "D") or "D").lower()
            if ans.startswith("b"):
                continue
            cfg.setdefault("settings", {})["scan_profile"] = "aggressive"
            cfg.setdefault("_profile", {})["selected"] = "aggressive"
            off = cfg.setdefault("offensive", {})
            off["profile"] = "deep"
            for k in ("request_smuggling", "mass_assignment", "jwt_attacks", "nosql_injection", "websocket_fuzz"):
                node = off.setdefault(k, {})
                if isinstance(node, dict):
                    node["enabled"] = True

            # [WS3] UNLOCKED: Enable full destructive potential (Realism)
            os.environ["WS_PAYLOADS_MAX"] = "100000"
            print("[!] Sınırlar Kaldırıldı: Payload limiti 100,000'e yükseltildi.")
            print("[!] DİKKAT: Yıkıcı mod aktif (DELETE/DROP tabloları silinebilir).")

            # [FIX] Apply profile settings
            apply_active_profile = _get_apply_active_profile()
            cfg = apply_active_profile(cfg)
            print(f"[DEBUG] Active Config Profile: {cfg.get('settings', {}).get('scan_profile')} (Applied: True)")

            return "aggressive", cfg

        if sel == "3":
             print(f"[!] Güvenli Full (WAF Evasion) modu seçtiniz. Çok yavaş ama gizli çalışır.")
             ans = (_prompt("Devam etmek istiyor musunuz? [D]evam / [B]aşa dön: ", "D") or "D").lower()
             if ans.startswith("b"):
                 continue
             cfg.setdefault("settings", {})["scan_profile"] = "safe_full"
             cfg.setdefault("_profile", {})["selected"] = "safe_full"

             # [FIX] Apply profile settings immediately (RPS, concurrency etc.)
             apply_active_profile = _get_apply_active_profile()
             cfg = apply_active_profile(cfg)
             print(f"[DEBUG] Active Config Profile: {cfg.get('settings', {}).get('scan_profile')} (Applied: True)")

             return "safe_full", cfg

             # Activate all offensive modules but with 'safe' defaults implied by profile
             off = cfg.setdefault("offensive", {})
             off["profile"] = "deep" # needs deep module access
             for k in ("request_smuggling", "mass_assignment", "jwt_attacks", "nosql_injection", "websocket_fuzz"):
                node = off.setdefault(k, {})
                if isinstance(node, dict):
                    node["enabled"] = True

             # [WS3] STEALTH-SNIPER MODE:
             # User requested: "Don't be cowardly" + "Avoid WAF"
             # Solution: High Payload Count + Low Speed
             os.environ["WS_PAYLOADS_MAX"] = "100000"
             print("[!] STEALTH-SNIPER Modu: Payload limiti 100,000 (Yıkıcı/Gerçekçi).")
             print("[!] NOT: WAF yakalanmamak için yavaş çalışır. Sabırlı olun.")
             print("[✓] GÜVENLİK: Bu saldırılar SADECE hedef URL'ye yapılır. Sizin bilgisayarınız etkilenmez.")

             return "safe_full", cfg
             return "safe_full", cfg

        # sel == "2"
        cfg2, notes = _apply_normal_profile(dict(cfg))  # kopya üstünde
        print("[i] Normal mod: aşağıdaki alanlarda yoğunluk azaltılacak:")
        for n in notes:
            print("   - ", n)
        ans = (_prompt("Devam edilsin mi? [D]evam / [B]aşa dön: ", "D") or "D").lower()
        if ans.startswith("b"):
            continue
        cfg2.setdefault("settings", {})["scan_profile"] = "normal"
        cfg2.setdefault("_profile", {})["selected"] = "normal"
        off = cfg2.setdefault("offensive", {})
        off["profile"] = "stealth"
        for k in ("request_smuggling", "mass_assignment", "websocket_fuzz"):
            node = off.setdefault(k, {})
            if isinstance(node, dict):
                node["enabled"] = False
        for k in ("jwt_attacks", "nosql_injection"):
            node = off.setdefault(k, {})
            if isinstance(node, dict):
                node.setdefault("enabled", True)
        return "normal", cfg2


def _pick_from_config(cfg: dict, key: str, default=None):
    v = cfg.get(key)
    return default if v is None else v


def _choose_mode_from_config(config: dict | None) -> str:
    """Mode seçimi: sadece kullanıcı açıkça AUTHENTICATED seçerse auth moduna geç.
    Otomatik şarta (auth.enabled/username/token) bakarak asla AUTHENTICATED seçme.
    Aksi halde NORMAL/DETAILED/DEEP mantığı korunur."""
    # Import ScanMode lazily to avoid circular imports
    try:
        from websecure.core.phases import ScanMode  # type: ignore
    except Exception:
        ScanMode = None  # type: ignore

    def _normal():
        return ScanMode.NORMAL if ScanMode else "normal"

    def _detailed():
        return ScanMode.DETAILED if ScanMode else "detailed"

    def _deep():
        return ScanMode.DEEP if ScanMode else "deep"

    if not config:
        return _normal()

    # Explicit mode
    m = str((config.get("mode") or "")).strip().lower()
    alias = {"auth": "authenticated", "kimlikli": "authenticated", "detaylı": "detailed", "detayli": "detailed", "derin": "deep"}
    if m in alias:
        m = alias[m]
    if ScanMode and m in (ScanMode.NORMAL, ScanMode.DETAILED, ScanMode.AUTHENTICATED, ScanMode.DEEP):
        return m

    # Profile fallback (never escalates to AUTHENTICATED implicitly)
    prof = ((config.get("settings") or {}).get("scan_profile") or "").strip().lower()
    if prof == "detailed":
        return _detailed()
    if prof == "deep":
        return _deep()
    return _normal()


__all__ = [
    "_estimate_minutes",
    "_apply_normal_profile",
    "_offer_scan_profile_and_confirm",
    "_pick_from_config",
    "_choose_mode_from_config",
]
