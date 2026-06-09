"""
websecure.core.cli.interactive
-------------------------------
Interactive wizard prompts extracted from main():
  - setup_tor   — Tor anonymity choice + auto-start
  - setup_auth  — Authenticated scan credential collection
  - setup_proxy — Proxy pool configuration + OpSec summary

Each function mutates `cfg` in-place and returns None.
All functions respect args.dry_run / args.batch (non-interactive mode).
"""
from __future__ import annotations

import logging
import os
import subprocess
import time as _time
from argparse import Namespace


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_logger = logging.getLogger(__name__)

def _try_autostart_tor() -> str | None:
    """Detect a running Tor instance or start one. Returns socks URL or None."""
    from websecure.core.session_factory import _proxy_alive  # noqa: PLC0415

    for _port in [9150, 9050]:
        if _proxy_alive(f"socks5h://127.0.0.1:{_port}"):
            return f"socks5h://127.0.0.1:{_port}"

    from websecure.core.platform_compat import tor_browser_exe_candidates as _tor_candidates
    for _tb in _tor_candidates():
        if os.path.exists(_tb):
            try:
                subprocess.Popen([_tb], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for _ in range(20):
                    _time.sleep(1)
                    if _proxy_alive("socks5h://127.0.0.1:9150"):
                        return "socks5h://127.0.0.1:9150"
            except Exception as _fix_e:
                _logger.debug(f"[core.cli.interactive] {type(_fix_e).__name__}: {_fix_e!r}")

    try:
        subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(15):
            _time.sleep(1)
            if _proxy_alive("socks5h://127.0.0.1:9050"):
                return "socks5h://127.0.0.1:9050"
    except Exception as _fix_e:
        _logger.debug(f"[core.cli.interactive] {type(_fix_e).__name__}: {_fix_e!r}")

    return None


def _read(prompt: str, default: str) -> str:
    """Read one line from stdin; return default on EOF/empty."""
    try:
        val = input(prompt)
        s = (val if isinstance(val, str) else "").strip()
        return s if s else default
    except EOFError:
        return default


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def setup_tor(cfg: dict, args: Namespace) -> None:
    """
    Interactive Tor anonymity choice.
    Mutates cfg['_tor_proxy'], cfg['http']['proxies'], cfg['privacy']['tor'].
    In dry-run / batch mode silently skips (no Tor).
    """
    if args.dry_run or args.batch:
        cfg["_tor_proxy"] = None
        return

    print("\n" + "=" * 60)
    print("  [?] Tor Anonimlik Ayari")
    print("  Tor kullanilmadan tarama yapilirsa GERCEK IP ADRESINIZ")
    print("  hedef sunucuya, ISP'ye ve ag dinleyicilerine acik olur.")
    print("  Tum araclar (Nmap, SQLMap, FFUF, Nuclei) da ayni sekilde")
    print("  gercek IP ile baglanir.")
    print("")

    _tor_ans = _read("  Tor ile anonim tarama yapmak ister misiniz? (E/h): ", "e").lower()

    if _tor_ans.startswith("e"):
        print("  [*] Tor baglantisi kontrol ediliyor...")
        _socks = _try_autostart_tor()
        if _socks:
            http_cfg = cfg.setdefault("http", {})
            proxies = http_cfg.setdefault("proxies", {})
            proxies["http"] = _socks
            proxies["https"] = _socks
            cfg.setdefault("privacy", {}).setdefault("tor", {})["enabled"] = True
            cfg["privacy"]["tor"]["socks_url"] = _socks
            cfg["_tor_proxy"] = _socks
            # Tor is slow (onion latency) and target WAFs answer payloads with 403.
            # Flag Tor active so the HTTP layer raises its per-request timeout floor
            # and the circuit breaker switches to tolerant thresholds — otherwise a
            # 4-5s read timeout + 50 % 403 ratio aborts whole phases on every run.
            try:
                from websecure.core.http import set_power_flags
                set_power_flags(tor_active=True)
            except Exception:
                pass
            try:
                from websecure.core.circuit_breaker import reset_circuit_breaker
                reset_circuit_breaker()  # cfg=None → picks up tolerant env defaults
            except Exception:
                pass
            # KRİTİK gizlilik: yalnız proxied requests.Session Tor'dan geçiyordu; ham
            # socket.create_connection (TLS scanner ~12 probe, ws_fuzz, port kontrolü)
            # ve proxy'siz doğrudan requests çağrıları GERÇEK IP ile bağlanıyordu +
            # DNS lokal sızıyordu. Tüm process socket'lerini Tor'a + uzak-DNS'e zorla.
            _sock_routed = False
            try:
                from urllib.parse import urlparse as _up
                from websecure.core.egress import enable_global_tor_socket, disable_global_tor_socket
                _pp = _up(_socks)
                _sock_routed = enable_global_tor_socket(_pp.hostname or "127.0.0.1", _pp.port or 9050)
                if _sock_routed:
                    import atexit as _atx
                    _atx.register(disable_global_tor_socket)
            except Exception as _e_sock:
                print(f"  [!] Socket-seviyesi Tor zorlaması kurulamadı: {_e_sock}")
            print(f"  [+] Tor aktif: {_socks}")
            if _sock_routed:
                print("  [+] HAM SOCKET + DNS de Tor'dan geçer (TLS/ws_fuzz IP+DNS sızıntısı kapatıldı; localhost bypass).")
            else:
                print("  [!] UYARI: PySocks yok — ham socket bağlantıları (TLS analizi/ws_fuzz) GERÇEK IP ile gidebilir!")
            print("  [+] Python HTTP trafiği + SQLMap, FFUF, Nuclei, Katana -> Tor (gercek IP gizli).")
            print("  [!] ISTISNA — NMAP: Port taramasi raw-socket/dogrudan TCP kullanir.")
            print("      Tor yalnizca TCP stream tasir; SYN/UDP/OS tespiti ve ping")
            print("      Tor'dan GECMEZ. Bu yuzden Nmap fazi GERCEK IP'nizi hedefe gosterir.")
            print("      Anonimlik kritikse: Nmap'i kapatin (--no-nmap) ya da -sT + proxychains.")
            print("  [!] TARAYICI (Playwright/Selenium): WebRTC/DNS sizdirabilir; tam")
            print("      anonimlik icin tarayicili tarama yerine Tor Browser kullanin.")
        else:
            print("  [!] Tor baslatilamadi veya bulunamadi.")
            print("  [!] Tor Browser'i elle acin ve tekrar deneyin.")
            print("  [!] UYARI: Bu tarama GERCEK IP ile yapilacak!")
            cfg["_tor_proxy"] = None
    else:
        print("")
        print("  +======================================================+")
        print("  |  [!]  GIZLILIK UYARISI                                |")
        print("  |  Tor kullanilmiyor!                                  |")
        print("  |  IP adresiniz hedef sunucuya acikca gorunuyor.       |")
        print("  |  ISP ve ag dinleyicileri tarama yaptigınızı biliyor. |")
        print("  |  Sadece yetkili olduguz sistemlerde devam edin.      |")
        print("  +======================================================+")
        print("")
        cfg["_tor_proxy"] = None

    print("=" * 60 + "\n")


def setup_auth(cfg: dict, args: Namespace) -> None:
    """
    Interactive authentication credential collection.
    Mutates cfg['authenticated']['auth_profiles'] with user-supplied credentials.
    In dry-run / batch mode skips interactivity.
    """
    _auth_profiles_cfg = ((cfg.get("authenticated") or {}).get("auth_profiles") or [])
    _profile_valid = (
        _auth_profiles_cfg
        and _auth_profiles_cfg[0].get("username")
        and _auth_profiles_cfg[0].get("username") != "KULLANICI_ADI"
        and _auth_profiles_cfg[0].get("password")
        and _auth_profiles_cfg[0].get("password") != "SIFRE"
        and _auth_profiles_cfg[0].get("login_url")
        and "hedef-site" not in _auth_profiles_cfg[0].get("login_url", "")
    )

    if args.dry_run or args.batch:
        return

    print("\n" + "=" * 60)
    print("  [?] Kimlik Dogrulama (Authenticated Scan)")
    print("  Hedef sitede hesap varsa login bilgilerini girin.")
    print("  Login gerektiren sayfalar da taranacak.")
    print("")
    print("  +======================================================+")
    print("  |  [!]  OPERASYONEL GUVENLIK (OpSec) UYARISI           |")
    print("  |                                                      |")
    print("  |  GERCEK hesabinizla giris yaparsaniz:               |")
    print("  |   • Hesabiniz hedef sunucu LOGLARINDA gorunur       |")
    print("  |   • IP adresiniz hesabinizla ESLESTIRILIR           |")
    print("  |   • Anormal istek paterni hesaba BAGLANIR           |")
    print("  |   • Hesabiniz banlanabilir / kimliginiz ifsa olur   |")
    print("  |                                                      |")
    print("  |  -> Mutlaka OZEL BIR TEST HESABI olusturun!         |")
    print("  |  -> Test hesabi: test_scan@gecici-mail.com gibi      |")
    print("  |  -> Gercek isim / gercek mail KULLANMAYIN            |")
    print("  +======================================================+")
    print("")

    if _profile_valid:
        print(f"  [+] Config'de kayitli profil: {_auth_profiles_cfg[0].get('username')}")
        _ans = _read("  Bu profili kullanmak ister misiniz? (E/h): ", "e").lower()
    else:
        _ans = _read("  Giris bilgileri girecek misiniz? (e/h): ", "h").lower()

    if _ans == "e":
        if not _profile_valid:
            _login_url = _read("  Login sayfasi URL (ornek: https://site.com/login): ", "")
            _username  = _read("  Kullanici adi / e-posta (TEST hesabi kullanin!): ", "")
            _password  = _read("  Sifre: ", "")
            _ufield    = _read("  Username input name (Enter = username): ", "username")
            _pfield    = _read("  Password input name (Enter = password): ", "password")
            _success   = _read("  Giris sonrasi sayfada gecen kelime (Enter = dashboard): ", "dashboard")

            if _login_url and _username and _password:
                _new_profile = {
                    "login_url":        _login_url,
                    "username":         _username,
                    "password":         _password,
                    "username_field":   _ufield,
                    "password_field":   _pfield,
                    "success_indicator": _success,
                }
                profiles = cfg.setdefault("authenticated", {}).setdefault("auth_profiles", [])
                if profiles:
                    profiles[0] = _new_profile
                else:
                    profiles.append(_new_profile)
                print("  [+] Kimlik bilgileri alindi. Otomatik giris yapilacak.")
            else:
                print("  [!] Eksik bilgi. Kimlik dogrulama atlaniyor.")
        else:
            print("  [+] Mevcut profil kullanilacak.")
    else:
        print("  [i] Kimlik dogrulama atlaniyor.")

    print("=" * 60 + "\n")


def setup_proxy(cfg: dict, args: Namespace) -> None:
    """
    Interactive proxy / IP-rotation setup and OpSec summary.
    Mutates cfg['http']['proxies'] and cfg['network']['proxies'].
    In dry-run / batch mode skips interactivity.
    """
    if args.dry_run or args.batch:
        if args.dry_run:
            print("[Dry-Run] Proxy sorusu atlanıyor (varsayilan: hayir).")
        return

    print("\n" + "=" * 60)
    print("  [?] Proxy / IP Rotasyon Ayari")
    print("  Tek IP ile tarama = hedef loglarinda ayni IP surekli gorunur.")
    print("  Proxy havuzu ile rotasyon = her istekte farkli IP, tespiti zorlaştiriyor.")
    print("")
    print("  Secenekler:")
    print("    1) Proxy yok  — Gercek IP (Tor sectiyseniz o gecerli)")
    print("    2) Tek proxy  — Burp Suite / HTTPS proxy (debug/intercept)")
    print("    3) Proxy havuzu — Birden fazla proxy, otomatik rotasyon")
    print("")
    _choice = (_read("  Seciminiz [1/2/3, Enter=1]: ", "1") or "1").strip()

    if _choice == "2":
        purl = _read("  Proxy URL (ornek: http://127.0.0.1:8080): ", "").strip()
        if purl:
            cfg.setdefault("http", {}).setdefault("proxies", {})
            cfg["http"]["proxies"]["http"]  = purl
            cfg["http"]["proxies"]["https"] = purl
            cfg.setdefault("network", {}).setdefault("proxies", {})["pool"] = [purl]
            print(f"  [+] Tek proxy ayarlandi: {purl}")
        else:
            print("  [!] URL girilmedi, proxy atlanıyor.")

    elif _choice == "3":
        print("  Her satirda bir proxy URL girin. Bos satir ile bitirin.")
        print("  Format: http://user:pass@host:port  veya  socks5h://host:port")
        _pool: list[str] = []
        _idx = 1
        while True:
            _pline = _read(f"  Proxy #{_idx} (bos birak = bitti): ", "").strip()
            if not _pline:
                break
            _pool.append(_pline)
            _idx += 1

        if _pool:
            cfg.setdefault("network", {}).setdefault("proxies", {})
            cfg["network"]["proxies"]["pool"]              = _pool
            cfg["network"]["proxies"]["rotate"]            = "round_robin"
            cfg["network"]["proxies"]["failure_threshold"] = 3
            cfg.setdefault("http", {}).setdefault("proxies", {})
            cfg["http"]["proxies"]["http"]  = _pool[0]
            cfg["http"]["proxies"]["https"] = _pool[0]
            print(f"  [+] {len(_pool)} proxy yuklendi. Rotasyon: round_robin")
            try:
                from websecure.core.waf_bypass import init_egress_manager  # noqa: PLC0415
                init_egress_manager(cfg)
                print("  [+] IP rotasyon motoru (EgressManager) baslatildi.")
            except Exception as _em_ex:
                print(f"  [!] EgressManager baslanamadi: {_em_ex}")
        else:
            print("  [!] Hicbir proxy girilmedi. Proxy havuzu atlanıyor.")
    else:
        print("  [i] Proxy kullanilmayacak.")

    print("=" * 60 + "\n")

    # --- OpSec Summary ---
    _tor_on    = bool(cfg.get("_tor_proxy"))
    _pool_on   = bool((cfg.get("network", {}).get("proxies") or {}).get("pool"))
    # Tor açıkken http.proxies.https Tor adresiyle dolar; bunu "tek proxy" sanma.
    _https_proxy = str((cfg.get("http", {}).get("proxies") or {}).get("https") or "")
    _proxy_is_tor = "socks" in _https_proxy.lower() or bool(_tor_on)
    _single_on = bool(_https_proxy) and not _pool_on and not _proxy_is_tor
    # Placeholder profil (KULLANICI_ADI) gerçek hesap değildir.
    _uname     = (((cfg.get("authenticated") or {}).get("auth_profiles") or [{}])[0].get("username") or "")
    _auth_on   = bool(_uname) and _uname != "KULLANICI_ADI"

    print("  +-----------------------------------------------------+")
    print("  |              TARAMA OPSec OZETI                     |")
    print("  +-----------------------------------------------------+")
    _tor_str = "[OK] AKTIF" if _tor_on else "[FAIL] Kapali — Gercek IP gorunuyor"
    print(f"  |  Tor           : {_tor_str:40}|")
    if _pool_on:
        _pc = len(cfg["network"]["proxies"]["pool"])
        print(f"  |  Proxy havuzu  : [OK] {_pc} proxy, round_robin rotasyon{' ' * max(0, 17 - len(str(_pc)))}|")
    elif _single_on:
        print(f"  |  Tek proxy     : [OK] AKTIF{' ' * 30}|")
    else:
        print(f"  |  Proxy         : [FAIL] Yok — Gercek IP{' ' * 19}|")
    if _auth_on:
        print(f"  |  Hesap         : [!] {_uname[:36]:36}|")
        print(f"  |  (!) Hedef bu hesabi loglarinda gorecek{' ' * 14}|")
    else:
        print(f"  |  Hesap         : Kimlik dogrulama yok{' ' * 16}|")
    print("  +-----------------------------------------------------+")
    print("")
