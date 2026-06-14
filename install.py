"""
WebSecure Otomatik Kurulum Scripti
====================================
Çalıştır: python install.py
"""
from __future__ import annotations

import subprocess
import sys
import importlib

# ---------------------------------------------------------------------------
# Renkli terminal çıktısı
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"{GREEN}[✓]{RESET} {msg}")
def warn(msg): print(f"{YELLOW}[!]{RESET} {msg}")
def err(msg):  print(f"{RED}[✗]{RESET} {msg}")
def info(msg): print(f"{CYAN}[→]{RESET} {msg}")
def title(msg):print(f"\n{BOLD}{CYAN}{msg}{RESET}")

# ---------------------------------------------------------------------------
# Paket kurulum ve kontrol
# ---------------------------------------------------------------------------

def pip_install(*packages: str, quiet: bool = False) -> bool:
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + list(packages)
    if quiet:
        cmd.append("-q")
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0


def is_importable(module: str) -> bool:
    """Modülün import edilebilir olup olmadığını kontrol et.

    ImportError dışında OSError (eksik sistem DLL/so) ve diğer
    runtime hatalarını da yakalar — weasyprint gibi native bağımlılığı
    olan paketler pip'ten kurulsa bile sistem kütüphanesi eksikse
    OSError/AttributeError fırlatabilir.
    """
    try:
        importlib.import_module(module)
        return True
    except (ImportError, ModuleNotFoundError):
        return False
    except Exception:
        # OSError (libgobject, pango vb.), AttributeError, vs.
        # Paket kurulu ama çalışmıyor → False döndür, çöktürme
        return False


# ---------------------------------------------------------------------------
# Paket listesi
# ---------------------------------------------------------------------------

# (pip_name, import_name, zorunlu_mu, açıklama)
PACKAGES = [
    # --- Zorunlu temel ---
    ("requests>=2.32.0",        "requests",        True,  "HTTP istemcisi"),
    ("beautifulsoup4>=4.12.2",  "bs4",             True,  "HTML ayrıştırıcı"),
    ("lxml>=5.2.2",             "lxml",            True,  "XML/HTML kütüphanesi"),
    ("tldextract>=5.1.2",       "tldextract",      True,  "Alan adı ayrıştırıcı"),
    ("cryptography>=42.0.0",    "cryptography",    True,  "RSA/AES (OAST şifreleme)"),
    ("jinja2>=3.1.0",           "jinja2",          True,  "Şablon motoru"),
    ("cvss>=3.2",               "cvss",            True,  "CVSS skorlama"),
    ("regex>=2024.4.16",        "regex",           True,  "Gelişmiş regex"),

    # --- WAF Bypass (en kritik) ---
    ("curl-cffi>=0.6.0",        "curl_cffi",       False, "TLS parmak izi taklidi (JA3/JA4) — Cloudflare bypass"),
    ("tls-client>=1.0.1",       "tls_client",      False, "TLS parmak izi fallback"),
    ("cloudscraper>=1.2.71",    "cloudscraper",    False, "Cloudflare JS challenge bypass"),

    # --- Proxy desteği ---
    ("PySocks>=1.7.1",          "socks",           False, "SOCKS4/SOCKS5 proxy"),
    ("requests[socks]>=2.32.0", "requests",        False, "requests SOCKS eklentisi"),

    # --- Tarayıcı otomasyonu ---
    ("playwright>=1.46.0",      "playwright",      False, "DOM XSS, JS crawl (Playwright)"),

    # --- Raporlama ---
    ("weasyprint>=61.0",        "weasyprint",      False, "PDF raporu"),

    # --- Performans ---
    ("python-Levenshtein>=0.25.0", "Levenshtein",  False, "Hızlı string benzerliği"),
    ("httpx[http2]>=0.27.0",    "httpx",           False, "HTTP/2 desteği"),
]


# ---------------------------------------------------------------------------
# Ana kurulum akışı
# ---------------------------------------------------------------------------

def main():
    title("=" * 52)
    title("  WebSecure — Otomatik Bağımlılık Kurulumu")
    title("=" * 52)

    # pip'i güncelle
    info("pip güncelleniyor...")
    pip_install("pip", quiet=True)

    failed_critical = []
    failed_optional = []
    installed = []
    already_ok = []

    title("Paketler kuruluyor...")
    for pip_name, import_name, critical, desc in PACKAGES:
        base_name = pip_name.split(">=")[0].split("[")[0]

        if is_importable(import_name):
            already_ok.append(base_name)
            ok(f"{base_name:<28} zaten kurulu  ({desc})")
            continue

        info(f"{base_name:<28} kuruluyor...  ({desc})")
        success = pip_install(pip_name, quiet=True)

        if success and is_importable(import_name):
            installed.append(base_name)
            ok(f"{base_name:<28} kuruldu")
        else:
            if critical:
                failed_critical.append(base_name)
                err(f"{base_name:<28} BAŞARISIZ (zorunlu!)")
            else:
                failed_optional.append(base_name)
                warn(f"{base_name:<28} kurulamadı (opsiyonel)")

    # Playwright tarayıcı binary'si
    if is_importable("playwright"):
        title("Playwright tarayıcısı kontrol ediliyor...")
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            ok("Playwright Chromium kuruldu")
        else:
            warn("Playwright Chromium kurulamadı (DOM XSS taraması devre dışı)")

    # Özet
    title("=" * 52)
    title("  Kurulum Özeti")
    title("=" * 52)
    print(f"  {GREEN}Kuruldu    :{RESET} {len(installed)}")
    print(f"  {CYAN}Zaten vardı:{RESET} {len(already_ok)}")
    print(f"  {YELLOW}Opsiyonel  :{RESET} {len(failed_optional)}")
    print(f"  {RED}Kritik hata:{RESET} {len(failed_critical)}")

    if failed_critical:
        title("HATA — Zorunlu paketler eksik!")
        for p in failed_critical:
            err(p)
        print(f"\n  Manuel kur: {BOLD}pip install {' '.join(failed_critical)}{RESET}")
        sys.exit(1)

    if failed_optional:
        title("Eksik opsiyonel paketler:")
        for p in failed_optional:
            note = ""
            if p == "curl-cffi":
                note = "← Cloudflare bypass için ÖNEMLİ"
            elif p == "PySocks":
                note = "← Residential proxy için gerekli"
            warn(f"  {p} {note}")

    # Önemli uyarılar
    if "curl-cffi" in failed_optional:
        print(f"""
{YELLOW}⚠  curl-cffi kurulamadı!{RESET}
   Cloudflare, Akamai gibi WAF'lar Python'un TLS imzasını tanir.
   curl-cffi olmadan bu WAF'lari bypass etmek cok daha zordur.

   Cozum (Windows):
     pip install curl-cffi --pre

   Cozum (Linux/Mac):
     pip install curl-cffi
""")

    if "weasyprint" in failed_optional:
        print(f"""
{YELLOW}⚠  weasyprint PDF motoru calismiyor!{RESET}
   WeasyPrint Windows'ta GTK/Pango sistem kutuphanelerine ihtiyac duyar.
   Bu kutuphaneler Python ile gelmiyor, ayri kurulumu gerekiyor.

   Cozum A — GTK for Windows Runtime kur (onerilir):
     1. https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
     2. GTK3-Runtime-*.exe indirip kur
     3. Bilgisayari yeniden baslat, sonra tekrar: python install.py

   Cozum B — weasyprint'i atla, PDF yerine HTML raporu kullan:
     python -m websecure scan --target https://hedef.com --format html

   Cozum C — Linux/WSL kullan:
     sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
     pip install weasyprint
""")

    if not failed_critical:
        print(f"\n{GREEN}{BOLD}  Kurulum tamamlandı! WebSecure kullanıma hazır.{RESET}")
        print(f"  Başlatmak için: {BOLD}python -m websecure --help{RESET}\n")


if __name__ == "__main__":
    main()
