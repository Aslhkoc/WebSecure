# -*- coding: utf-8 -*-
"""
websecure.core.startup
-----------------------
Scan startup checks: dependency verification and auto-installation.

All _ensure_* functions are collected here so main.py stays lean.
Each function is self-contained, prints progress, and returns bool.

Auto-install coverage:
  Go binaries  : nuclei, httpx, katana, subfinder, dalfox, ffuf,
                 feroxbuster, amass, interactsh-client
  System tools : nmap (OS package manager instructions)
  Python deps  : playwright, curl_cffi
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import time
import subprocess
import urllib.request
from pathlib import Path
from typing import Optional

from websecure.core.platform_compat import (
    binary_name as _bin_name,
    github_release_info as _platform_info,
    extract_binary_from_archive as _extract_binary,
)
from websecure.core import paths as _paths

# Yazılabilir tools/drivers kökü. Kaynak modda proje köküdür (eski davranış);
# dondurulmuş .exe içinde kullanıcı veri dizinine (user_data_dir) yönlenir.
_ROOT = _paths.writable_root()


# ---------------------------------------------------------------------------
# Go binary registry
# ---------------------------------------------------------------------------

# os_name / arch aliases — different tools use different naming conventions
# in their GitHub release asset filenames.
_OS_ALIASES: dict[str, list[str]] = {
    "linux":   ["linux"],
    "darwin":  ["darwin", "macos", "osx", "apple"],
    "windows": ["windows", "win"],
}
_ARCH_ALIASES: dict[str, list[str]] = {
    "amd64": ["amd64", "x86_64", "x64"],
    "arm64": ["arm64", "aarch64"],
    "386":   ["386", "i386", "i686"],
}

# tool_key -> {repo, bin, dest_subdir}
# dest_subdir is relative to _ROOT
_GO_TOOLS: dict[str, dict] = {
    "nuclei":      {"repo": "projectdiscovery/nuclei",     "bin": "nuclei",            "dest": "tools/nuclei"},
    "httpx":       {"repo": "projectdiscovery/httpx",      "bin": "httpx",             "dest": "tools/httpx"},
    "katana":      {"repo": "projectdiscovery/katana",     "bin": "katana",            "dest": "tools/katana"},
    "subfinder":   {"repo": "projectdiscovery/subfinder",  "bin": "subfinder",         "dest": "tools/subfinder"},
    "dalfox":      {"repo": "hahwul/dalfox",               "bin": "dalfox",            "dest": "tools/dalfox"},
    "ffuf":        {"repo": "ffuf/ffuf",                   "bin": "ffuf",              "dest": "tools/ffuf"},
    "feroxbuster": {"repo": "epi052/feroxbuster",          "bin": "feroxbuster",       "dest": "tools/feroxbuster"},
    "amass":       {"repo": "owasp-amass/amass",           "bin": "amass",             "dest": "tools/amass"},
    "interactsh":  {"repo": "projectdiscovery/interactsh", "bin": "interactsh-client", "dest": "drivers"},
}


# ---------------------------------------------------------------------------
# Generic Go binary downloader
# ---------------------------------------------------------------------------

def _asset_matches(filename: str, os_name: str, arch: str) -> bool:
    """
    Returns True if *filename* (lower-cased) contains at least one alias
    for both the OS and the architecture.

    Handles edge cases:
      dalfox   → Linux_x86_64 / macOS_x86_64
      ferox    → x86_64-unknown-linux-musl / apple-darwin
      ffuf     → linux_amd64
      nuclei   → linux_amd64
    """
    fname = filename.lower()
    os_match   = any(alias in fname for alias in _OS_ALIASES.get(os_name, [os_name]))
    arch_match = any(alias in fname for alias in _ARCH_ALIASES.get(arch, [arch]))
    return os_match and arch_match


def _download_go_binary(
    tool_key: str,
    *,
    silent: bool = False,
) -> bool:
    """
    Downloads the correct platform binary from GitHub releases.

    Steps
    -----
    1. GET /repos/{owner}/{repo}/releases/latest  (GitHub API)
    2. Find asset whose filename matches current OS + arch
       (.zip preferred over .tar.gz)
    3. Download archive → tools/{tool}/
    4. Extract binary via platform_compat.extract_binary_from_archive()
    5. Clean up archive

    Returns True on success, False on any failure.
    """
    spec = _GO_TOOLS.get(tool_key)
    if not spec:
        return False

    os_name, arch = _platform_info()
    bin_base  = spec["bin"]
    native    = _bin_name(bin_base)        # "nuclei" or "nuclei.exe"
    dest_dir  = _ROOT / spec["dest"]
    dest_path = dest_dir / native

    if not silent:
        print(f"[*] {bin_base} bulunamadı. GitHub'dan indiriliyor ({os_name}/{arch})…")

    try:
        api_url = f"https://api.github.com/repos/{spec['repo']}/releases/latest"
        with urllib.request.urlopen(api_url, timeout=15) as r:
            data = json.loads(r.read())

        # Prefer .zip, then .tar.gz
        asset_url: Optional[str] = None
        for ext in (".zip", ".tar.gz"):
            asset_url = next(
                (
                    a["browser_download_url"]
                    for a in data.get("assets", [])
                    if _asset_matches(a["name"], os_name, arch)
                    and a["name"].endswith(ext)
                    # Exclude checksums / sbom / pem files
                    and not any(s in a["name"].lower()
                                for s in ("sha256", "md5", "sbom", ".pem", ".sig"))
                ),
                None,
            )
            if asset_url:
                break

        if not asset_url:
            if not silent:
                print(
                    f"[!] {bin_base}: {os_name}/{arch} için asset bulunamadı.\n"
                    f"    Elle indirin: https://github.com/{spec['repo']}/releases"
                )
            return False

        archive_name = asset_url.split("/")[-1]
        archive_path = dest_dir / archive_name
        dest_dir.mkdir(parents=True, exist_ok=True)

        if not silent:
            print(f"    ↓ {archive_name}")
        urllib.request.urlretrieve(asset_url, archive_path)

        ok = _extract_binary(archive_path, dest_path, bin_base)
        archive_path.unlink(missing_ok=True)

        if not ok:
            if not silent:
                print(f"[!] {bin_base}: binary arşivden çıkarılamadı.")
            return False

        if not silent:
            print(f"[+] {bin_base} kuruldu → {dest_path}")
        return True

    except Exception as exc:
        if not silent:
            print(f"[!] {bin_base} indirme hatası: {exc}")
        return False


def _ensure_go_binary(tool_key: str) -> bool:
    """
    Ensures that the Go binary for *tool_key* is available.

    Discovery order
    ---------------
    1. System PATH (shutil.which)
    2. tools/<tool>/<bin>[.exe]  or  drivers/<bin>[.exe]
    3. Auto-download from GitHub releases
    """
    spec = _GO_TOOLS.get(tool_key)
    if not spec:
        return False

    bin_base = spec["bin"]
    native   = _bin_name(bin_base)

    # 1. PATH
    if shutil.which(bin_base) or (native != bin_base and shutil.which(native)):
        return True

    # 2. tools/ / drivers/
    dest_dir = _ROOT / spec["dest"]
    for candidate in (dest_dir / native, dest_dir / bin_base):
        if candidate.exists():
            return True

    # 3. Download
    return _download_go_binary(tool_key)


# ---------------------------------------------------------------------------
# nmap — system package (not a portable Go binary)
# ---------------------------------------------------------------------------

_NMAP_INSTALL_HINTS: dict[str, str] = {
    "linux":   (
        "  Ubuntu/Debian : sudo apt-get install -y nmap\n"
        "  Fedora/RHEL   : sudo dnf install -y nmap\n"
        "  Arch          : sudo pacman -S nmap\n"
        "  Alpine        : apk add nmap"
    ),
    "darwin":  "  macOS (Homebrew): brew install nmap",
    "windows": (
        "  winget : winget install Insecure.Nmap\n"
        "  choco  : choco install nmap\n"
        "  Manuel : https://nmap.org/download.html"
    ),
}


def ensure_nmap() -> bool:
    """
    Returns True if nmap is on PATH.
    If not found, prints OS-specific installation instructions.
    """
    if shutil.which("nmap"):
        return True

    import platform as _plat
    sys_key = {"Windows": "windows", "Darwin": "darwin"}.get(_plat.system(), "linux")
    hint = _NMAP_INSTALL_HINTS.get(sys_key, _NMAP_INSTALL_HINTS["linux"])

    print(
        f"[!] nmap bulunamadı. Port tarama ve servis tespiti devre dışı.\n"
        f"    Kurulum:\n{hint}"
    )
    return False


# ---------------------------------------------------------------------------
# Python/system dependencies
# ---------------------------------------------------------------------------

def ensure_playwright_chromium() -> bool:
    """
    Playwright kurulu ve chromium binary'si mevcut olduğunu kontrol eder.
    Eksikse otomatik olarak 'playwright install chromium' çalıştırır.
    """
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError:
        print("[!] Playwright kurulu değil. Kuruluyor: pip install playwright")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "playwright"],
                check=True, capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            print(f"[!] playwright kurulumu başarısız: {exc}. XSS DOM doğrulaması devre dışı.")
            return False

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        print("[*] Playwright chromium binary bulunamadı. Kuruluyor…")
        try:
            subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                check=True, capture_output=True, text=True, timeout=300,
            )
            print("[+] Playwright chromium kuruldu.")
            return True
        except Exception as exc:
            print(f"[!] playwright install chromium başarısız: {exc}")
            print("[!] XSS DOM doğrulaması bu taramada devre dışı.")
            return False


def ensure_curl_cffi() -> bool:
    """curl_cffi kurulu değilse otomatik kurar (JA3/JA4 TLS taklidi için)."""
    try:
        from curl_cffi import requests as _  # noqa: F401
        return True
    except ImportError:
        print("[*] curl_cffi kuruluyor (TLS parmak izi gizleme)…")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "curl_cffi"],
                check=True, capture_output=True, timeout=120,
            )
            print("[+] curl_cffi kuruldu.")
            return True
        except Exception as exc:
            print(f"[!] curl_cffi kurulamadı: {exc}")
            return False


# ---------------------------------------------------------------------------
# interactsh — special: needs to be launched + token captured
# ---------------------------------------------------------------------------

def ensure_interactsh(cfg: dict) -> bool:
    """
    interactsh-client binary'sini indirir (gerekirse) ve arka planda başlatır.
    Token/host bilgisini stdout'tan okur, cfg['oast'] alanlarını doldurur.
    Config'de zaten geçerli bir token varsa hiçbir şey yapmaz.
    """
    _oast = cfg.get("oast", {}) or {}
    _ic   = _oast.get("interactsh", {}) or {}
    _tok  = _ic.get("token", "")
    if _oast.get("enabled") and _ic.get("enabled") and _tok and "BURAYA" not in _tok:
        return True

    # Ensure binary is present (download if needed)
    if not _ensure_go_binary("interactsh"):
        print("[!] interactsh-client indirilemedi. OAST devre dışı.")
        return False

    # Resolve actual path
    native   = _bin_name("interactsh-client")
    exe_path = _ROOT / "drivers" / native
    if not exe_path.exists():
        found = shutil.which("interactsh-client")
        if found:
            exe_path = Path(found)
        else:
            print("[!] interactsh-client bulunamadı.")
            return False

    print("[*] interactsh-client başlatılıyor…")
    try:
        proc = subprocess.Popen(
            [str(exe_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
        )
        token, host = None, None
        _ansi_re   = re.compile(r'\x1b\[[0-9;]*m|\[[0-9]+m')
        _domain_re = re.compile(r'([a-z0-9]{10,})\.(oast\.[a-z]+|interact\.sh)', re.IGNORECASE)

        for _ in range(100):
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            clean = _ansi_re.sub("", line).strip()
            m = re.search(r"Listing on\s+(\S+)", clean)
            if m:
                subdomain = m.group(1).strip()
                parts = subdomain.split(".", 1)
                if len(parts) == 2:
                    token, host = parts[0], subdomain
                    break
            m2 = _domain_re.search(clean)
            if m2:
                host  = m2.group(0).strip()
                token = m2.group(1).strip()
                break
            time.sleep(0.1)

        if token and host:
            cfg.setdefault("oast", {})["enabled"] = True
            cfg["oast"].setdefault("interactsh", {})["enabled"] = True
            cfg["oast"]["interactsh"]["token"]  = token
            cfg["oast"]["interactsh"]["server"] = (
                "https://" + host.split(".", 1)[1] if "." in host else "https://oast.me"
            )
            cfg["oast"]["dns_domain"]   = host
            cfg["_interactsh_proc"]     = proc
            print(f"[+] interactsh aktif → {host}")
            return True
        else:
            print("[!] interactsh token alınamadı. Config'deki token kullanılacak.")
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
            return False

    except Exception as exc:
        print(f"[!] interactsh başlatılamadı: {exc}")
        return False


# ---------------------------------------------------------------------------
# Convenience wrappers (backward compat + single-call form)
# ---------------------------------------------------------------------------

def ensure_nuclei(cfg: dict) -> bool:  # noqa: ARG001
    """tools/nuclei/nuclei[.exe] yoksa GitHub'dan indirir."""
    return _ensure_go_binary("nuclei")


def ensure_httpx() -> bool:
    return _ensure_go_binary("httpx")


def ensure_katana() -> bool:
    return _ensure_go_binary("katana")


def ensure_subfinder() -> bool:
    return _ensure_go_binary("subfinder")


def ensure_dalfox() -> bool:
    return _ensure_go_binary("dalfox")


def ensure_ffuf() -> bool:
    return _ensure_go_binary("ffuf")


def ensure_feroxbuster() -> bool:
    return _ensure_go_binary("feroxbuster")


def ensure_amass() -> bool:
    return _ensure_go_binary("amass")


# ---------------------------------------------------------------------------
# setup_all — tek komutla her şeyi kur
# ---------------------------------------------------------------------------

def setup_all(cfg: dict | None = None) -> dict[str, bool]:
    """
    Tüm dış araçları kontrol et, eksik olanları indir/kur.

    Kullanım
    --------
    websecure --setup          → CLI'dan çağrılır
    setup_all()                → Python'dan doğrudan
    setup_all(cfg)             → cfg varsa interactsh token'ı doldurur

    Dönüş
    -----
    dict[tool_name, bool]  — her araç için True=mevcut/kuruldu, False=başarısız
    """
    cfg = cfg or {}
    results: dict[str, bool] = {}

    _BANNER = "=" * 60
    print(f"\n{_BANNER}")
    print("  WebSecure — Dış Araç Kurulum Kontrolü")
    print(_BANNER)

    # --- Go araçları ---------------------------------------------------------
    _GO_ORDER = [
        ("nuclei",      "CVE + misconfiguration tarayıcı"),
        ("httpx",       "HTTP/2 hızlı prob + teknoloji tespiti"),
        ("katana",      "JavaScript-aware web crawler"),
        ("subfinder",   "Pasif subdomain enumeration"),
        ("dalfox",      "XSS doğrulama ve analiz"),
        ("ffuf",        "Hızlı içerik/parametre keşif"),
        ("feroxbuster", "Rust tabanlı dizin tarayıcı"),
        ("amass",       "Subdomain + ASN enumeration"),
        ("interactsh",  "OOB/OAST callback sunucusu"),
    ]

    for key, desc in _GO_ORDER:
        sys.stdout.write(f"  [{key:<14}] kontrol ediliyor…\r")
        sys.stdout.flush()
        if key == "interactsh":
            ok = ensure_interactsh(cfg)
        else:
            ok = _ensure_go_binary(key)
        status = "✓" if ok else "✗"
        print(f"  [{key:<14}] {status}  {desc}")
        results[key] = ok

    # --- nmap ----------------------------------------------------------------
    sys.stdout.write(f"  [{'nmap':<14}] kontrol ediliyor…\r")
    sys.stdout.flush()
    ok = ensure_nmap()
    status = "✓" if ok else "!"
    print(f"  [{'nmap':<14}] {status}  Ağ port tarama")
    results["nmap"] = ok

    # --- Python bağımlılıkları -----------------------------------------------
    for fn, label in [
        (ensure_playwright_chromium, "Playwright chromium (DOM XSS)"),
        (ensure_curl_cffi,           "curl_cffi (JA3/JA4 TLS taklidi)"),
    ]:
        try:
            ok = fn()
        except Exception:
            ok = False
        name = label.split()[0].lower()
        status = "✓" if ok else "!"
        print(f"  [{name:<14}] {status}  {label}")
        results[name] = ok

    # --- Özet ----------------------------------------------------------------
    total   = len(results)
    success = sum(1 for v in results.values() if v)
    print(f"\n{_BANNER}")
    print(f"  Sonuç: {success}/{total} araç hazır")
    if success < total:
        missing = [k for k, v in results.items() if not v]
        print(f"  Eksik : {', '.join(missing)}")
        print("  Eksik araçlar devre dışı bırakılır, scan devam eder.")
    print(_BANNER + "\n")

    return results


# ---------------------------------------------------------------------------
# run_all_startup_checks — scan başlangıcında çağrılır (hızlı, sessiz)
# ---------------------------------------------------------------------------

def run_all_startup_checks(cfg: dict) -> dict[str, bool]:
    """
    Scan başlamadan önce kritik bağımlılıkları kontrol et:
    playwright (DOM XSS), curl_cffi (TLS taklidi), nuclei ve interactsh (OAST).
    Eksik olanlar otomatik kurulmaya çalışılır; başarısızlık scan'i durdurmaz.
    Tam/ağır kurulum (tüm Go araçları) için websecure --setup kullanın.
    """
    return {
        "playwright": ensure_playwright_chromium(),
        "curl_cffi":  ensure_curl_cffi(),
        "nuclei":     ensure_nuclei(cfg),
        "interactsh": ensure_interactsh(cfg),
    }


# ---------------------------------------------------------------------------
# initialize_persistence — Adım 20 kalıcılık katmanı
# ---------------------------------------------------------------------------

def initialize_persistence(cfg: dict = None) -> dict:
    """DB, FPLearner, ScoreTracker singleton'larını başlatır."""
    result = {"db": False, "fp_learner": False, "score_tracker": False}
    cfg    = cfg or {}

    try:
        from websecure.db import get_db
        db = get_db()
        result["db"] = True
        print("[+] WebSecure DB başlatıldı.")
    except Exception as exc:
        print(f"[!] DB başlatılamadı: {exc}")
        db = None

    try:
        from websecure.core.fp_learner import get_fp_learner
        get_fp_learner()
        result["fp_learner"] = True
        print("[+] FP öğrenme motoru başlatıldı.")
    except Exception as exc:
        print(f"[!] FP learner başlatılamadı: {exc}")

    try:
        from websecure.core.score_tracker import get_score_tracker
        get_score_tracker(db=db)
        result["score_tracker"] = True
        print("[+] Skor takip motoru başlatıldı.")
    except Exception as exc:
        print(f"[!] Score tracker başlatılamadı: {exc}")

    return result
