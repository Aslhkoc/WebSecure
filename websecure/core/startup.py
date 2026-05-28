"""
websecure.core.startup
-----------------------
Scan startup checks: dependency verification and auto-installation.

All _ensure_* functions are collected here so main.py stays lean.
Each function is self-contained, prints progress, and returns bool.
"""
from __future__ import annotations

import re
import sys
import time
import subprocess
import urllib.request
from pathlib import Path

from websecure.core.platform_compat import (
    binary_name as _bin_name,
    github_release_info as _platform_info,
    extract_binary_from_archive as _extract_binary,
)

_ROOT = Path(__file__).resolve().parent.parent.parent  # project root


def ensure_playwright_chromium() -> bool:
    """
    Playwright'ın kurulu ve chromium binary'sinin mevcut olduğunu kontrol eder.
    Eksikse otomatik olarak 'playwright install chromium' çalıştırır.
    Başarısız olursa sadece uyarı verir, scan devam eder.
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
        except subprocess.CalledProcessError as e:
            print(f"[!] playwright kurulumu başarısız: {e}. XSS DOM doğrulaması devre dışı.")
            return False

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        print("[*] Playwright chromium binary bulunamadı. Kuruluyor...")
        try:
            subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                check=True, capture_output=True, text=True, timeout=300,
            )
            print("[+] Playwright chromium başarıyla kuruldu.")
            return True
        except Exception as exc:
            print(f"[!] playwright install chromium başarısız: {exc}")
            print("[!] XSS DOM doğrulaması bu taramada devre dışı kalacak.")
            return False


def ensure_curl_cffi() -> bool:
    """curl_cffi kurulu değilse otomatik kurar (JA3/JA4 TLS taklidi için)."""
    try:
        from curl_cffi import requests as _  # noqa: F401
        return True
    except ImportError:
        print("[*] curl_cffi kuruluyor (TLS parmak izi gizleme)...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "curl_cffi"],
                check=True, capture_output=True, timeout=120,
            )
            print("[+] curl_cffi kuruldu. TLS parmak izi aktif.")
            return True
        except Exception as exc:
            print(f"[!] curl_cffi kurulamadi: {exc}")
            return False


def ensure_interactsh(cfg: dict) -> bool:
    """
    drivers/interactsh-client.exe'yi arka planda başlatır, stdout'tan token/host okur,
    cfg['oast']['interactsh'] alanlarını doldurur.
    Exe yoksa GitHub releases'tan otomatik indirir.
    Config'de zaten geçerli bir token varsa hiçbir şey yapmaz.
    """
    _oast = cfg.get("oast", {}) or {}
    _ic = _oast.get("interactsh", {}) or {}
    _tok = _ic.get("token", "")
    if _oast.get("enabled") and _ic.get("enabled") and _tok and "BURAYA" not in _tok:
        return True

    os_name, arch = _platform_info()
    _ic_bin = _bin_name("interactsh-client")
    exe_path = _ROOT / "drivers" / _ic_bin

    # Also check PATH — if already installed system-wide, skip download
    import shutil as _shutil
    if not exe_path.exists() and _shutil.which("interactsh-client"):
        exe_path = Path(_shutil.which("interactsh-client"))

    if not exe_path.exists():
        print(f"[*] {_ic_bin} bulunamadi. GitHub'dan indiriliyor ({os_name}/{arch})...")
        try:
            import json as _json
            api_url = "https://api.github.com/repos/projectdiscovery/interactsh/releases/latest"
            with urllib.request.urlopen(api_url, timeout=15) as r:
                data = _json.loads(r.read())

            # Match asset for current platform — prefer .zip, fall back to .tar.gz
            asset_url = None
            for _ext in (".zip", ".tar.gz"):
                asset_url = next(
                    (a["browser_download_url"] for a in data.get("assets", [])
                     if os_name in a["name"].lower()
                     and arch in a["name"].lower()
                     and a["name"].endswith(_ext)),
                    None,
                )
                if asset_url:
                    break

            if not asset_url:
                print(f"[!] interactsh {os_name}/{arch} binary bulunamadi. Elle indirin.")
                return False

            archive_name = asset_url.split("/")[-1]
            archive_path = _ROOT / "drivers" / archive_name
            exe_path.parent.mkdir(parents=True, exist_ok=True)
            print(f"[*] indiriliyor: {archive_name}")
            urllib.request.urlretrieve(asset_url, archive_path)

            dest_path = _ROOT / "drivers" / _ic_bin
            ok = _extract_binary(archive_path, dest_path, "interactsh-client")
            archive_path.unlink(missing_ok=True)

            if not ok:
                print("[!] interactsh binary arsivden cikartilamadi.")
                return False

            exe_path = dest_path
            print(f"[+] {_ic_bin} indirildi: {exe_path}")
        except Exception as exc:
            print(f"[!] interactsh indirme hatasi: {exc}")
            return False

    print("[*] interactsh-client baslatiliyor...")
    try:
        proc = subprocess.Popen(
            [str(exe_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
        )
        token, host = None, None
        _ansi_re = re.compile(r'\x1b\[[0-9;]*m|\[[0-9]+m')
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
                host = m2.group(0).strip()
                token = m2.group(1).strip()
                break
            time.sleep(0.1)

        if token and host:
            cfg.setdefault("oast", {})["enabled"] = True
            cfg["oast"].setdefault("interactsh", {})["enabled"] = True
            cfg["oast"]["interactsh"]["token"] = token
            cfg["oast"]["interactsh"]["server"] = (
                "https://" + host.split(".", 1)[1] if "." in host else "https://oast.me"
            )
            cfg["oast"]["dns_domain"] = host
            cfg["_interactsh_proc"] = proc
            print(f"[+] interactsh aktif. Subdomain: {host}")
            return True
        else:
            print("[!] interactsh token alinamadi. Config'deki token kullanilacak.")
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
            return False
    except Exception as exc:
        print(f"[!] interactsh baslatilamadi: {exc}")
        return False


def ensure_nuclei(cfg: dict) -> bool:  # noqa: ARG001
    """
    tools/nuclei/nuclei[.exe] varsa True döner.
    Yoksa GitHub releases'tan mevcut platform için doğru binary'yi indirir
    (Windows: .zip/nuclei.exe, Linux/macOS: .zip or .tar.gz/nuclei).
    """
    import shutil as _shutil

    os_name, arch = _platform_info()
    _nuclei_bin = _bin_name("nuclei")

    candidates = [
        _ROOT / "tools" / "nuclei" / _nuclei_bin,
        _ROOT / "tools" / _nuclei_bin,
    ]
    for c in candidates:
        if c.exists():
            return True

    # Also accept if available system-wide in PATH
    if _shutil.which("nuclei"):
        return True

    print(f"[*] Nuclei bulunamadi. GitHub'dan indiriliyor ({os_name}/{arch})...")
    try:
        import json as _json
        api_url = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
        with urllib.request.urlopen(api_url, timeout=15) as r:
            data = _json.loads(r.read())

        asset_url = None
        for _ext in (".zip", ".tar.gz"):
            asset_url = next(
                (a["browser_download_url"] for a in data.get("assets", [])
                 if os_name in a["name"].lower()
                 and arch in a["name"].lower()
                 and a["name"].endswith(_ext)),
                None,
            )
            if asset_url:
                break

        if not asset_url:
            print(f"[!] Nuclei {os_name}/{arch} binary bulunamadi.")
            return False

        dest_dir = _ROOT / "tools" / "nuclei"
        dest_dir.mkdir(parents=True, exist_ok=True)
        archive_name = asset_url.split("/")[-1]
        archive_path = dest_dir / archive_name
        print(f"[*] Nuclei indiriliyor: {archive_name}")
        urllib.request.urlretrieve(asset_url, archive_path)

        dest_path = dest_dir / _nuclei_bin
        ok = _extract_binary(archive_path, dest_path, "nuclei")
        archive_path.unlink(missing_ok=True)

        if not ok:
            print("[!] Nuclei binary arsivden cikartilamadi.")
            return False

        print(f"[+] Nuclei kuruldu: {dest_path}")
        return True
    except Exception as exc:
        print(f"[!] Nuclei indirme hatasi: {exc}")
        return False


def initialize_persistence(cfg: dict = None) -> dict:
    """
    Adım 20 kalıcılık katmanını başlat:
    DB, FPLearner, ScoreTracker singleton'ları oluştur.

    Döndürür
    --------
    dict — başlatılan bileşenler
    """
    result = {"db": False, "fp_learner": False, "score_tracker": False}
    cfg = cfg or {}

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


def run_all_startup_checks(cfg: dict) -> dict[str, bool]:
    """Run all pre-scan dependency checks. Returns a status dict."""
    return {
        "playwright": ensure_playwright_chromium(),
        "curl_cffi":  ensure_curl_cffi(),
        "nuclei":     ensure_nuclei(cfg),
        "interactsh": ensure_interactsh(cfg),
    }
