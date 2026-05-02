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
import zipfile
import urllib.request
from pathlib import Path

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

    exe_path = _ROOT / "drivers" / "interactsh-client.exe"

    if not exe_path.exists():
        print("[*] interactsh-client.exe bulunamadi. GitHub'dan indiriliyor...")
        try:
            import json as _json
            api_url = "https://api.github.com/repos/projectdiscovery/interactsh/releases/latest"
            with urllib.request.urlopen(api_url, timeout=15) as r:
                data = _json.loads(r.read())
            asset_url = next(
                (a["browser_download_url"] for a in data.get("assets", [])
                 if "windows" in a["name"].lower() and "amd64" in a["name"].lower()
                 and a["name"].endswith(".zip")),
                None,
            )
            if not asset_url:
                print("[!] interactsh Windows binary bulunamadi. Elle indirin.")
                return False
            zip_path = _ROOT / "drivers" / "interactsh-client.zip"
            exe_path.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(asset_url, zip_path)
            with zipfile.ZipFile(zip_path, "r") as zf:
                for member in zf.namelist():
                    if member.endswith(".exe") and "interactsh-client" in member:
                        with zf.open(member) as src, open(exe_path, "wb") as dst:
                            dst.write(src.read())
                        break
            zip_path.unlink(missing_ok=True)
            print(f"[+] interactsh-client.exe indirildi: {exe_path}")
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
            return False
    except Exception as exc:
        print(f"[!] interactsh baslatilamadi: {exc}")
        return False


def ensure_nuclei(cfg: dict) -> bool:  # noqa: ARG001
    """
    tools/nuclei/nuclei.exe varsa True döner.
    Yoksa GitHub releases'tan en güncel Windows amd64 sürümünü indirir.
    """
    candidates = [
        _ROOT / "tools" / "nuclei" / "nuclei.exe",
        _ROOT / "tools" / "nuclei.exe",
    ]
    for c in candidates:
        if c.exists():
            return True

    print("[*] Nuclei bulunamadi. GitHub'dan indiriliyor...")
    try:
        import json as _json
        api_url = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
        with urllib.request.urlopen(api_url, timeout=15) as r:
            data = _json.loads(r.read())
        asset_url = next(
            (a["browser_download_url"] for a in data.get("assets", [])
             if "windows" in a["name"].lower() and "amd64" in a["name"].lower()
             and a["name"].endswith(".zip")),
            None,
        )
        if not asset_url:
            print("[!] Nuclei Windows binary bulunamadi.")
            return False

        dest_dir = _ROOT / "tools" / "nuclei"
        dest_dir.mkdir(parents=True, exist_ok=True)
        zip_path = dest_dir / "nuclei.zip"
        print(f"[*] Nuclei indiriliyor: {asset_url.split('/')[-1]}")
        urllib.request.urlretrieve(asset_url, zip_path)

        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                if member.endswith(".exe") and "nuclei" in member.lower():
                    with zf.open(member) as src, open(dest_dir / "nuclei.exe", "wb") as dst:
                        dst.write(src.read())
                    break
        zip_path.unlink(missing_ok=True)
        print(f"[+] Nuclei kuruldu: {dest_dir / 'nuclei.exe'}")
        return True
    except Exception as exc:
        print(f"[!] Nuclei indirme hatasi: {exc}")
        return False


def run_all_startup_checks(cfg: dict) -> dict[str, bool]:
    """Run all pre-scan dependency checks. Returns a status dict."""
    return {
        "playwright": ensure_playwright_chromium(),
        "curl_cffi":  ensure_curl_cffi(),
        "nuclei":     ensure_nuclei(cfg),
        "interactsh": ensure_interactsh(cfg),
    }
