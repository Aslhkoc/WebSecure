#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSecure — PyInstaller build yardımcısı (cross-platform).

Kullanım
--------
    python build_exe.py

Bulunduğu OS için ``dist/websecure[.exe]`` standalone binary üretir.
PyInstaller kurulu değilse otomatik kurar. Linux/macOS binary'leri yalnızca
ilgili OS üzerinde üretilir (cross-compile yok) — CI matrisi bunun içindir.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = ROOT / "websecure.spec"


def _ensure_pyinstaller() -> bool:
    try:
        import PyInstaller  # noqa: F401
        return True
    except ImportError:
        print("[*] PyInstaller kuruluyor...")
        r = subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller>=6.0"])
        return r.returncode == 0


def main() -> None:
    if not SPEC.exists():
        print(f"[!] Spec bulunamadı: {SPEC}")
        sys.exit(1)
    if not _ensure_pyinstaller():
        print("[!] PyInstaller kurulamadı.")
        sys.exit(1)

    cmd = [sys.executable, "-m", "PyInstaller", str(SPEC), "--clean", "--noconfirm"]
    print("[*] Build başlıyor:", " ".join(cmd))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("[!] Build başarısız.")
        sys.exit(result.returncode)

    exe_name = "websecure.exe" if sys.platform == "win32" else "websecure"
    exe_path = ROOT / "dist" / exe_name
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n[+] Tamamlandı: {exe_path}  ({size_mb:.0f} MB)")
        print(f"    Çalıştır: {exe_path} --help")
    else:
        print(f"[!] Beklenen çıktı bulunamadı: {exe_path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
