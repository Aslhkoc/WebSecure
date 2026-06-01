# -*- coding: utf-8 -*-
"""
WebSecure — PyInstaller giriş noktası (frozen entry point).

Dondurulmuş ``.exe`` / standalone binary bu dosyayı çalıştırır.
Kaynak koddan çalıştırmak için hâlâ ``python -m websecure`` kullanılabilir;
bu script yalnızca PyInstaller build'i içindir.
"""
from __future__ import annotations

import multiprocessing


def _run() -> None:
    # Frozen + multiprocessing güvenliği: alt süreçlerin ana programı yeniden
    # çalıştırmasını engeller (Windows 'spawn' modunda zorunlu).
    multiprocessing.freeze_support()

    # Windows konsolu (cp1252) Unicode çıktıda (↓ … ✓ ✗ ş) UnicodeEncodeError
    # fırlatıp araç indirmeyi/çıktıyı çökertebilir. UTF-8 + errors=replace ile
    # yeniden yapılandır — çökme yerine en kötü ihtimalle '?' gösterir.
    import sys
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    from websecure.main import main
    main()


if __name__ == "__main__":
    _run()
