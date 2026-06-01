# -*- coding: utf-8 -*-
"""
websecure.core.paths
~~~~~~~~~~~~~~~~~~~~~
Tüm dosya sistemi konumları için **tek doğruluk kaynağı** (single source of truth).

Hem kaynak koddan (`python -m websecure`) hem de PyInstaller ile dondurulmuş
(`websecure.exe` / `./websecure`) çalıştırmada doğru çalışır ve Windows / Linux /
macOS üzerinde taşınabilirdir.

İki tür konum vardır
--------------------
1. **Salt-okunur paketlenmiş kaynaklar** — kod, config.json, wordlist'ler,
   profiller, playbook'lar, rapor şablonları.
   → :func:`bundle_root` / :func:`package_root`
   Dondurulmuş modda bunlar PyInstaller'ın geçici çıkarım dizininden
   (``sys._MEIPASS``) gelir.

2. **Yazılabilir çalışma-zamanı verisi** — indirilen binary araçlar, tarama
   çıktıları, veritabanı, kayıt/checkpoint dosyaları.
   → :func:`user_data_dir` ve ondan türeyen :func:`tools_dir`, :func:`drivers_dir`,
   :func:`output_dir` vb.
   Dondurulmuş modda bunlar ASLA exe'nin içine yazılamaz (Windows'ta orası
   geçici/salt-okunur); kullanıcıya özel veri dizinine yönlendirilir.

Tasarım (SOLID)
---------------
- SRP : Bu modül yalnızca yol çözümlemesi yapar.
- DIP : Diğer modüller ``sys.platform`` / ``__file__`` hesaplaması tekrarlamak
        yerine buraya bağımlı olur — `sys._MEIPASS` mantığı tek yerde durur.

Ortam değişkeni override'ları
-----------------------------
- ``WEBSECURE_HOME``   : yazılabilir veri dizinini değiştirir.
- ``WEBSECURE_CONFIG`` : kullanılacak config.json yolunu zorlar.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

__all__ = [
    "APP_NAME",
    "is_frozen",
    "bundle_root",
    "package_root",
    "user_data_dir",
    "writable_root",
    "tools_dir",
    "drivers_dir",
    "output_dir",
    "records_dir",
    "db_path",
    "config_file",
    "config_schema_file",
    "wordlists_dir",
    "profiles_dir",
    "playbooks_dir",
    "report_templates_dir",
    "ensure",
]

APP_NAME = "WebSecure"


# ---------------------------------------------------------------------------
# Çekirdek: çalışma modu tespiti
# ---------------------------------------------------------------------------

def is_frozen() -> bool:
    """PyInstaller (veya benzeri) ile dondurulmuş bir çalıştırılabilir içinde
    miyiz? ``True`` ise kaynaklar ``sys._MEIPASS`` altındadır."""
    return bool(getattr(sys, "frozen", False))


def bundle_root() -> Path:
    """Salt-okunur paketlenmiş kaynakların kök dizini.

    - Dondurulmuş : PyInstaller geçici çıkarım dizini (``sys._MEIPASS``).
      onedir/onefile dışı bir senaryoda ``sys._MEIPASS`` yoksa exe'nin bulunduğu
      dizine düşülür.
    - Kaynak kod  : proje kökü (``config.json`` / ``tools`` / ``drivers``'ın
      bulunduğu dizin). ``paths.py`` ``websecure/core/`` altında olduğundan
      üç üst dizin proje köküdür.
    """
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    # websecure/core/paths.py → parent(core) → parent(websecure) → parent(proje kökü)
    return Path(__file__).resolve().parent.parent.parent


def package_root() -> Path:
    """``websecure/`` paket dizini — ``wordlists/``, ``config/`` (profiller +
    playbook'lar) ve ``reporters/templates/`` bunun altındadır.

    Dondurulmuş modda data dosyaları ``websecure/`` alt ağacıyla birlikte
    paketlenir; yoksa bundle köküne düşülür.
    """
    if is_frozen():
        cand = bundle_root() / "websecure"
        return cand if cand.exists() else bundle_root()
    # websecure/core/paths.py → parent(core) → parent(websecure)
    return Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Yazılabilir kullanıcı veri dizini
# ---------------------------------------------------------------------------

def user_data_dir() -> Path:
    """Kullanıcıya özel, yazılabilir veri dizini (ilk erişimde oluşturulur).

    Öncelik:
    1. ``WEBSECURE_HOME`` ortam değişkeni (varsa).
    2. OS standardı:
       - Windows : ``%LOCALAPPDATA%\\WebSecure``
       - macOS   : ``~/Library/Application Support/WebSecure``
       - Linux   : ``$XDG_DATA_HOME/websecure`` ya da ``~/.local/share/websecure``
    """
    override = os.environ.get("WEBSECURE_HOME")
    if override:
        base = Path(override).expanduser()
    elif sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        base = Path(local) / APP_NAME
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        base = Path(xdg) / "websecure"
    return ensure(base)


def writable_root() -> Path:
    """Çalışma-zamanı yazılabilir verinin kök dizini.

    - Dondurulmuş : :func:`user_data_dir` (exe'nin içine yazılamaz).
    - Kaynak kod  : proje kökü — geliştirme davranışı bugünküyle **bire bir aynı**
      kalır (araçlar ``<proje>/tools`` altına iner, çıktı ``<proje>/...`` olur).
    """
    return user_data_dir() if is_frozen() else bundle_root()


# ---------------------------------------------------------------------------
# Türetilmiş yazılabilir konumlar
# ---------------------------------------------------------------------------

def tools_dir() -> Path:
    """İndirilen harici binary araçların (nuclei, ffuf, sqlmap…) kök dizini."""
    return ensure(writable_root() / "tools")


def drivers_dir() -> Path:
    """WebDriver / interactsh-client gibi sürücü binary'lerinin dizini."""
    return ensure(writable_root() / "drivers")


def output_dir() -> Path:
    """Tarama çıktı dizini (results.json, report.html, SARIF, kanıtlar…)."""
    return ensure(writable_root() / "output")


def records_dir() -> Path:
    """Crawl durumu / checkpoint kayıt dizini."""
    return ensure(writable_root() / "records")


def db_path() -> Path:
    """Merkezi SQLite veritabanı dosya yolu.

    Geriye dönük uyumluluk için ``~/.websecure/websecure.db`` korunur
    (mevcut ``db.database`` varsayılanıyla aynı). ``WEBSECURE_HOME`` ayarlıysa
    veritabanı da o dizine taşınır.
    """
    if os.environ.get("WEBSECURE_HOME"):
        return user_data_dir() / "websecure.db"
    return ensure(Path.home() / ".websecure") / "websecure.db"


# ---------------------------------------------------------------------------
# Salt-okunur paketlenmiş kaynaklar
# ---------------------------------------------------------------------------

def config_file() -> Path:
    """Kullanılacak ``config.json`` yolunu çözer.

    Arama sırası (ilk var olan kazanır):
    1. ``WEBSECURE_CONFIG`` ortam değişkeni.
    2. Çalışma dizini (``./config.json``) — kullanıcı kendi config'ini yanına koyabilir.
    3. Kullanıcı veri dizini (``user_data_dir/config.json``).
    4. Paketlenmiş varsayılan (``bundle_root/config.json``).

    Hiçbiri yoksa paketlenmiş varsayılanın (var olmayan) yolu döner; çağıran
    taraf eksikliği zaten built-in default'larla tolere eder.
    """
    env = os.environ.get("WEBSECURE_CONFIG")
    if env:
        p = Path(env).expanduser()
        if p.exists():
            return p
    candidates = [
        Path.cwd() / "config.json",
        user_data_dir() / "config.json",
        bundle_root() / "config.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return bundle_root() / "config.json"


def config_schema_file() -> Path:
    """``config.schema.json`` yolu (paketlenmiş varsayılan)."""
    return bundle_root() / "config.schema.json"


def wordlists_dir() -> Path:
    """Yerleşik wordlist dizini (``websecure/wordlists``)."""
    return package_root() / "wordlists"


def profiles_dir() -> Path:
    """YAML tarama profilleri dizini (``websecure/config/profiles``)."""
    return package_root() / "config" / "profiles"


def playbooks_dir() -> Path:
    """Exploit zinciri playbook dizini (``websecure/config/playbooks``)."""
    return package_root() / "config" / "playbooks"


def report_templates_dir() -> Path:
    """Jinja2 rapor şablonları dizini (``websecure/reporters/templates``)."""
    return package_root() / "reporters" / "templates"


# ---------------------------------------------------------------------------
# Yardımcı
# ---------------------------------------------------------------------------

def ensure(path: Path) -> Path:
    """Dizini (gerekirse üst dizinleriyle) oluştur ve aynı yolu döndür.

    Bir dosya yolu için üst dizini oluşturmaz; dizin yolları içindir.
    Hata durumunda sessizce yolu döndürür (çağıran taraf var olmayan yolu
    kendi mantığıyla tolere eder).
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return path
