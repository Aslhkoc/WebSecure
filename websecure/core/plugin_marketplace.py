"""
websecure.core.plugin_marketplace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Plugin/harici scanner modülü yükleme ve güncelleme sistemi.

Özellikler
----------
* Yerel plugin dizininden otomatik keşif
* Uzak git reposundan plugin kurulumu (stdlib subprocess)
* Plugin etkinleştirme / devre dışı bırakma
* Plugin registry (JSON kalıcılık)
* BasePlugin soyut interface (SOLID-LSP uyumlu)
* Plugin çalıştırma: findings döndüren standart arayüz

Dizin yapısı
------------
~/.websecure/plugins/
    <plugin_name>/
        plugin.json    # metadata
        scanner.py     # BasePlugin implement eden sınıf

SOLID
-----
- SRP  : PluginLoader yükler, PluginMarketplace yönetir.
- OCP  : Yeni plugin eklemek mevcut kodu değiştirmez.
- LSP  : Tüm plugin'ler BasePlugin sözleşmesini uygular.
- ISP  : BasePlugin minimum arayüz sunar.
- DIP  : PluginMarketplace somut sınıflara değil BasePlugin'e bağımlı.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import shutil
import subprocess
import sys
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Plugin dizini
# ---------------------------------------------------------------------------

_PLUGIN_DIR = Path.home() / ".websecure" / "plugins"
_REGISTRY_FILE = Path.home() / ".websecure" / "plugin_registry.json"


# ---------------------------------------------------------------------------
# BasePlugin — sözleşme
# ---------------------------------------------------------------------------

class BasePlugin(ABC):
    """
    Tüm harici scanner plugin'lerinin implement etmesi gereken arayüz.

    Kullanım
    --------
    ```python
    class MyScanner(BasePlugin):
        name = "my-scanner"
        version = "1.0.0"
        description = "Özel tarayıcım"

        def scan(self, target: str, options: dict) -> list:
            return [{"title": "Test", "severity": "Low", "url": target}]
    ```
    """

    #: Plugin kimliği — benzersiz, küçük harf, tire ile
    name: str = ""
    version: str = "0.0.0"
    description: str = ""
    author: str = ""
    tags: List[str] = []

    @abstractmethod
    def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Tarama yap ve bulguları döndür.

        Parametreler
        ------------
        target  : Hedef URL
        options : Profil seçenekleri (timeout, threads, ...)

        Döndürür
        --------
        List[Dict] — Her dict'te en az: title, severity, url
        """

    def health_check(self) -> bool:
        """Plugin hazır mı? (bağımlılık kontrolü vb.)"""
        return True

    def cleanup(self) -> None:
        """Tarama sonrası temizlik (opsiyonel)."""


# ---------------------------------------------------------------------------
# PluginMeta — plugin metadata
# ---------------------------------------------------------------------------

@dataclass
class PluginMeta:
    """Plugin kayıt bilgisi."""
    name: str
    version: str = "0.0.0"
    description: str = ""
    author: str = ""
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    path: str = ""                   # plugin dizini yolu
    source: str = "local"            # "local" / "git"
    source_url: str = ""             # git repo URL
    installed_at: str = ""
    last_updated: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PluginMeta":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# PluginLoader — dinamik yükleme
# ---------------------------------------------------------------------------

class PluginLoader:
    """Plugin dizininden BasePlugin subclass'larını dinamik yükler."""

    @staticmethod
    def load_from_dir(plugin_dir: Path) -> Optional[Type[BasePlugin]]:
        """
        Bir plugin dizininden scanner.py'yi yükle ve BasePlugin sınıfını bul.

        Döndürür
        --------
        Type[BasePlugin] veya None (bulunamazsa)
        """
        scanner_file = plugin_dir / "scanner.py"
        if not scanner_file.exists():
            logger.warning(f"[PluginLoader] scanner.py bulunamadı: {plugin_dir}")
            return None

        module_name = f"websecure_plugin_{plugin_dir.name}"
        spec = importlib.util.spec_from_file_location(module_name, scanner_file)
        if not spec or not spec.loader:
            return None

        try:
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:
            logger.error(f"[PluginLoader] Yükleme hatası {plugin_dir.name}: {exc}")
            return None

        # BasePlugin subclass'ı bul
        for obj_name in dir(module):
            obj = getattr(module, obj_name)
            try:
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and obj.name  # boş name kabul etme
                ):
                    return obj
            except TypeError:
                continue

        logger.warning(f"[PluginLoader] BasePlugin subclass bulunamadı: {plugin_dir.name}")
        return None

    @staticmethod
    def load_meta(plugin_dir: Path) -> Optional[PluginMeta]:
        """plugin.json'dan metadata oku."""
        meta_file = plugin_dir / "plugin.json"
        if not meta_file.exists():
            return None
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8"))
            data["path"] = str(plugin_dir)
            return PluginMeta.from_dict(data)
        except Exception as exc:
            logger.warning(f"[PluginLoader] plugin.json hata {plugin_dir}: {exc}")
            return None


# ---------------------------------------------------------------------------
# PluginMarketplace — ana yönetici
# ---------------------------------------------------------------------------

class PluginMarketplace:
    """
    Plugin keşif, kurulum, güncelleme ve çalıştırma merkezi.

    Kullanım
    --------
    ```python
    market = PluginMarketplace()

    # Mevcut plugin'leri listele:
    plugins = market.list_plugins()

    # Git'ten kur:
    market.install_from_git("https://github.com/user/my-scanner")

    # Tarama:
    findings = market.run("my-scanner", "https://example.com")
    ```
    """

    def __init__(
        self,
        plugin_dir: Optional[Path] = None,
        registry_file: Optional[Path] = None,
    ) -> None:
        self._plugin_dir = plugin_dir or _PLUGIN_DIR
        self._registry_file = registry_file or _REGISTRY_FILE
        self._registry: Dict[str, PluginMeta] = {}
        self._instances: Dict[str, Type[BasePlugin]] = {}
        self._lock = threading.Lock()
        self._plugin_dir.mkdir(parents=True, exist_ok=True)
        self._load_registry()
        self._discover()

    # ------------------------------------------------------------------
    # Keşif
    # ------------------------------------------------------------------

    def _discover(self) -> None:
        """Plugin dizinindeki tüm plugin'leri keşfet."""
        for item in self._plugin_dir.iterdir():
            if not item.is_dir():
                continue
            if item.name in self._registry:
                continue  # zaten kayıtlı

            meta = PluginLoader.load_meta(item)
            if meta:
                with self._lock:
                    self._registry[meta.name] = meta
                logger.debug(f"[Marketplace] Keşfedildi: {meta.name} v{meta.version}")

        self._save_registry()

    # ------------------------------------------------------------------
    # Kurulum
    # ------------------------------------------------------------------

    def install_from_git(
        self,
        repo_url: str,
        branch: str = "main",
        plugin_name: Optional[str] = None,
    ) -> Optional[PluginMeta]:
        """
        Git reposundan plugin kur.

        Parametreler
        ------------
        repo_url    : HTTPS git URL
        branch      : Branch adı
        plugin_name : Dizin adı (yoksa repodan alınır)

        Döndürür
        --------
        PluginMeta — kurulum başarılıysa
        """
        if not shutil.which("git"):
            logger.error("[Marketplace] git bulunamadı. Kurulum atlandı.")
            return None

        name = plugin_name or repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        dest = self._plugin_dir / name

        if dest.exists():
            logger.info(f"[Marketplace] Güncelleniyor: {name}")
            result = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=str(dest),
                capture_output=True,
                text=True,
                timeout=120,
            )
        else:
            logger.info(f"[Marketplace] Kuruluyor: {name}")
            result = subprocess.run(
                ["git", "clone", "--depth=1", "--branch", branch, repo_url, str(dest)],
                capture_output=True,
                text=True,
                timeout=120,
            )

        if result.returncode != 0:
            logger.error(f"[Marketplace] git hatası: {result.stderr[:200]}")
            return None

        meta = PluginLoader.load_meta(dest)
        if not meta:
            # plugin.json yoksa minimal meta oluştur
            import datetime as _dt
            meta = PluginMeta(
                name=name,
                path=str(dest),
                source="git",
                source_url=repo_url,
                installed_at=_dt.datetime.utcnow().isoformat(),
            )
            (dest / "plugin.json").write_text(
                json.dumps(meta.to_dict(), indent=2), encoding="utf-8"
            )

        with self._lock:
            self._registry[meta.name] = meta
        self._save_registry()
        logger.info(f"[Marketplace] Kuruldu: {meta.name} v{meta.version}")
        return meta

    def install_local(self, plugin_dir: Path) -> Optional[PluginMeta]:
        """Yerel dizinden plugin kur (symlink veya kopyala)."""
        if not plugin_dir.is_dir():
            logger.error(f"[Marketplace] Dizin bulunamadı: {plugin_dir}")
            return None

        dest = self._plugin_dir / plugin_dir.name
        if not dest.exists():
            shutil.copytree(str(plugin_dir), str(dest))

        meta = PluginLoader.load_meta(dest)
        if not meta:
            meta = PluginMeta(name=plugin_dir.name, path=str(dest), source="local")

        with self._lock:
            self._registry[meta.name] = meta
        self._save_registry()
        return meta

    # ------------------------------------------------------------------
    # Yönetim
    # ------------------------------------------------------------------

    def enable(self, plugin_name: str) -> bool:
        with self._lock:
            meta = self._registry.get(plugin_name)
            if meta:
                meta.enabled = True
        self._save_registry()
        return meta is not None

    def disable(self, plugin_name: str) -> bool:
        with self._lock:
            meta = self._registry.get(plugin_name)
            if meta:
                meta.enabled = False
        self._save_registry()
        return meta is not None

    def uninstall(self, plugin_name: str) -> bool:
        with self._lock:
            meta = self._registry.pop(plugin_name, None)
        if meta and meta.path:
            dest = Path(meta.path)
            if dest.exists():
                shutil.rmtree(str(dest), ignore_errors=True)
        # Önbellekten kaldır
        self._instances.pop(plugin_name, None)
        self._save_registry()
        return meta is not None

    def list_plugins(
        self,
        enabled_only: bool = False,
    ) -> List[PluginMeta]:
        with self._lock:
            plugins = list(self._registry.values())
        if enabled_only:
            plugins = [p for p in plugins if p.enabled]
        return sorted(plugins, key=lambda p: p.name)

    def get_meta(self, plugin_name: str) -> Optional[PluginMeta]:
        with self._lock:
            return self._registry.get(plugin_name)

    # ------------------------------------------------------------------
    # Çalıştırma
    # ------------------------------------------------------------------

    def run(
        self,
        plugin_name: str,
        target: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Plugin'i çalıştır ve bulgularını döndür.

        Döndürür
        --------
        List[Dict] — bulgular (boş liste hata durumunda)
        """
        meta = self._registry.get(plugin_name)
        if not meta:
            logger.error(f"[Marketplace] Plugin bulunamadı: {plugin_name}")
            return []
        if not meta.enabled:
            logger.warning(f"[Marketplace] Plugin devre dışı: {plugin_name}")
            return []

        plugin_cls = self._get_instance_class(plugin_name, meta)
        if not plugin_cls:
            return []

        try:
            instance = plugin_cls()
            if not instance.health_check():
                logger.warning(f"[Marketplace] Health check başarısız: {plugin_name}")
                return []
            findings = instance.scan(target, options or {})
            instance.cleanup()
            logger.info(
                f"[Marketplace] {plugin_name}: {len(findings)} bulgu ({target})"
            )
            return findings
        except Exception as exc:
            logger.error(f"[Marketplace] {plugin_name} çalıştırma hatası: {exc}")
            return []

    def run_all(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Aktif tüm plugin'leri çalıştır."""
        results: Dict[str, List[Dict]] = {}
        for meta in self.list_plugins(enabled_only=True):
            results[meta.name] = self.run(meta.name, target, options)
        return results

    def _get_instance_class(
        self,
        plugin_name: str,
        meta: PluginMeta,
    ) -> Optional[Type[BasePlugin]]:
        """Plugin sınıfını yükle veya önbellekten al."""
        if plugin_name in self._instances:
            return self._instances[plugin_name]

        plugin_dir = Path(meta.path)
        cls = PluginLoader.load_from_dir(plugin_dir)
        if cls:
            self._instances[plugin_name] = cls
        return cls

    # ------------------------------------------------------------------
    # Registry kalıcılığı
    # ------------------------------------------------------------------

    def _save_registry(self) -> None:
        try:
            self._registry_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._registry_file.with_suffix(".tmp")
            with self._lock:
                data = [m.to_dict() for m in self._registry.values()]
            tmp.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            tmp.replace(self._registry_file)
        except Exception as exc:
            logger.error(f"[Marketplace] Registry kayıt hatası: {exc!r}")

    def _load_registry(self) -> None:
        if not self._registry_file.exists():
            return
        try:
            data = json.loads(self._registry_file.read_text(encoding="utf-8"))
            for d in data:
                meta = PluginMeta.from_dict(d)
                self._registry[meta.name] = meta
            logger.debug(f"[Marketplace] {len(self._registry)} plugin yüklendi.")
        except Exception as exc:
            logger.error(f"[Marketplace] Registry yükleme hatası: {exc!r}")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_marketplace_instance: Optional[PluginMarketplace] = None


def get_marketplace() -> PluginMarketplace:
    """Global PluginMarketplace singleton'ını döndür."""
    global _marketplace_instance
    if _marketplace_instance is None:
        _marketplace_instance = PluginMarketplace()
    return _marketplace_instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "BasePlugin",
    "PluginMeta",
    "PluginLoader",
    "PluginMarketplace",
    "get_marketplace",
]
