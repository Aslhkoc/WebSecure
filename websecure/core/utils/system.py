import os
import sys
import logging
import importlib
import threading
from typing import Any, Dict, Optional

# ========================== Import Helpers ==========================
def _ws_import_any(module_name: str, package: str = None) -> Optional[Any]:
    try:
        return importlib.import_module(module_name, package)
    except ImportError:
        return None

def _ws_maybe_import_any(*names: str) -> Optional[Any]:
    for n in names:
        m = _ws_import_any(n)
        if m: return m
    return None

# ========================== Logging ==========================
def setup_logging(level: str = "INFO", log_file: str = None):
    fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
        
    logging.basicConfig(level=level, format=fmt, handlers=handlers)
    
    # [FIX] Suppress noisy third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("selenium").setLevel(logging.WARNING)

# ========================== WebDriver ==========================
def _chrome_service():
    """WDM önce, yoksa yerel drivers/ klasörü."""
    from selenium.webdriver.chrome.service import Service
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        path = ChromeDriverManager().install()
        logging.info(f"[WebDriver] ChromeDriver (WDM): {path}")
        return Service(path)
    except Exception as e:
        logging.warning(f"[WebDriver] WDM başarısız: {e}")

    from websecure.core.platform_compat import binary_name as _bn
    from websecure.core.paths import drivers_dir as _drivers_dir
    local = str(_drivers_dir() / _bn("chromedriver"))
    if os.path.exists(local):
        logging.info(f"[WebDriver] Yerel driver: {local}")
        return Service(executable_path=local)

    return None


def _chrome_opts(headless: bool, proxy: str, profile_dir: str,
                  new_headless: bool = True, swiftshader: bool = False):
    from selenium.webdriver.chrome.options import Options
    opts = Options()

    if headless:
        opts.add_argument("--headless=new" if new_headless else "--headless")

    if proxy:
        opts.add_argument(f"--proxy-server={proxy}")

    if profile_dir:
        opts.add_argument(f"--user-data-dir={profile_dir}")

    # Sandbox & process isolation
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")

    # GPU — swiftshader = pure software rendering (Chrome instance exited hatası için)
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-gpu-sandbox")
    opts.add_argument("--disable-software-rasterizer")
    opts.add_argument("--disable-features=VizDisplayCompositor")
    opts.add_argument("--in-process-gpu")
    if swiftshader:
        opts.add_argument("--use-gl=swiftshader")
        opts.add_argument("--use-angle=swiftshader")

    # Crash / logging
    opts.add_argument("--disable-crash-reporter")
    opts.add_argument("--disable-logging")
    opts.add_argument("--log-level=3")
    opts.add_argument("--silent")

    # Otomasyon / uzantı gürültüsü
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-default-apps")
    opts.add_argument("--no-first-run")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--disable-web-security")
    # NOT: --remote-debugging-port=0 kullanma — DevToolsActivePort hatasına yol açar
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    return opts


def setup_webdriver(headless: bool = True, proxy: str = None):
    try:
        import tempfile
        from selenium import webdriver

        service = _chrome_service()
        if service is None:
            logging.warning("[WebDriver] Uyumlu ChromeDriver bulunamadı.")
            return None

        attempts = [
            # (headless, new_headless, swiftshader, use_profile, label)
            (headless, True,  False, True,  "headless=new"),
            (headless, False, False, True,  "headless eski mod"),
            (False,    False, False, True,  "GUI mod"),
            (headless, True,  True,  True,  "headless=new + SwiftShader"),
            (False,    False, True,  False, "GUI + SwiftShader (profil yok)"),
        ]

        last_exc: Optional[Exception] = None
        for is_headless, new_hl, swift, use_profile, label in attempts:
            # Her denemeye TAZE profil dizini ver — bir önceki denemenin
            # bıraktığı SingletonLock, sonraki denemeleri "user data dir
            # already in use" ile zincirleme düşürmesin.
            pdir = tempfile.mkdtemp(prefix="ws_chrome_") if use_profile else None
            try:
                driver = webdriver.Chrome(
                    service=service,
                    options=_chrome_opts(is_headless, proxy, pdir, new_hl, swift),
                )
                logging.info(f"[WebDriver] Chrome başlatıldı ({label}).")
                return driver
            except Exception as exc:
                last_exc = exc
                # Gerçek hata mesajının ilk satırını göster (sadece sınıf adı değil) —
                # SessionNotCreated mesajı sürüm uyuşmazlığını/sebebi açıkça yazar.
                raw = str(exc).strip()
                first = raw.splitlines()[0] if raw else type(exc).__name__
                logging.warning(f"[WebDriver] {label} başarısız: {first[:220]} — sonraki deneniyor...")

        logging.warning("[WebDriver] Tüm başlatma denemeleri başarısız.")
        if last_exc is not None:
            logging.warning(f"[WebDriver] Son hata ayrıntısı: {str(last_exc)[:400]}")
            logging.warning(
                "[WebDriver] İpucu: (1) CMD'yi 'Yönetici olarak' çalıştırmak Chrome "
                "başlatmayı engelleyebilir — normal kullanıcı olarak deneyin. "
                "(2) Chrome ↔ ChromeDriver sürümü uyuşmuyorsa Chrome'u güncelleyip "
                "%USERPROFILE%\\.wdm önbelleğini silin. "
                "(3) Açık kalmış chrome.exe süreçlerini kapatın."
            )
        return None

    except Exception as e:
        logging.warning(f"WebDriver init failed: {e}")
        return None

def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path

_CURRENT_IDENTITY: Dict[str, Any] = {}
_IDENTITY_LOCK = threading.Lock()


def current_identity(config: Optional[dict] = None) -> Dict[str, Any]:
    """Return the current identity dict. Falls back to config proxy when not explicitly set."""
    with _IDENTITY_LOCK:
        if _CURRENT_IDENTITY:
            return dict(_CURRENT_IDENTITY)
    if config and isinstance(config, dict):
        proxy = config.get("proxy") or {}
        if isinstance(proxy, dict) and proxy.get("enabled") and proxy.get("url"):
            return {"proxy_url": proxy["url"]}
    return {}


def set_identity(identity: Dict[str, Any]) -> None:
    """Replace the current identity (thread-safe write)."""
    with _IDENTITY_LOCK:
        _CURRENT_IDENTITY.clear()
        _CURRENT_IDENTITY.update(identity)
