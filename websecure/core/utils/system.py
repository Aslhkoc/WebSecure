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

    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from websecure.core.platform_compat import binary_name as _bn
    local = os.path.join(root_dir, "drivers", _bn("chromedriver"))
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

        profile_dir = tempfile.mkdtemp(prefix="ws_chrome_")

        attempts = [
            # (headless, new_headless, swiftshader, label)
            (headless, True,  False, "headless=new"),
            (headless, False, False, "headless eski mod"),
            (False,    False, False, "GUI mod"),
            (headless, True,  True,  "headless=new + SwiftShader"),
            (False,    False, True,  "GUI + SwiftShader (profil yok)"),
        ]

        for is_headless, new_hl, swift, label in attempts:
            # Son denemede user-data-dir'i de kaldır (bazı ortamlarda temp sorun çıkarır)
            pdir = profile_dir if label != "GUI + SwiftShader (profil yok)" else None
            try:
                driver = webdriver.Chrome(
                    service=service,
                    options=_chrome_opts(is_headless, proxy, pdir, new_hl, swift),
                )
                logging.info(f"[WebDriver] Chrome başlatıldı ({label}).")
                return driver
            except Exception as exc:
                logging.warning(f"[WebDriver] {label} başarısız: {type(exc).__name__} — sonraki deneniyor...")

        logging.warning("[WebDriver] Tüm başlatma denemeleri başarısız.")
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
