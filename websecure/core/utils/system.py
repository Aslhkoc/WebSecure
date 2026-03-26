import os
import sys
import logging
import importlib.util
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
def setup_webdriver(headless: bool = True, proxy: str = None):
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.chrome.options import Options
        
        opts = Options()
        if headless:
            opts.add_argument("--headless=new")
        if proxy:
            opts.add_argument(f"--proxy-server={proxy}")
            
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_experimental_option("excludeSwitches", ["enable-automation"])
        
        # Try to use webdriver-manager if available
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            service = Service(ChromeDriverManager().install())
            logging.info(f"[WebDriver] Auto-configured via webdriver-manager.")
        except ImportError:
            # Fallback to local driver if manager is not installed
            root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            driver_path = os.path.join(root_dir, "drivers", "chromedriver.exe")
            
            if os.path.exists(driver_path):
                 logging.warning(f"Local driver found at: {driver_path}")
                 service = Service(executable_path=driver_path)
            else:
                 logging.warning("[!] webdriver-manager not found and local driver missing.")
                 return None
        except Exception as e:
            logging.warning(f"[!] WebDriver Manager failed: {e}")
            # Try local fallback even if manager failed
            root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            driver_path = os.path.join(root_dir, "drivers", "chromedriver.exe")
            if os.path.exists(driver_path):
                 service = Service(executable_path=driver_path)
            else:
                 return None

        if service:
            return webdriver.Chrome(service=service, options=opts)
        return webdriver.Chrome(options=opts)
    except Exception as e:
        import traceback
        
        msg = str(e)
        if "SessionNotCreatedException" in msg or "version" in msg:
             logging.warning(f"[!] WebDriver Sürüm Uyumsuzluğu: Tarayıcınız ve Sürücünüzün (chromedriver.exe) sürümleri eşleşmiyor.")
             logging.warning(f"[!] webdriver-manager kurulumu sorunu çözebilir.")
        else:
             logging.warning(f"WebDriver init failed: {e}")

        return None

def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path

_CURRENT_IDENTITY: Dict[str, Any] = {}
_IDENTITY_LOCK = threading.Lock()


def current_identity(config: Optional[dict] = None) -> Dict[str, Any]:
    """Return the current identity dict (thread-safe read)."""
    with _IDENTITY_LOCK:
        return dict(_CURRENT_IDENTITY)


def set_identity(identity: Dict[str, Any]) -> None:
    """Replace the current identity (thread-safe write)."""
    with _IDENTITY_LOCK:
        _CURRENT_IDENTITY.clear()
        _CURRENT_IDENTITY.update(identity)
