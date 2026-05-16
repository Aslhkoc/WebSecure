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
    local = os.path.join(root_dir, "drivers", "chromedriver.exe")
    if os.path.exists(local):
        logging.info(f"[WebDriver] Yerel driver: {local}")
        return Service(executable_path=local)

    return None


def _chrome_opts(headless: bool, proxy: str, profile_dir: str, new_headless: bool = True):
    from selenium.webdriver.chrome.options import Options
    opts = Options()

    if headless:
        # --headless=new bazı Windows Admin kurulumlarında crash yapabiliyor;
        # new_headless=False olduğunda eski --headless modunu kullan
        opts.add_argument("--headless=new" if new_headless else "--headless")

    if proxy:
        opts.add_argument(f"--proxy-server={proxy}")

    opts.add_argument(f"--user-data-dir={profile_dir}")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-gpu-sandbox")
    opts.add_argument("--disable-software-rasterizer")
    opts.add_argument("--disable-features=VizDisplayCompositor")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-default-apps")
    opts.add_argument("--no-first-run")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--log-level=3")
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

        # Deneme 1: --headless=new (modern mod)
        try:
            driver = webdriver.Chrome(service=service, options=_chrome_opts(headless, proxy, profile_dir, new_headless=True))
            logging.info("[WebDriver] Chrome başlatıldı (headless=new).")
            return driver
        except Exception as e1:
            logging.warning(f"[WebDriver] headless=new başarısız: {type(e1).__name__} — eski mod deneniyor...")

        # Deneme 2: eski --headless modu
        try:
            driver = webdriver.Chrome(service=service, options=_chrome_opts(headless, proxy, profile_dir, new_headless=False))
            logging.info("[WebDriver] Chrome başlatıldı (headless eski mod).")
            return driver
        except Exception as e2:
            logging.warning(f"[WebDriver] Eski headless de başarısız: {type(e2).__name__} — headless=False deneniyor...")

        # Deneme 3: headless olmadan (GUI modu, son çare)
        try:
            driver = webdriver.Chrome(service=service, options=_chrome_opts(False, proxy, profile_dir, new_headless=False))
            logging.info("[WebDriver] Chrome başlatıldı (headless=False, GUI modu).")
            return driver
        except Exception as e3:
            logging.warning(f"[WebDriver] GUI mod da başarısız: {e3}")
            raise e3

    except Exception as e:
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
