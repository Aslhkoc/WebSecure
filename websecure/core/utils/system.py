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
        import tempfile
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.chrome.options import Options

        opts = Options()
        if headless:
            opts.add_argument("--headless=new")
        if proxy:
            opts.add_argument(f"--proxy-server={proxy}")

        # Admin/root altında çalışırken Chrome'un default profil diziniyle
        # çakışmaması için izole bir geçici profil kullan
        _tmp_profile = tempfile.mkdtemp(prefix="ws_chrome_")
        opts.add_argument(f"--user-data-dir={_tmp_profile}")

        # Temel kararlılık flag'leri
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")                      # Windows headless için zorunlu
        opts.add_argument("--disable-software-rasterizer")
        opts.add_argument("--disable-extensions")
        opts.add_argument("--disable-default-apps")
        opts.add_argument("--no-first-run")
        opts.add_argument("--window-size=1920,1080")
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_argument("--log-level=3")                      # Chrome konsolunu sustur
        opts.add_argument("--remote-debugging-port=0")          # random port — çakışma yok
        opts.add_argument("--disable-background-networking")
        opts.add_experimental_option("excludeSwitches", ["enable-automation"])
        opts.add_experimental_option("useAutomationExtension", False)

        service = None

        # 1. webdriver-manager ile Chrome sürümüne uygun driver indir
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            # cache_valid_range=1: 1 günden yeni cache kullan, eskiyse yeniden indir
            driver_path = ChromeDriverManager().install()
            service = Service(driver_path)
            logging.info(f"[WebDriver] ChromeDriver: {driver_path}")
        except ImportError:
            logging.warning("[WebDriver] webdriver-manager kurulu değil.")
        except Exception as e:
            logging.warning(f"[WebDriver] webdriver-manager hatası: {e}")

        # 2. webdriver-manager başarısız olduysa yerel driver dene
        #    (ama Chrome sürümüyle uyumluluğu kontrol et)
        if service is None:
            root_dir = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            )
            local_path = os.path.join(root_dir, "drivers", "chromedriver.exe")
            if os.path.exists(local_path):
                # Sürüm uyumluluğunu kontrol et
                try:
                    import subprocess as _sp
                    _ver_out = _sp.run(
                        [local_path, "--version"], capture_output=True, text=True, timeout=5
                    ).stdout.strip()
                    _local_major = int(_ver_out.split("ChromeDriver ")[-1].split(".")[0])
                    # Chrome major version
                    import re as _re
                    _chrome = os.path.join(
                        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
                    )
                    if os.path.exists(_chrome):
                        import win32api  # type: ignore
                        _chrome_ver = win32api.GetFileVersionInfo(_chrome, "\\")
                        _chrome_major = (_chrome_ver["FileVersionMS"] >> 16) & 0xFFFF
                    else:
                        _chrome_major = _local_major  # bilinmiyor, kullan
                    if abs(_local_major - _chrome_major) <= 1:
                        service = Service(executable_path=local_path)
                        logging.info(f"[WebDriver] Yerel driver kullanılıyor: {local_path}")
                    else:
                        logging.warning(
                            f"[WebDriver] Yerel driver ({_local_major}) Chrome ({_chrome_major}) "
                            f"ile uyumsuz — atlanıyor."
                        )
                except Exception:
                    # Sürüm kontrolü başarısız → driver'ı yine de dene
                    service = Service(executable_path=local_path)

        if service is None:
            logging.warning("[WebDriver] Uyumlu ChromeDriver bulunamadı.")
            return None

        try:
            return webdriver.Chrome(service=service, options=opts)
        except Exception as _first_err:
            # İlk deneme başarısız → --headless=new yerine eski headless modu dene
            logging.warning(f"[WebDriver] İlk başlatma başarısız ({_first_err!r}), eski headless ile yeniden deneniyor...")
            try:
                opts2 = Options()
                opts2.add_argument("--headless")          # eski Chrome headless modu
                opts2.add_argument("--no-sandbox")
                opts2.add_argument("--disable-dev-shm-usage")
                opts2.add_argument("--disable-gpu")
                opts2.add_argument("--disable-software-rasterizer")
                opts2.add_argument("--window-size=1920,1080")
                opts2.add_argument("--log-level=3")
                opts2.add_argument(f"--user-data-dir={_tmp_profile}")
                return webdriver.Chrome(service=service, options=opts2)
            except Exception as _second_err:
                raise _second_err

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
