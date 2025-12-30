import os
import sys
import logging
import importlib.util
from typing import Optional, Any

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

# ========================== WebDriver ==========================
def setup_webdriver(headless: bool = True, proxy: str = None):
    # Minimal stealth setup
    from selenium import webdriver
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
    
    return webdriver.Chrome(options=opts)

def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path

_CURRENT_IDENTITY = {}
def current_identity():
    return _CURRENT_IDENTITY
