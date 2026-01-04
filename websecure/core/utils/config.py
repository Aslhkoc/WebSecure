import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

# ========================== Config Loading ==========================
def load_config(path: str = "config.json") -> Dict[str, Any]:
    p = Path(path)
    cfg = {}
    if p.exists():
        try:
            with p.open("r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            logging.error(f"Failed to load config from {path}: {e}")
            
    # Normalize/Validate
    _apply_defaults(cfg)
    return cfg

def _apply_defaults(cfg: Dict[str, Any]) -> None:
    # HTTP Defaults
    http = cfg.setdefault("http", {})
    http.setdefault("timeout_seconds", 20)
    http.setdefault("retries", 2)
    http.setdefault("user_agent", "WebSecure/1.0")
    
    # Scanners Defaults
    cfg.setdefault("scanners", {})
    cfg.setdefault("mode", "normal")
    
    # Logging
    lg = cfg.setdefault("logging", {})
    lg.setdefault("level", "INFO")
    lg.setdefault("structured", True)

def get_active_profile(cfg: Dict[str, Any]) -> Dict[str, Any]:
    settings = cfg.get("settings", {})
    profile = settings.get("scan_profile", "stealth")
    profiles = settings.get("profiles", {})
    return profiles.get(profile, {})

def validate_and_normalize_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(cfg, dict):
        raise ValueError("Config must be a dictionary")
    
    # Simple migration/normalization logic
    if "target" in cfg:
        cfg["target"] = cfg["target"].strip()
        
    return cfg

def ensure_wordlists(cfg: Dict[str, Any]) -> Dict[str, Any]:
    wl = cfg.setdefault("wordlists", {})
    base = wl.get("base_dir", "wordlists")
    
    p = Path(base)
    if not p.exists():
        # Fallback: check one level up if we are in core
        p_up = Path("..") / base
        if p_up.exists():
             p = p_up
             
    if p.exists():
        print(f"[Wordlists] Klasör doğrulandı: {p.absolute()}")
        # Check for common files
        common = p / "common.txt"
        if common.exists():
            count = sum(1 for _ in open(common, "r", encoding="utf-8", errors="ignore"))
            print(f"            -> common.txt yüklendi ({count} satır)")
        else:
            print(f"            [!] common.txt eksik!")
    else:
        print(f"[Wordlists] UYARI: Wordlist klasörü ({base}) bulunamadı!")
        
    return cfg

def verify_for_phase(phase: str) -> bool:
    return True

def get_logging_prefs(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return cfg.get("logging", {})
