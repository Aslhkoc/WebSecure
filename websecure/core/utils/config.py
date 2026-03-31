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
    # Use 'root' from config if present, else default to websecure/wordlists
    base = wl.get("root", "websecure/wordlists")
    
    # [FIX] Robust path resolution
    candidates = [
        # 1. As explicitly defined (relative to CWD)
        Path(base).absolute(),
        # 2. Relative to CWD (if "websecure/wordlists" but CWD is inside "websecure/")
        Path(base.replace("websecure/", "")).absolute(),  # Try stripping one level
        # 3. Relative to this file's package (websecure/core/utils/../../wordlists -> websecure/wordlists)
        Path(__file__).parent.parent.parent / "wordlists" 
    ]

    final_path = None
    for cand in candidates:
        if cand.exists() and cand.is_dir():
            final_path = cand
            break
            
    if final_path:
        # Update config with absolute path so other modules find it
        wl["root"] = str(final_path.resolve())
        logging.debug(f"[Wordlists] Path resolved to: {wl['root']}")
    else:
        # Only warn if it really doesn't exist
        print(f"[Wordlists] UYARI: Wordlist klasörü bulunamadı! (Aranan konumlar: {[str(c) for c in candidates]})")
        
    return cfg

def verify_for_phase(phase: str) -> bool:
    return True

def get_logging_prefs(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return cfg.get("logging", {})

def apply_active_profile(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Applies the settings from the currently selected 'scan_profile' 
    (in settings.scan_profile) to the main configuration object.
    Overwrites keys like 'fuzz', 'http', 'scanners' with profile values.
    """
    active_name = cfg.get("settings", {}).get("scan_profile")
    if not active_name:
        return cfg

    profile = cfg.get("settings", {}).get("profiles", {}).get(active_name)
    
    # [FIX] Built-in Profile Fallback
    # If custom config doesn't define 'safe_full' etc., we must provide the defaults here
    # otherwise it resolves to None and we get a shallow scan.
    # Built-in profiller: 2 mod var — agresif (hızlı) ve stealth (yavaş, WAF bypass)
    # Her iki mod da TAM KAPSAM kullanır (tüm araç/payload/wordlist)
    _FULL_SCOPE_OFFENSIVE = {"enabled": True, "profile": "deep"}
    _BUILTIN_PROFILES = {
        "aggressive": {
            "rps": 15,
            "concurrency": 20,
            "description": "Agresif: Tam kapsam, maksimum hiz (Built-in)",
            "modules": ["*"],
            "offensive": _FULL_SCOPE_OFFENSIVE,
            "http": {"timeout_seconds": 20, "retries": 2},
        },
        "stealth": {
            "rps": 1,
            "concurrency": 2,
            "description": "Stealth: Tam kapsam, yavas, WAF bypass (Built-in)",
            "modules": ["*"],
            "offensive": _FULL_SCOPE_OFFENSIVE,
            "http": {"timeout_seconds": 30, "retries": 3},
        },
        # Geriye dönük uyumluluk
        "safe_full": {
            "rps": 4,
            "concurrency": 8,
            "description": "Safe Full → Stealth'e eslendi (Built-in)",
            "modules": ["*"],
            "offensive": _FULL_SCOPE_OFFENSIVE,
            "http": {"timeout_seconds": 30, "retries": 3},
        },
        "deep": {
            "rps": 15,
            "concurrency": 20,
            "description": "Deep → Agresif'e eslendi (Built-in)",
            "modules": ["*"],
            "offensive": _FULL_SCOPE_OFFENSIVE,
        },
        "normal": {
            "rps": 10,
            "concurrency": 10,
            "description": "Normal → Stealth'e eslendi (Built-in)",
            "modules": ["*"],
            "offensive": _FULL_SCOPE_OFFENSIVE,
        },
    }
    if not profile and active_name in _BUILTIN_PROFILES:
        profile = _BUILTIN_PROFILES[active_name]
            
    if not profile:
        logging.warning(f"[Config] Profile '{active_name}' not found in settings.profiles")
        return cfg

    logging.info(f"[Config] Applying profile '{active_name}'...")
    cfg["_resolved_profile"] = profile
    
    # 1. Apply root-level overrides (rps, concurrency -> fuzz.rps, fuzz.concurrency)
    # Profiles usually define these shorthand
    if "rps" in profile:
        cfg.setdefault("fuzz", {})["rps"] = profile["rps"]
    if "concurrency" in profile:
        cfg.setdefault("fuzz", {})["concurrency"] = profile["concurrency"]
        
    # 2. Apply explicit subsections (modules, http, etc.)
    # If profile has "http": {...}, merge it into cfg["http"]
    for key, val in profile.items():
        if key in ("rps", "concurrency", "description"):
            continue # Handled or metadata
            
        if isinstance(val, dict) and isinstance(cfg.get(key), dict):
            # Shallow merge for sections
            cfg[key].update(val)
        else:
            # Direct overwrite
            cfg[key] = val
            
    # 3. Normalize http.timeout → http.timeout_seconds
    # Profiles set "timeout" but http.py reads "timeout_seconds"
    http_sec = cfg.get("http")
    if isinstance(http_sec, dict) and "timeout" in http_sec and "timeout_seconds" not in http_sec:
        http_sec["timeout_seconds"] = http_sec["timeout"]

    # 4. Special handling for 'safe_full' or 'aggressive' flags
    if active_name == "safe_full":
        # Ensure deep scan mode is reflected
        if "fuzz" in cfg:
            cfg["fuzz"]["rate_limit"] = cfg["fuzz"].get("rate_limit", {})
            cfg["fuzz"]["rate_limit"]["max_rate_ms"] = 1500 # Slower

    return cfg
