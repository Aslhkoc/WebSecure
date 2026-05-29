import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

# ========================== Config Loading ==========================
_SUPPORTED_SCHEMA_VERSION = (1, 0)

try:
    import jsonschema as _jsonschema
    _JSONSCHEMA_AVAILABLE = True
except ImportError:
    _jsonschema = None  # type: ignore[assignment]
    _JSONSCHEMA_AVAILABLE = False


def validate_config(cfg: dict, schema_path: Optional[str] = None) -> List[str]:
    """
    Validate *cfg* against a JSON Schema (if jsonschema is installed and the
    schema file exists) or fall back to manual type-checking of critical fields.

    Returns a list of warning message strings (empty list means no issues).
    Never raises — validation failures are always non-fatal.
    """
    warnings: List[str] = []

    # ------------------------------------------------------------------ #
    # Strategy 1: jsonschema + schema file                                 #
    # ------------------------------------------------------------------ #
    if _JSONSCHEMA_AVAILABLE:
        # Locate the schema file
        candidates: List[Path] = []
        if schema_path:
            candidates.append(Path(schema_path))
        # Default: project root (two levels up from websecure/core/utils/)
        candidates.append(Path(__file__).parent.parent.parent.parent / "config.schema.json")
        candidates.append(Path(__file__).parent.parent.parent / "config.schema.json")

        schema_file: Optional[Path] = next(
            (c for c in candidates if c.exists()), None
        )

        if schema_file:
            try:
                with schema_file.open("r", encoding="utf-8") as fh:
                    schema = json.load(fh)
                validator = _jsonschema.Draft7Validator(schema)
                for error in sorted(validator.iter_errors(cfg), key=lambda e: list(e.path)):
                    msg = f"[Config] Schema validation warning at '{'.'.join(str(p) for p in error.path)}': {error.message}"
                    warnings.append(msg)
            except Exception as exc:
                warnings.append(f"[Config] Could not run jsonschema validation: {exc}")
        else:
            # jsonschema available but no schema file — fall through to manual checks
            warnings.extend(_manual_type_checks(cfg))
    else:
        # ------------------------------------------------------------------ #
        # Strategy 2: manual type-checking of critical fields                 #
        # ------------------------------------------------------------------ #
        warnings.extend(_manual_type_checks(cfg))

    return warnings


def _manual_type_checks(cfg: dict) -> List[str]:
    """Return warning strings for critical config fields that fail type constraints."""
    issues: List[str] = []

    # http.timeout_seconds must be int in 1..300
    timeout = cfg.get("http", {}).get("timeout_seconds")
    if timeout is not None:
        if not isinstance(timeout, int) or not (1 <= timeout <= 300):
            issues.append(
                f"[Config] http.timeout_seconds must be an integer between 1 and 300 "
                f"(got {timeout!r})"
            )

    # scan.max_workers must be int in 1..64
    max_workers = cfg.get("scan", {}).get("max_workers")
    if max_workers is not None:
        if not isinstance(max_workers, int) or not (1 <= max_workers <= 64):
            issues.append(
                f"[Config] scan.max_workers must be an integer between 1 and 64 "
                f"(got {max_workers!r})"
            )

    # oast.dns_domain if present must be a non-empty string
    dns_domain = cfg.get("oast", {}).get("dns_domain")
    if dns_domain is not None:
        if not isinstance(dns_domain, str) or not dns_domain.strip():
            issues.append(
                f"[Config] oast.dns_domain must be a non-empty string (got {dns_domain!r})"
            )

    return issues


def _resolve_config_path(path: str) -> Path:
    """config.json'u CWD'de değilse proje kökünde ara.

    Dosya yapısı: <project_root>/websecure/core/utils/config.py
    config.json:  <project_root>/config.json
    Bu yüzden 4 üst dizin == proje kökü.
    """
    p = Path(path)
    if p.exists():
        return p
    # websecure/core/utils/config.py → 4 üst = proje kökü
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    candidate = project_root / path
    if candidate.exists():
        return candidate
    return p  # bulunamadıysa orijinali döndür, caller handle eder


def load_config(path: str = "config.json") -> Dict[str, Any]:
    p = _resolve_config_path(path)
    cfg = {}
    found = False
    if p.exists():
        found = True
        try:
            with p.open("r", encoding="utf-8") as f:
                cfg = json.load(f)
        except json.JSONDecodeError as e:
            logging.error(
                "config.json parse hatası — satır %d sütun %d: %s. "
                "Tüm tarayıcılar built-in defaults ile çalışacak.",
                e.lineno, e.colno, e.msg,
            )
        except Exception as e:
            logging.error("Config yüklenemedi (%s): %s — built-in defaults kullanılıyor.", path, e)

    # Versiyon uyarısını yalnızca dosya bulundu ama alan eksikse göster
    if found:
        _validate_version(cfg, str(p))

    # Run comprehensive validation; emit every warning found
    for msg in validate_config(cfg):
        logging.warning(msg)

    _apply_defaults(cfg)
    return cfg


def _validate_version(cfg: Dict[str, Any], path: str) -> None:
    ver = cfg.get("version")
    if ver is None:
        logging.debug(
            "[Config] 'version' alanı bulunamadı (%s). "
            "config.json'a \"version\": \"1.0\" ekleyin.",
            path,
        )
        return
    try:
        parts = [int(x) for x in str(ver).split(".", 2)[:2]]
        if tuple(parts[:2]) > _SUPPORTED_SCHEMA_VERSION:
            logging.warning(
                "[Config] Config versiyonu (%s) bu WebSecure sürümünün desteklediğinden "
                "(%s) yüksek. Bilinmeyen alanlar görmezden gelinecek.",
                ver,
                ".".join(str(x) for x in _SUPPORTED_SCHEMA_VERSION),
            )
        else:
            logging.debug("[Config] Version %s OK.", ver)
    except (ValueError, TypeError):
        logging.warning("[Config] Geçersiz version formatı: %r (beklenen: '1.0')", ver)

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
        logging.warning("[Wordlists] Wordlist klasörü bulunamadı. Aranan konumlar: %s", [str(c) for c in candidates])
        
    return cfg

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
            "description": "Safe Full -> Stealth'e eslendi (Built-in)",
            "modules": ["*"],
            "offensive": _FULL_SCOPE_OFFENSIVE,
            "http": {"timeout_seconds": 30, "retries": 3},
        },
        "deep": {
            "rps": 15,
            "concurrency": 20,
            "description": "Deep -> Agresif'e eslendi (Built-in)",
            "modules": ["*"],
            "offensive": _FULL_SCOPE_OFFENSIVE,
        },
        "normal": {
            "rps": 10,
            "concurrency": 10,
            "description": "Normal -> Stealth'e eslendi (Built-in)",
            "modules": ["*"],
            "offensive": _FULL_SCOPE_OFFENSIVE,
        },
    }
    if not profile and active_name in _BUILTIN_PROFILES:
        profile = _BUILTIN_PROFILES[active_name]

    # ProfileRegistry fallback: bug_bounty, cicd, api_only, authenticated, compliance vb.
    if not profile:
        try:
            from websecure.core.profiles import get_registry as _get_registry
            _reg_profile = _get_registry().get(active_name)
            if _reg_profile is not None:
                logging.info(f"[Config] Profile '{active_name}' ProfileRegistry üzerinden uygulanıyor.")
                return _reg_profile.apply(cfg)
        except Exception as _exc:
            logging.debug(f"[Config] ProfileRegistry fallback başarısız: {_exc!r}")

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
            
    # 3. Normalize http.timeout -> http.timeout_seconds
    # Profiles set "timeout" but http.py reads "timeout_seconds"
    # Use pop() to remove the old key so both keys don't coexist
    http_sec = cfg.get("http")
    if isinstance(http_sec, dict) and "timeout" in http_sec:
        if "timeout_seconds" not in http_sec:
            http_sec["timeout_seconds"] = http_sec.pop("timeout")
        else:
            # timeout_seconds already present — remove stale "timeout" to avoid confusion
            del http_sec["timeout"]

    # 4. Special handling for 'safe_full' or 'aggressive' flags
    if active_name == "safe_full":
        # Ensure deep scan mode is reflected
        if "fuzz" in cfg:
            cfg["fuzz"]["rate_limit"] = cfg["fuzz"].get("rate_limit", {})
            cfg["fuzz"]["rate_limit"]["max_rate_ms"] = 1500 # Slower

    return cfg
