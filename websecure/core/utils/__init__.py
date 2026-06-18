# Facade for backward compatibility — explicit imports replace wildcard exports

# --- net.py ---
from .net import (
    silence_insecure_request_warnings,
    SchemeDetectionResult,
    detect_canonical_scheme,
    apply_detected_scheme,
    http_to_ws,
    make_curl_poc,
    allowed_http_methods,
    build_raw_http_request,
    build_response_head,
    normalize_url,
    resolve_canonical_base,
    canonicalize_url,
    same_origin,
    same_site,
    registrable_domain,
    is_junk_url,
    is_streaming_endpoint,
    is_static_asset,
    run_content_discovery,
    validate_url,
)

# --- helpers.py ---
from .helpers import (
    random_string,
    apply_auth_context,
    sig_params,
    kw_filter,
    guess_host_from_url,
)

# redact_sensitive — canonical implementation lives in core.redaction
from ..redaction import redact_sensitive

# --- system.py ---
from .system import (
    setup_logging,
    setup_webdriver,
    quit_driver,
    reap_drivers,
    ensure_dir,
    current_identity,
    set_identity,
    _ws_import_any,
    _ws_maybe_import_any,
)

# --- config.py ---
from .config import (
    load_config,
    get_active_profile,
    validate_and_normalize_config,
    ensure_wordlists,
    get_logging_prefs,
    apply_active_profile,
)

# --- wordlists.py ---
from .wordlists import (
    collect_all_wordlists,
    get_best_wordlist,
    get_tech_extensions,
)

# Façade'in dışa açtığı public API — re-export'ları açıkça beyan eder
# (pyflakes "unused import" yanılgısını önler, public yüzeyi belgeler).
__all__ = [
    # net
    "silence_insecure_request_warnings", "SchemeDetectionResult",
    "detect_canonical_scheme", "apply_detected_scheme", "http_to_ws",
    "make_curl_poc", "allowed_http_methods", "build_raw_http_request",
    "build_response_head", "normalize_url", "resolve_canonical_base",
    "canonicalize_url", "same_origin", "same_site", "registrable_domain", "is_junk_url",
    "is_streaming_endpoint", "is_static_asset",
    "run_content_discovery", "validate_url",
    # helpers
    "random_string", "apply_auth_context", "sig_params", "kw_filter",
    "guess_host_from_url",
    # redaction
    "redact_sensitive",
    # system
    "setup_logging", "setup_webdriver", "quit_driver", "reap_drivers",
    "ensure_dir", "current_identity",
    "set_identity", "_ws_import_any", "_ws_maybe_import_any",
    # config
    "load_config", "get_active_profile", "validate_and_normalize_config",
    "ensure_wordlists", "get_logging_prefs", "apply_active_profile",
    # wordlists
    "collect_all_wordlists", "get_best_wordlist", "get_tech_extensions",
]
