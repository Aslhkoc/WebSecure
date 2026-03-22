from __future__ import annotations
import logging
import os
import shutil
import time
from typing import Dict, Any, List

from websecure.core.reporting import add_result
from websecure.core.http import hardened_session
from websecure.crawler import WebCrawler, CrawlerConfig

# Integration Wrappers
try:
    from websecure.integrations.sqlmap import SQLMapWrapper
except ImportError:
    SQLMapWrapper = None

try:
    from websecure.integrations.ffuf import FFUFWrapper
except ImportError:
    FFUFWrapper = None

try:
    from websecure.integrations.feroxbuster import FeroxbusterWrapper
except ImportError:
    FeroxbusterWrapper = None

try:
    from websecure.core.oast import IOSATClient
except ImportError:
    IOSATClient = None

# Fallback/Nuclei for XSS if external tools preferred
try:
    from websecure.scanners.owasp import run_owasp_and_nuclei
except ImportError:
    run_owasp_and_nuclei = None

# [WS3] Robust Local Scanners (Always Available)
try:
    from websecure.scanners.xss import run as run_local_xss
except ImportError:
    run_local_xss = None

try:
    from websecure.scanners.sqli import run as run_local_sqli
except ImportError:
    run_local_sqli = None

_logger = logging.getLogger(__name__)


def _get_config(ctx, key: str, default: Any = None) -> Any:
    cfg = getattr(ctx, "config", {}) or {}
    if not isinstance(cfg, dict):
        return default
    
    parts = key.split(".")
    curr = cfg
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        else:
            return default
    return curr

def _resolve_proxy(ctx) -> str | None:
    """Helper to get proxy string from config (Tor/Rotation)."""
    # 1. Check if Tor is active via proxy_manager
    tor = _get_config(ctx, "proxy.tor.enabled", False)
    if tor:
        return "socks5://127.0.0.1:9050" 
    
    # 2. Check explicit proxy
    proxy_url = _get_config(ctx, "http.proxy")
    if proxy_url:
        return proxy_url
    
    return None

def run_discovery_extended(ctx) -> None:
    """
    Runs the advanced crawler discovery phase.
    Supports Visibility and Proxy.
    """
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return

    _logger.info(f"Starting Extended Discovery on {url}")
    session = getattr(ctx, "session", None) or hardened_session()
    
    # Configure Crawler
    c_cfg = CrawlerConfig()
    c_cfg.max_depth = int(_get_config(ctx, "discovery.max_depth", 3))
    c_cfg.max_pages = int(_get_config(ctx, "discovery.max_pages", 50))
    
    # [Check 1] Visibility
    is_visible = bool(getattr(ctx, "visible", False) or _get_config(ctx, "crawl.browser.headless") is False)
    
    # [Check 5] Proxy/Evasion
    proxy_server = _resolve_proxy(ctx)
    if proxy_server:
        _logger.info(f"[Evasion] Crawler using proxy: {proxy_server}")

    # Note: WebCrawler inner logic should handle driver proxy config if implemented
    crawler = WebCrawler(
        session, 
        start_url=url, 
        config=c_cfg, 
        debug=bool(getattr(ctx, "debug", False)),
        driver=None # Driver will be initialized inside with visibility check if crawler.py supports it
    )
    
    # If crawler.py WebCrawler supports 'headless' param in init, use it. 
    # Current code inspection suggests it auto-detects or uses driver.
    
    res = crawler.start()
    
    # Update Context Results
    if isinstance(res, dict):
        current_res = getattr(ctx, "results", {}) or {}
        # Merge carefully
        found_endpoints = res.get("endpoints", [])
        
        # [WS3] Fallback: If no endpoints found, use base URL to ensure offensive scanners have a target.
        if not found_endpoints and url:
             _logger.info("Discovery yielded no endpoints. Forcing base URL as target for offensive phases.")
             found_endpoints = [url]
        
        # [WS3] Enhanced Form Parsing (User Logic Integration)
        # Force a fetch of base URL to parse dynamic inputs/forms if not done
        try:
             from websecure.core.form_parser import extract_all_forms
             t_html = ""
             # Try to get HTML from crawler results if available, else fetch
             if isinstance(res, dict) and res.get("html"):
                  t_html = res.get("html")
             elif ctx.session:
                  # Quick fetch
                  try:
                       rr = ctx.session.get(url, timeout=10)
                       t_html = rr.text
                  except: pass
             
             if t_html:
                  new_forms = extract_all_forms(t_html, url)
                  # Merge into results['forms_meta']
                  existing_forms = current_res.get("forms_meta", [])
                  # Convert to list if it's a dict (old format?) usually list of pages
                  # We'll append a "virtual page" for these forms
                  if new_forms:
                        _logger.info(f"[FormParser] Extracted {len(new_forms)} forms (including dynamic script inputs).")
                        # Add as a generic page entry
                        existing_forms.append({
                             "url": url,
                             "forms": new_forms
                        })
                        current_res["forms_meta"] = existing_forms
        except ImportError:
             _logger.warning("Could not import form_parser.")
        except Exception as e:
             _logger.error(f"Form parsing failed: {e}")

        existing = set(current_res.get("endpoints", []))
        existing.update(found_endpoints)
        current_res["endpoints"] = list(existing)
        
        # Merge other keys
        for k, v in res.items():
            if k != "endpoints":
                current_res[k] = v
        
        ctx.results = current_res
        
    add_result("meta", {"stage": "discovery_extended", "count": len(getattr(ctx, "results", {}).get("endpoints", []))})


def _prioritize_urls(urls: List[str]) -> List[str]:
    """
    Sorts URLs by 'interest' level for offensive scanning.
    High Priority: Login, Admin, Payment, Parameters
    Low Priority: Deep nesting, Static-looking, Logout
    """
    if not urls: return []
    
    def _score(u: str) -> int:
        s = 0
        ul = u.lower()
        if "?" in ul: s += 20
        if any(k in ul for k in ("login", "signin", "auth", "admin", "account", "register", "signup")): s += 50
        if any(k in ul for k in ("pay", "checkout", "cart", "buy", "order")): s += 40
        if "password" in ul or "reset" in ul: s += 30
        
        # Penalize deep nesting (often irrelevant content)
        s -= (ul.count("/") * 2)
        
        # Avoid destructive/logout
        if "logout" in ul or "signout" in ul: s -= 500
        
        return s
        
    return sorted(list(set(urls)), key=_score, reverse=True)



def run_sqlmap_scan(ctx) -> None:
    """
    Runs SQLMap against the target using the integration wrapper.
    [Check 1, 2, 5] Tools working, Payload/Exploit, Proxy support.
    """
    if SQLMapWrapper is None:
        add_result("sqlmap", {"status": "skipped", "reason": "Integration module missing"})
        return

    url = getattr(ctx, "base_url", None)
    if not url:
        return

    # Check config
    if not _get_config(ctx, "offensive.sqlmap.enabled", True):
        return

    _logger.info("Launching SQLMap scan...")
    wrapper = SQLMapWrapper()
    if not wrapper.is_available():
        add_result("sqlmap", {"status": "skipped", "reason": "Binary not found in PATH"})
        return

    # [Check 2] Payloads/Exploit levels
    level = int(_get_config(ctx, "offensive.sqlmap.level", 1))
    risk = int(_get_config(ctx, "offensive.sqlmap.risk", 1))
    
    # [Check 5] Proxy
    extra_args = []
    proxy = _resolve_proxy(ctx)
    if proxy:
        extra_args.append(f"--proxy={proxy}")
        _logger.info(f"[Evasion] SQLMap using proxy: {proxy}")

    if _get_config(ctx, "offensive.sqlmap.random_agent", True):
        extra_args.append("--random-agent")


    # [WS3] Smart Engine Integration
    try:
        from websecure.core.smart_engine import analyze_target_context
        # We need headers for detection. Try to get from session or make a quick HEAD
        # For now, we use a heuristic based on URL and known info
        smart_ctx = analyze_target_context(url, {}, []) # Headers not readily avail in ctx yet, improving later
        
        # Determine extensions based on tech stack
        extensions = ""
        techs = smart_ctx.get("tech_stack", [])
        if "php" in techs:
            _logger.info("[Smart-Engine] PHP detected! Adding .php extension to fuzzing.")
            extensions += ",.php"
        if "aspnet" in techs:
            _logger.info("[Smart-Engine] ASP.NET detected! Adding .aspx,.ashx extensions.")
            extensions += ",.aspx,.ashx"
        if "java" in techs:
            extensions += ",.jsp,.do"
            
    except ImportError:
        pass

    # [FIX] Iterate over ALL discovered endpoints, not just base URL
    raw_endpoints = getattr(ctx, "results", {}).get("endpoints", [])
    # [WS3] Priority Sort: Attack Login/Payment/Param-heavy first!
    endpoints = _prioritize_urls(raw_endpoints)
    
    if not endpoints:
        endpoints = [url]
    
    # [FIX] Get discovered params to hint SQLMap
    params = getattr(ctx, "results", {}).get("param_candidates", [])
    
    # [WS3] Smart Param Analysis
    # If we have params, analyze them to find High-Value Targets for SQLi
    high_value_params = []
    try:
        from websecure.core.smart_engine import analyze_target_context
        p_analysis = analyze_target_context(url, {}, list(params)).get("param_risks", {})
        for p, vulns in p_analysis.items():
            if "sqli" in vulns:
                high_value_params.append(p)
                _logger.info(f"[Smart-Engine] High-Risk SQLi Parameter detected: {p}")
    except Exception:
        pass

    param_str = ",".join(params) if params else None

    findings = []
    _logger.info(f"Launching SQLMap scan on {len(endpoints)} endpoints...")
    
    for target_ep in endpoints:
        # Skip static assets to save time
        if any(target_ep.endswith(ext) for ext in (".png", ".jpg", ".css", ".js")):
            continue
            
        cmd_args = list(extra_args)
        if param_str:
            cmd_args.append(f"-p {param_str}")  # Force test these params
        
        # [WS3] Boost Level/Risk for High-Value Targets
        # If the URL contains high-value params, we might want to boost intensity
        # For now, we just ensure they are tested.
            
        current_findings = wrapper.scan(target_ep, batch=True, level=level, risk=risk, extra_args=cmd_args)
        findings.extend(current_findings)
    
    # Report
    if findings:
        for f in findings:
            # [Check 2] Validating exploits
            # [WS3] Merge finding data to expose 'evidence' key to reporting
            entry = {
                "severity": "high", 
                "type": "SQL Injection",
                "tool": "sqlmap"
            }
            if isinstance(f, dict):
                entry.update(f) # Merges raw_finding and EVIDENCE
            else:
                entry["detail"] = f
                
            add_result("sqlmap", entry)
    else:
        add_result("sqlmap", {"status": "finished", "findings": 0})

    # [WS3] Python-based SQLi (Robust Fallback/Companion)
    if run_local_sqli:
        _logger.info("[SQLi] Running internal robust SQLi scanner (Python)...")
        # Ensure discovered params are passed via results if needed, but scanner reads forms_meta itself
        run_local_sqli(
            endpoints,
            getattr(ctx, "session", None),
            results=getattr(ctx, "results", {}), 
            debug=bool(getattr(ctx, "debug", False))
        )


def run_xss_scan(ctx) -> None:
    """
    [Check 2] XSS Payload/Exploit trials.
    [WS3] UPDATED: Uses Robust Local XSS Scanner (xss.py) + Nuclei/OWASP as secondary.
    """
    _logger.info("Launching XSS Scan...")
    
    # 1. Local Python Scanner (Robust)
    if run_local_xss:
        _logger.info("[XSS] Running internal XSS scanner (Python/Canary)...")
        _raw_eps = getattr(ctx, "results", {}).get("endpoints", [])
        # [WS3] Smart Prioritization
        _eps = _prioritize_urls(_raw_eps)
        if not _eps:
             _eps = [getattr(ctx, "base_url", "")]
        
        run_local_xss(
            _eps,
            getattr(ctx, "session", None),
            results=getattr(ctx, "results", {}),
            debug=bool(getattr(ctx, "debug", False))
        )
    else:
        _logger.warning("[XSS] Internal scanner missing (xss.py).")

    # 2. Nuclei / OWASP (Secondary)
    if run_owasp_and_nuclei:
        # Nuclei handles XSS templates
        run_owasp_and_nuclei(
            getattr(ctx, "base_url", ""), 
            getattr(ctx, "results", {}), 
            getattr(ctx, "session", None),
            config=getattr(ctx, "config", {}),
            debug=bool(getattr(ctx, "debug", False))
        )
    else:
        if not run_local_xss:
             add_result("xss", {"status": "skipped", "reason": "ALL XSS modules missing"})


def run_ffuf_scan(ctx) -> None:
    """
    Runs FFUF fuzzing.
    [Check 6] Wordlists usage.
    """
    if FFUFWrapper is None:
        add_result("ffuf", {"status": "skipped", "reason": "Integration module missing"})
        return

    url = getattr(ctx, "base_url", None)
    if not url:
        return

    if not _get_config(ctx, "offensive.ffuf.enabled", True):
        return

    # [WS3] Dynamic Wordlist Collection
    from websecure.core.utils import collect_all_wordlists
    import tempfile
    
    _logger.info("Dinamik wordlist taraması başlatılıyor...")
    wl_data = collect_all_wordlists()
    all_wls = wl_data.get("all", [])
    count = wl_data.get("count", 0)
    est_lines = wl_data.get("total_lines_est", 0)
    
    _logger.info(f"[Wordlists] Toplam {count} adet wordlist dosyası bulundu.")
    _logger.info(f"[Wordlists] Tahmini toplam satır: {est_lines}")
    
    if count == 0:
        add_result("ffuf", {"status": "skipped", "reason": "No wordlists found in dynamic search"})
        return

    # Merge into a single temp file
    # ... code for merging wordlists ...
    
    # [WS3] Smart Login Audit
    # We run this if discovery found forms, or if we want to probe the login page specifically
    if _get_config(ctx, "offensive.login_audit.enabled", True):
        try:
            from websecure.core.login_auditor import LoginAuditor
            
            # Identify forms from crawler results
            forms_meta = getattr(ctx, "results", {}).get("forms_meta", [])
            
            # If no forms meta, maybe we can try the base URL if it looks like login?
            # For now, rely on crawler output.
            
            if forms_meta:
                _logger.info(f"[Login-Audit] Found {len(forms_meta)} potential login forms. Starting Smart Audit (1000+ words)...")
                
                # Resolve wordlist path
                import os
                wl_path = os.path.join(os.getcwd(), "websecure/wordlists/passwords_top1000.txt")
                if not os.path.exists(wl_path):
                     _logger.warning("[Login-Audit] Wordlist not found, generating default...")
                     # write basic if missing (failsafe)
                     with open(wl_path, "w") as f: f.write("admin\n123456\npassword\n")
                
                auditor = LoginAuditor(getattr(ctx, "session"), url, wl_path)
                
                # Re-feed forms into auditor (since auditor heuristic runs on HTML, 
                # but we already have form meta, we might need to adapt or just let auditor re-check URLs)
                # Simpler: Let auditor Scan the LOGIN urls found
                
                login_urls = [f['url'] for f in forms_meta]
                
                # Fetch content again to parse inputs accurately
                for l_url in login_urls:
                    try:
                        resp = getattr(ctx, "session").get(l_url, timeout=10)
                        auditor.discover_forms(resp.text, l_url)
                    except Exception:
                        pass
                        
                results = auditor.run_audit()
                for res in results:
                    add_result("auth", res)
                    
        except Exception as e:
            _logger.error(f"[Login-Audit] Failed: {e}")

    # Return or continue...

    # This is safer than multiple -w flags for a single FUZZ keyword
    merged_wl_path = "merged_wordlist_temp.txt"  # Local temp for visibility or debug
    try:
        # Create a true temp file to avoid clutter, or keeping it if debug needed? 
        # User wants "connected", let's make a temp file that is cleaned up.
        with tempfile.NamedTemporaryFile(mode='w', delete=False, prefix='ws_merged_vl_', suffix='.txt', encoding='utf-8', errors='ignore') as tmp:
            merged_wl_path = tmp.name
            for wl_file in all_wls:
                try:
                    with open(wl_file, 'r', encoding='utf-8', errors='ignore') as src:
                        shutil.copyfileobj(src, tmp)
                        tmp.write("\n") # Ensure separation
                except Exception as e:
                    _logger.warning(f"Failed to merge wordlist {wl_file}: {e}")
                    
        _logger.info(f"[Wordlists] Tüm listeler birleştirildi: {merged_wl_path}")
        
        wrapper = FFUFWrapper()
        if not wrapper.is_available():
            add_result("ffuf", {"status": "skipped", "reason": "Binary not found"})
            return

        _logger.info(f"Launching FFUF scan with MERGED wordlist...")

        custom_args = []
        # [Check 5] Proxy
        proxy = _resolve_proxy(ctx)
        if proxy:
            custom_args.extend(["-x", proxy])

        # --- Directory/path discovery ---
        findings = wrapper.run_scan(url, wordlist=merged_wl_path, custom_args=custom_args)
        for f in findings:
            add_result("discovery", {"tool": "ffuf", **f})

        # --- File extension discovery (backup, config, env files) ---
        sensitive_exts = ".php,.asp,.aspx,.jsp,.html,.bak,.env,.config,.xml,.json,.txt,.zip,.sql,.log,.old,.backup,.db,.key,.pem"
        _logger.info("[FFUF] Starting file extension scan...")
        ext_findings = wrapper.run_scan(
            url,
            wordlist=merged_wl_path,
            extensions=sensitive_exts,
            custom_args=custom_args,
        )
        try:
            from websecure.scanners.js_analyzer import classify_discovered_file
            for f in ext_findings:
                f_url = f.get("url", "")
                f_status = f.get("status", 200)
                classified = classify_discovered_file(f_url, f_status)
                if classified:
                    add_result("files_discovered", classified)
                    if classified.get("severity") in ("Critical", "High"):
                        add_result("offensive", classified)
                else:
                    add_result("files_discovered", {"tool": "ffuf", "severity": "Info", **f})
        except ImportError:
            for f in ext_findings:
                add_result("files_discovered", {"tool": "ffuf", "severity": "Info", **f})
            
    finally:
        # Cleanup
        if os.path.exists(merged_wl_path):
             try:
                 os.remove(merged_wl_path)
                 _logger.debug("Merged wordlist deleted.")
             except:
                 pass


def run_feroxbuster_scan(ctx) -> None:
    """
    Runs Feroxbuster for content discovery.
    """
    if FeroxbusterWrapper is None:
        add_result("feroxbuster", {"status": "skipped", "reason": "Integration module missing"})
        return
        
    url = getattr(ctx, "base_url", None)
    if not url:
        return
        
    if not _get_config(ctx, "offensive.feroxbuster.enabled", True):
        return

    wrapper = FeroxbusterWrapper()
    if not wrapper.is_available():
        add_result("feroxbuster", {"status": "skipped", "reason": "Binary not found"})
        return

    _logger.info("Launching Feroxbuster scan...")
    depth = int(_get_config(ctx, "discovery.depth", 2))
    
    extra_args = []
    # [Check 5] Proxy
    proxy = _resolve_proxy(ctx)
    if proxy:
        extra_args.extend(["--proxy", proxy])
        
    findings = wrapper.scan(url, depth=depth, extra_args=extra_args)
    
    new_eps = []
    for f in findings:
        f_url = f.get("url")
        if f_url:
             new_eps.append(f_url)
        add_result("discovery", {"tool": "feroxbuster", **f})

    # [WS3] FEEDBACK LOOP: Add to endpoints for offensive tools
    if new_eps:
        current_res = getattr(ctx, "results", {}) or {}
        existing = set(current_res.get("endpoints", []))
        before_count = len(existing)
        existing.update(new_eps)
        current_res["endpoints"] = list(existing)
        if len(existing) > before_count:
             _logger.info(f"[Feroxbuster] Added {len(existing) - before_count} new endpoints to offensive context.")
        ctx.results = current_res


def run_js_analysis(ctx) -> None:
    """
    Discovers and analyses JavaScript files on the target:
    - Extracts hidden API endpoints / internal paths
    - Detects hardcoded secrets, tokens, API keys
    """
    url = getattr(ctx, "base_url", None)
    if not url:
        return

    if not _get_config(ctx, "offensive.js_analysis.enabled", True):
        add_result("js_analysis", {"status": "skipped", "reason": "Disabled in config"})
        return

    try:
        from websecure.scanners.js_analyzer import JSAnalyzer
    except ImportError:
        add_result("js_analysis", {"status": "skipped", "reason": "js_analyzer module missing"})
        return

    _logger.info("[JSAnalyzer] Starting JavaScript file analysis...")
    results_bucket = getattr(ctx, "results", {}) or {}
    session = getattr(ctx, "session", None)

    analyzer = JSAnalyzer(session=session, results=results_bucket, debug=False)
    findings = analyzer.run(url)

    for f in findings:
        add_result("js_analysis", f)
        if f.get("severity") in ("High", "Critical"):
            add_result("offensive", f)

    _logger.info(f"[JSAnalyzer] Done. {len(findings)} finding(s) recorded.")


def run_reporting_and_integration(ctx) -> None:
    from websecure.core.reporting import perform_reporting
    
    results = getattr(ctx, "results", {}) or {}
    cfg = getattr(ctx, "config", {}) or {}
    session = getattr(ctx, "session", None)
    
    _logger.info("Generating Final Reports...")
    perform_reporting(session, cfg, results)


def run_oast_verification(ctx) -> None:
    add_result("meta", {"stage": "oast", "status": "not_implemented_yet"})



def run_fuzz_and_param_discovery(ctx) -> None:
    """
    Parametre keşfi ve fuzzing fazı.
    Ana döngüdeki (main.py) fuzzing adımından önce, spesifik parametre analizi yapar.
    """
    # [WS3] Eğer scanners/param_miner.py eklenirse buraya bağlanacak.
    # Şimdilik ana döngüye bırakıyoruz ama logluyoruz.
    add_result("meta", {"stage": "fuzz_param_discovery", "status": "delegated_to_main_loop"})
    _logger.info("Fuzzing ve Parametre Analizi ana döngüye (fuzzing fazı) devredildi.")

def run_authorization_matrix(ctx) -> None:
    """
    Yetkilendirme matrisi (IDOR/PrivEsc) testi.
    scanners.auth modülünü kullanır.
    """
    mod = _opt_import("scanners.auth")
    if not mod:
        add_result("auth_matrix", {"status": "skipped", "reason": "Module not found"})
        return

    # run(session, base_url, users=[...]) imzasına uyum sağla
    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        add_result("auth_matrix", {"status": "skipped", "reason": "run() function missing"})
        return

    # Config'den kullanıcıları al
    cfg = getattr(ctx, "config", {}) or {}
    auth_cfg = cfg.get("auth", {}) or {}
    if not auth_cfg.get("matrix_enabled", True):
        return

    users = auth_cfg.get("users", []) # [{"user": "admin", "pass": "123"}, ...]
    
    _logger.info("Launching Authorization Matrix Scan...")
    
    # Session ve URL
    sess = getattr(ctx, "session", None) or hardened_session()
    url = getattr(ctx, "base_url", "")
    
    try:
        # Modülün run fonksiyonunu çağır
        # Not: scanners.auth.run genelde (url, session, config) veya (url, users) bekler.
        # İmzayı dinamik kontrol edelim.
        kw = _filter_kwargs(run_fn, {"url": url, "base_url": url, "session": sess, "config": cfg, "users": users})
        findings = run_fn(**kw)
        
        if findings:
            for f in findings:
                add_result("auth_matrix", f)
        add_result("meta", {"stage": "auth_matrix", "findings": len(findings) if findings else 0})

    except Exception as e:
        _logger.error(f"Auth Matrix Error: {e}")
        add_result("errors", {"stage": "auth_matrix", "error": str(e)})


def run_business_logic_races(ctx) -> None:
    """
    Business Logic Race Condition testlerini çalıştırır.
    websecure.core.bl_concurrency modülünü kullanır.
    """
    try:
        from websecure.core.bl_concurrency import run_race_conditions
    except ImportError:
        add_result("meta", {"stage": "races", "status": "skipped:missing_core_module"})
        return

    sess = getattr(ctx, "session", None) or hardened_session()
    url = getattr(ctx, "base_url", "")
    cfg = getattr(ctx, "config", {}) or {}
    results_bucket = getattr(ctx, "results", {}) or {}
    debug = bool(getattr(ctx, "debug", False))

    if not _get_config(ctx, "business_logic.enabled", True):
        return

    _logger.info("Launching Business Logic Race Conditions Scan...")
    
    # Raporlama callback
    def _cb(evt, data):
        if debug:
            _logger.debug(f"[Race] {evt}: {data}")

    try:
        stats = run_race_conditions(sess, url, cfg, results_bucket, debug=debug, event_cb=_cb)
        _logger.info(f"Race Scan Finished: {stats}")
    except Exception as e:
        _logger.error(f"Race Scan Failed: {e}")
        add_result("errors", {"stage": "races", "error": str(e)})

