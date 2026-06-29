from __future__ import annotations
from importlib.util import find_spec as _find_spec
from websecure.core.reporting import add_result
import logging
import random
import time
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse
import json as _json
import shlex as _shlex
import shutil as _shutil
import subprocess as _subprocess

_logger = logging.getLogger(__name__)

# NOT: injection fonksiyonları bu modülde tekrar ETMİYOR.
# Gerekirse main zaten scanners.injection üzerinden çağırıyor.

# ----------------- ortak yardımcılar -----------------
def _ensure_bucket(results: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    results.setdefault(key, [])
    return results[key]

def _summary(results: Dict[str, Any], key: str, count: int):
    results[f"{key}_summary"] = {"vulnerabilities": int(count)}


def _safe_get(session, url: str, *, timeout: int = 7, allow_redirects: bool = True, headers: Optional[Dict[str, str]] = None):
    """
    HEAD ile yoklar, 405/501 ise GET'e döner. Ağı/SSL'i asla yukarı fırlatmaz.
    Başarısızlıkta minimal bir "dummy" yanıt döner (status_code=0, headers={}, text="").
    """
    verify = getattr(session, "verify", True)
    try:
        r = session.head(url, timeout=timeout, allow_redirects=allow_redirects, verify=verify, headers=headers or {})
        if getattr(r, "status_code", 0) in (405, 501):
            r = session.get(url, timeout=timeout, allow_redirects=allow_redirects, verify=verify, headers=headers or {})
        return r
    except Exception as _e:
        class _Dummy:
            def __init__(self, url, err):
                self.status_code = 0
                self.headers = {}
                self.text = ""
                self.url = url
                self.error = str(err)
        return _Dummy(url, _e)
def _try_get(session, url: str, *, timeout: int = 7, allow_redirects: bool = True, headers: Optional[Dict[str, str]] = None):
    return _safe_get(session, url, timeout=timeout, allow_redirects=allow_redirects, headers=headers)


def _looks_directory_listing(text: str) -> bool:
    t = (text or "").lower()
    # yaygın imzalar
    return ("index of /" in t) or ("directory listing for" in t) or ("parent directory" in t)

def _has_session_cookie(set_cookie_header: str) -> bool:
    sc = (set_cookie_header or "")
    return ("session" in sc.lower()) or ("sid=" in sc.lower()) or ("jwt" in sc.lower())

def _cacheable_headers(h: Dict[str, str]) -> Tuple[bool, List[str]]:
    hints: List[str] = []
    cc = (h.get("Cache-Control") or "").lower()
    pragma = (h.get("Pragma") or "").lower()
    age = h.get("Age")
    vary = (h.get("Vary") or "").lower()
    if "public" in cc or "s-maxage" in cc or "max-age" in cc:
        hints.append("cacheable-cc")
    if age and age.isdigit() and int(age) > 0:
        hints.append("age>0")
    if "host" not in vary and vary != "":
        # Vary mevcut ama Host yok (çoğu cache Host'a göre bölümlemez; ipucu)
        hints.append("vary-miss-host")
    if not cc and pragma != "no-cache":
        hints.append("no-cc")
    return (len(hints) > 0), hints

def _reflects(text: str, needle: str) -> bool:
    return needle.lower() in (text or "").lower()

# ----------------- A01: Broken Access Control -----------------
def check_broken_access_control(url: str, results: Dict, session, debug: bool = False):
    """
    Hafif/gürültüsü az heuristikler:
      - /admin, /dashboard, /config erişilebilir mi?
      - /.git/HEAD, /server-status, /actuator (spring) sızıntıları
      - /.env, /.DS_Store, /.well-known/ açıkları
      - dizin listelemesi
    """
    bucket = "a01_broken_access_control"
    items = _ensure_bucket(results, bucket)
    vulns = 0

    targets = [
        "/admin",
        "/dashboard",
        "/config",
        "/.git/HEAD",
        "/server-status",
        "/actuator",
        "/.env",
        "/.DS_Store",
        "/.well-known/security.txt",
        "/.well-known/openid-configuration",
    ]

    base = url.rstrip("/")

    for path in targets:
        u = base + path
        r = _try_get(session, u, timeout=7, allow_redirects=False)
        if r is None:
            if debug:
                items.append({"issue": "kontrol hatası", "path": path, "severity": "Yok"})
            continue

        code = int(getattr(r, "status_code", 0))
        body = getattr(r, "text", "") or ""

        # .git/HEAD sızıntısı
        if path == "/.git/HEAD" and code == 200 and "ref: refs/heads/" in body:
            items.append({"issue": "VCS sızıntısı (.git/HEAD)", "path": path, "status": code, "severity": "High"})
            vulns += 1
            continue

        # Apache server-status (açık olmamalı)
        if path == "/server-status" and code == 200 and ("apache server status" in body.lower()):
            items.append({"issue": "server-status erişilebilir", "path": path, "status": code, "severity": "Medium"})
            vulns += 1
            continue

        # Spring actuator yüzeyi
        if path == "/actuator" and code in (200, 302) and ("beans" in body.lower() or "health" in body.lower() or "env" in body.lower()):
            items.append({"issue": "Spring Actuator yüzeyi", "path": path, "status": code, "severity": "Medium"})
            vulns += 1
            continue

        # .env dosyası
        if path == "/.env" and code == 200 and ("db_" in body.lower() or "aws_" in body.lower() or "secret" in body.lower()):
            items.append({"issue": ".env dosyası sızıntısı", "path": path, "status": code, "severity": "High"})
            vulns += 1
            continue

        # .DS_Store sızıntısı
        if path == "/.DS_Store" and code == 200 and len(body) > 0:
            items.append({"issue": "Gizli dosya sızıntısı (.DS_Store)", "path": path, "status": code, "severity": "Low"})
            vulns += 1
            continue

        # OIDC discovery güvenliği (bilgi amaçlı)
        if path == "/.well-known/openid-configuration" and code == 200:
            items.append({"issue": "OIDC discovery yayınlanıyor (bilgi)", "path": path, "status": code, "severity": "Low"})

        # Admin benzeri paneller 200 dönüyorsa şüpheli
        if path in ("/admin", "/dashboard", "/config") and code == 200:
            # login sayfasına yönlenmediyse / içerik doluysa
            if ("login" not in (getattr(r, "url", "") or "").lower()) and not _looks_directory_listing(body):
                items.append({"issue": "Yetkisiz erişim olası", "path": path, "status": 200, "severity": "Medium"})
                vulns += 1
                continue

        # Dizin listelemesi
        if code == 200 and _looks_directory_listing(body):
            items.append({"issue": "Dizin listelemesi açık", "path": path, "status": 200, "severity": "Low"})
            vulns += 1

    _summary(results, bucket, vulns)

# ----------------- A02: Cryptographic Failures -----------------
def check_sensitive_data_exposure(url: str, results: Dict, session, debug: bool = False):
    """
    Basit sinyaller:
      - HTTP şeması
      - Set-Cookie içinde Secure/HttpOnly bayrakları
      - Cache-Control yokluğu (oturum çerezi varsa uyarı)
    """
    bucket = "a02_crypto_failures"
    items = _ensure_bucket(results, bucket)
    vulns = 0

    pr = urlparse(url)
    if pr.scheme == "http":
        items.append({"issue": "HTTP üzerinden içerik", "severity": "High"})
        vulns += 1

    r = _safe_get(session, url, timeout=7, allow_redirects=True)
    if r is None or getattr(r, "status_code", 0) == 0:
        items.append({"issue": "İstek hatası (soft)", "severity": "Yok"})
        _summary(results, bucket, vulns)
        return

    hdrs = (getattr(r, "headers", {}) or {})
    set_cookie = hdrs.get("Set-Cookie", "") or ""
    cache_ctrl = (hdrs.get("Cache-Control", "") or "").lower()
    pragma = (hdrs.get("Pragma", "") or "").lower()

    if set_cookie:
        low = str(set_cookie).lower()
        if "secure" not in low:
            items.append({"issue": "Secure bayrağı olmayan cookie", "severity": "Medium"})
            vulns += 1
        if "httponly" not in low:
            items.append({"issue": "HttpOnly bayrağı olmayan cookie", "severity": "Low"})
            vulns += 1

    # oturum çerezi varsa ve agresif cache kontrolü yoksa uyar
    if _has_session_cookie(str(set_cookie)) and not any(k in cache_ctrl for k in ("no-store", "must-revalidate")):
        if pragma != "no-cache":
            items.append({"issue": "Duyarlı içerikte zayıf cache kontrolü", "severity": "Low"})
            vulns += 1

    _summary(results, bucket, vulns)

# ----------------- A07 Identification & Authentication Failures -----------------
def check_authentication(url: str, results: Dict, session, debug: bool = False):
    """
    Clickjacking koruması ve temel header’lar:
      - X-Frame-Options VEYA CSP frame-ancestors
      - X-Content-Type-Options nosniff
    """
    bucket = "a07_authentication"
    items = _ensure_bucket(results, bucket)
    vulns = 0

    r = _safe_get(session, url, timeout=7, allow_redirects=True)
    if r is None or getattr(r, "status_code", 0) == 0:
        items.append({"issue": "İstek hatası (soft)", "severity": "Yok"})
        _summary(results, bucket, vulns)
        return

    hdrs = (getattr(r, "headers", {}) or {})

    xfo = hdrs.get("X-Frame-Options", "")
    csp = (hdrs.get("Content-Security-Policy", "") or "").lower()
    xcto = (hdrs.get("X-Content-Type-Options", "") or "").lower()

    frame_ok = (xfo != "") or ("frame-ancestors" in csp)
    if not frame_ok:
        items.append({"issue": "Clickjacking koruması zayıf (XFO/CSP yok)", "severity": "Low"})
        vulns += 1

    if xcto != "nosniff":
        items.append({"issue": "X-Content-Type-Options nosniff eksik", "severity": "Low"})
        vulns += 1

    _summary(results, bucket, vulns)


# ----------------- Cache Poisoning / Host Header Injection -----------------
def check_cache_poisoning_and_host_header(url: str, results: Dict[str, Any], session, debug: bool = False):
    """
    Host/Forwarded başlık manipulasyonu ile yansımaları ve cache davranışını incele.
    - Güvenli yöntem: request tarafında Cache-Control: no-cache + benzersiz query kullanılır.
    - HEAD->GET fallback ile hafif içerik alımı.
    """
    bucket = "a05_cache_poisoning"
    items = _ensure_bucket(results, bucket)
    vulns = 0

    pr = urlparse(url)
    bust = str(int(time.time())) + "-" + str(random.randint(1000, 9999))
    target = url if pr.query else f"{url}?cb={bust}"

    evil = "evil.example"
    req_base_headers = {
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "User-Agent": "WebSecure/OWASP 1.1"
    }

    variants = [
        ("host-equal-evil", {"Host": evil}, {}),
        ("x-forwarded-host", {"X-Forwarded-Host": evil}, {}),
        ("x-original-host", {"X-Original-Host": evil}, {}),
        ("forwarded", {"Forwarded": f"host={evil};proto=http"}, {}),
        ("xf-proto-http", {"X-Forwarded-Proto": "http"}, {}),
        ("xf-port-81", {"X-Forwarded-Port": "81"}, {}),
    ]

    # Baseline
    r0 = _try_get(session, target, allow_redirects=False, timeout=7, headers=req_base_headers)
    if r0 is None:
        if debug:
            items.append({"issue": "baseline hata", "severity": "Yok"})
        _summary(results, bucket, vulns)
        return

    base_cacheable, base_hints = _cacheable_headers(r0.headers or {})

    for name, hdrs, _ in variants:
        hdrs_all = {**req_base_headers, **hdrs}
        r = _try_get(session, target, allow_redirects=False, timeout=7, headers=hdrs_all)
        if r is None:
            if debug:
                items.append({"issue": "istek hatası", "variant": name, "severity": "Yok"})
            continue

        cacheable, hints = _cacheable_headers(r.headers or {})
        ref_in_loc = _reflects(r.headers.get("Location", "") or "", evil)
        body_txt = getattr(r, "text", "") or ""
        ref_in_body = _reflects(body_txt[:1200], evil)

        sev = None
        reason = None
        if r.status_code in (301, 302, 303, 307, 308) and ref_in_loc:
            sev = "High"; reason = "Host injection yansıması Location içinde."
        elif (ref_in_body and r.status_code == 200):
            sev = "Medium"; reason = "Host yansıması içerikte."
        elif cacheable and not base_cacheable:
            sev = "Low"; reason = "Cache davranışı değişti (vary/no-cc)."
        elif cacheable and ref_in_loc:
            sev = "High"; reason = "Cache’e uygun yanıt + Location yansıması (yüksek risk)."

        if sev:
            items.append({
                "issue": "Host header/cache poisoning",
                "variant": name,
                "status": r.status_code,
                "severity": sev,
                "reason": reason,
                "hints": hints,
                "headers": {k: (r.headers.get(k) or "") for k in ("Cache-Control","Vary","Age","Location","Via","X-Cache")}
            })
            vulns += 1
        elif debug:
            items.append({
                "issue": "Host header denemesi",
                "variant": name,
                "status": r.status_code,
                "severity": "Yok",
                "hints": hints
            })

    _summary(results, bucket, vulns)

# ----------------- Backup Dosya Taraması -----------------
BACKUP_GLOBS = [
    # VCS ve gizli dizinler
    "/.git/config", "/.git/index", "/.git/HEAD",
    "/.svn/entries", "/.hg/",
    # Çevre/konfig
    "/.env", "/.env.backup", "/.env.prod", "/.env.local",
    "/config.php.bak", "/config.php.save", "/config.old", "/config.yml~", "/config.json.bak",
    "/settings.py~", "/settings.py.bak",
    # Uygulama spesifik
    "/wp-config.php.bak",
    # Editör yedekleri
    "/index.php~", "/index.html~", "/index.jsp~",
    "/admin.php.swp", "/.htaccess.bak",
    # Arşivler / dump’lar
    "/backup.zip", "/site.zip", "/www.zip", "/web.zip",
    "/backup.tar", "/backup.tar.gz", "/backup.tgz",
    "/dump.sql", "/database.sql", "/db.sql", "/backup.sql",
]

def _looks_leak(path: str, status: int, headers: Dict[str,str], body_sample: str) -> Tuple[Optional[str], str]:
    p = path.lower()
    ct = (headers.get("Content-Type") or "").lower()
    cl = headers.get("Content-Length") or ""
    # .git/config içerik imzası
    if p.endswith("/.git/config") and status == 200 and ("[core]" in body_sample or "repositoryformatversion" in body_sample.lower()):
        return "High", "Git repo yapılandırma sızıntısı"
    if p.endswith("/.git/head") and status == 200 and "ref: refs/heads/" in body_sample:
        return "High", ".git/HEAD sızıntısı"
    if p.endswith(".env") and status == 200 and any(k in body_sample.lower() for k in ("db_", "aws_", "secret", "key=")):
        return "High", ".env içeriği erişilebilir"
    if any(p.endswith(ext) for ext in (".zip",".tar",".gz",".tgz")) and status == 200 and (("application/zip" in ct) or ("application/x-" in ct) or cl.isdigit() and int(cl) > 0):
        return "Medium", "Arşiv/dump erişilebilir (içerik kontrol edilmeli)"
    if any(p.endswith(ext) for ext in (".bak",".swp","~",".save",".old")) and status == 200 and len(body_sample) > 0:
        return "Low", "Editör/backup dosyası erişilebilir"
    return None, ""

def check_backup_files(url: str, results: Dict[str, Any], session, debug: bool = False):
    """
    Yedek/konfig/VCS artefaktları için hafif tarama.
    """
    bucket = "a05_backup_scan"
    items = _ensure_bucket(results, bucket)
    vulns = 0

    base = url.rstrip("/")
    for path in BACKUP_GLOBS:
        u = base + path
        r = _try_get(session, u, timeout=7, allow_redirects=False)
        if r is None:
            continue
        status = int(getattr(r, "status_code", 0))
        body = (getattr(r, "text", "") or "")[:800]
        sev, why = _looks_leak(path, status, r.headers or {}, body)
        if sev:
            items.append({"issue": "Backup/Gizli dosya", "path": path, "status": status, "severity": sev, "reason": why})
            vulns += 1
        elif debug and status < 400:
            items.append({"issue": "kontrol", "path": path, "status": status, "severity": "Yok"})

    _summary(results, bucket, vulns)

# A08:2021 — Insecure Deserialization (tek gerçek bağımsız kontrol; gerisi
# vestigial boş stub'tı ve run() tarafından hiç çağrılmıyordu → kaldırıldı.
# İlgili OWASP kategorileri zaten özel fazlarla kapsanıyor: A03 code/RCE → cmdi,
# A10 SSRF → ssrf_xxe, A10 file upload → file_upload, A05 CSRF → CSRF Scanner fazı.)
def check_insecure_deserialization(url: str, results: Dict, session, debug: bool = False):
    """
    Insecure Deserialization — Java, PHP, .NET ViewState, Python pickle, Ruby/Node payload tespiti.
    İki teknik:
    1. Yanıt body'sinde bilinen serialize marker'larını ara (passive detection).
    2. İstek parametrelerine serialize payload enjekte et, hata imzalarını kontrol et.
    """
    import re
    bucket = "a08_insecure_deserialization"
    _ensure_bucket(results, bucket)

    try:
        resp = session.get(url, timeout=10)
    except Exception:
        _summary(results, bucket, 0)
        return

    body = resp.text or ""
    hdrs = str(resp.headers)

    # Passive: detect serialized objects in responses
    passive_patterns = {
        "Java Serialized Object": r"rO0AB",         # base64-encoded Java "ac ed 00 05"
        "PHP Serialized Object":  r'O:\d+:"[^"]+?":\d+:\{',
        "PHP Serialize (string)": r's:\d+:"',
        ".NET ViewState":         r"__VIEWSTATE.*[A-Za-z0-9+/=]{40,}",
        "Python Pickle":          r"\\x80\\x04\\x95|\\x80\\x02|cos\ngetattr\n",
        "Java AMF":               r"\\x00\\x00\\x00\\x00\\x00\\x03|AMF\\d",
        "PHP phar://":            r"phar://",
    }

    for name, pattern in passive_patterns.items():
        if re.search(pattern, body + hdrs, re.IGNORECASE):
            results[bucket].append({
                "type": f"Insecure Deserialization — {name} (Passive)",
                "severity": "High",
                "url": url,
                "evidence": f"Pattern '{pattern[:40]}' found in response",
                "description": f"Response contains {name} marker. Application may deserialize attacker-controlled data.",
            })
            add_result(bucket, results[bucket][-1])

    # Active: inject canary payloads
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    parsed = urlparse(url)
    params = parse_qsl(parsed.query)
    if not params:
        _summary(results, bucket, len(results[bucket]))
        return

    # Java ysoserial-style DNS callback canary (base64 URLDNS chain header)
    java_payload_b64 = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAAhwb3J0SWQACAhwcm90b2NvbEwABGF1dGh0ABJMamF2YS9sYW5nL1N0cmluZztMAAhob3N0bmFtZXEAfgAETAAEcGF0aHEAfgAETAAFcXVlcnlxAH4ABEwACHJlZmVyZW5jZXEAfgAEeHD//////////3EAfgAGdAAEaHR0cHQADHdzLXByb2JlLmludHQAAXQAAHB4"
    error_sigs = [
        r"java\.io\.InvalidClassException",
        r"java\.lang\.ClassNotFoundException",
        r"Caused by:.*Deserializ",
        r"org\.apache\.commons",
        r"ysoserial",
        r"com\.sun\.org\.apache",
        r"Java.*deserialization",
        r"unserialize\(\)",
        r"__PHP_Incomplete_Class",
        r"Deserialization of untrusted data",
    ]

    viewstate_payloads = [
        "__VIEWSTATE=" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "__VIEWSTATE=/wEPDwUKMTY3OTEwOTc0Ng9kFgICAw8WAh4EVGV4dAUFSGVsbG94ZGQCBg8WAh4EVGV4dAUFV29ybGR4ZGRkZGQTK==",
    ]

    for param, orig_val in params[:3]:
        # Java payload
        injected = urlunparse(parsed._replace(query=urlencode(
            [(k, java_payload_b64 if k == param else v) for k, v in params]
        )))
        try:
            resp2 = session.get(injected, timeout=8)
            text2 = resp2.text or ""
            for sig in error_sigs:
                if re.search(sig, text2, re.IGNORECASE):
                    results[bucket].append({
                        "type": "Insecure Deserialization — Java (Active)",
                        "severity": "Critical",
                        "url": url, "parameter": param,
                        "payload": java_payload_b64[:40] + "...",
                        "evidence": f"Deserialization error signature: '{sig}'",
                    })
                    add_result(bucket, results[bucket][-1])
                    break
        except Exception:
            pass

        # .NET ViewState
        for vs_payload in viewstate_payloads:
            try:
                resp3 = session.post(url, data={param: vs_payload}, timeout=8)
                text3 = resp3.text or ""
                if any(re.search(s, text3, re.IGNORECASE) for s in error_sigs):
                    results[bucket].append({
                        "type": "Insecure Deserialization — .NET ViewState (Active)",
                        "severity": "High",
                        "url": url, "parameter": param,
                        "payload": vs_payload[:60],
                        "evidence": "Deserialization error in ViewState response",
                    })
                    add_result(bucket, results[bucket][-1])
                    break
            except Exception:
                pass

    _summary(results, bucket, len(results[bucket]))

# ----------------- Orchestrator -----------------
def run(url: str = "", session=None, config: Dict[str, Any] | None = None, debug: bool = False, **kwargs) -> Dict[str, Any]:
    """
    OWASP yüzeyi: pratik konfig açıkları için hafif ve gürültüsüz kontroller.
    Bu run() fonksiyonu _call_scanner_if_available ile uyumlu (url, session, debug).
    """
    if session is None:
        try:
            from websecure.core.http import hardened_session as _hs
            session = _hs({})
        except ImportError:
            import requests as _req
            session = _req.Session()

    results: Dict[str, Any] = {"target": url}
    # Çekirdek kontroller
    check_broken_access_control(url, results, session, debug=debug)
    check_sensitive_data_exposure(url, results, session, debug=debug)
    check_authentication(url, results, session, debug=debug)
    # Cache ve backup kontrolleri
    check_cache_poisoning_and_host_header(url, results, session, debug=debug)
    check_backup_files(url, results, session, debug=debug)
    # Genişletilmiş kontroller (auto-append faz)
    host_header_cache_poison(url, session, results, debug=debug)
    backup_hunt(url, session, results, debug=debug)
    # Insecure deserialization (A08:2021)
    check_insecure_deserialization(url, results, session, debug=debug)
    return results


# ============================================================================
# NUCLEI ENTEGRASYONU — İmza Tabanlı Hızlı Taramalar (OWASP sonrası)
# ============================================================================
# Amaç: OWASP sezgisel kontroller tamamlandıktan sonra Nuclei ile imza tabanlı
# tarama çalıştırmak ve bulguları rapora kovalamak.
# Konfig: config.json -> integrations.nuclei
# ----------------------------------------------------------------------------


def _load_nuclei_cfg() -> dict:
    if _find_spec("core.utils") is not None:  # core.utils varsa konfigi yükle
        from websecure.core.utils import load_config as _load_config  # type: ignore
        cfg = _load_config() or {}
    else:
        cfg = {}
    integ = (cfg.get("integrations") or {}).get("nuclei") or {}
    defaults = {
        "enabled": True,
        "bin": "nuclei",
        "docker": False,
        "image": "projectdiscovery/nuclei:latest",
        "templates": None,
        "templates_update": False,
        "tags": None,
        "severity": None,
        "rate_limit": 50,
        "concurrency": 50,
        "timeout": 10,
        "retries": 1,
        "include_headers": True,
        "include_cookies": True,
        "max_findings": 500,
        "extra_args": []
    }
    out = dict(defaults)
    out.update(integ)
    return out

def _flatten_cookie_str(session, auth_ctx: dict | None) -> str:
    parts: list[str] = []
    cj = getattr(session, "cookies", None)
    if cj and hasattr(cj, "get_dict"):
        cdict = cj.get_dict()
        if isinstance(cdict, dict):
            parts.extend([f"{k}={v}" for k, v in cdict.items()])
    if auth_ctx and isinstance(auth_ctx.get("cookies"), dict):
        for k, v in auth_ctx["cookies"].items():
            kv = f"{k}={v}"
            if all(not p.startswith(f"{k}=") for p in parts):
                parts.append(kv)
    return "; ".join(parts)

def _headers_from(session, auth_ctx: dict | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    sh = (getattr(session, "headers", {}) or {})
    for k, v in sh.items():
        if str(k).lower() == "cookie":
            continue
        line = f"{k}: {v}"
        lk = line.lower()
        if lk not in seen:
            out.append(line)
            seen.add(lk)
    if auth_ctx and isinstance(auth_ctx.get("headers"), dict):
        for k, v in auth_ctx["headers"].items():
            if str(k).lower() == "cookie":
                continue
            line = f"{k}: {v}"
            lk = line.lower()
            if lk not in seen:
                out.append(line)
                seen.add(lk)
    return out

def _nuclei_available(bin_path: str) -> bool:
    if _shutil.which(bin_path):
        return True
    # Docker kullanılacaksa ikili bulunması gerekmeyebilir
    return False

def _build_nuclei_cmd(url: str, cfg: dict, session, auth_ctx: dict | None) -> list[str]:
    base_cmd: list[str] = []
    if cfg.get("docker"):
        # Docker mod: image çekimi kullanıcıya bırakılmış; burada sadece çağırıyoruz
        base_cmd = ["docker", "run", "--rm", "-i"]
        # TLS hataları yaşamamak için host network tercih edilebilir (opsiyonel)
        # base_cmd += ["--network", "host"]
        # Session headers/cookies'i image içine doğrudan aktaramayız; CLI -H ile geçeriz
        base_cmd += [cfg.get("image") or "projectdiscovery/nuclei:latest"]
    else:
        base_cmd = [cfg.get("bin") or "nuclei"]

    # Temel argümanlar
    args = [
        "-u", url,
        "-jsonl",
        "-silent",
        "-retries", str(int(cfg.get("retries", 1))),
        "-timeout", str(int(cfg.get("timeout", 10))),
        "-rl", str(int(cfg.get("rate_limit", 50))),
        "-c", str(int(cfg.get("concurrency", 50))),
    ]

    # Templates
    if cfg.get("templates"):
        args += ["-t", str(cfg["templates"])]
    if bool(cfg.get("templates_update", False)):
        args += ["-update-templates"]

    # Filtreler
    if cfg.get("tags"):
        args += ["-tags", str(cfg["tags"])]
    if cfg.get("severity"):
        args += ["-severity", str(cfg["severity"])]

    # Headers / Cookies
    if bool(cfg.get("include_headers", True)):
        for h in _headers_from(session, auth_ctx):
            args += ["-H", h]
    if bool(cfg.get("include_cookies", True)):
        ck = _flatten_cookie_str(session, auth_ctx)
        if ck:
            args += ["-H", "Cookie: " + ck]

    # Ekstra argümanlar
    for ea in (cfg.get("extra_args") or []):
        args.append(str(ea))

    return base_cmd + args

def run_nuclei_signatures(
    url: str,
    results: Dict[str, Any],
    session,
    config: Dict[str, Any] | None = None,
    *,
    debug: bool = False,
    auth_ctx: Dict[str, Any] | None = None
) -> int:
    """
    Nuclei'yi URL üzerinde çalıştırır, JSON satırlarını parse eder, 'nuclei' kovasına ekler.
    Dönüş: bulunan finding sayısı.
    """
    bucket = "nuclei"
    results.setdefault(bucket, [])

    nucfg = _load_nuclei_cfg()
    if not nucfg.get("enabled", True):
        if debug:
            results[bucket].append({"status": "devre dışı", "severity": "Yok"})
        results["nuclei_summary"] = {"findings": 0}
        return 0

    # İkili mevcut mu (docker değilse)?
    if not nucfg.get("docker") and not _nuclei_available(nucfg.get("bin", "nuclei")):
        if debug:
            results[bucket].append({"status": "nuclei bulunamadı", "severity": "Yok", "bin": nucfg.get("bin", "nuclei")})
        results["nuclei_summary"] = {"findings": 0}
        return 0

    cmd = _build_nuclei_cmd(url, nucfg, session, auth_ctx)
    if debug:
        results[bucket].append({"cmd": " ".join([_shlex.quote(c) for c in cmd])})


    proc = _subprocess.Popen(
        cmd,
        stdout=_subprocess.PIPE,
        stderr=_subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    findings = 0
    severities_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    max_lines = int(nucfg.get("max_findings", 500))

    stdout_stream = proc.stdout if proc.stdout is not None else []
    for i, line in enumerate(stdout_stream):
        if i >= max_lines:
            break
        line = (line or "").strip()
        if not line or line[0] not in "{[":  # JSON değilse atla (try'siz filtre)
            continue

        try:
            obj = _json.loads(line)
        except _json.JSONDecodeError as exc:
            _logger.debug("[OWASPScanner] Nuclei output JSON parse error: %s", exc)
            continue
        if not isinstance(obj, dict):
            continue

        findings += 1
        sev = str(obj.get("severity", "unknown")).lower()
        if sev not in severities_count:
            sev = "unknown"
        severities_count[sev] += 1

        entry = {
            "template_id": obj.get("template-id") or obj.get("templateID") or obj.get("id"),
            "name": obj.get("info", {}).get("name") if isinstance(obj.get("info"), dict) else obj.get("name"),
            "severity": sev.capitalize(),
            "matcher_name": obj.get("matcher-name") or obj.get("matcherName"),
            "type": obj.get("type") or obj.get("info", {}).get("type"),
            "extracted_results": obj.get("extracted-results") or obj.get("extractedResults") or [],
            "matched_at": obj.get("matched-at") or obj.get("matchedAt") or obj.get("url") or url,
            "curl_command": obj.get("curl-command") or obj.get("curlCommand"),
            "raw": obj,
        }
        results[bucket].append(entry)

    # stderr yakala ve süreci sonlandır
    stderr = (proc.stderr.read().strip() if proc.stderr is not None else "")
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            # terminate sonrası bekleyememe durumunda işlem üst katmana zaten görünür
            pass

    if debug and stderr:
        results[bucket].append({"stderr": stderr[:4000]})

    results["nuclei_summary"] = {"findings": findings, "by_severity": severities_count}
    return findings

def run_owasp_and_nuclei(
    url: str,
    results: Dict[str, Any],
    session,
    *,
    open_ports=None,
    config: Dict[str, Any] | None = None,
    debug: bool = False,
    auth_ctx: Dict[str, Any] | None = None,
    run_nuclei: bool = True,
) -> Dict[str, Any]:
    """
    Kolaylaştırıcı: önce mevcut OWASP kontrollerini çalıştırır, ardından Nuclei’yi çağırır.
    main.py bu fonksiyonu çağırırsa istenen “OWASP sonrası Nuclei” entegrasyonu gerçekleşir.
    (Susturma yok—hata olursa yükselir ve üst seviyede görünür.)

    ``run_nuclei=False`` verildiğinde nuclei ATLANır — bu, dedike ``nuclei`` fazı
    zaten nuclei'yi koşturuyorsa çağrılır (Madde 3: nuclei'nin aynı taramada
    birden çok kez koşmasını engeller). Varsayılan True (geriye dönük uyum).
    """
    check_broken_access_control(url, results, session, debug=debug)
    check_sensitive_data_exposure(url, results, session, debug=debug)
    check_authentication(url, results, session, debug=debug)
    check_cache_poisoning_and_host_header(url, results, session, debug=debug)
    check_backup_files(url, results, session, debug=debug)
    # Genişletilmiş kontroller
    host_header_cache_poison(url, session, results, debug=debug)
    backup_hunt(url, session, results, debug=debug)

    # OWASP sonrası nuclei — yalnız dedike nuclei fazı koşmuyorsa.
    if run_nuclei:
        run_nuclei_signatures(url, results, session, config=config, debug=debug, auth_ctx=auth_ctx)
    return results


# EKLEMELER (AUTO-APPEND) ===


def _hx_safe_req(session, method: str, url: str, *, timeout: int = 7, allow_redirects: bool = False, headers: Optional[Dict[str,str]] = None):
    try:
        meth = getattr(session, method.lower())
        verify = getattr(session, "verify", True)
        return meth(url, timeout=timeout, allow_redirects=allow_redirects, verify=verify, headers=headers or {})
    except Exception as _e:
        class _Dummy:
            def __init__(self, url, err):
                self.status_code = 0
                self.headers: Dict[str, str] = {}
                self.text = ""
                self.url = url
                self.error = str(err)
        return _Dummy(url, _e)

def host_header_cache_poison(
    url: str,
    session,
    results: Dict[str, Any],
    *,
    evil_host: str = "evil.example",
    debug: bool = False
) -> Dict[str, Any]:
    pr = urlparse(url)
    bust = str(int(time.time())) + "-" + str(random.randint(1000, 9999))
    target = url if pr.query else (url + ("&" if "?" in url else "?") + f"cb={bust}")
    base_headers = {"Cache-Control": "no-cache", "Pragma": "no-cache", "User-Agent": "OWASP-Ext 1.0"}
    variants = [
        ("Host", {"Host": evil_host}),
        ("X-Forwarded-Host", {"X-Forwarded-Host": evil_host}),
        ("X-Original-Host", {"X-Original-Host": evil_host}),
        ("Forwarded", {"Forwarded": f"host={evil_host};proto=http"}),
        ("X-Forwarded-Proto", {"X-Forwarded-Proto": "http"}),
        ("X-Forwarded-Port", {"X-Forwarded-Port": "81"}),
    ]
    out: List[Dict[str, Any]] = []

    r0 = _hx_safe_req(session, "HEAD", target, allow_redirects=False, headers=base_headers)

    def _cacheable(h: Dict[str, str]) -> Tuple[bool, List[str]]:
        hints: List[str] = []
        cc = (h.get("Cache-Control") or "").lower()
        vary = (h.get("Vary") or "").lower()
        age = h.get("Age")
        if "max-age" in cc or "s-maxage" in cc or "public" in cc:
            hints.append("cacheable-cc")
        if age and str(age).isdigit() and int(age) > 0:
            hints.append("age>0")
        if vary and "host" not in vary:
            hints.append("vary-miss-host")
        return bool(hints), hints

    base_cacheable, base_hints = _cacheable(getattr(r0, "headers", {}) or {})

    for name, hdr in variants:
        r = _hx_safe_req(session, "HEAD", target, allow_redirects=False, headers={**base_headers, **hdr})
        cacheable, hints = _cacheable(r.headers or {})
        ref_loc = evil_host in ((r.headers.get("Location") or "") + (r.headers.get("Content-Location") or ""))
        body = getattr(r, "text", "") or ""
        ref_body = evil_host in body[:1000].lower()

        sev = None
        why = None
        if r.status_code in (301, 302, 303, 307, 308) and ref_loc:
            sev, why = "High", "Location yansıması"
        elif ref_body and r.status_code == 200:
            sev, why = "Medium", "Body yansıması"
        elif cacheable and not base_cacheable:
            sev, why = "Low", "Cache davranışı değişti"

        if sev:
            out.append({
                "variant": name,
                "status": r.status_code,
                "severity": sev,
                "reason": why,
                "headers": {k: (r.headers.get(k) or "") for k in ("Cache-Control", "Vary", "Age", "Location", "Via", "X-Cache")}
            })
        elif debug:
            out.append({"variant": name, "status": r.status_code, "severity": "Yok", "hints": hints})

    results.setdefault("a05_cache_poisoning_ext", out)
    return {"host_cache": out}


def backup_hunt(url: str, session, results: Dict[str, Any], debug: bool = False) -> Dict[str, Any]:
    base = url.rstrip("/")
    wordlist = [
        "/.git/config","/.git/HEAD","/.svn/entries","/.hg/",
        "/.env",".env.backup",".env.prod",".env.local",
        "/config.php.bak","/config.yml~","/config.json.bak",
        "/settings.py~","/settings.py.bak","/wp-config.php.bak",
        "/index.php~","/index.html~","/index.jsp~","/admin.php.swp","/.htaccess.bak",
        "/backup.zip","/backup.tar","/backup.tgz","/backup.tar.gz","/site.zip","/dump.sql","/database.sql","/db.sql","/backup.sql"
    ]
    findings: List[Dict[str, Any]] = []
    for p in wordlist:
        target = base + (p if p.startswith("/") else "/" + p)
        r = _hx_safe_req(session, "HEAD", target, allow_redirects=False, headers={"User-Agent": "OWASP-Ext 1.0"})
        code = int(getattr(r, "status_code", 0))
        if code == 200:
            ct = (r.headers.get("Content-Type") or "").lower()
            cl = r.headers.get("Content-Length") or ""
            sev: Optional[str]
            why: str
            if p.endswith("/.git/HEAD"):
                sev, why = "High", ".git/HEAD"
            elif p.endswith("/.git/config"):
                sev, why = "High", ".git/config"
            elif p.endswith(".env"):
                sev, why = "High", ".env"
            elif any(p.endswith(ext) for ext in (".zip", ".tar", ".gz", ".tgz")) and (("application/zip" in ct) or ("application/x-" in ct) or (cl.isdigit() and int(cl) > 0)):
                sev, why = "Medium", "Arşiv"
            else:
                sev, why = "Low", "Muhtemel gizli artefakt"
            findings.append({"path": p, "status": code, "severity": sev, "why": why, "headers": {"Content-Type": ct, "Content-Length": cl}})
        elif debug and code < 400:
            findings.append({"path": p, "status": code, "severity": "Yok"})
    results.setdefault("a05_backup_scan_ext", findings)
    return {"backup": findings}

def payload_sample(finding: dict) -> str:
    return str((finding or {}).get('payload') or (finding or {}).get('poc') or '')
def repro_steps(finding: dict) -> dict:
    url = str((finding or {}).get('url') or '')
    method = str((finding or {}).get('method') or 'GET')
    body = (finding or {}).get('payload') or ''
    curl = ['curl','-i','-X', method, url]
    if isinstance(body, dict) and body:
        import json as _j
        curl += ['-H','Content-Type: application/json','--data-binary', _j.dumps(body)]
    elif isinstance(body, str) and body:
        curl += ['--data-raw', body]
    return {'curl': ' '.join(curl)}
def verify(session, finding: dict, cfg: dict | None = None) -> dict:
    url = str((finding or {}).get('url') or '')
    method = str((finding or {}).get('method') or 'GET').upper()
    if not url:
        return {'verified': False, 'reason': 'no-url'}
    if method == 'POST':
        resp = session.post(url, data=(finding or {}).get('payload'), timeout=(cfg or {}).get('timeout', 12))
    else:
        resp = session.get(url, timeout=(cfg or {}).get('timeout', 12))
    code = int(getattr(resp, 'status_code', 0) or 0)
    ok = (200 <= code < 400)
    add_result('verification', {
        'module': __name__.split('.')[-1],
        'url': url, 'method': method, 'status': code,
        'verified': ok,
        'payload_sample': payload_sample(finding),
        'repro': repro_steps(finding)
    })
    return {'verified': ok, 'status': code}
