from __future__ import annotations
from websecure.core.http import hardened_session
import logging
import re
from abc import ABC, abstractmethod
from importlib.util import find_spec
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Pattern
from urllib.parse import urljoin, urlparse

import requests

__all__ = [
    "smart_login",
    "login",
    "refresh_csrf",
    "ensure_session",
    "is_session_alive",
    "install_auth_retry_adapter",
    "run_auth_flow",
    "build_role_sessions",
    "attach_auth_meta",
    "_webdriver_login",
    "_sync_driver_cookies_to_session",
    "_sync_session_cookies_to_driver",
    "extract_csrf",
]

# -----------------------------------------------------------------------------
# Opsiyonel Selenium - varlık kontrolü
# -----------------------------------------------------------------------------

def _mod_available(mod: str) -> bool:
    return find_spec(mod) is not None

def _import_attr(mod: str, name: str) -> Optional[Any]:
    # MAINLINK v1: dual import (core.* → fallback to top-level)
    candidates = [mod]
    if mod.startswith('core.'):
        candidates.append(mod.split('.', 1)[1])
    for m in candidates:
        if _mod_available(m):
            module = __import__(m, fromlist=[name])
            return getattr(module, name, None) if hasattr(module, name) else None
    return None

By = _import_attr("selenium.webdriver.common.by", "By")
WebDriverWait = _import_attr("selenium.webdriver.support.ui", "WebDriverWait")
EC = _import_attr("selenium.webdriver.support.expected_conditions", "presence_of_element_located")
# Not: EC içinden fonksiyonlar çok; burada presence_of_element_located’a erişim teyidi yeter.
_has_selenium = all(v is not None for v in (By, WebDriverWait, EC))

# -----------------------------------------------------------------------------
# İç import yardımcıları (opsiyonel modüller)
# -----------------------------------------------------------------------------

def _import_optional(module: str, names: Iterable[str]) -> List[Optional[Any]]:
    # MAINLINK v1: dual import (core.* → fallback to top-level) and merge hits
    candidates = [module]
    if module.startswith('core.'):
        candidates.append(module.split('.', 1)[1])
    out: List[Optional[Any]] = [None for _ in names]
    for modname in candidates:
        if not _mod_available(modname):
            continue
        mod = __import__(modname, fromlist=list(names))
        for i, n in enumerate(names):
            if out[i] is None and hasattr(mod, n):
                out[i] = getattr(mod, n)
    return out

read_captcha_config, solve_image_captcha_png_bytes, solve_recaptcha_v2_token = _import_optional(
    "websecure.core.analysis", ["read_captcha_config", "solve_image_captcha_png_bytes", "solve_recaptcha_v2_token"]
)
read_2fa_config, get_otp_provider = _import_optional(
    "websecure.core.auth", ["read_2fa_config", "create_twofactor_provider"]
)

# -----------------------------------------------------------------------------
# Yardımcılar
# -----------------------------------------------------------------------------

def _is_http_url(u: str) -> bool:
    if not u:
        return False
    p = urlparse(u)
    return p.scheme in ("http", "https") and bool(p.netloc)

def _infer_login_fields(html: str) -> tuple[Optional[str], Optional[str]]:
    if not html:
        return (None, None)
    m = re.search(r'<input[^>]+type=["\']password["\'][^>]*name=["\']([^"\']+)["\']', html, re.I)
    pwd_name = m.group(1) if m else None
    u = re.search(r'<input[^>]+type=["\']email["\'][^>]*name=["\']([^"\']+)["\']', html, re.I)
    if not u:
        u = re.search(r'<input[^>]+type=["\']text["\'][^>]*name=["\']([^"\']+)["\']', html, re.I)
    user_name = u.group(1) if u else None
    for pat in ("user", "login", "email"):
        u2 = re.search(rf'<input[^>]+name=["\']([^"\']*{pat}[^"\']*)["\']', html, re.I)
        if u2:
            cand = u2.group(1)
            if not user_name or len(cand) <= len(user_name):
                user_name = cand
    return (user_name, pwd_name)

# -----------------------------------------------------------------------------
# Başarı göstergeleri
# -----------------------------------------------------------------------------

_DEFAULT_SUCCESS_HINTS: Tuple[Pattern[str], ...] = (
    re.compile(r"(?i)\blogout\b"),
    re.compile(r"(?i)\b(?:my\s*account|profile|dashboard|hesabım|profil)\b"),
)

def _safe_compile_marker(s: str) -> Optional[Pattern[str]]:
    """İleri düzey regex içerenleri düz metin olarak işler; çökme yok, sessizlik yok."""
    if not isinstance(s, str) or not s.strip():
        return None
    # Basit: sadece harf/rakam/boşluk gibi durumlarda doğrudan escape ile derle
    simple = re.fullmatch(r"[A-Za-z0-9_\-\s\.:/]+", s) is not None
    return re.compile(re.escape(s), re.I) if not (s.startswith("(?") or not simple) else None

def _compile_success_hints(cfg: Optional[Dict[str, Any]]) -> Tuple[Pattern[str], ...]:
    hints: List[Pattern[str]] = list(_DEFAULT_SUCCESS_HINTS)
    markers = (((cfg or {}).get("auth") or {}).get("success_markers") or [])
    for m in markers:
        rx = _safe_compile_marker(m)
        if rx:
            hints.append(rx)
    # uniq
    uniq: List[Pattern[str]] = []
    seen = set()
    for rx in hints:
        if rx.pattern in seen:
            continue
        uniq.append(rx)
        seen.add(rx.pattern)
    return tuple(uniq)

def _looks_authenticated(text: str, resp: Optional[requests.Response] = None,
                         hints: Optional[Tuple[Pattern[str], ...]] = None) -> bool:
    src = text or ""
    for rx in (hints or _DEFAULT_SUCCESS_HINTS):
        if rx.search(src):
            return True
    if resp is not None:
        sc = resp.headers.get("Set-Cookie", "")
        if any(k for k in sc.split(",") if ("session" in k.lower() or "auth" in k.lower())):
            return True
    return False

# -----------------------------------------------------------------------------
# Cookie senkronizasyonu
# -----------------------------------------------------------------------------

def _sync_driver_cookies_to_session(driver, session: requests.Session, base_url: Optional[str] = None) -> None:
    if not driver:
        return
    cookies = driver.get_cookies() if hasattr(driver, "get_cookies") else []
    for c in cookies or []:
        name = c.get("name"); value = c.get("value")
        if not name:
            continue
        # Güvenli: domain/path set etmeden basit ekleme (driver alanları sorun çıkarabiliyor)
        session.cookies.set(str(name), str(value))

def _sync_session_cookies_to_driver(session: requests.Session, driver, base_url: Optional[str] = None) -> None:
    if not driver:
        return
    if base_url and hasattr(driver, "get"):
        driver.get(base_url)
    for k, v in (session.cookies.get_dict() or {}).items():
        if hasattr(driver, "add_cookie"):
            driver.add_cookie({"name": str(k), "value": str(v)})

# -----------------------------------------------------------------------------
# CSRF çıkarımı (DOM-first; regex fallback)
# -----------------------------------------------------------------------------

_CSRF_NAMES = ("csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken", "xsrf", "_xsrf", "authenticity_token")

def _extract_csrf_dom(html_text: str) -> Optional[str]:
    # selectolax
    if _mod_available("selectolax.parser"):
        HTMLParser = _import_attr("selectolax.parser", "HTMLParser")
        tree = HTMLParser(html_text or "")
        if tree:
            for n in _CSRF_NAMES:
                el = tree.css_first(f'input[name="{n}"], input[id="{n}"]')
                if el:
                    val = el.attributes.get("value")
                    if val:
                        return val
    # lxml
    if _mod_available("lxml.html") or _mod_available("lxml"):
        lxml_html = _import_attr("lxml", "html") or _import_attr("lxml.html", "fromstring")
        # lxml.html.fromstring erişimi:
        if hasattr(lxml_html, "fromstring"):
            root = lxml_html.fromstring(html_text or "")
            for n in _CSRF_NAMES:
                if hasattr(root, "cssselect"):
                    els = root.cssselect(f'input[name="{n}"], input#{n}')
                    if els:
                        val = els[0].get("value")
                        if val:
                            return val
    return None

def _extract_csrf_regex(html_text: str) -> Optional[str]:
    m = re.search(
        r'(?is)(?:name|id)\s*=\s*["\'](?:csrf|_csrf|csrf_token|csrfmiddlewaretoken|xsrf|_xsrf|authenticity_token)["\']\s+value\s*=\s*["\']([^"\']+)["\']',
        html_text or "",
    )
    return m.group(1) if m else None

def extract_csrf(html_text: str) -> Optional[str]:
    ext, = _import_optional("websecure.core.analysis", ["extract_csrf"])
    if callable(ext):
        v = ext(html_text)  # type: ignore[misc]
        if v:
            return v
    return _extract_csrf_dom(html_text) or _extract_csrf_regex(html_text)

# -----------------------------------------------------------------------------
# Selenium yardımcıları
# -----------------------------------------------------------------------------

def _find_first(driver, selectors: List[Tuple[Any, str]], timeout: int = 8):
    if not (driver and _has_selenium):
        return None
    # İstisna atmayan yol: find_elements ile ilk eşleşeni döndür
    for by, sel in selectors:
        if hasattr(driver, "find_elements"):
            found = driver.find_elements(by, sel)  # type: ignore[arg-type]
            if found:
                return found[0]
    return None

def _click_safe(el) -> bool:
    if el is None:
        return False
    if hasattr(el, "click"):
        el.click()
        return True
    if hasattr(el, "submit"):
        el.submit()
        return True
    return False

def _type_safe(el, text: str) -> bool:
    if el is None:
        return False
    if hasattr(el, "clear"):
        el.clear()
    if hasattr(el, "send_keys"):
        el.send_keys(text)
        return True
    return False

def _run_flow_dsl(driver, config: Dict[str, Any], debug: bool = False) -> None:
    if not (driver and _has_selenium):
        return
    settings = (config or {}).get("settings", {})
    flow_steps = (settings or {}).get("flow_dsl", []) or []
    for step in flow_steps:
        if "navigate" in step and hasattr(driver, "get"):
            url = step["navigate"]
            base = getattr(driver, "current_url", "")
            driver.get(url if _is_http_url(str(url)) else urljoin(str(base), str(url)))
            if debug:
                logging.debug(f"[flow_dsl] Navigate → {url}")
        elif "type" in step:
            selector = step["type"]["selector"]
            el = _find_first(driver, [(By.CSS_SELECTOR, selector)], timeout=6) if _has_selenium else None  # type: ignore[arg-type]
            if _type_safe(el, step["type"]["value"]) and debug:
                logging.debug(f"[flow_dsl] Type → {selector}")
        elif "click" in step:
            selector = step["click"]["selector"]
            el = _find_first(driver, [(By.CSS_SELECTOR, selector)], timeout=6) if _has_selenium else None  # type: ignore[arg-type]
            if _click_safe(el) and debug:
                logging.debug(f"[flow_dsl] Click → {selector}")
        elif "wait" in step:
            # İstisnasız bekleme: element görünüp görünmediğine hızlı bak ve geç
            selector = step["wait"]["selector"]
            _ = _find_first(driver, [(By.CSS_SELECTOR, selector)], timeout=int(step["wait"].get("timeout", 8))) if _has_selenium else None  # type: ignore[arg-type]
            if debug:
                logging.debug(f"[flow_dsl] Wait-ish → {selector}")

# -----------------------------------------------------------------------------
# WebDriver ile sezgisel form login
# -----------------------------------------------------------------------------

def _merge_selectors(defaults: List[str], extra: Iterable[str]) -> List[str]:
    return list(dict.fromkeys([*defaults, *list(extra or [])]))

def _webdriver_login(
    driver,
    base_url: str,
    username: str,
    password: str,
    login_url: Optional[str] = None,
    debug: bool = False,
    selectors: Optional[Dict[str, Iterable[str]]] = None,
) -> bool:
    if not (driver and _has_selenium):
        return False

    target = login_url or urljoin((base_url or "").rstrip("/") + "/", "login")
    if not _is_http_url(target):
        return False
    if hasattr(driver, "get"):
        driver.get(target)

    user_sel = _merge_selectors(
        ["input[name='username']", "input[name='email']", "input#username", "input#email",
         "input[type='email']", "input[type='text']"],
        (selectors or {}).get("username", []))
    pass_sel = _merge_selectors(
        ["input[name='password']", "input#password", "input[type='password']"],
        (selectors or {}).get("password", []))
    submit_sel = _merge_selectors(
        ["button[type='submit']", "input[type='submit']", "button[class*='login']"],
        (selectors or {}).get("submit", []))

    def _q(sel_list: List[str]):
        if not _has_selenium:
            return None
        for s in sel_list:
            if hasattr(driver, "find_elements"):
                els = driver.find_elements(By.CSS_SELECTOR, s)  # type: ignore[arg-type]
                if els:
                    return els[0]
        return None

    uel = _q(user_sel)
    pel = _q(pass_sel)
    sel = _q(submit_sel)
    if not (uel and pel and sel):
        return False

    _ = _type_safe(uel, username)
    _ = _type_safe(pel, password)
    _ = _click_safe(sel)

    page = getattr(driver, "page_source", "") or ""
    return _looks_authenticated(page)

# -----------------------------------------------------------------------------
# Requests tabanlı login / session yardımcıları
# -----------------------------------------------------------------------------

def extract_csrf_legacy(html: str, *, field_names: Iterable[str] = ("csrf", "_csrf", "csrf_token")) -> Optional[str]:
    for name in field_names:
        m = re.search(rf'name=["\']{re.escape(name)}["\'][^>]*value=["\']([^"\']+)["\']', html, re.I)
        if m:
            return m.group(1)
    return None

def _apply_bearer(session: requests.Session, token: Optional[str]) -> None:
    if not token:
        return
    session.headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"

def login(session: requests.Session, config: Dict[str, Any]) -> Dict[str, Any]:
    auth = (config.get("auth") or {})
    login_url = (auth.get("login_url") or "").strip()
    user = (auth.get("username") or "").strip()
    pwd = (auth.get("password") or "").strip()
    if not (_is_http_url(login_url) and user and pwd):
        raise ValueError("auth.login_url/username/password zorunlu ve geçerli bir URL gerekli.")

    csrf = None
    csrf_get = (auth.get("csrf_get") or "").strip()
    if _is_http_url(csrf_get):
        r0 = session.get(csrf_get, timeout=20)
        csrf = extract_csrf(r0.text) or extract_csrf_legacy(r0.text)

    data = {auth.get("username_field", "username"): user,
            auth.get("password_field", "password"): pwd}
    if csrf:
        for k in _CSRF_NAMES:
            data.setdefault(k, csrf)

    method = (auth.get("method") or "POST").upper()
    if method == "GET":
        r = session.get(login_url, params=data, timeout=20, allow_redirects=True)
    else:
        r = session.post(login_url, data=data, timeout=20, allow_redirects=True)

    if r.status_code >= 400:
        raise RuntimeError(f"Giriş başarısız: {r.status_code}")

    token: Optional[str] = None
    auth_hdr = r.headers.get("Authorization")
    if auth_hdr:
        token = auth_hdr

    if not token:
        ctype = r.headers.get("Content-Type", "")
        if "application/json" in ctype.lower():
            j = r.json()
            for k in ("token", "access_token", "jwt", "id_token"):
                if isinstance(j.get(k), str) and j[k]:
                    token = j[k]
                    break

    if not token:
        m = re.search(r"eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+", r.text or "")
        if m:
            token = m.group(0)

    _apply_bearer(session, token)

    if not getattr(session, "base_url", None):
        session.base_url = login_url.rsplit("/", 1)[0]  # type: ignore[attr-defined]
    if not getattr(session, "check_url", None):
        session.check_url = auth.get("auth_check_url") or getattr(session, "base_url", None)  # type: ignore[attr-defined]

    return {"user": user, "token": (session.headers.get("Authorization") if token else None)}

def refresh_csrf(session: requests.Session) -> Optional[str]:
    base = getattr(session, "base_url", None)
    if not _is_http_url(str(base or "")):
        return None
    r = session.get(str(base), timeout=10, allow_redirects=True)
    token = extract_csrf(r.text) or extract_csrf_legacy(r.text)
    if token:
        session.headers["X-CSRF-Token"] = token
    return token

def ensure_session(session: requests.Session, config: Optional[Dict[str, Any]] = None) -> bool:
    cfg = (config or {}).get("auth", {}) if config is not None else {}
    check_url = cfg.get("auth_check_url") or getattr(session, "check_url", None) or "/profile"
    if not _is_http_url(str(check_url)):
        return False
    r = session.get(str(check_url), timeout=10, allow_redirects=False)
    if not (200 <= r.status_code < 300):
        return False
    marker = cfg.get("valid_marker")
    return (marker in (r.text or "")) if marker else True

def is_session_alive(session: requests.Session) -> bool:
    return ensure_session(session, None)

# -----------------------------------------------------------------------------
# Token yenileme ve 401 retry
# -----------------------------------------------------------------------------

def _refresh_token(session: requests.Session, cfg: Dict[str, Any]) -> bool:
    auth = (cfg.get("auth") or {})
    refresh = (auth.get("refresh") or {})
    url = (refresh.get("url") or "").strip()
    if not _is_http_url(url):
        return False
    method = (refresh.get("method") or "POST").upper()
    data = refresh.get("data") or {}
    headers = refresh.get("headers") or {}

    r = session.request(
        method, url,
        data=None if method == "GET" else data,
        params=data if method == "GET" else None,
        headers=headers, timeout=20,
    )
    if r.status_code // 100 != 2:
        return False

    ctype = r.headers.get("Content-Type", "")
    j = r.json() if "application/json" in ctype.lower() else {}
    token = j.get(refresh.get("token_field") or "access_token")
    if token:
        _apply_bearer(session, token)
    return bool(token)

def install_auth_retry_adapter(session: requests.Session, cfg: Dict[str, Any]) -> None:
    orig = getattr(session, "request", None)
    if not callable(orig) or getattr(session, "_auth_retry_installed", False):
        return

    def wrapped(method, url, **kwargs):
        resp = orig(method, url, **kwargs)
        if resp is not None and getattr(resp, "status_code", 0) == 401 and _refresh_token(session, cfg):
            resp = orig(method, url, **kwargs)
        return resp

    session.request = wrapped  # type: ignore[assignment]
    session._auth_retry_installed = True  # type: ignore[attr-defined]

# -----------------------------------------------------------------------------
# Strategy Pattern
# -----------------------------------------------------------------------------

class LoginStrategy(ABC):
    @abstractmethod
    def run(self) -> bool: ...

class RequestsLoginStrategy(LoginStrategy):
    def __init__(self, session: requests.Session, cfg: Dict[str, Any], base_url: Optional[str], hints: Tuple[Pattern[str], ...],
                 event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.session = session
        self.cfg = cfg
        self.base_url = base_url
        self.hints = hints
        self.event_cb = event_cb

    def _emit(self, evt: str, data: Dict[str, Any]) -> None:
        if self.event_cb:
            self.event_cb(evt, data)

    def run(self) -> bool:
        auth = (self.cfg.get("auth") or {})
        login_cfg = (auth.get("login") or {})
        base = self.base_url or (self.cfg.get("base_url") or self.cfg.get("target") or "")
        if not login_cfg.get("url"):
            return False

        def _abs(u: str) -> str:
            return u if _is_http_url(u) else urljoin(str(base).rstrip("/") + "/", (u or "").lstrip("/"))

        ln = _abs(str(login_cfg["url"]))
        if not _is_http_url(ln):
            return False

        r0 = self.session.get(ln, timeout=int(self.cfg.get("timeout", 12)), allow_redirects=True, verify=getattr(self.session, "verify", True))
        token = extract_csrf(getattr(r0, "text", "") or "") or extract_csrf_legacy(getattr(r0, "text", "") or "")
        data = dict(login_cfg.get("data") or {})
        if token and not any(k in data for k in _CSRF_NAMES):
            data["_csrf"] = token
        method = (login_cfg.get("method") or "POST").upper()
        hdrs = dict(login_cfg.get("headers") or {})
        r1 = self.session.request(
            method, ln,
            data=None if method == "GET" else data,
            params=data if method == "GET" else None,
            headers=hdrs, timeout=int(self.cfg.get("timeout", 12)), allow_redirects=True, verify=getattr(self.session, "verify", True)
        )
        ok = _looks_authenticated(r1.text, r1, self.hints)
        self._emit("auth.requests_login", {"ok": bool(ok), "status": getattr(r1, "status_code", None)})
        return bool(ok)

class WebDriverLoginStrategy(LoginStrategy):
    def __init__(self, session: requests.Session, cfg: Dict[str, Any], driver, base_url: Optional[str], hints: Tuple[Pattern[str], ...],
                 event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.session = session
        self.cfg = cfg
        self.driver = driver
        self.base_url = base_url
        self.hints = hints
        self.event_cb = event_cb

    def _emit(self, evt: str, data: Dict[str, Any]) -> None:
        if self.event_cb:
            self.event_cb(evt, data)

    def run(self) -> bool:
        if not self.driver:
            return False
        auth = (self.cfg.get("auth") or {})
        login_cfg = (auth.get("login") or {})
        profs = ((auth.get("profiles") or []) if isinstance(auth.get("profiles"), list) else [])
        user = profs[0].get("username") if profs else None
        password = profs[0].get("password") if profs else None
        selectors = (profs[0].get("selectors") if profs and isinstance(profs[0].get("selectors"), dict) else None)
        base = self.base_url or (self.cfg.get("base_url") or self.cfg.get("target") or "")
        if not (user and password and base):
            return False

        target_login_url = None
        if login_cfg.get("url"):
            u = str(login_cfg["url"])
            target_login_url = u if _is_http_url(u) else urljoin(str(base).rstrip("/") + "/", u.lstrip("/"))

        ok = _webdriver_login(self.driver, str(base), str(user), str(password), login_url=target_login_url, debug=bool(self.cfg.get("debug")), selectors=selectors)
        if ok:
            _sync_driver_cookies_to_session(self.driver, self.session, str(base))
            self._emit("auth.webdriver_login", {"ok": True})
            return True
        self._emit("auth.webdriver_login", {"ok": False})
        return False

# -----------------------------------------------------------------------------
# Akış: header/cookie/bearer uygula + strategylere denetim ver
# -----------------------------------------------------------------------------

def run_auth_flow(
    session: requests.Session,
    cfg: Dict[str, Any],
    driver=None,
    base_url: Optional[str] = None,
    debug: bool = False,
    event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> bool:
    def emit(evt: str, data: Dict[str, Any]) -> None:
        if event_cb:
            event_cb(evt, data)

    authenticated = False
    auth = (cfg.get("auth") or {})

    bearer = auth.get("bearer") or auth.get("bearer_token") or auth.get("token")
    if bearer:
        _apply_bearer(session, bearer)
        authenticated = True
        emit("auth.apply_bearer", {"has_bearer": True})

    if auth.get("api_key_header") and auth.get("api_key"):
        session.headers[str(auth["api_key_header"])] = str(auth["api_key"])
        authenticated = True
        emit("auth.apply_api_key", {"header": str(auth["api_key_header"])})

    if auth.get("headers"):
        for k, v in (auth.get("headers") or {}).items():
            session.headers[str(k)] = str(v)
        authenticated = True
        emit("auth.apply_headers", {"count": len(auth.get("headers") or {})})

    if auth.get("cookie"):
        for k, v in (auth.get("cookie") or {}).items():
            session.cookies.set(str(k), str(v))
        authenticated = True
        emit("auth.apply_cookies", {"count": len(auth.get("cookie") or {})})

    hints = _compile_success_hints(cfg)

    reqs = RequestsLoginStrategy(session, cfg, base_url, hints, event_cb=event_cb)
    if reqs.run():
        authenticated = True

    wds = WebDriverLoginStrategy(session, cfg, driver, base_url, hints, event_cb=event_cb)
    if not authenticated and wds.run():
        authenticated = True

    add_result = _import_attr("core.reporting", "add_result")
    if callable(add_result):
        add_result("meta", {"stage": "auth", "authenticated": bool(authenticated)})

        emit("auth.final", {"authenticated": bool(authenticated)})
        return bool(authenticated)

# -----------------------------------------------------------------------------
# Rol oturumları (YENİ ŞEMA): cfg.auth.roles
# -----------------------------------------------------------------------------

SUCCESS_CODES = {200, 201, 202, 204, 302, 303}

def _login_with_form(session: requests.Session, login_cfg: Dict[str, Any],
                     username: str, password: str, debug: bool = False) -> Dict[str, Any]:
    url = (login_cfg.get("url") or "").strip()
    if not _is_http_url(url):
        return {"ok": False, "code": 0, "text": ""}

    method = (login_cfg.get("method") or "POST").upper()
    uf = login_cfg.get("username_field", "username")
    pf = login_cfg.get("password_field", "password")
    extra = login_cfg.get("extra", {}) or {}
    data = {uf: username, pf: password, **extra}

    r = session.post(url, data=data, allow_redirects=True, timeout=30) if method == "POST" else \
        session.get(url, params=data, allow_redirects=True, timeout=30)

    ok = (r.status_code in SUCCESS_CODES) and (len(session.cookies) > 0 or "logout" in (r.text or "").lower())
    if debug:
        logging.debug(f"[auth_flow] code={r.status_code} cookies={len(session.cookies)} ok={ok}")

    auth_hdr = r.headers.get("Authorization")
    if auth_hdr:
        _apply_bearer(session, auth_hdr)

    ctype = r.headers.get("Content-Type", "")
    if "application/json" in (ctype or "").lower():
        j = r.json()
        for k in ("token", "access_token", "jwt", "id_token"):
            if isinstance(j.get(k), str) and j[k]:
                _apply_bearer(session, j[k])
                break

    return {"ok": ok, "code": r.status_code, "text": r.text or ""}

def build_role_sessions(base_session: requests.Session, cfg: Dict[str, Any], debug: bool = False) -> Dict[str, requests.Session]:
    s_base = base_session or hardened_session({})
    sessions: Dict[str, requests.Session] = {"anon": s_base}
    roles = ((cfg.get("auth") or {}).get("roles") or [])

    for rcfg in roles:
        name = (rcfg.get("name") or "role").lower()
        s = hardened_session({})
        s.headers.update(s_base.headers)
        for c in s_base.cookies:
            s.cookies.set_cookie(c)

        if rcfg.get("bearer"):
            _apply_bearer(s, rcfg.get("bearer"))
        for k, v in (rcfg.get("headers") or {}).items():
            s.headers[str(k)] = str(v)
        for k, v in (rcfg.get("cookie") or {}).items():
            s.cookies.set(str(k), str(v))

        login_cfg = rcfg.get("login") or {}
        if login_cfg.get("url") and (rcfg.get("username") and rcfg.get("password")):
            res = _login_with_form(s, login_cfg, str(rcfg["username"]), str(rcfg["password"]), debug=debug)
            if not res["ok"] and debug:
                logging.debug(f"[auth_flow] {name} login başarısız olabilir → code={res['code']}")

        sessions[name] = s

    return sessions

# -----------------------------------------------------------------------------
# Meta yardımcı ve smart_login
# -----------------------------------------------------------------------------

def attach_auth_meta(results: Dict[str, Any], authenticated: bool) -> None:
    results.setdefault("meta", {})["authenticated"] = bool(authenticated)

def smart_login(session: requests.Session,
                cfg: Dict[str, Any],
                driver=None,
                base_url: Optional[str] = None,
                debug: bool = False,
                event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> bool:
    ok = run_auth_flow(session, cfg, driver=driver, base_url=base_url, debug=debug, event_cb=event_cb)
    roles = ((cfg.get("auth") or {}).get("roles") or [])
    if roles:
        _ = build_role_sessions(session, cfg, debug=debug)
    return bool(ok)

# -----------------------------------------------------------------------------
# [WS3-ANCHOR] Auto-Signup & Device Code helpers
# -----------------------------------------------------------------------------

import time
import json
import imaplib
from email.parser import BytesParser

class MailboxAdapter:
    """Basit MailHog veya IMAP arayüzü. Doğrulama linkini almak için kullanılır."""
    def __init__(self, cfg: Dict[str, Any]):
        mcfg = ((cfg or {}).get("auth") or {}).get("auto_signup") or {}
        self.kind = (((mcfg.get("mailbox") or {}).get("type") or "mailhog").lower())
        self.base_url = ((mcfg.get("mailbox") or {}).get("base_url") or "")
        self.imap = (mcfg.get("mailbox") or {}).get("imap") or {}

    def fetch_last_verification_link(self, to_hint: Optional[str] = None) -> Optional[str]:
        if self.kind == "mailhog":
            if not _is_http_url(f"{self.base_url}/api/v2/messages"):
                return None
            r = requests.get(f"{self.base_url}/api/v2/messages", timeout=10)
            if r.status_code // 100 != 2:
                return None
            payload = r.json()
            msgs = (payload or {}).get("items") or []
            for m in reversed(msgs):
                blob = json.dumps(m)
                if to_hint and to_hint not in blob:
                    continue
                body = self._extract_body_mailhog(m)
                link = self._extract_link(body)
                if link:
                    return link
            return None

        # IMAP
        host = self.imap.get("host"); user = self.imap.get("user"); pwd = self.imap.get("password")
        port = int(self.imap.get("port", 993)); use_ssl = bool(self.imap.get("ssl", True))
        M = imaplib.IMAP4_SSL(host, port) if use_ssl else imaplib.IMAP4(host, port)
        M.login(user, pwd)
        M.select('INBOX')
        typ, data = M.search(None, 'ALL')
        for num in reversed(data[0].split()):
            typ, msg_data = M.fetch(num, '(RFC822)')
            msg = BytesParser().parsebytes(msg_data[0][1])
            body = (msg.get_payload(decode=True) or b'').decode(errors='ignore')
            link = self._extract_link(body)
            if link:
                return link
        return None

    @staticmethod
    def _extract_body_mailhog(m: Dict[str, Any]) -> str:
        return (m.get("Content") or {}).get("Body") or ""

    @staticmethod
    def _extract_link(body: str) -> Optional[str]:
        m = re.search(r"https?://[^\s'\"]+", body or "")
        return m.group(0) if m else None

def run_auto_signup(session, cfg: Dict[str, Any]) -> bool:
    acfg = (((cfg or {}).get("auth") or {}).get("auto_signup") or {})
    if not acfg.get("enabled"):
        return False
    signup_url = (acfg.get("signup_url") or "").strip()
    if not _is_http_url(signup_url):
        return False
    fields = (acfg.get("form_fields") or {})
    email_field = fields.get("email", "email")
    pass_field = fields.get("password", "password")
    pass2_field = fields.get("password2", pass_field)

    email_addr = f"test{int(time.time())}@example.invalid"
    pwd = "P@ssw0rd!234"
    resp = session.post(signup_url, data={email_field: email_addr, pass_field: pwd, pass2_field: pwd})
    if getattr(resp, "status_code", 500) >= 400:
        return False

    adapter = MailboxAdapter(cfg)
    vlink = adapter.fetch_last_verification_link(to_hint=email_addr)
    if not vlink:
        return False
    vresp = session.get(vlink)
    return getattr(vresp, "status_code", 500) < 400

def run_device_code_flow(session, cfg: Dict[str, Any]) -> bool:
    assisted = ((cfg or {}).get("auth") or {}).get("assisted") or {}
    if not assisted.get("enabled"):
        return False
    dcfg = assisted.get("device_code") or {}
    device_url = (dcfg.get("device_url") or "").strip()
    token_url = (dcfg.get("token_url") or "").strip()
    client_id = dcfg.get("client_id")
    scope = dcfg.get("scope") or "openid profile email"
    if not (_is_http_url(device_url) and _is_http_url(token_url) and client_id):
        return False

    r = requests.post(device_url, data={"client_id": client_id, "scope": scope}, timeout=10)
    if r.status_code // 100 != 2:
        return False
    payload = r.json()
    user_code = payload.get("user_code")
    verify_uri = payload.get("verification_uri") or payload.get("verification_uri_complete")
    interval = int(payload.get("interval", 5))
    device_code = payload.get("device_code")
    if not (user_code and verify_uri and device_code):
        return False

    print(f"[Assisted Auth] Doğrulayın: {verify_uri}  Kod: {user_code}")
    while True:
        tr = requests.post(token_url, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code, "client_id": client_id}, timeout=10)
        if tr.status_code == 200:
            tok = tr.json().get("access_token")
            if tok:
                session.headers.update({"Authorization": f"Bearer {tok}"})
                return True
        elif tr.status_code in (400, 428):
            time.sleep(interval)
            continue
        else:
            return False

# -----------------------------------------------------------------------------
# Yardımcı: perform_login (opsiyonel importlar korumalı)
# -----------------------------------------------------------------------------

def perform_login(cfg: dict, session=None):
    sess = session
    if sess is None:
        # Attempt hardened session if available, else plain requests.Session
        if _mod_available("core.http"):
            _hs = _import_attr("core.http", "hardened_session")
            if callable(_hs):
                sess = _hs(cfg)  # type: ignore[misc]
        if sess is None:
            import requests as _rq  # type: ignore
            sess = _rq.Session()
            sess.verify = bool((cfg or {}).get("tls_verify", True))

    auth = (cfg.get("auth") or {})
    base = (cfg.get("base_url") or cfg.get("target") or "").strip()
    login_url = (auth.get("login_url") or "").strip()

    # 1) Basic login()
    ok = False
    if login_url:
        try_res = login(sess, cfg)
        ok = bool(try_res and (ensure_session(sess, cfg) or is_session_alive(sess)))

    # 2) Strategy flow (requests + webdriver)
    if not ok:
        ok2 = run_auth_flow(sess, cfg, driver=None, base_url=base or None, debug=bool(cfg.get("debug")), event_cb=None)
        ok = bool(ok2 and ensure_session(sess, cfg))

    if ok:
        setattr(sess, "_authenticated", True)  # type: ignore[attr-defined]
        return {"ok": True, "session": sess, "info": {"login_url": login_url or "", "flow": "strategy" if not login_url else "basic"}}

    return {"ok": False, "session": sess, "error": "login failed"}
