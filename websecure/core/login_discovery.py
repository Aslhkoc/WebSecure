from __future__ import annotations
from websecure.core.http import verify_for_phase
import logging, re, xml.etree.ElementTree as ET
from dataclasses import dataclass
from importlib import import_module
from importlib.util import find_spec
from typing import List, Tuple, Set, Optional, Dict, Any, Callable
from urllib.parse import urljoin, urlparse
import requests


if find_spec("bs4") is not None:
    BeautifulSoup = getattr(import_module("bs4"), "BeautifulSoup", None)
else:
    BeautifulSoup = None


if find_spec("websecure.core.reporting") is not None:
    add_result = getattr(import_module("websecure.core.reporting"), "add_result")
else:
    def add_result(*a: Any, **k: Any) -> None:
        return None

# --- 2.3: Güvenli regex köprüsü ---
_SRX_SEARCH: Optional[Callable[..., Any]] = None
_srx = None
if find_spec("websecure.core.safe_regex") is not None:
    _srx = import_module("websecure.core.safe_regex")
    _cand = getattr(_srx, "search", None)
    if callable(_cand):
        _SRX_SEARCH = _cand

def _re_search_safe(pattern: str, text: str, flags: int = 0):
    """
    safe_regex mevcut ve 'search' çağrılabilir ise onu kullanır; değilse re.search.
    Hata yutma yok: Bağımlılık içi hatalar üst katmana yükselir.
    """
    target = text or ""
    if _SRX_SEARCH is not None:
        return _SRX_SEARCH(pattern, target, flags=flags)
    return re.search(pattern, target, flags)
# =========================
# SOLID: Ayarlar + Çekirdek
# =========================
@dataclass(frozen=True)
class LoginDiscoveryOptions:
    robots_timeout: int = 8
    sitemap_timeout: int = 10
    homepage_timeout: int = 10
    follow_redirects: bool = True
    verify_tls: bool = True  # TLS varsayılan güvenli
    max_sitemap_items: int = 500
    max_candidates: int = 200
    keywords: Tuple[str, ...] = ("login", "signin", "auth", "session", "giris", "oturum")
    tech_guess: bool = True                 # teknoloji-aware tahminleri etkinleştir
    tech_weight: int = 4                    # teknoloji eşleşmesine puan katkısı
    tech_timeout: int = 8                   # teknoloji keşfi için istek süresi
    use_wappalyzer: bool = True             # Wappalyzer uygunsa kullan
    wappalyzer_timeout: int = 8             # Wappalyzer çekimi için üst sınır
    wappalyzer_user_agent: Optional[str] = None  # özel UA gerekiyorsa

COMMON_LOGIN_PATHS = (
    "/login", "/signin", "/account/login", "/users/sign_in", "/session/new",
    "/auth/login", "/admin/login", "/wp-login.php", "/user/login", "/login.php",
    "/index.php?route=account/login"
)

# --- Teknoloji -> login yolları eşlemesi (genişletilebilir) ---
TECH_LOGIN_HINTS: Dict[str, List[str]] = {
    # CMS
    "WordPress": ["/wp-login.php", "/wp-admin/"],
    "Joomla": ["/index.php?option=com_users&view=login", "/administrator/index.php"],
    "Drupal": ["/user/login", "/user"],
    "Magento": ["/customer/account/login"],
    "OpenCart": ["/index.php?route=account/login"],
    # Framework
    "Ruby on Rails": ["/users/sign_in", "/admin/login"],
    "Laravel": ["/login", "/admin/login"],
    "Django": ["/admin/login", "/accounts/login/"],
    "Spring": ["/login", "/signin"],
    "Express": ["/login", "/signin"],
    "Next.js": ["/login", "/api/auth/signin"],
    "Nuxt.js": ["/login"],
    # DevOps / Uygulamalar
    "Grafana": ["/login"],
    "Jenkins": ["/login"],
    "Kibana": ["/login", "/app/login"],
    "GitLab": ["/users/sign_in"],
    "Jira": ["/login.jsp"],
    "Confluence": ["/dologin.action"],
    "phpMyAdmin": ["/phpmyadmin/"],
    "cPanel": ["/login/"],
}

TECH_EXTRA_KEYWORDS: Dict[str, List[str]] = {
    "WordPress": ["wp", "wordpress"],
    "Joomla": ["joomla"],
    "Drupal": ["drupal"],
    "Magento": ["magento"],
    "OpenCart": ["opencart"],
    "Ruby on Rails": ["rails", "ruby"],
    "Laravel": ["laravel"],
    "Django": ["django"],
    "Spring": ["spring security", "spring-boot"],
    "Express": ["express"],
    "Next.js": ["nextjs", "next.js"],
    "Nuxt.js": ["nuxt", "nuxt.js"],
    "Grafana": ["grafana"],
    "Jenkins": ["jenkins"],
    "Kibana": ["kibana"],
    "GitLab": ["gitlab"],
    "Jira": ["jira"],
    "Confluence": ["confluence"],
    "phpMyAdmin": ["phpmyadmin"],
    "cPanel": ["cpanel"],
}

# --- Wappalyzer opsiyonel ---
_WAPP_AVAILABLE = False
Wappalyzer = None
WebPage = None
if find_spec("Wappalyzer") is not None:
    _wapp_mod = import_module("Wappalyzer")
    Wappalyzer = getattr(_wapp_mod, "Wappalyzer", None)
    WebPage = getattr(_wapp_mod, "WebPage", None)
    _WAPP_AVAILABLE = (Wappalyzer is not None) and (WebPage is not None)


class LoginDiscovery:
    """Tek sorumluluk: login URL’lerini sezgisel olarak keşfetmek ve skorlamak."""
    def __init__(self, session: requests.Session, options: Optional["LoginDiscoveryOptions"] = None):
        self.s = session
        self.opt = options or LoginDiscoveryOptions()
        # TLS varsayılanını güvenli tarafta tut (özellik mevcutsa)
        if getattr(self.s, "verify", None) is None:
            self.s.verify = True
        # teknoloji cache (host -> [tech])
        self._tech_cache: Dict[str, List[str]] = {}
        # son wappalyzer kategorileri (rapor/puanlama için)
        self._last_wapp_cats: Dict[str, Dict] = {}

    # --- yardımcılar ---
    @staticmethod
    def _same_host(u: str, base: str) -> bool:
        u_host = urlparse(u).netloc.split(":")[0].lower()
        b_host = urlparse(base).netloc.split(":")[0].lower()
        return (u_host != "") and (u_host == b_host)

    def _req(self, url: str, timeout: int):
        # Kısa takma adlar – "unresolved" saçmalığını bitirelim
        s = self.s
        cfg = getattr(self, "cfg", {})
        opt = getattr(self, "opt", None)

        # Header’ları kur
        headers = dict(getattr(s, "headers", {}) or {})
        ua = getattr(opt, "wappalyzer_user_agent", None) if opt else None
        if ua:
            headers["User-Agent"] = ua

        # Redirect ve TLS doğrulama bayrakları
        allow_redirects = bool(getattr(opt, "follow_redirects", True)) if opt else True
        verify = verify_for_phase(cfg, "discovery", url)  # doğru argüman sırası: (cfg, phase, url)

        # Tek, temiz çağrı
        return s.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            headers=headers or None,
        )

    # --- teknoloji keşfi ---
    def _detect_technologies(self, base_url: str) -> List[str]:
        if not bool(self.opt.tech_guess):
            return []

        host_key = urlparse(base_url).netloc.lower()
        if host_key in self._tech_cache:
            return self._tech_cache[host_key][:]

        techs: List[str] = []

        # 1) Wappalyzer ile (varsa ve açık ise)
        if _WAPP_AVAILABLE and bool(getattr(self.opt, "use_wappalyzer", True)) and Wappalyzer and WebPage:
            r = self._req(base_url, min(int(self.opt.wappalyzer_timeout), int(self.opt.homepage_timeout)))
            # Bazı sürümlerde new_from_response olmayabilir; mevcut yol seçilir.
            if hasattr(WebPage, "new_from_response"):
                wp = WebPage.new_from_response(base_url, r)  # type: ignore[attr-defined]
            else:
                wp = WebPage.new_from_url(base_url, timeout=int(self.opt.wappalyzer_timeout))
            wapp = Wappalyzer.latest()
            detected = wapp.analyze_with_categories(wp) or {}
            techs.extend(sorted(set(list(detected.keys()))))
            self._last_wapp_cats = detected  # type: ignore[assignment]

        # 2) Basit heuristik (headers + html) — wappalyzer yoksa ya da ek sinyaller
        r2 = self._req(base_url, int(self.opt.homepage_timeout))
        txt = (r2.text or "").lower()
        hdrs = " ".join([f"{str(k)}:{str(v)}" for k, v in (dict(r2.headers or {}) ).items()]).lower()

        pairs = [
            ("wordpress", "WordPress"),
            ("wp-content", "WordPress"),
            ("joomla", "Joomla"),
            ("drupal", "Drupal"),
            ("magento", "Magento"),
            ("opencart", "OpenCart"),
            ("rails", "Ruby on Rails"),
            ("laravel", "Laravel"),
            ("django", "Django"),
            ("spring", "Spring"),
            ("express", "Express"),
            ("next.js", "Next.js"),
            ("nuxt", "Nuxt.js"),
            ("grafana", "Grafana"),
            ("jenkins", "Jenkins"),
            ("kibana", "Kibana"),
            ("gitlab", "GitLab"),
            ("jira", "Jira"),
            ("confluence", "Confluence"),
            ("phpmyadmin", "phpMyAdmin"),
            ("cpanel", "cPanel"),
        ]
        for needle, label in pairs:
            if (needle in txt) or (needle in hdrs):
                techs.append(label)

        out = sorted(set(techs))
        self._tech_cache[host_key] = out
        return out

    # --- robots.txt ---
    def fetch_robots_txt(self, base_url: str) -> List[str]:
        u = urljoin(base_url, "/robots.txt")
        r = self._req(u, int(self.opt.robots_timeout))
        if r.status_code >= 400 or not (r.text or ""):
            return []

        out: List[str] = []
        for raw in r.text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            i = line.find(":")
            if i <= 0:
                continue
            key = line[:i].strip().lower()
            if key not in ("disallow", "allow"):
                continue
            part = line[i + 1:].strip()
            if not part or part == "/":
                continue
            if not part.startswith("/"):
                part = f"/{part}"
            out.append(part)

        # sıra korunarak tekilleştir
        seen: set[str] = set()
        uniq: List[str] = []
        for p in out:
            if p in seen:
                continue
            seen.add(p)
            uniq.append(p)
        return uniq

    # --- sitemap.xml / sitemap_index.xml ---
    def fetch_sitemap_urls(self, base_url: str) -> List[str]:
        """
        sitemap.xml/sitemap_index.xml içinden URL’leri dayanıklı şekilde çıkarır.
        - Önce ElementTree ile dener (hızlı yol)
        - ET başarısız ise: UTF-8 ignore decode + tekrar dener
        - Hâlâ olmazsa: BeautifulSoup (varsa)
        - En sonda: regex fallback ile <loc> etiketlerini toplar (ns:loc dahil)
        Geçersiz/bozuk içerik parse hatası yüzünden akışı KESMEZ.
        """
        candidates = ["/sitemap.xml", "/sitemap_index.xml"]
        urls: List[str] = []
        limit = int(self.opt.max_sitemap_items)

        def _extract_with_et(content: bytes) -> List[str]:
            out: List[str] = []
            try:
                root = ET.fromstring(content)
                for elem in root.iter():
                    tag = elem.tag.split('}', 1)[-1] if isinstance(elem.tag, str) and '}' in elem.tag else elem.tag
                    if tag == "loc":
                        txt = (elem.text or "").strip()
                        if txt:
                            out.append(txt)
            except ET.ParseError:
                pass
            return out

        def _extract_with_bs(text: str) -> List[str]:
            out: List[str] = []
            if BeautifulSoup is None:
                return out
            try:
                # 'xml' parser mevcut değilse html.parser ile de <loc> yakalanır
                soup = BeautifulSoup(text, "xml") if "xml" in getattr(BeautifulSoup, "__name__", "").lower() else BeautifulSoup(text, "html.parser")
                for loc in soup.find_all(["loc"]):
                    t = (loc.text or "").strip()
                    if t:
                        out.append(t)
            except Exception:
                return out
            return out

        def _extract_with_regex(text: str) -> List[str]:
            rx = re.compile(r"<(?:\w+:)?loc>\s*([^<]+)\s*</(?:\w+:)?loc>", re.I)
            return [m.group(1).strip() for m in rx.finditer(text)]

        for path in candidates:
            r = self._req(urljoin(base_url, path), int(self.opt.sitemap_timeout))
            content = r.content or b""
            if r.status_code >= 400 or not content:
                continue

            data = content.lstrip()
            # hızlı kontrol: XML benzeri değilse atla
            if not data.startswith(b"<"):
                continue

            # 1) ET (ham bayt)
            found = _extract_with_et(data)
            if not found:
                # 2) ET (utf-8 ignore)
                text = data.decode("utf-8", "ignore")
                found = _extract_with_et(text.encode("utf-8"))
                if not found:
                    # 3) BeautifulSoup
                    found = _extract_with_bs(text)
                    if not found:
                        # 4) Regex fallback
                        found = _extract_with_regex(text)

            for u in found:
                if u and u not in urls:
                    urls.append(u)
                    if len(urls) >= limit:
                        return urls

        return urls

    def _score_login_page(self, url: str, html: str, techs: Optional[List[str]] = None) -> int:
        score = 0
        u = (url or "").lower()
        if any(k in u for k in self.opt.keywords):
            score += 3
        if _re_search_safe(r'type=["\']password["\']', html or "", re.I):
            score += 4
        if _re_search_safe(r'name=["\'](username|email|login|identifier)["\']', html or "", re.I):
            score += 3
        if _re_search_safe(r'(g-recaptcha|hcaptcha|captcha)', html or "", re.I):
            score += 1
        # teknoloji eşleşmesi varsa ek ağırlık
        if techs:
            tnames = set(techs)
            for t, hints in TECH_LOGIN_HINTS.items():
                if t in tnames and any(h in u for h in hints):
                    score += self.opt.tech_weight
                    break
        # Wappalyzer kategorilerinden "CMS", "Ecommerce", "DevOps" gibi sinyallere küçük bonus
        cats = getattr(self, "_last_wapp_cats", {}) or {}
        all_cats: set[str] = set()

        def _collect_cat(val) -> None:
            if isinstance(val, str):
                all_cats.add(val.strip().lower())
            elif isinstance(val, dict):
                # hem "name" alanı hem de dict’in anahtar/değerleri kategori olabilir
                if "name" in val:
                    all_cats.add(str(val["name"]).strip().lower())
                for k in val.keys():
                    if isinstance(k, str):
                        all_cats.add(k.strip().lower())
                    elif isinstance(k, dict) and "name" in k:
                        all_cats.add(str(k["name"]).strip().lower())
                for v in val.values():
                    _collect_cat(v)
            elif isinstance(val, (list, tuple, set)):
                for item in val:
                    _collect_cat(item)

        if isinstance(cats, dict):
            for _, catmap in cats.items():
                _collect_cat(catmap)
        else:
            _collect_cat(cats)

        cats_bonus = 1 if any(x in all_cats for x in ("cms", "ecommerce", "devops", "database")) else 0
        score += cats_bonus

        # title + anahtar kelime sinyali
        html_text = (html or "")
        kw_list = [str(k).lower() for k in (getattr(self.opt, "keywords", []) or [])]
        if _re_search_safe(r'<title[^>]*>(.*?)</title>', html_text, re.I) and (
                bool(kw_list) and any(k in html_text.lower() for k in kw_list)
        ):
            score += 1

        return score
    # --- ana keşif ---
    def discover_login_urls(self, base_url: str, seeds: Optional[List[str]] = None) -> List[Tuple[str, int]]:
        cand: List[str] = []

        # 0) Teknoloji tespiti (wappalyzer/heuristic)
        techs = self._detect_technologies(base_url) if self.opt.tech_guess else []

        # 1) sabit path denemeleri
        cand.extend([urljoin(base_url, p) for p in COMMON_LOGIN_PATHS])

        # 1.b) teknolojiye özel path tahminleri
        for t in techs:
            for p in TECH_LOGIN_HINTS.get(t, []):
                cand.append(urljoin(base_url, p))

        # 2) dışarıdan gelen tohumlar
        if seeds:
            cand.extend([urljoin(base_url, s) for s in seeds])

        # 3) robots/sitemap tabanlı olası yollar
        for path in self.fetch_robots_txt(base_url):
            if any(k in path.lower() for k in self.opt.keywords):
                cand.append(urljoin(base_url, path))
        for s in self.fetch_sitemap_urls(base_url):
            if self._same_host(s, base_url) and any(k in s.lower() for k in self.opt.keywords):
                cand.append(s)

        # 4) ana sayfadaki linkler (bs4 varsa)
        home_links: List[str] = []
        r = self._req(base_url, int(self.opt.homepage_timeout))
        if BeautifulSoup is not None and r.ok and (r.text or ""):
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                u = str(a.get("href") or "")
                if not u or u.startswith("#"):
                    continue
                full = urljoin(base_url, u)
                if self._same_host(full, base_url):
                    home_links.append(full)

        for u in home_links:
            u_low = u.lower()
            kws = list(getattr(self.opt, "keywords", []) or [])
            if any(k in u_low for k in kws):
                cand.append(u)

        # normalize + dedup + sınır
        norm: List[str] = []
        seen: Set[str] = set()
        for u in cand:
            uu = u.split("#", 1)[0].strip()
            if not uu:
                continue
            if uu not in seen:
                seen.add(uu)
                norm.append(uu)
            if len(norm) >= int(self.opt.max_candidates):
                break

        # hızlı örnekle ve skorla
        scored: List[Tuple[str, int]] = []
        for u in norm:
            r = self._req(u, min(6, int(self.opt.homepage_timeout)))
            if r.status_code < 400 and (r.text or ""):
                sc = self._score_login_page(u, r.text or "", techs=techs)
                if sc > 0:
                    scored.append((u, sc))

        scored.sort(key=lambda x: (-x[1], x[0]))
        add_result("login_discovery", {
            "base": base_url,
            "detected_tech": techs,
            "candidates": [{"url": u, "score": s} for u, s in scored[:20]],
            "count": len(scored)
        })
        return scored

def extract_csrf(html_text: str) -> Optional[str]:
    if not html_text:
        return None
    # yaygın isimler: csrf, _csrf, _token, authenticity_token
    m = re.search(
        r'(?:name|id)\s*=\s*["\'](?:csrf|_csrf|_token|authenticity_token)["\']\s+value\s*=\s*["\']([^"\']+)["\']',
        html_text,
        re.I
    )
    return m.group(1) if m else None

def fetch_sitemap_urls(
    base_url: str,
    session: "requests.Session | None" = None,
    timeout: int = 10,
    allow_guess: bool = True,
    max_items: int | None = None,
    **_ignored,
) -> list[str]:
    """
    Robots.txt ve yaygın sitemap yollarıyla sitemap URL’lerini döndürür.
    - max_items: döndürülen URL sayısına üst sınır (None = sınırsız).
    Not: Hata yutma yoktur; ağ/XML hataları üst katmana yükselir.
    """
    from urllib.parse import urlparse, urljoin
    import re
    import gzip
    import requests as _rq

    # Eğer proje içinde sınıf-temelli API mevcutsa onu kullan
    LD = globals().get("LoginDiscovery")
    LDO = globals().get("LoginDiscoveryOptions")
    if LD and LDO:
        opts = LDO(sitemap_timeout=timeout)
        ld = LD(session or _rq.Session(), options=opts)
        return ld.fetch_sitemap_urls(base_url)

    # --- Yardımcılar (try/except yok) ---
    def _normalize_base(url: str) -> str:
        if "://" not in url:
            url = "https://" + url
        p = urlparse(url)
        host = p.netloc or p.path
        scheme = p.scheme or "https"
        return f"{scheme}://{host}".rstrip("/")

    def _unique(seq):
        seen = set()
        out = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    # .xml ve .xml.gz içeriklerinden <loc> toplayan basit ayrıştırıcı
    _RE_LOC = re.compile(r"<(?:\w+:)?loc>\s*([^<\s][^<]*)\s*</(?:\w+:)?loc>", re.IGNORECASE)
    _RE_ROOT = re.compile(r"<(?:\w+:)?(?:urlset|sitemapindex)\b", re.IGNORECASE)
    _RE_INDEX = re.compile(r"<(?:\w+:)?sitemapindex\b", re.IGNORECASE)

    def _parse(xml_text: str) -> list[str]:
        return [m.group(1).strip() for m in _RE_LOC.finditer(xml_text) if m.group(1).strip()]

    def _read(sess: "_rq.Session", url: str, *, _timeout: int) -> str:
        resp = sess.get(url, timeout=_timeout, allow_redirects=True, verify=getattr(sess, "verify", True))
        # requests transfer-encoding gzip'i otomatik çözer; ancak .xml.gz dosyası içerik olarak gziptir.
        ctype = (resp.headers.get("Content-Type") or "").lower()
        raw = resp.content
        if url.lower().endswith(".gz") or "gzip" in ctype:
            text = gzip.decompress(raw).decode("utf-8", "ignore")
        else:
            # resp.text bazen yanlış kodlama tahmin edebilir; içerik güvenli yolu:
            text = raw.decode("utf-8", "ignore") if raw else (resp.text or "")
        return text

    # Ortak oturum ve taban
    sess = session or _rq.Session()
    base = _normalize_base(base_url)

    # ===================== YAKLAŞIM #1: robots.txt + tahminler + tek geçiş =====================
    # 1) robots.txt içinden Sitemap: satırlarını topla
    robot_urls: list[str] = []
    r_robots = sess.get(urljoin(base, "/robots.txt"), timeout=timeout, allow_redirects=True, verify=getattr(sess, "verify", True))
    if r_robots.ok and (r_robots.text or ""):
        for raw in r_robots.text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            i = line.find(":")
            if i <= 0:
                continue
            key = line[:i].strip().lower()
            if key != "sitemap":
                continue
            val = line[i + 1 :].strip()
            if val:
                robot_urls.append(val)

    # 2) Yaygın tahmini yollar
    guess_list = (
        [
            "/sitemap.xml",
            "/sitemap_index.xml",
            "/sitemap1.xml",
            "/sitemap/sitemap.xml",
            "/sitemaps/sitemap.xml",
            "/sitemap.xml.gz",
            "/sitemap_index.xml.gz",
        ]
        if allow_guess
        else []
    )

    # 3) Aday URL kümesi (yinelenenleri çıkar)
    candidates: list[str] = _unique(robot_urls + [urljoin(base, p) for p in guess_list])

    # 4) Adayları indirip <loc> içeriklerini çıkar
    urls: list[str] = []
    seen_urls = set()  # type: set[str]
    for cu in candidates:
        text = _read(sess, cu, _timeout=timeout)
        if "<" not in text:
            continue
        if not _RE_ROOT.search(text) and not _RE_LOC.search(text):
            continue
        for loc in _parse(text):
            if loc in seen_urls:
                continue
            seen_urls.add(loc)
            urls.append(loc)
            if max_items is not None and len(urls) >= int(max_items):
                return urls

    # ===================== YAKLAŞIM #2: (ESKİ BLOK) BFS ile sitemapindex takip =====================
    # Eski blok korunarak işlevselleştirildi.
    robots_text = _read(sess, urljoin(base + "/", "robots.txt"), _timeout=timeout)
    sitemaps: list[str] = []
    for line in (robots_text or "").splitlines():
        m = re.match(r"(?i)^\s*sitemap\s*:\s*(\S+)", line.strip())
        if m:
            sitemaps.append(m.group(1).strip())
    if not sitemaps and allow_guess:
        sitemaps = [
            urljoin(base + "/", "sitemap.xml"),
            urljoin(base + "/", "sitemap_index.xml"),
            urljoin(base + "/", "sitemap.xml.gz"),
            urljoin(base + "/", "sitemap_index.xml.gz"),
        ]

    seen_index = set()
    queue = _unique(sitemaps)
    while queue:
        sm = queue.pop(0)
        if sm in seen_index:
            continue
        seen_index.add(sm)

        txt = _read(sess, sm, _timeout=timeout)
        locs = _parse(txt)
        if not locs:
            continue

        # sitemapindex tespiti: explicit tag veya heuristik (sitemap*.xml* lokasyonları)
        is_index = bool(_RE_INDEX.search(txt)) or any(
            ("sitemap" in u.lower()) and u.lower().endswith((".xml", ".xml.gz")) for u in locs
        )
        if is_index:
            for u in locs:
                if u not in seen_index:
                    queue.append(u)
            continue

        # urlset -> gerçek sayfa/link loc'ları
        for u in locs:
            if u in seen_urls:
                continue
            seen_urls.add(u)
            urls.append(u)
            if max_items is not None and len(urls) >= int(max_items):
                return urls

    # Üst sınır uygula (varsa) ve döndür
    if isinstance(max_items, int) and max_items > 0:
        return urls[:max_items]
    return urls


# === PATCH: WebSecure Upgrade (auto-applied) @ 2025-09-07T16:43:08.489221 ===

# Ek: Config destekli keşif ve HEAD preflight
if find_spec("websecure.core.reporting") is not None:
    _add_result_patch = getattr(import_module("websecure.core.reporting"), "add_result")  # type: ignore[assignment]
else:
    def _add_result_patch(*a: Any, **k: Any) -> None:  # type: ignore[no-redef]
        return None


def _head_ok(session, url: str, timeout: int = 6, verify: bool | None = None) -> bool:
    # Koruyucu kontroller — susturma yok
    if not hasattr(session, "request"):
        raise TypeError("session nesnesi request() metodunu sağlamıyor")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout pozitif bir sayı olmalı")

    v = getattr(session, "verify", True) if verify is None else bool(verify)
    r = session.request("HEAD", url, timeout=timeout, allow_redirects=True, verify=v)
    return r.status_code < 400


def discover_login_urls_with_config(session, base_url: str, cfg: dict | None = None) -> list[tuple[str, int]]:
    """
    Config destekli sarmalayıcı:
      - config.login_discovery.extra_paths (liste) tohum olarak kullanılır.
      - TLS verify daima güvenli tarafta (True) varsayılır.
    """
    if not hasattr(session, "request"):
        raise TypeError("session nesnesi request() metodunu sağlamıyor")

    # TLS verify güvenli tarafta
    if getattr(session, "verify", None) is None:
        session.verify = True  # type: ignore[assignment]

    # cfg sözlük değilse nötrle
    cfg = cfg if isinstance(cfg, dict) else {}

    # extra_paths çıkarımı (susturmadan, şekil denetimiyle)
    ld_section = cfg.get("login_discovery")
    if isinstance(ld_section, dict) and isinstance(ld_section.get("extra_paths"), list):
        extra = list(ld_section["extra_paths"])
    else:
        extra: list[str] = []

    ld = LoginDiscovery(session, options=LoginDiscoveryOptions())
    seeds = [s for s in extra if isinstance(s, str) and s.strip()]
    cands = ld.discover_login_urls(base_url, seeds=seeds)

    # HEAD preflight ile hızlı doğrulama: skor 0 olmayanların 400+ dönmediğini teyit et
    checked: list[tuple[str,int]] = []
    for u, s in cands:
        if _head_ok(session, u, timeout=min(6, ld.opt.homepage_timeout)):
            checked.append((u, s))
    if checked != cands:
        _add_result_patch("login_discovery", {"base": base_url, "checked": len(checked), "original": len(cands)})
    return checked
