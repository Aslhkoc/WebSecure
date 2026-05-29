import os
import pathlib
from typing import List, Dict

# ---------------------------------------------------------------------------
# Common external wordlist suite paths (SecLists, PayloadAllTheThings, etc.)
# Checked in priority order; first found wins for each category.
# ---------------------------------------------------------------------------
_SECLISTS_ROOTS = [
    # Linux / macOS standard locations
    "/usr/share/seclists",
    "/usr/share/SecLists",
    "/opt/SecLists",
    "/opt/seclists",
    # Kali / Parrot
    "/usr/share/wordlists/seclists",
    # Windows common install paths
    r"C:\tools\SecLists",
    r"C:\SecLists",
    r"C:\ProgramData\SecLists",
    # User home-relative fallbacks (expanded at runtime)
    os.path.join(os.path.expanduser("~"), "tools", "SecLists"),
    os.path.join(os.path.expanduser("~"), "SecLists"),
    os.path.join(os.path.expanduser("~"), "Desktop", "SecLists"),
]

_PATT_ROOTS = [
    "/usr/share/payloadallthethings",
    "/usr/share/PayloadAllTheThings",
    "/opt/PayloadAllTheThings",
    r"C:\tools\PayloadAllTheThings",
    r"C:\PayloadAllTheThings",
]

_DIRBUSTER_ROOTS = [
    "/usr/share/dirbuster/wordlists",
    "/usr/share/wordlists/dirbuster",
]

_DIRB_ROOTS = [
    "/usr/share/dirb/wordlists",
    "/usr/share/wordlists/dirb",
]

_GENERIC_ROOTS = [
    "/usr/share/wordlists",
    "/usr/local/share/wordlists",
]


def _find_root(candidates: List[str]) -> str:
    """Return first existing path from candidates, or empty string."""
    for c in candidates:
        if os.path.isdir(c):
            return c
    return ""


# ---------------------------------------------------------------------------
# Curated high-value wordlists by category
# Paths are relative to a SecLists root (if found) or absolute fallbacks
# ---------------------------------------------------------------------------
_SECLISTS_CURATED: Dict[str, List[str]] = {
    "discovery": [
        "Discovery/Web-Content/raft-large-directories.txt",
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/big.txt",
        "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "Discovery/Web-Content/directory-list-2.3-big.txt",
    ],
    "files": [
        "Discovery/Web-Content/raft-large-files.txt",
        "Discovery/Web-Content/raft-medium-files.txt",
        "Discovery/Web-Content/common-and-french.txt",
    ],
    "api": [
        "Discovery/Web-Content/api/api-endpoints.txt",
        "Discovery/Web-Content/api/objects.txt",
        "Discovery/Web-Content/api/actions.txt",
    ],
    "params": [
        "Discovery/Web-Content/burp-parameter-names.txt",
    ],
    "subdomains": [
        "Discovery/DNS/subdomains-top1million-20000.txt",
        "Discovery/DNS/subdomains-top1million-110000.txt",
    ],
    "fuzzing": [
        "Fuzzing/special-chars.txt",
        "Fuzzing/SQLi/Generic-SQLi.txt",
        "Fuzzing/XSS/XSS-Jhaddix.txt",
        "Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
        "Fuzzing/SSRF.txt",
    ],
    "passwords": [
        "Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
        "Passwords/Common-Credentials/top-passwords-shortlist.txt",
    ],
    "usernames": [
        "Usernames/top-usernames-shortlist.txt",
        "Usernames/Names/names.txt",
    ],
}


def collect_all_wordlists(base_dirs: List[str] = None) -> Dict[str, object]:
    """
    Finds all wordlist files from:
      1. Project-local websecure/wordlists/ and websecure/wordlists_custom/
      2. SecLists (auto-detected from common OS install paths)
      3. PayloadAllTheThings (auto-detected)
      4. DirBuster / dirb system wordlists

    Returns:
        {
          "all": [path1, path2, ...],
          "count": int,
          "total_lines_est": int,
          "curated": {
              "discovery": [...],   # best dirs for dir busting
              "fuzzing": [...],     # XSS/SQLi/LFI payloads
              "api": [...],         # API endpoint lists
              "params": [...],      # parameter name lists
              "subdomains": [...],  # subdomain lists
          },
          "seclists_root": str,     # path or "" if not found
          "patt_root": str,
        }
    """
    if base_dirs is None:
        _here = pathlib.Path(__file__).resolve().parent.parent.parent  # websecure/
        base_dirs = [
            str(_here / "wordlists"),
            str(_here / "wordlists_custom"),
        ]

    # --- Discover external suites ---
    seclists_root = _find_root(_SECLISTS_ROOTS)
    patt_root = _find_root(_PATT_ROOTS)
    dirbuster_root = _find_root(_DIRBUSTER_ROOTS)
    dirb_root = _find_root(_DIRB_ROOTS)
    generic_root = _find_root(_GENERIC_ROOTS)

    # Add discovered external roots to scan dirs
    extra_dirs = []
    for root in filter(None, [seclists_root, patt_root, dirbuster_root, dirb_root, generic_root]):
        if root not in extra_dirs:
            extra_dirs.append(root)

    all_scan_dirs = base_dirs + extra_dirs

    found_files = []
    seen = set()
    total_size = 0

    ALLOWED_EXTENSIONS = {'.txt', '.lst', '.fuzz', '.list', '.dict', '.csv', '.json'}

    for d in all_scan_dirs:
        p = pathlib.Path(d)
        if not p.exists():
            continue

        for f in p.rglob("*"):
            if not f.is_file():
                continue
            resolved = str(f.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)

            suffix = f.suffix.lower()
            if not suffix:
                found_files.append(resolved)
                total_size += f.stat().st_size
            elif suffix in ALLOWED_EXTENSIONS:
                found_files.append(resolved)
                total_size += f.stat().st_size

    # --- Build curated index (SecLists shortcuts) ---
    curated: Dict[str, List[str]] = {k: [] for k in _SECLISTS_CURATED}
    if seclists_root:
        for category, rel_paths in _SECLISTS_CURATED.items():
            for rp in rel_paths:
                full = os.path.join(seclists_root, rp)
                if os.path.isfile(full):
                    curated[category].append(full)

    # PayloadAllTheThings fuzzing payloads — files already in found_files from first pass;
    # walk again only to build the curated fuzzing index
    if patt_root:
        for root, dirs, files in os.walk(patt_root):
            for fname in files:
                if fname.lower().endswith(".txt"):
                    curated.setdefault("fuzzing", []).append(os.path.join(root, fname))

    estimated_lines = total_size // 10

    return {
        "all": found_files,
        "count": len(found_files),
        "total_lines_est": estimated_lines,
        "curated": curated,
        "seclists_root": seclists_root,
        "patt_root": patt_root,
    }


def get_best_wordlist(category: str = "discovery") -> str:
    """
    Returns the path of the best available wordlist for a given category.
    Falls back gracefully if external suites not installed.
    Suitable for single-wordlist tools (nmap NSE, nuclei, etc.).
    """
    data = collect_all_wordlists()
    curated = data.get("curated", {})
    candidates = curated.get(category, [])
    if candidates:
        return candidates[0]
    # Fallback: first file in all
    all_files = data.get("all", [])
    return all_files[0] if all_files else ""


def get_tech_extensions(tech_stack: List[str]) -> str:
    """
    Given detected technologies, return comma-separated file extensions
    for FFUF -e flag (e.g. '.php,.php5,.php7' for PHP stack).
    """
    ext_map = {
        "php": [".php", ".php5", ".php7", ".phtml", ".php.bak", ".php~"],
        "asp": [".asp", ".aspx", ".ashx", ".asmx", ".axd"],
        "java": [".jsp", ".jspx", ".do", ".action", ".faces", ".jsf", ".java"],
        "python": [".py", ".pyc", ".wsgi"],
        "ruby": [".rb", ".rhtml", ".erb"],
        "coldfusion": [".cfm", ".cfc", ".cfml"],
        "perl": [".pl", ".cgi", ".pm"],
        "node": [".js", ".json", ".ts"],
        "wordpress": [".php", ".php5"],
        "drupal": [".php", ".inc", ".module"],
        "joomla": [".php"],
        "laravel": [".php", ".blade.php"],
        "django": [".py", ".html"],
        "flask": [".py", ".html"],
        "spring": [".do", ".action", ".jsp", ".jspx"],
        "nginx": [],
        "apache": [".htaccess", ".htpasswd"],
        "iis": [".asp", ".aspx", ".axd", ".ashx", ".config"],
        "tomcat": [".jsp", ".do", ".action"],
    }

    extensions = set()
    # Always include common backup/config extensions
    extensions.update([".bak", ".old", ".backup", ".config", ".conf", ".log", ".txt", ".xml"])

    for tech in tech_stack:
        tech_lower = tech.lower()
        for key, exts in ext_map.items():
            if key in tech_lower:
                extensions.update(exts)

    return ",".join(sorted(extensions)) if extensions else ".php,.asp,.aspx,.jsp,.txt,.bak"
