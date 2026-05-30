"""
websecure.core.platform_compat
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cross-platform helper utilities used throughout the codebase.

Responsibilities (SRP):
- OS / architecture detection
- Binary name normalisation (.exe on Windows, bare name elsewhere)
- Candidate path list generation for tools/ directory lookup
- GitHub release asset selection across platforms
- Archive extraction for both .zip (Windows) and .tar.gz (Linux / macOS)

Import this module instead of repeating `sys.platform == "win32"` checks.
"""
from __future__ import annotations

import os
import sys
import platform
import tarfile
import zipfile
from pathlib import Path

__all__ = [
    "exe_suffix",
    "binary_name",
    "binary_candidates",
    "github_release_info",
    "extract_binary_from_archive",
    "tor_browser_exe_candidates",
]


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------

def exe_suffix() -> str:
    """Return ``'.exe'`` on Windows, empty string elsewhere."""
    return ".exe" if sys.platform == "win32" else ""


def binary_name(base: str) -> str:
    """
    Append the platform-appropriate executable suffix.

    Examples
    --------
    >>> binary_name("nuclei")
    'nuclei'          # Linux / macOS
    'nuclei.exe'      # Windows
    """
    return base + exe_suffix()


def binary_candidates(root: Path, tool: str) -> list[Path]:
    """
    Return an ordered list of candidate paths to find *tool* inside the
    project ``tools/`` directory.

    Checks platform-native name first (e.g. ``nuclei.exe`` on Windows),
    then the bare name, so the function works on every OS.

    Parameters
    ----------
    root:
        Project root directory (typically computed via ``Path(__file__).resolve().parent…``).
    tool:
        Tool short name, e.g. ``"nuclei"``, ``"ffuf"``.
    """
    native = binary_name(tool)
    candidates: list[Path] = []

    # <root>/tools/<tool>/<tool>[.exe]  — versioned sub-directory layout
    candidates.append(root / "tools" / tool / native)
    if native != tool:
        candidates.append(root / "tools" / tool / tool)

    # <root>/tools/<tool>[.exe]  — flat layout
    candidates.append(root / "tools" / native)
    if native != tool:
        candidates.append(root / "tools" / tool)

    return candidates


# ---------------------------------------------------------------------------
# GitHub release asset selection
# ---------------------------------------------------------------------------

def github_release_info() -> tuple[str, str]:
    """
    Return ``(os_name, arch)`` suitable for filtering GitHub release assets.

    Returns
    -------
    os_name : str
        One of ``'windows'``, ``'linux'``, ``'darwin'``.
    arch : str
        One of ``'amd64'``, ``'arm64'``, ``'386'``.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {
        "windows": "windows",
        "linux":   "linux",
        "darwin":  "darwin",  # macOS
    }
    arch_map = {
        "x86_64":  "amd64",
        "amd64":   "amd64",
        "arm64":   "arm64",
        "aarch64": "arm64",
        "i386":    "386",
        "i686":    "386",
    }

    os_name = os_map.get(system, system)
    arch    = arch_map.get(machine, "amd64")
    return os_name, arch


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------

def extract_binary_from_archive(
    archive_path: Path,
    dest_path: Path,
    name_hint: str,
) -> bool:
    """
    Extract a binary from a ``.zip`` or ``.tar.gz`` archive.

    Automatically handles:
    - ``.zip``  — used by all ProjectDiscovery Windows releases
    - ``.tar.gz`` / ``.tgz`` — used by Linux / macOS releases

    On non-Windows systems the extracted file is made executable (chmod 755).

    Parameters
    ----------
    archive_path:
        Path to the downloaded archive.
    dest_path:
        Destination file path for the extracted binary.
    name_hint:
        Substring that must be in the member filename (e.g. ``"nuclei"``).

    Returns
    -------
    bool
        ``True`` if extraction succeeded, ``False`` otherwise.
    """
    archive_str = str(archive_path).lower()
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    def _make_executable(p: Path) -> None:
        if sys.platform != "win32":
            try:
                p.chmod(0o755)
            except Exception:
                pass

    # ── ZIP ──────────────────────────────────────────────────────────────────
    if archive_str.endswith(".zip"):
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                for member in zf.namelist():
                    fname = member.split("/")[-1].lower()
                    if not fname:          # directory entry
                        continue
                    if name_hint.lower() not in fname:
                        continue
                    # Skip .exe on non-Windows; skip non-.exe on Windows
                    if sys.platform == "win32" and not fname.endswith(".exe"):
                        continue
                    if sys.platform != "win32" and fname.endswith(".exe"):
                        continue
                    with zf.open(member) as src:
                        dest_path.write_bytes(src.read())
                    _make_executable(dest_path)
                    return True
        except Exception:
            return False

    # ── TAR.GZ / TGZ ─────────────────────────────────────────────────────────
    if archive_str.endswith((".tar.gz", ".tgz")):
        try:
            with tarfile.open(archive_path, "r:gz") as tf:
                for member in tf.getmembers():
                    fname = member.name.split("/")[-1].lower()
                    if not fname or not member.isfile():
                        continue
                    if name_hint.lower() not in fname:
                        continue
                    if sys.platform == "win32" and not fname.endswith(".exe"):
                        continue
                    if sys.platform != "win32" and fname.endswith(".exe"):
                        continue
                    f = tf.extractfile(member)
                    if f:
                        dest_path.write_bytes(f.read())
                        _make_executable(dest_path)
                        return True
        except Exception:
            return False

    return False


# ---------------------------------------------------------------------------
# Tor Browser executable candidates
# ---------------------------------------------------------------------------

def tor_browser_exe_candidates() -> list[str]:
    """
    Return an ordered list of Tor Browser executable paths to try, covering
    Windows, Linux, and macOS installations.

    Paths use ``os.path.expandvars`` / ``os.path.expanduser`` so they resolve
    correctly regardless of the current username.
    """
    home = os.path.expanduser("~")
    candidates: list[str] = []

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        programfiles = os.environ.get("ProgramFiles", r"C:\Program Files")
        programfiles_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        candidates = [
            # Standard user installation via Tor Browser installer
            os.path.join(home, "Desktop", "Tor Browser", "Browser", "firefox.exe"),
            os.path.join(appdata, "Tor Browser", "Browser", "firefox.exe"),
            os.path.join(localappdata, "Programs", "Tor Browser", "Browser", "firefox.exe"),
            # System-wide installations
            os.path.join(programfiles, "Tor Browser", "Browser", "firefox.exe"),
            os.path.join(programfiles_x86, "Tor Browser", "Browser", "firefox.exe"),
            # Chocolatey / portable common paths
            r"C:\tools\tor-browser\Browser\firefox.exe",
            r"C:\tor-browser\Browser\firefox.exe",
        ]

    elif sys.platform == "darwin":  # macOS
        candidates = [
            "/Applications/Tor Browser.app/Contents/MacOS/firefox",
            os.path.join(home, "Applications", "Tor Browser.app", "Contents", "MacOS", "firefox"),
        ]

    else:  # Linux
        candidates = [
            os.path.join(home, "tor-browser", "Browser", "start-tor-browser.desktop"),
            os.path.join(home, ".local", "share", "torbrowser", "tbb", "x86_64", "tor-browser", "Browser", "firefox"),
            "/usr/bin/torbrowser-launcher",
            "/usr/local/bin/torbrowser-launcher",
            # Flatpak
            "/var/lib/flatpak/app/com.github.micahflee.torbrowser-launcher/current/active/export/bin/torbrowser-launcher",
        ]

    return candidates
