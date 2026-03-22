"""
websecure.scanners.file_upload
------------------------------
Checks for file upload vulnerabilities by identifying upload forms
and attempting to upload various test payloads (polyglots, benign files).
"""
import logging
import random
import string
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

# Try to import BeautifulSoup for form parsing
try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)

PAYLOADS = [
    {
        "name": "ws_test_benign.txt",
        "content": b"WebSecure Scanner Test File - Safe",
        "mime": "text/plain",
        "check": "safe"
    },
    {
        "name": "ws_test_html.html",
        "content": b"<html><body><script>console.log('WS_XSS_TEST')</script>WS_TEST_HTML</body></html>",
        "mime": "text/html",
        "check": "xss"
    },
    {
        "name": "ws_test_php.php",
        "content": b"<?php echo 'WS_PHP_EXEC_TEST'; ?>",
        "mime": "application/x-php",
        "check": "rce"
    },
    {
        "name": "ws_test_fake.jpg.php",
        "content": b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xFE\x00\x13<?php echo 'WS_POLY'; ?>",
        "mime": "image/jpeg",
        "check": "polyglot"
    }
]

def _generate_boundary():
    return "".join(random.choices(string.ascii_letters + string.digits, k=30))

def _looks_like_upload_form(form_html: str) -> bool:
    if not form_html: return False
    # Check for file input or multipart encoding
    if 'type="file"' in form_html.lower() or "type='file'" in form_html.lower():
        return True
    if 'multipart/form-data' in form_html.lower():
        return True
    return False

def _parse_upload_forms(url: str, html: str) -> List[Dict]:
    forms = []
    if not html: return forms

    if _BS4_AVAILABLE:
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            if not form.find('input', {'type': 'file'}):
                continue
            
            action = form.get('action') or ""
            method = (form.get('method') or "POST").upper()
            inputs = []
            
            file_param = "file" # Default fallback
            
            for inp in form.find_all('input'):
                iname = inp.get('name')
                itype = inp.get('type', 'text').lower()
                if not iname: continue
                
                if itype == 'file':
                    file_param = iname
                    # We only support one file param for now
                    inputs.append({"name": iname, "type": "file"})
                elif itype not in ('submit', 'button', 'image', 'reset'):
                    inputs.append({"name": iname, "type": "text", "value": inp.get('value', '1')})
            
            forms.append({
                "action": urljoin(url, action),
                "method": method,
                "file_param": file_param,
                "inputs": inputs
            })
    else:
        # Regex fallback (Less robust)
        # Look for <form ...> ... <input type="file" name="X"> ... </form>
        # This is very hard with regex, so we'll do a simpler check
        if 'type="file"' in html.lower():
            # Assume current URL has a form
            forms.append({
                "action": url, 
                "method": "POST", 
                "file_param": "file",  # Guess
                "inputs": []
            })
            
    return forms

def run(session, endpoints: List[str], results: Dict[str, Any], debug: bool = False, base_url: str = None) -> List[Dict[str, Any]]:
    findings = []
    checked_urls = set()

    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"[FileUpload] scanning {len(endpoints)} endpoints.")

    # 1. Identify Upload Forms
    upload_forms = []
    
    # Heuristic limit to avoid scanning static assets
    candidates = [
        u for u in endpoints 
        if not any(u.endswith(ext) for ext in 
                   ('.css', '.js', '.png', '.jpg', '.gif', '.woff', '.ttf', '.svg', '.ico'))
    ]

    for url in candidates:
        if url in checked_urls: continue
        checked_urls.add(url)
        
        try:
            resp = session.get(url, timeout=10)
            if _looks_like_upload_form(resp.text):
                found = _parse_upload_forms(url, resp.text)
                if found:
                    upload_forms.extend(found)
                    if debug: logger.debug(f"[FileUpload] Found upload form at {url}")
        except Exception:
            continue

    if not upload_forms:
        # [WS3] Fallback Probing
        common_paths = ["/upload", "/upload.php", "/fileupload", "/api/upload", "/v1/upload"]
        if debug: logger.info("[FileUpload] No forms found, probing common paths...")
        
        for path in common_paths:
             try:
                 # Probe
                 start = endpoints[0] if endpoints else base_url or "http://example.com" # Should have base_url from run()
                 target = urljoin(start, path)
                 if target in checked_urls: continue
                 
                 checked_urls.add(target)
                 resp = session.get(target, timeout=5)
                 if resp.status_code == 200 and _looks_like_upload_form(resp.text):
                      found = _parse_upload_forms(target, resp.text)
                      if found:
                           upload_forms.extend(found)
                           if debug: logger.info(f"[FileUpload] Discovered hidden upload form at {target}")
             except:
                 pass

    if not upload_forms:
        msg = "No file upload forms discovered or probed."
        if debug: logger.debug(msg)
        add_result("offensive", {"type": "File Upload", "severity": "Info", "reason": msg})
        return findings

    # 2. Attack Upload Forms
    for form in upload_forms:
        target_url = form['action']
        file_key = form['file_param']
        
        for payload in PAYLOADS:
            try:
                # Prepare files
                files = {
                    file_key: (payload['name'], payload['content'], payload['mime'])
                }
                
                # Prepare other data
                data = {
                    inp['name']: inp.get('value', 'test') 
                    for inp in form['inputs'] 
                    if inp['type'] != 'file'
                }
                
                if debug:
                    logger.debug(f"[FileUpload] Attacking {target_url} with {payload['name']}")

                # Send Request
                r = session.post(target_url, files=files, data=data, timeout=15)
                
                # Analyze Response
                # 1. Check status code (2xx usually means success)
                # 2. Check content for reflection of filename, implies upload might be successful
                # 3. Check for specific markers (WS_XSS_TEST, WS_PHP_EXEC_TEST) if we can find the file URL
                #    (Finding the uploaded file URL is the hardest part without complex parsing)

                evidence = {}
                is_vuln = False
                severity = "Info"
                
                if r.status_code in (200, 201):
                    # Check if filename is reflected in response
                    if payload['name'] in r.text:
                        evidence['reflected_filename'] = True
                        
                        # Try to find link to uploaded file
                        # Regex for common patterns: src=".../name", href=".../name"
                        # Simple naive check:
                        link_match = re.search(r'["\']([^"\']*/' + re.escape(payload['name']) + r')["\']', r.text)
                        
                        uploaded_url = None
                        if link_match:
                            uploaded_url = urljoin(target_url, link_match.group(1))
                            evidence['uploaded_url'] = uploaded_url
                        
                        # Phase 2: Verify Execution if we found the URL
                        if uploaded_url and payload['check'] != 'safe':
                            try:
                                v_resp = session.get(uploaded_url, timeout=10)
                                if payload['check'] == 'rce' and b'WS_PHP_EXEC_TEST' in v_resp.content:
                                    is_vuln = True
                                    severity = "Critical"
                                    evidence['execution'] = "PHP Code Executed"
                                elif payload['check'] == 'xss' and b'WS_XSS_TEST' in v_resp.content:
                                    # Check content-type
                                    ct = v_resp.headers.get('Content-Type', '').lower()
                                    if 'html' in ct:
                                        is_vuln = True
                                        severity = "High"
                                        evidence['execution'] = "Stored XSS via File Upload"
                                elif payload['check'] == 'polyglot' and b'WS_POLY' in v_resp.content:
                                     # Harder to verify execution without requesting as php, but good enough
                                     pass
                            except Exception:
                                pass
                                
                    else:
                         # Upload might be successful but silent
                         pass
                
                if is_vuln:
                    # Report
                    f = {
                        "type": "Unrestricted File Upload",
                        "severity": severity,
                        "url": target_url,
                        "payload": payload['name'],
                        "evidence": evidence
                    }
                    findings.append(f)
                    add_result("file_upload", f)
                    if debug: logger.info(f"[!] File Upload VULN: {target_url}")

            except Exception as e:
                logger.error(f"Error exploiting {target_url}: {e}")

    return findings
