"""
websecure.scanners.auth
-----------------------
Consolidated module for:
- Authenticated Session Management (formerly authenticated_scan.py)
- Authorization Testing & IDOR (formerly authorization.py)
"""
from __future__ import annotations
import re
import time
import json
import base64
import logging
import copy
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urljoin
from difflib import SequenceMatcher

import requests
from websecure.core.http import hardened_session
from websecure.core.reporting import add_result, redact_sensitive

_logger = logging.getLogger(__name__)

# ============================================================================
# SECTION 1: AUTHENTICATED SESSION (formerly authenticated_scan.py)
# ============================================================================

@dataclass
class AuthContext:
    is_authenticated: bool = False
    user: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    token: Optional[str] = None  # Bearer/JWT
    last_login_ts: float = 0.0

class AuthenticatedSession:
    def __init__(self, base_url: str, login_path: str = "/login", *, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.login_path = login_path
        self.verify_tls = bool(verify_tls)
        self.session = hardened_session({})
        self.session.verify = self.verify_tls
        self.ctx = AuthContext()
        
    def login(self, username: str, password: str, csrf_selector: Optional[str] = None) -> bool:
        target = urljoin(self.base_url + "/", self.login_path.lstrip("/"))
        try:
            r = self.session.get(target, timeout=15)
        except Exception:
            return False
            
        data = {"username": username, "password": password}
        # basic csrf extraction logic
        if csrf_selector and r.ok:
            m = re.search(csrf_selector, r.text or "")
            if m:
                val = m.group(1) if m.groups() else m.group(0)
                # naive assumption: extracting value to inject? 
                # usually we need key name too. assuming user provided enough info or we use common names.
                # keeping simple for now.
                pass
                
        try:
            r2 = self.session.post(r.url, data=data, timeout=20)
        except Exception:
            return False
            
        if r2.status_code < 400:
            self.ctx.is_authenticated = True
            self.ctx.last_login_ts = time.time()
            
            # Token extraction
            tok = None
            if "json" in r2.headers.get("content-type", ""):
                try:
                    j = r2.json()
                    tok = j.get("token") or j.get("access_token")
                except: pass
            
            if not tok:
                # Cookie fallback
                pass # Already in session cookies
                
            self.ctx.token = tok
            return True
        return False
        
    def get(self, path, **kwargs):
        url = urljoin(self.base_url + "/", path.lstrip("/")) if not path.startswith("http") else path
        hdr = kwargs.pop("headers", {}) or {}
        if self.ctx.token: hdr["Authorization"] = f"Bearer {self.ctx.token}"
        return self.session.get(url, headers=hdr, **kwargs)

    def proof(self, resp: requests.Response) -> Dict[str, Any]:
        return redact_sensitive({
            "url": resp.request.url,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body_snippet": (resp.text or "")[:500]
        })

# ============================================================================
# SECTION 2: AUTHORIZATION & IDOR (formerly authorization.py)
# ============================================================================

@dataclass
class RoleProfile:
    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

@dataclass
class RoleContext:
    base: requests.Session
    roles: List[RoleProfile]
    
    def build_sessions(self) -> Dict[str, requests.Session]:
        sessions = {}
        # Anonymous
        anon = hardened_session({}); anon.verify = self.base.verify
        sessions["anonymous"] = anon
        
        for rp in self.roles:
            s = hardened_session({}); s.verify = self.base.verify
            # Copy base headers excluding auth
            for k,v in self.base.headers.items():
                if k.lower() not in ("authorization", "cookie"): s.headers[k] = v
            # Apply role specific
            s.headers.update(rp.headers)
            for k,v in rp.cookies.items(): s.cookies.set(k,v)
            sessions[rp.name] = s
        return sessions

def compare_roles(url: str, sessions: Dict[str, requests.Session]) -> List[Dict[str, Any]]:
    findings = []
    responses = {}
    
    for name, s in sessions.items():
        try:
            r = s.get(url, timeout=10)
            responses[name] = r
        except:
            responses[name] = None
            
    # Simple logic: if anon gets 200 and admin gets 200 and bodies represent sensitive data...
    # For now, just simplistic status check
    r_anon = responses.get("anonymous")
    r_admin = responses.get("admin") or responses.get("root")
    
    if r_anon and r_admin and r_anon.status_code == 200 and r_admin.status_code == 200:
        sim = SequenceMatcher(None, r_anon.text, r_admin.text).ratio()
        if sim > 0.95:
            findings.append({
                "type": "Broken Access Control",
                "url": url,
                "severity": "High",
                "detail": f"Anonymous user sees same content as Admin (sim={sim:.2f})"
            })
            
    return findings

def check_idor(sessions: Dict[str, requests.Session], url: str) -> List[Dict[str, Any]]:
    findings = []
    # Heuristic: look for numeric ID in URL
    m = re.search(r"/(\d+)(?:/|$)", url)
    if not m: return findings
    
    orig_id = m.group(1)
    new_id = str(int(orig_id) + 1)
    new_url = url.replace(orig_id, new_id)
    
    # Try with low priv user
    user_role = next((r for r in sessions if r not in ("admin", "root", "anonymous")), None)
    if not user_role: return findings
    
    s = sessions[user_role]
    try:
        r = s.get(new_url, timeout=10)
        if r.status_code == 200:
            # Check if it looks like valid data, not an error page tailored as 200
            if "error" not in r.text.lower() and "not found" not in r.text.lower():
                findings.append({
                    "type": "IDOR",
                    "url": new_url,
                    "severity": "High",
                    "detail": f"User '{user_role}' accessed ID {new_id}"
                })
    except:
        pass
        
    return findings

def probe_auth_only(session: requests.Session, method: str, url: str) -> Optional[Dict[str, Any]]:
    # Clone anon
    anon = hardened_session({})
    anon.verify = session.verify
    
    try:
        r_auth = session.request(method, url, timeout=10)
        r_anon = anon.request(method, url, timeout=10)
        
        if r_auth.status_code == 200 and r_anon.status_code in (401, 403):
             return {
                 "type": "Auth Only Resource",
                 "url": url,
                 "severity": "Info",
                 "detail": "Resource requires authentication."
             }
    except:
        pass
    return None
