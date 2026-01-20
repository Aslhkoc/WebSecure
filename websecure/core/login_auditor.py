
import requests
import time
import logging
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("websec")

class LoginAuditor:
    def __init__(self, session, target_url, wordlist_path):
        self.session = session
        self.target = target_url
        self.wordlist_path = wordlist_path
        self.found_forms = []
        self.max_attempts = 1000 # Safety cap
        self.concurrency = 10

    def discover_forms(self, html_content, page_url):
        # Heuristic detection of login forms
        # Look for <form> with input type=password
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            for f in forms:
                inputs = f.find_all('input')
                has_pass = any(i.get('type') == 'password' for i in inputs)
                if has_pass:
                    action = f.get('action') or ''
                    full_action = urljoin(page_url, action)
                    method = (f.get('method') or 'POST').upper()
                    
                    # Extract input names
                    user_field = None
                    pass_field = None
                    csrf_token = {}
                    
                    for i in inputs:
                        name = i.get('name')
                        if not name: continue
                        itype = i.get('type')
                        val = i.get('value')
                        
                        if itype == 'password':
                            pass_field = name
                        elif itype in ['text', 'email'] and not user_field:
                             # Guess user field
                             if any(x in name.lower() for x in ['user', 'mail', 'login', 'id']):
                                 user_field = name
                        elif itype == 'hidden':
                             csrf_token[name] = val
                    
                    # Fallback user field guess
                    if not user_field:
                         # Pick first text input that isn't password
                         for i in inputs:
                             if i.get('type') in ['text', 'email'] and i.get('name'):
                                 user_field = i.get('name')
                                 break

                    if user_field and pass_field:
                        logger.info(f"[Login-Auditor] Login Form Detected at {page_url}")
                        self.found_forms.append({
                            "url": full_action,
                            "method": method,
                            "user_field": user_field,
                            "pass_field": pass_field,
                            "extra": csrf_token,
                            "referer": page_url
                        })
        except Exception as e:
            logger.error(f"[Login-Auditor] Detection error: {e}")

    def run_audit(self):
        if not self.found_forms:
            return []

        if not self.wordlist_path:
             logger.warning("[Login-Auditor] No password list provided.")
             return []

        passwords = []
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [l.strip() for l in f if l.strip()]
        except Exception:
            passwords = ["admin", "123456", "password", "admin123"] # Fallback
            
        # Limit
        passwords = passwords[:self.max_attempts]
        
        results = []
        
        for form in self.found_forms:
            logger.info(f"[Login-Auditor] Auditing form at {form['url']} with {len(passwords)} passwords.")
            
            # Try a few common usernames
            usernames = ["admin", "administrator", "root", "user", "test"]
            
            # Simple strategy: Brute force 'admin' first, then others if requested
            # For 1000 pwd, we'll stick to 'admin' + 1-2 others to avoid massive spam
            
            target_users = ["admin"]
            
            for user in target_users:
                found = self._brute_user(form, user, passwords)
                if found:
                    results.append(found)
                    break # Stop if we cracked one user on this form
                    
        return results

    def _brute_user(self, form, user, passwords):
        # Threaded brute force
        # Success criteria: 
        # - Status 302/303 Redirect
        # - Content length change significantly? (hard to detect in batch)
        # - Body contains "Welcome", "Dashboard", "Logout"
        
        # Baseline request
        base_resp = self._attempt(form, "dummy_invalid_user", "dummy_invalid_pass")
        fail_len = len(base_resp.text)
        fail_code = base_resp.status_code
        
        for pwd in passwords:
            resp = self._attempt(form, user, pwd)
            
            # Analysis
            is_success = False
            
            # 1. Status Code Difference (e.g. 302 vs 200)
            if resp.status_code != fail_code and resp.status_code in [302, 303]:
                 is_success = True
                 reason = f"Status changed ({fail_code} -> {resp.status_code})"
                 
            # 2. Keyword detection
            block = resp.text.lower()
            if "logout" in block or "sign out" in block or "dashboard" in block:
                 # Check if baseline had it (false positive check)
                 if "logout" not in base_resp.text.lower():
                      is_success = True
                      reason = "Logout keyword found"
            
            # 3. Invalid credentials message missing?
            error_msgs = ["invalid password", "wrong user", "hata", "giriş başarısız"]
            if any(e in base_resp.text.lower() for e in error_msgs):
                 if not any(e in block for e in error_msgs):
                      is_success = True
                      reason = "Error message disappeared"

            if is_success:
                logger.critical(f"[Login-Auditor] CRACKED! User: {user} | Pass: {pwd} | Reason: {reason}")
                
                # [WS3] Register Session
                try:
                    from websecure.core.reporting import add_session
                    cookies = resp.cookies.get_dict()
                    add_session(user, cookies, origin_url=form['url'])
                except Exception as e:
                    logger.error(f"Failed to register session: {e}")

                return {
                    "type": "Weak Credentials",
                    "severity": "Critical",
                    "url": form['url'],
                    "param": f"{form['user_field']}={user}",
                    "payload": pwd,
                    "evidence": {
                        "username": user,
                        "password": pwd,
                        "reason": reason,
                        "mechanism": "Brute-Force"
                    }
                }
            
            # Be polite
            time.sleep(0.05) 
            
        return None

    def _attempt(self, form, u, p):
        data = form['extra'].copy()
        data[form['user_field']] = u
        data[form['pass_field']] = p
        
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Referer": form['referer']
        }
        
        try:
            if form['method'] == 'POST':
                return self.session.post(form['url'], data=data, headers=headers, allow_redirects=False)
            else:
                return self.session.get(form['url'], params=data, headers=headers, allow_redirects=False)
        except Exception:
            # dummy obj
            class Dummy:
                status_code = 999
                text = ""
            return Dummy()
