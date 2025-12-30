import time
import logging
import requests
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)

class DeviceCodeAuth:
    """
    RFC 8628 OAuth 2.0 Device Authorization Grant implementation.
    Used for 'Assisted Auth': User authorizes the scan on another device/browser.
    """
    def __init__(self, client_id: str, device_auth_url: str, token_url: str, 
                 scope: str = "openid profile", client_secret: Optional[str] = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.device_auth_url = device_auth_url
        self.token_url = token_url
        self.scope = scope
        self.session = requests.Session()

    def authenticate(self) -> Optional[Dict[str, Any]]:
        """
        Executes the full Device Flow:
        1. Request device code.
        2. Display code to user (Assisted).
        3. Poll for access token.
        """
        # 1. Start Device Auth
        resp_data = self._initiate_auth()
        if not resp_data:
            return None

        device_code = resp_data.get("device_code")
        user_code = resp_data.get("user_code")
        verification_uri = resp_data.get("verification_uri") or resp_data.get("verification_uri_complete")
        interval = int(resp_data.get("interval", 5))
        expires_in = int(resp_data.get("expires_in", 300))

        if not device_code or not user_code or not verification_uri:
            logger.error("Invalid device auth response.")
            return None

        # 2. User Interaction
        print("\n" + "="*60)
        print("ASSISTED AUTHENTICATION REQUIRED")
        print(f"Please visit: {verification_uri}")
        print(f"And enter code: {user_code}")
        print("="*60 + "\n")
        logger.info(f"Waiting for user to authorize with code: {user_code}")

        # 3. Poll for Token
        return self._poll_for_token(device_code, interval, expires_in)

    def _initiate_auth(self) -> Optional[Dict]:
        """Step 1: POST to device_authorization_endpoint"""
        data = {
            "client_id": self.client_id,
            "scope": self.scope
        }
        try:
            r = self.session.post(self.device_auth_url, data=data, timeout=10)
            if r.status_code == 200:
                return r.json()
            else:
                logger.error(f"Device auth init failed ({r.status_code}): {r.text}")
        except Exception as e:
            logger.error(f"Device auth connection error: {e}")
        return None

    def _poll_for_token(self, device_code: str, interval: int, expires_in: int) -> Optional[Dict]:
        """Step 2: Loop POST to token_endpoint until success or timeout"""
        deadline = time.time() + expires_in
        
        while time.time() < deadline:
            time.sleep(interval)
            
            data = {
                "client_id": self.client_id,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code
            }
            if self.client_secret:
                data["client_secret"] = self.client_secret

            try:
                r = self.session.post(self.token_url, data=data, timeout=10)
                resp = r.json()

                if r.status_code == 200 and "access_token" in resp:
                    logger.info("Device auth successful! Token received.")
                    return resp
                
                error = resp.get("error")
                if error == "authorization_pending":
                    pass # Continue waiting
                elif error == "slow_down":
                    interval += 5 # Backoff
                elif error in ["access_denied", "expired_token"]:
                    logger.warning(f"Device auth failed: {error}")
                    return None
                else:
                    logger.warning(f"Unexpected device auth error: {error}")
                    
            except Exception as e:
                logger.debug(f"Polling error: {e}")
        
        logger.error("Device auth timed out.")
        return None
