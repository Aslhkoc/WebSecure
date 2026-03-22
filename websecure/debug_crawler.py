
import sys
import logging
import os

import sys
import logging
import os

# Adjust path to find websecure package (parent of current dir)
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), "..")))

from websecure.main import discover_dynamic_endpoints
from websecure.crawler import WebCrawler, CrawlerConfig
from websecure.core.http import hardened_session

def test_crawler():
    url = "https://animecix.tv"
    print(f"Testing Crawler on {url}...")
    
    # 1. Test Dynamic Discovery (Browser)
    print("\n--- [1] Browser Discovery (Headless) ---")
    try:
        eps, artifacts = discover_dynamic_endpoints(
            url, 
            headless=True, 
            timeout_ms=30000, 
            max_pages=20, 
            prefer="selenium",
            record_dir="./debug_artifacts"
        )
        print(f"Browser found {len(eps)} endpoints.")
        for e in eps[:5]:
            print(f" - {e}")
    except Exception as e:
        print(f"Browser Discovery FAILED: {e}")
        import traceback
        traceback.print_exc()

    # 2. Test Static Crawler (WebCrawler class)
    print("\n--- [2] Static/Requests Crawler ---")
    try:
        session = hardened_session()
        cfg = CrawlerConfig(max_depth=2, max_pages=20)
        wc = WebCrawler(session, url, config=cfg, debug=True)
        res = wc.start()
        
        eps = res.get("endpoints", [])
        forms = res.get("forms_meta", [])
        
        print(f"Static found {len(eps)} endpoints and {len(forms)} forms.")
        for f in forms:
            print(f" - Form: {f.get('action') or f.get('page')} (Inputs: {len(f.get('inputs', []))})")
            
    except Exception as e:
        print(f"Static Crawler FAILED: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    test_crawler()
