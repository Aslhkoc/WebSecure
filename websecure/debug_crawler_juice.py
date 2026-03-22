
import sys
import os
import logging
import json

# Add project root to path
sys.path.insert(0, os.getcwd())

from websecure.crawler import WebCrawler, CrawlerConfig
from websecure.core.http import hardened_session

# Setup logging to console
logging.basicConfig(level=logging.DEBUG, format='[DEBUG] %(message)s')

def debug_juice():
    url = "https://juice-shop.herokuapp.com/#/"
    print(f"[*] Debugging Crawler on {url}")
    
    # Config similar to what we set in config.json
    cfg = CrawlerConfig(
        max_pages=10, # Keep it short
        browser_js_discovery=True,
        headless=True, # Visible=False for speed/debug, checking logic
        browser_timeout_ms=30000,
        browser_prefer="playwright"
    )
    
    sess = hardened_session()
    
    try:
        crawler = WebCrawler(sess, url, config=cfg, debug=True)
        print("[*] Crawler initialized. Starting...")
        results = crawler.start()
        
        print("\n" + "="*50)
        print("CRAWLER RESULTS SUMMARY")
        print("="*50)
        print(f"Endpoints Found: {len(results.get('endpoints', []))}")
        print(f"Forms Found: {len(results.get('forms_meta', []))}")
        print(f"API Params (JSON Keys): {len(results.get('param_candidates', set()))}")
        print(f"Secrets: {len(results.get('secrets', []))}")
        
        print("\n[-] Examples of Endpoints:")
        for e in list(results.get('endpoints', []))[:5]:
            print(f"  - {e}")
            
        print("\n[-] Examples of Params:")
        for p in list(results.get('param_candidates', set()))[:5]:
            print(f"  - {p}")
            
    except Exception as e:
        print(f"[!] CRASH: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_juice()
