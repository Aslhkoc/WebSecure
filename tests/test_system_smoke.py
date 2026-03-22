
import sys
import os
import importlib
import importlib.util
import logging

# Setup path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

# Setup basic logging
logging.basicConfig(level=logging.WARN)

print("Starting System Smoke Test...")
modules_to_test = [
    "websecure.scanners.csrf",
    "websecure.core.chain_reactor",
    "websecure.scanners.sqli",
    "websecure.scanners.xss",
    "websecure.scanners.nosqli",
    "websecure.scanners.ssrf_xxe",
    "websecure.scanners.rate_limit",
    "websecure.scanners.mass_assignment",
    "websecure.scanners.ws_fuzz",
    "websecure.core.reporting",
    "websecure.core.nuclei_integration"
]

failed = []
passed = []

for mod_name in modules_to_test:
    try:
        if mod_name == "websecure.core.nuclei_integration":
             # This might not exist if it's integrated into main/owasp directly, checking conditionally
             if importlib.util.find_spec(mod_name) is None:
                 print(f" [?] {mod_name} skipped (not a standalone module?)")
                 continue
                 
        importlib.import_module(mod_name)
        print(f" [OK] {mod_name} imported successfully")
        passed.append(mod_name)
    except Exception as e:
        print(f" [FAIL] {mod_name}: {e}")
        failed.append(mod_name)

print("\n--- Summary ---")
print(f"Passed: {len(passed)}")
print(f"Failed: {len(failed)}")

if failed:
    sys.exit(1)
else:
    sys.exit(0)
