
from websecure.scanners.sqli import SQLI_PAYLOADS
from websecure.scanners.xss import XSS_PAYLOADS
from websecure.core.payloads import load_external_payloads

print(f"SQLi Payload Count: {len(SQLI_PAYLOADS)}")
print(f"XSS Payload Count: {len(XSS_PAYLOADS)}")

if len(SQLI_PAYLOADS) > 20: 
    print("[SUCCESS] SQLi loaded external wordlists.")
else:
    print("[FAIL] SQLi using only hardcoded defaults.")

if len(XSS_PAYLOADS) > 20:
    print("[SUCCESS] XSS loaded external wordlists.")
else:
    print("[FAIL] XSS using only hardcoded defaults.")
