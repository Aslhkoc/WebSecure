
import sys

print("[*] Verifying Scanner Payload Loading...")

try:
    # 1. Check SQLi
    from websecure.scanners.sqli import SQLI_PAYLOADS
    print(f"SQLi: {len(SQLI_PAYLOADS)} payloads")
    
    # 2. Check XSS
    from websecure.scanners.xss import XSS_PAYLOADS
    print(f"XSS: {len(XSS_PAYLOADS)} payloads")
    
    # 3. Check NoSQLi
    from websecure.scanners.nosqli import URL_PAYLOADS, NOSQL_PAYLOADS
    print(f"NoSQLi: {len(URL_PAYLOADS) + len(NOSQL_PAYLOADS)} payloads")

    # 4. Check GraphQL
    from websecure.scanners.graphql import FUZZ_QUERIES
    print(f"GraphQL: {len(FUZZ_QUERIES)} fuzz queries")

    if len(SQLI_PAYLOADS) > 30 and len(XSS_PAYLOADS) > 30 and (len(URL_PAYLOADS) + len(NOSQL_PAYLOADS)) > 20:
        print("\n[SUCCESS] All core scanners are using extended wordlists!")
    else:
        print("\n[FAIL] Some scanners are still using defaults.")
        
except Exception as e:
    print(f"\n[ERROR] Verification crashed: {e}")
