
import sys
import os
import unittest
# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from websecure.core import chain_reactor
from websecure.core import reporting

class TestChainReactor(unittest.TestCase):
    def test_csrf_xss_chain(self):
        print("\nTESTING: Self-XSS + CSRF Chain...")
        results = {
            "xss_findings": [
                {"type": "Reflected XSS", "payload": "<script>alert(1)</script>", "severity": "Low"}
            ],
            "csrf_findings": [
                {"type": "CSRF", "url": "http://example.com/change-password", "severity": "High", "location": "Password Change"}
            ]
        }
        
        chain_reactor.analyze_chains(results)
        
        # Check global buckets instead of input dict
        chain_bucket = reporting.get_bucket_results().get("chain_reactor", [])
        
        # Clear buckets for next test
        reporting.reset()
        
        self.assertTrue(len(chain_bucket) > 0, "Chain Reactor failed to detect XSS+CSRF chain")
        
        finding = chain_bucket[0]
        print(f" [+] Detected: {finding['title']}")
        print(f" [+] Severity: {finding['severity']}")
        
        self.assertEqual(finding['severity'], 'Critical')
        self.assertIn("Account Takeover", finding['title'])

    def test_info_idor_chain(self):
        print("\nTESTING: Info Disclosure + IDOR Chain...")
        results = {
            "leaks": [
                {"type": "Information Leak", "severity": "Low", "url": "http://example.com/.git/HEAD"}
            ],
            "idor_findings": [
                {"type": "IDOR", "url": "http://example.com/user/123", "severity": "High"}
            ]
        }
        
        chain_reactor.analyze_chains(results)
        chain_bucket = reporting.get_bucket_results().get("chain_reactor", [])
        reporting.reset()
        self.assertTrue(len(chain_bucket) > 0, "Chain Reactor failed to detect Info+IDOR chain")
        
        finding = chain_bucket[0]
        print(f" [+] Detected: {finding['title']}")
        print(f" [+] Severity: {finding['severity']}")
        self.assertEqual(finding['severity'], 'High')

if __name__ == '__main__':
    unittest.main()
