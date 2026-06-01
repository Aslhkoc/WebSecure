"""
tests/test_chaining.py — Chain Reactor v3.0 Testleri

Kapsam:
  - XSS + CSRF → ATO / PrivEsc zincirleri
  - Info Disclosure + IDOR → Mass Leak zinciri
  - LFI → Log Poisoning → RCE (3-hop)
  - SQLi → Credential Dump → ATO (4-hop)
  - SSRF → Cloud Compromise
  - ExploitGraph düğüm / kenar yönetimi
  - CVSSChainCalculator formülü
  - analyze_chains() geriye uyumlu API
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from websecure.core import reporting
from websecure.core.chain_reactor import (
    ChainReactor,
    ExploitGraph,
    ExploitGraphBuilder,
    ChainNode,
    ChainEdge,
    CVSSChainCalculator,
    analyze_chains,
)


def _make_results(**buckets):
    """Test için kolayca results dict oluşturur."""
    return buckets


def _run_and_get_bucket(results: dict) -> list:
    """analyze_chains çalıştırır, tespit edilen zincir bulgularını döner.

    Zincirler 'vulnerability' bucket'ına raporlanır (dashboard/raporlar oradan
    okur — ayrı bir 'chain_reactor' bucket'ı yoktur). chain_id'si olan kayıtlar
    zincirdir; ham bulgular bucket'a eklenmez, bu yüzden filtre güvenlidir.
    """
    reporting.reset()
    analyze_chains(results)
    bucket = [f for f in reporting.get_bucket_results().get("vulnerability", [])
              if f.get("chain_id")]
    reporting.reset()
    return bucket


# ─────────────────────────────────────────────────────────────────────────────
# ExploitGraph testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestExploitGraph(unittest.TestCase):

    def _make_node(self, nid, vtype, sev="High", cvss=7.5):
        return ChainNode(
            node_id=nid, vuln_type=vtype,
            severity=sev, cvss=cvss,
            url=f"http://target.com/{nid}", raw={},
        )

    def test_add_and_retrieve_node(self):
        g = ExploitGraph()
        n = self._make_node("n1", "xss")
        g.add_node(n)
        self.assertEqual(g.get_node("n1").vuln_type, "xss")
        self.assertEqual(len(g.nodes()), 1)

    def test_add_edge_and_adjacency(self):
        g = ExploitGraph()
        n1 = self._make_node("n1", "xss")
        n2 = self._make_node("n2", "csrf")
        g.add_node(n1)
        g.add_node(n2)
        g.add_edge(ChainEdge("n1", "n2", "enables", 1.3))
        self.assertEqual(len(g.out_edges("n1")), 1)
        self.assertEqual(g.out_edges("n1")[0].target_id, "n2")
        self.assertEqual(len(g.in_edges("n2")), 1)

    def test_find_all_paths_direct(self):
        g = ExploitGraph()
        for nid in ["a", "b", "c"]:
            g.add_node(self._make_node(nid, "xss"))
        g.add_edge(ChainEdge("a", "b", "enables"))
        g.add_edge(ChainEdge("b", "c", "enables"))
        paths = g.find_all_paths("a", "c")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0], ["a", "b", "c"])

    def test_find_all_paths_no_cycle(self):
        """Döngülü yapıda sonsuz loop olmamalı."""
        g = ExploitGraph()
        for nid in ["x", "y"]:
            g.add_node(self._make_node(nid, "sqli"))
        g.add_edge(ChainEdge("x", "y", "enables"))
        g.add_edge(ChainEdge("y", "x", "enables"))  # back-edge
        paths = g.find_all_paths("x", "y", max_depth=4)
        # Döngüsüz en az bir yol bulunmalı
        self.assertGreaterEqual(len(paths), 1)

    def test_topological_sort(self):
        g = ExploitGraph()
        for nid, t in [("lfi", "lfi"), ("poison", "log_poisoning"), ("rce", "rce")]:
            g.add_node(self._make_node(nid, t))
        g.add_edge(ChainEdge("lfi", "poison", "enables"))
        g.add_edge(ChainEdge("poison", "rce", "enables"))
        order = g.topological_sort()
        self.assertEqual(order.index("lfi"),    0)
        self.assertEqual(order.index("poison"), 1)
        self.assertEqual(order.index("rce"),    2)


# ─────────────────────────────────────────────────────────────────────────────
# CVSSChainCalculator testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestCVSSChainCalculator(unittest.TestCase):

    def test_combined_single_score(self):
        result = CVSSChainCalculator.combined([7.5])
        self.assertAlmostEqual(result, 7.5)

    def test_combined_two_scores_amplified(self):
        result = CVSSChainCalculator.combined([7.5, 9.5], [1.3])
        # base=9.5, amplification=1.3*0.15=0.195 → 9.695 → round → 9.7
        self.assertAlmostEqual(result, 9.7)

    def test_combined_capped_at_10(self):
        result = CVSSChainCalculator.combined([9.8, 9.9, 9.7], [1.5, 1.5])
        self.assertLessEqual(result, 10.0)

    def test_combined_empty(self):
        self.assertEqual(CVSSChainCalculator.combined([]), 0.0)

    def test_vector_string_format(self):
        vec = CVSSChainCalculator.vector_string()
        self.assertTrue(vec.startswith("CVSS:3.1/"))
        self.assertIn("/AV:N/", vec)

    def test_score_for_severity(self):
        self.assertEqual(CVSSChainCalculator.score_for_severity("Critical"), 9.5)
        self.assertEqual(CVSSChainCalculator.score_for_severity("High"),     7.5)
        self.assertEqual(CVSSChainCalculator.score_for_severity("Medium"),   5.0)
        self.assertEqual(CVSSChainCalculator.score_for_severity("Low"),      2.5)
        self.assertEqual(CVSSChainCalculator.score_for_severity("Info"),     0.0)


# ─────────────────────────────────────────────────────────────────────────────
# ExploitGraphBuilder testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestExploitGraphBuilder(unittest.TestCase):

    def test_normalizes_xss_type(self):
        builder = ExploitGraphBuilder()
        results = {
            "findings": [
                {"type": "Reflected XSS", "severity": "High", "url": "http://t.com/a"},
            ]
        }
        graph = builder.build(results)
        nodes = graph.nodes()
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].vuln_type, "xss")

    def test_normalizes_sqli_type(self):
        builder = ExploitGraphBuilder()
        results = {"f": [{"type": "SQL Injection", "severity": "Critical", "url": "http://t.com"}]}
        graph = builder.build(results)
        self.assertEqual(graph.nodes()[0].vuln_type, "sqli")

    def test_cvss_extracted_from_field(self):
        builder = ExploitGraphBuilder()
        results = {"f": [{"type": "XSS", "severity": "Low", "url": "http://t.com", "cvss": 8.5}]}
        graph = builder.build(results)
        self.assertAlmostEqual(graph.nodes()[0].cvss, 8.5)

    def test_cvss_fallback_from_severity(self):
        builder = ExploitGraphBuilder()
        results = {"f": [{"type": "XSS", "severity": "High", "url": "http://t.com"}]}
        graph = builder.build(results)
        self.assertAlmostEqual(graph.nodes()[0].cvss, 7.5)

    def test_skips_non_dict_findings(self):
        builder = ExploitGraphBuilder()
        results = {"f": ["not_a_dict", 42, None]}
        graph = builder.build(results)
        self.assertEqual(len(graph.nodes()), 0)


# ─────────────────────────────────────────────────────────────────────────────
# ChainReactor — 2-Hop Zincir Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestChainReactorTwoHop(unittest.TestCase):

    def test_xss_csrf_chain_detected(self):
        """XSS + CSRF → en az bir Critical zincir tespit edilmeli."""
        print("\nTESTING: XSS + CSRF → ATO / PrivEsc Chain...")
        results = _make_results(
            xss_findings=[
                {"type": "Reflected XSS", "severity": "High",
                 "url": "http://example.com/search"},
            ],
            csrf_findings=[
                {"type": "CSRF", "severity": "High",
                 "url": "http://example.com/change-password"},
            ],
        )
        bucket = _run_and_get_bucket(results)
        self.assertGreater(len(bucket), 0, "XSS+CSRF zinciri tespit edilemedi")

        # En az bir Critical bulgu olmalı
        critical = [f for f in bucket if f.get("severity") == "Critical"]
        self.assertGreater(len(critical), 0, "Critical zincir bulunamadı")

        finding = critical[0]
        print(f" [+] Tespit: {finding['title']}")
        print(f" [+] Severity: {finding['severity']}, CVSS: {finding['cvss_score']}")
        self.assertIn("XSS", finding["title"])

    def test_info_disclosure_idor_chain(self):
        """Info Disclosure + IDOR → High zincir tespit edilmeli."""
        print("\nTESTING: Info Disclosure + IDOR → Mass Data Leak...")
        results = _make_results(
            leaks=[
                {"type": "Information Leak", "severity": "Low",
                 "url": "http://example.com/.git/HEAD"},
            ],
            idor_findings=[
                {"type": "IDOR", "severity": "High",
                 "url": "http://example.com/api/user/123"},
            ],
        )
        bucket = _run_and_get_bucket(results)
        self.assertGreater(len(bucket), 0, "Info+IDOR zinciri tespit edilemedi")

        finding = bucket[0]
        print(f" [+] Tespit: {finding['title']}")
        print(f" [+] Severity: {finding['severity']}, CVSS: {finding['cvss_score']}")
        self.assertIn(finding["severity"], ("Critical", "High"))

    def test_ssrf_cloud_compromise_chain(self):
        """SSRF + cloud metadata kanıtı → Critical zincir."""
        print("\nTESTING: SSRF → Cloud Metadata Compromise...")
        results = _make_results(
            ssrf_findings=[
                {"type": "SSRF", "severity": "Critical",
                 "url": "http://example.com/proxy",
                 "evidence": "Connected to 169.254.169.254/latest/meta-data/iam/"},
            ],
        )
        bucket = _run_and_get_bucket(results)
        cloud_chains = [f for f in bucket if "cloud" in f.get("chain_id", "").lower()
                        or "Cloud" in f.get("title", "")]
        self.assertGreater(len(cloud_chains), 0, "SSRF→Cloud zinciri tespit edilemedi")
        self.assertEqual(cloud_chains[0]["severity"], "Critical")

    def test_upload_lfi_rce_chain(self):
        """File Upload + LFI → RCE zinciri."""
        print("\nTESTING: Upload + LFI → RCE...")
        results = _make_results(
            upload_findings=[
                {"type": "File Upload", "severity": "High",
                 "url": "http://example.com/upload"},
            ],
            lfi_findings=[
                {"type": "LFI", "severity": "High",
                 "url": "http://example.com/read?file=../etc/passwd"},
            ],
        )
        bucket = _run_and_get_bucket(results)
        rce_chains = [f for f in bucket if "rce" in f.get("chain_id", "").lower()
                      or "RCE" in f.get("title", "")]
        self.assertGreater(len(rce_chains), 0, "Upload+LFI→RCE zinciri tespit edilemedi")
        self.assertEqual(rce_chains[0]["severity"], "Critical")


# ─────────────────────────────────────────────────────────────────────────────
# ChainReactor — 3-Hop & 4-Hop Zincir Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestChainReactorMultiHop(unittest.TestCase):

    def test_lfi_log_poisoning_rce_chain(self):
        """LFI → Log Poisoning → RCE (3-hop) zinciri."""
        print("\nTESTING: LFI → Log Poisoning → RCE (3-hop)...")
        results = _make_results(
            lfi_findings=[
                {"type": "LFI", "severity": "High",
                 "url": "http://example.com/page?file=../etc/passwd",
                 "evidence": "root:x:0:0 accessed via /var/log/apache2/access.log"},
            ],
        )
        bucket = _run_and_get_bucket(results)
        lfi_chains = [f for f in bucket if "log_poison" in f.get("chain_id", "")]
        self.assertGreater(len(lfi_chains), 0, "LFI→LogPoison→RCE zinciri tespit edilemedi")

        finding = lfi_chains[0]
        print(f" [+] Tespit: {finding['title']}")
        print(f" [+] Zincir uzunluğu: {finding['chain_length']}")
        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["chain_length"], 3)

    def test_sqli_cred_dump_ato_chain(self):
        """SQLi → Credential Dump → Password Reuse → ATO (4-hop) zinciri."""
        print("\nTESTING: SQLi → Cred Dump → Password Reuse → ATO (4-hop)...")
        results = _make_results(
            sqli_findings=[
                {"type": "SQL Injection", "severity": "Critical",
                 "url": "http://example.com/login?id=1"},
            ],
        )
        bucket = _run_and_get_bucket(results)
        sqli_chains = [f for f in bucket if "cred_dump" in f.get("chain_id", "")]
        self.assertGreater(len(sqli_chains), 0, "SQLi→ATO (4-hop) zinciri tespit edilemedi")

        finding = sqli_chains[0]
        print(f" [+] Tespit: {finding['title']}")
        print(f" [+] CVSS: {finding['cvss_score']}, Zincir uzunluğu: {finding['chain_length']}")
        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["chain_length"], 4)
        self.assertGreaterEqual(finding["cvss_score"], 9.0)

    def test_xss_csrf_privesc_chain(self):
        """XSS → CSRF → Privilege Escalation (3-hop) zinciri."""
        print("\nTESTING: XSS → CSRF → PrivEsc (3-hop)...")
        results = _make_results(
            xss_f=[
                {"type": "Stored XSS", "severity": "High",
                 "url": "http://example.com/comment"},
            ],
            csrf_f=[
                {"type": "CSRF", "severity": "High",
                 "url": "http://example.com/admin/promote"},
            ],
        )
        bucket = _run_and_get_bucket(results)
        privesc_chains = [f for f in bucket if "privesc" in f.get("chain_id", "")]
        self.assertGreater(len(privesc_chains), 0, "XSS→CSRF→PrivEsc zinciri tespit edilemedi")

        finding = privesc_chains[0]
        print(f" [+] Tespit: {finding['title']}")
        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["chain_length"], 3)

    def test_sqli_admin_filewrite_rce_chain(self):
        """SQLi(Critical) → Admin Bypass → File Write → RCE (4-hop) zinciri."""
        print("\nTESTING: SQLi → Admin Bypass → FileWrite → RCE (4-hop)...")
        results = _make_results(
            sqli_f=[
                {"type": "Union SQL Injection", "severity": "Critical",
                 "url": "http://example.com/product?id=1"},
            ],
        )
        bucket = _run_and_get_bucket(results)
        fw_chains = [f for f in bucket if "filewrite" in f.get("chain_id", "")]
        self.assertGreater(len(fw_chains), 0, "SQLi→FileWrite→RCE zinciri tespit edilemedi")
        self.assertEqual(fw_chains[0]["chain_length"], 4)


# ─────────────────────────────────────────────────────────────────────────────
# ChainReactor — Genel Davranış Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestChainReactorBehavior(unittest.TestCase):

    def test_no_false_positive_with_empty_results(self):
        """Boş results → hiç zincir tetiklenmemeli."""
        bucket = _run_and_get_bucket({})
        self.assertEqual(len(bucket), 0, "Boş bulgulardan yanlış zincir oluştu")

    def test_no_chain_without_required_type(self):
        """Yalnızca XSS varsa CSRF gerektiren zincir tetiklenmemeli."""
        results = _make_results(
            xss_findings=[
                {"type": "XSS", "severity": "High", "url": "http://example.com/"},
            ],
        )
        reporting.reset()
        analyze_chains(results)
        bucket = [f for f in reporting.get_bucket_results().get("vulnerability", [])
                  if f.get("chain_id")]
        reporting.reset()

        # CSRF yoksa xss_csrf_* zincirleri tetiklenmemeli
        csrf_chains = [f for f in bucket if "csrf" in f.get("chain_id", "")]
        self.assertEqual(len(csrf_chains), 0)

    def test_chain_finding_has_required_fields(self):
        """Her zincir bulgusu zorunlu alanları içermeli."""
        results = _make_results(
            sqli=[
                {"type": "SQL Injection", "severity": "Critical",
                 "url": "http://example.com/q"},
            ],
        )
        bucket = _run_and_get_bucket(results)
        self.assertGreater(len(bucket), 0)
        for finding in bucket:
            for field in ("title", "severity", "cvss_score", "chain_id",
                          "description", "node_types", "chain_length"):
                self.assertIn(field, finding, f"Eksik alan: {field}")

    def test_cvss_score_in_valid_range(self):
        """Tüm zincir CVSS skorları 0–10 arasında olmalı."""
        results = _make_results(
            sqli=[{"type": "SQL Injection", "severity": "Critical",
                   "url": "http://t.com/x"}],
            lfi=[{"type": "LFI", "severity": "High", "url": "http://t.com/y"}],
            xss=[{"type": "XSS", "severity": "High", "url": "http://t.com/z"}],
            csrf=[{"type": "CSRF", "severity": "High", "url": "http://t.com/w"}],
        )
        bucket = _run_and_get_bucket(results)
        for finding in bucket:
            cvss = finding.get("cvss_score", -1)
            self.assertGreaterEqual(cvss, 0.0, f"CVSS < 0: {cvss}")
            self.assertLessEqual(cvss, 10.0,   f"CVSS > 10: {cvss}")

    def test_analyze_chains_backward_compat(self):
        """analyze_chains() eski API uyumluluğu — exception fırlatmamalı."""
        try:
            analyze_chains({
                "xss_findings": [{"type": "XSS", "severity": "High",
                                   "url": "http://example.com/"}],
                "csrf_findings": [{"type": "CSRF", "severity": "High",
                                   "url": "http://example.com/action"}],
            })
        except Exception as exc:
            self.fail(f"analyze_chains() beklenmeyen exception: {exc!r}")
        finally:
            reporting.reset()


if __name__ == "__main__":
    unittest.main(verbosity=2)
