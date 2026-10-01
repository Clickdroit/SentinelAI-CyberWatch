import unittest
from sentinel.db import SentinelDB
from sentinel.collectors import ThreatFeedCollector, CVE_PATTERN
from sentinel.ai import SecurityAnalystAI

class TestSentinelAI(unittest.TestCase):
    def setUp(self):
        self.db = SentinelDB(":memory:")

    def tearDown(self):
        self.db.close()

    def test_cve_regex(self):
        sample = "Avis CERTFR concernant CVE-2024-12345 et CVE-2023-9999"
        cves = CVE_PATTERN.findall(sample)
        self.assertEqual(len(cves), 2)
        self.assertIn("CVE-2024-12345", cves)
        self.assertIn("CVE-2023-9999", cves)

    def test_db_advisory_storage(self):
        adv = {
            "id": "ALERT-001",
            "title": "Alerte Critique Linux Kernel",
            "link": "https://example.com/alert-001",
            "published_date": "2026-10-01",
            "cves": ["CVE-2026-1111"],
            "cvss_score": 9.8,
            "summary": "Impact critique sur le noyau.",
            "notified": True
        }
        self.assertFalse(self.db.is_processed("ALERT-001"))
        self.db.save_advisory(adv)
        self.assertTrue(self.db.is_processed("ALERT-001"))

        recent = self.db.get_recent(5)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["cvss_score"], 9.8)

    def test_cvss_estimation(self):
        score_crit = ThreatFeedCollector.estimate_cvss("Exécution de code à distance", "Faillle critique RCE", ["CVE-2026-1000"])
        self.assertEqual(score_crit, 9.8)

        score_info = ThreatFeedCollector.estimate_cvss("Mise à jour mineure", "Information", [])
        self.assertEqual(score_info, 4.0)

    def test_ai_fallback_summary(self):
        ai = SecurityAnalystAI(ollama_endpoint="http://invalid-host:99999")
        summary = ai.summarize_advisory("Test Title", "Test Desc", ["CVE-2026-1234"])
        self.assertIn("Impact", summary)
        self.assertIn("Remédiation", summary)

if __name__ == "__main__":
    unittest.main()
