import unittest
from app.ai_engine import analyze_logs, cve_remediation_advice

class AiEngineTests(unittest.TestCase):
    def test_detects_security_log_patterns(self):
        report = analyze_logs([
            {"message": "EventID=1102 Security audit log cleared", "source": "Windows Security"},
            {"message": "ordinary service started", "source": "System"},
            {"message": "EventID=4625 failed password", "source": "Windows Security"},
        ])
        self.assertEqual(report["events_reviewed"], 3)
        self.assertEqual(report["findings_total"], 2)
        self.assertEqual(report["severity_counts"]["critical"], 1)
        self.assertEqual(report["severity_counts"]["medium"], 1)

    def test_cve_advice_never_runs_automatic_remediation(self):
        advice = cve_remediation_advice("CVE-2024-12345", "high", "Example", "1.0", "Example issue")
        self.assertFalse(advice["automatic_remediation"])
        self.assertTrue(advice["validation_required"])

    def test_invalid_cve_does_not_create_reference(self):
        advice = cve_remediation_advice("NOT-A-CVE", "unknown", "Example", "", "")
        self.assertEqual(advice["references"], [])

if __name__ == "__main__":
    unittest.main()
