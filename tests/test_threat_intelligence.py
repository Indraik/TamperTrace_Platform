import unittest
from unittest.mock import patch
from app.services.virustotal_service import VirusTotalService
from app.repositories.threat_repository import ThreatRepository

class TestThreatIntelligence(unittest.TestCase):
    """Unit tests for threat intelligence categorization and severity scoring."""

    def test_threat_level_classification(self):
        self.assertEqual(VirusTotalService.get_threat_level({"malicious": 0, "suspicious": 0}), "safe")
        self.assertEqual(VirusTotalService.get_threat_level({"malicious": 0, "suspicious": 1}), "suspicious")
        self.assertEqual(VirusTotalService.get_threat_level({"malicious": 3, "suspicious": 0}), "malicious")

    def test_threat_severity_mapping(self):
        self.assertEqual(VirusTotalService.get_threat_severity(25), "CRITICAL")
        self.assertEqual(VirusTotalService.get_threat_severity(7), "HIGH")
        self.assertEqual(VirusTotalService.get_threat_severity(3), "MEDIUM")
        self.assertEqual(VirusTotalService.get_threat_severity(0), "LOW")

    def test_infer_threat_types_phishing(self):
        stats = {"malicious": 4, "suspicious": 1}
        threats = VirusTotalService._infer_threat_types(stats, "https://secure-bank-login-verify.com")
        self.assertTrue(any("PHISHING" in t for t in threats))

    def test_infer_threat_types_crypto(self):
        stats = {"malicious": 2, "suspicious": 0}
        threats = VirusTotalService._infer_threat_types(stats, "https://free-bitcoin-mining.xyz")
        self.assertTrue(any("CRYPTO" in t for t in threats))

    @patch.object(ThreatRepository, "get_by_url")
    def test_cached_scan_returns_early(self, mock_get_by_url):
        import datetime
        now = datetime.datetime.now()
        mock_get_by_url.return_value = {
            "url": "https://example.com",
            "malicious": 0,
            "last_checked": now
        }
        service = VirusTotalService(api_key="fake_key")
        result = service.scan_url("https://example.com", force_rescan=False)
        self.assertEqual(result["malicious"], 0)

if __name__ == "__main__":
    unittest.main()
