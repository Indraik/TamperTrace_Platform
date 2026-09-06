import os
import tempfile
import unittest
from unittest.mock import patch
from app.services.restore_service import RestoreService
from app.repositories.scan_repository import ScanRepository

class TestRestore(unittest.TestCase):
    """Unit tests for the disaster recovery and template restoration service."""

    def test_url_to_template_path_root(self):
        with patch("config.Config.TARGET_SITE_ROOT", r"C:\fake\site"):
            path = RestoreService.url_to_template_path("http://localhost:5000/")
            self.assertTrue(path.endswith("index.html"))

    def test_url_to_template_path_route(self):
        with patch("config.Config.TARGET_SITE_ROOT", r"C:\fake\site"):
            path = RestoreService.url_to_template_path("http://localhost:5000/admin_dashboard")
            self.assertTrue(path.endswith("admin_dashboard.html"))

    def test_restore_missing_snapshot(self):
        with patch.object(ScanRepository, "get_last_clean_snapshot", return_value=None):
            result = RestoreService.restore_website("http://example.com/notfound")
            self.assertFalse(result["success"])
            self.assertIn("No SAFE baseline snapshot found", result["message"])

    def test_restore_file_backup_and_overwrite(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tpl_dir = os.path.join(tmpdir, "templates")
            os.makedirs(tpl_dir)
            target_tpl = os.path.join(tpl_dir, "portal.html")

            # Create defaced file
            with open(target_tpl, "w", encoding="utf-8") as f:
                f.write("<h1>HACKED</h1>")

            fake_snapshot = {
                "url": "http://127.0.0.1:5000/portal",
                "html_content": "<h1>SAFE VERIFIED CONTENT</h1>",
                "hash": "abc123safehash",
                "timestamp": "2026-09-01 10:00:00"
            }

            with patch("config.Config.TARGET_SITE_ROOT", tmpdir), \
                 patch.object(ScanRepository, "get_last_clean_snapshot", return_value=fake_snapshot), \
                 patch("app.repositories.restore_repository.RestoreRepository.log_restore"), \
                 patch("app.repositories.scan_repository.ScanRepository.log_restored_snapshot"), \
                 patch("app.repositories.url_repository.UrlRepository.mark_restored"):

                result = RestoreService.restore_website("http://127.0.0.1:5000/portal")
                self.assertTrue(result["success"])

                # Verify file was overwritten with safe content
                with open(target_tpl, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertEqual(content, "<h1>SAFE VERIFIED CONTENT</h1>")

                # Verify backup .bak file was created
                backup_file = os.path.join(tmpdir, "restore_backup", "portal.html.bak")
                self.assertTrue(os.path.exists(backup_file))
                with open(backup_file, "r", encoding="utf-8") as f:
                    bak_content = f.read()
                self.assertEqual(bak_content, "<h1>HACKED</h1>")

if __name__ == "__main__":
    unittest.main()
