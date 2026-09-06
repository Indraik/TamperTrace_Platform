import unittest
from unittest.mock import patch, MagicMock
from app.services.monitoring_service import MonitoringService
from app.repositories.url_repository import UrlRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.settings_repository import SettingsRepository

class TestMonitoring(unittest.TestCase):
    """Unit tests for the monitoring cycle lifecycle and staging logic."""

    @patch.object(SettingsRepository, "is_scheduler_enabled", return_value=False)
    def test_cycle_skips_when_scheduler_disabled(self, mock_sched):
        result = MonitoringService.run_monitoring_cycle()
        self.assertEqual(result["status"], "paused")
        self.assertEqual(result["checked"], 0)

    @patch.object(SettingsRepository, "is_scheduler_enabled", return_value=True)
    @patch.object(UrlRepository, "get_all")
    def test_cycle_skips_unreviewed_incident(self, mock_get_all, mock_sched):
        mock_get_all.return_value = [{
            "url": "http://example.com",
            "admin_email": "admin@example.com",
            "change_detected": True  # Pending review
        }]
        result = MonitoringService.run_monitoring_cycle()
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["checked"], 0)

    @patch.object(SettingsRepository, "is_scheduler_enabled", return_value=True)
    @patch.object(UrlRepository, "get_all")
    @patch("app.services.browser_service.BrowserService.capture_page")
    @patch.object(UrlRepository, "update_baseline")
    def test_lifecycle_warmup_advances_to_baseline(self, mock_update, mock_capture, mock_get_all, mock_sched):
        mock_get_all.return_value = [{
            "_id": "mock_id",
            "url": "http://example.com",
            "admin_email": "admin@example.com",
            "change_detected": False,
            "html_hash": "dummy_hash",
            "baseline_stage": "WARMUP"
        }]
        mock_capture.return_value = ("<html><title>Hi</title></html>", "path/to/shot.png", True, "http://example.com")

        result = MonitoringService.run_monitoring_cycle()
        self.assertEqual(result["checked"], 1)
        mock_update.assert_called_once()
        self.assertEqual(mock_update.call_args.kwargs["stage"], "BASELINE")

    @patch.object(SettingsRepository, "is_scheduler_enabled", return_value=True)
    @patch.object(UrlRepository, "get_all")
    @patch("app.services.browser_service.BrowserService.capture_page")
    @patch.object(UrlRepository, "update_baseline")
    @patch.object(ScanRepository, "save_baseline_snapshot")
    def test_lifecycle_baseline_advances_to_active(self, mock_save_snap, mock_update, mock_capture, mock_get_all, mock_sched):
        mock_get_all.return_value = [{
            "_id": "mock_id",
            "url": "http://example.com",
            "admin_email": "admin@example.com",
            "change_detected": False,
            "html_hash": "dummy_hash",
            "baseline_stage": "BASELINE"
        }]
        mock_capture.return_value = ("<html><title>Hi</title></html>", "path/to/shot.png", True, "http://example.com")

        result = MonitoringService.run_monitoring_cycle()
        self.assertEqual(result["checked"], 1)
        mock_update.assert_called_once()
        self.assertEqual(mock_update.call_args.kwargs["stage"], "ACTIVE")
        mock_save_snap.assert_called_once()

if __name__ == "__main__":
    unittest.main()
