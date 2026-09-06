import unittest
from app import create_app
from config import TestingConfig

class TestRoutes(unittest.TestCase):
    """Integration tests for Flask application routes and blueprints."""

    def setUp(self):
        self.app = create_app(TestingConfig)
        self.client = self.app.test_client()

    def test_root_redirect_to_dashboard(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/dashboard", response.headers["Location"])

    def test_dashboard_route_200(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)

    def test_threats_route_200(self):
        response = self.client.get("/threats")
        self.assertEqual(response.status_code, 200)

    def test_alerts_route_200(self):
        response = self.client.get("/alerts")
        self.assertEqual(response.status_code, 200)

    def test_add_url_get_200(self):
        response = self.client.get("/add_url")
        self.assertEqual(response.status_code, 200)

    def test_download_report_200(self):
        response = self.client.get("/download_report")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")

    def test_restore_without_body_returns_400(self):
        response = self.client.post("/restore", json={})
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
