import datetime
from app.database import get_vt_results_col

class ThreatRepository:
    """Repository handling VirusTotal threat intelligence records and caching."""

    @staticmethod
    def get_by_url(url):
        """Retrieve the latest VirusTotal scan result for a URL."""
        return get_vt_results_col().find_one({"url": url}, sort=[("scan_date", -1)])

    @staticmethod
    def save_scan_result(result):
        """Upsert a VirusTotal scan result record."""
        return get_vt_results_col().update_one(
            {"url": result["url"]},
            {"$set": result},
            upsert=True
        )

    @staticmethod
    def get_recent_scans(limit=10):
        """Retrieve recent scans ordered newest first."""
        return list(get_vt_results_col().find().sort("last_checked", -1).limit(limit))

    @staticmethod
    def delete_by_url(url):
        """Delete VirusTotal scan results for a specific URL."""
        return get_vt_results_col().delete_many({"url": url})
