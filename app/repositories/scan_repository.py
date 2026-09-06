import datetime
from app.database import get_scans_col

class ScanRepository:
    """Repository handling historical clean snapshots and baseline storage."""

    @staticmethod
    def save_baseline_snapshot(url, html_content, html_hash):
        """Save an authoritative clean baseline snapshot."""
        return get_scans_col().insert_one({
            "url": url,
            "html_content": html_content,
            "hash": html_hash,
            "status": "SAFE",
            "timestamp": datetime.datetime.now(),
            "is_baseline": True
        })

    @staticmethod
    def get_last_clean_snapshot(url):
        """Retrieve the most recent verified SAFE snapshot for a URL."""
        return get_scans_col().find_one(
            {"url": url, "status": "SAFE"},
            sort=[("timestamp", -1)]
        )

    @staticmethod
    def log_restored_snapshot(url, html_content, html_hash):
        """Log a snapshot entry representing a successful restore operation."""
        return get_scans_col().insert_one({
            "url": url,
            "html_content": html_content,
            "hash": html_hash,
            "status": "SAFE",
            "timestamp": datetime.datetime.utcnow(),
            "restored": True
        })

    @staticmethod
    def delete_by_url(url):
        """Delete all scan history for a URL."""
        return get_scans_col().delete_many({"url": url})
