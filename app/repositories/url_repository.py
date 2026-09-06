import datetime
from app.database import get_monitored_urls_col

class UrlRepository:
    """Repository handling database operations for monitored URLs."""

    @staticmethod
    def get_all():
        """Retrieve all monitored URL records."""
        return list(get_monitored_urls_col().find())

    @staticmethod
    def get_by_url(url):
        """Find a single monitored site record by URL."""
        return get_monitored_urls_col().find_one({"url": url})

    @staticmethod
    def get_active_urls():
        """Retrieve all URLs currently active for scanning."""
        return list(get_monitored_urls_col().find({}, {"url": 1}))

    @staticmethod
    def add_url(site_data):
        """Insert a newly registered site into the monitored list."""
        return get_monitored_urls_col().insert_one(site_data)

    @staticmethod
    def update_baseline(url, html_hash, screenshot_path, core_features=None, stage=None, status=None):
        """Update the baseline hash, features, screenshot, and status for a URL."""
        update_fields = {
            "html_hash": html_hash,
            "screenshot_path": screenshot_path,
            "change_detected": False,
            "last_checked": datetime.datetime.now(),
            "last_verified": datetime.datetime.now()
        }
        if core_features is not None:
            update_fields["core_features"] = core_features
        if stage is not None:
            update_fields["baseline_stage"] = stage
        if status is not None:
            update_fields["status"] = status

        return get_monitored_urls_col().update_one(
            {"url": url},
            {"$set": update_fields}
        )

    @staticmethod
    def flag_tamper(url, decision, reason, core_features, screenshot_path):
        """Flag a monitored site as tampered/defaced and freeze automated scans."""
        now = datetime.datetime.now()
        return get_monitored_urls_col().update_one(
            {"url": url},
            {"$set": {
                "decision": decision,
                "change_reason": reason,
                "change_detected": True,
                "core_features": core_features,
                "screenshot_path": screenshot_path,
                "status": "🚨 Defaced / Under Investigation",
                "last_checked": now,
                "last_change": now
            }}
        )

    @staticmethod
    def confirm_defaced(url):
        """Manually mark a site as confirmed defaced."""
        return get_monitored_urls_col().update_one(
            {"url": url},
            {"$set": {
                "status": "🚨 Defaced / Under Investigation",
                "change_detected": True,
                "last_verified": datetime.datetime.now()
            }}
        )

    @staticmethod
    def mark_restored(url, restored_hash=None):
        """Mark a site as restored to safe baseline."""
        payload = {
            "change_detected": False,
            "status": "✅ Restored to SAFE baseline",
            "last_verified": datetime.datetime.now(),
            "last_change": None
        }
        if restored_hash:
            payload["html_hash"] = restored_hash

        return get_monitored_urls_col().update_one(
            {"url": url},
            {"$set": payload}
        )

    @staticmethod
    def update_stage(record_id, fields):
        """Update baseline staging fields by record _id."""
        return get_monitored_urls_col().update_one(
            {"_id": record_id},
            {"$set": fields}
        )

    @staticmethod
    def delete_by_url(url):
        """Remove a URL from the monitored list."""
        return get_monitored_urls_col().delete_one({"url": url})

    @staticmethod
    def get_stats():
        """Calculate threat metrics summary across all monitored sites."""
        records = UrlRepository.get_all()
        safe_count = len([
            r for r in records
            if not r.get("change_detected", False) and r.get("vt_malicious", 0) == 0
        ])
        defaced_count = len([r for r in records if r.get("change_detected", False)])
        high_threat_count = len([r for r in records if r.get("vt_malicious", 0) > 0])
        malicious_resources = sum([r.get("malicious_resources", 0) for r in records])

        return {
            "total": len(records),
            "safe": safe_count,
            "defaced": defaced_count,
            "high_threat": high_threat_count,
            "malicious_resources": malicious_resources
        }
