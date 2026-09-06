import datetime
from app.database import get_change_logs_col

class IncidentRepository:
    """Repository handling tamper incident logs, forensics, and evidence records."""

    @staticmethod
    def record_incident(incident_data):
        """Insert a tamper incident audit log with diff percentages and evidence paths."""
        if "detected_at" not in incident_data:
            incident_data["detected_at"] = datetime.datetime.now()
        return get_change_logs_col().insert_one(incident_data)

    @staticmethod
    def get_all(limit=100):
        """Retrieve recent incident logs ordered newest first."""
        return list(get_change_logs_col().find().sort("detected_at", -1).limit(limit))

    @staticmethod
    def get_by_url(url, limit=20):
        """Retrieve incident history for a specific URL."""
        return list(get_change_logs_col().find({"url": url}).sort("detected_at", -1).limit(limit))

    @staticmethod
    def delete_by_url(url):
        """Delete all incident logs for a given URL."""
        return get_change_logs_col().delete_many({"url": url})
