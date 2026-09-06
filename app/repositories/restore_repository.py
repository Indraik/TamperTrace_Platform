import datetime
from app.database import get_restore_logs_col

class RestoreRepository:
    """Repository handling audit logging of website restoration events."""

    @staticmethod
    def log_restore(url, restored_from_timestamp, restored_by="admin", note="Restored to last verified SAFE snapshot"):
        """Record an immutable audit log entry for a restore operation."""
        restore_log = {
            "url": url,
            "restored_from_timestamp": restored_from_timestamp,
            "restored_at": datetime.datetime.utcnow(),
            "restored_by": restored_by,
            "restore_status": "SUCCESS",
            "note": note
        }
        return get_restore_logs_col().insert_one(restore_log)

    @staticmethod
    def get_recent_restores(limit=50):
        """Retrieve recent restore audit logs."""
        return list(get_restore_logs_col().find().sort("restored_at", -1).limit(limit))
