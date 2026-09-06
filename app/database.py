from pymongo import MongoClient
from config import Config

_client = None
_db = None

def get_mongo_client():
    """Returns a singleton MongoClient instance."""
    global _client
    if _client is None:
        _client = MongoClient(Config.MONGO_URI)
    return _client

def get_db():
    """Returns the application MongoDB database instance."""
    global _db
    if _db is None:
        client = get_mongo_client()
        _db = client[Config.DATABASE_NAME]
    return _db

def get_monitored_urls_col():
    """Collection for monitored target websites."""
    return get_db()["monitored_urls"]

def get_vt_results_col():
    """Collection for VirusTotal threat intelligence scan results."""
    return get_db()["vt_scan_results"]

def get_change_logs_col():
    """Collection for detected tamper incidents and diff forensics."""
    return get_db()["change_logs"]

def get_scans_col():
    """Collection for historical safe baselines and snapshots."""
    return get_db()["scans"]

def get_settings_col():
    """Collection for system-wide configuration flags."""
    return get_db()["settings"]

def get_restore_logs_col():
    """Collection for audit logs of website restore events."""
    return get_db()["restore_logs"]

def init_system_settings():
    """Ensure system settings exist in the database with defaults."""
    settings_col = get_settings_col()
    if not settings_col.find_one({"name": "system"}):
        settings_col.insert_one({
            "name": "system",
            "scheduler_enabled": False,
            "threat_intel_enabled": False
        })
        print("Initialized default system settings in MongoDB.")
