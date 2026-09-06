from pymongo import MongoClient, ASCENDING, DESCENDING
from config import Config

_client = None
_db = None

def get_mongo_client():
    """Returns a singleton MongoClient instance with connection pooling."""
    global _client
    if _client is None:
        _client = MongoClient(Config.MONGO_URI, maxPoolSize=50, serverSelectionTimeoutMS=5000)
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

def ensure_indexes():
    """Create essential database indexes if not already present."""
    try:
        db = get_db()
        db["monitored_urls"].create_index([("url", ASCENDING)], unique=True)
        db["vt_scan_results"].create_index([("url", ASCENDING)], unique=True)
        db["scans"].create_index([("url", ASCENDING), ("timestamp", DESCENDING)])
        db["change_logs"].create_index([("url", ASCENDING), ("detected_at", DESCENDING)])
        db["settings"].create_index([("name", ASCENDING)], unique=True)
        db["restore_logs"].create_index([("url", ASCENDING), ("restored_at", DESCENDING)])
    except Exception as e:
        print(f"⚠️ Index creation notice: {e}")

def init_system_settings():
    """Ensure default system settings and indexes exist in the database."""
    ensure_indexes()
    settings_col = get_settings_col()
    if not settings_col.find_one({"name": "system"}):
        settings_col.insert_one({
            "name": "system",
            "scheduler_enabled": False,
            "threat_intel_enabled": False
        })
        print("Initialized default system settings in MongoDB.")
