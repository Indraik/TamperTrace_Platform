from datetime import datetime
from scheduler import get_last_clean_snapshot
import os
from urllib.parse import urlparse, unquote

# 🔥 TARGET WEBSITE ROOT (FundTrail demo site)
TARGET_SITE_ROOT = os.getenv("TARGET_SITE_ROOT", r"D:\Projects\fundtrail_backend_web")
TARGET_BASE_URL = os.getenv("TARGET_BASE_URL", "http://127.0.0.1:5002")


def url_to_template_path(url):
    """
    Map monitored URL to template file
    inside the TARGET website project.
    """

    parsed = urlparse(url)
    path = unquote((parsed.path or "").strip())

    if path == "" or path == "/":
        template_name = "index.html"
    else:
        template_name = path.strip("/") + ".html"

    template_path = os.path.join(
        TARGET_SITE_ROOT,
        "templates",
        template_name
    )

    return template_path



def restore_website(db, url, restored_by="admin"):
    """
    Restore a website to its last known SAFE snapshot.

    Returns:
        dict -> result status and message
    """

    if not TARGET_SITE_ROOT or not os.path.isdir(TARGET_SITE_ROOT):
        return {
            "success": False,
            "message": f"Invalid TARGET_SITE_ROOT: {TARGET_SITE_ROOT}"
        }

    # 1️⃣ Fetch last SAFE snapshot
    snapshot = get_last_clean_snapshot(db, url)

    if not snapshot:
        return {
            "success": False,
            "message": "No SAFE snapshot found. Restore not possible."
        }

    # 2️⃣ Prepare restored data (REAL restore)
    restored_html = snapshot.get("html_content")
    restored_hash = snapshot.get("hash")

    if not restored_html:
        return {
            "success": False,
            "message": "Snapshot HTML missing. Restore aborted."
        }
    # 🔥 REAL FILE RESTORE STARTS HERE
    template_path = url_to_template_path(url)

    if not os.path.exists(template_path):
        return {
            "success": False,
            "message": f"Template file not found: {template_path}"
        }
    # Backup current template
    backup_dir = os.path.join(TARGET_SITE_ROOT, "restore_backup")
    os.makedirs(backup_dir, exist_ok=True)

    backup_path = os.path.join(
        backup_dir,
        os.path.basename(template_path) + ".bak"
    )
    with open(template_path, "r", encoding="utf-8") as f:
        current_html = f.read()

    with open(backup_path, "w", encoding="utf-8") as f:
        f.write(current_html)

    # 🔥 OVERWRITE TEMPLATE WITH SAFE HTML  # 🔥 REAL RESTORE
    with open(template_path, "w", encoding="utf-8") as f:
        f.write(restored_html)
        
    # # 2️⃣ Prepare restored data (logical restore)
    #restored_html = snapshot.get("html_content")
    #restored_hash = snapshot.get("hash")

    #if not restored_html or not restored_hash:
    #    return {
    #        "success": False,
    #        "message": "Snapshot data incomplete. Restore aborted."
    #    }

    # 3️⃣ Insert restore record (audit + forensic trail)
    restore_log = {
        "url": url,
        "restored_from_timestamp": snapshot.get("timestamp"),
        "restored_at": datetime.utcnow(),
        "restored_by": restored_by,
        "restore_status": "SUCCESS",
        "note": "Restored to last SAFE snapshot"
    }

    db.restore_logs.insert_one(restore_log)

    # 4️⃣ Insert a new scan entry marking site as SAFE after restore
    db.scans.insert_one({
        "url": url,
        "html_content": restored_html,
        "hash": restored_hash,
        "status": "SAFE",
        "timestamp": datetime.utcnow(),
        "restored": True
    })

    return {
        "success": True,
        "message": "Website successfully restored to last SAFE version.",
        "restored_hash": restored_hash,
        "template_path": template_path
    }
# Example usage:
# db = MongoClient('mongodb://localhost:27017/').tampertrace_db
# result = restore_website(db, "http://example.com", restored_by="admin_user")
# print(result)