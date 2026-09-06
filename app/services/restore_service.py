import os
from datetime import datetime
from urllib.parse import urlparse, unquote
from config import Config
from app.database import get_db, get_scans_col, get_restore_logs_col

class RestoreService:
    """Service handling rollback of tampered target web templates to verified safe baselines."""

    @staticmethod
    def get_last_clean_snapshot(url):
        """Fetch the most recent verified SAFE snapshot for a URL."""
        scans_col = get_scans_col()
        return scans_col.find_one(
            {"url": url, "status": "SAFE"},
            sort=[("timestamp", -1)]
        )

    @staticmethod
    def url_to_template_path(url):
        """Map monitored URL route to template file inside target site repository."""
        parsed = urlparse(url)
        path = unquote((parsed.path or "").strip())

        if path == "" or path == "/":
            template_name = "index.html"
        else:
            template_name = path.strip("/") + ".html"

        template_path = os.path.join(
            Config.TARGET_SITE_ROOT,
            "templates",
            template_name
        )
        return template_path

    @classmethod
    def restore_website(cls, url, restored_by="admin"):
        """
        Restore target template to last clean baseline snapshot.
        Returns result dictionary.
        """
        if not Config.TARGET_SITE_ROOT or not os.path.isdir(Config.TARGET_SITE_ROOT):
            return {
                "success": False,
                "message": f"Invalid TARGET_SITE_ROOT directory: {Config.TARGET_SITE_ROOT}"
            }

        snapshot = cls.get_last_clean_snapshot(url)
        if not snapshot:
            return {
                "success": False,
                "message": "No SAFE baseline snapshot found. Restore not possible."
            }

        restored_html = snapshot.get("html_content")
        restored_hash = snapshot.get("hash")
        if not restored_html:
            return {
                "success": False,
                "message": "Snapshot HTML content is empty. Restore aborted."
            }

        template_path = cls.url_to_template_path(url)
        if not os.path.exists(template_path):
            return {
                "success": False,
                "message": f"Target template file not found: {template_path}"
            }

        try:
            # 1. Backup current template before overwriting
            backup_dir = os.path.join(Config.TARGET_SITE_ROOT, "restore_backup")
            os.makedirs(backup_dir, exist_ok=True)

            backup_path = os.path.join(
                backup_dir,
                os.path.basename(template_path) + ".bak"
            )
            with open(template_path, "r", encoding="utf-8") as f:
                current_html = f.read()

            with open(backup_path, "w", encoding="utf-8") as f:
                f.write(current_html)

            # 2. Overwrite template with safe HTML baseline
            with open(template_path, "w", encoding="utf-8") as f:
                f.write(restored_html)

            # 3. Log audit event
            restore_log = {
                "url": url,
                "restored_from_timestamp": snapshot.get("timestamp"),
                "restored_at": datetime.utcnow(),
                "restored_by": restored_by,
                "restore_status": "SUCCESS",
                "note": "Restored to last verified SAFE snapshot"
            }
            get_restore_logs_col().insert_one(restore_log)

            # 4. Insert safe verification record in scans
            get_scans_col().insert_one({
                "url": url,
                "html_content": restored_html,
                "hash": restored_hash,
                "status": "SAFE",
                "timestamp": datetime.utcnow(),
                "restored": True
            })

            return {
                "success": True,
                "message": "Website template successfully restored to last SAFE version.",
                "restored_hash": restored_hash,
                "template_path": template_path
            }

        except Exception as e:
            return {
                "success": False,
                "message": f"File restoration failed: {str(e)}"
            }

# Backward compatibility module-level function
def restore_website(db, url, restored_by="admin"):
    return RestoreService.restore_website(url, restored_by=restored_by)
