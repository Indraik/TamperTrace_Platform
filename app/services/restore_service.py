import os
from urllib.parse import urlparse, unquote
from config import Config
from app.repositories.scan_repository import ScanRepository
from app.repositories.restore_repository import RestoreRepository
from app.repositories.url_repository import UrlRepository

class RestoreService:
    """Service handling rollback of tampered target templates to verified clean baselines."""

    @staticmethod
    def get_last_clean_snapshot(url):
        return ScanRepository.get_last_clean_snapshot(url)

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
        1. Validates target directory
        2. Retrieves last clean snapshot from ScanRepository
        3. Creates safety backup of defaced file
        4. Overwrites template with safe HTML
        5. Logs audit record in RestoreRepository
        6. Updates site state in UrlRepository
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

            # 3. Log audit event in RestoreRepository
            RestoreRepository.log_restore(
                url=url,
                restored_from_timestamp=snapshot.get("timestamp"),
                restored_by=restored_by
            )

            # 4. Insert safe verification record in ScanRepository
            ScanRepository.log_restored_snapshot(
                url=url,
                html_content=restored_html,
                html_hash=restored_hash
            )

            # 5. Update monitored URL state in UrlRepository
            UrlRepository.mark_restored(url, restored_hash=restored_hash)

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
