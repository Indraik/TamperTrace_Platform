import os
import time
import hashlib
import datetime
from config import Config
from app.repositories.incident_repository import IncidentRepository
from app.repositories.url_repository import UrlRepository

class IncidentService:
    """Service handling incident recording, evidence preservation, and URL state freezing."""

    @staticmethod
    def preserve_evidence_screenshot(previous_screenshot_path, url):
        """Archive the previous baseline screenshot into static/archive/ for forensic history."""
        if not previous_screenshot_path or not os.path.exists(previous_screenshot_path):
            return None

        try:
            archive_dir = Config.ARCHIVE_FOLDER
            os.makedirs(archive_dir, exist_ok=True)

            timestamp = int(time.time())
            archive_name = f"{hashlib.md5((url + str(timestamp)).encode()).hexdigest()}.png"
            archive_path = os.path.join(archive_dir, archive_name)

            with open(previous_screenshot_path, "rb") as fr, open(archive_path, "wb") as fw:
                fw.write(fr.read())

            return archive_path
        except Exception as e:
            print(f"⚠️ Failed to archive screenshot evidence: {e}")
            return None

    @classmethod
    def handle_tamper_incident(cls, url, old_hash, new_hash, decision, reason,
                               diff_percent, old_screenshot_path, new_screenshot_path,
                               diff_image_path, core_features):
        """
        Record the tampering incident, preserve evidence, and update monitored URL state.
        Returns the created incident record dictionary.
        """
        # 1. Archive the previous safe screenshot
        cls.preserve_evidence_screenshot(old_screenshot_path, url)

        # 2. Record incident in database
        incident_data = {
            "url": url,
            "detected_at": datetime.datetime.now(),
            "old_hash": old_hash,
            "new_hash": new_hash,
            "decision": decision,
            "reason": reason,
            "visual_diff_percentage": diff_percent,
            "old_screenshot": old_screenshot_path,
            "new_screenshot": new_screenshot_path,
            "diff_image": diff_image_path
        }
        IncidentRepository.record_incident(incident_data)

        # 3. Flag site state in repository (freeze automated scans until admin action)
        UrlRepository.flag_tamper(
            url=url,
            decision=decision,
            reason=reason,
            core_features=core_features,
            screenshot_path=new_screenshot_path
        )

        return incident_data
