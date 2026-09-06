from app.database import get_settings_col

class SettingsRepository:
    """Repository handling system configuration flags in MongoDB."""

    @staticmethod
    def get_system_settings():
        """Retrieve system settings document, returning safe defaults if missing."""
        settings = get_settings_col().find_one({"name": "system"})
        if not settings:
            return {
                "name": "system",
                "scheduler_enabled": False,
                "threat_intel_enabled": False
            }
        return settings

    @staticmethod
    def is_scheduler_enabled():
        """Return True if background scheduler is active."""
        settings = SettingsRepository.get_system_settings()
        return settings.get("scheduler_enabled", False)

    @staticmethod
    def is_threat_intel_enabled():
        """Return True if threat intelligence auto-scan is active."""
        settings = SettingsRepository.get_system_settings()
        return settings.get("threat_intel_enabled", False)

    @staticmethod
    def toggle_scheduler():
        """Toggle scheduler enabled flag and return the new boolean state."""
        current = SettingsRepository.is_scheduler_enabled()
        new_val = not current
        get_settings_col().update_one(
            {"name": "system"},
            {"$set": {"scheduler_enabled": new_val}},
            upsert=True
        )
        return new_val

    @staticmethod
    def toggle_threat_intel():
        """Toggle threat intel enabled flag and return the new boolean state."""
        current = SettingsRepository.is_threat_intel_enabled()
        new_val = not current
        get_settings_col().update_one(
            {"name": "system"},
            {"$set": {"threat_intel_enabled": new_val}},
            upsert=True
        )
        return new_val
