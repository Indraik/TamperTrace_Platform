import os
import shutil

class FileManager:
    """Safe filesystem utilities for backups, archives, and asset cleanup."""

    @staticmethod
    def ensure_directory(path):
        """Create directory if it does not already exist."""
        os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def safe_copy(src, dst):
        """Copy file safely, creating parent directories if needed."""
        if not os.path.exists(src):
            return False
        FileManager.ensure_directory(os.path.dirname(dst))
        shutil.copy2(src, dst)
        return True

    @staticmethod
    def safe_delete(path):
        """Remove file if it exists, ignoring errors."""
        try:
            if path and os.path.exists(path):
                os.remove(path)
                return True
        except Exception:
            pass
        return False
