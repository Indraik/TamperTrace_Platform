"""
Legacy compatibility wrapper for restore_service.py.
Domain implementation has been refactored into app.services.restore_service.
"""
from app.services.restore_service import RestoreService, restore_website

__all__ = ["RestoreService", "restore_website"]