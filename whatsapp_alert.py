"""
Legacy compatibility wrapper for whatsapp_alert.py.
Implementation has been refactored into app.integrations.whatsapp and app.services.alert_service.
"""
from app.services.alert_service import AlertService

def send_whatsapp_alert(to_number, url, reason):
    """Legacy wrapper delegating to AlertService."""
    return AlertService.send_whatsapp_alert(to_number, url, reason)

__all__ = ["send_whatsapp_alert"]
