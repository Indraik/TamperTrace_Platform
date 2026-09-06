"""
AlertService - Coordinates notification decisions and dispatches alerts via external integrations
(EmailClient, WhatsAppClient in app.integrations)
"""
from config import Config
from app.integrations.email import EmailClient
from app.integrations.whatsapp import WhatsAppClient

class AlertService:
    """Service deciding which notifications to dispatch and coordinating external providers."""

    @staticmethod
    def send_email_alert(to_email, url, content_changes, diff_percentage,
                         old_screenshot_path, new_screenshot_path, diff_path):
        """Dispatch HTML email alert with inline diff comparison."""
        return EmailClient.send_tamper_alert(
            to_email=to_email,
            url=url,
            content_changes=content_changes,
            diff_percentage=diff_percentage,
            old_screenshot_path=old_screenshot_path,
            new_screenshot_path=new_screenshot_path,
            diff_path=diff_path
        )

    @staticmethod
    def send_whatsapp_alert(to_number, url, reason):
        """Dispatch instant WhatsApp alert via Twilio."""
        return WhatsAppClient.send_tamper_alert(
            to_number=to_number,
            url=url,
            reason=reason
        )

    @classmethod
    def notify_tamper(cls, url, reason, diff_percentage, old_screenshot,
                       new_screenshot, diff_img, admin_email, admin_phone=None):
        """Unified method to dispatch alerts across all configured channels."""
        # 1. Email Notification
        if admin_email:
            cls.send_email_alert(
                to_email=admin_email,
                url=url,
                content_changes=[reason],
                diff_percentage=diff_percentage,
                old_screenshot_path=old_screenshot,
                new_screenshot_path=new_screenshot,
                diff_path=diff_img
            )

        # 2. WhatsApp Notification
        phone = admin_phone or Config.ADMIN_WHATSAPP
        if phone:
            cls.send_whatsapp_alert(to_number=phone, url=url, reason=reason)
