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
        res = EmailClient.send_tamper_alert(
            to_email=to_email,
            url=url,
            content_changes=content_changes,
            diff_percentage=diff_percentage,
            old_screenshot_path=old_screenshot_path,
            new_screenshot_path=new_screenshot_path,
            diff_path=diff_path
        )
        return res[0] if isinstance(res, tuple) else res

    @staticmethod
    def send_test_email(to_email=None):
        """Dispatch a diagnostic test email to confirm SMTP connectivity and delivery."""
        recipient = to_email or Config.EMAIL_SENDER
        return EmailClient.send_test_email(recipient)

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
        results = {"email": False, "whatsapp": False}

        # 1. Email Notification
        if admin_email:
            results["email"] = cls.send_email_alert(
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
            results["whatsapp"] = cls.send_whatsapp_alert(to_number=phone, url=url, reason=reason)

        return results
