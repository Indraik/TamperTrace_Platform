import os
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from twilio.rest import Client as TwilioClient
from config import Config

class AlertService:
    """Service dispatching multi-channel tamper notifications (Email + WhatsApp)."""

    @staticmethod
    def send_whatsapp_alert(to_number, url, reason):
        """Send instant WhatsApp alert via Twilio."""
        try:
            sid = Config.TWILIO_SID
            token = Config.TWILIO_AUTH_TOKEN
            if not sid or not token:
                print("⚠️ Twilio credentials missing in config.")
                return False

            if not to_number:
                to_number = Config.ADMIN_WHATSAPP

            if not to_number:
                print("⚠️ No recipient phone number provided for WhatsApp.")
                return False

            client = TwilioClient(sid, token)
            message = client.messages.create(
                from_="whatsapp:+14155238886",  # Twilio Sandbox
                to=f"whatsapp:{to_number}",
                body=(
                    "🚨 *TamperTrace Alert*\n\n"
                    f"🌐 Website: {url}\n"
                    f"⚠️ Issue: {reason}\n\n"
                    "Please check your dashboard immediately."
                )
            )
            print(f"📲 WhatsApp alert sent → SID: {message.sid}")
            return True
        except Exception as e:
            print(f"❌ WhatsApp alert failed: {e}")
            return False

    @staticmethod
    def send_email_alert(to_email, url, content_changes, diff_percentage,
                         old_screenshot_path, new_screenshot_path, diff_path):
        """Send rich HTML email with embedded comparison images and approve/deny action links."""
        try:
            if not Config.EMAIL_SENDER or not Config.EMAIL_PASSWORD:
                print("⚠️ Email credentials missing in config (EMAIL_SENDER / EMAIL_PASSWORD).")
                return False

            subject = f"🚨 TamperTrace Alert: Changes on {url}"
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            changes_html = "".join(f"<li>{c}</li>" for c in content_changes) if content_changes else "<li>Visual difference detected</li>"

            body = f"""
            <div style="font-family:Arial, sans-serif; color:#111; max-width:600px; margin:0 auto; padding:20px;">
                <h2 style="color:#dc2626;">🚨 TamperTrace: Change Detected</h2>
                <p><strong>URL:</strong> <a href="{url}">{url}</a></p>
                <p><strong>Detected at:</strong> {timestamp} (Local Time)</p>
                <ul style="background:#fef2f2; padding:15px; border-left:4px solid #dc2626; border-radius:4px;">
                    {changes_html}
                </ul>
                <p><strong>Visual Difference Score:</strong> {diff_percentage:.2f}%</p>
                <div style="margin:25px 0;">
                    <a href="http://127.0.0.1:5000/approve_change?url={url}" 
                       style="display:inline-block; padding:10px 20px; background:#22c55e; color:#fff; text-decoration:none; border-radius:6px; font-weight:bold;">
                       ✅ Approve Change
                    </a>
                    &nbsp;&nbsp;
                    <a href="http://127.0.0.1:5000/deny_change?url={url}" 
                       style="display:inline-block; padding:10px 20px; background:#dc2626; color:#fff; text-decoration:none; border-radius:6px; font-weight:bold;">
                       🚨 Confirm Defacement
                    </a>
                </div>
                <hr style="border:0; border-top:1px solid #e5e7eb; margin:20px 0;">
                <p style="color:#6b7280; font-size:13px;">Forensic evidence captured and attached inline.</p>
            </div>
            """

            msg = MIMEMultipart()
            msg["From"] = Config.EMAIL_SENDER
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))

            def attach_inline(path, cid_name):
                if path and os.path.exists(path):
                    with open(path, "rb") as f:
                        img = MIMEImage(f.read())
                        img.add_header("Content-ID", f"<{cid_name}>")
                        img.add_header("Content-Disposition", "inline", filename=os.path.basename(path))
                        msg.attach(img)
                        return True
                return False

            attach_inline(old_screenshot_path, "before_image")
            attach_inline(new_screenshot_path, "after_image")
            attach_inline(diff_path, "diff_image")

            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=30)
            server.ehlo()
            server.starttls()
            server.login(Config.EMAIL_SENDER, Config.EMAIL_PASSWORD)
            server.sendmail(Config.EMAIL_SENDER, [to_email], msg.as_string())
            server.quit()

            print(f"📧 Alert email sent to {to_email}")
            return True

        except Exception as e:
            print(f"❌ Failed to send alert email: {e}")
            return False

    @classmethod
    def notify_tamper(cls, url, reason, diff_percentage, old_screenshot,
                       new_screenshot, diff_img, admin_email, admin_phone=None):
        """Unified method to dispatch alerts to all configured channels."""
        # 1. Send Email
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

        # 2. Send WhatsApp
        phone = admin_phone or Config.ADMIN_WHATSAPP
        if phone:
            cls.send_whatsapp_alert(to_number=phone, url=url, reason=reason)
