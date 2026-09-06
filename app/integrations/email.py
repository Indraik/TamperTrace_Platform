import os
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from config import Config

class EmailClient:
    """External email integration using SMTP with support for inline CID forensic images."""

    @staticmethod
    def send_tamper_alert(to_email, url, content_changes, diff_percentage,
                          old_screenshot_path, new_screenshot_path, diff_path):
        """Send rich HTML tamper notification with embedded inline Before/After/Diff images."""
        if not Config.EMAIL_SENDER or not Config.EMAIL_PASSWORD:
            print("⚠️ Email credentials missing (EMAIL_SENDER / EMAIL_PASSWORD). Skipping email.")
            return False

        try:
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
                <p style="color:#6b7280; font-size:13px;">Forensic evidence captured and attached inline below.</p>
            </div>
            """

            msg = MIMEMultipart()
            msg["From"] = Config.EMAIL_SENDER
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))

            def attach_inline(path, cid_name):
                if path and os.path.exists(path):
                    try:
                        with open(path, "rb") as f:
                            img = MIMEImage(f.read())
                            img.add_header("Content-ID", f"<{cid_name}>")
                            img.add_header("Content-Disposition", "inline", filename=os.path.basename(path))
                            msg.attach(img)
                            return True
                    except Exception as ex:
                        print(f"⚠️ Could not attach image {path}: {ex}")
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

            print(f"📧 Alert email successfully sent to {to_email}")
            return True

        except Exception as e:
            print(f"❌ Failed to send alert email: {e}")
            return False
