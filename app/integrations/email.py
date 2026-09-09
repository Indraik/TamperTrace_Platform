import os
import sys
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from config import Config

def _safe_log(msg):
    """Safely log messages to stdout without crashing on Windows cp1252 character encodings."""
    try:
        print(msg)
    except Exception:
        try:
            print(msg.encode(sys.stdout.encoding or "ascii", errors="replace").decode(sys.stdout.encoding or "ascii"))
        except Exception:
            pass

class EmailClient:
    """External email integration using SMTP with support for inline CID forensic images."""

    @staticmethod
    def send_tamper_alert(to_email, url, content_changes, diff_percentage,
                          old_screenshot_path, new_screenshot_path, diff_path):
        """Send rich HTML tamper notification with embedded inline Before/After/Diff images."""
        if not Config.EMAIL_SENDER or not Config.EMAIL_PASSWORD:
            _safe_log("⚠️ Email credentials missing (EMAIL_SENDER / EMAIL_PASSWORD). Skipping email.")
            return False, "Email credentials missing in configuration (EMAIL_SENDER / EMAIL_PASSWORD)."

        if not to_email:
            _safe_log("⚠️ Recipient email address missing. Skipping email.")
            return False, "Recipient email address missing."

        try:
            subject = f"🚨 TamperTrace Alert: Defacement Detected on {url}"
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            changes_html = "".join(f"<li style='margin-bottom:6px;'>{c}</li>" for c in content_changes) if content_changes else "<li>Visual or DOM discrepancy detected</li>"

            # Check which screenshot files actually exist on disk
            has_old = bool(old_screenshot_path and os.path.exists(old_screenshot_path))
            has_new = bool(new_screenshot_path and os.path.exists(new_screenshot_path))
            has_diff = bool(diff_path and os.path.exists(diff_path))

            evidence_html = ""
            if has_old or has_new or has_diff:
                evidence_html = """
                <div style="margin-top:25px; padding-top:20px; border-top:1px solid #e2e8f0;">
                    <h3 style="color:#0f172a; margin-bottom:15px; font-size:16px;">🔍 Forensic Evidence (Captured Inline)</h3>
                """
                if has_old and has_new:
                    evidence_html += """
                    <table style="width:100%; border-collapse:collapse; margin-bottom:20px;">
                        <tr>
                            <td style="width:50%; vertical-align:top; padding-right:10px;">
                                <div style="font-weight:bold; font-size:13px; color:#10b981; margin-bottom:5px;">✅ Verified Safe Baseline:</div>
                                <img src="cid:before_image" style="width:100%; max-width:280px; border:1px solid #10b981; border-radius:6px; display:block;" alt="Baseline Screenshot">
                            </td>
                            <td style="width:50%; vertical-align:top; padding-left:10px;">
                                <div style="font-weight:bold; font-size:13px; color:#ef4444; margin-bottom:5px;">🚨 Detected Alteration:</div>
                                <img src="cid:after_image" style="width:100%; max-width:280px; border:1px solid #ef4444; border-radius:6px; display:block;" alt="Altered Screenshot">
                            </td>
                        </tr>
                    </table>
                    """
                if has_diff:
                    evidence_html += """
                    <div style="margin-top:15px;">
                        <div style="font-weight:bold; font-size:13px; color:#dc2626; margin-bottom:5px;">🔥 Visual Difference Heatmap:</div>
                        <img src="cid:diff_image" style="width:100%; max-width:580px; border:2px solid #dc2626; border-radius:6px; display:block;" alt="Diff Heatmap">
                    </div>
                    """
                evidence_html += "</div>"

            body_html = f"""
            <!DOCTYPE html>
            <html>
            <body style="font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color:#f8fafc; color:#1e293b; margin:0; padding:20px;">
                <div style="max-width:620px; margin:0 auto; background-color:#ffffff; border-radius:10px; border:1px solid #e2e8f0; padding:25px; box-shadow:0 4px 6px rgba(0,0,0,0.05);">
                    <div style="display:flex; align-items:center; border-bottom:2px solid #ef4444; padding-bottom:15px; margin-bottom:20px;">
                        <h2 style="color:#ef4444; margin:0; font-size:20px;">🛡️ TamperTrace Alert: Defacement Detected</h2>
                    </div>

                    <p style="font-size:15px; line-height:1.5;">
                        TamperTrace automated security sensors have detected an unauthorized visual or structural change on your monitored endpoint.
                    </p>

                    <div style="background-color:#f1f5f9; border-left:4px solid #3b82f6; padding:12px 15px; border-radius:4px; margin-bottom:20px; font-size:14px;">
                        <div style="margin-bottom:6px;"><strong>Target Endpoint:</strong> <a href="{url}" style="color:#2563eb; word-break:break-all;">{url}</a></div>
                        <div style="margin-bottom:6px;"><strong>Detection Timestamp:</strong> {timestamp} (Local Time)</div>
                        <div><strong>Visual Diff Score:</strong> <span style="color:#dc2626; font-weight:bold;">{diff_percentage:.2f}%</span></div>
                    </div>

                    <div style="margin-bottom:20px;">
                        <strong style="font-size:14px; color:#0f172a;">Specific Change Indicators:</strong>
                        <ul style="background-color:#fef2f2; border:1px solid #fee2e2; border-radius:6px; padding:12px 25px; margin-top:8px; color:#991b1b; font-size:14px;">
                            {changes_html}
                        </ul>
                    </div>

                    <div style="margin:25px 0; text-align:center;">
                        <a href="http://127.0.0.1:5000/approve_change?url={url}" 
                           style="display:inline-block; padding:10px 22px; background-color:#10b981; color:#ffffff; text-decoration:none; border-radius:6px; font-weight:600; font-size:14px; margin-right:10px;">
                           ✅ Approve Change
                        </a>
                        <a href="http://127.0.0.1:5000/deny_change?url={url}" 
                           style="display:inline-block; padding:10px 22px; background-color:#ef4444; color:#ffffff; text-decoration:none; border-radius:6px; font-weight:600; font-size:14px;">
                           🚨 Confirm Defacement
                        </a>
                    </div>

                    {evidence_html}

                    <div style="margin-top:30px; padding-top:15px; border-top:1px solid #f1f5f9; font-size:12px; color:#94a3b8; text-align:center;">
                        TamperTrace Autonomous Cybersecurity Platform &bull; Automated Telemetry Dispatch
                    </div>
                </div>
            </body>
            </html>
            """

            # Top-level RFC 2387 container for inline CID images
            msg = MIMEMultipart("related")
            msg["From"] = f"TamperTrace Security <{Config.EMAIL_SENDER}>"
            msg["To"] = to_email
            msg["Subject"] = subject

            # Alternative part for plain text + HTML
            msg_alt = MIMEMultipart("alternative")
            msg.attach(msg_alt)

            plain_text = (
                f"TamperTrace Alert: Defacement Detected on {url}\n"
                f"Detected at: {timestamp}\n"
                f"Visual Diff: {diff_percentage:.2f}%\n"
                f"Details: {', '.join(content_changes)}\n\n"
                f"Review dashboard at http://127.0.0.1:5000/dashboard\n"
            )
            msg_alt.attach(MIMEText(plain_text, "plain", "utf-8"))
            msg_alt.attach(MIMEText(body_html, "html", "utf-8"))

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
                        _safe_log(f"⚠️ Could not attach image {path}: {ex}")
                return False

            if has_old:
                attach_inline(old_screenshot_path, "before_image")
            if has_new:
                attach_inline(new_screenshot_path, "after_image")
            if has_diff:
                attach_inline(diff_path, "diff_image")

            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=25)
            server.ehlo()
            server.starttls()
            server.login(Config.EMAIL_SENDER, Config.EMAIL_PASSWORD)
            server.sendmail(Config.EMAIL_SENDER, [to_email], msg.as_string())
            server.quit()

            _safe_log(f"📧 Alert email successfully dispatched to {to_email}")
            return True, f"Alert email successfully dispatched to {to_email}"

        except Exception as e:
            err = str(e)
            _safe_log(f"❌ Failed to send alert email: {err}")
            return False, f"SMTP Error: {err}"

    @staticmethod
    def send_test_email(to_email):
        """Send a diagnostic test email to verify SMTP credentials and network reachability."""
        if not Config.EMAIL_SENDER or not Config.EMAIL_PASSWORD:
            return False, "EMAIL_SENDER or EMAIL_PASSWORD is not configured in .env file."

        recipient = to_email or Config.EMAIL_SENDER
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            subject = "🛡️ TamperTrace Test: SMTP Alerting System Verified"

            html = f"""
            <!DOCTYPE html>
            <html>
            <body style="font-family:Arial, sans-serif; background-color:#0b1020; color:#e6e9f0; padding:25px;">
                <div style="max-width:550px; margin:0 auto; background-color:#11182f; border:1px solid #38bdf8; border-radius:10px; padding:25px;">
                    <h2 style="color:#00e5ff; margin-top:0;">🛡️ TamperTrace SMTP Diagnostics</h2>
                    <p>This is a live test notification from your <strong>TamperTrace Platform</strong>.</p>
                    <div style="background-color:rgba(0, 229, 255, 0.1); border-left:4px solid #00e5ff; padding:12px; margin:15px 0; font-size:14px;">
                        <div><strong>Sender:</strong> {Config.EMAIL_SENDER}</div>
                        <div><strong>Recipient:</strong> {recipient}</div>
                        <div><strong>SMTP Server:</strong> {Config.SMTP_SERVER}:{Config.SMTP_PORT}</div>
                        <div><strong>Timestamp:</strong> {timestamp}</div>
                    </div>
                    <p style="color:#10b981; font-weight:bold;">✅ Your SMTP configuration is fully active and ready to deliver real-time defacement alerts.</p>
                    <div style="margin-top:20px; font-size:12px; color:#9aa4bf;">
                        If this email landed in your Spam or Promotions folder, mark it as 'Not Spam' to ensure critical security alerts reach your primary inbox.
                    </div>
                </div>
            </body>
            </html>
            """

            msg = MIMEMultipart("alternative")
            msg["From"] = f"TamperTrace Security <{Config.EMAIL_SENDER}>"
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.attach(MIMEText(f"TamperTrace test email sent successfully at {timestamp}.", "plain", "utf-8"))
            msg.attach(MIMEText(html, "html", "utf-8"))

            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=25)
            server.ehlo()
            server.starttls()
            server.login(Config.EMAIL_SENDER, Config.EMAIL_PASSWORD)
            server.sendmail(Config.EMAIL_SENDER, [recipient], msg.as_string())
            server.quit()

            _safe_log(f"✅ Diagnostic test email successfully sent to {recipient}")
            return True, f"Diagnostic test email successfully sent to {recipient}"

        except Exception as e:
            err = str(e)
            _safe_log(f"❌ Diagnostic test email failed: {err}")
            return False, f"SMTP Error: {err}"
