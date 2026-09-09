import sys
from twilio.rest import Client as TwilioClient
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

class WhatsAppClient:
    """External WhatsApp integration using Twilio REST API."""

    @staticmethod
    def send_tamper_alert(to_number, url, reason):
        """Send instant WhatsApp alert message."""
        sid = Config.TWILIO_SID
        token = Config.TWILIO_AUTH_TOKEN

        if not sid or not token:
            _safe_log("⚠️ Twilio credentials missing in configuration. Skipping WhatsApp.")
            return False

        recipient = to_number or Config.ADMIN_WHATSAPP
        if not recipient:
            _safe_log("⚠️ No recipient phone number configured for WhatsApp.")
            return False

        try:
            client = TwilioClient(sid, token)
            message = client.messages.create(
                from_="whatsapp:+14155238886",  # Twilio Sandbox number
                to=f"whatsapp:{recipient}",
                body=(
                    "🚨 *TamperTrace Alert*\n\n"
                    f"🌐 Website: {url}\n"
                    f"⚠️ Issue: {reason}\n\n"
                    "Please review your admin dashboard immediately."
                )
            )
            _safe_log(f"📲 WhatsApp alert sent successfully -> SID: {message.sid}")
            return True
        except Exception as e:
            _safe_log(f"❌ WhatsApp alert failed: {e}")
            return False
