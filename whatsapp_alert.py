import os
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

def send_whatsapp_alert(to_number, url, reason):
    try:
        account_sid = os.getenv("TWILIO_SID")
        auth_token = os.getenv("TWILIO_AUTH_TOKEN")

        if not account_sid or not auth_token:
            print("❌ Twilio credentials missing")
            return

        client = Client(account_sid, auth_token)

        message = client.messages.create(
            from_="whatsapp:+14155238886",  # Twilio Sandbox
            to=f"whatsapp:{to_number}",
            body=(
                "🚨 *TamperTrace Alert*\n\n"
                f"🌐 Website: {url}\n"
                f"⚠️ Issue: {reason}\n\n"
                "Please check immediately."
            )
        )

        print("📲 WhatsApp alert sent → SID:", message.sid)

    except Exception as e:
        print("❌ WhatsApp alert failed:", e)
