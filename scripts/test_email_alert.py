import os
import sys
import smtplib

# Reconfigure stdout to prevent Windows cp1252 UnicodeEncodeError
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from app.integrations.email import EmailClient

def run_email_diagnostics():
    """Run full diagnostic test suite on TamperTrace SMTP configuration."""
    print("=" * 65)
    print("🛡️  TamperTrace SMTP Alerting Diagnostic Tool")
    print("=" * 65)

    sender = Config.EMAIL_SENDER
    password = Config.EMAIL_PASSWORD
    server = Config.SMTP_SERVER
    port = Config.SMTP_PORT

    print(f"📧 EMAIL_SENDER   : {sender if sender else '❌ NOT CONFIGURED'}")
    print(f"🔑 EMAIL_PASSWORD : {'*' * len(password) if password else '❌ NOT CONFIGURED'}")
    print(f"🌐 SMTP_SERVER    : {server}:{port}")
    print("-" * 65)

    if not sender or not password:
        print("❌ ERROR: Email credentials missing in your .env file!")
        print("   Please ensure EMAIL_SENDER and EMAIL_PASSWORD are set.")
        print("   For Gmail, use a 16-character Google App Password.")
        return False

    # Step 1: Network & SMTP Handshake
    print("Step 1: Connecting to SMTP server...")
    try:
        smtp = smtplib.SMTP(server, port, timeout=15)
        smtp.ehlo()
        print("✅ SMTP handshake successful.")
    except Exception as e:
        print(f"❌ Failed to connect to {server}:{port} -> {e}")
        return False

    # Step 2: STARTTLS
    print("Step 2: Initiating STARTTLS encryption...")
    try:
        smtp.starttls()
        smtp.ehlo()
        print("✅ TLS encryption established.")
    except Exception as e:
        print(f"❌ TLS negotiation failed -> {e}")
        smtp.close()
        return False

    # Step 3: Authentication
    print("Step 3: Authenticating credentials...")
    try:
        smtp.login(sender, password)
        print("✅ Authentication SUCCESSFUL!")
        smtp.quit()
    except Exception as e:
        print(f"❌ Authentication failed -> {e}")
        print("\n💡 Tips for Gmail users:")
        print("   1. Enable 2-Step Verification on your Google Account.")
        print("   2. Generate an 'App Password' at: https://myaccount.google.com/apppasswords")
        print("   3. Put that 16-character password into EMAIL_PASSWORD in .env.")
        return False

    # Step 4: Dispatch live test email
    target = sys.argv[1] if len(sys.argv) > 1 else sender
    print(f"\nStep 4: Dispatching live verification email to {target}...")
    success, message = EmailClient.send_test_email(target)

    if success:
        print("=" * 65)
        print("🎉 SUCCESS: Test alert email sent and accepted by mail server!")
        print(f"   Target Inbox : {target}")
        print("   ⚠️ Note: If you do not see it in your Primary inbox, check:")
        print("      - Spam / Junk folder")
        print("      - Promotions folder (in Gmail)")
        print("=" * 65)
        return True
    else:
        print(f"❌ Delivery dispatch failed -> {message}")
        return False

if __name__ == "__main__":
    run_email_diagnostics()
