import os
import sys

# Auto-locate project virtual environment site-packages if run with global Python
_base_dir = os.path.dirname(os.path.abspath(__file__))
_site_pkgs = os.path.join(_base_dir, "venv", "Lib", "site-packages")
if os.path.exists(_site_pkgs) and _site_pkgs not in sys.path:
    sys.path.insert(0, _site_pkgs)

from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base application configuration."""
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-123")
    
    # Directory paths
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "static/screenshots")
    ARCHIVE_FOLDER = os.getenv("ARCHIVE_FOLDER", "static/archive")
    
    # MongoDB connection
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    DATABASE_NAME = os.getenv("DATABASE_NAME", "tampertrace")
    
    # VirusTotal API
    VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
    
    # Alerting - SMTP Email
    EMAIL_SENDER = os.getenv("EMAIL_SENDER", "").strip()
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "").strip()
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    
    # Alerting - Twilio WhatsApp
    TWILIO_SID = os.getenv("TWILIO_SID", "").strip()
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
    ADMIN_WHATSAPP = os.getenv("ADMIN_WHATSAPP", "").strip()
    
    # Disaster Recovery (Target site)
    TARGET_SITE_ROOT = os.getenv("TARGET_SITE_ROOT", r"D:\Projects\fundtrail_backend_web")
    TARGET_BASE_URL = os.getenv("TARGET_BASE_URL", "http://127.0.0.1:5002")
    
    # Authenticated Scanning (optional for password protected target routes)
    AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")
    AUTH_LOGIN_URL = os.getenv("AUTH_LOGIN_URL", "http://127.0.0.1:5002/login").strip()
    AUTH_USERNAME = os.getenv("AUTH_USERNAME", "").strip()
    AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "").strip()
    AUTH_USERNAME_SELECTOR = os.getenv("AUTH_USERNAME_SELECTOR", "").strip()
    AUTH_PASSWORD_SELECTOR = os.getenv("AUTH_PASSWORD_SELECTOR", "").strip()
    AUTH_SUBMIT_SELECTOR = os.getenv("AUTH_SUBMIT_SELECTOR", "").strip()
    
    # Monitoring Engine Stabilization & Thresholds
    DOM_STABLE_SECONDS = float(os.getenv("DOM_STABLE_SECONDS", "3.0"))
    NETWORK_IDLE_SECONDS = float(os.getenv("NETWORK_IDLE_SECONDS", "1.5"))
    PAGE_LOAD_TIMEOUT = int(os.getenv("PAGE_LOAD_TIMEOUT", "25"))
    SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", "35"))
    VISUAL_DIFF_THRESHOLD = float(os.getenv("VISUAL_DIFF_THRESHOLD", "8.0"))

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = False
    DATABASE_NAME = os.getenv("TEST_DATABASE_NAME", "tampertrace_test")
