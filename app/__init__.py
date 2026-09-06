import os
from flask import Flask
from config import Config, DevelopmentConfig
from app.database import init_system_settings, get_settings_col
from app.services.virustotal_service import get_threat_level
from app.routes import register_blueprints

def create_app(config_class=DevelopmentConfig):
    """
    Application Factory creating and configuring the Flask application instance.
    """
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    template_dir = os.path.join(root_dir, "templates")
    static_dir = os.path.join(root_dir, "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )

    # Load configuration
    app.config.from_object(config_class)

    # Ensure runtime directories exist
    os.makedirs(os.path.join(root_dir, app.config.get("UPLOAD_FOLDER", "static/screenshots")), exist_ok=True)
    os.makedirs(os.path.join(root_dir, app.config.get("ARCHIVE_FOLDER", "static/archive")), exist_ok=True)

    # Initialize system settings in MongoDB
    try:
        init_system_settings()
    except Exception as e:
        print(f"⚠️ Could not initialize database on app startup: {e}")

    # Register template context processors
    @app.context_processor
    def utility_processor():
        return dict(get_threat_level=get_threat_level)

    @app.context_processor
    def inject_settings():
        try:
            settings = get_settings_col().find_one({"name": "system"})
        except Exception:
            settings = {"scheduler_enabled": False, "threat_intel_enabled": False}
        return dict(settings=settings)

    # Register blueprints
    register_blueprints(app)

    return app
