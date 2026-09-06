from app.routes.dashboard import dashboard_bp
from app.routes.urls import urls_bp
from app.routes.threats import threats_bp
from app.routes.recovery import recovery_bp
from app.routes.alerts import alerts_bp
from app.routes.system import system_bp

def register_blueprints(app):
    """Register all modular application blueprints."""
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(urls_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(recovery_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(system_bp)
