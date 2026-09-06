from flask import Blueprint, render_template, redirect
from app.repositories.url_repository import UrlRepository
from app.services.virustotal_service import VirusTotalService

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def home():
    """Root redirect to dashboard."""
    return redirect("/dashboard")

@dashboard_bp.route("/dashboard")
def dashboard():
    """Main administrative command center."""
    records = UrlRepository.get_all()
    scan_history = VirusTotalService.get_scan_history(limit=5)
    threat_stats = UrlRepository.get_stats()

    return render_template(
        "dashboard.html",
        urls=records,
        scan_history=scan_history,
        threat_stats=threat_stats
    )
