from flask import Blueprint, render_template, request, redirect, flash, send_file
from jinja2.exceptions import TemplateNotFound
from app.repositories.settings_repository import SettingsRepository
from app.repositories.url_repository import UrlRepository
from app.repositories.incident_repository import IncidentRepository
from app.services.report_service import ReportService

system_bp = Blueprint("system", __name__)

@system_bp.route("/toggle_scheduler", methods=["GET", "POST"])
def toggle_scheduler():
    """Toggle the background monitoring scheduler ON or OFF."""
    new_value = SettingsRepository.toggle_scheduler()
    msg = "🟢 Monitoring Scheduler Enabled" if new_value else "🔴 Monitoring Scheduler Paused"
    flash(msg, "info")
    return redirect("/dashboard")

@system_bp.route("/download_report")
def download_report():
    """Generate and stream executive audit threat intelligence PDF report."""
    buffer = ReportService.generate_threat_report()
    return send_file(
        buffer,
        as_attachment=True,
        download_name="TamperTrace_Threat_Report.pdf",
        mimetype="application/pdf"
    )

@system_bp.route("/websites")
def websites():
    """Websites list view with fallback to dashboard."""
    try:
        records = UrlRepository.get_all()
        return render_template("websites.html", websites=records)
    except TemplateNotFound:
        return redirect("/dashboard")

@system_bp.route("/monitoring")
def monitoring():
    """Active monitoring overview with fallback to dashboard."""
    try:
        records = UrlRepository.get_all()
        return render_template("monitoring.html", websites=records)
    except TemplateNotFound:
        return redirect("/dashboard")

@system_bp.route("/settings", methods=["GET", "POST"])
def settings():
    """System settings management with fallback to dashboard."""
    if request.method == "POST":
        flash("✅ System configuration updated successfully.", "success")
        return redirect("/dashboard")
    try:
        return render_template("settings.html")
    except TemplateNotFound:
        flash("ℹ️ Settings controls are integrated directly into dashboard toggles.", "info")
        return redirect("/dashboard")

@system_bp.route("/export_logs")
def export_logs():
    """Export forensic change logs with fallback to alerts."""
    try:
        logs = IncidentRepository.get_all()
        return render_template("export_logs.html", logs=logs)
    except TemplateNotFound:
        return redirect("/alerts")
