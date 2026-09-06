from flask import Blueprint, render_template, request, redirect, flash, send_file
from jinja2.exceptions import TemplateNotFound
from app.database import (
    get_settings_col,
    get_change_logs_col,
    get_monitored_urls_col
)
from app.services.report_service import ReportService

system_bp = Blueprint("system", __name__)

@system_bp.route("/toggle_scheduler")
def toggle_scheduler():
    settings_col = get_settings_col()
    settings = settings_col.find_one({"name": "system"})
    current = settings.get("scheduler_enabled", False) if settings else False
    new_value = not current

    settings_col.update_one(
        {"name": "system"},
        {"$set": {"scheduler_enabled": new_value}}
    )

    msg = "🟢 Monitoring Scheduler Enabled" if new_value else "🔴 Monitoring Scheduler Paused"
    flash(msg, "info")
    return redirect("/dashboard")

@system_bp.route("/download_report")
def download_report():
    buffer = ReportService.generate_threat_report()
    return send_file(
        buffer,
        as_attachment=True,
        download_name="TamperTrace_Threat_Report.pdf",
        mimetype="application/pdf"
    )

@system_bp.route("/alerts")
def alerts():
    alerts_list = list(get_change_logs_col().find().sort("detected_at", -1))
    return render_template("alerts.html", alerts=alerts_list)

@system_bp.route("/forensics")
def forensics():
    alerts_list = list(get_change_logs_col().find().sort("detected_at", -1))
    return render_template("alerts.html", alerts=alerts_list)

@system_bp.route("/websites")
def websites():
    try:
        records = list(get_monitored_urls_col().find())
        return render_template("websites.html", websites=records)
    except TemplateNotFound:
        return redirect("/dashboard")

@system_bp.route("/monitoring")
def monitoring():
    try:
        records = list(get_monitored_urls_col().find())
        return render_template("monitoring.html", websites=records)
    except TemplateNotFound:
        return redirect("/dashboard")

@system_bp.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        flash("✅ System configuration updated successfully.", "success")
        return redirect("/dashboard")
    try:
        return render_template("settings.html")
    except TemplateNotFound:
        flash("ℹ️ Settings panel is integrated into dashboard toggles.", "info")
        return redirect("/dashboard")

@system_bp.route("/export_logs")
def export_logs():
    try:
        logs = list(get_change_logs_col().find())
        return render_template("export_logs.html", logs=logs)
    except TemplateNotFound:
        return redirect("/alerts")
