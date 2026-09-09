from flask import Blueprint, render_template, request, redirect, flash, jsonify
from app.repositories.incident_repository import IncidentRepository
from app.services.alert_service import AlertService
from config import Config

alerts_bp = Blueprint("alerts", __name__)

@alerts_bp.route("/alerts")
def alerts():
    """Display forensic audit log of all detected tampering incidents."""
    incident_logs = IncidentRepository.get_all(limit=100)
    return render_template("alerts.html", alerts=incident_logs, email_sender=Config.EMAIL_SENDER)

@alerts_bp.route("/forensics")
def forensics():
    """Alias route to alerts forensics view."""
    incident_logs = IncidentRepository.get_all(limit=100)
    return render_template("alerts.html", alerts=incident_logs, email_sender=Config.EMAIL_SENDER)

@alerts_bp.route("/test_email", methods=["GET", "POST"])
def test_email():
    """Send a live diagnostic test email to verify SMTP configuration."""
    if request.is_json:
        data = request.get_json() or {}
        to_email = data.get("to_email", "").strip() or Config.EMAIL_SENDER
    else:
        to_email = (request.form.get("to_email") or request.args.get("to_email") or "").strip() or Config.EMAIL_SENDER

    success, message = AlertService.send_test_email(to_email)

    if request.is_json or request.headers.get("Accept") == "application/json":
        status_code = 200 if success else 400
        return jsonify({"success": success, "message": message}), status_code

    if success:
        flash(f"✅ Diagnostic test email successfully delivered to {to_email}! Check your inbox (and Spam/Promotions folder).", "success")
    else:
        flash(f"❌ Failed to deliver test email: {message}", "error")

    return redirect(request.referrer or "/alerts")
