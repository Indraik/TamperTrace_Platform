from flask import Blueprint, render_template
from app.repositories.incident_repository import IncidentRepository

alerts_bp = Blueprint("alerts", __name__)

@alerts_bp.route("/alerts")
def alerts():
    """Display forensic audit log of all detected tampering incidents."""
    incident_logs = IncidentRepository.get_all(limit=100)
    return render_template("alerts.html", alerts=incident_logs)

@alerts_bp.route("/forensics")
def forensics():
    """Alias route to alerts forensics view."""
    incident_logs = IncidentRepository.get_all(limit=100)
    return render_template("alerts.html", alerts=incident_logs)
