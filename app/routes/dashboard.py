from flask import Blueprint, render_template, redirect
from app.database import get_monitored_urls_col
from app.services.virustotal_service import VirusTotalService

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def home():
    return redirect("/dashboard")

@dashboard_bp.route("/dashboard")
def dashboard():
    collection = get_monitored_urls_col()
    records = list(collection.find())
    scan_history = VirusTotalService.get_scan_history(5)

    safe_count = len([
        r for r in records
        if not r.get('change_detected', False) and r.get('vt_malicious', 0) == 0
    ])

    defaced_count = len([
        r for r in records
        if r.get('change_detected', False)
    ])

    high_threat_count = len([
        r for r in records
        if r.get('vt_malicious', 0) > 0
    ])

    threat_stats = {
        'total': len(records),
        'safe': safe_count,
        'defaced': defaced_count,
        'high_threat': high_threat_count,
        'malicious_resources': sum([r.get('malicious_resources', 0) for r in records])
    }

    return render_template(
        "dashboard.html",
        urls=records,
        scan_history=scan_history,
        threat_stats=threat_stats
    )
