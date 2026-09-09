from flask import Blueprint, render_template, redirect, jsonify
from app.repositories.url_repository import UrlRepository
from app.repositories.settings_repository import SettingsRepository
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

@dashboard_bp.route("/api/worker_telemetry")
def worker_telemetry():
    """Real-time monitoring engine telemetry for frontend status ticker and live stage updates."""
    records = UrlRepository.get_all()
    threat_stats = UrlRepository.get_stats()

    stages = {
        "warmup": 0,
        "baseline": 0,
        "active": 0,
        "defaced": 0
    }
    recent_activity = []

    for r in records:
        url = r.get("url", "unknown")
        last_checked = r.get("last_checked")
        time_str = last_checked.strftime("%H:%M:%S") if last_checked else "Pending"

        if r.get("change_detected"):
            stages["defaced"] += 1
            recent_activity.append({
                "url": url,
                "stage": "DEFACED",
                "status": "🚨 Defacement Detected",
                "time": time_str
            })
        else:
            st = r.get("baseline_stage", "WARMUP")
            if st == "WARMUP":
                stages["warmup"] += 1
            elif st == "BASELINE":
                stages["baseline"] += 1
            else:
                stages["active"] += 1

            recent_activity.append({
                "url": url,
                "stage": st,
                "status": r.get("status", "Active Baseline"),
                "time": time_str
            })

    is_scheduler_running = SettingsRepository.is_scheduler_enabled()

    return jsonify({
        "scheduler_running": is_scheduler_running,
        "stats": threat_stats,
        "stages": stages,
        "total_monitored": len(records),
        "recent_activity": recent_activity
    })
