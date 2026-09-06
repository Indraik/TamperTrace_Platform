import time
import datetime
from flask import Blueprint, render_template, request, redirect, flash
from app.database import (
    get_monitored_urls_col,
    get_vt_results_col,
    get_settings_col
)
from app.services.virustotal_service import VirusTotalService, get_threat_level

threats_bp = Blueprint("threats", __name__)

@threats_bp.route("/threats")
def threat_dashboard():
    monitored_urls = list(get_monitored_urls_col().find({}, {"url": 1}))
    vt_results_col = get_vt_results_col()

    threats = []
    suspicious = []
    clean = []

    malicious_count = 0
    suspicious_count = 0
    clean_count = 0

    for rec in monitored_urls:
        url = rec["url"]
        scan = vt_results_col.find_one({"url": url}, sort=[("scan_date", -1)])

        if not scan:
            clean.append({
                "url": url,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "cached_result": True,
                "last_checked": None
            })
            clean_count += 1
            continue

        malicious = scan.get("malicious", 0)
        suspicious_cnt = scan.get("suspicious", 0)

        if malicious > 0:
            threats.append(scan)
            malicious_count += 1
        elif suspicious_cnt > 0:
            suspicious.append(scan)
            suspicious_count += 1
        else:
            clean.append(scan)
            clean_count += 1

    threat_stats = {
        "total_scans": len(monitored_urls),
        "malicious": malicious_count,
        "suspicious": suspicious_count,
        "clean": clean_count
    }

    return render_template(
        "threat_dashboard.html",
        threats=threats,
        suspicious=suspicious,
        clean=clean,
        threat_stats=threat_stats
    )

@threats_bp.route("/scan_url", methods=["POST"])
def scan_url():
    url = VirusTotalService.normalize_url(request.form.get("url", ""))
    if not url:
        flash("❌ Please enter a valid URL", "error")
        return redirect("/dashboard")

    settings = get_settings_col().find_one({"name": "system"})
    if not settings or not settings.get("threat_intel_enabled", False):
        flash("⚠️ Threat Intelligence is disabled. Enable it to run scans.", "warning")
        return redirect("/dashboard")

    try:
        vt_service = VirusTotalService()
        result = vt_service.scan_url(url, force_rescan=True)
        if not result:
            flash("❌ Scan failed (no response from threat intelligence engine)", "error")
            return redirect("/dashboard")

        threat_lvl = get_threat_level(result)
        flash(f"🔍 Scan Completed → Threat Level: {threat_lvl.upper()}", "success")
    except Exception as e:
        flash(f"❌ Scan failed: {str(e)}", "error")

    return redirect("/dashboard")

@threats_bp.route("/toggle_threat_intel")
def toggle_threat_intel():
    settings_col = get_settings_col()
    settings = settings_col.find_one({"name": "system"})
    current = settings.get("threat_intel_enabled", False) if settings else False
    new_value = not current

    settings_col.update_one(
        {"name": "system"},
        {"$set": {"threat_intel_enabled": new_value}}
    )

    if new_value:
        flash("🟢 Threat Intelligence Enabled – Scanning monitored URLs in background", "success")
        vt_service = VirusTotalService()
        urls = list(get_monitored_urls_col().find({}, {"url": 1}))

        for rec in urls:
            try:
                vt_service.scan_url(rec["url"])
                time.sleep(1)
            except Exception as e:
                print(f"VT scan failed for {rec['url']}: {e}")
        vt_service.close()
    else:
        flash("🔴 Threat Intelligence Disabled", "warning")

    return redirect("/threats")
