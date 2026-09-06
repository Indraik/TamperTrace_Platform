import time
from flask import Blueprint, render_template, request, redirect, flash
from app.repositories.url_repository import UrlRepository
from app.repositories.threat_repository import ThreatRepository
from app.repositories.settings_repository import SettingsRepository
from app.services.virustotal_service import VirusTotalService, get_threat_level

threats_bp = Blueprint("threats", __name__)

@threats_bp.route("/threats")
def threat_dashboard():
    """Threat intelligence dashboard displaying categorized scans and stats."""
    monitored_urls = UrlRepository.get_active_urls()

    threats = []
    suspicious = []
    clean = []

    malicious_count = 0
    suspicious_count = 0
    clean_count = 0

    for rec in monitored_urls:
        url = rec["url"]
        scan = ThreatRepository.get_by_url(url)

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
    """Execute on-demand threat intelligence scan on a specified URL."""
    url = VirusTotalService.normalize_url(request.form.get("url", ""))
    if not url:
        flash("❌ Please enter a valid URL", "error")
        return redirect("/dashboard")

    if not SettingsRepository.is_threat_intel_enabled():
        flash("⚠️ Threat Intelligence is disabled in settings. Please enable it to run scans.", "warning")
        return redirect("/dashboard")

    try:
        vt_service = VirusTotalService()
        result = vt_service.scan_url(url, force_rescan=True)
        if not result:
            flash("❌ Scan failed (no response from threat intelligence engine)", "error")
            return redirect("/dashboard")

        threat_lvl = get_threat_level(result)
        flash(f"🔍 Threat Intelligence Scan Completed → Threat Level: {threat_lvl.upper()}", "success")
    except Exception as e:
        flash(f"❌ Scan failed: {str(e)}", "error")

    return redirect("/dashboard")

@threats_bp.route("/toggle_threat_intel", methods=["GET", "POST"])
def toggle_threat_intel():
    """Toggle automated Threat Intelligence scanning."""
    new_value = SettingsRepository.toggle_threat_intel()

    if new_value:
        flash("🟢 Threat Intelligence Enabled – Background analysis active", "success")
    else:
        flash("🔴 Threat Intelligence Disabled", "warning")

    return redirect("/threats")
