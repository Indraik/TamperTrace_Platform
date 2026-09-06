import os
import datetime
import urllib.parse
from flask import Blueprint, render_template, request, redirect, flash
from config import Config
from app.repositories.url_repository import UrlRepository
from app.repositories.threat_repository import ThreatRepository
from app.repositories.incident_repository import IncidentRepository
from app.repositories.settings_repository import SettingsRepository
from app.services.browser_service import BrowserService
from app.services.virustotal_service import VirusTotalService

urls_bp = Blueprint("urls", __name__)

@urls_bp.route("/add_url", methods=["GET", "POST"])
def add_url():
    """Register and establish initial baseline for a target website."""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        admin_email = request.form.get("admin_email", "").strip()
        admin_phone = request.form.get("phone", "").strip()

        if not url:
            flash("❌ Please enter a valid URL", "error")
            return redirect("/add_url")

        try:
            print(f"🚀 Capturing initial baseline for URL: {url}")
            html_source, html_hash, screenshot_path = BrowserService.capture_initial_baseline(url)

            site_data = {
                "url": url,
                "admin_email": admin_email,
                "admin_phone": admin_phone,
                "html_hash": html_hash,
                "screenshot_path": screenshot_path,
                "external_resources": [],
                "change_detected": False,
                "last_checked": datetime.datetime.now(),
                "last_change": None,
                "status": "Normal",
                "threat_level": "unknown",
                "malicious_resources": 0,
                "baseline_stage": "WARMUP",
                "baseline_completed": False,
                "created_at": datetime.datetime.now()
            }

            UrlRepository.add_url(site_data)

            # Auto Threat Intel scan if enabled
            if SettingsRepository.is_threat_intel_enabled():
                try:
                    vt_service = VirusTotalService()
                    vt_service.scan_url(url)
                except Exception as e:
                    print(f"Auto VT scan notice: {e}")

            flash(f"✅ Successfully added {url} for monitoring!", "success")
            return redirect("/dashboard")

        except Exception as e:
            error_msg = str(e)
            print(f"❌ Error adding URL {url}: {error_msg}")
            if "timeout" in error_msg.lower():
                flash(f"❌ Timeout error: Website {url} took too long to load.", "error")
            elif "net::" in error_msg:
                flash(f"❌ Network error: Cannot reach {url}.", "error")
            else:
                flash(f"❌ Error adding URL: {error_msg[:120]}...", "error")
            return redirect("/add_url")

    return render_template("add_url.html")

@urls_bp.route("/approve_change", methods=["GET", "POST"])
def approve_change():
    """Approve observed changes and update the safe baseline."""
    url = request.args.get("url") if request.method == "GET" else request.form.get("url")
    if not url:
        flash("❌ Invalid request: URL missing", "error")
        return redirect("/dashboard")

    record = UrlRepository.get_by_url(url)
    if not record:
        flash("❌ URL not found in database", "error")
        return redirect("/dashboard")

    try:
        html_source, new_hash, screenshot_path = BrowserService.capture_initial_baseline(url)
        UrlRepository.update_baseline(
            url=url,
            html_hash=new_hash,
            screenshot_path=screenshot_path,
            status="✅ Approved by Admin"
        )
        flash(f"✅ Approved! Safe baseline updated for {url}", "success")
    except Exception as e:
        flash(f"❌ Error updating baseline: {str(e)}", "error")

    return redirect("/dashboard")

@urls_bp.route("/deny_change", methods=["GET", "POST"])
def deny_change():
    """Flag changes as confirmed tampering / defacement under active investigation."""
    url = request.args.get("url") if request.method == "GET" else request.form.get("url")
    if not url:
        flash("❌ Invalid request: URL missing", "error")
        return redirect("/dashboard")

    record = UrlRepository.get_by_url(url)
    if not record:
        flash("❌ URL not found in database", "error")
        return redirect("/dashboard")

    UrlRepository.confirm_defaced(url)
    flash(f"🚨 Tampering confirmed for {url}. Incident flagged for investigation.", "warning")
    return redirect("/dashboard")

@urls_bp.route("/delete_url", methods=["GET", "POST"])
def delete_url():
    """Remove a URL from active monitoring and clean up associated assets."""
    raw_url = request.args.get("url") if request.method == "GET" else request.form.get("url")
    if not raw_url:
        flash("❌ Invalid URL parameter", "error")
        return redirect("/dashboard")

    url = urllib.parse.unquote(raw_url)
    record = UrlRepository.get_by_url(url)
    if not record:
        flash("❌ URL not found", "error")
        return redirect("/dashboard")

    # Clean up screenshots and archives
    try:
        sh_path = record.get("screenshot_path")
        if sh_path and os.path.exists(sh_path):
            os.remove(sh_path)
    except Exception:
        pass

    try:
        archive_dir = Config.ARCHIVE_FOLDER
        if os.path.exists(archive_dir):
            url_clean = url.replace("://", "").replace("/", "_")
            for f in os.listdir(archive_dir):
                if url_clean in f:
                    os.remove(os.path.join(archive_dir, f))
    except Exception:
        pass

    # Remove records across repositories
    UrlRepository.delete_by_url(url)
    ThreatRepository.delete_by_url(url)
    IncidentRepository.delete_by_url(url)

    flash(f"🗑️ {url} removed from monitoring and threat intelligence", "success")
    return redirect("/dashboard")
