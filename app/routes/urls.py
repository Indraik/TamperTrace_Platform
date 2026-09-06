import os
import datetime
import urllib.parse
from flask import Blueprint, render_template, request, redirect, flash
from config import Config
from app.database import (
    get_monitored_urls_col,
    get_vt_results_col,
    get_change_logs_col,
    get_settings_col
)
from app.services.browser_service import BrowserService
from app.services.virustotal_service import VirusTotalService

urls_bp = Blueprint("urls", __name__)

@urls_bp.route("/add_url", methods=["GET", "POST"])
def add_url():
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

            get_monitored_urls_col().insert_one(site_data)

            # Auto Threat Intel scan if enabled
            settings = get_settings_col().find_one({"name": "system"})
            if settings and settings.get("threat_intel_enabled", False):
                try:
                    vt_service = VirusTotalService()
                    vt_result = vt_service.scan_url(url)
                    if vt_result:
                        vt_result["scan_date"] = datetime.datetime.now()
                        get_vt_results_col().insert_one(vt_result)
                except Exception as e:
                    print("Threat Intel scan failed:", e)

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

@urls_bp.route("/approve_change")
def approve_change():
    url = request.args.get("url")
    if not url:
        flash("❌ Invalid request", "error")
        return redirect("/dashboard")

    collection = get_monitored_urls_col()
    record = collection.find_one({"url": url})
    if not record:
        flash("❌ URL not found in database", "error")
        return redirect("/dashboard")

    try:
        # Re-capture current state to lock new baseline
        html_source, new_hash, screenshot_path = BrowserService.capture_initial_baseline(url)

        collection.update_one({"url": url}, {
            "$set": {
                "html_hash": new_hash,
                "screenshot_path": screenshot_path,
                "change_detected": False,
                "last_verified": datetime.datetime.now(),
                "status": "✅ Approved by Admin"
            }
        })
        flash(f"✅ Approved! Baseline updated for {url}", "success")
    except Exception as e:
        flash(f"❌ Error updating baseline: {str(e)}", "error")

    return redirect("/dashboard")

@urls_bp.route("/deny_change")
def deny_change():
    url = request.args.get("url")
    if not url:
        flash("❌ Invalid request", "error")
        return redirect("/dashboard")

    collection = get_monitored_urls_col()
    record = collection.find_one({"url": url})
    if not record:
        flash("❌ URL not found in database", "error")
        return redirect("/dashboard")

    collection.update_one({"url": url}, {
        "$set": {
            "status": "🚨 Defaced / Under Investigation",
            "change_detected": True,
            "last_verified": datetime.datetime.now()
        }
    })
    flash(f"🚨 Tampering confirmed for {url}. Incident flagged.", "warning")
    return redirect("/dashboard")

@urls_bp.route("/delete_url")
def delete_url():
    url = request.args.get("url")
    if not url:
        flash("❌ Invalid URL parameter", "error")
        return redirect("/dashboard")

    url = urllib.parse.unquote(url)
    collection = get_monitored_urls_col()
    record = collection.find_one({"url": url})
    if not record:
        flash("❌ URL not found", "error")
        return redirect("/dashboard")

    # Remove screenshots
    try:
        screenshot_path = record.get("screenshot_path")
        if screenshot_path and os.path.exists(screenshot_path):
            os.remove(screenshot_path)
    except Exception:
        pass

    # Remove archived captures
    try:
        archive_dir = Config.ARCHIVE_FOLDER
        if os.path.exists(archive_dir):
            url_clean = url.replace("://", "").replace("/", "_")
            for f in os.listdir(archive_dir):
                if url_clean in f:
                    os.remove(os.path.join(archive_dir, f))
    except Exception:
        pass

    # Remove database records across collections
    collection.delete_one({"url": url})
    get_vt_results_col().delete_many({"url": url})
    get_change_logs_col().delete_many({"url": url})

    flash(f"🗑️ {url} removed from monitoring and threat intelligence", "success")
    return redirect("/dashboard")
