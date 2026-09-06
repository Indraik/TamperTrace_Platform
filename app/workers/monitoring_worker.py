import os
import sys
import time
import hashlib
import datetime

# Fix Windows console UTF-8 emoji encoding
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from config import Config
from app.database import (
    get_monitored_urls_col,
    get_change_logs_col,
    get_scans_col,
    get_settings_col
)
from app.services.browser_service import BrowserService
from app.services.detection_service import DetectionService
from app.services.alert_service import AlertService

def safe_print(*args, **kwargs):
    """Safely print text handling Windows charmap encoding limitations."""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        encoded_args = [
            arg.encode(sys.stdout.encoding or "ascii", errors="replace").decode(sys.stdout.encoding or "ascii")
            if isinstance(arg, str) else arg
            for arg in args
        ]
        print(*encoded_args, **kwargs)

def monitor_websites():
    """Execute a single monitoring pass across all monitored URLs."""
    settings = get_settings_col().find_one({"name": "system"})
    if not settings or not settings.get("scheduler_enabled", False):
        safe_print("⏸ Scheduler is paused in database. Skipping monitoring cycle.")
        return

    collection = get_monitored_urls_col()
    change_logs = get_change_logs_col()
    scans_col = get_scans_col()

    cycle_start = time.time()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    safe_print("=" * 60)
    safe_print(f"🟢 Starting monitoring cycle at {now_str}")
    safe_print("=" * 60)

    records = list(collection.find({}))
    safe_print(f"📋 Found {len(records)} monitored URLs")

    total_urls = len(records)
    checked_count = 0
    skipped_count = 0
    alert_count = 0

    for rec in records:
        url = rec.get("url")
        admin_email = rec.get("admin_email")
        admin_phone = rec.get("admin_phone")

        if not url or not admin_email:
            continue

        # Skip if an unreviewed tampering incident is already pending
        if rec.get("change_detected", False):
            safe_print(f"⏳ Pending admin review → skipping scan for {url}")
            skipped_count += 1
            continue

        safe_print(f"\n🔎 Checking: {url}")
        checked_count += 1

        is_first_scan = not rec.get("first_scan_done", False)
        if not rec.get("html_hash") or rec.get("html_hash") == "pending_initial_scan":
            collection.update_one(
                {"_id": rec["_id"]},
                {"$set": {"last_checked": datetime.datetime.now()}}
            )
            continue

        # Capture live page
        html_now, new_screenshot_path, is_success, loaded_url = BrowserService.capture_page(url)
        if not html_now:
            collection.update_one(
                {"_id": rec["_id"]},
                {"$set": {"last_checked": datetime.datetime.now()}}
            )
            safe_print("❌ Capture failed → skipped")
            continue

        # Route validation
        if loaded_url and not BrowserService.is_same_route(url, loaded_url):
            safe_print(f"⚠️ Route mismatch → expected {url}, loaded {loaded_url}. Skipping.")
            skipped_count += 1
            collection.update_one(
                {"_id": rec["_id"]},
                {"$set": {
                    "last_checked": datetime.datetime.now(),
                    "status": f"⚠️ Redirected to {loaded_url}"
                }}
            )
            continue

        if is_first_scan:
            time.sleep(2)
            collection.update_one(
                {"_id": rec["_id"]},
                {"$set": {"first_scan_done": True}}
            )

        try:
            new_hash = hashlib.sha256(html_now.encode("utf-8")).hexdigest()
        except Exception:
            new_hash = hashlib.sha256(html_now.encode("latin-1", errors="ignore")).hexdigest()

        old_hash = rec.get("html_hash")
        new_core = DetectionService.extract_core_html_features(html_now)
        old_core = rec.get("core_features", {})

        # Staging: WARMUP -> BASELINE -> ACTIVE
        baseline_stage = rec.get("baseline_stage", "WARMUP")

        if baseline_stage == "WARMUP":
            safe_print("🟡 WARMUP scan → capturing page baseline")
            collection.update_one(
                {"_id": rec["_id"]},
                {"$set": {
                    "html_hash": new_hash,
                    "core_features": new_core,
                    "screenshot_path": new_screenshot_path,
                    "baseline_stage": "BASELINE",
                    "last_checked": datetime.datetime.now()
                }}
            )
            continue

        if baseline_stage == "BASELINE":
            safe_print("🟢 BASELINE scan → locking safe baseline")
            collection.update_one(
                {"_id": rec["_id"]},
                {"$set": {
                    "html_hash": new_hash,
                    "core_features": new_core,
                    "screenshot_path": new_screenshot_path,
                    "baseline_stage": "ACTIVE",
                    "last_checked": datetime.datetime.now()
                }}
            )
            scans_col.insert_one({
                "url": url,
                "html_content": html_now,
                "hash": new_hash,
                "status": "SAFE",
                "timestamp": datetime.datetime.now(),
                "is_baseline": True
            })
            continue

        # ACTIVE Monitoring
        diff_percent, diff_img, visual_changed = DetectionService.compare_screenshots_meaningful(
            rec.get("screenshot_path"),
            new_screenshot_path
        )

        decision, reason = DetectionService.decide_tamper(old_core, new_core, diff_percent)

        if decision == "TAMPER":
            safe_print(f"🚨 TAMPER CONFIRMED for {url}: {reason} (diff: {diff_percent:.2f}%)")
            alert_count += 1

            # Archive previous screenshot
            try:
                prev_sh = rec.get("screenshot_path")
                if prev_sh and os.path.exists(prev_sh):
                    os.makedirs(Config.ARCHIVE_FOLDER, exist_ok=True)
                    archive_name = f"{hashlib.md5((url + str(time.time())).encode()).hexdigest()}.png"
                    archive_path = os.path.join(Config.ARCHIVE_FOLDER, archive_name)
                    with open(prev_sh, "rb") as fr, open(archive_path, "wb") as fw:
                        fw.write(fr.read())
            except Exception:
                pass

            # Insert incident forensic log
            change_logs.insert_one({
                "url": url,
                "detected_at": datetime.datetime.now(),
                "old_hash": old_hash,
                "new_hash": new_hash,
                "decision": decision,
                "reason": reason,
                "visual_diff_percentage": diff_percent,
                "old_screenshot": rec.get("screenshot_path"),
                "new_screenshot": new_screenshot_path,
                "diff_image": diff_img
            })

            # Send Email and WhatsApp alerts
            AlertService.notify_tamper(
                url=url,
                reason=reason,
                diff_percentage=diff_percent,
                old_screenshot=rec.get("screenshot_path"),
                new_screenshot=new_screenshot_path,
                diff_img=diff_img,
                admin_email=admin_email,
                admin_phone=admin_phone
            )

            # Freeze site state pending admin review
            collection.update_one(
                {"_id": rec["_id"]},
                {"$set": {
                    "core_features": new_core,
                    "screenshot_path": new_screenshot_path,
                    "decision": decision,
                    "change_reason": reason,
                    "change_detected": True,
                    "last_checked": datetime.datetime.now(),
                    "last_change": datetime.datetime.now()
                }}
            )

        else:
            # IGNORE → Dynamic noise / ad change: update baseline silently
            collection.update_one(
                {"_id": rec["_id"]},
                {"$set": {
                    "html_hash": new_hash,
                    "core_features": new_core,
                    "screenshot_path": new_screenshot_path,
                    "decision": decision,
                    "change_detected": False,
                    "last_checked": datetime.datetime.now()
                }}
            )

        time.sleep(1)

    duration = round(time.time() - cycle_start, 2)
    safe_print(f"\n✅ Cycle completed in {duration}s (Checked: {checked_count}, Skipped: {skipped_count}, Alerts: {alert_count})")
    safe_print("=" * 60)

def run_monitoring_loop():
    """Continuous background worker loop honoring database scheduler toggle."""
    safe_print("🕒 TamperTrace Background Monitoring Worker Started")
    safe_print(f"⚙️ Config: Interval={Config.SCAN_INTERVAL_SECONDS}s, Timeout={Config.PAGE_LOAD_TIMEOUT}s")

    while True:
        try:
            settings = get_settings_col().find_one({"name": "system"})
            if settings and settings.get("scheduler_enabled", False):
                monitor_websites()
            else:
                safe_print("🔴 Scheduler is OFF in system settings. Standing by...")

            time.sleep(Config.SCAN_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            safe_print("\n🛑 Monitoring worker stopped by user.")
            break
        except Exception as e:
            safe_print(f"❌ Worker cycle exception: {e}")
            time.sleep(15)
