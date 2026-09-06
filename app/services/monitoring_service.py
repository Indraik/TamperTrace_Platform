import os
import sys
import time
import hashlib
import datetime
from app.repositories.url_repository import UrlRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.settings_repository import SettingsRepository
from app.services.browser_service import BrowserService
from app.services.incident_service import IncidentService
from app.services.alert_service import AlertService
from app.detection.html_analyzer import HtmlAnalyzer
from app.detection.visual_analyzer import VisualAnalyzer
from app.detection.decision_engine import DecisionEngine

def _log(msg):
    """Print message safely without Windows charmap encoding errors."""
    try:
        print(msg)
    except UnicodeEncodeError:
        safe_msg = msg.encode(sys.stdout.encoding or "ascii", errors="replace").decode(sys.stdout.encoding or "ascii")
        print(safe_msg)

class MonitoringService:
    """Core orchestration service for automated website defacement scanning and baseline lifecycle."""

    @classmethod
    def run_monitoring_cycle(cls):
        """
        Execute a single monitoring cycle across all registered URLs.
        Preserves complete WARMUP -> BASELINE -> ACTIVE lifecycle.
        Returns a summary dictionary of cycle metrics.
        """
        if not SettingsRepository.is_scheduler_enabled():
            _log("[INFO] Monitoring scheduler is paused in settings. Skipping cycle.")
            return {"status": "paused", "checked": 0, "skipped": 0, "alerts": 0}

        cycle_start = time.time()
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        _log("=" * 60)
        _log(f"[CYCLE] Starting monitoring cycle at {now_str}")
        _log("=" * 60)

        records = UrlRepository.get_all()
        _log(f"[INFO] Found {len(records)} monitored URLs")

        checked_count = 0
        skipped_count = 0
        alert_count = 0

        for rec in records:
            url = rec.get("url")
            admin_email = rec.get("admin_email")
            admin_phone = rec.get("admin_phone")

            if not url or not admin_email:
                continue

            # Skip scanning if a defacement incident is unreviewed / pending
            if rec.get("change_detected", False):
                _log(f"[PENDING] Pending admin review -> skipping scan for {url}")
                skipped_count += 1
                continue

            _log(f"\n[SCAN] Checking: {url}")
            checked_count += 1

            is_first_scan = not rec.get("first_scan_done", False)
            if not rec.get("html_hash") or rec.get("html_hash") == "pending_initial_scan":
                UrlRepository.update_stage(rec["_id"], {"last_checked": datetime.datetime.now()})
                continue

            # Capture live page using BrowserService
            html_now, new_screenshot_path, is_success, loaded_url = BrowserService.capture_page(url)
            if not html_now:
                UrlRepository.update_stage(rec["_id"], {"last_checked": datetime.datetime.now()})
                _log(f"[ERROR] Capture failed for {url} -> skipped")
                continue

            # Verify route hasn't been unexpectedly redirected
            if loaded_url and not BrowserService.is_same_route(url, loaded_url):
                _log(f"[WARN] Route mismatch -> expected {url}, loaded {loaded_url}. Skipping.")
                skipped_count += 1
                UrlRepository.update_stage(rec["_id"], {
                    "last_checked": datetime.datetime.now(),
                    "status": f"Redirected to {loaded_url}"
                })
                continue

            if is_first_scan:
                time.sleep(2)
                UrlRepository.update_stage(rec["_id"], {"first_scan_done": True})

            # Calculate SHA-256 hash
            try:
                new_hash = hashlib.sha256(html_now.encode("utf-8")).hexdigest()
            except Exception:
                new_hash = hashlib.sha256(html_now.encode("latin-1", errors="ignore")).hexdigest()

            old_hash = rec.get("html_hash")
            new_core = HtmlAnalyzer.extract_core_features(html_now)
            old_core = rec.get("core_features", {})

            # Baseline Lifecycle: WARMUP -> BASELINE -> ACTIVE
            baseline_stage = rec.get("baseline_stage", "WARMUP")

            if baseline_stage == "WARMUP":
                _log(f"[WARMUP] Capturing initial page baseline for {url}")
                UrlRepository.update_baseline(
                    url=url,
                    html_hash=new_hash,
                    screenshot_path=new_screenshot_path,
                    core_features=new_core,
                    stage="BASELINE"
                )
                continue

            if baseline_stage == "BASELINE":
                _log(f"[BASELINE] Locking verified safe baseline snapshot for {url}")
                UrlRepository.update_baseline(
                    url=url,
                    html_hash=new_hash,
                    screenshot_path=new_screenshot_path,
                    core_features=new_core,
                    stage="ACTIVE"
                )
                ScanRepository.save_baseline_snapshot(
                    url=url,
                    html_content=html_now,
                    html_hash=new_hash
                )
                continue

            # ACTIVE Monitoring
            diff_percent, diff_img, visual_changed = VisualAnalyzer.compare_screenshots(
                rec.get("screenshot_path"),
                new_screenshot_path
            )

            decision, reason = DecisionEngine.evaluate(old_core, new_core, diff_percent)

            if decision == "TAMPER":
                _log(f"[TAMPER] CONFIRMED for {url}: {reason} (Diff: {diff_percent:.2f}%)")
                alert_count += 1

                IncidentService.handle_tamper_incident(
                    url=url,
                    old_hash=old_hash,
                    new_hash=new_hash,
                    decision=decision,
                    reason=reason,
                    diff_percent=diff_percent,
                    old_screenshot_path=rec.get("screenshot_path"),
                    new_screenshot_path=new_screenshot_path,
                    diff_image_path=diff_img,
                    core_features=new_core
                )

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

            else:
                UrlRepository.update_baseline(
                    url=url,
                    html_hash=new_hash,
                    screenshot_path=new_screenshot_path,
                    core_features=new_core
                )

            time.sleep(1)

        duration = round(time.time() - cycle_start, 2)
        _log(f"\n[DONE] Cycle completed in {duration}s (Checked: {checked_count}, Skipped: {skipped_count}, Alerts: {alert_count})")
        _log("=" * 60)

        return {
            "status": "completed",
            "duration": duration,
            "checked": checked_count,
            "skipped": skipped_count,
            "alerts": alert_count
        }
