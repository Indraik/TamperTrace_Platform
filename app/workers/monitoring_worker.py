import sys
import time

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from config import Config
from app.services.monitoring_service import MonitoringService

def monitor_websites():
    """Execute a single monitoring cycle delegating to MonitoringService."""
    return MonitoringService.run_monitoring_cycle()

def run_monitoring_loop():
    """Continuous background worker loop honoring scan intervals and handling top-level exceptions."""
    print("🕒 TamperTrace Autonomous Monitoring Engine Starting...")
    print(f"⚙️ Config: Interval={Config.SCAN_INTERVAL_SECONDS}s, Timeout={Config.PAGE_LOAD_TIMEOUT}s")

    while True:
        try:
            MonitoringService.run_monitoring_cycle()
            time.sleep(Config.SCAN_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            print("\n🛑 Monitoring worker stopped by user.")
            break
        except Exception as e:
            print(f"❌ Worker cycle exception: {e}")
            time.sleep(15)

if __name__ == "__main__":
    run_monitoring_loop()
