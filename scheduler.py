"""
TamperTrace - Monitoring Scheduler Entrypoint (Legacy Compatibility Wrapper)
"""
import os
import sys
import subprocess

# Auto-switch to project virtual environment if invoked with global Python
_base_dir = os.path.dirname(os.path.abspath(__file__))
_venv_python = os.path.join(_base_dir, "venv", "Scripts", "python.exe")

if os.path.exists(_venv_python):
    current_exe = os.path.abspath(sys.executable).lower()
    target_exe = os.path.abspath(_venv_python).lower()
    if current_exe != target_exe:
        try:
            result = subprocess.call([_venv_python] + sys.argv)
            sys.exit(result)
        except Exception:
            pass

    _site_pkgs = os.path.join(_base_dir, "venv", "Lib", "site-packages")
    if os.path.exists(_site_pkgs) and _site_pkgs not in sys.path:
        sys.path.insert(0, _site_pkgs)

from app.workers.monitoring_worker import monitor_websites, run_monitoring_loop
from app.services.restore_service import RestoreService
from app.database import get_db

def get_last_clean_snapshot(db, url):
    """Legacy helper for backward compatibility."""
    return RestoreService.get_last_clean_snapshot(url)

if __name__ == "__main__":
    print("🕒 Starting TamperTrace Monitoring Worker (via scheduler.py wrapper)...")
    run_monitoring_loop()