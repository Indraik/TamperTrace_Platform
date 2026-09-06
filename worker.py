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

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from app.workers.monitoring_worker import run_monitoring_loop

if __name__ == "__main__":
    print("🕒 TamperTrace Autonomous Monitoring Engine Starting...")
    run_monitoring_loop()
