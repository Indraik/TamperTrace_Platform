import schedule
import time
import subprocess
import sys  # ✅ Add this

def run_monitor():
    print("⏳ Starting TamperTrace monitoring cycle...")
    # ✅ Use the same Python executable as current environment
    subprocess.run([sys.executable, "scheduler.py"])
    print("✅ Monitoring cycle finished.\n")

# Run every 5 minutes
schedule.every(1).minutes.do(run_monitor)

print("🕒 TamperTrace Auto-Scheduler started (runs every 5 minutes)…")

while True:
    schedule.run_pending()
    time.sleep(1)
