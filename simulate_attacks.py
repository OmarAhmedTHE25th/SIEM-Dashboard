import time
from datetime import datetime, timezone, timedelta
import os

from pathlib import Path

TARGET_LOG = Path(os.getenv("SIEM_LOG_PATH", "/var/log/auth.log"))


def write_log(line: str):
    """Appends a line to the monitored log file."""
    with open(TARGET_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
    print(f"[*] Injected: {line}")


def fmt_iso(dt: datetime) -> str:
    return dt.isoformat()


# ==========================================
# 1. SCENARIO: OFF-HOURS LOGIN
# (Default window: 22:00 to 06:00)
# ==========================================
def test_off_hours():
    print("\n--- Triggering OFF_HOURS_LOGIN ---")
    # Craft a timestamp set explicitly at 03:30 AM UTC
    t = datetime.now(timezone.utc).replace(hour=3, minute=30, second=0)
    line = f"{fmt_iso(t)} test-srv sshd[101]: Accepted password for backup_admin from 192.168.1.50 port 22 ssh2"
    write_log(line)


# ==========================================
# 2. SCENARIO: IMPOSSIBLE TRAVEL
# (Uses the London/Tokyo demo IP pair; tests inject their offline coordinates)
# ==========================================
def test_impossible_travel():
    print("\n--- Triggering IMPOSSIBLE_TRAVEL ---")
    now = datetime.now(timezone.utc)

    # Login 1: London, UK (Public IP: 81.2.69.142)
    t1 = now - timedelta(minutes=15)
    line1 = f"{fmt_iso(t1)} test-srv sshd[102]: Accepted password for globetrotter from 81.2.69.142 port 22 ssh2"
    write_log(line1)
    time.sleep(1)

    # Login 2: Tokyo, Japan (Public IP: 133.242.0.1) 15 minutes later (>800 km/h)
    line2 = f"{fmt_iso(now)} test-srv sshd[103]: Accepted password for globetrotter from 133.242.0.1 port 22 ssh2"
    write_log(line2)


# ==========================================
# 3. SCENARIO: SUCCESS AFTER MANY FAILURES
# (Threshold: 5 failures within 300s, then success)
# ==========================================
def test_success_after_many_failures():
    print("\n--- Triggering SUCCESS_AFTER_MANY_FAILURES ---")
    now = datetime.now(timezone.utc)
    ip = "203.0.113.88"
    user = "alice"

    # Send 5 failed attempts
    for i in range(5):
        t = now - timedelta(seconds=60 - (i * 10))
        line = f"{fmt_iso(t)} test-srv sshd[20{i}]: Failed password for {user} from {ip} port 22 ssh2"
        write_log(line)
        time.sleep(0.2)

    # Send the successful login
    line = f"{fmt_iso(now)} test-srv sshd[210]: Accepted password for {user} from {ip} port 22 ssh2"
    write_log(line)


# ==========================================
# 4. SCENARIO: SUDO SESSION LOG
# ==========================================
def test_sudo_elevation():
    print("\n--- Triggering SUDO SESSION LOG ---")
    t = datetime.now(timezone.utc).replace(hour=2, minute=0, second=0)  # triggers OFF_HOURS too!
    line = f"{fmt_iso(t)} test-srv sudo: pam_unix(sudo:session): session opened for user root by analyst(uid=0)"
    write_log(line)


# ==========================================
# 5. SCENARIO: ML OUTLIER (PASSWORD SPRAY / REGULAR ROBOT)
# ==========================================
def test_ml_anomaly():
    print("\n--- Triggering ML_ANOMALOUS_BEHAVIOR (User Enumeration Spray) ---")
    now = datetime.now(timezone.utc)
    ip = "198.51.100.99"
    target_users = ["root", "admin", "guest", "oracle", "test", "deploy", "ubuntu"]

    for i, user in enumerate(target_users):
        t = now + timedelta(seconds=i * 2)  # Highly uniform 2.0s timing
        line = f"{fmt_iso(t)} test-srv sshd[30{i}]: Failed password for invalid user {user} from {ip} port 22 ssh2"
        write_log(line)
        time.sleep(0.3)


if __name__ == "__main__":
    test_off_hours()
    time.sleep(1)
    test_impossible_travel()
    time.sleep(1)
    test_success_after_many_failures()
    time.sleep(1)
    test_sudo_elevation()
    time.sleep(1)
    test_ml_anomaly()