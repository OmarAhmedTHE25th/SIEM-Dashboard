from parser import parse_auth_line
from engine import BruteForceDetector
from ingestionGen import tail_file
from database import init_db, insert_event, insert_alert

LOG_PATH = "/var/log/auth.log"

if __name__ == "__main__":
    init_db()
    detector = BruteForceDetector(threshold=3, window_seconds=60)
    print(f"[*] SIEM Agent live. Watching {LOG_PATH} and writing to siem.db...")

    for raw_line in tail_file(LOG_PATH):
        event = parse_auth_line(raw_line)
        if not event:
            continue

        # 1. Persist the raw event
        insert_event(event)

        # 2. Evaluate correlation engine
        alert = detector.process_event(event)
        if alert:
            insert_alert(alert)
            print(f"\n[!] ALERT STORED: {alert['rule_name']} | Attacker: {alert['attacker_ip']} | Target: {alert['target_user']}")
            print(f"    {alert['description']}\n")
        else:
            print(f"[INGEST] {event['timestamp'].time()} - {event['status']} login for {event['user']} from {event['source_ip']}")