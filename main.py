from collections import defaultdict
from datetime import datetime, timezone
from parser import parse_auth_line
from engine import BruteForceDetector
from ingestionGen import tail_file
from database import init_db, insert_event, insert_alert
from ml_engine import AnomalyScorer

LOG_PATH = "/var/log/auth.log"


class RealtimeBehaviorTracker:
    """Tracks per-IP operational metrics in memory for real-time ML scoring."""

    def __init__(self, max_history=50):
        self.history = defaultdict(list)
        self.max_history = max_history

    def add_and_extract(self, event: dict) -> dict:
        ip = event["source_ip"]
        t = event["timestamp"]
        # Normalize timezone awareness
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)

        self.history[ip].append({
            "timestamp": t,
            "status": event["status"],
            "user": event["user"]
        })

        # Keep sliding history capped
        if len(self.history[ip]) > self.max_history:
            self.history[ip].pop(0)

        events = self.history[ip]
        total_attempts = len(events)
        failures = sum(1 for e in events if e["status"] == "failed")
        unique_users = len({e["user"] for e in events})
        failure_rate = failures / total_attempts if total_attempts > 0 else 0.0

        if total_attempts > 1:
            intervals = [
                (events[i]["timestamp"] - events[i - 1]["timestamp"]).total_seconds()
                for i in range(1, total_attempts)
            ]
            mean_interval = sum(intervals) / len(intervals)
            std_interval = (sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)) ** 0.5
        else:
            mean_interval = 3600.0
            std_interval = 0.0

        return {
            "total_attempts": total_attempts,
            "failure_rate": failure_rate,
            "unique_users": unique_users,
            "mean_interval": mean_interval,
            "std_interval": std_interval
        }


if __name__ == "__main__":
    init_db()
    rule_detector = BruteForceDetector(threshold=3, window_seconds=60)
    ml_scorer = AnomalyScorer()
    tracker = RealtimeBehaviorTracker()

    print(f"[*] SIEM Agent live. Watching {LOG_PATH} with Rule + ML Detection...")

    for raw_line in tail_file(LOG_PATH):
        event = parse_auth_line(raw_line)
        if not event:
            continue

        insert_event(event)

        # 2. Machine Learning Anomaly Detection
        features = tracker.add_and_extract(event)

        # DEBUG: See what is actually happening every time an event arrives
        print(f"[*] IP: {event['source_ip']} | Attempts: {features['total_attempts']} | is_ready: {ml_scorer.is_ready}")

        if not ml_scorer.is_ready:
            print("[!] WARNING: ml_scorer.is_ready is False! Model file failed to load.")

        # Only score once an IP has generated at least 3 attempts
        if features["total_attempts"] >= 3 and ml_scorer.is_ready:
            is_anomaly, score = ml_scorer.score_ip_behavior(features)


            if is_anomaly:
                ml_alert = {
                    "timestamp": datetime.now(timezone.utc),
                    "rule_name": "ML_ANOMALOUS_BEHAVIOR",
                    "severity": "HIGH",
                    "attacker_ip": event["source_ip"],
                    "target_user": event["user"],
                    "description": f"IsolationForest outlier detected (Score: {score:.3f}, FailRate: {features['failure_rate']:.2f}, SprayCount: {features['unique_users']})"
                }
                insert_alert(ml_alert)
                print(f"[ML ALERT] Anomaly from {event['source_ip']} (Score: {score:.3f})")