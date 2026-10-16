import argparse
import os
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from parser import parse_line
from engine import BruteForceDetector
from detection_rules import (
    SuccessfulAfterFailuresDetector,
    ImpossibleTravelDetector,
    OffHoursLoginDetector,
)
from enrichment import IPEnricher
from ingestionGen import tail_file
from database import init_db, insert_event, insert_alert
from ml_engine import AnomalyScorer, severity_from_score
from threat_intel import IOCMatcher
from correlator import CorrelationEngine
from rules_loader import load_rules
from attack import lookup

DEFAULT_LOG_PATH = "/var/log/auth.log"
ML_ALERT_COOLDOWN = timedelta(minutes=5)


def resolve_log_path() -> str:
    parser = argparse.ArgumentParser(description="SIEM Real-Time Ingestion and Anomaly Detection Engine")
    parser.add_argument(
        "--log-path",
        "-l",
        type=str,
        default=None,
        help=f"Path to the authentication log file (default: $SIEM_LOG_PATH or {DEFAULT_LOG_PATH})"
    )
    args, _ = parser.parse_known_args()

    if args.log_path:
        return args.log_path

    return os.getenv("SIEM_LOG_PATH", DEFAULT_LOG_PATH)


LOG_PATH = resolve_log_path()
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


@dataclass
class DetectionPipeline:
    detectors: list
    correlator: object
    enricher: object
    ml_scorer: object
    tracker: RealtimeBehaviorTracker
    ioc_matcher: object
    last_ml_alert: dict


def build_pipeline(rules=None, enricher=None, ml_scorer=None, ioc_matcher=None, correlator=None):
    loaded = rules or load_rules()
    detectors = list(getattr(loaded, "rules", loaded))
    pipeline = DetectionPipeline(
        detectors=detectors,
        correlator=correlator or CorrelationEngine(),
        enricher=enricher or IPEnricher(),
        ml_scorer=ml_scorer or AnomalyScorer(),
        tracker=RealtimeBehaviorTracker(),
        ioc_matcher=ioc_matcher or IOCMatcher(),
        last_ml_alert={},
    )
    roles = [type(detector).__name__ for detector in detectors]
    print(f"[*] Loaded detectors: {', '.join(roles) if roles else 'none'}")
    return pipeline


def process_event(event: dict, pipeline: DetectionPipeline) -> list[dict]:
    alerts = []
    location = pipeline.enricher.lookup(event["source_ip"])
    matches = pipeline.ioc_matcher.match(event)
    if matches:
        weight = max(getattr(match, "weight", 0.0) for match in matches)
        severity = "HIGH" if weight >= 0.7 else "MEDIUM" if weight >= 0.4 else "LOW"
        alerts.append({
            "timestamp": event["timestamp"], "rule_name": "IOC_MATCH",
            "severity": severity, "attacker_ip": event["source_ip"],
            "target_user": event["user"],
            "description": f"Local IOC match: {', '.join(matches)}",
            "source": event.get("source", "sshd"),
            "mitre": lookup("IOC_MATCH")["mitre_technique"],
            **lookup("IOC_MATCH"),
            "event_status": event.get("status"),
        })
    if event.get("source") == "suricata":
        alerts.append({
            "timestamp": event["timestamp"], "rule_name": "SURICATA_ALERT",
            "severity": "HIGH", "attacker_ip": event["source_ip"],
            "target_user": event["user"], "description": "Suricata event",
            "source": "suricata", "event_status": event.get("status"),
            "mitre": lookup("SURICATA_ALERT")["mitre_technique"],
            **lookup("SURICATA_ALERT"),
        })

    for detector in pipeline.detectors:
        if isinstance(detector, ImpossibleTravelDetector):
            alert = detector.process_event(event, location)
        else:
            alert = detector.process_event(event)
        if alert:
            alert["source"] = event.get("source", "sshd")
            alert["event_status"] = event.get("status")
            alert["description"] += f" [{pipeline.enricher.describe(location)}]"
            alerts.append(alert)

    features = pipeline.tracker.add_and_extract(event)
    if features["total_attempts"] >= 3 and pipeline.ml_scorer.is_ready:
        anomalous, score = pipeline.ml_scorer.score_ip_behavior(features)
        now = datetime.now(timezone.utc)
        ip = event["source_ip"]
        if anomalous and (not pipeline.last_ml_alert.get(ip) or now - pipeline.last_ml_alert[ip] >= ML_ALERT_COOLDOWN):
            pipeline.last_ml_alert[ip] = now
            alerts.append({
                "timestamp": now, "rule_name": "ML_ANOMALOUS_BEHAVIOR",
                "severity": severity_from_score(score, pipeline.ml_scorer.threshold),
                "attacker_ip": ip, "target_user": event["user"],
                "description": f"IsolationForest outlier detected (Score: {score:.3f})",
                "source": event.get("source", "sshd"), "event_status": event.get("status"),
            })

    correlated = []
    for alert in alerts:
        correlated.extend(pipeline.correlator.feed(alert))
    return alerts + correlated


if __name__ == "__main__":
    init_db()
    pipeline = build_pipeline()
    pipeline.correlator = CorrelationEngine.replay_from_db()

    print(f"[*] SIEM Agent live. Watching {LOG_PATH} with Rule + ML Detection...")
    if not pipeline.ml_scorer.is_ready:
        print("[!] WARNING: ML model not loaded. Run `python ml_engine.py` to train it. Rules only for now.")

    # Monitors logs; triggers rule-based and ML-driven security alerts
    for raw_line in tail_file(LOG_PATH):
        event = parse_line(raw_line)
        if not event:
            continue

        insert_event(event)
        for alert in process_event(event, pipeline):
            insert_alert(alert)
            print(f"[ALERT] {alert['rule_name']} from {alert['attacker_ip']}")