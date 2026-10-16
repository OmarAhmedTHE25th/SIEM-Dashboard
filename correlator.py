"""Alert-stream correlation with bounded per-IP history."""
import os
import sqlite3
from collections import defaultdict, deque
from datetime import datetime

from config import DB_PATH
from attack import lookup


def _window(name, default):
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return float(default)


class CorrelationEngine:
    SUCCESS_RULES = {"SUCCESS_AFTER_MANY_FAILURES", "OFF_HOURS_LOGIN", "IMPOSSIBLE_TRAVEL"}

    def __init__(self):
        self.history = defaultdict(deque)

    def feed(self, alert: dict) -> list[dict]:
        ip = alert.get("attacker_ip")
        if not ip:
            return []
        previous = list(self.history[ip])
        results = []
        for candidate in previous:
            age = (alert["timestamp"] - candidate["timestamp"]).total_seconds()
            if age < 0:
                continue
            if age <= _window("SIEM_CORR_COMPROMISE_WINDOW", 600):
                if candidate.get("rule_name") == "SSH_BRUTE_FORCE" and self._is_success(alert):
                    results.append(self._correlated("CORR_COMPROMISE_SUSPECTED", "CRITICAL", alert, candidate))
                elif alert.get("rule_name") == "SSH_BRUTE_FORCE" and self._is_success(candidate):
                    results.append(self._correlated("CORR_COMPROMISE_SUSPECTED", "CRITICAL", alert, candidate))
            if age <= _window("SIEM_CORR_MULTI_STAGE_WINDOW", 900):
                if bool(candidate.get("source") == "suricata") != bool(alert.get("source") == "suricata"):
                    results.append(self._correlated("CORR_MULTI_STAGE_ATTACK", "CRITICAL", alert, candidate))
            if age <= _window("SIEM_CORR_ACCOUNT_TAKEOVER_WINDOW", 3600):
                rules = {candidate.get("rule_name"), alert.get("rule_name")}
                if rules == {"OFF_HOURS_LOGIN", "IMPOSSIBLE_TRAVEL"} and (
                    candidate.get("target_user") == alert.get("target_user")
                ):
                    results.append(self._correlated("CORR_ACCOUNT_TAKEOVER", "HIGH", alert, candidate))
        self.history[ip].append(alert)
        self._prune(ip, alert["timestamp"])
        return results

    def _is_success(self, alert):
        return alert.get("status") == "success" or alert.get("event_status") == "success" or alert.get("rule_name") in self.SUCCESS_RULES

    @staticmethod
    def _correlated(name, severity, current, previous):
        ids = [str(previous.get("id", "?")), str(current.get("id", "?"))]
        alert = {
            "timestamp": current["timestamp"], "rule_name": name, "severity": severity,
            "attacker_ip": current.get("attacker_ip", "unknown"),
            "target_user": current.get("target_user", "unknown"),
            "description": f"Correlated alerts {', '.join(ids)}",
            "source": "correlation",
        }
        technique = lookup(name)
        if technique:
            alert.update(technique)
        return alert

    def _prune(self, ip, now):
        cutoff = max(
            _window("SIEM_CORR_COMPROMISE_WINDOW", 600),
            _window("SIEM_CORR_MULTI_STAGE_WINDOW", 900),
            _window("SIEM_CORR_ACCOUNT_TAKEOVER_WINDOW", 3600),
        )
        while self.history[ip] and (now - self.history[ip][0]["timestamp"]).total_seconds() > cutoff:
            self.history[ip].popleft()

    @classmethod
    def replay_from_db(cls, alerts=None, db_path=DB_PATH):
        engine = cls()
        if alerts is None:
            with sqlite3.connect(db_path) as conn:
                rows = conn.execute(
                    "SELECT id, timestamp, rule_name, severity, attacker_ip, target_user, description, source "
                    "FROM alerts ORDER BY timestamp ASC"
                ).fetchall()
            alerts = [
                {"id": row[0], "timestamp": datetime.fromisoformat(row[1]), "rule_name": row[2],
                 "severity": row[3], "attacker_ip": row[4], "target_user": row[5],
                 "description": row[6], "source": row[7]}
                for row in rows
            ]
        for alert in sorted(alerts, key=lambda item: item["timestamp"]):
            engine.feed(alert)
        return engine
