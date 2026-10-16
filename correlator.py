"""Higher-order alert correlations over emitted alert/event streams."""
import os
from collections import defaultdict, deque
from datetime import timedelta


def _window(name, default):
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return float(default)


class CorrelationEngine:
    def __init__(self, alerts=None):
        self.alerts = list(alerts or [])
        self.history = defaultdict(deque)

    def process_alert(self, alert):
        now = alert["timestamp"]
        ip = alert.get("attacker_ip")
        if not ip:
            return []
        self.history[ip].append(alert)
        results = []
        for item in self.history[ip]:
            if item is alert:
                continue
            age = (now - item["timestamp"]).total_seconds()
            if age < 0:
                continue
            if item.get("rule_name") == "SSH_BRUTE_FORCE" and (
                alert.get("event_status") == "success" or alert.get("rule_name") == "SUCCESS_AFTER_MANY_FAILURES"
            ) and age <= _window("SIEM_CORR_COMPROMISE_WINDOW", 600):
                results.append(self._make("CORR_COMPROMISE_SUSPECTED", "CRITICAL", ip, alert, item))
            if item.get("source") == "suricata" and alert.get("source") != "suricata" and age <= _window("SIEM_CORR_MULTI_STAGE_WINDOW", 900):
                results.append(self._make("CORR_MULTI_STAGE_ATTACK", "CRITICAL", ip, alert, item))
            if {item.get("rule_name"), alert.get("rule_name")} == {"OFF_HOURS_LOGIN", "IMPOSSIBLE_TRAVEL"} and age <= _window("SIEM_CORR_ACCOUNT_TAKEOVER_WINDOW", 3600):
                results.append(self._make("CORR_ACCOUNT_TAKEOVER", "HIGH", ip, alert, item))
        self._prune(ip, now)
        return results

    def _prune(self, ip, now):
        while self.history[ip] and (now - self.history[ip][0]["timestamp"]).total_seconds() > 3600:
            self.history[ip].popleft()

    @staticmethod
    def _make(name, severity, ip, current, previous):
        ids = [str(x) for x in (previous.get("id", "?"), current.get("id", "?"))]
        return {"timestamp": current["timestamp"], "rule_name": name, "severity": severity,
                "attacker_ip": ip, "target_user": current.get("target_user", "unknown"),
                "description": f"Correlated alerts {', '.join(ids)}", "source": "correlation"}

    def feed(self, alert):
        self.alerts.append(alert)
        return self.process_alert(alert)

    process = feed
    on_alert = feed
