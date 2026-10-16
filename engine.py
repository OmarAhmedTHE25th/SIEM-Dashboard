from collections import defaultdict, deque
from datetime import timedelta

class BruteForceDetector:
    def __init__(self, threshold: int = 3, window_seconds: int = 60, source=("sshd", None)):
        self.threshold = int(__import__("os").getenv("SIEM_BRUTE_FORCE_THRESHOLD", threshold))
        self.window = timedelta(seconds=int(__import__("os").getenv("SIEM_BRUTE_FORCE_WINDOW", window_seconds)))
        self.sources = set(source if isinstance(source, (list, tuple, set)) else [source])
        # Key: source_ip (str) -> Value: deque of datetime timestamps
        self.ip_windows = defaultdict(deque)

    def process_event(self, event: dict) -> dict | None:
        if event.get("source", "sshd") not in self.sources:
            return None
        # Ignore events that aren't failed logins
        if event.get("status") != "failed":
            return None

        ip = event["source_ip"]
        current_time = event["timestamp"]

        history = self.ip_windows[ip]

        # 1. Prune timestamps outside the sliding window [current_time - window, current_time]
        cutoff_time = current_time - self.window
        while history and history[0] < cutoff_time:
            history.popleft()

        # 2. Record this new failed attempt
        history.append(current_time)

        # 3. Check if threshold is breached for this specific IP
        if len(history) >= self.threshold:
            # Clear this IP's queue so we don't spam duplicate alerts on the next failure
            history.clear()

            return {
                "rule_name": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "attacker_ip": ip,
                "target_user": event["user"],
                "timestamp": current_time,
                "description": (
                    f"Observed {self.threshold} failed logins from {ip} "
                    f"within {self.window.total_seconds()}s window."
                )
            }

        return None