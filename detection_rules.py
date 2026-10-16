"""Streaming correlation rules beyond brute-force detection."""
import math
import os
from collections import defaultdict, deque
from datetime import timedelta


def _int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


class SuccessfulAfterFailuresDetector:
    def __init__(self, threshold=None, window_seconds=None, source=("sshd", None)):
        self.threshold = _int("SIEM_SUCCESS_AFTER_FAILURES", threshold or 5)
        self.window = timedelta(seconds=_int("SIEM_FAILURE_CORRELATION_WINDOW", window_seconds or 300))
        self.failures = defaultdict(deque)
        self.sources = set(source if isinstance(source, (list, tuple, set)) else [source])

    def process_event(self, event):
        if event.get("source", "sshd") not in self.sources:
            return None
        key = (event["source_ip"], event["user"])
        history = self.failures[key]
        now = event["timestamp"]
        while history and history[0] < now - self.window:
            history.popleft()
        if event.get("status") == "failed":
            history.append(now)
            return None
        if event.get("status") == "success" and len(history) >= self.threshold:
            count = len(history)
            history.clear()
            return {
                "timestamp": now, "rule_name": "SUCCESS_AFTER_MANY_FAILURES",
                "severity": "HIGH", "attacker_ip": event["source_ip"],
                "target_user": event["user"],
                "description": f"Successful login after {count} failures for {event['user']} within {self.window.total_seconds()}s.",
            }
        return None


class OffHoursLoginDetector:
    def __init__(self, start=None, end=None, source=("sshd", None)):
        self.start = _int("SIEM_OFF_HOURS_START", 22 if start is None else start)
        self.end = _int("SIEM_OFF_HOURS_END", 6 if end is None else end)
        self.sources = set(source if isinstance(source, (list, tuple, set)) else [source])

    def process_event(self, event):
        if event.get("source", "sshd") not in self.sources:
            return None
        if event.get("status") != "success":
            return None
        hour = event["timestamp"].hour
        off_hours = (self.start > self.end and (hour >= self.start or hour < self.end)) or (
            self.start < self.end and self.start <= hour < self.end
        )
        if not off_hours:
            return None
        return {
            "timestamp": event["timestamp"], "rule_name": "OFF_HOURS_LOGIN",
            "severity": "MEDIUM", "attacker_ip": event["source_ip"],
            "target_user": event["user"],
            "description": f"Successful login for {event['user']} at {event['timestamp'].isoformat()} outside normal hours.",
        }


class ImpossibleTravelDetector:
    def __init__(self, max_speed_kmh=None, window_seconds=None):
        self.max_speed = float(os.getenv("SIEM_IMPOSSIBLE_TRAVEL_KMH", max_speed_kmh or 800))
        self.window = timedelta(seconds=_int("SIEM_IMPOSSIBLE_TRAVEL_WINDOW", window_seconds or 86400))
        self.last = {}

    @staticmethod
    def _distance(a, b):
        lat1, lon1, lat2, lon2 = map(math.radians, (float(a["latitude"]), float(a["longitude"]),
                                                       float(b["latitude"]), float(b["longitude"])))
        x = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
        return 6371.0 * 2 * math.asin(math.sqrt(x))

    def process_event(self, event, location=None):
        if event.get("status") != "success" or not location or location.get("latitude") is None or location.get("longitude") is None:
            return None
        key = event["user"]
        previous = self.last.get(key)
        self.last[key] = (event["timestamp"], location)
        if not previous:
            return None
        previous_time, previous_location = previous
        elapsed = (event["timestamp"] - previous_time).total_seconds()
        if elapsed <= 0 or elapsed > self.window.total_seconds():
            return None
        distance = self._distance(previous_location, location)
        speed = distance / (elapsed / 3600)
        if speed <= self.max_speed:
            return None
        return {
            "timestamp": event["timestamp"], "rule_name": "IMPOSSIBLE_TRAVEL",
            "severity": "HIGH", "attacker_ip": event["source_ip"],
            "target_user": event["user"],
            "description": f"User {event['user']} traveled {distance:.0f} km in {elapsed / 3600:.1f}h ({speed:.0f} km/h).",
        }
