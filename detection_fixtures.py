"""Fixture runner for repeatable detector regression tests."""
import json
from pathlib import Path
from parser import parse_auth_line


def load_fixture(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data if isinstance(data, list) else data.get("events", [])


def run_fixture(path, detector):
    alerts = []
    for item in load_fixture(path):
        event = parse_auth_line(item) if isinstance(item, str) else item
        if event:
            alert = detector.process_event(event)
            if alert:
                alerts.append(alert)
    return alerts
