import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from main import build_pipeline, process_event
from rules_loader import load_rules


class _Enricher:
    def lookup(self, ip):
        return {"private": True}

    @staticmethod
    def describe(location):
        return "offline"


class _IOC:
    @staticmethod
    def match(event):
        return []


class _ML:
    is_ready = False


def event(at, status="failed"):
    return {"timestamp": at, "hostname": "host", "source_ip": "192.0.2.10",
            "user": "admin", "status": status, "raw": "raw", "source": "sshd"}


class PipelineTests(unittest.TestCase):
    def pipeline(self, rules=None):
        return build_pipeline(rules=rules, enricher=_Enricher(), ml_scorer=_ML(), ioc_matcher=_IOC())

    def test_yaml_threshold_is_used_by_agent(self):
        pipeline = self.pipeline(load_rules())
        start = datetime(2026, 10, 10, 12)
        alerts = []
        for offset in range(4):
            alerts.extend(process_event(event(start + timedelta(seconds=offset)), pipeline))
        self.assertNotIn("SSH_BRUTE_FORCE", {alert["rule_name"] for alert in alerts})

    def test_missing_detector_does_not_crash_startup(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
            handle.write("rules:\n  - type: off_hours_login\n    start: 22\n    end: 6\n")
            path = handle.name
        try:
            pipeline = self.pipeline(load_rules(path))
            self.assertEqual(len(pipeline.detectors), 1)
            self.assertEqual(process_event(event(datetime(2026, 10, 10, 12)), pipeline), [])
        finally:
            os.unlink(path)

    def test_env_var_overrides_yaml(self):
        with patch.dict(os.environ, {"SIEM_BRUTE_FORCE_THRESHOLD": "2"}):
            pipeline = self.pipeline(load_rules())
            start = datetime(2026, 10, 10, 12)
            process_event(event(start), pipeline)
            alerts = process_event(event(start + timedelta(seconds=1)), pipeline)
        self.assertIn("SSH_BRUTE_FORCE", {alert["rule_name"] for alert in alerts})


if __name__ == "__main__":
    unittest.main()
