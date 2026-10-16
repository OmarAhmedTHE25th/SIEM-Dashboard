import json
import unittest
from datetime import datetime
from pathlib import Path

from engine import BruteForceDetector
from parser import parse_line


class DetectionFixtureTests(unittest.TestCase):
    def test_fixture_directories_have_expected_shape(self):
        root = Path(__file__).parent / "detections"
        for directory in root.iterdir():
            if not directory.is_dir():
                continue
            self.assertTrue((directory / "input.log").exists())
            expected = json.loads((directory / "expected_alerts.json").read_text())
            detector = BruteForceDetector()
            fired = []
            for line in (directory / "input.log").read_text().splitlines():
                event = parse_line(line)
                if event:
                    alert = detector.process_event(event)
                    if alert:
                        fired.append(alert["rule_name"])
            self.assertEqual(set(fired), {item["rule_name"] for item in expected})
