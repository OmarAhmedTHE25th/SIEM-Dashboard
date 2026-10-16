import json
import unittest
from datetime import datetime
from pathlib import Path

from enrichment import IPEnricher
from main import build_pipeline, process_event
from parser import parse_line
from threat_intel.matcher import IOCMatcher


class NoML:
    is_ready = False


class OfflineEnricher(IPEnricher):
    LOCATIONS = {
        "81.2.69.142": {"latitude": 51.5074, "longitude": -0.1278},
        "133.242.0.1": {"latitude": 35.6762, "longitude": 139.6503},
    }

    def __init__(self):
        super().__init__(geoip_provider=self.LOCATIONS.get)


class DetectionFixtureTests(unittest.TestCase):
    def test_fixtures_run_full_pipeline(self):
        root = Path(__file__).parent / "detections"
        for directory in sorted(root.iterdir()):
            if not directory.is_dir():
                continue
            with self.subTest(fixture=directory.name):
                expected = json.loads((directory / "expected_alerts.json").read_text())
                wanted = {item["rule_name"] for item in expected.get("expected", expected)}
                forbidden = set(expected.get("not_expected", [])) if isinstance(expected, dict) else set()
                ioc_path = directory / "iocs.txt"
                matcher = IOCMatcher(ioc_path) if ioc_path.exists() else IOCMatcher(directory / "missing-iocs.txt")
                pipeline = build_pipeline(enricher=OfflineEnricher(), ioc_matcher=matcher, ml_scorer=NoML())
                fired = []
                for line in (directory / "input.log").read_text().splitlines():
                    event = parse_line(line)
                    if event:
                        fired.extend(process_event(event, pipeline))
                names = {alert["rule_name"] for alert in fired}
                self.assertTrue(wanted.issubset(names), (directory.name, wanted, names))
                self.assertTrue(forbidden.isdisjoint(names), (directory.name, forbidden, names))


if __name__ == "__main__":
    unittest.main()
