import unittest

from attack import lookup
from engine import BruteForceDetector
from datetime import datetime


class AttackMetadataTests(unittest.TestCase):
    def test_lookup_returns_id_and_name(self):
        self.assertEqual(
            lookup("SSH_BRUTE_FORCE"),
            {"mitre_technique": "T1110.001", "technique_name": "Brute Force: Password Guessing"},
        )

    def test_native_alert_contains_metadata(self):
        detector = BruteForceDetector(threshold=1)
        alert = detector.process_event({
            "timestamp": datetime(2026, 1, 1),
            "source_ip": "192.0.2.1",
            "user": "alice",
            "status": "failed",
        })
        self.assertEqual(alert["mitre_technique"], "T1110.001")
        self.assertEqual(alert["technique_name"], "Brute Force: Password Guessing")


if __name__ == "__main__":
    unittest.main()
