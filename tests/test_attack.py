import unittest

from attack import ATTACK, metadata, lookup
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

    def test_multi_technique_metadata(self):
        self.assertEqual(lookup("IMPOSSIBLE_TRAVEL")["mitre_technique"], "T1078,T1133")
        item = metadata("CORR_COMPROMISE_SUSPECTED")
        self.assertEqual(
            item["techniques"],
            ["T1110.001", "T1078"],
        )
        self.assertIn("Credential Access", item["tactics"])
        self.assertIn("Initial Access", item["tactics"])

    def test_every_rule_has_tactics(self):
        for rule_name in ATTACK:
            self.assertTrue(metadata(rule_name)["tactics"], rule_name)


if __name__ == "__main__":
    unittest.main()
