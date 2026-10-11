import unittest
from datetime import datetime, timedelta

from engine import BruteForceDetector


def failed_event(ip, timestamp, user="admin"):
    return {
        "source_ip": ip,
        "timestamp": timestamp,
        "status": "failed",
        "user": user,
    }


class BruteForceDetectorTests(unittest.TestCase):
    def test_alerts_when_threshold_is_reached(self):
        detector = BruteForceDetector(threshold=3, window_seconds=60)
        start = datetime(2026, 10, 10, 14, 0, 0)

        self.assertIsNone(detector.process_event(failed_event("192.0.2.10", start)))
        self.assertIsNone(
            detector.process_event(failed_event("192.0.2.10", start + timedelta(seconds=10)))
        )
        alert = detector.process_event(
            failed_event("192.0.2.10", start + timedelta(seconds=20), user="root")
        )

        self.assertEqual(alert["rule_name"], "SSH_BRUTE_FORCE")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["attacker_ip"], "192.0.2.10")
        self.assertEqual(alert["target_user"], "root")
        self.assertIn("Observed 3 failed logins", alert["description"])

    def test_ignores_successes_and_keeps_ips_isolated(self):
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        start = datetime(2026, 10, 10, 14, 0, 0)

        success = failed_event("192.0.2.10", start)
        success["status"] = "success"
        self.assertIsNone(detector.process_event(success))
        self.assertIsNone(detector.process_event(failed_event("192.0.2.10", start)))
        self.assertIsNone(detector.process_event(failed_event("198.51.100.7", start)))
        self.assertIsNotNone(
            detector.process_event(failed_event("192.0.2.10", start + timedelta(seconds=1)))
        )

    def test_prunes_attempts_outside_window(self):
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        start = datetime(2026, 10, 10, 14, 0, 0)

        self.assertIsNone(detector.process_event(failed_event("192.0.2.10", start)))
        self.assertIsNone(
            detector.process_event(
                failed_event("192.0.2.10", start + timedelta(seconds=61))
            )
        )

    def test_clears_history_after_alert(self):
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        start = datetime(2026, 10, 10, 14, 0, 0)

        detector.process_event(failed_event("192.0.2.10", start))
        self.assertIsNotNone(
            detector.process_event(
                failed_event("192.0.2.10", start + timedelta(seconds=1))
            )
        )
        self.assertIsNone(
            detector.process_event(
                failed_event("192.0.2.10", start + timedelta(seconds=2))
            )
        )


if __name__ == "__main__":
    unittest.main()
