import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta

from correlator import CorrelationEngine


def alert(rule, when, ip="192.0.2.10", user="admin", source="sshd", status=None):
    value = {"timestamp": when, "rule_name": rule, "severity": "HIGH",
             "attacker_ip": ip, "target_user": user, "source": source}
    if status:
        value["status"] = status
    return value


class CorrelatorTests(unittest.TestCase):
    def test_compromise_positive_and_negative(self):
        engine = CorrelationEngine()
        start = datetime(2026, 1, 1, 12)
        engine.feed(alert("SSH_BRUTE_FORCE", start))
        self.assertEqual(engine.feed(alert("OFF_HOURS_LOGIN", start + timedelta(minutes=1)))[0]["rule_name"], "CORR_COMPROMISE_SUSPECTED")
        result = engine.feed(alert("SUCCESS_AFTER_MANY_FAILURES", start + timedelta(minutes=2)))
        self.assertEqual(result[0]["rule_name"], "CORR_COMPROMISE_SUSPECTED")
        self.assertEqual(CorrelationEngine().feed(alert("OFF_HOURS_LOGIN", start)), [])

    def test_multi_stage_checks_both_sides(self):
        start = datetime(2026, 1, 1, 12)
        engine = CorrelationEngine()
        engine.feed(alert("SSH_BRUTE_FORCE", start))
        result = engine.feed(alert("SURICATA_ALERT", start + timedelta(minutes=1), source="suricata"))
        self.assertEqual(result[0]["rule_name"], "CORR_MULTI_STAGE_ATTACK")
        engine = CorrelationEngine()
        engine.feed(alert("SURICATA_ALERT", start, source="suricata"))
        self.assertEqual(engine.feed(alert("SSH_BRUTE_FORCE", start + timedelta(minutes=1)))[0]["rule_name"], "CORR_MULTI_STAGE_ATTACK")

    def test_account_takeover_requires_same_user(self):
        start = datetime(2026, 1, 1, 12)
        engine = CorrelationEngine()
        engine.feed(alert("OFF_HOURS_LOGIN", start))
        self.assertEqual(engine.feed(alert("IMPOSSIBLE_TRAVEL", start + timedelta(minutes=1), user="bob")), [])
        result = engine.feed(alert("IMPOSSIBLE_TRAVEL", start + timedelta(minutes=2)))
        self.assertEqual(result[0]["rule_name"], "CORR_ACCOUNT_TAKEOVER")

    def test_restart_replay(self):
        start = datetime(2026, 1, 1, 12)
        engine = CorrelationEngine.replay_from_db([
            alert("SSH_BRUTE_FORCE", start),
        ])
        result = engine.feed(alert("SUCCESS_AFTER_MANY_FAILURES", start + timedelta(minutes=1)))
        self.assertEqual(result[0]["rule_name"], "CORR_COMPROMISE_SUSPECTED")


if __name__ == "__main__":
    unittest.main()
