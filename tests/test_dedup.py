import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import database


class DedupTests(unittest.TestCase):
    def setUp(self):
        self.old = database.DB_NAME
        database.DB_NAME = tempfile.mktemp(suffix=".db")
        database.init_db()

    def tearDown(self):
        database.DB_NAME = self.old

    def make_alert(self, when, rule="RULE", ip="192.0.2.1"):
        return {"timestamp": when, "rule_name": rule, "severity": "HIGH",
                "attacker_ip": ip, "target_user": "admin", "description": "test"}

    def test_duplicate_count_and_window(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for _ in range(5):
            database.insert_alert(self.make_alert(start))
        with __import__("sqlite3").connect(database.DB_NAME) as conn:
            row = conn.execute("SELECT COUNT(*), dedup_count FROM alerts").fetchone()
        self.assertEqual(row, (1, 5))
        database.insert_alert(self.make_alert(start + timedelta(minutes=6)))
        with __import__("sqlite3").connect(database.DB_NAME) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 2)

    def test_different_keys_are_separate(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        database.insert_alert(self.make_alert(now, "A", "192.0.2.1"))
        database.insert_alert(self.make_alert(now, "B", "192.0.2.1"))
        database.insert_alert(self.make_alert(now, "A", "192.0.2.2"))
        with __import__("sqlite3").connect(database.DB_NAME) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 3)
