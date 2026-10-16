import os
import sqlite3
import tempfile
import unittest
import gc
from datetime import datetime, timezone

import api
import database
from fastapi import HTTPException


class AlertTriageTests(unittest.TestCase):
    def setUp(self):
        self.db_path = tempfile.mktemp(suffix=".db")
        self.old_database_db = database.DB_NAME
        self.old_api_db = api.DB_NAME
        database.DB_NAME = self.db_path
        api.DB_NAME = self.db_path
        database.init_db()
        database.insert_alert({
            "timestamp": datetime.now(timezone.utc),
            "rule_name": "TRIAGE_TEST",
            "severity": "HIGH",
            "attacker_ip": "192.0.2.10",
            "target_user": "admin",
            "description": "triage test",
        })
        self.alert_id = 1

    def tearDown(self):
        database.DB_NAME = self.old_database_db
        api.DB_NAME = self.old_api_db
        gc.collect()
        if os.path.exists(self.db_path):
            try:
                os.unlink(self.db_path)
            except PermissionError:
                pass

    def test_migration_adds_triage_columns(self):
        with sqlite3.connect(self.db_path) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
        self.assertTrue({
            "verdict", "verdict_reason", "verdict_at", "suppressed_reason",
            "escalated_at", "closed_at",
        }.issubset(columns))

    def test_ack_accepts_optional_verdict_and_reason(self):
        result = api.ack_alert(self.alert_id, {
            "verdict": "false_positive",
            "reason": "Known scanner",
        })
        self.assertEqual(result["status"], "acknowledged")
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT status, verdict, verdict_reason, verdict_at FROM alerts WHERE id = ?",
                (self.alert_id,),
            ).fetchone()
        self.assertEqual(row[:3], ("acknowledged", "false_positive", "Known scanner"))
        self.assertIsNotNone(row[3])

    def test_ack_rejects_invalid_verdict(self):
        for verdict in ("benign", "suspicious", "unknown", "not-a-verdict"):
            with self.subTest(verdict=verdict):
                with self.assertRaises(HTTPException) as error:
                    api.ack_alert(self.alert_id, {"verdict": verdict})
                self.assertEqual(error.exception.status_code, 400)

    def test_suppress_validates_reason_code(self):
        with self.assertRaises(HTTPException) as error:
            api.suppress_alert(self.alert_id, {"reason_code": "not-a-reason"})
        self.assertEqual(error.exception.status_code, 400)

        for reason_code in ("false_positive", "duplicate", "maintenance", "accepted_risk", "other"):
            with self.subTest(reason_code=reason_code):
                with self.assertRaises(HTTPException) as error:
                    api.suppress_alert(self.alert_id, {"reason_code": reason_code})
                self.assertEqual(error.exception.status_code, 400)

        result = api.suppress_alert(self.alert_id, {"reason_code": "known_scanner"})
        self.assertEqual(result["status"], "suppressed")
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("SELECT suppressed_reason FROM alerts WHERE id = ?", (self.alert_id,)).fetchone()[0],
                "known_scanner",
            )

    def test_escalate_preserves_status(self):
        api.ack_alert(self.alert_id)
        result = api.escalate_alert(self.alert_id)
        self.assertEqual(result["status"], "acknowledged")
        with sqlite3.connect(self.db_path) as conn:
            status, escalated_at = conn.execute(
                "SELECT status, escalated_at FROM alerts WHERE id = ?", (self.alert_id,)
            ).fetchone()
        self.assertEqual(status, "acknowledged")
        self.assertIsNotNone(escalated_at)

    def test_alert_list_and_detail_include_triage_fields(self):
        api.ack_alert(self.alert_id, {"verdict": "benign_true_positive", "reason": "Test"})
        listed = api.get_alerts()[0]
        detail = api.get_alert(self.alert_id)
        for item in (listed, detail):
            self.assertIn("verdict", item)
            self.assertIn("verdict_reason", item)
            self.assertIn("verdict_at", item)
            self.assertIn("suppressed_reason", item)
            self.assertIn("escalated_at", item)
            self.assertIn("closed_at", item)


if __name__ == "__main__":
    unittest.main()
