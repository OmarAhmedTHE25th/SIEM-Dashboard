import unittest
from datetime import datetime

from correlation import CorrelationEngine
from rules_loader import load_rules
from sources.auditd import parse_auditd_line


class SourcesAndRulesTests(unittest.TestCase):
    def test_auditd_is_normalized(self):
        event = parse_auditd_line(
            "type=USER_AUTH msg=audit(1700000000.0:1): "
            "acct=alice addr=192.0.2.1 res=failed"
        )
        self.assertEqual(event["source"], "auditd")
        self.assertEqual(event["status"], "failed")

    def test_default_yaml_rules_are_loaded(self):
        rules = load_rules()
        self.assertGreaterEqual(len(rules), 4)

    def test_engine_dispatches_rules(self):
        class Rule:
            def process_event(self, event):
                return {"timestamp": event["timestamp"]}

        alerts = CorrelationEngine([Rule()]).process_event(
            {"timestamp": datetime(2026, 1, 1)}
        )
        self.assertEqual(len(alerts), 1)


if __name__ == "__main__":
    unittest.main()
