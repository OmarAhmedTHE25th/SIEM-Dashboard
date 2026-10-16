import unittest
from sigma.interpreter import SigmaInterpreter


class SigmaUnsupportedTests(unittest.TestCase):
    def test_aggregation_is_rejected(self):
        rule = SigmaInterpreter({"title": "bad", "detection": {
            "selection": {"raw|contains": "x"}, "condition": "1 of selection"
        }})
        with self.assertRaises(ValueError):
            rule.matches({"raw": "x"})

    def test_count_modifier_is_rejected(self):
        rule = SigmaInterpreter({"title": "bad", "detection": {
            "selection": {"raw|count": 3}, "condition": "selection"
        }})
        with self.assertRaises(ValueError):
            rule.matches({"raw": "x"})
