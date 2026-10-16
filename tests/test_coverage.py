import unittest
from unittest.mock import patch

try:
    from api import get_coverage
except ModuleNotFoundError:
    get_coverage = None


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query):
        return [{"rule_name": "SSH_BRUTE_FORCE", "count": 2}]


@unittest.skipUnless(get_coverage, "API dependencies are not installed")
class CoverageApiTests(unittest.TestCase):
    def test_coverage_includes_zero_tactics_and_rule_counts(self):
        with patch("api.get_db", return_value=_Connection()):
            result = get_coverage()

        self.assertEqual(result["total_rules"], 9)
        brute_force = next(rule for rule in result["rules"]
                           if rule["rule_name"] == "SSH_BRUTE_FORCE")
        self.assertEqual(brute_force["alert_count"], 2)
        self.assertTrue(brute_force["covered"])
        self.assertEqual(result["tactic_counts"]["Execution"], 0)
        self.assertEqual(
            next(t for t in result["tactics"] if t["tactic"] == "Credential Access")["count"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
