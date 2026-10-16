import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _attack_rules():
    tree = ast.parse((ROOT / "attack.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "ATTACK"
            for target in node.targets
        ):
            return set(ast.literal_eval(node.value))
    raise AssertionError("ATTACK dictionary not found")


class AttackCoverageDocumentTests(unittest.TestCase):
    def setUp(self):
        self.doc = (ROOT / "docs" / "ATTACK_COVERAGE.md").read_text(encoding="utf-8")

    def _rule_rows(self):
        table = self.doc.split("## Rule-level mappings", 1)[1]
        return {
            match.group(1): match.group(2).strip()
            for match in re.finditer(
                r"^\|\s*([A-Z][A-Z0-9_]+)\s*\|\s*([^|]+)\s*\|",
                table,
                re.MULTILINE,
            )
            if match.group(1) != "ML_ANOMALOUS_BEHAVIOR"
        }

    def test_attack_rules_and_documented_rows_match(self):
        rows = self._rule_rows()
        self.assertEqual(_attack_rules(), set(rows), "ATTACK and doc rule sets differ")
        self.assertIn("ML_ANOMALOUS_BEHAVIOR", self.doc)

    def test_technique_columns_match_attack_dict(self):
        attack = ast.literal_eval(
            next(
                node.value
                for node in ast.parse((ROOT / "attack.py").read_text(encoding="utf-8")).body
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "ATTACK"
                    for target in node.targets
                )
            )
        )
        for rule_name, technique in self._rule_rows().items():
            self.assertEqual(
                technique,
                attack[rule_name][0],
                f"{rule_name}: doc has {technique!r}, code has {attack[rule_name][0]!r}",
            )

    def test_coverage_rules_are_documented_or_explicitly_excluded(self):
        coverage = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
        for rule_name in re.findall(r"^\|\s*([A-Z][A-Z0-9_]+)\s*\|", coverage, re.MULTILINE):
            if rule_name == "ML_ANOMALOUS_BEHAVIOR":
                self.assertIn(rule_name, self.doc)
            elif rule_name == "Sigma":
                self.assertIn("Sigma is covered by `docs/SIGMA.md`", self.doc)
            else:
                self.assertIn(rule_name, self._rule_rows())


if __name__ == "__main__":
    unittest.main()
