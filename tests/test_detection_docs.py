import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class DetectionDocumentationTests(unittest.TestCase):
    def test_coverage_rules_have_detection_documentation(self):
        coverage = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
        detections = (ROOT / "docs" / "DETECTIONS.md").read_text(encoding="utf-8")
        rules = set(re.findall(r"^\|\s*([A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+)\s*\|", coverage, re.MULTILINE))
        documented = set(re.findall(r"^###\s+([A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+)\s*$", detections, re.MULTILINE))
        missing = sorted(rules - documented)
        extra = sorted(documented - rules)
        self.assertFalse(
            missing or extra,
            "Coverage/documentation rule mismatch; missing: "
            + (", ".join(missing) or "none")
            + "; extra: "
            + (", ".join(extra) or "none"),
        )

    def test_each_detection_has_required_subsections(self):
        detections = (ROOT / "docs" / "DETECTIONS.md").read_text(encoding="utf-8")
        rules = re.findall(r"^###\s+([A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+)\s*$", detections, re.MULTILINE)
        required = (
            "Hypothesis", "ATT&CK", "Data", "Logic", "False positives",
            "Tuning", "Fixture", "Gaps",
        )
        for rule in rules:
            section = re.search(
                rf"^###\s+{re.escape(rule)}\s*$([\s\S]*?)(?=^###\s+|\Z)",
                detections,
                re.MULTILINE,
            ).group(1)
            for heading in required:
                self.assertIn(f"#### {heading}", section, f"{rule} lacks {heading}")

    def test_correlation_false_positive_sections_have_multiple_scenarios(self):
        detections = (ROOT / "docs" / "DETECTIONS.md").read_text(encoding="utf-8")
        for rule in (
            "CORR_COMPROMISE_SUSPECTED",
            "CORR_MULTI_STAGE_ATTACK",
            "CORR_ACCOUNT_TAKEOVER",
        ):
            section = re.search(
                rf"^###\s+{re.escape(rule)}\s*$([\s\S]*?)(?=^###\s+|\Z)",
                detections,
                re.MULTILINE,
            ).group(1)
            false_positives = re.search(
                r"^#### False positives\s*$([\s\S]*?)(?=^####\s+|\Z)",
                section,
                re.MULTILINE,
            ).group(1)
            self.assertGreaterEqual(
                len(re.findall(r"^- ", false_positives, re.MULTILINE)),
                3,
                rule,
            )


if __name__ == "__main__":
    unittest.main()
