"""Run deterministic detection fixtures and print their ATT&CK mappings."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from attack import metadata
from tests.test_detections import DetectionFixtureTests


def main():
    suite = __import__("unittest").TestSuite()
    suite.addTest(DetectionFixtureTests("test_fixtures_run_full_pipeline"))
    result = __import__("unittest").TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1

    seen = set()
    for expected_path in sorted((ROOT / "tests" / "detections").glob("*/expected_alerts.json")):
        data = json.loads(expected_path.read_text(encoding="utf-8"))
        items = data.get("expected", data) if isinstance(data, dict) else data
        for item in items:
            rule_name = item["rule_name"]
            if rule_name in seen:
                continue
            seen.add(rule_name)
            info = metadata(rule_name)
            if info:
                print(f"- {rule_name}: {info['mitre']} - {info['technique_name']}")
            else:
                print(f"- {rule_name}: unmapped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
