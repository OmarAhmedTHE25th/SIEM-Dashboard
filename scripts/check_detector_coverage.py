"""Verify that removing each detector breaks at least one fixture.

For each native detector, build a pipeline without it, run every fixture in
tests/detections/, and report which fixtures failed. A detector with no
failing fixture is unverified — its fixture is passing for other reasons.
"""
import sys
import json
import tempfile
import os
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from main import build_pipeline, process_event
from parser import parse_line
from rules_loader import load_rules
from enrichment import IPEnricher
from threat_intel.matcher import IOCMatcher


# Which detectors to test, and how to configure them if they need args.
# Mirrors rules/native.yml but as code so we can subtract one at a time.
BASE_RULES = [
    {"type": "brute_force", "threshold": 5, "window_seconds": 60},
    {"type": "successful_after_failures", "threshold": 5, "window_seconds": 300},
    {"type": "off_hours_login", "start": 22, "end": 6},
    {"type": "impossible_travel"},
]


class NoML:
    is_ready = False


class OfflineEnricher(IPEnricher):
    LOCATIONS = {
        "81.2.69.142": {"latitude": 51.5074, "longitude": -0.1278},
        "133.242.0.1": {"latitude": 35.6762, "longitude": 139.6503},
    }

    def __init__(self):
        super().__init__(geoip_provider=self.LOCATIONS.get)


def rules_yaml(entries):
    """Turn a list of rule dicts into the YAML text load_rules expects."""
    import yaml
    return yaml.safe_dump({"rules": entries})


def run_fixtures(pipeline):
    """Run every fixture through the pipeline; return {fixture_name: fired_rules}."""
    root = ROOT / "tests" / "detections"
    results = {}
    for directory in sorted(root.iterdir()):
        if not directory.is_dir():
            continue
        ioc_path = directory / "iocs.txt"
        matcher = IOCMatcher(ioc_path) if ioc_path.exists() else IOCMatcher(directory / "missing.txt")
        pipe = build_pipeline(
            rules=pipeline,
            enricher=OfflineEnricher(),
            ioc_matcher=matcher,
            ml_scorer=NoML(),
        )
        fired = []
        for line in (directory / "input.log").read_text().splitlines():
            event = parse_line(line)
            if event:
                fired.extend(process_event(event, pipe))
        results[directory.name] = {a["rule_name"] for a in fired}
    return results


def expected_for(directory):
    data = json.loads((directory / "expected_alerts.json").read_text())
    items = data.get("expected", data) if isinstance(data, dict) else data
    return {item["rule_name"] for item in items}


def main():
    root = Path("tests/detections")
    print("Baseline: all detectors loaded")
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(rules_yaml(BASE_RULES))
        baseline_path = f.name
    try:
        baseline = run_fixtures(load_rules(baseline_path))
    finally:
        os.unlink(baseline_path)

    for omitted in BASE_RULES:
        rule_type = omitted["type"]
        print(f"\n=== Omitting {rule_type} ===")
        reduced = [r for r in BASE_RULES if r["type"] != rule_type]
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write(rules_yaml(reduced))
            reduced_path = f.name
        try:
            reduced_results = run_fixtures(load_rules(reduced_path))
        finally:
            os.unlink(reduced_path)

        any_fail = False
        for name in sorted(baseline):
            expected = expected_for(root / name)
            got = reduced_results[name]
            missing = expected - got
            if missing:
                any_fail = True
                print(f"  {name}: FAILS (missing {sorted(missing)})")
        if not any_fail:
            print(f"  !! NO FIXTURE FAILED — {rule_type} is unverified")


if __name__ == "__main__":
    main()