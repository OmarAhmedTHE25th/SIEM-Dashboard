"""Load native and Sigma rules from YAML files."""
from pathlib import Path
import yaml

from correlation import CorrelationEngine
from engine import BruteForceDetector
from detection_rules import (
    ImpossibleTravelDetector, OffHoursLoginDetector, SuccessfulAfterFailuresDetector,
)
from sigma.interpreter import SigmaInterpreter

_NATIVE = {
    "brute_force": BruteForceDetector,
    "ssh_brute_force": BruteForceDetector,
    "successful_after_failures": SuccessfulAfterFailuresDetector,
    "off_hours_login": OffHoursLoginDetector,
    "impossible_travel": ImpossibleTravelDetector,
}


def _rule_config(item):
    if not isinstance(item, dict):
        return None
    rule_type = item.get("type") or item.get("kind")
    config = dict(item.get("config") or {})
    config.update({k: v for k, v in item.items() if k in {
        "threshold", "window_seconds", "start", "end", "max_speed_kmh",
        "mitre", "mitre_technique", "technique_name", "source"
    }})
    if rule_type in _NATIVE:
        return _NATIVE[rule_type](**config)
    if rule_type == "sigma" or "detection" in item:
        return SigmaInterpreter(item).as_detector()
    return None


def load_rules(path=None) -> CorrelationEngine:
    """Load configured detectors; malformed rules fail loudly."""
    paths = [Path(path)] if path and Path(path).is_file() else []
    if path and Path(path).is_dir():
        paths = sorted(Path(path).glob("*.y*ml"))
    if path is None:
        paths = sorted((Path(__file__).parent / "rules").glob("*.y*ml"))
    rules = []
    for rule_path in paths:
        with rule_path.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
        entries = document if isinstance(document, list) else document.get("rules", [document])
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"Malformed rule in {rule_path}")
            if "detection" not in entry and "type" not in entry and "name" not in entry:
                raise ValueError(f"Rule in {rule_path} is missing name/type")
            detector = _rule_config(entry)
            if detector is None:
                raise ValueError(f"Unsupported rule in {rule_path}")
            rules.append(detector)
    return CorrelationEngine(rules)


def load_rule_definitions(path=None):
    root = Path(path or Path(__file__).parent / "rules")
    paths = [root] if root.is_file() else sorted(root.glob("*.y*ml"))
    definitions = []
    for rule_path in paths:
        with rule_path.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
        entries = document if isinstance(document, list) else document.get("rules", [document])
        for item in entries:
            required = {"name", "severity", "description"}
            if not required.issubset(item):
                raise ValueError(f"Rule {rule_path} missing required fields: {required - set(item)}")
            definitions.append(item)
    return definitions


__all__ = ["load_rules"]
