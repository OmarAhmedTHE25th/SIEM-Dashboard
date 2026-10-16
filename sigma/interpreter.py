"""Small, dependency-free subset of the Sigma rule language."""
from dataclasses import dataclass


@dataclass
class SigmaRule:
    title: str
    detection: dict
    level: str = "medium"
    rule_id: str | None = None


class SigmaInterpreter:
    def __init__(self, rule):
        self.rule = SigmaRule(
            rule.get("title", rule.get("name", "Sigma rule")),
            rule.get("detection", {}),
            rule.get("level", "medium"),
            rule.get("id"),
        )

    @staticmethod
    def _match_value(actual, expected):
        if isinstance(expected, list):
            return any(SigmaInterpreter._match_value(actual, value) for value in expected)
        if isinstance(expected, str):
            text = str(actual).lower()
            value = expected.lower()
            if "|" in value:
                value, operator = value.rsplit("|", 1)
                if operator == "contains": return value in text
                if operator == "startswith": return text.startswith(value)
                if operator == "endswith": return text.endswith(value)
                raise ValueError(f"unsupported Sigma modifier: {operator}")
            if value.endswith("*"):
                return text.startswith(value[:-1])
        return str(actual).lower() == str(expected).lower()

    def matches(self, event):
        detection = self.rule.detection
        condition = detection.get("condition", "selection")
        selections = {
            name: all(self._match_value(event.get(field), value) for field, value in values.items())
            for name, values in detection.items()
            if name != "condition" and isinstance(values, dict)
        }
        if condition in selections:
            return selections[condition]
        if condition.lower() in {"1 of them", "1 of *", "any"}:
            raise ValueError("unsupported Sigma condition: 1 of")
        if " and " in condition.lower():
            return all(selections.get(part.strip(), False) for part in condition.split("and"))
        if " or " in condition.lower():
            raise ValueError("unsupported Sigma condition: or")
        return any(selections.values())

    def process_event(self, event):
        if not self.matches(event):
            return None
        return {
            "timestamp": event["timestamp"],
            "rule_name": self.rule.title,
            "severity": self.rule.level.upper(),
            "attacker_ip": event.get("source_ip", "unknown"),
            "target_user": event.get("user", "unknown"),
            "description": f"Sigma rule matched: {self.rule.title}",
            **({"mitre_technique": event["mitre_technique"]} if event.get("mitre_technique") else {}),
        }

    def as_detector(self):
        return self
