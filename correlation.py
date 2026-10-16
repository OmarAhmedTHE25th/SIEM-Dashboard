"""Composable streaming correlation engine."""
from collections.abc import Iterable


class CorrelationRule:
    """Minimal protocol/base class for stateful streaming rules."""

    def process_event(self, event):
        raise NotImplementedError


class CorrelationEngine:
    """Dispatch events to rules and return all alerts emitted by those rules."""

    def __init__(self, rules: Iterable = ()):
        self.rules = list(rules)

    def add_rule(self, rule):
        self.rules.append(rule)
        return rule

    def __iter__(self):
        return iter(self.rules)

    def __len__(self):
        return len(self.rules)

    def process_event(self, event):
        alerts = []
        for rule in self.rules:
            alert = rule.process_event(event)
            if alert is not None:
                alerts.extend(alert if isinstance(alert, list) else [alert])
        return alerts

    def process(self, events):
        for event in events:
            yield from self.process_event(event)

    def reset(self):
        for rule in self.rules:
            reset = getattr(rule, "reset", None)
            if reset:
                reset()
