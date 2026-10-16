from collections import Counter

events_ingested = Counter()
alerts = Counter()
parser_failures = 0
db_write_errors = 0
detection_latencies = []


def snapshot():
    return {"events_ingested_total": dict(events_ingested),
            "parser_failures_total": parser_failures,
            "alerts_total": {f"{rule}:{severity}": count for (rule, severity), count in alerts.items()},
            "detection_latency_seconds": list(detection_latencies)}


def prometheus():
    lines = []
    for source, value in events_ingested.items():
        lines.append(f'events_ingested_total{{source="{source}"}} {value}')
    lines.append(f"parser_failures_total {parser_failures}")
    for (rule, severity), value in alerts.items():
        lines.append(f'alerts_total{{rule="{rule}",severity="{severity}"}} {value}')
    return "\n".join(lines) + "\n"
