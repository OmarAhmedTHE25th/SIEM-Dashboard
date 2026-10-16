from .auditd import AuditdSource
from .sshd import SshdSource
from .sudo import SudoSource
from .suricata import SuricataSource

SOURCES = [SshdSource(), SudoSource(), SuricataSource(), AuditdSource()]


def parse_any(line: str) -> dict | None:
    for source in SOURCES:
        event = source.parse(line)
        if event is not None:
            event.setdefault("source", source.name)
            return event
    return None
