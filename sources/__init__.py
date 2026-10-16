"""Pluggable log sources.

Sources yield the normalized event dictionaries consumed by the existing
detectors.  The small registry keeps ingestion code independent of a source's
parser while retaining ``parse_auth_line`` compatibility.
"""

from .base import LogSource, Source, SourceRegistry
from .auditd import AuditdSource, parse_auditd_line
from .sshd import SshdSource
from .sudo import SudoSource
from .suricata import SuricataSource

default_registry = SourceRegistry()
default_registry.register("auditd", AuditdSource)


class AuthSource:
    name = "auth"

    def parse(self, line):
        from parser import parse_auth_line
        return parse_auth_line(line)


default_registry.register("auth", AuthSource)

__all__ = [
    "LogSource", "Source", "SourceRegistry", "AuditdSource", "SshdSource",
    "SudoSource", "SuricataSource", "AuthSource",
    "parse_auditd_line", "default_registry",
]
