"""Linux auditd (``ausearch``/audit.log) source."""
import re
import shlex
from datetime import datetime, timezone


_AUDIT_RE = re.compile(r"msg=audit\((?P<seconds>\d+(?:\.\d+)?):[^)]*\)")


def _fields(text):
    try:
        return dict((token.split("=", 1) for token in shlex.split(text) if "=" in token))
    except ValueError:
        return {}


def parse_auditd_line(line: str) -> dict | None:
    """Parse an auditd authentication record into the common event shape."""
    if not line or "type=" not in line or "msg=audit(" not in line:
        return None
    fields = _fields(line)
    event_type = fields.get("type", "")
    if event_type not in {"USER_AUTH", "USER_LOGIN", "USER_ACCT", "USER_START", "EXECVE", "SYSCALL"}:
        return None
    match = _AUDIT_RE.search(line)
    if not match:
        return None
    timestamp = datetime.fromtimestamp(float(match.group("seconds")), tz=timezone.utc)
    result = fields.get("res", "").lower()
    status = "success" if result in {"success", "yes", "1"} else "failed"
    user = fields.get("acct") or fields.get("user") or fields.get("uid") or fields.get("auid") or "unknown"
    source_ip = fields.get("addr") or fields.get("hostname") or "local"
    return {
        "timestamp": timestamp,
        "hostname": fields.get("hostname", "localhost"),
        "status": status if event_type not in {"EXECVE", "SYSCALL"} else "success",
        "user": user.strip('"'),
        "source_ip": source_ip.strip('"'),
        "source": "auditd",
        "event_type": event_type,
        "raw": line.strip(),
    }


class AuditdSource:
    name = "auditd"

    def parse(self, line):
        return parse_auditd_line(line)

    def events(self, lines):
        for line in lines:
            event = self.parse(line)
            if event:
                yield event
