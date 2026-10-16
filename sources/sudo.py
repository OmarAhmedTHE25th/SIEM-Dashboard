import re
from .base import Source
from .common import parse_header


class SudoSource(Source):
    name = "sudo"

    def parse(self, line):
        if "sudo" not in line or "session" not in line or "for user" not in line or "by" not in line:
            return None
        timestamp, hostname, message = parse_header(line.strip())
        if timestamp is None:
            return None
        match = re.search(r"session (?:opened|closed) for user (?P<user>\S+)", message)
        actor = re.search(r"by (?P<actor>\S+)\(uid=", message)
        if not match or not actor:
            return None
        return {"timestamp": timestamp, "hostname": hostname, "status": "success",
                "user": match.group("user"), "source_ip": "local", "source": self.name,
                "raw": line.strip()}
