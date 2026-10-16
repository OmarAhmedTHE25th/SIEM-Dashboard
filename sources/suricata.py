import re
from .base import Source
from .common import parse_header


class SuricataSource(Source):
    name = "suricata"

    def parse(self, line):
        if "suricata" not in line.lower() or "ET " not in line:
            return None
        timestamp, hostname, message = parse_header(line.strip())
        if timestamp is None:
            return None
        match = re.search(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s*:\s*(?P<port>\d+)", message)
        if not match:
            return None
        user = re.search(r"for (?P<user>\S+)", message)
        return {"timestamp": timestamp, "hostname": hostname, "status": "failed",
                "user": user.group("user") if user else "unknown",
                "source_ip": match.group("ip"), "source": self.name, "raw": line.strip()}
