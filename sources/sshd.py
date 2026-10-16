from .base import Source
from .common import parse_header


class SshdSource(Source):
    name = "sshd"

    def parse(self, line):
        if "sshd" not in line or not ("Failed password" in line or "Accepted password" in line):
            return None
        timestamp, hostname, message = parse_header(line.strip())
        if timestamp is None:
            return None
        tokens = message.split()
        try:
            source_ip = tokens[tokens.index("from") + 1]
            index = tokens.index("for") + 1
            if tokens[index:index + 2] == ["invalid", "user"]:
                index += 2
            user = tokens[index]
        except (ValueError, IndexError):
            return None
        return {"timestamp": timestamp, "hostname": hostname,
                "status": "failed" if "Failed" in tokens else "success",
                "user": user, "source_ip": source_ip, "source": self.name,
                "raw": line.strip()}
