from pathlib import Path


class IOCMatcher:
    def __init__(self, path=None):
        self.path = Path(path or "threat_intel/iocs.txt")
        self.iocs = self._load()

    def _load(self):
        values = []
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and ":" in line:
                    kind, value = line.split(":", 1)
                    values.append((kind.strip().lower(), value.strip()))
        return values

    def match(self, event):
        haystack = " ".join(str(event.get(key, "")) for key in ("source_ip", "raw", "user", "hostname"))
        return [f"{kind}:{value}" for kind, value in self.iocs
                if (kind == "ip" and event.get("source_ip") == value) or
                (kind != "ip" and value.lower() in haystack.lower())]
