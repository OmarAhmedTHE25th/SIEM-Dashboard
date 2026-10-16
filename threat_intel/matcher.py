from datetime import datetime, timezone
from pathlib import Path


TYPE_WEIGHTS = {
    "hash": 1.0,
    "ip": 0.3,
    "domain": 0.7,
    "url": 0.6,
    "email": 0.5,
}


def is_expired(expires_at, now=None):
    """Return whether an IOC expiry value is at or before ``now``."""
    if not expires_at:
        return False
    if now is None:
        now = datetime.now(timezone.utc)
    if isinstance(expires_at, str):
        value = expires_at.strip().replace("Z", "+00:00")
        try:
            expires_at = datetime.fromisoformat(value)
        except ValueError:
            return True
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return expires_at <= now


def confidence_weight(ioc, confidence=None):
    """Combine confidence and indicator type into a comparable match weight."""
    if isinstance(ioc, dict):
        kind = str(ioc.get("type", "")).lower()
        confidence = ioc.get("confidence", 0.5) if confidence is None else confidence
    else:
        kind = str(ioc).lower()
        confidence = 0.5 if confidence is None else confidence
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))
    return confidence * TYPE_WEIGHTS.get(kind, 0.5)


class IOCMatch(str):
    """String-compatible match carrying the computed IOC weight."""

    def __new__(cls, value, weight):
        result = super().__new__(cls, value)
        result.weight = weight
        return result


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
                    ioc = {"type": kind.strip().lower(), "value": value.strip(), "confidence": 0.5}
                    ioc["weight"] = confidence_weight(ioc)
                    values.append(ioc)
        return values

    def match(self, event, min_weight=0.0):
        haystack = " ".join(str(event.get(key, "")) for key in ("source_ip", "raw", "user", "hostname"))
        matches = []
        for ioc in self.iocs:
            if ioc["weight"] < min_weight or is_expired(ioc.get("expires_at")):
                continue
            kind, value = ioc["type"], ioc["value"]
            if ((kind == "ip" and event.get("source_ip") == value) or
                    (kind != "ip" and value.lower() in haystack.lower())):
                matches.append(IOCMatch(f"{kind}:{value}", ioc["weight"]))
        return matches
