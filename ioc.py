"""Small, deterministic IOC matcher used by ingestion and the API."""
import re
from typing import Iterable

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_iocs(value: str) -> set[tuple[str, str]]:
    text = value or ""
    found = {("ip", x) for x in IP_RE.findall(text)}
    found.update(("hash", x.lower()) for x in HASH_RE.findall(text))
    found.update(("domain", x.lower()) for x in DOMAIN_RE.findall(text))
    return found


def match_iocs(event: dict, indicators: Iterable[dict]) -> list[dict]:
    """Return matching indicators without making network calls."""
    values = extract_iocs(" ".join(str(event.get(k, "")) for k in
                                   ("source_ip", "hostname", "user", "raw", "description")))
    return [ioc for ioc in indicators
            if (str(ioc.get("type", "")).lower(), str(ioc.get("value", "")).lower()) in values]
