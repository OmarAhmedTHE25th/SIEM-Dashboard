"""Small, deterministic IOC matcher used by ingestion and the API."""
import re
from typing import Iterable
from threat_intel.matcher import confidence_weight, is_expired

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_iocs(value: str) -> set[tuple[str, str]]:
    text = value or ""
    found = {("ip", x) for x in IP_RE.findall(text)}
    found.update(("hash", x.lower()) for x in HASH_RE.findall(text))
    found.update(("domain", x.lower()) for x in DOMAIN_RE.findall(text))
    return found


def match_iocs(event: dict, indicators: Iterable[dict], min_weight=0.0) -> list[dict]:
    """Return matching indicators without making network calls."""
    values = extract_iocs(" ".join(str(event.get(k, "")) for k in
                                   ("source_ip", "hostname", "user", "raw", "description")))
    matches = []
    for ioc in indicators:
        if is_expired(ioc.get("expires_at")):
            continue
        weight = float(ioc.get("weight") if ioc.get("weight") is not None else confidence_weight(ioc))
        if weight < min_weight:
            continue
        if (str(ioc.get("type", "")).lower(), str(ioc.get("value", "")).lower()) in values:
            item = dict(ioc)
            item["weight"] = weight
            matches.append(item)
    return matches
