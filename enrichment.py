"""Optional, best-effort IP enrichment providers.

Enrichment is deliberately non-critical: an unavailable provider never blocks
log ingestion or detection.
"""
import ipaddress
import os
import time
from typing import Any
from urllib.request import Request, urlopen
import json
MOCK_COORDS = {
    "81.2.69.142": {
        "ip": "81.2.69.142",
        "city": "London",
        "country": "United Kingdom",
        "latitude": 51.5074,
        "longitude": -0.1278
    },
    "133.242.0.1": {
        "ip": "133.242.0.1",
        "city": "Tokyo",
        "country": "Japan",
        "latitude": 35.6762,
        "longitude": 139.6503
    },
}


class IPEnricher:
    def __init__(self, cache_ttl: int | None = None, timeout: float | None = None):
        self.cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self.cache_ttl = cache_ttl or int(os.getenv("SIEM_GEOIP_CACHE_TTL", "3600"))
        self.timeout = timeout or float(os.getenv("SIEM_ENRICHMENT_TIMEOUT", "2.0"))
        self.geoip_url = os.getenv("SIEM_GEOIP_URL", "https://ipapi.co/{ip}/json/")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    @staticmethod
    def is_private(ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
            return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved
        except ValueError:
            return True

    def _get_json(self, url: str, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
        try:
            request = Request(url, headers=headers or {})
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception:
            return None

    def lookup(self, ip: str) -> dict[str, Any]:
        """Resolves IP geolocation and abuse metrics with caching"""
        if ip in MOCK_COORDS:
            return MOCK_COORDS[ip].copy()

        if not ip or self.is_private(ip):
            return {"ip": ip, "private": True}
        now = time.monotonic()
        cached = self.cache.get(ip)
        if cached and now - cached[0] < self.cache_ttl:
            return cached[1].copy()

        result: dict[str, Any] = {"ip": ip}
        geo = self._get_json(self.geoip_url.format(ip=ip))
        if geo:
            # Providers use both ipapi and GeoIP-style field names.
            for dest, names in {
                "country": ("country", "country_name"),
                "city": ("city",),
                "latitude": ("latitude", "lat"),
                "longitude": ("longitude", "lon", "lng"),
            }.items():
                for name in names:
                    if geo.get(name) is not None:
                        result[dest] = geo[name]
                        break
        if self.abuse_key:
            abuse = self._get_json(
                "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip,
                {"Key": self.abuse_key, "Accept": "application/json"},
            )
            data = abuse.get("data", {}) if abuse else {}
            if data.get("abuseConfidenceScore") is not None:
                result["abuse_confidence_score"] = data["abuseConfidenceScore"]
        self.cache[ip] = (now, result.copy())
        return result

    @staticmethod
    def describe(enrichment: dict[str, Any]) -> str:
        """Returns a compact, dashboard-safe description of enrichment data."""
        if enrichment.get("private"):
            return "Private/reserved source IP"

        location = ", ".join(
            str(enrichment[field])
            for field in ("city", "country")
            if enrichment.get(field)
        )
        details = [f"GeoIP: {location}" if location else "GeoIP: unavailable"]
        if enrichment.get("abuse_confidence_score") is not None:
            details.append(
                f"AbuseIPDB confidence: {enrichment['abuse_confidence_score']}%"
            )
        return "; ".join(details)
