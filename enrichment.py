"""Optional, best-effort IP enrichment providers.

Enrichment is deliberately non-critical: an unavailable provider never blocks
log ingestion or detection.
"""
import ipaddress
import os
import time
from typing import Any, Callable
from urllib.request import Request, urlopen
import json


class IPEnricher:
    def __init__(
        self,
        cache_ttl: int | None = None,
        timeout: float | None = None,
        geoip_provider: Callable[[str], dict[str, Any] | None] | None = None,
    ):
        self.cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self.cache_ttl = cache_ttl or int(os.getenv("SIEM_GEOIP_CACHE_TTL", "3600"))
        self.timeout = timeout or float(os.getenv("SIEM_ENRICHMENT_TIMEOUT", "2.0"))
        self.geoip_url = os.getenv("SIEM_GEOIP_URL", "https://ipapi.co/{ip}/json/")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        self.geoip_provider = geoip_provider

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
        if not ip or self.is_private(ip):
            return {"ip": ip, "private": True}
        now = time.monotonic()
        cached = self.cache.get(ip)
        if cached and now - cached[0] < self.cache_ttl:
            return cached[1].copy()

        result: dict[str, Any] = {"ip": ip}
        geo = (
            self.geoip_provider(ip)
            if self.geoip_provider is not None
            else self._get_json(self.geoip_url.format(ip=ip))
        )
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


class ThreatIntelEnricher:
    """Best-effort VirusTotal and OTX lookups, disabled unless keys are set."""
    def __init__(self, timeout: float = 2.0, vt_key: str | None = None,
                 otx_key: str | None = None, fetcher: Callable | None = None):
        self.timeout = timeout
        self.vt_key = vt_key or os.getenv("VT_API_KEY")
        self.otx_key = otx_key or os.getenv("OTX_API_KEY")
        self.fetcher = fetcher or self._fetch

    def _fetch(self, url: str, headers: dict[str, str]) -> dict[str, Any] | None:
        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception:
            return None

    def lookup(self, indicator: str, indicator_type: str = "ip") -> dict[str, Any]:
        result = {"indicator": indicator, "type": indicator_type, "providers": {}}
        if self.vt_key:
            result["providers"]["virustotal"] = self.fetcher(
                f"https://www.virustotal.com/api/v3/{indicator_type}s/{indicator}",
                {"x-apikey": self.vt_key})
        if self.otx_key:
            result["providers"]["otx"] = self.fetcher(
                f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general",
                {"X-OTX-API-KEY": self.otx_key})
        return result
