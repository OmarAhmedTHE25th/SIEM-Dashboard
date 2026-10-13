import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from detection_rules import (
    ImpossibleTravelDetector,
    OffHoursLoginDetector,
    SuccessfulAfterFailuresDetector,
)
from enrichment import IPEnricher


def event(when, status, ip="198.51.100.10", user="alice"):
    return {"timestamp": when, "status": status, "source_ip": ip, "user": user}


class DetectionRuleTests(unittest.TestCase):
    def test_success_after_many_failures(self):
        detector = SuccessfulAfterFailuresDetector(threshold=2, window_seconds=60)
        start = datetime(2026, 10, 10, 12)
        detector.process_event(event(start, "failed"))
        detector.process_event(event(start + timedelta(seconds=1), "failed"))
        alert = detector.process_event(event(start + timedelta(seconds=2), "success"))
        self.assertEqual(alert["rule_name"], "SUCCESS_AFTER_MANY_FAILURES")
        self.assertEqual(alert["target_user"], "alice")

    def test_off_hours(self):
        detector = OffHoursLoginDetector(start=22, end=6)
        alert = detector.process_event(event(datetime(2026, 10, 10, 23), "success"))
        self.assertEqual(alert["rule_name"], "OFF_HOURS_LOGIN")
        self.assertIsNone(detector.process_event(event(datetime(2026, 10, 10, 14), "success")))

    def test_impossible_travel(self):
        detector = ImpossibleTravelDetector(max_speed_kmh=500)
        first = event(datetime(2026, 10, 10, 12), "success")
        second = event(datetime(2026, 10, 10, 13), "success", ip="203.0.113.10")
        london = {"latitude": 51.5, "longitude": -0.1}
        new_york = {"latitude": 40.7, "longitude": -74.0}
        self.assertIsNone(detector.process_event(first, london))
        alert = detector.process_event(second, new_york)
        self.assertEqual(alert["rule_name"], "IMPOSSIBLE_TRAVEL")


class EnrichmentTests(unittest.TestCase):
    def test_injected_provider_supplies_offline_coordinates(self):
        locations = {
            "81.2.69.142": {
                "city": "London",
                "country": "United Kingdom",
                "latitude": 51.5074,
                "longitude": -0.1278,
            },
            "133.242.0.1": {
                "city": "Tokyo",
                "country": "Japan",
                "latitude": 35.6762,
                "longitude": 139.6503,
            },
        }
        enricher = IPEnricher(geoip_provider=locations.get)

        self.assertEqual(enricher.lookup("81.2.69.142")["city"], "London")
        self.assertEqual(enricher.lookup("133.242.0.1")["city"], "Tokyo")

    def test_private_addresses_do_not_call_provider(self):
        enricher = IPEnricher()
        with patch.object(enricher, "_get_json") as lookup:
            result = enricher.lookup("192.168.1.10")
        lookup.assert_not_called()
        self.assertTrue(result["private"])

    def test_enrichment_is_cached(self):
        enricher = IPEnricher(cache_ttl=60)
        with patch.object(enricher, "_get_json", return_value={"country_name": "Example"} ) as lookup:
            first = enricher.lookup("8.8.8.8")
            second = enricher.lookup("8.8.8.8")
        self.assertEqual(first["country"], "Example")
        self.assertEqual(second["country"], "Example")
        lookup.assert_called_once()

    def test_describes_geoip_and_reputation(self):
        description = IPEnricher.describe({
            "city": "London",
            "country": "GB",
            "abuse_confidence_score": 75,
        })

        self.assertEqual(description, "GeoIP: London, GB; AbuseIPDB confidence: 75%")


if __name__ == "__main__":
    unittest.main()
