import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threat_intel.matcher import IOCMatcher, confidence_weight, is_expired


class IOCWeightTests(unittest.TestCase):
    def test_confidence_and_type_weight(self):
        self.assertEqual(confidence_weight({"type": "hash", "confidence": 0.8}), 0.8)
        self.assertEqual(confidence_weight({"type": "ip", "confidence": 0.5}), 0.15)

    def test_expiry(self):
        now = datetime.now(timezone.utc)
        self.assertTrue(is_expired(now - timedelta(seconds=1), now))
        self.assertFalse(is_expired(now + timedelta(seconds=1), now))
        self.assertFalse(is_expired(None, now))

    def test_match_filters_by_weight(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "iocs.txt"
            path.write_text("hash:0123456789abcdef0123456789abcdef\nip:203.0.113.10\n")
            matcher = IOCMatcher(path)
            matches = matcher.match(
                {"source_ip": "203.0.113.10", "raw": "0123456789abcdef0123456789abcdef"},
                min_weight=0.5,
            )
            self.assertEqual(matches, ["hash:0123456789abcdef0123456789abcdef"])
            self.assertEqual(matches[0].weight, 0.5)


if __name__ == "__main__":
    unittest.main()
