import unittest
from datetime import datetime

from parser import parse_auth_line


class ParseAuthLineTests(unittest.TestCase):
    def test_parses_iso_timestamp_and_valid_user(self):
        line = (
            "2026-10-10T19:13:47.907110+03:00 server1 sshd[123]: "
            "Accepted password for omar from 192.0.2.10 port 22 ssh2"
        )

        event = parse_auth_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["timestamp"], datetime.fromisoformat("2026-10-10T19:13:47.907110+03:00"))
        self.assertEqual(event["hostname"], "server1")
        self.assertEqual(event["status"], "success")
        self.assertEqual(event["user"], "omar")
        self.assertEqual(event["source_ip"], "192.0.2.10")
        self.assertEqual(event["raw"], line)

    def test_parses_legacy_timestamp_and_invalid_user(self):
        line = (
            "Oct 10 14:00:10 server1 sshd[123]: "
            "Failed password for invalid user admin from 198.51.100.7 port 22 ssh2"
        )

        event = parse_auth_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["timestamp"], datetime(2026, 10, 10, 14, 0, 10))
        self.assertEqual(event["hostname"], "server1")
        self.assertEqual(event["status"], "failed")
        self.assertEqual(event["user"], "admin")
        self.assertEqual(event["source_ip"], "198.51.100.7")

    def test_parses_sudo_session_events(self):
        line = (
            "2026-10-10T19:13:47+03:00 server1 sudo: "
            "pam_unix(sudo:session): session opened for user root by omar(uid=0)"
        )

        event = parse_auth_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["status"], "success")
        self.assertEqual(event["user"], "root")
        self.assertEqual(event["source_ip"], "local")

    def test_ignores_non_ssh_or_non_password_lines(self):
        lines = (
            "2026-10-10T19:13:47+03:00 server1 cron: job completed",
            "2026-10-10T19:13:47+03:00 server1 sshd[123]: "
            "Connection closed by 192.0.2.10 port 22",
        )

        for line in lines:
            with self.subTest(line=line):
                self.assertIsNone(parse_auth_line(line))

    def test_returns_none_for_malformed_matching_lines(self):
        lines = (
            "not-a-date server1 sshd[123]: Failed password for user",
            "Oct 10 server1 sshd[123]: Failed password for user admin",
            "Oct 10 14:00:10 server1 sshd[123]: Failed password for user admin",
        )

        for line in lines:
            with self.subTest(line=line):
                self.assertIsNone(parse_auth_line(line))


if __name__ == "__main__":
    unittest.main()
