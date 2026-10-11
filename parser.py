import re
from datetime import datetime


def _parse_header_and_body(line: str):
    try:
        header_part, message_part = line.split(": ", 1)
    except ValueError:
        return None, None, None

    header_tokens = header_part.split()
    if len(header_tokens) < 2:
        return None, None, None

    if "T" in header_tokens[0]:
        try:
            timestamp = datetime.fromisoformat(header_tokens[0])
        except ValueError:
            return None, None, None
        hostname = header_tokens[1]
    else:
        if len(header_tokens) < 4:
            return None, None, None
        date_str = f"2026 {header_tokens[0]} {header_tokens[1]} {header_tokens[2]}"
        try:
            timestamp = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None, None, None
        hostname = header_tokens[3]

    return timestamp, hostname, message_part


def parse_auth_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None

    if "sshd" in line and ("Failed password" in line or "Accepted password" in line):
        timestamp, hostname, message_part = _parse_header_and_body(line)
        if timestamp is None:
            return None

        msg_tokens = message_part.split()
        status = "failed" if "Failed" in msg_tokens else "success"

        try:
            from_idx = msg_tokens.index("from")
            source_ip = msg_tokens[from_idx + 1]

            for_idx = msg_tokens.index("for")
            if msg_tokens[for_idx + 1] == "invalid" and msg_tokens[for_idx + 2] == "user":
                user = msg_tokens[for_idx + 3]
            else:
                user = msg_tokens[for_idx + 1]
        except (ValueError, IndexError):
            return None

        return {
            "timestamp": timestamp,
            "hostname": hostname,
            "status": status,
            "user": user,
            "source_ip": source_ip,
            "raw": line,
        }

    # Support a narrow set of additional security log patterns without breaking SSH handling.
    if "sudo" in line and "session" in line and "user" in line and "by" in line:
        timestamp, hostname, message_part = _parse_header_and_body(line)
        if timestamp is None:
            return None

        user_match = re.search(r"session (?:opened|closed) for user (?P<user>\S+)", message_part)
        if not user_match:
            return None

        actor_match = re.search(r"by (?P<actor>\S+)\(uid=", message_part)
        if not actor_match:
            return None

        return {
            "timestamp": timestamp,
            "hostname": hostname,
            "status": "success",
            "user": user_match.group("user"),
            "source_ip": "local",
            "raw": line,
        }

    if "suricata" in line.lower() and "ET " in line:
        timestamp, hostname, message_part = _parse_header_and_body(line)
        if timestamp is None:
            return None

        ip_match = re.search(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s*:\s*(?P<port>\d+)", message_part)
        user_match = re.search(r"for (?P<user>\S+)", message_part)
        if not ip_match:
            return None

        return {
            "timestamp": timestamp,
            "hostname": hostname,
            "status": "failed",
            "user": user_match.group("user") if user_match else "unknown",
            "source_ip": ip_match.group("ip"),
            "raw": line,
        }

    return None