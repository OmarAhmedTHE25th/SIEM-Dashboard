from datetime import datetime

def parse_auth_line(line: str) -> dict | None:
    line = line.strip()

    # We only care about SSH password failures or successes
    if "sshd" not in line or not ("Failed password" in line or "Accepted password" in line):
        return None

    # Split header from message body at ": "
    try:
        header_part, message_part = line.split(": ", 1)
    except ValueError:
        return None

    header_tokens = header_part.split()
    if len(header_tokens) < 2:
        return None

    # 1. Parse Timestamp & Hostname
    # Modern ISO format (e.g. 2026-10-10T19:13:47.907110+03:00)
    if "T" in header_tokens[0]:
        try:
            timestamp = datetime.fromisoformat(header_tokens[0])
        except ValueError:
            return None
        hostname = header_tokens[1]
    else:
        # Legacy syslog format fallback (e.g. Oct 10 14:00:10)
        if len(header_tokens) < 4:
            return None
        date_str = f"2026 {header_tokens[0]} {header_tokens[1]} {header_tokens[2]}"
        try:
            timestamp = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        hostname = header_tokens[3]

    # 2. Parse Message Body (Action, User, IP)
    msg_tokens = message_part.split()
    status = "failed" if "Failed" in msg_tokens else "success"

    try:
        # Source IP follows 'from'
        from_idx = msg_tokens.index("from")
        source_ip = msg_tokens[from_idx + 1]

        # Target user follows 'for'
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
        "raw": line
    }