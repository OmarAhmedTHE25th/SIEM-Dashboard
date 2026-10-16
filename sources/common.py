from datetime import datetime


def parse_header(line: str):
    try:
        header, message = line.split(": ", 1)
    except ValueError:
        return None, None, None
    tokens = header.split()
    if len(tokens) >= 2 and "T" in tokens[0]:
        try:
            return datetime.fromisoformat(tokens[0]), tokens[1], message
        except ValueError:
            return None, None, None
    if len(tokens) < 4:
        return None, None, None
    try:
        timestamp = datetime.strptime(
            f"2026 {tokens[0]} {tokens[1]} {tokens[2]}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None, None, None
    return timestamp, tokens[3], message
