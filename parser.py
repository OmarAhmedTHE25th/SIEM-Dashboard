"""Backward-compatible log parsing entry points."""

from sources.registry import parse_any


def parse_line(line: str) -> dict | None:
    return parse_any(line)


def parse_auth_line(line: str) -> dict | None:
    """Deprecated compatibility wrapper for the original parser API."""
    return parse_line(line)
