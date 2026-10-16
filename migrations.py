"""Idempotent database migrations for source and ATT&CK metadata."""


def add_column_if_missing(conn, table, column, definition):
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def migrate(conn):
    """Upgrade an existing SIEM database without dropping user data."""
    add_column_if_missing(conn, "events", "source", "TEXT NOT NULL DEFAULT 'auth'")
    add_column_if_missing(conn, "events", "mitre_technique", "TEXT")
    add_column_if_missing(conn, "alerts", "source", "TEXT NOT NULL DEFAULT 'unknown'")
    add_column_if_missing(conn, "alerts", "mitre_technique", "TEXT")
    conn.commit()
