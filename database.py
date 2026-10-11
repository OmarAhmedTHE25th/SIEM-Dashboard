import sqlite3
from config import DB_PATH

DB_NAME = DB_PATH


def _ensure_alert_columns(conn):
    columns = [row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()]
    if "status" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")


def init_db():
    """Initializes tables and indexes if they don't exist."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        # Events table
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS events
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           timestamp
                           TEXT
                           NOT
                           NULL,
                           hostname
                           TEXT
                           NOT
                           NULL,
                           source_ip
                           TEXT
                           NOT
                           NULL,
                           user
                           TEXT
                           NOT
                           NULL,
                           status
                           TEXT
                           NOT
                           NULL,
                           raw
                           TEXT
                           NOT
                           NULL
                       );
                       """)

        # Alerts table
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS alerts
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           timestamp
                           TEXT
                           NOT
                           NULL,
                           rule_name
                           TEXT
                           NOT
                           NULL,
                           severity
                           TEXT
                           NOT
                           NULL,
                           attacker_ip
                           TEXT
                           NOT
                           NULL,
                           target_user
                           TEXT
                           NOT
                           NULL,
                           description
                           TEXT
                           NOT
                           NULL,
                           status
                           TEXT
                           NOT
                           NULL
                           DEFAULT 'active'
                       );
                       """)

        _ensure_alert_columns(conn)

        # Indexes for fast querying during dashboard searches and ML extraction
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")

        conn.commit()


def insert_event(event: dict):
    """Inserts a single normalized log event."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
                       INSERT INTO events (timestamp, hostname, source_ip, user, status, raw)
                       VALUES (?, ?, ?, ?, ?, ?)
                       """, (
                           event["timestamp"].isoformat(),
                           event["hostname"],
                           event["source_ip"],
                           event["user"],
                           event["status"],
                           event["raw"]
                       ))
        conn.commit()


def insert_alert(alert: dict):
    """Inserts a triggered alert record."""
    status = alert.get("status", "active")
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
                       INSERT INTO alerts (timestamp, rule_name, severity, attacker_ip, target_user, description, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       """, (
                           alert["timestamp"].isoformat(),
                           alert["rule_name"],
                           alert["severity"],
                           alert["attacker_ip"],
                           alert["target_user"],
                           alert["description"],
                           status
                       ))
        conn.commit()