import sqlite3
import os


DB_NAME = "/home/omar-25th/siem.db"


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
                           NULL
                       );
                       """)

        # Indexes for fast querying during dashboard searches and ML extraction
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);")

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
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
                       INSERT INTO alerts (timestamp, rule_name, severity, attacker_ip, target_user, description)
                       VALUES (?, ?, ?, ?, ?, ?)
                       """, (
                           alert["timestamp"].isoformat(),
                           alert["rule_name"],
                           alert["severity"],
                           alert["attacker_ip"],
                           alert["target_user"],
                           alert["description"]
                       ))
        conn.commit()