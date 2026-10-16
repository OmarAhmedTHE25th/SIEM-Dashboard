import sqlite3
from config import DB_PATH

DB_NAME = DB_PATH


def _ensure_alert_columns(conn):
    columns = [row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()]
    if "status" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
    if "source" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown'")
    if "mitre_technique" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN mitre_technique TEXT")
    if "mitre" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN mitre TEXT")
    if "technique_name" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN technique_name TEXT")
    if "dedup_key" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN dedup_key TEXT")
    if "acknowledged_at" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT")
    if "sla_due_at" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN sla_due_at TEXT")
    if "dedup_count" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN dedup_count INTEGER NOT NULL DEFAULT 1")
    if "verdict" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN verdict TEXT")
    if "verdict_reason" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN verdict_reason TEXT")
    if "verdict_at" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN verdict_at TEXT")
    if "suppressed_reason" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN suppressed_reason TEXT")
    if "escalated_at" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN escalated_at TEXT")
    if "closed_at" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN closed_at TEXT")


def _ensure_event_columns(conn):
    columns = [row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()]
    if "source" not in columns:
        conn.execute("ALTER TABLE events ADD COLUMN source TEXT NOT NULL DEFAULT 'sshd'")
    if "mitre_technique" not in columns:
        conn.execute("ALTER TABLE events ADD COLUMN mitre_technique TEXT")


def _ensure_iocs_columns(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(iocs)").fetchall()}
    if "first_seen" not in columns:
        conn.execute("ALTER TABLE iocs ADD COLUMN first_seen TEXT")
    if "last_seen" not in columns:
        conn.execute("ALTER TABLE iocs ADD COLUMN last_seen TEXT")
    if "expires_at" not in columns:
        conn.execute("ALTER TABLE iocs ADD COLUMN expires_at TEXT")
    if "confidence" not in columns:
        conn.execute("ALTER TABLE iocs ADD COLUMN confidence REAL NOT NULL DEFAULT 0.5")
    else:
        conn.execute("UPDATE iocs SET confidence = 0.5 WHERE confidence IS NULL")
    if "source" not in columns:
        conn.execute("ALTER TABLE iocs ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'")
    if "verified" not in columns:
        conn.execute("ALTER TABLE iocs ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
    if "weight" not in columns:
        conn.execute("ALTER TABLE iocs ADD COLUMN weight REAL NOT NULL DEFAULT 0.5")


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
        _ensure_event_columns(conn)
        # Case management, indicator enrichment and audit-friendly matching.
        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'new',
            severity TEXT NOT NULL DEFAULT 'MEDIUM', assignee TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, closed_at TEXT,
            notes TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS case_alerts (
            case_id INTEGER NOT NULL, alert_id INTEGER NOT NULL,
            PRIMARY KEY (case_id, alert_id),
            FOREIGN KEY(case_id) REFERENCES cases(id), FOREIGN KEY(alert_id) REFERENCES alerts(id)
        );
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL,
            type TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'manual',
            confidence REAL NOT NULL DEFAULT 0.5, tags TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(type, value)
        );
        CREATE TABLE IF NOT EXISTS ioc_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ioc_id INTEGER NOT NULL,
            event_id INTEGER, alert_id INTEGER, matched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ioc_id, event_id, alert_id),
            FOREIGN KEY(ioc_id) REFERENCES iocs(id)
        );
        CREATE TABLE IF NOT EXISTS enrichments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, indicator TEXT NOT NULL, provider TEXT NOT NULL,
            payload TEXT NOT NULL, fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(indicator, provider)
        );
        CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
        CREATE INDEX IF NOT EXISTS idx_case_alerts_alert ON case_alerts(alert_id);
        """)
        _ensure_iocs_columns(conn)
        case_columns = {row[1] for row in cursor.execute("PRAGMA table_info(cases)")}
        if "severity" not in case_columns:
            cursor.execute("ALTER TABLE cases ADD COLUMN severity TEXT NOT NULL DEFAULT 'MEDIUM'")
        if "notes" not in case_columns:
            cursor.execute("ALTER TABLE cases ADD COLUMN notes TEXT NOT NULL DEFAULT ''")

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
                       INSERT INTO events
                       (timestamp, hostname, source_ip, user, status, raw, source, mitre_technique)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       """, (
                           event["timestamp"].isoformat(),
                           event["hostname"],
                           event["source_ip"],
                           event["user"],
                           event["status"],
                           event["raw"],
                           event.get("source", "sshd"),
                           event.get("mitre_technique")
                       ))
        conn.commit()


def insert_alert(alert: dict):
    """Inserts a triggered alert record."""
    status = alert.get("status", "active")
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        dedup_key = alert.get("dedup_key") or "|".join(str(alert.get(k, "")) for k in
                                                        ("rule_name", "attacker_ip", "target_user"))
        # Do not flood the console with the same active finding.
        duplicate = cursor.execute(
            "SELECT id, timestamp FROM alerts WHERE dedup_key = ? AND status = 'active' "
            "ORDER BY id DESC LIMIT 1", (dedup_key,)).fetchone()
        if duplicate:
            from datetime import datetime, timedelta
            existing_time = datetime.fromisoformat(duplicate[1])
            current_time = alert["timestamp"]
            if current_time - existing_time > timedelta(minutes=5):
                duplicate = None
        if duplicate:
            cursor.execute("UPDATE alerts SET dedup_count = dedup_count + 1 WHERE id = ?", (duplicate[0],))
            conn.commit()
            return duplicate[0]
        cursor.execute("""
                       INSERT INTO alerts
                       (timestamp, rule_name, severity, attacker_ip, target_user, description, status, source, mitre_technique, mitre, technique_name, dedup_key, sla_due_at, dedup_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                       """, (
                           alert["timestamp"].isoformat(),
                           alert["rule_name"],
                           alert["severity"],
                           alert["attacker_ip"],
                           alert["target_user"],
                           alert["description"],
                           status,
                           alert.get("source", "rule"),
                           alert.get("mitre_technique") or alert.get("mitre"),
                           alert.get("mitre_technique") or alert.get("mitre"),
                           alert.get("technique_name"),
                           dedup_key,
                           alert.get("sla_due_at")
                       ))
        conn.commit()
        return cursor.lastrowid