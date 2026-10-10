import sqlite3
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI(title="Custom SIEM API", version="1.0")

import os

DB_NAME = os.path.expanduser("~/siem.db")


def query_db(query: str, args: tuple = (), one: bool = False):
    """Helper to query sqlite and return dictionaries instead of tuples."""
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query, args)
        rv = cur.fetchall()
        return (rv[0] if rv else None) if one else rv


@app.get("/api/stats")
def get_stats():
    total_events = query_db("SELECT COUNT(*) as count FROM events", one=True)["count"]
    failed_logins = query_db("SELECT COUNT(*) as count FROM events WHERE status = 'failed'", one=True)["count"]
    total_alerts = query_db("SELECT COUNT(*) as count FROM alerts", one=True)["count"]

    return {
        "total_events": total_events,
        "failed_logins": failed_logins,
        "total_alerts": total_alerts
    }


@app.get("/api/alerts")
def get_alerts(limit: int = 15):
    rows = query_db(
        "SELECT id, timestamp, rule_name, severity, attacker_ip, target_user, description "
        "FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    return [dict(row) for row in rows]




BASE_DIR = Path(__file__).resolve().parent

@app.get("/")
def serve_dashboard():
    dashboard_path = BASE_DIR / "dashboard.html"
    return FileResponse(dashboard_path)