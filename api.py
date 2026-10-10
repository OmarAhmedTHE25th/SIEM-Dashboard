import os
import sqlite3
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from config import DB_PATH

app = FastAPI(title="SIEM Dashboard API")

BASE_DIR = Path(__file__).resolve().parent


DB_NAME = DB_PATH


def get_db():
    if not os.path.exists(DB_NAME):
        raise FileNotFoundError(f"Database file does not exist at: {DB_NAME}")

    conn = sqlite3.connect(DB_NAME, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn


@app.get("/")
def serve_dashboard():
    dashboard_path = BASE_DIR / "dashboard.html"
    if not dashboard_path.exists():
        raise HTTPException(status_code=404, detail="dashboard.html not found")
    return FileResponse(dashboard_path)


@app.get("/api/stats")
def get_stats():
    try:
        with get_db() as conn:
            cur = conn.cursor()
            total_events = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            failed_logins = cur.execute(
                "SELECT COUNT(*) FROM events WHERE status = 'failed'"
            ).fetchone()[0]
            total_alerts = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            unique_ips = cur.execute("SELECT COUNT(DISTINCT attacker_ip) FROM alerts").fetchone()[0]

            return {
                "total_events": total_events,
                "failed_logins": failed_logins,
                "total_alerts": total_alerts,
                "unique_attacker_ips": unique_ips
            }
    except Exception as e:
        print(f"[API ERROR /api/stats]: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            rows = cur.execute(
                "SELECT timestamp, rule_name, severity, attacker_ip, target_user, description "
                "FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"[API ERROR /api/alerts]: {e}")
        raise HTTPException(status_code=500, detail=str(e))