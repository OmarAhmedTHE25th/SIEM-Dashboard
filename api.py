import os
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
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


def require_api_auth(request: Request):
    token = os.getenv("SIEM_API_TOKEN")
    if not token:
        return

    auth_header = request.headers.get("authorization", "")
    x_api_key = request.headers.get("x-api-key", "")
    query_token = request.query_params.get("token")
    provided = None

    if auth_header.lower().startswith("bearer "):
        provided = auth_header.split(" ", 1)[1].strip()
    elif x_api_key:
        provided = x_api_key.strip()
    elif query_token:
        provided = query_token.strip()

    if provided != token:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/", dependencies=[Depends(require_api_auth)])
def serve_dashboard():
    dashboard_path = BASE_DIR / "dashboard.html"
    if not dashboard_path.exists():
        raise HTTPException(status_code=404, detail="dashboard.html not found")
    return FileResponse(dashboard_path)


@app.get("/api/stats", dependencies=[Depends(require_api_auth)])
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


@app.get("/api/alerts", dependencies=[Depends(require_api_auth)])
def get_alerts(limit: int = 50, status: str | None = None):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            if status:
                rows = cur.execute(
                    "SELECT id, timestamp, rule_name, severity, attacker_ip, target_user, description, status "
                    "FROM alerts WHERE status = ? ORDER BY id DESC LIMIT ?",
                    (status.lower(), limit),
                ).fetchall()
            else:
                rows = cur.execute(
                    "SELECT id, timestamp, rule_name, severity, attacker_ip, target_user, description, status "
                    "FROM alerts ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"[API ERROR /api/alerts]: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/incidents", dependencies=[Depends(require_api_auth)])
def get_incidents(limit: int = 10):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            rows = cur.execute(
                """
                SELECT attacker_ip, rule_name, COUNT(*) AS count, MAX(timestamp) AS last_seen,
                       MIN(timestamp) AS first_seen, SUM(CASE WHEN status = 'suppressed' THEN 1 ELSE 0 END) AS suppressed_count
                FROM alerts
                WHERE status != 'suppressed'
                GROUP BY attacker_ip, rule_name
                ORDER BY count DESC, last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"[API ERROR /api/incidents]: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/alerts/{alert_id}/ack", dependencies=[Depends(require_api_auth)])
def ack_alert(alert_id: int):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            updated = cursor.execute(
                "UPDATE alerts SET status = 'acknowledged' WHERE id = ?",
                (alert_id,),
            )
            conn.commit()
            if updated.rowcount == 0:
                raise HTTPException(status_code=404, detail="Alert not found")
            return {"status": "acknowledged", "alert_id": alert_id}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[API ERROR /api/alerts/{alert_id}/ack]: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/alerts/{alert_id}/suppress", dependencies=[Depends(require_api_auth)])
def suppress_alert(alert_id: int):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            updated = cursor.execute(
                "UPDATE alerts SET status = 'suppressed' WHERE id = ?",
                (alert_id,),
            )
            conn.commit()
            if updated.rowcount == 0:
                raise HTTPException(status_code=404, detail="Alert not found")
            return {"status": "suppressed", "alert_id": alert_id}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[API ERROR /api/alerts/{alert_id}/suppress]: {e}")
        raise HTTPException(status_code=500, detail=str(e))