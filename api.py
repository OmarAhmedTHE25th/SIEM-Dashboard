import os
import sqlite3
import json
import csv
import io
from pathlib import Path
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse

from config import DB_PATH
from database import init_db
from enrichment import ThreatIntelEnricher
from ioc import match_iocs
from threat_intel.matcher import confidence_weight
from metrics import snapshot as metrics_snapshot, prometheus as metrics_prometheus
from attack import ATTACK, TACTICS, metadata as attack_metadata

app = FastAPI(title="SIEM Dashboard API")

BASE_DIR = Path(__file__).resolve().parent
DB_NAME = DB_PATH
ALERT_VERDICTS = {"true_positive", "false_positive", "benign_true_positive"}
SUPPRESSION_REASON_CODES = {"known_scanner", "authorized_test", "monitoring_account", "tuning_needed"}
IOC_DEFAULT_TTL = timedelta(days=90)


def get_db():
    if not os.path.exists(DB_NAME):
        raise FileNotFoundError(f"Database file does not exist at: {DB_NAME}")

    init_db()
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


@app.get("/api/coverage", dependencies=[Depends(require_api_auth)])
def get_coverage():
    """Return static ATT&CK rule coverage and alert-backed tactic counts."""
    try:
        with get_db() as conn:
            alert_rows = conn.execute(
                "SELECT rule_name, COUNT(*) AS count FROM alerts GROUP BY rule_name"
            )
            if hasattr(alert_rows, "fetchall"):
                alert_rows = alert_rows.fetchall()
            alert_counts = {row["rule_name"]: row["count"] for row in alert_rows}

        rules = []
        tactic_counts = {tactic: 0 for tactic in TACTICS}
        tactic_alert_counts = {tactic: 0 for tactic in TACTICS}
        for rule_name in ATTACK:
            item = attack_metadata(rule_name)
            count = alert_counts.get(rule_name, 0)
            item["alert_count"] = count
            item["covered"] = count > 0
            rules.append(item)
            for tactic in item["tactics"]:
                tactic_counts[tactic] += 1
                tactic_alert_counts[tactic] += count

        tactics = [
            {"tactic": tactic, "count": tactic_counts[tactic],
             "alert_count": tactic_alert_counts[tactic]}
            for tactic in TACTICS
        ]
        return {
            "tactics": tactics,
            "tactic_counts": {item["tactic"]: item["count"] for item in tactics},
            "rules": rules,
            "rule_coverage": rules,
            "total_rules": len(rules),
            "covered_rules": sum(rule["covered"] for rule in rules),
        }
    except Exception as e:
        print(f"[API ERROR /api/coverage]: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/alerts", dependencies=[Depends(require_api_auth)])
def get_alerts(limit: int = 50, status: str | None = None):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            limit = max(1, min(limit, 500))
            if status:
                rows = cur.execute(
                    "SELECT id, timestamp, rule_name, severity, attacker_ip, target_user, description, status, mitre, mitre_technique, technique_name, sla_due_at, dedup_key, dedup_count, verdict, verdict_reason, verdict_at, suppressed_reason, escalated_at, closed_at "
                    "FROM alerts WHERE status = ? ORDER BY id DESC LIMIT ?",
                    (status.lower(), limit),
                ).fetchall()
            else:
                rows = cur.execute(
                    "SELECT id, timestamp, rule_name, severity, attacker_ip, target_user, description, status, mitre, mitre_technique, technique_name, sla_due_at, dedup_key, dedup_count, verdict, verdict_reason, verdict_at, suppressed_reason, escalated_at, closed_at "
                    "FROM alerts ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"[API ERROR /api/alerts]: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/alerts/export", dependencies=[Depends(require_api_auth)])
def export_alerts_csv(format: str = "csv"):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id,timestamp,rule_name,severity,attacker_ip,target_user,status,description,mitre,mitre_technique,technique_name,verdict,verdict_reason,verdict_at,suppressed_reason,escalated_at,closed_at "
            "FROM alerts ORDER BY id DESC").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(rows[0].keys() if rows else ["id", "timestamp", "rule_name", "severity"])
    writer.writerows([tuple(r) for r in rows])
    if format == "json":
        return [dict(row) for row in rows]
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=alerts.csv"})


@app.get("/api/incidents", dependencies=[Depends(require_api_auth)])
def get_incidents(limit: int = 10):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            rows = cur.execute(
                """
                SELECT attacker_ip, rule_name, COUNT(*) AS count, MAX(timestamp) AS last_seen,
                       MIN(timestamp) AS first_seen, SUM(dedup_count) AS count_including_dedup,
                       SUM(CASE WHEN status = 'suppressed' THEN 1 ELSE 0 END) AS suppressed_count
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
def ack_alert(alert_id: int, payload: dict | None = None):
    try:
        payload = payload or {}
        verdict = payload.get("verdict")
        reason = payload.get("reason")
        if verdict is not None:
            verdict = str(verdict).strip().lower()
            if verdict not in ALERT_VERDICTS:
                raise HTTPException(400, "invalid verdict")
        if reason is not None and not isinstance(reason, str):
            raise HTTPException(400, "reason must be a string")
        with get_db() as conn:
            cursor = conn.cursor()
            updated = cursor.execute(
                "UPDATE alerts SET status = 'acknowledged', acknowledged_at = CURRENT_TIMESTAMP, "
                "verdict = COALESCE(?, verdict), verdict_reason = COALESCE(?, verdict_reason), "
                "verdict_at = CASE WHEN ? IS NOT NULL THEN CURRENT_TIMESTAMP ELSE verdict_at END "
                "WHERE id = ?",
                (verdict, reason, verdict, alert_id),
            )
            conn.commit()
            if updated.rowcount == 0:
                raise HTTPException(status_code=404, detail="Alert not found")
            return {"status": "acknowledged", "alert_id": alert_id, "verdict": verdict,
                    "verdict_reason": reason}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[API ERROR /api/alerts/{alert_id}/ack]: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/alerts/{alert_id}/suppress", dependencies=[Depends(require_api_auth)])
def suppress_alert(alert_id: int, payload: dict | None = None):
    try:
        payload = payload or {}
        reason_code = payload.get("reason_code") if isinstance(payload, dict) else None
        if reason_code not in SUPPRESSION_REASON_CODES:
            raise HTTPException(400, "invalid reason_code")
        with get_db() as conn:
            cursor = conn.cursor()
            updated = cursor.execute(
                "UPDATE alerts SET status = 'suppressed', suppressed_reason = ? WHERE id = ?",
                (reason_code, alert_id),
            )
            conn.commit()
            if updated.rowcount == 0:
                raise HTTPException(status_code=404, detail="Alert not found")
            return {"status": "suppressed", "alert_id": alert_id, "reason_code": reason_code}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[API ERROR /api/alerts/{alert_id}/suppress]: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/alerts/{alert_id}/escalate", dependencies=[Depends(require_api_auth)])
def escalate_alert(alert_id: int):
    try:
        with get_db() as conn:
            row = conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Alert not found")
            conn.execute("UPDATE alerts SET escalated_at = CURRENT_TIMESTAMP WHERE id = ?", (alert_id,))
            conn.commit()
            return {"status": row["status"], "alert_id": alert_id, "escalated": True}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[API ERROR /api/alerts/{alert_id}/escalate]: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/events", dependencies=[Depends(require_api_auth)])
def get_events(limit: int = 100, q: str | None = None, source: str | None = None):
    limit = max(1, min(limit, 1000))
    clauses, params = [], []
    if q:
        clauses.append("(raw LIKE ? OR source_ip LIKE ? OR user LIKE ? OR hostname LIKE ?)")
        params.extend([f"%{q}%"] * 4)
    if source:
        clauses.append("source = ?"); params.append(source)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM events" + where + " ORDER BY id DESC LIMIT ?",
                            (*params, limit)).fetchall()
        return [dict(row) for row in rows]


@app.get("/api/events/{event_id}", dependencies=[Depends(require_api_auth)])
def get_event(event_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Event not found")
        return dict(row)


@app.get("/api/alerts/{alert_id}", dependencies=[Depends(require_api_auth)])
def get_alert(alert_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Alert not found")
        result = dict(row)
        result["events"] = [dict(event) for event in conn.execute(
            "SELECT * FROM events WHERE source_ip = ? AND timestamp BETWEEN datetime(?, '-5 minutes') AND datetime(?, '+5 minutes')",
            (row["attacker_ip"], row["timestamp"], row["timestamp"])).fetchall()]
        return result


@app.get("/api/search", dependencies=[Depends(require_api_auth)])
def search(q: str = "", source: str | None = None, user: str | None = None,
           ip: str | None = None, rule: str | None = None, severity: str | None = None,
           status: str | None = None, since: str | None = None, until: str | None = None,
           kind: str = "both", offset: int = 0, limit: int = 100):
    limit = max(1, min(limit, 500))
    with get_db() as conn:
        term = f"%{q}%"
        event_clauses, event_params = ["(raw LIKE ? OR source_ip LIKE ? OR user LIKE ? OR hostname LIKE ?)"], [term] * 4
        alert_clauses, alert_params = ["(description LIKE ? OR rule_name LIKE ? OR attacker_ip LIKE ? OR target_user LIKE ?)"], [term] * 4
        if source: event_clauses.append("source = ?"); event_params.append(source)
        if user: event_clauses.append("user LIKE ?"); event_params.append(user + "%")
        if ip: event_clauses.append("source_ip = ?"); event_params.append(ip)
        if rule: alert_clauses.append("rule_name = ?"); alert_params.append(rule)
        if severity: alert_clauses.append("severity = ?"); alert_params.append(severity)
        if status: alert_clauses.append("status = ?"); alert_params.append(status)
        if since: event_clauses.append("timestamp >= ?"); event_params.append(since); alert_clauses.append("timestamp >= ?"); alert_params.append(since)
        if until: event_clauses.append("timestamp <= ?"); event_params.append(until); alert_clauses.append("timestamp <= ?"); alert_params.append(until)
        events = conn.execute("SELECT * FROM events WHERE " + " AND ".join(event_clauses) + " ORDER BY id DESC LIMIT ? OFFSET ?", (*event_params, limit, offset)).fetchall() if kind in {"events", "both"} else []
        alerts = conn.execute("SELECT * FROM alerts WHERE " + " AND ".join(alert_clauses) + " ORDER BY id DESC LIMIT ? OFFSET ?", (*alert_params, limit, offset)).fetchall() if kind in {"alerts", "both"} else []
        return {"events": [dict(r) for r in events], "alerts": [dict(r) for r in alerts],
                "total": {"events": len(events), "alerts": len(alerts)}}


@app.get("/api/metrics", dependencies=[Depends(require_api_auth)])
def metrics():
    with get_db() as conn:
        result = {
            "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "cases": conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0],
            "open_cases": conn.execute("SELECT COUNT(*) FROM cases WHERE status = 'open'").fetchone()[0],
            "severity": [dict(r) for r in conn.execute(
                "SELECT severity, COUNT(*) count FROM alerts GROUP BY severity").fetchall()],
            "status": [dict(r) for r in conn.execute(
                "SELECT status, COUNT(*) count FROM alerts GROUP BY status").fetchall()],
        }
        result["process"] = metrics_snapshot()
        return result


@app.get("/metrics")
def prometheus_metrics():
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(metrics_prometheus(), media_type="text/plain")


@app.get("/api/metrics/timeseries", dependencies=[Depends(require_api_auth)])
def metrics_timeseries(days: int = 7):
    days = max(1, min(days, 365))
    with get_db() as conn:
        rows = conn.execute(
            "SELECT substr(timestamp,1,10) day, COUNT(*) count FROM alerts "
            "WHERE timestamp >= datetime('now', ?) GROUP BY day ORDER BY day",
            (f"-{days} days",)).fetchall()
        return [dict(r) for r in rows]


@app.post("/api/cases", dependencies=[Depends(require_api_auth)])
def create_case(payload: dict):
    title = str(payload.get("title", "")).strip()
    if not title:
        raise HTTPException(400, "title is required")
    with get_db() as conn:
        status = payload.get("status", "new")
        if status not in {"new", "investigating", "contained", "closed"}:
            raise HTTPException(400, "invalid status")
        cur = conn.execute("INSERT INTO cases(title,status,severity,assignee,notes) VALUES(?,?,?,?,?)",
                           (title, status, payload.get("severity", "MEDIUM"),
                            payload.get("assignee"), payload.get("notes", "")))
        for alert_id in payload.get("alert_ids", []):
            conn.execute("INSERT OR IGNORE INTO case_alerts(case_id,alert_id) VALUES(?,?)",
                         (cur.lastrowid, int(alert_id)))
        conn.commit()
        return {"id": cur.lastrowid, "title": title}


@app.get("/api/cases", dependencies=[Depends(require_api_auth)])
def list_cases(status: str | None = None):
    with get_db() as conn:
        if status:
            rows = conn.execute("SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC", (status,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
        return [dict(r) for r in rows]


@app.get("/api/cases/{case_id}", dependencies=[Depends(require_api_auth)])
def get_case(case_id: int):
    with get_db() as conn:
        case = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not case:
            raise HTTPException(404, "Case not found")
        alerts = conn.execute(
            "SELECT a.* FROM alerts a JOIN case_alerts ca ON ca.alert_id=a.id WHERE ca.case_id=?",
            (case_id,)).fetchall()
        result = dict(case); result["alerts"] = [dict(r) for r in alerts]
        return result


@app.patch("/api/cases/{case_id}", dependencies=[Depends(require_api_auth)])
def update_case(case_id: int, payload: dict):
    allowed = {"title", "status", "severity", "assignee", "notes"}
    if "status" in payload and payload["status"] not in {"new", "investigating", "contained", "closed"}:
        raise HTTPException(400, "invalid status")
    fields = [(k, payload[k]) for k in allowed if k in payload]
    if not fields:
        raise HTTPException(400, "no fields to update")
    fields.append(("updated_at", __import__("datetime").datetime.utcnow().isoformat()))
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE cases SET " + ", ".join(f"{k} = ?" for k, _ in fields) + " WHERE id = ?",
                    [v for _, v in fields] + [case_id])
        conn.commit()
        if cur.rowcount == 0: raise HTTPException(404, "Case not found")
        return {"id": case_id, "updated": True}


@app.post("/api/cases/{case_id}/alerts", dependencies=[Depends(require_api_auth)])
def add_case_alerts(case_id: int, payload: dict):
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
            raise HTTPException(404, "Case not found")
        for alert_id in payload.get("alert_ids", []):
            conn.execute("INSERT OR IGNORE INTO case_alerts(case_id, alert_id) VALUES (?, ?)", (case_id, int(alert_id)))
        conn.commit()
    return {"case_id": case_id, "added": payload.get("alert_ids", [])}


@app.delete("/api/cases/{case_id}/alerts/{alert_id}", dependencies=[Depends(require_api_auth)])
def remove_case_alert(case_id: int, alert_id: int):
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
            raise HTTPException(404, "Case not found")
        conn.execute("DELETE FROM case_alerts WHERE case_id=? AND alert_id=?", (case_id, alert_id))
        conn.commit()
    return {"removed": True}


@app.post("/api/cases/{case_id}/notes", dependencies=[Depends(require_api_auth)])
def add_case_note(case_id: int, payload: dict):
    note = str(payload.get("note", "")).strip()
    if not note:
        raise HTTPException(400, "note is required")
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
            raise HTTPException(404, "Case not found")
        conn.execute("UPDATE cases SET notes = CASE WHEN notes = '' THEN ? ELSE notes || char(10) || ? END, updated_at=CURRENT_TIMESTAMP WHERE id=?", (note, note, case_id))
        conn.commit()
    return {"case_id": case_id, "note": note}


@app.post("/api/iocs", dependencies=[Depends(require_api_auth)])
def create_ioc(payload: dict):
    value, kind = str(payload.get("value", "")).strip(), str(payload.get("type", "")).lower()
    if not value or kind not in {"ip", "domain", "hash", "url", "email"}:
        raise HTTPException(400, "value and supported type are required")
    confidence = payload.get("confidence", 0.5)
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        raise HTTPException(400, "confidence must be a number between 0 and 1")
    expires_at = payload.get("expires_at")
    if expires_at is None:
        expires_at = (datetime.now(timezone.utc) + IOC_DEFAULT_TTL).isoformat()
    ioc = {"type": kind, "confidence": confidence}
    weight = confidence_weight(ioc)
    with get_db() as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO iocs
               (value,type,source,confidence,tags,first_seen,last_seen,expires_at,verified,weight)
               VALUES(?,?,?,?,?,COALESCE(?,CURRENT_TIMESTAMP),CURRENT_TIMESTAMP,?,?,?)""",
            (value, kind, payload.get("source", "manual"), confidence, payload.get("tags", ""),
             payload.get("first_seen"), expires_at,
             int(bool(payload.get("verified", False))), weight),
        )
        conn.commit()
        return {"id": cur.lastrowid or conn.execute("SELECT id FROM iocs WHERE type=? AND value=?", (kind,value)).fetchone()[0]}


@app.get("/api/iocs", dependencies=[Depends(require_api_auth)])
def list_iocs(active: bool | None = None, min_weight: float | None = None):
    with get_db() as conn:
        clauses, params = [], []
        if active is True:
            clauses.append("(expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)")
        elif active is False:
            clauses.append("expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP")
        if min_weight is not None:
            clauses.append("weight >= ?")
            params.append(min_weight)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM iocs{where} ORDER BY id DESC", params).fetchall()]


@app.post("/api/iocs/{ioc_id}/expire", dependencies=[Depends(require_api_auth)])
def expire_ioc(ioc_id: int):
    with get_db() as conn:
        updated = conn.execute(
            "UPDATE iocs SET expires_at = CURRENT_TIMESTAMP WHERE id = ?", (ioc_id,))
        conn.commit()
        if updated.rowcount == 0:
            raise HTTPException(404, "IOC not found")
    return {"id": ioc_id, "expired": True}


@app.post("/api/iocs/match/{event_id}", dependencies=[Depends(require_api_auth)])
def match_event_iocs(event_id: int, min_weight: float = 0.0):
    with get_db() as conn:
        event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if not event: raise HTTPException(404, "Event not found")
        indicators = [dict(r) for r in conn.execute("SELECT * FROM iocs").fetchall()]
        matches = match_iocs(dict(event), indicators, min_weight=min_weight)
        for ioc in matches:
            conn.execute("INSERT OR IGNORE INTO ioc_matches(ioc_id,event_id) VALUES(?,?)",
                         (ioc["id"], event_id))
        conn.commit()
        return {"event_id": event_id, "matches": matches}


@app.post("/api/enrichment", dependencies=[Depends(require_api_auth)])
def enrich(payload: dict):
    indicator = str(payload.get("indicator", "")).strip()
    if not indicator: raise HTTPException(400, "indicator is required")
    result = ThreatIntelEnricher().lookup(indicator, payload.get("type", "ip"))
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO enrichments(indicator,provider,payload) VALUES(?,?,?)",
                     (indicator, "virustotal+otx", json.dumps(result)))
        conn.commit()
    return result
