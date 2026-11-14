"""Atomic ingestion, event deduplication, correlation, and investigation history."""
import hashlib
import json
import sqlite3
import re
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
from parser import parse_logs
from detector import detect
from config import RuleConfig

def utc_now():
    return datetime.now(timezone.utc).isoformat()

@contextmanager
def connect(db):
    connection = sqlite3.connect(db, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

def fingerprint(event):
    # Ignore filename, line number, PID, and presentation whitespace.
    keys = ("timestamp", "hostname", "username", "source_ip", "event_type")
    # Keep authentication method and port to distinguish otherwise equal events.
    return hashlib.sha256(json.dumps([event[k] for k in keys] +
        [re.search(r"(?:Failed|Accepted) (\S+) for ", event["raw_line"]).group(1),
         (re.search(r" from \S+ port (\d+)", event["raw_line"]) or [None, ""])[1]],
        separators=(",", ":")).encode()).hexdigest()

def initialize(db):
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    with connect(db) as con:
        for statement in [
            "CREATE TABLE IF NOT EXISTS imports (id TEXT PRIMARY KEY, name TEXT NOT NULL, rejected TEXT NOT NULL)",
            """CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY,
                import_id TEXT NOT NULL REFERENCES imports(id), timestamp TEXT, hostname TEXT,
                username TEXT, source_ip TEXT, event_type TEXT, raw_line TEXT, line_number INTEGER)""",
            """CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, import_id TEXT NOT NULL REFERENCES imports(id),
                rule TEXT, severity TEXT, source_ip TEXT, first_seen TEXT, last_seen TEXT,
                explanation TEXT, event_ids TEXT, status TEXT)""",
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            """CREATE TABLE IF NOT EXISTS import_events (import_id TEXT REFERENCES imports(id),
                event_id INTEGER REFERENCES events(id), PRIMARY KEY(import_id,event_id))""",
            """CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, timestamp TEXT,
                alert_id TEXT, action TEXT, detail TEXT)"""]:
            con.execute(statement)
        for table, column, declaration in [
            ("events", "fingerprint", "TEXT"), ("alerts", "hostname", "TEXT"),
            ("alerts", "active", "INTEGER NOT NULL DEFAULT 1"),
            ("alerts", "config_json", "TEXT")]:
            if column not in {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
        if not con.execute("SELECT 1 FROM settings WHERE key='schema_v2'").fetchone():
            seen = {}
            for row in con.execute("SELECT * FROM events ORDER BY id").fetchall():
                event = dict(row)
                fp = fingerprint(event)
                target = seen.get(fp, event["id"])
                con.execute("INSERT OR IGNORE INTO import_events VALUES (?,?)", (event["import_id"], target))
                if fp in seen:
                    con.execute("DELETE FROM events WHERE id=?", (event["id"],))
                else:
                    seen[fp] = target
                    con.execute("UPDATE events SET fingerprint=? WHERE id=?", (fp, target))
            con.execute("UPDATE alerts SET active=0")
            con.execute("INSERT INTO settings VALUES ('schema_v2','1')")
            _analyze(con, RuleConfig())
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS event_identity ON events(fingerprint)")
        con.execute("CREATE INDEX IF NOT EXISTS event_time ON events(timestamp)")
        con.execute("CREATE INDEX IF NOT EXISTS event_source ON events(hostname,source_ip,timestamp)")

def get_config(db):
    with connect(db) as con:
        row = con.execute("SELECT value FROM settings WHERE key='rules'").fetchone()
    return RuleConfig(**json.loads(row["value"])) if row else RuleConfig()

def _analyze(con, config):
    events = [dict(r) for r in con.execute("SELECT * FROM events")]
    alerts = detect(events, config)
    existing = {row["id"]:dict(row) for row in con.execute("SELECT * FROM alerts")}
    con.execute("UPDATE alerts SET active=0")
    snapshot = json.dumps(config.to_dict(), sort_keys=True)
    for alert in alerts:
        old = existing.get(alert["id"])
        evidence = json.dumps(alert["event_ids"])
        changed = old and (not old["active"] or old["event_ids"] != evidence or old["config_json"] != snapshot)
        status = "New" if not old or changed else old["status"]
        origin = con.execute("SELECT import_id FROM events WHERE id=?", (alert["event_ids"][0],)).fetchone()[0]
        con.execute("""INSERT INTO alerts
            (id,import_id,rule,severity,source_ip,first_seen,last_seen,explanation,event_ids,status,hostname,active,config_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?)
            ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,
                explanation=excluded.explanation,event_ids=excluded.event_ids,status=excluded.status,
                hostname=excluded.hostname,active=1,config_json=excluded.config_json""",
            (alert["id"], origin, alert["rule"], alert["severity"], alert["source_ip"],
             alert["first_seen"], alert["last_seen"], alert["explanation"], evidence, status,
             alert["hostname"], snapshot))
        if not old or changed:
            con.execute("INSERT INTO audit(timestamp,alert_id,action,detail) VALUES (?,?,?,?)",
                (utc_now(), alert["id"], "Created" if not old else "Evidence or rules changed",
                 json.dumps({"status":status,"event_ids":alert["event_ids"],"rules":config.to_dict()})))
    con.execute("INSERT OR REPLACE INTO settings VALUES ('rules',?)", (snapshot,))
    return len(alerts)

def reanalyze(db, config):
    with connect(db) as con:
        count = _analyze(con, config)
        con.execute("INSERT INTO audit(timestamp,alert_id,action,detail) VALUES (?,NULL,?,?)",
                    (utc_now(), "Rules applied", json.dumps(config.to_dict())))
    return count

def ingest(db, content, name, year=2026, offset="+00:00"):
    if len(content) > 10 * 1024 * 1024:
        raise ValueError("Maximum upload size is 10 MB")
    events, rejected = parse_logs(content.decode("utf-8-sig"), year, offset)
    identity = hashlib.sha256(content + f"|{year}|{offset}".encode()).hexdigest()
    inserted = 0
    with connect(db) as con:
        if con.execute("SELECT 1 FROM imports WHERE id=?", (identity,)).fetchone():
            return dict(duplicate=True, events=0, duplicates=len(events), alerts=0, rejected=rejected)
        con.execute("INSERT INTO imports VALUES (?,?,?)", (identity, name, json.dumps(rejected)))
        for event in events:
            fp = fingerprint(event)
            cursor = con.execute("""INSERT OR IGNORE INTO events
                (import_id,timestamp,hostname,username,source_ip,event_type,raw_line,line_number,fingerprint)
                VALUES (?,?,?,?,?,?,?,?,?)""", (identity, *[event[k] for k in
                ("timestamp","hostname","username","source_ip","event_type","raw_line","line_number")], fp))
            inserted += cursor.rowcount
            event_id = con.execute("SELECT id FROM events WHERE fingerprint=?", (fp,)).fetchone()[0]
            con.execute("INSERT OR IGNORE INTO import_events VALUES (?,?)", (identity,event_id))
        saved = con.execute("SELECT value FROM settings WHERE key='rules'").fetchone()
        config = RuleConfig(**json.loads(saved[0])) if saved else RuleConfig()
        count = _analyze(con, config)
    return dict(duplicate=False, events=inserted, duplicates=len(events)-inserted, alerts=count, rejected=rejected)

def rows(db, table):
    if table not in {"events", "alerts", "imports", "audit", "import_events"}:
        raise ValueError("Unknown table")
    with connect(db) as con:
        clause = " WHERE active=1" if table == "alerts" else ""
        return [dict(row) for row in con.execute(f"SELECT * FROM {table}{clause}")]

def set_status(db, alert_id, status, note=""):
    if status not in {"New", "Investigating", "Resolved"}:
        raise ValueError("Invalid status")
    if len(note) > 2000:
        raise ValueError("Notes must be at most 2000 characters")
    with connect(db) as con:
        old = con.execute("SELECT status FROM alerts WHERE id=? AND active=1", (alert_id,)).fetchone()
        if not old:
            raise ValueError("Alert no longer active; refresh the dashboard")
        con.execute("UPDATE alerts SET status=? WHERE id=?", (status,alert_id))
        con.execute("INSERT INTO audit(timestamp,alert_id,action,detail) VALUES (?,?,?,?)",
            (utc_now(),alert_id,"Status updated",json.dumps({"from":old[0],"to":status,"note":note})))
