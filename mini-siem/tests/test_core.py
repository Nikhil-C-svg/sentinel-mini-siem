import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parser import parse_logs
from detector import detect
from database import initialize, ingest, rows, set_status

def line(second, result="Failed", user="admin", ip="192.0.2.10", minute=0):
    return f"2026-11-15T10:{minute:02}:{second:02}Z lab sshd[123]: {result} password for {user} from {ip} port 2200 ssh2"

def parsed(lines):
    events, rejected = parse_logs("\n".join(lines))
    assert not rejected
    return [dict(e, id=i+1) for i, e in enumerate(events)]

def test_parser_timezone_ipv6_and_bad_lines():
    events, rejected = parse_logs("Nov 15 10:00:00 lab sshd[1]: Accepted publickey for alice from 2001:db8::1 port 22 ssh2\nbad", 2026, "+05:30")
    assert events[0]["timestamp"] == "2026-11-15T04:30:00+00:00"
    assert len(rejected) == 1

def test_bad_ip_and_naive_timestamp_rejected():
    assert len(parse_logs(line(0, ip="invalid"))[1]) == 1
    assert len(parse_logs(line(0).replace("00Z", "00"))[1]) == 1

def test_normal():
    assert detect(parsed([line(0, "Accepted"), line(1)])) == []

def test_failures_merged_and_success_linked():
    events = parsed([line(i) for i in range(8)] + [line(9, "Accepted")])
    alerts = detect(events[::-1])
    assert len(alerts) == 2
    assert len(next(a for a in alerts if a["severity"] == "High")["event_ids"]) == 9
    assert len(next(a for a in alerts if a["severity"] == "Medium")["event_ids"]) == 8

def test_window_boundary():
    assert len(detect(parsed([line(i) for i in range(4)] + [line(0, minute=5)]))) == 1
    assert not detect(parsed([line(i) for i in range(4)] + [line(4, minute=5)]))

def test_different_user_does_not_match_success():
    alerts = detect(parsed([line(i) for i in range(5)] + [line(6, "Accepted", "other")]))
    assert not any(a["severity"] == "High" for a in alerts)

def test_multiple_accounts():
    alerts = detect(parsed([line(i, user=f"user{i}") for i in range(5)]))
    assert any(a["rule"] == "Multiple accounts targeted" for a in alerts)

def test_expired_success():
    alerts = detect(parsed([line(i) for i in range(5)] + [line(5, "Accepted", minute=11)]))
    assert not any(a["severity"] == "High" for a in alerts)

def test_database_duplicate_evidence_status(tmp_path):
    db = tmp_path / "test.db"
    initialize(db)
    content = "\n".join(line(i) for i in range(6)).encode()
    assert ingest(db, content, "test.log")["alerts"] == 1
    assert ingest(db, content, "renamed.log")["duplicate"]
    assert len(rows(db, "events")) == 6
    alert = rows(db, "alerts")[0]
    set_status(db, alert["id"], "Resolved")
    assert rows(db, "alerts")[0]["status"] == "Resolved"
