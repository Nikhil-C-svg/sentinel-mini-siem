import json
import sqlite3
from unittest.mock import patch
import pytest
from test_core import line, parsed
from config import RuleConfig
from detector import detect
from database import initialize, ingest, rows, set_status, reanalyze, get_config
from exports import safe_csv
import pandas as pd

def upload(db, lines, name="test.log"):
    return ingest(db, "\n".join(lines).encode(), name)

def test_split_files_overlap_and_late_arrival(tmp_path):
    db = tmp_path/"lab.db"
    initialize(db)
    failures = [line(i) for i in range(8)]
    upload(db, failures[4:] + [line(9,"Accepted")], "later.log")
    assert not rows(db,"alerts")
    result = upload(db, failures[:6], "earlier.log")
    assert result["duplicates"] == 2
    assert len(rows(db,"events")) == 9
    alerts = rows(db,"alerts")
    assert len(alerts) == 2
    assert len(json.loads(next(a for a in alerts if a["severity"]=="High")["event_ids"])) == 9
    assert len(rows(db,"import_events")) == 11

def test_duplicate_format_and_pid(tmp_path):
    db=tmp_path/"lab.db"
    initialize(db)
    upload(db,[line(0)])
    result=upload(db,[line(0).replace("sshd[123]","sshd[999]")])
    assert result["events"] == 0
    assert result["duplicates"] == 1

def test_host_isolation():
    events=parsed([line(i).replace(" lab ", " serverA " if i<3 else " serverB ") for i in range(6)])
    assert not detect(events)

def test_status_preserved_then_reopened(tmp_path):
    db=tmp_path/"lab.db"
    initialize(db)
    upload(db,[line(i) for i in range(5)])
    alert=rows(db,"alerts")[0]
    set_status(db,alert["id"],"Resolved","Expected lab traffic")
    upload(db,[line(40,"Accepted",ip="192.0.2.20")])
    assert rows(db,"alerts")[0]["status"] == "Resolved"
    upload(db,[line(6)])
    updated=rows(db,"alerts")[0]
    assert updated["id"] == alert["id"]
    assert updated["status"] == "New"
    assert len(json.loads(updated["event_ids"])) == 6
    assert any(r["action"]=="Evidence or rules changed" for r in rows(db,"audit"))

def test_rule_change_and_retired_alert_history(tmp_path):
    db=tmp_path/"lab.db"
    initialize(db)
    upload(db,[line(i) for i in range(5)])
    set_status(db, rows(db,"alerts")[0]["id"], "Resolved")
    assert reanalyze(db,RuleConfig(failure_threshold=6)) == 0
    assert get_config(db).failure_threshold == 6
    assert rows(db,"audit")
    assert reanalyze(db,RuleConfig()) == 1
    assert rows(db,"alerts")[0]["status"] == "New"

@pytest.mark.parametrize("value",[0,-1,True,1.5,10001])
def test_invalid_config(value):
    with pytest.raises(ValueError):
        RuleConfig(failure_threshold=value)

def test_config_changes_detection():
    events=parsed([line(i) for i in range(3)])
    assert not detect(events)
    assert len(detect(events,RuleConfig(failure_threshold=3)))==1

def test_successes_are_not_username_attack():
    assert not detect(parsed([line(i,"Accepted",user=f"user{i}") for i in range(6)]))

def test_transaction_rollback(tmp_path):
    db=tmp_path/"lab.db"
    initialize(db)
    with patch("database.detect",side_effect=RuntimeError("simulated detector failure")):
        with pytest.raises(RuntimeError):
            upload(db,[line(0)])
    assert rows(db,"events")==[]
    assert rows(db,"imports")==[]

def test_csv_formula_escape():
    csv=safe_csv(pd.DataFrame({"username":["=SUM(1,2)","  @test","alice"],"count":[1,2,3]}))
    assert "'=SUM" in csv and "'  @test" in csv
    assert "alice" in csv

def test_v1_migration_preserves_events(tmp_path):
    db=tmp_path/"v1.db"
    con=sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE imports (id TEXT PRIMARY KEY,name TEXT NOT NULL,rejected TEXT NOT NULL);
        CREATE TABLE events (id INTEGER PRIMARY KEY, import_id TEXT, timestamp TEXT, hostname TEXT,
            username TEXT,source_ip TEXT,event_type TEXT,raw_line TEXT,line_number INTEGER);
        CREATE TABLE alerts (id TEXT PRIMARY KEY,import_id TEXT,rule TEXT,severity TEXT,source_ip TEXT,
            first_seen TEXT,last_seen TEXT,explanation TEXT,event_ids TEXT,status TEXT);
        INSERT INTO imports VALUES ('old','old.log','[]');
    """)
    for event in parsed([line(i) for i in range(5)]):
        con.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)",(event["id"],"old",
            *[event[k] for k in ("timestamp","hostname","username","source_ip","event_type","raw_line","line_number")]))
    con.commit()
    con.close()
    initialize(db)
    initialize(db)
    assert len(rows(db,"events"))==5
    assert len(rows(db,"alerts"))==1

def test_success_on_other_host_does_not_correlate():
    lines=[line(i) for i in range(5)]+[line(8,"Accepted").replace(" lab "," another-host ")]
    assert not any(a["severity"]=="High" for a in detect(parsed(lines)))

def test_upload_order_does_not_change_findings(tmp_path):
    batches=[[line(i) for i in range(3)],[line(i) for i in range(2,8)]+[line(9,"Accepted")]]
    findings=[]
    for index, order in enumerate([batches,batches[::-1]]):
        db=tmp_path/f"order{index}.db"
        initialize(db)
        for batch in order:
            upload(db,batch)
        findings.append(sorted((a["id"],a["rule"],a["first_seen"],a["last_seen"],
            len(json.loads(a["event_ids"]))) for a in rows(db,"alerts")))
    assert findings[0]==findings[1]
