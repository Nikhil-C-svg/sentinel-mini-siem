"""Reproducible synthetic scenario evaluation and local ingestion benchmark."""
import argparse
import json
import platform
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from time import perf_counter
from database import initialize, ingest, rows

BASE = datetime(2026,11,15,10,tzinfo=timezone.utc)
BRUTE = "Repeated failed logins"
SUCCESS = "Success after failures"
SPRAY = "Multiple accounts targeted"

def event(second, result="Failed", user="admin", ip="192.0.2.10", host="lab"):
    stamp=(BASE+timedelta(seconds=second)).isoformat()
    return f"{stamp} {host} sshd[123]: {result} password for {user} from {ip} port 2200 ssh2"

def scenarios():
    burst=[event(i) for i in range(8)]
    return [
        ("normal", [[event(i,"Accepted") for i in range(12)]], []),
        ("mistyped_password", [[event(0),event(1),event(2,"Accepted")]], []),
        ("brute_force", [burst], [BRUTE]),
        ("success_after_failures", [burst+[event(9,"Accepted")]], [BRUTE,SUCCESS]),
        ("account_spray", [[event(i,user=f"user{i}") for i in range(5)]], [BRUTE,SPRAY]),
        ("outside_window", [[event(i*400) for i in range(8)]], []),
        ("different_hosts", [[event(i,host="serverA" if i<3 else "serverB") for i in range(6)]], []),
        ("different_account_success", [burst+[event(9,"Accepted","other")]], [BRUTE]),
        ("cross_file_late_and_overlap", [burst[4:]+[event(9,"Accepted")],burst[:6]], [BRUTE,SUCCESS]),
    ]

def evaluate(benchmark_size=10000):
    results=[]
    tp=fp=fn=0
    for name,batches,expected in scenarios():
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/"lab.db"
            initialize(db)
            for index,batch in enumerate(batches):
                ingest(db,("\n".join(batch)+"\n").encode(),f"{index}.log")
            actual={a["rule"] for a in rows(db,"alerts")}
            truth=set(expected)
            tp+=len(actual & truth)
            fp+=len(actual-truth)
            fn+=len(truth-actual)
            results.append({"scenario":name,"expected_rules":sorted(truth),
                "detected_rules":sorted(actual),"passed":actual==truth})
    with tempfile.TemporaryDirectory() as folder:
        db=Path(folder)/"benchmark.db"
        initialize(db)
        # Distinct source IPs spread benign activity; every timestamp is unique.
        content=("\n".join(event(i,"Accepted",user=f"user{i%20}",
            ip=f"192.0.2.{i%100+1}") for i in range(benchmark_size))+"\n").encode()
        started=perf_counter()
        ingestion=ingest(db,content,"benchmark.log")
        seconds=perf_counter()-started
        stored=len(rows(db,"events"))
    with tempfile.TemporaryDirectory() as folder:
        db=Path(folder)/"dense.db"
        initialize(db)
        dense=("\n".join(event(i/1000) for i in range(benchmark_size))+"\n").encode()
        started=perf_counter()
        dense_result=ingest(db,dense,"dense.log")
        dense_seconds=perf_counter()-started
        dense_evidence=len(json.loads(rows(db,"alerts")[0]["event_ids"])) if rows(db,"alerts") else 0
    return {"dense_benchmark":{"events":benchmark_size,"seconds":round(dense_seconds,4),
        "events_per_second":round(benchmark_size/dense_seconds,1),"active_alerts":dense_result["alerts"],
        "largest_incident_evidence":dense_evidence,
        "scope":"Synthetic single-host failure burst at 1000 events/second; full ingestion and correlation."},
        "dataset":"9 deterministic synthetic scenarios; scenario-rule pairs are evaluation units",
        "limitations":"Designed lab scenarios only; these scores do not estimate production accuracy or attack coverage.",
        "environment":{"python":platform.python_version(),"platform":platform.platform()},
        "true_positives":tp,"false_positives":fp,"false_negatives":fn,
        "precision":tp/(tp+fp) if tp+fp else None,"recall":tp/(tp+fn) if tp+fn else None,
        "scenarios_passed":sum(r["passed"] for r in results),"scenarios":results,
        "benchmark":{"events":stored,"input_bytes":len(content),"seconds":round(seconds,4),
            "events_per_second":round(stored/seconds,1),"active_alerts":ingestion["alerts"],
            "scope":"One local benign batch: parsing, inserts, deduplication, full correlation and commit; database creation excluded."}}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--benchmark",type=int,default=10000)
    args=parser.parse_args()
    if not 1<=args.benchmark<=50000:
        parser.error("--benchmark must be between 1 and 50000")
    result=evaluate(args.benchmark)
    folder=Path(__file__).parent/"reports"
    folder.mkdir(exist_ok=True)
    (folder/"evaluation.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    lines=["# Synthetic evaluation","",
        result["limitations"],"",
        f"Scenario checks: {result['scenarios_passed']}/9",
        f"Scenario-rule precision: {result['precision']:.2%}",
        f"Scenario-rule recall: {result['recall']:.2%}","",
        "| Scenario | Expected rules | Detected rules | Passed |",
        "|---|---|---|---|"]
    for item in result["scenarios"]:
        lines.append(f"| {item['scenario']} | {', '.join(item['expected_rules']) or 'None'} | {', '.join(item['detected_rules']) or 'None'} | {item['passed']} |")
    dense=result["dense_benchmark"]
    lines.extend(["","## Dense failure burst","", f"{dense['events']:,} events in {dense['seconds']} seconds; {dense['active_alerts']} grouped alert(s), {dense['largest_incident_evidence']:,} evidence events.",dense["scope"]])
    bench=result["benchmark"]
    lines.extend(["","## Local benchmark","",
        f"{bench['events']:,} benign events in {bench['seconds']} seconds ({bench['events_per_second']:,.1f} events/second).",
        bench["scope"],"",
        "Results depend on hardware, dataset and existing database size. Reanalysis scans all stored events.",
        f"Python {result['environment']['python']} on {result['environment']['platform']}."])
    (folder/"EVALUATION.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps({key:value for key,value in result.items() if key!="scenarios"},indent=2))
    if result["scenarios_passed"] != 9:
        raise SystemExit(1)

if __name__=="__main__":
    main()
