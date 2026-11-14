"""Event-time correlation scoped to destination hostname and source IP."""
from collections import defaultdict, deque
from datetime import datetime, timedelta
import hashlib
import json
from config import RuleConfig

def detect(events, config=None):
    config = config or RuleConfig()
    failures, accounts, user_failures = defaultdict(deque), defaultdict(deque), defaultdict(deque)
    active, alerts = {}, []
    def trim(queue, now, minutes):
        while queue and now - datetime.fromisoformat(queue[0]["timestamp"]) > timedelta(minutes=minutes):
            queue.popleft()

    def emit(rule, severity, group, evidence, explanation):
        first, last = evidence[0]["timestamp"], evidence[-1]["timestamp"]
        key = (rule, group)
        previous = active.get(key)
        if previous and first <= previous["last_seen"]:
            previous["event_ids"].add(evidence[-1]["id"])
            previous["last_seen"] = last
            return
        # First evidence time anchors identity so extending a burst keeps its ID.
        identity = json.dumps([rule, group, first], separators=(",", ":"))
        alert = dict(id=hashlib.sha256(identity.encode()).hexdigest()[:24],
            rule=rule, severity=severity, hostname=evidence[-1]["hostname"],
            source_ip=evidence[-1]["source_ip"], first_seen=first, last_seen=last,
            explanation=explanation, event_ids={e["id"] for e in evidence}, status="New")
        active[key] = alert
        alerts.append(alert)

    ordered = sorted(events, key=lambda e: (e["timestamp"], e.get("fingerprint", ""), e["id"]))
    for event in ordered:
        now = datetime.fromisoformat(event["timestamp"])
        host, ip, user = event["hostname"], event["source_ip"], event["username"]
        source, account = (host, ip), (host, ip, user)
        trim(failures[source], now, config.failure_minutes)
        trim(accounts[source], now, config.username_minutes)
        trim(user_failures[account], now, config.success_minutes)
        if event["event_type"] == "login_failed":
            failures[source].append(event)
            accounts[source].append(event)
            user_failures[account].append(event)
            if len(failures[source]) >= config.failure_threshold:
                emit("Repeated failed logins", "Medium", source, failures[source],
                     f"At least {config.failure_threshold} failures on {host} from this IP within {config.failure_minutes} minutes.")
            if len({e["username"] for e in accounts[source]}) >= config.username_threshold:
                emit("Multiple accounts targeted", "Medium", source, accounts[source],
                     f"At least {config.username_threshold} distinct usernames failed authentication on {host} within {config.username_minutes} minutes.")
        elif event["event_type"] == "login_success":
            matched = user_failures[account]
            if len(matched) >= config.success_threshold:
                emit("Success after failures", "High", account, list(matched) + [event],
                     f"Success for {user} on {host} after at least {config.success_threshold} failures from the same IP within {config.success_minutes} minutes. Review evidence; compromise is not confirmed.")
            matched.clear()
    for alert in alerts:
        alert["event_ids"] = sorted(alert["event_ids"])
    return alerts
