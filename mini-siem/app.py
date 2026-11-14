"""Run with: python -m streamlit run app.py"""
import json
import os
from pathlib import Path
import pandas as pd
import streamlit as st
from database import initialize, ingest, rows, set_status, get_config, reanalyze
from config import RuleConfig
from exports import safe_csv

st.set_page_config(page_title="Sentinel | Mini SIEM", page_icon="🛡️", layout="wide")
DB = Path(os.environ.get("SIEM_DB", str(Path(__file__).parent / "data" / "siem.db")))
initialize(DB)
st.title("🛡️ Sentinel")
st.caption("Mini SIEM · SSH authentication log analysis")
st.info("Events correlate across uploads by destination host and source IP. Duplicate events are stored once; changed evidence reopens an alert.")

with st.sidebar:
    st.header("Ingest logs")
    uploaded = st.file_uploader("SSH authentication log", type=["log", "txt"])
    year = st.number_input("Year for traditional syslog", min_value=1970, max_value=2100, value=2026)
    offset = st.selectbox("Timezone for traditional syslog", ["+00:00", "+05:30", "-05:00", "+01:00"])
    st.caption("ISO timestamps must include their own timezone. Traditional logs must stay within one calendar year.")
    if st.button("Analyze upload", disabled=uploaded is None, type="primary"):
        if uploaded.size > 10 * 1024 * 1024:
            st.error("Use a file smaller than 10 MB.")
        else:
            try:
                result = ingest(DB, uploaded.getvalue(), uploaded.name, int(year), offset)
                st.session_state["ingestion"] = result
            except (UnicodeDecodeError, ValueError) as exc:
                st.error(f"Cannot read this log: {exc}")
    st.divider()
    st.subheader("Try a sample")
    for name in ["normal.log", "suspicious.log", "cross_file_part1.log", "cross_file_part2.log"]:
        st.download_button(name, (Path(__file__).parent / "sample_logs" / name).read_bytes(), file_name=name)
    st.caption("Data is stored locally in data/siem.db. Rule changes reanalyze all stored events.")
    current = get_config(DB)
    with st.expander("Detection settings"):
        with st.form("rules"):
            values = {}
            labels = {
                "failure_threshold": "Failed login count", "failure_minutes": "Failure window (minutes)",
                "success_threshold": "Failures before success", "success_minutes": "Success window (minutes)",
                "username_threshold": "Distinct failed usernames", "username_minutes": "Username window (minutes)"}
            for key, value in current.to_dict().items():
                values[key] = int(st.number_input(labels[key], 1, 10000, value, key=key))
            if st.form_submit_button("Apply rules and reanalyze"):
                reanalyze(DB, RuleConfig(**values))
                st.success("Rules applied to all stored events.")
    st.caption("Thresholds are lab heuristics. Review evidence before drawing conclusions.")

if "ingestion" in st.session_state:
    result = st.session_state["ingestion"]
    if result["duplicate"]:
        st.warning("This file has already been analyzed with these timestamp settings.")
    else:
        st.success(f'{result["events"]} new events · {result.get("duplicates", 0)} duplicates skipped · {result["alerts"]} total active alerts · {len(result["rejected"])} unsupported or malformed lines')
    if result["rejected"]:
        with st.expander("Skipped lines"):
            st.dataframe(pd.DataFrame(result["rejected"]), hide_index=True, use_container_width=True)

events = pd.DataFrame(rows(DB, "events"))
alerts = pd.DataFrame(rows(DB, "alerts"))
overview, event_tab, alert_tab = st.tabs(["Overview", "Events", "Alerts & investigation"])

with overview:
    cols = st.columns(4)
    counts = [len(events), 0 if events.empty else int((events.event_type == "login_failed").sum()),
              0 if events.empty else int((events.event_type == "login_success").sum()), len(alerts)]
    for col, label, value in zip(cols, ["Events", "Failed logins", "Successful logins", "Alerts"], counts):
        col.metric(label, value)
    if events.empty:
        st.info("Upload a log from the sidebar, or download and upload a sample to begin.")
    else:
        st.subheader("Authentication activity · UTC")
        chart = events.copy()
        chart["timestamp"] = pd.to_datetime(chart.timestamp, utc=True)
        activity = chart.groupby([pd.Grouper(key="timestamp", freq="1min"), "event_type"]).size().unstack(fill_value=0)
        st.line_chart(activity)
        left, right = st.columns(2)
        with left:
            st.subheader("Most active source IPs")
            st.bar_chart(events.source_ip.value_counts().head(10))
        with right:
            st.subheader("Alerts by severity")
            if not alerts.empty:
                st.bar_chart(alerts.severity.value_counts())
            else:
                st.caption("No alerts detected.")

with event_tab:
    if not events.empty:
        left, middle, right = st.columns(3)
        ips = left.multiselect("Source IP", sorted(events.source_ip.unique()))
        users = middle.multiselect("Username", sorted(events.username.unique()))
        kinds = right.multiselect("Event type", sorted(events.event_type.unique()))
        hosts = st.multiselect("Destination hostname", sorted(events.hostname.unique()))
        dates = pd.to_datetime(events.timestamp, utc=True)
        selected_dates = st.date_input("UTC date range", value=(dates.min().date(), dates.max().date()))
        filtered = events.copy()
        for column, values in [("source_ip", ips), ("username", users), ("event_type", kinds), ("hostname", hosts)]:
            if values:
                filtered = filtered[filtered[column].isin(values)]
        if isinstance(selected_dates, (tuple, list)) and len(selected_dates) == 2:
            event_dates = pd.to_datetime(filtered.timestamp, utc=True).dt.date
            filtered = filtered[(event_dates >= selected_dates[0]) & (event_dates <= selected_dates[1])]
        filtered = filtered.sort_values("timestamp")
        st.caption(f"{len(filtered)} matching events")
        st.dataframe(filtered, hide_index=True, use_container_width=True)
        st.download_button("Export filtered events", safe_csv(filtered), "events.csv", "text/csv")
    else:
        st.info("No events yet.")

with alert_tab:
    if alerts.empty:
        st.info("No alerts yet. Try suspicious.log.")
    else:
        severity = st.multiselect("Severity", ["High", "Medium"])
        status_filter = st.multiselect("Status", ["New", "Investigating", "Resolved"])
        visible = alerts.copy()
        if severity:
            visible = visible[visible.severity.isin(severity)]
        if status_filter:
            visible = visible[visible.status.isin(status_filter)]
        st.dataframe(visible.drop(columns=["event_ids", "import_id"]), hide_index=True, use_container_width=True)
        st.download_button("Export matching alerts", safe_csv(visible), "alerts.csv", "text/csv")
        if not visible.empty:
            selected = st.selectbox("Investigate alert", visible.id.tolist(),
                format_func=lambda key: f"{visible.set_index('id').loc[key, 'rule']} · {visible.set_index('id').loc[key, 'source_ip']} · {key[-6:]}")
            alert = visible[visible.id == selected].iloc[0]
            st.subheader(alert["rule"])
            st.write(alert["explanation"])
            st.caption(f'{alert["severity"]} · {alert["first_seen"]} → {alert["last_seen"]}')
            evidence = events[events.id.isin(json.loads(alert["event_ids"]))].sort_values("timestamp").copy()
            import_names = {item["id"]:item["name"] for item in rows(DB, "imports")}
            origins = {}
            for link in rows(DB, "import_events"):
                origins.setdefault(link["event_id"], set()).add(import_names[link["import_id"]])
            evidence["source_files"] = evidence.id.map(lambda key: ", ".join(sorted(origins.get(key, set()))))
            st.dataframe(evidence[["timestamp", "hostname", "username", "source_ip", "event_type", "source_files", "raw_line"]], hide_index=True, use_container_width=True)
            statuses = ["New", "Investigating", "Resolved"]
            new_status = st.selectbox("Investigation status", statuses, index=statuses.index(alert["status"]), key=f"status_{selected}")
            note = st.text_area("Investigation note", max_chars=2000, key=f"note_{selected}")
            history = [entry for entry in rows(DB, "audit") if entry["alert_id"] == selected]
            with st.expander("Investigation history"):
                st.dataframe(pd.DataFrame(history), hide_index=True, use_container_width=True)
            if st.button("Save status"):
                set_status(DB, selected, new_status, note)
                st.rerun()
