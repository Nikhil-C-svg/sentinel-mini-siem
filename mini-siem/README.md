# Sentinel — Security Log Analyzer

A Python application that correlates SSH authentication events across uploaded files,
detects suspicious login sequences, and preserves evidence and investigation history.

**Stack:** Python, Streamlit, SQLite, pandas, pytest.

## Quick start

Use Python 3.11 or newer. Open a terminal in this folder.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m streamlit run app.py --server.address 127.0.0.1
```

Open http://localhost:8501. On macOS/Linux substitute .venv/bin/python.
The requirements file specifies compatible ranges; requirements-tested.txt records the direct versions used for validation.

## Features

- UTF-8 SSH login parsing, IPv4/IPv6 support, UTC normalization and skipped-line reporting.
- Cross-file event-time correlation, including out-of-order uploads.
- Semantic event fingerprints and many-to-many file provenance.
- Three configurable rules with linked event evidence.
- Event filters, activity charts, CSV exports, investigation notes and status history.
- Evidence changes or rule changes reopen an affected alert.
- Transactional ingestion, indexed SQLite storage, and migration from the original starter schema.

## Five-minute demo

Use a fresh database for the expected counts below. To isolate a demo in PowerShell:
```powershell
$env:SIEM_DB = "data/demo.db"
python -m streamlit run app.py --server.address 127.0.0.1
```

1. Upload sample_logs/normal.log: 12 successful events and no alerts.
2. Upload cross_file_part1.log: three failures and no alerts.
3. Upload cross_file_part2.log: six new events, one duplicate skipped, and two alerts.
4. Investigate Success after failures: eight failures and one success, with both source files visible.
5. Add a note and mark the alert Resolved.
6. Apply a failed-login threshold of 20. The repeated-failure alert becomes inactive; the high-severity rule remains.
7. Restore defaults. Inspect rule-change history.
8. Re-upload the same file: no extra events.

suspicious.log is an alternative standalone demo: 14 events and four alerts with default rules.
Uploading it after the cross-file samples adds only the five account-spray events.

## Detection rules

| Rule | Default trigger | Scope |
|---|---|---|
| Repeated failed logins | 5 failures in 5 minutes | Host and source IP |
| Success after failures | Success following 5 failures in 10 minutes | Host, source IP and username |
| Multiple accounts targeted | 5 distinct failed usernames in 10 minutes | Host and source IP |

Window boundaries are inclusive. Successful authentication clears the preceding failure queue for that account's success-after-failures rule.
Overlapping matches are grouped into an incident with the union of evidence.
Rule settings are persisted in SQLite and reapplied to all stored events.

## Input format

```text
2026-11-15T10:00:00Z lab sshd[123]: Failed password for admin from 192.0.2.10 port 2200 ssh2
Nov 15 10:00:00 lab sshd[123]: Accepted publickey for alice from 2001:db8::1 port 2200 ssh2
```

Supported methods: password, publickey, keyboard-interactive/pam.
ISO timestamps must include a timezone. For traditional syslog supply the year and timezone;
one such file must stay within one calendar year.
Only login messages in this documented format are supported.
Uploads are limited to 10 MB. The original raw lines are retained.

## Verify

```powershell
python -m pytest -q
python evaluate.py --benchmark 10000
```

See reports/EVALUATION.md and reports/evaluation.json for reproducible synthetic results.
The dependency-free python verify_core.py command checks the original nine core cases.
See VALIDATION.md for the complete validation scope.

## Design and learning material

- docs/ARCHITECTURE.md — data model, event identity, alert lifecycle, and tradeoffs.
- docs/INTERVIEW_GUIDE.md — code walkthrough, questions, and honest resume wording.
- docs/DEMO.md — demonstration script and expected output.
- CHANGELOG.md — changes from the starter.

## Limits

This is a local portfolio application, without authentication or production operational controls.
Run on localhost. Hostname is the destination identity; logs with inconsistent hostnames must be normalized before use.
Timestamps with identical precision cannot establish actual causal order; fingerprint and ID break ties deterministically.

A fingerprint includes UTC time, host, account, IP, outcome, authentication method and source port.
If two real events have exactly the same fingerprint they collapse into one event. Missing source ports and coarse timestamps increase that risk.
Import provenance is retained, but original line numbers are stored only for the first occurrence.
Late events can change an incident's first timestamp, creating a new alert ID; the older row is retained as inactive.
Original v1 alerts are archived during migration and active alerts are rebuilt; review statuses start fresh.

Full reanalysis on ingestion is simple and handles late data, but cost grows with total stored history.
This is a batch analyzer, not a live SIEM. The built-in audit log is editable by anyone with database access.
CSV exports prefix formula-like text with an apostrophe.

Synthetic precision/recall scores only describe designed lab scenarios. Rules do not prove compromise,
and IP addresses do not identify a person. No claim of production accuracy or enterprise scalability is made.

## Repository preparation

Source, tests, sample data, documentation, and a GitHub Actions workflow are included.
Runtime databases and virtual environments are ignored. Review files before publishing to your own GitHub account.
