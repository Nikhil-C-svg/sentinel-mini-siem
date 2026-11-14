# Understand and defend the project

## Read the code in this order

1. parser.py: raw text, supported patterns, timezone normalization and rejected lines.
2. config.py: typed immutable rule settings with range validation.
3. detector.py: event sorting, queue trimming, matching and incident grouping.
4. database.py: schema migration, fingerprints, atomic ingestion and alert reconciliation.
5. app.py and exports.py: investigation workflow, filtering and safe CSV text.
6. tests/: boundary cases and UI integration.
7. evaluate.py: scenario labels and timing boundaries.

## Questions you should answer

**Why build this?**
To turn raw authentication logs into explainable investigation leads and learn event processing,
database design, detection rules and a usable analyst workflow.

**What happens if one attack spans two files?**
All unique stored events are reanalyzed after an upload, so the file boundary does not break a time window.

**What if files arrive out of order?**
Events are sorted by normalized event time. Earlier evidence may update or replace an incident anchor.

**How do you stop overlapping files from causing false alerts?**
A unique fingerprint index deduplicates canonical events. import_events retains every source-file association.
Explain the same-second collision tradeoff.

**Why use deques?**
Removing the oldest event from a deque is efficient, which fits sliding time windows.
Sorting and distinct-username checks mean the entire algorithm is not simply linear.

**What happens if the detector crashes during ingestion?**
The write transaction rolls back the import and its new events. The rollback test simulates that failure.

**Why can a resolved alert reopen?**
Additional evidence or rule changes can invalidate an earlier review. The audit log records that transition.

**Why SQLite?**
Simple local setup, parameterized SQL, indexes and transactions. A server database would be preferable
for more concurrent writers and a deployed service.

**Are the results 100% accurate?**
No. The included designed scenarios match their expected rule labels. This is not a representative
real-world dataset, and the project does not claim production precision or recall.

**What creates false positives?**
Shared IPs, administrative tasks, user mistakes, incorrect timestamps, and unsuitable thresholds.
Review host, account, timing and context; tune rules using labeled operational data.

**What is missing for production?**
Authenticated users and ingestion, durable append-only audit history, retention, incremental processing,
monitoring and larger-scale validation.

## Resume wording

Implemented a Python security log analyzer with cross-file SSH event correlation,
SQLite event deduplication, configurable detection rules, and evidence-based investigation workflows.

Optional measured detail:
Validated nine synthetic detection scenarios and implemented 28 automated checks.
Use the final count in VALIDATION.md if it changes.
The included 10,000-event timing is a local benign batch result; state its scope when quoting it.

## Ownership checklist

Before an interview, implement one additional small rule yourself, explain each database table without notes,
trace an event through the pipeline, and change a threshold while predicting the outcome.
