# Synthetic evaluation

Designed lab scenarios only; these scores do not estimate production accuracy or attack coverage.

Scenario checks: 9/9
Scenario-rule precision: 100.00%
Scenario-rule recall: 100.00%

| Scenario | Expected rules | Detected rules | Passed |
|---|---|---|---|
| normal | None | None | True |
| mistyped_password | None | None | True |
| brute_force | Repeated failed logins | Repeated failed logins | True |
| success_after_failures | Repeated failed logins, Success after failures | Repeated failed logins, Success after failures | True |
| account_spray | Multiple accounts targeted, Repeated failed logins | Multiple accounts targeted, Repeated failed logins | True |
| outside_window | None | None | True |
| different_hosts | None | None | True |
| different_account_success | Repeated failed logins | Repeated failed logins | True |
| cross_file_late_and_overlap | Repeated failed logins, Success after failures | Repeated failed logins, Success after failures | True |

## Dense failure burst

10,000 events in 4.1918 seconds; 1 grouped alert(s), 10,000 evidence events.
Synthetic single-host failure burst at 1000 events/second; full ingestion and correlation.

## Local benchmark

10,000 benign events in 0.695 seconds (14,387.6 events/second).
One local benign batch: parsing, inserts, deduplication, full correlation and commit; database creation excluded.

Results depend on hardware, dataset and existing database size. Reanalysis scans all stored events.
Python 3.14.6 on Windows-11-10.0.22000-SP0.
