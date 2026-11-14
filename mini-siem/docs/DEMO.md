# Placement demonstration script

Start with a fresh data/demo.db and default thresholds. No external attack is required.

1. **Problem — 20 seconds.** Authentication logs are hard to inspect manually. This tool highlights suspicious sequences and preserves the evidence needed to review them.
2. **Normal activity — 20 seconds.** Upload normal.log. Show 12 successful events and zero alerts.
3. **Cross-file correlation — 40 seconds.** Upload cross_file_part1.log, then part2. Explain that the files overlap by one event. The database contains 21 total unique events (12 normal plus nine suspicious), not 22. There are two active alerts.
4. **Investigation — 40 seconds.** Open Success after failures. Show the timeline, host, IP, eight failures and one success. Show source-file provenance. Explain why this is suspicious but does not prove account compromise.
5. **Workflow — 20 seconds.** Add a note and resolve the alert. Show its audit entry.
6. **Rule tuning — 30 seconds.** Increase failure_threshold to 20. Explain why the repeated-failure alert disappears while the separately configured success-after-failures finding remains. Rule changes reopen matched findings for review.
7. **Engineering — 30 seconds.** Show tests for overlapping files, out-of-order uploads, rollback and status reopening. Open the synthetic evaluation report and state its limitations.

If files were uploaded previously, use a new SIEM_DB path. Re-uploading an identical file will be skipped.
Do not delete an existing database to reset a demo unless you no longer need its investigations.
