# ARG - Tasks

Open work, most valuable first. Move an item to CHANGELOG.md when it ships. Context: [CONTEXT.md](CONTEXT.md).

## Open

1. **Identity scans never run.** Online: the tenant is not marked as having Microsoft Graph permission
   (`connect_azure.py` registers it with `graph_permissions_granted: False`). Offline: no Graph client is built.
   Needs: Graph application permissions with admin consent for `arg-scanner` (opt-in flag), and a Graph client from
   `az login` for the offline engine.
2. **Skipped scanners show as "completed".** Add a `skipped` scan status (PostgreSQL enum migration) and show it on
   the Scans page.
3. **Fix steps still repeat per finding** for most types (95-100 % identical text). The Findings page now shows the
   fix once per issue; the stored text and the offline report still carry it on every finding.
4. **Scores hit 0 quickly.** Governance / security scores subtract per finding, so a large estate sits at 0 and
   fixing things does not move it. Score per issue, not per row; one formula for the four places that compute it
   (`governance.py`, `security.py`, `dashboard.py`, `scan_worker.snapshot_scores`).
5. **Scan start accepts anything.** Unknown scanner names run nothing and still "complete"; `resource_groups` is
   accepted and ignored; a second scan of the same subscription can start while one runs.
6. **Suppress without a reason.** Status changes are not audited and need no reason.
7. **Graph paging.** Identity scanners read the first 999 users / apps only.
8. **Mermaid from a CDN.** The Analysis page loads a script from jsdelivr; bundle it and tighten the CSP.
9. **`test_daily_automatic_scan_runs_at_nine_ist`** reads the developer's `.env`; it fails when `FULL_SCAN_SCHEDULE`
   is set locally.

## Done recently

See CHANGELOG.md, "One finding per issue" (2026-11-11).
