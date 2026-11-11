# ARG - Context

What a newcomer (person or AI assistant) needs before changing anything. Rules and gotchas: [MEMORY.md](MEMORY.md).
Open work: [TASK.md](TASK.md).

## What it is

Azure Resource Guardian finds waste, security gaps and governance gaps in Azure subscriptions. It is read-only:
it never changes Azure. It suggests commands; a person runs them.

## Two engines, one set of scanners

| | Online (Docker stack) | Offline (local tooling) |
|---|---|---|
| Start | `docker compose up -d --build` | `python -m scripts.subscription_analysis -s <id>` or `scripts/Start-LocalPortal.ps1` |
| Signs in as | service principal `arg-scanner` (per tenant) | your own `az login` |
| Runs scanners in | `workers/scan_worker.py` (Celery) | `scripts/subscription_analysis/collector.py` |
| Stores | PostgreSQL (`findings`, `resource_inventory`) | files under `reports/` |
| Shows | React UI on port 3000 | markdown reports, local portal on port 8765 |

Both import the same `scanners/` modules and the same merge step
(`scripts/subscription_analysis/correlate.py`), so the same subscription must give the same findings in both. Check
this after any scanner or merge change.

## Layout

- `scanners/` - one class per check (`BaseScanner`), grouped by area. `scanners/base/` holds shared Azure calls.
- `scripts/subscription_analysis/` - offline engine, report writer, merge step, guidance text.
- `workers/scan_worker.py` - online engine: runs scanners, merges, stores findings.
- `backend/` - FastAPI API. Routes in `api/routes/`, access rules in `services/access.py`, schema in
  `models/models.py`, migrations in `migrations/versions/`.
- `frontend/` - React 18, MUI, Vite. Pages in `src/pages/`.
- `docker/` - Dockerfiles, nginx config. `docker-compose.yml` builds from source; `docker-compose.hub.yml` runs the
  published images (the README repeats it - change all three together).

## How a finding flows (online)

1. A scanner returns `ScannerFinding` objects for one subscription.
2. `correlate()` merges duplicates: Defender / Advisor items a native finding covers, and every finding on a
   resource that should be removed.
3. `_persist_finding` upserts by fingerprint (`scanners/base/fingerprint.py`), so a re-scan updates the row and
   keeps its status.
4. Findings a clean run no longer reports are resolved, or suppressed with the reason.

## Checks before a commit

- `python -m pytest tests/unit -q` and `ruff check --select F,E9 backend workers scanners scripts tests`
- `cd frontend && npm run build`
- Scanner or merge change: run both engines on one subscription and compare the finding counts.
