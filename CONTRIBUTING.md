# Contributing to Azure Resource Guardian

Thanks for considering a contribution — bug reports, scanner additions, and pull requests all genuinely help.

## Before you start

- Check [ROADMAP.md](ROADMAP.md) to see if what you're planning is already a known gap (and whether there's context on why it hasn't been done yet).
- For anything non-trivial, open an issue first to discuss the approach before writing a lot of code — saves everyone time if the direction needs adjusting.

## Development setup

```bash
git clone https://github.com/jahmed-cloud/ARG.git
cd ARG
cp .env.example .env
# edit .env — at minimum set POSTGRES_PASSWORD, SECRET_KEY, ENCRYPTION_KEY, ADMIN_PASSWORD
docker compose up -d --build
docker compose exec backend python -m scripts.seed_admin
```

Frontend hot-reload during UI work:
```bash
cd frontend
npm install
npm run dev
```

## Making changes

- **Test against a real `docker compose up --build`**, not just `python -m py_compile` or a TypeScript build. Import-level checks miss real runtime bugs (wrong env var names, missing Docker `COPY` lines, SQLAlchemy `passive_deletes` gaps, Graph SDK version mismatches — all real bugs found this way during development, not by static checks).
- **Adding a scanner?** Follow the existing pattern in `scanners/`:
  - Subclass `BaseScanner`, set `scanner_name`, `category`, `severity`
  - Register with `@register_scanner`
  - Implement `scan()` to return a `ScanOutput`
  - Provide a `_mock_*()` fallback so the scanner is testable without live Azure credentials (`context.resource_graph_client is None` / `context.graph_client is None` checks)
  - If it calls Microsoft Graph, double-check the query against [Graph's actual filter support](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity) — several existing scanners had to be fixed for filter combinations Graph silently rejects.
- **Touching the database schema?** Generate a real Alembic migration (`alembic revision --autogenerate -m "description"`) and actually run `alembic upgrade head` against a real Postgres instance to confirm it applies cleanly — don't hand-write migration files.
- **Frontend changes** should run through `npm run build` (the real TypeScript compiler + Vite build), not just look right in dev mode.

## Pull requests

- One feature or fix per PR — easier to review, easier to revert if something's wrong.
- Describe what changed and why, not just what.
- If you fixed a bug, a short note on how you confirmed the fix (not just "should work") is genuinely useful — this codebase has a history of bugs that looked fixed but weren't (e.g. an `asyncio.run()`-per-scanner pattern that caused cross-scanner failures, only caught by tracing real worker logs, not by code review alone).

## Code of conduct

Be respectful, assume good faith, keep discussion focused on the code. Nothing more elaborate than that for a project this size.

## Questions

Open a GitHub issue, or reach out directly — see [README.md](README.md#-about--author) for contact details.
