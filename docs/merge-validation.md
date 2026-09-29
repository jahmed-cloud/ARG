# Merge and validation record

Implementation started 2026-09-25; upstream refreshed 2026-09-26.

## Provenance and merge decisions

- Remote: `https://github.com/jahmed-cloud/ARG`.
- Initial fetched revision: `4c8108f7836c63a373f9ebde3863026311331e57`.
- Latest fetched revision: `da69387` (`chore: release 0.2`), refreshed 2026-09-28.
- Local working branch: `codex/merge-optimize-ui`, now based on the latest revision.
- The supplied local directory had no `.git` history. This is a reviewed file reconciliation onto the fetched history, not a two-parent Git merge commit.
- All 112 supplied local files were preserved under `.merge/local-backup/` before replacement. That directory is ignored by Git and Docker. `.merge/upstream/` retains the fetched comparison checkout.
- Line endings were normalized for comparison. Against the earliest fetched revision, 103 of 112 supplied files matched and the remaining nine contained older behavior described below. No local-only file was found. Against current upstream, 23 local files differed in content.
- Changes remain local and reviewable; no commit, push, pull request or image publication was performed. Local Docker deployment is tracked in the follow-up record below.
- On the user's second pull request, five additional upstream commits were fast-forwarded after stashing the local improvements. Reapplication merged cleanly except for the appended stylesheet blocks; both the estate styles and responsive redesign were kept. The safety stash is retained locally. No unresolved Git conflicts remain.

| Local difference | Resolution and reason |
|---|---|
| Dashboard mapped compute/network/storage findings into governance/security scores | Kept upstream category-specific scoring so dashboard and dedicated pages agree |
| Backend router/model and Settings UI lacked governance configuration | Retained upstream route, model, migrations, UI and `PUT` helper as one coherent feature |
| Worker did not load configured tags/naming patterns | Retained upstream configuration propagation |
| Identity/governance findings lacked remediation script fields | Retained upstream scanner fields and persisted script columns |
| Older scanners lacked later pagination/enrichment fixes | Retained upstream scanner implementations, shared clients and offline tests |
| Local folder lacked CLI, local portal, extra scanners, docs and launchers | Integrated the upstream additions |
| Second fetch added Estate inventory, configuration and 31-type usage metrics | Integrated all five commits, including Marketplace SaaS scanning, duplicate-name report protection, parallel CLI analysis and author credits |
| Upstream tracked `.env` | Excluded it from the merged working tree and index; retained Git history and changed example secrets to placeholders |

The local Docker preview now has a generated, ignored `.env`; its credentials were preserved through the latest pull. For a new checkout create your own with `python -m scripts.configure_env` (or `--local` for host development). If values previously distributed in tracked/example files were used in a deployment, replace those deployment credentials through the relevant rotation process. This work does not rewrite published history.

## Completed verification

| Check | Result |
|---|---|
| Python regression suite | **205 passed**; includes all existing scanner, pagination, report, export, estate and portal tests plus six new readiness/configuration/migration/concurrency tests |
| Python dependency consistency | `pip check`: no broken requirements |
| Python compilation and backend imports | Passed; backend registers 62 routes |
| Alembic migration graph | One head: `0b009e144f7a` |
| Offline migration SQL generation | Full upgrade to head generated successfully; an inherited introspection failure in offline mode was fixed |
| Frontend production build | TypeScript and Vite passed; all 16 pages emitted as independent lazy chunks |
| Compose configuration | Base, development and production models rendered successfully |
| Compose behavioral assertions | Production DB/Redis/API ports absent; production `APP_ENV` correct; downstream startup waits for backend health; development DB/Redis bind to loopback |
| Script checks | Portal JavaScript syntax, PowerShell module parsing, and Bash launcher/entrypoint syntax passed |
| Python lint | `ruff check --select F,E9 scripts tests`: passed |
| Git diff whitespace | Passed |

The build before lazy loading emitted a 161.12 kB application entry chunk (44.03 kB gzip). The final entry chunk is 68.31 kB (24.55 kB gzip). These are entry-chunk sizes, **not total application size or measured page-load timings**: code also moves between vendor and page chunks. The approximately 410 kB chart bundle is deferred to pages that use charts.

## Browser verification

Headless Microsoft Edge exercised both UIs at 1440px desktop and 390px mobile widths. The local portal used an isolated fake Azure session and three fixture subscriptions; the React dashboard used intercepted fixture API responses. No live scan or remediation was triggered.

Verified:

- Portal login, subscription filtering and empty search state.
- Selection count across filters, mixed-state select-all, and disabled subscription behavior.
- Inline handling of a failed analysis request.
- React dashboard rendering, including its chart.
- Dashboard retains its last successful data after a periodic refresh returns HTTP 503.
- Desktop sidebar collapse followed by mobile navigation still displays labels.
- No document-level horizontal overflow at mobile width on either dashboard.
- Estate filtering, Resources/Suggestions switching, keyboard row expansion and narrow-screen layout.
- Estate load and refresh-status network failures produce visible messages instead of silent/unhandled failures.
- No uncaught browser page errors during these checks.

Local evidence is in `.validation/`: `browser-result.json`, six desktop/mobile screenshots, the fixture server and browser-check scripts, resolved Compose JSON, and generated migration SQL. These artifacts are intentionally ignored by Git/Docker and use fixture data.

## Limits and remaining deployment checks

- Docker Desktop's `desktop-linux` engine pipe was unavailable. A background Desktop startup was attempted, but no usable engine could be verified and the stalled version-check helper was stopped. Container builds, Nginx runtime, a full stack boot, live PostgreSQL migration execution, and report/Beat persistence across container recreation were **not run locally**. Compose model validation is not a substitute for them.
- The new `.github/workflows/validate.yml` will build/test the frontend and Python code, build/start a disposable Docker stack, and probe API/worker health when run on GitHub. It has not been run remotely in this task.
- Azure calls, OAuth, SMTP, tenant credentials, live costs, and real scan/remediation flows were not exercised against a tenant. Existing offline tests verify fixtures and contracts, not Azure permissions or service availability.
- Existing dependency deprecation warnings remain (Python UTC timestamps, FastAPI lifecycle hooks and the Vite CJS API). Direct dependency versions were kept stable; this is not a full security or dependency upgrade audit.
- The launcher cache optimization was syntax-reviewed; the complete bootstrap flow on a clean Linux/macOS/Windows installation was not repeated.

Before release, run the documented container startup checks, sign in, configure a test tenant, complete a read-only scan, inspect findings/governance, and generate/download reports. On upgrades, back up the database and existing report files first and verify old report downloads after restoring the volume. See [Docker deployment](docker-deployment.md).

No regression was found by the completed tests. Zero degradation across all real deployments cannot be guaranteed without the remaining integration checks.

## 2026-09-28 review and redesign

Pulled four upstream commits through v0.2 (`da69387`) using a safety stash. Resolved README, changelog and local portal navigation conflicts while retaining both upstream fixes and local improvements. Private Docker configuration was backed up locally and restored; `.env` remains excluded from Git.

The Docker UI is a separate React application from the Python local portal. Its previous generic appearance came from repeated KPI cards, gradient accents and empty charts. The new design uses a forest/stone palette, compact grouped navigation, editorial sign-in layout, a single estate summary, prioritized findings, clear assessment coverage and a first-scan setup path. No sample metrics are injected into the running database.

Review fixes: dashboard queries no longer share an AsyncSession concurrently; all summary queries honor subscription scope; cost history uses ResourceCost records rather than fabricated zeros; unassessed categories retain null assessment timestamps; history date validation returns 422; severity ordering is explicit. The upstream percentile helper now follows its documented nearest-rank definition.

Validation: 236 Python tests passed, including upstream storage/utilisation cases and new dashboard/percentile regressions. TypeScript/Vite production build and targeted Python lint passed. Existing dependency deprecation warnings remain. This review does not establish tenant-level authorization isolation: the existing application uses authenticated, role-based workspace access. Live Azure scans, OAuth, SMTP and remediation were not exercised.

## 2026-09-29 upstream merge, deployment and Azure connection

Committed the local redesign (`3341345`) and merged nine upstream commits through `9f8b159` as a real two-parent merge (`da07cbd`). Conflicts in `.dockerignore`, `.gitattributes`, `CHANGELOG.md` and `docker/Dockerfile.backend` kept both sides; `MEMORY.md` is untracked as upstream decided and kept locally. Pushed to `origin main`.

Deployed locally with `docker compose up -d --build`: backend, worker and beat images rebuilt from the merged code; the frontend was recreated after its health check was fixed (`127.0.0.1` instead of `localhost`). All services healthy; administrator sign-in through the frontend proxy returned 200.

Added `scripts.connect_azure` (one-command Azure connection) and in-place tenant credential updates. Its read-only Azure CLI calls (account, principal lookup, role listing) were exercised against a real tenant; creating the principal, role assignments and registration are covered by offline tests with a fake CLI and API, not yet run end to end.

Validation: 281 Python tests passed; `ruff check --select F,E9 scripts tests` passed; frontend production build passed.
