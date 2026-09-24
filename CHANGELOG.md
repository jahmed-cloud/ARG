# Changelog

All notable changes to Azure Resource Guardian are documented here.
Format: [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **31 posture and FinOps scanners** (62 in total) across network, compute/App Service, database, storage,
  security, governance/observability and cost. See [docs/scanner-catalog.md](docs/scanner-catalog.md).
- Shared Azure API layer for scanners: paginated and tenant-scoped Resource Graph, an ARM REST client (metrics, Cost
  Management with `CostUSD`, 429 retry), a per-scan cost and metric cache, Defender plan lookup, and Retail Prices.
- `PostureScanner` base class and shared environment-naming helpers.
- **Subscription analysis CLI** (`python -m scripts.subscription_analysis`). Uses your `az login`, supports
  `--subscription` (repeatable) and `--all`, and writes `reports/<subscription>/` (README, summary.json, 01-05) plus a
  `reports/README.md` index.
- **Local portal** (`python -m scripts.local_portal`, `http://127.0.0.1:8765`). Simple local login, uses the az login
  session, runs analyses with live progress, and renders the markdown reports.
- Launchers that work from any folder: `scripts/Start-LocalPortal.ps1`, `scripts/Invoke-SubscriptionAnalysis.ps1`
  (shared `scripts/ArgLocal.psm1`), `scripts/start-local-portal.sh`. Plus `requirements-local.txt` and the make targets
  `test`, `analyze`, `analyze-all` and `portal`.
- Unit tests in `tests/unit` for the scanners, report generator and portal.
- Docs: [user guide](docs/subscription-analysis.md), [PRD](docs/PRD-subscription-analysis.md),
  [scanner catalog](docs/scanner-catalog.md), and the Copilot skill `.github/skills/arg-subscription-analysis`.

### Changed
- The worker injects an ARM client into `ScanContext`, so live scans verify metrics and configuration.
- `unused_storage_account_scanner` checks 7-day transaction metrics in live scans and only reports idle accounts,
  with actual cost as the saving.
- `missing_diagnostic_settings_scanner` checks diagnostic settings per resource in live scans and covers more
  resource types (SQL databases, web apps, AI Services, IoT Hub, Cosmos DB). The CLI example now uses the `allLogs`
  category group.
- `ORPHAN_FINDING_TYPES` includes the new orphan and idle finding types.

### Fixed
- Older scanners' Resource Graph queries now follow skip tokens. Before, results stopped at 1,000 rows, or at
  100 for the snapshot, deallocated-VM and VMSS scanners, so large subscriptions were silently under-reported.

### Changed (inventory)
- The subscription-analysis inventory is built from paginated Resource Graph, with creation dates merged from ARM
  per resource group, rather than from one subscription-wide ARM list.

### Security
- The local portal binds to loopback only, checks Host and Origin, uses HttpOnly/SameSite=Strict sessions and a strict
  CSP, and neutralises HTML in rendered reports.
