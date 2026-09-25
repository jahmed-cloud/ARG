# Changelog

All notable changes to Azure Resource Guardian are documented here.
Format: [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Estate inventory** across all subscriptions: portal **Estate** page (`/estate`) and `reports/_estate/`
  (markdown overview + `estate.json`). One Resource Graph query (~30 s for 12,000 resources) gives every resource's
  category, readable type, size / SKU (VM size, VMSS, disk SKU + GB, storage SKU/kind/tier, App Service plan, SQL,
  Redis, AKS pools, Arc SQL version/edition/vCores), OS and Hybrid Benefit, state, environment, region, tags and
  30-day cost, joined with every report finding. Filters (category, type, size, subscription, region, environment,
  state, suggestions, suggestion type, severity, search), clickable breakdowns, Resources and Suggestions views,
  sortable/paged table with detail rows, CSV export and shareable filtered links. Tag/naming findings are counted
  as hygiene, separately from actionable suggestions. CLI `--estate`; the estate is re-joined after every analysis.
- CLI `--parallel N` to analyse several subscriptions at once (launcher `-Parallel`, `-Estate`); `--all` honours `--tenant`.
- Per-subscription resource inventory shows size / SKU and state; the VM table adds size, OS image, power state and cost.
- Estate **Configuration** column and filled Size / SKU for types without a SKU: VMs (zones, data disks, NICs, Spot,
  availability set), AVD host pools / app groups / workspaces / scaling plans, VM and Arc extensions, gallery images,
  restore points, web apps (plan, HTTPS, runtime), container apps and instances (vCPU / memory, scale, image), NICs,
  public IPs, VNets, NSGs, route tables, private endpoints, DNS zones, load balancers, Key Vaults, alerts, action groups,
  availability tests, App Insights, Log Analytics, Arc machines and SQL databases, Cosmos DB and more. State now shows
  Attached / Unattached, Associated / Unassociated, expired certificates, disabled alerts and pending private endpoints.
- Estate **vCPU, RAM, 30-day average CPU % and memory used %** for VMs and scale sets (Compute SKU catalogue + Azure
  Monitor), a CPU-band breakdown and filter, and right-sizing candidates in the markdown overview. Child resources are
  named like the Azure portal (`vm › extension`); VM / Arc extensions and license profiles are hidden by default.
- Estate **usage metrics for 31 resource types** (last 30 days, Azure Monitor metrics batch API): storage
  transactions / used capacity / egress, web and function app requests / 5xx / executions, SQL CPU / connections /
  storage, PostgreSQL / MySQL / Redis / AKS / Data Explorer CPU and memory, App Service plan CPU and memory, Cosmos DB
  requests and RU peak, Key Vault API calls, AI calls and tokens, messaging, runs, gateway requests, registry pulls
  and more. New **Usage (30 d)** column, CPU / memory columns for every type that reports them, an **Activity**
  breakdown and filter with an **idle** flag, and a usage section in the markdown overview (per-type table and the
  costliest idle resources).
- `MEMORY.md`: project memory (repository, git rules, running, decisions, pitfalls).
- Author credit "Author: Junaid Ahmed · jahmed.cloud · github.com/jahmed-cloud/ARG" in the local portal footer,
  report / index / estate footers and the PDF cover.
- **Marketplace SaaS scanner** (`marketplace_saas_scanner`, 63 scanners in total): unsubscribed SaaS left behind,
  suspended or never-activated plans, terms ending within 90 days (auto-renew on or off) and material SaaS
  commitments, using the SaaS status/term from Resource Graph and 12-month cost per SaaS resource.
- **31 posture and FinOps scanners** (62 in the 0.1 baseline) across network, compute/App Service, database, storage,
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
- Subscriptions sharing a display name (e.g. several "Visual Studio Professional Subscription"s) overwrote one report
  folder; each now gets its own (`<name>_<first 8 of ID>/`, owner recorded in `.subscription-id`), and the index and
  portal show the short ID next to duplicate names.
- Executive summary trend no longer compares the first and last month with cost and labels it "possibly partial": it
  uses the last full month, the peak, credits/refunds, and flags lumpy (up-front) spend. The forecast then uses the
  12-month average instead of 30 days × 12; the monthly chart's axis now includes negative months.
- Defender recommendation titles named a GUID or the subscription ID; they now name the recommendation.
- `budget_missing` is High when the peak monthly spend is ≥ 10,000 USD (was always Medium).
- Environment detection recognises `non prod` / `nonprod` / `public non-prod`, `core prod` / `public prod` /
  `Non public-prod`, `prep`, `systest` and numbered stages (`stage1`); these were treated as unknown before, which
  also affects the environment-mismatch and mixed App Service plan checks.

### Changed (inventory)
- The subscription-analysis inventory is built from paginated Resource Graph, with creation dates merged from ARM
  per resource group, rather than from one subscription-wide ARM list.

### Security
- The local portal binds to loopback only, checks Host and Origin, uses HttpOnly/SameSite=Strict sessions and a strict
  CSP, and neutralises HTML in rendered reports.
