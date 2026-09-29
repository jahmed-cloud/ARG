# Changelog

All notable changes to Azure Resource Guardian are documented here.
Format: [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- **Savings at your own price.** Savings that were list-price estimates are now valued at the resource's own
  30-day amortized cost, so negotiated discounts, reservations and savings plans count. Removals (idle IoT Hub,
  unattached disk, old snapshot, unused or orphaned public IP, public IP next to Bastion, empty load balancer and
  Application Gateway, unused Private Link DNS zone) save what the resource actually costs; price changes (App
  Service plan generation) are scaled to it, never above the list-price difference. Without cost data the list
  estimate stays, labelled as such (`saving_basis`, `list_price_saving_usd`, `amortized_cost_usd_30d` in the
  evidence). See the guide, section 5a-2.
- **Cost basis is amortized cost.** Actual cost put reservation and savings-plan purchases on the subscription that
  bought them, so a VM covered by a savings plan bought elsewhere showed ~2 CHF a month instead of ~147 CHF, and
  the buying subscription looked expensive. Per-resource cost, subscription totals, trends, savings and the estate
  now use AmortizedCost (Cost Management spreads the commitment over the resources that use it); the report states
  the basis and shows the invoiced (actual) cost next to it. Budgets are still compared with actual cost (that is
  what Azure evaluates), and Marketplace SaaS stays on actual cost (purchases are not amortized). VM right-sizing
  detects commitment coverage from invoiced vs amortized cost. The Docker cost dashboard uses the same basis.
- The Copilot skill (`.github/skills/arg-subscription-analysis`) stays in the repository and is up to date: PDF
  export, `-Parallel` / `-Estate` runs, the idle and utilisation logic, amortized cost, budgets on their own scope,
  resource providers and validated VM right-sizing.

### Added
- **Podman on Windows.** `scripts/Start-PodmanStack.ps1` builds and starts the Docker stack with Podman Desktop:
  it builds with `podman build` (podman-compose on Windows drops the `dockerfile:` path) from a clean
  `git archive` of HEAD (the Windows client ignores `.dockerignore`) and runs the stack rootless, so its ports
  reach Windows `localhost`. See local-run.md, section 8.
- **Resource providers.** Each report (01 - Current findings, section 7) shows which providers the subscription
  accepts (registered) and which not, against what it uses: in use, registered but not in use, platform (always
  registered), not registered, registering, and in use but not registered. It lists the "Allowed resource types" /
  "Not allowed resource types" policy assignments that apply (on the subscription, a resource group or an ancestor
  management group, enforced or audit only). The estate overview adds the same view across all subscriptions. New
  finding `resource_type_denied_by_policy` (`resource_provider_policy_scanner`) for resource types in use that such a
  policy denies. Registered but unused providers are not findings - Azure registers many on its own.

### Removed
- `MEMORY.md` is no longer part of the repository; maintainers keep their AI-assistant notes locally.

### Fixed
- VM right-sizing titles and severity used the list-price difference while the saving was capped at what the VM
  actually costs (e.g. "~USD 142/month" on a finding worth USD 66). Title, severity and savings now use the capped
  value, the description names both figures and why they differ, and a capped saving under USD 10/month is not
  suggested.
- The backend container stopped at once when its image was built from a Windows checkout
  (`exec /entrypoint.sh: No such file or directory`, CRLF line endings). `.gitattributes` keeps shell and docker
  files LF, and the image strips carriage returns from the entrypoint. `.dockerignore` keeps `reports/` and
  `.venv-local/` out of the build context.
- **Budgets were compared with the whole subscription.** Resource-group budgets and budgets filtered to a meter (for
  example one per AI model) were judged against the entire subscription's monthly cost, producing "exceeded by
  80,391 %" on a 20 CHF budget. Each budget is now evaluated like Azure does: actual cost at its own scope and with
  its own filter, with Azure's current spend in the evidence. "Overlapping budgets" is reported only for budgets
  with the same scope and filter. The report overview compares only subscription-wide, unfiltered budgets with the
  subscription total, and budgets show "-" instead of a 0.00 cost.

### Added
- **Validated VM right-sizing** (`vm_rightsizing_scanner`, finding `vm_rightsizing_opportunity`). Based on Azure
  Advisor's documented resize criteria with the stricter user-facing limits for every VM: over 30 days of 30-minute
  windows, the target size must keep CPU P95 at or below 40 % (P99 at or below 80 %), memory P99 at or below 60 %,
  disk use at or below 40 % of its limits and network under 100 Mbps; keep Premium Storage, Accelerated Networking,
  CPU architecture, Hyper-V generation, the temp disk and the disk / NIC counts; be offered in the region and be
  cheaper. Burstable targets must also stay under their documented base CPU performance. Candidates are Azure
  Advisor's own target and one size down in the same family; the cheapest that passes wins, and Advisor targets
  that fail are named with the failed check. Network appliances, Spot, scale-set / AKS / Databricks VMs, ephemeral
  OS disks and VMs younger than 30 days are never suggested. The value is the retail price difference, capped at
  the VM's actual cost; commitment-covered VMs and end-of-life series are called out. The estate overview lists
  the validated suggestions first; its average-CPU list is now labelled a screening list.

### Fixed
- VM retail prices match both price-list name formats (`Standard_D8s_v5` and `D8als v6`).
- A portal analysis that fails with an `ImportError` (code updated while the portal was running) now says to restart
  the portal instead of only showing the import error.
- **An expired `az login` no longer produces a partial report.** Conditional Access can expire the CLI token in the
  middle of a run; every scanner then logged warnings and the report was written with holes. The credential now
  fails fast after the first token error (`FailFastCredential`) and the run stops with "run az login again"; token
  calls time out after 60 s instead of hanging when `az` waits for an interactive prompt.
- The local portal no longer hangs on start-up or page loads when the Azure CLI session has expired (20 s token
  timeout, clear message to run `az login`).
- `docs/run-locally.md` (portal start, sign-in, reports, stop, troubleshooting) - `local-run.md` linked to it.
- `python -m scripts.generate_scanner_catalog` regenerates `docs/scanner-catalog.md` from the scanner registry.
- `.env` is no longer tracked (it only held the `.env.example` placeholders; `.gitignore` already excluded it).

### Docker workspace redesign and review - 2026-09-28

- Pulled upstream v0.2 through `da69387`, preserving local changes and Docker configuration.
- Redesigned the React sign-in, navigation and overview with a restrained forest/stone palette, editorial typography, grouped navigation, an estate summary, prioritized findings and guided first-use setup.
- Fixed concurrent database-session use in the dashboard, applied subscription filters to all summary queries, and replaced fabricated zero-cost history with recorded billing data.
- Unassessed posture areas display no score; invalid/reversed history dates return validation errors. History failures now show an explicit message.
- Sorted priority findings by severity explicitly and placed unknown savings last.
- Corrected the upstream nearest-rank percentile implementation and added boundary coverage.
- Hardened the Linux entrypoint against Windows CRLF line endings.
- Validation: 236 Python tests pass; frontend TypeScript/Vite production build and targeted Python lint pass.

### Upstream refresh and Estate integration - 2026-09-26

- Pulled five additional commits through `8929fe9`, retaining estate inventory/configuration/usage, the Marketplace SaaS scanner, parallel analysis and report naming fixes alongside the local improvements.
- Resolved the shared stylesheet overlap without dropping estate-specific styles or the responsive design.
- Extended responsive and keyboard support to Estate, added accessible view/sort/expansion states, and surfaced network/status failures.
- Prevented duplicate estate metric collection when multiple refresh requests arrive together; a concurrent-request regression test verifies one collection.
- Revalidated the expanded offline suite: 205 tests pass. See the [validation record](docs/merge-validation.md) for browser checks and integration limits.

### Local merge and deployment improvements - 2026-09-25

- Integrated upstream `4c8108f` with the local source snapshot; retained local originals in an ignored backup. See [merge decisions and validation](docs/merge-validation.md).
- Kept the local portal, subscription CLI, scanner pagination, parallel ARM enrichment, governance configuration, remediation scripts and full-stack deployment from upstream.
- Added BuildKit pip/npm download caches and strict frontend lockfile installation to the existing multi-stage images.
- Fixed production port removal using Compose reset tags and corrected `ENVIRONMENT` to `APP_ENV`; right-sized API worker/pool defaults.
- Made worker, scheduler and frontend startup wait for backend readiness. Readiness returns 503 on database failures; added pooled connection checking.
- Added persistent report and Beat volumes, loopback-only development database/API bindings and an optional Redis development override.
- Added safe environment generation, dependency-hash caching in local launchers, LF shell-script rules, and a CI workflow for Python, frontend and container smoke checks.
- Removed `.env` from the tracked working tree and replaced reusable secret values in `.env.example` with placeholders. Git history is unchanged.
- Added route-level loading/error recovery, deferred page bundles, a same-origin API default, and a real favicon.
- Improved React dashboard hierarchy, mobile drawer behavior, Scans navigation, keyboard labels, focus visibility, reduced-motion support and shared table containment.
- Kept successful dashboard data during refresh errors, canceled obsolete requests and prevented overlapping polling.
- Refreshed the local portal with a workspace overview, responsive cards/tables, clearer selection counts, mixed-state select-all, empty search state and inline connection/action errors.
- Moved local login throttling off the async event loop; added regression tests for readiness and environment generation.
- Fixed offline Alembic SQL generation for the existing finding-script migration while retaining its online behavior and migration identity; added a regression test.
- Added architecture, local setup, deployment/rollback, and validation documentation; corrected stale README development commands and nonexistent folders.


## [0.2] - 2026-09-28

### Fixed
- **Utilisation that averaged away busy periods, and "saturated" from one-minute spikes.** An App Service plan
  that idles with nightly one-minute bursts showed 1.5 % CPU in the reports while the Azure portal chart (daily
  maximum) showed 100 %, and `app_service_plan_cpu_saturated` fired on any one-minute peak of 95 %. Metrics now
  carry an hourly profile - **busiest hour**, **P95 of hourly averages** and **hours with a 90 %+ burst** - next to
  the 30-day average and the one-minute peak. Saturation needs a busy hour (80 %+) or a busy month (60 %+ average);
  bursts are reported as bursts.
- `sql_database_utilization_scanner` reads CPU / DTU hourly: idle = no connections and no hour above 5 % (maintenance
  spikes no longer hide an unused database), under-utilised = connections but no hour above 5 %, saturated = an
  hour at 80 %+ (was: any one-minute peak of 95 % with a 10 % average).
- Estate: the hourly profile for every percentage metric - CPU busiest hour column, P95 and burst hours in the
  tooltip, memory busiest hour, and the busiest hour of API Management capacity, Cosmos DB RU, Data Explorer
  ingestion and storage percentages in the Usage column. Right-sizing also excludes VMs whose busiest hour is 40 %+
  and shows the busiest hour next to one-minute bursts.
- **No emoji anywhere:** severity labels in reports are plain `Critical` / `High` / `Medium` / `Low` / `Info`;
  scanner texts say "Warning:"; README headings, portal templates, notifications and scripts use plain text.

### Added
- `app_service_plan_underutilized`: plans whose P95 hourly CPU is under 10 %, busiest hour under 30 % and memory
  under 40 % are reported as over-provisioned with the next smaller SKU of the same family and an estimated saving
  of half the plan's 30-day cost.
- `local-run.md`: end-to-end runbook - sign in, fresh start, estate refresh, full analysis, portal, reading
  utilisation, tests, git workflow, Docker vs local, troubleshooting.
- **Idle storage accounts that were in use.** `unused_storage_account_scanner` and the estate counted every
  transaction against a flat 200-per-30-days threshold, so accounts with real reads and writes (static websites,
  `GetBlob` / `PutBlob` traffic) hidden under ~120 housekeeping calls were reported as idle and "delete". The 30-day
  `Transactions` metric is now split by `ApiName`; Defender / portal / inventory calls (`GetBlobServiceProperties`,
  `ListContainers`, ...) are subtracted, and an account is idle only with at most 10 real data operations. Heavy
  `Unknown` (anonymous / failed-auth) traffic counts as activity. The total-based threshold stays as a fallback.
- **Idle accounts that hold data are no longer deletion candidates.** An idle account with more than 1 GB is reported
  as `dormant_storage_data` (tier to Cold / Archive, confirm retention with the owner) with the saving estimated
  against the Cold tier, instead of the full cost. Premium page-blob accounts (VHDs) get copy-to-Standard guidance.
- Storage accounts whose VHDs back a VM (unmanaged disks) are no longer reported; boot-diagnostics targets get a note.
- **AI deep dive showed no spend.** The page promised "accounts, deployments, spend" but only listed findings (whose
  saving is "-" for security findings). It now opens with every AI account (kind, SKU, region, 30-day cost, top
  meters, model deployments incl. SKU and capacity) and AI spend on resources deleted within the window. Every other
  deep-dive page gets a "Spend in scope" table, and finding tables show the resource's 30-day cost next to the saving.
  Deployments are collected per report (`05-deep-dive/raw/inventory/ai-deployments.json`).
- **Estate recommendations.** Right-sizing candidates now also need under 40 % memory used (one size down halves the
  RAM) and never include network virtual appliances (FortiGate, Palo Alto, ... detected from the image; they report
  ~100 % memory and are licensed per vCPU); excluded counts, burst peaks and missing memory data are shown per VM,
  with a note that savings-plan / reservation-covered compute shows ~0 cost. The idle list no longer includes SQL
  `master` databases or geo / standby replicas, nor resources with failed runs or 5xx errors or registries that
  received pushes; idle storage holding data is shown as **Dormant data** on the Estate page and in the overview.
  The estate splits storage `Transactions` by `ApiName` like the scanner.
- `idle_sql_database` skips geo / standby secondaries: a DR replica takes no connections by design and was reported
  as "delete".
- **Blank values in reports and the estate.** Report tables drop columns that are blank in every row (resource
  inventory, service baselines, deep dives); a resource with no charge shows `0.00` instead of nothing; the action list
  and deep dives show an **Impact** (the saving, else Security / Performance / Operational / Structural); the savings
  register lists actions with a saving first, then the other actions without an empty saving column, and summarises
  tag / naming hygiene as counts (it listed ~1,800 rows with a blank "Monthly impact"); scanner runs show 0 warnings
  and "not reported" instead of blanks; cost drivers say "stable" / "first month" instead of an empty "Largest change".
  The report inventory adds Configuration and 30-day cost columns.
- **Estate details for types that showed nothing:** storage accounts (network exposure, private endpoints, shared key,
  blob public access, TLS, ADLS Gen2, SFTP), managed disks (OS / data, VM, zone, tier, public access, bursting,
  shared), snapshots (incremental, source, date), SQL databases (max size, zone redundancy, backup redundancy,
  auto-pause), smart detector alerts (frequency, detector, disabled), Event Grid topic source, registries (admin user,
  network, zone redundancy), runbooks (state), Arc SQL instances (license, host, disconnected) and the VM OS-disk type.
  The Estate page shows a muted "-" with a tooltip explaining why a cell is empty, and `0` cost for resources of
  analysed subscriptions that had no charge. Environment falls back to the subscription name.

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
