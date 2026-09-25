# Subscription Analysis - User Guide

Run every ARG scanner against your Azure subscriptions **from your own workstation**, with your own
`az login` session. There's no Docker, database or service principal. You get a FinOps and architecture review per
subscription as markdown files, either from the command line or from a small local web portal.

- Product requirements: [PRD-subscription-analysis.md](./PRD-subscription-analysis.md)
- All scanners and finding types: [scanner-catalog.md](./scanner-catalog.md)

---

## 1. Where to run it

| You run… | From which folder | Notes |
|---|---|---|
| `scripts\Start-LocalPortal.ps1` / `scripts\Invoke-SubscriptionAnalysis.ps1` | **Any folder.** Call the script by its path, e.g. `C:\src\ARG\scripts\Start-LocalPortal.ps1` | The scripts switch to the ARG repository root themselves. A relative `-ReportsPath` is resolved from the folder you're in. |
| `./scripts/start-local-portal.sh` | Any folder | Same behaviour on Linux/macOS. |
| `python -m scripts.subscription_analysis …` / `python -m scripts.local_portal …` | **The ARG repository root** (the folder with `requirements-local.txt`) | `python -m` finds the `scripts` package relative to the current folder. |
| `make portal` / `make analyze SUB=…` / `make analyze-all` | The ARG repository root | Uses the `python` on PATH, so activate `.venv-local` first. |

**Reports always land in `<ARG repo>\reports\`** unless you pass `-ReportsPath` / `--reports-dir`, whichever
folder you started from. `reports/` is git-ignored.

---

## 2. Prerequisites (one-time)

1. **Python 3.10+** on PATH (`python --version`).
2. **Azure CLI** on PATH (`az --version`).
3. Sign in with your own account: `az login` (or `az login --tenant <tenant-id>`).
4. Your account needs these roles on every subscription you want to analyse:

   | Role | Used for |
   |---|---|
   | Reader | Resource Graph, ARM configuration, Azure Monitor metrics, diagnostic settings |
   | Cost Management Reader | Cost trend, per-resource cost, budgets, actual-cost savings |
   | Security Reader | Defender plans, secure score, Defender recommendations |

   If a role is missing, that part of the report is empty and the reason appears under *Collection Warnings* in
   `05-deep-dive/README.md`.

The launch scripts create `.venv-local` in the repository root and install
[`requirements-local.txt`](../requirements-local.txt) on first use. To do it by hand:

```powershell
cd C:\src\ARG
python -m venv .venv-local
.\.venv-local\Scripts\pip install -r requirements-local.txt
.\.venv-local\Scripts\Activate.ps1
```

---

## 3. Local portal

```powershell
az login
$env:ARG_PORTAL_PASSWORD = 'choose-a-password'   # optional
C:\src\ARG\scripts\Start-LocalPortal.ps1         # opens http://127.0.0.1:8765
```

| Step | What happens |
|---|---|
| Portal sign-in | Username `admin` (or `ARG_PORTAL_USER`) and `ARG_PORTAL_PASSWORD`. Without a password, a one-time password is printed in the terminal. **This login only protects the portal. It never signs in to Azure.** |
| Azure CLI session card | Shows the account and tenant of your `az login`. To switch, run `az login` / `az login --tenant <id>` in a terminal and click **Refresh**. |
| Subscriptions table | Every subscription the CLI account can see, with last-analysed date, Critical/High counts, 30-day cost and estimated savings from the latest report. Use the filter box to narrow it down. |
| Analyze | Select one or more subscriptions and click **Analyze** (two run in parallel by default, `--workers`). Progress shows live. A subscription takes a few minutes, mostly Cost Management throttling. |
| Reports | Click a subscription name or open **Reports**. Markdown pages render with a sidebar; mermaid diagrams render when the browser can reach the jsDelivr CDN. JSON evidence is pretty-printed, with a raw download link. |

Options: `-Port 9000`, `-ReportsPath D:\arg-reports`, `-TenantId <id>`, `-NoBrowser`.
With plain python: `python -m scripts.local_portal --port 9000 --reports-dir D:\arg-reports --tenant <id> --workers 2 --no-browser`.

---

## 4. Command line

```powershell
# one or more subscriptions (ID or display name)
C:\src\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription 'pp-buehler_insights_leybold_optics'
C:\src\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription 'sub-a', 'sub-b'

# every enabled subscription visible to az login
C:\src\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -All -ReportsPath 'D:\arg-reports'
```

Python equivalent (run from the repository root):

```bash
python -m scripts.subscription_analysis --subscription <id-or-name> [--subscription <another>]
python -m scripts.subscription_analysis --all --tenant <id> --parallel 3     # whole tenant, 3 at a time
python -m scripts.subscription_analysis --all --tenant <id> --estate         # estate inventory + usage (~4-5 min)
```

| Option | Meaning |
|---|---|
| `--reports-dir DIR` | Root folder for per-subscription reports (default `<repo>/reports`) |
| `--output DIR` | Exact folder, for a single subscription only (no index update) |
| `--tenant ID` | Tenant of the az login session to use |
| `--scanners a,b` | Run only these scanners (names in [scanner-catalog.md](./scanner-catalog.md)) |
| `--config FILE` | JSON with threshold overrides, see [§7](#7-tuning-thresholds) |
| `--skip-cost` | Skip the report's cost datasets (trend, breakdowns). Cost-aware scanners still query per-resource cost |
| `--estate` | Only refresh the estate inventory (`reports/_estate/`) for `--all` / `-s` targets: one Resource Graph query plus VM size specs and 30-day usage metrics (about 4-5 minutes for 12,000 resources), joined with the existing reports. No scanners, see [§5c](#5c-estate-inventory-all-subscriptions) |
| `--parallel N` | Analyse up to N subscriptions at once (default 1). `--all --parallel 3` is a good balance; beyond that Cost Management throttling (429 retries) eats most of the gain |
| `--auth default` | Use `DefaultAzureCredential` (env vars / managed identity) instead of az login, for automation |
| `-v` | Verbose logging |

The exit code is non-zero if any subscription failed. The others are still written.

---

## 5. Output layout

```
reports/
├── README.md                        index: one row per analysed subscription
├── _estate/                         estate inventory across all subscriptions (§5c)
└── <subscription-name>/             display name made filesystem-safe; <name>_<first 8 of ID>/ when another
    │                                subscription with the same name already owns <name>/
    ├── README.md                    executive summary, headline savings, top risks, prioritised actions
    ├── summary.json                 totals used by the index and the portal
    ├── 01-current-findings/         baseline, workloads, architecture diagram, resource-inventory.md
    ├── 02-gap-analysis/             gaps by area × severity (structural, security, operational, performance, FinOps)
    ├── 03-cost-drivers/             12-month trend, service/RG/resource breakdown, forecast, savings-register.md
    ├── 04-architectural-critique/   inferred evolution, decision-by-decision critique, target architecture, roadmap
    └── 05-deep-dive/
        ├── README.md                index, scanner runs, collection warnings
        ├── networking/ compute-appservice/ data-sql-storage/ ai-foundry/
        ├── security-identity/ observability-operations/ cost-finops/
        └── raw/                     findings.json, scanner-runs.json, metadata.json, inventory/, cost/
```

- Findings are numbered `F-001…` by severity then savings. The same reference is used in every file.
- **Savings waves:** wave 1 is no-regret cleanup, wave 2 is optimisation, and wave 3 is structural (no direct saving).
- **Currency:** savings are computed in USD (list prices or actual `CostUSD`) and shown in the billing currency at the
  subscription's implied rate.
- Re-running a subscription **replaces** its generated files. Copy the folder first if you want history.
- **Same display name:** each folder records its owner in `.subscription-id`, so subscriptions that share a name
  (e.g. several "Visual Studio Professional Subscription"s) never overwrite each other. The index and the portal show
  their short ID next to the name.
- **Lumpy spend:** when one month carries at least half of the year's charges, is at least 3× the other months and the
  subscription existed for the whole window (e.g. an annual Marketplace SaaS or reservation charge), the summary says so
  and the forecast uses the 12-month average instead of the last 30 days, which are not a monthly run-rate then.
  Negative months (credits/refunds) are called out.

---

## 5a. Marketplace SaaS (`marketplace_saas_scanner`)

Marketplace SaaS plans (`microsoft.saas/resources`, e.g. email security or backup services bought in the Azure portal)
are billed to the subscription, often as one large up-front charge, but have no metrics. The scanner reads the SaaS
status and term from Resource Graph and the **12-month** cost per SaaS resource from Cost Management.

| Finding | Rule | Severity |
|---|---|---|
| `marketplace_saas_unsubscribed` | Status `Unsubscribed`: the plan no longer bills but the resource is left behind | Low |
| `marketplace_saas_inactive` | Status `Suspended` (usually a failed payment) or `PendingFulfillmentStart` (bought, never activated) | High / Medium |
| `marketplace_saas_term_ending` | `Subscribed` and the term ends within `saas_renewal_window_days` (90). Auto-renew on: renewal decision due. Off: the service stops | Medium; High if auto-renew is off and ≤ 30 days remain |
| `marketplace_saas_commitment` | `Subscribed`, not a free trial, ≥ `saas_commitment_min_usd` (1,000) charged in 12 months | Low (owner and review date) |

No saving is estimated: whether to renew, resize or cancel is a business decision for the plan owner.

A missing budget (`budget_missing`) is **High** instead of Medium when the peak monthly spend in the last six full months
is at least `budget_missing_high_monthly_usd` (10,000 USD).

---

## 5c. Estate inventory (all subscriptions)

The subscription reports answer "what is wrong in this subscription". The **estate** answers "what do we run,
where, at what size, and what should change" across the whole tenant, so architecture and FinOps decisions can
be made on the complete picture (e.g. "all deallocated D-series VMs", "every Premium disk that is unattached",
"which subscriptions still run SQL Server 2016 on Arc").

| | |
|---|---|
| **Portal** | **Estate** in the top bar (`/estate`). Click **Refresh inventory** for a live Resource Graph query plus VM specs and 30-day usage metrics across every enabled subscription of the signed-in tenant (~4-5 min) |
| **CLI** | `python -m scripts.subscription_analysis --all --tenant <id> --estate` |
| **Files** | `reports/_estate/README.md` (markdown overview, linked from `reports/README.md`), `estate.json` (portal data), `inventory.json` (raw inventory) |
| **Kept current** | Every analysis (CLI or portal job) re-joins the estate offline, so new findings and costs appear without a new inventory query |

What each resource carries: category (Compute, Storage, Networking, Databases, Hybrid & Arc, …), readable type,
**size / SKU** (VM size; VMSS SKU × instances; disk SKU + GB; storage SKU · kind · access tier; App Service plan SKU ×
instances; SQL / PostgreSQL / Redis SKU; AKS version, pools and nodes; Arc SQL version · edition · vCores), OS image
and Azure Hybrid Benefit (`· AHB`), power / disk / agent state, environment (from `Environment` tags such as
`Core Prod`, `Non public-prod`, `public non-prod`, `prep`, then from names), region, subscription, resource group,
tags, last-30-days cost and the report findings on it. A **Configuration** column adds per-type details (VM zone,
data disks, Spot; NIC attachment and IP; private endpoint target; certificate expiry; alert severity, ...).

**VMs and scale sets** also get **vCPU** and **RAM** (from the Compute SKU catalogue of their region) and the
**30-day average CPU %** and **memory used %** (Azure Monitor platform metrics `Percentage CPU` and
`Available Memory Bytes`; memory used = 1 - available / RAM). Hover the CPU value for the 30-day peak. Deallocated
VMs have no metrics. Network virtual appliances (firewalls) often report almost no available memory, so they show
~100 % memory used - that is how the appliance reserves memory, not a problem. The markdown overview lists running
VMs by average-CPU band and the **right-sizing candidates** (4+ vCPU, under 5 % average CPU) - check the peak and
memory before downsizing.

Child resources are named like the Azure portal (`vm-app-01 › DSC` for the DSC extension on `vm-app-01`). VM / Arc
extensions and Arc license profiles are hidden unless you tick *Include VM / Arc extensions and license profiles*.

**Usage - last 30 days (every type Azure Monitor reports on).** On refresh, ARG reads platform metrics for 31
resource types through the Azure Monitor **metrics batch API** (`<region>.metrics.monitor.azure.com … metrics:getBatch`,
up to 50 resources of one type / region / subscription per call, daily points, averaged or summed over 30 days). No
agent is needed. The **Usage (30 d)** column shows the activity and extra facts; **CPU avg / Memory avg** appear for
every type that reports them.

| Type | Metrics → shown as |
|---|---|
| VMs, scale sets | `Percentage CPU` → CPU avg (+ peak); `Available Memory Bytes` ÷ RAM → memory used % |
| App Service plans | `CpuPercentage`, `MemoryPercentage` |
| Web / Function apps, slots | `Requests`, `Http5xx` (failed), `FunctionExecutionCount` |
| Storage accounts | `Transactions`, `UsedCapacity` (latest), `Egress` (transferred) |
| SQL databases / elastic pools | `cpu_percent`, `connection_successful`, `storage_percent` |
| PostgreSQL / MySQL flexible | `cpu_percent`, `memory_percent`, `storage_percent` |
| Cosmos DB | `TotalRequests` (Count), `NormalizedRUConsumption` peak |
| Redis | `serverLoad` (as CPU), `usedmemorypercentage`, `connectedclients` |
| AKS | `node_cpu_usage_percentage`, `node_memory_working_set_percentage` |
| Container apps / registries | `Requests`, `Replicas` / `SuccessfulPullCount`, `StorageUsed` |
| Key Vault, AI Services, AI Search | `ServiceApiHit` / `TotalCalls` + prompt/generated tokens / `SearchQueriesPerSecond` |
| Service Bus, Event Hubs, IoT Hub, Event Grid, SignalR | incoming messages / events (+ bytes, active messages, devices) |
| Data Factory, Logic apps, Automation | succeeded / failed runs, jobs |
| Application Gateway, APIM, Front Door, Firewall, Load balancer | requests / capacity, data processed, bytes |
| Data Explorer | `CPU`, `IngestionUtilization` |

**Idle** means the type's activity metric was zero for 30 days - storage uses the same ≤ 200 transactions threshold
as the idle-storage scanner (platform housekeeping), container apps must also have scaled to zero, and web apps must
also have no function executions (timer/queue-triggered functions get no HTTP requests). Use the **Activity** breakdown
to list idle resources; the markdown overview adds a usage table per type and the costliest idle resources. A batch
that fails is retried with the type's primary metric only; global resources (Front Door) use the per-resource metrics
API. Azure throttles metric reads per caller, so a full refresh of ~2,500 measured resources takes 3-4 minutes
(more parallelism does not help). Treat idle as a strong hint and confirm with the owner before deleting.

The **Estate** page:
- **Tiles** per category and **breakdowns** (by type, size/SKU, average CPU band, region, subscription, environment,
  suggestion type) that follow the current filters; click any entry to filter on it.
- **Filters:** search (name, resource group, tag, size), category, type, size / SKU, subscription, region,
  environment, state, "with actionable / critical-high / no suggestions", suggestion type and severity.
- **Resources** view: sortable, paged table; click a row for the full ID, tags, Azure portal and report links and its
  suggestions. **Suggestions** view: every finding across the estate (including subscription-level ones such as
  missing budgets), sortable by severity and estimated saving.
- **Hygiene vs actionable:** tag and naming findings (`missing_required_tags`, `naming_convention_violation`,
  `tag_key_typo`) sit on almost every resource, so they are counted separately and hidden unless you tick
  *Include tag / naming hygiene findings* or pick that suggestion type.
- **Download CSV** exports the filtered rows (all pages); **Copy link** shares the filtered view (filters live in the URL).

Suggestions and cost come from the latest report of each subscription; subscriptions that were never analysed
still appear in the inventory, without suggestions.

---

## 6. What it analyses

63 scanners across network, compute/App Service, database, storage, security, identity, governance/observability
and cost. See [scanner-catalog.md](./scanner-catalog.md). The five Microsoft Graph (Entra ID) scanners are **skipped**
locally; they need the Docker stack with a service principal and Graph consent. Terraform drift is skipped unless state
was imported into the Docker stack.

---

## 7. Tuning thresholds

Pass a JSON file with `--config`. Keys apply to every scanner that reads them:

```json
{
  "required_tags": ["owner", "environment", "cost-center", "application"],
  "cpu_avg_threshold": 60, "cpu_max_threshold": 95,
  "saturated_max": 95, "saturated_min_avg": 10,
  "idle_transactions_7d": 50, "hot_transactions_7d": 50000000, "min_family_size": 10,
  "management_ports": [22, 3389, 5985, 5986],
  "max_owners": 3, "secure_score_target": 0.8, "defender_severities": ["High"],
  "min_daily_cap_gb": 0.5, "max_workspaces": 2, "max_workloads_per_subscription": 2,
  "overrun_months": 3, "ai_min_monthly_usd": 100, "max_ai_accounts": 2,
  "timeout_seconds": 900
}
```

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| Browser shows `ERR_CONNECTION_REFUSED` on `http://127.0.0.1:8765` | The portal isn't running. It only runs while `Start-LocalPortal.ps1` (or `python -m scripts.local_portal`) is running in a terminal. Start it and keep that terminal open. Ctrl+C or closing the terminal stops it. |
| "The Azure CLI is not signed in", or `AADSTS70043 … sign-in frequency checks by conditional access` | Your tenant's Conditional Access requires re-authentication (for example every hour). Run `az login` in a terminal, then click **Refresh** (portal) or re-run. Start long `--all` runs right after signing in. |
| A subscription isn't listed | It belongs to another tenant: `az login --tenant <id>`, then Refresh. Or it's disabled. |
| Cost sections empty / `cost query … 403` warning | Grant *Cost Management Reader* on the subscription. |
| Defender sections empty | Grant *Security Reader*. |
| Slow run, "429 … retrying" in the log | Normal. Cost Management allows a few calls per minute and the client waits for `Retry-After`. |
| `No module named scripts` | You ran `python -m …` outside the repo root. `cd` to the repo, or use the `.ps1` / `.sh` launchers. |
| Diagrams show as code | The browser couldn't load mermaid from the CDN (offline / proxy). The content is still there. |
| Port already in use | `-Port 9000` / `--port 9000`. |

---

## 9. Security notes

- The portal binds to **127.0.0.1 only** and rejects other Host headers (DNS rebinding) and cross-origin POSTs.
  It uses an HttpOnly, SameSite=Strict session cookie and a strict Content-Security-Policy.
- Rendered reports have raw HTML neutralised, because tag values and names come from Azure.
- The tools are **read-only** against Azure. Remediation commands in the reports are for review and are never executed.
- Reports contain resource IDs, IP addresses and principal IDs. Keep `reports/` out of source control; it's git-ignored.
