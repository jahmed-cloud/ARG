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
   | Cost Management Reader | Cost trend, per-resource cost (amortized), budgets (actual), savings |
   | Security Reader | Defender plans, secure score, Defender recommendations |

   If a role is missing, that part of the report is empty and the reason appears under *Collection Warnings* in
   `05-deep-dive/README.md`. `scripts\Grant-ArgRoles.ps1 -Assignee <user> -IncludeReader` assigns the missing
   roles on every subscription the person running it can manage (Owner or User Access Administrator); preview with
   `-WhatIf`.

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
C:\src\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription 'pp-example_workload'
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
| `--estate` | Only refresh the estate inventory (`reports/_estate/`) for `--all` / `-s` targets: one Resource Graph query plus VM size specs and 30-day usage metrics (a few minutes for 10,000+ resources), joined with the existing reports. No scanners, see [§5c](#5c-estate-inventory-all-subscriptions) |
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
    ├── 01-current-findings/         baseline, workloads, architecture diagram, resource-inventory.md,
    │                                resource-providers.md (every provider and its status)
    ├── 02-gap-analysis/             gaps by area × severity (structural, security, operational, performance, FinOps)
    ├── 03-cost-drivers/             12-month trend, service/RG/resource breakdown, forecast, savings-register.md
    │                                (per wave: actions with a saving, other actions, tag / naming hygiene counts)
    ├── 04-architectural-critique/   inferred evolution, decision-by-decision critique, target architecture, roadmap
    └── 05-deep-dive/
        ├── README.md                index, scanner runs, collection warnings
        ├── networking/ compute-appservice/ data-sql-storage/ ai-foundry/
        ├── security-identity/ observability-operations/ cost-finops/
        └── raw/                     findings.json, scanner-runs.json, metadata.json, inventory/, cost/
```

- Findings are numbered `F-001…` by severity then savings. The same reference is used in every file.
- **Savings waves:** wave 1 is no-regret cleanup, wave 2 is optimisation, and wave 3 is structural (no direct saving).
- **Currency:** savings are computed in USD - at each resource's own amortized cost where it is known, otherwise at list
  prices (see *Savings at your own price* in 5a-2) - and shown in the billing currency at the subscription's implied rate.
  The local portal's **Currency** dropdown (top bar) shows every page in another currency: *Billing currency* (each
  subscription's own, the default), USD, or any currency with a European Central Bank reference rate (downloaded
  once every 12 hours, no key). Billing amounts convert through USD at the subscription's own invoice rate, so they
  stay consistent with the invoice. `DISPLAY_CURRENCY=USD` makes USD the default; the choice is kept in a cookie.
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
- **summary** = README, current findings (without resource inventory), gap analysis, cost drivers, savings register,
  critique, deep-dive index. **full** adds the resource inventory, the full resource-provider list and every
  deep-dive page (large for big subscriptions).
- Output: `reports/<subscription>/report-<detail>.pdf`, plus `report-<detail>.html` (a standalone, print-ready copy).
  Both are replaced on re-run.
- **How:** the report is rendered into one HTML document (cover page, table of contents, one section per page,
  internal links turned into in-document links, author credit).  The Microsoft Edge (or Chrome)
  already on the machine then prints it headlessly. Nothing extra to install. Set `ARG_PDF_BROWSER` to a browser path
  to override.
- No Edge/Chrome, or printing failed? Open `report-<detail>.html` (or the portal's **Print view**) and use the browser's
  **Print > Save as PDF**. Mermaid diagrams need access to the jsDelivr CDN at print time; offline they appear as code.

---

## 5a-2. Cost basis: amortized vs actual

Reports use **amortized cost** by default: Cost Management spreads reservation and savings-plan purchases over the
resources that use them. Switch to **actual (invoiced) cost** with `--actual-cost`, `AMORTIZED_COST=false` in the
environment (also for the local portal), or `{"amortized_cost": false}` in the `--config` file; in the Docker stack
it is *Settings → Governance Configuration → Analysis settings*. The README and the 12-month trend name the basis used. With actual cost a VM covered by a savings plan bought in another subscription shows almost nothing
(for example 2 CHF instead of 147 CHF a month) and the buying subscription carries the whole commitment. The README
states the basis and shows the **invoiced (actual)** cost for the same 12 months next to it; the 12-month trend has
both columns.

Actual cost is still used where it is the right measure: **budgets** (Azure evaluates them on actual cost, at the
budget's own scope - subscription or resource group - and filter, for example one AI model's meter) and
**Marketplace SaaS** (purchases are not amortized). VM right-sizing reads both: when most of a VM's amortized cost is
not invoiced as pay-as-you-go, it is covered by a commitment and the resize frees that commitment for other VMs.

**Savings at your own price.** A saving is valued at what the resource actually costs you - its amortized cost over
the last 30 days, so negotiated discounts, reservations and savings plans count - not at the public list price:

| Recommendation | Saving |
|---|---|
| Remove it (idle, unattached, orphaned, empty) | Its 30-day amortized cost. This can be above the list estimate, e.g. an idle WAF_v2 Application Gateway with capacity units |
| Change its price (VM size, App Service plan generation) | The list-price difference scaled by actual / list cost (your discount), never more than the list-price difference |
| No cost data (no Cost Management access, or no cost row for the resource yet) | The list-price estimate, labelled as such |

Each finding's evidence records `saving_basis` (`amortized cost, last 30 days` or `list price`),
`list_price_saving_usd` and `amortized_cost_usd_30d`, and the description gives both figures when they differ.
Savings that already start from the resource's own cost (idle storage and SQL, one size down, AI accounts,
Marketplace SaaS, SQL Hyperscale storage) are unchanged. Storage-account sprawl stays a list-price estimate: its
saving is the Defender for Storage price per account.

## 5a-3. Resource providers

Section 7 of *01 - Current findings* shows which resource providers the subscription **accepts** (registered) and
which it does not, against what it actually uses. `01-current-findings/resource-providers.md` lists **every** provider
of the subscription (also in the full PDF):

| Status | Meaning |
|---|---|
| In use | Registered and resources exist |
| Registered, not in use | Registered, nothing deployed yet - normal for core services and the governance baseline; information only for niche providers |
| Platform (always registered) | Registration-free providers Azure keeps registered |
| Not registered | The subscription cannot create these resources until an Owner / Contributor registers the provider |
| Registering / Unregistering | A registration change in progress |
| In use, not registered | Resources exist although the provider is not registered (usually created before it was unregistered) |

A registered provider without resources is normal and costs nothing. **Core services** (Compute, Storage, Network,
Key Vault, Web, SQL, containers, messaging, Logic Apps, AI, backup, DevTestLab for VM auto-shutdown, Blueprint,
Capacity, ManagedServices, ... - `CORE_PROVIDERS`) and the **governance baseline** (`PLATFORM_PROVIDERS`: Defender,
Policy, Monitor, Cost Management, Advisor, Update Manager, managed identities) are never unregister candidates:
unregistering saves nothing and breaks the next deployment until someone registers the provider again. Findings
(`resource_provider_registration_scanner`):

| Finding | When | Severity |
|---|---|---|
| `resource_provider_blocked_registered` | A provider on the `blocked_resource_providers` list is registered (default: the retired classic providers `Microsoft.ClassicCompute`, `ClassicNetwork`, `ClassicStorage`, `ClassicInfrastructureMigrate`) | Low; Medium when resources of it exist |
| `resource_providers_registered_unused` | Opt-in (`report_unused_providers`, off by default): niche providers registered with no resources - core services and the governance baseline excluded. Informational; the unregister commands are commented out | Info |

For services the company does not allow, the control that sticks is a "Not allowed resource types" (or "Allowed
resource types") policy at the management group - the portal re-registers an unregistered provider on the next
deployment by anyone with rights.

It also lists the **"Allowed resource types" / "Not allowed resource types"** policy assignments that apply -
on the subscription, one of its resource groups or an ancestor management group - with their enforcement mode.
Resource types in use that such a policy denies raise `resource_type_denied_by_policy`. The estate overview adds
the same view across all subscriptions: providers in use, niche providers registered but unused, and every provider with the number
of subscriptions where it is in use, registered, registered but unused, or not registered.

## 5a-4. Why, when not, cost of implementation and references

Every finding carries an implementation analysis (`scripts/subscription_analysis/guidance.py`, the same in the local
report and the Docker UI's finding detail):

| Part | What it says |
|---|---|
| Why it is needed | The mechanism: what goes wrong, or what is wasted, if nothing changes |
| When it is not needed | The honest exceptions (dev/test, compensating controls, cases where the fix costs more than the risk) |
| Cost of implementation | **Azure run-cost change per month** (e.g. a private endpoint about USD 7.30, API Management Basic v2 about USD 150, Defender plans per resource) and **engineering effort** in hours (and a one-off amount when `engineering_hourly_rate_usd` is set) |
| Net effect | For findings with a saving: the saving minus the run cost of the change (the AI gateway saving is already net) |
| References | Microsoft Learn pages and the Azure pricing page for the change |

Where it shows: the *Cost to implement* column of the action list, gap analysis, savings register (with *Net /
month*) and deep-dive tables; the full analysis under each finding in the deep dives; the README totals for waves
1 + 2 (wave 3 is reported separately - it is project work); `implementation` on every finding in
`raw/findings.json`. Prices are USD pay-as-you-go list prices from the Azure Retail Prices API
(`scanners/base/guidance.py`, `PRICES_AS_OF`); enterprise agreements and other regions differ, so they are estimates
for planning.

**Defender for Cloud recommendations** are imported per resource (High by default, `defender_severities`):

- Recommendations that only ask to **buy a paid plan** ("Microsoft Defender for Storage plan should be enabled with
  Malware Scanning ...", "Microsoft Defender CSPM should be enabled", "... for Resource Manager / Key Vault / SQL ...")
  are left out - plan choice is a central cost decision, not a configuration gap. The README and the security deep
  dive say how many were left out; `defender_plan_recommendations` brings them back. The per-subscription plan
  overview with the price of each plan (`defender_plan_disabled`) is off by default too (`defender_plan_coverage`).
- Per-package OS updates ("Update openssl", "Update libc6", ...) become one entry per machine.
- The most common recommendations have curated guidance with commands for the affected resource
  (`scanners/security/defender_guidance.py`) - e.g. *Linux / Windows virtual machines should enable Azure Disk
  Encryption or EncryptionAtHost*: managed disks are already encrypted at rest, encryption at host adds the temp disk,
  caches and host-to-storage flow at no extra charge (one restart), and Azure Disk Encryption retires on
  15 September 2028. Other recommendations show Microsoft's own description, remediation and links from Defender.

**AI gateway.** `ai_spend_without_gateway` prices the gateway itself (API Management `ai_gateway_sku`, Basic v2 by
default, from the Retail Prices API) and shares it across the subscription's AI accounts by spend. The saving is
the assumed reduction (`ai_gateway_saving_ratio`, 15 %) **minus** that cost; below break-even the finding stays at Low
with no saving and states the AI spend from which the gateway pays for itself. It also says what the gateway
delivers (per-app token metrics, token limits, managed-identity access, failover, optional semantic cache - which
needs Azure Managed Redis on top).

## 5a-4b. What the executive summary leads with

The README is written for the person who has to decide, not for the person who fixes one resource
(`scripts/subscription_analysis/insights.py`):

| View | What it answers |
|---|---|
| **Actionable vs hygiene** | Findings are counted without tag / naming hygiene (rated Low; reported as cost allocation instead) |
| **Where the money is** | The 10 costliest resources, their share of spend and which findings address them. Spend with **no recommendation** is called out - it needs a design review with the owner, because ARG (or Advisor) has no analyser for it |
| **Cost allocation** | Share of the last 30 days' spend on resources that carry every required tag, and the most-missed tag weighted by cost - the chargeback KPI, instead of hundreds of per-resource tag findings |
| **By environment** | Production vs non-production spend (tags, names, the subscription naming convention) |
| **Systemic issues** | A gap on 10+ resources (or 3+ and half of a type) is a platform default: one row with the **built-in Azure Policy guardrail** (Audit → remediate → Deny); the gap analysis shows it once, the deep dive lists every resource |
| **Quick wins** | Material items (a saving, or critical / high) that take an hour or less and add no run cost |
| **Retirement calendar** | Azure retirements that affect the subscription (`service_retirement_scanner`, from Advisor - feature, API version, SKU, VM series, runtime - with the date and days left) plus ARG's end-of-support checks; overdue first |
| **Resilience posture** | Open Advisor reliability recommendations (zone redundancy, backup, geo-replication, scalability), production first, in *01 - Current findings §8*; items ARG already reports are not repeated |
| **Changes since the previous analysis** | New, resolved and re-rated findings against the report that was in the folder, and a trend over the last runs (`history.json`, kept across re-runs) |

**No double counting.** Defender for Cloud and Advisor items that a ARG finding already covers on the same
resource are merged into it (`correlate.py`; "also reported by" in the evidence), and an Advisor cost item on a
resource that already carries a ARG saving is dropped. Advisor recommendations that Azure marks Completed /
Resolved or that were dismissed are never imported.

**Advisor cost recommendations** (`advisor_cost_scanner`) bring in the savings ARG has no native analyser for -
for example Data Explorer table cache policies (per table: current and recommended hot period, the `.alter table ...
policy caching` command), VM and App Service right-sizing, Basic logs - capped at the resource's own 30-day cost.

**Azure Boards backlog.** Every report folder has `backlog.csv` for *Boards → Queries → Import work items*: one Task
per systemic issue (guardrail and all affected resources) and per remaining actionable finding, with description,
why, cost, remediation, commands, references and a "done when"; priority from severity, Remaining Work from the effort
estimate, tags `ARG; <subscription>; <area>; wave <n>; <finding type>`.

## 5a-5. Settings

| Where | How |
|---|---|
| Local portal | **Settings** in the top bar; saved to `<reports-dir>/settings.json` and used by the next analysis from the portal, `Invoke-SubscriptionAnalysis.ps1` or `python -m scripts.subscription_analysis` |
| Docker stack | Settings → Governance Configuration → *Analysis Settings* (admins); used from the next scan. Findings of a check that is switched off are suppressed with the reason; findings a clean scan no longer reports are resolved |
| One run | `--config file.json` overrides both |

| Setting | Default | Effect |
|---|---|---|
| `naming_convention_enabled` | on | Naming convention check (`naming_convention_violation`). Most resources cannot be renamed in place - switch off unless a naming standard is being enforced |
| `required_tags_check` | off | One `missing_required_tags` finding per resource without the required tags. Off: tag coverage is still the cost-allocation KPI in the summary, without thousands of findings |
| `display_currency` | Billing currency | Docker web app: amounts in the Azure invoice's currency (e.g. CHF) at Cost Management's own rate (billing cost / USD cost, last 30 days, refreshed with the estate inventory), or USD. The local report always shows the billing currency with USD alongside |
| `ai_reasoning`, `ai_endpoint`, `ai_deployment`, `ai_max_findings` | off | The optional AI review of thinking mode (see *Thinking mode*) |
| `sensitive_data_tags` | empty | `Tag=value` pairs marking confidential data (e.g. `DataClassification=Confidential`). An open storage account, Key Vault, database or AI endpoint carrying one gets a private-endpoint recommendation even when it is idle (see *Network access: the target architecture*) |
| `defender_recommendations` | off | Import Defender for Cloud recommendations as findings. Off: the report shows them as a summary by severity, each linked to Defender for Cloud, where triage, exemptions and owners are tracked |
| `defender_plan_recommendations` | off | Include Defender's paid plan-enablement recommendations |
| `defender_plan_coverage` | off | One finding listing the Defender plans on Free with the cost of each on this subscription |
| `report_unused_providers` | off | `resource_providers_registered_unused` for niche providers only (core services and the governance baseline are never listed); informational |
| `blocked_resource_providers` | classic providers | Providers that must not be registered |
| `engineering_hourly_rate_usd` | not set | Turns effort hours into a one-off amount |
| `ai_gateway_sku` | Basic v2 | API Management tier priced into the AI gateway recommendation (Basic v2, Standard v2, Developer) |

### Network access: the target architecture

For storage accounts, Key Vaults, SQL servers, Cosmos DB and AI accounts open to all networks the scanners
recommend the **target architecture** (Well-Architected / Cloud Adoption Framework landing zone) - not the cheapest
control - and rank every other option (`scanners/base/access_need.py`):

| Situation (Resource Graph + 30 days of metrics) | Target | Interim step |
|---|---|---|
| Data in active use (production, non-production or unknown) | Private endpoint + private DNS, public access off | When the endpoint needs prerequisites (no subnet in the region, no `privatelink.*` zone in the tenant, callers without a private path): a service endpoint for VNet callers, else IP rules - closes the internet exposure today, free |
| Confidential-data tag (`sensitive_data_tags`) | Private endpoint, always | as above |
| 0-10 data operations / API calls in 30 days - it only keeps data | Public access off: no network path at all (stronger than a private endpoint nobody uses) | - |
| Holds VM boot diagnostics | Managed boot diagnostics, then public access off / delete | - |
| Written only by Azure services | Default Deny + trusted Microsoft services | - |
| Tagged `arg-public` (external clients, static website, CDN origin) | Public, hardened (Entra ID, short-lived SAS) | - |

Each option is listed with its role (target / interim / alternative / not suitable), the exposure that remains
after it, its run cost and why it does or does not fit this resource. Severity: high for production data in use
and confidential data, medium when the environment is unknown, low for non-production, idle data and endpoints
public by design. The README's *Open endpoints - target architecture* line summarises them; *Recommendations that
add run cost* lists what the targets cost.

### Thinking mode

**Built-in reasoning (always on, `reasoning.py`).** Every finding carries *How ARG reasoned*: what was observed
(the resource's own values - usage, configuration, callers, private DNS, environment), what changes the answer here
(environment, prerequisites, other findings on the same resource, when it is not needed), every option considered
with its role, the recommendation, the risks specific to the finding type, how to verify the fix (CLI and metrics)
and the confidence with its reason. Shown in the deep dives, `raw/findings.json` and the Docker finding detail.

**AI review (optional, `thinking.py`, setting `ai_reasoning`).** An Azure OpenAI model in the company tenant reviews
the subscription like a principal architect: challenges recommendations where the evidence points elsewhere, finds
themes across findings (one root cause, sequencing) and asks the owner what the data cannot answer. It is told to
cite resources and numbers and never to give generic advice.

| Setting | Meaning |
|---|---|
| `ai_reasoning` | Switch the AI review on (off by default) |
| `ai_endpoint` | `https://<name>.openai.azure.com` (or `*.cognitiveservices.azure.com`, `*.services.ai.azure.com`); other hosts are refused |
| `ai_deployment` | The chat model deployment (JSON output), e.g. `gpt-4.1` |
| `ai_max_findings` | Findings sent per subscription (default 30, most severe / most expensive; tag and naming hygiene excluded) |

What is sent: subscription name, environment, cost by service, and per finding its type, severity, resource name and
type, evidence facts and the built-in recommendation and options. GUIDs are replaced by aliases; tag values and
secrets are never sent. Sign-in: Entra ID - the `az login` session locally, the service principal in Docker (it
needs *Cognitive Services OpenAI User* on the resource) - or the `ARG_AOAI_API_KEY` environment variable. One request
per subscription, typically 6-15k input and 2-4k output tokens. Output: an *AI review* line in the README,
`05-deep-dive/thinking.md` (summary, themes, a verdict per finding, questions for the owner) and an *AI review* block
per finding (deep dives, Docker finding detail). A failed call never fails the report.

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
VMs by average-CPU band and the **right-sizing candidates**: running, 4+ vCPU, under 5 % average CPU, a busiest hour
under 40 % **and** under 40 % memory used (one size down halves the RAM and doubles the load). Network virtual appliances (FortiGate, Palo Alto, Check Point, Cisco,
... detected from the Marketplace image) are never listed - they are vendor-sized and licensed per vCPU - and the
excluded counts are shown. A peak of 80 % or more, or missing memory data, is noted per VM. VM costs are what Cost
Management attributes to the VM: compute covered by a reservation or savings plan shows close to 0, so check the
commitment before counting a saving.

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
| App Service plans | `CpuPercentage`, `MemoryPercentage` (plus an hourly batch: busiest hour, P95, burst hours) |
| Web / Function apps, slots | `Requests`, `Http5xx` (failed), `FunctionExecutionCount` |
| Storage accounts | `Transactions` (plus a second batch split by `ApiName` to subtract housekeeping), `UsedCapacity` (latest), `Egress` (transferred) |
| SQL databases / elastic pools | `cpu_percent`, `connection_successful`, `storage_percent` |
| PostgreSQL / MySQL flexible | `cpu_percent`, `memory_percent`, `storage_percent` |
| Cosmos DB | `TotalRequests` (Count), `NormalizedRUConsumption` peak |
| Redis | `serverLoad` (as CPU), `usedmemorypercentage`, `connectedclients` |
| AKS | `node_cpu_usage_percentage`, `node_memory_working_set_percentage` |
| Container apps / registries | `Requests`, `Replicas` / `SuccessfulPullCount`, `SuccessfulPushCount` |
| Key Vault, AI Services, AI Search | `ServiceApiHit` / `TotalCalls` + prompt/generated tokens / `SearchQueriesPerSecond` |
| Service Bus, Event Hubs, IoT Hub, Event Grid, SignalR | incoming messages / events (+ bytes, active messages, devices) |
| Data Factory, Logic apps, Automation | succeeded / failed runs, jobs |
| Application Gateway, APIM, Front Door, Firewall, Load balancer | requests / capacity, data processed, bytes |
| Data Explorer | `CPU`, `IngestionUtilization` |

### VM right-sizing (`vm_rightsizing_opportunity`)

A resize is suggested only when the new size passes **every** check below - the aim is no false positives. Each
VM gets two candidates: Azure Advisor's own target (when Advisor has one) and one size down in the same family
(half the vCPUs and memory, never below 2 vCPU). The cheapest candidate that passes wins; an Advisor target that
fails is named in the finding with the check it failed (for example memory that would reach 88 % on Advisor's
burstable size).

| Check | Rule | Source |
|---|---|---|
| CPU on the target | P95 of 30-minute CPU peaks at most 40 %, P99 at most 80 %, over 30 days | Azure Advisor's user-facing limit (40 %); P99 and 30 days added |
| Memory on the target | P99 of memory used (from the lowest available memory per 30 minutes) at most 60 % | Azure Advisor, user-facing |
| Burstable target (B-series) | Projected average at most 80 % of the size's base CPU performance, P95 at most twice the baseline | Azure Advisor burstable rule; baselines from the Microsoft Learn Bv1 / Bsv2 / Basv2 pages |
| Disk | VM cached / uncached IOPS and bandwidth consumed %, projected on the target's limits, at most 40 % at P95 | Advisor's performance metrics |
| Network | P95 outbound at most 100 Mbps | Fixed ceiling (bandwidth is not in the SKU catalogue) |
| Compatibility | Same Premium Storage, Accelerated Networking when a NIC uses it, CPU architecture, Hyper-V generation, disk / NIC counts, not restricted in the region / zone, a temp disk when the current size has one | Advisor rules; Azure resize limitations |
| Data | At least 90 % of the 30 days measured; VM at least 30 days old | Added |
| Never suggested | Network virtual appliances, Spot, scale-set / AKS / Databricks VMs, ephemeral OS disks, `arg-ignore` / `arg-reserved` tags | Advisor's own list of cases where resizing does not apply |
| Value | Retail pay-as-you-go difference; capped at what the VM actually costs (the title, severity and savings register show the capped value, and under USD 10/month is not suggested), and a VM covered by a reservation or savings plan says so (the resize frees commitment rather than cutting its invoice line); end-of-life series are named | Advisor's limitation note |

The finding states the utilisation now and projected on the new size, the monthly and yearly value, whether Azure
Advisor agrees, and the steps (owner confirmation, maintenance-window resize with a restart, one week of
monitoring). Resizing within an availability set may require deallocating the whole set.

**Hourly profile.** For every CPU, memory and percentage metric a second batch reads hourly points: the **CPU
busiest hour** column, P95 and burst hours in the CPU tooltip, the memory busiest hour, and "... busiest hour N %"
for capacity / RU / ingestion percentages in the Usage column. A 30-day average alone hides busy hours; a daily
maximum alone is a one-minute spike.

**Idle** means the type's activity metric was zero for 30 days. Storage uses the same rule as the idle-storage
scanner: `Transactions` split by `ApiName`, platform housekeeping (`GetBlobServiceProperties`, `ListContainers`,
preflight, ~120 calls a month on every account) subtracted, at most 10 real data operations (at most 200 transactions
when the split is unavailable); an idle account holding more than 1 GB is **Dormant data** (tier or archive it, don't
delete it). Container apps must also have scaled to zero, and web apps must also have no function executions
(timer/queue-triggered functions get no HTTP requests). Never idle: SQL `master` / system databases and geo / standby
replicas (DR copies take no connections until a failover); resources with failed runs or 5xx errors (something still
calls them); registries that received pushes. Use the **Activity** breakdown
to list idle resources; the markdown overview adds a usage table per type and the costliest idle resources. A batch
that fails is retried metric by metric; global resources (Front Door) use the per-resource metrics
API. Azure throttles metric reads per caller, so a full refresh of ~2,500 measured resources takes 3-4 minutes
(more parallelism does not help). Treat idle as a strong hint and confirm with the owner before deleting.

The report scanner `unused_storage_account_scanner` applies the storage rule per account: empty idle accounts are
`unused_storage_account` (saving = the account's 30-day cost), idle accounts with data are `dormant_storage_data`
(saving = cost minus the same data in the Cold tier, an estimate), and accounts holding the VHDs of a VM are skipped.
The **AI** deep-dive page lists every AI account with its 30-day cost, top meters and model deployments; every other
deep-dive page shows the area's costliest resources.

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
- **Empty cells** show a muted `-`; hover it for the reason (no SKU for this type, no activity metric, not a VM...).
  **Last 30 d** is `0` for resources of analysed subscriptions that had no charge, and `-` only where the
  subscription has no report yet. **Environment** comes from tags, then the resource / resource-group name, then
  the subscription name.

Suggestions and cost come from the latest report of each subscription; subscriptions that were never analysed
still appear in the inventory, without suggestions.

### Architecture diagrams

The estate refresh also collects, read-only through Resource Graph, the management-group hierarchy
(`managementGroupAncestorsChain`), the Azure Policy assignments on management groups and subscriptions (effect,
enforcement, and the parameters of the built-in *Allowed locations*, *Allowed resource types* and *Not allowed
resource types* policies) and every VNet with its address space, subnets and peerings. `diagram.py` draws two views
from it with the official Microsoft Azure architecture icons (`scripts/subscription_analysis/azure_icons/`, used
unchanged under Microsoft's icon terms - see its `NOTICE.md`):

| View | Shows |
|---|---|
| Tenant | Tenant root -> management groups -> subscriptions (grid per group: environment colour, resources, 30-day cost); per group its policy assignments - deny, allowed locations, allowed / not allowed types, DeployIfNotExists / Modify, initiatives; a badge for assignments made on a subscription itself (Defender for Cloud's own *ASC ...* assignments left out) |
| Subscription | Management-group path; effective policy - what is allowed, what is not, deny policies and what in use violates them; VNets with peerings (a peered VNet in another subscription opens that one); every resource group with its services, counts and cost |

A second layer, **Network** (`network.py`, `network_diagram.py`), uses the same refresh: subnets with NSG, route
table (and the 0.0.0.0/0 next hop), NAT gateway, delegation and service endpoints; private endpoints and their
targets; which VM sits in which subnet and whether it has a public IP; gateways, firewalls, Bastion, App Gateway,
load balancers, AKS, Container Apps, API Management and flexible databases; public IPs; and the network exposure of
21 PaaS and app types (public network access, firewall default action and rules, private endpoints, VNet
integration).

| View | Shows |
|---|---|
| Tenant network | Hubs (gateway / firewall subnet with peerings, or 3+ peerings) with their spokes, peerings without a hub, isolated VNets; peering state; address-space overlaps between connected VNets (and isolated VNets that reuse ranges); the VNet hosting the default-route NVA / firewall |
| Subscription network | Internet and on-premises entry points; each VNet with its subnets and what runs in them - VMs coloured by power state (amber deallocated, red stopped but billed), private endpoints, gateways and platform services - with NSG / route / NAT / service-endpoint / delegation badges; every PaaS service and app grouped by exposure, with lines from private endpoints to their services and from apps to their VNet-integration subnets |

Service Bus, Event Hubs and Redis keep their firewall rules in child resources Resource Graph does not return; they
are shown as *rules not in Resource Graph* rather than as open.

Local portal: **Architecture** (Resources & policy / Network). Docker UI: **Architecture** (admins),
`GET /estate/architecture.svg[?subscription=][&view=network]`. The overview pages (local home page, Docker
*Overview* for admins, `GET /estate/telemetry`) chart the same inventory: spend by category, service and
subscription, VM power state and CPU bands, data services and apps by exposure, VMs with public IPs, private
endpoints, tag coverage and suggestions by severity.
Both: wheel or buttons to zoom, drag to pan, search, click a subscription to open it, *Export SVG* / *Export PNG*
(PNG up to 2x, at most 16,000 px on the long side). Effects inside initiatives are not resolved in these two views:
an initiative is shown by name, and deny counts only include assignments whose own `effect` parameter is a deny (the
Landing zone view below resolves them).

### Landing zone view

A third layer, **Landing zone** (`landing_zone.py`, `landing_zone_diagram.py`, `policy_catalog.py`), compares the
tenant with Microsoft's **Azure Landing Zones** reference - the
[Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library) (MIT), one pinned release kept
unchanged in `scripts/subscription_analysis/alz_library` (`SOURCE.md` names it; update with
`python -m scripts.update_alz_library [release]` and review the diff). It answers what AzAdvertizer / Azure Governance
Visualizer answer, for this tenant:

| Part | What it shows |
|---|---|
| Structure | Every management group with its ALZ archetype (intermediate root, platform, connectivity, identity, management, security, landing zones, corp, online, local, sandbox, decommissioned), next to the ALZ reference tree; which archetypes are missing; subscriptions outside the intermediate root (no root guardrail reaches them); environment-split landing zones; where the hub networks live |
| Controls | Each ALZ policy assignment of an archetype at the groups mapped to it: **in place**, **audit only** (ALZ denies or remediates, the tenant audits or does not enforce), **on every / some subscriptions** (assigned per subscription, e.g. Defender's default initiative), **similar** (one of your policies reads most of the same distinctive resource properties - named, to confirm), **disabled**, **missing**. ALZ initiatives are compared policy by policy |
| Policy depth | Per management group: each assignment (initiative or policy, number of policies, built-in / custom, effects, enforcement), non-compliant resources, exemptions; deprecated policies in force; exemptions without an end date or expired; assignments made on subscriptions directly |
| Connectivity | Hubs - Azure Firewall or NVA firewall VMs, firewall policy, gateways / Route Server, Bastion, DNS resolver (hub or peered), DDoS - and per spoke: peered to a hub, default route (route tables, or learned over BGP from the hub's Route Server / gateway), DNS that resolves private endpoints, DDoS, subnets without NSG |

How the archetype is chosen: the `landing_zone_mapping` setting (one `management group = archetype` per line,
display name or ID; Settings > Analysis settings), else the group's name, else its position - the tenant root's
child holding most subscriptions is the intermediate root, its children with subscriptions are landing zones, groups
below take their parent's. Name your corp (private, hub-connected) and online (Internet-facing) groups in the setting -
ALZ gives them different policies.

What is collected (read-only, with the estate refresh): every policy assignment, custom definition and initiative,
exemption and compliance state through Resource Graph; the built-in definitions and initiatives in one paged ARM
list each (Resource Graph does not return them; about 7 s, cached 12 h). Every assignment is resolved to its policies
with the effect each runs with (assignment parameter > initiative default > definition default). Stored compactly -
assignments with the same definition and parameters share one profile, only referenced definitions are kept -
locally in `reports/_estate/policy.json` (about 1 MB for 200 assignments) and in the Docker snapshot (left out of
`GET /estate`). Routes: local `/architecture?view=landing`, `/api/landing-zone.html`, `/api/landing-zone.md`; Docker
`GET /estate/architecture.svg?view=landing`, `GET /estate/landing-zone`.

---

### Cheaper region (`cheaper_region_available`)

For every running VM (not Spot, not an AKS node) and every Premium v2 / v3 App Service plan, the pay-as-you-go list
price of the same size is compared across the regions of its **geography** - Europe (West / North Europe, Sweden
Central, Germany West Central, France Central, Switzerland North, UK South, Norway East, Italy North, Poland Central,
Spain Central), North America and Asia Pacific - so data residency and latency stay comparable. A region is
suggested when it is **at least 10 % cheaper** and the difference is **at least USD 20/month**, valued at the
resource's own amortized price (5a-2). If an **"Allowed locations"** Azure Policy applies to the subscription (directly
or from a management group, enforced), only its regions are compared.

The finding lists up to three cheaper regions with their hourly price and difference, and says what a move involves:
data residency and compliance, latency to users and to dependent services (which may have to move too), inter-region
egress, zones and quota for the size, and region-bound reservations (savings plans are not). It is a **wave 3
(structural)** suggestion - for new deployments, rebuilds and disaster-recovery placement - so its saving is shown on
the finding but not added to the headline wave 1 + 2 savings; in the Docker UI it is marked **Region move** and kept
out of the potential-savings total. Tag a resource `arg-region-fixed` to skip it (e.g. pinned by data residency).
Settings: `region_min_saving_pct` (10), `region_min_saving_usd` (20), `region_excluded` (list), `region_groups`
(replace the geographies). It appears in the report (03 cost drivers, 05 deep dive cost-finops), in the Estate
**Suggestions** view of the local portal and on the Docker UI's Findings and Cost Savings pages.

## 6. What it analyses

75 scanners across network, compute/App Service, database, storage, security, identity, governance/observability
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
  "ai_gateway_sku": "Basic v2", "ai_gateway_saving_ratio": 0.15,
  "naming_convention_enabled": true, "defender_plan_recommendations": false, "defender_plan_coverage": false,
  "report_unused_providers": true, "blocked_resource_providers": ["Microsoft.ClassicCompute"],
  "engineering_hourly_rate_usd": 100,
  "arm_concurrency": 8, "timeout_seconds": 900
}
```

The settings in [5a-5](#5a-5-settings) can be kept in `<reports-dir>/settings.json` (the portal's Settings page)
instead; `--config` wins for a single run.

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

## Local UI and deployment updates (2026-09-26)

The local portal now includes a workspace overview, responsive table containers, keyboard focus/skip navigation,
selection counts across filters, and visible analysis/network errors. In Estate, Resources/Suggestions controls
announce the selected view; resource rows expand with Enter or Space. Simultaneous inventory refresh requests
share one collection. An interrupted browser connection does not imply the server-side analysis stopped.

Launchers reuse an unchanged dependency environment based on the requirements SHA-256. To force verification
after manually changing packages, remove `.venv-local/.requirements-local.sha256` before the next launch.

See [local setup](local-development.md), [architecture](architecture.md), [Docker deployment](docker-deployment.md),
and the [merge/validation record](merge-validation.md) for the two execution modes and tested boundaries.
