# ARG - Project Memory

Short, durable facts for whoever works on this repository next (people or AI assistants). Keep it current: update it
in the same change that makes an entry wrong.

## Who and where

- **Author:** Junaid Ahmed - [jahmed.cloud](https://jahmed.cloud) · [github.com/jahmed-cloud/ARG](https://github.com/jahmed-cloud/ARG).
- Two ways to run ARG: the **Docker stack** (backend, worker, React UI, service principal) and the **local tooling**
  (`scripts/subscription_analysis` CLI + `scripts/local_portal`, the user's own `az login`, no service principal).
- Local reports go to `reports/` (git-ignored: resource IDs, IPs, principal IDs); the estate is in `reports/_estate/`.

## Git rules

- Every commit is authored **and** committed as `Junaid Ahmed <jahmed.cloud@outlook.com>`, conventional prefix
  (`feat:`, `fix:`, `docs:`), bullet body, **no `Co-authored-by` trailer**. Push to `origin main`.
- The GitHub contributors list must show only `jahmed-cloud`.
- Before committing a feature: update CHANGELOG, README, `docs/subscription-analysis.md`, the PRD, ROADMAP when
  relevant, the Copilot skill (`.github/skills/arg-subscription-analysis`) and this file.

## Running it

The full cycle (sign in, fresh start, estate, all subscriptions, portal, tests, git) is in [local-run.md](local-run.md).

- `az login` (Reader + Cost Management Reader + Security Reader on each subscription).
- Portal: `scripts/Start-LocalPortal.ps1` → `http://127.0.0.1:8765` (login from `ARG_PORTAL_USER` /
  `ARG_PORTAL_PASSWORD`, or a one-time password printed at start). Sessions are in memory; restart after Python
  changes. A `#hash` change in the browser does not reload the page.
- Many subscriptions: `python -m scripts.subscription_analysis --all --tenant <id> --parallel 3`. Estate only:
  `--all --tenant <id> --estate` (a few minutes including usage metrics).
- Tests: `python -m pytest tests/unit -q` (offline); lint: `ruff check --select F,E9 scripts tests`.
- Docker: the worker runs the same scanner modules, so images rebuilt with `./build-push.sh` give the same
  findings as the local reports.

## Decisions worth remembering

- **Cost** is Cost Management actual cost over rolling 30 days / 12 months, per resource and meter, in the billing
  currency. Savings are computed in USD and converted at the implied rate. Lumpy up-front charges (SaaS,
  reservations) switch the forecast to the 12-month average.
- **Usage** is Azure Monitor platform metrics, last 30 days, daily points (no agents). Scanners use per-resource
  calls; the estate uses the **metrics batch API** for 31 types (`USAGE_SPECS` in `estate.py`). Idle = zero activity
  (storage ≤ 10 data operations after subtracting housekeeping by `ApiName`; idle + > 1 GB = dormant data, not
  delete; container apps also scaled to zero, web apps also no function executions; never idle: SQL master, DR
  replicas, failed runs). Right-sizing needs < 5 % CPU **and** < 40 % memory and skips NVAs (image offer). VM cost
  is actual cost, so savings-plan / reservation-covered compute shows ~0.
- **Estate** = one Resource Graph query + Compute SKU catalogue + usage, joined with report findings and cost. Tag /
  naming findings are "hygiene", counted apart from actionable suggestions. VM / Arc extensions are hidden by default
  and named `vm › extension`. New per-type facts go into `RESOURCE_DETAILS` (`cfg` pack) → `_profile()`.
- **Utilisation** = average + busiest hour + P95 + one-minute peak / burst hours (hourly points,
  `azure_api.point_profile`). Saturated needs a busy hour (80 %+); one-minute peaks are bursts. Over-provisioned
  plans: P95 < 10 %, busiest hour < 30 %, memory < 40 %.
- **VM right-sizing** (`vm_rightsizing_scanner`) = Advisor's documented rules with the user-facing limits for all
  VMs (target CPU P95 <= 40 %, memory P99 <= 60 %) + disk / network / capability / 30-day checks; candidates are
  Advisor's target and one size down; value capped at actual cost. No false positives beats more suggestions.
- **No emoji** in code, reports, docs or UI - plain words ("Critical", "Warning:").
- **No blank cells:** reports drop all-blank columns (`md_table(drop_empty=True)`), show `0.00` for no charge
  (`Model.cost30`) and an Impact label; the Estate page renders empty values as a muted `-` with a reason tooltip.
- **Report folders** are keyed by subscription ID (`.subscription-id`); duplicate display names get `_<id8>`.
- The analysis is **read-only**. Remediation commands are for review; never execute them.

## Things that bit us

- Cost Management rejects custom periods longer than 364 days.
- KQL: `time` is reserved - `pack('time', ...)` gives a bare `ParserFailure`; bisect `case()` branches to find it.
- Cosmos DB `TotalRequests` supports only the Count aggregation.
- The metrics batch API is throttled per caller (~6 s per call); more than ~16 in parallel does not help.
- Network virtual appliances report ~0 available memory, so they show ~100 % memory used; `estate.is_nva` keeps
  them out of right-sizing.
- Storage `Transactions` totals hide real use: ~120 housekeeping calls a month on every account. Split by `ApiName`
  (`azure_api.storage_data_operations`, `top=100`); heavy `Unknown` traffic is real.
- SQL `master` and geo / standby replicas have zero connections by design - never idle.
- PowerShell `$args` is automatic - a local `$args = @(...)` passed to `Start-Process` becomes empty.
- Resource Graph queries must page with skip tokens (`query_resource_graph`), otherwise results stop at 100 / 1,000.
