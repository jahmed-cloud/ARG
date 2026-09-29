# Local Run - Running ARG End to End

End-to-end runbook for running Azure Resource Guardian (ARG) on a workstation: sign in, refresh the estate,
analyse every subscription, look at the results in the local portal, and keep the code in step. No Docker,
database or service principal is needed - everything uses your own `az login` session and is **read-only** in Azure.

Step-by-step portal details (login variables, VS Code, stopping, resetting the virtual environment) are in
[docs/run-locally.md](docs/run-locally.md). What every report section and metric means is in
[docs/subscription-analysis.md](docs/subscription-analysis.md).

## 1. What you need (once)

| Item | Why |
|---|---|
| Windows 11 with PowerShell 7 (`pwsh`), or Linux / macOS with bash | The launchers |
| Python 3.12 on `PATH` | The launchers create `.venv-local` from it on first run |
| Azure CLI (`az`) | Your sign-in; ARG reuses its token |
| Microsoft Edge or Google Chrome | Only for PDF export |
| **Reader**, **Cost Management Reader** and **Security Reader** on every subscription | Inventory, metrics, cost, Defender |

Portal login (a local username / password that only protects the portal, not Azure) - set it once as user
environment variables, then open a **new** terminal:

```powershell
[Environment]::SetEnvironmentVariable('ARG_PORTAL_USER', 'admin', 'User')
[Environment]::SetEnvironmentVariable('ARG_PORTAL_PASSWORD', '<choose-a-password>', 'User')
```

## 2. Sign in to Azure

```powershell
az login --tenant <tenant-id>
az account show --query "{user:user.name, tenant:tenantId}" -o table
```

Conditional Access can expire the CLI token about **every hour**, even in the middle of a run. ARG then stops with
a clear "sign-in expired" message instead of writing a partial report - run `az login` again and restart the step.

## 3. Fresh start (the full cycle)

Use this after pulling or changing code, or when the reports should reflect today's state of Azure.

**3.1 Stop what is running.** Close the portal window (Ctrl+C) and any analysis still running. To find leftovers:

```powershell
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -match 'scripts\.(local_portal|subscription_analysis)' } |
    Select-Object ProcessId, CommandLine
# Stop-Process -Id <ProcessId>   # for each one you want to end
```

**3.2 Start the portal** (new window, keeps running; picks up the current code):

```powershell
.\scripts\Start-LocalPortal.ps1              # http://127.0.0.1:8765, add -NoBrowser to skip opening the browser
```

**3.3 Refresh the estate** - one Resource Graph query across every subscription, plus VM specs and 30-day usage
metrics (about 5 minutes for 12,000 resources):

```powershell
.\scripts\Invoke-SubscriptionAnalysis.ps1 -All -TenantId <tenant-id> -Estate
```

**3.4 Analyse every subscription** - all scanners, Cost Management and the markdown / HTML reports (about 40 seconds per
subscription; `-Parallel 3` runs three at a time). Cost Management "429 - retrying" warnings are normal throttling:

```powershell
.\scripts\Invoke-SubscriptionAnalysis.ps1 -All -TenantId <tenant-id> -Parallel 3
```

At the end the estate is re-joined with the new findings and costs, and `reports/README.md` (the index) is rewritten.
The portal picks the new files up on the next page reload - no restart needed for data.

**3.5 One subscription only** (after a fix, or to check a single finding):

```powershell
.\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription '<subscription-id-or-name>' -Pdf summary
```

Python equivalents, from the repository root:

```bash
python -m scripts.subscription_analysis --all --tenant <tenant-id> --estate
python -m scripts.subscription_analysis --all --tenant <tenant-id> --parallel 3
python -m scripts.subscription_analysis --subscription "<id-or-name>" --pdf summary
python -m scripts.local_portal --port 8765
# options: --reports-dir DIR  --scanners a,b  --config thresholds.json  --skip-cost  --pdf full
```

## 4. Where the results are

```
reports/                              git-ignored: contains resource IDs, IPs and principal IDs
├── README.md                         index of every analysed subscription
├── _estate/                          README.md (overview), estate.json (portal), inventory.json (raw)
└── <subscription>/                   README.md, 01-... to 05-deep-dive/, raw JSON, report-full.html / .pdf
```

In the portal: **Subscriptions** (analyse, open reports, export PDF) and **Estate** (every resource, filters,
suggestions, CSV). An empty cell on the Estate page shows a muted `-`; hover it for the reason.

## 5. Reading utilisation correctly

The Azure portal chart and ARG can both be right. A plan that idles with nightly one-minute bursts has a
**30-day average** of 1.5 % and a **daily maximum** of 100 %. ARG therefore shows, for CPU and every percentage
metric:

| Value | Meaning |
|---|---|
| Average (30 d) | The mean over the month |
| Busiest hour | The highest hourly average - what "busy" means for sizing |
| P95 | 95 % of hours are at or below this |
| 1-minute peak and burst hours | The highest single minute, and in how many hours a minute reached 90 % |

"Saturated" findings need a busy **hour** (80 %+); one-minute spikes are reported as bursts.

**Costs are amortized** (reservations and savings plans spread over the resources that use them); the invoiced
amount is shown next to it and budgets are compared with the invoice, each on its own scope and filter. Section 7
of *01 - Current findings* shows the subscription's **resource providers** (registered = accepted, not registered)
against what it uses, and any allow / deny resource-type policy.

**VM right-sizing suggestions** (`vm_rightsizing_opportunity`) are validated, not estimated: the new size must keep
CPU P95 at most 40 %, memory P99 at most 60 %, disk and network headroom and every hardware capability the VM uses,
over 30 days - Azure Advisor's rules for user-facing workloads, applied to every VM. Advisor's own suggestion is
checked the same way and named when it fails. The estate's average-CPU list is only a screening list. Details:
[docs/subscription-analysis.md](docs/subscription-analysis.md).

## 6. After changing code

```powershell
.\.venv-local\Scripts\python.exe -m pytest tests/unit -q     # all offline, about 10 s
ruff check --select F,E9 scanners scripts tests
.\.venv-local\Scripts\python.exe -m scripts.generate_scanner_catalog   # when a finding type changed
```

Python changes need a portal restart (3.1 + 3.2); JavaScript / CSS and report data only need a browser reload
(a real reload - a `#hash` change does not reload the page).

## 7. Contributing changes

Run the tests and lint (section 6), keep generated text free of emoji and em / en dashes, and follow
[CONTRIBUTING.md](CONTRIBUTING.md).

## 8. Docker vs local

The Docker stack (backend, Celery worker, frontend) runs **the same scanner modules** with a service principal, so
its findings match the local reports once its images are rebuilt from the same code (`./build-push.sh`, or
`docker compose up -d --build`). The markdown / HTML reports and the Estate page are local-tool features.

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| "sign-in expired" / `AADSTS70043` mid-run | `az login` again, re-run the step (finished subscriptions keep their reports) |
| `az account get-access-token` hangs | Your session expired; ARG times out after 60 s. Close stray `az` windows, `az login` |
| `429 - retrying in 38s` | Normal Cost Management / metrics throttling; the run waits and continues |
| Port 8765 already in use | An old portal is still running - see 3.1 |
| Portal shows old behaviour after a code change | Restart the portal (3.1 + 3.2), then reload the page |
| Portal login fails after setting variables | Open a new terminal (user variables only reach new processes); names are case-sensitive |
| Estate cost "-" | That subscription has no report yet - run 3.4 or 3.5 |
