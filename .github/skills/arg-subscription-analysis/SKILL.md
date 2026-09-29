---
name: arg-subscription-analysis
description: Runs Azure Resource Guardian (ARG) subscription analyses with the user's own az login, via the CLI or the local portal. It produces per-subscription FinOps, security and architecture reviews as markdown (and optional PDF) under reports/<subscription>/, and explains or summarises them. Use when the user asks to analyse, review, audit or cost-check an Azure subscription with ARG, start or troubleshoot the ARG local portal, export a report to PDF, find where ARG reports are written, summarise an ARG report, explain idle/unused detection, or add or tune ARG scanners.
---

# ARG Subscription Analysis

Read-only analysis of Azure subscriptions using the user's **`az login`** session. There's no service principal,
Docker or database. Output is one folder of markdown per subscription, plus an optional PDF.

## Quick start

```powershell
az account show --query "{user:user.name, tenant:tenantId}" -o table   # must be signed in; else: az login
<ARG repo>\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription '<name-or-id>' -Pdf summary   # any folder
<ARG repo>\scripts\Start-LocalPortal.ps1                                                       # http://127.0.0.1:8765
```

Reports land in `<ARG repo>\reports\<subscription>\` (the PDF is `report-summary.pdf` there), with the index at
`<ARG repo>\reports\README.md`.

## Workflow: analyse subscriptions

- [ ] Confirm `az login` is active and on the right tenant (`az login --tenant <id>`). Conditional Access may force
      a new login about hourly (`AADSTS70043`).
- [ ] Confirm **Reader + Cost Management Reader + Security Reader** on each target subscription.
- [ ] Run the launcher with `-Subscription a, b` or `-All` (optionally `-ReportsPath`, `-TenantId`, `-SkipCost`,
      `-Pdf summary|full`). With plain python, **cd to the repo root first**:
      `python -m scripts.subscription_analysis -s <name-or-id> [-s …] | --all [--pdf]`.
- [ ] Expect 3-4 minutes for about 200 resources, about 15 for 2,000. `429 … retrying` is normal.
- [ ] Check `05-deep-dive/README.md` → *Collection Warnings* for missing roles or skipped scanners.
- [ ] Whole tenant: add `--parallel 3` (`-Parallel 3`). For the cross-subscription **estate inventory** (types, sizes,
      SKUs, regions, vCPU/RAM, 30-day usage and idle flag, suggestions, with filters) use the portal's **Estate** page or `--all --estate` (`-Estate`, ~4-5 min);
      output in `reports/_estate/`.

## Workflow: local portal and PDF

- [ ] Portal login: `ARG_PORTAL_USER` / `ARG_PORTAL_PASSWORD` (a one-time password is printed if unset). It **never**
      signs in to Azure. The process must keep running (`ERR_CONNECTION_REFUSED` means it isn't).
- [ ] **Analyze** subscriptions, watch the job table, then open the report.
- [ ] PDF: **Export PDF (summary|full)** on any report page, or `--pdf-only -s <name> --pdf summary` (no Azure calls).
      Uses the local Edge/Chrome headlessly. The fallback is `report-<detail>.html` → Print → Save as PDF.

## Workflow: summarise or explain a report

1. `reports/<subscription>/summary.json` has the totals. `README.md` has the summary and actions.
   `03-cost-drivers/README.md` covers cost.
2. Quote findings by `F-nnn`. Details and CLI commands are in `05-deep-dive/<area>/README.md`, and the data is in
   `05-deep-dive/raw/findings.json`.
3. Idle logic uses 30-day metrics: storage ≤ 10 data operations after subtracting housekeeping (split by `ApiName`), > 1 GB idle = dormant data; SQL 0 successful connections and no hour above 5 % CPU/DTU; saturation needs a busy hour (80 %+), one-minute peaks are bursts. Utilisation shows average, busiest hour, P95 and burst hours
   (connections but low CPU = `sql_database_underutilized`); IoT 0 devices and messages; vaults 0 protected items.
   Marketplace SaaS (`marketplace_saas_*`) uses status + term + 12-month cost: unsubscribed leftovers, suspended,
   term ending within 90 days, material commitments. Lumpy (up-front) spend switches the forecast to the 12-month average.
   Recommend confirming with the owner before deleting anything.
4. Costs are **amortized** (reservations and savings plans spread over the resources that use them); the invoiced
   (actual) amount is shown next to it. Savings use each resource's own amortized cost (`saving_basis` in the
   evidence); list prices only when a resource has no cost data. Budgets are compared with the invoice on their own scope and filter
   (resource group, meter), never with the whole subscription. VM right-sizing (`vm_rightsizing_opportunity`) is
   validated, not estimated: the new size keeps CPU P95 ≤ 40 %, memory P99 ≤ 60 %, disk / network headroom and every
   hardware feature over 30 days. Section 7 of `01-current-findings` lists **resource providers** (registered =
   accepted, not registered) against usage and allow / deny resource-type policies (`resource_type_denied_by_policy`).
5. State estimates as estimates (savings are USD converted to the billing currency; the critique's "why" is inferred).

## Guardrails

- Never execute remediation commands from a report without explicit user approval. The analysis itself is read-only.
- Never commit `reports/` (it holds resource IDs, IPs and principal IDs; it's git-ignored).
- Don't create service principals or change RBAC to make a run work. Report the missing role instead.
- Graph (Entra ID) scanners are skipped locally, and that's expected.

## More

- Options, layout, thresholds, troubleshooting: [REFERENCE.md](REFERENCE.md)
- User guide `docs/subscription-analysis.md` · runbook `local-run.md` ·
  scanners `docs/scanner-catalog.md`
- Adding or tuning scanners: `CONTRIBUTING.md` → *Adding a scanner*
