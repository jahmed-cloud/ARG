---
name: arg-subscription-analysis
description: Runs Azure Resource Guardian (ARG) subscription analyses with the user's own az login, via the CLI or the local portal. It produces per-subscription FinOps and architecture reviews as markdown under reports/<subscription>/ and helps interpret them. Use when the user asks to analyse, review, audit or cost-check an Azure subscription with ARG, start or troubleshoot the ARG local portal, find where ARG reports are written, summarise an ARG report, or add or tune ARG scanners.
---

# ARG Subscription Analysis

Read-only analysis of Azure subscriptions using the user's **`az login`** session. There's no service principal,
Docker or database. Output is one folder of markdown per subscription.

## Quick start

```powershell
az account show --query "{user:user.name, tenant:tenantId}" -o table   # must be signed in; else: az login
<ARG repo>\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription '<name-or-id>'   # any folder
<ARG repo>\scripts\Start-LocalPortal.ps1                                          # portal, http://127.0.0.1:8765
```

Reports land in `<ARG repo>\reports\<subscription>\`, with the index at `<ARG repo>\reports\README.md`.

## Workflow: analyse subscriptions

- [ ] Confirm `az login` is active and on the right tenant (`az login --tenant <id>` if not).
- [ ] Confirm the account has **Reader + Cost Management Reader + Security Reader** on each target subscription.
- [ ] Run the launcher with `-Subscription a, b` or `-All` (optionally `-ReportsPath`, `-TenantId`, `-SkipCost`).
      With plain python, **cd to the ARG repo root first**:
      `python -m scripts.subscription_analysis -s <name-or-id> [-s …] | --all`.
- [ ] Expect minutes per subscription. `429 … retrying` log lines are normal (Cost Management throttling).
- [ ] Check `05-deep-dive/README.md` → *Collection Warnings* for missing roles or skipped scanners.
- [ ] Whole tenant: add `--parallel 3` (`-Parallel 3`). For the cross-subscription **estate inventory** (types, sizes,
      SKUs, regions, suggestions with filters) use the portal's **Estate** page or `--all --estate` (`-Estate`, ~30 s);
      output in `reports/_estate/`.

## Workflow: start the local portal

- [ ] `$env:ARG_PORTAL_PASSWORD = '<pw>'` (optional; otherwise a one-time password is printed).
- [ ] Run `scripts\Start-LocalPortal.ps1` (`-Port`, `-ReportsPath`, `-TenantId`, `-NoBrowser`).
- [ ] Sign in as `admin` (or `ARG_PORTAL_USER`). That's the portal login only; it **never** signs in to Azure.
- [ ] Select subscriptions → **Analyze** → open the report when the job is `completed`.
- [ ] Switch Azure account or tenant with `az login` in a terminal, then **Refresh**.

## Workflow: summarise a report for the user

1. Read `reports/<subscription>/summary.json` for totals (cost, findings by severity, savings per wave).
2. Read `README.md` (executive summary, top risks, action list), then `03-cost-drivers/README.md` for cost.
3. Quote findings by their `F-nnn` reference. Evidence and CLI commands are in `05-deep-dive/<area>/README.md`,
   and machine-readable data is in `05-deep-dive/raw/findings.json`.
4. State estimates as estimates. Savings are USD converted to the billing currency. The critique's "why" is
   **inferred**, and the Hyperscale pricing saving needs confirmation from Microsoft or the CSP.

## Guardrails

- Never execute remediation commands from a report without explicit user approval. The analysis itself is read-only.
- Never commit `reports/`. It holds resource IDs, IPs and principal IDs, and it's git-ignored.
- Don't create service principals or change RBAC to make a run work. Report the missing role instead.
- Graph (Entra ID) scanners are skipped locally, and that's expected.

## More

- Output layout, options, thresholds and troubleshooting: [REFERENCE.md](REFERENCE.md)
- Full user guide: `docs/subscription-analysis.md`. Scanner list: `docs/scanner-catalog.md`
- Adding or tuning scanners: `CONTRIBUTING.md` → *Adding a scanner*
