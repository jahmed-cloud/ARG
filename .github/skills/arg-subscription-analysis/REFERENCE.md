# ARG Subscription Analysis — Reference

## Commands

| Goal | Command (launchers work from any folder; `python -m` needs the repo root) |
|---|---|
| One or more subscriptions | `scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription 'a','b'` · `python -m scripts.subscription_analysis -s a -s b` |
| All enabled subscriptions | `scripts\Invoke-SubscriptionAnalysis.ps1 -All` · `python -m scripts.subscription_analysis --all` |
| Custom report root | `-ReportsPath D:\arg-reports` · `--reports-dir D:\arg-reports` |
| Exact folder, one subscription | `--output D:\review\sub-x` (no index update) |
| Specific tenant | `-TenantId <id>` · `--tenant <id>` (the az login must cover it) |
| Only some scanners | `--scanners unassociated_ddos_plan_scanner,budget_scanner` |
| Threshold overrides | `--config thresholds.json` (keys below) |
| Faster, no cost datasets | `-SkipCost` · `--skip-cost` |
| Portal | `scripts\Start-LocalPortal.ps1 [-Port 8765] [-ReportsPath …] [-TenantId …] [-NoBrowser]` · `python -m scripts.local_portal` |
| Make targets (repo root, venv active) | `make analyze SUB=<name>` · `make analyze-all` · `make portal` · `make test` |

## Output layout

```
reports/README.md                           index of analysed subscriptions
reports/<subscription>/README.md            executive summary, headline savings, top risks, action list
reports/<subscription>/summary.json         totals (cost_12m, cost_30d, findings_by_severity, savings_usd, savings_billing)
reports/<subscription>/01-current-findings/ baseline, workloads, architecture diagram, resource-inventory.md
reports/<subscription>/02-gap-analysis/     gaps by area x severity
reports/<subscription>/03-cost-drivers/     trend, breakdowns, forecast, savings-register.md
reports/<subscription>/04-architectural-critique/  inferred evolution, critique per decision, target, roadmap
reports/<subscription>/05-deep-dive/<area>/ networking, compute-appservice, data-sql-storage, ai-foundry,
                                            security-identity, observability-operations, cost-finops
reports/<subscription>/05-deep-dive/raw/    findings.json, scanner-runs.json, metadata.json, inventory/, cost/
```

Finding record fields in `findings.json`: `ref`, `finding_type`, `title`, `description`, `severity`, `category`,
`area`, `folder`, `wave` (1 no-regret, 2 optimise, 3 structural), `resource_id`, `evidence`, `remediation_steps`,
`azure_cli_script`, `estimated_monthly_savings_usd`, `scanner`.

## Threshold keys (`--config`)

`required_tags`, `cpu_avg_threshold` (60), `cpu_max_threshold` (95), `saturated_max` (95), `saturated_min_avg` (10),
`idle_transactions_7d` (50), `hot_transactions_7d` (50,000,000), `min_family_size` (10), `management_ports`
([22, 3389, 5985, 5986]), `max_owners` (3), `secure_score_target` (0.8), `defender_severities` (["High"]),
`min_daily_cap_gb` (0.5), `max_workspaces` (2), `max_workloads_per_subscription` (2), `overrun_months` (3),
`ai_min_monthly_usd` (100), `max_ai_accounts` (2), `timeout_seconds` (900).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ERR_CONNECTION_REFUSED` on `http://127.0.0.1:8765` | Portal not running. Start `scripts\Start-LocalPortal.ps1` and keep that terminal open |
| "Azure CLI is not signed in" | `az login`, then re-run or click Refresh in the portal |
| Subscription missing from the list | Other tenant (`az login --tenant <id>`) or disabled |
| Cost sections empty, 403 in warnings | Missing Cost Management Reader |
| Defender sections empty | Missing Security Reader |
| `No module named scripts` | `python -m` run outside the repo root. Use the launchers or `cd` to the repo |
| Diagrams shown as code in the portal | Browser can't reach the jsDelivr CDN; content is unaffected |
| Port in use | `-Port 9000` |
