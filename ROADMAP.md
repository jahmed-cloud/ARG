# Roadmap

This reflects what's actually planned, based on known gaps in the current build - not aspirational marketing copy. Items are roughly ordered by priority within each section, not by date (this is a side project, not a funded roadmap with deadlines).

## Architect review (2026-10-06) - next

From reviewing real production reports. Done in this round: actionable vs
hygiene, cost-weighted tag allocation, systemic issues with Azure Policy guardrails, "where the money is" coverage,
quick wins, Advisor cost recommendations (Data Explorer cache policy, right-sizing), service retirement calendar,
resilience posture, Defender / Advisor de-duplication, changes since the previous run, Azure Boards backlog CSV,
completed / dismissed Advisor items excluded. Still open, by value:

- **Analysers where the money is.** Data Explorer (SKU vs hot-cache size, optimized autoscale off, follower /
  streaming settings), Cosmos DB (RU utilisation, autoscale, serverless fit), Log Analytics (commitment tiers,
  Basic / Auxiliary tables, retention), Azure Cache for Redis and API Management capacity. In one reviewed subscription five
  Data Explorer clusters carry ~71 % of the spend; only Advisor's cache recommendations cover them today.
- **Commitment coverage and utilisation.** Share of eligible compute / database spend covered by reservations and
  savings plans, and the utilisation of the ones owned (Cost Management PricingModel and reservation utilisation
  APIs) - the FinOps KPI after cost allocation.
- **Cost anomalies and unit cost.** Month-over-month jumps per service / resource group, Cost Management anomaly
  alerts, cost per workload and environment over time (from `history.json` and the tag allocation).
- **Exceptions register.** Accept a risk with owner, reason and expiry (local and Docker), so accepted items leave
  the counts and come back when they expire; feed it into the backlog export.
- **Guardrails as code.** Generate the Bicep / Terraform policy assignments for the systemic issues of a subscription
  or management group, Audit first, with remediation tasks.
- **Azure Boards sync.** Create / update work items through the Azure DevOps REST API (idempotent per finding key)
  instead of a CSV import.
- **DR posture per workload.** Backup policy, geo-redundancy and paired-region readiness per workload tag, with an
  RPO / RTO statement the owner confirms.
- **Control mapping.** Microsoft cloud security benchmark / CIS pass-fail per control from Defender regulatory
  compliance, next to ARG's findings.

## Near-term

- **Estate history and trend.** The estate inventory (`reports/_estate/`) is a snapshot: keep dated copies and show new / removed resources, usage and cost trend between refreshes.
- **Rightsizing beyond VMs.** VMs have validated right-sizing (30-day percentiles, Advisor cross-check, prices); scale-set instance counts and current-series targets for end-of-life sizes are next.
- **More usage metrics.** Managed-disk IOPS / throughput vs provisioned, AKS node pools, VPN / ExpressRoute bandwidth, App Insights and Log Analytics ingestion, and caching metrics between refreshes to make them faster.
- **Email through Microsoft Graph (requirement).** Send password-reset (then scan-completed and scheduled-report)
  emails with Graph `sendMail` instead of SMTP: `MAIL_PROVIDER=graph`, a shared sender mailbox
  (`GRAPH_MAIL_SENDER`), an app registration with Graph **Mail.Send** (Application, admin consent) limited to that
  mailbox by Exchange Online RBAC for Applications, client-credentials token, failures logged but never blocking.
  Full requirement: [docs/docker-deployment.md](docs/docker-deployment.md#email).
- **Cheaper regions for more services.** `cheaper_region_available` covers VMs and Premium App Service plans;
  SQL Database / Managed Instance vCores, PostgreSQL / MySQL flexible servers and storage are next.
- **Configuration-level Terraform drift detection.** Today, drift detection only compares *existence* (managed / unmanaged / missing). It doesn't yet detect when a resource exists in both Terraform state and Azure but has drifted in *configuration* (e.g. a tag or SKU changed out-of-band). `TerraformState.drifted_count` is wired up but always reports `0` until this is built.
- **Dormant-user × privileged-role cross-reference.** `dormant_user_scanner` currently always reports `is_privileged=False` for real (non-mock) results - it doesn't cross-reference against `permanent_global_admin_scanner`'s role membership data, so a dormant account that also holds Global Admin won't get the elevated severity it should. Needs either a shared lookup within one scan pass or a second targeted Graph call.
- **Resource Visualizer.** A graph view showing relationships between Azure resources (VNet → subnet → NIC → VM, storage account → private endpoint, etc.), not just a flat findings list. Mentioned in the UI as a nav item; not yet built.
- **Per-tenant Graph permission verification.** Right now "Graph Access" in Settings is a single on/off toggle the admin sets manually after granting consent in Azure AD. There's no in-app way to verify which of the five required permissions are actually granted - a partial-consent tenant will silently behave like a no-consent one with a generic 403, rather than telling you exactly which permission is missing.
- **Release publishing.** `.github/workflows/validate.yml` now defines offline tests, a frontend build and a disposable container smoke check. Execute it in GitHub and add a separately controlled image publishing/release workflow; no images are published by validation.
- **Test suite.** `tests/unit/` now covers the posture scanners (mock mode + detection helpers) and the subscription analysis report generator (`make test`). `tests/integration/` and `tests/e2e/` are still missing, and the original scanners/API have no tests yet.
- **Surface subscription analysis in the Docker UI.** The `scripts.subscription_analysis` CLI and the lightweight `scripts.local_portal` render the full 01-05 markdown review; the same renderer could back a "Subscription review" report type in `backend/services/report_service.py`.

## Planned, not yet started

- **Scheduled report delivery.** `workers/report_worker.py` for periodic report generation (e.g. weekly governance summary emailed to stakeholders) isn't implemented - reports are currently on-demand only.
- **Webhook delivery on scan completion.** The webhook *registration* API exists (`backend/api/routes/webhooks.py`), but nothing actually fires a webhook when a scan finishes. Today it's a configured-but-inert feature.
- **One-click automated remediation.** Currently `FEATURE_AUTO_REMEDIATION=false` by default and intentionally - the Remediation page generates scripts/checklists for a human to review and run, it doesn't execute anything against Azure itself. Turning this on safely needs a real approval workflow, not just a flag flip.
- **Microsoft Defender for Cloud integration (deeper).** Defender plan coverage, secure score and unhealthy High-severity assessments are now imported through Resource Graph (`securityresources`). Defender recommendations that a ARG finding already covers are merged into it (`scripts/subscription_analysis/correlate.py`). Still missing: regulatory-compliance standards and attack paths.
- **Per-permission Graph consent UI.** Show exactly which of `User.Read.All` / `AuditLog.Read.All` / `Reports.Read.All` / `RoleManagement.Read.Directory` / `Application.Read.All` Azure AD actually granted, rather than a single boolean.
- **Multi-tenant Service Principal validation.** A "Test Connection" button when registering a tenant, so a typo'd Tenant ID or bad credential is caught at registration time instead of surfacing as a cryptic auth error on the next scan.

## Known limitations (not bugs, won't be "fixed" - Azure/Graph constraints)

- **MFA, dormant-user, and stale-guest checks require Azure AD Premium P1/P2.** Microsoft Graph enforces this server-side on `signInActivity` and the authentication methods report - no code change or permission grant works around it on a non-Premium tenant.
- **Resource scanners target Azure-native resource types** (VMs, storage accounts, networking, PaaS). Subscriptions that are primarily Azure Arc / hybrid-managed will see most scanners correctly report zero findings, since those resource types aren't what the scanner library currently evaluates.

## Contributing to the roadmap

If something here matters to you, or you have a gap to report that isn't listed, open an issue on [GitHub](https://github.com/jahmed-cloud/ARG/issues) - real usage is what should drive priority here, not guesswork.
