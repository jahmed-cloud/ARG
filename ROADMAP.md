# Roadmap

This reflects what's actually planned, based on known gaps in the current build — not aspirational marketing copy. Items are roughly ordered by priority within each section, not by date (this is a side project, not a funded roadmap with deadlines).

## Near-term

- **Configuration-level Terraform drift detection.** Today, drift detection only compares *existence* (managed / unmanaged / missing). It doesn't yet detect when a resource exists in both Terraform state and Azure but has drifted in *configuration* (e.g. a tag or SKU changed out-of-band). `TerraformState.drifted_count` is wired up but always reports `0` until this is built.
- **Dormant-user × privileged-role cross-reference.** `dormant_user_scanner` currently always reports `is_privileged=False` for real (non-mock) results — it doesn't cross-reference against `permanent_global_admin_scanner`'s role membership data, so a dormant account that also holds Global Admin won't get the elevated severity it should. Needs either a shared lookup within one scan pass or a second targeted Graph call.
- **Resource Visualizer.** A graph view showing relationships between Azure resources (VNet → subnet → NIC → VM, storage account → private endpoint, etc.), not just a flat findings list. Mentioned in the UI as a nav item; not yet built.
- **Per-tenant Graph permission verification.** Right now "Graph Access" in Settings is a single on/off toggle the admin sets manually after granting consent in Azure AD. There's no in-app way to verify which of the five required permissions are actually granted — a partial-consent tenant will silently behave like a no-consent one with a generic 403, rather than telling you exactly which permission is missing.
- **CI/CD pipeline.** `.github/workflows/` doesn't exist yet — no automated test run, build check, or image publish on push.
- **Test suite.** `tests/unit/`, `tests/integration/`, `tests/e2e/` are empty placeholders. All verification so far has been manual (`docker compose up --build` + live API calls during development), which doesn't scale and won't catch regressions automatically.

## Planned, not yet started

- **Scheduled report delivery.** `workers/report_worker.py` for periodic report generation (e.g. weekly governance summary emailed to stakeholders) isn't implemented — reports are currently on-demand only.
- **Webhook delivery on scan completion.** The webhook *registration* API exists (`backend/api/routes/webhooks.py`), but nothing actually fires a webhook when a scan finishes. Today it's a configured-but-inert feature.
- **One-click automated remediation.** Currently `FEATURE_AUTO_REMEDIATION=false` by default and intentionally — the Remediation page generates scripts/checklists for a human to review and run, it doesn't execute anything against Azure itself. Turning this on safely needs a real approval workflow, not just a flag flip.
- **Microsoft Defender for Cloud integration.** `azure-mgmt-security` is already a dependency but no scanner uses it yet — Defender's own recommendations aren't pulled in alongside ARG's own findings.
- **Per-permission Graph consent UI.** Show exactly which of `User.Read.All` / `AuditLog.Read.All` / `Reports.Read.All` / `RoleManagement.Read.Directory` / `Application.Read.All` Azure AD actually granted, rather than a single boolean.
- **Multi-tenant Service Principal validation.** A "Test Connection" button when registering a tenant, so a typo'd Tenant ID or bad credential is caught at registration time instead of surfacing as a cryptic auth error on the next scan.

## Known limitations (not bugs, won't be "fixed" — Azure/Graph constraints)

- **MFA, dormant-user, and stale-guest checks require Azure AD Premium P1/P2.** Microsoft Graph enforces this server-side on `signInActivity` and the authentication methods report — no code change or permission grant works around it on a non-Premium tenant.
- **Resource scanners target Azure-native resource types** (VMs, storage accounts, networking, PaaS). Subscriptions that are primarily Azure Arc / hybrid-managed will see most scanners correctly report zero findings, since those resource types aren't what the scanner library currently evaluates.

## Contributing to the roadmap

If something here matters to you, or you have a gap to report that isn't listed, open an issue on [GitHub](https://github.com/jahmed-cloud/ARG/issues) — real usage is what should drive priority here, not guesswork.
