"""
Azure Resource Guardian - Governance, Observability & FinOps Posture Scanners
==============================================================================
Scanners in this module:
1. EnvironmentTagMismatchScanner   — Name says dev/test, tag says prod (or the reverse)
2. TagKeyTypoScanner               — Tag keys one or two edits away from a standard key
3. SubscriptionWorkloadSprawlScanner — Many unrelated workloads sharing one subscription
4. LogAnalyticsScanner             — Tiny daily caps that silently drop data; workspace sprawl
5. AppInsightsWorkspaceScanner     — App Insights linked to deleted workspaces, or classic mode
6. ServiceHealthAlertScanner       — No Service Health activity-log alert for the subscription
7. EmptyResourceGroupScanner       — Resource groups with no resources
8. BudgetScanner                   — Missing budget, or budget exceeded month after month
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from datetime import date, timedelta
from typing import Any, Dict, List, Optional

from scanners.base.azure_api import run_cost_query
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.naming import env_from_name, env_from_tags
from scanners.base.posture_scanner import PostureScanner

STANDARD_TAG_KEYS = ["environment", "owner", "costcenter", "cost-center", "application", "projectname",
                     "resourceowner", "billingcontact", "technicalcontact", "securitycontact", "managedby"]
WORKLOAD_TAG_KEYS = ("projectname", "project", "application", "workload", "app")
SKIP_RG_PREFIXES = ("mc_", "databricks-rg-", "ma_", "networkwatcherrg")


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def near_miss_tag_key(key: str, standard: List[str]) -> Optional[str]:
    """Standard key that `key` looks like a typo of (edit distance 1-2), else None."""
    low = key.lower()
    if low in standard or len(low) < 5:
        return None
    best = min(standard, key=lambda s: levenshtein(low, s))
    distance = levenshtein(low, best)
    return best if 0 < distance <= 2 else None


# ---------------------------------------------------------------------------
# 1. Environment tag vs name mismatch
# ---------------------------------------------------------------------------

@register_scanner
class EnvironmentTagMismatchScanner(PostureScanner):
    """
    e.g. a database named '...-Test' tagged environment=prod: operators and
    environment-scoped policies treat a production system as disposable.
    """

    scanner_name = "environment_tag_mismatch_scanner"
    display_name = "Environment Tag / Name Mismatch"
    description = "Detects resources whose name implies one environment while the environment tag says another"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.MEDIUM

    CRITICAL_TYPES = ("microsoft.sql/servers/databases", "microsoft.sql/servers", "microsoft.web/sites",
                      "microsoft.web/serverfarms", "microsoft.storage/storageaccounts", "microsoft.keyvault/vaults")

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where isnotnull(tags) and (isnotnull(tags['environment']) or isnotnull(tags['Environment'])
                or isnotnull(tags['env']) or isnotnull(tags['environmen']))
        | project id, name, type = tolower(type), resourceGroup, subscriptionId, location, tags
        """
        try:
            resources = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for r in resources:
            by_tag = env_from_tags(r.get("tags"))
            by_name = env_from_name((r.get("name") or "").split("/")[-1])
            if not by_tag or not by_name or by_tag == by_name:
                continue
            tag_value = next((v for k, v in (r.get("tags") or {}).items()
                              if k.lower() in ("environment", "env", "environmen")), None)
            critical = r.get("type") in self.CRITICAL_TYPES and by_tag == "prod"
            findings.append(self.resource_finding(
                r,
                finding_type="environment_tag_name_mismatch",
                title=f"Name implies {'non-production' if by_name == 'nonprod' else 'production'}, "
                      f"tagged '{tag_value}': {r['name']}",
                description=(
                    f"'{r['name']}' ({r.get('type')}) is tagged environment='{tag_value}' but its name implies a "
                    f"{'non-production' if by_name == 'nonprod' else 'production'} resource. "
                    + ("A production system with a dev/test name is at risk of accidental deletion, wrong "
                       "maintenance windows and weaker policy coverage." if by_tag == "prod" else
                       "A non-production resource named as production distorts cost and risk reporting.")
                ),
                severity=SeverityLevel.HIGH if critical else SeverityLevel.MEDIUM,
                remediation_steps=("Confirm the real environment with the owner; fix the tag, and plan a rename "
                                   "(re-creation via IaC) for production resources carrying non-prod names."),
                azure_cli_script=f'az tag update --resource-id "{r["id"]}" --operation Merge --tags environment=<correct-value>',
                evidence={"environment_tag": tag_value, "implied_by_name": by_name},
                estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(resources))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql-app-1/databases/AppDb-Test",
            "name": "sql-app-1/AppDb-Test", "type": "microsoft.sql/servers/databases", "resourceGroup": "rg-data",
            "subscriptionId": "sub-1", "location": "westeurope", "tags": {"environment": "prod"},
        }]


# ---------------------------------------------------------------------------
# 2. Tag key typos
# ---------------------------------------------------------------------------

@register_scanner
class TagKeyTypoScanner(PostureScanner):
    scanner_name = "tag_key_typo_scanner"
    display_name = "Tag Key Typos"
    description = "Detects tag keys that are near-misses of standard keys (e.g. 'environmen')"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.LOW

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where isnotnull(tags) and array_length(bag_keys(tags)) > 0
        | project id, name, type = tolower(type), resourceGroup, subscriptionId, location, tags
        """
        try:
            resources = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        standard = sorted({k.lower() for k in STANDARD_TAG_KEYS + list(self.setting("required_tags", []))})
        findings = []
        for r in resources:
            typos = {k: near_miss_tag_key(k, standard) for k in (r.get("tags") or {})}
            typos = {k: v for k, v in typos.items() if v}
            if not typos:
                continue
            findings.append(self.resource_finding(
                r,
                finding_type="tag_key_typo",
                title=f"Tag key typo: {', '.join(typos)} on {r['name']}",
                description=("Tag key(s) look like misspellings of standard keys: "
                             + ", ".join(f"'{k}' → '{v}'" for k, v in typos.items())
                             + ". Policies, cost reports and tag inheritance keyed on the standard name miss this resource."),
                remediation_steps="Re-tag with the standard key and delete the misspelled key.",
                azure_cli_script="\n".join(
                    f'az tag update --resource-id "{r["id"]}" --operation Merge --tags {v}="{r["tags"][k]}"\n'
                    f'az tag update --resource-id "{r["id"]}" --operation Delete --tags {k}="{r["tags"][k]}"'
                    for k, v in typos.items()
                ),
                evidence={"typos": typos},
                estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(resources))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/ddosProtectionPlans/ddos-unused-1",
            "name": "ddos-unused-1", "type": "microsoft.network/ddosprotectionplans", "resourceGroup": "rg-net",
            "subscriptionId": "sub-1", "location": "westeurope", "tags": {"environmen": "prod", "projectName": "App"},
        }]


# ---------------------------------------------------------------------------
# 3. Many workloads in one subscription
# ---------------------------------------------------------------------------

@register_scanner
class SubscriptionWorkloadSprawlScanner(PostureScanner):
    scanner_name = "subscription_workload_sprawl_scanner"
    display_name = "Multiple Workloads per Subscription"
    description = "Detects subscriptions shared by many unrelated workloads (landing-zone gap)"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.LOW

    MAX_WORKLOADS = 2

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where isnotnull(tags)
        | mv-expand bagexpansion=array tag = tags
        | extend key = tolower(tostring(tag[0])), value = tolower(trim(' ', tostring(tag[1])))
        | where key in ('projectname', 'project', 'application', 'workload', 'app')
        | summarize resources = count() by value
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        workloads = sorted({r["value"] for r in rows if r.get("value")})
        limit = int(self.setting("max_workloads_per_subscription", self.MAX_WORKLOADS))
        if len(workloads) <= limit:
            return ScanOutput(resources_scanned=len(rows))
        finding = self.subscription_finding(
            context,
            finding_type="subscription_multiple_workloads",
            title=f"{len(workloads)} workloads share one subscription",
            description=("Workload tags show unrelated workloads in one subscription: " + ", ".join(workloads)
                         + ". They share RBAC, budget, policy exemptions and quota, so none can be governed or "
                         "charged back on its own."),
            remediation_steps=("Move each workload (and prod vs non-prod) into its own landing-zone subscription "
                               "under the right management group, deployed via IaC."),
            evidence={"workloads": workloads},
            caf_control="Landing zones",
        )
        return ScanOutput(findings=[finding], resources_scanned=len(rows))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{"value": v, "resources": 10} for v in ("apptimize", "machine-management", "bot", "twincat coagent")]


# ---------------------------------------------------------------------------
# 4. Log Analytics caps and sprawl
# ---------------------------------------------------------------------------

@register_scanner
class LogAnalyticsScanner(PostureScanner):
    scanner_name = "log_analytics_scanner"
    display_name = "Log Analytics Caps & Sprawl"
    description = "Detects Log Analytics daily caps so low that data is dropped, and workspace sprawl"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.HIGH

    MIN_CAP_GB = 0.5
    MAX_WORKSPACES = 2

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.operationalinsights/workspaces'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  cap_gb = todouble(properties.workspaceCapping.dailyQuotaGb),
                  retention = toint(properties.retentionInDays), sku = tostring(properties.sku.name)
        """
        try:
            workspaces = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        min_cap = float(self.setting("min_daily_cap_gb", self.MIN_CAP_GB))
        findings = []
        for ws in workspaces:
            cap = ws.get("cap_gb")
            if cap is None or cap < 0 or cap >= min_cap:
                continue
            findings.append(self.resource_finding(
                ws,
                finding_type="log_analytics_restrictive_daily_cap",
                title=f"Daily cap {cap * 1024:,.0f} MB: {ws['name']}",
                description=(f"Log Analytics workspace '{ws['name']}' stops ingesting after {cap} GB/day "
                             f"(~{cap * 1024:,.0f} MB). Everything sent after the cap — App Insights telemetry, VM "
                             f"and audit logs — is dropped, typically during incidents when volume spikes."),
                resource_type="microsoft.operationalinsights/workspaces",
                remediation_steps=("Raise or remove the cap, add an alert on the '_LogOperation' cap event, and use "
                                   "Basic/Auxiliary table plans or DCR filtering to control cost instead."),
                azure_cli_script=f"az monitor log-analytics workspace update -g {ws.get('resourceGroup')} -n {ws['name']} --quota -1",
                evidence={"daily_cap_gb": cap, "retention_days": ws.get("retention"), "sku": ws.get("sku")},
                estimated_monthly_savings_usd=0.0,
            ))
        max_ws = int(self.setting("max_workspaces", self.MAX_WORKSPACES))
        if len(workspaces) > max_ws:
            findings.append(self.subscription_finding(
                context,
                finding_type="log_analytics_workspace_sprawl",
                title=f"{len(workspaces)} Log Analytics workspaces in one subscription",
                description=("Workspaces: " + ", ".join(w["name"] for w in workspaces)
                             + ". Telemetry for one workload is spread across workspaces, which breaks correlation "
                             "and duplicates configuration (caps, retention, access)."),
                severity=SeverityLevel.LOW,
                remediation_steps="Consolidate to one workspace per environment (or the central platform workspace).",
                evidence={"workspaces": [w["name"] for w in workspaces]},
            ))
        return ScanOutput(findings=findings, resources_scanned=len(workspaces))

    def _mock_data(self) -> List[Dict[str, Any]]:
        base = "/subscriptions/sub-1/resourceGroups/rg-mon/providers/Microsoft.OperationalInsights/workspaces"
        common = {"type": "microsoft.operationalinsights/workspaces", "resourceGroup": "rg-mon",
                  "subscriptionId": "sub-1", "location": "westeurope", "retention": 30, "sku": "PerGB2018"}
        return [{**common, "id": f"{base}/law-app", "name": "law-app", "cap_gb": 0.023},
                {**common, "id": f"{base}/law-default", "name": "law-default", "cap_gb": -1.0},
                {**common, "id": f"{base}/law-other", "name": "law-other", "cap_gb": -1.0}]


# ---------------------------------------------------------------------------
# 5. App Insights -> workspace link
# ---------------------------------------------------------------------------

@register_scanner
class AppInsightsWorkspaceScanner(PostureScanner):
    scanner_name = "app_insights_workspace_scanner"
    display_name = "Application Insights Workspace Link"
    description = "Detects App Insights components linked to missing workspaces or still in classic mode"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.HIGH

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.insights/components'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  workspace_id = tolower(tostring(properties.WorkspaceResourceId)),
                  ingestion_mode = tostring(properties.IngestionMode)
        """
        try:
            components = await self.arg(context, query)
            existing = await self._existing_workspaces(context, components)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for c in components:
            ws = c.get("workspace_id")
            if not ws:
                findings.append(self.resource_finding(
                    c, finding_type="app_insights_classic_mode", title=f"Classic App Insights: {c['name']}",
                    description=f"Application Insights '{c['name']}' is not workspace-based (classic mode is retired).",
                    resource_type="microsoft.insights/components", severity=SeverityLevel.MEDIUM,
                    remediation_steps="Migrate to a workspace-based resource.",
                    azure_cli_script=(f"az monitor app-insights component update -g {c.get('resourceGroup')} "
                                      f"--app {c['name']} --workspace <workspace-resource-id>"),
                    evidence={}, estimated_monthly_savings_usd=0.0,
                ))
            elif ws not in existing:
                findings.append(self.resource_finding(
                    c, finding_type="app_insights_workspace_missing",
                    title=f"App Insights linked to missing workspace: {c['name']}",
                    description=(f"Application Insights '{c['name']}' points to workspace '{ws.split('/')[-1]}', which "
                                 f"does not exist in any subscription visible to the scanner. Telemetry is lost or "
                                 f"unqueryable."),
                    resource_type="microsoft.insights/components",
                    remediation_steps="Re-link the component to a live workspace (one per environment).",
                    azure_cli_script=(f"az monitor app-insights component update -g {c.get('resourceGroup')} "
                                      f"--app {c['name']} --workspace <workspace-resource-id>"),
                    evidence={"workspace_resource_id": ws, "ingestion_mode": c.get("ingestion_mode")},
                    estimated_monthly_savings_usd=0.0,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(components))

    async def _existing_workspaces(self, context: ScanContext, components: List[Dict[str, Any]]) -> set:
        ids = sorted({c["workspace_id"] for c in components if c.get("workspace_id")})
        if not ids:
            return set()
        if context.resource_graph_client is None:
            return {i for i in ids if not i.endswith("-deleted")}
        id_list = ", ".join(f"'{i}'" for i in ids)
        rows = await self.arg(context, f"""
            Resources
            | where type =~ 'microsoft.operationalinsights/workspaces'
            | where tolower(id) in ({id_list})
            | project id = tolower(id)
        """, tenant_scope=True)
        return {r["id"] for r in rows}

    def _mock_data(self) -> List[Dict[str, Any]]:
        base = "/subscriptions/sub-1/resourceGroups/rg-mon/providers/Microsoft.Insights/components"
        ws = "/subscriptions/sub-1/resourcegroups/rg-mon/providers/microsoft.operationalinsights/workspaces"
        common = {"type": "microsoft.insights/components", "resourceGroup": "rg-mon", "subscriptionId": "sub-1",
                  "location": "westeurope", "ingestion_mode": "LogAnalytics"}
        return [{**common, "id": f"{base}/ai-ok", "name": "ai-ok", "workspace_id": f"{ws}/law-app"},
                {**common, "id": f"{base}/ai-broken", "name": "ai-broken", "workspace_id": f"{ws}/law-gone-deleted"}]


# ---------------------------------------------------------------------------
# 6. Service Health alert
# ---------------------------------------------------------------------------

@register_scanner
class ServiceHealthAlertScanner(PostureScanner):
    scanner_name = "service_health_alert_scanner"
    display_name = "Service Health Alert"
    description = "Detects subscriptions with no Service Health activity-log alert"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.insights/activitylogalerts'
        | where tobool(properties.enabled) == true
        | where tostring(properties.condition) contains 'ServiceHealth'
        | project id, name
        """
        try:
            alerts = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])
        if alerts:
            return ScanOutput(resources_scanned=len(alerts))
        finding = self.subscription_finding(
            context,
            finding_type="service_health_alert_missing",
            title="No Service Health alert",
            description=("No enabled Service Health activity-log alert exists in this subscription, so platform "
                         "incidents, planned maintenance and retirements affecting it are not pushed to anyone. "
                         "(Alerts defined centrally in another subscription are not visible to this check.)"),
            remediation_steps="Create a Service Health alert (Incident, Maintenance, Health advisory, Security) to the workload action group.",
            azure_cli_script=(
                f"az monitor activity-log alert create -g <rg> -n service-health --scope /subscriptions/{context.subscription_id} "
                "--condition category=ServiceHealth --action-group <action-group-id>"
            ),
            evidence={"service_health_alerts": 0},
        )
        return ScanOutput(findings=[finding], resources_scanned=0)


# ---------------------------------------------------------------------------
# 7. Empty resource groups
# ---------------------------------------------------------------------------

@register_scanner
class EmptyResourceGroupScanner(PostureScanner):
    scanner_name = "empty_resource_group_scanner"
    display_name = "Empty Resource Groups"
    description = "Detects resource groups that contain no resources"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.LOW

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        ResourceContainers
        | where type =~ 'microsoft.resources/subscriptions/resourcegroups'
        | project rg_id = tolower(id), name, location, subscriptionId, tags
        | join kind=leftouter (
            Resources | summarize resource_count = count() by rg_id = tolower(strcat('/subscriptions/', subscriptionId, '/resourceGroups/', resourceGroup))
          ) on rg_id
        | where isnull(resource_count) or resource_count == 0
        | project id = rg_id, name, location, subscriptionId, tags
        """
        try:
            groups = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for g in groups:
            if (g.get("name") or "").lower().startswith(SKIP_RG_PREFIXES) or (g.get("tags") or {}).get("arg-reserved"):
                continue
            findings.append(self.make_finding(
                finding_type="empty_resource_group",
                title=f"Empty resource group: {g['name']}",
                description=f"Resource group '{g['name']}' ({g.get('location')}) contains no resources.",
                resource_id=g["id"], resource_name=g["name"], resource_type="microsoft.resources/resourcegroups",
                resource_group=g["name"], subscription_id=g.get("subscriptionId") or context.subscription_id,
                location=g.get("location") or "",
                remediation_steps="Delete the resource group (check for locks and deployment history first).",
                azure_cli_script=f"az group delete -n {g['name']} --yes",
                powershell_script=f"Remove-AzResourceGroup -Name '{g['name']}' -Force",
                evidence={}, estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(groups))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{"id": "/subscriptions/sub-1/resourcegroups/rg-empty", "name": "rg-empty", "location": "centralus",
                 "subscriptionId": "sub-1", "tags": None}]


# ---------------------------------------------------------------------------
# 8. Budgets
# ---------------------------------------------------------------------------

@register_scanner
class BudgetScanner(PostureScanner):
    """
    Live mode reads Consumption budgets and 6 full months of actual cost.
    A monthly budget exceeded in most months is not a control: either the
    budget is unrealistic or nobody acts on the alerts.
    """

    scanner_name = "budget_scanner"
    display_name = "Budget Coverage & Overrun"
    description = "Detects missing budgets and budgets exceeded in most recent months"
    category = ScannerCategory.COST
    severity = SeverityLevel.HIGH

    MONTHS = 6
    OVERRUN_MONTHS = 3

    async def scan(self, context: ScanContext) -> ScanOutput:
        if not self.is_live(context):
            budgets, monthly = self._mock_sets()
        else:
            try:
                budgets = await context.arm_client.get_all(
                    f"/subscriptions/{context.subscription_id}/providers/Microsoft.Consumption/budgets", "2023-05-01")
                monthly = await self._monthly_costs(context)
            except Exception as e:
                return ScanOutput(warnings=[f"Budget/cost query failed: {e}"])

        if not budgets:
            return ScanOutput(findings=[self.subscription_finding(
                context, finding_type="budget_missing", title="No budget on subscription",
                description="The subscription has no Cost Management budget, so overspend raises no alert.",
                severity=SeverityLevel.MEDIUM,
                remediation_steps="Create a monthly budget with actual and forecast alerts to the workload owners.",
                azure_cli_script=(f"az consumption budget create --budget-name monthly --amount <amount> --time-grain Monthly "
                                  f"--start-date {date.today().replace(day=1).isoformat()} --end-date 2030-12-31 --category Cost"),
                evidence={},
            )])

        findings = []
        for b in budgets:
            props = b.get("properties") or {}
            if (props.get("timeGrain") or "").lower() != "monthly":
                continue
            amount = float(props.get("amount") or 0)
            start = str((props.get("timePeriod") or {}).get("startDate") or "")[:7]
            eligible = [m for m in monthly if not start or m["month"] >= start]
            over = [m for m in eligible if amount and m["cost"] > amount]
            required = min(int(self.setting("overrun_months", self.OVERRUN_MONTHS)), len(eligible))
            if len(eligible) < 2 or len(over) < required:
                continue
            notifications = props.get("notifications") or {}
            owner_contacts = any(n.get("contactEmails") or n.get("contactRoles") for n in notifications.values())
            currency = monthly[0].get("currency") if monthly else ""
            peak = max(m["cost"] for m in eligible)
            findings.append(self.make_finding(
                finding_type="budget_consistently_exceeded",
                title=f"Budget '{b.get('name')}' exceeded in {len(over)}/{len(eligible)} months",
                description=(
                    f"Monthly budget '{b.get('name')}' is {amount:,.0f} {currency}; actual cost exceeded it in "
                    f"{len(over)} of the {len(eligible)} full months since it applies (peak {peak:,.0f} {currency}, "
                    f"{peak / amount:.0%} of budget). "
                    + ("Alerts reach only action groups — no owner e-mail or role is notified. "
                       if not owner_contacts else "Owners are notified, yet spend stays above budget. ")
                    + (f"{len(budgets)} budgets exist on this subscription; overlapping budgets dilute ownership."
                       if len(budgets) > 1 else "")
                ),
                resource_id=b.get("id") or f"/subscriptions/{context.subscription_id}/providers/Microsoft.Consumption/budgets/{b.get('name')}",
                resource_name=b.get("name"),
                resource_type="microsoft.consumption/budgets",
                resource_group="(subscription)",
                subscription_id=context.subscription_id,
                location="global",
                remediation_steps=("Agree a realistic budget per workload with its owner, add owner e-mails/roles to "
                                   "the notifications, and define what happens on breach (review, freeze, escalate)."),
                evidence={"budget_amount": amount, "budget_start": start, "months": eligible,
                          "owner_contacts": owner_contacts,
                          "budgets_on_subscription": [x.get("name") for x in budgets]},
                estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(budgets))

    async def _monthly_costs(self, context: ScanContext) -> List[Dict[str, Any]]:
        first_this_month = date.today().replace(day=1)
        start = first_this_month
        for _ in range(self.MONTHS):
            start = (start - timedelta(days=1)).replace(day=1)
        rows = await run_cost_query(context, start, first_this_month - timedelta(days=1), [], granularity="Monthly") or []
        months = []
        for r in rows:
            month = str(r.get("BillingMonth") or r.get("UsageDate") or "")[:7]
            months.append({"month": month, "cost": float(r.get("Cost") or 0.0), "currency": r.get("Currency")})
        return sorted(months, key=lambda m: m["month"])

    def _mock_sets(self):
        budgets = [{"name": "governance_budget", "properties": {
            "timeGrain": "Monthly", "amount": 2600,
            "notifications": {"actual_90": {"contactGroups": ["/subscriptions/sub-1/.../actionGroups/ag-ccoe"],
                                            "contactEmails": [], "contactRoles": []}}}}]
        monthly = [{"month": m, "cost": c, "currency": "CHF"} for m, c in
                   (("2026-03", 4549), ("2026-04", 4699), ("2026-05", 6733),
                    ("2026-06", 6937), ("2026-07", 8056), ("2026-08", 7513))]
        return budgets, monthly
