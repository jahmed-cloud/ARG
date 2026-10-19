"""
Azure Resource Guardian - Governance, Observability & FinOps Posture Scanners
==============================================================================
Scanners in this module:
1. EnvironmentTagMismatchScanner   - Name says dev/test, tag says prod (or the reverse)
2. TagKeyTypoScanner               - Tag keys one or two edits away from a standard key
3. SubscriptionWorkloadSprawlScanner - Many unrelated workloads sharing one subscription
4. LogAnalyticsScanner             - Tiny daily caps that silently drop data; workspace sprawl
5. AppInsightsWorkspaceScanner     - App Insights linked to deleted workspaces, or classic mode
6. ServiceHealthAlertScanner       - No Service Health activity-log alert for the subscription
7. EmptyResourceGroupScanner       - Resource groups with no resources
8. BudgetScanner                   - Missing budget, or budget exceeded month after month
9. ResourceProviderPolicyScanner   - Resource types in use that an allow / deny resource-type policy does not permit
10. ResourceProviderRegistrationScanner - Blocked providers that are registered; registered providers nobody uses
11. ServiceRetirementScanner       - Azure feature / API / SKU / runtime retirements that affect a resource (Advisor),
                                     with the retirement date and the days left
"""

import json
import re
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from datetime import date, timedelta
from typing import Any, Dict, List, Optional

from scanners.base.azure_api import ACTUAL_COST, missing_resources, run_cost_query, top_level_id
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.naming import ENV_TAG_KEYS, env_from_name, env_from_subscription, env_from_tags
from scanners.base.posture_scanner import ADVISOR_ACTIVE_FILTER, PostureScanner
from scanners.base.providers import (
    DEFAULT_BLOCKED_PROVIDERS,
    blocked_registered,
    build_analysis,
    get_provider_analysis,
    unused_registered,
)

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
        # tag keys are case-sensitive in KQL ('Env', 'ENVIRONMENT'): env_from_tags decides, case-insensitively
        query = """
        Resources
        | where isnotnull(tags)
        | project id, name, type = tolower(type), resourceGroup, subscriptionId, location, tags
        """
        try:
            resources = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        subscription_env = env_from_subscription(getattr(context, "subscription_name", "") or "")
        findings = []
        for r in resources:
            by_tag = env_from_tags(r.get("tags"))
            by_name = env_from_name((r.get("name") or "").split("/")[-1])
            if not by_tag or not by_name or by_tag == by_name:
                continue
            tag_value = next((v for k, v in (r.get("tags") or {}).items() if k.lower() in ENV_TAG_KEYS), None)
            critical = r.get("type") in self.CRITICAL_TYPES and by_tag == "prod"
            # The resource group and subscription are named by a different process than the resource: when both
            # agree with the tag, the tag is right and the name is the outlier (legacy naming), not the other way.
            context_envs = [e for e in (env_from_name(r.get("resourceGroup") or ""), subscription_env) if e]
            tag_confirmed = bool(context_envs) and all(e == by_tag for e in context_envs)
            if tag_confirmed:
                fix = ("The tag is right - the resource group and subscription say the same. Keep the tag; rename at "
                       "the next rebuild (names cannot change in place)"
                       + ("; until then a CanNotDelete lock stops someone deleting it as 'just dev'." if by_tag == "prod"
                          else "."))
            else:
                fix = ("Confirm the real environment with the owner; fix the tag, and plan a rename (re-creation via "
                       "IaC) for production resources carrying non-prod names.")
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
                remediation_steps=fix,
                azure_cli_script=None if tag_confirmed else
                f'az tag update --resource-id "{r["id"]}" --operation Merge --tags environment=<correct-value>',
                evidence={"environment_tag": tag_value, "implied_by_name": by_name,
                          "resource_group_and_subscription": context_envs, "tag_confirmed": tag_confirmed},
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
    # Project-level keys win over component-level keys: 'application' values such as
    # "WebShopClient" / "WebShopAnalytics" are parts of one project, not separate workloads.
    WORKLOAD_KEY_PRIORITY = ("projectname", "project", "workload", "application", "app")

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where isnotnull(tags) and array_length(bag_keys(tags)) > 0
        | project tags
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        workloads = sorted({w for w in (self.workload_of(r.get("tags") or {}) for r in rows) if w})
        limit = int(self.setting("max_workloads_per_subscription", self.MAX_WORKLOADS))
        if len(workloads) <= limit:
            return ScanOutput(resources_scanned=len(rows))
        finding = self.subscription_finding(
            context,
            finding_type="subscription_multiple_workloads",
            title=f"{len(workloads)} workloads share one subscription",
            description=("Workload tags (projectName/project, else workload/application) show unrelated workloads "
                         "in one subscription: " + ", ".join(workloads)
                         + ". They share RBAC, budget, policy exemptions and quota, so none can be governed or "
                         "charged back on its own."),
            remediation_steps=("Move each workload (and prod vs non-prod) into its own landing-zone subscription "
                               "under the right management group, deployed via IaC."),
            evidence={"workloads": workloads},
            caf_control="Landing zones",
        )
        return ScanOutput(findings=[finding], resources_scanned=len(rows))

    @classmethod
    def workload_of(cls, tags: Dict[str, Any]) -> Optional[str]:
        lowered = {str(k).lower(): str(v).strip().lower() for k, v in tags.items() if v not in (None, "")}
        for key in cls.WORKLOAD_KEY_PRIORITY:
            if lowered.get(key):
                return lowered[key]
        return None

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [
            {"tags": {"projectName": "WebShop", "Application": "WebShopClient"}},
            {"tags": {"projectName": "WebShop", "Application": "WebShopAnalytics"}},
            {"tags": {"projectName": "fleet-management"}},
            {"tags": {"Application": "BOT"}},
            {"tags": {"projectName": "Edge Gateway "}},
        ]


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
                             f"(~{cap * 1024:,.0f} MB). Everything sent after the cap - App Insights telemetry, VM "
                             f"and audit logs - is dropped, typically during incidents when volume spikes."),
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

def budget_scope(budget: Dict[str, Any]) -> str:
    """'/subscriptions/x' or '/subscriptions/x/resourcegroups/rg' - where the budget applies (lower case)."""
    return str(budget.get("id") or "").lower().split("/providers/microsoft.consumption/budgets/")[0]


def describe_budget_filter(cost_filter: Dict[str, Any]) -> str:
    """'MeterSubCategory in Azure OpenAI GPT5' for a budget filter (dimensions / tags, and-combined)."""
    parts = []
    for clause in (cost_filter.get("and") or []) + [cost_filter]:
        for kind in ("dimensions", "tags"):
            c = clause.get(kind) if isinstance(clause, dict) else None
            if c:
                parts.append(f"{'tag ' if kind == 'tags' else ''}{c.get('name')} in {', '.join(map(str, c.get('values') or []))}")
    return "; ".join(parts) or "a filter"


@register_scanner
class BudgetScanner(PostureScanner):
    """
    Live mode reads Consumption budgets and 6 full months of actual cost at each budget's own scope (subscription
    or resource group) and filter (e.g. one model's meter) - the way Azure evaluates it.
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
    MISSING_HIGH_MONTHLY_USD = 10000.0

    async def scan(self, context: ScanContext) -> ScanOutput:
        warnings: List[str] = []
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
            peak = max(monthly, key=lambda x: x.get("cost_usd") or 0.0) if monthly else None
            peak_usd = (peak or {}).get("cost_usd") or 0.0
            high_usd = float(self.setting("budget_missing_high_monthly_usd", self.MISSING_HIGH_MONTHLY_USD))
            spend = (f" Peak monthly spend in the last {len(monthly)} full months was "
                     f"{peak['cost']:,.0f} {peak.get('currency') or ''} ({peak['month']})." if peak and peak["cost"] else "")
            return ScanOutput(findings=[self.subscription_finding(
                context, finding_type="budget_missing", title="No budget on subscription",
                description="The subscription has no Cost Management budget, so overspend raises no alert." + spend,
                severity=SeverityLevel.HIGH if peak_usd >= high_usd else SeverityLevel.MEDIUM,
                remediation_steps="Create a monthly budget with actual and forecast alerts to the workload owners.",
                azure_cli_script=(f"az consumption budget create --budget-name monthly --amount <amount> --time-grain Monthly "
                                  f"--start-date {date.today().replace(day=1).isoformat()} --end-date 2030-12-31 --category Cost"),
                evidence={"months": monthly, "peak_monthly_usd": peak_usd, "high_threshold_usd": high_usd},
            )])

        findings = []
        signatures = [(budget_scope(x), json.dumps((x.get("properties") or {}).get("filter") or {}, sort_keys=True))
                      for x in budgets]
        for b in budgets:
            props = b.get("properties") or {}
            if (props.get("timeGrain") or "").lower() != "monthly":
                continue
            scope = budget_scope(b)
            cost_filter = props.get("filter") or {}
            # Each budget is judged like Azure judges it: its own scope (subscription or resource group) and filter.
            if self.is_live(context) and (scope != f"/subscriptions/{context.subscription_id}".lower() or cost_filter):
                try:
                    months = await self._monthly_costs(context, scope=scope, cost_filter=cost_filter or None)
                except Exception as exc:
                    warnings.append(f"Budget '{b.get('name')}': scoped cost unavailable ({exc}); not evaluated.")
                    continue
            else:
                months = monthly
            amount = float(props.get("amount") or 0)
            start_month = str((props.get("timePeriod") or {}).get("startDate") or "")[:7]
            eligible = [m for m in months if not start_month or m["month"] >= start_month]
            over = [m for m in eligible if amount and m["cost"] > amount]
            required = min(int(self.setting("overrun_months", self.OVERRUN_MONTHS)), len(eligible))
            if len(eligible) < 2 or len(over) < required:
                continue
            notifications = props.get("notifications") or {}
            owner_contacts = any(n.get("contactEmails") or n.get("contactRoles") for n in notifications.values())
            currency = next((m.get("currency") for m in eligible if m.get("currency")), "")
            peak = max(m["cost"] for m in eligible)
            current = props.get("currentSpend") or {}
            duplicates = signatures.count((scope, json.dumps(cost_filter, sort_keys=True))) - 1
            rg = scope.split("/resourcegroups/")[1] if "/resourcegroups/" in scope else None
            covers = (f"resource group {rg}" if rg else "the whole subscription") + (
                f", filtered to {describe_budget_filter(cost_filter)}" if cost_filter else "")
            findings.append(self.make_finding(
                finding_type="budget_consistently_exceeded",
                title=f"Budget '{b.get('name')}' exceeded in {len(over)}/{len(eligible)} months",
                description=(
                    f"Monthly budget '{b.get('name')}' ({amount:,.0f} {currency}, covering {covers}): its actual cost "
                    f"exceeded it in {len(over)} of the {len(eligible)} full months since it applies (peak "
                    f"{peak:,.0f} {currency}, {peak / amount:.0%} of budget)"
                    + (f"; this month so far {float(current.get('amount') or 0):,.0f} {current.get('unit') or currency}"
                       if current.get("amount") is not None else "") + ". "
                    + ("Alerts reach only action groups - no owner e-mail or role is notified. "
                       if not owner_contacts else "Owners are notified, yet spend stays above budget. ")
                    + (f"{duplicates} other budget(s) cover exactly the same scope and filter; duplicates dilute "
                       f"ownership." if duplicates else "")
                ),
                resource_id=b.get("id") or f"/subscriptions/{context.subscription_id}/providers/Microsoft.Consumption/budgets/{b.get('name')}",
                resource_name=b.get("name"),
                resource_type="microsoft.consumption/budgets",
                resource_group=rg or "(subscription)",
                subscription_id=context.subscription_id,
                location="global",
                remediation_steps=("Agree a realistic budget per workload with its owner, add owner e-mails/roles to "
                                   "the notifications, and define what happens on breach (review, freeze, escalate)."),
                evidence={"budget_amount": amount, "budget_start": start_month, "scope": scope,
                          "filter": cost_filter or None, "months": eligible, "current_spend": current or None,
                          "owner_contacts": owner_contacts, "duplicate_budgets": duplicates,
                          "budgets_on_subscription": [x.get("name") for x in budgets]},
                estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(budgets), warnings=warnings)

    async def _monthly_costs(self, context: ScanContext, scope: Optional[str] = None,
                             cost_filter: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        first_this_month = date.today().replace(day=1)
        start = first_this_month
        for _ in range(self.MONTHS):
            start = (start - timedelta(days=1)).replace(day=1)
        # Budgets are evaluated on actual (invoiced) cost, not amortized, at their own scope and filter.
        rows = await run_cost_query(context, start, first_this_month - timedelta(days=1), [], granularity="Monthly",
                                    cost_type=ACTUAL_COST, scope=scope, cost_filter=cost_filter) or []
        months = []
        for r in rows:
            month = str(r.get("BillingMonth") or r.get("UsageDate") or "")[:7]
            if len(month) == 8 and month.isdigit():
                month = f"{month[:4]}-{month[4:6]}"
            cost = float(r.get("Cost") or 0.0)
            usd = r.get("CostUSD")
            if usd is None and (r.get("Currency") or "").upper() == "USD":
                usd = cost
            months.append({"month": month, "cost": cost, "cost_usd": float(usd) if usd is not None else None,
                           "currency": r.get("Currency")})
        return sorted(months, key=lambda m: m["month"])

    def _mock_sets(self):
        budgets = [{"name": "governance_budget", "id": "/subscriptions/sub-1/providers/Microsoft.Consumption/budgets/"
                    "governance_budget", "properties": {
            "timeGrain": "Monthly", "amount": 2600,
            "notifications": {"actual_90": {"contactGroups": ["/subscriptions/sub-1/.../actionGroups/ag-cloud-team"],
                                            "contactEmails": [], "contactRoles": []}}}}]
        monthly = [{"month": m, "cost": c, "currency": "CHF"} for m, c in
                   (("2026-03", 4549), ("2026-04", 4699), ("2026-05", 6733),
                    ("2026-06", 6937), ("2026-07", 8056), ("2026-08", 7513))]
        return budgets, monthly


# ---------------------------------------------------------------------------
# 9. Resource types that Azure Policy denies but that exist
# ---------------------------------------------------------------------------

@register_scanner
class ResourceProviderPolicyScanner(PostureScanner):
    """
    Resource types in use that an applicable "Allowed resource types" / "Not allowed resource types" assignment
    denies - usually resources created before the policy, which now sit outside the governance model. Registration
    hygiene (blocked or unused providers) is ResourceProviderRegistrationScanner's job.

    Emits finding_type="resource_type_denied_by_policy".
    """

    scanner_name = "resource_provider_policy_scanner"
    display_name = "Resource Types Denied by Policy"
    description = "Detects resources whose type an applicable allow / deny resource-type policy does not permit"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        if self.is_live(context) and context.resource_graph_client is not None:
            try:
                analysis = await get_provider_analysis(context)
            except Exception as e:
                return ScanOutput(warnings=[f"Resource provider analysis unavailable: {e}"])
        else:
            analysis = self._mock_data()[0]
        denied = (analysis or {}).get("denied_in_use") or []
        if not denied:
            return ScanOutput(resources_scanned=len((analysis or {}).get("providers") or []))
        resources = sum(d["resources"] for d in denied)
        types = sorted({d["type"] for d in denied})
        finding = self.subscription_finding(
            context,
            finding_type="resource_type_denied_by_policy",
            title=f"{resources} resource(s) of {len(types)} type(s) that Azure Policy denies",
            description=("Resources exist whose type an assigned resource-type policy does not allow: "
                         + "; ".join(f"{d['type']} x{d['resources']} ({d['effect']} '{d['policy']}'"
                                     f"{'' if d['enforced'] else ', not enforced'})" for d in denied)
                         + ". They were usually created before the policy or through an exemption, and now sit "
                           "outside the agreed governance model."),
            remediation_steps=("1. Confirm with the owner whether each resource is still needed.\n"
                               "2. Migrate it to an allowed type or remove it, or record a policy exemption with an "
                               "expiry date if it must stay."),
            evidence={"denied_in_use": denied, "policies": (analysis or {}).get("policies")},
        )
        return ScanOutput(findings=[finding], resources_scanned=len((analysis or {}).get("providers") or []))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [build_analysis(
            "sub-1",
            [{"namespace": "Microsoft.Compute", "registrationState": "Registered",
              "registrationPolicy": "RegistrationRequired"},
             {"namespace": "Microsoft.Storage", "registrationState": "Registered",
              "registrationPolicy": "RegistrationRequired"}],
            {"microsoft.compute/virtualmachines": 2, "microsoft.storage/storageaccounts": 3}, ["mg-prod"],
            [{"name": "VM creation not allowed (prod)", "scope": "/providers/microsoft.management/managementgroups/mg-prod",
              "def": "/providers/microsoft.authorization/policydefinitions/6c112d4e-5bc7-47ae-a041-ea2d9dccd749",
              "enforcement": "Default", "denied": ["Microsoft.Compute/virtualMachines"]}])]


# ---------------------------------------------------------------------------
# 10. Resource provider registration hygiene
# ---------------------------------------------------------------------------

@register_scanner
class ResourceProviderRegistrationScanner(PostureScanner):
    """
    A registered resource provider is permission for the subscription to host that service. Microsoft's guidance is
    to register a provider only when it is about to be used, so that nothing can be deployed with the others.

    - resource_provider_blocked_registered: a provider on the `blocked_resource_providers` list (default: the retired
      classic providers) is registered.
    - resource_providers_registered_unused (opt-in, `report_unused_providers`): niche providers registered with no
      resources - core services and the governance baseline excluded; informational, since unregistering saves
      nothing and a resource-type policy is the control that sticks.
    """

    scanner_name = "resource_provider_registration_scanner"
    display_name = "Resource Provider Registration"
    description = "Detects blocked resource providers that are registered, and registered providers nobody uses"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.LOW
    finding_types = {"resource_provider_blocked_registered", "resource_providers_registered_unused"}

    async def scan(self, context: ScanContext) -> ScanOutput:
        if self.is_live(context) and context.resource_graph_client is not None:
            try:
                analysis = await get_provider_analysis(context)
            except Exception as e:
                return ScanOutput(warnings=[f"Resource provider analysis unavailable: {e}"])
        else:
            analysis = self._mock_data()[0]
        rows = (analysis or {}).get("providers") or []
        sub = context.subscription_id
        findings = []

        blocked = blocked_registered(rows, self.setting("blocked_resource_providers", list(DEFAULT_BLOCKED_PROVIDERS)))
        if blocked:
            in_use = [r for r in blocked if r["resources"]]
            findings.append(self.subscription_finding(
                context,
                finding_type="resource_provider_blocked_registered",
                title=f"{len(blocked)} blocked resource provider(s) registered: "
                      + ", ".join(r["namespace"] for r in blocked[:3]) + ("…" if len(blocked) > 3 else ""),
                description=("Resource providers on the block list are registered, so the subscription accepts their "
                             "resources: " + ", ".join(f"{r['namespace']} ({r['resources']} resources)" for r in blocked)
                             + "." + (" Resources exist - they must be migrated or removed before the provider can "
                                      "be unregistered." if in_use else "")),
                severity=SeverityLevel.MEDIUM if in_use else SeverityLevel.LOW,
                remediation_steps=("1. Confirm nobody needs the provider (no resources, no pipeline that deploys it).\n"
                                   "2. Unregister it.\n"
                                   "3. Prevent re-registration with a 'Not allowed resource types' assignment at the "
                                   "management group. The block list is the `blocked_resource_providers` setting."),
                azure_cli_script="\n".join(f"az provider unregister --namespace {r['namespace']} --subscription {sub}"
                                           for r in blocked),
                evidence={"blocked_registered": [{k: r[k] for k in ("namespace", "state", "resources", "types")}
                                                 for r in blocked],
                          "cost_of_change": {"monthly_usd": 0.0, "basis": "registration changes are free"}},
            ))

        unused = unused_registered(rows) if self.setting("report_unused_providers", False) else []
        if unused:
            names = [r["namespace"] for r in unused]
            findings.append(self.subscription_finding(
                context,
                finding_type="resource_providers_registered_unused",
                title=f"{len(unused)} niche resource provider(s) registered but not used",
                description=("Registered with no resources in the subscription: " + ", ".join(names)
                             + ". Core services (Compute, Storage, Network, Key Vault, Web, ...) and the governance "
                               "baseline (Defender, Policy, Monitor, Cost Management) are excluded - they are expected "
                               "to be registered. For information: a registration costs nothing and unregistering "
                               "saves nothing; it only stops that service being deployed until someone registers it "
                               "again (the portal does it automatically for anyone with rights)."),
                severity=SeverityLevel.INFO,
                remediation_steps=("1. If the company does not allow one of these services, block it where it sticks: "
                                   "a 'Not allowed resource types' (or 'Allowed resource types') policy at the "
                                   "management group.\n"
                                   "2. Optional, only for providers registered by a one-off test that nobody will "
                                   "use: unregister them (commands below) - reversible, and Azure refuses while "
                                   "resources of the provider exist.\n"
                                   "3. Never unregister core service providers - the next deployment fails until "
                                   "they are registered again."),
                azure_cli_script=("# Optional - only providers nobody will deploy:\n"
                                  + "\n".join(f"# az provider unregister --namespace {n} --subscription {sub}"
                                              for n in names)),
                evidence={"unused_registered": names,
                          "cost_of_change": {"monthly_usd": 0.0, "basis": "registration changes are free"}},
            ))
        return ScanOutput(findings=findings, resources_scanned=len(rows))

    def _mock_data(self) -> List[Dict[str, Any]]:
        def provider(ns: str, state: str = "Registered", policy: str = "RegistrationRequired") -> Dict[str, str]:
            return {"namespace": ns, "registrationState": state, "registrationPolicy": policy}

        return [build_analysis(
            "sub-1",
            [provider("Microsoft.Compute"), provider("Microsoft.Web"), provider("Microsoft.Security"),
             provider("Microsoft.ClassicCompute"), provider("Microsoft.Resources", policy="RegistrationFree"),
             provider("Microsoft.Sql", state="NotRegistered")],
            {"microsoft.compute/virtualmachines": 2}, [], [])]


# ---------------------------------------------------------------------------
# 11. Service retirements (Azure Advisor)
# ---------------------------------------------------------------------------

def _days_left(value: str, today: date) -> Optional[int]:
    try:
        return (date.fromisoformat(str(value)[:10]) - today).days
    except ValueError:
        return None


@register_scanner
class ServiceRetirementScanner(PostureScanner):
    """
    Features, API versions, SKUs, VM series and runtimes Azure is retiring that a resource still uses, from Advisor's
    open "ServiceUpgradeAndRetirement" recommendations (completed / dismissed ones are left out). One finding per
    resource, dated: overdue or within `retirement_urgent_days` (90) is High, within a year Medium, later Low.
    """

    scanner_name = "service_retirement_scanner"
    display_name = "Service Retirements"
    description = "Detects Azure retirements (features, API versions, SKUs, runtimes) that affect a resource, with dates"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.MEDIUM
    finding_types = {"service_retirement"}

    URGENT_DAYS = 90

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = f"""
        advisorresources
        | where type =~ 'microsoft.advisor/recommendations'
        | where subscriptionId == '{context.subscription_id}'
        | where tostring(properties.extendedProperties.recommendationSubCategory) == 'ServiceUpgradeAndRetirement'
        {ADVISOR_ACTIVE_FILTER}
        | project resource_id = tostring(properties.resourceMetadata.resourceId),
                  problem = tostring(properties.shortDescription.problem),
                  solution = tostring(properties.shortDescription.solution),
                  impact = tostring(properties.impact),
                  impacted_type = tolower(tostring(properties.impactedField)),
                  impacted_name = tostring(properties.impactedValue),
                  retirement_date = tostring(properties.extendedProperties.retirementDate),
                  feature = trim(' ', tostring(properties.extendedProperties.retirementFeatureName)),
                  cost_implication = tostring(properties.extendedProperties.recommendationCostImplication),
                  changes = tostring(properties.extendedProperties.descriptionOfChanges),
                  api_version = tostring(properties.extendedProperties.apiVersion),
                  last_call = tostring(properties.extendedProperties.lastCall)
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])
        gone = await missing_resources(context, [r.get("resource_id") for r in rows])
        rows = [r for r in rows if top_level_id(r.get("resource_id")) not in gone]

        today = date.fromisoformat(self.setting("as_of", date.today().isoformat()))
        urgent = int(self.setting("retirement_urgent_days", self.URGENT_DAYS))
        # Advisor files general upgrade advice under the same sub-category ("Migrate workload to VMSS Flex",
        # "Convert Standard to Premium disk") - without a retirement date it is not a retirement.
        if not self.setting("retirement_include_undated", False):
            undated = sum(1 for r in rows if not (r.get("retirement_date") or "").strip())
            rows = [r for r in rows if (r.get("retirement_date") or "").strip()]
        else:
            undated = 0
        by_resource: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            rid = r.get("resource_id") or f"/subscriptions/{context.subscription_id}"
            items = by_resource.setdefault(rid.lower(), [])
            if any(i["problem"] == r.get("problem") for i in items):
                continue
            try:
                changes = json.loads(r.get("changes") or "[]")
            except ValueError:
                changes = [r.get("changes")] if r.get("changes") else []
            items.append({
                "problem": r.get("problem") or "Retirement", "solution": r.get("solution") or "",
                "feature": r.get("feature") or "", "retirement_date": (r.get("retirement_date") or "")[:10] or None,
                "days_left": _days_left(r.get("retirement_date") or "", today),
                "impact": r.get("impact") or "", "cost_implication": r.get("cost_implication") or None,
                "changes": [str(c) for c in changes if c] if isinstance(changes, list) else [str(changes)],
                "api_version": r.get("api_version") or None, "last_call": (r.get("last_call") or "")[:10] or None,
                "impacted_type": r.get("impacted_type") or "", "impacted_name": r.get("impacted_name") or "",
                "resource_id": rid,
            })

        findings = []
        for items in by_resource.values():
            rid = items[0]["resource_id"]
            items.sort(key=lambda i: (i["days_left"] is None, i["days_left"] if i["days_left"] is not None else 0))
            first = items[0]
            days = first["days_left"]
            if days is None:
                severity, when = SeverityLevel.LOW, "Retirement announced (no date)"
            elif days < 0:
                severity, when = SeverityLevel.HIGH, f"Past retirement date {first['retirement_date']}"
            else:
                severity = (SeverityLevel.HIGH if days <= urgent else
                            SeverityLevel.MEDIUM if days <= 365 else SeverityLevel.LOW)
                when = f"Retires {first['retirement_date']} ({days} days)"
            name = first["impacted_name"] or rid.rsplit("/", 1)[-1]
            slot = re.search(r"/sites/([^/]+)/slots/([^/]+)$", rid, re.IGNORECASE)
            if slot:   # Advisor names a slot by the slot alone ('dev', 'stage') - say whose
                name = f"{slot.group(1)}/{slot.group(2)}"
            label = first["feature"] or first["problem"]
            no_cost = all((i["cost_implication"] or "").lower() == "none" for i in items)

            def line(i: Dict[str, Any]) -> str:
                left = i["days_left"]
                if not i["retirement_date"] or left is None:
                    return f"{i['problem']} - date not announced"
                return f"{i['problem']} - {i['retirement_date']} ({'overdue' if left < 0 else f'{left} days left'})"

            parts = rid.split("/")
            lowered = [p.lower() for p in parts]
            rg = parts[lowered.index("resourcegroups") + 1] if "resourcegroups" in lowered else "(subscription)"
            kwargs = dict(
                finding_type="service_retirement",
                title=(f"{when}: {label} ({name})" if len(items) == 1
                       else f"{when}: {label} and {len(items) - 1} more ({name})"),
                description=("Azure is retiring what this resource uses: " + "; ".join(line(i) for i in items)
                             + ". After the date the feature stops working or loses support and security fixes."),
                severity=severity,
                remediation_steps="\n".join(
                    f"- {i['solution'] or i['problem']}"
                    + (f" (API version in use: {i['api_version']}" + (f", last call {i['last_call']}" if i["last_call"] else "") + ")"
                       if i["api_version"] else "")
                    + (f" Change: {'; '.join(i['changes'])}." if i["changes"] else "")
                    for i in items)
                + "\nPlan the change before the first date; the Advisor 'Service Retirement' workbook lists every "
                  "affected resource across subscriptions.",
                evidence={"retirements": items,
                          **({"cost_of_change": {"monthly_usd": 0.0,
                                                 "basis": "Advisor states no cost implication"}} if no_cost else {})},
                estimated_monthly_savings_usd=0.0,
            )
            if len(parts) <= 3:
                findings.append(self.subscription_finding(context, **kwargs))
            else:
                provider_idx = lowered.index("providers") if "providers" in lowered else -1
                rtype = "/".join(lowered[provider_idx + 1:provider_idx + 3]) if provider_idx > 0 else first["impacted_type"]
                findings.append(self.make_finding(resource_id=rid, resource_name=name, resource_type=rtype,
                                                  resource_group=rg, subscription_id=context.subscription_id,
                                                  location="", **kwargs))
        return ScanOutput(findings=findings, resources_scanned=len(rows),
                          metadata={"undated_upgrade_advice_skipped": undated} if undated else {})

    def _mock_data(self) -> List[Dict[str, Any]]:
        kv = "/subscriptions/sub-1/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-legacy-1"
        app = "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/sites/app-portal"
        return [
            {"resource_id": kv, "problem": "Azure Key Vault API versions prior to 2026-02-01 are being retired",
             "solution": "Azure Key Vault API versions prior to 2026-02-01 are being retired", "impact": "High",
             "impacted_type": "microsoft.keyvault/vaults", "impacted_name": "kv-legacy-1",
             "retirement_date": "2027-02-27", "feature": "API versions prior to 2026-02-01",
             "cost_implication": "None", "changes": "[\"No Cost Impact\"]", "api_version": "2019-09-01"},
            {"resource_id": app, "problem": "Community support for Node 20 LTS is ending",
             "solution": "Upgrade the app to Node 22 LTS", "impact": "Medium", "impacted_type": "microsoft.web/sites",
             "impacted_name": "app-portal", "retirement_date": "2026-04-30", "feature": "Support for Node 20 LTS"},
        ]
