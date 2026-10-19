"""
Azure Resource Guardian - Security Posture Scanners
====================================================
Scanners in this module:
1. KeyVaultHardeningScanner        - Access-policy model, soft delete, purge protection, open network
2. AIServicesHardeningScanner      - Foundry / Azure OpenAI key auth and open network access
3. DefenderPlanCoverageScanner     - Defender plans left on Free while matching resources exist, with their
                                     estimated monthly cost (off by default: `defender_plan_coverage`)
4. DefenderRecommendationsScanner  - Unhealthy Defender for Cloud assessments (High by default), without the paid
                                     plan-enablement recommendations unless `defender_plan_recommendations` is on
5. PrivilegedRoleAssignmentScanner - Owners > 3, standing User Access Administrator, privileged SPs
6. SecureScoreScanner              - Defender secure score below target

Covers the "Microsoft Defender for Cloud integration" roadmap item by
reading securityresources through Resource Graph (no extra SDK needed).
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from typing import Any, Dict, List, Optional, Tuple

from scanners.base import access_need
from scanners.base.azure_api import DEFAULT_ARM_CONCURRENCY, cached_metrics, gather_limited, get_defender_plans
from scanners.base.guidance import PRICE, PRICES_AS_OF, html_links, html_to_text, portal_link
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.posture_scanner import PostureScanner
from scanners.security import defender_guidance

ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
ROLE_CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
ROLE_UAA = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
ROLE_NAMES = {ROLE_OWNER: "Owner", ROLE_CONTRIBUTOR: "Contributor", ROLE_UAA: "User Access Administrator"}

# Defender plan -> resource types that make the plan relevant ('*' = always relevant).
DEFENDER_PLAN_RESOURCES: Dict[str, List[str]] = {
    "AI": ["microsoft.cognitiveservices/accounts"],
    "CloudPosture": ["*"],
    "StorageAccounts": ["microsoft.storage/storageaccounts"],
    "SqlServers": ["microsoft.sql/servers"],
    "AppServices": ["microsoft.web/serverfarms"],
    "KeyVaults": ["microsoft.keyvault/vaults"],
    "VirtualMachines": ["microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets"],
    "CosmosDbs": ["microsoft.documentdb/databaseaccounts"],
    "Api": ["microsoft.apimanagement/service"],
    "Containers": ["microsoft.containerservice/managedclusters", "microsoft.containerregistry/registries"],
    "OpenSourceRelationalDatabases": ["microsoft.dbforpostgresql/flexibleservers", "microsoft.dbformysql/flexibleservers"],
    "Arm": ["*"],
}
HIGH_VALUE_PLANS = {"AI", "CloudPosture", "SqlServers", "StorageAccounts", "KeyVaults"}

# Defender plan -> (monthly USD list price per unit, unit, what counts as a unit, when the plan is worth its price).
# Units: "resources" = matching resources, "instances" = sum of sku.capacity (App Service plan / VMSS instances),
# "subscription" = one per subscription; None price = usage-based (tokens, RU/s, vCores, API calls).
DEFENDER_PLAN_COST: Dict[str, Tuple[Optional[float], str, str, str]] = {
    "VirtualMachines": (PRICE["defender_servers_p1"], "server (Plan 1)", "resources",
                        "worth it for production and internet-facing servers (EDR, vulnerability assessment); "
                        "Plan 2 (about USD 14.60) adds JIT and file integrity monitoring"),
    "StorageAccounts": (PRICE["defender_storage_account"], "storage account", "resources",
                        "worth it for accounts that receive files from outside (malware scanning, USD 0.15/GB scanned) "
                        "or hold confidential data; not for diagnostics, function runtime or Cloud Shell accounts - "
                        "exclude those per account"),
    "SqlServers": (PRICE["defender_sql_server"], "logical server", "resources",
                   "worth it for servers with production or personal data; not for dev/test"),
    "AppServices": (PRICE["defender_app_service_instance"], "plan instance", "instances",
                    "worth it for internet-facing production apps"),
    "KeyVaults": (PRICE["defender_key_vault"], "vault", "resources",
                  "cheap; worth it wherever vaults hold production secrets"),
    "Arm": (PRICE["defender_arm_subscription"], "subscription", "subscription",
            "cheap; detects suspicious management-plane operations - usually enabled for all subscriptions centrally"),
    "CloudPosture": (PRICE["defender_cspm_resource"], "billable resource (VMs, storage accounts, databases)",
                     "cspm", "attack-path analysis and agentless scanning; decide centrally at management-group level"),
    "OpenSourceRelationalDatabases": (PRICE["defender_oss_db_server"], "server", "resources",
                                      "worth it for production PostgreSQL / MySQL with sensitive data"),
    "AI": (None, "1,000 tokens (USD 0.0008)", "usage",
           "prompt-injection / jailbreak detection; worth it for user-facing generative-AI apps"),
    "CosmosDbs": (None, "100 RU/s (USD 0.88 per month)", "usage", "worth it for production accounts with sensitive data"),
    "Containers": (PRICE["defender_containers_vcore"], "AKS vCore", "usage",
                   "worth it for production clusters; priced per vCore of the node pools"),
    "Api": (None, "plan by API call volume", "usage", "only for public APIs with sensitive data"),
}
CSPM_BILLABLE_TYPES = ("microsoft.compute/virtualmachines", "microsoft.storage/storageaccounts", "microsoft.sql/servers",
                       "microsoft.dbforpostgresql/flexibleservers", "microsoft.dbformysql/flexibleservers")


def defender_plan_cost(plan: str, counts: Dict[str, int], units: Dict[str, int]) -> Dict[str, Any]:
    """Estimated monthly list price of enabling one Defender plan on this subscription's current resources."""
    price, unit, basis, worth = DEFENDER_PLAN_COST.get(plan, (None, "resource", "usage", ""))
    types = DEFENDER_PLAN_RESOURCES.get(plan, [])
    if basis == "subscription":
        quantity = 1
    elif basis == "instances":
        quantity = sum(units.get(t, 0) or counts.get(t, 0) for t in types)
    elif basis == "cspm":
        quantity = sum(counts.get(t, 0) for t in CSPM_BILLABLE_TYPES)
    elif basis == "resources":
        quantity = sum(counts.get(t, 0) for t in types)
    else:
        quantity = None
    monthly = round(price * quantity, 2) if price is not None and quantity is not None else None
    return {"plan": plan, "unit": unit, "unit_price_usd": price, "units": quantity, "monthly_usd": monthly,
            "worth_it_when": worth}

_SEVERITY_MAP = {"high": SeverityLevel.HIGH, "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW}


async def _requests_30d(scanner: PostureScanner, context: ScanContext, items: List[Dict[str, Any]], metric: str,
                        warnings: List[str]) -> None:
    """item["requests_30d"] = the metric's 30-day total (live scans only; None when unavailable)."""
    if not scanner.is_live(context) or not items:
        return

    async def fetch(item: Dict[str, Any]) -> None:
        try:
            m = await cached_metrics(context, item["id"], [metric], days=30, interval="P1D", aggregation="Total")
            item["requests_30d"] = (m.get(metric) or {}).get("total") or 0.0
        except Exception as exc:
            warnings.append(f"{metric} unavailable for {item.get('name')}: {exc}")
    await gather_limited(items, fetch, scanner.setting("arm_concurrency", DEFAULT_ARM_CONCURRENCY))


def _open_network(public: Any, acl: Any, pe_count: Any) -> bool:
    if (public or "Enabled").lower() == "disabled" or pe_count:
        return False
    return (acl or "Allow").lower() == "allow"


# ---------------------------------------------------------------------------
# 1. Key Vault hardening
# ---------------------------------------------------------------------------

@register_scanner
class KeyVaultHardeningScanner(PostureScanner):
    scanner_name = "key_vault_hardening_scanner"
    display_name = "Key Vault Hardening"
    description = "Detects Key Vaults on access policies, without soft delete/purge protection, or open to all networks"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.HIGH

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.keyvault/vaults'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  rbac = tobool(properties.enableRbacAuthorization),
                  soft_delete = tobool(properties.enableSoftDelete),
                  purge_protection = tobool(properties.enablePurgeProtection),
                  public_network = tostring(properties.publicNetworkAccess),
                  default_action = tostring(properties.networkAcls.defaultAction),
                  ip_rules = array_length(properties.networkAcls.ipRules),
                  vnet_rules = array_length(properties.networkAcls.virtualNetworkRules),
                  pe_count = array_length(properties.privateEndpointConnections)
        """
        try:
            vaults = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings: List[str] = []
        await _requests_30d(self, context, [kv for kv in vaults if _open_network(
            kv.get("public_network"), kv.get("default_action"), kv.get("pe_count"))], "ServiceApiHit", warnings)
        findings = []
        for kv in vaults:
            rg, name = kv.get("resourceGroup"), kv["name"]
            common = {"resource_type": "microsoft.keyvault/vaults", "estimated_monthly_savings_usd": 0.0}
            if kv.get("rbac") is not True:
                findings.append(self.resource_finding(
                    kv, finding_type="key_vault_access_policy_model", title=f"Key Vault uses access policies: {name}",
                    description=(f"Key Vault '{name}' uses the legacy access-policy model: permissions are not visible "
                                 f"in Azure RBAC, cannot be PIM-managed and any vault Contributor can grant themselves data access."),
                    severity=SeverityLevel.HIGH,
                    remediation_steps="Map access policies to RBAC roles (Key Vault Secrets User, etc.), then switch the permission model.",
                    azure_cli_script=f"az keyvault update -g {rg} -n {name} --enable-rbac-authorization true",
                    evidence={"enableRbacAuthorization": kv.get("rbac")}, **common,
                ))
            # Azure enforces soft delete on every vault (it can no longer be turned off); a vault that does not report
            # the property has it. Only an explicit false - a legacy vault not yet migrated - is a gap.
            if kv.get("soft_delete") is False:
                findings.append(self.resource_finding(
                    kv, finding_type="key_vault_soft_delete_disabled", title=f"Key Vault soft delete disabled: {name}",
                    description=f"Key Vault '{name}' reports soft delete disabled - deleted secrets, keys and certificates are unrecoverable.",
                    severity=SeverityLevel.HIGH,
                    remediation_steps="Enable soft delete (mandatory for new vaults; legacy vaults must be updated).",
                    azure_cli_script=f"az keyvault update -g {rg} -n {name} --enable-soft-delete true",
                    evidence={"enableSoftDelete": kv.get("soft_delete")}, **common,
                ))
            if kv.get("purge_protection") is not True:
                findings.append(self.resource_finding(
                    kv, finding_type="key_vault_purge_protection_disabled", title=f"Purge protection disabled: {name}",
                    description=f"Key Vault '{name}' can be purged immediately after deletion (no purge protection).",
                    severity=SeverityLevel.MEDIUM,
                    remediation_steps="Enable purge protection (irreversible - confirm no automation depends on purging).",
                    azure_cli_script=f"az keyvault update -g {rg} -n {name} --enable-purge-protection true",
                    evidence={"enablePurgeProtection": kv.get("purge_protection")}, cis_control="8.5", **common,
                ))
            if _open_network(kv.get("public_network"), kv.get("default_action"), kv.get("pe_count")):
                fix = await access_need.assess(self, context, "keyvault", kv, data_operations_30d=kv.get("requests_30d"),
                                               requests_label="API calls", ip_rules=kv.get("ip_rules") or 0,
                                               vnet_rules=kv.get("vnet_rules") or 0)
                decision = fix["decision"]
                findings.append(self.resource_finding(
                    kv, finding_type="key_vault_public_network_open",
                    title=f"Key Vault open to all networks: {name} - {decision['title'].lower()}",
                    description=(f"Key Vault '{name}' accepts requests from all networks and has no private endpoint "
                                 f"({decision['usage']}). {decision['why']}"),
                    severity=fix["severity"], remediation_steps=fix["remediation_steps"],
                    azure_cli_script=fix["azure_cli_script"],
                    evidence={"publicNetworkAccess": kv.get("public_network"), "defaultAction": kv.get("default_action"),
                              **fix["evidence"]},
                    **common,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(vaults), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-legacy-1",
            "name": "kv-legacy-1", "type": "microsoft.keyvault/vaults", "resourceGroup": "rg-sec",
            "subscriptionId": "sub-1", "location": "westeurope", "rbac": False, "soft_delete": False,
            "purge_protection": None, "public_network": "Enabled", "default_action": "", "pe_count": 0,
        }]


# ---------------------------------------------------------------------------
# 2. AI Services / Azure OpenAI hardening
# ---------------------------------------------------------------------------

@register_scanner
class AIServicesHardeningScanner(PostureScanner):
    scanner_name = "ai_services_hardening_scanner"
    display_name = "AI Services (Foundry / OpenAI) Hardening"
    description = "Detects AI Services accounts with key authentication enabled or open network access"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.HIGH

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.cognitiveservices/accounts'
        | project id, name, type, resourceGroup, subscriptionId, location, tags, kind,
                  local_auth_disabled = tobool(properties.disableLocalAuth),
                  public_network = tostring(properties.publicNetworkAccess),
                  default_action = tostring(properties.networkAcls.defaultAction),
                  ip_rules = array_length(properties.networkAcls.ipRules),
                  vnet_rules = array_length(properties.networkAcls.virtualNetworkRules),
                  pe_count = array_length(properties.privateEndpointConnections)
        """
        try:
            accounts = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings: List[str] = []
        await _requests_30d(self, context, [a for a in accounts if _open_network(
            a.get("public_network"), a.get("default_action"), a.get("pe_count"))], "TotalCalls", warnings)
        findings = []
        for acc in accounts:
            name = acc["name"]
            genai = (acc.get("kind") or "").lower() in ("openai", "aiservices")
            if acc.get("local_auth_disabled") is not True:
                findings.append(self.resource_finding(
                    acc, finding_type="ai_services_local_auth_enabled", title=f"API-key auth enabled: {name}",
                    description=(f"{acc.get('kind')} account '{name}' accepts API keys. Keys are shared secrets with no "
                                 f"per-caller identity, so token spend and abuse cannot be attributed."),
                    resource_type="microsoft.cognitiveservices/accounts",
                    severity=SeverityLevel.HIGH if genai else SeverityLevel.MEDIUM,
                    remediation_steps=("Give callers managed identities with 'Cognitive Services OpenAI User' / "
                                       "'Azure AI User', then disable local auth."),
                    azure_cli_script=(f"az resource update --ids {acc['id']} --set properties.disableLocalAuth=true"),
                    evidence={"disableLocalAuth": acc.get("local_auth_disabled"), "kind": acc.get("kind")},
                    estimated_monthly_savings_usd=0.0,
                ))
            if _open_network(acc.get("public_network"), acc.get("default_action"), acc.get("pe_count")):
                fix = await access_need.assess(self, context, "ai", acc, data_operations_30d=acc.get("requests_30d"),
                                               requests_label="calls", ip_rules=acc.get("ip_rules") or 0,
                                               vnet_rules=acc.get("vnet_rules") or 0)
                decision = fix["decision"]
                findings.append(self.resource_finding(
                    acc, finding_type="ai_services_public_network_open",
                    title=f"AI endpoint open to all networks: {name} - {decision['title'].lower()}",
                    description=(f"{acc.get('kind')} account '{name}' accepts requests from any network and has no "
                                 f"private endpoint ({decision['usage']}). {decision['why']}"),
                    resource_type="microsoft.cognitiveservices/accounts", severity=fix["severity"],
                    remediation_steps=fix["remediation_steps"], azure_cli_script=fix["azure_cli_script"],
                    evidence={"publicNetworkAccess": acc.get("public_network"), "defaultAction": acc.get("default_action"),
                              **fix["evidence"]},
                    estimated_monthly_savings_usd=0.0,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(accounts), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/aoai-dev-1",
            "name": "aoai-dev-1", "type": "microsoft.cognitiveservices/accounts", "resourceGroup": "rg-ai",
            "subscriptionId": "sub-1", "location": "westeurope", "kind": "AIServices",
            "local_auth_disabled": None, "public_network": "Enabled", "default_action": "Allow", "pe_count": 0,
        }]


# ---------------------------------------------------------------------------
# 3. Defender plan coverage
# ---------------------------------------------------------------------------

@register_scanner
class DefenderPlanCoverageScanner(PostureScanner):
    """
    Paid Defender plans left on Free while resources they would protect exist, with what each plan would cost on
    this subscription. Off by default (`defender_plan_coverage`): which plans to buy is a central cost decision, not
    a per-subscription gap, and the finding is only useful when that decision is being prepared.
    """

    scanner_name = "defender_plan_coverage_scanner"
    display_name = "Defender for Cloud Plan Coverage"
    description = "Defender plans on the Free tier while matching resources exist, with the cost of enabling each"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.MEDIUM
    requires_defender = True
    finding_types = {"defender_plan_disabled"}

    async def scan(self, context: ScanContext) -> ScanOutput:
        if not self.setting("defender_plan_coverage", False):
            return ScanOutput(metadata={"disabled_by_setting": "defender_plan_coverage"})
        type_query = ("Resources | summarize n = count(), units = sum(toint(sku.capacity)) "
                      "by type = tolower(type)")
        try:
            if context.resource_graph_client is None:
                plans, counts, units = self._mock_sets()
            else:
                plans = await get_defender_plans(context) or {}
                rows = await self.arg(context, type_query)
                counts = {r["type"]: r["n"] for r in rows}
                units = {r["type"]: int(r.get("units") or 0) for r in rows}
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        gaps = []
        for plan, tier in plans.items():
            if (tier or "").lower() != "free" or plan not in DEFENDER_PLAN_RESOURCES:
                continue
            types = DEFENDER_PLAN_RESOURCES[plan]
            relevant = sum(counts.values()) if "*" in types else sum(counts.get(t, 0) for t in types)
            if relevant:
                gaps.append({"matching_resources": relevant, **defender_plan_cost(plan, counts, units)})
        if not gaps:
            return ScanOutput(resources_scanned=len(plans))

        known = sum(g["monthly_usd"] for g in gaps if g["monthly_usd"] is not None)
        usage = [g["plan"] for g in gaps if g["monthly_usd"] is None]

        def line(g: Dict[str, Any]) -> str:
            cost = (f"about USD {g['monthly_usd']:,.2f}/month ({g['units']} x USD {g['unit_price_usd']:,.2f} per "
                    f"{g['unit']})" if g["monthly_usd"] is not None else f"usage-based, per {g['unit']}")
            return f"- {g['plan']} ({g['matching_resources']} resources): {cost} - {g['worth_it_when']}."

        high = any(g["plan"] in HIGH_VALUE_PLANS for g in gaps)
        finding = self.subscription_finding(
            context,
            finding_type="defender_plan_disabled",
            title=f"{len(gaps)} Defender plan(s) on Free - about USD {known:,.0f}/month to enable all",
            description=("Defender for Cloud plans on Free although resources they protect exist: "
                         + ", ".join(f"{g['plan']} ({g['matching_resources']} resources)" for g in gaps)
                         + f". Enabling all of them would cost about USD {known:,.2f} per month at list price"
                         + (f" plus usage-based charges for {', '.join(usage)}" if usage else "") + "."),
            severity=SeverityLevel.HIGH if high else SeverityLevel.MEDIUM,
            remediation_steps=("Decide per plan, against its price, whether the protected data justifies it - this is "
                               "usually set once for all subscriptions at management-group level:\n"
                               + "\n".join(line(g) for g in gaps)
                               + f"\nPrices: USD list prices of {PRICES_AS_OF} (Azure Retail Prices API); enterprise "
                                 f"agreements differ. Record plans you decline as an exemption."),
            azure_cli_script="\n".join(f"az security pricing create -n {g['plan']} --tier Standard" for g in gaps),
            evidence={"disabled_plans": gaps,
                      "cost_of_change": {"monthly_usd": round(known, 2),
                                         "basis": "list price of every disabled plan for the resources that exist "
                                                  "today" + (f"; usage-based: {', '.join(usage)}" if usage else "")}},
        )
        return ScanOutput(findings=[finding], resources_scanned=len(plans))

    def _mock_sets(self):
        return ({"AI": "Free", "CloudPosture": "Free", "StorageAccounts": "Standard", "Containers": "Free"},
                {"microsoft.cognitiveservices/accounts": 5, "microsoft.storage/storageaccounts": 37},
                {})


# ---------------------------------------------------------------------------
# 4. Defender recommendations
# ---------------------------------------------------------------------------

@register_scanner
class DefenderRecommendationsScanner(PostureScanner):
    """
    One finding per resource summarising its unhealthy Defender assessments of the configured severities.

    Paid plan-enablement recommendations ("Microsoft Defender for Storage plan should be enabled ...") are left out
    unless `defender_plan_recommendations` is on - they are purchasing decisions, not configuration gaps. Per-package
    OS update assessments ("Update openssl", ...) are collapsed into one entry per machine. Each finding carries the
    curated guidance of scanners/security/defender_guidance.py (steps, commands for the resource) or, for other
    recommendations, Microsoft's own description, remediation text and links.
    """

    scanner_name = "defender_recommendations_scanner"
    display_name = "Defender for Cloud Recommendations"
    description = "Imports unhealthy Microsoft Defender for Cloud assessments (without paid-plan upsells)"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.HIGH
    requires_defender = True
    finding_types = {"defender_recommendations"}

    MAX_LISTED_UPDATES = 8

    async def scan(self, context: ScanContext) -> ScanOutput:
        # Off by default (`defender_recommendations`): Defender for Cloud is where these are worked on (exemptions,
        # owners, due dates); the report shows a summary with links instead of repeating them as findings.
        if not self.setting("defender_recommendations", False):
            return ScanOutput(metadata={"disabled_by_setting": "defender_recommendations"})
        severities = [s.lower() for s in self.setting("defender_severities", ["High"])]
        sev_filter = ", ".join(f"'{s}'" for s in severities)
        query = f"""
        securityresources
        | where type =~ 'microsoft.security/assessments'
        | where subscriptionId == '{context.subscription_id}'
        | where tostring(properties.status.code) =~ 'Unhealthy'
        | extend severity = tolower(tostring(properties.metadata.severity))
        | where severity in ({sev_filter})
        | project resource_id = tostring(properties.resourceDetails.Id),
                  assessment = tostring(properties.displayName), severity,
                  category = tostring(properties.metadata.categories[0]),
                  assessment_key = name,
                  recommendation_category = tostring(properties.metadata.recommendationCategory),
                  effort = tostring(properties.metadata.implementationEffort),
                  user_impact = tostring(properties.metadata.userImpact),
                  portal = tostring(properties.links.azurePortal),
                  ms_description = tostring(properties.metadata.description),
                  ms_remediation = tostring(properties.metadata.remediationDescription)
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        include_plans = bool(self.setting("defender_plan_recommendations", False))
        excluded = sorted({r["assessment"] for r in rows
                           if not include_plans and defender_guidance.is_plan_recommendation(r.get("assessment"))})
        rows = [r for r in rows if include_plans or not defender_guidance.is_plan_recommendation(r.get("assessment"))]

        by_resource: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            by_resource.setdefault(r.get("resource_id") or f"/subscriptions/{context.subscription_id}", []).append(r)

        findings = []
        for rid, items in by_resource.items():
            parts = rid.split("/")
            lowered = [p.lower() for p in parts]
            # Subscription-level checks and Defender "security entities" (…/Microsoft.Security/…/<guid>) have no
            # meaningful resource name, so the recommendation itself names the finding.
            is_sub = len(parts) <= 3 or ("providers" in lowered
                                         and lowered[lowered.index("providers") + 1:][:1] == ["microsoft.security"])
            worst = min((_SEVERITY_MAP.get(i["severity"], SeverityLevel.LOW) for i in items),
                        key=lambda s: list(SeverityLevel).index(s))
            target = "subscription" if is_sub else parts[-1]
            details = self._details(items, rid, context.subscription_id)
            names = [d["label"].rstrip(".") for d in details]
            title = (f"Defender: {names[0]} ({target})" if len(names) == 1
                     else f"{len(names)} Defender recommendations on {target}: {names[0]}, …")
            kwargs = dict(
                finding_type="defender_recommendations",
                title=title,
                description=(f"Defender for Cloud reports {len(names)} unhealthy recommendation(s) on "
                             f"{'the subscription' if is_sub else target}: " + "; ".join(names) + "."),
                severity=worst,
                remediation_steps="\n\n".join(f"{d['label'].rstrip('.')}:\n{d['steps']}" for d in details),
                azure_cli_script="\n\n".join(f"# {d['label']}\n{d['cli']}" for d in details if d.get("cli")) or None,
                evidence={"assessments": [self._evidence_row(d) for d in details]},
                estimated_monthly_savings_usd=0.0,
            )
            if len(parts) <= 3:
                findings.append(self.subscription_finding(context, **kwargs))
            elif is_sub:
                findings.append(self.make_finding(
                    resource_id=rid, resource_name=f"Defender entity {parts[-1][:8]}",
                    resource_type="microsoft.security/assessments", resource_group="(subscription)",
                    subscription_id=context.subscription_id, location="global", **kwargs,
                ))
            else:
                rg = parts[lowered.index("resourcegroups") + 1] if "resourcegroups" in lowered else "(subscription)"
                provider_idx = lowered.index("providers") if "providers" in lowered else -1
                rtype = "/".join(lowered[provider_idx + 1:provider_idx + 3]) if provider_idx > 0 else "unknown"
                findings.append(self.make_finding(
                    resource_id=rid, resource_name=parts[-1], resource_type=rtype, resource_group=rg,
                    subscription_id=context.subscription_id, location="", **kwargs,
                ))
        metadata = {"excluded_plan_recommendations": excluded} if excluded else {}
        return ScanOutput(findings=findings, resources_scanned=len(rows), metadata=metadata)

    def _details(self, items: List[Dict[str, Any]], resource_id: str, subscription_id: str) -> List[Dict[str, Any]]:
        """One entry per distinct recommendation (all OS-package updates as one), worst severity first."""
        updates = sorted({i["assessment"][len("Update "):] for i in items
                          if defender_guidance.is_system_update(i["assessment"], i.get("recommendation_category"))})
        grouped: Dict[str, Dict[str, Any]] = {}
        for i in items:
            if defender_guidance.is_system_update(i["assessment"], i.get("recommendation_category")):
                key = "__updates__"
                label = (f"Install missing OS / package updates ({len(updates)}: "
                         + ", ".join(updates[:self.MAX_LISTED_UPDATES])
                         + (", …" if len(updates) > self.MAX_LISTED_UPDATES else "") + ")")
            else:
                key, label = i["assessment"], i["assessment"]
            entry = grouped.setdefault(key, {"label": label, "assessment": i["assessment"], "rows": []})
            entry["rows"].append(i)

        details = []
        for key, entry in grouped.items():
            first = entry["rows"][0]
            curated = (defender_guidance.by_key("system_updates") if key == "__updates__"
                       else defender_guidance.match(first["assessment"]))
            ms_text = html_to_text(first.get("ms_remediation"))
            detail = {
                "label": entry["label"], "assessment": first["assessment"] if key != "__updates__" else "Update <package>",
                "severity": min((i["severity"] for i in entry["rows"]),
                                key=lambda s: list(_SEVERITY_MAP).index(s) if s in _SEVERITY_MAP else 9),
                "category": first.get("category"), "assessment_key": first.get("assessment_key"),
                "effort": first.get("effort") or None, "user_impact": first.get("user_impact") or None,
                "portal": portal_link(first.get("portal")), "guidance_key": curated.key if curated else None,
                "packages": updates if key == "__updates__" else None,
                "ms_description": html_to_text(first.get("ms_description"), limit=900) or None,
                "ms_remediation": ms_text or None,
                "ms_links": html_links((first.get("ms_description") or "") + (first.get("ms_remediation") or "")),
            }
            if curated:
                detail["steps"] = curated.steps
                detail["cli"] = defender_guidance.cli_for(curated, resource_id, subscription_id)
            else:
                detail["steps"] = ms_text or "Open the recommendation in Defender for Cloud and follow its remediation."
                detail["cli"] = None
            if detail["portal"]:
                detail["steps"] += f"\nDefender for Cloud: {detail['portal']}"
            details.append(detail)
        details.sort(key=lambda d: (list(_SEVERITY_MAP).index(d["severity"]) if d["severity"] in _SEVERITY_MAP else 9,
                                    d["label"]))
        return details

    def suppression_reason_for(self, evidence: Dict[str, Any]) -> Optional[str]:
        """Why an earlier finding is no longer reported when a setting - not a fix - removed it (Docker worker)."""
        names = [a.get("assessment") or "" for a in (evidence or {}).get("assessments") or []]
        if (names and not self.setting("defender_plan_recommendations", False)
                and all(defender_guidance.is_plan_recommendation(n) for n in names)):
            return "Defender plan-enablement recommendation, excluded by setting (defender_plan_recommendations)"
        return None

    @staticmethod
    def _evidence_row(detail: Dict[str, Any]) -> Dict[str, Any]:
        # steps / cli stay with the row so the report can rebuild the finding when other scanners already cover
        # some of its recommendations (scripts/subscription_analysis/correlate.py)
        return {k: v for k, v in detail.items() if v not in (None, [], "")}

    def _mock_data(self) -> List[Dict[str, Any]]:
        vm = "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-app-1"
        return [
            {"resource_id": "/subscriptions/sub-1", "assessment": "A maximum of 3 owners should be designated for subscriptions",
             "severity": "high", "category": "IdentityAndAccess"},
            {"resource_id": "/subscriptions/sub-1/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-legacy-1",
             "assessment": "Role-Based Access Control should be used on Azure Keyvault Services (AKV)",
             "severity": "high", "category": "IdentityAndAccess"},
            {"resource_id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdata1",
             "assessment": "Microsoft Defender for Storage plan should be enabled with Malware Scanning and Sensitive "
                           "Data Threat Detection", "severity": "high", "category": "Data"},
            {"resource_id": "/subscriptions/sub-1", "assessment": "Microsoft Defender CSPM should be enabled",
             "severity": "high", "category": "Compute"},
            {"resource_id": vm, "assessment": "Linux virtual machines should enable Azure Disk Encryption or "
                                              "EncryptionAtHost.", "severity": "high", "category": "Compute",
             "portal": "portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/a40cc620"},
            {"resource_id": vm, "assessment": "Update openssl", "severity": "high", "category": "Compute",
             "recommendation_category": "SystemUpdate"},
            {"resource_id": vm, "assessment": "Update libc6", "severity": "high", "category": "Compute",
             "recommendation_category": "SystemUpdate"},
        ]


# ---------------------------------------------------------------------------
# 5. Privileged role assignments at subscription scope
# ---------------------------------------------------------------------------

@register_scanner
class PrivilegedRoleAssignmentScanner(PostureScanner):
    """
    Active (non-PIM-eligible) assignments at subscription scope. PIM
    activations also appear as active while in effect, so treat the result
    as "who can act right now", then check which are permanent.
    """

    scanner_name = "privileged_role_assignment_scanner"
    display_name = "Privileged Subscription Role Assignments"
    description = "Detects too many Owners, standing User Access Administrator and privileged service principals"
    category = ScannerCategory.IDENTITY
    severity = SeverityLevel.HIGH

    MAX_OWNERS = 3

    async def scan(self, context: ScanContext) -> ScanOutput:
        sub_scope = f"/subscriptions/{context.subscription_id}".lower()
        query = f"""
        authorizationresources
        | where type =~ 'microsoft.authorization/roleassignments'
        | where subscriptionId == '{context.subscription_id}'
        | extend scope = tolower(tostring(properties.scope)),
                 role_id = tolower(extract('([0-9a-fA-F-]{{36}})$', 1, tostring(properties.roleDefinitionId)))
        | where scope == '{sub_scope}'
        | where role_id in ('{ROLE_OWNER}', '{ROLE_CONTRIBUTOR}', '{ROLE_UAA}')
        | project role_id, principal_id = tostring(properties.principalId),
                  principal_type = tostring(properties.principalType), created = tostring(properties.createdOn)
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        def members(role: str, ptype: str = None) -> List[Dict[str, Any]]:
            return [r for r in rows if r["role_id"] == role and (ptype is None or r["principal_type"] == ptype)]

        findings = []
        owners = members(ROLE_OWNER)
        max_owners = int(self.setting("max_owners", self.MAX_OWNERS))
        if len(owners) > max_owners:
            findings.append(self.subscription_finding(
                context, finding_type="excessive_subscription_owners",
                title=f"{len(owners)} direct Owners on subscription (max {max_owners})",
                description=(f"{len(owners)} principals hold Owner directly at subscription scope "
                             f"({sum(1 for o in owners if o['principal_type'] == 'User')} users). "
                             f"Inherited management-group Owners come on top."),
                severity=SeverityLevel.HIGH,
                remediation_steps="Reduce to at most 3 Owners, preferably Entra groups with PIM-eligible (just-in-time) access.",
                azure_cli_script=f"az role assignment list --scope {sub_scope} --role Owner -o table",
                evidence={"owners": owners}, cis_control="1.23",
            ))
        uaa = members(ROLE_UAA)
        if uaa:
            findings.append(self.subscription_finding(
                context, finding_type="standing_user_access_administrator",
                title=f"{len(uaa)} standing User Access Administrator assignment(s)",
                description=("User Access Administrator at subscription scope lets the holder grant any role - "
                             "including Owner - to anyone. Holders: "
                             + ", ".join(f"{u['principal_type']} {u['principal_id']}" for u in uaa) + "."),
                severity=SeverityLevel.HIGH,
                remediation_steps="Remove standing UAA; make it PIM-eligible with approval, or use a constrained RBAC Administrator role.",
                azure_cli_script=f"az role assignment list --scope {sub_scope} --role 'User Access Administrator' -o table",
                evidence={"assignments": uaa},
            ))
        sps = [r for r in rows if r["principal_type"] == "ServicePrincipal"]
        if sps:
            findings.append(self.subscription_finding(
                context, finding_type="service_principal_privileged_role",
                title=f"{len(sps)} service principal(s) with privileged subscription roles",
                description=("Service principals holding Owner/Contributor/UAA at subscription scope: "
                             + ", ".join(f"{ROLE_NAMES[s['role_id']]} → {s['principal_id']}" for s in sps)
                             + ". Their credentials are a direct path to full control."),
                severity=SeverityLevel.MEDIUM,
                remediation_steps=("Scope each SP to the resource groups it deploys, prefer workload identity federation "
                                   "over secrets, and document the owner of every SP."),
                azure_cli_script=f"az role assignment list --scope {sub_scope} --query \"[?principalType=='ServicePrincipal']\" -o table",
                evidence={"assignments": sps},
            ))
        return ScanOutput(findings=findings, resources_scanned=len(rows))

    def _mock_data(self) -> List[Dict[str, Any]]:
        users = [{"role_id": ROLE_OWNER, "principal_id": f"user-{i}", "principal_type": "User", "created": ""} for i in range(4)]
        return users + [
            {"role_id": ROLE_UAA, "principal_id": "user-9", "principal_type": "User", "created": ""},
            {"role_id": ROLE_CONTRIBUTOR, "principal_id": "sp-1", "principal_type": "ServicePrincipal", "created": ""},
        ]


# ---------------------------------------------------------------------------
# 6. Secure score
# ---------------------------------------------------------------------------

@register_scanner
class SecureScoreScanner(PostureScanner):
    scanner_name = "secure_score_scanner"
    display_name = "Defender Secure Score"
    description = "Detects subscriptions whose Defender for Cloud secure score is below target"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.MEDIUM
    requires_defender = True

    TARGET = 0.80

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = f"""
        securityresources
        | where type =~ 'microsoft.security/securescores'
        | where subscriptionId == '{context.subscription_id}'
        | project current = todouble(properties.score.current), max = todouble(properties.score.max),
                  pct = todouble(properties.score.percentage)
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        target = float(self.setting("secure_score_target", self.TARGET))
        findings = []
        for r in rows[:1]:
            if r.get("pct") is None or r["pct"] >= target:
                continue
            findings.append(self.subscription_finding(
                context, finding_type="low_secure_score",
                title=f"Secure score {r['pct']:.0%} (target {target:.0%})",
                description=f"Defender for Cloud secure score is {r.get('current')}/{r.get('max')} ({r['pct']:.0%}).",
                severity=SeverityLevel.HIGH if r["pct"] < 0.6 else SeverityLevel.MEDIUM,
                remediation_steps="Work through the security controls with the largest potential score increase first.",
                evidence=r,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(rows))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{"current": 24.85, "max": 35.0, "pct": 0.71}]
