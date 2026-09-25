"""
Azure Resource Guardian - Security Posture Scanners
====================================================
Scanners in this module:
1. KeyVaultHardeningScanner        - Access-policy model, soft delete, purge protection, open network
2. AIServicesHardeningScanner      - Foundry / Azure OpenAI key auth and open network access
3. DefenderPlanCoverageScanner     - Defender plans left on Free while matching resources exist
4. DefenderRecommendationsScanner  - Unhealthy Defender for Cloud assessments (High by default)
5. PrivilegedRoleAssignmentScanner - Owners > 3, standing User Access Administrator, privileged SPs
6. SecureScoreScanner              - Defender secure score below target

Covers the "Microsoft Defender for Cloud integration" roadmap item by
reading securityresources through Resource Graph (no extra SDK needed).
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from typing import Any, Dict, List

from scanners.base.azure_api import get_defender_plans
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.posture_scanner import PostureScanner

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

_SEVERITY_MAP = {"high": SeverityLevel.HIGH, "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW}


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
                  pe_count = array_length(properties.privateEndpointConnections)
        """
        try:
            vaults = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

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
            if kv.get("soft_delete") is False or kv.get("soft_delete") is None:
                findings.append(self.resource_finding(
                    kv, finding_type="key_vault_soft_delete_disabled", title=f"Key Vault soft delete not enabled: {name}",
                    description=f"Key Vault '{name}' does not report soft delete - deleted secrets, keys and certificates are unrecoverable.",
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
                findings.append(self.resource_finding(
                    kv, finding_type="key_vault_public_network_open", title=f"Key Vault open to all networks: {name}",
                    description=f"Key Vault '{name}' accepts requests from all networks and has no private endpoint.",
                    severity=SeverityLevel.MEDIUM,
                    remediation_steps="Add a private endpoint or firewall rules and set the default action to Deny.",
                    azure_cli_script=f"az keyvault update -g {rg} -n {name} --default-action Deny",
                    evidence={"publicNetworkAccess": kv.get("public_network"), "defaultAction": kv.get("default_action")},
                    **common,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(vaults))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-legacy-1",
            "name": "kv-legacy-1", "type": "microsoft.keyvault/vaults", "resourceGroup": "rg-sec",
            "subscriptionId": "sub-1", "location": "westeurope", "rbac": False, "soft_delete": None,
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
                  pe_count = array_length(properties.privateEndpointConnections)
        """
        try:
            accounts = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for acc in accounts:
            rg, name = acc.get("resourceGroup"), acc["name"]
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
                findings.append(self.resource_finding(
                    acc, finding_type="ai_services_public_network_open", title=f"AI endpoint open to all networks: {name}",
                    description=f"{acc.get('kind')} account '{name}' accepts requests from any network and has no private endpoint.",
                    resource_type="microsoft.cognitiveservices/accounts", severity=SeverityLevel.HIGH,
                    remediation_steps="Restrict with a private endpoint (or IP rules) and set the network default action to Deny.",
                    azure_cli_script=f"az cognitiveservices account network-rule add -g {rg} -n {name} --ip-address <egress-ip>\n"
                                     f"az resource update --ids {acc['id']} --set properties.networkAcls.defaultAction=Deny",
                    evidence={"publicNetworkAccess": acc.get("public_network"), "defaultAction": acc.get("default_action")},
                    estimated_monthly_savings_usd=0.0,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(accounts))

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
    scanner_name = "defender_plan_coverage_scanner"
    display_name = "Defender for Cloud Plan Coverage"
    description = "Detects Defender plans on the Free tier while matching resources exist"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.MEDIUM
    requires_defender = True

    async def scan(self, context: ScanContext) -> ScanOutput:
        type_query = "Resources | summarize n = count() by type = tolower(type)"
        try:
            if context.resource_graph_client is None:
                plans, counts = self._mock_sets()
            else:
                plans = await get_defender_plans(context) or {}
                counts = {r["type"]: r["n"] for r in await self.arg(context, type_query)}
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        gaps = []
        for plan, tier in plans.items():
            if (tier or "").lower() != "free" or plan not in DEFENDER_PLAN_RESOURCES:
                continue
            types = DEFENDER_PLAN_RESOURCES[plan]
            relevant = sum(counts.values()) if "*" in types else sum(counts.get(t, 0) for t in types)
            if relevant:
                gaps.append({"plan": plan, "matching_resources": relevant})
        if not gaps:
            return ScanOutput(resources_scanned=len(plans))

        high = any(g["plan"] in HIGH_VALUE_PLANS for g in gaps)
        finding = self.subscription_finding(
            context,
            finding_type="defender_plan_disabled",
            title=f"{len(gaps)} Defender plan(s) on Free with matching resources",
            description="Defender for Cloud plans left on Free although protected resource types exist: "
                        + ", ".join(f"{g['plan']} ({g['matching_resources']} resources)" for g in gaps) + ".",
            severity=SeverityLevel.HIGH if high else SeverityLevel.MEDIUM,
            remediation_steps=("Enable the plans that match your risk (e.g. Defender for AI where Azure OpenAI is in "
                               "use, Defender CSPM for attack-path analysis) or document the exception."),
            azure_cli_script="\n".join(f"az security pricing create -n {g['plan']} --tier Standard" for g in gaps),
            evidence={"disabled_plans": gaps},
        )
        return ScanOutput(findings=[finding], resources_scanned=len(plans))

    def _mock_sets(self):
        return ({"AI": "Free", "CloudPosture": "Free", "StorageAccounts": "Standard", "Containers": "Free"},
                {"microsoft.cognitiveservices/accounts": 5, "microsoft.storage/storageaccounts": 37})


# ---------------------------------------------------------------------------
# 4. Defender recommendations
# ---------------------------------------------------------------------------

@register_scanner
class DefenderRecommendationsScanner(PostureScanner):
    """One finding per resource summarising its unhealthy Defender assessments of the configured severities."""

    scanner_name = "defender_recommendations_scanner"
    display_name = "Defender for Cloud Recommendations"
    description = "Imports unhealthy Microsoft Defender for Cloud assessments"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.HIGH
    requires_defender = True

    async def scan(self, context: ScanContext) -> ScanOutput:
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
                  category = tostring(properties.metadata.categories[0])
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

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
            names = sorted({i["assessment"] for i in items})
            target = "subscription" if is_sub else parts[-1]
            title = (f"Defender: {names[0]} ({target})" if len(names) == 1
                     else f"{len(names)} Defender recommendations on {target}: {names[0]}, …")
            kwargs = dict(
                finding_type="defender_recommendations",
                title=title,
                description="Unhealthy Defender for Cloud assessments: " + "; ".join(names) + ".",
                severity=worst,
                remediation_steps="Open Defender for Cloud → Recommendations for this resource and follow the remediation steps.",
                evidence={"assessments": items},
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
        return ScanOutput(findings=findings, resources_scanned=len(rows))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [
            {"resource_id": "/subscriptions/sub-1", "assessment": "A maximum of 3 owners should be designated for subscriptions",
             "severity": "high", "category": "IdentityAndAccess"},
            {"resource_id": "/subscriptions/sub-1/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-legacy-1",
             "assessment": "Role-Based Access Control should be used on Azure Keyvault Services (AKV)",
             "severity": "high", "category": "IdentityAndAccess"},
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
