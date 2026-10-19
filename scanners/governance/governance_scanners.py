"""
Azure Resource Guardian - Governance Scanners
===============================================
Detects tag compliance, naming convention, and resource lock gaps.

Scanners in this module:
1. MissingRequiredTagsScanner - Resources missing required governance tags
2. NamingConventionScanner    - Resources not following CAF naming patterns
3. MissingResourceLockScanner - Production resources without deletion locks

Governance findings often carry zero direct cost impact but are
foundational for cost attribution, security notification routing, and
compliance audits.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import re
from typing import Dict, List, Optional

from scanners.base.naming import env_from_tags
from scanners.base.base_scanner import (
    BaseScanner,
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)

DEFAULT_REQUIRED_TAGS = ["owner", "environment", "cost-center", "application"]

CAF_PATTERNS = {
    "microsoft.compute/virtualmachines": re.compile(r"^vm-[a-z0-9]+-[a-z]+-[a-z]+-\d{3}$", re.I),
    "microsoft.network/virtualnetworks": re.compile(r"^vnet-[a-z0-9]+-[a-z]+-[a-z]+$", re.I),
    "microsoft.storage/storageaccounts": re.compile(r"^st[a-z0-9]{3,22}$", re.I),
    "microsoft.keyvault/vaults": re.compile(r"^kv-[a-z0-9]+-[a-z]+-[a-z]+$", re.I),
    "microsoft.network/networksecuritygroups": re.compile(r"^nsg-[a-z0-9]+-[a-z]+-[a-z]+$", re.I),
}

SKIP_RG_PREFIXES = ("mc_", "databricks-rg-", "defaultresourcegroup-", "networkwatcherrg")


# ---------------------------------------------------------------------------
# Missing Required Tags Scanner
# ---------------------------------------------------------------------------

@register_scanner
class MissingRequiredTagsScanner(BaseScanner):
    """
    Detects resources missing required governance tags (owner, environment,
    cost-center, application by default). Skips Microsoft-managed auto-
    generated resource groups (AKS node RGs, Databricks RGs, etc.) since
    the customer has no control over tagging there.
    """

    scanner_name = "missing_required_tags_scanner"
    display_name = "Missing Required Tags"
    description = "Detects resources missing required governance tags"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.LOW

    REQUIRED_TAGS = DEFAULT_REQUIRED_TAGS
    finding_types = {"missing_required_tags"}

    async def scan(self, context: ScanContext) -> ScanOutput:
        # Optional (`required_tags_check`): tagging thousands of existing resources one by one is rarely the plan -
        # the report's cost-allocation KPI and the tag policies cover it without a finding per resource.
        if not self.config.get("required_tags_check", False):
            return ScanOutput(metadata={"disabled_by_setting": "required_tags_check"})
        required_tags = self.config.get("required_tags", self.REQUIRED_TAGS)
        tag_filter = " or ".join(f"isnull(tags['{tag}'])" for tag in required_tags)

        query = f"""
        Resources
        | where isnull(tags) or ({tag_filter})
        | project id, name, type, resourceGroup, subscriptionId, location, tags
        | order by type asc
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        resources = [
            r for r in resources
            if not any((r.get("resourceGroup") or "").lower().startswith(p) for p in SKIP_RG_PREFIXES)
        ]

        findings = []
        for resource in resources:
            existing_tags = resource.get("tags") or {}
            present = {k.lower() for k in existing_tags}   # Azure tag names are case-insensitive
            missing = [t for t in required_tags if t.lower() not in present]
            if not missing:
                continue

            # Hygiene, not risk: one untagged resource is low on its own. The report weighs the gap by cost
            # (share of spend that cannot be charged back) and recommends the tag policies once.
            severity = SeverityLevel.LOW

            findings.append(self.make_finding(
                finding_type="missing_required_tags",
                title=f"Missing tags: {resource['name']}",
                description=(
                    f"Resource '{resource['name']}' ({resource.get('type', 'Unknown')}) is "
                    f"missing {len(missing)} required tag(s): {', '.join(missing)}. "
                    f"Existing tags: {list(existing_tags.keys()) or 'none'}."
                ),
                resource_id=resource["id"],
                resource_name=resource["name"],
                resource_type=resource.get("type"),
                resource_group=resource.get("resourceGroup"),
                subscription_id=resource.get("subscriptionId"),
                location=resource.get("location"),
                severity=severity,
                remediation_steps=(
                    f"Add the following required tags: {', '.join(missing)}.\n"
                    "Consider enforcing via Azure Policy with an 'Append' effect, and enabling "
                    "tag inheritance from resource groups for new resources."
                ),
                azure_cli_script="\n".join(
                    f'az tag update --resource-id "{resource["id"]}" '
                    f'--operation Merge --tags {tag}="<value>"'
                    for tag in missing
                ),
                powershell_script="\n".join(
                    f'Update-AzTag -ResourceId "{resource["id"]}" '
                    f'-Tag @{{"{tag}"="<value>"}} -Operation Merge'
                    for tag in missing
                ),
                evidence={
                    "missing_tags": missing,
                    "existing_tags": list(existing_tags.keys()),
                    "resource_type": resource.get("type"),
                },
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(resources))

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from scanners.base.azure_api import query_resource_graph

        return await query_resource_graph(context, query) or []

    def _mock_data(self) -> List[Dict]:
        return [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-untagged-1",
                "name": "vm-untagged-1",
                "type": "microsoft.compute/virtualmachines",
                "resourceGroup": "rg-app",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "tags": {"environment": "production"},
            }
        ]


# ---------------------------------------------------------------------------
# Naming Convention Scanner
# ---------------------------------------------------------------------------

@register_scanner
class NamingConventionScanner(BaseScanner):
    """
    Detects resources that don't follow CAF (Cloud Adoption Framework)
    naming conventions, e.g. vm-<workload>-<env>-<region>-<instance>.

    Only checks resource types with well-defined CAF prefixes. Flagged
    at Low severity since naming is organization-specific and orgs may
    intentionally deviate from CAF defaults. Switched off with the
    `naming_convention_enabled` setting (Settings page / settings.json):
    most resources cannot be renamed in place, so the check is only
    useful while a naming standard is being enforced.
    """

    scanner_name = "naming_convention_scanner"
    display_name = "Naming Convention Violations"
    description = "Detects resources that don't follow CAF naming conventions"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.LOW
    finding_types = {"naming_convention_violation"}

    async def scan(self, context: ScanContext) -> ScanOutput:
        if not self.config.get("naming_convention_enabled", True):
            return ScanOutput(metadata={"disabled_by_setting": "naming_convention_enabled"})
        query = """
        Resources
        | where type in~ (
            'microsoft.compute/virtualmachines',
            'microsoft.network/virtualnetworks',
            'microsoft.storage/storageaccounts',
            'microsoft.keyvault/vaults',
            'microsoft.network/networksecuritygroups'
        )
        | project id, name, type, resourceGroup, subscriptionId, location
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        # Use admin-configured patterns if available, else built-in CAF defaults
        custom_patterns_raw = self.config.get("naming_patterns", {})
        effective_patterns = {
            rtype: re.compile(pat, re.I)
            for rtype, pat in custom_patterns_raw.items()
            if pat
        } if custom_patterns_raw else CAF_PATTERNS

        findings = []
        for resource in resources:
            rtype = (resource.get("type") or "").lower()
            pattern = effective_patterns.get(rtype)
            if not pattern:
                continue

            name = resource.get("name", "")
            if pattern.match(name):
                continue

            findings.append(self.make_finding(
                finding_type="naming_convention_violation",
                title=f"Naming violation: {name}",
                description=(
                    f"Resource '{name}' ({rtype}) does not follow CAF naming conventions. "
                    f"Expected pattern: {pattern.pattern}"
                ),
                resource_id=resource["id"],
                resource_name=name,
                resource_type=rtype,
                resource_group=resource.get("resourceGroup"),
                subscription_id=resource.get("subscriptionId"),
                location=resource.get("location"),
                severity=SeverityLevel.LOW,
                remediation_steps=(
                    "Do not rename in isolation: Azure cannot rename most resources in place, so a new name means "
                    "a new resource, a data migration and updated references. Apply the naming standard to new "
                    "resources through IaC, and rename this one only when it is rebuilt anyway (re-platforming, "
                    "region move, major upgrade). If the standard does not fit this resource type, adjust the "
                    "pattern in Settings or switch the check off there."
                ),
                azure_cli_script=(
                    f"# Most Azure resources cannot be renamed - provision a replacement and migrate.\n"
                    f"# 1. Export current resource config:\n"
                    f"az resource show --ids \"{resource['id']}\" --output json > current-config.json\n"
                    f"# 2. Review current-config.json, create a renamed replacement, then delete this resource.\n"
                    f"# Resource ID: {resource['id']}"
                ),
                powershell_script=(
                    f"# Most Azure resources cannot be renamed - provision a replacement and migrate.\n"
                    f"# 1. Export current resource config:\n"
                    f"Get-AzResource -ResourceId \"{resource['id']}\" | ConvertTo-Json -Depth 10 > current-config.json\n"
                    f"# 2. Review current-config.json, create a renamed replacement, then delete this resource.\n"
                    f"# Resource ID: {resource['id']}"
                ),
                evidence={"current_name": name, "expected_pattern": pattern.pattern},
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(resources))

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from scanners.base.azure_api import query_resource_graph

        return await query_resource_graph(context, query) or []

    def _mock_data(self) -> List[Dict]:
        return [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/myserver1",
                "name": "myserver1",
                "type": "microsoft.compute/virtualmachines",
                "resourceGroup": "rg-app",
                "location": "eastus",
                "subscriptionId": "sub-1",
            }
        ]


# ---------------------------------------------------------------------------
# Missing Resource Lock Scanner
# ---------------------------------------------------------------------------

def lock_scopes(locks: List[Dict]) -> List[str]:
    """Scope (subscription, resource group or resource ID, lower case) of each management lock."""
    return [(lk.get("id") or "").lower().split("/providers/microsoft.authorization/locks/")[0] for lk in locks
            if lk.get("id")]


def covering_lock(resource_id: str, scopes: List[str]) -> Optional[str]:
    """The lock scope that protects the resource - the resource itself, its resource group or the subscription."""
    rid = (resource_id or "").lower()
    return next((s for s in scopes if s and (rid == s or rid.startswith(s + "/"))), None)


@register_scanner
class MissingResourceLockScanner(BaseScanner):
    """
    Production critical resources with no CanNotDelete / ReadOnly lock on themselves, their resource group or the
    subscription. Locks are not in Resource Graph; one ARM call lists every lock in the subscription (any scope).
    """

    scanner_name = "missing_resource_lock_scanner"
    display_name = "Resource Locks"
    description = "Detects production resources without a deletion lock (own, resource group or subscription)"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.HIGH
    finding_types = {"missing_resource_lock"}

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type in~ (
            'microsoft.compute/virtualmachines',
            'microsoft.network/virtualnetworks',
            'microsoft.storage/storageaccounts',
            'microsoft.sql/servers',
            'microsoft.keyvault/vaults',
            'microsoft.documentdb/databaseaccounts'
        )
        | where isnotnull(tags)
        | project id, name, type, resourceGroup, subscriptionId, location, tags
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])
        # tag keys are case-sensitive in KQL ('Environment' vs 'environment'): decide in Python
        resources = [r for r in resources if env_from_tags(r.get("tags")) == "prod"]

        scopes: List[str] = []
        if getattr(context, "arm_client", None) is not None:
            try:
                scopes = lock_scopes(await context.arm_client.get_all(
                    f"/subscriptions/{context.subscription_id}/providers/Microsoft.Authorization/locks", "2020-05-01"))
            except Exception as e:
                return ScanOutput(warnings=[f"Resource locks unavailable ({e}) - lock coverage not checked."],
                                  resources_scanned=len(resources))

        findings = []
        for resource in resources:
            if covering_lock(resource["id"], scopes):
                continue
            findings.append(self.make_finding(
                finding_type="missing_resource_lock",
                title=f"No delete lock: {resource['name']}",
                description=(
                    f"Production resource '{resource['name']}' ({resource.get('type', 'Unknown')}) has no "
                    f"CanNotDelete or ReadOnly lock - not on the resource, its resource group "
                    f"'{resource.get('resourceGroup')}' or the subscription - so one wrong delete removes it."
                ),
                resource_id=resource["id"],
                resource_name=resource["name"],
                resource_type=resource.get("type"),
                resource_group=resource.get("resourceGroup"),
                subscription_id=resource.get("subscriptionId"),
                location=resource.get("location"),
                severity=SeverityLevel.HIGH,
                remediation_steps=(
                    "Apply a CanNotDelete lock. For databases and storage, consider ReadOnly "
                    "locks after validating your application doesn't require write-path "
                    "metadata operations."
                ),
                azure_cli_script=(
                    f"az lock create --name 'protect-{resource['name']}' "
                    f"--resource-group {resource.get('resourceGroup')} "
                    f"--lock-type CanNotDelete "
                    f"--resource-name {resource['name']} "
                    f"--resource-type {resource.get('type')}"
                ),
                powershell_script=(
                    f"New-AzResourceLock -LockName 'protect-{resource['name']}' "
                    f"-LockLevel CanNotDelete "
                    f"-ResourceGroupName '{resource.get('resourceGroup')}' "
                    f"-ResourceName '{resource['name']}' "
                    f"-ResourceType '{resource.get('type')}' -Force"
                ),
                evidence={"resource_type": resource.get("type"), "locks_in_subscription": len(scopes)},
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(resources))

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from scanners.base.azure_api import query_resource_graph

        return await query_resource_graph(context, query) or []

    def _mock_data(self) -> List[Dict]:
        return [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-prod-1",
                "name": "sql-prod-1",
                "type": "microsoft.sql/servers",
                "resourceGroup": "rg-prod",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "tags": {"environment": "production"},
            }
        ]
