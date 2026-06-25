"""
Azure Resource Guardian - Storage Scanners
===========================================
Detects orphaned and potentially unused storage resources.

Scanners in this module:
1. UnusedStorageAccountScanner — Storage accounts with no apparent activity
2. OrphanedBackupVaultScanner  — Recovery Services Vaults with no protected items

Note: True transaction-level "unused" detection requires Azure Monitor
Storage Insights metrics, which are not queryable from Resource Graph.
These scanners flag candidates for manual verification rather than
claiming certainty — see each scanner's description for caveats.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from typing import Any, Dict, List

from scanners.base.base_scanner import (
    BaseScanner,
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)


# ---------------------------------------------------------------------------
# Unused Storage Account Scanner
# ---------------------------------------------------------------------------

@register_scanner
class UnusedStorageAccountScanner(BaseScanner):
    """
    Flags storage accounts that appear unused based on Resource Graph
    metadata alone (kind, public access settings). This is a coarse
    first-pass filter — analysts should verify with Storage Insights
    transaction metrics before deletion.
    """

    scanner_name = "unused_storage_account_scanner"
    display_name = "Potentially Unused Storage Accounts"
    description = "Detects storage accounts with no apparent recent activity"
    category = ScannerCategory.STORAGE
    severity = SeverityLevel.MEDIUM
    requires_cost = True

    BASE_MONTHLY_COST = 0.50  # Minimal cost just for the account existing

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | project
            id, name, resourceGroup, subscriptionId, location, tags,
            kind, sku_name = sku.name,
            allow_blob_public_access = properties.allowBlobPublicAccess,
            access_tier = properties.accessTier
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for sa in resources:
            tags = sa.get("tags") or {}
            if tags.get("arg-ignore") or tags.get("arg-reserved"):
                continue

            is_blob_only = (sa.get("kind") or "").lower() == "blobstorage"
            severity = SeverityLevel.HIGH if is_blob_only else SeverityLevel.MEDIUM
            public_access = bool(sa.get("allow_blob_public_access"))

            description = (
                f"Storage account '{sa['name']}' (kind: {sa.get('kind', 'Unknown')}, "
                f"SKU: {sa.get('sku_name', 'Unknown')}) could not be confirmed as actively "
                f"used from Resource Graph metadata alone — verify with Storage Insights "
                f"transaction metrics before taking action."
            )
            if public_access:
                description += " ⚠️ Public blob access is enabled on this account."
                severity = SeverityLevel.HIGH

            findings.append(self.make_finding(
                finding_type="unused_storage_account",
                title=f"Verify usage: {sa['name']}",
                description=description,
                resource_id=sa["id"],
                resource_name=sa["name"],
                resource_type="microsoft.storage/storageaccounts",
                resource_group=sa.get("resourceGroup"),
                subscription_id=sa.get("subscriptionId"),
                location=sa.get("location"),
                severity=severity,
                remediation_steps=(
                    "1. Check Azure Monitor Storage Insights for transaction metrics over 90 days.\n"
                    "2. List containers/queues/tables/shares to confirm no data is present.\n"
                    "3. If confirmed empty and unused, delete the account.\n"
                    "4. If intentionally reserved, tag with 'arg-reserved: true' to suppress."
                ),
                azure_cli_script=(
                    f"# Verify empty before deleting:\n"
                    f"az storage container list --account-name {sa['name']} --output table\n"
                    f"# If confirmed empty:\n"
                    f"az storage account delete --name {sa['name']} "
                    f"--resource-group {sa.get('resourceGroup')} --yes"
                ),
                powershell_script=(
                    f"$ctx = New-AzStorageContext -StorageAccountName '{sa['name']}'\n"
                    f"Get-AzStorageContainer -Context $ctx\n"
                    f"# If empty:\n"
                    f"Remove-AzStorageAccount -Name '{sa['name']}' "
                    f"-ResourceGroupName '{sa.get('resourceGroup')}' -Force"
                ),
                evidence={
                    "kind": sa.get("kind"),
                    "sku": sa.get("sku_name"),
                    "access_tier": sa.get("access_tier"),
                    "public_access_enabled": public_access,
                },
                estimated_monthly_savings_usd=self.BASE_MONTHLY_COST,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(resources))

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from azure.mgmt.resourcegraph.models import QueryRequest

        request = QueryRequest(
            subscriptions=[context.subscription_id],
            query=query,
            options={"resultFormat": "objectArray", "$top": 1000},
        )
        response = context.resource_graph_client.resources(request)
        return response.data or []

    def _mock_data(self) -> List[Dict]:
        return [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stunused1",
                "name": "stunused1",
                "resourceGroup": "rg-data",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "kind": "StorageV2",
                "sku_name": "Standard_LRS",
                "allow_blob_public_access": False,
                "access_tier": "Hot",
                "tags": {},
            }
        ]


# ---------------------------------------------------------------------------
# Orphaned Backup Vault Scanner
# ---------------------------------------------------------------------------

@register_scanner
class OrphanedBackupVaultScanner(BaseScanner):
    """
    Flags Recovery Services Vaults that may have no protected items.

    Resource Graph cannot directly enumerate backup items inside a vault,
    so this scanner raises an advisory finding for every vault — analysts
    confirm emptiness via the Backup Items blade before deletion.
    """

    scanner_name = "orphaned_backup_vault_scanner"
    display_name = "Potentially Empty Recovery Services Vaults"
    description = "Detects Recovery Services Vaults that may have no protected items"
    category = ScannerCategory.STORAGE
    severity = SeverityLevel.LOW

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.recoveryservices/vaults'
        | project
            id, name, resourceGroup, subscriptionId, location, tags,
            redundancy = properties.redundancySettings.standardTierStorageRedundancy,
            provisioning_state = properties.provisioningState
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for vault in resources:
            findings.append(self.make_finding(
                finding_type="orphaned_backup_vault",
                title=f"Verify backup items: {vault['name']}",
                description=(
                    f"Recovery Services Vault '{vault['name']}' may have no protected items. "
                    f"Verify in the Azure Portal under Backup Items. "
                    f"Redundancy: {vault.get('redundancy', 'Unknown')}."
                ),
                resource_id=vault["id"],
                resource_name=vault["name"],
                resource_type="microsoft.recoveryservices/vaults",
                resource_group=vault.get("resourceGroup"),
                subscription_id=vault.get("subscriptionId"),
                location=vault.get("location"),
                severity=SeverityLevel.LOW,
                remediation_steps=(
                    "1. Navigate to the vault in Azure Portal → Backup Items.\n"
                    "2. If no items are protected, disable soft-delete and clear any backup data.\n"
                    "3. Once empty, delete the vault. Vaults cannot be deleted while they "
                    "contain backup data."
                ),
                azure_cli_script=(
                    f"az backup item list --vault-name {vault['name']} "
                    f"--resource-group {vault.get('resourceGroup')} --output table\n"
                    f"# If empty:\n"
                    f"az backup vault delete --name {vault['name']} "
                    f"--resource-group {vault.get('resourceGroup')} --yes"
                ),
                evidence={
                    "redundancy": vault.get("redundancy"),
                    "provisioning_state": vault.get("provisioning_state"),
                },
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(resources))

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from azure.mgmt.resourcegraph.models import QueryRequest

        request = QueryRequest(
            subscriptions=[context.subscription_id],
            query=query,
            options={"resultFormat": "objectArray", "$top": 1000},
        )
        response = context.resource_graph_client.resources(request)
        return response.data or []

    def _mock_data(self) -> List[Dict]:
        return [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-backup/providers/Microsoft.RecoveryServices/vaults/rsv-empty-1",
                "name": "rsv-empty-1",
                "resourceGroup": "rg-backup",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "redundancy": "GeoRedundant",
                "provisioning_state": "Succeeded",
                "tags": {},
            }
        ]
