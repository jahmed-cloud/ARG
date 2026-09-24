"""
Azure Resource Guardian - Storage Posture Scanners
===================================================
Scanners in this module:
1. StorageAccessHardeningScanner  - Shared-key access, open public network, blob soft delete
2. StorageAccountSprawlScanner    - Many near-identical accounts in one resource group
3. StorageTransactionHotspotScanner - Accounts whose transaction volume dominates their bill
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import re
from typing import Any, Dict, List

from scanners.base.azure_api import DEFAULT_ARM_CONCURRENCY, gather_limited, cached_metrics, cost_for, get_defender_plans, get_resource_costs
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.posture_scanner import PostureScanner

DEFENDER_FOR_STORAGE_USD_PER_ACCOUNT = 10.0


def account_family(name: str) -> str:
    """'apptimize0dev0client04' -> 'apptimize0dev0client' (trailing digits stripped)."""
    return re.sub(r"\d+$", "", (name or "").lower())


@register_scanner
class StorageAccessHardeningScanner(PostureScanner):
    """Shared keys give full-account access; defaultAction=Allow with no private endpoint is Internet-reachable."""

    scanner_name = "storage_access_hardening_scanner"
    display_name = "Storage Account Access Hardening"
    description = "Detects storage accounts allowing shared keys, open public networks or no blob soft delete"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | project id, name, type, resourceGroup, subscriptionId, location, tags, kind,
                  shared_key = tobool(properties.allowSharedKeyAccess),
                  public_network = tostring(properties.publicNetworkAccess),
                  default_action = tostring(properties.networkAcls.defaultAction),
                  pe_count = array_length(properties.privateEndpointConnections)
        """
        try:
            accounts = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings = []
        if self.is_live(context):
            async def _enrich(sa):
                if (sa.get("kind") or "").lower() not in ("storagev2", "blobstorage", "blockblobstorage"):
                    return
                try:
                    blob = await context.arm_client.get(f"{sa['id']}/blobServices/default", "2023-01-01")
                    policy = (blob.get("properties") or {}).get("deleteRetentionPolicy") or {}
                    sa["blob_soft_delete"] = bool(policy.get("enabled"))
                except Exception as exc:
                    warnings.append(f"blobServices unavailable for {sa['name']}: {exc}")
            await gather_limited(accounts, _enrich, self.setting("arm_concurrency", DEFAULT_ARM_CONCURRENCY))

        findings = []
        for sa in accounts:
            rg, name = sa.get("resourceGroup"), sa["name"]
            if sa.get("shared_key") is not False:
                findings.append(self.resource_finding(
                    sa, finding_type="storage_shared_key_access_enabled", title=f"Shared-key access allowed: {name}",
                    description=(f"Storage account '{name}' accepts account-key and SAS-from-key authentication. "
                                 f"Anyone holding a key has full data-plane access with no identity or audit trail."),
                    resource_type="microsoft.storage/storageaccounts",
                    remediation_steps=("Move clients to Entra ID (managed identity + RBAC, user-delegation SAS), "
                                       "then disable shared-key access. Azure Files SMB with keys must migrate first."),
                    azure_cli_script=f"az storage account update -g {rg} -n {name} --allow-shared-key-access false",
                    powershell_script=f"Set-AzStorageAccount -ResourceGroupName '{rg}' -Name '{name}' -AllowSharedKeyAccess $false",
                    evidence={"allowSharedKeyAccess": sa.get("shared_key")}, cis_control="3.3",
                    estimated_monthly_savings_usd=0.0,
                ))
            open_network = ((sa.get("public_network") or "Enabled").lower() != "disabled"
                            and (sa.get("default_action") or "Allow").lower() == "allow")
            if open_network and not sa.get("pe_count"):
                findings.append(self.resource_finding(
                    sa, finding_type="storage_public_network_access", title=f"Storage open to all networks: {name}",
                    description=(f"Storage account '{name}' allows data-plane traffic from all networks "
                                 f"(firewall defaultAction=Allow) and has no private endpoint."),
                    resource_type="microsoft.storage/storageaccounts",
                    remediation_steps=("Add a private endpoint (or VNet/IP rules for the known clients) and set the "
                                       "firewall default action to Deny."),
                    azure_cli_script=f"az storage account update -g {rg} -n {name} --default-action Deny",
                    evidence={"publicNetworkAccess": sa.get("public_network"), "defaultAction": sa.get("default_action")},
                    cis_control="3.8", nist_control="SC-7", estimated_monthly_savings_usd=0.0,
                ))
            if sa.get("blob_soft_delete") is False:
                findings.append(self.resource_finding(
                    sa, finding_type="storage_blob_soft_delete_disabled", title=f"Blob soft delete disabled: {name}",
                    description=f"Storage account '{name}' has blob soft delete disabled - deleted or overwritten blobs are unrecoverable.",
                    resource_type="microsoft.storage/storageaccounts", severity=SeverityLevel.LOW,
                    remediation_steps="Enable blob (and container) soft delete with 7-30 days retention.",
                    azure_cli_script=f"az storage account blob-service-properties update -g {rg} --account-name {name} "
                                     f"--enable-delete-retention true --delete-retention-days 14",
                    evidence={"blob_soft_delete": False}, estimated_monthly_savings_usd=0.0,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(accounts), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stclient01",
            "name": "stclient01", "type": "microsoft.storage/storageaccounts", "resourceGroup": "rg-data",
            "subscriptionId": "sub-1", "location": "westeurope", "kind": "StorageV2", "shared_key": None,
            "public_network": "Enabled", "default_action": "Allow", "pe_count": 0, "blob_soft_delete": False,
        }]


@register_scanner
class StorageAccountSprawlScanner(PostureScanner):
    """
    One account per customer/tenant multiplies per-account fees (Defender for
    Storage, Event Grid system topics), keys to rotate and attack surface.
    A container/share per tenant in a few accounts is usually enough.
    """

    scanner_name = "storage_account_sprawl_scanner"
    display_name = "Storage Account Sprawl"
    description = "Detects resource groups with many near-identical storage accounts"
    category = ScannerCategory.COST
    severity = SeverityLevel.LOW

    MIN_FAMILY_SIZE = 10
    TARGET_ACCOUNTS = 3

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | project name, resourceGroup, subscriptionId, location
        """
        try:
            accounts = await self.arg(context, query)
            plans = await get_defender_plans(context)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        defender_on = (plans or {}).get("StorageAccounts", "Standard" if plans is None else "Free") == "Standard"
        families: Dict[tuple, List[Dict[str, Any]]] = {}
        for sa in accounts:
            families.setdefault(((sa.get("resourceGroup") or "").lower(), account_family(sa["name"])), []).append(sa)

        threshold = int(self.setting("min_family_size", self.MIN_FAMILY_SIZE))
        findings = []
        for (rg, family), members in families.items():
            if len(members) < threshold:
                continue
            surplus = len(members) - self.TARGET_ACCOUNTS
            saving = surplus * DEFENDER_FOR_STORAGE_USD_PER_ACCOUNT if defender_on else 0.0
            rg_name = members[0].get("resourceGroup")
            findings.append(self.make_finding(
                finding_type="storage_account_sprawl",
                title=f"{len(members)} '{family}*' storage accounts in {rg_name}",
                description=(
                    f"Resource group '{rg_name}' holds {len(members)} storage accounts named '{family}NN'. "
                    f"Consolidating to ~{self.TARGET_ACCOUNTS} accounts with a container/share per tenant removes "
                    f"{surplus} sets of per-account charges"
                    + (" (Defender for Storage is billed per account)." if defender_on else ".")
                ),
                resource_id=f"/subscriptions/{context.subscription_id}/resourceGroups/{rg_name}",
                resource_name=rg_name,
                resource_type="microsoft.resources/resourcegroups",
                resource_group=rg_name,
                subscription_id=context.subscription_id,
                location=members[0].get("location") or "",
                remediation_steps=(
                    "1. Design tenant isolation with containers/shares + Entra RBAC (ABAC conditions) or "
                    "user-delegation SAS.\n2. Migrate tenants with AzCopy.\n3. Delete emptied accounts."
                ),
                evidence={"family": family, "accounts": sorted(m["name"] for m in members),
                          "defender_for_storage": defender_on},
                estimated_monthly_savings_usd=saving,
                caf_control="Cost Optimization",
            ))
        return ScanOutput(findings=findings, resources_scanned=len(accounts))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{"name": f"stclient{i:02d}", "resourceGroup": "rg-data", "subscriptionId": "sub-1",
                 "location": "westeurope"} for i in range(1, 13)]


@register_scanner
class StorageTransactionHotspotScanner(PostureScanner):
    """Accounts with very high transaction volume (live mode) - often cheaper on a provisioned/premium model."""

    scanner_name = "storage_transaction_hotspot_scanner"
    display_name = "Storage Transaction Hotspot"
    description = "Detects storage accounts whose transaction volume is unusually high"
    category = ScannerCategory.COST
    severity = SeverityLevel.LOW

    HOT_TRANSACTIONS_30D = 200_000_000

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | project id, name, type, resourceGroup, subscriptionId, location, tags, sku_name = tostring(sku.name)
        """
        try:
            accounts = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings = []
        costs = None
        if self.is_live(context) and accounts:
            costs = await get_resource_costs(context)
            async def _enrich(sa):
                try:
                    m = await cached_metrics(context, sa["id"], ["Transactions"], days=30, interval="P1D", aggregation="Total")
                    sa["transactions_30d"] = (m.get("Transactions") or {}).get("total") or 0.0
                except Exception as exc:
                    warnings.append(f"Storage metrics unavailable for {sa['name']}: {exc}")
                sa["meters"] = (cost_for(costs, sa["id"]) or {}).get("meters") or {}
            await gather_limited(accounts, _enrich, self.setting("arm_concurrency", DEFAULT_ARM_CONCURRENCY))

        limit = float(self.setting("hot_transactions_30d", self.HOT_TRANSACTIONS_30D))
        findings = []
        for sa in accounts:
            tx = sa.get("transactions_30d")
            if not tx or tx < limit:
                continue
            findings.append(self.resource_finding(
                sa, finding_type="storage_transaction_hotspot",
                title=f"{tx / 1e6:,.0f}M transactions in 30 days: {sa['name']}",
                description=(f"Storage account '{sa['name']}' ({sa.get('sku_name')}) served {tx:,.0f} transactions in 30 days. "
                             f"On pay-as-you-go tiers transactions can rival capacity cost; the provisioned (Premium / "
                             f"provisioned v2) Files model has no per-transaction charges."),
                resource_type="microsoft.storage/storageaccounts",
                remediation_steps=("Break down cost by meter, check for chatty clients (polling, missing caching), and "
                                   "price the provisioned Files model for this share."),
                evidence={"transactions_30d": tx, "cost_by_meter_30d": sa.get("meters")},
                estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(accounts), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stclient04",
            "name": "stclient04", "type": "microsoft.storage/storageaccounts", "resourceGroup": "rg-data",
            "subscriptionId": "sub-1", "location": "westeurope", "sku_name": "Standard_LRS",
            "transactions_30d": 652_000_000.0, "meters": {"Files": 107.02},
        }]
