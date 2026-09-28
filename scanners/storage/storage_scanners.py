"""
Azure Resource Guardian - Storage Scanners
===========================================
Detects orphaned and potentially unused storage resources.

Scanners in this module:
1. UnusedStorageAccountScanner - Storage accounts with no apparent activity
2. OrphanedBackupVaultScanner  - Recovery Services Vaults with no protected items

Note: True transaction-level "unused" detection requires Azure Monitor
metrics, which are not queryable from Resource Graph. When an ArmClient is
available (live scans) UnusedStorageAccountScanner reads the 30-day
Transactions metric split by API name (housekeeping excluded) and the
latest UsedCapacity; idle accounts that still hold data are reported as
dormant data, empty ones as deletion candidates. Without an ArmClient it
falls back to flagging candidates for manual verification.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from typing import Any, Dict, List, Optional

from scanners.base.azure_api import (
    DEFAULT_ARM_CONCURRENCY,
    cached_metrics,
    cost_for,
    gather_limited,
    get_resource_costs,
    storage_data_operations,
)
from scanners.base.base_scanner import (
    BaseScanner,
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)


def _account_of(uri: Optional[str]) -> Optional[str]:
    """'https://acct.blob.core.windows.net/vhds/x.vhd' -> 'acct'."""
    if not uri or "://" not in uri:
        return None
    return uri.split("://", 1)[1].split(".", 1)[0].lower() or None


# ---------------------------------------------------------------------------
# Unused Storage Account Scanner
# ---------------------------------------------------------------------------

@register_scanner
class UnusedStorageAccountScanner(BaseScanner):
    """
    Storage accounts nobody reads or writes. In live scans the 30-day
    Transactions metric is split by API so platform housekeeping (Defender,
    portal and inventory calls, ~120 a month on every account) is not
    mistaken for use, and any real read or write keeps the account out.
    An idle account that still holds data is reported as dormant data
    (tier or archive it) rather than as a deletion candidate. Accounts whose
    VHDs back a VM are left to the VM scanners.

    Emits finding_type="unused_storage_account" (empty, or unverifiable
    without metrics) and finding_type="dormant_storage_data" (idle, holds data).
    """

    scanner_name = "unused_storage_account_scanner"
    display_name = "Potentially Unused Storage Accounts"
    description = "Detects storage accounts with no data-plane reads or writes in 30 days"
    category = ScannerCategory.STORAGE
    severity = SeverityLevel.MEDIUM
    requires_cost = True

    BASE_MONTHLY_COST = 0.50  # Minimal cost just for the account existing
    IDLE_TRANSACTIONS_30D = 200  # Fallback when the ApiName split is unavailable: housekeeping is ~120/30 d
    IDLE_DATA_OPERATIONS_30D = 10  # Reads/writes (housekeeping excluded) at or below this are idle: a portal browse
    EMPTY_GB = 1.0  # At or below this the account is treated as empty
    COLD_USD_PER_GB = 0.0045  # Blob Cold tier, LRS, per GB-month - the target for dormant data
    REDUNDANCY_FACTOR = {"lrs": 1.0, "zrs": 1.25, "grs": 2.0, "ragrs": 2.0, "gzrs": 2.5, "ragzrs": 2.5}

    VM_REFERENCES_QUERY = """
        Resources
        | where type =~ 'microsoft.compute/virtualmachines'
        | extend osVhd = tostring(properties.storageProfile.osDisk.vhd.uri),
                 bootDiag = tostring(properties.diagnosticsProfile.bootDiagnostics.storageUri)
        | mv-expand dataDisk = iff(array_length(properties.storageProfile.dataDisks) > 0,
                                   properties.storageProfile.dataDisks, dynamic([{}]))
        | extend dataVhd = tostring(dataDisk.vhd.uri)
        | where isnotempty(osVhd) or isnotempty(dataVhd) or isnotempty(bootDiag)
        | project name, osVhd, dataVhd, bootDiag
        """

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

        warnings: List[str] = []
        vhd_users, boot_diag_users = await self._vm_references(context, warnings)
        live = getattr(context, "arm_client", None) is not None
        costs = await get_resource_costs(context) if live and resources else None
        activities: Dict[str, Optional[Dict[str, Any]]] = {}
        if live:
            async def fetch(sa: Dict[str, Any]) -> None:
                if sa["name"].lower() not in vhd_users:
                    activities[sa["id"]] = await self._activity(context, sa["id"], warnings)

            await gather_limited(resources, fetch, self.config.get("arm_concurrency", DEFAULT_ARM_CONCURRENCY))

        findings = []
        for sa in resources:
            tags = sa.get("tags") or {}
            if tags.get("arg-ignore") or tags.get("arg-reserved"):
                continue
            name_key = sa["name"].lower()
            if name_key in vhd_users:
                continue  # unmanaged disks of a VM: the account lives and dies with the VM

            activity: Optional[Dict[str, Any]] = activities.get(sa["id"])
            if activity is not None and not self._is_idle(activity):
                continue
            findings.append(self._finding(sa, activity, costs, sorted(boot_diag_users.get(name_key, ()))))

        return ScanOutput(findings=findings, resources_scanned=len(resources), warnings=warnings)

    # -- classification ---------------------------------------------------

    def _is_idle(self, activity: Dict[str, Any]) -> bool:
        if activity.get("data_operations_30d") is not None:
            limit = float(self.config.get("idle_data_operations_30d", self.IDLE_DATA_OPERATIONS_30D))
            return activity["data_operations_30d"] <= limit
        limit = float(self.config.get("idle_transactions_30d", self.IDLE_TRANSACTIONS_30D))
        return activity["transactions_30d"] <= limit

    def _dormant_saving(self, sa: Dict[str, Any], used_gb: float, cost_usd: Optional[float]) -> Optional[float]:
        """Current cost minus the same data kept in the Cold tier (estimate)."""
        if not cost_usd:
            return None
        redundancy = str(sa.get("sku_name") or "").split("_")[-1].lower()
        cold = used_gb * self.COLD_USD_PER_GB * self.REDUNDANCY_FACTOR.get(redundancy, 1.0)
        return round(max(0.0, cost_usd - cold), 2) or None

    def _finding(self, sa: Dict[str, Any], activity: Optional[Dict[str, Any]],
                 costs: Optional[Dict[str, Dict[str, Any]]], boot_diag_vms: List[str]):
        name, rg = sa["name"], sa.get("resourceGroup")
        kind, sku = sa.get("kind") or "Unknown", sa.get("sku_name") or "Unknown"
        public_access = bool(sa.get("allow_blob_public_access"))
        premium = str(sku).lower().startswith("premium")
        severity = SeverityLevel.HIGH if kind.lower() == "blobstorage" else SeverityLevel.MEDIUM
        cost_usd = (cost_for(costs, sa["id"]) or {}).get("cost_usd")
        finding_type = "unused_storage_account"
        evidence: Dict[str, Any] = {"kind": sa.get("kind"), "sku": sa.get("sku_name"),
                                    "access_tier": sa.get("access_tier"), "public_access_enabled": public_access}
        delete_steps = (
            "1. Check Azure Monitor Storage Insights (Transactions split by API name) over 90 days.\n"
            "2. List containers/queues/tables/shares to confirm no data is present.\n"
            "3. If confirmed empty and unused, delete the account.\n"
            "4. If intentionally reserved, tag with 'arg-reserved: true' to suppress."
        )

        if activity is None:
            title = f"Verify usage: {name}"
            description = (
                f"Storage account '{name}' (kind: {kind}, SKU: {sku}) could not be confirmed as actively used "
                f"from Resource Graph metadata alone - verify with Storage Insights transaction metrics before "
                f"taking action."
            )
            saving: Optional[float] = self.BASE_MONTHLY_COST
            remediation = delete_steps
            cli, ps = self._delete_scripts(name, rg)
        elif activity["used_capacity_gb"] > float(self.config.get("empty_gb", self.EMPTY_GB)):
            used_gb = activity["used_capacity_gb"]
            evidence.update(activity)
            finding_type = "dormant_storage_data"
            severity = SeverityLevel.MEDIUM if premium else SeverityLevel.LOW
            ops = activity.get("data_operations_30d")
            title = f"Dormant data: {name} ({used_gb:,.1f} GB, " + (
                f"{ops:,.0f} data operation{'s' if ops != 1 else ''} in 30 days)" if ops
                else "no reads or writes in 30 days)")
            saving = self._dormant_saving(sa, used_gb, cost_usd)
            description = (
                f"Storage account '{name}' (kind: {kind}, SKU: {sku}) holds {used_gb:,.2f} GB but "
                f"{self._traffic_text(activity)}. The data is kept, not used: a tiering or archiving candidate, "
                f"not a deletion candidate - confirm retention with the owner first."
            )
            if premium:
                description += (
                    " Premium storage is billed on provisioned size (page blobs / VHDs) and cannot be tiered - copy "
                    "the data to a Standard account in the Cold or Archive tier, then remove the premium account."
                )
            if saving:
                description += (f" Estimated saving: USD {saving:,.0f}/month versus keeping the same data in the "
                                f"Cold tier (estimate).")
            remediation = (
                "1. Confirm with the owner whether the data must be kept, and for how long.\n"
                "2. If it must be kept: add a lifecycle management rule that moves blobs to Cold/Archive"
                + (" (Premium cannot be tiered: AzCopy the blobs to a Standard account first)" if premium else "")
                + ".\n"
                "3. If it is no longer needed: take a final copy if required, then delete the account.\n"
                "4. If intentionally kept as-is, tag with 'arg-reserved: true' to suppress."
            )
            cli = (
                f"# Review what is stored before deciding:\n"
                f"az storage container list --account-name {name} --auth-mode login --output table\n"
                f"# Keep the data but pay less - lifecycle rule to Cold / Archive:\n"
                f"az storage account management-policy create --account-name {name} "
                f"--resource-group {rg} --policy @policy.json"
            )
            ps = (
                f"$ctx = New-AzStorageContext -StorageAccountName '{name}' -UseConnectedAccount\n"
                f"Get-AzStorageContainer -Context $ctx"
            )
        else:
            evidence.update(activity)
            title = f"Idle storage account: {name}"
            description = (
                f"Storage account '{name}' (kind: {kind}, SKU: {sku}) {self._traffic_text(activity)} and holds "
                f"{activity['used_capacity_gb']:,.2f} GB. Per-account charges (e.g. Defender for Storage) keep "
                f"accruing while it sits idle."
            )
            saving = round(cost_usd, 2) if cost_usd else self.BASE_MONTHLY_COST
            remediation = delete_steps
            cli, ps = self._delete_scripts(name, rg)

        if boot_diag_vms:
            evidence["boot_diagnostics_for"] = boot_diag_vms
            description += (f" It is the boot-diagnostics target of {', '.join(boot_diag_vms[:5])}"
                            f"{' and more' if len(boot_diag_vms) > 5 else ''} - switch those VMs to managed boot "
                            f"diagnostics before removing it.")
        if public_access:
            description += " ⚠️ Public blob access is enabled on this account."
            severity = SeverityLevel.HIGH

        return self.make_finding(
            finding_type=finding_type,
            title=title,
            description=description,
            resource_id=sa["id"],
            resource_name=name,
            resource_type="microsoft.storage/storageaccounts",
            resource_group=rg,
            subscription_id=sa.get("subscriptionId"),
            location=sa.get("location"),
            severity=severity,
            remediation_steps=remediation,
            azure_cli_script=cli,
            powershell_script=ps,
            evidence=evidence,
            estimated_monthly_savings_usd=saving,
        )

    @staticmethod
    def _traffic_text(activity: Dict[str, Any]) -> str:
        if activity.get("data_operations_30d") is None:
            return f"served {activity['transactions_30d']:,.0f} data-plane transactions in the last 30 days"
        ops = activity["data_operations_30d"]
        reads = f"{ops:,.0f} data read/write operation{'s' if ops != 1 else ''}" if ops else "no data reads or writes"
        rest = max(0.0, activity["transactions_30d"] - ops)
        return (f"had {reads} in the last 30 days ({'the other' if ops else 'all'} {rest:,.0f} transactions are "
                f"platform housekeeping such as Defender and portal listing calls)")

    @staticmethod
    def _delete_scripts(name: str, rg: Optional[str]):
        cli = (
            f"# Verify empty before deleting:\n"
            f"az storage container list --account-name {name} --output table\n"
            f"# If confirmed empty:\n"
            f"az storage account delete --name {name} --resource-group {rg} --yes"
        )
        ps = (
            f"$ctx = New-AzStorageContext -StorageAccountName '{name}'\n"
            f"Get-AzStorageContainer -Context $ctx\n"
            f"# If empty:\n"
            f"Remove-AzStorageAccount -Name '{name}' -ResourceGroupName '{rg}' -Force"
        )
        return cli, ps

    # -- data ---------------------------------------------------------------

    async def _vm_references(self, context: ScanContext, warnings: List[str]):
        """({account name: VMs with VHDs in it}, {account name: VMs sending boot diagnostics to it})."""
        vhd: Dict[str, set] = {}
        boot: Dict[str, set] = {}
        if context.resource_graph_client is None:
            return vhd, boot
        try:
            rows = await self._run_arg_query(context, self.VM_REFERENCES_QUERY)
        except Exception as exc:
            warnings.append(f"VM storage references unavailable: {exc}")
            return vhd, boot
        for row in rows:
            for key, target in (("osVhd", vhd), ("dataVhd", vhd), ("bootDiag", boot)):
                account = _account_of(row.get(key))
                if account:
                    target.setdefault(account, set()).add(row.get("name"))
        return vhd, boot

    async def _activity(self, context: ScanContext, resource_id: str, warnings: List[str]) -> Optional[Dict[str, Any]]:
        """30-day transactions (split by API when possible) and latest used capacity; None if unavailable."""
        try:
            tx = await cached_metrics(context, resource_id, ["Transactions"], days=30, interval="P1D", aggregation="Total")
            cap = await cached_metrics(context, resource_id, ["UsedCapacity"], days=7, interval="PT12H", aggregation="Average")
        except Exception as exc:
            warnings.append(f"Storage metrics unavailable for {resource_id.split('/')[-1]}: {exc}")
            return None
        used = (cap.get("UsedCapacity") or {}).get("latest_average") or 0.0
        activity: Dict[str, Any] = {
            "transactions_30d": (tx.get("Transactions") or {}).get("total") or 0.0,
            "used_capacity_gb": round(used / 1024 ** 3, 2),
        }
        split = getattr(context.arm_client, "metric_totals_by", None)
        if split is not None:
            try:
                by_api = await split(resource_id, "Transactions", "ApiName", days=30)
            except Exception as exc:
                warnings.append(f"Storage API breakdown unavailable for {resource_id.split('/')[-1]}: {exc}")
            else:
                activity["data_operations_30d"] = storage_data_operations(by_api)
                activity["transactions_by_api"] = dict(sorted(by_api.items(), key=lambda kv: -kv[1])[:15])
        return activity

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from scanners.base.azure_api import query_resource_graph

        return await query_resource_graph(context, query) or []

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
    so this scanner raises an advisory finding for every vault - analysts
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

        # Live scans count protected items per vault; a vault with items is in use, not orphaned.
        protected: Dict[str, Optional[int]] = {}
        warnings: List[str] = []
        arm = getattr(context, "arm_client", None)
        if arm is not None:
            for vault in resources:
                try:
                    items = await arm.get_all(f"{vault['id']}/backupProtectedItems", "2023-04-01")
                    protected[vault["id"]] = len(items)
                except Exception as exc:
                    warnings.append(f"Backup items unavailable for {vault['name']}: {exc}")

        findings = []
        for vault in resources:
            count = protected.get(vault["id"])
            if count:
                continue
            verified = count == 0
            findings.append(self.make_finding(
                finding_type="orphaned_backup_vault",
                title=f"{'Empty vault' if verified else 'Verify backup items'}: {vault['name']}",
                description=(
                    f"Recovery Services Vault '{vault['name']}' "
                    f"{'has no protected items' if verified else 'may have no protected items'}. "
                    f"{'' if verified else 'Verify in the Azure Portal under Backup Items. '}"
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
                    "protected_items": count,
                },
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(resources), warnings=warnings)

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from scanners.base.azure_api import query_resource_graph

        return await query_resource_graph(context, query) or []

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
