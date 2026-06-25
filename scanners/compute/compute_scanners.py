"""
Azure Resource Guardian - Compute Scanners
==========================================
Detects orphaned and wasteful compute resources.

Scanners in this module:
1. UnattachedDiskScanner    — Managed disks with no VM attached
2. OldSnapshotScanner       — Disk snapshots older than threshold
3. DeallocatedVMScanner     — VMs stopped/deallocated (still billing for disk/IP)
4. IdleVMSSScanner          — VM Scale Sets with 0 instances
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from datetime import datetime, timedelta, timezone
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
# Unattached Managed Disk Scanner
# ---------------------------------------------------------------------------

@register_scanner
class UnattachedDiskScanner(BaseScanner):
    """
    Finds managed disks that are not attached to any virtual machine.

    Unattached disks continue billing at full Premium/Standard SSD rates
    even though no workload is using them. This is one of the highest-ROI
    optimizations in Azure cost management.

    ARG query: Find disks where diskState == 'Unattached'.
    """

    scanner_name = "unattached_disk_scanner"
    display_name = "Unattached Managed Disks"
    description  = "Detects managed disks not attached to any virtual machine"
    category     = ScannerCategory.COMPUTE
    severity     = SeverityLevel.HIGH
    requires_cost = True

    # Default cost estimates by SKU (USD/month per GiB approximately)
    COST_PER_GIB: Dict[str, float] = {
        "Premium_LRS":  0.135,
        "Premium_ZRS":  0.170,
        "StandardSSD_LRS": 0.076,
        "StandardSSD_ZRS": 0.095,
        "Standard_LRS": 0.040,
        "UltraSSD_LRS": 0.125,
    }

    async def scan(self, context: ScanContext) -> ScanOutput:
        findings = []

        # Azure Resource Graph query for unattached disks
        # Using KQL — the ARG query language
        query = """
        Resources
        | where type == 'microsoft.compute/disks'
        | where properties.diskState == 'Unattached'
        | where properties.osType !in ('Windows', 'Linux')  // Exclude OS disks
        | project
            id,
            name,
            resourceGroup,
            location,
            subscriptionId,
            sku_name = sku.name,
            disk_size_gb = toint(properties.diskSizeGB),
            disk_state = properties.diskState,
            time_created = properties.timeCreated,
            tags
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        for disk in resources:
            # Calculate estimated monthly cost
            sku = disk.get("sku_name", "Standard_LRS")
            size_gb = disk.get("disk_size_gb", 0) or 0
            cost_per_gib = self.COST_PER_GIB.get(sku, 0.040)
            estimated_cost = size_gb * cost_per_gib

            # Age calculation
            created_str = disk.get("time_created", "")
            age_days = self._calculate_age_days(created_str)

            # Generate CLI script for safe deletion
            cli_script = (
                f"# Verify disk has no snapshots before deletion\n"
                f"az disk show --ids '{disk['id']}' --query 'diskState'\n"
                f"\n"
                f"# Delete the unattached disk\n"
                f"az disk delete --ids '{disk['id']}' --yes"
            )

            ps_script = (
                f"# PowerShell: Remove unattached managed disk\n"
                f"$disk = Get-AzDisk -ResourceGroupName '{disk['resourceGroup']}' "
                f"-DiskName '{disk['name']}'\n"
                f"if ($disk.DiskState -eq 'Unattached') {{\n"
                f"    Remove-AzDisk -ResourceGroupName '{disk['resourceGroup']}' "
                f"-DiskName '{disk['name']}' -Force\n"
                f"}}"
            )

            findings.append(self.make_finding(
                finding_type="unattached_managed_disk",
                title=f"Unattached managed disk: {disk['name']}",
                description=(
                    f"Managed disk '{disk['name']}' ({size_gb} GiB, {sku}) in resource group "
                    f"'{disk['resourceGroup']}' has been unattached for {age_days} days. "
                    f"This disk is billing approximately ${estimated_cost:.2f}/month with no workload using it."
                ),
                resource_id=disk["id"],
                resource_name=disk["name"],
                resource_type="microsoft.compute/disks",
                resource_group=disk["resourceGroup"],
                subscription_id=disk["subscriptionId"],
                location=disk["location"],
                severity=SeverityLevel.HIGH if estimated_cost > 50 else SeverityLevel.MEDIUM,
                remediation_steps=(
                    "1. Confirm the disk is no longer needed by checking with the resource owner\n"
                    "2. Create a final snapshot if archival is needed\n"
                    "3. Delete the disk using the Azure CLI or PowerShell scripts below\n"
                    "4. Verify no snapshots reference this disk before deletion"
                ),
                powershell_script=ps_script,
                azure_cli_script=cli_script,
                evidence={
                    "disk_state": disk.get("disk_state"),
                    "disk_size_gb": size_gb,
                    "sku": sku,
                    "age_days": age_days,
                    "time_created": created_str,
                    "tags": disk.get("tags", {}),
                },
                estimated_monthly_savings_usd=estimated_cost,
                caf_control="Cost Optimization",
                cis_control="6.3",
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(resources),
            metadata={"query": "unattached_disks", "total_potential_savings": sum(
                f.estimated_monthly_savings_usd or 0 for f in findings
            )},
        )

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        """Execute an Azure Resource Graph query and return results."""
        if context.resource_graph_client is None:
            # Return mock data for testing when no real client
            return self._mock_data()

        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        request = QueryRequest(
            subscriptions=[context.subscription_id],
            query=query,
            options={"resultFormat": "objectArray", "$top": 1000}
        )
        response = context.resource_graph_client.resources(request)
        return response.data or []

    def _calculate_age_days(self, created_str: str) -> int:
        if not created_str:
            return 0
        try:
            # Azure returns ISO 8601
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - created).days
        except Exception:
            return 0

    def _mock_data(self) -> List[Dict]:
        """Mock data for unit testing without Azure credentials."""
        return [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-legacy/providers/Microsoft.Compute/disks/disk-old-1",
                "name": "disk-old-1",
                "resourceGroup": "rg-legacy",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "sku_name": "Premium_LRS",
                "disk_size_gb": 512,
                "disk_state": "Unattached",
                "time_created": (datetime.now(timezone.utc) - timedelta(days=90)).isoformat(),
                "tags": {},
            }
        ]


# ---------------------------------------------------------------------------
# Old Snapshot Scanner
# ---------------------------------------------------------------------------

@register_scanner
class OldSnapshotScanner(BaseScanner):
    """
    Finds disk snapshots older than a configurable threshold.

    Organizations often take snapshots for one-time migrations or testing
    and forget to delete them. Snapshots stored long-term cost $0.05-0.052/GiB/month.
    A 1 TB snapshot costs ~$50/month indefinitely.
    """

    scanner_name = "old_snapshot_scanner"
    display_name = "Old Disk Snapshots"
    description  = "Detects disk snapshots older than the configured threshold"
    category     = ScannerCategory.COMPUTE
    severity     = SeverityLevel.MEDIUM
    requires_cost = True

    DEFAULT_AGE_THRESHOLD_DAYS = 90
    SNAPSHOT_COST_PER_GIB = 0.052  # Standard snapshot price USD/GiB/month

    async def scan(self, context: ScanContext) -> ScanOutput:
        threshold_days = self.config.get("age_threshold_days", self.DEFAULT_AGE_THRESHOLD_DAYS)
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=threshold_days)

        query = f"""
        Resources
        | where type == 'microsoft.compute/snapshots'
        | where todatetime(properties.timeCreated) < todatetime('{cutoff_date.isoformat()}')
        | project
            id,
            name,
            resourceGroup,
            location,
            subscriptionId,
            size_gb = toint(properties.diskSizeGB),
            time_created = properties.timeCreated,
            source_disk = properties.creationData.sourceResourceId,
            snapshot_type = properties.incremental,
            tags
        """

        try:
            snapshots = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Snapshot query failed: {e}"])

        findings = []
        for snap in snapshots:
            size_gb = snap.get("size_gb", 0) or 0
            estimated_cost = size_gb * self.SNAPSHOT_COST_PER_GIB
            age_days = self._calculate_age_days(snap.get("time_created", ""))
            source_disk_id = snap.get("source_disk", "N/A")

            findings.append(self.make_finding(
                finding_type="old_disk_snapshot",
                title=f"Old snapshot: {snap['name']} ({age_days} days old)",
                description=(
                    f"Snapshot '{snap['name']}' ({size_gb} GiB) is {age_days} days old "
                    f"(threshold: {threshold_days} days). "
                    f"Monthly cost: ~${estimated_cost:.2f}. "
                    f"Source disk: {source_disk_id}"
                ),
                resource_id=snap["id"],
                resource_name=snap["name"],
                resource_type="microsoft.compute/snapshots",
                resource_group=snap["resourceGroup"],
                subscription_id=snap["subscriptionId"],
                location=snap["location"],
                remediation_steps=(
                    f"1. Verify the snapshot is no longer needed (source disk may have been deleted)\n"
                    f"2. If archival is required, export to Azure Blob Storage (cheaper long-term)\n"
                    f"3. Delete snapshot: az snapshot delete --ids '{snap['id']}'"
                ),
                azure_cli_script=f"az snapshot delete --ids '{snap['id']}' --yes",
                evidence={
                    "age_days": age_days,
                    "size_gb": size_gb,
                    "time_created": snap.get("time_created"),
                    "source_disk_id": source_disk_id,
                    "is_incremental": snap.get("snapshot_type", False),
                },
                estimated_monthly_savings_usd=estimated_cost,
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(snapshots),
        )

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return []
        from azure.mgmt.resourcegraph.models import QueryRequest
        request = QueryRequest(
            subscriptions=[context.subscription_id],
            query=query,
        )
        return context.resource_graph_client.resources(request).data or []

    def _calculate_age_days(self, created_str: str) -> int:
        if not created_str:
            return 0
        try:
            created = datetime.fromisoformat(str(created_str).replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - created).days
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# Deallocated VM Scanner
# ---------------------------------------------------------------------------

@register_scanner
class DeallocatedVMScanner(BaseScanner):
    """
    Finds virtual machines that are stopped/deallocated.

    Deallocated VMs don't bill for compute, BUT they still bill for:
    - Attached managed disks
    - Reserved public IP addresses
    - Diagnostics storage

    VMs deallocated for >30 days are strong candidates for deletion
    or rightsizing (resize + restart vs. keep paying for idle infra).
    """

    scanner_name = "deallocated_vm_scanner"
    display_name = "Deallocated Virtual Machines"
    description  = "Finds VMs that are stopped/deallocated and may be candidates for deletion"
    category     = ScannerCategory.COMPUTE
    severity     = SeverityLevel.MEDIUM

    DEFAULT_THRESHOLD_DAYS = 30

    async def scan(self, context: ScanContext) -> ScanOutput:
        threshold_days = self.config.get("threshold_days", self.DEFAULT_THRESHOLD_DAYS)

        query = """
        Resources
        | where type == 'microsoft.compute/virtualmachines'
        | extend vmStatus = properties.extended.instanceView.powerState.displayStatus
        | where vmStatus in ('VM deallocated', 'VM stopped')
        | project
            id,
            name,
            resourceGroup,
            location,
            subscriptionId,
            vm_size = properties.hardwareProfile.vmSize,
            os_type = properties.storageProfile.osDisk.osType,
            data_disks = array_length(properties.storageProfile.dataDisks),
            vm_status = vmStatus,
            tags
        """

        try:
            vms = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"VM query failed: {e}"])

        findings = []
        for vm in vms:
            vm_status = vm.get("vm_status", "Unknown")
            vm_size = vm.get("vm_size", "Unknown")
            data_disk_count = vm.get("data_disks", 0) or 0
            tags = vm.get("tags", {}) or {}
            owner = tags.get("Owner", tags.get("owner", "Unknown"))

            findings.append(self.make_finding(
                finding_type="deallocated_virtual_machine",
                title=f"Deallocated VM: {vm['name']} ({vm_size})",
                description=(
                    f"Virtual machine '{vm['name']}' (size: {vm_size}) is currently "
                    f"'{vm_status}'. It has {data_disk_count} data disk(s) that continue "
                    f"billing. Owner: {owner}. "
                    f"Consider deleting this VM and its resources if no longer needed."
                ),
                resource_id=vm["id"],
                resource_name=vm["name"],
                resource_type="microsoft.compute/virtualmachines",
                resource_group=vm["resourceGroup"],
                subscription_id=vm["subscriptionId"],
                location=vm["location"],
                remediation_steps=(
                    "1. Contact the VM owner to determine if it's still needed\n"
                    "2. If unused: capture a managed image if archival is needed\n"
                    "3. Delete the VM and choose to also delete attached disks and NIC\n"
                    "4. If needed occasionally: consider Azure DevTest Labs or Spot instances"
                ),
                azure_cli_script=(
                    f"# Delete VM and associated resources\n"
                    f"az vm delete --ids '{vm['id']}' --yes\n"
                    f"# Then delete orphaned NICs and disks separately"
                ),
                evidence={
                    "vm_status": vm_status,
                    "vm_size": vm_size,
                    "os_type": vm.get("os_type"),
                    "data_disk_count": data_disk_count,
                    "owner": owner,
                    "tags": tags,
                },
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(vms),
        )

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return []
        from azure.mgmt.resourcegraph.models import QueryRequest
        request = QueryRequest(subscriptions=[context.subscription_id], query=query)
        return context.resource_graph_client.resources(request).data or []


# ---------------------------------------------------------------------------
# Idle VMSS Scanner
# ---------------------------------------------------------------------------

@register_scanner
class IdleVMSSScanner(BaseScanner):
    """
    Finds VM Scale Sets with zero running instances.

    Empty VMSS resources don't bill for compute, but they:
    - Represent configuration drift / orphaned infra
    - May have load balancers and public IPs still attached (billing!)
    - Clutter the resource inventory
    """

    scanner_name = "idle_vmss_scanner"
    display_name = "Idle VM Scale Sets"
    description  = "Finds VM Scale Sets with zero instances that may be orphaned"
    category     = ScannerCategory.COMPUTE
    severity     = SeverityLevel.LOW

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type == 'microsoft.compute/virtualmachinescalesets'
        | extend instance_count = toint(properties.singlePlacementGroup)
        | extend sku_capacity = toint(sku.capacity)
        | where sku_capacity == 0
        | project
            id,
            name,
            resourceGroup,
            location,
            subscriptionId,
            sku_name = sku.name,
            capacity = sku.capacity,
            tags
        """

        try:
            vmss_list = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"VMSS query failed: {e}"])

        findings = []
        for vmss in vmss_list:
            findings.append(self.make_finding(
                finding_type="idle_vmss",
                title=f"Idle VMSS: {vmss['name']} (0 instances)",
                description=(
                    f"VM Scale Set '{vmss['name']}' in resource group '{vmss['resourceGroup']}' "
                    f"has 0 running instances. Verify this is expected (e.g., scheduled scale-to-zero) "
                    f"or delete if no longer needed."
                ),
                resource_id=vmss["id"],
                resource_name=vmss["name"],
                resource_type="microsoft.compute/virtualmachinescalesets",
                resource_group=vmss["resourceGroup"],
                subscription_id=vmss["subscriptionId"],
                location=vmss["location"],
                remediation_steps=(
                    "1. Check if the VMSS is part of an auto-scaling solution (scale to 0 = intended)\n"
                    "2. Check associated load balancer health probes\n"
                    "3. If unused: az vmss delete --name <name> --resource-group <rg>"
                ),
                azure_cli_script=f"az vmss delete --ids '{vmss['id']}' --yes",
                evidence={
                    "sku_name": vmss.get("sku_name"),
                    "capacity": vmss.get("capacity", 0),
                    "tags": vmss.get("tags", {}),
                },
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(vmss_list),
        )

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return []
        from azure.mgmt.resourcegraph.models import QueryRequest
        request = QueryRequest(subscriptions=[context.subscription_id], query=query)
        return context.resource_graph_client.resources(request).data or []
