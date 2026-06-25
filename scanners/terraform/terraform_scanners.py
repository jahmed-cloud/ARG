"""
Azure Resource Guardian - Terraform Drift Scanner
====================================================
Compares live Azure resource inventory against an uploaded Terraform
state file to identify:
  1. Resources in Azure NOT in Terraform (unmanaged — shadow IT)
  2. Resources in Terraform NOT in Azure (missing — drift or failed destroy)

Why drift detection matters:
  - Unmanaged resources accumulate quietly and bypass change control.
  - Missing resources can indicate a failed `terraform destroy` or
    out-of-band deletion that needs reconciliation.

Terraform state is uploaded via the API and stored in the
terraform_states table as JSON (TerraformState.resources). The worker
is responsible for loading that JSON and attaching it to the
ScanContext as `context.terraform_state` before invoking this scanner —
the scanner itself never touches the database directly, consistent
with every other scanner in this package.
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

# Resource types skipped in drift detection — auto-managed by Azure itself,
# never expected to appear in a Terraform state file.
SKIP_DRIFT_TYPES = {
    "microsoft.compute/virtualmachines/extensions",
    "microsoft.network/networkwatchers",
    "microsoft.alertsmanagement/smartdetectoralertrules",
    "microsoft.insights/webtests",
}

# Best-effort Azure resource type -> Terraform resource type mapping,
# used only to generate a plausible `terraform import` command for
# unmanaged resources. Not exhaustive — operators should verify the
# correct resource type for anything not in this map.
TF_TYPE_MAP = {
    "microsoft.compute/virtualmachines": "azurerm_linux_virtual_machine",
    "microsoft.network/virtualnetworks": "azurerm_virtual_network",
    "microsoft.network/publicipaddresses": "azurerm_public_ip",
    "microsoft.network/networkinterfaces": "azurerm_network_interface",
    "microsoft.storage/storageaccounts": "azurerm_storage_account",
    "microsoft.keyvault/vaults": "azurerm_key_vault",
    "microsoft.sql/servers": "azurerm_sql_server",
    "microsoft.network/networksecuritygroups": "azurerm_network_security_group",
    "microsoft.compute/disks": "azurerm_managed_disk",
}


@register_scanner
class TerraformDriftScanner(BaseScanner):
    """
    Detects resources in Azure that aren't tracked by Terraform, and
    resources tracked by Terraform that no longer exist in Azure.

    Unlike other scanners, this one depends on external input (an
    uploaded Terraform state file) rather than purely on the Resource
    Graph. If no state has been imported for the subscription being
    scanned, this scanner returns zero findings with a warning rather
    than raising — there's nothing to compare against yet.
    """

    scanner_name = "terraform_drift_scanner"
    display_name = "Terraform Drift Detection"
    description = "Detects Azure resources not managed by Terraform, and Terraform resources missing from Azure"
    category = ScannerCategory.TERRAFORM
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        tf_state = getattr(context, "terraform_state", None)
        if not tf_state:
            return ScanOutput(
                warnings=["No Terraform state imported for this subscription — skipping drift check."]
            )

        query = """
        Resources
        | project id, name, type, resourceGroup, subscriptionId, location
        | order by type asc
        """

        try:
            live_resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        tf_managed = self._parse_terraform_state(tf_state)
        findings = []

        # Unmanaged: live in Azure, absent from Terraform state
        for resource in live_resources:
            rtype = (resource.get("type") or "").lower()
            if rtype in SKIP_DRIFT_TYPES:
                continue

            az_id = (resource.get("id") or "").lower()
            if not az_id or az_id in tf_managed:
                continue

            import_cmd = self._generate_import_command(resource)
            findings.append(self.make_finding(
                finding_type="terraform_unmanaged_resource",
                title=f"Unmanaged by Terraform: {resource['name']}",
                description=(
                    f"Azure resource '{resource['name']}' ({rtype}) exists in Azure but is "
                    f"not tracked in the imported Terraform state. It was likely created "
                    f"manually or via a script outside the IaC pipeline."
                ),
                resource_id=resource["id"],
                resource_name=resource["name"],
                resource_type=rtype,
                resource_group=resource.get("resourceGroup"),
                subscription_id=resource.get("subscriptionId"),
                location=resource.get("location"),
                severity=SeverityLevel.MEDIUM,
                remediation_steps=(
                    "Import this resource into Terraform using the generated import command, "
                    "or document why it is intentionally unmanaged. All production resources "
                    "should be managed as code."
                ),
                azure_cli_script=import_cmd,
                evidence={"drift_status": "unmanaged", "import_command": import_cmd},
                estimated_monthly_savings_usd=0.0,
            ))

        # Missing: tracked by Terraform, absent from live Azure
        live_ids = {(r.get("id") or "").lower() for r in live_resources}
        for tf_id, tf_addr in tf_managed.items():
            if tf_id in live_ids:
                continue

            findings.append(self.make_finding(
                finding_type="terraform_missing_resource",
                title=f"Missing resource (in Terraform, not in Azure): {tf_addr}",
                description=(
                    f"Terraform state references resource '{tf_addr}' but it does not exist "
                    f"in Azure. It may have been deleted outside of Terraform."
                ),
                resource_id=tf_id,
                resource_name=tf_addr,
                resource_type="unknown",
                resource_group="",
                subscription_id=getattr(context, "subscription_id", None) or "",
                severity=SeverityLevel.HIGH,
                remediation_steps=(
                    "Run 'terraform plan' to see what Terraform proposes. If the resource was "
                    "intentionally deleted outside Terraform, remove it from state with "
                    f"'terraform state rm {tf_addr}' to reconcile."
                ),
                azure_cli_script=f"terraform state rm '{tf_addr}'",
                evidence={"drift_status": "missing", "terraform_address": tf_addr},
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(live_resources),
            metadata={
                "terraform_managed_count": len(tf_managed),
                "unmanaged_count": sum(1 for f in findings if f.finding_type == "terraform_unmanaged_resource"),
                "missing_count": sum(1 for f in findings if f.finding_type == "terraform_missing_resource"),
            },
        )

    def _parse_terraform_state(self, tf_state: Dict[str, Any]) -> Dict[str, str]:
        """
        Parse a Terraform state JSON blob into {azure_resource_id: tf_address}.

        Supports Terraform 0.12+ state format where `resources` is a flat
        list with `instances` containing `attributes.id`.
        """
        tf_managed: Dict[str, str] = {}
        for tf_resource in tf_state.get("resources", []):
            module = tf_resource.get("module", "")
            rtype = tf_resource.get("type", "")
            rname = tf_resource.get("name", "")
            for instance in tf_resource.get("instances", []):
                attrs = instance.get("attributes", {})
                az_id = attrs.get("id", "")
                if not az_id:
                    continue
                addr = f"{module}.{rtype}.{rname}" if module else f"{rtype}.{rname}"
                tf_managed[az_id.lower()] = addr
        return tf_managed

    def _generate_import_command(self, resource: Dict[str, Any]) -> str:
        """Generate a best-effort `terraform import` command for an unmanaged resource."""
        rtype = (resource.get("type") or "").lower()
        tf_type = TF_TYPE_MAP.get(rtype, f"azurerm_{rtype.split('/')[-1]}")
        resource_name = (resource.get("name") or "imported_resource").lower().replace("-", "_")
        return (
            f"terraform import {tf_type}.{resource_name} '{resource.get('id')}'\n"
            f"# Then run: terraform plan to review configuration drift"
        )

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
                "id": "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-unmanaged-1",
                "name": "vm-unmanaged-1",
                "type": "microsoft.compute/virtualmachines",
                "resourceGroup": "rg-app",
                "location": "eastus",
                "subscriptionId": "sub-1",
            }
        ]
