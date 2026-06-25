"""
Azure Resource Guardian - Network Scanners
===========================================
Detects orphaned and wasteful network resources.

Scanners in this module:
1. UnusedPublicIPScanner          — Public IPs not attached to any resource
2. OrphanedNICScanner              — Network interfaces not attached to any VM
3. EmptyLoadBalancerScanner        — Load balancers with no backend pool members
4. EmptyApplicationGatewayScanner  — App Gateways with no backend pool members

Network orphans are particularly costly because Standard SKU resources
(public IPs, load balancers, app gateways) bill continuously regardless
of whether they're routing any traffic.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from datetime import datetime, timezone
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
# Unused Public IP Scanner
# ---------------------------------------------------------------------------

@register_scanner
class UnusedPublicIPScanner(BaseScanner):
    """
    Detects public IP addresses not associated with any resource.

    Unattached Standard SKU static public IPs still incur charges
    (~$3.65/month each). Basic SKU dynamic IPs are free when detached,
    but we still flag them at lower severity to reduce IP sprawl and
    avoid hitting subscription IP quota limits.
    """

    scanner_name = "unused_public_ip_scanner"
    display_name = "Unused Public IP Addresses"
    description = "Detects public IP addresses not associated with any resource"
    category = ScannerCategory.NETWORK
    severity = SeverityLevel.HIGH
    requires_cost = True

    COST_BY_SKU: Dict[str, float] = {
        "standard": 3.65,
        "basic": 2.92,
    }

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.network/publicipaddresses'
        | where isnull(properties.ipConfiguration) and isnull(properties.natGateway)
        | project
            id, name, resourceGroup, subscriptionId, location, tags,
            sku_name = sku.name,
            allocation_method = properties.publicIPAllocationMethod,
            ip_address = properties.ipAddress
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for ip in resources:
            sku = (ip.get("sku_name") or "basic").lower()
            is_static = (ip.get("allocation_method") or "").lower() == "static"
            monthly_cost = self.COST_BY_SKU.get(sku, self.COST_BY_SKU["basic"])
            saving = monthly_cost if is_static else 0.0
            severity = SeverityLevel.HIGH if is_static else SeverityLevel.MEDIUM

            findings.append(self.make_finding(
                finding_type="unused_public_ip",
                title=f"Unattached public IP: {ip['name']}",
                description=(
                    f"Public IP address '{ip['name']}' ({sku.title()} SKU, "
                    f"{ip.get('allocation_method', 'Unknown')} allocation) is not attached "
                    f"to any network interface, load balancer, or NAT gateway."
                ),
                resource_id=ip["id"],
                resource_name=ip["name"],
                resource_type="microsoft.network/publicipaddresses",
                resource_group=ip.get("resourceGroup"),
                subscription_id=ip.get("subscriptionId"),
                location=ip.get("location"),
                severity=severity,
                remediation_steps=(
                    "1. Confirm no upcoming workload requires this IP address.\n"
                    "2. Delete the public IP via the Azure CLI or PowerShell script below."
                ),
                azure_cli_script=(
                    f"az network public-ip delete "
                    f"--name {ip['name']} --resource-group {ip.get('resourceGroup')}"
                ),
                powershell_script=(
                    f"Remove-AzPublicIpAddress -Name '{ip['name']}' "
                    f"-ResourceGroupName '{ip.get('resourceGroup')}' -Force"
                ),
                evidence={
                    "sku": sku,
                    "allocation_method": ip.get("allocation_method"),
                    "current_ip": ip.get("ip_address"),
                },
                estimated_monthly_savings_usd=saving,
                caf_control="Cost Optimization",
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(resources),
            metadata={"total_potential_savings": sum(f.estimated_monthly_savings_usd or 0 for f in findings)},
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
                "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/publicIPAddresses/pip-orphan-1",
                "name": "pip-orphan-1",
                "resourceGroup": "rg-net",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "sku_name": "Standard",
                "allocation_method": "Static",
                "ip_address": "20.10.20.30",
                "tags": {},
            }
        ]


# ---------------------------------------------------------------------------
# Orphaned NIC Scanner
# ---------------------------------------------------------------------------

@register_scanner
class OrphanedNICScanner(BaseScanner):
    """
    Detects network interfaces not attached to any virtual machine.

    NICs carry no direct hourly cost, but orphaned NICs clutter the
    network space, can retain NSG/IP associations with their own
    billing implications, and block resource group cleanup.
    """

    scanner_name = "orphaned_nic_scanner"
    display_name = "Orphaned Network Interfaces"
    description = "Detects network interfaces not attached to any virtual machine"
    category = ScannerCategory.NETWORK
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.network/networkinterfaces'
        | where isnull(properties.virtualMachine)
        | project
            id, name, resourceGroup, subscriptionId, location, tags,
            private_ip = properties.ipConfigurations[0].properties.privateIPAddress,
            has_public_ip = isnotnull(properties.ipConfigurations[0].properties.publicIPAddress),
            nsg_id = properties.networkSecurityGroup.id
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for nic in resources:
            findings.append(self.make_finding(
                finding_type="orphaned_nic",
                title=f"Orphaned network interface: {nic['name']}",
                description=(
                    f"Network interface '{nic['name']}' is not attached to any virtual machine. "
                    f"Private IP: {nic.get('private_ip', 'N/A')}. "
                    f"Has public IP: {nic.get('has_public_ip', False)}."
                ),
                resource_id=nic["id"],
                resource_name=nic["name"],
                resource_type="microsoft.network/networkinterfaces",
                resource_group=nic.get("resourceGroup"),
                subscription_id=nic.get("subscriptionId"),
                location=nic.get("location"),
                severity=SeverityLevel.MEDIUM,
                remediation_steps=(
                    "Delete this NIC if the VM it was attached to has been removed. "
                    "Check for any NSG associations before deletion."
                ),
                azure_cli_script=(
                    f"az network nic delete --name {nic['name']} "
                    f"--resource-group {nic.get('resourceGroup')}"
                ),
                powershell_script=(
                    f"Remove-AzNetworkInterface -Name '{nic['name']}' "
                    f"-ResourceGroupName '{nic.get('resourceGroup')}' -Force"
                ),
                evidence={
                    "private_ip": nic.get("private_ip"),
                    "has_public_ip": nic.get("has_public_ip", False),
                    "has_nsg": bool(nic.get("nsg_id")),
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
                "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/networkInterfaces/nic-orphan-1",
                "name": "nic-orphan-1",
                "resourceGroup": "rg-net",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "private_ip": "10.0.1.5",
                "has_public_ip": False,
                "nsg_id": None,
                "tags": {},
            }
        ]


# ---------------------------------------------------------------------------
# Empty Load Balancer Scanner
# ---------------------------------------------------------------------------

@register_scanner
class EmptyLoadBalancerScanner(BaseScanner):
    """
    Detects Standard SKU load balancers with no backend pool members.

    Standard LB costs ~$18.25/month base + ~$5/rule/month. An empty LB
    with a handful of rules can cost $20-30/month while routing zero
    traffic. Basic SKU LBs are free, so they're flagged at Low severity
    purely for hygiene.
    """

    scanner_name = "empty_load_balancer_scanner"
    display_name = "Empty Load Balancers"
    description = "Detects load balancers with empty backend address pools"
    category = ScannerCategory.NETWORK
    severity = SeverityLevel.HIGH
    requires_cost = True

    MONTHLY_COST_STANDARD = 18.25
    COST_PER_RULE = 5.0

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.network/loadbalancers'
        | extend hasBackendMembers = iff(
            array_length(properties.backendAddressPools) > 0,
            array_length(properties.backendAddressPools[0].properties.backendIPConfigurations) > 0
                or array_length(properties.backendAddressPools[0].properties.loadBalancerBackendAddresses) > 0,
            false
        )
        | where not(hasBackendMembers)
        | project
            id, name, resourceGroup, subscriptionId, location, tags,
            sku_name = sku.name,
            rule_count = array_length(properties.loadBalancingRules)
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for lb in resources:
            sku = (lb.get("sku_name") or "basic").lower()
            rule_count = lb.get("rule_count") or 0

            if sku == "standard":
                monthly_cost = self.MONTHLY_COST_STANDARD + (rule_count * self.COST_PER_RULE)
                severity = SeverityLevel.HIGH
            else:
                monthly_cost = 0.0
                severity = SeverityLevel.LOW

            findings.append(self.make_finding(
                finding_type="empty_load_balancer",
                title=f"Empty load balancer: {lb['name']}",
                description=(
                    f"Load balancer '{lb['name']}' ({sku.title()} SKU) has no backend pool "
                    f"members. It has {rule_count} load balancing rule(s) defined but no "
                    f"instances to route to."
                ),
                resource_id=lb["id"],
                resource_name=lb["name"],
                resource_type="microsoft.network/loadbalancers",
                resource_group=lb.get("resourceGroup"),
                subscription_id=lb.get("subscriptionId"),
                location=lb.get("location"),
                severity=severity,
                remediation_steps=(
                    "If this load balancer is no longer needed, delete it along with its "
                    "frontend IP configurations and rules. If reserved for an upcoming "
                    "deployment, suppress this finding instead."
                ),
                azure_cli_script=(
                    f"az network lb delete --name {lb['name']} "
                    f"--resource-group {lb.get('resourceGroup')}"
                ),
                powershell_script=(
                    f"Remove-AzLoadBalancer -Name '{lb['name']}' "
                    f"-ResourceGroupName '{lb.get('resourceGroup')}' -Force"
                ),
                evidence={"sku": sku, "rule_count": rule_count},
                estimated_monthly_savings_usd=monthly_cost,
                caf_control="Cost Optimization",
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(resources),
            metadata={"total_potential_savings": sum(f.estimated_monthly_savings_usd or 0 for f in findings)},
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
                "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/loadBalancers/lb-empty-1",
                "name": "lb-empty-1",
                "resourceGroup": "rg-net",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "sku_name": "Standard",
                "rule_count": 2,
                "tags": {},
            }
        ]


# ---------------------------------------------------------------------------
# Empty Application Gateway Scanner
# ---------------------------------------------------------------------------

@register_scanner
class EmptyApplicationGatewayScanner(BaseScanner):
    """
    Detects Application Gateways with no backend pool members.

    App Gateway V2 costs roughly $0.246/hr fixed (~$180/month) just to
    exist, plus capacity unit charges. An idle gateway is one of the
    single most expensive orphan types ARG can detect.
    """

    scanner_name = "empty_application_gateway_scanner"
    display_name = "Empty Application Gateways"
    description = "Detects Application Gateways with no backend pool members"
    category = ScannerCategory.NETWORK
    severity = SeverityLevel.CRITICAL
    requires_cost = True

    MONTHLY_COST_V2 = 180.0
    MONTHLY_COST_V1 = 30.0

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.network/applicationgateways'
        | extend hasBackendMembers = iff(
            array_length(properties.backendAddressPools) > 0,
            array_length(properties.backendAddressPools[0].properties.backendAddresses) > 0,
            false
        )
        | where not(hasBackendMembers)
        | project
            id, name, resourceGroup, subscriptionId, location, tags,
            tier = properties.sku.tier,
            operational_state = properties.operationalState
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for agw in resources:
            tier = (agw.get("tier") or "standard").lower()
            is_v2 = "v2" in tier
            monthly_cost = self.MONTHLY_COST_V2 if is_v2 else self.MONTHLY_COST_V1

            findings.append(self.make_finding(
                finding_type="empty_application_gateway",
                title=f"Empty Application Gateway: {agw['name']}",
                description=(
                    f"Application Gateway '{agw['name']}' ({tier.upper()}) has no members in "
                    f"its backend pools. State: '{agw.get('operational_state', 'unknown')}'. "
                    f"Estimated cost: ${monthly_cost:.0f}/month while idle."
                ),
                resource_id=agw["id"],
                resource_name=agw["name"],
                resource_type="microsoft.network/applicationgateways",
                resource_group=agw.get("resourceGroup"),
                subscription_id=agw.get("subscriptionId"),
                location=agw.get("location"),
                severity=SeverityLevel.CRITICAL,
                remediation_steps=(
                    "Delete this Application Gateway if it is not serving traffic. "
                    f"Idle V2 gateways cost approximately ${self.MONTHLY_COST_V2:.0f}/month."
                ),
                azure_cli_script=(
                    f"az network application-gateway delete --name {agw['name']} "
                    f"--resource-group {agw.get('resourceGroup')}"
                ),
                powershell_script=(
                    f"Remove-AzApplicationGateway -Name '{agw['name']}' "
                    f"-ResourceGroupName '{agw.get('resourceGroup')}'"
                ),
                evidence={"tier": tier, "is_v2": is_v2},
                estimated_monthly_savings_usd=monthly_cost,
                caf_control="Cost Optimization",
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(resources),
            metadata={"total_potential_savings": sum(f.estimated_monthly_savings_usd or 0 for f in findings)},
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
                "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/applicationGateways/agw-empty-1",
                "name": "agw-empty-1",
                "resourceGroup": "rg-net",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "tier": "Standard_v2",
                "operational_state": "Running",
                "tags": {},
            }
        ]
