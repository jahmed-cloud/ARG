"""
Azure Resource Guardian - Network Posture Scanners
===================================================
Network waste and exposure checks that complement network_scanners.py.

Scanners in this module:
1. UnassociatedDdosPlanScanner        — DDoS Network Protection plans protecting nothing
2. OrphanedNSGScanner                  — NSGs attached to no subnet and no NIC
3. OpenManagementPortScanner           — NSG rules allowing RDP/SSH/WinRM from the Internet
4. PublicIPOnOrphanedNICScanner        — Public IPs held by NICs that have no VM
5. VMPublicIPWithBastionScanner        — VMs keeping a public IP in a VNet that has Bastion
6. PrivateDnsZoneWithoutEndpointsScanner — privatelink.* zones with no records
7. SubnetWithoutNSGScanner             — Workload subnets with no NSG

At most one finding is emitted per (resource, finding_type): the worker
upserts on that pair, so per-rule / per-subnet details go into evidence.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from typing import Any, Dict, Iterable, List, Optional, Set

from scanners.base.azure_api import (
    HOURS_PER_MONTH,
    cost_for,
    get_resource_costs,
    get_retail_price,
)
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.posture_scanner import PostureScanner

INTERNET_SOURCES = {"*", "internet", "0.0.0.0/0", "any", "::/0"}
MANAGEMENT_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS"}
PLATFORM_SUBNETS = {
    "gatewaysubnet", "azurebastionsubnet", "azurefirewallsubnet",
    "azurefirewallmanagementsubnet", "routeserversubnet",
}


def port_spec_covers(spec: Optional[str], port: int) -> bool:
    """True if an NSG port spec ('*', '3389', '3000-4000') includes `port`."""
    if spec is None:
        return False
    spec = str(spec).strip()
    if spec in ("*", ""):
        return spec == "*"
    if "-" in spec:
        low, _, high = spec.partition("-")
        try:
            return int(low) <= port <= int(high)
        except ValueError:
            return False
    try:
        return int(spec) == port
    except ValueError:
        return False


def exposed_management_ports(rule_props: Dict[str, Any], ports: Iterable[int]) -> List[int]:
    """Management ports an inbound Allow rule opens to the Internet (empty if none)."""
    if (rule_props.get("direction") or "").lower() != "inbound":
        return []
    if (rule_props.get("access") or "").lower() != "allow":
        return []
    sources = [rule_props.get("sourceAddressPrefix")] + list(rule_props.get("sourceAddressPrefixes") or [])
    if not any((s or "").lower() in INTERNET_SOURCES for s in sources):
        return []
    specs = [rule_props.get("destinationPortRange")] + list(rule_props.get("destinationPortRanges") or [])
    return sorted({p for p in ports for s in specs if port_spec_covers(s, p)})


# ---------------------------------------------------------------------------
# 1. Unassociated DDoS plan
# ---------------------------------------------------------------------------

@register_scanner
class UnassociatedDdosPlanScanner(PostureScanner):
    """
    DDoS Network Protection bills a flat ~USD 2,944/month per plan and only
    protects public IPs inside VNets that are linked to it. A plan with no
    linked VNets (and no directly linked public IPs) protects nothing.
    """

    scanner_name = "unassociated_ddos_plan_scanner"
    display_name = "Unassociated DDoS Protection Plan"
    description = "Detects DDoS Network Protection plans with no protected VNets or public IPs"
    category = ScannerCategory.NETWORK
    severity = SeverityLevel.CRITICAL

    FALLBACK_MONTHLY_USD = 2944.0

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.network/ddosprotectionplans'
        | extend vnet_count = array_length(properties.virtualNetworks),
                 pip_count = array_length(properties.publicIPAddresses)
        | where isnull(vnet_count) or vnet_count == 0
        | where isnull(pip_count) or pip_count == 0
        | project id, name, type, resourceGroup, subscriptionId, location, tags
        """
        try:
            plans = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        costs = await get_resource_costs(context) if self.is_live(context) and plans else None
        findings = []
        for plan in plans:
            actual = cost_for(costs, plan["id"])
            if actual and actual.get("cost_usd"):
                monthly = round(actual["cost_usd"], 2)
                basis = "actual cost, last 30 days"
            else:
                hourly = await get_retail_price(
                    context,
                    "serviceName eq 'Azure DDOS Protection' and meterName eq 'Network Protection Plan' "
                    f"and armRegionName eq '{plan.get('location')}'",
                )
                monthly = round(hourly * HOURS_PER_MONTH, 2) if hourly else self.FALLBACK_MONTHLY_USD
                basis = "list price" if hourly else "static list price"

            findings.append(self.resource_finding(
                plan,
                finding_type="unused_ddos_protection_plan",
                title=f"DDoS plan protects nothing: {plan['name']}",
                description=(
                    f"DDoS Network Protection plan '{plan['name']}' has no associated virtual networks "
                    f"or public IPs, so it protects no resource while billing a flat monthly fee "
                    f"(~USD {monthly:,.0f}/month, {basis}). Note that a VNet DDoS plan cannot protect "
                    f"multi-tenant PaaS endpoints such as App Service — use Front Door/WAF for those."
                ),
                resource_type="microsoft.network/ddosprotectionplans",
                remediation_steps=(
                    "1. Confirm no policy or protection-class requirement mandates this plan.\n"
                    "2. If VNets with public IPs must be protected, associate them — or link the spokes "
                    "to the central (hub) DDoS plan instead of paying for a second plan.\n"
                    "3. For a handful of public IPs, DDoS IP Protection per IP is far cheaper.\n"
                    "4. Otherwise delete the plan."
                ),
                azure_cli_script=(
                    f"az network ddos-protection show -g {plan.get('resourceGroup')} -n {plan['name']} "
                    f"--query \"{{vnets:virtualNetworks, pips:publicIpAddresses}}\"\n"
                    f"az network ddos-protection delete -g {plan.get('resourceGroup')} -n {plan['name']}"
                ),
                powershell_script=(
                    f"Remove-AzDdosProtectionPlan -ResourceGroupName '{plan.get('resourceGroup')}' "
                    f"-Name '{plan['name']}'"
                ),
                evidence={
                    "associated_vnets": 0,
                    "associated_public_ips": 0,
                    "monthly_cost_basis": basis,
                    "actual_cost_30d": actual.get("cost") if actual else None,
                    "billing_currency": actual.get("currency") if actual else None,
                },
                estimated_monthly_savings_usd=monthly,
                caf_control="Cost Optimization",
            ))

        return ScanOutput(findings=findings, resources_scanned=len(plans))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/ddosProtectionPlans/ddos-unused-1",
            "name": "ddos-unused-1", "type": "microsoft.network/ddosprotectionplans",
            "resourceGroup": "rg-net", "subscriptionId": "sub-1", "location": "westeurope", "tags": {},
        }]


# ---------------------------------------------------------------------------
# 2. Orphaned NSG
# ---------------------------------------------------------------------------

@register_scanner
class OrphanedNSGScanner(PostureScanner):
    """NSGs with no subnet and no NIC association — clutter and latent exposure."""

    scanner_name = "orphaned_nsg_scanner"
    display_name = "Orphaned Network Security Groups"
    description = "Detects NSGs not associated with any subnet or network interface"
    category = ScannerCategory.NETWORK
    severity = SeverityLevel.LOW

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.network/networksecuritygroups'
        | where isnull(properties.subnets) or array_length(properties.subnets) == 0
        | where isnull(properties.networkInterfaces) or array_length(properties.networkInterfaces) == 0
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  rule_count = array_length(properties.securityRules)
        """
        try:
            nsgs = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = [
            self.resource_finding(
                nsg,
                finding_type="orphaned_nsg",
                title=f"Orphaned NSG: {nsg['name']}",
                description=(
                    f"Network security group '{nsg['name']}' is not associated with any subnet or NIC "
                    f"({nsg.get('rule_count') or 0} custom rules). Orphaned NSGs are often left over "
                    f"from deleted VMs and silently re-apply permissive rules if re-attached."
                ),
                resource_type="microsoft.network/networksecuritygroups",
                remediation_steps="Delete the NSG if it is no longer referenced by any deployment template.",
                azure_cli_script=f"az network nsg delete -g {nsg.get('resourceGroup')} -n {nsg['name']}",
                powershell_script=(
                    f"Remove-AzNetworkSecurityGroup -ResourceGroupName '{nsg.get('resourceGroup')}' "
                    f"-Name '{nsg['name']}' -Force"
                ),
                evidence={"custom_rule_count": nsg.get("rule_count") or 0},
                estimated_monthly_savings_usd=0.0,
            )
            for nsg in nsgs
        ]
        return ScanOutput(findings=findings, resources_scanned=len(nsgs))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-orphan-1",
            "name": "nsg-orphan-1", "type": "microsoft.network/networksecuritygroups",
            "resourceGroup": "rg-net", "subscriptionId": "sub-1", "location": "westeurope", "rule_count": 2,
        }]


# ---------------------------------------------------------------------------
# 3. Management ports open to the Internet
# ---------------------------------------------------------------------------

@register_scanner
class OpenManagementPortScanner(PostureScanner):
    """
    Inbound Allow rules exposing RDP/SSH/WinRM to '*' / Internet. CRITICAL
    when the NSG is effective (on a subnet or on a NIC attached to a VM);
    HIGH when latent (orphaned NSG or a NIC without VM) — re-attaching the
    NIC or NSG would expose a machine instantly.
    """

    scanner_name = "open_management_port_scanner"
    display_name = "Management Ports Open to Internet"
    description = "Detects NSG rules allowing RDP/SSH/WinRM from any source"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.HIGH

    async def scan(self, context: ScanContext) -> ScanOutput:
        nsg_query = """
        Resources
        | where type =~ 'microsoft.network/networksecuritygroups'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  rules = properties.securityRules,
                  subnet_count = array_length(properties.subnets),
                  nic_ids = properties.networkInterfaces
        """
        nic_query = """
        Resources
        | where type =~ 'microsoft.network/networkinterfaces'
        | where isnotnull(properties.virtualMachine)
        | project nic_id = tolower(id)
        """
        try:
            nsgs = await self.arg(context, nsg_query)
            nics_with_vm = await self._nics_with_vm(context, nic_query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        ports = [int(p) for p in self.setting("management_ports", list(MANAGEMENT_PORTS))]
        findings = []
        for nsg in nsgs:
            exposed = []
            for rule in nsg.get("rules") or []:
                open_ports = exposed_management_ports(rule.get("properties") or {}, ports)
                if open_ports:
                    exposed.append({
                        "rule": rule.get("name"),
                        "ports": open_ports,
                        "priority": (rule.get("properties") or {}).get("priority"),
                    })
            if not exposed:
                continue

            nic_ids = {(n.get("id") or "").lower() for n in (nsg.get("nic_ids") or [])}
            effective = bool(nsg.get("subnet_count")) or bool(nic_ids & nics_with_vm)
            severity = SeverityLevel.CRITICAL if effective else SeverityLevel.HIGH
            port_names = sorted({MANAGEMENT_PORTS.get(p, str(p)) for e in exposed for p in e["ports"]})
            state = "applied to a running workload path" if effective else "currently latent (no VM behind it)"

            findings.append(self.resource_finding(
                nsg,
                finding_type="nsg_management_port_open_to_internet",
                title=f"{'/'.join(port_names)} open to Internet: {nsg['name']}",
                description=(
                    f"NSG '{nsg['name']}' has {len(exposed)} inbound rule(s) allowing "
                    f"{', '.join(port_names)} from any source; the NSG is {state}."
                ),
                resource_type="microsoft.network/networksecuritygroups",
                severity=severity,
                remediation_steps=(
                    "1. Remove the rule(s) or restrict the source to specific corporate ranges.\n"
                    "2. Use Azure Bastion or Just-In-Time VM access instead of open management ports.\n"
                    "3. Enforce the built-in policy 'Management ports should be closed on your virtual machines'."
                ),
                azure_cli_script="\n".join(
                    f"az network nsg rule delete -g {nsg.get('resourceGroup')} --nsg-name {nsg['name']} -n '{e['rule']}'"
                    for e in exposed
                ),
                powershell_script="\n".join(
                    f"Get-AzNetworkSecurityGroup -ResourceGroupName '{nsg.get('resourceGroup')}' -Name '{nsg['name']}' | "
                    f"Remove-AzNetworkSecurityRuleConfig -Name '{e['rule']}' | Set-AzNetworkSecurityGroup"
                    for e in exposed
                ),
                evidence={"exposed_rules": exposed, "effective": effective},
                cis_control="6.1",
                nist_control="SC-7",
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(nsgs))

    async def _nics_with_vm(self, context: ScanContext, query: str) -> Set[str]:
        if context.resource_graph_client is None:
            return {"/subscriptions/sub-1/resourcegroups/rg-net/providers/microsoft.network/networkinterfaces/nic-vm-1"}
        rows = await self.arg(context, query)
        return {r.get("nic_id") for r in rows}

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-rdp-open",
            "name": "nsg-rdp-open", "type": "microsoft.network/networksecuritygroups",
            "resourceGroup": "rg-net", "subscriptionId": "sub-1", "location": "westeurope",
            "subnet_count": 0,
            "nic_ids": [{"id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/networkInterfaces/nic-orphan-1"}],
            "rules": [
                {"name": "RDP", "properties": {"direction": "Inbound", "access": "Allow", "priority": 300,
                                               "sourceAddressPrefix": "*", "destinationPortRange": "3389"}},
                {"name": "HTTPS", "properties": {"direction": "Inbound", "access": "Allow", "priority": 320,
                                                 "sourceAddressPrefix": "*", "destinationPortRange": "443"}},
            ],
        }]


# ---------------------------------------------------------------------------
# 4. Public IP held by an orphaned NIC
# ---------------------------------------------------------------------------

@register_scanner
class PublicIPOnOrphanedNICScanner(PostureScanner):
    """
    unused_public_ip_scanner only sees PIPs with no ipConfiguration at all.
    A PIP bound to a NIC whose VM was deleted looks "attached" but serves
    nothing — and a Standard static PIP keeps billing.
    """

    scanner_name = "public_ip_on_orphaned_nic_scanner"
    display_name = "Public IP on Orphaned NIC"
    description = "Detects public IPs attached to network interfaces that have no VM"
    category = ScannerCategory.NETWORK
    severity = SeverityLevel.MEDIUM

    MONTHLY_USD = {"standard": 3.65, "basic": 2.92}

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.network/networkinterfaces'
        | where isnull(properties.virtualMachine) and isnull(properties.privateEndpoint)
        | mv-expand ipc = properties.ipConfigurations
        | where isnotnull(ipc.properties.publicIPAddress.id)
        | project nic_name = name, pip_id = tolower(tostring(ipc.properties.publicIPAddress.id))
        | join kind=inner (
            Resources
            | where type =~ 'microsoft.network/publicipaddresses'
            | project pip_id = tolower(id), id, name, type, resourceGroup, subscriptionId, location, tags,
                      sku_name = tostring(sku.name), ip_address = tostring(properties.ipAddress)
          ) on pip_id
        | project id, name, type, resourceGroup, subscriptionId, location, tags, sku_name, ip_address, nic_name
        """
        try:
            pips = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for pip in pips:
            sku = (pip.get("sku_name") or "basic").lower()
            findings.append(self.resource_finding(
                pip,
                finding_type="public_ip_on_orphaned_nic",
                title=f"Public IP on orphaned NIC: {pip['name']}",
                description=(
                    f"Public IP '{pip['name']}' ({pip.get('ip_address') or 'n/a'}, {sku} SKU) is bound to NIC "
                    f"'{pip.get('nic_name')}', which is not attached to any VM."
                ),
                resource_type="microsoft.network/publicipaddresses",
                remediation_steps=(
                    "Delete the orphaned NIC and then the public IP (dissociate first if the NIC must be kept)."
                ),
                azure_cli_script=(
                    f"az network nic delete -g {pip.get('resourceGroup')} -n {pip.get('nic_name')}\n"
                    f"az network public-ip delete -g {pip.get('resourceGroup')} -n {pip['name']}"
                ),
                powershell_script=(
                    f"Remove-AzNetworkInterface -ResourceGroupName '{pip.get('resourceGroup')}' -Name '{pip.get('nic_name')}' -Force\n"
                    f"Remove-AzPublicIpAddress -ResourceGroupName '{pip.get('resourceGroup')}' -Name '{pip['name']}' -Force"
                ),
                evidence={"nic_name": pip.get("nic_name"), "sku": sku, "ip_address": pip.get("ip_address")},
                estimated_monthly_savings_usd=self.MONTHLY_USD.get(sku, 3.65),
                caf_control="Cost Optimization",
            ))
        return ScanOutput(findings=findings, resources_scanned=len(pips))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/publicIPAddresses/pip-on-orphan",
            "name": "pip-on-orphan", "type": "microsoft.network/publicipaddresses",
            "resourceGroup": "rg-net", "subscriptionId": "sub-1", "location": "westeurope",
            "sku_name": "Standard", "ip_address": "20.1.2.3", "nic_name": "nic-orphan-1",
        }]


# ---------------------------------------------------------------------------
# 5. VM keeps a public IP although Bastion is deployed
# ---------------------------------------------------------------------------

@register_scanner
class VMPublicIPWithBastionScanner(PostureScanner):
    """A VM public IP in a VNet that already has Bastion is a redundant, direct attack path."""

    scanner_name = "vm_public_ip_with_bastion_scanner"
    display_name = "VM Public IP Bypasses Bastion"
    description = "Detects VMs with public IPs in VNets where Azure Bastion is available"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.HIGH

    async def scan(self, context: ScanContext) -> ScanOutput:
        bastion_query = """
        Resources
        | where type =~ 'microsoft.network/bastionhosts'
        | extend subnet_id = tostring(properties.ipConfigurations[0].properties.subnet.id),
                 dev_vnet = tostring(properties.virtualNetwork.id)
        | extend vnet_id = tolower(iff(isnotempty(dev_vnet), dev_vnet, substring(subnet_id, 0, indexof(subnet_id, '/subnets/'))))
        | project bastion = name, sku = tostring(sku.name), vnet_id
        """
        nic_query = """
        Resources
        | where type =~ 'microsoft.network/networkinterfaces'
        | where isnotnull(properties.virtualMachine)
        | mv-expand ipc = properties.ipConfigurations
        | where isnotnull(ipc.properties.publicIPAddress.id)
        | extend subnet_id = tostring(ipc.properties.subnet.id)
        | project nic_name = name,
                  vm_id = tostring(properties.virtualMachine.id),
                  pip_id = tostring(ipc.properties.publicIPAddress.id),
                  vnet_id = tolower(substring(subnet_id, 0, indexof(subnet_id, '/subnets/'))),
                  resourceGroup, subscriptionId, location
        """
        try:
            bastions = await self._rows(context, bastion_query, "bastions")
            nics = await self._rows(context, nic_query, "nics")
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        bastion_by_vnet = {b["vnet_id"]: b for b in bastions if b.get("vnet_id")}
        findings = []
        for nic in nics:
            bastion = bastion_by_vnet.get(nic.get("vnet_id"))
            if not bastion:
                continue
            vm_name = (nic.get("vm_id") or "").split("/")[-1]
            pip_name = (nic.get("pip_id") or "").split("/")[-1]
            findings.append(self.make_finding(
                finding_type="vm_public_ip_bypasses_bastion",
                title=f"VM public IP next to Bastion: {vm_name}",
                description=(
                    f"VM '{vm_name}' keeps public IP '{pip_name}' although Bastion '{bastion['bastion']}' "
                    f"({bastion.get('sku')}) serves the same VNet. The public IP is a second, direct entry path."
                ),
                resource_id=nic.get("vm_id"),
                resource_name=vm_name,
                resource_type="microsoft.compute/virtualmachines",
                resource_group=nic.get("resourceGroup"),
                subscription_id=nic.get("subscriptionId"),
                location=nic.get("location") or "",
                remediation_steps="Dissociate and delete the public IP; connect through Bastion (or JIT) only.",
                azure_cli_script=(
                    f"az network nic ip-config update -g {nic.get('resourceGroup')} --nic-name {nic.get('nic_name')} "
                    f"-n ipconfig1 --remove publicIpAddress\n"
                    f"az network public-ip delete -g {nic.get('resourceGroup')} -n {pip_name}"
                ),
                evidence={"public_ip": pip_name, "nic": nic.get("nic_name"),
                          "bastion": bastion["bastion"], "bastion_sku": bastion.get("sku")},
                nist_control="AC-17",
                estimated_monthly_savings_usd=3.65,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(nics))

    async def _rows(self, context: ScanContext, query: str, kind: str) -> List[Dict[str, Any]]:
        if context.resource_graph_client is None:
            return self._mock_sets()[kind]
        return await self.arg(context, query)

    def _mock_sets(self) -> Dict[str, List[Dict[str, Any]]]:
        vnet = "/subscriptions/sub-1/resourcegroups/rg-net/providers/microsoft.network/virtualnetworks/vnet-1"
        return {
            "bastions": [{"bastion": "bas-1", "sku": "Developer", "vnet_id": vnet}],
            "nics": [{
                "nic_name": "nic-vm-1",
                "vm_id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Compute/virtualMachines/vm-jump-1",
                "pip_id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/publicIPAddresses/pip-vm-1",
                "vnet_id": vnet, "resourceGroup": "rg-net", "subscriptionId": "sub-1", "location": "westeurope",
            }],
        }


# ---------------------------------------------------------------------------
# 6. privatelink.* DNS zone with no endpoints
# ---------------------------------------------------------------------------

@register_scanner
class PrivateDnsZoneWithoutEndpointsScanner(PostureScanner):
    """A privatelink.* zone holding only its SOA record means no private endpoint uses it."""

    scanner_name = "private_dns_zone_without_endpoints_scanner"
    display_name = "Unused Private Link DNS Zone"
    description = "Detects privatelink.* private DNS zones that contain no endpoint records"
    category = ScannerCategory.NETWORK
    severity = SeverityLevel.LOW

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.network/privatednszones'
        | where name startswith 'privatelink.'
        | extend record_sets = toint(properties.numberOfRecordSets)
        | where isnull(record_sets) or record_sets <= 1
        | project id, name, type, resourceGroup, subscriptionId, location, tags, record_sets,
                  vnet_links = toint(properties.numberOfVirtualNetworkLinks)
        """
        try:
            zones = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = [
            self.resource_finding(
                z,
                finding_type="private_dns_zone_without_endpoints",
                title=f"Unused Private Link zone: {z['name']}",
                description=(
                    f"Private DNS zone '{z['name']}' holds {z.get('record_sets') or 0} record set(s) "
                    f"(SOA only) and {z.get('vnet_links') or 0} VNet link(s): no private endpoint registers here. "
                    f"If private endpoints are introduced later, prefer the central hub zones."
                ),
                resource_type="microsoft.network/privatednszones",
                remediation_steps="Remove the VNet links and delete the zone, or start using it for private endpoints.",
                azure_cli_script=(
                    f"az network private-dns link vnet list -g {z.get('resourceGroup')} -z {z['name']} -o table\n"
                    f"az network private-dns zone delete -g {z.get('resourceGroup')} -n {z['name']} --yes"
                ),
                evidence={"record_sets": z.get("record_sets"), "vnet_links": z.get("vnet_links")},
                estimated_monthly_savings_usd=0.5,
            )
            for z in zones
        ]
        return ScanOutput(findings=findings, resources_scanned=len(zones))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/privateDnsZones/privatelink.azurewebsites.net",
            "name": "privatelink.azurewebsites.net", "type": "microsoft.network/privatednszones",
            "resourceGroup": "rg-net", "subscriptionId": "sub-1", "location": "global",
            "record_sets": 1, "vnet_links": 1,
        }]


# ---------------------------------------------------------------------------
# 7. Subnet without NSG
# ---------------------------------------------------------------------------

@register_scanner
class SubnetWithoutNSGScanner(PostureScanner):
    """Workload subnets without an NSG rely on per-NIC NSGs only (or on nothing)."""

    scanner_name = "subnet_without_nsg_scanner"
    display_name = "Subnets Without NSG"
    description = "Detects workload subnets that have no network security group"
    category = ScannerCategory.NETWORK
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.network/virtualnetworks'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  subnets = properties.subnets,
                  peering_count = array_length(properties.virtualNetworkPeerings)
        """
        try:
            vnets = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for vnet in vnets:
            bare = [
                s.get("name") for s in (vnet.get("subnets") or [])
                if (s.get("name") or "").lower() not in PLATFORM_SUBNETS
                and not (s.get("properties") or {}).get("networkSecurityGroup")
            ]
            if not bare:
                continue
            findings.append(self.resource_finding(
                vnet,
                finding_type="subnet_without_nsg",
                title=f"Subnet(s) without NSG in {vnet['name']}",
                description=(
                    f"VNet '{vnet['name']}' has {len(bare)} workload subnet(s) with no NSG: {', '.join(bare)}. "
                    f"VNet peerings: {vnet.get('peering_count') or 0}."
                ),
                resource_type="microsoft.network/virtualnetworks",
                remediation_steps=(
                    "Associate an NSG with each workload subnet (deny-by-default inbound), and assign the "
                    "built-in policy 'Subnets should be associated with a Network Security Group'."
                ),
                azure_cli_script="\n".join(
                    f"az network vnet subnet update -g {vnet.get('resourceGroup')} --vnet-name {vnet['name']} "
                    f"-n {s} --network-security-group <nsg-name>"
                    for s in bare
                ),
                evidence={"subnets_without_nsg": bare, "peering_count": vnet.get("peering_count") or 0},
                nist_control="SC-7",
                estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(vnets))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-1",
            "name": "vnet-1", "type": "microsoft.network/virtualnetworks",
            "resourceGroup": "rg-net", "subscriptionId": "sub-1", "location": "westeurope",
            "peering_count": 0,
            "subnets": [{"name": "default", "properties": {}}, {"name": "AzureBastionSubnet", "properties": {}}],
        }]
