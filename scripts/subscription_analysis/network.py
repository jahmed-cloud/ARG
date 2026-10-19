"""
Network topology for the architecture diagrams: what sits in which subnet, how traffic gets in and out, and how
exposed every PaaS service and app is. Read-only Resource Graph queries, run with the estate refresh
(estate.collect_architecture) and stored in estate.json under architecture.network.

- subnets (from the VNet query): address prefix, NSG, route table, NAT gateway, delegation, service endpoints;
- private endpoints: subnet and target resource / sub-resource;
- NICs: which VM sits in which subnet and whether it has a public IP;
- edge and platform: VPN / ExpressRoute gateways, Azure Firewall, Bastion, Application Gateway, NAT gateway,
  load balancers, AKS, Container Apps environments, API Management, flexible database servers, Front Door / CDN -
  with the subnets they use;
- route tables: the default route (0.0.0.0/0) and its next hop, i.e. whether traffic leaves through a firewall;
- PaaS and apps: public network access, firewall default action and rules, private endpoints, the VNet-integration
  subnet of App Service / Functions / Logic Apps Standard, Logic Apps Consumption access control.

exposure() classifies a PaaS item; the classification is shared by the diagrams and the overview telemetry.
"""

import re
from typing import Any, Dict, Iterable, List, Optional

PE_QUERY = """
resources
| where type =~ 'microsoft.network/privateendpoints'
| extend links = array_concat(coalesce(properties.privateLinkServiceConnections, dynamic([])),
                              coalesce(properties.manualPrivateLinkServiceConnections, dynamic([])))
| mv-expand c = links
| project id = tolower(id), name, subscriptionId = tolower(subscriptionId), resourceGroup, location,
          subnet = tolower(tostring(properties.subnet.id)), target = tolower(tostring(c.properties.privateLinkServiceId)),
          group_id = tostring(c.properties.groupIds[0]), state = tostring(c.properties.privateLinkServiceConnectionState.status)
"""

NIC_QUERY = """
resources
| where type =~ 'microsoft.network/networkinterfaces'
| extend vm = tolower(tostring(properties.virtualMachine.id))
| where isnotempty(vm)
| mv-expand ipc = properties.ipConfigurations
| project vm, subscriptionId = tolower(subscriptionId), subnet = tolower(tostring(ipc.properties.subnet.id)),
          public_ip = isnotempty(tostring(ipc.properties.publicIPAddress.id))
"""

EDGE_TYPES = (
    "microsoft.network/virtualnetworkgateways", "microsoft.network/azurefirewalls", "microsoft.network/bastionhosts",
    "microsoft.network/applicationgateways", "microsoft.network/natgateways", "microsoft.network/loadbalancers",
    "microsoft.containerservice/managedclusters", "microsoft.app/managedenvironments",
    "microsoft.apimanagement/service", "microsoft.dbforpostgresql/flexibleservers",
    "microsoft.dbformysql/flexibleservers", "microsoft.network/frontdoors", "microsoft.cdn/profiles",
    "microsoft.network/expressroutecircuits", "microsoft.compute/virtualmachinescalesets",
    "microsoft.network/dnsresolvers", "microsoft.network/networkvirtualappliances",
)
EDGE_QUERY = """
resources
| where type in~ ({types})
| extend t = tolower(type), p = properties
| project id = tolower(id), name, t, subscriptionId = tolower(subscriptionId), resourceGroup, location,
          sku = tostring(coalesce(sku.name, p.sku.name, p.sku.tier)),
          refs = pack_array(p.ipConfigurations, p.gatewayIPConfigurations, p.frontendIPConfigurations,
                            p.agentPoolProfiles, p.vnetConfiguration, p.virtualNetworkConfiguration, p.network,
                            p.subnets, p.virtualMachineProfile.networkProfile, p.publicIpAddresses),
          gateway_type = tostring(p.gatewayType), private_cluster = tobool(p.apiServerAccessProfile.enablePrivateCluster),
          internal = tobool(p.vnetConfiguration.internal), vnet_type = tostring(p.virtualNetworkType),
          firewall_policy = tostring(p.firewallPolicy.id), waf = tobool(p.webApplicationFirewallConfiguration.enabled),
          public_access = tostring(p.network.publicNetworkAccess)
""".format(types=", ".join(f"'{t}'" for t in EDGE_TYPES))

ROUTE_QUERY = """
resources
| where type =~ 'microsoft.network/routetables'
| project id = tolower(id), subscriptionId = tolower(subscriptionId), subnets = properties.subnets,
          routes = properties.routes, propagation = tobool(properties.disableBgpRoutePropagation)
"""

PAAS_TYPES = (
    "microsoft.storage/storageaccounts", "microsoft.keyvault/vaults", "microsoft.sql/servers",
    "microsoft.documentdb/databaseaccounts", "microsoft.cognitiveservices/accounts",
    "microsoft.containerregistry/registries", "microsoft.servicebus/namespaces", "microsoft.eventhub/namespaces",
    "microsoft.cache/redis", "microsoft.search/searchservices", "microsoft.appconfiguration/configurationstores",
    "microsoft.signalrservice/signalr", "microsoft.web/sites", "microsoft.logic/workflows",
    "microsoft.machinelearningservices/workspaces", "microsoft.kusto/clusters", "microsoft.datafactory/factories",
    "microsoft.synapse/workspaces", "microsoft.eventgrid/topics", "microsoft.devices/iothubs",
    "microsoft.web/staticsites",
)
PAAS_QUERY = """
resources
| where type in~ ({types})
| extend t = tolower(type), p = properties
| project id = tolower(id), name, t, app_kind = tolower(kind), subscriptionId = tolower(subscriptionId), resourceGroup,
          location,
          public = tostring(coalesce(p.publicNetworkAccess, p.siteConfig.publicNetworkAccess)),
          acl = tostring(coalesce(p.networkAcls.defaultAction, p.networkRuleSet.defaultAction,
                                  p.networkACLs.defaultAction, p.networkRuleSets.defaultAction)),
          ip_rules = coalesce(array_length(p.networkAcls.ipRules), array_length(p.ipRules),
                              array_length(p.networkRuleSet.ipRules), array_length(p.ipFilterRules),
                              array_length(p.inboundIpRules), array_length(p.allowedIpRangeList), 0),
          vnet_rules = coalesce(array_length(p.networkAcls.virtualNetworkRules), array_length(p.virtualNetworkRules),
                                array_length(p.networkRuleSet.virtualNetworkRules), 0),
          vnet_filter = tobool(p.isVirtualNetworkFilterEnabled),
          pe = coalesce(array_length(p.privateEndpointConnections), 0),
          integration = tolower(tostring(p.virtualNetworkSubnetId)),
          access_control = isnotnull(p.accessControl), state = tostring(p.state)
""".format(types=", ".join(f"'{t}'" for t in PAAS_TYPES))

DNS_LINK_QUERY = """
resources
| where type =~ 'microsoft.network/privatednszones/virtualnetworklinks'
| project zone = tolower(tostring(split(id, '/')[8])), vnet = tolower(tostring(properties.virtualNetwork.id)),
          registration = tobool(properties.registrationEnabled), subscriptionId = tolower(subscriptionId)
"""

PUBLIC_IP_QUERY = """
resources
| where type =~ 'microsoft.network/publicipaddresses'
| project id = tolower(id), name, subscriptionId = tolower(subscriptionId), resourceGroup,
          owner = tolower(tostring(properties.ipConfiguration.id)), ip = tostring(properties.ipAddress),
          sku = tostring(sku.name)
"""

SUBNET_ID = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.network/virtualnetworks/"
                       r"[^/]+/subnets/[^/\"']+", re.IGNORECASE)
APP_TYPES = ("microsoft.web/sites", "microsoft.logic/workflows", "microsoft.web/staticsites")


def subnet_ids(value: Any) -> List[str]:
    """Every subnet resource ID anywhere inside a nested Resource Graph value."""
    found: List[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            found.extend(m.group(0).lower() for m in SUBNET_ID.finditer(v))
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
    walk(value)
    return sorted(set(found))


def subnet_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = (raw or {}).get("properties") or {}
    prefixes = props.get("addressPrefixes") or ([props["addressPrefix"]] if props.get("addressPrefix") else [])
    return {
        "id": (raw.get("id") or "").lower(), "name": raw.get("name"), "prefix": ", ".join(prefixes),
        "nsg": ((props.get("networkSecurityGroup") or {}).get("id") or "").lower() or None,
        "route_table": ((props.get("routeTable") or {}).get("id") or "").lower() or None,
        "nat": ((props.get("natGateway") or {}).get("id") or "").lower() or None,
        "delegations": sorted({(d.get("properties") or {}).get("serviceName") for d in props.get("delegations") or []
                               if (d.get("properties") or {}).get("serviceName")}),
        "service_endpoints": sorted({s.get("service") for s in props.get("serviceEndpoints") or [] if s.get("service")}),
        "ip_configurations": len(props.get("ipConfigurations") or []),
    }


def default_route(routes: Iterable[Dict[str, Any]]) -> Optional[str]:
    """'VirtualAppliance 10.0.1.4' / 'Internet' / ... for a 0.0.0.0/0 route, else None."""
    for r in routes or []:
        props = (r or {}).get("properties") or {}
        if props.get("addressPrefix") == "0.0.0.0/0":
            return " ".join(x for x in (props.get("nextHopType"), props.get("nextHopIpAddress")) if x)
    return None


def build_network(pe_rows, nic_rows, edge_rows, route_rows, paas_rows, pip_rows, dns_link_rows=()) -> Dict[str, Any]:
    """Normalised network inventory from the raw query rows."""
    endpoints: Dict[str, Dict[str, Any]] = {}
    for r in pe_rows:
        e = endpoints.setdefault(r["id"], {"id": r["id"], "name": r.get("name"), "subscriptionId": r.get("subscriptionId"),
                                           "resourceGroup": r.get("resourceGroup"), "location": r.get("location"),
                                           "subnet": r.get("subnet"), "targets": []})
        if r.get("target"):
            e["targets"].append({"id": r["target"], "group": r.get("group_id"), "state": r.get("state")})
    vms: Dict[str, Dict[str, Any]] = {}
    for r in nic_rows:
        v = vms.setdefault(r["vm"], {"id": r["vm"], "subscriptionId": r.get("subscriptionId"), "subnets": [],
                                     "public_ip": False})
        if r.get("subnet") and r["subnet"] not in v["subnets"]:
            v["subnets"].append(r["subnet"])
        v["public_ip"] = v["public_ip"] or bool(r.get("public_ip"))
    edge = []
    for r in edge_rows:
        edge.append({"id": r["id"], "name": r.get("name"), "type": r.get("t"), "subscriptionId": r.get("subscriptionId"),
                     "resourceGroup": r.get("resourceGroup"), "location": r.get("location"), "sku": r.get("sku") or "",
                     "subnets": subnet_ids(r.get("refs")),
                     "public_ips": sorted({x.lower() for x in re.findall(
                         r"/subscriptions/[^\"']+?/providers/microsoft\.network/publicipaddresses/[^/\"']+",
                         str(r.get("refs")), re.IGNORECASE)}),
                     "gateway_type": r.get("gateway_type") or None, "private_cluster": r.get("private_cluster"),
                     "internal": r.get("internal"), "vnet_type": r.get("vnet_type") or None,
                     "firewall_policy": bool(r.get("firewall_policy")), "waf": r.get("waf"),
                     "public_access": r.get("public_access") or None})
    routes = []
    for r in route_rows:
        routes.append({"id": r["id"], "subscriptionId": r.get("subscriptionId"),
                       "subnets": [((s or {}).get("id") or "").lower() for s in r.get("subnets") or []],
                       "default_route": default_route(r.get("routes") or []),
                       "routes": len(r.get("routes") or []), "bgp_propagation_disabled": bool(r.get("propagation"))})
    paas = []
    for r in paas_rows:
        paas.append({"id": r["id"], "name": r.get("name"), "type": r.get("t"), "kind": r.get("app_kind") or "",
                     "subscriptionId": r.get("subscriptionId"), "resourceGroup": r.get("resourceGroup"),
                     "location": r.get("location"), "public": r.get("public") or "", "acl": r.get("acl") or "",
                     "ip_rules": r.get("ip_rules") or 0, "vnet_rules": r.get("vnet_rules") or 0,
                     "vnet_filter": r.get("vnet_filter"), "pe": r.get("pe") or 0,
                     "integration": r.get("integration") or None, "access_control": bool(r.get("access_control")),
                     "state": r.get("state") or ""})
    public_ips = [{"id": r["id"], "name": r.get("name"), "subscriptionId": r.get("subscriptionId"),
                   "owner": r.get("owner") or None, "ip": r.get("ip") or "", "sku": r.get("sku") or ""}
                  for r in pip_rows]
    dns_links = [{"zone": r.get("zone") or "", "vnet": r.get("vnet") or "", "registration": bool(r.get("registration")),
                  "subscriptionId": r.get("subscriptionId")} for r in dns_link_rows if r.get("vnet")]
    return {"private_endpoints": list(endpoints.values()), "vms": list(vms.values()), "edge": edge,
            "route_tables": routes, "paas": paas, "public_ips": public_ips, "dns_links": dns_links}


async def collect_network(client: Any, subscription_ids: List[str], arg_rows) -> Dict[str, Any]:
    """Run the queries (arg_rows(client, query, subscriptions) pages Resource Graph) and normalise them."""
    rows = []
    for query in (PE_QUERY, NIC_QUERY, EDGE_QUERY, ROUTE_QUERY, PAAS_QUERY, PUBLIC_IP_QUERY, DNS_LINK_QUERY):
        try:
            rows.append(await arg_rows(client, query, subscription_ids))
        except Exception:
            rows.append([])
    return build_network(*rows)


def merge_network(parts: Iterable[Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    out: Dict[str, List[Any]] = {"private_endpoints": [], "vms": [], "edge": [], "route_tables": [], "paas": [],
                                 "public_ips": [], "dns_links": []}
    for part in parts:
        for key in out:
            out[key].extend((part or {}).get(key) or [])
    return out


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

OPEN, RESTRICTED, PRIVATE, CLOSED, APP_PUBLIC, UNVERIFIED = ("open", "restricted", "private", "closed",
                                                               "app-public", "unverified")
EXPOSURE_LABELS = {
    OPEN: "Open to all networks", UNVERIFIED: "Public endpoint, rules not in Resource Graph",
    RESTRICTED: "Restricted (firewall / VNet rules)", PRIVATE: "Private endpoint", CLOSED: "Public access off",
    APP_PUBLIC: "Public app endpoint",
}
# firewall rules of these live in child resources Resource Graph does not return
RULES_NOT_VISIBLE = ("microsoft.servicebus/namespaces", "microsoft.eventhub/namespaces", "microsoft.cache/redis")


def exposure(item: Dict[str, Any]) -> str:
    """How reachable a PaaS service or app is from the internet."""
    public = (item.get("public") or "").lower()
    if public == "disabled":
        return PRIVATE if item.get("pe") else CLOSED
    if item.get("type") in APP_TYPES:
        if item.get("pe") and public != "enabled":
            return PRIVATE   # an app with a private endpoint and no explicit public access is private-only
        return RESTRICTED if item.get("access_control") else APP_PUBLIC
    if (item.get("acl") or "").lower() == "deny" or item.get("ip_rules") or \
            (item.get("vnet_rules") and item.get("vnet_filter") in (None, True)):  # older snapshots hold 1 / 0
        return RESTRICTED
    if item.get("type") == "microsoft.sql/servers":
        return RESTRICTED   # public SQL is still limited by its server firewall (rules not in Resource Graph)
    if item.get("type") in RULES_NOT_VISIBLE:
        return UNVERIFIED
    return OPEN
