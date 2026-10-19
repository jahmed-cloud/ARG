"""
Fit-for-purpose network access for PaaS endpoints that are open to all networks.

"Add a private endpoint" is not the answer for every open endpoint: a storage account that only keeps data nobody
reads needs public access switched off (free), an account written by Azure Monitor needs "trusted Microsoft services"
(free), an app in the same region reaches a database through a service endpoint (free). A private endpoint (about
USD 7.30 per month per sub-resource, plus private DNS and USD 0.01 per GB) is the right control when the data is
confidential, when on-premises or cross-region clients must reach it privately, or when private endpoints are
already the pattern for that service in the subscription.

decide() picks the cheapest control that fits how the resource is actually used and lists the alternatives it
considered, with their cost and why they do or do not fit. The scanners put the result in evidence["access_decision"]
and its cost in evidence["cost_of_change"], so the report, the cost columns and the Docker UI all show the chosen
control instead of a blanket private endpoint.
"""

from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple

from scanners.base.guidance import PRICE

PE_USD = PRICE["private_endpoint"]
DNS_ZONE_USD = 0.50
IDLE_OPERATIONS_30D = 10            # data reads / writes at or below this: the data is kept, not used

SERVICES = {
    # service: (display name, CLI to switch public access off, service-endpoint service, private DNS zone)
    "storage": ("storage account", "az storage account update -g {rg} -n {name} --public-network-access Disabled",
                "Microsoft.Storage", "privatelink.blob.core.windows.net"),
    "keyvault": ("Key Vault", "az keyvault update -g {rg} -n {name} --public-network-access Disabled",
                 "Microsoft.KeyVault", "privatelink.vaultcore.azure.net"),
    "sql": ("SQL server", "az sql server update -g {rg} -n {name} --enable-public-network false",
            "Microsoft.Sql", "privatelink.database.windows.net"),
    "cosmos": ("Cosmos DB account", "az cosmosdb update -g {rg} -n {name} --public-network-access Disabled",
               "Microsoft.AzureCosmosDB", "privatelink.documents.azure.com"),
    "ai": ("AI account", "az resource update --ids {id} --set properties.publicNetworkAccess=Disabled",
           "Microsoft.CognitiveServices", "privatelink.cognitiveservices.azure.com"),
}

PE_TARGET_TYPES = {
    "storage": "microsoft.storage/storageaccounts", "keyvault": "microsoft.keyvault/vaults",
    "sql": "microsoft.sql/servers", "cosmos": "microsoft.documentdb/databaseaccounts",
    "ai": "microsoft.cognitiveservices/accounts",
}

CONTEXT_QUERY = """
Resources
| where type in~ ('microsoft.network/virtualnetworkgateways', 'microsoft.network/expressroutecircuits',
                  'microsoft.network/privateendpoints', 'microsoft.web/sites', 'microsoft.network/virtualnetworks',
                  'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachinescalesets',
                  'microsoft.containerservice/managedclusters')
| project t = tolower(type), name, location = tolower(location),
          integration = tolower(tostring(properties.virtualNetworkSubnetId)),
          links = properties.privateLinkServiceConnections, manual = properties.manualPrivateLinkServiceConnections,
          peerings = properties.virtualNetworkPeerings
"""


DNS_ZONE_QUERY = """
resources
| where type =~ 'microsoft.network/privatednszones' and name startswith 'privatelink.'
| summarize by name = tolower(name)
"""


class Option(NamedTuple):
    key: str
    title: str
    monthly_usd: float
    hours: Tuple[float, float]


def _options(service: str, sub_resources: int) -> Dict[str, Option]:
    pe = round(PE_USD * max(1, sub_resources) + DNS_ZONE_USD, 2)
    return {
        "keep_public": Option("keep_public", "Keep it public by design and harden authentication", 0.0, (0.25, 1)),
        "disable_public": Option("disable_public", "Switch public network access off", 0.0, (0.1, 0.5)),
        "trusted_services": Option("trusted_services", "Deny by default, allow trusted Microsoft services only",
                                   0.0, (0.25, 0.5)),
        "service_endpoint": Option("service_endpoint", "Service endpoint + VNet rule for the calling subnets",
                                   0.0, (0.5, 2)),
        "ip_rules": Option("ip_rules", "Deny by default + IP rules for the known callers", 0.0, (0.5, 2)),
        "private_endpoint": Option("private_endpoint",
                                   f"Private endpoint{'s' if sub_resources > 1 else ''} + private DNS, then public "
                                   f"access off", pe, (1, 4)),
    }


# ---------------------------------------------------------------------------
# Subscription context (one Resource Graph query per scan, shared by the scanners)
# ---------------------------------------------------------------------------

async def network_context(context: Any, query) -> Dict[str, Any]:
    """Where callers can come from in this subscription. `query(context, kql)` runs a Resource Graph query."""
    cache = getattr(context, "cache", None)
    if cache is not None and "access_need:context" in cache:
        return cache["access_need:context"]
    live = getattr(context, "resource_graph_client", None) is not None
    rows = await query(context, CONTEXT_QUERY) if live else []
    out = summarise_context(rows or [])
    if live:   # central private DNS zones usually live in the hub subscription: look tenant-wide
        try:
            zones = await query(context, DNS_ZONE_QUERY, tenant_scope=True) or []
            out["private_dns_zones"] = sorted({(z.get("name") or "").lower() for z in zones if z.get("name")})
        except Exception:
            out["private_dns_zones"] = None   # unknown - the zone is then listed as a prerequisite to check
    if cache is not None:
        cache["access_need:context"] = out
    return out


def summarise_context(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    vnet_regions: set = set()
    integrated: Dict[str, List[str]] = {}
    compute_regions: set = set()
    onprem = False
    pe_targets: set = set()
    for r in rows:
        t, loc = r.get("t") or "", (r.get("location") or "").replace(" ", "")
        if t == "microsoft.network/virtualnetworks":
            vnet_regions.add(loc)
            for p in r.get("peerings") or []:
                if ((p or {}).get("properties") or {}).get("useRemoteGateways"):
                    onprem = True   # spoke reaching on-premises through the hub's gateway
        elif t in ("microsoft.network/virtualnetworkgateways", "microsoft.network/expressroutecircuits"):
            onprem = True
        elif t == "microsoft.web/sites" and r.get("integration"):
            integrated.setdefault(loc, []).append(r.get("name"))
        elif t in ("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets",
                   "microsoft.containerservice/managedclusters"):
            compute_regions.add(loc)
        elif t == "microsoft.network/privateendpoints":
            for c in list(r.get("links") or []) + list(r.get("manual") or []):
                target = (((c or {}).get("properties") or {}).get("privateLinkServiceId") or "").lower()
                parts = target.split("/providers/")
                if len(parts) > 1:
                    pe_targets.add("/".join(parts[-1].split("/")[:2]))
    return {"vnet_regions": sorted(vnet_regions), "integrated_apps": integrated,
            "compute_regions": sorted(compute_regions), "onprem": onprem, "pe_target_types": sorted(pe_targets)}


def sensitive(tags: Optional[Dict[str, Any]], rules: Iterable[str]) -> Optional[str]:
    """The first 'Tag=value' rule (case-insensitive) the resource matches, e.g. 'DataClassification=Confidential'."""
    lowered = {str(k).lower(): str(v).strip().lower() for k, v in (tags or {}).items()}
    for rule in rules or []:
        key, _, value = str(rule).partition("=")
        if key.strip().lower() in lowered and (not value or lowered[key.strip().lower()] == value.strip().lower()):
            return rule.strip()
    return None


# ---------------------------------------------------------------------------
# Decision: the target architecture first, every option ranked
# ---------------------------------------------------------------------------

# What is still reachable once a control is in place, and how strong it is (5 = no public path at all).
SECURITY = {"private_endpoint": 5, "disable_public": 5, "trusted_services": 4, "service_endpoint": 4, "ip_rules": 3,
            "keep_public": 1}
EXPOSURE_AFTER = {
    "private_endpoint": "no public path; reachable from the VNet, peered VNets and on-premises only",
    "disable_public": "no network path at all (trusted Azure services excepted where enabled)",
    "trusted_services": "public endpoint for Azure platform services only",
    "service_endpoint": "public endpoint, limited to the allowed subnets of the region (traffic on the backbone)",
    "ip_rules": "public endpoint, limited to the allowed IP addresses",
    "keep_public": "public endpoint, open to the internet (authentication is the only control)",
}
ROLE_ORDER = {"target": 0, "interim": 1, "alternative": 2, "not suitable": 3}


def decide(service: str, resource: Dict[str, Any], ctx: Dict[str, Any], *,
           data_operations_30d: Optional[float] = None, requests_label: str = "data operations",
           azure_services_only: Optional[str] = None, boot_diagnostics_vms: Optional[List[str]] = None,
           sensitive_rule: Optional[str] = None,
           sub_resources: int = 1, ip_rules: int = 0, vnet_rules: int = 0,
           production: Optional[bool] = None) -> Dict[str, Any]:
    """The target-architecture control for an endpoint open to all networks, an interim step when the target needs
    prerequisites, and every other option ranked with its role, remaining exposure, cost and resource-specific
    pros and cons. Cost informs the ranking of equally strong options; it never replaces the target."""
    display, disable_cli, se_service, dns_zone = SERVICES[service]
    options = _options(service, sub_resources)
    region = (resource.get("location") or "").lower().replace(" ", "")
    tags = {str(k).lower(): v for k, v in (resource.get("tags") or {}).items()}
    by_design = "arg-public" in tags
    idle = data_operations_30d is not None and data_operations_30d <= IDLE_OPERATIONS_30D
    apps = (ctx.get("integrated_apps") or {}).get(region) or []
    vnet_callers = bool(apps) or region in (ctx.get("compute_regions") or [])
    vnet_here = region in (ctx.get("vnet_regions") or [])
    pe_standard = PE_TARGET_TYPES[service] in (ctx.get("pe_target_types") or [])
    onprem = bool(ctx.get("onprem"))
    env = {True: "production", False: "non-production"}.get(production, "environment not known")
    usage = (f"{data_operations_30d:,.0f} {requests_label} in 30 days" if data_operations_30d is not None
             else "usage not measured")
    pe_cost = options["private_endpoint"].monthly_usd
    callers = (f"{len(apps)} VNet-integrated app(s) in {region} ({', '.join(apps[:3])}{' …' if len(apps) > 3 else ''})"
               if apps else f"VMs / AKS in VNets in {region}" if vnet_callers else "")

    # prerequisites of the private endpoint in this subscription
    prereq = []
    if not vnet_here:
        prereq.append(f"a subnet for the endpoint in {region or 'its region'} (a spoke VNet peered to the hub)")
    zones = ctx.get("private_dns_zones")
    dns_ready = pe_standard or (zones is not None and dns_zone in zones)
    if not dns_ready:
        prereq.append(f"the {dns_zone} private DNS zone (none found in the tenant)" if zones is not None else
                      f"the {dns_zone} private DNS zone linked to every VNet that resolves the name (normally the "
                      f"hub's central zone)")
    if not vnet_callers and not onprem:
        prereq.append("a private path for each caller (VNet integration for apps, the hub for on-premises clients)")

    interim: Optional[str] = None
    if by_design:
        target, why = "keep_public", (
            f"Tagged arg-public: the {display} serves external clients by design (website, CDN origin, partner "
            f"access). The target is a public endpoint with identity-based access and short-lived SAS - restricting "
            f"the network would break its purpose. Usage: {usage}.")
    elif boot_diagnostics_vms and not sensitive_rule:
        vms = ", ".join(boot_diagnostics_vms[:3]) + (" …" if len(boot_diagnostics_vms) > 3 else "")
        target, why = "disable_public", (
            f"It holds boot diagnostics of {len(boot_diagnostics_vms)} VM(s) ({vms}). The target is managed boot "
            f"diagnostics - Azure keeps the screenshots and serial log without any customer storage account - so this "
            f"account can then be closed (public access off) or deleted. A private endpoint or firewall does not fit: "
            f"custom boot-diagnostics storage behind a firewall is not supported.")
    elif idle and not sensitive_rule:
        target, why = "disable_public", (
            f"It only keeps data ({usage}, {env}). The target is no network path at all: public access off. That is "
            f"stronger than a private endpoint - which would add a private path nobody uses - and when someone needs "
            f"the data, a private endpoint (or a temporary IP rule) is added then.")
    elif azure_services_only and not sensitive_rule:
        target, why = "trusted_services", (
            f"Only Azure platform services write to it ({azure_services_only}). They connect through the trusted-"
            f"services exception, not through a private endpoint, so the target is default Deny with that exception.")
    else:
        target = "private_endpoint"
        reasons = [f"{env} data in active use ({usage})" if not idle else f"{env} data ({usage})"]
        if sensitive_rule:
            reasons.append(f"tagged {sensitive_rule} (confidential data)")
        if pe_standard:
            reasons.append(f"private endpoints are already the pattern for {display}s in this subscription")
        if onprem:
            reasons.append("on-premises clients reach Azure through the hub's VPN / ExpressRoute gateway")
        if callers:
            reasons.append(f"callers: {callers}")
        why = ("Target architecture (Well-Architected, landing-zone pattern): private endpoint with private DNS and "
               "public access off - " + "; ".join(reasons) + ".")
        if prereq:
            interim = "service_endpoint" if vnet_callers else "ip_rules"
            why += (" Before it works the subscription needs " + "; ".join(prereq) + ". Interim step, today: "
                    + options[interim].title.lower() + " - closes the internet exposure within the hour, free.")

    pros_cons = {
        "private_endpoint": (
            ["no public endpoint left", "reachable from peered VNets and on-premises",
             "the data-exfiltration path through the public endpoint is gone"],
            [f"about USD {pe_cost:,.2f}/month plus USD 0.01/GB", "needs private DNS for every caller",
             "callers without VNet integration (multi-tenant services) lose access"]),
        "disable_public": (
            ["no network path at all", "free, reversible in a minute"],
            ["every current caller loses access" if not idle else "someone who needs the data asks for access first"]),
        "trusted_services": (
            ["blocks everything except Azure platform services", "free"],
            ["does not cover your own apps", "trusted services of any tenant can reach it with valid authorisation"]),
        "service_endpoint": (
            ["free", "traffic stays on the Azure backbone", "no DNS change"],
            ["public endpoint remains", "same region only, no on-premises access",
             "exfiltration to other accounts needs service-endpoint policies"]),
        "ip_rules": (
            ["free", "works for callers outside Azure with fixed egress IPs"],
            ["public endpoint remains", "shared egress IPs (NAT, proxies) admit everyone behind them",
             "lists drift as callers change"]),
        "keep_public": (
            ["no change for external clients"],
            ["open to the internet", "authentication is the only control"]),
    }

    def role(key: str) -> str:
        if key == target:
            return "target"
        if key == interim:
            return "interim"
        unsuitable = {
            "keep_public": not by_design,
            "disable_public": not (idle or boot_diagnostics_vms),
            "trusted_services": not azure_services_only and target != "trusted_services",
            "service_endpoint": not vnet_callers,
        }
        return "not suitable" if unsuitable.get(key) else "alternative"

    ranked = []
    for o in options.values():
        r = role(o.key)
        pros, cons = pros_cons[o.key]
        ranked.append({"option": o.key, "title": o.title, "monthly_usd": o.monthly_usd, "role": r,
                       "fits": r in ("target", "interim", "alternative"), "chosen": r == "target",
                       "security": SECURITY[o.key], "exposure_after": EXPOSURE_AFTER[o.key],
                       "pros": pros, "cons": cons, "note": _option_note(o.key, r, idle, callers, prereq)})
    ranked.sort(key=lambda a: (ROLE_ORDER[a["role"]], -a["security"], a["monthly_usd"]))

    chosen = options[target]
    if target in ("keep_public", "disable_public") or (target == "trusted_services" and not sensitive_rule):
        level = "low" if target != "trusted_services" else "medium"
    elif sensitive_rule or production:
        level = "high"
    else:
        level = "medium" if production is None else "low"
    rg, name = resource.get("resourceGroup") or "<rg>", resource.get("name") or "<name>"
    return {
        "service": service, "option": target, "title": chosen.title, "monthly_usd": chosen.monthly_usd,
        "hours": list(chosen.hours), "why": why, "usage": usage, "idle": idle, "level": level,
        "interim": ({"option": interim, "title": options[interim].title, "monthly_usd": options[interim].monthly_usd,
                     "hours": list(options[interim].hours)} if interim else None),
        "prerequisites": prereq if target == "private_endpoint" else [],
        "alternatives": ranked, "disable_cli": disable_cli.format(rg=rg, name=name, id=resource.get("id")),
        "service_endpoint": se_service, "dns_zone": dns_zone,
        "signals": {"data_operations_30d": data_operations_30d, "vnet_callers": vnet_callers,
                    "integrated_apps": apps[:10], "onprem": onprem, "pe_standard": pe_standard,
                    "vnet_in_region": vnet_here, "dns_zone_exists": dns_ready, "sensitive": sensitive_rule,
                    "azure_services_only": azure_services_only,
                    "boot_diagnostics_vms": (boot_diagnostics_vms or [])[:10],
                    "ip_rules": ip_rules, "vnet_rules": vnet_rules, "production": production},
    }


def _option_note(key: str, role: str, idle: bool, callers: str, prereq: List[str]) -> str:
    if role == "target":
        return "Recommended target."
    if role == "interim":
        return "Do this now: it closes the internet exposure while the target's prerequisites are put in place."
    return {
        "keep_public": "Only for endpoints that serve external clients by design (tag arg-public).",
        "disable_public": ("Strongest, but every current caller loses access." if not idle else
                           "No traffic to keep."),
        "trusted_services": "Covers Azure platform services only, not your applications.",
        "service_endpoint": (f"Valid for {callers}; the public endpoint stays." if callers else
                             "No VNet-integrated apps or VMs in this region."),
        "ip_rules": "Weaker: public endpoint stays; use it only for callers outside Azure with fixed IPs.",
        "private_endpoint": ("Not needed: there is no traffic to protect." if idle else
                             "Weaker fit here than the target."),
    }[key]


def cost_of_change(decision: Dict[str, Any]) -> Dict[str, Any]:
    """evidence["cost_of_change"] for the target control (read by guidance.implementation_analysis)."""
    return {"monthly_usd": decision["monthly_usd"], "basis": decision["title"].lower()}


def _steps(option: str, decision: Dict[str, Any], display: str) -> List[str]:
    return {
        "keep_public": ["Confirm the external clients with the owner and keep the arg-public tag.",
                        "Use Entra ID / managed identities or short-lived SAS; disable shared keys or local auth."],
        "disable_public": (["Switch the VMs to managed boot diagnostics: az vm boot-diagnostics enable -g <rg> -n <vm> "
                            "(no --storage).",
                            "Check no other application uses the account (usage above).",
                            f"Switch public network access off on the {display} (or delete it when empty)."]
                           if decision["signals"].get("boot_diagnostics_vms") else
                           ["Confirm with the owner that no application reads or writes it (see the usage above).",
                            f"Switch public network access off on the {display}.",
                            "When someone needs the data: add a private endpoint (or a temporary IP rule) then."]),
        "trusted_services": ["Set the default action to Deny with the 'Allow trusted Microsoft services' exception.",
                             "Check the diagnostics / backup jobs still write (Activity log, the service's metrics)."],
        "service_endpoint": [f"Enable the {decision['service_endpoint']} service endpoint on the calling subnets "
                             f"(VNet-integration subnet of the apps, VM subnets).",
                             "Add those subnets as VNet rules, plus the egress IPs of any caller outside Azure.",
                             "Set the default action to Deny and watch failed requests for a day."],
        "ip_rules": ["Find the callers: the resource's logs / Insights (client IPs) over 7-30 days.",
                     "Add their egress IPs (and VNet rules for Azure callers), then set the default action to Deny.",
                     "Watch failed requests for a day."],
        "private_endpoint": ([f"Prerequisite: {p}." for p in decision.get("prerequisites") or []]
                             + [f"Create the private endpoint in the workload's subnet with a DNS zone group on the "
                                f"{decision['dns_zone']} zone.",
                                "Point the callers at it (same host name; DNS resolves to the private IP) and check "
                                "name resolution from each caller (nslookup returns a 10.x / 172.x address).",
                                f"Switch public network access off on the {display}; watch failed requests for a "
                                f"day."]),
    }[option]


def remediation(decision: Dict[str, Any], display: str) -> str:
    """Numbered steps: the interim step first (when there is one), then the target."""
    lines = []
    interim = decision.get("interim")
    if interim:
        lines.append(f"Now - interim ({interim['title'].lower()}, free):")
        lines += [f"  {i}. {s}" for i, s in enumerate(_steps(interim["option"], decision, display), 1)]
        lines.append(f"Target - {decision['title'].lower()}:")
        lines += [f"  {i}. {s}" for i, s in enumerate(_steps(decision["option"], decision, display), 1)]
        return "\n".join(lines)
    return "\n".join(f"{i}. {s}" for i, s in enumerate(_steps(decision["option"], decision, display), 1))


GROUP_IDS = {"storage": "blob", "keyvault": "vault", "sql": "sqlServer", "cosmos": "Sql", "ai": "account"}


def cli_for(decision: Dict[str, Any], resource: Dict[str, Any]) -> str:
    """Azure CLI for the target control, preceded by the interim step's when there is one."""
    interim = decision.get("interim")
    if interim:
        return (f"# Now - interim: {interim['title'].lower()}\n" + _cli(decision, resource, interim["option"])
                + f"\n\n# Target: {decision['title'].lower()}\n" + _cli(decision, resource, decision["option"]))
    return _cli(decision, resource, decision["option"])


def _cli(decision: Dict[str, Any], resource: Dict[str, Any], option: str) -> str:
    """Azure CLI for one control (placeholders in <angle brackets>)."""
    service = decision["service"]
    rg, name, rid = resource.get("resourceGroup") or "<rg>", resource.get("name") or "<name>", resource.get("id")
    deny = {
        "storage": f"az storage account update -g {rg} -n {name} --default-action Deny",
        "keyvault": f"az keyvault update -g {rg} -n {name} --default-action Deny",
        "sql": f"az sql server firewall-rule delete -g {rg} -s {name} -n AllowAllWindowsAzureIps",
        "cosmos": f"az cosmosdb update -g {rg} -n {name} --enable-virtual-network true",
        "ai": f"az resource update --ids {rid} --set properties.networkAcls.defaultAction=Deny",
    }[service]
    if option == "disable_public":
        return decision["disable_cli"]
    if option == "keep_public":
        return {"storage": f"az storage account update -g {rg} -n {name} --allow-shared-key-access false",
                "ai": f"az resource update --ids {rid} --set properties.disableLocalAuth=true",
                "cosmos": f"az resource update --ids {rid} --set properties.disableLocalAuth=true"}.get(
            service, "# No network change: keep it public and use Entra ID authentication.")
    if option == "trusted_services":
        return {"storage": f"az storage account update -g {rg} -n {name} --default-action Deny --bypass AzureServices",
                "keyvault": f"az keyvault update -g {rg} -n {name} --default-action Deny --bypass AzureServices",
                "cosmos": f"az cosmosdb update -g {rg} -n {name} --network-acl-bypass AzureServices",
                "ai": f"az resource update --ids {rid} --set properties.networkAcls.defaultAction=Deny "
                      f"properties.networkAcls.bypass=AzureServices"}.get(service, deny)
    if option == "service_endpoint":
        rule = {
            "storage": f"az storage account network-rule add -g {rg} --account-name {name} --vnet-name <vnet> "
                       f"--subnet <subnet>",
            "keyvault": f"az keyvault network-rule add -g {rg} -n {name} --vnet-name <vnet> --subnet <subnet>",
            "sql": f"az sql server vnet-rule create -g {rg} -s {name} -n allow-<subnet> --vnet-name <vnet> "
                   f"--subnet <subnet>",
            "cosmos": f"az cosmosdb network-rule add -g {rg} -n {name} --vnet-name <vnet> --subnet <subnet>",
            "ai": f"az cognitiveservices account network-rule add -g {rg} -n {name} --vnet <vnet> --subnet <subnet>",
        }[service]
        return (f"# 1. Service endpoint on each calling subnet (VNet integration subnet of the apps, VM subnets)\n"
                f"az network vnet subnet update -g <vnet-rg> --vnet-name <vnet> -n <subnet> "
                f"--service-endpoints {decision['service_endpoint']}\n"
                f"# 2. Allow those subnets\n{rule}\n# 3. Deny everything else\n{deny}")
    if option == "ip_rules":
        rule = {
            "storage": f"az storage account network-rule add -g {rg} --account-name {name} --ip-address <egress-ip>",
            "keyvault": f"az keyvault network-rule add -g {rg} -n {name} --ip-address <egress-ip>",
            "sql": f"az sql server firewall-rule create -g {rg} -s {name} -n caller-1 --start-ip-address <egress-ip> "
                   f"--end-ip-address <egress-ip>",
            "cosmos": f"az cosmosdb update -g {rg} -n {name} --ip-range-filter <egress-ip>",
            "ai": f"az cognitiveservices account network-rule add -g {rg} -n {name} --ip-address <egress-ip>",
        }[service]
        return f"# 1. Allow the callers' egress IPs\n{rule}\n# 2. Deny everything else\n{deny}"
    pe = f"pe-{name}"
    return (f"az network private-endpoint create -g {rg} -n {pe} --vnet-name <vnet> --subnet <subnet> "
            f"--private-connection-resource-id {rid} --group-id {GROUP_IDS[service]} --connection-name {pe}\n"
            f"az network private-endpoint dns-zone-group create -g {rg} --endpoint-name {pe} -n default "
            f"--private-dns-zone <{decision['dns_zone']} zone id> --zone-name {decision['dns_zone'].split('.')[1]}\n"
            f"# after the callers resolve the private IP:\n{decision['disable_cli']}")


# ---------------------------------------------------------------------------
# Scanner helper
# ---------------------------------------------------------------------------

LEVELS = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH"}


def _price(monthly_usd: float) -> str:
    return "free" if not monthly_usd else f"about USD {monthly_usd:,.2f}/month"


def production_of(resource: Dict[str, Any], context: Any) -> Optional[bool]:
    from scanners.base.naming import environment_of

    env = environment_of(resource, getattr(context, "subscription_name", "") or "")
    return {"Production": True, "Non-production": False}.get(env)


async def assess(scanner: Any, context: Any, service: str, resource: Dict[str, Any], **signals: Any) -> Dict[str, Any]:
    """decide() with the subscription context, the sensitive-data tag rules (setting) and the environment filled in.

    Returns the finding fields to merge: severity, remediation_steps, azure_cli_script and evidence entries."""
    from scanners.base.azure_api import query_resource_graph
    from scanners.base.base_scanner import SeverityLevel

    ctx = await network_context(context, query_resource_graph)
    rule = sensitive(resource.get("tags"), scanner.config.get("sensitive_data_tags") or [])
    decision = decide(service, resource, ctx, sensitive_rule=rule, production=production_of(resource, context),
                      **signals)
    display = SERVICES[service][0]
    return {
        "decision": decision,
        "severity": getattr(SeverityLevel, LEVELS[decision["level"]]),
        "remediation_steps": (f"Target: {decision['title']} ({_price(decision['monthly_usd'])}).\n"
                              + remediation(decision, display)),
        "azure_cli_script": cli_for(decision, resource),
        "evidence": {"access_decision": decision, "cost_of_change": cost_of_change(decision)},
    }
