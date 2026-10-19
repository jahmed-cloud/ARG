"""
Implementation analysis per finding: why the change is needed, when it is not, what it costs to implement (Azure
run-cost change per month and engineering effort), the net effect against the finding's saving, and Microsoft Learn
references.

implementation_analysis(finding) is the one entry point. It is used by the markdown report (deep dives, gap analysis,
savings register, executive summary), stored with every finding in findings.json, and returned by the Docker API's
finding detail - so the local report and the Docker UI give the same answer.

Sources, in order of precedence:
1. the scanner's own estimate in evidence["cost_of_change"] (AI gateway, Defender plans, ...);
2. for Defender for Cloud findings, the curated catalogue in scanners/security/defender_guidance.py per
   recommendation, else Microsoft's own description, remediation text and links stored with the finding;
3. GUIDANCE below, per finding type.
Prices are USD list prices (scanners/base/guidance.py, PRICES_AS_OF) - estimates for planning, not quotes.
"""

from typing import Any, Dict, Iterable, List, Optional

from scanners.base.guidance import PRICE, PRICES_AS_OF, Guidance, pricing
from scanners.security import defender_guidance

PE = PRICE["private_endpoint"]

_LEARN = "https://learn.microsoft.com/azure"


def _g(why: str, skip_when: str, effort: str, hours, monthly_usd: Optional[float], run_cost: str, *references,
       cost_factor: Optional[float] = None) -> Guidance:
    return Guidance(why, skip_when, effort, tuple(hours), monthly_usd, run_cost, tuple(references), cost_factor)


FREE = "No Azure cost."
CHOSEN = ("The control is chosen per resource from its usage and context (see the decision in the finding): public "
          "access off when nobody uses it, trusted Microsoft services, a service endpoint for callers in VNets, IP "
          "rules - a private endpoint only for confidential data, on-premises or cross-region clients, or where it "
          "is already the standard.")
RUN = (f"Free for public access off, trusted services, service endpoints and IP rules; a private endpoint is about "
       f"USD {PE:.2f}/month per sub-resource plus private DNS - only when the decision requires it.")
DELETE = "None - removing it ends the charge (the saving is shown separately)."

GUIDANCE: Dict[str, Guidance] = {
    # --- Network ---------------------------------------------------------------------------------------------
    "unused_ddos_protection_plan": _g(
        "A DDoS Network Protection plan bills a flat monthly fee (about USD 2,944 plus overage per protected IP) and "
        "protects only public IPs inside VNets linked to it. With no VNet linked it protects nothing.",
        "The plan is linked from VNets in other subscriptions (one plan can cover VNets across subscriptions of the "
        "tenant) - check its virtualNetworks list before deleting, or a requirement mandates it and VNets are about "
        "to be linked.",
        "Delete the plan, or link the VNets that need it. No downtime.", (0.5, 1), 0.0, DELETE,
        ("Azure DDoS Protection overview", f"{_LEARN}/ddos-protection/ddos-protection-overview"),
        ("DDoS Network vs IP Protection", f"{_LEARN}/ddos-protection/ddos-protection-sku-comparison"),
        ("Azure DDoS Protection pricing", "https://azure.microsoft.com/pricing/details/ddos-protection/")),
    "orphaned_nsg": _g(
        "An NSG attached to nothing costs nothing, but its rules are applied unchanged to any NIC or subnet it is "
        "attached to later - permissive leftovers re-expose whatever they are reused for.",
        "It is kept on purpose as a template - then it belongs in IaC, not as a live resource.",
        "Delete after checking no deployment references it.", (0.1, 0.25), 0.0, FREE,
        ("Network security groups", f"{_LEARN}/virtual-network/network-security-groups-overview")),
    "orphaned_nic": _g(
        "A detached NIC keeps a private IP of the subnet (and possibly a public IP and NSG): no charge of its own, but "
        "it consumes address space and misleads IP address management.",
        "It belongs to a VM that is being rebuilt and will be re-attached shortly.",
        "Delete the NIC (and its public IP if unused).", (0.1, 0.25), 0.0, FREE,
        ("Network interfaces", f"{_LEARN}/virtual-network/virtual-network-network-interface")),
    "unused_public_ip": _g(
        "Standard public IPs are billed per hour whether attached or not, and an unused allow-listed address is a "
        "liability if it is ever reassigned.",
        "The address is reserved because partners allow-list it - document the owner and keep it.",
        "Delete (or keep and document). No downtime.", (0.1, 0.25), 0.0, DELETE,
        ("Public IP addresses", f"{_LEARN}/virtual-network/ip-services/public-ip-addresses"),
        ("IP address pricing", "https://azure.microsoft.com/pricing/details/ip-addresses/")),
    "public_ip_on_orphaned_nic": _g(
        "The public IP is billed and reachable configuration remains, but the NIC it sits on has no VM.",
        "The VM is being rebuilt and will get the NIC back.",
        "Delete the NIC and the public IP together.", (0.1, 0.25), 0.0, DELETE,
        ("Public IP addresses", f"{_LEARN}/virtual-network/ip-services/public-ip-addresses")),
    "empty_load_balancer": _g(
        "A Standard load balancer is billed per configured rule per hour (and per GB processed) even when its "
        "backend pool is empty.",
        "Its frontend IP is reserved for an upcoming deployment.",
        "Delete after confirming no DNS record points at its frontend IP.", (0.25, 0.5), 0.0, DELETE,
        ("Azure Load Balancer overview", f"{_LEARN}/load-balancer/load-balancer-overview"),
        ("Load Balancer pricing", "https://azure.microsoft.com/pricing/details/load-balancer/")),
    "empty_application_gateway": _g(
        "An Application Gateway v2 bills a fixed hourly charge plus capacity units even without backends.",
        "It is the planned front end of a deployment in progress.",
        "Delete after confirming no DNS record or certificate binding still uses it.", (0.5, 1), 0.0, DELETE,
        ("Application Gateway overview", f"{_LEARN}/application-gateway/overview"),
        ("Application Gateway pricing", "https://azure.microsoft.com/pricing/details/application-gateway/")),
    "private_dns_zone_without_endpoints": _g(
        "A privatelink.* zone linked to a VNet answers authoritatively for that service. When it holds no records, "
        "names of resources that do have private endpoints elsewhere resolve to nothing (NXDOMAIN) from that VNet, "
        "which breaks future private-link work in confusing ways.",
        "The zone is the central zone that endpoints will be registered in shortly.",
        "Delete the zone or remove its VNet links; or enable fallback to internet resolution.", (0.25, 0.5), 0.0,
        "None - removes USD 0.50 per zone per month.",
        ("Private endpoint DNS configuration", f"{_LEARN}/private-link/private-endpoint-dns"),
        ("Private DNS fallback to internet", f"{_LEARN}/dns/private-dns-fallback")),
    "subnet_without_nsg": _g(
        "Without an NSG there is no layer-4 filtering inside the VNet: a compromised workload can reach every port of "
        "every other one (lateral movement).",
        "GatewaySubnet, AzureFirewallSubnet, AzureBastionSubnet and RouteServerSubnet are managed and must not get one.",
        "Create an NSG with deny-by-default plus the required rules; test the workloads in the subnet.", (1, 4), 0.0,
        "No Azure cost (flow logs, if enabled, are billed per GB).",
        ("Network security groups", f"{_LEARN}/virtual-network/network-security-groups-overview"),
        ("Microsoft cloud security benchmark - network security",
         "https://learn.microsoft.com/security/benchmark/azure/mcsb-network-security")),
    "nsg_management_port_open_to_internet": _g(
        "RDP / SSH open to the internet are brute-forced within hours of exposure and remain one of the most common "
        "initial-access paths.",
        "Never acceptable on the internet. If nobody needs remote access, simply delete the rule.",
        "Remove the inbound rule; connect through Azure Bastion or just-in-time access.", (0.5, 2), 0.0,
        f"No change when a Bastion already serves the VNet (Developer SKU is free; Basic about USD "
        f"{PRICE['bastion_basic']:,.0f}/month). JIT needs Defender for Servers Plan 2 (about USD "
        f"{PRICE['defender_servers_p2']:.2f} per server per month).",
        ("Azure Bastion overview", f"{_LEARN}/bastion/bastion-overview"),
        ("Enable just-in-time access", f"{_LEARN}/defender-for-cloud/enable-just-in-time-access"),
        pricing("bastion")),
    "vm_public_ip_bypasses_bastion": _g(
        "Bastion is already paid for, but the VM's public IP keeps a second, direct path open that bypasses it.",
        "The VM publishes a service to the internet on purpose - then expose only that port, never 22 / 3389.",
        "Dissociate and delete the public IP. If the VM needs outbound internet and sits in a subnet without default "
        "outbound access, add a NAT gateway.", (0.5, 1), 0.0,
        "Saves the public IP; a NAT gateway (hourly + per GB) is only needed where outbound access would break.",
        ("Azure Bastion overview", f"{_LEARN}/bastion/bastion-overview"),
        ("Default outbound access", f"{_LEARN}/virtual-network/ip-services/default-outbound-access"),
        ("NAT gateway", f"{_LEARN}/nat-gateway/nat-overview")),
    # --- Compute / App Service -------------------------------------------------------------------------------
    "vm_unsupported_os": _g(
        "An OS past end of support gets no security fixes: every new vulnerability stays open for good, and audits "
        "flag it.",
        "Isolated machines with Extended Security Updates (free on Azure for Windows Server 2012 / 2012 R2), on a "
        "dated decommission plan.",
        "In-place upgrade or rebuild on a supported image; test the application; maintenance window.", (4, 16), 0.0,
        "No change at the same VM size.",
        ("Windows Server in-place upgrade on Azure", f"{_LEARN}/virtual-machines/windows-in-place-upgrade"),
        ("Extended Security Updates",
         "https://learn.microsoft.com/windows-server/get-started/extended-security-updates-overview"),
        ("Microsoft product lifecycle", "https://learn.microsoft.com/lifecycle/")),
    "managed_disk_public_network_access": _g(
        "The disk can be exported (downloaded) or overwritten through a SAS URL from any network - a leaked SAS means "
        "the whole disk leaves the company.",
        "Disks that are exported on purpose, e.g. for image distribution - restrict them to a private disk access.",
        "Set networkAccessPolicy DenyAll and publicNetworkAccess Disabled; no downtime.", (0.1, 0.25), 0.0, FREE,
        ("Restrict managed disk import / export", f"{_LEARN}/virtual-machines/disks-restrict-import-export-overview")),
    "unattached_managed_disk": _g(
        "Managed disks are billed for their provisioned size whether attached or not.",
        "It is waiting to be re-attached, or must be retained (legal hold) - then a snapshot on Standard HDD storage "
        "is cheaper than the disk.",
        "Snapshot if the data may be needed, then delete.", (0.1, 0.5), 0.0, DELETE,
        ("Find and delete unattached disks", f"{_LEARN}/virtual-machines/disks-find-unattached-portal"),
        pricing("disks")),
    "old_disk_snapshot": _g(
        "Snapshots are billed per GB used and outlive the reason they were taken (a change, a migration).",
        "It is the only copy kept for a retention requirement - then move retention to Azure Backup with a policy.",
        "Delete after confirming no restore depends on it.", (0.1, 0.25), 0.0, DELETE,
        ("Snapshots of managed disks", f"{_LEARN}/virtual-machines/snapshot-copy-managed-disk")),
    "deallocated_virtual_machine": _g(
        "A deallocated VM stops compute charges, but its disks (and public IPs) keep billing indefinitely.",
        "VMs stopped by a schedule and started regularly, or DR standby machines.",
        "Confirm with the owner; snapshot or back up, then delete the VM and its disks.", (0.25, 1), 0.0, DELETE,
        ("VM states and billing", f"{_LEARN}/virtual-machines/states-billing")),
    "idle_vmss": _g(
        "Scale-set instances bill compute while doing no work.",
        "Pools kept warm on purpose for fast scale-out - then cap the minimum instance count.",
        "Scale to zero or set autoscale with a lower minimum; delete if abandoned.", (0.5, 1), 0.0, DELETE,
        ("Autoscale for scale sets",
         f"{_LEARN}/virtual-machine-scale-sets/virtual-machine-scale-sets-autoscale-overview")),
    "app_service_plan_previous_generation": _g(
        "Premium v2 runs on previous-generation hardware: Premium v3 gives more memory per core at a lower price and "
        "is eligible for reservations and savings plans.",
        "The plan's scale unit cannot host Pv3 and the plan is about to be retired anyway.",
        "Scale up to the recommended Pv3 size; if the stamp does not support Pv3, create a new plan and move the apps. "
        "Apps restart once.", (1, 4), 0.0, "None - the new tier is cheaper (saving shown separately).",
        ("Configure Premium v3", f"{_LEARN}/app-service/app-service-configure-premium-v3-tier"),
        pricing("app_service")),
    "app_service_plan_single_instance": _g(
        "With one instance, platform maintenance and instance failures restart the only worker: every app on the "
        "plan is briefly unavailable whenever that happens, with nothing to fail over to.",
        "Development / test plans and apps where a few minutes of downtime are acceptable.",
        "Scale out to 2 instances (3 for zone redundancy) or add autoscale with a minimum of 2.", (0.25, 0.5), None,
        "One more instance - the same again as the plan's current instance cost.",
        ("Reliability in App Service", f"{_LEARN}/reliability/reliability-app-service"),
        ("Scale up / out an App Service plan", f"{_LEARN}/app-service/manage-scale-up"),
        pricing("app_service"), cost_factor=1.0),
    "app_service_plan_cpu_saturated": _g(
        "Hours at 80 %+ CPU mean queued requests and slow responses at exactly the busiest times.",
        "A known nightly batch peak with no user traffic.",
        "Profile the app first (a hot loop or chatty dependency is cheaper to fix); then autoscale out on CPU, or "
        "scale up one size.", (1, 8), None,
        "Up to one more instance-equivalent while busy - autoscale bills only the hours it runs.",
        ("Get started with autoscale", f"{_LEARN}/azure-monitor/autoscale/autoscale-get-started"),
        ("Scale up / out an App Service plan", f"{_LEARN}/app-service/manage-scale-up"), cost_factor=0.5),
    "app_service_plan_underutilized": _g(
        "The plan pays for capacity that its apps never use.",
        "Capacity held for a known seasonal peak.",
        "Scale down to the recommended size; apps restart once.", (0.25, 1), 0.0,
        "None - the smaller size is cheaper (saving shown separately).",
        ("Scale up / out an App Service plan", f"{_LEARN}/app-service/manage-scale-up"), pricing("app_service")),
    "vm_rightsizing_opportunity": _g(
        "The VM's busiest hours stay far below its size: the company pays for cores and memory that are never used.",
        "Memory- or licence-bound workloads (SQL Server licensed per core, vendor sizing requirements).",
        "Resize to the recommended size (a reboot), watch performance for two weeks.", (0.5, 1), 0.0,
        "None - the smaller size is cheaper (saving shown separately).",
        ("Resize a virtual machine", f"{_LEARN}/virtual-machines/sizes/resize-vm"),
        ("Advisor cost recommendations", f"{_LEARN}/advisor/advisor-cost-recommendations")),
    "cheaper_region_available": _g(
        "The same size lists for at least 10 % less in another region of the same geography that policy allows.",
        "Latency-sensitive workloads near users or data, data-residency rules, or dependencies that would then "
        "cross regions (egress charges and latency).",
        "A migration: rebuild or move the resource, its network and dependencies, test, cut over.", (16, 80), None,
        "Same size elsewhere is cheaper, but inter-region data transfer and duplicate running during the move cost "
        "extra.",
        ("Azure Resource Mover overview", f"{_LEARN}/resource-mover/overview"),
        ("Bandwidth (data transfer) pricing", "https://azure.microsoft.com/pricing/details/bandwidth/")),
    "resource_type_denied_by_policy": _g(
        "The resources exist although a resource-type policy forbids their type - usually created before the policy, "
        "so they sit outside the agreed governance model.",
        "An approved exception - then record a policy exemption with an expiry date.",
        "Migrate to an allowed type or remove; otherwise create an exemption.", (1, 8), 0.0, FREE,
        ("Azure Policy exemptions", f"{_LEARN}/governance/policy/concepts/exemption-structure")),
    "app_service_plan_mixed_environments": _g(
        "Production and non-production apps share the plan's instances: test load slows production, and the plan's "
        "cost cannot be attributed to an environment.",
        "Very small, low-risk workloads where separation costs more than the risk.",
        "Create a separate small non-production plan and move the non-production apps.", (1, 4), None,
        "A small non-production plan (Basic B1 / P0v3, tens of USD per month), often offset by shrinking the "
        "production plan.",
        ("App Service plans", f"{_LEARN}/app-service/overview-hosting-plans"), pricing("app_service")),
    "web_app_https_not_enforced": _g(
        "The app still answers plain HTTP: credentials and session cookies can be read or changed on the way.",
        "Never - redirect HTTP to HTTPS instead of serving it.",
        "Turn on 'HTTPS Only'. No downtime.", (0.1, 0.25), 0.0, FREE,
        ("Secure a custom domain with TLS", f"{_LEARN}/app-service/configure-ssl-bindings")),
    "web_app_managed_identity_missing": _g(
        "Without a managed identity the app reaches SQL, Storage and Key Vault with connection strings and keys kept "
        "in settings - secrets that leak, never rotate and identify no caller.",
        "Apps that call no Azure service.",
        "Assign the identity (no restart), grant data-plane roles, switch the app's connections to it.", (0.5, 8),
        0.0, FREE,
        ("Managed identities for App Service", f"{_LEARN}/app-service/overview-managed-identity")),
    "web_app_eol_runtime": _g(
        "The language runtime is out of support: no security fixes, and App Service may stop offering it.",
        "Never long-term; plan the upgrade with the application team.",
        "Upgrade the code to a supported runtime, test, deploy through a slot.", (4, 40), 0.0, FREE,
        ("App Service language support policy", f"{_LEARN}/app-service/language-support-policy")),
    "web_app_weak_tls": _g(
        "TLS 1.0 / 1.1 have known weaknesses and are being retired across Azure.",
        "Only while a named legacy client cannot do TLS 1.2 - fix the client.",
        "Set the minimum TLS version to 1.2. No downtime.", (0.1, 0.25), 0.0, FREE,
        ("TLS in App Service", f"{_LEARN}/app-service/overview-tls")),
    "web_app_ftp_enabled": _g(
        "FTP sends deployment credentials and code in clear text; basic-auth publishing credentials bypass Entra ID.",
        "Never needed with modern deployment (zip deploy, GitHub / Azure DevOps).",
        "Disable FTP (or allow FTPS only) and basic-auth publishing.", (0.1, 0.25), 0.0, FREE,
        ("Deploy with FTP / FTPS", f"{_LEARN}/app-service/deploy-ftp"),
        ("Disable basic authentication", f"{_LEARN}/app-service/configure-basic-auth-disable")),
    "web_app_health_check_missing": _g(
        "Without a health check App Service keeps sending traffic to an instance whose app has hung.",
        "Single-instance plans: health check only takes effect with two or more instances.",
        "Add a lightweight /health endpoint and configure the path.", (0.5, 2), 0.0, FREE,
        ("Monitor instances with health check", f"{_LEARN}/app-service/monitor-instances-health-check")),
    "web_app_32bit_worker": _g(
        "A 32-bit worker process can address only 2-4 GB of memory, so a larger instance's memory goes unused.",
        "Apps with 32-bit native dependencies.",
        "Switch the platform to 64-bit and test.", (0.25, 1), 0.0, FREE,
        ("Configure an App Service app", f"{_LEARN}/app-service/configure-common")),
    # --- Data ------------------------------------------------------------------------------------------------
    "public_sql_server": _g(
        "The SQL endpoint is reachable from the internet, protected only by firewall rules and credentials.",
        "Clients outside Azure without VPN / ExpressRoute by design - keep tightly scoped IP rules.",
        CHOSEN, (0.25, 4), 0.0, RUN,
        ("Azure SQL connectivity settings", f"{_LEARN}/azure-sql/database/connectivity-settings"),
        ("Azure SQL VNet rules", f"{_LEARN}/azure-sql/database/vnet-service-endpoint-rule-overview"),
        ("Azure SQL private endpoints", f"{_LEARN}/azure-sql/database/private-endpoint-overview"),
        pricing("private_link")),
    "sql_firewall_allow_all_azure_services": _g(
        "'Allow Azure services' admits every Azure resource of every customer - including an attacker's - to try "
        "credentials against the server.",
        "Services that cannot use VNet integration or private endpoints - rare; prefer specific rules.",
        "Replace with VNet rules or a private endpoint, then remove the 0.0.0.0 rule.", (1, 4), 0.0,
        f"No cost for VNet rules; a private endpoint is about USD {PE:.2f}/month.",
        ("Azure SQL firewall rules", f"{_LEARN}/azure-sql/database/firewall-configure")),
    "sql_firewall_wide_ip_range": _g(
        "A wide IP range admits far more addresses than the clients that need access.",
        "A documented corporate egress range.",
        "Narrow the rule to the actual client addresses or move to private access.", (0.25, 1), 0.0, FREE,
        ("Azure SQL firewall rules", f"{_LEARN}/azure-sql/database/firewall-configure")),
    "sql_firewall_individual_ip_rules": _g(
        "Per-person IP rules (often portal-generated) stay after people leave or their home IP changes owner.",
        "Short-lived rules removed by automation.",
        "Remove personal rules; administer through Bastion / VPN and Entra ID.", (0.25, 1), 0.0, FREE,
        ("Azure SQL firewall rules", f"{_LEARN}/azure-sql/database/firewall-configure")),
    "sql_entra_only_auth_disabled": _g(
        "SQL logins are passwords outside Entra ID: no MFA, no Conditional Access, no central offboarding.",
        "Applications that cannot use Entra ID yet - migrate them first.",
        "Move apps to managed identities and admins to Entra groups, then enable Entra-only authentication.", (2, 16),
        0.0, FREE,
        ("Microsoft Entra-only authentication", f"{_LEARN}/azure-sql/database/authentication-azure-ad-only-authentication")),
    "sql_entra_admin_individual_user": _g(
        "A single person as Entra admin is a leaver risk and a single point of failure.",
        "Never - use a group.",
        "Set an Entra group (with PIM where possible) as the server admin.", (0.25, 0.5), 0.0, FREE,
        ("Configure Microsoft Entra authentication", f"{_LEARN}/azure-sql/database/authentication-aad-configure")),
    "sql_entra_admin_missing": _g(
        "Without an Entra admin only SQL logins can administer the server, and identity-based access cannot be set up.",
        "Never.",
        "Set an Entra group as the server admin.", (0.25, 0.5), 0.0, FREE,
        ("Configure Microsoft Entra authentication", f"{_LEARN}/azure-sql/database/authentication-aad-configure")),
    "sql_hyperscale_legacy_storage_pricing": _g(
        "The database is still billed on the legacy Hyperscale storage meter, which costs more per GB than the "
        "current one.",
        "Never, unless the database is about to be deleted.",
        "Follow Microsoft's switch to the current pricing model (no data movement); check reservations.", (0.5, 2),
        0.0, "None - the current meter is cheaper (saving shown separately).",
        ("Hyperscale service tier", f"{_LEARN}/azure-sql/database/service-tier-hyperscale"), pricing("sql")),
    "idle_sql_database": _g(
        "The database had (almost) no connections or CPU for 30 days but bills its full compute.",
        "Databases used only at month or year end - then serverless with auto-pause fits better than deleting.",
        "Export a backup (or rely on PITR / LTR), then delete, or move to serverless with auto-pause.", (0.5, 1), 0.0,
        DELETE, ("Serverless compute tier", f"{_LEARN}/azure-sql/database/serverless-tier-overview")),
    "sql_database_underutilized": _g(
        "The database's busiest hours use a fraction of its provisioned vCores / DTUs.",
        "Headroom kept for a known peak.",
        "Scale down one step and watch performance; consider serverless for spiky use.", (0.5, 1), 0.0,
        "None - the smaller size is cheaper (saving shown separately).",
        ("Scale single database resources", f"{_LEARN}/azure-sql/database/single-database-scale")),
    "sql_database_cpu_saturated": _g(
        "CPU at its limit for whole hours means queued queries and timeouts.",
        "A known batch window with no users waiting.",
        "Tune first (Query Store: top queries, missing indexes) - often free; scale up only what remains.", (2, 16),
        None, "Zero if tuning fixes it; one size up roughly doubles the database's compute cost.",
        ("Monitoring and performance tuning", f"{_LEARN}/azure-sql/database/monitor-tune-overview"),
        ("Scale single database resources", f"{_LEARN}/azure-sql/database/single-database-scale"),
        cost_factor=1.0),
    "cross_region_app_data_tier": _g(
        "Every request crosses regions: added latency, inter-region data transfer charges, and availability depending "
        "on two regions without any DR benefit.",
        "A deliberate active/passive design with replication.",
        "Co-locate the tiers (move the smaller one); use geo-replication for DR.", (8, 40), None,
        "Removes inter-region transfer; the move itself is a one-off project.",
        ("Choose Azure regions", f"{_LEARN}/cloud-adoption-framework/ready/azure-setup-guide/regions"),
        ("Bandwidth (data transfer) pricing", "https://azure.microsoft.com/pricing/details/bandwidth/")),
    "cosmos_public_network_access": _g(
        "The Cosmos DB account accepts connections from any network; keys are the only barrier.",
        "Accounts called by external clients by design (tag arg-public).",
        CHOSEN, (0.1, 4), 0.0, RUN,
        ("Cosmos DB IP firewall", f"{_LEARN}/cosmos-db/how-to-configure-firewall"),
        ("Cosmos DB VNet service endpoints", f"{_LEARN}/cosmos-db/how-to-configure-vnet-service-endpoint"),
        ("Cosmos DB private endpoints", f"{_LEARN}/cosmos-db/how-to-configure-private-endpoints"),
        pricing("private_link")),
    "idle_cosmos_db": _g(
        "Provisioned throughput is billed per hour whether requests arrive or not.",
        "Accounts used occasionally - serverless fits them better than deleting.",
        "Back up, then delete, or move to serverless.", (0.5, 1), 0.0, DELETE,
        ("Cosmos DB serverless", f"{_LEARN}/cosmos-db/serverless")),
    "public_storage_account": _g(
        "Anonymous blob access lets anyone with the URL read the data - no key, no record of who it was.",
        "Content meant to be public - serve it from a dedicated account behind Front Door / CDN.",
        "Disallow anonymous access after checking no container is meant to be public.", (0.25, 1), 0.0, FREE,
        ("Prevent anonymous read access to blobs", f"{_LEARN}/storage/blobs/anonymous-read-access-prevent")),
    "storage_shared_key_access_enabled": _g(
        "An account key grants full control of all data, never expires and identifies nobody; SAS tokens signed with "
        "it inherit that.",
        "Clients that still need keys (Azure Files SMB with key mounts, Functions / Logic Apps runtime storage, some "
        "backup tools) - check the Transactions metric by authentication type first.",
        "Move clients to Entra ID, confirm no SharedKey traffic remains, then disable.", (0.5, 8), 0.0, FREE,
        ("Prevent Shared Key authorization", f"{_LEARN}/storage/common/shared-key-authorization-prevent")),
    "storage_public_network_access": _g(
        "The account accepts requests from every network; a leaked key or SAS works from anywhere.",
        "Accounts public by design (tag arg-public): external clients, static websites, CDN origins.",
        CHOSEN, (0.1, 4), 0.0, RUN,
        ("Azure Storage network security", f"{_LEARN}/storage/common/storage-network-security"),
        ("Private endpoints for Azure Storage", f"{_LEARN}/storage/common/storage-private-endpoints"),
        ("Service endpoints", f"{_LEARN}/virtual-network/virtual-network-service-endpoints-overview"),
        pricing("private_link")),
    "storage_blob_soft_delete_disabled": _g(
        "A deleted or overwritten blob is gone immediately - no undo for a script error or ransomware.",
        "Scratch / cache accounts whose data is reproducible.",
        "Enable blob (and container) soft delete with 7-14 days retention.", (0.1, 0.25), None,
        "Deleted data is billed during the retention period - usually a few percent of the account's storage cost.",
        ("Soft delete for blobs", f"{_LEARN}/storage/blobs/soft-delete-blob-overview")),
    "storage_account_sprawl": _g(
        "Many near-identical accounts multiply per-account work (keys, networking, monitoring, Defender charges) "
        "without adding isolation that containers could not give.",
        "Accounts separated on purpose for scale targets, regions or customer isolation contracts.",
        "Consolidate new tenants into a few accounts with a container per tenant; migrate opportunistically.",
        (8, 40), 0.0, "None - fewer accounts reduce per-account charges.",
        ("Storage account overview", f"{_LEARN}/storage/common/storage-account-overview"),
        ("Scalability targets", f"{_LEARN}/storage/common/scalability-targets-standard-account")),
    "storage_transaction_hotspot": _g(
        "Transaction charges dominate this account's bill - the access pattern, not the stored data, drives cost.",
        "Short-lived migrations or one-off jobs.",
        "Find the caller (metrics by API name), cache or batch; for Files consider the provisioned billing model.",
        (2, 8), 0.0, "None - lowers transaction charges.",
        ("Understand Azure Files billing", f"{_LEARN}/storage/files/understanding-billing"),
        ("Blob access tiers", f"{_LEARN}/storage/blobs/access-tiers-overview")),
    "unused_storage_account": _g(
        "No data operations for 30 days and (almost) no data, but the account still bills its per-account charges "
        "and remains an attack surface with valid keys.",
        "Accounts that are boot-diagnostics targets, Function runtime storage or Cloud Shell - the description says "
        "so when known.",
        "Confirm with the owner; delete (or lock and tag for review).", (0.25, 0.5), 0.0, DELETE,
        ("Storage account overview", f"{_LEARN}/storage/common/storage-account-overview")),
    "dormant_storage_data": _g(
        "Data nobody has read for 30+ days sits in a hot tier priced for frequent access.",
        "Data read rarely but needing instant, cheap access - and Cool / Cold / Archive have minimum storage "
        "durations (30 / 90 / 180 days) with early-deletion fees.",
        "Add a lifecycle management rule (Hot → Cool → Cold / Archive by last access).", (0.5, 2), 0.0,
        "None - lower tiers are cheaper per GB; reads and rehydration cost more.",
        ("Lifecycle management", f"{_LEARN}/storage/blobs/lifecycle-management-overview"),
        ("Blob access tiers", f"{_LEARN}/storage/blobs/access-tiers-overview")),
    "orphaned_backup_vault": _g(
        "The vault protects nothing current but may still bill retained backup data.",
        "Retention required for compliance - keep it until the retention ends.",
        "Stop protection with delete of data (after checking retention), then delete the vault.", (0.5, 1), 0.0, DELETE,
        ("Delete a Recovery Services vault", f"{_LEARN}/backup/backup-azure-delete-vault")),
    # --- AI --------------------------------------------------------------------------------------------------
    "ai_services_local_auth_enabled": _g(
        "API keys are shared secrets: every caller looks the same, so token spend and abuse cannot be attributed, "
        "and a leaked key works until rotated.",
        "Callers that cannot use Entra ID yet - set a deadline and rotate keys meanwhile.",
        "Give callers managed identities with 'Cognitive Services OpenAI User' / 'Azure AI User', then disable keys.",
        (1, 8), 0.0, FREE,
        ("Disable local authentication", f"{_LEARN}/ai-services/disable-local-auth")),
    "ai_services_public_network_open": _g(
        "The model endpoint can be called - and billed - from any network a key or token leaks to.",
        "Public-facing callers outside Azure by design (tag arg-public) - use a gateway with authentication.",
        CHOSEN, (0.1, 3), 0.0, RUN,
        ("Configure virtual networks for Azure AI services", f"{_LEARN}/ai-services/cognitive-services-virtual-networks"),
        pricing("private_link")),
    "ai_spend_without_gateway": _g(
        "Without a gateway nobody can cap, cache or attribute token spend per application.",
        "AI spend below the gateway's break-even and no chargeback requirement - see the finding for the numbers.",
        "API Management in front of the model endpoints with token-limit, token-metric and backend-pool policies.",
        (8, 24), PRICE["apim_basic_v2"], f"API Management Basic v2 about USD {PRICE['apim_basic_v2']:,.0f}/month "
                                          f"(0 if a shared gateway is reused).",
        ("AI gateway capabilities in API Management", f"{_LEARN}/api-management/genai-gateway-capabilities"),
        ("llm-token-limit policy", f"{_LEARN}/api-management/llm-token-limit-policy"),
        ("llm-emit-token-metric policy", f"{_LEARN}/api-management/llm-emit-token-metric-policy"),
        ("Semantic cache store policy", f"{_LEARN}/api-management/llm-semantic-cache-store-policy"),
        ("API Management v2 tiers", f"{_LEARN}/api-management/v2-service-tiers-overview"), pricing("apim")),
    "ai_account_sprawl": _g(
        "Quotas, content filters, logging, keys and networking are configured per account: every extra account is "
        "another place for drift, and quota is fragmented.",
        "Accounts separated on purpose for data residency or customer isolation.",
        "One Foundry resource per environment with a project per use case; move deployments as models are refreshed.",
        (8, 40), 0.0, "None - billing is per token, not per account.",
        ("What is Microsoft Foundry", f"{_LEARN}/foundry/what-is-foundry"),
        ("Quotas and limits", f"{_LEARN}/foundry/openai/quotas-limits")),
    # --- Security & identity ---------------------------------------------------------------------------------
    "key_vault_access_policy_model": _g(
        "Access policies are invisible to Azure RBAC tooling, cannot be PIM-managed, and any vault Contributor can "
        "grant themselves data access.",
        "Never for new vaults; plan the switch for old ones so no application loses access.",
        "Map each policy to an RBAC role, then switch the permission model.", (0.5, 2), 0.0, FREE,
        ("Migrate to Azure RBAC", f"{_LEARN}/key-vault/general/rbac-migration"),
        ("Key Vault RBAC guide", f"{_LEARN}/key-vault/general/rbac-guide")),
    "key_vault_soft_delete_disabled": _g(
        "Deleted secrets, keys and certificates cannot be recovered.",
        "Never - soft delete is mandatory for new vaults.",
        "Enable soft delete.", (0.1, 0.25), 0.0, FREE,
        ("Soft-delete overview", f"{_LEARN}/key-vault/general/soft-delete-overview")),
    "key_vault_purge_protection_disabled": _g(
        "During the soft-delete window anyone with purge rights - or an attacker - can destroy keys permanently, "
        "including keys that encrypt data elsewhere.",
        "Short-lived test vaults that automation re-creates under the same name.",
        "Enable purge protection (irreversible).", (0.1, 0.25), 0.0, FREE,
        ("Key Vault recovery", f"{_LEARN}/key-vault/general/key-vault-recovery")),
    "key_vault_public_network_open": _g(
        "The vault answers from every network; a stolen token works from anywhere.",
        "Vaults read by external clients by design (tag arg-public).",
        CHOSEN, (0.1, 3), 0.0, RUN,
        ("Key Vault network security", f"{_LEARN}/key-vault/general/network-security"),
        ("Key Vault private link", f"{_LEARN}/key-vault/general/private-link-service"), pricing("private_link")),
    "defender_plan_disabled": _g(
        "Paid Defender plans add threat detection and vulnerability management for their resource type.",
        "Plans whose price is not justified by the data the resources hold - see the per-plan list in the finding. "
        "Usually decided once at management-group level.",
        "Enable the chosen plans (per subscription or by policy at the management group).", (0.5, 2), None,
        "Per plan - the finding lists each plan's estimated monthly cost.",
        ("Defender for Cloud overview", f"{_LEARN}/defender-for-cloud/defender-for-cloud-introduction"),
        ("Select a Defender for Servers plan", f"{_LEARN}/defender-for-cloud/plan-defender-for-servers-select-plan"),
        pricing("defender")),
    # Used only when a Defender finding carries no per-recommendation evidence (findings from older scans).
    "defender_recommendations": _g(
        "Defender for Cloud evaluates the resource against the Microsoft cloud security benchmark; an unhealthy "
        "recommendation is a configuration gap with a known attack path.",
        "Resources outside the recommendation's intent (test, short-lived, compensating control) - record an "
        "exemption in Defender with the reason so it stops counting against the secure score.",
        "Follow the recommendation's remediation; most are configuration changes without downtime.", (0.5, 4), None,
        "Depends on the recommendation - re-scan to get the per-recommendation cost.",
        ("Secure score", f"{_LEARN}/defender-for-cloud/secure-score-security-controls"),
        ("Microsoft cloud security benchmark - network security",
         "https://learn.microsoft.com/security/benchmark/azure/mcsb-network-security")),
    "low_secure_score": _g(
        "The secure score summarises how many Defender recommendations are open, weighted by risk.",
        "Not a change in itself - act on the individual recommendations.",
        "Work through the controls with the highest potential score increase.", (4, 40), 0.0, FREE,
        ("Secure score", f"{_LEARN}/defender-for-cloud/secure-score-security-controls")),
    "excessive_subscription_owners": _g(
        "Every Owner can change any resource and grant access to anyone; more standing Owners means more accounts an "
        "attacker can phish to take over the subscription.",
        "Owners that are PIM-eligible rather than active do not count.",
        "Move Owners to an Entra group with PIM-eligible activation; keep at most three.", (1, 3), 0.0,
        "No Azure cost; PIM needs Microsoft Entra ID P2 / ID Governance licences.",
        ("Azure RBAC best practices", f"{_LEARN}/role-based-access-control/best-practices"),
        ("Configure PIM", "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure")),
    "standing_user_access_administrator": _g(
        "User Access Administrator can grant any role, including Owner, to anyone - standing, it is Owner in all "
        "but name.",
        "Never standing; break-glass accounts are handled separately.",
        "Remove it, or make it PIM-eligible with approval; use the constrained 'Role Based Access Control "
        "Administrator' role where delegation is needed.", (0.5, 1), 0.0,
        "No Azure cost; PIM needs Microsoft Entra ID P2 / ID Governance licences.",
        ("Azure RBAC best practices", f"{_LEARN}/role-based-access-control/best-practices"),
        ("Configure PIM", "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure")),
    "service_principal_privileged_role": _g(
        "A service principal with Owner / Contributor on the subscription turns a leaked secret into full control.",
        "Platform automation that genuinely manages the whole subscription - then federated credentials only.",
        "Scope each principal to the resource groups it deploys; use workload identity federation instead of secrets.",
        (1, 4), 0.0, FREE,
        ("Workload identity federation", "https://learn.microsoft.com/entra/workload-id/workload-identity-federation"),
        ("Azure RBAC best practices", f"{_LEARN}/role-based-access-control/best-practices")),
    "dormant_member_user": _g(
        "Accounts nobody signs in with are prime takeover targets: password sprays and leaked credentials go "
        "unnoticed because nobody uses the account.",
        "Seasonal or emergency accounts - document and monitor them.",
        "Confirm with the manager, then disable; delete after the retention period.", (0.1, 0.5), 0.0, FREE,
        ("Manage inactive user accounts",
         "https://learn.microsoft.com/entra/identity/monitoring-health/howto-manage-inactive-user-accounts"),
        ("Access reviews", "https://learn.microsoft.com/entra/id-governance/access-reviews-overview")),
    "guest_never_signed_in": _g(
        "An invitation that was never redeemed or used still grants whatever access was assigned to it.",
        "Invitations sent in the last few days.",
        "Remove the guest (or re-invite when the collaboration starts).", (0.1, 0.25), 0.0, FREE,
        ("Access reviews", "https://learn.microsoft.com/entra/id-governance/access-reviews-overview")),
    "mfa_not_enabled": _g(
        "Accounts without MFA fall to password spray and phishing; MFA blocks the large majority of account "
        "compromise attempts.",
        "Break-glass accounts (excluded and monitored separately).",
        "Require MFA through Conditional Access for all users; register the remaining users.", (0.25, 1), 0.0,
        "No Azure cost (Conditional Access needs Microsoft Entra ID P1).",
        ("How MFA works", "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"),
        ("Require MFA strength for all users",
         "https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength")),
    "permanent_global_admin": _g(
        "A permanent Global Administrator controls the whole tenant 24/7; phishing that account is a full tenant "
        "compromise.",
        "Two cloud-only break-glass accounts, excluded and monitored.",
        "Make Global Administrator PIM-eligible with approval and MFA on activation.", (0.5, 2), 0.0,
        "No Azure cost; PIM needs Microsoft Entra ID P2 / ID Governance licences.",
        ("Configure PIM", "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure"),
        ("Emergency access accounts",
         "https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access")),
    "expired_app_secret": _g(
        "An expired secret either broke the application already or is dead weight that confuses ownership.",
        "Never keep it; remove expired credentials.",
        "Rotate to a certificate or federated credential if the app is in use; remove the expired secret.", (0.25, 1),
        0.0, FREE,
        ("Certificate credentials", "https://learn.microsoft.com/entra/identity-platform/certificate-credentials"),
        ("Workload identity federation", "https://learn.microsoft.com/entra/workload-id/workload-identity-federation")),
    "expired_app_certificate": _g(
        "An expired certificate either broke the application already or is dead weight that confuses ownership.",
        "Never keep it; remove expired credentials.",
        "Rotate the certificate if the app is in use; remove the expired one.", (0.25, 1), 0.0, FREE,
        ("Certificate credentials", "https://learn.microsoft.com/entra/identity-platform/certificate-credentials")),
    # --- Governance / observability --------------------------------------------------------------------------
    "missing_diagnostic_settings": _g(
        "Without resource logs there is no record of who read data, changed configuration or called the service - "
        "incidents and audits have nothing to work with.",
        "Non-production resources without sensitive data, or resources about to be covered by a central policy.",
        "One diagnostic setting per resource - better a DeployIfNotExists policy per resource type.", (0.1, 0.5),
        None, f"Log Analytics ingestion at about USD {PRICE['log_analytics_gb']:.2f} per GB (first 5 GB per month "
              f"free); audit categories are usually small - send verbose ones to storage or Basic logs.",
        ("Diagnostic settings", f"{_LEARN}/azure-monitor/data-collection/diagnostic-settings"),
        ("Azure Monitor cost best practices", f"{_LEARN}/azure-monitor/fundamentals/best-practices-cost"),
        pricing("monitor")),
    "log_analytics_restrictive_daily_cap": _g(
        "A cap far below normal volume stops ingestion every day - logs are silently dropped, most likely during an "
        "incident, when volume spikes.",
        "Sandbox workspaces where losing data is acceptable.",
        "Raise the cap above the normal daily volume and alert on it instead of enforcing it.", (0.25, 0.5), None,
        f"Ingestion above the old cap is billed at about USD {PRICE['log_analytics_gb']:.2f} per GB.",
        ("Daily cap", f"{_LEARN}/azure-monitor/logs/daily-cap"), pricing("monitor")),
    "log_analytics_workspace_sprawl": _g(
        "Many workspaces split the data you need to correlate during an incident and multiply access and retention "
        "settings.",
        "Workspaces separated for data residency or access boundaries.",
        "Point diagnostic settings at the environment's (or platform's) central workspace.", (2, 8), 0.0,
        "None - commitment tiers get cheaper with consolidated volume.",
        ("Design a Log Analytics workspace architecture", f"{_LEARN}/azure-monitor/logs/workspace-design")),
    "app_insights_workspace_missing": _g(
        "The Application Insights resource points at a deleted workspace - telemetry has nowhere to land.",
        "Resources no longer in use - delete them instead.",
        "Re-link to an existing workspace.", (0.25, 0.5), 0.0, "Ingestion billed as before.",
        ("Diagnostic settings", f"{_LEARN}/azure-monitor/data-collection/diagnostic-settings")),
    "app_insights_classic_mode": _g(
        "Classic Application Insights is retired; workspace-based resources get the current features and pricing.",
        "Resources about to be deleted.",
        "Migrate to workspace-based (in place, no data loss).", (0.25, 1), 0.0, "Billed on the workspace's pricing.",
        ("Migrate to workspace-based Application Insights",
         "https://learn.microsoft.com/previous-versions/azure/azure-monitor/app/convert-classic-resource")),
    "service_health_alert_missing": _g(
        "Without a Service Health alert nobody hears about Azure incidents, planned maintenance or retirements that "
        "affect the subscription.",
        "Subscriptions covered by a central alert that targets them.",
        "Create an activity-log alert for Service Health with the owners' action group.", (0.25, 0.5), 0.0,
        "No Azure cost (e-mail notifications are free; SMS / voice are charged).",
        ("Service Health alerts", f"{_LEARN}/service-health/alerts-activity-log-service-notifications-portal")),
    "environment_tag_name_mismatch": _g(
        "Name and environment tag disagree: maintenance windows, cost reports and environment-scoped policies treat "
        "the resource as the wrong environment.",
        "Names that contain an environment word by coincidence.",
        "Correct the tag (the name usually cannot be changed).", (0.1, 0.25), 0.0, FREE,
        ("Resource tagging", f"{_LEARN}/cloud-adoption-framework/ready/azure-best-practices/resource-tagging")),
    "tag_key_typo": _g(
        "A misspelled tag key escapes tag-based policies, cost reports and automation that look for the right key.",
        "Never; fix it.",
        "Rename the tag key on the resources (merge the value into the correct key).", (0.1, 0.25), 0.0, FREE,
        ("Resource tagging", f"{_LEARN}/cloud-adoption-framework/ready/azure-best-practices/resource-tagging"),
        ("Tag policies", f"{_LEARN}/azure-resource-manager/management/tag-policies")),
    "missing_required_tags": _g(
        "Without owner / environment / cost-center tags, cost cannot be charged back and nobody knows whom to ask "
        "about the resource.",
        "Resources that inherit the tags through Cost Management tag inheritance - for cost purposes only.",
        "Add the tags; enforce with policy (modify / inherit from resource group).", (0.05, 0.25), 0.0, FREE,
        ("Resource tagging", f"{_LEARN}/cloud-adoption-framework/ready/azure-best-practices/resource-tagging"),
        ("Tag policies", f"{_LEARN}/azure-resource-manager/management/tag-policies"),
        ("Tag inheritance in Cost Management", f"{_LEARN}/cost-management-billing/costs/enable-tag-inheritance")),
    "naming_convention_violation": _g(
        "Names that do not follow the standard make ownership, environment and purpose hard to read at a glance.",
        "Almost always for existing resources: Azure cannot rename most resources in place, so renaming means "
        "re-creating and migrating. Apply the standard to new resources through IaC and rename only during a "
        "rebuild. The check can be switched off in Settings.",
        "Only as part of a planned rebuild: new resource, data migration, reference updates, cut-over.", (4, 40), 0.0,
        "No run-cost change; the cost is the migration effort (and a short period running both).",
        ("Define your naming convention", f"{_LEARN}/cloud-adoption-framework/ready/azure-best-practices/resource-naming"),
        ("Abbreviations for resource types",
         f"{_LEARN}/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations"),
        ("Move resources (name changes need re-creation)",
         f"{_LEARN}/azure-resource-manager/management/move-resource-group-and-subscription")),
    "missing_resource_lock": _g(
        "A CanNotDelete lock stops accidental deletion of a production resource by a person or a script.",
        "Resources managed by IaC pipelines that replace them (locks block terraform destroy / replace); ReadOnly "
        "locks break operations such as listing storage keys.",
        "Add a CanNotDelete lock (after checking whether one is inherited).", (0.1, 0.25), 0.0, FREE,
        ("Lock resources", f"{_LEARN}/azure-resource-manager/management/lock-resources")),
    "subscription_multiple_workloads": _g(
        "Unrelated workloads share RBAC, budget, Defender scope and blast radius: none can be governed, charged back "
        "or decommissioned on its own.",
        "Small shared-services subscriptions run by one team.",
        "Landing-zone subscription per workload and environment; move workloads during their next major change.",
        (40, 200), 0.0, "No run-cost change; the cost is the migration effort.",
        ("Azure landing zones", f"{_LEARN}/cloud-adoption-framework/ready/landing-zone/"),
        ("Landing zone design principles", f"{_LEARN}/cloud-adoption-framework/ready/landing-zone/design-principles")),
    "empty_resource_group": _g(
        "An empty resource group still carries role assignments, policies and locks - and suggests something lives "
        "there.",
        "Groups created ahead of a deployment, or holding RBAC for a team.",
        "Delete after checking role assignments and deployments.", (0.05, 0.1), 0.0, FREE,
        ("Manage resource groups", f"{_LEARN}/azure-resource-manager/management/manage-resource-groups-portal")),
    "terraform_unmanaged_resource": _g(
        "Resources outside Terraform drift from the code, are invisible in reviews and are not re-created after a "
        "disaster.",
        "Resources created by platform services on purpose (managed resource groups).",
        "Import into Terraform or remove.", (0.5, 2), 0.0, FREE,
        ("Terraform import", "https://developer.hashicorp.com/terraform/language/import")),
    "terraform_missing_resource": _g(
        "Terraform expects a resource that no longer exists: the next apply re-creates it or fails.",
        "Resources deleted on purpose - then remove them from the code.",
        "Re-apply, or remove the resource from code and state.", (0.25, 1), 0.0, FREE,
        ("Terraform import", "https://developer.hashicorp.com/terraform/language/import")),
    "resource_provider_blocked_registered": _g(
        "A registered provider is permission for the subscription to host that service. Blocked providers (by default "
        "the retired classic ones) should not be registered at all.",
        "A documented exception for a migration still in progress.",
        "Unregister; prevent re-registration with a 'Not allowed resource types' policy at the management group.",
        (0.25, 0.5), 0.0, FREE,
        ("Resource providers and types", f"{_LEARN}/azure-resource-manager/management/resource-providers-and-types"),
        ("Resource providers for Azure services",
         f"{_LEARN}/azure-resource-manager/management/azure-services-resource-providers")),
    "resource_providers_registered_unused": _g(
        "Microsoft's guidance is to register a provider only when you are ready to use it: every registered provider "
        "lets anyone with deployment rights create that service without a further step.",
        "Providers a team is about to use. Unregistering is undone by the next portal deployment, so for services "
        "that are not allowed at all a 'Not allowed resource types' policy is the durable control.",
        "Unregister the providers nobody needs (reversible; Azure refuses while resources exist).", (0.25, 1), 0.0, FREE,
        ("Resource providers and types", f"{_LEARN}/azure-resource-manager/management/resource-providers-and-types"),
        ("Resource providers for Azure services",
         f"{_LEARN}/azure-resource-manager/management/azure-services-resource-providers")),
    # Azure Policy (scanners/governance/policy_scanners.py)
    "no_policy_assignments": _g(
        "Nothing is assigned on the subscription or any management group above it, so no guardrail - allowed "
        "regions, required tags, diagnostics, security baseline - is evaluated or enforced.",
        "A short-lived sandbox subscription that is deleted on a schedule.",
        "Move the subscription under the management group that carries the baseline, or assign the baseline "
        "initiative to it; start in DoNotEnforce, review compliance, then enforce.", (2, 8), 0.0, FREE,
        ("Azure Policy overview", f"{_LEARN}/governance/policy/overview"),
        ("Management groups", f"{_LEARN}/governance/management-groups/overview")),
    "policy_assignments_not_enforced": _g(
        "DoNotEnforce only reports: Deny does not block and DeployIfNotExists / Modify do not deploy on new "
        "resources, so the guardrail exists on paper only.",
        "An agreed audit phase with a date to switch to enforcement.",
        "Review the non-compliant resources, exempt the justified ones with an expiry, then set the enforcement "
        "mode to Default.", (1, 4), 0.0, FREE,
        ("Assignment enforcement mode", f"{_LEARN}/governance/policy/concepts/assignment-structure#enforcement-mode")),
    "policy_exemption_no_expiry": _g(
        "An exemption without an expiry is an unbounded risk acceptance that nobody reviews again, while compliance "
        "still counts the resources as covered.",
        "A permanent, documented exception (e.g. a mitigated control) recorded with ticket and approver metadata.",
        "Set an expiry date of at most 12 months and record the ticket and approver in the metadata.", (0.25, 1),
        0.0, FREE,
        ("Exemption structure", f"{_LEARN}/governance/policy/concepts/exemption-structure")),
    "policy_exemption_expired": _g(
        "Expired exemptions no longer apply but stay in the estate and hide whether the risk was closed.",
        "Never - renew it if the exception is still approved.",
        "Delete the exemption, or renew it with a new expiry.", (0.25, 0.5), 0.0, FREE,
        ("Exemption structure", f"{_LEARN}/governance/policy/concepts/exemption-structure")),
    "policy_exemption_orphaned": _g(
        "The exemption points at an assignment that no longer exists: it does nothing today and silently applies "
        "again if an assignment with the same id comes back.",
        "Never.",
        "Delete it, or re-create it against the assignment that replaced the old one.", (0.25, 0.5), 0.0, FREE,
        ("Exemption structure", f"{_LEARN}/governance/policy/concepts/exemption-structure")),
    "policy_exemption_whole_initiative": _g(
        "Exempting a whole initiative switches off every control in it for that scope, including ones that have "
        "nothing to do with the original exception.",
        "The scope is being decommissioned and the exemption expires with it.",
        "Limit the exemption to the policy definition reference ids it is meant for.", (0.5, 2), 0.0, FREE,
        ("Exemption structure - policyDefinitionReferenceIds",
         f"{_LEARN}/governance/policy/concepts/exemption-structure")),
    "policy_remediation_never_run": _g(
        "DeployIfNotExists and Modify only act when a resource is created or updated; resources that existed "
        "before the assignment (or before a subscription tag changed) stay non-compliant until a remediation task "
        "runs.",
        "The assignment is still in an audit phase, or the deployment it would trigger is not yet approved.",
        "Check the assignment identity's roles, create a remediation task per policy (ReEvaluateCompliance) and "
        "review its deployments.", (1, 4), None,
        "Depends on what the policy deploys (e.g. diagnostic settings add Log Analytics ingestion); Modify (tags) "
        "is free.",
        ("Remediate non-compliant resources", f"{_LEARN}/governance/policy/how-to/remediate-resources")),
    "policy_definition_mode_skips_containers": _g(
        "Indexed mode only evaluates resource types that support tags and location; resource groups and "
        "subscriptions are never evaluated, so the policy has no effect on what it was written for.",
        "Never.",
        "Change the definition's mode to All (or split it: Indexed for resources, All for resource groups), then "
        "re-evaluate and remediate.", (1, 4), 0.0, FREE,
        ("Definition mode", f"{_LEARN}/governance/policy/concepts/definition-structure-basics#mode")),
    "allowed_locations_skip_resource_groups": _g(
        "'Allowed locations' is Indexed and ignores resource groups, so groups - and the metadata they hold - can "
        "be created in any region.",
        "Region is not a requirement for resource-group metadata in your organisation.",
        "Assign the built-in 'Allowed locations for resource groups' with the same list at the same scope, in "
        "audit first.", (0.5, 2), 0.0, FREE,
        ("Built-in policy definitions", f"{_LEARN}/governance/policy/samples/built-in-policies")),
    "resource_types_without_policy": _g(
        "No assignment has produced a compliance result for these types, so no guardrail (diagnostics, network "
        "exposure, encryption) applies to them.",
        "The types are short-lived or platform-managed and covered by other controls.",
        "Find the built-in policies or initiatives for the types (e.g. Microsoft cloud security benchmark) and "
        "assign them in audit.", (2, 8), 0.0, FREE,
        ("Built-in policy definitions", f"{_LEARN}/governance/policy/samples/built-in-policies")),
    "vm_required_extension_missing": _g(
        "Without the required agent the machine is outside monitoring, protection or backup coverage, and gaps "
        "stay invisible until an incident.",
        "The machine is deallocated for good or exempt by design (record a policy exemption).",
        "Install the extension, or let the DeployIfNotExists policy that installs it remediate the machine.",
        (0.25, 1), None, "Depends on the agent (e.g. data ingestion for monitoring agents).",
        ("Azure virtual machine extensions", f"{_LEARN}/virtual-machines/extensions/overview")),
    "vm_required_extension_failed": _g(
        "The extension is present but not provisioned, so the agent is not running.",
        "Never.",
        "Read the extension status message, fix the cause (network egress, agent version, OS support) and "
        "reinstall.", (0.5, 2), 0.0, FREE,
        ("Troubleshoot VM extensions", f"{_LEARN}/virtual-machines/extensions/troubleshoot")),
    # --- Cost / FinOps ---------------------------------------------------------------------------------------
    "budget_consistently_exceeded": _g(
        "A budget exceeded month after month is not a control: either the budget or the spend is wrong, and the "
        "alerts are ignored.",
        "Never; fix the budget amount or the spend.",
        "Agree the real baseline with the owner; set budgets per workload with owner contacts.", (1, 2), 0.0, FREE,
        ("Create and manage budgets", f"{_LEARN}/cost-management-billing/costs/tutorial-acm-create-budgets")),
    "budget_missing": _g(
        "Without a budget nobody is alerted when spend jumps.",
        "Subscriptions covered by a budget at a higher scope that includes their owners.",
        "Create a monthly budget with actual and forecast alerts to the owners.", (0.25, 0.5), 0.0, FREE,
        ("Create and manage budgets", f"{_LEARN}/cost-management-billing/costs/tutorial-acm-create-budgets")),
    "commitment_discount_opportunity": _g(
        "Steady usage paid at pay-as-you-go prices; a reservation or savings plan lowers the rate for the same usage.",
        "Usage that will be cleaned up or rightsized within the term - commit after waves 1 and 2.",
        "Buy the recommended reservation / savings plan for the stable baseline.", (1, 2), 0.0,
        "None - a commitment lowers the rate (saving shown separately), but it is a 1- or 3-year obligation.",
        ("Reservations", f"{_LEARN}/cost-management-billing/reservations/save-compute-costs-reservations"),
        ("Savings plan", f"{_LEARN}/cost-management-billing/savings-plan/savings-plan-overview")),
    "advisor_cost_recommendation": _g(
        "Azure Advisor measured the resource's usage and found capacity, cache or retention that is paid for but not "
        "used. For Data Explorer the hot cache drives the cluster size, so tables cached far longer than queries "
        "reach back are the main cost lever.",
        "Query patterns about to change (new dashboards over older data), seasonal peaks, or retention the business "
        "requires in the hot tier - Advisor only sees the last weeks of usage.",
        "Apply per table / resource. A Data Explorer cache policy is a management command without downtime (older "
        "queries become slower); the saving appears once optimized autoscale shrinks the cluster.", (1, 4), 0.0,
        "None - lowers cost (Advisor's saving, capped at the resource's own cost, is shown separately).",
        ("Advisor cost recommendations", f"{_LEARN}/advisor/advisor-cost-recommendations"),
        ("Data Explorer cache policy", "https://learn.microsoft.com/kusto/management/cache-policy"),
        ("Data Explorer optimized autoscale", f"{_LEARN}/data-explorer/manage-cluster-horizontal-scaling")),
    "service_retirement": _g(
        "Azure is retiring a feature, API version, SKU, VM series or runtime this resource still uses. After the date "
        "it stops working, stops being supported, or loses security fixes - an outage or audit finding with a known "
        "date.",
        "Resources that will be decommissioned before the retirement date (record it), or retirements Advisor still "
        "lists after the change was made (they clear within days).",
        "Upgrade the API version in templates / SDKs, move to the successor SKU or runtime, or migrate the workload; "
        "plan by date - overdue and next-90-days first.", (1, 16), None,
        "Depends on the successor - Advisor states the cost implication where it knows it.",
        ("Advisor service retirement workbook", f"{_LEARN}/advisor/advisor-workbook-service-retirement"),
        ("Azure updates - retirements", "https://azure.microsoft.com/updates/?updateType=retirements")),
    "idle_iot_hub": _g(
        "A paid IoT Hub tier bills per unit whether devices send messages or not.",
        "Hubs waiting for a device roll-out - downgrade to the free tier meanwhile.",
        "Confirm no devices depend on it, then delete (or downgrade).", (0.25, 0.5), 0.0, DELETE,
        ("Choose the right IoT Hub tier", f"{_LEARN}/iot-hub/iot-hub-scaling")),
    "marketplace_saas_unsubscribed": _g(
        "The SaaS subscription was cancelled; the leftover resource only causes confusion.",
        "Never needed.",
        "Delete the resource.", (0.1, 0.1), 0.0, FREE,
        ("SaaS subscription lifecycle", "https://learn.microsoft.com/marketplace/saas-subscription-lifecycle-management")),
    "marketplace_saas_inactive": _g(
        "The SaaS plan is suspended or was never activated, yet may be billed or block a renewal decision.",
        "Plans being activated right now.",
        "Activate it with the vendor or cancel it.", (0.5, 1), 0.0, "None - cancelling stops the charge.",
        ("SaaS subscription lifecycle", "https://learn.microsoft.com/marketplace/saas-subscription-lifecycle-management")),
    "marketplace_saas_term_ending": _g(
        "The term ends or auto-renews soon: decide before it renews for another full term.",
        "Plans the business has already decided to renew.",
        "Confirm the need and the seat count with the owner; switch off auto-renew if not needed.", (0.5, 1), 0.0,
        "None - avoids an unwanted renewal.",
        ("SaaS subscription lifecycle", "https://learn.microsoft.com/marketplace/saas-subscription-lifecycle-management")),
    "marketplace_saas_commitment": _g(
        "A material up-front SaaS commitment: make sure it is used and owned.",
        "Commitments already reviewed this term.",
        "Review usage and owner; plan the renewal decision.", (0.5, 1), 0.0, FREE,
        ("SaaS subscription lifecycle", "https://learn.microsoft.com/marketplace/saas-subscription-lifecycle-management")),
}


def _refs(refs) -> List[Dict[str, str]]:
    seen, out = set(), []
    for title, url in refs:
        if url and url not in seen:
            seen.add(url)
            out.append({"title": title, "url": url})
    return out


def _defender_items(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Per-recommendation guidance of a defender_recommendations finding: curated, else Microsoft's own text."""
    items = []
    for row in (finding.get("evidence") or {}).get("assessments") or []:
        name = row.get("assessment") or ""
        entry = (defender_guidance.by_key(row["guidance_key"]) if row.get("guidance_key")
                 else defender_guidance.match(name))
        label = row.get("label") or name
        links = [tuple(link) for link in row.get("ms_links") or []]
        portal = [("Open in Defender for Cloud", row["portal"])] if row.get("portal") else []
        if entry:
            g = entry.guidance
            items.append({"label": label, "source": "curated", "why": g.why, "skip_when": g.skip_when,
                          "effort": g.effort, "hours": list(g.hours), "monthly_usd": g.monthly_usd,
                          "run_cost": g.run_cost, "references": _refs(list(g.references) + links + portal)})
        else:
            effort = (row.get("effort") or "").lower()
            hours = {"low": (0.25, 1.0), "moderate": (1.0, 4.0), "high": (4.0, 16.0)}.get(effort, (0.5, 4.0))
            items.append({
                "label": label, "source": "microsoft",
                "why": row.get("ms_description") or f"Defender for Cloud recommendation: {name}.",
                "skip_when": ("Resources outside the recommendation's intent (test, short-lived, compensating control) "
                              "- record an exemption in Defender with the reason."),
                "effort": f"Microsoft rates the implementation effort {effort or 'unknown'}"
                          + (f" and the user impact {row['user_impact'].lower()}" if row.get("user_impact") else "")
                          + ".",
                "hours": list(hours), "monthly_usd": None,
                "run_cost": "Depends on the change - see Microsoft's remediation steps.",
                "references": _refs(links + portal)})
    return items


def implementation_analysis(finding: Dict[str, Any], *, resource_monthly_usd: Optional[float] = None,
                            hourly_rate_usd: Optional[float] = None) -> Dict[str, Any]:
    """
    Why the finding matters, when it does not, and what acting on it costs.

    resource_monthly_usd: the affected resource's current monthly cost in USD, when known - turns a cost_factor
    ("one more instance") into an amount. hourly_rate_usd: engineering rate, when configured - turns the effort
    hours into a one-off amount.
    """
    ftype = finding.get("finding_type") or ""
    evidence = finding.get("evidence") or {}
    saving = finding.get("estimated_monthly_savings_usd") or 0.0
    items: List[Dict[str, Any]] = []

    if ftype == "defender_recommendations" and evidence.get("assessments"):
        items = _defender_items(finding)
        known = [i["monthly_usd"] for i in items if i["monthly_usd"] is not None]
        result = {
            "source": "defender",
            "why": " ".join(f"{i['label'].rstrip('.')}: {i['why']}" for i in items) if len(items) > 1
            else items[0]["why"],
            "skip_when": " ".join(f"{i['label'].rstrip('.')}: {i['skip_when']}" for i in items) if len(items) > 1
            else items[0]["skip_when"],
            "effort": " ".join(f"{i['label'].rstrip('.')}: {i['effort']}" for i in items) if len(items) > 1
            else items[0]["effort"],
            "hours": [round(sum(i["hours"][0] for i in items), 2), round(sum(i["hours"][1] for i in items), 2)],
            "monthly_usd": round(sum(known), 2) if len(known) == len(items) else (round(sum(known), 2) or None),
            "run_cost": " ".join(f"{i['label'].rstrip('.')}: {i['run_cost']}" for i in items) if len(items) > 1
            else items[0]["run_cost"],
            "references": _refs([(r["title"], r["url"]) for i in items for r in i["references"]]),
            "partial_cost": len(known) != len(items),
        }
    else:
        g = GUIDANCE.get(ftype)
        if g is None:
            result = {"source": "generic", "why": finding.get("description") or "", "skip_when": "",
                      "effort": "", "hours": None, "monthly_usd": None,
                      "run_cost": "Not estimated for this finding type.", "references": [], "partial_cost": False}
        else:
            monthly = g.monthly_usd
            run_cost = g.run_cost
            if monthly is None and g.cost_factor is not None and resource_monthly_usd:
                monthly = round(resource_monthly_usd * g.cost_factor, 2)
                run_cost += (f" Based on this resource's current cost: about USD {monthly:,.2f}/month.")
            result = {"source": "curated", "why": g.why, "skip_when": g.skip_when, "effort": g.effort,
                      "hours": list(g.hours), "monthly_usd": monthly, "run_cost": run_cost,
                      "references": _refs(g.references), "partial_cost": False}

    included = False
    scanner_cost = evidence.get("cost_of_change")
    if isinstance(scanner_cost, dict) and scanner_cost.get("monthly_usd") is not None:
        result["monthly_usd"] = round(float(scanner_cost["monthly_usd"]), 2)
        result["run_cost"] = (f"About USD {result['monthly_usd']:,.2f}/month: {scanner_cost.get('basis')}."
                              if result["monthly_usd"] else f"No run-cost change ({scanner_cost.get('basis')}).")
        included = bool(scanner_cost.get("included_in_saving"))

    decision = evidence.get("access_decision")
    if isinstance(decision, dict) and decision.get("option"):
        # open PaaS endpoints: the control fitted to how the resource is used, and what else was considered
        result["effort"] = f"{decision['title']}. {result.get('effort') or ''}".strip()
        result["hours"] = list(decision.get("hours") or result.get("hours") or []) or None
        result["decision"] = {"option": decision["option"], "title": decision["title"], "why": decision.get("why"),
                              "monthly_usd": decision.get("monthly_usd")}
        result["options"] = decision.get("alternatives") or []

    monthly = result.get("monthly_usd")
    result["saving_usd"] = round(saving, 2) if saving else None
    result["net_monthly_usd"] = ((round(saving if included else saving - monthly, 2) if monthly is not None
                                  else round(saving, 2)) if saving else None)
    result["cost_included_in_saving"] = included
    hours = result.get("hours")
    result["one_off_usd"] = ([round(hours[0] * hourly_rate_usd), round(hours[1] * hourly_rate_usd)]
                             if hours and hourly_rate_usd else None)
    result["story_points"] = (story_points(hours) or {}).get("points")
    result["effort_estimate"] = effort_label(hours)
    result["prices_as_of"] = PRICES_AS_OF
    if items:
        result["items"] = items
    return result


def cost_summary(analysis: Dict[str, Any]) -> str:
    """One line: Azure run-cost change and effort, e.g. '+USD 7.30/month · 1 SP (4h / 0.5 days / 0.03 sprints)
    (generic estimate)'."""
    monthly = analysis.get("monthly_usd")
    if monthly is None:
        run = "run cost: usage-based"
    elif monthly == 0:
        run = "no extra run cost"
    else:
        run = f"+USD {monthly:,.2f}/month" + (" (in saving)" if analysis.get("cost_included_in_saving") else "")
    effort = effort_label(analysis.get("hours"))
    if analysis.get("one_off_usd"):
        effort += f" (≈ USD {analysis['one_off_usd'][0]:,}-{analysis['one_off_usd'][1]:,})"
    return " · ".join(x for x in (run, effort) if x)


# The team's story-point scale: points -> hours, days and sprints. Effort is planned in these points - a generic
# estimate of the size of the change, not hours anyone measured.
STORY_POINTS = (
    (1, 4, "0.5 days", "0.03 sprints"), (2, 8, "1 day", "0.07 sprints"), (3, 12, "1.5 days", "0.10 sprints"),
    (5, 20, "2.5 days", "0.17 sprints"), (8, 32, "4 days", "0.27 sprints"), (13, 52, "6.5 days", "0.43 sprints"),
    (21, 84, "10.5 days", "0.70 sprints"), (55, 220, "27.5 days", "2.75 sprints"), (89, 356, "44.5 days", "4.45 sprints"),
)
HOURS_PER_POINT = 4
SPRINT_DAYS = 15        # sprints of a total: the scale's 1-21 point rows (e.g. 10.5 days = 0.70 sprints)
GENERIC_ESTIMATE = "(generic estimate)"


def story_points(hours: Any) -> Optional[Dict[str, Any]]:
    """The point on the scale an effort is planned at: the smallest that covers its upper hour estimate."""
    if not hours:
        return None
    high = float(hours[-1] if isinstance(hours, (list, tuple)) else hours)
    for points, scale_hours, days, sprints in STORY_POINTS:
        if high <= scale_hours:
            return {"points": points, "hours": scale_hours, "days": days, "sprints": sprints, "more": False}
    points, scale_hours, days, sprints = STORY_POINTS[-1]
    return {"points": points, "hours": scale_hours, "days": days, "sprints": sprints, "more": True}


def effort_label(hours: Any) -> str:
    """'3 SP (12h / 1.5 days / 0.10 sprints) (generic estimate)'; '' when the effort is unknown."""
    sp = story_points(hours)
    if not sp:
        return ""
    more = "+" if sp["more"] else ""
    return f"{sp['points']}{more} SP ({sp['hours']}h{more} / {sp['days']} / {sp['sprints']}) {GENERIC_ESTIMATE}"


def total_effort_label(efforts: Iterable[Any]) -> str:
    """The story points of several changes added up - each planned on the scale first - with the duration they stand
    for: '34 SP (136h / 17 days / 1.13 sprints) (generic estimate)'."""
    total = sum(sp["points"] for sp in (story_points(h) for h in efforts) if sp)
    if not total:
        return ""
    days = total * HOURS_PER_POINT / 8
    return (f"{total} SP ({total * HOURS_PER_POINT:,}h / {days:g} days / {days / SPRINT_DAYS:.2f} sprints) "
            f"{GENERIC_ESTIMATE}")
