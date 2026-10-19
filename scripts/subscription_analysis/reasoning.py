"""
Built-in reasoning ("thinking mode", always on): how ARG arrived at a recommendation, from this finding's own
evidence - not a generic checklist.

reason(finding) returns
- observed:    the facts read from Azure for this resource (values, not categories);
- context:     what changes the answer here (environment, related findings on the resource, prerequisites);
- considered:  every option with its role (target / interim / alternative / not suitable) and why;
- recommendation and sequence: what to do, in which order;
- risks:       what can break, specific to the finding type;
- verify:      how to check the fix worked (commands and metrics);
- confidence:  how sure the analysis is, and why.

It runs wherever a finding is shown: the markdown report (deep dives, raw/findings.json), the Docker API's finding
detail and the cloud analysis report. The optional AI review (thinking.py) reads this reasoning and challenges it.
"""

from typing import Any, Dict, List, Optional

from scripts.subscription_analysis.guidance import implementation_analysis

# evidence keys that are bookkeeping, not facts about the resource
SKIP_KEYS = {"cost_of_change", "access_decision", "assessments", "verified", "guidance_key", "saving_basis",
             "transactions_by_api", "rules", "disabled_plans", "deployments", "items", "recommendations"}
LABELS = {
    "data_operations_30d": "data reads / writes in 30 days", "transactions_30d": "transactions in 30 days",
    "used_capacity_gb": "data stored (GB)", "requests_30d": "requests in 30 days", "cpu": "average CPU % (30 days)",
    "cpu95": "CPU P95 %", "cpu_max": "peak CPU %", "mem": "memory used %", "instances": "instances",
    "sites": "apps on the plan", "publicNetworkAccess": "public network access", "defaultAction": "firewall default",
    "public_network_access": "public network access", "production": "production", "sku": "SKU",
    "current_sku": "current SKU", "recommended_sku": "recommended SKU", "kind": "kind", "access_tier": "access tier",
    "days_deallocated": "days deallocated", "power_state": "power state", "disk_size_gb": "disk size (GB)",
    "days_unattached": "days unattached", "retirement_date": "retirement date", "days_left": "days left",
    "cost_30d": "cost, 30 days", "cost_usd_30d": "cost, 30 days (USD)", "zone_redundant": "zone redundant",
    "allowSharedKeyAccess": "shared-key access", "enableRbacAuthorization": "RBAC authorisation",
    "resource_type": "resource type",
}

# Finding-type knowledge: what can break, and how to verify the fix. {name} {rg} {id} {sub} are filled in.
KNOWLEDGE: Dict[str, Dict[str, List[str]]] = {
    "storage_public_network_access": {
        "risks": ["Callers without a private path (multi-tenant services such as Power BI, Logic Apps Consumption, "
                  "Azure DevOps hosted agents) lose access when public access is switched off.",
                  "A private endpoint without the DNS zone link resolves to the public IP and fails closed."],
        "verify": ["az storage account show -n {name} -g {rg} --query \"{{public:publicNetworkAccess, "
                   "acl:networkRuleSet.defaultAction, pe:length(privateEndpointConnections)}}\"",
                   "Storage Insights - Transactions split by ResponseType: no AuthorizationFailure / NetworkError "
                   "for 24 h after the change."]},
    "key_vault_public_network_open": {
        "risks": ["Apps that read secrets at start-up (App Service Key Vault references, AKS CSI driver) fail to "
                  "start without a private path or VNet rule.",
                  "Azure DevOps / GitHub hosted runners lose access - use self-hosted agents in the VNet."],
        "verify": ["az keyvault show -n {name} --query \"properties.{{public:publicNetworkAccess, "
                   "acl:networkAcls.defaultAction}}\"",
                   "Key Vault metrics - ServiceApiResult by StatusCode: no 403 for 24 h after the change."]},
    "public_sql_server": {
        "risks": ["Clients with hard-coded public IPs in firewall rules lose access once public access is off.",
                  "Connection strings must keep the server FQDN so DNS can resolve the private IP."],
        "verify": ["az sql server show -n {name} -g {rg} --query publicNetworkAccess",
                   "Azure SQL metrics - connection_failed and blocked_by_firewall stay at 0 after the change."]},
    "sql_firewall_allow_all_azure_services": {
        "risks": ["Azure services without a fixed IP or VNet path (Logic Apps Consumption, Power BI) lose access - "
                  "list them before removing the 0.0.0.0 rule."],
        "verify": ["az sql server firewall-rule list -g {rg} -s {name} -o table   # no 0.0.0.0 rule left"]},
    "cosmos_public_network_access": {
        "risks": ["The Azure portal Data Explorer needs an IP rule or the 'Accept connections from within public "
                  "Azure datacenters' option once the firewall is on."],
        "verify": ["az cosmosdb show -n {name} -g {rg} --query \"{{public:publicNetworkAccess, ip:ipRules, "
                   "vnet:isVirtualNetworkFilterEnabled}}\""]},
    "ai_services_public_network_open": {
        "risks": ["AI Foundry projects, prompt flows and agents that call the account from managed compute need a "
                  "managed private endpoint first."],
        "verify": ["az cognitiveservices account show -n {name} -g {rg} --query \"properties.{{public:"
                   "publicNetworkAccess, acl:networkAcls.defaultAction}}\""]},
    "storage_shared_key_access_enabled": {
        "risks": ["Clients still using account keys or SAS signed with a key (older SDKs, AzCopy scripts, Azure "
                  "Files SMB with keys, Function apps' AzureWebJobsStorage) fail."],
        "verify": ["Storage Insights - Transactions split by Authentication: SAS / AccountKey = 0 for 7 days BEFORE "
                   "switching it off.",
                   "az storage account show -n {name} -g {rg} --query allowSharedKeyAccess"]},
    "storage_blob_soft_delete_disabled": {
        "risks": ["Soft-deleted data is billed until it expires - high-churn accounts pay for every overwrite."],
        "verify": ["az storage account blob-service-properties show --account-name {name} -g {rg} "
                   "--query deleteRetentionPolicy"]},
    "dormant_storage_data": {
        "risks": ["Archive tier needs hours of rehydration and has early-deletion charges (180 days); Cold has 90.",
                  "A process that reads once a quarter or year (audit, restore test) may not show in 30 days."],
        "verify": ["Storage Insights - Transactions by API over 90 days before tiering.",
                   "az storage account show -n {name} -g {rg} --query accessTier"]},
    "unused_storage_account": {
        "risks": ["Deletion is permanent once soft delete of the account (14 days, if enabled) has passed - "
                  "export or snapshot what may be needed."],
        "verify": ["az storage container list --account-name {name} --auth-mode login -o table   # empty?",
                   "Storage Insights - zero data operations over 90 days."]},
    "deallocated_virtual_machine": {
        "risks": ["Disks, snapshots and public IPs keep billing while the VM is deallocated.",
                  "Deleting the VM leaves its disks and NIC behind unless they are deleted too; snapshot the OS "
                  "disk first if the system may be needed again."],
        "verify": ["az vm get-instance-view -g {rg} -n {name} --query \"instanceView.statuses[1].code\"",
                   "Activity log - last Start / Deallocate operation on the VM (how long it has been off)."]},
    "vm_rightsizing_opportunity": {
        "risks": ["Resizing restarts the VM (minutes of downtime) and the target size must be available in the "
                  "zone / host group.",
                  "Memory, disk IOPS and network limits of the smaller size matter as much as CPU."],
        "verify": ["Azure Monitor - CPU and memory P95 below 80 % for 7 days after the resize.",
                   "az vm show -g {rg} -n {name} --query hardwareProfile.vmSize"]},
    "vm_unsupported_os": {
        "risks": ["An in-place OS upgrade can break the workload; rebuilding on a supported image is usually safer.",
                  "No security updates are published for the current OS."],
        "verify": ["az vm get-instance-view -g {rg} -n {name} --query \"instanceView.{{os:osName, "
                   "version:osVersion}}\""]},
    "unattached_managed_disk": {
        "risks": ["The disk may be the only copy of a deleted VM's data - snapshot it (cheaper, incremental) "
                  "before deleting if in doubt."],
        "verify": ["az disk show -g {rg} -n {name} --query \"{{state:diskState, owner:managedBy}}\""]},
    "old_disk_snapshot": {
        "risks": ["A snapshot may be the only restore point outside Azure Backup."],
        "verify": ["az snapshot show -g {rg} -n {name} --query \"{{created:timeCreated, source:"
                   "creationData.sourceResourceId}}\""]},
    "unused_public_ip": {
        "risks": ["Partners may allow-list the address; DNS records may still point at it - a deleted Standard IP "
                  "cannot be recovered."],
        "verify": ["az network public-ip show -g {rg} -n {name} --query \"{{ip:ipAddress, attached:"
                   "ipConfiguration.id}}\""]},
    "nsg_management_port_open_to_internet": {
        "risks": ["Admins lose their current RDP / SSH path - Bastion (or JIT) must work before the rule goes."],
        "verify": ["az network nsg rule list -g {rg} --nsg-name {name} --query \"[?access=='Allow' && "
                   "direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet')]\" -o table"]},
    "vm_public_ip_bypasses_bastion": {
        "risks": ["Outbound traffic of the VM changes source IP once the public IP is removed (allow-lists at "
                  "partners); a NAT gateway or the hub firewall must provide outbound access."],
        "verify": ["az vm list-ip-addresses -g {rg} -n {name} -o table"]},
    "subnet_without_nsg": {
        "risks": ["An NSG with a default deny on a subnet in use cuts traffic - start with allow rules that "
                  "mirror today's flows (VNet flow logs show them)."],
        "verify": ["az network vnet subnet show --ids {id} --query networkSecurityGroup.id"]},
    "missing_diagnostic_settings": {
        "risks": ["Verbose categories (allLogs on App Service, AKS) can ingest GBs per day - start with the audit "
                  "category group."],
        "verify": ["az monitor diagnostic-settings list --resource {id} -o table"]},
    "app_service_plan_single_instance": {
        "risks": ["A second instance doubles the plan's compute cost; apps that keep state in memory or on the "
                  "local disk need sticky sessions or external state first."],
        "verify": ["az appservice plan show -g {rg} -n {name} --query \"{{sku:sku.name, workers:sku.capacity, "
                   "zoneRedundant:properties.zoneRedundant}}\""]},
    "app_service_plan_underutilized": {
        "risks": ["Scaling in removes headroom for peaks that the 30-day window may not contain (month end, "
                  "releases)."],
        "verify": ["App Service plan metrics - CPU and memory P95 after the change below 70 %."]},
    "ai_spend_without_gateway": {
        "risks": ["A gateway adds a hop (a few ms) and must be scaled for the token rate; clients change their "
                  "endpoint and authentication."],
        "verify": ["API Management analytics - tokens per subscription / app after the rollout.",
                   "Cost Management - AI spend by tag / meter after chargeback starts."]},
    "ai_services_local_auth_enabled": {
        "risks": ["Clients using API keys fail once local auth is off - move them to managed identities first."],
        "verify": ["az cognitiveservices account show -n {name} -g {rg} --query properties.disableLocalAuth"]},
    "key_vault_access_policy_model": {
        "risks": ["Switching the permission model ignores existing access policies immediately - create the "
                  "equivalent RBAC role assignments first."],
        "verify": ["az role assignment list --scope {id} -o table"]},
    "key_vault_purge_protection_disabled": {
        "risks": ["Purge protection cannot be switched off again; deleted vault names stay reserved for the "
                  "retention period."],
        "verify": ["az keyvault show -n {name} --query properties.enablePurgeProtection"]},
    "web_app_https_not_enforced": {
        "risks": ["Clients calling http:// get a redirect; machine clients that do not follow redirects fail."],
        "verify": ["az webapp show -g {rg} -n {name} --query httpsOnly"]},
    "web_app_weak_tls": {
        "risks": ["Old clients (TLS 1.0/1.1 only) can no longer connect."],
        "verify": ["az webapp config show -g {rg} -n {name} --query minTlsVersion"]},
    "web_app_ftp_enabled": {
        "risks": ["Deployment pipelines still using FTP fail - move them to zip deploy / run-from-package."],
        "verify": ["az webapp config show -g {rg} -n {name} --query ftpsState"]},
    "web_app_eol_runtime": {
        "risks": ["A runtime upgrade can change behaviour - test in a deployment slot before swapping."],
        "verify": ["az webapp config show -g {rg} -n {name} --query \"{{linux:linuxFxVersion, "
                   "net:netFrameworkVersion}}\""]},
    "sql_entra_only_auth_disabled": {
        "risks": ["Applications using SQL logins fail once Entra-only authentication is on - move them to "
                  "managed identities first."],
        "verify": ["az sql server ad-only-auth get -g {rg} -n {name}"]},
    "service_retirement": {
        "risks": ["After the retirement date the feature stops working or is migrated by Microsoft on its own "
                  "terms."],
        "verify": ["Azure Advisor - the retirement recommendation for the resource is gone."]},
    "advisor_cost_recommendation": {
        "risks": ["Advisor's saving assumes the recent usage pattern continues."],
        "verify": ["Azure Advisor - the cost recommendation is resolved; Cost Management shows the lower run rate "
                   "after a full billing cycle."]},
    "commitment_discount_opportunity": {
        "risks": ["A reservation / savings plan is a 1- or 3-year commitment - buy for the steady-state baseline "
                  "after rightsizing, not for peaks."],
        "verify": ["Cost Management - Reservations utilisation above 95 % after the first month."]},
    "mfa_not_enabled": {
        "risks": ["Users without registered methods are locked out - run a registration campaign first."],
        "verify": ["Entra ID - Authentication methods activity: the user has a registered strong method; sign-in "
                   "logs show MFA satisfied."]},
    "excessive_subscription_owners": {
        "risks": ["Removing Owner from automation identities breaks pipelines that create role assignments."],
        "verify": ["az role assignment list --scope /subscriptions/{sub} --role Owner -o table"]},
}

MEASURED_KEYS = {"data_operations_30d", "transactions_30d", "requests_30d", "cpu", "cpu95", "mem", "used_capacity_gb",
                 "cost_30d", "cost_usd_30d", "days_deallocated", "days_unattached"}


def _fmt(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:,.2f}".rstrip("0").rstrip(".") if abs(value) < 1000 else f"{value:,.0f}"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, (list, tuple)):
        items = [_fmt(v) for v in value if not isinstance(v, (dict, list))]
        return ", ".join(items[:5]) + (f" (+{len(items) - 5})" if len(items) > 5 else "") if items else ""
    if isinstance(value, dict):
        pairs = [f"{k}={_fmt(v)}" for k, v in value.items() if not isinstance(v, (dict, list))][:4]
        return ", ".join(pairs)
    text = str(value)
    return text if len(text) <= 160 else text[:157] + "…"


def observed_facts(finding: Dict[str, Any]) -> List[str]:
    """The facts read from Azure for this resource - evidence values with readable labels."""
    facts = []
    if finding.get("resource_name") or finding.get("resource_id"):
        name = finding.get("resource_name") or (finding.get("resource_id") or "").rstrip("/").split("/")[-1]
        rtype = finding.get("resource_type") or ""
        where = " · ".join(x for x in (finding.get("resource_group") and f"resource group {finding['resource_group']}",
                                       finding.get("location")) if x)
        facts.append(f"{name}" + (f" ({rtype})" if rtype else "") + (f" - {where}" if where else ""))
    evidence = finding.get("evidence") or {}
    decision = evidence.get("access_decision") or {}
    for key, value in evidence.items():
        if key in SKIP_KEYS or value in (None, "", [], {}):
            continue
        text = _fmt(value)
        if text:
            facts.append(f"{LABELS.get(key, key.replace('_', ' '))}: {text}")
    if decision:
        signals = decision.get("signals") or {}
        facts.append(f"usage: {decision.get('usage')}")
        if signals.get("integrated_apps"):
            facts.append("VNet-integrated apps in the region: " + ", ".join(signals["integrated_apps"][:5]))
        facts.append("private endpoints already used for this service here: "
                     + ("yes" if signals.get("pe_standard") else "no"))
        if signals.get("dns_zone_exists") is not None:
            facts.append(f"{decision.get('dns_zone')} zone in the tenant: "
                         + ("yes" if signals.get("dns_zone_exists") else "no"))
        if signals.get("onprem"):
            facts.append("on-premises connectivity: yes (VPN / ExpressRoute gateway or hub gateway transit)")
        if signals.get("sensitive"):
            facts.append(f"confidential-data tag: {signals['sensitive']}")
    return facts[:14]


def _environment(finding: Dict[str, Any]) -> Optional[str]:
    evidence = finding.get("evidence") or {}
    production = evidence.get("production")
    if not isinstance(production, bool):   # some findings use "production" for a list of apps
        production = ((evidence.get("access_decision") or {}).get("signals") or {}).get("production")
    return {True: "production", False: "non-production"}.get(production) if isinstance(production, bool) else None


def _confidence(finding: Dict[str, Any]) -> Dict[str, str]:
    evidence = finding.get("evidence") or {}
    title = finding.get("title") or ""
    measured = sorted(k for k in MEASURED_KEYS if evidence.get(k) is not None)
    decision = evidence.get("access_decision") or {}
    if decision and (decision.get("signals") or {}).get("data_operations_30d") is not None             and "data_operations_30d" not in measured:
        measured.append(decision.get("usage") or "usage over 30 days")
    if title.startswith("Verify") or evidence.get("verified") is False:
        return {"level": "low", "why": "The condition could not be confirmed from Azure (no access to the "
                                       "setting or metric) - verify it before acting."}
    if measured:
        return {"level": "high", "why": "Based on the configuration read from Azure and measured usage ("
                                        + ", ".join(LABELS.get(k, k) for k in measured[:3]) + ")."}
    if finding.get("finding_type") in ("advisor_cost_recommendation", "service_retirement"):
        return {"level": "high", "why": "Reported by Azure Advisor for this resource."}
    return {"level": "medium", "why": "The configuration is certain (read from Azure); whether the change fits "
                                      "depends on the owner's intent, which Azure does not record."}


def reason(finding: Dict[str, Any], related: Optional[List[str]] = None,
           implementation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """How ARG reasoned about one finding. `related`: titles of other findings on the same resource."""
    impl = implementation or implementation_analysis(finding)
    evidence = finding.get("evidence") or {}
    decision = evidence.get("access_decision") or {}
    ftype = finding.get("finding_type") or ""
    rid = finding.get("resource_id") or ""
    parts = rid.split("/")
    fill = {"name": finding.get("resource_name") or (parts[-1] if parts else "<name>"),
            "rg": finding.get("resource_group") or (parts[4] if len(parts) > 4 else "<rg>"),
            "id": rid or "<resource-id>", "sub": finding.get("subscription_id") or (parts[2] if len(parts) > 2
                                                                                     else "<subscription>")}
    knowledge = KNOWLEDGE.get(ftype) or {}

    context = []
    env = _environment(finding)
    if env:
        context.append(f"Environment: {env}.")
    for p in decision.get("prerequisites") or []:
        context.append(f"Prerequisite for the target: {p}.")
    if related:
        context.append("Also reported on this resource: " + "; ".join(related[:5]) + ".")
    if impl.get("skip_when"):
        context.append(f"Not needed when: {impl['skip_when']}")

    considered = []
    for option in decision.get("alternatives") or impl.get("options") or []:
        considered.append({"option": option.get("title"), "role": option.get("role") or
                           ("target" if option.get("chosen") else "alternative" if option.get("fits") else
                            "not suitable"),
                           "run_cost": option.get("monthly_usd"), "exposure_after": option.get("exposure_after"),
                           "why": option.get("note") or ""})
    if not considered and impl.get("why"):
        considered.append({"option": (impl.get("effort") or "Apply the remediation").split(".")[0],
                           "role": "target", "run_cost": impl.get("monthly_usd"), "why": impl["why"]})
        if impl.get("skip_when"):
            considered.append({"option": "Leave as is", "role": "alternative", "run_cost": 0.0,
                               "why": f"Only when: {impl['skip_when']}"})

    steps = [line.strip() for line in (finding.get("remediation_steps") or "").splitlines() if line.strip()]
    recommendation = ((decision.get("why") if decision else None) or impl.get("effort")
                      or (steps[0] if steps else ""))
    risks = list(knowledge.get("risks") or [])
    if impl.get("monthly_usd"):
        risks.append(f"Adds about USD {impl['monthly_usd']:,.2f}/month of Azure run cost.")
    if not risks:
        risks.append("Check with the resource owner that no process depends on the current configuration - Azure "
                     "does not record intent.")
    verify = [v.format(**fill) for v in knowledge.get("verify") or []]
    if not verify:
        verify.append(f"Re-run the analysis: finding `{ftype}` closes on {fill['name']} once the change is in place.")
    return {"observed": observed_facts(finding), "context": context, "considered": considered,
            "recommendation": recommendation, "sequence": steps[:10], "risks": risks, "verify": verify,
            "confidence": _confidence(finding)}


def markdown(r: Dict[str, Any]) -> List[str]:
    """The reasoning as markdown for the deep dives."""
    lines = ["", "**How ARG reasoned**", ""]
    if r.get("observed"):
        lines += ["*Observed*", ""] + [f"- {x}" for x in r["observed"]] + [""]
    if r.get("context"):
        lines += ["*What changes the answer here*", ""] + [f"- {x}" for x in r["context"]] + [""]
    if r.get("considered"):
        lines += ["*Options considered*", "", "| Role | Option | Run cost | Remaining exposure | Why |",
                  "|---|---|---:|---|---|"]
        for c in r["considered"]:
            cost = "free" if not c.get("run_cost") else f"USD {c['run_cost']:,.2f}/month"
            role = f"**{c['role']}**" if c.get("role") in ("target", "interim") else c.get("role") or ""
            lines.append(f"| {role} | {c.get('option') or ''} | {cost} | {c.get('exposure_after') or ''} | "
                         f"{(c.get('why') or '').replace('|', '/')} |")
        lines.append("")
    if r.get("recommendation"):
        lines += ["*Recommendation*", "", r["recommendation"], ""]
    if r.get("risks"):
        lines += ["*Risks*", ""] + [f"- {x}" for x in r["risks"]] + [""]
    if r.get("verify"):
        lines += ["*How to verify*", ""] + [f"- `{x}`" if x.startswith("az ") else f"- {x}" for x in r["verify"]] + [""]
    conf = r.get("confidence") or {}
    if conf:
        lines += [f"*Confidence: {conf.get('level')}* - {conf.get('why')}", ""]
    return lines
