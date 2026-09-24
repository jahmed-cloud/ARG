"""
Static knowledge used to turn scanner findings into a review report:
which gap area / deep-dive folder / savings wave a finding belongs to,
and the architectural critique text for each design decision a set of
findings points at. Kept as data so new scanners only need a row here.
"""

from typing import Dict, List, NamedTuple, Optional

AREAS = [
    "Structural / Architecture",
    "Security & Identity",
    "Operational / Observability",
    "Performance & Resilience",
    "FinOps / Governance",
]
STRUCTURAL, SECURITY, OPERATIONAL, PERFORMANCE, FINOPS = AREAS

DEEP_DIVE_FOLDERS = {
    "networking": "Networking — VNets, NICs, public IPs, NSGs, DDoS, Bastion, DNS",
    "compute-appservice": "Compute & App Service — VMs, plans, sites, runtime configuration",
    "data-sql-storage": "Data platform — SQL, storage accounts, Cosmos DB",
    "ai-foundry": "AI — Foundry / Azure OpenAI accounts, deployments, spend",
    "security-identity": "Security & identity — Defender, RBAC, Key Vault, Entra ID",
    "observability-operations": "Observability, operations & governance — logs, alerts, tags, naming",
    "cost-finops": "Cost & FinOps — budgets, commitments, idle services",
}

WAVE_NO_REGRET, WAVE_OPTIMISE, WAVE_STRUCTURAL = 1, 2, 3
WAVE_NAMES = {
    WAVE_NO_REGRET: "Wave 1 — No-regret cleanup",
    WAVE_OPTIMISE: "Wave 2 — Optimisation",
    WAVE_STRUCTURAL: "Wave 3 — Structural",
}


class Classification(NamedTuple):
    area: str
    folder: str
    wave: int = WAVE_STRUCTURAL
    critique: Optional[str] = None


FINDING_CLASSIFICATION: Dict[str, Classification] = {
    # Network
    "unused_ddos_protection_plan": Classification(FINOPS, "networking", WAVE_NO_REGRET, "ddos"),
    "orphaned_nsg": Classification(FINOPS, "networking", WAVE_NO_REGRET),
    "orphaned_nic": Classification(FINOPS, "networking", WAVE_NO_REGRET),
    "unused_public_ip": Classification(FINOPS, "networking", WAVE_NO_REGRET),
    "public_ip_on_orphaned_nic": Classification(FINOPS, "networking", WAVE_NO_REGRET),
    "empty_load_balancer": Classification(FINOPS, "networking", WAVE_NO_REGRET),
    "empty_application_gateway": Classification(FINOPS, "networking", WAVE_NO_REGRET),
    "private_dns_zone_without_endpoints": Classification(STRUCTURAL, "networking", WAVE_NO_REGRET, "network"),
    "subnet_without_nsg": Classification(STRUCTURAL, "networking", WAVE_STRUCTURAL, "network"),
    "nsg_management_port_open_to_internet": Classification(SECURITY, "networking", WAVE_NO_REGRET, "jumphost"),
    "vm_public_ip_bypasses_bastion": Classification(SECURITY, "networking", WAVE_NO_REGRET, "jumphost"),
    # Compute / App Service
    "vm_unsupported_os": Classification(SECURITY, "compute-appservice", WAVE_NO_REGRET, "jumphost"),
    "managed_disk_public_network_access": Classification(SECURITY, "compute-appservice", WAVE_NO_REGRET),
    "unattached_managed_disk": Classification(FINOPS, "compute-appservice", WAVE_NO_REGRET),
    "old_disk_snapshot": Classification(FINOPS, "compute-appservice", WAVE_NO_REGRET),
    "deallocated_virtual_machine": Classification(FINOPS, "compute-appservice", WAVE_NO_REGRET),
    "idle_vmss": Classification(FINOPS, "compute-appservice", WAVE_NO_REGRET),
    "app_service_plan_previous_generation": Classification(FINOPS, "compute-appservice", WAVE_OPTIMISE, "appservice"),
    "app_service_plan_single_instance": Classification(PERFORMANCE, "compute-appservice", WAVE_OPTIMISE, "appservice"),
    "app_service_plan_cpu_saturated": Classification(PERFORMANCE, "compute-appservice", WAVE_OPTIMISE, "appservice"),
    "app_service_plan_mixed_environments": Classification(STRUCTURAL, "compute-appservice", WAVE_OPTIMISE, "appservice"),
    "web_app_https_not_enforced": Classification(SECURITY, "compute-appservice", WAVE_NO_REGRET),
    "web_app_managed_identity_missing": Classification(SECURITY, "compute-appservice", WAVE_OPTIMISE, "datapath"),
    "web_app_eol_runtime": Classification(SECURITY, "compute-appservice", WAVE_OPTIMISE),
    "web_app_weak_tls": Classification(SECURITY, "compute-appservice", WAVE_NO_REGRET),
    "web_app_ftp_enabled": Classification(SECURITY, "compute-appservice", WAVE_NO_REGRET),
    "web_app_health_check_missing": Classification(OPERATIONAL, "compute-appservice", WAVE_OPTIMISE),
    "web_app_32bit_worker": Classification(PERFORMANCE, "compute-appservice", WAVE_OPTIMISE),
    # Data
    "public_sql_server": Classification(SECURITY, "data-sql-storage", WAVE_OPTIMISE, "datapath"),
    "sql_firewall_allow_all_azure_services": Classification(SECURITY, "data-sql-storage", WAVE_NO_REGRET, "datapath"),
    "sql_firewall_wide_ip_range": Classification(SECURITY, "data-sql-storage", WAVE_NO_REGRET, "datapath"),
    "sql_firewall_individual_ip_rules": Classification(SECURITY, "data-sql-storage", WAVE_NO_REGRET, "datapath"),
    "sql_entra_only_auth_disabled": Classification(SECURITY, "data-sql-storage", WAVE_OPTIMISE, "datapath"),
    "sql_entra_admin_individual_user": Classification(SECURITY, "data-sql-storage", WAVE_NO_REGRET),
    "sql_entra_admin_missing": Classification(SECURITY, "data-sql-storage", WAVE_NO_REGRET),
    "sql_hyperscale_legacy_storage_pricing": Classification(FINOPS, "data-sql-storage", WAVE_OPTIMISE, "database"),
    "idle_sql_database": Classification(FINOPS, "data-sql-storage", WAVE_NO_REGRET),
    "sql_database_cpu_saturated": Classification(PERFORMANCE, "data-sql-storage", WAVE_OPTIMISE, "database"),
    "cross_region_app_data_tier": Classification(STRUCTURAL, "data-sql-storage", WAVE_STRUCTURAL, "crossregion"),
    "cosmos_public_network_access": Classification(SECURITY, "data-sql-storage", WAVE_OPTIMISE),
    "idle_cosmos_db": Classification(FINOPS, "data-sql-storage", WAVE_NO_REGRET),
    "public_storage_account": Classification(SECURITY, "data-sql-storage", WAVE_NO_REGRET, "storage"),
    "storage_shared_key_access_enabled": Classification(SECURITY, "data-sql-storage", WAVE_OPTIMISE, "storage"),
    "storage_public_network_access": Classification(SECURITY, "data-sql-storage", WAVE_OPTIMISE, "storage"),
    "storage_blob_soft_delete_disabled": Classification(PERFORMANCE, "data-sql-storage", WAVE_NO_REGRET),
    "storage_account_sprawl": Classification(STRUCTURAL, "data-sql-storage", WAVE_OPTIMISE, "storage"),
    "storage_transaction_hotspot": Classification(PERFORMANCE, "data-sql-storage", WAVE_OPTIMISE, "storage"),
    "unused_storage_account": Classification(FINOPS, "data-sql-storage", WAVE_NO_REGRET, "storage"),
    "orphaned_backup_vault": Classification(FINOPS, "data-sql-storage", WAVE_NO_REGRET),
    # AI
    "ai_services_local_auth_enabled": Classification(SECURITY, "ai-foundry", WAVE_OPTIMISE, "ai"),
    "ai_services_public_network_open": Classification(SECURITY, "ai-foundry", WAVE_NO_REGRET, "ai"),
    "ai_spend_without_gateway": Classification(FINOPS, "ai-foundry", WAVE_OPTIMISE, "ai"),
    "ai_account_sprawl": Classification(STRUCTURAL, "ai-foundry", WAVE_OPTIMISE, "ai"),
    # Security & identity
    "key_vault_access_policy_model": Classification(SECURITY, "security-identity", WAVE_OPTIMISE),
    "key_vault_soft_delete_disabled": Classification(SECURITY, "security-identity", WAVE_NO_REGRET),
    "key_vault_purge_protection_disabled": Classification(SECURITY, "security-identity", WAVE_NO_REGRET),
    "key_vault_public_network_open": Classification(SECURITY, "security-identity", WAVE_OPTIMISE, "datapath"),
    "defender_plan_disabled": Classification(SECURITY, "security-identity", WAVE_OPTIMISE),
    "defender_recommendations": Classification(SECURITY, "security-identity", WAVE_OPTIMISE),
    "low_secure_score": Classification(SECURITY, "security-identity", WAVE_OPTIMISE),
    "excessive_subscription_owners": Classification(SECURITY, "security-identity", WAVE_NO_REGRET, "identity"),
    "standing_user_access_administrator": Classification(SECURITY, "security-identity", WAVE_NO_REGRET, "identity"),
    "service_principal_privileged_role": Classification(SECURITY, "security-identity", WAVE_OPTIMISE, "identity"),
    # Governance / observability
    "missing_diagnostic_settings": Classification(OPERATIONAL, "observability-operations", WAVE_OPTIMISE, "observability"),
    "log_analytics_restrictive_daily_cap": Classification(OPERATIONAL, "observability-operations", WAVE_NO_REGRET, "observability"),
    "log_analytics_workspace_sprawl": Classification(OPERATIONAL, "observability-operations", WAVE_OPTIMISE, "observability"),
    "app_insights_workspace_missing": Classification(OPERATIONAL, "observability-operations", WAVE_NO_REGRET, "observability"),
    "app_insights_classic_mode": Classification(OPERATIONAL, "observability-operations", WAVE_OPTIMISE, "observability"),
    "service_health_alert_missing": Classification(OPERATIONAL, "observability-operations", WAVE_NO_REGRET),
    "environment_tag_name_mismatch": Classification(STRUCTURAL, "observability-operations", WAVE_NO_REGRET, "naming"),
    "tag_key_typo": Classification(FINOPS, "observability-operations", WAVE_NO_REGRET, "naming"),
    "missing_required_tags": Classification(FINOPS, "observability-operations", WAVE_OPTIMISE, "naming"),
    "naming_convention_violation": Classification(FINOPS, "observability-operations", WAVE_STRUCTURAL, "naming"),
    "missing_resource_lock": Classification(OPERATIONAL, "observability-operations", WAVE_OPTIMISE),
    "subscription_multiple_workloads": Classification(STRUCTURAL, "observability-operations", WAVE_STRUCTURAL, "landingzone"),
    "empty_resource_group": Classification(FINOPS, "observability-operations", WAVE_NO_REGRET),
    "terraform_unmanaged_resource": Classification(OPERATIONAL, "observability-operations", WAVE_STRUCTURAL, "landingzone"),
    "terraform_missing_resource": Classification(OPERATIONAL, "observability-operations", WAVE_STRUCTURAL, "landingzone"),
    # Cost / FinOps
    "budget_consistently_exceeded": Classification(FINOPS, "cost-finops", WAVE_NO_REGRET, "finops"),
    "budget_missing": Classification(FINOPS, "cost-finops", WAVE_NO_REGRET, "finops"),
    "commitment_discount_opportunity": Classification(FINOPS, "cost-finops", WAVE_OPTIMISE, "finops"),
    "idle_iot_hub": Classification(FINOPS, "cost-finops", WAVE_NO_REGRET),
}

CATEGORY_DEFAULTS = {
    "network": Classification(STRUCTURAL, "networking"),
    "compute": Classification(PERFORMANCE, "compute-appservice"),
    "storage": Classification(FINOPS, "data-sql-storage"),
    "database": Classification(PERFORMANCE, "data-sql-storage"),
    "identity": Classification(SECURITY, "security-identity"),
    "security": Classification(SECURITY, "security-identity"),
    "governance": Classification(FINOPS, "observability-operations"),
    "terraform": Classification(OPERATIONAL, "observability-operations"),
    "cost": Classification(FINOPS, "cost-finops"),
}


def classify(finding_type: str, category: str) -> Classification:
    if finding_type in FINDING_CLASSIFICATION:
        return FINDING_CLASSIFICATION[finding_type]
    return CATEGORY_DEFAULTS.get(category, Classification(OPERATIONAL, "observability-operations"))


class Critique(NamedTuple):
    title: str
    likely_rationale: str
    why_it_falls_short: str
    alternatives: List[str]


CRITIQUES: Dict[str, Critique] = {
    "ddos": Critique(
        "DDoS Network Protection plan",
        "Usually created to satisfy a protection-class or audit requirement ('DDoS must be enabled'), "
        "then never linked to a VNet.",
        "A VNet DDoS plan bills a flat fee and protects only public IPs inside linked VNets. Multi-tenant "
        "PaaS endpoints (App Service, Storage, SQL) cannot be covered by it, and they already receive Azure's "
        "infrastructure-level DDoS protection.",
        ["No extra plan, relying on infrastructure DDoS protection, when no requirement mandates it.",
         "Azure Front Door (Standard/Premium) with WAF in front of public web apps, for edge L3/4 plus L7 "
         "protection, rate limiting and TLS.",
         "DDoS IP Protection per public IP when only a few IPs need coverage.",
         "Link spoke VNets to the central (hub) DDoS plan. One plan can cover VNets across subscriptions."],
    ),
    "appservice": Critique(
        "One App Service plan for every app and environment",
        "Slots and extra apps were added to the plan that already existed, to avoid paying for more plans. "
        "The SKU was chosen before Premium v3 existed and never revisited.",
        "Slots and apps share the plan's instances, so dev/stage load degrades production. A single instance "
        "gives no redundancy during platform upgrades. Premium v2 is previous-generation hardware with no "
        "reservation option, and plan cost can't be attributed to an environment.",
        ["Production plan on Premium v3 with at least 2 instances (zone-redundant where possible), autoscale, and a "
         "1-year reservation for the baseline.",
         "Separate, smaller non-production plan (P0v3 / B-series) with scheduled scale-down.",
         "Azure Container Apps for APIs and background jobs: scale-to-zero for non-prod and revision-based deployments."],
    ),
    "database": Critique(
        "Database tiering and data lifecycle",
        "The database grew organically. Hyperscale was picked to escape size limits and the storage/pricing "
        "model was never revisited.",
        "When most of the cost is storage, historical data is being kept in an OLTP engine at OLTP prices. "
        "Legacy Hyperscale meters and peak-time maintenance jobs make it worse.",
        ["Hot/cold split: recent data in SQL, history in ADLS Gen2 (Parquet/Delta) queried by Fabric / Synapse "
         "serverless or Azure Data Explorer.",
         "Re-evaluate the tier after archiving: General Purpose vCore or Hyperscale serverless.",
         "Route reporting to the read-scale replica and use Query Store instead of blanket index rebuilds.",
         "Reserved capacity for steady-state vCores after rightsizing."],
    ),
    "storage": Critique(
        "Storage account per tenant, reached with shared keys over public endpoints",
        "Account-per-customer is the simplest isolation model when access is by account key, and portal "
        "defaults leave the firewall open.",
        "Per-account charges (Defender for Storage, Event Grid topics), key rotation and attack surface grow "
        "with every tenant. Shared keys give full-account access with no identity or audit trail.",
        ["A few accounts per environment with a container/share per tenant, Entra RBAC/ABAC or user-delegation SAS.",
         "Private endpoints and firewall default action Deny.",
         "Lifecycle management (Hot → Cool → Archive), and the provisioned Files model for transaction-heavy shares."],
    ),
    "jumphost": Critique(
        "Legacy jump host with a public IP",
        "A workstation VM was built for tooling (SSMS, scripts) and exposed with RDP for convenience. Bastion "
        "was added later without removing the public path.",
        "An unsupported OS receives no security fixes, and a public IP next to Bastion keeps a second, direct "
        "attack path open. Permissive NSGs left on orphaned NICs re-expose any VM they get attached to.",
        ["No VM: Entra-authenticated tools against private endpoints through Bastion (Developer SKU is free).",
         "Microsoft Dev Box or Azure Virtual Desktop for developer tooling.",
         "If a VM is unavoidable: supported image, Trusted Launch, no public IP, JIT access."],
    ),
    "datapath": Critique(
        "Public data plane with secrets instead of identities",
        "Apps were connected the quickest way: public endpoints, 'Allow Azure services', developer IP rules "
        "and connection strings.",
        "The only barrier to the data is a secret or a firewall rule that any Azure tenant, or a stale home IP, "
        "satisfies. There's no private network boundary and no per-app identity.",
        ["Spoke VNet peered to the hub, App Service VNet integration, private endpoints for SQL, Storage, "
         "Key Vault and AI, using central private DNS zones.",
         "Managed identities everywhere, with Entra-only auth on SQL and shared keys disabled on Storage.",
         "Remove 0.0.0.0 and personal firewall rules. Administer via Bastion or VPN."],
    ),
    "crossregion": Critique(
        "App tier and data tier in different regions",
        "Likely a data-residency preference for the database, or a separate team choice, while reusing an "
        "existing App Service plan elsewhere.",
        "Every request pays cross-region latency and egress, and availability depends on two regions without "
        "any DR benefit.",
        ["Co-locate both tiers in one region.", "Use geo-replication / failover groups for DR."],
    ),
    "ai": Critique(
        "Independent AI accounts per experiment",
        "Individuals created accounts and deployments wherever they had quota, to get to new models fast.",
        "Capacity, quotas, content filters, logging and keys are managed per account. With no gateway, "
        "spend can't be capped, cached or attributed to an app or team.",
        ["One Foundry resource per environment, with a project per use-case.",
         "APIM AI Gateway: llm-token-limit per product, llm-emit-token-metric with app/user/project dimensions, "
         "semantic caching, backend pools (PTU with PAYG spill-over when volume justifies it).",
         "Model routing, with small models by default and flagship models on escalation.",
         "Entra-only auth, private endpoints, Defender for AI, diagnostic logs and monthly AI budgets per project."],
    ),
    "identity": Critique(
        "Standing privileged access",
        "Access was granted directly to individuals when needed and never revoked.",
        "Standing Owner or User Access Administrator lets any holder, or anyone who phishes them, take full "
        "control of the subscription. Service principals with subscription-wide rights turn a leaked "
        "secret into a full compromise.",
        ["PIM-eligible (just-in-time, approval) for Owner and UAA, with at most 3 Owners.",
         "Group-based RBAC per workload and environment, reviewed quarterly.",
         "Workload identity federation for pipelines, scoped to the resource groups they deploy."],
    ),
    "observability": Critique(
        "Observability by default",
        "Default workspaces were auto-created, and caps were set to avoid surprise log bills.",
        "Tiny daily caps and broken workspace links silently drop telemetry exactly when an incident "
        "multiplies log volume. Missing diagnostic settings leave no audit trail.",
        ["One Log Analytics workspace per environment (or the central platform workspace).",
         "Cap alerts instead of hard caps. Basic/Auxiliary table plans and DCR filtering for verbose data.",
         "Diagnostic settings deployed by policy (DINE) for every critical resource type."],
    ),
    "naming": Critique(
        "Names and tags that don't describe the resource",
        "Resources were named after their first purpose (dev/test) and kept their names when they were "
        "promoted to production. Tags were added by hand.",
        "Operators, maintenance windows and environment-scoped policies treat production systems as "
        "disposable. Cost can't be attributed, and tag typos escape tag-based policies.",
        ["Enforce a tag set with policy (deny or modify, plus remediation tasks) and a naming standard in IaC.",
         "Re-create mis-named production resources through IaC during the re-platforming wave."],
    ),
    "landingzone": Critique(
        "One flat subscription for many workloads",
        "The subscription was the fastest place to start new work, because it already had quota and "
        "permissions.",
        "Unrelated workloads share RBAC, budget, Defender scope and blast radius. Nothing can be governed, "
        "charged back or decommissioned on its own.",
        ["Landing-zone subscriptions per workload and environment under the right management groups.",
         "Deployed and changed only through IaC pipelines, with no standing Contributor for users."],
    ),
    "network": Critique(
        "No network design",
        "VNets were created ad hoc for single VMs, with no connection to a hub.",
        "There's no place for private endpoints or VNet integration, no subnet-level filtering, and leftover "
        "private DNS zones confuse future private-link work.",
        ["Hub/spoke from the connectivity landing zone, with non-overlapping CIDRs from IPAM.",
         "NSGs on every workload subnet, and central private DNS zones."],
    ),
    "finops": Critique(
        "Budget without a feedback loop",
        "A governance budget was set centrally, and its alerts go to a platform action group.",
        "A budget exceeded every month is not a control. Workload owners never see the alerts, and "
        "commitments bought before clean-up would lock in waste.",
        ["A budget per workload and environment, with owner contacts and a defined breach process.",
         "Clean up (wave 1), rightsize (wave 2), then buy reservations or a savings plan for the steady state."],
    ),
}
