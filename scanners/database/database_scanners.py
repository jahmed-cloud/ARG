"""
Azure Resource Guardian - Database Scanners
============================================
Scanners in this module:
1. SqlFirewallScanner                  — 'Allow Azure services', wide ranges, ad-hoc single-IP rules
2. SqlEntraAuthScanner                 — Entra-only auth disabled / admin is an individual / no admin
3. SqlHyperscaleLegacyPricingScanner   — Hyperscale DBs billed on the pre-Dec-2023 storage meter
4. SqlDatabaseUtilizationScanner       — Idle databases and CPU-saturated databases
5. CrossRegionAppDataScanner           — Web apps and their SQL server in different regions
6. CosmosDbScanner                     — Public Cosmos DB accounts and idle accounts
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import ipaddress
import re
from typing import Any, Dict, List

from scanners.base.azure_api import cost_for, get_resource_costs, get_retail_price
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.posture_scanner import PostureScanner

PORTAL_GENERATED_RULE = re.compile(r"^(ClientIPAddress_|ClientIp-|query-editor-|AllowClient)", re.I)
LEGACY_HYPERSCALE_STORAGE_SUBCATEGORY = "sql database hyperscale - storage"
# USD per GB-month, westeurope (Aug 2026): legacy meter vs current single-DB meter.
HYPERSCALE_STORAGE_USD = {"legacy": 0.301724, "current": 0.119}


def ip_range_size(start: str, end: str) -> int:
    try:
        return int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(start)) + 1
    except ValueError:
        return 0


def classify_firewall_rules(rules: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Split SQL firewall rules into allow_azure / wide / individual buckets."""
    out: Dict[str, List[Dict[str, Any]]] = {"allow_azure": [], "wide": [], "individual": []}
    for rule in rules:
        props = rule.get("properties") or rule
        start, end = props.get("startIpAddress"), props.get("endIpAddress")
        entry = {"name": rule.get("name"), "start": start, "end": end,
                 "portal_generated": bool(PORTAL_GENERATED_RULE.match(rule.get("name") or ""))}
        if start == "0.0.0.0" and end == "0.0.0.0":
            out["allow_azure"].append(entry)
            continue
        size = ip_range_size(start or "", end or "")
        entry["addresses"] = size
        if size > 65536:
            out["wide"].append(entry)
        elif size == 1:
            out["individual"].append(entry)
    return out


# ---------------------------------------------------------------------------
# 1. SQL firewall rules
# ---------------------------------------------------------------------------

@register_scanner
class SqlFirewallScanner(PostureScanner):
    """
    With public network access enabled, firewall rules are the only network
    control. 0.0.0.0-0.0.0.0 ("Allow Azure services") admits traffic from any
    Azure tenant; single-IP rules are usually developer home/office IPs added
    from the portal and never removed.
    """

    scanner_name = "sql_firewall_scanner"
    display_name = "SQL Server Firewall Rules"
    description = "Detects permissive or ad-hoc Azure SQL firewall rules"
    category = ScannerCategory.DATABASE
    severity = SeverityLevel.HIGH

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.sql/servers'
        | where tostring(properties.publicNetworkAccess) !~ 'Disabled'
        | project id, name, type, resourceGroup, subscriptionId, location, tags
        """
        try:
            servers = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings = []
        if self.is_live(context):
            for srv in servers:
                try:
                    srv["firewall_rules"] = await context.arm_client.get_all(f"{srv['id']}/firewallRules", "2021-11-01")
                except Exception as exc:
                    warnings.append(f"Firewall rules unavailable for {srv['name']}: {exc}")

        findings = []
        for srv in servers:
            buckets = classify_firewall_rules(srv.get("firewall_rules") or [])
            rg, name = srv.get("resourceGroup"), srv["name"]

            if buckets["allow_azure"]:
                findings.append(self.resource_finding(
                    srv,
                    finding_type="sql_firewall_allow_all_azure_services",
                    title=f"'Allow Azure services' enabled: {name}",
                    description=(
                        f"SQL server '{name}' has the 0.0.0.0 rule ('Allow Azure services and resources to "
                        f"access this server'), which admits connections from any Azure-hosted service in any "
                        f"tenant. Authentication becomes the only barrier."
                    ),
                    resource_type="microsoft.sql/servers",
                    severity=SeverityLevel.CRITICAL,
                    remediation_steps=(
                        "1. Give the calling apps private endpoints / VNet integration (or at least their outbound IPs).\n"
                        "2. Delete the AllowAllWindowsAzureIps rule.\n"
                        "3. Disable public network access once private connectivity works."
                    ),
                    azure_cli_script=f"az sql server firewall-rule delete -g {rg} -s {name} -n AllowAllWindowsAzureIps",
                    powershell_script=(f"Remove-AzSqlServerFirewallRule -ResourceGroupName '{rg}' -ServerName '{name}' "
                                       f"-FirewallRuleName 'AllowAllWindowsAzureIps'"),
                    evidence={"rules": buckets["allow_azure"]},
                    cis_control="4.1.2",
                    nist_control="SC-7",
                    estimated_monthly_savings_usd=0.0,
                ))

            if buckets["wide"]:
                findings.append(self.resource_finding(
                    srv,
                    finding_type="sql_firewall_wide_ip_range",
                    title=f"Wide IP range allowed: {name}",
                    description=(
                        f"SQL server '{name}' allows {len(buckets['wide'])} rule(s) spanning more than 65,536 "
                        f"addresses: " + ", ".join(f"{r['name']} ({r['start']}-{r['end']})" for r in buckets["wide"])
                    ),
                    resource_type="microsoft.sql/servers",
                    severity=(SeverityLevel.CRITICAL if any(r["addresses"] > 2**31 for r in buckets["wide"])
                              else SeverityLevel.HIGH),
                    remediation_steps="Narrow each rule to the specific egress ranges that need access.",
                    azure_cli_script="\n".join(
                        f"az sql server firewall-rule delete -g {rg} -s {name} -n '{r['name']}'" for r in buckets["wide"]
                    ),
                    evidence={"rules": buckets["wide"]},
                    cis_control="4.1.2",
                    estimated_monthly_savings_usd=0.0,
                ))

            if buckets["individual"]:
                generated = [r for r in buckets["individual"] if r["portal_generated"]]
                findings.append(self.resource_finding(
                    srv,
                    finding_type="sql_firewall_individual_ip_rules",
                    title=f"{len(buckets['individual'])} single-IP firewall rule(s): {name}",
                    description=(
                        f"SQL server '{name}' has {len(buckets['individual'])} single-address rule(s) "
                        f"({len(generated)} auto-generated by the portal): "
                        + ", ".join(r["name"] for r in buckets["individual"])
                        + ". These are typically developer home/ISP addresses that outlive their purpose."
                    ),
                    resource_type="microsoft.sql/servers",
                    severity=SeverityLevel.HIGH if generated else SeverityLevel.MEDIUM,
                    remediation_steps=(
                        "Review each rule with its owner; remove personal/ad-hoc addresses and use Entra-authenticated "
                        "access through a private endpoint (Bastion / VPN) for administration."
                    ),
                    azure_cli_script="\n".join(
                        f"az sql server firewall-rule delete -g {rg} -s {name} -n '{r['name']}'"
                        for r in buckets["individual"]
                    ),
                    evidence={"rules": buckets["individual"]},
                    estimated_monthly_savings_usd=0.0,
                ))

        return ScanOutput(findings=findings, resources_scanned=len(servers), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql-app-1",
            "name": "sql-app-1", "type": "microsoft.sql/servers", "resourceGroup": "rg-data",
            "subscriptionId": "sub-1", "location": "westeurope",
            "firewall_rules": [
                {"name": "AllowAllWindowsAzureIps", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}},
                {"name": "ClientIPAddress_20260328073118",
                 "properties": {"startIpAddress": "89.1.2.3", "endIpAddress": "89.1.2.3"}},
                {"name": "Office", "properties": {"startIpAddress": "212.1.2.0", "endIpAddress": "212.1.2.255"}},
            ],
        }]


# ---------------------------------------------------------------------------
# 2. Entra authentication on SQL servers
# ---------------------------------------------------------------------------

@register_scanner
class SqlEntraAuthScanner(PostureScanner):
    """Entra-only auth, and whether the Entra admin is a group rather than a person."""

    scanner_name = "sql_entra_auth_scanner"
    display_name = "SQL Server Entra Authentication"
    description = "Detects SQL servers without Entra-only auth or with an individual Entra admin"
    category = ScannerCategory.DATABASE
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.sql/servers'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  entra_only = tobool(properties.administrators.azureADOnlyAuthentication),
                  admin_login = tostring(properties.administrators.login),
                  admin_type = tostring(properties.administrators.principalType)
        """
        try:
            servers = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for srv in servers:
            rg, name = srv.get("resourceGroup"), srv["name"]
            if not srv.get("admin_login"):
                findings.append(self.resource_finding(
                    srv, finding_type="sql_entra_admin_missing", title=f"No Entra admin: {name}",
                    description=f"SQL server '{name}' has no Microsoft Entra administrator; only SQL logins can administer it.",
                    resource_type="microsoft.sql/servers", severity=SeverityLevel.HIGH,
                    remediation_steps="Set an Entra group as administrator, then enable Entra-only authentication.",
                    azure_cli_script=f"az sql server ad-admin create -g {rg} -s {name} -u <group-name> -i <group-object-id>",
                    evidence={}, cis_control="4.4", estimated_monthly_savings_usd=0.0,
                ))
            elif (srv.get("admin_type") or "").lower() == "user":
                findings.append(self.resource_finding(
                    srv, finding_type="sql_entra_admin_individual_user", title=f"Entra admin is a single user: {name}",
                    description=(f"SQL server '{name}' uses an individual user ({srv.get('admin_login')}) as Entra admin — "
                                 f"admin access is lost or orphaned when that person changes role or leaves."),
                    resource_type="microsoft.sql/servers", severity=SeverityLevel.LOW,
                    remediation_steps="Replace the user with an Entra security group of DBAs.",
                    azure_cli_script=f"az sql server ad-admin update -g {rg} -s {name} -u <group-name> -i <group-object-id>",
                    evidence={"admin_login": srv.get("admin_login")}, estimated_monthly_savings_usd=0.0,
                ))
            if srv.get("entra_only") is not True:
                findings.append(self.resource_finding(
                    srv, finding_type="sql_entra_only_auth_disabled", title=f"SQL authentication enabled: {name}",
                    description=(f"SQL server '{name}' still accepts SQL (password) authentication; Entra-only "
                                 f"authentication is disabled."),
                    resource_type="microsoft.sql/servers",
                    remediation_steps="Move apps to managed identities, then enable Entra-only authentication.",
                    azure_cli_script=f"az sql server ad-only-auth enable -g {rg} -n {name}",
                    powershell_script=(f"Enable-AzSqlServerActiveDirectoryOnlyAuthentication -ResourceGroupName '{rg}' "
                                       f"-ServerName '{name}'"),
                    evidence={"azureADOnlyAuthentication": srv.get("entra_only")},
                    cis_control="4.5", estimated_monthly_savings_usd=0.0,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(servers))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql-app-1",
            "name": "sql-app-1", "type": "microsoft.sql/servers", "resourceGroup": "rg-data",
            "subscriptionId": "sub-1", "location": "westeurope",
            "entra_only": None, "admin_login": "dba@contoso.com", "admin_type": "User",
        }]


# ---------------------------------------------------------------------------
# 3. Hyperscale on legacy storage pricing
# ---------------------------------------------------------------------------

@register_scanner
class SqlHyperscaleLegacyPricingScanner(PostureScanner):
    """
    Hyperscale databases created before 2023-12-15 keep the legacy storage
    meter ("SQL Database Hyperscale - Storage"), priced ~2.5x the current
    single-database meter. Detected from actual billing meters (live mode).
    """

    scanner_name = "sql_hyperscale_legacy_pricing_scanner"
    display_name = "Hyperscale Legacy Storage Pricing"
    description = "Detects Hyperscale databases billed on the legacy (pre-Dec-2023) storage meter"
    category = ScannerCategory.COST
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.sql/servers/databases'
        | where tostring(sku.tier) =~ 'Hyperscale'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  sku_name = tostring(sku.name), vcores = toint(sku.capacity),
                  created = tostring(properties.creationDate),
                  ha_replicas = toint(properties.highAvailabilityReplicaCount)
        """
        try:
            dbs = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        if self.is_live(context) and dbs:
            costs = await get_resource_costs(context)
            for db in dbs:
                entry = cost_for(costs, db["id"]) or {}
                legacy = sum(v for k, v in (entry.get("meters") or {}).items()
                             if k.lower() == LEGACY_HYPERSCALE_STORAGE_SUBCATEGORY)
                total, total_usd = entry.get("cost") or 0.0, entry.get("cost_usd")
                db["legacy_storage_cost"] = legacy
                db["legacy_storage_cost_usd"] = (legacy * total_usd / total) if total and total_usd else None
                db["currency"] = entry.get("currency")

        findings = []
        for db in dbs:
            if not db.get("legacy_storage_cost"):
                continue
            region = f"armRegionName eq '{db.get('location')}' and meterName eq 'Hyperscale Data Stored'"
            old = await get_retail_price(context, f"{region} and productName eq 'SQL Database Hyperscale - Storage'",
                                         fallback=HYPERSCALE_STORAGE_USD["legacy"])
            new = await get_retail_price(context, f"{region} and productName eq 'SQL Database SingleDB Hyperscale - Storage'",
                                         fallback=HYPERSCALE_STORAGE_USD["current"])
            ratio = (new / old) if old else 0.0
            usd = db.get("legacy_storage_cost_usd")
            saving = round(usd * (1 - ratio), 2) if usd else None
            billed_gb = round(usd / old) if usd and old else None
            findings.append(self.resource_finding(
                db,
                finding_type="sql_hyperscale_legacy_storage_pricing",
                title=f"Hyperscale on legacy storage pricing: {db['name']}",
                description=(
                    f"Hyperscale database '{db['name']}' ({db.get('sku_name')} {db.get('vcores')} vCore, created "
                    f"{(db.get('created') or '')[:10]}) is billed {db['legacy_storage_cost']:,.2f} "
                    f"{db.get('currency') or ''} / 30 days on the legacy 'SQL Database Hyperscale - Storage' meter "
                    f"(~USD {old}/GB-month vs {new}/GB-month on the current meter"
                    + (f", ~{billed_gb:,} GB billed" if billed_gb else "") + "). Validate the migration path "
                    "(e.g. database copy) with Microsoft before acting."
                ),
                resource_type="microsoft.sql/servers/databases",
                remediation_steps=(
                    "1. Confirm with Microsoft/CSP how this database can move to current Hyperscale pricing.\n"
                    "2. Independently, archive cold data (partition by date, export to ADLS Parquet) — every GB "
                    "removed is billed at the legacy rate today.\n"
                    "3. After rightsizing, consider reserved capacity for the vCores."
                ),
                azure_cli_script=f"az sql db show --ids {db['id']} --query \"{{sku:sku, created:creationDate}}\"",
                evidence={"legacy_storage_cost_30d": db.get("legacy_storage_cost"), "currency": db.get("currency"),
                          "legacy_usd_per_gb": old, "current_usd_per_gb": new, "estimated_billed_gb": billed_gb,
                          "ha_replicas": db.get("ha_replicas")},
                estimated_monthly_savings_usd=saving,
                caf_control="Cost Optimization",
            ))
        return ScanOutput(findings=findings, resources_scanned=len(dbs))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql-app-1/databases/db-hs-1",
            "name": "sql-app-1/db-hs-1", "type": "microsoft.sql/servers/databases", "resourceGroup": "rg-data",
            "subscriptionId": "sub-1", "location": "westeurope", "sku_name": "HS_Gen5", "vcores": 4,
            "created": "2019-07-24T15:39:23Z", "ha_replicas": 1,
            "legacy_storage_cost": 875.0, "legacy_storage_cost_usd": 875.0, "currency": "USD",
        }]


# ---------------------------------------------------------------------------
# 4. Idle / saturated databases
# ---------------------------------------------------------------------------

@register_scanner
class SqlDatabaseUtilizationScanner(PostureScanner):
    """30-day CPU/DTU per database (live mode): zero activity -> idle, peaks at 100% -> saturated."""

    scanner_name = "sql_database_utilization_scanner"
    display_name = "SQL Database Utilization"
    description = "Detects idle SQL databases and databases whose CPU saturates"
    category = ScannerCategory.DATABASE
    severity = SeverityLevel.MEDIUM

    SATURATED_MAX = 95.0
    SATURATED_MIN_AVG = 10.0  # a lone spike on an otherwise idle database is not saturation

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.sql/servers/databases'
        | where name !~ 'master' and tostring(sku.tier) !~ 'System'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  sku_name = tostring(sku.name), sku_tier = tostring(sku.tier), capacity = toint(sku.capacity)
        """
        try:
            dbs = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings = []
        if self.is_live(context) and dbs:
            costs = await get_resource_costs(context)
            for db in dbs:
                dtu = (db.get("sku_tier") or "").lower() in ("basic", "standard", "premium")
                metric = "dtu_consumption_percent" if dtu else "cpu_percent"
                try:
                    m = await context.arm_client.metrics_summary(db["id"], [metric])
                    db["util_avg"] = (m.get(metric) or {}).get("average")
                    db["util_max"] = (m.get(metric) or {}).get("maximum")
                    db["metric"] = metric
                except Exception as exc:
                    warnings.append(f"Metrics unavailable for {db['name']}: {exc}")
                db["cost_usd_30d"] = (cost_for(costs, db["id"]) or {}).get("cost_usd")

        findings = []
        for db in dbs:
            peak, avg = db.get("util_max"), db.get("util_avg")
            if peak is None:
                continue
            label = f"{db.get('sku_name')}/{db.get('capacity')}"
            if peak < 1.0:
                findings.append(self.resource_finding(
                    db, finding_type="idle_sql_database", title=f"Idle database: {db['name']}",
                    description=(f"Database '{db['name']}' ({label}) peaked at {peak:.1f}% {db.get('metric')} over "
                                 f"30 days — no meaningful workload."),
                    resource_type="microsoft.sql/servers/databases", severity=SeverityLevel.LOW,
                    remediation_steps="Confirm with the owner; export a BACPAC and delete, or move to serverless with auto-pause.",
                    azure_cli_script=f"az sql db delete --ids {db['id']} --yes",
                    evidence={"metric": db.get("metric"), "max_30d": peak, "avg_30d": avg},
                    estimated_monthly_savings_usd=round(db["cost_usd_30d"], 2) if db.get("cost_usd_30d") else None,
                ))
            elif peak >= float(self.setting("saturated_max", self.SATURATED_MAX)) and (avg or 0) >= float(
                    self.setting("saturated_min_avg", self.SATURATED_MIN_AVG)):
                findings.append(self.resource_finding(
                    db, finding_type="sql_database_cpu_saturated",
                    title=f"Database hits {peak:.0f}% {db.get('metric')}: {db['name']}",
                    description=(f"Database '{db['name']}' ({label}) averaged {avg or 0:.1f}% and peaked at {peak:.0f}% "
                                 f"{db.get('metric')} over 30 days; users see throttling during peaks."),
                    resource_type="microsoft.sql/servers/databases", severity=SeverityLevel.HIGH,
                    remediation_steps=("Review Query Store top consumers, move reporting to a read replica, and "
                                       "schedule maintenance jobs off-peak before scaling up."),
                    azure_cli_script=f"az sql db show --ids {db['id']} --query \"{{sku:sku, readScale:readScale}}\"",
                    evidence={"metric": db.get("metric"), "max_30d": peak, "avg_30d": avg},
                    estimated_monthly_savings_usd=0.0,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(dbs), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        base = "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql-app-1/databases"
        common = {"type": "microsoft.sql/servers/databases", "resourceGroup": "rg-data",
                  "subscriptionId": "sub-1", "location": "westeurope"}
        return [
            {**common, "id": f"{base}/db-analysis", "name": "sql-app-1/db-analysis", "sku_name": "Standard",
             "sku_tier": "Standard", "capacity": 10, "metric": "dtu_consumption_percent",
             "util_avg": 0.0, "util_max": 0.0, "cost_usd_30d": 14.7},
            {**common, "id": f"{base}/db-hs-1", "name": "sql-app-1/db-hs-1", "sku_name": "HS_Gen5",
             "sku_tier": "Hyperscale", "capacity": 4, "metric": "cpu_percent",
             "util_avg": 40.1, "util_max": 100.0, "cost_usd_30d": 1580.0},
        ]


# ---------------------------------------------------------------------------
# 5. App tier and data tier in different regions
# ---------------------------------------------------------------------------

@register_scanner
class CrossRegionAppDataScanner(PostureScanner):
    """
    Heuristic: a resource group whose web apps run in one region while its
    SQL server lives in another. Every query pays cross-region latency and
    egress, and availability depends on two regions.
    """

    scanner_name = "cross_region_app_data_scanner"
    display_name = "Cross-Region App and Data Tier"
    description = "Detects resource groups whose web apps and SQL server are in different regions"
    category = ScannerCategory.DATABASE
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type in~ ('microsoft.web/sites', 'microsoft.sql/servers')
        | project id, name, type = tolower(type), resourceGroup = tolower(resourceGroup), subscriptionId, location, tags
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        by_rg: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for r in rows:
            bucket = by_rg.setdefault(r.get("resourceGroup") or "", {"apps": [], "sql": []})
            bucket["sql" if r["type"] == "microsoft.sql/servers" else "apps"].append(r)

        findings = []
        for rg, bucket in by_rg.items():
            app_regions = {a.get("location") for a in bucket["apps"]}
            for srv in bucket["sql"]:
                if not bucket["apps"] or srv.get("location") in app_regions:
                    continue
                findings.append(self.resource_finding(
                    srv,
                    finding_type="cross_region_app_data_tier",
                    title=f"App tier in {', '.join(sorted(app_regions))}, SQL in {srv.get('location')}: {srv['name']}",
                    description=(
                        f"Resource group '{rg}' runs web app(s) {', '.join(a['name'] for a in bucket['apps'])} in "
                        f"{', '.join(sorted(app_regions))} while SQL server '{srv['name']}' is in {srv.get('location')}."
                    ),
                    resource_type="microsoft.sql/servers",
                    remediation_steps=("Co-locate the app and data tiers in one region; use geo-replication/failover "
                                       "groups for DR instead of a split-region layout."),
                    evidence={"app_regions": sorted(app_regions), "sql_region": srv.get("location"),
                              "apps": [a["name"] for a in bucket["apps"]]},
                    estimated_monthly_savings_usd=0.0,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(rows))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [
            {"id": "/subscriptions/sub-1/resourceGroups/rg-mm/providers/Microsoft.Web/sites/app-mm", "name": "app-mm",
             "type": "microsoft.web/sites", "resourceGroup": "rg-mm", "subscriptionId": "sub-1", "location": "westeurope"},
            {"id": "/subscriptions/sub-1/resourceGroups/rg-mm/providers/Microsoft.Sql/servers/sql-mm", "name": "sql-mm",
             "type": "microsoft.sql/servers", "resourceGroup": "rg-mm", "subscriptionId": "sub-1",
             "location": "germanywestcentral"},
        ]


# ---------------------------------------------------------------------------
# 6. Cosmos DB exposure and idleness
# ---------------------------------------------------------------------------

@register_scanner
class CosmosDbScanner(PostureScanner):
    """Public Cosmos DB accounts, and accounts with zero requests in 30 days (live mode)."""

    scanner_name = "cosmos_db_scanner"
    display_name = "Cosmos DB Exposure & Usage"
    description = "Detects public Cosmos DB accounts and accounts with no requests"
    category = ScannerCategory.DATABASE
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.documentdb/databaseaccounts'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  public_access = tostring(properties.publicNetworkAccess),
                  pe_count = array_length(properties.privateEndpointConnections),
                  free_tier = tobool(properties.enableFreeTier)
        """
        try:
            accounts = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings = []
        if self.is_live(context):
            for acc in accounts:
                try:
                    m = await context.arm_client.metrics_summary(acc["id"], ["TotalRequests"], aggregation="Count,Total")
                    acc["requests_30d"] = (m.get("TotalRequests") or {}).get("total") or 0.0
                except Exception as exc:
                    warnings.append(f"Metrics unavailable for {acc['name']}: {exc}")

        findings = []
        for acc in accounts:
            rg, name = acc.get("resourceGroup"), acc["name"]
            if (acc.get("public_access") or "Enabled").lower() != "disabled" and not acc.get("pe_count"):
                findings.append(self.resource_finding(
                    acc, finding_type="cosmos_public_network_access", title=f"Public Cosmos DB account: {name}",
                    description=f"Cosmos DB account '{name}' accepts traffic from public networks and has no private endpoint.",
                    resource_type="microsoft.documentdb/databaseaccounts",
                    remediation_steps="Add a private endpoint and disable public network access (or restrict with IP/VNet rules).",
                    azure_cli_script=f"az cosmosdb update -g {rg} -n {name} --public-network-access Disabled",
                    evidence={"public_network_access": acc.get("public_access")}, estimated_monthly_savings_usd=0.0,
                ))
            if acc.get("requests_30d") == 0:
                findings.append(self.resource_finding(
                    acc, finding_type="idle_cosmos_db", title=f"Cosmos DB account with no requests: {name}",
                    description=(f"Cosmos DB account '{name}' served 0 requests in 30 days"
                                 + (" (free tier)." if acc.get("free_tier") else ".")),
                    resource_type="microsoft.documentdb/databaseaccounts", severity=SeverityLevel.LOW,
                    remediation_steps="Confirm with the owner and delete the account if the workload was abandoned.",
                    azure_cli_script=f"az cosmosdb delete -g {rg} -n {name} --yes",
                    evidence={"requests_30d": 0, "free_tier": acc.get("free_tier")}, estimated_monthly_savings_usd=0.0,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(accounts), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-bot/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-bot-1",
            "name": "cosmos-bot-1", "type": "microsoft.documentdb/databaseaccounts", "resourceGroup": "rg-bot",
            "subscriptionId": "sub-1", "location": "germanywestcentral", "public_access": "Enabled",
            "pe_count": 0, "free_tier": True, "requests_30d": 0,
        }]
