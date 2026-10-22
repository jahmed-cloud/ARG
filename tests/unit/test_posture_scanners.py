"""
Unit tests for the posture / FinOps scanners.

Every scanner runs in mock mode (no Azure clients injected), which is the
same contract the original scanners use: offline, deterministic data that
exercises the detection logic. Pure helper functions are tested directly.
"""

import asyncio
from datetime import date

import pytest

import scanners.compute.compute_posture_scanners as compute
import scanners.compute.machine_security_scanners  # noqa: F401
import scanners.cost.cost_scanners  # noqa: F401
import scanners.database.database_scanners as database
import scanners.governance.governance_posture_scanners as governance
import scanners.governance.governance_scanners  # noqa: F401
import scanners.network.network_posture_scanners as network
import scanners.security.security_posture_scanners  # noqa: F401
import scanners.storage.storage_posture_scanners as storage
from scanners.base.azure_api import cached_metrics, get_resource_costs, rid_segment, summarize_metrics
from scanners.base.base_scanner import ORPHAN_FINDING_TYPES, ScanContext, ScannerRegistry, SeverityLevel
from scanners.base.naming import env_from_name, env_from_tags, name_tokens


def _context() -> ScanContext:
    return ScanContext(subscription_id="sub-1", tenant_id="tenant-1", scan_job_id="job-1")


# Scanners that are off by default are exercised with their switch on.
ENABLED = {"defender_plan_coverage_scanner": {"defender_plan_coverage": True},
           "defender_recommendations_scanner": {"defender_recommendations": True}}


def _run(scanner_name: str, config=None):
    cls = ScannerRegistry.get(scanner_name)
    assert cls is not None, f"{scanner_name} is not registered"
    return asyncio.run(cls(config=config if config is not None else ENABLED.get(scanner_name, {})).execute(_context()))


# ---------------------------------------------------------------------------
# Mock-mode behaviour of every new scanner
# ---------------------------------------------------------------------------

EXPECTED = {
    "unassociated_ddos_plan_scanner": {"unused_ddos_protection_plan"},
    "orphaned_nsg_scanner": {"orphaned_nsg"},
    "open_management_port_scanner": {"nsg_management_port_open_to_internet"},
    "public_ip_on_orphaned_nic_scanner": {"public_ip_on_orphaned_nic"},
    "vm_public_ip_with_bastion_scanner": {"vm_public_ip_bypasses_bastion"},
    "private_dns_zone_without_endpoints_scanner": {"private_dns_zone_without_endpoints"},
    "subnet_without_nsg_scanner": {"subnet_without_nsg"},
    "unsupported_os_image_scanner": {"vm_unsupported_os"},
    "machine_security_scanner": {"internet_facing_machine_unpatched", "machine_vulnerability_scan_missing",
                                 "sql_server_end_of_support"},
    "managed_disk_network_access_scanner": {"managed_disk_public_network_access"},
    "app_service_plan_generation_scanner": {"app_service_plan_previous_generation", "app_service_plan_single_instance"},
    "app_service_plan_utilization_scanner": {"app_service_plan_cpu_saturated", "app_service_plan_underutilized"},
    "vm_rightsizing_scanner": {"vm_rightsizing_opportunity"},
    "resource_provider_policy_scanner": {"resource_type_denied_by_policy"},
    "resource_provider_registration_scanner": {"resource_provider_blocked_registered"},
    "app_service_mixed_environment_scanner": {"app_service_plan_mixed_environments"},
    "web_app_https_identity_scanner": {"web_app_https_not_enforced", "web_app_managed_identity_missing"},
    "web_app_configuration_scanner": {"web_app_eol_runtime", "web_app_health_check_missing", "web_app_32bit_worker"},
    "sql_firewall_scanner": {"sql_firewall_allow_all_azure_services", "sql_firewall_individual_ip_rules"},
    "sql_entra_auth_scanner": {"sql_entra_only_auth_disabled", "sql_entra_admin_individual_user"},
    "sql_hyperscale_legacy_pricing_scanner": {"sql_hyperscale_legacy_storage_pricing"},
    "sql_database_utilization_scanner": {"idle_sql_database", "sql_database_underutilized", "sql_database_cpu_saturated"},
    "cross_region_app_data_scanner": {"cross_region_app_data_tier"},
    "cosmos_db_scanner": {"cosmos_public_network_access", "idle_cosmos_db"},
    "storage_access_hardening_scanner": {"storage_shared_key_access_enabled", "storage_public_network_access",
                                         "storage_blob_soft_delete_disabled"},
    "storage_account_sprawl_scanner": {"storage_account_sprawl"},
    "storage_transaction_hotspot_scanner": {"storage_transaction_hotspot"},
    "key_vault_hardening_scanner": {"key_vault_access_policy_model", "key_vault_soft_delete_disabled",
                                    "key_vault_purge_protection_disabled", "key_vault_public_network_open"},
    "ai_services_hardening_scanner": {"ai_services_local_auth_enabled", "ai_services_public_network_open"},
    "defender_plan_coverage_scanner": {"defender_plan_disabled"},
    "defender_recommendations_scanner": {"defender_recommendations"},
    "privileged_role_assignment_scanner": {"excessive_subscription_owners", "standing_user_access_administrator",
                                           "service_principal_privileged_role"},
    "secure_score_scanner": {"low_secure_score"},
    "environment_tag_mismatch_scanner": {"environment_tag_name_mismatch"},
    "tag_key_typo_scanner": {"tag_key_typo"},
    "subscription_workload_sprawl_scanner": {"subscription_multiple_workloads"},
    "log_analytics_scanner": {"log_analytics_restrictive_daily_cap", "log_analytics_workspace_sprawl"},
    "app_insights_workspace_scanner": {"app_insights_workspace_missing"},
    "service_health_alert_scanner": {"service_health_alert_missing"},
    "empty_resource_group_scanner": {"empty_resource_group"},
    "budget_scanner": {"budget_consistently_exceeded"},
    "idle_iot_hub_scanner": {"idle_iot_hub"},
    "region_price_scanner": {"cheaper_region_available"},
    "ai_spend_governance_scanner": {"ai_spend_without_gateway", "ai_account_sprawl"},
    "commitment_discount_scanner": {"commitment_discount_opportunity"},
    "advisor_cost_scanner": {"advisor_cost_recommendation"},
    "service_retirement_scanner": {"service_retirement"},
    "marketplace_saas_scanner": {"marketplace_saas_unsubscribed", "marketplace_saas_term_ending",
                                 "marketplace_saas_commitment", "marketplace_saas_inactive"},
}


@pytest.mark.parametrize("scanner_name, expected", sorted(EXPECTED.items()))
def test_scanner_mock_mode_produces_expected_finding_types(scanner_name, expected):
    output = _run(scanner_name)
    assert not output.warnings, output.warnings
    assert {f.finding_type for f in output.findings} == expected


@pytest.mark.parametrize("scanner_name", sorted(EXPECTED))
def test_one_finding_per_resource_and_type(scanner_name):
    # The worker upserts on (resource, finding_type); duplicates would silently collapse.
    keys = [(f.resource_id, f.finding_type) for f in _run(scanner_name).findings]
    assert len(keys) == len(set(keys))
    assert all(f.resource_id and f.resource_name and f.resource_group for f in _run(scanner_name).findings)


def test_new_orphan_types_are_registered_for_inventory_flagging():
    for t in ("unused_ddos_protection_plan", "orphaned_nsg", "public_ip_on_orphaned_nic", "idle_iot_hub",
              "idle_cosmos_db", "empty_resource_group", "private_dns_zone_without_endpoints"):
        assert t in ORPHAN_FINDING_TYPES


def test_ddos_saving_uses_list_price_without_live_client():
    finding = _run("unassociated_ddos_plan_scanner").findings[0]
    assert finding.severity == SeverityLevel.CRITICAL
    assert finding.estimated_monthly_savings_usd == pytest.approx(2944.0)


def test_rdp_rule_reaching_no_vm_is_low():
    finding = _run("open_management_port_scanner").findings[0]
    assert finding.severity == SeverityLevel.LOW
    assert "no exposure today" in finding.description
    assert finding.evidence["exposed_rules"] == [{"rule": "RDP", "ports": [3389], "priority": 300}]


@pytest.mark.parametrize("power, subnets, severity", [
    ("PowerState/running", 0, SeverityLevel.CRITICAL),
    ("PowerState/deallocated", 0, SeverityLevel.MEDIUM),
    ("PowerState/stopped", 0, SeverityLevel.MEDIUM),
    ("PowerState/deallocated", 1, SeverityLevel.CRITICAL),   # on a subnet: reachable whatever this VM does
])
def test_rdp_rule_severity_follows_what_it_exposes(monkeypatch, power, subnets, severity):
    cls = ScannerRegistry.get("open_management_port_scanner")
    nsg = cls()._mock_data()[0]
    nic = nsg["nic_ids"][0]["id"].lower()
    nsg["subnet_count"] = subnets

    async def nics(self, context, query):
        return {nic: {"vm": "vm-1", "power": power}}
    monkeypatch.setattr(cls, "_mock_data", lambda self: [nsg])
    monkeypatch.setattr(cls, "_nics_with_vm", nics)
    finding = asyncio.run(cls(config={}).execute(_context())).findings[0]
    assert finding.severity == severity


def test_app_service_pv2_to_pv3_saving():
    finding = next(f for f in _run("app_service_plan_generation_scanner").findings
                   if f.finding_type == "app_service_plan_previous_generation")
    assert finding.evidence["recommended_sku"] == "P2v3"
    assert finding.estimated_monthly_savings_usd == pytest.approx((0.800 - 0.676) * 730, rel=1e-3)


def test_hyperscale_saving_uses_price_ratio():
    finding = _run("sql_hyperscale_legacy_pricing_scanner").findings[0]
    ratio = database.HYPERSCALE_STORAGE_USD["current"] / database.HYPERSCALE_STORAGE_USD["legacy"]
    assert finding.estimated_monthly_savings_usd == pytest.approx(875.0 * (1 - ratio), rel=1e-3)


def test_budget_finding_is_attached_to_budget_resource():
    finding = _run("budget_scanner").findings[0]
    assert finding.resource_type == "microsoft.consumption/budgets"
    assert "6/6" in finding.title


def test_budget_only_counts_months_since_budget_start():
    cls = ScannerRegistry.get("budget_scanner")

    class LateBudget(cls):
        def _mock_sets(self):
            budgets, monthly = super()._mock_sets()
            budgets[0]["properties"]["timePeriod"] = {"startDate": "2026-07-01T00:00:00Z"}
            budgets[0]["properties"]["notifications"] = {"a": {"contactEmails": ["owner@contoso.com"]}}
            return budgets, monthly

    finding = asyncio.run(LateBudget().execute(_context())).findings[0]
    assert "2/2" in finding.title
    assert "Owners are notified" in finding.description


def test_commitment_scanner_keeps_best_term_per_recommendation():
    finding = _run("commitment_discount_scanner").findings[0]
    assert finding.estimated_monthly_savings_usd == pytest.approx((3311.0 + 1647.0) / 12, rel=1e-3)


def test_budget_missing_is_high_when_spend_is_material():
    cls = ScannerRegistry.get("budget_scanner")

    class NoBudget(cls):
        def _mock_sets(self):
            _, monthly = super()._mock_sets()
            monthly[-1]["cost_usd"] = 218000.0
            return [], monthly

    finding = asyncio.run(NoBudget(config={}).execute(_context())).findings[0]
    assert finding.finding_type == "budget_missing"
    assert finding.severity == SeverityLevel.HIGH
    assert "Peak monthly spend" in finding.description

    class SmallNoBudget(cls):
        def _mock_sets(self):
            return [], [{"month": "2026-08", "cost": 50.0, "cost_usd": 60.0, "currency": "CHF"}]

    assert asyncio.run(SmallNoBudget(config={}).execute(_context())).findings[0].severity == SeverityLevel.MEDIUM


def test_marketplace_saas_rules():
    by_name = {f.resource_name: f for f in _run("marketplace_saas_scanner").findings}
    assert by_name["mail-shield-2024"].finding_type == "marketplace_saas_unsubscribed"
    assert by_name["mail-shield-2024"].severity == SeverityLevel.LOW
    renew = by_name["mail-shield"]
    assert renew.finding_type == "marketplace_saas_term_ending" and "auto-renews in 45 days" in renew.title
    assert renew.severity == SeverityLevel.MEDIUM
    assert by_name["backup-saas"].finding_type == "marketplace_saas_commitment"
    assert by_name["analytics-saas"].finding_type == "marketplace_saas_inactive"
    assert by_name["analytics-saas"].severity == SeverityLevel.HIGH
    assert "marketplace_saas_unsubscribed" in ORPHAN_FINDING_TYPES


def test_marketplace_saas_term_ending_without_auto_renew_is_urgent():
    cls = ScannerRegistry.get("marketplace_saas_scanner")

    class Expiring(cls):
        def _mock_data(self):
            row = super()._mock_data()[1]
            row.update(autoRenew=False, termEnd=date.today().isoformat())
            return [row]

    finding = asyncio.run(Expiring(config={}).execute(_context())).findings[0]
    assert "auto-renew off" in finding.title and finding.severity == SeverityLevel.HIGH


def test_defender_titles_name_the_recommendation_not_a_guid():
    cls = ScannerRegistry.get("defender_recommendations_scanner")
    guid = "12345678-1234-4123-8123-123456789abc"

    class Entities(cls):
        def _mock_data(self):
            return [{"resource_id": f"/subscriptions/sub-1/providers/Microsoft.Security/pricings/CloudPosture/securityentitydata/{guid}",
                     "assessment": "Guest accounts with read permissions on Azure resources should be removed",
                     "severity": "high", "category": "IdentityAndAccess"}] + super()._mock_data()

    findings = asyncio.run(Entities(config=ENABLED["defender_recommendations_scanner"]).execute(_context())).findings
    titles = {f.title for f in findings}
    assert "Defender: Guest accounts with read permissions on Azure resources should be removed (subscription)" in titles
    assert "Defender: Role-Based Access Control should be used on Azure Keyvault Services (AKV) (kv-legacy-1)" in titles
    assert not any(guid in t or "sub-1" in t for t in titles)


@pytest.mark.parametrize("scanner_name", sorted(EXPECTED))
def test_declared_finding_types_cover_what_the_scanner_emits(scanner_name):
    # The Docker worker closes open findings of the declared types that a run no longer reports.
    declared = ScannerRegistry.get(scanner_name).finding_types
    if declared:
        assert {f.finding_type for f in _run(scanner_name).findings} <= set(declared)


def test_defender_plan_recommendations_are_left_out_unless_switched_on():
    default = _run("defender_recommendations_scanner")
    text = " ".join(f.title + f.description for f in default.findings)
    assert "Defender for Storage plan" not in text and "Defender CSPM" not in text
    assert "stdata1" not in {f.resource_name for f in default.findings}   # its only recommendation was a plan upsell
    assert len(default.metadata["excluded_plan_recommendations"]) == 2
    included = _run("defender_recommendations_scanner", {"defender_recommendations": True,
                                                     "defender_plan_recommendations": True})
    assert "stdata1" in {f.resource_name for f in included.findings}
    assert not included.metadata


def test_defender_recommendations_are_a_summary_unless_switched_on():
    off = _run("defender_recommendations_scanner", {})
    assert off.findings == [] and off.metadata == {"disabled_by_setting": "defender_recommendations"}


def test_plan_recommendation_pattern():
    from scanners.security.defender_guidance import is_plan_recommendation

    for name in ("Microsoft Defender for Storage plan should be enabled with Malware Scanning and Sensitive Data "
                 "Threat Detection", "Microsoft Defender CSPM should be enabled",
                 "Microsoft Defender for SQL should be enabled for unprotected Azure SQL servers",
                 "Azure Kubernetes Service clusters should have Defender profile enabled"):
        assert is_plan_recommendation(name), name
    for name in ("Windows Defender Exploit Guard should be enabled on machines",
                 "Linux virtual machines should enable Azure Disk Encryption or EncryptionAtHost.",
                 "Storage accounts should prevent shared key access"):
        assert not is_plan_recommendation(name), name


def test_defender_finding_is_specific_os_updates_collapse_and_encryption_has_commands():
    vm = next(f for f in _run("defender_recommendations_scanner").findings if f.resource_name == "vm-app-1")
    assert "Install missing OS / package updates (2: libc6, openssl)" in vm.description
    assert "Update openssl" not in vm.description                       # one entry per machine, not per package
    assert "az vm update -g rg-app -n vm-app-1 --set securityProfile.encryptionAtHost=true" in vm.azure_cli_script
    assert "az vm install-patches -g rg-app -n vm-app-1" in vm.azure_cli_script
    assert "Open Defender for Cloud" not in vm.remediation_steps         # the old generic text is gone
    keys = {a.get("guidance_key") for a in vm.evidence["assessments"]}
    assert keys == {"system_updates", "encryption_at_host"}


def test_suppression_reason_only_for_plan_only_findings():
    scanner = ScannerRegistry.get("defender_recommendations_scanner")(config={})
    plan_only = {"assessments": [{"assessment": "Microsoft Defender CSPM should be enabled"}]}
    mixed = {"assessments": [{"assessment": "Microsoft Defender CSPM should be enabled"},
                             {"assessment": "Storage accounts should prevent shared key access"}]}
    assert "excluded by setting" in scanner.suppression_reason_for(plan_only)
    assert scanner.suppression_reason_for(mixed) is None


def test_defender_plan_coverage_is_off_by_default_and_prices_each_plan():
    off = _run("defender_plan_coverage_scanner", {})
    assert off.findings == [] and off.metadata == {"disabled_by_setting": "defender_plan_coverage"}
    finding = _run("defender_plan_coverage_scanner").findings[0]
    plans = {p["plan"]: p for p in finding.evidence["disabled_plans"]}
    assert plans["CloudPosture"]["monthly_usd"] == pytest.approx(37 * 5.00)   # 37 storage accounts are billable
    assert plans["AI"]["monthly_usd"] is None                                # token-based
    assert finding.evidence["cost_of_change"]["monthly_usd"] == pytest.approx(185.0)
    assert "USD 185/month" in finding.title


def test_ai_gateway_saving_is_net_of_the_gateway_cost():
    findings = {f.resource_name: f for f in _run("ai_spend_governance_scanner").findings
                if f.finding_type == "ai_spend_without_gateway"}
    big = findings["ai-agents-1"]
    gateway = big.evidence["gateway"]
    assert gateway["monthly_usd"] == 150.0 and gateway["sku"] == "Basic v2"
    assert gateway["allocated_usd"] == pytest.approx(150.0 * 2200 / 2350, abs=0.01)
    assert big.estimated_monthly_savings_usd == pytest.approx(2200 * 0.15 - gateway["allocated_usd"], abs=0.01)
    assert big.evidence["cost_of_change"]["included_in_saving"] is True
    assert "What a gateway delivers" in big.description


def test_ai_gateway_below_break_even_claims_no_saving():
    cls = ScannerRegistry.get("ai_spend_governance_scanner")

    class Small(cls):
        def _mock_data(self):
            return [dict(super()._mock_data()[2], cost_usd_30d=300.0)]   # 15 % of 300 = 45 < 150 gateway

    finding = asyncio.run(Small(config={}).execute(_context())).findings[0]
    assert finding.estimated_monthly_savings_usd == 0.0 and finding.severity == SeverityLevel.LOW
    assert "below break-even" in finding.title and "about USD 1,000/month" in finding.description


def test_naming_convention_check_can_be_switched_off():
    assert _run("naming_convention_scanner", {}).findings
    off = _run("naming_convention_scanner", {"naming_convention_enabled": False})
    assert off.findings == [] and off.metadata == {"disabled_by_setting": "naming_convention_enabled"}


def test_provider_registration_findings_skip_the_governance_baseline_and_core_services():
    default = {f.finding_type for f in _run("resource_provider_registration_scanner").findings}
    assert default == {"resource_provider_blocked_registered"}           # unused providers: opt-in
    out = _run("resource_provider_registration_scanner", {"report_unused_providers": True})
    by_type = {f.finding_type: f for f in out.findings}
    unused = by_type["resource_providers_registered_unused"]
    # not Microsoft.Security (governance baseline), not Microsoft.Web / Compute (core services)
    assert unused.evidence["unused_registered"] == ["Microsoft.ClassicCompute"]
    assert unused.severity.value == "info" and "# az provider unregister" in unused.azure_cli_script
    blocked = by_type["resource_provider_blocked_registered"]
    assert "az provider unregister --namespace Microsoft.ClassicCompute --subscription sub-1" in blocked.azure_cli_script
    quiet = _run("resource_provider_registration_scanner", {"report_unused_providers": False,
                                                            "blocked_resource_providers": []})
    assert quiet.findings == []


def test_os_scanner_respects_as_of_date():
    assert not _run("unsupported_os_image_scanner", {"as_of": "2019-01-01"}).findings


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec, port, expected", [
    ("*", 3389, True), ("3389", 3389, True), ("3000-4000", 3389, True),
    ("443", 3389, False), ("", 22, False), (None, 22, False), ("abc", 22, False),
])
def test_port_spec_covers(spec, port, expected):
    assert network.port_spec_covers(spec, port) is expected


def test_exposed_management_ports_requires_internet_source():
    rule = {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "10.0.0.0/8",
            "destinationPortRange": "3389"}
    assert network.exposed_management_ports(rule, [22, 3389]) == []
    rule["sourceAddressPrefixes"] = ["Internet"]
    assert network.exposed_management_ports(rule, [22, 3389]) == [3389]


def test_os_end_of_support_uses_the_release_and_edition_of_the_image():
    label, eos = compute.os_end_of_support("Windows-10", "19h2-pro", date(2026, 1, 1))
    assert label == "Windows 10 1909" and eos == date(2021, 5, 11)
    assert compute.os_end_of_support("windows-11", "win11-24h2-pro", date(2026, 1, 1)) is None
    assert compute.os_end_of_support("windows-11", "win11-24h2-pro", date(2026, 10, 22))[1] == date(2026, 10, 13)


@pytest.mark.parametrize("config, expected", [
    ({"netFrameworkVersion": "v6.0"}, ".NET 6"),
    ({"linuxFxVersion": "DOTNETCORE|6.0"}, ".NET 6"),
    ({"linuxFxVersion": "NODE|20-lts"}, "Node.js 20"),
    ({"linuxFxVersion": "NODE|24-lts"}, None),
    ({"netFrameworkVersion": "v4.0"}, None),
])
def test_runtime_end_of_support(config, expected):
    hit = compute.runtime_end_of_support(compute.runtime_stack(config))
    assert (hit[0] if hit else None) == expected


def test_classify_firewall_rules():
    buckets = database.classify_firewall_rules([
        {"name": "AllowAllWindowsAzureIps", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}},
        {"name": "ClientIPAddress_1", "properties": {"startIpAddress": "1.2.3.4", "endIpAddress": "1.2.3.4"}},
        {"name": "Everything", "properties": {"startIpAddress": "0.0.0.1", "endIpAddress": "255.255.255.255"}},
        {"name": "Office", "properties": {"startIpAddress": "10.0.0.0", "endIpAddress": "10.0.0.255"}},
    ])
    assert [r["name"] for r in buckets["allow_azure"]] == ["AllowAllWindowsAzureIps"]
    assert buckets["individual"][0]["portal_generated"] is True
    assert [r["name"] for r in buckets["wide"]] == ["Everything"]


def test_environment_inference_from_names_and_tags():
    assert name_tokens("webshop0dev0client04")[:1] == ["webshop0dev0client04"]
    assert env_from_name("webshop0dev0client04") == "nonprod"
    assert env_from_name("WebShopDatabase-Test") == "nonprod"
    assert env_from_name("sql-prod-weu") == "prod"
    assert env_from_name("lods-machineapi") is None
    assert env_from_tags({"Environment": "prod"}) == "prod"
    assert env_from_tags({"environmen": "dev"}) == "nonprod"


def test_tag_key_typo_detection():
    standard = ["environment", "owner", "costcenter"]
    assert governance.near_miss_tag_key("environmen", standard) == "environment"
    assert governance.near_miss_tag_key("Environment", standard) is None
    assert governance.near_miss_tag_key("GitBranch", standard) is None


def test_storage_account_family():
    assert storage.account_family("webshop0dev0client104") == "webshop0dev0client"


def test_site_environment_prefers_slot_name_then_custom_domain():
    sites = compute.mock_sites()
    assert compute.site_environment(sites[0]) == "prod"
    assert compute.site_environment(sites[1]) == "nonprod"


def test_summarize_metrics_ignores_missing_points():
    payload = {"value": [{"name": {"value": "CpuPercentage"}, "timeseries": [{"data": [
        {"average": 10.0, "maximum": 50.0}, {"average": None}, {"average": 30.0, "maximum": 100.0}]}]}]}
    summary = summarize_metrics(payload)["CpuPercentage"]
    assert summary["average"] == 20.0 and summary["maximum"] == 100.0 and summary["latest_average"] == 30.0


def test_rid_segment():
    rid = "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Web/sites/app"
    assert rid_segment(rid, "resourcegroups") == "rg-1"
    assert rid_segment(rid, "missing") is None


class _FakeArm:
    def __init__(self):
        self.metric_calls = 0
        self.cost_calls = 0

    async def metrics_summary(self, resource_id, names, **kwargs):
        self.metric_calls += 1
        return {names[0]: {"total": 5.0}}

    async def cost_query(self, scope, body):
        self.cost_calls += 1
        return [
            {"ResourceId": "/subscriptions/S/RG/X", "MeterSubCategory": "Files", "Cost": 10.0, "CostUSD": 12.0, "Currency": "CHF"},
            {"ResourceId": "/subscriptions/s/rg/x", "MeterSubCategory": "Defender", "Cost": 5.0, "CostUSD": 6.0, "Currency": "CHF"},
        ]


def test_live_helpers_cache_per_scan():
    ctx = _context()
    ctx.arm_client = _FakeArm()

    async def scenario():
        await cached_metrics(ctx, "/x", ["Transactions"])
        await cached_metrics(ctx, "/X", ["Transactions"])
        first = await get_resource_costs(ctx)
        second = await get_resource_costs(ctx)
        return first, second

    first, second = asyncio.run(scenario())
    assert ctx.arm_client.metric_calls == 1
    assert ctx.arm_client.cost_calls == 1
    assert first is second
    entry = first["/subscriptions/s/rg/x"]
    assert entry["cost"] == 15.0 and entry["cost_usd"] == 18.0 and entry["meters"] == {"Files": 10.0, "Defender": 5.0}
