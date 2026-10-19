"""Target-architecture controls for open PaaS endpoints (scanners/base/access_need.py), the scanners that use them,
and ARG's built-in reasoning (scripts/subscription_analysis/reasoning.py)."""
import asyncio

import pytest

import scanners.compute.compute_posture_scanners  # noqa: F401 - registers the scanners under test
import scanners.security.security_scanners  # noqa: F401
import scanners.storage.storage_posture_scanners  # noqa: F401
from scanners.base import access_need
from scanners.base.access_need import cli_for, decide, sensitive, summarise_context
from scanners.base.base_scanner import ScanContext, ScannerRegistry, SeverityLevel
from scripts.subscription_analysis import reasoning
from scripts.subscription_analysis.guidance import cost_summary, implementation_analysis

ACCOUNT = {"id": "/subscriptions/s/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdata",
           "name": "stdata", "resourceGroup": "rg-data", "location": "westeurope", "tags": {}}
EMPTY = summarise_context([])
APPS = summarise_context([{"t": "microsoft.web/sites", "name": "app-1", "location": "westeurope",
                           "integration": "/subscriptions/s/.../subnets/snet-int"},
                          {"t": "microsoft.network/virtualnetworks", "location": "westeurope"}])
READY = {**APPS, "private_dns_zones": ["privatelink.blob.core.windows.net", "privatelink.vaultcore.azure.net"]}


def _roles(d):
    return {o["option"]: o["role"] for o in d["alternatives"]}


def test_active_production_data_targets_a_private_endpoint_with_a_free_interim_step():
    d = decide("storage", ACCOUNT, APPS, data_operations_30d=52_000, production=True)
    assert d["option"] == "private_endpoint" and d["level"] == "high" and d["monthly_usd"] == pytest.approx(7.80)
    assert d["interim"]["option"] == "service_endpoint"                  # callers sit in VNets of the region
    assert any("privatelink.blob.core.windows.net" in p for p in d["prerequisites"])
    roles = _roles(d)
    assert roles["private_endpoint"] == "target" and roles["service_endpoint"] == "interim"
    assert roles["disable_public"] == "not suitable" and roles["keep_public"] == "not suitable"
    assert d["alternatives"][0]["option"] == "private_endpoint"          # ranked: target first
    cli = cli_for(d, ACCOUNT)
    assert cli.index("# Now - interim") < cli.index("# Target") and "--group-id blob" in cli
    steps = access_need.remediation(d, "storage account")
    assert steps.startswith("Now - interim") and "Target - private endpoint" in steps


def test_no_interim_when_the_landing_zone_is_ready():
    d = decide("storage", ACCOUNT, READY, data_operations_30d=52_000, production=True)
    assert d["option"] == "private_endpoint" and d["interim"] is None and d["prerequisites"] == []
    assert d["signals"]["dns_zone_exists"] is True


def test_data_nobody_reads_gets_no_network_path_rather_than_a_private_endpoint():
    d = decide("storage", ACCOUNT, APPS, data_operations_30d=0, production=True)
    assert d["option"] == "disable_public" and d["level"] == "low" and d["interim"] is None
    assert "stronger than a private endpoint" in d["why"]
    assert _roles(d)["private_endpoint"] == "alternative"
    assert next(o for o in d["alternatives"] if o["option"] == "private_endpoint")["note"].startswith("Not needed")


def test_boot_diagnostics_azure_only_writers_and_public_by_design():
    boot = decide("storage", ACCOUNT, EMPTY, data_operations_30d=4000, boot_diagnostics_vms=["vm-1", "vm-2"])
    assert boot["option"] == "disable_public" and "managed boot diagnostics" in boot["why"]
    assert "az vm boot-diagnostics enable" in access_need.remediation(boot, "storage account")
    trusted = decide("storage", ACCOUNT, EMPTY, data_operations_30d=900, azure_services_only="Azure Monitor")
    assert trusted["option"] == "trusted_services"
    public = decide("storage", {**ACCOUNT, "tags": {"arg-public": "cdn origin"}}, EMPTY, data_operations_30d=9e6)
    assert public["option"] == "keep_public" and public["level"] == "low"


def test_confidential_data_always_targets_a_private_endpoint():
    d = decide("storage", ACCOUNT, EMPTY, data_operations_30d=0, sensitive_rule="DataClassification=Confidential")
    assert d["option"] == "private_endpoint" and d["level"] == "high" and "DataClassification=Confidential" in d["why"]
    two = decide("storage", ACCOUNT, EMPTY, sensitive_rule="x", sub_resources=2)   # blob + dfs (ADLS)
    assert two["monthly_usd"] == pytest.approx(2 * 7.30 + 0.50)
    assert sensitive({"DataClassification": "Confidential"}, ["dataclassification=internal", "DataClassification=Confidential"]) == "DataClassification=Confidential"
    assert sensitive({"DataClassification": "x"}, ["dataclassification"]) == "dataclassification"
    assert sensitive({"DataClassification": "Confidential"}, ["DataClassification=Public"]) is None


def test_context_summary():
    ctx = summarise_context([
        {"t": "microsoft.network/virtualnetworks", "location": "westeurope",
         "peerings": [{"properties": {"useRemoteGateways": True}}]},
        {"t": "microsoft.network/privateendpoints", "location": "westeurope", "links": [
            {"properties": {"privateLinkServiceId": "/subscriptions/s/resourceGroups/r/providers/"
                                                    "Microsoft.KeyVault/vaults/kv-other"}}]}])
    assert ctx["onprem"] and ctx["pe_target_types"] == ["microsoft.keyvault/vaults"]
    assert ctx["vnet_regions"] == ["westeurope"]


def test_implementation_carries_the_target_and_its_cost():
    d = decide("storage", ACCOUNT, APPS, data_operations_30d=52_000, production=True)
    impl = implementation_analysis({"finding_type": "storage_public_network_access",
                                    "evidence": {"access_decision": d, "cost_of_change": access_need.cost_of_change(d)}})
    assert impl["monthly_usd"] == pytest.approx(7.80) and impl["decision"]["option"] == "private_endpoint"
    assert impl["hours"] == [1, 4] and cost_summary(impl).startswith("+USD 7.80/month")


# ---- reasoning ------------------------------------------------------------------------------------------------------

def test_reasoning_cites_the_evidence_ranks_options_and_says_how_to_verify():
    d = decide("storage", ACCOUNT, APPS, data_operations_30d=52_000, production=True)
    finding = {"finding_type": "storage_public_network_access", "resource_id": ACCOUNT["id"], "resource_name": "stdata",
               "resource_group": "rg-data", "title": "Storage open to all networks: stdata",
               "remediation_steps": "1. a\n2. b",
               "evidence": {"publicNetworkAccess": "Enabled", "data_operations_30d": 52_000, "access_decision": d,
                            "cost_of_change": access_need.cost_of_change(d)}}
    r = reasoning.reason(finding, related=["Shared-key access allowed: stdata"])
    assert "data reads / writes in 30 days: 52,000" in r["observed"]
    assert "VNet-integrated apps in the region: app-1" in r["observed"]
    assert [c["role"] for c in r["considered"]][:2] == ["target", "interim"]
    assert "Environment: production." in r["context"]
    assert any("Shared-key access allowed" in c for c in r["context"])
    assert any(v.startswith("az storage account show -n stdata -g rg-data") for v in r["verify"])
    assert any("Power BI" in x for x in r["risks"]) and r["confidence"]["level"] == "high"
    md = "\n".join(reasoning.markdown(r))
    assert "**How ARG reasoned**" in md and "| **target** | Private endpoint" in md


def test_reasoning_for_other_findings_uses_their_own_values():
    finding = {"finding_type": "deallocated_virtual_machine", "title": "Deallocated VM: vm-old",
               "resource_id": "/subscriptions/s/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-old",
               "evidence": {"days_deallocated": 120, "size": "Standard_D4s_v5"}, "remediation_steps": "1. Snapshot"}
    r = reasoning.reason(finding)
    assert "days deallocated: 120" in r["observed"] and "size: Standard_D4s_v5" in r["observed"]
    assert r["verify"][0].startswith("az vm get-instance-view -g rg-app -n vm-old")
    unknown = reasoning.reason({"finding_type": "something_new", "title": "Verify x", "evidence": {"verified": False}})
    assert unknown["confidence"]["level"] == "low" and unknown["verify"][0].startswith("Re-run the analysis")


# ---- scanners --------------------------------------------------------------------------------------------------------

def _context(subscription_name="sub-dev-app"):
    return ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j", subscription_name=subscription_name)


def test_storage_scanner_puts_the_target_in_the_finding():
    cls = ScannerRegistry.get("storage_access_hardening_scanner")
    finding = next(f for f in asyncio.run(cls(config={}).execute(_context("sub-prod-app"))).findings
                   if f.finding_type == "storage_public_network_access")
    decision = finding.evidence["access_decision"]
    assert decision["option"] == "private_endpoint" and decision["interim"]["option"] == "ip_rules"
    assert finding.evidence["cost_of_change"]["monthly_usd"] == pytest.approx(7.80)
    assert finding.severity == SeverityLevel.HIGH and finding.remediation_steps.startswith("Target: Private endpoint")
    nonprod = next(f for f in asyncio.run(cls(config={}).execute(_context("sub-dev-app"))).findings
                   if f.finding_type == "storage_public_network_access")
    assert nonprod.severity == SeverityLevel.LOW


def test_public_sql_server_no_longer_sells_defender():
    cls = ScannerRegistry.get("public_sql_server_scanner")
    findings = asyncio.run(cls(config={}).execute(_context("sub-prod-app"))).findings
    assert findings and all("Defender" not in (f.remediation_steps or "") for f in findings)
    assert all(f.severity != SeverityLevel.CRITICAL for f in findings)
    assert all(f.evidence.get("access_decision") for f in findings)


def test_single_instance_plan_only_in_production():
    cls = ScannerRegistry.get("app_service_plan_generation_scanner")

    class Dev(cls):
        def _mock_data(self):
            return [{**row, "tags": {"Environment": "dev"}} for row in super()._mock_data()]

    dev = asyncio.run(Dev(config={}).execute(_context("sub-dev-app"))).findings
    assert not [f for f in dev if f.finding_type == "app_service_plan_single_instance"]


def test_diagnostics_use_the_audit_category_group_and_skip_nsgs():
    cls = ScannerRegistry.get("missing_diagnostic_settings_scanner")
    findings = asyncio.run(cls(config={}).execute(_context("sub-prod-app"))).findings
    assert findings and all('"categoryGroup": "audit"' in f.azure_cli_script for f in findings)
    assert all("networksecuritygroups" not in (f.resource_type or "") for f in findings)
