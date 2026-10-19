"""
Architect views: Advisor cost / retirement scanners, Defender / Advisor de-duplication, systemic issues, cost
coverage and allocation, quick wins, retirement calendar, changes between runs, Azure Boards backlog.
"""

import asyncio
import csv
import json
from datetime import date

import scanners.cost.cost_scanners  # noqa: F401
import scanners.governance.governance_posture_scanners  # noqa: F401
from scanners.base.base_scanner import ScanContext, ScannerRegistry, SeverityLevel
from scanners.base.posture_scanner import ADVISOR_ACTIVE_FILTER
from scripts.subscription_analysis import insights
from scripts.subscription_analysis.correlate import correlate


def _run(name, config=None):
    ctx = ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j")
    return asyncio.run(ScannerRegistry.get(name)(config=config or {}).execute(ctx))


def test_retirements_are_dated_and_rated_by_time_left():
    out = _run("service_retirement_scanner", {"as_of": "2026-10-06"})
    by_name = {f.resource_name: f for f in out.findings}
    node = by_name["app-portal"]
    assert node.severity == SeverityLevel.HIGH and node.title.startswith("Past retirement date 2026-04-30")
    kv = by_name["kv-legacy-1"]
    assert kv.severity == SeverityLevel.MEDIUM and "144 days" in kv.title
    assert kv.evidence["cost_of_change"]["monthly_usd"] == 0.0          # Advisor: no cost implication
    assert "API version in use: 2019-09-01" in kv.remediation_steps


def test_advisor_queries_skip_completed_and_dismissed_recommendations():
    assert "recommendationStatus" in ADVISOR_ACTIVE_FILTER and "Resolved" in ADVISOR_ACTIVE_FILTER


def test_advisor_cost_recommendations_are_grouped_per_resource_with_kusto_commands():
    finding = _run("advisor_cost_scanner").findings[0]
    assert finding.finding_type == "advisor_cost_recommendation" and finding.estimated_monthly_savings_usd == 500.0
    assert "(2 tables)" in finding.title and "adx-prod-1" in finding.title
    assert ".alter table Telemetry policy caching hot = 4d" in finding.azure_cli_script
    assert "hot cache 100 days → 4 Day(s)" in finding.remediation_steps


def _finding(ftype, rid, **kw):
    return {"finding_type": ftype, "resource_id": rid, "resource_name": rid.rsplit("/", 1)[-1], "title": ftype,
            "severity": kw.pop("severity", "medium"), "evidence": kw.pop("evidence", {}), **kw}


KV = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"


def test_defender_duplicates_merge_into_the_native_finding():
    native = _finding("key_vault_access_policy_model", KV)
    defender = _finding("defender_recommendations", KV.lower(), evidence={"assessments": [
        {"assessment": "Role-Based Access Control should be used on Azure Keyvault Services (AKV)", "steps": "a"},
        {"assessment": "Diagnostic logs in Key Vault should be enabled", "label": "Diagnostic logs in Key Vault "
                                                                                   "should be enabled", "steps": "b",
         "cli": "az monitor diagnostic-settings create"}]})
    kept, stats = correlate([native, defender])
    assert stats["defender_recommendations_merged"] == 1 and len(kept) == 2
    assert native["evidence"]["also_reported_by"] == [
        "Defender for Cloud: Role-Based Access Control should be used on Azure Keyvault Services (AKV)"]
    assert defender["title"] == "Defender: Diagnostic logs in Key Vault should be enabled (kv1)"
    assert defender["remediation_steps"].startswith("Diagnostic logs in Key Vault should be enabled:\nb")
    assert "Role-Based" not in defender["azure_cli_script"]


def test_fully_covered_defender_finding_and_advisor_duplicate_saving_are_dropped():
    sub_native = _finding("excessive_subscription_owners", "/subscriptions/s1")
    entity = _finding("defender_recommendations", "/subscriptions/s1/providers/microsoft.security/pricings/x/"
                                                  "securityentitydata/guid",
                      evidence={"assessments": [{"assessment": "A maximum of 3 owners should be designated for "
                                                               "subscriptions"}]})
    vm = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    rightsize = _finding("vm_rightsizing_opportunity", vm, estimated_monthly_savings_usd=80.0)
    advisor = _finding("advisor_cost_recommendation", vm.lower(), estimated_monthly_savings_usd=141.0,
                       evidence={"advisor": [{"problem": "Right-size or shutdown underutilized virtual machines"}]})
    kept, stats = correlate([sub_native, entity, rightsize, advisor])
    assert kept == [sub_native, rightsize] and stats["findings_dropped"] == 2
    assert rightsize["evidence"]["also_reported_by"] == [
        "Azure Advisor: Right-size or shutdown underutilized virtual machines"]


def test_systemic_issue_needs_many_resources_or_most_of_a_type():
    resources = [{"type": "Microsoft.Storage/storageAccounts"} for _ in range(12)] + [
        {"type": "Microsoft.KeyVault/vaults"} for _ in range(4)]
    findings = [_finding("storage_shared_key_access_enabled", f"/s/st{i}", ref=f"F-{i:03d}",
                         resource_type="microsoft.storage/storageaccounts") for i in range(11)]
    findings += [_finding("key_vault_purge_protection_disabled", f"/s/kv{i}", ref=f"F-1{i:02d}",
                          resource_type="microsoft.keyvault/vaults") for i in range(3)]
    findings += [_finding("orphaned_nic", "/s/nic", ref="F-200", resource_type="microsoft.network/networkinterfaces")]
    systemic = {s["finding_type"]: s for s in insights.systemic_issues(findings, resources)}
    assert set(systemic) == {"storage_shared_key_access_enabled", "key_vault_purge_protection_disabled"}
    shared = systemic["storage_shared_key_access_enabled"]
    assert shared["count"] == 11 and shared["population"] == 12 and shared["guardrails"]
    assert systemic["key_vault_purge_protection_disabled"]["share"] == 0.75


def test_allocation_and_coverage_are_weighted_by_cost():
    a = "/subscriptions/s/resourcegroups/rg/providers/x/y/a"
    b = "/subscriptions/s/resourcegroups/rg/providers/x/y/b"
    resources = [{"id": a, "tags": {"Owner": "x", "cost-center": "1"}}, {"id": b, "tags": {"owner": "y"}}]
    costs = {a: {"cost": 900.0}, b: {"cost": 100.0}, "/subscriptions/s/gone": {"cost": 0.0}}
    alloc = insights.allocation(resources, costs, ["owner", "cost-center"])
    assert alloc["share"] == 0.9 and alloc["missing_by_tag"] == {"cost-center": 100.0, "owner": 0.0}
    cov = insights.cost_coverage([(a, {"cost": 900.0, "meters": {"Compute": 900}}), (b, {"cost": 100.0})],
                                 [_finding("vm_rightsizing_opportunity", a, ref="F-001")], 1000.0)
    assert cov["uncovered_cost"] == 100.0 and cov["rows"][0]["findings"] == ["F-001"]


def test_quick_wins_calendar_and_changes():
    cheap = _finding("unused_public_ip", "/a", severity="high", ref="F-001", estimated_monthly_savings_usd=4.0,
                     implementation={"hours": [0.1, 0.25], "monthly_usd": 0.0})
    slow = _finding("vm_unsupported_os", "/b", severity="critical", ref="F-002",
                    implementation={"hours": [4, 16], "monthly_usd": 0.0},
                    evidence={"end_of_support": "2026-01-13"}, title="End-of-support OS (Windows 10): vm")
    pe = _finding("storage_public_network_access", "/c", severity="high", ref="F-003",
                  implementation={"hours": [1, 4], "monthly_usd": 7.3})
    assert insights.quick_wins([slow, pe, cheap]) == [cheap]
    retire = _finding("service_retirement", "/d", ref="F-004", evidence={"retirements": [
        {"retirement_date": "2027-02-27", "feature": "API versions prior to 2026-02-01", "cost_implication": "None"}]})
    calendar = insights.retirement_calendar([retire, slow], today=date(2026, 10, 6))
    assert [r["refs"] for r in calendar] == [["F-002"], ["F-004"]] and calendar[0]["days_left"] < 0
    assert calendar[1]["what"] == "API versions prior to 2026-02-01" and calendar[1]["resources"] == ["d"]
    before = [cheap, slow]
    after = [dict(slow, severity="critical"), dict(pe)]
    delta = insights.changes(before, after)
    assert [f["ref"] for f in delta["new"]] == ["F-003"] and [f["ref"] for f in delta["resolved"]] == ["F-001"]
    assert insights.changes(None, after) is None


def test_report_leads_with_architect_views_and_writes_backlog_and_history(tmp_path):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent))
    from test_subscription_report import _analysis

    from scripts.subscription_analysis.report import read_previous_findings, write_report

    data = _analysis()
    data.settings = {"required_tags": ["owner", "environment"]}
    data.reliability = [{"resource_id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Storage/"
                                        "storageAccounts/stprod1", "problem": "Enable zone redundancy for storage "
                                        "accounts", "sub_category": "ZoneResiliency", "impact": "High",
                         "impacted_name": "stprod1"},
                        {"resource_id": "/x", "problem": "Enable Soft Delete to protect your blob data",
                         "sub_category": "DataProtectionAndRecovery"}]
    write_report(data, tmp_path)
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    for text in ("actionable", "### Where the money is", "## Quick wins", "Cost allocation:", "backlog.csv"):
        assert text in readme, text
    current = (tmp_path / "01-current-findings" / "README.md").read_text(encoding="utf-8")
    assert "## 8. Resilience Posture (Azure Advisor)" in current and "Enable zone redundancy" in current
    assert "Soft Delete" not in current                                  # already a native ARG finding
    with (tmp_path / "backlog.csv").open(encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert rows and set(rows[0]) == {"Work Item Type", "Title", "Description", "Priority", "Tags", "Remaining Work"}
    assert all(r["Title"].startswith("[ARG") and r["Priority"] in "1234" for r in rows)
    assert not any("missing_required_tags" in r["Tags"] and "systemic" not in r["Tags"] for r in rows)

    previous = read_previous_findings(tmp_path)
    data.findings = [f for f in data.findings if f["finding_type"] != "unused_ddos_protection_plan"]
    write_report(data, tmp_path, previous_findings=previous)
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "## Changes since the previous analysis" in readme and "Resolved or no longer reported (1)" in readme
    history = json.loads((tmp_path / "history.json").read_text(encoding="utf-8"))
    assert len(history) == 2 and "(this run)" in readme


def test_undated_advisor_upgrade_advice_is_not_a_retirement():
    cls = ScannerRegistry.get("service_retirement_scanner")

    class WithUndated(cls):
        def _mock_data(self):
            return super()._mock_data() + [{
                "resource_id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
                "problem": "Migrate workload to Virtual Machine Scale Sets Flex", "impacted_name": "vm1",
                "retirement_date": ""}]

    ctx = ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j")
    out = asyncio.run(WithUndated(config={"as_of": "2026-10-06"}).execute(ctx))
    assert "vm1" not in {f.resource_name for f in out.findings}
    assert out.metadata == {"undated_upgrade_advice_skipped": 1}
    out = asyncio.run(WithUndated(config={"as_of": "2026-10-06", "retirement_include_undated": True}).execute(ctx))
    assert "vm1" in {f.resource_name for f in out.findings}


def test_advisor_runtime_retirement_merges_into_the_native_end_of_support_finding():
    app = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/app1"
    native = _finding("web_app_eol_runtime", app, evidence={"end_of_support": "2026-11-10"})
    advisor = _finding("service_retirement", app.lower(), evidence={"retirements": [
        {"problem": ".NET 8 (LTS) on App Service", "retirement_date": "2026-11-10"}]})
    kept, stats = correlate([native, advisor])
    assert kept == [native] and stats["retirements_merged"] == 1
    assert native["evidence"]["also_reported_by"] == ["Azure Advisor: .NET 8 (LTS) on App Service"]


def test_systemic_labels_read_like_english():
    assert insights.label("sql_firewall_allow_all_azure_services") == "SQL firewall allows all Azure services"
    assert insights.label("vm_public_ip_bypasses_bastion") == "VM public IP bypasses bastion"
