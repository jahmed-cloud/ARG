"""
Azure Policy governance: the policy snapshot analysis (scope, exemptions, remediation gaps, Indexed-mode blind spots,
location gap, coverage), the six scanners in mock mode, the what-governs lookup (pure function, CLI rendering, API
route) and the managed-by query. All offline - placeholder ids only.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import scanners.governance.policy_scanners as policy_scanners
from scanners.base.base_scanner import ScanContext, ScannerRegistry
from scanners.base.policy import (
    applies_to_subscription,
    build_snapshot,
    classify_exemption,
    governance_for_resource,
    location_gap,
    managed_by_query,
    mode_mismatches,
    remediation_gaps,
    scope_chain,
    summarize_managed,
    uncovered_types,
)

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)
SUB = "11111111-2222-3333-4444-555555555555"
MG = "/providers/microsoft.management/managementgroups/mg-landing-zones"
BUILTIN = "/providers/microsoft.authorization/policydefinitions/"


def _run(name, config=None):
    cls = ScannerRegistry.get(name)
    assert cls is not None, f"{name} is not registered"
    return asyncio.run(cls(config=config or {}).execute(
        ScanContext(subscription_id="sub-1", tenant_id="tenant-1", scan_job_id="job-1")))


def _assignment(name, scope, definition, enforcement="Default", **extra):
    return {"id": f"{scope}/providers/microsoft.authorization/policyassignments/{name}", "name": name, "scope": scope,
            "definitionId": definition, "enforcement": enforcement, **extra}


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

def test_assignments_apply_from_the_subscription_inside_it_and_ancestor_management_groups_only():
    ancestors = ["mg-landing-zones", "mg-root"]
    assert applies_to_subscription(f"/subscriptions/{SUB}", SUB, ancestors)
    assert applies_to_subscription(f"/subscriptions/{SUB.upper()}/resourceGroups/rg-app", SUB, ancestors)
    assert applies_to_subscription(MG, SUB, ancestors)
    assert not applies_to_subscription("/providers/microsoft.management/managementgroups/mg-sandbox", SUB, ancestors)
    assert not applies_to_subscription(f"/subscriptions/{SUB}0", SUB, ancestors)  # a different subscription


def test_scope_chain_runs_from_the_root_management_group_down_to_the_resource():
    rid = f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.Web/sites/web-1"
    assert scope_chain(rid, ["mg-landing-zones", "mg-root"]) == [
        "/providers/microsoft.management/managementgroups/mg-root", MG, f"/subscriptions/{SUB}",
        f"/subscriptions/{SUB}/resourcegroups/rg-app", rid.lower()]
    assert scope_chain(f"/subscriptions/{SUB}", []) == [f"/subscriptions/{SUB}"]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exemption, issues", [
    ({"expiresOn": "", "assignmentId": "a1", "refIds": ["x"]}, ["no_expiry"]),
    ({"expiresOn": "2026-01-01T00:00:00Z", "assignmentId": "a1", "refIds": ["x"]}, ["expired"]),
    ({"expiresOn": "2027-01-01T00:00:00Z", "assignmentId": "gone", "refIds": ["x"]}, ["orphaned"]),
    ({"expiresOn": "2027-01-01", "assignmentId": "a1", "refIds": [], "initiative": True}, ["whole_initiative"]),
    ({"expiresOn": "2027-01-01", "assignmentId": "a1", "refIds": [], "initiative": False}, []),  # single policy
])
def test_exemption_hygiene(exemption, issues):
    assert classify_exemption(exemption, {"a1"}, NOW) == issues


def test_remediation_gap_only_for_deploy_and_modify_with_non_compliant_resources_and_no_task():
    assignments = [{"id": "a1", "name": "Baseline", "enforced": True}, {"id": "a2", "name": "Tags", "enforced": False}]
    compliance = [
        {"assignmentId": "a1", "refId": "backup", "action": "deployifnotexists", "nonCompliant": 7},
        {"assignmentId": "a1", "refId": "diag", "action": "deployifnotexists", "nonCompliant": 3},  # remediated
        {"assignmentId": "a1", "refId": "tls", "action": "audit", "nonCompliant": 9},               # nothing to run
        {"assignmentId": "a1", "refId": "ok", "action": "modify", "nonCompliant": 0},               # compliant
        {"assignmentId": "a2", "refId": "", "action": "modify", "nonCompliant": 11},
        {"assignmentId": "other", "refId": "", "action": "modify", "nonCompliant": 5},              # not applied
    ]
    gaps = remediation_gaps(assignments, compliance, [{"assignmentId": "a1", "refId": "Diag"}])
    assert [(g["assignment"], g["reference"], g["non_compliant"], g["enforced"]) for g in gaps] == [
        ("Tags", None, 11, False), ("Baseline", "backup", 7, True)]


def test_indexed_definitions_aimed_at_resource_groups_are_flagged_all_mode_is_not():
    rule = {"if": {"field": "type", "equals": "Microsoft.Resources/subscriptions/resourceGroups"}}
    definitions = {"d1": {"name": "Tag RGs", "mode": "Indexed", "rule": rule},
                   "d2": {"name": "Tag RGs (fixed)", "mode": "All", "rule": rule},
                   "d3": {"name": "Tag resources", "mode": "Indexed", "rule": {"if": {"field": "tags", "exists": False}}}}
    assignments = [{"name": f"a-{d}", "definitionId": d} for d in ("d1", "d2", "d3", "builtin")]
    assert [m["definition"] for m in mode_mismatches(assignments, definitions)] == ["Tag RGs"]


def test_location_gap_needs_the_resource_group_policy_at_subscription_level():
    loc = {"name": "Allowed locations", "definitionId": BUILTIN + "e56962a6-4747-49cd-b67b-bf8b01975c4c",
           "resource_group": None}
    rg_loc = {"name": "Allowed RG locations", "definitionId": BUILTIN + "e765b5de-1225-4ba3-bd56-1ac6695af988",
              "resource_group": None}
    assert location_gap([loc]) == {"assignments": ["Allowed locations"]}
    assert location_gap([loc, rg_loc]) is None
    assert location_gap([loc, {**rg_loc, "resource_group": "rg-app"}]) is not None  # one RG does not cover all
    assert location_gap([]) is None


def test_uncovered_types_skip_evaluated_and_platform_types():
    usage = {"microsoft.web/sites": 4, "microsoft.compute/virtualmachines": 2,
             "microsoft.resources/subscriptions/resourcegroups": 5, "microsoft.security/assessments": 3}
    assert uncovered_types(usage, ["Microsoft.Compute/virtualMachines"]) == {"microsoft.web/sites": 4}


def test_snapshot_keeps_only_what_applies_and_judges_exemptions():
    other_mg = "/providers/microsoft.management/managementgroups/mg-sandbox"
    initiative = MG + "/providers/microsoft.authorization/policysetdefinitions/baseline"
    assignments = [
        _assignment("baseline", MG, initiative),
        _assignment("diag", f"/subscriptions/{SUB}", BUILTIN + "abc", enforcement="DoNotEnforce"),
        _assignment("sandbox-only", other_mg, BUILTIN + "def"),
        _assignment("other-sub", "/subscriptions/99999999-2222-3333-4444-555555555555", BUILTIN + "ghi"),
    ]
    exemptions = [{"id": "e1", "name": "Waiver", "scope": f"/subscriptions/{SUB}/resourcegroups/rg-legacy",
                   "expiresOn": "", "assignmentId": assignments[0]["id"], "refIds": []},
                  {"id": "e2", "name": "Elsewhere", "scope": other_mg, "expiresOn": "", "assignmentId": "x",
                   "refIds": []}]
    snap = build_snapshot(SUB, ["mg-landing-zones"], assignments, [], exemptions, [], [], {}, [], now=NOW)
    assert [a["name"] for a in snap["assignments"]] == ["baseline", "diag"]  # inherited first
    assert [(a["inherited"], a["enforced"], a["initiative"], a["builtin"]) for a in snap["assignments"]] == [
        (True, True, True, False), (False, False, False, True)]
    assert [(e["name"], e["issues"]) for e in snap["exemptions"]] == [("Waiver", ["no_expiry", "whole_initiative"])]


# ---------------------------------------------------------------------------
# Scanners (mock mode)
# ---------------------------------------------------------------------------

EXPECTED = {
    "policy_assignment_scanner": {"policy_assignments_not_enforced"},
    "policy_exemption_scanner": {"policy_exemption_no_expiry", "policy_exemption_expired", "policy_exemption_orphaned",
                                 "policy_exemption_whole_initiative"},
    "policy_remediation_scanner": {"policy_remediation_never_run"},
    "policy_effectiveness_scanner": {"policy_definition_mode_skips_containers", "allowed_locations_skip_resource_groups"},
    "policy_coverage_scanner": {"resource_types_without_policy"},
}


@pytest.mark.parametrize("name, types", sorted(EXPECTED.items()))
def test_policy_scanners_in_mock_mode(name, types):
    out = _run(name)
    assert not out.warnings
    assert {f.finding_type for f in out.findings} == types
    for f in out.findings:
        assert f.resource_type == "microsoft.resources/subscriptions" and f.remediation_steps


def test_remediation_finding_names_both_unremediated_policies_and_a_task_per_policy():
    (f,) = _run("policy_remediation_scanner").findings
    assert f.title.startswith("27 non-compliant resource(s) under 2 policy(ies)")
    assert f.azure_cli_script.count("az policy remediation create") == 2
    assert "--definition-reference-id deployVmBackup" in f.azure_cli_script


def test_no_assignment_at_all_is_one_finding_and_coverage_stays_quiet(monkeypatch):
    empty = build_snapshot("sub-1", [], [], [], [], [], [], {"microsoft.web/sites": 1}, [])
    monkeypatch.setattr(policy_scanners.PolicySnapshotScanner, "_mock_data", lambda self: [empty])
    assert [f.finding_type for f in _run("policy_assignment_scanner").findings] == ["no_policy_assignments"]
    assert _run("policy_coverage_scanner").findings == []


def test_unreadable_policy_data_is_a_warning_not_a_failed_scan(monkeypatch):
    async def boom(self, context):
        raise PermissionError("AuthorizationFailed")
    monkeypatch.setattr(policy_scanners.PolicySnapshotScanner, "snapshot", boom)
    out = _run("policy_exemption_scanner")
    assert out.findings == [] and "Azure Policy data unavailable" in out.warnings[0]


def test_required_extension_scanner_is_off_until_configured(monkeypatch):
    monkeypatch.delenv("REQUIRED_VM_EXTENSIONS", raising=False)
    assert _run("vm_required_extension_scanner").findings == []
    out = _run("vm_required_extension_scanner",
               {"required_vm_extensions": "AzureMonitorWindowsAgent|AzureMonitorLinuxAgent"})
    assert sorted((f.finding_type, f.resource_name) for f in out.findings) == [
        ("vm_required_extension_failed", "vm-app-03"), ("vm_required_extension_missing", "vm-app-02")]


def test_required_extension_list_from_the_environment(monkeypatch):
    monkeypatch.setenv("REQUIRED_VM_EXTENSIONS", "AzureMonitorWindowsAgent|AzureMonitorLinuxAgent, MDE.Windows|MDE.Linux")
    out = _run("vm_required_extension_scanner")
    missing = {f.resource_name: f.evidence.get("missing") for f in out.findings
               if f.finding_type == "vm_required_extension_missing"}
    assert missing["vm-app-01"] == ["mde.windows | mde.linux"]  # has the monitor agent, lacks the EDR agent


def test_parse_requirements_and_arc_matching():
    assert policy_scanners.parse_requirements(" A|B , C ,, ") == [["a", "b"], ["c"]]
    assert policy_scanners.parse_requirements(["X|y"]) == [["x", "y"]]
    arc = {"id": "/subscriptions/s/resourcegroups/r/providers/microsoft.hybridcompute/machines/srv-1"}
    ext = [{"machine": arc["id"], "name": "custom-name", "extensionType": "mde.linux", "state": "Succeeded"}]
    assert policy_scanners.missing_extensions([arc], ext, [["mde.windows", "mde.linux"]]) == []  # matched by type


def test_every_new_finding_type_has_a_report_placement():
    from scripts.subscription_analysis.knowledge import FINDING_CLASSIFICATION

    new_types = set().union(*EXPECTED.values(), {"no_policy_assignments", "vm_required_extension_missing",
                                                 "vm_required_extension_failed"})
    assert new_types <= set(FINDING_CLASSIFICATION)


# ---------------------------------------------------------------------------
# What governs this resource?
# ---------------------------------------------------------------------------

RID = f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.Web/sites/web-1"


def _governance():
    assignments = [
        _assignment("Allowed locations", MG, BUILTIN + "e56962a6-4747-49cd-b67b-bf8b01975c4c"),
        _assignment("Deny public web", f"/subscriptions/{SUB}", BUILTIN + "abc",
                    notScopes=[f"/subscriptions/{SUB}/resourceGroups/rg-app"]),     # excluded
        _assignment("Diagnostics", f"/subscriptions/{SUB}/resourcegroups/rg-app",
                    MG + "/providers/microsoft.authorization/policysetdefinitions/diag", enforcement="DoNotEnforce"),
        _assignment("Other RG", f"/subscriptions/{SUB}/resourcegroups/rg-other", BUILTIN + "def"),
    ]
    exemptions = [{"name": "Pilot", "scope": f"/subscriptions/{SUB}/resourcegroups/rg-app", "category": "Waiver",
                   "expiresOn": "", "assignmentId": "x", "refIds": []},
                  {"name": "Old", "scope": RID.lower(), "category": "Mitigated",
                   "expiresOn": (NOW - timedelta(days=1)).isoformat(), "assignmentId": "y", "refIds": ["m1"]}]
    states = [{"state": "Compliant", "effect": "audit", "policy": "p1", "assignment": "a"},
              {"state": "NonCompliant", "effect": "deny", "policy": "p2", "assignment": "b", "refId": "r2"}]
    return governance_for_resource(RID, ["mg-landing-zones"], assignments, exemptions, states, now=NOW)


def test_what_governs_lists_assignments_per_scope_with_not_scopes_applied():
    result = _governance()
    by_scope = {lvl["scope"]: [a["name"] for a in lvl["assignments"]] for lvl in result["scopes"]}
    assert by_scope == {MG: ["Allowed locations"], f"/subscriptions/{SUB}": [],
                        f"/subscriptions/{SUB}/resourcegroups/rg-app": ["Diagnostics"], RID.lower(): []}
    assert result["summary"] == {"evaluations": 2, "non_compliant": 1, "exempt": 0, "assignments": 2}
    assert result["compliance"][0]["state"] == "NonCompliant"  # problems first
    assert [(e["name"], e["status"], e["whole_assignment"]) for e in result["exemptions"]] == [
        ("Pilot", "never expires", True), ("Old", "expired", False)]


def test_what_governs_cli_renders_and_rejects_bad_ids():
    from scripts import what_governs

    text = "\n".join(what_governs.render(_governance()))
    assert "-> Diagnostics  [DoNotEnforce, initiative]" in text and "ENTIRE assignment" in text
    assert "NO EXPIRY" in text
    only = "\n".join(what_governs.render(_governance(), non_compliant_only=True))
    assert "p2" in only and " p1" not in only
    with pytest.raises(SystemExit):
        what_governs.main(["--resource-id", "/resourceGroups/rg-app"])


def test_managed_by_query_escapes_the_value_and_summary_counts_types():
    query = managed_by_query("team's tool")
    assert "== 'team\\'s tool'" in query
    assert summarize_managed([{"type": "Microsoft.Authorization/policyAssignments"},
                              {"type": "microsoft.authorization/policyassignments"},
                              {"type": "microsoft.authorization/policyexemptions"}]) == {
        "microsoft.authorization/policyassignments": 2, "microsoft.authorization/policyexemptions": 1}


# ---------------------------------------------------------------------------
# API route
# ---------------------------------------------------------------------------

class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Db:
    def __init__(self, subscription, tenant):
        self.subscription, self.tenant = subscription, tenant

    async def execute(self, query):
        return _Result(self.subscription)

    async def get(self, model, key):
        return self.tenant


def _call(resource_id, subscription, tenant, allowed=None):
    from backend.api.routes import governance

    scope = SimpleNamespace(require=lambda sid: None if allowed is None or sid in allowed else (_ for _ in ()).throw(
        HTTPException(status_code=404, detail="Not found")))
    return asyncio.run(governance.get_what_governs(resource_id=resource_id, db=_Db(subscription, tenant), scope=scope))


def test_route_validates_scopes_and_returns_the_lookup(monkeypatch):
    from backend.api.routes import governance

    sub = SimpleNamespace(id="row-1", subscription_id=SUB, tenant_id="t-row")
    tenant = SimpleNamespace(is_active=True, tenant_id="tenant-guid", client_id="app", client_secret_encrypted="enc")

    async def fake_lookup(t, subscription_id, resource_id):
        return {"resource_id": resource_id, "subscription": subscription_id}
    monkeypatch.setattr(governance, "lookup_governance", fake_lookup)

    assert _call(RID, sub, tenant) == {"resource_id": RID, "subscription": SUB}
    for bad in ("/resourceGroups/x" + "y" * 40, f"/subscriptions/not-a-guid-{'x' * 30}"):
        with pytest.raises(HTTPException) as exc:
            _call(bad, sub, tenant)
        assert exc.value.status_code == 400
    with pytest.raises(HTTPException) as exc:
        _call(RID, None, tenant)  # subscription not registered
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as exc:
        _call(RID, sub, tenant, allowed={"row-2"})  # scoped user without this subscription
    assert exc.value.status_code == 404


def test_route_turns_azure_errors_into_502(monkeypatch):
    from backend.api.routes import governance

    async def failing(*args):
        raise RuntimeError("AuthorizationFailed for tenant secret value")
    monkeypatch.setattr(governance, "lookup_governance", failing)
    sub = SimpleNamespace(id="row-1", subscription_id=SUB, tenant_id="t-row")
    with pytest.raises(HTTPException) as exc:
        _call(RID, sub, SimpleNamespace(is_active=True))
    assert exc.value.status_code == 502 and "secret" not in exc.value.detail  # no Azure error text leaks out
