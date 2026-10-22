"""Azure Policy analyzer (scripts/subscription_analysis/policy_analyzer.py) and the policy collection it reads."""

from datetime import date

from scripts.subscription_analysis import policy_analyzer, policy_catalog

TODAY = date(2026, 10, 22)
MG = "/providers/microsoft.management/managementgroups/"
SUB_A, SUB_B, SUB_C = "aaaa", "bbbb", "cccc"
BENCH = "/providers/microsoft.authorization/policysetdefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
DENY_LOC = "/providers/microsoft.authorization/policydefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"
DINE_DIAG = "/providers/microsoft.authorization/policydefinitions/diag"
OLD = "/providers/microsoft.authorization/policydefinitions/old"
PREVIEW = "/providers/microsoft.authorization/policydefinitions/preview"
AUDIT_TAG = "/providers/microsoft.authorization/policydefinitions/tag"


def estate():
    return {"subscriptions": [{"id": SUB_A, "name": "sub-prod"}, {"id": SUB_B, "name": "sub-dev"},
                              {"id": SUB_C, "name": "sub-orphan"}],
            "architecture": {"management_groups": {
                "root": {"displayName": "Tenant Root Group", "parent": None},
                "org": {"displayName": "Contoso", "parent": "root"},
                "lz": {"displayName": "Landing zones", "parent": "org"}},
                "subscription_parents": {SUB_A: ["lz", "org", "root"], SUB_B: ["lz", "org", "root"]}}}


def assignment(aid, scope, profile, **kw):
    return {"id": aid, "name": aid.rsplit("/", 1)[-1], "display": kw.pop("display", aid.rsplit("/", 1)[-1]),
            "scope": scope, "enforcement": kw.pop("enforcement", "Default"), "profile": profile,
            "not_scope_list": kw.pop("not_scopes", []), "identity": kw.pop("identity", ""),
            "noncompliant": kw.pop("bad", None), "resources": kw.pop("res", None), "created": "2026-01-01", **kw}


def policy():
    return {
        "collected_at": "2026-10-22T08:00:00+00:00",
        "definitions": {
            DENY_LOC: {"display": "Allowed locations", "source": "BuiltIn", "category": "General", "effect": "deny"},
            DINE_DIAG: {"display": "Deploy diagnostic settings", "source": "BuiltIn", "category": "Monitoring",
                        "effect": "deployifnotexists"},
            OLD: {"display": "[Deprecated]: Old control", "source": "BuiltIn", "category": "Security", "deprecated": True,
                  "effect": "audit"},
            PREVIEW: {"display": "[Preview]: New control", "source": "BuiltIn", "category": "Security", "preview": True,
                      "effect": "deny"},
            AUDIT_TAG: {"display": "Require a tag", "source": "Custom", "category": "Tags", "effect": "audit"},
            BENCH: {"display": "Microsoft cloud security benchmark", "source": "BuiltIn", "set": True, "members": 2},
        },
        "profiles": {
            "p-loc": {"def": DENY_LOC, "members": [[DENY_LOC, "deny"]]},
            "p-diag": {"def": DINE_DIAG, "members": [[DINE_DIAG, "deployifnotexists"]]},
            "p-bench": {"def": BENCH, "members": [[OLD, "audit"], [PREVIEW, "deny"]]},
            "p-off": {"def": AUDIT_TAG, "members": [[AUDIT_TAG, "disabled"]]},
            "p-tag": {"def": AUDIT_TAG, "members": [[AUDIT_TAG, "audit"]]},
        },
        "assignments": [
            assignment(MG + "org/providers/microsoft.authorization/policyassignments/loc", MG + "org", "p-loc",
                       display="Allowed locations", bad=3, res=100, not_scopes=[f"/subscriptions/{SUB_B}"]),
            assignment(f"/subscriptions/{SUB_A}/providers/microsoft.authorization/policyassignments/loc2",
                       f"/subscriptions/{SUB_A}", "p-loc", display="Allowed locations (again)"),
            assignment(MG + "lz/providers/microsoft.authorization/policyassignments/diag", MG + "lz", "p-diag",
                       display="Diagnostics"),
            assignment(MG + "lz/providers/microsoft.authorization/policyassignments/diag-test", MG + "lz", "p-diag",
                       display="Diagnostics (test)", enforcement="DoNotEnforce"),
            assignment(f"/subscriptions/{SUB_A}/providers/microsoft.authorization/policyassignments/bench",
                       f"/subscriptions/{SUB_A}", "p-bench", display="ASC Default", identity="SystemAssigned"),
            assignment(f"/subscriptions/{SUB_B}/resourcegroups/rg-1/providers/microsoft.authorization/"
                       "policyassignments/off", f"/subscriptions/{SUB_B}/resourcegroups/rg-1", "p-off",
                       display="Tag (switched off)"),
        ],
        "exemptions": [
            {"id": f"/subscriptions/{SUB_A}/providers/microsoft.authorization/policyexemptions/forever",
             "display": "Forever", "category": "Waiver", "assignment": MG + "org/providers/microsoft.authorization/"
                                                                         "policyassignments/loc", "expires": ""},
            {"id": f"/subscriptions/{SUB_A}/providers/microsoft.authorization/policyexemptions/old",
             "display": "Old", "category": "Mitigated", "assignment": "x", "expires": "2024-01-17T00:00:00Z"},
            {"id": f"/subscriptions/{SUB_A}/providers/microsoft.authorization/policyexemptions/soon",
             "display": "Soon", "category": "Waiver", "assignment": "x", "expires": "2026-11-01T00:00:00Z"},
        ],
        "compliance": {
            "by_subscription": [{"sub": SUB_A, "noncompliant": 5, "resources": 20}],
            "by_policy": [{"assignment": MG + "org/providers/microsoft.authorization/policyassignments/loc",
                           "definition": DENY_LOC, "noncompliant": 3}],
        },
        "unassigned_custom": [{"key": "/x", "display": "Old custom initiative", "category": "", "set": True}],
    }


def result():
    return policy_analyzer.analyse(estate(), policy(), TODAY)


def test_every_issue_type_is_found_with_its_items():
    issues = {i["key"]: i for i in result()["issues"]}
    assert issues["no_identity"]["severity"] == "high" and issues["no_identity"]["count"] == 1
    assert "Diagnostics (management group Landing zones)" in issues["no_identity"]["items"][0]
    assert issues["not_enforced"]["items"][0].startswith("Diagnostics (test)")
    assert issues["deprecated"]["items"] == ["[Deprecated]: Old control - in ASC Default (subscription sub-prod)"]
    assert "[Preview]: New control (deny)" in issues["preview"]["items"][0]
    assert issues["exemption_no_expiry"]["count"] == 1 and issues["exemption_expired"]["count"] == 1
    assert issues["redundant"]["items"] == ["Allowed locations (again) at sub-prod - already assigned at Contoso"]
    assert issues["all_disabled"]["items"] == ["Tag (switched off) (resource group sub-dev / rg-1)"]
    assert issues["deny_noncompliant"]["severity"] == "info"
    assert {i.split(" (")[0] for i in issues["sub_no_deny"]["items"]} == {"sub-dev", "sub-orphan"}
    assert set(issues["sub_no_benchmark"]["items"]) == {"sub-dev", "sub-orphan"}
    assert issues["unassigned_custom"]["items"] == ["Old custom initiative (initiative)"]
    assert [i["severity"] for i in result()["issues"]][0] == "high"            # most severe first


def test_policy_in_effect_per_subscription_follows_the_hierarchy_and_exclusions():
    subs = {s["name"]: s for s in result()["subscriptions"]}
    prod, dev, orphan = subs["sub-prod"], subs["sub-dev"], subs["sub-orphan"]
    assert prod["path"] == "Tenant Root Group › Contoso › Landing zones"
    assert (prod["inherited"], prod["direct"]) == (3, 2) and prod["deny"] == 2 and prod["benchmark"]
    assert prod["compliance"] == 75.0 and prod["issues"] == []
    # excluded from the Contoso assignment; the DoNotEnforce one does not count towards the effects
    assert dev["inherited"] == 2 and dev["deny"] == 0 and dev["effects"] == {"remediate": 1}
    assert dev["resourceGroupAssignments"] == 1
    assert orphan["assignments"] == 0 and "not in the management-group hierarchy" in orphan["issues"]


def test_assignments_policies_and_exemptions_tables():
    r = result()
    rows = {a["display"]: a for a in r["assignments"]}
    loc = rows["Allowed locations"]
    assert loc["scopeKind"] == "Management group" and loc["scopeLabel"] == "Contoso" and loc["compliance"] == 97.0
    assert loc["memberNoncompliant"] == {DENY_LOC: 3} and loc["exemptions"] == 1 and "members" not in loc
    assert r["profiles"][loc["profile"]] == [[DENY_LOC, "deny"]]
    assert rows["Tag (switched off)"]["scopeKind"] == "Resource group"
    assert r["assignments"][0]["scopeKind"] == "Management group"                # management groups first
    policies = {p["display"]: p for p in r["policies"]}
    assert policies["Allowed locations"]["assignments"] == 2 and policies["Allowed locations"]["noncompliant"] == 3
    assert policies["Deploy diagnostic settings"]["notEnforced"] == 1
    assert policies["Require a tag"]["strongest"] == "disabled"
    status = {e["display"]: e["status"] for e in r["exemptions"]}
    assert status == {"Forever": "no end date", "Old": "expired", "Soon": "expires soon"}
    s = r["summary"]
    assert s["assignments"] == 6 and s["byScope"] == {"Management group": 3, "Subscription": 2, "Resource group": 1}
    assert s["compliance"] == 75.0 and s["exemptionsNoExpiry"] == 1 and s["complianceDetail"]


def test_identity_is_only_judged_when_the_collection_has_it():
    old = policy()
    for a in old["assignments"]:
        a.pop("identity")
    keys = {i["key"] for i in policy_analyzer.analyse(estate(), old, TODAY)["issues"]}
    assert "no_identity" not in keys and "not_enforced" in keys


def test_markdown_report_lists_issues_assignments_and_subscriptions():
    text = policy_analyzer.markdown(result())
    assert text.startswith("# Azure Policy analysis")
    assert "### DeployIfNotExists / Modify without a managed identity (1, high)" in text
    assert "## Policy in effect per subscription" in text and "| sub-prod |" in text
    assert "## Exemptions" in text


def test_collection_keeps_only_custom_definitions_and_merges_the_analyzer_parts():
    assert "properties.policyType) =~ 'Custom'" in policy_catalog.CUSTOM_DEFINITION_QUERY
    assert "properties.policyType) =~ 'Custom'" in policy_catalog.CUSTOM_SET_QUERY
    assert "identity = tostring(identity.type)" in policy_catalog.ASSIGNMENT_QUERY
    built = policy_catalog.build_policy([{"id": "a1", "definition": DENY_LOC, "scope": "/subscriptions/x",
                                          "identity": "SystemAssigned", "not_scope_list": ["/Subscriptions/Y"],
                                          "created": "2026-01-01T10:00:00Z"}], {DENY_LOC: {"effect": "deny"}}, {})
    a = built["assignments"][0]
    assert a["identity"] == "SystemAssigned" and a["not_scope_list"] == ["/subscriptions/y"] and a["created"] == "2026-01-01"
    merged = policy_catalog.merge_policy([policy(), policy(), {"error": "x"}])
    assert len(merged["compliance"]["by_policy"]) == 2 and len(merged["unassigned_custom"]) == 2


def test_assignment_tree_places_assignments_and_counts_what_reaches_each_scope():
    tree = result()["tree"]
    nodes = tree["nodes"]
    assert tree["roots"] == ["mg:root", "outside"]
    assert nodes["mg:root"]["children"] == ["mg:org"] and nodes["mg:org"]["children"] == ["mg:lz"]
    assert nodes["mg:lz"]["children"] == ["sub:bbbb", "sub:aaaa"]                # by name: sub-dev, sub-prod
    assert nodes["mg:org"]["kind"] == "Management group" and nodes["mg:org"]["label"] == "Contoso"
    assert len(nodes["mg:org"]["assigned"]) == 1 and nodes["mg:lz"]["inherited"] == 1
    assert nodes["mg:lz"]["effects"] == {"remediate": 2} and nodes["mg:lz"]["notEnforced"] == 1
    assert nodes["sub:aaaa"]["inherited"] == 3 and len(nodes["sub:aaaa"]["assigned"]) == 2
    assert nodes["sub:bbbb"]["inherited"] == 2                                    # excluded from Contoso's
    rg = nodes["rg:bbbb/rg-1"]
    assert rg["parent"] == "sub:bbbb" and rg["inherited"] == 2 and rg["scope"] == "/subscriptions/bbbb/resourcegroups/rg-1"
    assert nodes["sub:cccc"]["parent"] == "outside"
    assert (nodes["mg:root"]["subscriptions"], nodes["outside"]["subscriptions"]) == (2, 1)
    assert nodes["mg:org"]["assignedBelow"] == 5 and nodes["mg:root"]["assignedBelow"] == 6
    text = policy_analyzer.markdown(result())
    assert "## Assignment tree" in text
    assert "- **Tenant Root Group** (management group) - 0 assigned, 0 inherited, 2 subscriptions below" in text
    assert "    - **Landing zones** (management group) - 2 assigned, 1 inherited" in text
    assert "ASC Default [initiative Microsoft cloud security benchmark, 2 policies]" in text
    assert "Allowed locations [policy Allowed locations]" in text
