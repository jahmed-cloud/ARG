"""
Landing-zone view: the ALZ reference library, management groups mapped to ALZ archetypes, ALZ controls rated against
the policy in force, policy depth, connectivity, the diagram and the routes (local portal and Docker).
"""

import json

from scripts.subscription_analysis import landing_zone as lz
from scripts.subscription_analysis import policy_catalog as pc
from scripts.subscription_analysis.landing_zone_diagram import render_landing
from tests.unit.test_architecture import _docker_client, _snapshot
from tests.unit.test_local_portal import _login, client  # noqa: F401 - pytest fixture

SUB_A, SUB_B, SUB_HUB, SUB_S, SUB_V = ("aaaa0000-0000-0000-0000-000000000001", "bbbb0000-0000-0000-0000-000000000002",
                                      "cccc0000-0000-0000-0000-000000000003", "dddd0000-0000-0000-0000-000000000004",
                                      "eeee0000-0000-0000-0000-000000000005")
MG = "/providers/microsoft.management/managementgroups/"
BUILTIN = "/providers/microsoft.authorization/policydefinitions/"
K_HTTP, K_MGMT, K_CLASSIC, K_SB1, K_SB2 = (BUILTIN + n for n in ("http", "mgmt", "classic", "sb1", "sb2"))
K_CUSTOM = MG + "contoso/providers/microsoft.authorization/policydefinitions/no-public-sandbox"
K_SET = MG + "contoso/providers/microsoft.authorization/policysetdefinitions/contoso-baseline"
NET = "/subscriptions/{s}/resourcegroups/rg-net/providers/microsoft.network/virtualnetworks/{n}"


def _definition(display, aliases, effect="Deny", param=True):
    return {"display": display, "source": "BuiltIn", "category": "", "version": "1.0.0", "deprecated": False,
            "preview": False, "effect": effect.lower(), "effect_param": "effect" if param else None,
            "aliases": aliases, "types": []}


def policy():
    defs = {
        K_HTTP: _definition("Secure transfer to storage", ["microsoft.storage/storageaccounts/supportshttpstrafficonly"]),
        K_MGMT: _definition("Management ports blocked", ["microsoft.network/networksecuritygroups/securityrules/access"]),
        K_CLASSIC: _definition("Not allowed resource types", []),
        K_SB1: _definition("Sandbox: no public IP", ["microsoft.network/publicipaddresses/sku.name",
                                                     "microsoft.network/publicipaddresses/ipconfiguration.id"]),
        K_SB2: _definition("Sandbox: no ER", ["microsoft.network/expressroutecircuits/serviceproviderproperties"]),
        K_CUSTOM: {**_definition("Contoso - no public IP in sandboxes", ["microsoft.network/publicipaddresses/sku.name",
                                                                        "microsoft.network/publicipaddresses/ipconfiguration.id"]),
                   "source": "Custom"},
    }
    sets = {K_SET: pc.compact_set({"displayName": "Contoso baseline", "parameters": {"classicEffect": {"defaultValue": "Deny"}},
                                   "policyDefinitions": [{"policyDefinitionId": K_CLASSIC,
                                                          "parameters": {"effect": {"value": "[parameters('classicEffect')]"}}}]},
                                  "Custom", pc.definition_key)}
    assignments = [
        {"id": MG + "contoso/providers/microsoft.authorization/policyassignments/baseline", "name": "baseline",
         "display": "Contoso baseline", "scope": MG + "contoso", "definition": K_SET, "parameters": {}},
        {"id": MG + "prodsvc/providers/microsoft.authorization/policyassignments/https", "name": "https",
         "display": "Storage HTTPS (audit)", "scope": MG + "prodsvc", "definition": K_HTTP,
         "parameters": {"effect": {"value": "Audit"}}},
        {"id": MG + "sandbox/providers/microsoft.authorization/policyassignments/nopip", "name": "nopip",
         "display": "Sandbox guardrail", "scope": MG + "sandbox", "definition": K_CUSTOM, "parameters": {}},
    ] + [{"id": f"/subscriptions/{s}/providers/microsoft.authorization/policyassignments/mgmt", "name": "mgmt",
          "display": "Mgmt ports", "scope": f"/subscriptions/{s}", "definition": K_MGMT, "parameters": {}}
         for s in (SUB_A, SUB_B)]
    exemptions = [{"id": f"/subscriptions/{SUB_A}/providers/microsoft.authorization/policyexemptions/ex1",
                   "display": "Legacy app", "category": "Waiver",
                   "assignment": MG + "prodsvc/providers/microsoft.authorization/policyassignments/https",
                   "expires": ""}]
    compliance = [{"assignment": MG + "contoso/providers/microsoft.authorization/policyassignments/baseline",
                   "noncompliant": 3, "resources": 10}]
    out = pc.build_policy(assignments, defs, sets, exemptions, compliance)
    out["definitions"].update({k: defs[k] for k in (K_SB1, K_SB2)})
    out["reference"] = {"release": "test", "controls": {
        "Deny-Classic-Resources": [[K_CLASSIC, "deny"]], "Deny-Storage-http": [[K_HTTP, "deny"]],
        "Deny-MgmtPorts-Internet": [[K_MGMT, "deny"]], "Enforce-ALZ-Sandbox": [[K_SB1, "deny"], [K_SB2, "deny"]]}}
    out["alias_frequency"] = {"microsoft.network/publicipaddresses/sku.name": 300}   # a selector
    return out


def data():
    hub, spoke1, spoke2, lonely = (NET.format(s=SUB_HUB, n="hub"), NET.format(s=SUB_A, n="spoke1"),
                                   NET.format(s=SUB_B, n="spoke2"), NET.format(s=SUB_S, n="lonely"))
    groups = {
        "tenant": {"name": "tenant", "displayName": "Tenant Root Group", "parent": None},
        "contoso": {"name": "contoso", "displayName": "Contoso", "parent": "tenant"},
        "platform": {"name": "platform", "displayName": "Platform", "parent": "contoso"},
        "connectivity": {"name": "connectivity", "displayName": "Connectivity", "parent": "platform"},
        "prodsvc": {"name": "prodsvc", "displayName": "Prod Services", "parent": "contoso"},
        "sandbox": {"name": "sandbox", "displayName": "Sandbox", "parent": "contoso"},
        "vs": {"name": "vs", "displayName": "Visual Studio", "parent": "tenant"},
    }
    parents = {SUB_HUB: ["connectivity", "platform", "contoso", "tenant"], SUB_A: ["prodsvc", "contoso", "tenant"],
               SUB_B: ["prodsvc", "contoso", "tenant"], SUB_S: ["sandbox", "contoso", "tenant"],
               SUB_V: ["vs", "tenant"]}

    def subnet(vnet, name, route_table=None, nsg=True):
        return {"id": f"{vnet}/subnets/{name}".lower(), "name": name, "nsg": "nsg" if nsg else None,
                "route_table": route_table}
    vnets = [
        {"id": hub, "name": "hub", "subscriptionId": SUB_HUB, "location": "westeurope", "space": ["10.0.0.0/22"],
         "subnets": 3, "dns": [], "ddos": False,
         "subnet_list": [subnet(hub, "RouteServerSubnet"), subnet(hub, "snet-inside"), subnet(hub, "snet-outside")],
         "peerings": [{"remote": spoke1, "remote_gateways": False}, {"remote": spoke2, "remote_gateways": False}]},
        {"id": spoke1, "name": "spoke1", "subscriptionId": SUB_A, "location": "westeurope", "space": ["10.1.0.0/24"],
         "subnets": 1, "dns": ["10.0.0.4"], "ddos": False, "subnet_list": [subnet(spoke1, "app")],
         "peerings": [{"remote": hub, "remote_gateways": True}]},
        {"id": spoke2, "name": "spoke2", "subscriptionId": SUB_B, "location": "westeurope", "space": ["10.2.0.0/24"],
         "subnets": 1, "dns": [], "ddos": False, "subnet_list": [subnet(spoke2, "app", route_table="rt", nsg=False)],
         "peerings": [{"remote": hub, "remote_gateways": False}]},
        {"id": lonely, "name": "lonely", "subscriptionId": SUB_S, "location": "westeurope", "space": ["10.9.0.0/24"],
         "subnets": 1, "dns": [], "ddos": False, "subnet_list": [subnet(lonely, "default")], "peerings": []},
    ]
    network = {"edge": [], "vms": [{"id": f"/subscriptions/{SUB_HUB}/resourcegroups/rg/providers/microsoft.compute/"
                                           f"virtualmachines/vm-fw01", "subnets": [f"{hub}/subnets/snet-inside"]}],
               "route_tables": [{"id": "rt", "default_route": "Internet", "subnets": []}],
               "private_endpoints": [{"subnet": f"{spoke2}/subnets/app"}], "dns_links": []}
    return {"subscriptions": [{"id": s, "name": n} for s, n in ((SUB_HUB, "hub-sub"), (SUB_A, "app-a"),
                                                                (SUB_B, "app-b"), (SUB_S, "sandbox-1"), (SUB_V, "vs-1"))],
            "architecture": {"management_groups": groups, "subscription_parents": parents, "vnets": vnets,
                             "network": network, "policies": []}}


# ---- reference and mapping --------------------------------------------------------------------------------------

def test_reference_library_is_the_pinned_alz_release():
    ref = lz.load_reference()
    assert ref["release"] == "platform/alz/2026.10.0"
    assert set(ref["archetypes"]) >= {"root", "platform", "landing_zones", "corp", "online", "sandbox",
                                      "connectivity", "identity", "management", "decommissioned"}
    assert "Deny-Storage-http" in ref["archetypes"]["landing_zones"] and len(ref["assignments"]) >= 80
    controls = lz.reference_controls(ref, dict(ref["definitions"]), dict(ref["sets"]))
    sandbox = controls["Enforce-ALZ-Sandbox"]
    # ALZ initiative resolved member by member; built-in members get their effect once the built-ins are loaded
    assert len(sandbox) >= 2 and all(effect for key, effect in sandbox if key.startswith("alz:"))


def test_groups_map_by_name_position_and_setting():
    groups = lz.map_groups(data()["architecture"])
    assert groups["root"] == "contoso"   # the tenant root's child holding most subscriptions
    g = groups["groups"]
    assert (g["contoso"]["archetype"], g["platform"]["archetype"], g["connectivity"]["archetype"]) == \
        ("root", "platform", "connectivity")
    assert (g["prodsvc"]["archetype"], g["prodsvc"]["mapped_by"]) == ("landing_zones", "position")
    assert g["sandbox"]["archetype"] == "sandbox"
    assert not g["vs"]["inside"] and g["vs"]["archetype"] is None
    mapped = lz.map_groups(data()["architecture"], ["Prod Services = corp", "visual studio = sandbox"])["groups"]
    assert (mapped["prodsvc"]["archetype"], mapped["prodsvc"]["mapped_by"]) == ("corp", "setting")
    assert mapped["vs"]["archetype"] == "sandbox"


def test_member_effect_follows_assignment_then_initiative_default():
    definition = _definition("x", [])
    assert pc.member_effect(definition, {}, {}, {"effect": {"value": "Audit"}}) == "audit"
    assert pc.member_effect(definition, {"effect": "[parameters('e')]"}, {"e": "Disabled"}, {}) == "disabled"
    assert pc.member_effect(definition, {"effect": "[parameters('e')]"}, {"e": "Disabled"},
                            {"e": {"value": "Deny"}}) == "deny"
    aliases, types = pc.rule_footprint({"if": {"allOf": [{"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
                                                         {"field": "Microsoft.Storage/storageAccounts/minimumTlsVersion",
                                                          "notEquals": "TLS1_2"}]}})
    assert aliases == ["microsoft.storage/storageaccounts/minimumtlsversion"]
    assert types == ["microsoft.storage/storageaccounts"]


def test_identical_assignments_share_one_profile():
    p = policy()
    mgmt = [a for a in p["assignments"] if a["name"] == "mgmt"]
    assert len(mgmt) == 2 and mgmt[0]["profile"] == mgmt[1]["profile"]


# ---- controls -------------------------------------------------------------------------------------------------------

def _status(result, archetype, control, group):
    row = next(r for r in result["controls"][archetype]["controls"] if r["name"] == control)
    return row["groups"][group]


def test_controls_are_rated_against_the_policy_in_force():
    result = lz.analyse(data(), policy())
    root = _status(result, "root", "Deny-Classic-Resources", "contoso")
    assert root["status"] == lz.IN_PLACE and "Contoso baseline" in root["detail"]
    https = _status(result, "landing_zones", "Deny-Storage-http", "prodsvc")
    assert https["status"] == lz.AUDIT_ONLY            # ALZ denies, the tenant only audits
    mgmt = _status(result, "landing_zones", "Deny-MgmtPorts-Internet", "prodsvc")
    assert mgmt["status"] == lz.IN_PLACE and "every subscription" in mgmt["detail"]
    sandbox = _status(result, "sandbox", "Enforce-ALZ-Sandbox", "sandbox")
    # the custom policy reads the same distinctive property (the shared selector does not count): similar, 1 missing
    assert sandbox["status"] == "partly" and sandbox["counts"] == {lz.SIMILAR: 1, lz.MISSING: 1}
    unresolved = _status(result, "landing_zones", "Deny-IP-forwarding", "prodsvc")
    assert unresolved["status"] == lz.UNRESOLVED


def test_policy_depth_exemptions_and_observations():
    result = lz.analyse(data(), policy(), today="2026-10-07")
    rows = result["policy"]["by_group"]["contoso"]["direct"]
    assert rows[0]["initiative"] and rows[0]["noncompliant"] == 3 and rows[0]["resources"] == 10
    assert result["policy"]["exemptions"][0]["expires"] == "never"
    assert result["kpis"]["exemptions_without_expiry"] == 1 and result["kpis"]["outside_root"] == 1
    notes = " ".join(result["observations"])
    assert "outside the intermediate root" in notes and "Visual Studio" in notes
    assert "No 'Decommissioned' management group" in notes


def test_connectivity_recognises_nva_hubs_route_server_and_gaps():
    net = lz.analyse(data(), policy())["connectivity"]
    hub = net["hubs"][0]
    assert hub["name"] == "hub" and hub["nva"] == 1 and hub["route_server"] and hub["firewall_policy"] is None
    spokes = {s["name"]: s for s in net["spokes"]}
    assert spokes["spoke1"]["route"] == "learned from the hub (BGP)" and spokes["spoke1"]["dns"] == "hub DNS"
    issues = " ".join(spokes["spoke2"]["issues"])
    assert "bypasses the hub firewall" in issues and "no private DNS zone" in issues and "without NSG" in issues
    assert spokes["lonely"]["issues"] == ["isolated - no peering"]


def test_markdown_and_diagram_render():
    result = lz.analyse(data(), policy())
    text = lz.markdown(result)
    assert "## Controls - Landing zones" in text and "🟡 audit only" in text and "## Connectivity landing zone" in text
    svg = render_landing(result)
    assert svg.startswith("<svg") and "Landing zone" in svg and 'data-label="prod services"' in svg
    assert "NVA firewall" in svg and "Route Server" in svg
    bare = lz.analyse(data(), None)   # before the first refresh that collects policy
    assert not bare["policy_collected"] and render_landing(bare).startswith("<svg")


# ---- routes ---------------------------------------------------------------------------------------------------------

def test_docker_landing_zone_routes_keep_policy_on_the_server():
    snapshot = _snapshot({**data(), "format": 2, "types": {}, "resources": [], "suggestions": [], "policy": policy()})
    docker = _docker_client(snapshot)
    svg = docker.get("/estate/architecture.svg?view=landing")
    assert svg.status_code == 200 and "Azure Landing Zones" in svg.text
    details = docker.get("/estate/landing-zone").json()
    assert "## Management groups" in details["markdown"] and "<table>" in details["html"]
    assert "policy" not in docker.get("/estate").json()


def test_local_landing_zone_page_and_details(client, tmp_path):  # noqa: F811 - pytest fixture
    from scripts.subscription_analysis.estate import ESTATE_DIR, ESTATE_FILE, POLICY_FILE

    (tmp_path / ESTATE_DIR).mkdir(exist_ok=True)
    (tmp_path / ESTATE_DIR / ESTATE_FILE).write_text(json.dumps(data()), encoding="utf-8")
    (tmp_path / ESTATE_DIR / POLICY_FILE).write_text(json.dumps(policy()), encoding="utf-8")
    _login(client)
    page = client.get("/architecture?view=landing")
    assert page.status_code == 200 and 'aria-current="page">Landing zone</a>' in page.text
    assert 'id="arch-sub"' not in page.text and 'id="lz-details"' in page.text
    assert client.get("/api/architecture.svg?view=landing").status_code == 200
    html = client.get("/api/landing-zone.html")
    assert html.status_code == 200 and "Deny-Storage-http" in html.text
    md = client.get("/api/landing-zone.md")
    assert md.status_code == 200 and md.headers["content-disposition"].endswith('landing-zone.md"')
