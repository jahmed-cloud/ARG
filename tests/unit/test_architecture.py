"""Architecture diagrams (diagram.py), the data behind them (estate.collect_architecture helpers) and the routes that
serve them - the local portal's /architecture and the Docker /estate/architecture(.svg)."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from scripts.subscription_analysis import diagram
from scripts.subscription_analysis.diagram_icons import TYPE_ICONS, icon_for, icon_stems
from scripts.subscription_analysis.estate import merge_architecture, policy_record

SUB_A, SUB_B, SUB_C = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002", \
    "cccccccc-0000-0000-0000-000000000003"
MG = "/providers/microsoft.management/managementgroups/"
ALLOWED_LOCATIONS = "/providers/microsoft.authorization/policydefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"
NOT_ALLOWED_TYPES = "/providers/microsoft.authorization/policydefinitions/6c112d4e-5bc7-47ae-a041-ea2d9dccd749"


def _policy(scope, name, **kw):
    return {"id": f"{scope}/providers/microsoft.authorization/policyassignments/{name}", "name": name, "scope": scope,
            "initiative": False, "enforced": True, "effect": "", "allowed_locations": [], "allowed_types": [],
            "denied_types": [], **kw}


def estate():
    """Root -> Platform (SUB_A) and Landing zones -> Corp (SUB_B); SUB_C has no placement."""
    resources = [
        {"id": f"/subscriptions/{SUB_A}/resourcegroups/rg-net/providers/microsoft.network/virtualnetworks/hub",
         "name": "hub", "type": "microsoft.network/virtualnetworks", "s": 0, "rg": "rg-net", "loc": "westeurope",
         "cost": 12.0},
        {"id": f"/subscriptions/{SUB_B}/resourcegroups/rg-app/providers/microsoft.web/sites/app-1", "name": "app-1",
         "type": "microsoft.web/sites", "s": 1, "rg": "rg-app", "loc": "westeurope", "cost": 40.0, "kind": "app"},
        {"id": f"/subscriptions/{SUB_B}/resourcegroups/rg-app/providers/microsoft.compute/virtualmachines/vm-1",
         "name": "vm-1", "type": "microsoft.compute/virtualmachines", "s": 1, "rg": "rg-app", "loc": "eastus",
         "cost": 99.0},
        {"id": f"/subscriptions/{SUB_B}/resourcegroups/rg-app/providers/microsoft.contoso/widgets/w-1", "name": "w-1",
         "type": "microsoft.contoso/widgets", "s": 1, "rg": "rg-app", "loc": "westeurope"},
    ]
    return {
        "format": 2,
        "subscriptions": [{"id": SUB_A, "name": "connectivity-prod"}, {"id": SUB_B, "name": "corp-app-<script>-dev"},
                          {"id": SUB_C, "name": "orphan-sandbox"}],
        "types": {}, "resources": resources, "suggestions": [],
        "architecture": {
            "collected_at": "2026-10-06T12:00:00+00:00",
            "management_groups": {
                "root": {"name": "root", "displayName": "Tenant Root Group", "parent": None},
                "platform": {"name": "platform", "displayName": "Platform", "parent": "root"},
                "lz": {"name": "lz", "displayName": "Landing zones", "parent": "root"},
                "corp": {"name": "corp", "displayName": "Corp", "parent": "lz"},
            },
            "subscription_parents": {SUB_A: ["platform", "root"], SUB_B: ["corp", "lz", "root"]},
            "policies": [
                _policy(MG + "root", "Allowed locations", effect="Deny", allowed_locations=["westeurope", "northeurope"]),
                _policy(MG + "lz", "Not allowed resource types", effect="Deny",
                        denied_types=["microsoft.compute/virtualmachines"]),
                _policy(MG + "corp", "Deploy diagnostics", effect="DeployIfNotExists"),
                _policy(f"/subscriptions/{SUB_B}", f"ASC Default (subscription: {SUB_B})", initiative=True),
                _policy(f"/subscriptions/{SUB_B}", "Require a cost centre tag", effect="Deny"),
            ],
            "vnets": [{"id": f"/subscriptions/{SUB_A}/resourcegroups/rg-net/providers/microsoft.network/virtualnetworks/hub",
                       "name": "hub", "subscriptionId": SUB_A, "resourceGroup": "rg-net", "location": "westeurope",
                       "space": ["10.0.0.0/16"], "subnets": 3,
                       "peerings": [{"remote": f"/subscriptions/{SUB_B}/resourcegroups/rg-app/providers/"
                                               "microsoft.network/virtualnetworks/spoke", "state": "Connected"}]}],
        },
    }


# ---- data helpers ----------------------------------------------------------------------------------------------

def test_policy_record_reads_allow_and_deny_lists_and_defaults_their_effect_to_deny():
    loc = policy_record({"id": "a1", "name": "Allowed locations", "scope": MG + "root", "definition": ALLOWED_LOCATIONS,
                         "allowed_locations": ["WestEurope"], "enforcement": "Default"})
    assert loc["allowed_locations"] == ["westeurope"] and loc["effect"] == "Deny" and loc["enforced"]
    deny = policy_record({"id": "a2", "definition": NOT_ALLOWED_TYPES, "denied_types": ["Microsoft.Compute/disks"],
                          "enforcement": "DoNotEnforce"})
    assert deny["denied_types"] == ["microsoft.compute/disks"] and not deny["enforced"]
    other = policy_record({"id": "a3", "definition": "/providers/microsoft.authorization/policysetdefinitions/x",
                           "allowed_locations": ["eastus"]})   # parameters only count for the known built-ins
    assert other["initiative"] and other["allowed_locations"] == [] and other["effect"] == ""


def test_merge_architecture_combines_parts_and_skips_failed_ones():
    a = estate()["architecture"]
    merged = merge_architecture([a, {"error": "no access"}, {"policies": a["policies"][:1], "vnets": [],
                                                              "management_groups": {}, "subscription_parents": {}}])
    assert len(merged["policies"]) == len(a["policies"])          # the same assignment is listed once
    assert merged["subscription_parents"][SUB_B] == ["corp", "lz", "root"] and len(merged["vnets"]) == 1


def test_effective_policy_follows_the_management_group_chain():
    policy = diagram.effective_policy(estate()["architecture"], SUB_B)
    assert policy["allowed_locations"] == {"westeurope", "northeurope"}
    assert policy["denied_types"] == {"microsoft.compute/virtualmachines"}
    assert [name for _, name in policy["chain"]] == ["Tenant Root Group", "Landing zones", "Corp"]
    assert {p["where"] for p in policy["assignments"]} == {"Tenant Root Group", "Landing zones", "Corp",
                                                           "this subscription"}


def test_icon_map_uses_shipped_official_icons_and_refines_by_kind():
    shipped = {p.stem for p in diagram.ICON_DIR.glob("*.svg")}
    assert icon_stems() <= shipped
    assert icon_for("Microsoft.Web/sites", "functionapp,linux")[1] == "Function Apps"
    assert icon_for("microsoft.cognitiveservices/accounts", "OpenAI") == TYPE_ICONS["microsoft.cognitiveservices/accounts#openai"]
    assert icon_for("microsoft.contoso/widgets") is None


# ---- diagrams ----------------------------------------------------------------------------------------------------

def test_tenant_diagram_draws_groups_policies_and_clickable_subscriptions():
    svg = diagram.render_tenant(estate(), "/architecture?subscription={id}")
    assert svg.startswith("<svg") and "<script>" not in svg and "corp-app-&lt;script&gt;-dev" in svg
    for text in ("Tenant Root Group (tenant root)", "Landing zones", "Corp", "Placement not collected / no access",
                 "Allowed locations: northeurope, westeurope", "Not allowed resource types: 1",
                 "DINE · Deploy diagnostics"):
        assert text in svg, text
    assert f'data-subscription="{SUB_B}"' in svg and f'href="/architecture?subscription={SUB_B}"' in svg
    assert 'id="ic-subscriptions"' in svg and "data:image/svg+xml;base64," in svg     # the official icon, embedded
    # Defender for Cloud's own assignment is not counted in the subscription's policy badge
    assert "Policy: Require a cost centre tag (deny)" in svg and "+ 1 Defender for Cloud default assignment(s)" in svg


def test_tenant_diagram_without_architecture_data_still_renders_and_says_so():
    data = estate()
    data.pop("architecture")
    svg = diagram.render_tenant(data)
    assert "not collected yet - refresh the estate inventory" in svg and svg.count("data-subscription=") == 3
    assert "<a href=" not in svg                                     # no link template: the page handles clicks


def test_subscription_diagram_shows_what_is_allowed_denied_and_violated():
    svg = diagram.render_subscription(estate(), SUB_B, "/architecture")
    for text in ("Locations: northeurope, westeurope", "✕ microsoft.compute/virtualmachines",
                 "1 resource(s) in eastus", "1 x microsoft.compute/virtualmachines", "Require a cost centre tag",
                 "Defender for Cloud default assignments (1)", "Tenant Root Group › Landing zones › Corp",
                 "rg-app", "App Services", "Virtual machines"):
        assert text in svg, text
    assert 'href="/architecture"' in svg
    with pytest.raises(KeyError):
        diagram.render_subscription(estate(), "not-a-subscription")


def test_subscription_diagram_draws_vnets_and_links_peered_subscriptions():
    svg = diagram.render_subscription(estate(), SUB_A)
    assert "hub" in svg and "spoke" in svg and f'data-subscription="{SUB_B}"' in svg


# ---- Docker routes --------------------------------------------------------------------------------------------------

class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Db:
    def __init__(self, snapshot):
        self.snapshot = snapshot

    async def execute(self, query):
        return _Result(self.snapshot)

    async def scalar(self, query):   # governance config: none saved, the defaults apply
        return None


def _docker_client(snapshot, role="admin"):
    from backend.api.dependencies import auth
    from backend.api.dependencies.database import get_db
    from backend.api.routes import estate as estate_routes
    from backend.models.models import UserRole

    app = FastAPI()
    app.include_router(estate_routes.router, prefix="/estate")
    app.dependency_overrides[get_db] = lambda: _Db(snapshot)
    app.dependency_overrides[auth.get_current_user] = lambda: SimpleNamespace(
        id="u1", role=UserRole(role), is_active=True)
    return TestClient(app)


def _snapshot(data):
    now = datetime(2026, 10, 6, tzinfo=timezone.utc)
    return SimpleNamespace(id="snap-1", status="completed", triggered_by="manual", started_at=now, completed_at=now,
                           error_message=None, subscriptions_count=3, resources_count=4, suggestions_count=0, data=data)


def test_docker_architecture_routes_serve_the_picker_and_both_diagrams():
    client = _docker_client(_snapshot(estate()))
    index = client.get("/estate/architecture").json()
    assert [s["name"] for s in index["subscriptions"]] == ["connectivity-prod", "corp-app-<script>-dev",
                                                            "orphan-sandbox"]
    assert index["subscriptions"][1]["management_group"] == "Corp" and index["architecture_collected"]
    tenant = client.get("/estate/architecture.svg")
    assert tenant.status_code == 200 and tenant.headers["content-type"].startswith("image/svg+xml")
    assert "Landing zones" in tenant.text and "href=\"/architecture" not in tenant.text
    sub = client.get(f"/estate/architecture.svg?subscription={SUB_B}")
    assert sub.status_code == 200 and "What is not allowed" in sub.text
    assert client.get("/estate/architecture.svg?subscription=nope").status_code == 404


def test_docker_architecture_needs_an_inventory_and_an_admin():
    assert _docker_client(None).get("/estate/architecture.svg").status_code == 404
    assert _docker_client(_snapshot(estate()), role="viewer").get("/estate/architecture.svg").status_code == 403
