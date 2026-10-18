"""
Cheaper region in the same geography (region_price_scanner / cheaper_region_available): same-geography comparison,
10 % and USD 20 floors, 'Allowed locations' policy, valuation at the resource's own price.
"""

import asyncio

from scanners.base.base_scanner import ScanContext, ScannerRegistry
from scanners.base.providers import allowed_location_set
from scanners.cost.cost_scanners import REGION_GROUPS, cheaper_regions, region_group


def scanner():
    return ScannerRegistry.get("region_price_scanner")(config={})


def offline():
    return ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j")


def test_regions_are_compared_within_one_geography():
    assert region_group("West Europe", REGION_GROUPS)[0] == "Europe"
    assert region_group("eastus2", REGION_GROUPS)[0] == "North America"
    assert region_group("brazilsouth", REGION_GROUPS) is None       # no group: nothing is suggested
    prices = {"westeurope": 1.0, "northeurope": 0.95, "swedencentral": 0.85, "eastus": 0.5}
    alts = cheaper_regions("westeurope", prices, set(REGION_GROUPS["Europe"]), 10)
    assert [a["region"] for a in alts] == ["swedencentral"]           # 5 % is under the floor; eastus is elsewhere
    assert alts[0]["cheaper_pct"] == 15.0


def test_mock_scan_suggests_only_real_differences():
    found = {f.resource_name: f for f in asyncio.run(scanner().execute(offline())).findings}
    assert set(found) == {"vm-web-01", "asp-portal"}                  # vm-web-02 already runs in the cheapest region
    vm = found["vm-web-01"]
    assert vm.title == "Cheaper region for vm-web-01: Standard_D8s_v5 lists 12% less in swedencentral"
    assert vm.estimated_monthly_savings_usd == 35.04                  # (0.384 - 0.336) x 730 h
    assert [a["region"] for a in vm.evidence["alternatives"]] == ["swedencentral"]
    assert "northeurope" not in vm.description                        # 8.3 % cheaper: under the 10 % floor
    assert "A region move is a migration" in vm.description
    plan = found["asp-portal"]
    assert plan.evidence["alternatives"][0]["region"] == "northeurope" and plan.estimated_monthly_savings_usd == 122.64
    assert plan.azure_cli_script.startswith("az appservice list-locations")


def test_allowed_locations_policy_limits_the_candidates():
    s = scanner()
    cases = {c["row"]["name"]: c for c in s._mock_data()}
    allowed = {"westeurope", "northeurope", "switzerlandnorth"}
    evaluate = lambda name: asyncio.run(s._evaluate(offline(), cases[name], REGION_GROUPS, set(), allowed))  # noqa: E731
    assert evaluate("vm-web-01") is None                              # swedencentral is not allowed
    plan = evaluate("asp-portal")
    assert plan.evidence["allowed_locations"] == sorted(allowed) and "Allowed locations" in plan.description


def test_allowed_location_set_rules():
    sub = "/subscriptions/sub-1"
    mg = "/providers/microsoft.management/managementgroups/contoso-root"
    assignments = [
        {"scope": mg, "enforcement": "Default", "locations": ["West Europe", "northeurope", "switzerlandnorth"]},
        {"scope": sub, "enforcement": "Default", "locations": ["westeurope", "switzerlandnorth", "eastus"]},
        {"scope": f"{sub}/resourcegroups/rg-x", "locations": ["eastus"]},              # part of the subscription only
        {"scope": sub, "enforcement": "DoNotEnforce", "locations": ["westeurope"]},     # audit only
        {"scope": "/subscriptions/other", "locations": ["uksouth"]},                    # another subscription
    ]
    assert allowed_location_set("SUB-1", ["contoso-root"], assignments) == {"westeurope", "switzerlandnorth"}
    assert allowed_location_set("sub-1", [], []) is None


def test_region_minimums_are_settings():
    s = ScannerRegistry.get("region_price_scanner")(config={"region_min_saving_pct": 20})
    names = {f.resource_name for f in asyncio.run(s.execute(offline())).findings}
    assert names == {"asp-portal"}                                    # vm-web-01 is 12.5 % cheaper only
