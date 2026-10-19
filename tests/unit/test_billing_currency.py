"""
Amounts in each subscription's billing currency (the rate Cost Management applied to its amortized cost) - report
pages, the estate overview and the estate page data - instead of USD.
"""

from scripts.subscription_analysis.currency import localise_amounts
from scripts.subscription_analysis.estate import build_estate, saving_text


def test_report_text_is_converted_at_the_subscription_rate():
    rate = 0.8
    assert localise_amounts("Target: private endpoint (USD 7.30/month)", rate, "CHF") == \
        "Target: private endpoint (CHF 5.84/month)"
    assert localise_amounts("adds +USD 10 and USD 1,000-2,000 one-off", rate, "CHF") == \
        "adds +CHF 8 and CHF 800-1,600 one-off"
    assert localise_amounts("wave 1: 91 CHF (USD 113)", rate, "CHF") == "wave 1: 91 CHF"
    assert localise_amounts("2,483 USD/yr; cost, 30 days (USD): 1,000", rate, "CHF") == \
        "1,986 CHF/yr; cost, 30 days (CHF): 800"
    assert localise_amounts("- amortized cost usd 30d: 531.1", rate, "CHF") == "- amortized cost CHF 30d: 424.9"
    assert localise_amounts("Prices are USD list prices of 2026-10-06", rate, "EUR") == \
        "Prices are USD list prices of 2026-10-06, shown in EUR"
    page = "Target (USD 7.30/month); USD list price; 91 CHF (USD 113)"
    once = localise_amounts(page, rate, "CHF")
    assert localise_amounts(once, rate, "CHF") == once   # converting twice changes nothing
    # not an amount, not a USD billing currency, no rate: unchanged
    assert localise_amounts("CostUSD column", rate, "CHF") == "CostUSD column"
    assert localise_amounts("USD 7.30", 1.0, "USD") == "USD 7.30"
    assert localise_amounts("USD 7.30", None, "CHF") == "USD 7.30"


def test_amortized_cost_setting_picks_the_cost_type_of_every_unspecified_query():
    import asyncio
    from types import SimpleNamespace

    from scanners.base.azure_api import (ACTUAL_COST, COST_BASIS, cost_basis_from, cost_basis_of,
                                         get_resource_costs)
    from scripts.subscription_analysis.settings import DEFAULTS

    assert DEFAULTS["amortized_cost"] is True and cost_basis_from(DEFAULTS) == COST_BASIS
    assert cost_basis_from({"amortized_cost": False}) == ACTUAL_COST
    context = SimpleNamespace(cost_basis=ACTUAL_COST)
    assert cost_basis_of(context) == ACTUAL_COST and cost_basis_of(context, COST_BASIS) == COST_BASIS
    assert cost_basis_of(SimpleNamespace()) == COST_BASIS

    sent = []

    class Arm:
        async def cost_query(self, scope, body):
            sent.append(body["type"])
            return []

    asyncio.run(get_resource_costs(SimpleNamespace(arm_client=Arm(), subscription_id="s", cache={},
                                                   cost_basis=ACTUAL_COST)))
    assert sent == [ACTUAL_COST]


def test_each_subscription_keeps_its_own_currency():
    assert saving_text(100.0, {"currency": "CHF", "perUsd": 0.81}) == "81 CHF"
    assert saving_text(100.0, {"currency": "EUR", "perUsd": 0.92}) == "92 EUR"
    assert saving_text(100.0, {"currency": "CHF"}) == "100 USD"   # rate unknown: USD, labelled
    reports = {
        "sub-ch": {"folder": "ch", "name": "ch", "generated_at": None, "currency": "CHF", "per_usd": 0.81,
                   "findings": [{"ref": "F-001", "title": "Idle disk: d1 (USD 10/month)", "severity": "low",
                                 "finding_type": "unattached_disk", "estimated_monthly_savings_usd": 10.0}],
                   "costs": {}, "resources": []},
        "sub-eu": {"folder": "eu", "name": "eu", "generated_at": None, "currency": "EUR", "per_usd": 0.92,
                   "findings": [], "costs": {}, "resources": []},
    }
    estate = build_estate(None, {"subscriptions": [], "resources": []}, reports)
    subs = {s["id"]: s for s in estate["subscriptions"]}
    assert (subs["sub-ch"]["currency"], subs["sub-ch"]["perUsd"]) == ("CHF", 0.81)
    assert (subs["sub-eu"]["currency"], subs["sub-eu"]["perUsd"]) == ("EUR", 0.92)
    assert estate["suggestions"][0]["title"] == "Idle disk: d1 (CHF 8/month)"
    assert estate["suggestions"][0]["savingsUsd"] == 10.0   # the data stays in USD; pages convert
