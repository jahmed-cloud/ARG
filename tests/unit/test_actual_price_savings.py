"""
Savings at the subscription's own price: a list-price estimate is replaced by the resource's 30-day amortized cost
(removals) or scaled to it (price changes), so negotiated discounts, reservations and savings plans count. Without
cost data the list-price estimate stands and is labelled as such.
"""

import asyncio
from types import SimpleNamespace

import scanners.compute.compute_posture_scanners as compute
import scanners.network.network_posture_scanners  # noqa: F401 - registers the scanners under test
import scanners.network.network_scanners  # noqa: F401
from scanners.base.azure_api import (
    COST_BASIS,
    HOURS_PER_MONTH,
    price_at_actual_cost,
    saving_at_actual_price,
)
from scanners.base.base_scanner import ScanContext, ScannerRegistry

NET = "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Network"
PIP = f"{NET}/publicIPAddresses/pip-orphan-1"


def live(costs):
    """A live context (arm_client set) without a Resource Graph client, so scanners use their mock rows."""
    ctx = ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j")
    ctx.arm_client = ctx.cost_management_client = object()
    ctx.cache[f"resource_costs:30:{COST_BASIS}"] = {
        rid.lower(): {"cost": usd, "cost_usd": usd, "currency": "USD", "meters": {}} for rid, usd in costs.items()}
    return ctx


def run(name, ctx):
    return asyncio.run(ScannerRegistry.get(name)(config={}).execute(ctx)).findings


def test_saving_rules():
    assert saving_at_actual_price(3.65, None) == 3.65                      # no cost data: list price stands
    assert saving_at_actual_price(3.65, 2.1) == 2.1                        # removal saves what it actually costs
    assert saving_at_actual_price(180.0, 412.5) == 412.5                   # ... also when that is above list
    assert saving_at_actual_price(None, 7.0) == 7.0
    assert saving_at_actual_price(5.0, -0.3) == 0.0                        # refunds never make a saving negative
    assert saving_at_actual_price(100.0, 120.0, list_cost=200.0) == 60.0   # price change at a 40 % discount
    assert saving_at_actual_price(100.0, 500.0, list_cost=200.0) == 100.0  # never above the list-price saving


def test_offline_finding_keeps_its_list_price():
    finding = SimpleNamespace(estimated_monthly_savings_usd=3.65, resource_id=PIP, evidence={}, description="d.")
    asyncio.run(price_at_actual_cost(ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j"), finding))
    assert finding.estimated_monthly_savings_usd == 3.65 and finding.description == "d."
    assert finding.evidence == {"saving_basis": "list price", "list_price_saving_usd": 3.65,
                                "amortized_cost_usd_30d": None}


def test_removal_is_valued_at_the_resource_cost():
    [f] = run("unused_public_ip_scanner", live({PIP: 2.1}))
    assert f.estimated_monthly_savings_usd == 2.1
    assert f.evidence["saving_basis"] == "amortized cost, last 30 days" and f.evidence["list_price_saving_usd"] == 3.65
    assert ("Valued at what pip-orphan-1 actually costs: USD 2.10/month" in f.description
            and "the list-price estimate is USD 3.65/month" in f.description)


def test_resource_without_a_cost_row_keeps_its_list_price():
    [f] = run("unused_public_ip_scanner", live({}))
    assert f.estimated_monthly_savings_usd == 3.65 and f.evidence["saving_basis"] == "list price"


def test_vm_finding_saves_the_public_ip_not_the_vm():
    vm = "/subscriptions/sub-1/resourceGroups/rg-net/providers/Microsoft.Compute/virtualMachines/vm-jump-1"
    pip = f"{NET}/publicIPAddresses/pip-vm-1"
    [f] = run("vm_public_ip_with_bastion_scanner", live({vm: 250.0, pip: 3.1}))
    assert f.resource_id == vm and f.estimated_monthly_savings_usd == 3.1


def test_price_change_is_scaled_to_the_actual_price(monkeypatch):
    async def list_price(context, sku, linux, region):
        return compute.APP_SERVICE_HOURLY_USD[(sku, linux)]
    monkeypatch.setattr(compute, "app_service_hourly_usd", list_price)
    plan = "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/asp-shared-1"
    list_monthly = 0.800 * HOURS_PER_MONTH                                   # P3v2 Windows, one instance
    list_saving = round((0.800 - 0.676) * HOURS_PER_MONTH, 2)                # to P2v3
    findings = run("app_service_plan_generation_scanner", live({plan: 0.6 * list_monthly}))   # 40 % discount
    [f] = [f for f in findings if f.finding_type == "app_service_plan_previous_generation"]
    assert f.estimated_monthly_savings_usd == round(0.6 * list_saving, 2)
    assert f.evidence["list_price_saving_usd"] == list_saving
    assert "Valued at asp-shared-1's own price" in f.description
