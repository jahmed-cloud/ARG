"""
Resource providers (registered = accepted, not registered, in use, allow / deny resource-type policies) and the
amortized cost basis (reservations / savings plans spread over the resources that use them; budgets on actual).
"""

import asyncio

from scanners.base.base_scanner import ScanContext, ScannerRegistry
from scanners.base.providers import applicable_policies, build_analysis, provider_status

SUB = "11111111-2222-3333-4444-555555555555"


def test_provider_status():
    assert provider_status("Registered", "RegistrationRequired", True) == "In use"
    assert provider_status("Registered", "RegistrationRequired", False) == "Registered, not in use"
    assert provider_status("Registered", "RegistrationFree", False) == "Platform (always registered)"
    assert provider_status("NotRegistered", "RegistrationRequired", False) == "Not registered"
    assert provider_status("NotRegistered", "RegistrationRequired", True) == "In use, not registered"
    assert provider_status("Registering", "RegistrationRequired", False) == "Registering"


def test_policies_apply_from_the_subscription_its_resource_groups_and_ancestor_management_groups():
    deny = "/providers/microsoft.authorization/policydefinitions/6c112d4e-5bc7-47ae-a041-ea2d9dccd749"
    allow = "/providers/microsoft.authorization/policydefinitions/a08ec900-254a-4555-9bf5-e42af04b5c5c"
    assignments = [
        {"name": "sub deny", "scope": f"/subscriptions/{SUB}", "def": deny, "denied": ["Microsoft.Web/sites"]},
        {"name": "mg allow", "scope": "/providers/microsoft.management/managementgroups/corp", "def": allow,
         "allowed": ["microsoft.storage/storageaccounts"], "enforcement": "DoNotEnforce"},
        {"name": "rg deny", "scope": f"/subscriptions/{SUB}/resourcegroups/rg1", "def": deny, "denied": ["x/y"]},
        {"name": "other sub", "scope": "/subscriptions/other", "def": deny, "denied": ["a/b"]},
        {"name": "other mg", "scope": "/providers/microsoft.management/managementgroups/sandbox", "def": deny},
    ]
    got = applicable_policies(SUB, ["corp", "root"], assignments)
    assert [(p["name"], p["effect"], p["enforced"], p["resource_group"]) for p in got] == [
        ("sub deny", "deny list", True, None), ("mg allow", "allow list", False, None), ("rg deny", "deny list", True, "rg1")]


def test_analysis_classifies_providers_and_denied_types():
    providers = [{"namespace": "Microsoft.Compute", "registrationState": "Registered", "registrationPolicy": "RegistrationRequired"},
                 {"namespace": "Microsoft.Web", "registrationState": "Registered", "registrationPolicy": "RegistrationRequired"},
                 {"namespace": "Microsoft.Features", "registrationState": "Registered", "registrationPolicy": "RegistrationFree"},
                 {"namespace": "Microsoft.Batch", "registrationState": "NotRegistered", "registrationPolicy": "RegistrationRequired"}]
    usage = {"microsoft.compute/virtualmachines": 3, "microsoft.compute/disks": 5}
    deny = "/providers/microsoft.authorization/policydefinitions/6c112d4e-5bc7-47ae-a041-ea2d9dccd749"
    a = build_analysis(SUB, providers, usage, [], [
        {"name": "No VMs", "scope": f"/subscriptions/{SUB}", "def": deny, "denied": ["Microsoft.Compute/virtualMachines"]}])
    status = {r["namespace"]: (r["status"], r["resources"]) for r in a["providers"]}
    assert status == {"Microsoft.Compute": ("In use", 8), "Microsoft.Web": ("Registered, not in use", 0),
                      "Microsoft.Features": ("Platform (always registered)", 0), "Microsoft.Batch": ("Not registered", 0)}
    assert [r["namespace"] for r in a["providers"]][0] == "Microsoft.Compute"          # in use first
    assert a["denied_in_use"] == [{"type": "microsoft.compute/virtualmachines", "resources": 3, "policy": "No VMs",
                                   "effect": "deny list", "enforced": True}]


def test_scanner_raises_one_finding_for_denied_types():
    ctx = ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j")
    out = asyncio.run(ScannerRegistry.get("resource_provider_policy_scanner")(config={}).execute(ctx))
    assert [f.finding_type for f in out.findings] == ["resource_type_denied_by_policy"]
    assert out.findings[0].title == "2 resource(s) of 1 type(s) that Azure Policy denies"


def _model(**cost):
    from scripts.subscription_analysis.collector import AnalysisData
    from scripts.subscription_analysis.report import Model

    data = AnalysisData(subscription={"id": SUB, "name": "sub"}, generated_at=None,
                        cost=dict({"currency": "CHF", "usd_to_billing": 0.8}, **cost))
    return Model(data)


def test_report_states_the_cost_basis_and_compares_budgets_with_invoiced_cost():
    m = _model(cost_basis="AmortizedCost",
               monthly_by_service=[{"BillingMonth": "2026-08-01", "Cost": 1400.0, "ServiceName": "Virtual Machines"}],
               monthly_actual=[{"BillingMonth": "2026-08-01", "Cost": 690.0}])
    assert m.amortized and m.cost_basis_label == "amortized cost"
    assert m.total_12m == 1400.0 and m.total_12m_actual == 690.0
    assert m.budget_month_cost("2026-08") == 690.0                  # budgets track the invoice, not amortized
    legacy = _model(monthly_by_service=[{"BillingMonth": "2026-08-01", "Cost": 700.0, "ServiceName": "x"}])
    assert not legacy.amortized and legacy.budget_month_cost("2026-08") == 700.0   # old reports keep working


def test_report_section_lists_registered_providers_and_policies():
    from scripts.subscription_analysis.report import _resource_providers

    m = _model()
    m.data.resource_providers = build_analysis(SUB, [
        {"namespace": "Microsoft.Compute", "registrationState": "Registered", "registrationPolicy": "RegistrationRequired"},
        {"namespace": "Microsoft.Batch", "registrationState": "NotRegistered", "registrationPolicy": "RegistrationRequired"}],
        {"microsoft.compute/virtualmachines": 2}, [], [])
    text = "\n".join(_resource_providers(m))
    assert "## 7. Resource Providers" in text and "| Microsoft.Compute | In use | on request | 2 | virtualmachines (2) |" in text
    assert "**Not registered (1):**" in text and "Microsoft.Batch" in text
    assert "No \"Allowed resource types\" or \"Not allowed resource types\" policy applies" in text


def test_estate_provider_overview():
    from scripts.subscription_analysis.estate import _providers_overview, provider_overview

    resources = [{"type": "microsoft.compute/virtualmachines", "subscriptionId": "a"},
                 {"type": "microsoft.compute/disks", "subscriptionId": "b"}]
    providers = {"a": [{"namespace": "Microsoft.Compute", "state": "Registered", "policy": "RegistrationRequired"},
                       {"namespace": "Microsoft.Web", "state": "Registered", "policy": "RegistrationRequired"}],
                 "b": [{"namespace": "Microsoft.Compute", "state": "Registered", "policy": "RegistrationRequired"},
                       {"namespace": "Microsoft.Web", "state": "NotRegistered", "policy": "RegistrationRequired"}],
                 "c": [{"namespace": "Microsoft.Compute", "state": "Registered", "policy": "RegistrationRequired"}]}
    rows = {r["namespace"]: r for r in provider_overview(resources, providers)}
    assert (rows["Microsoft.Compute"]["in_use"], rows["Microsoft.Compute"]["registered"],
            rows["Microsoft.Compute"]["registered_unused"], rows["Microsoft.Compute"]["resources"]) == (2, 3, 1, 2)
    assert (rows["Microsoft.Web"]["registered"], rows["Microsoft.Web"]["not_registered"]) == (1, 1)
    text = "\n".join(_providers_overview(list(rows.values()), 3))
    assert "### Providers in use (1)" in text and "| Microsoft.Compute | 2 | 2 | 3 | 0 |" in text
    assert "| Microsoft.Web | 1 | 1 |" in text                     # registered but unused in one subscription


class BudgetArm:
    """Consumption budgets plus cost queries answered per (scope, filter), recording every query."""

    def __init__(self, budgets, cost_by_scope):
        self.budgets, self.cost_by_scope, self.queries = budgets, cost_by_scope, []

    async def get_all(self, path, api_version, params=None):
        return self.budgets

    async def cost_query(self, scope, body):
        flt = (body["dataset"].get("filter") or {}).get("dimensions", {}).get("values", [""])[0]
        self.queries.append((scope.lower(), body["type"], flt))
        cost = self.cost_by_scope[(scope.lower(), flt)]
        return [{"BillingMonth": m, "Cost": cost, "CostUSD": cost * 1.24, "Currency": "CHF"}
                for m in ("2026-06-01", "2026-07-01", "2026-08-01")]


def _budget(name, amount, rg=None, meter=None):
    scope = f"/subscriptions/{SUB}" + (f"/resourceGroups/{rg}" if rg else "")
    props = {"timeGrain": "Monthly", "amount": amount, "timePeriod": {"startDate": "2026-06-01T00:00:00Z"},
             "notifications": {}, "currentSpend": {"amount": 4.2, "unit": "CHF"}}
    if meter:
        props["filter"] = {"dimensions": {"name": "MeterSubCategory", "operator": "In", "values": [meter]}}
    return {"name": name, "id": f"{scope}/providers/Microsoft.Consumption/budgets/{name}", "properties": props}


def test_budgets_are_judged_on_their_own_scope_and_filter():
    sub_scope, rg_scope = f"/subscriptions/{SUB}", f"/subscriptions/{SUB}/resourcegroups/rg-ai"
    arm = BudgetArm(
        [_budget("governance_budget", 10000), _budget("ai-budget", 200, rg="rg-ai"),
         _budget("ai-budget-gpt", 20, rg="rg-ai", meter="Azure OpenAI GPT5"),
         _budget("ai-budget-gpt-copy", 20, rg="rg-ai", meter="Azure OpenAI GPT5")],
        {(sub_scope, ""): 16078.0, (rg_scope, ""): 95.0, (rg_scope, "Azure OpenAI GPT5"): 31.0})
    ctx = ScanContext(subscription_id=SUB, tenant_id="t", scan_job_id="j", arm_client=arm, cost_management_client=arm)
    out = asyncio.run(ScannerRegistry.get("budget_scanner")(config={}).execute(ctx))
    found = {f.resource_name: f for f in out.findings}
    # the subscription total (16,078) is only compared with the subscription budget; the RG budget sees its 95
    assert set(found) == {"governance_budget", "ai-budget-gpt", "ai-budget-gpt-copy"}
    assert (rg_scope, "ActualCost", "Azure OpenAI GPT5") in arm.queries and (rg_scope, "ActualCost", "") in arm.queries
    gpt = found["ai-budget-gpt"]
    assert "covering resource group rg-ai, filtered to MeterSubCategory in Azure OpenAI GPT5" in gpt.description
    assert "peak 31 CHF, 155% of budget" in gpt.description and "this month so far 4 CHF" in gpt.description
    assert "1 other budget(s) cover exactly the same scope and filter" in gpt.description
    assert "other budget" not in found["governance_budget"].description     # different scopes are not duplicates
    assert gpt.resource_group == "rg-ai"


def test_report_overview_uses_only_subscription_wide_budgets_and_no_cost_for_budgets():
    m = _model(budgets=[_budget("governance_budget", 10000), _budget("ai-budget", 200, rg="rg-ai"),
                        _budget("filtered", 50, meter="x")], last30_by_resource={"/other": {"cost": 1.0}})
    assert [b["name"] for b in m.subscription_budgets()] == ["governance_budget"]
    assert m.cost30(f"/subscriptions/{SUB}/resourceGroups/rg-ai/providers/Microsoft.Consumption/budgets/ai-budget") == "-"
