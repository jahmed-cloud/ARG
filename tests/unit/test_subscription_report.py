"""
Tests for the subscription analysis report generator, using findings from
mock-mode scanner runs plus small synthetic inventory/cost datasets.
"""

import asyncio
import json
from datetime import datetime, timezone

from scanners.base.base_scanner import ScanContext
from scripts.subscription_analysis.collector import AnalysisData, load_scanners, run_scanners
from scripts.subscription_analysis.knowledge import CRITIQUES, FINDING_CLASSIFICATION, classify
from scripts.subscription_analysis.report import (
    SUMMARY_FILE,
    display_names,
    read_summaries,
    resolve_report_folder,
    write_index,
    write_report,
)


def _analysis(config=None) -> AnalysisData:
    load_scanners()
    data = AnalysisData(
        subscription={"id": "sub-1", "name": "sub-demo", "tenant_id": "tenant-1"},
        generated_at=datetime(2026, 9, 24, tzinfo=timezone.utc),
        resources=[
            {"id": "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/asp-shared-1",
             "name": "asp-shared-1", "type": "Microsoft.Web/serverfarms", "location": "westeurope",
             "sku": {"name": "P3v2", "tier": "PremiumV2", "capacity": 1}, "createdTime": "2019-05-01T00:00:00Z",
             "tags": {"projectName": "App"}},
            {"id": "/subscriptions/sub-1/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/ai-1",
             "name": "ai-1", "type": "Microsoft.CognitiveServices/accounts", "location": "germanywestcentral",
             "kind": "AIServices", "createdTime": "2026-02-09T00:00:00Z", "tags": {}},
        ],
        resource_groups=[{"name": "rg-web", "location": "westeurope"}, {"name": "rg-ai", "location": "germanywestcentral"}],
        cost={
            "currency": "CHF", "usd_to_billing": 0.8,
            "window_12m": {"from": "2025-10-01", "to": "2026-09-24"},
            "monthly_by_service": [
                {"Cost": 4000.0, "BillingMonth": "2025-10-01T00:00:00", "ServiceName": "Azure DDOS Protection", "Currency": "CHF"},
                {"Cost": 3000.0, "BillingMonth": "2026-08-01T00:00:00", "ServiceName": "Foundry Models", "Currency": "CHF"},
                {"Cost": 2200.0, "BillingMonth": "2026-08-01T00:00:00", "ServiceName": "Azure DDOS Protection", "Currency": "CHF"},
            ],
            "last30_by_rg_service": [
                {"Cost": 2200.0, "CostUSD": 2750.0, "ResourceGroupName": "rg-net", "ServiceName": "Azure DDOS Protection", "Currency": "CHF"},
                {"Cost": 3000.0, "CostUSD": 3750.0, "ResourceGroupName": "rg-ai", "ServiceName": "Foundry Models", "Currency": "CHF"},
            ],
            "last30_by_resource": {
                "/subscriptions/sub-1/resourcegroups/rg-ai/providers/microsoft.cognitiveservices/accounts/ai-1":
                    {"cost": 3000.0, "cost_usd": 3750.0, "currency": "CHF", "meters": {"Azure OpenAI": 3000.0}},
            },
            "budgets": [{"name": "b1", "properties": {"amount": 2600, "timeGrain": "Monthly"}}],
        },
    )
    context = ScanContext(subscription_id="sub-1", tenant_id="tenant-1", scan_job_id="job")
    asyncio.run(run_scanners(context, None, config or {}, data))
    return data


def test_report_writes_expected_structure(tmp_path):
    data = _analysis()
    model = write_report(data, tmp_path)

    expected = [
        "README.md",
        "01-current-findings/README.md", "01-current-findings/resource-inventory.md",
        "02-gap-analysis/README.md",
        "03-cost-drivers/README.md", "03-cost-drivers/savings-register.md",
        "04-architectural-critique/README.md",
        "05-deep-dive/README.md", "05-deep-dive/networking/README.md", "05-deep-dive/ai-foundry/README.md",
        "05-deep-dive/raw/findings.json", "05-deep-dive/raw/inventory/resources.json",
        "05-deep-dive/raw/cost/monthly_by_service.json",
    ]
    for rel in expected:
        assert (tmp_path / rel).is_file(), rel

    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "sub-demo" in readme and "Headline savings" in readme and "Prioritised Action List" in readme
    assert "exceeded in 2 of 2 months" in readme
    assert "Author: Junaid Ahmed" in readme and "(https://github.com/jahmed-cloud/ARG)" in readme
    critique = (tmp_path / "04-architectural-critique" / "README.md").read_text(encoding="utf-8")
    assert "DDoS Network Protection plan" in critique
    assert model.savings_by_wave()[1] > 0
    assert model.to_billing(100.0) == 80.0


def test_every_finding_gets_a_reference_and_classification(tmp_path):
    data = _analysis()
    model = write_report(data, tmp_path)
    refs = [f["ref"] for f in model.findings]
    assert len(refs) == len(set(refs)) and refs[0] == "F-001"
    assert all(f["area"] and f["folder"] and f["wave"] for f in model.findings)


def test_knowledge_base_is_consistent():
    for finding_type, c in FINDING_CLASSIFICATION.items():
        assert c.critique is None or c.critique in CRITIQUES, finding_type
    assert classify("some_future_type", "network").folder == "networking"


def _summary(folder, sub_id, name):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / SUMMARY_FILE).write_text(json.dumps({"subscription": {"id": sub_id, "name": name}}), encoding="utf-8")


def test_subscriptions_sharing_a_name_get_their_own_folder(tmp_path):
    a = {"id": "aaaaaaaa-1111-2222-3333-444444444444", "name": "Visual Studio Professional Subscription"}
    b = {"id": "bbbbbbbb-1111-2222-3333-444444444444", "name": "Visual Studio Professional Subscription"}
    _summary(tmp_path / "Visual_Studio_Professional_Subscription", a["id"], a["name"])

    assert resolve_report_folder(tmp_path, a).name == "Visual_Studio_Professional_Subscription"
    folder_b = resolve_report_folder(tmp_path, b)
    assert folder_b.name == "Visual_Studio_Professional_Subscription_bbbbbbbb"
    assert resolve_report_folder(tmp_path, b) == folder_b  # claimed before any summary.json is written
    _summary(folder_b, b["id"], b["name"])

    labels = display_names(read_summaries(tmp_path))
    assert labels == {"Visual_Studio_Professional_Subscription": "Visual Studio Professional Subscription (aaaaaaaa)",
                      "Visual_Studio_Professional_Subscription_bbbbbbbb": "Visual Studio Professional Subscription (bbbbbbbb)"}
    index = write_index(tmp_path).read_text(encoding="utf-8")
    assert "(aaaaaaaa)" in index and "(bbbbbbbb)" in index


def test_unique_names_keep_the_plain_folder(tmp_path):
    sub = {"id": "cccccccc-1111-2222-3333-444444444444", "name": "cp-example"}
    assert resolve_report_folder(tmp_path, sub).name == "cp-example"
    assert display_names([{"folder": "cp-example", "subscription": sub}]) == {"cp-example": "cp-example"}


def test_lumpy_saas_spend_is_explained_and_not_used_as_run_rate(tmp_path):
    data = _analysis()
    data.cost.update({
        "window_12m": {"from": "2025-10-01", "to": "2026-09-25"},
        "monthly_by_service": [
            {"Cost": -25000.0, "BillingMonth": "2025-12-01T00:00:00", "ServiceName": "SaaS", "Currency": "CHF"},
            {"Cost": 150000.0, "BillingMonth": "2026-08-01T00:00:00", "ServiceName": "SaaS", "Currency": "CHF"},
        ],
        "last30_by_rg_service": [{"Cost": 150000.0, "CostUSD": 185000.0, "ResourceGroupName": "rsg-example",
                                  "ServiceName": "SaaS", "Currency": "CHF"}],
    })
    model = write_report(data, tmp_path)
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "possibly partial" not in readme
    assert "last full month" in readme and "credits/refunds of -25,000 CHF (2025-12)" in readme
    assert "not a monthly run-rate" in readme
    assert model.lumpy and model.run_rate == model.total_12m / 12
    cost = (tmp_path / "03-cost-drivers" / "README.md").read_text(encoding="utf-8")
    assert "Status quo (12-month average; spend is lumpy)" in cost
    assert 'y-axis "CHF" -' in cost


def test_steady_spend_uses_last_30_days(tmp_path):
    model = write_report(_analysis(), tmp_path)
    assert not model.lumpy and model.run_rate == model.total_30


def test_young_subscription_ramping_up_is_not_lumpy(tmp_path):
    data = _analysis()
    for r in data.resources:
        r["createdTime"] = "2026-07-15T00:00:00Z"
    data.cost["monthly_by_service"] = [
        {"Cost": 100.0, "BillingMonth": "2026-07-01T00:00:00", "ServiceName": "VMs", "Currency": "CHF"},
        {"Cost": 5000.0, "BillingMonth": "2026-08-01T00:00:00", "ServiceName": "VMs", "Currency": "CHF"},
    ]
    assert not write_report(data, tmp_path).lumpy


def test_report_explains_why_cost_and_references_per_finding(tmp_path):
    data = _analysis({"defender_recommendations": True})
    write_report(data, tmp_path)
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "Cost of implementing waves 1 + 2 (estimate)" in readme and "SP (" in readme
    assert "(generic estimate)" in readme
    assert "| Cost to implement |" in readme
    assert "Not included:** 2 Defender for Cloud plan-enablement recommendation(s)" in readme
    security = (tmp_path / "05-deep-dive" / "security-identity" / "README.md").read_text(encoding="utf-8")
    assert "Microsoft Defender for Storage plan should be enabled" not in security.split("are not listed:")[0]
    assert "Subscription: sub-demo (`sub-1`)" in security
    for heading in ("**Why it is needed**", "**When it is not needed**", "**Cost of implementation (estimate)**",
                    "**References**"):
        assert heading in security
    assert "encryptionAtHost=true" in security and "15 September 2028" in security
    gap = (tmp_path / "02-gap-analysis" / "README.md").read_text(encoding="utf-8")
    assert "| Cost to implement | Learn more |" in gap and "](https://learn.microsoft.com/" in gap
    register = (tmp_path / "03-cost-drivers" / "savings-register.md").read_text(encoding="utf-8")
    assert "| Net / month |" in register
    findings = json.loads((tmp_path / "05-deep-dive" / "raw" / "findings.json").read_text(encoding="utf-8"))
    assert all("implementation" in f for f in findings)


def test_resource_provider_page_lists_every_provider(tmp_path):
    from scanners.base.providers import build_analysis

    data = _analysis()
    providers = [{"namespace": f"Microsoft.Svc{i:02d}", "registrationState": "NotRegistered",
                  "registrationPolicy": "RegistrationRequired"} for i in range(60)]
    providers += [{"namespace": "Microsoft.Web", "registrationState": "Registered", "registrationPolicy": "RegistrationRequired"},
                  {"namespace": "Microsoft.Batch", "registrationState": "Registered", "registrationPolicy": "RegistrationRequired"},
                  {"namespace": "Microsoft.Security", "registrationState": "Registered", "registrationPolicy": "RegistrationRequired"}]
    data.resource_providers = build_analysis("sub-1", providers, {"microsoft.web/serverfarms": 1}, [], [])
    write_report(data, tmp_path)
    page = (tmp_path / "01-current-findings" / "resource-providers.md").read_text(encoding="utf-8")
    assert "## All providers (63)" in page and "Microsoft.Svc59" in page
    assert "# az provider unregister --namespace Microsoft.Batch --subscription sub-1" in page   # optional only
    assert "--namespace Microsoft.Security" not in page                 # governance baseline is never listed
    assert "--namespace Microsoft.Web" not in page                      # nor core services
    section = (tmp_path / "01-current-findings" / "README.md").read_text(encoding="utf-8")
    assert "for information (1):** Microsoft.Batch" in section and "Microsoft.Svc59" in section


def test_defender_is_a_summary_with_portal_links_unless_imported(tmp_path):
    data = _analysis()
    data.defender = {"recommendations": [
        {"recommendation": "Install missing OS / package updates", "severity": "High", "resources": 4,
         "link": "https://portal.azure.com/#view/Microsoft_Azure_Security/x"},
        {"recommendation": "Storage accounts should prevent shared key access", "severity": "Medium", "resources": 2,
         "link": "https://portal.azure.com/#view/Microsoft_Azure_Security/y"}],
        "plan_upsells_left_out": 3, "portal": "https://portal.azure.com/#view/Microsoft_Azure_Security/z",
        "by_severity": {"High": 1, "Medium": 1}}
    write_report(data, tmp_path)
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "**Defender for Cloud:** 2 open recommendation(s) - 1 high, 1 medium" in readme
    assert "Not included:** 3 Defender for Cloud plan-enablement recommendation(s)" in readme
    security = (tmp_path / "05-deep-dive" / "security-identity" / "README.md").read_text(encoding="utf-8")
    assert "## Defender for Cloud summary" in security
    assert "[Install missing OS / package updates](https://portal.azure.com/" in security
    assert not any(f["title"].startswith("Defender:") for f in data.findings)
