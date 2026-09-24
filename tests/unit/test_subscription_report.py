"""
Tests for the subscription analysis report generator, using findings from
mock-mode scanner runs plus small synthetic inventory/cost datasets.
"""

import asyncio
from datetime import datetime, timezone

from scanners.base.base_scanner import ScanContext
from scripts.subscription_analysis.collector import AnalysisData, load_scanners, run_scanners
from scripts.subscription_analysis.knowledge import CRITIQUES, FINDING_CLASSIFICATION, classify
from scripts.subscription_analysis.report import write_report


def _analysis() -> AnalysisData:
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
    asyncio.run(run_scanners(context, None, {}, data))
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
