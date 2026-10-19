"""
The amortized / actual cost setting and the .env defaults of the analysis settings: the cost type every unspecified
Cost Management query runs with, the CLI flag and environment, the saved settings, the Docker settings and the local
portal's default currency. The currency converter and endpoints are covered by test_currency_choice.py and
test_billing_currency.py. Offline.
"""

import asyncio
from types import SimpleNamespace

import pytest

ENV = ("AMORTIZED_COST", "DISPLAY_CURRENCY", "REQUIRED_VM_EXTENSIONS", "REQUIRED_VM_EXTENSIONS_INCLUDE_ARC")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)


def test_cost_basis_accepts_strings_from_env_and_json():
    from scanners.base.azure_api import ACTUAL_COST, COST_BASIS, cost_basis_from, cost_basis_of, get_resource_costs

    assert cost_basis_from({}) == COST_BASIS and cost_basis_from(None) == COST_BASIS
    assert cost_basis_from({"amortized_cost": False}) == ACTUAL_COST
    assert cost_basis_from({"amortized_cost": "false"}) == ACTUAL_COST
    assert cost_basis_from({"amortized_cost": "true"}) == COST_BASIS
    assert cost_basis_of(SimpleNamespace(cost_basis=ACTUAL_COST)) == ACTUAL_COST

    sent = []

    class Arm:
        async def cost_query(self, scope, body):
            sent.append(body["type"])
            return []

    asyncio.run(get_resource_costs(SimpleNamespace(arm_client=Arm(), subscription_id="s", cache={},
                                                   cost_basis=ACTUAL_COST)))
    assert sent == [ACTUAL_COST]


def test_cli_cost_basis_from_env_saved_settings_config_and_flag(monkeypatch, tmp_path):
    from scanners.base.azure_api import ACTUAL_COST, COST_BASIS, cost_basis_from
    from scripts.subscription_analysis import settings
    from scripts.subscription_analysis.cli import _parse_args, default_config

    assert cost_basis_from(default_config()) == COST_BASIS
    monkeypatch.setenv("AMORTIZED_COST", "false")
    assert cost_basis_from(default_config()) == ACTUAL_COST                     # .env default
    settings.save(tmp_path, {"amortized_cost": True})
    assert cost_basis_from(default_config(reports_dir=tmp_path)) == COST_BASIS  # saved setting wins over .env
    path = tmp_path / "c.json"
    path.write_text('{"amortized_cost": false}', encoding="utf-8")
    assert cost_basis_from(default_config(str(path), tmp_path)) == ACTUAL_COST  # --config wins over saved
    assert cost_basis_from(default_config(None, tmp_path, actual_cost=True)) == ACTUAL_COST
    assert _parse_args(["--all", "--actual-cost"]).actual_cost is True


def test_env_defaults_feed_the_analysis_settings(monkeypatch, tmp_path):
    from scripts.subscription_analysis import settings

    assert settings.effective(None)["display_currency"] == "Billing currency"
    assert settings.effective(None)["required_vm_extensions"] == ""
    monkeypatch.setenv("DISPLAY_CURRENCY", "usd")
    monkeypatch.setenv("REQUIRED_VM_EXTENSIONS", "MDE.Windows|MDE.Linux")
    monkeypatch.setenv("REQUIRED_VM_EXTENSIONS_INCLUDE_ARC", "true")
    effective = settings.effective(None)
    assert effective["display_currency"] == "USD"
    assert effective["required_vm_extensions"] == "MDE.Windows|MDE.Linux" and effective["include_arc_machines"] is True
    settings.save(tmp_path, {"display_currency": "Billing currency"})
    assert settings.effective(tmp_path)["display_currency"] == "Billing currency"


def test_docker_settings_include_vm_extensions_and_env_defaults(monkeypatch):
    from backend.api.routes.governance_config import DOCKER_SETTINGS, effective_settings

    assert {"required_vm_extensions", "include_arc_machines", "amortized_cost", "display_currency"} <= DOCKER_SETTINGS
    monkeypatch.setenv("AMORTIZED_COST", "false")
    assert effective_settings(None)["amortized_cost"] is False
    assert effective_settings({"amortized_cost": True})["amortized_cost"] is True   # saved wins


def test_vm_extension_scanner_reads_the_setting():
    from scanners.base.base_scanner import ScanContext, ScannerRegistry
    import scanners.governance.policy_scanners  # noqa: F401

    cls = ScannerRegistry.get("vm_required_extension_scanner")
    out = asyncio.run(cls(config={"required_vm_extensions": "AzureMonitorWindowsAgent|AzureMonitorLinuxAgent",
                                  "include_arc_machines": False}).execute(
        ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j")))
    assert {f.finding_type for f in out.findings} == {"vm_required_extension_missing", "vm_required_extension_failed"}


def test_report_labels_the_cost_basis():
    from datetime import datetime, timezone

    from scripts.subscription_analysis.collector import AnalysisData
    from scripts.subscription_analysis.report import Model

    data = AnalysisData(subscription={"id": "s", "name": "n"}, generated_at=datetime.now(timezone.utc))
    data.cost["cost_basis"] = "ActualCost"
    assert Model(data).cost_basis_label == "actual cost"
    data.cost["cost_basis"] = "AmortizedCost"
    assert Model(data).cost_basis_label == "amortized cost"
