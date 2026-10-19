"""
Currency dropdown (billing currency, USD or any ECB reference-rate currency) and the amortized / actual cost setting:
the converter, the local portal (cookie), the Docker endpoint and settings API, the worker's billing rate and the
cost type every unspecified Cost Management query runs with. Offline - reference rates are stubbed.
"""

import asyncio
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.subscription_analysis.currency as currency
from scripts.subscription_analysis.currency import BILLING, Converter, exchange_rate, localise_amounts, options

RATES = {"date": "2026-10-07", "source": "European Central Bank euro reference rates",
         "per_usd": {"USD": 1.0, "EUR": 0.9, "CHF": 0.83, "GBP": 0.75}}


@pytest.fixture
def rates(monkeypatch):
    monkeypatch.setattr(currency, "reference_rates", lambda timeout=10.0: RATES)


# ---------------------------------------------------------------------------
# Converter
# ---------------------------------------------------------------------------

def test_converter_keeps_billing_or_converts_through_usd():
    billing = Converter(BILLING, RATES)
    assert not billing.active and billing.money(1000, "CHF", 0.8) == "1,000 CHF"
    assert billing.from_usd(10, "CHF", 0.8) == (8.0, "CHF")
    eur = Converter("eur", RATES)
    assert eur.active and eur.target == "EUR"
    assert eur.money(800, "CHF", 0.8) == "900 EUR"   # through USD at the subscription's own (invoice) rate
    assert eur.from_usd(10) == (9.0, "EUR")
    assert Converter("XYZ", RATES).target == BILLING   # no rate: billing currency, never a wrong number
    assert Converter("EUR", None).target == BILLING    # rates unavailable
    assert Converter("USD", None).money(800, "CHF", 0.8) == "1,000 USD"


def test_page_text_is_converted_and_other_words_left_alone():
    page = ("Target: private endpoint (CHF 5.90/month); wave 1: 88 CHF; cost CHF 30d: 424.9; USD 1,000-2,000; "
            "THE ALL TRY 5 words")
    out = Converter("EUR", RATES).text(page, {"CHF": 0.8})
    assert "EUR 6.64/month" in out and "99 EUR" in out and "cost EUR 30d: 478.0" in out
    assert "EUR 900-1,800" in out and "THE ALL TRY 5 words" in out
    assert Converter(BILLING, RATES).text(page, {"CHF": 0.8}) == page


def test_report_text_in_the_billing_currency():
    assert localise_amounts("Target: private endpoint (USD 7.30/month)", 0.8, "CHF") == \
        "Target: private endpoint (CHF 5.84/month)"
    assert localise_amounts("wave 1: 91 CHF (USD 113)", 0.8, "CHF") == "wave 1: 91 CHF"
    assert localise_amounts("CostUSD column", 0.8, "CHF") == "CostUSD column"
    assert localise_amounts("USD 7.30", None, "CHF") == "USD 7.30"


def test_options_list_billing_first_then_usd_eur_chf():
    assert [o["code"] for o in options(RATES)][:5] == [BILLING, "USD", "EUR", "CHF", "GBP"]
    assert [o["code"] for o in options(None)] == [BILLING, "USD"]


def test_exchange_rate_from_per_resource_costs_picks_the_biggest_currency():
    fx = exchange_rate([{"r1": {"cost": 80.0, "cost_usd": 100.0, "currency": "EUR"},
                         "r2": {"cost": 5.0, "cost_usd": 5.0, "currency": "USD"}},
                        None, {"r3": {"cost": 8.0, "cost_usd": None, "currency": "EUR"}}])
    assert fx["currency"] == "EUR" and fx["per_usd"] == 0.8
    assert exchange_rate([{}]) is None


# ---------------------------------------------------------------------------
# Cost basis
# ---------------------------------------------------------------------------

def test_amortized_cost_setting_picks_the_cost_type_of_every_unspecified_query():
    from scanners.base.azure_api import ACTUAL_COST, COST_BASIS, cost_basis_from, cost_basis_of, get_resource_costs

    assert cost_basis_from({}) == COST_BASIS and cost_basis_from(None) == COST_BASIS
    assert cost_basis_from({"amortized_cost": False}) == ACTUAL_COST
    assert cost_basis_from({"amortized_cost": "false"}) == ACTUAL_COST   # env var / JSON string
    assert cost_basis_from({"amortized_cost": "true"}) == COST_BASIS
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


def test_cli_cost_basis_from_env_config_and_flag(monkeypatch, tmp_path):
    from scanners.base.azure_api import ACTUAL_COST, COST_BASIS, cost_basis_from
    from scripts.subscription_analysis.cli import _parse_args, default_config

    monkeypatch.delenv("AMORTIZED_COST", raising=False)
    assert cost_basis_from(default_config()) == COST_BASIS
    monkeypatch.setenv("AMORTIZED_COST", "false")
    assert cost_basis_from(default_config()) == ACTUAL_COST
    monkeypatch.setenv("AMORTIZED_COST", "true")
    path = tmp_path / "c.json"
    path.write_text('{"amortized_cost": false}', encoding="utf-8")
    assert cost_basis_from(default_config(str(path))) == ACTUAL_COST
    assert cost_basis_from(default_config(actual_cost=True)) == ACTUAL_COST
    assert _parse_args(["--all", "--actual-cost"]).actual_cost is True


def test_report_labels_the_cost_basis():
    from datetime import datetime, timezone

    from scripts.subscription_analysis.collector import AnalysisData
    from scripts.subscription_analysis.report import Model

    data = AnalysisData(subscription={"id": "s", "name": "n"}, generated_at=datetime.now(timezone.utc))
    data.cost["cost_basis"] = "ActualCost"
    assert Model(data).cost_basis_label == "actual cost"
    data.cost["cost_basis"] = "AmortizedCost"
    assert Model(data).cost_basis_label == "amortized cost"


# ---------------------------------------------------------------------------
# Local portal
# ---------------------------------------------------------------------------

def test_local_portal_follows_the_currency_cookie(client, tmp_path, rates):  # noqa: F811
    from tests.unit.test_local_portal import SUB, _login, fake_runner

    _login(client)
    fake_runner(None, SUB["id"], tmp_path, lambda *a: None)
    info = client.get("/api/currency").json()
    assert info["selected"] == BILLING and info["options"][0]["code"] == BILLING and info["per_usd"]["EUR"] == 0.9
    home = client.get("/")
    assert 'id="currency-pick"' in home.text and "/static/currency.js" in home.text and "100 CHF" in home.text
    client.cookies.set("arg_currency", "EUR")
    assert client.get("/api/currency").json()["selected"] == "EUR"
    assert "108 EUR" in client.get("/").text   # 100 CHF / 0.83 * 0.9


def test_local_portal_default_currency_from_env(client, rates, monkeypatch):  # noqa: F811
    from tests.unit.test_local_portal import _login

    _login(client)
    monkeypatch.setenv("DISPLAY_CURRENCY", "USD")
    assert client.get("/api/currency").json()["selected"] == "USD"


# ---------------------------------------------------------------------------
# Docker stack
# ---------------------------------------------------------------------------

def test_billing_display_uses_the_most_common_currency_at_its_latest_rate():
    from backend.api.routes.dashboard import billing_display

    rows = [{"currency": "EUR", "per_usd": 0.9, "as_of": "2026-10-01"},
            {"currency": "eur", "per_usd": 0.92, "as_of": "2026-10-18"},
            {"currency": "CHF", "per_usd": 0.8, "as_of": "2026-10-19"}, None, {"currency": "GBP"}]
    assert billing_display(rows) == {"currency": "EUR", "per_usd": 0.92, "basis": None, "as_of": "2026-10-18",
                                      "subscriptions": 2}
    assert billing_display([None]) is None


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


def _currency(config, fx_rows):
    from backend.api.routes import dashboard

    class Db:
        async def scalar(self, query):
            return config

        async def execute(self, query):
            return _Rows(fx_rows)

    scope = SimpleNamespace(where=lambda column: True)
    return asyncio.run(dashboard.display_currency(db=Db(), scope=scope))


def test_docker_currency_endpoint_offers_the_choices(rates, monkeypatch):
    monkeypatch.delenv("DISPLAY_CURRENCY", raising=False)
    body = _currency(None, [{"currency": "CHF", "per_usd": 0.81, "basis": "x", "as_of": "2026-10-18"}])
    assert body["currency"] == "CHF" and body["default"] == BILLING
    assert body["billing"] == {"currency": "CHF", "per_usd": 0.81}
    assert body["reference"]["per_usd"]["EUR"] == 0.9 and body["options"][1]["code"] == "USD"
    usd = _currency(SimpleNamespace(analysis_settings={"display_currency": "USD"}),
                    [{"currency": "CHF", "per_usd": 0.81}])
    assert usd["currency"] == "USD" and usd["per_usd"] == 1.0 and usd["default"] == "USD"
    assert _currency(None, [])["currency"] == "USD"   # no scan has recorded a rate yet


def test_analysis_settings_defaults_env_and_saved(monkeypatch):
    from backend.api.routes.governance_config import AnalysisSettings, effective_analysis_settings

    for name in ("AMORTIZED_COST", "DISPLAY_CURRENCY", "REQUIRED_VM_EXTENSIONS", "REQUIRED_VM_EXTENSIONS_INCLUDE_ARC"):
        monkeypatch.delenv(name, raising=False)
    assert effective_analysis_settings(None) == {"amortized_cost": True, "display_currency": "billing",
                                                 "required_vm_extensions": "", "include_arc_machines": False}
    monkeypatch.setenv("AMORTIZED_COST", "false")
    monkeypatch.setenv("REQUIRED_VM_EXTENSIONS", "MDE.Windows|MDE.Linux")
    assert effective_analysis_settings({})["amortized_cost"] is False
    saved = effective_analysis_settings({"amortized_cost": True, "unknown": 1})
    assert saved["amortized_cost"] is True and "unknown" not in saved
    assert saved["required_vm_extensions"] == "MDE.Windows|MDE.Linux"
    with pytest.raises(ValueError):
        AnalysisSettings(display_currency="EUR")   # the dropdown picks other currencies; the default is billing/USD


def test_saving_config_without_analysis_settings_keeps_them():
    from backend.api.routes import governance_config as gc

    row = SimpleNamespace(required_tags=["owner"], naming_patterns={}, analysis_settings={"amortized_cost": False})

    class Db:
        async def scalar(self, query):
            return row

        async def commit(self):
            pass

    body = gc.GovernanceConfigSchema(required_tags=["owner", "env"], naming_patterns={})
    out = asyncio.run(gc.update_governance_config(body=body, db=Db(), current_user=None))
    assert row.analysis_settings == {"amortized_cost": False} and out.analysis_settings.amortized_cost is False
    body = gc.GovernanceConfigSchema(required_tags=["owner"], naming_patterns={},
                                     analysis_settings=gc.AnalysisSettings(amortized_cost=True, display_currency="USD"))
    out = asyncio.run(gc.update_governance_config(body=body, db=Db(), current_user=None))
    assert row.analysis_settings["display_currency"] == "USD" and out.analysis_settings.amortized_cost is True


def test_worker_records_the_billing_rate_from_the_scan_costs():
    from workers import scan_worker

    executed = []

    class Db:
        def execute(self, statement):
            executed.append(statement)

        def commit(self):
            executed.append("commit")

        def rollback(self):
            pass

    context = SimpleNamespace(cache={"resource_costs:30:AmortizedCost": {
        "r": {"cost": 92.0, "cost_usd": 100.0, "currency": "EUR"}}, "other": {}})
    scan_worker._record_billing_fx(Db(), SimpleNamespace(id="row", subscription_id="s"), context)
    assert executed[-1] == "commit"
    assert executed[0].compile().params["billing_fx"]["per_usd"] == 0.92
    executed.clear()
    scan_worker._record_billing_fx(Db(), SimpleNamespace(id="row", subscription_id="s"), SimpleNamespace(cache={}))
    assert executed == []   # no cost data read: nothing recorded


def test_migration_adds_settings_and_billing_rate(monkeypatch):
    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parents[2]
    monkeypatch.chdir(root)
    output = StringIO()
    command.upgrade(Config(str(root / "alembic.ini"), output_buffer=output), "head", sql=True)
    sql = output.getvalue()
    assert "ADD COLUMN IF NOT EXISTS analysis_settings JSONB" in sql
    assert "ADD COLUMN IF NOT EXISTS billing_fx JSONB" in sql


from tests.unit.test_local_portal import client  # noqa: E402,F401 - pytest fixture
