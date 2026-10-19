"""
The Currency dropdown: billing currency (each subscription's own), USD or any reference-rate currency - the converter,
the local portal (cookie) and the Docker endpoint.
"""

import pytest

import scripts.subscription_analysis.currency as currency
from scripts.subscription_analysis.currency import BILLING, Converter, options

RATES = {"date": "2026-10-07", "source": "European Central Bank euro reference rates",
         "per_usd": {"USD": 1.0, "EUR": 0.9, "CHF": 0.83, "GBP": 0.75}}


def test_converter_keeps_billing_or_converts_through_usd():
    billing = Converter(BILLING, RATES)
    assert not billing.active and billing.money(1000, "CHF", 0.8) == "1,000 CHF"
    assert billing.from_usd(10, "CHF", 0.8) == (8.0, "CHF")
    eur = Converter("eur", RATES)
    assert eur.active and eur.target == "EUR"
    # a billing amount goes through USD at the subscription's own (invoice) rate, then to EUR
    assert eur.money(800, "CHF", 0.8) == "900 EUR"
    assert eur.from_usd(10) == (9.0, "EUR")
    assert Converter("XYZ", RATES).target == BILLING          # no rate: billing currency, not a wrong number
    assert Converter("EUR", None).target == BILLING           # rates unavailable
    assert Converter("USD", None).money(800, "CHF", 0.8) == "1,000 USD"


def test_page_text_is_converted_and_other_words_left_alone():
    page = ("Target: private endpoint (CHF 5.90/month); wave 1: 88 CHF; cost CHF 30d: 424.9; USD 1,000-2,000; "
            "THE ALL TRY 5 words")
    out = Converter("EUR", RATES).text(page, {"CHF": 0.8})
    assert "EUR 6.64/month" in out and "99 EUR" in out and "cost EUR 30d: 478.0" in out
    assert "EUR 900-1,800" in out and "THE ALL TRY 5 words" in out
    assert Converter(BILLING, RATES).text(page, {"CHF": 0.8}) == page


def test_options_list_billing_first_then_usd_eur_chf():
    codes = [o["code"] for o in options(RATES)]
    assert codes[:5] == [BILLING, "USD", "EUR", "CHF", "GBP"]
    assert [o["code"] for o in options(None)] == [BILLING, "USD"]


@pytest.fixture
def rates(monkeypatch):
    monkeypatch.setattr(currency, "reference_rates", lambda timeout=10.0: RATES)


def test_local_portal_follows_the_currency_cookie(client, tmp_path, rates):  # noqa: F811
    from tests.unit.test_local_portal import SUB, _login, fake_runner

    _login(client)
    fake_runner(None, SUB["id"], tmp_path, lambda *a: None)
    info = client.get("/api/currency").json()
    assert info["selected"] == BILLING and info["options"][0]["code"] == BILLING and info["per_usd"]["EUR"] == 0.9
    home = client.get("/")
    assert 'id="currency-pick"' in home.text and "/static/currency.js" in home.text
    client.cookies.set("arg_currency", "EUR")
    assert client.get("/api/currency").json()["selected"] == "EUR"
    assert " EUR" in client.get("/").text


def test_docker_currency_endpoint_offers_the_choices(rates):
    from types import SimpleNamespace

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from backend.api.dependencies.database import get_db
    from backend.api.routes import dashboard
    from backend.services.access import get_access_scope

    class Db:
        async def scalar(self, query):
            text = str(query)
            return {"currency": "CHF", "per_usd": 0.81, "basis": "x"} if "estate_snapshots" in text else None

    app = FastAPI()
    app.include_router(dashboard.router, prefix="/dashboard")
    app.dependency_overrides[get_db] = lambda: Db()
    app.dependency_overrides[get_access_scope] = lambda: SimpleNamespace(all=True)
    body = TestClient(app).get("/dashboard/currency").json()
    assert body["currency"] == "CHF" and body["default"] == BILLING
    assert body["billing"] == {"currency": "CHF", "per_usd": 0.81}
    assert body["reference"]["per_usd"]["EUR"] == 0.9 and body["options"][1]["code"] == "USD"


from tests.unit.test_local_portal import client  # noqa: E402,F401 - pytest fixture
