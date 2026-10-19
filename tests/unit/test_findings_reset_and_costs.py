"""POST /findings/reset (admins regenerate every finding) and GET /costs/summary's expandable savings rows."""
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from backend.api.dependencies import auth
from backend.api.dependencies.database import get_db
from backend.api.routes import costs, findings
from backend.models.models import AuditLog, FindingStatus, SeverityLevel, UserRole
from backend.services.access import AccessScope, get_access_scope

NOW = datetime.now(timezone.utc)


class Result:
    def __init__(self, value=None, rowcount=0):
        self.value, self.rowcount = value, rowcount

    def scalar_one(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return list(self.value)


class Db:
    def __init__(self, *results):
        self.results = list(results)
        self.sql, self.added, self.committed = [], [], False

    async def execute(self, query):
        self.sql.append(str(query.compile(dialect=postgresql.dialect())))
        return self.results.pop(0)

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.committed = True


def _app(db, router, prefix, role=UserRole.ADMIN):
    app = FastAPI()
    app.include_router(router, prefix=prefix)
    user = SimpleNamespace(id="00000000-0000-0000-0000-0000000000a1", role=role, is_active=True)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[auth.get_current_user] = lambda: user
    app.dependency_overrides[get_access_scope] = lambda: AccessScope(user=user)
    return TestClient(app)


def test_reset_needs_the_confirmation_word_and_an_admin():
    db = Db()
    assert _app(db, findings.router, "/findings").post("/findings/reset", json={"confirm": "yes"}).status_code == 400
    assert _app(db, findings.router, "/findings", role=UserRole.ANALYST).post(
        "/findings/reset", json={"confirm": "RESET"}).status_code == 403
    assert db.sql == [] and not db.committed


def test_reset_deletes_findings_and_estate_snapshots_and_is_audited():
    db = Db(Result(rowcount=11984), Result(rowcount=3), Result())
    r = _app(db, findings.router, "/findings").post("/findings/reset", json={"confirm": "RESET"})
    assert r.status_code == 200 and r.json() == {"findings_deleted": 11984, "estate_snapshots_deleted": 3}
    assert db.sql[0].startswith("DELETE FROM findings")
    assert db.sql[1].startswith("DELETE FROM estate_snapshots") and "status !=" in db.sql[1]   # a running one stays
    assert db.sql[2].startswith("UPDATE resource_inventory SET is_orphaned")
    audit = db.added[0]
    assert isinstance(audit, AuditLog) and audit.action == "findings.reset" and db.committed


def _saving(monthly, ftype="unattached_managed_disk", **kw):
    values = dict(id="00000000-0000-0000-0000-0000000000f1", title="Unattached disk disk-1", finding_type=ftype,
                  description="Premium SSD P30 unattached for 90 days", status=FindingStatus.OPEN,
                  severity=SeverityLevel.MEDIUM, category="cost", remediation_steps="Snapshot, then delete",
                  estimated_monthly_savings_usd=monthly, evidence={"saving_basis": "P30 list price"},
                  resource=SimpleNamespace(resource_name="disk-1", resource_type="Microsoft.Compute/disks",
                                           monthly_cost_usd=monthly))
    values.update(kw)
    return SimpleNamespace(**values)


def test_cost_savings_rows_explain_why_cost_to_implement_and_net_saving():
    sub = "aaaaaaaa-0000-0000-0000-000000000001"
    totals = {sub: {"cost": 810.0, "cost_usd": 1000.0, "currency": "CHF"},
              "not-visible": {"cost": 5.0, "cost_usd": 6.0, "currency": "CHF"}}
    # visible subscriptions, the newest estate snapshot's amortized 30-day totals, then the saving findings
    db = Db(Result([sub]), Result([(totals, {})]), Result([_saving(120.0)]))
    body = _app(db, costs.router, "/costs").get("/costs/summary").json()
    assert body["total_monthly_cost"] == 1000.0 and body["total_annual_cost"] == 12000.0
    assert "exists" in db.sql[1].lower()        # the snapshot read is filtered like every other query
    row = body["top_savings"][0]
    assert row["monthly_saving"] == 120.0 and row["annual_saving"] == 1440.0
    assert row["why"] and row["cost_to_implement"] and row["hours"]
    assert row["saving_basis"] == "P30 list price"
    assert row["net_monthly_usd"] is None or row["net_monthly_usd"] <= 120.0


# ---- display currency ----------------------------------------------------------------------------------------------

def test_exchange_rate_is_the_invoice_rate_of_the_main_billing_currency():
    from scripts.subscription_analysis.currency import display, exchange_rate

    fx = exchange_rate([{"a": {"cost": 80.0, "cost_usd": 100.0, "currency": "CHF"},
                         "b": {"cost": 8.0, "cost_usd": 10.0, "currency": "chf"}},
                        None, {"c": {"cost": 5.0, "cost_usd": 5.0, "currency": "USD"}, "d": {"cost": 0, "cost_usd": 3}}])
    assert fx["currency"] == "CHF" and fx["per_usd"] == 0.8 and "88 CHF = 110 USD" in fx["basis"]
    assert exchange_rate([{}, None]) is None
    assert display(fx)["currency"] == "CHF" and display(fx, "USD") == {"currency": "USD", "per_usd": 1.0,
                                                                         "basis": "amounts in US dollars"}
    assert display(None)["currency"] == "USD"


def test_currency_endpoint_uses_the_latest_estate_rate_unless_usd_is_chosen():
    from backend.api.routes import dashboard

    class ScalarDb:
        def __init__(self, *values):
            self.values = list(values)

        async def scalar(self, query):
            return self.values.pop(0)

    fx = {"currency": "CHF", "per_usd": 0.8, "basis": "x", "as_of": "2026-10-07"}
    for config, expected in ((None, "CHF"),
                             (SimpleNamespace(scanner_settings={"display_currency": "USD"}), "USD")):
        app = _app(ScalarDb(config, fx), dashboard.router, "/dashboard")
        body = app.get("/dashboard/currency").json()
        assert body["currency"] == expected
