"""Admin Estate in the Docker stack: database findings + live inventory -> snapshot, worker refresh, admin-only API."""
import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType, SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.dependencies import auth
from backend.api.dependencies.database import get_db
from backend.api.routes import estate as estate_routes
from backend.models.models import EstateSnapshot, SeverityLevel, UserRole
from backend.services import estate as service

SUB_A = "aaaaaaaa-1111-2222-3333-444444444444"
SUB_B = "bbbbbbbb-1111-2222-3333-444444444444"
VM = f"/subscriptions/{SUB_A}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-app-prod-1"
DISK = f"/subscriptions/{SUB_A}/resourceGroups/rg-app/providers/Microsoft.Compute/disks/disk-old"
STORAGE = f"/subscriptions/{SUB_B}/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdata"
NOW = datetime.now(timezone.utc)


def inventory(subs):
    rows = {
        SUB_A: [{"id": VM, "name": "vm-app-prod-1", "type": "microsoft.compute/virtualmachines", "subscriptionId": SUB_A,
                 "resourceGroup": "rg-app", "location": "westeurope", "vmSize": "Standard_D4s_v5",
                 "powerState": "PowerState/running"},
                {"id": DISK, "name": "disk-old", "type": "microsoft.compute/disks", "subscriptionId": SUB_A,
                 "resourceGroup": "rg-app", "location": "westeurope"}],
        SUB_B: [{"id": STORAGE, "name": "stdata", "type": "microsoft.storage/storageaccounts", "subscriptionId": SUB_B,
                 "resourceGroup": "rg-data", "location": "northeurope"}],
    }
    return {"generated_at": "2026-10-05T10:00:00+00:00", "source": "resource-graph",
            "subscriptions": [{"id": s["id"].lower(), "name": s["name"]} for s in subs],
            "usage": {"resources": 3, "with_data": 1}, "providers": {},
            "resources": [r for s in subs for r in rows[s["id"]]]}


def finding(fid, ftype, category, severity, resource, saving=None):
    return SimpleNamespace(id=fid, finding_type=ftype, category=category, severity=SeverityLevel(severity),
                           title=f"{ftype} on {resource and resource.resource_name}", subscription_id="sub-a-internal",
                           estimated_monthly_savings_usd=saving, resource=resource)


def resource(azure_id, name):
    return SimpleNamespace(azure_resource_id=azure_id, resource_name=name)


# ---- pure join ---------------------------------------------------------------------------------

def test_finding_row_carries_the_local_report_classification_and_the_finding_id():
    row = service.finding_row(finding("f-1", "unattached_managed_disk", "compute", "high", resource(DISK, "disk-old"), 20.0))
    assert row["ref"] == "f-1" and row["resource_id"] == DISK and row["severity"] == "high"
    assert row["folder"] == "compute-appservice" and row["wave"] == 1 and row["estimated_monthly_savings_usd"] == 20.0


def test_snapshot_joins_database_findings_and_costs_and_blanks_cost_without_access():
    subs = [{"id": SUB_A, "name": "sub-a"}, {"id": SUB_B, "name": "sub-b"}]
    findings = {SUB_A.lower(): [
        service.finding_row(finding("f-1", "unattached_managed_disk", "compute", "high", resource(DISK, "disk-old"), 20.0)),
        service.finding_row(finding("f-2", "missing_required_tags", "governance", "low", resource(VM, "vm-app-prod-1"))),
        service.finding_row(finding("f-3", "budget_missing", "cost", "medium", None)),
    ]}
    costs = {SUB_A.lower(): {VM.lower(): {"cost": 120.5, "currency": "CHF"}}, SUB_B.lower(): None}
    result = service.build_snapshot(service.merge_inventories([inventory(subs)]),
                                    service.reports_from_database(subs, findings, costs), costs)
    data = result["data"]
    assert data["format"] == 2 and data["source"] == "resource-graph" and data["cost_unavailable"] == [SUB_B.lower()]
    by_name = {r["name"]: r for r in data["resources"]}
    assert by_name["vm-app-prod-1"]["cost"] == 120.5 and by_name["vm-app-prod-1"]["cur"] == "CHF"
    assert by_name["disk-old"]["cost"] == 0.0           # cost access, no charge: 0
    assert "cost" not in by_name["stdata"]               # no cost access: unknown, not 0
    disk_suggestion = next(s for s in data["suggestions"] if s["type"] == "unattached_managed_disk")
    assert disk_suggestion["ref"] == "f-1" and data["resources"][disk_suggestion["r"]]["name"] == "disk-old"
    assert next(s for s in data["suggestions"] if s["type"] == "missing_required_tags")["hy"] == 1
    assert (result["resources"], result["suggestions"], result["subscriptions"]) == (3, 3, 2)
    assert "## Overview" in result["markdown"]


def test_inventories_of_several_tenants_are_merged():
    a = inventory([{"id": SUB_A, "name": "sub-a"}])
    b = inventory([{"id": SUB_B, "name": "sub-b"}])
    b["generated_at"] = "2026-10-05T09:00:00+00:00"
    b["providers"] = {SUB_B.lower(): [{"namespace": "Microsoft.Storage", "state": "Registered", "policy": ""}]}
    merged = service.merge_inventories([a, b])
    assert len(merged["resources"]) == 3 and len(merged["subscriptions"]) == 2
    assert merged["usage"] == {"resources": 6, "with_data": 2} and merged["generated_at"].startswith("2026-10-05T09")
    assert list(merged["providers"]) == [SUB_B.lower()]


# ---- worker refresh ----------------------------------------------------------------------------

class Rows:
    def __init__(self, value):
        self.value = value

    def scalars(self):
        return self

    def all(self):
        return list(self.value)


class SyncDb:
    """Scripted sync session: execute() returns the scripted results for SELECTs; writes are recorded."""

    def __init__(self, snapshot, *selects):
        self.snapshot, self.selects, self.writes, self.commits = snapshot, list(selects), [], 0

    def get(self, model, key):
        return self.snapshot if self.snapshot and self.snapshot.id == key else None

    def execute(self, statement):
        if statement.is_select:
            return Rows(self.selects.pop(0))
        self.writes.append(statement)
        return Rows([])

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass


def test_run_refresh_collects_per_tenant_and_stores_a_completed_snapshot():
    snapshot = EstateSnapshot(id="snap-1", status=service.RUNNING, triggered_by="manual")
    tenant = SimpleNamespace(id="tenant-1", tenant_id="t", client_id="c", client_secret_encrypted="x")
    sub_a = SimpleNamespace(id="sub-a-internal", tenant_id="tenant-1", subscription_id=SUB_A, display_name="sub-a",
                            last_scanned_at=NOW)
    disk = finding("f-1", "unattached_managed_disk", "compute", "high", resource(DISK, "disk-old"), 20.0)
    db = SyncDb(snapshot, [sub_a], [tenant], [disk], [])  # subscriptions, tenants, findings, prune
    seen = {}

    def collect(credential, subs):
        seen["collect"] = (credential, subs)
        return inventory([{"id": SUB_A, "name": "sub-a"}])

    def costs_for(cred, ids, cost_basis=None):
        seen["basis"] = cost_basis
        return {i.lower(): {} for i in ids}

    service.run_refresh(db, "snap-1", collect=collect, credential_for=lambda t: f"cred-{t.id}", costs_for=costs_for,
                        trend_for=lambda cred, ids, cost_basis=None: {
                            i.lower(): [{"month": "2026-09", "cost": 81.0, "cost_usd": 100.0}] for i in ids},
                        basis_for=lambda db: "ActualCost")
    assert seen["collect"] == ("cred-tenant-1", [{"id": SUB_A, "name": "sub-a"}])
    assert seen["basis"] == "ActualCost" and snapshot.data["cost_basis"] == "ActualCost"
    assert snapshot.data["cost_trend"][SUB_A.lower()][0]["cost_usd"] == 100.0
    assert snapshot.status == service.COMPLETED and snapshot.completed_at is not None
    assert snapshot.resources_count == 2 and snapshot.suggestions_count == 1
    assert snapshot.data["suggestions"][0]["ref"] == "f-1" and snapshot.overview_markdown.startswith("# Estate")


def test_run_refresh_records_a_failure_on_the_snapshot_instead_of_raising():
    snapshot = EstateSnapshot(id="snap-1", status=service.RUNNING, triggered_by="manual")
    db = SyncDb(snapshot, [], [])  # no active subscriptions
    service.run_refresh(db, "snap-1")
    failure = db.writes[-1].compile().params
    assert failure["status"] == service.FAILED and "connect_azure" in failure["error_message"]


def test_run_refresh_ignores_a_snapshot_that_is_no_longer_running():
    db = SyncDb(EstateSnapshot(id="snap-1", status=service.COMPLETED, triggered_by="manual"))
    service.run_refresh(db, "snap-1")
    assert db.writes == [] and db.commits == 0


def test_a_finished_scan_queues_one_refresh_and_never_fails_because_of_it(monkeypatch):
    from workers import scan_worker

    queued, claims = [], []

    def claim(db, triggered_by):
        claims.append(triggered_by)
        return claims_result.pop(0)

    monkeypatch.setattr(service, "claim_refresh", claim)
    monkeypatch.setattr(scan_worker.refresh_estate, "delay", lambda **kw: queued.append(kw))
    claims_result = [SimpleNamespace(id="snap-9"), None]
    scan_worker.queue_estate_refresh(object(), "scan:job-1")
    scan_worker.queue_estate_refresh(object(), "scan:job-2")  # one already running: skipped
    assert claims == ["scan:job-1", "scan:job-2"] and queued == [{"snapshot_id": "snap-9"}]

    def broken(db, triggered_by):
        raise RuntimeError("database gone")

    monkeypatch.setattr(service, "claim_refresh", broken)
    scan_worker.queue_estate_refresh(object(), "scan:job-3")  # logged, not raised


# ---- admin-only API ----------------------------------------------------------------------------

class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class AsyncDb:
    def __init__(self, *selects):
        self.selects, self.added, self.commits = list(selects), [], 0

    async def execute(self, statement):
        return Result(self.selects.pop(0) if statement.is_select else None)

    def add(self, obj):
        obj.id = obj.id or "snap-new"
        self.added.append(obj)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        pass


def client(db, role=UserRole.ADMIN):
    app = FastAPI()
    app.include_router(estate_routes.router, prefix="/estate")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[auth.get_current_user] = lambda: SimpleNamespace(id="admin-1", role=role, is_active=True)
    return TestClient(app)


def completed(**kw):
    values = dict(id="snap-1", status=service.COMPLETED, triggered_by="scan:job-1", started_at=NOW - timedelta(minutes=6),
                  completed_at=NOW, error_message=None, subscriptions_count=19, resources_count=6914,
                  suggestions_count=364, data={"format": 2, "resources": [], "suggestions": []},
                  overview_markdown="# Estate Inventory")
    values.update(kw)
    return SimpleNamespace(**values)


@pytest.mark.parametrize("role", [UserRole.ANALYST, UserRole.VIEWER, UserRole.AUDITOR])
@pytest.mark.parametrize("method,path", [("get", "/estate"), ("get", "/estate/status"),
                                         ("get", "/estate/overview.md"), ("post", "/estate/refresh")])
def test_estate_is_admin_only(role, method, path):
    assert getattr(client(AsyncDb(), role), method)(path).status_code == 403


def test_get_estate_returns_the_newest_completed_snapshot_or_404():
    assert client(AsyncDb(None)).get("/estate").status_code == 404
    body = client(AsyncDb(completed())).get("/estate").json()
    assert body["format"] == 2 and body["snapshot"]["resources"] == 6914 and body["snapshot"]["triggered_by"] == "scan:job-1"
    r = client(AsyncDb(completed())).get("/estate/overview.md")
    assert r.text == "# Estate Inventory" and "attachment" in r.headers["content-disposition"]


def test_status_reports_a_running_refresh_and_the_page_data_available():
    running = completed(id="snap-2", status=service.RUNNING, completed_at=None)
    body = client(AsyncDb(running, completed())).get("/estate/status").json()  # latest, available
    assert body["running"] is True and body["latest"]["id"] == "snap-2" and body["available"]["id"] == "snap-1"


def test_refresh_reuses_a_running_one_and_otherwise_queues_the_worker(monkeypatch):
    queued = []
    worker = ModuleType("workers.scan_worker")
    worker.refresh_estate = SimpleNamespace(delay=lambda **kw: queued.append(kw))
    monkeypatch.setitem(sys.modules, "workers.scan_worker", worker)

    running = completed(id="snap-2", status=service.RUNNING, completed_at=None)
    body = client(AsyncDb(running)).post("/estate/refresh").json()
    assert body["started"] is False and body["snapshot"]["id"] == "snap-2" and queued == []

    db = AsyncDb(None)  # no running refresh
    r = client(db).post("/estate/refresh")
    assert r.status_code == 202 and r.json()["started"] is True
    assert queued == [{"snapshot_id": "snap-new"}] and db.added[0].requested_by == "admin-1"
    assert db.added[0].status == service.RUNNING and db.added[0].triggered_by == "manual"


def test_refresh_marks_the_snapshot_failed_when_the_queue_is_down(monkeypatch):
    worker = ModuleType("workers.scan_worker")

    def down(**kw):
        raise ConnectionError("redis down")

    worker.refresh_estate = SimpleNamespace(delay=down)
    monkeypatch.setitem(sys.modules, "workers.scan_worker", worker)
    db = AsyncDb(None)
    assert client(db).post("/estate/refresh").status_code == 503
    assert db.added[0].status == service.FAILED and "redis down" in db.added[0].error_message


def test_migration_creates_the_estate_snapshots_table(monkeypatch):
    from io import StringIO
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parents[2]
    monkeypatch.chdir(root)
    output = StringIO()
    command.upgrade(Config(str(root / "alembic.ini"), output_buffer=output), "head", sql=True)
    sql = output.getvalue()
    assert "CREATE TABLE estate_snapshots" in sql
    assert "CREATE UNIQUE INDEX uq_estate_snapshots_one_running ON estate_snapshots (status) WHERE status = 'running'" in sql
