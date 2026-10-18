"""Docker API for CI/CD: personal API keys, the findings gate and the AI prompt (no database needed)."""
import asyncio
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from backend.api.dependencies import auth
from backend.api.dependencies.database import get_db
from backend.api.routes import api_keys, findings
from backend.models.models import ApiKey, FindingStatus, SeverityLevel, UserRole

NOW = datetime.now(timezone.utc)
SUB_GUID = "11111111-2222-3333-4444-555555555555"


class Result:
    def __init__(self, value):
        self.value = value

    def all(self):
        return list(self.value)

    def scalars(self):
        return self

    def scalar_one(self):
        return self.value

    def scalar_one_or_none(self):
        if isinstance(self.value, list):
            return self.value[0] if self.value else None
        return self.value


class ScriptedDb:
    """Returns the scripted results in order and records the SQL it was asked to run."""

    def __init__(self, *results):
        self.results = list(results)
        self.queries = []
        self.added = []

    async def execute(self, query):
        self.queries.append(str(query.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})))
        return Result(self.results.pop(0))

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        for obj in self.added:
            obj.id = obj.id or "key-1"

    async def refresh(self, obj):
        obj.created_at = obj.created_at or NOW


def user(role=UserRole.ANALYST, active=True):
    return SimpleNamespace(id="user-1", role=role, is_active=active, sso_provider=None, sso_subject=None,
                           deleted_at=None)


def stored_key(plain="arg_secret", **kw):
    return SimpleNamespace(id="key-1", user_id="user-1", key_hash=auth.hash_api_key(plain), revoked_at=None,
                           expires_at=NOW + timedelta(days=1), last_used_at=None, **kw)


def request():
    return SimpleNamespace(state=SimpleNamespace())


def run(coro):
    return asyncio.run(coro)


# ---- API key authentication --------------------------------------------------------------------

def test_api_key_in_bearer_or_header_authenticates_as_its_owner():
    key, owner, req = stored_key(), user(), request()
    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials="arg_secret")
    assert run(auth.get_current_user(req, bearer, None, ScriptedDb(key, owner))) is owner
    assert req.state.api_key_id == "key-1" and key.last_used_at is not None
    req = request()
    assert run(auth.get_current_user(req, None, "arg_secret", ScriptedDb(stored_key(), owner))) is owner


@pytest.mark.parametrize("change", [
    {"revoked_at": NOW}, {"expires_at": NOW - timedelta(seconds=1)}, {"key_hash": "other"},
])
def test_revoked_expired_or_unknown_api_keys_are_rejected(change):
    key = stored_key()
    for k, v in change.items():
        setattr(key, k, v)
    db = ScriptedDb(None if "key_hash" in change else key, user())
    with pytest.raises(HTTPException) as err:
        run(auth.get_current_user(request(), None, "arg_secret", db))
    assert err.value.status_code == 401


def test_disabled_owner_and_wrong_prefix_are_rejected():
    with pytest.raises(HTTPException) as err:
        run(auth.get_current_user(request(), None, "arg_secret", ScriptedDb(stored_key(), user(active=False))))
    assert err.value.status_code == 403
    with pytest.raises(HTTPException) as err:
        run(auth.get_current_user(request(), None, "not-a-key", ScriptedDb()))
    assert err.value.status_code == 401


def test_jwt_path_is_unchanged_for_non_key_tokens():
    db = ScriptedDb()
    with pytest.raises(HTTPException) as err:
        run(auth.get_current_user(request(), HTTPAuthorizationCredentials(scheme="Bearer", credentials="a.b.c"), None, db))
    assert err.value.status_code == 401 and db.queries == []


# ---- API key management ------------------------------------------------------------------------

def keys_client(db, via_api_key=False, role=UserRole.ANALYST):
    app = FastAPI()
    app.include_router(api_keys.router, prefix="/api-keys")
    app.dependency_overrides[get_db] = lambda: db

    def current(request: Request):
        if via_api_key:
            request.state.api_key_id = "key-0"
        return user(role)

    app.dependency_overrides[auth.get_current_user] = current
    return TestClient(app)


def test_create_returns_the_key_once_and_stores_only_its_hash():
    db = ScriptedDb([])  # no active keys yet
    r = keys_client(db).post("/api-keys", json={"name": "GitHub Actions", "expires_in_days": 30})
    assert r.status_code == 201
    body = r.json()
    stored = db.added[0]
    assert isinstance(stored, ApiKey) and body["key"].startswith("arg_") and body["prefix"] == body["key"][:12]
    assert stored.key_hash == auth.hash_api_key(body["key"]) and body["key"] not in stored.key_hash
    assert timedelta(days=29) < stored.expires_at - NOW <= timedelta(days=30, minutes=1)
    assert keys_client(ScriptedDb([])).post("/api-keys", json={"name": "x", "expires_in_days": 400}).status_code == 422


def test_api_keys_cannot_manage_api_keys_and_active_keys_are_capped():
    assert keys_client(ScriptedDb([]), via_api_key=True).post("/api-keys", json={"name": "x"}).status_code == 403
    assert keys_client(ScriptedDb([]), via_api_key=True).get("/api-keys").status_code == 403
    full = [stored_key() for _ in range(api_keys.MAX_ACTIVE_KEYS_PER_USER)]
    assert keys_client(ScriptedDb(full)).post("/api-keys", json={"name": "x"}).status_code == 400


def test_revoke_own_key_and_hide_other_users_keys():
    own = stored_key(name="ci", prefix="arg_abcdefg", created_at=NOW)
    r = keys_client(ScriptedDb(own)).delete("/api-keys/00000000-0000-0000-0000-000000000001")
    assert r.status_code == 200 and r.json()["active"] is False and own.revoked_at is not None
    other = stored_key(name="ci", prefix="arg_abcdefg", created_at=NOW)
    other.user_id = "someone-else"
    assert keys_client(ScriptedDb(other)).delete("/api-keys/00000000-0000-0000-0000-000000000001").status_code == 404
    assert keys_client(ScriptedDb(other), role=UserRole.ADMIN).delete(
        "/api-keys/00000000-0000-0000-0000-000000000001").status_code == 200


# ---- findings gate and AI prompt ---------------------------------------------------------------

def finding(sev, ftype, name, saving=None):
    return SimpleNamespace(
        id=f"f-{name}", finding_type=ftype, title=f"{ftype} on {name}", description="d", severity=SeverityLevel(sev),
        status=FindingStatus.OPEN, category="cost", subscription_id="sub-1", estimated_monthly_savings_usd=saving,
        first_detected_at=NOW, last_detected_at=NOW, resolved_at=None, remediation_steps=None, evidence={},
        caf_control=None, nist_control=None, cis_control=None, suppression_reason=None, scan_job_id=None,
        resource=SimpleNamespace(resource_name=name, resource_type="t", resource_group="rg",
                                 azure_resource_id=f"/subscriptions/{SUB_GUID}/x/{name}", location="westeurope"))


def findings_client(db, role=UserRole.ANALYST):
    app = FastAPI()
    app.include_router(findings.router, prefix="/findings")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[auth.get_current_user] = lambda: user(role)
    return TestClient(app)


def test_gate_counts_open_findings_at_or_above_threshold_minus_ignored_types():
    db = ScriptedDb(
        [(SeverityLevel.CRITICAL, 1), (SeverityLevel.HIGH, 2), (SeverityLevel.LOW, 4)],  # by severity
        2,                                                                           # blocking count
        [finding("critical", "public_storage", "st1")],                              # critical examples
        [finding("high", "unattached_disk", "d1", 40.0)],                            # high examples
    )
    r = findings_client(db).get("/findings/gate?fail_on=high&ignore=missing_tags")
    assert r.status_code == 200
    body = r.json()
    assert body["passed"] is False and body["blocking"] == 2 and body["total"] == 7
    assert body["findings_by_severity"] == {"critical": 1, "high": 2, "medium": 0, "low": 4, "info": 0}
    assert [f["finding_type"] for f in body["blocking_findings"]] == ["public_storage", "unattached_disk"]
    count_sql = db.queries[1]
    assert "'CRITICAL', 'HIGH'" in count_sql and "NOT IN ('missing_tags')" in count_sql and "'OPEN'" in count_sql


def test_gate_passes_with_no_blocking_findings_and_validates_input():
    r = findings_client(ScriptedDb([(SeverityLevel.LOW, 3)], 0)).get("/findings/gate?fail_on=critical")
    assert r.json()["passed"] is True and r.json()["blocking_findings"] == []
    assert findings_client(ScriptedDb()).get("/findings/gate?fail_on=urgent").status_code == 400
    assert findings_client(ScriptedDb()).get("/findings/gate?status=bogus").status_code == 400


def test_gate_for_an_invisible_subscription_is_404_not_a_silent_pass():
    viewer_db = ScriptedDb([], "sub-x")  # viewer grants: none; then the Azure subscription lookup
    r = findings_client(viewer_db, role=UserRole.VIEWER).get(f"/findings/gate?azure_subscription_id={SUB_GUID}")
    assert r.status_code == 404
    assert findings_client(ScriptedDb(None)).get(f"/findings/gate?azure_subscription_id={SUB_GUID}").status_code == 404


def test_ai_prompt_is_markdown_with_masked_ids_and_the_subscription_name():
    db = ScriptedDb([finding("high", "unattached_disk", "disk-1", 25.0), finding("critical", "public_storage", "st1")],
                    SimpleNamespace(display_name="sub-demo", subscription_id=SUB_GUID))
    r = findings_client(db).get("/findings/ai-prompt?severity=critical&severity=high")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown")
    text = r.text
    assert "sub-demo" in text and SUB_GUID not in text and "<id-1>" in text
    assert text.index("public_storage on st1") < text.index("unattached_disk on disk-1")
    assert "'CRITICAL', 'HIGH'" in db.queries[0]


def test_migration_creates_the_api_keys_table(monkeypatch):
    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parents[2]
    monkeypatch.chdir(root)
    output = StringIO()
    command.upgrade(Config(str(root / "alembic.ini"), output_buffer=output), "head", sql=True)
    sql = output.getvalue()
    assert "CREATE TABLE api_keys" in sql and "CREATE UNIQUE INDEX ix_api_keys_key_hash" in sql
