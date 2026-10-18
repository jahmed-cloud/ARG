"""
Tenant-wide data (Entra ID / identity findings and scores) is for admins and contributors only; on-demand scans are
for contributors and up; the local admin from .env can never be disabled, demoted or changed in the UI; the daily
automatic scan follows FULL_SCAN_SCHEDULE in SCAN_SCHEDULE_TIMEZONE (09:00 Asia/Kolkata by default).
"""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

from backend.core.config import settings
from backend.models.models import UserRole
from backend.services.access import AccessScope


def scope(role, subs=None):
    return AccessScope(user=SimpleNamespace(role=role), subscription_ids=subs)


def sql(condition) -> str:
    return str(condition.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))


@pytest.mark.parametrize("role, tenant", [
    (UserRole.SUPER_ADMIN, True), (UserRole.ADMIN, True), (UserRole.ANALYST, True),
    (UserRole.AUDITOR, False), (UserRole.VIEWER, False),
])
def test_only_admins_and_contributors_see_tenant_wide_findings(role, tenant):
    s = scope(role, {"sub-a"} if role == UserRole.VIEWER else None)
    assert s.tenant is tenant
    assert ("'identity'" in sql(s.findings())) is not tenant


def test_owner_or_reader_never_gets_identity_findings_even_under_their_subscription():
    sub = "11111111-2222-3333-4444-555555555555"
    s = scope(UserRole.VIEWER, {sub})
    text = sql(s.findings())
    assert "findings.subscription_id IN (" in text and "NOT IN ('identity')" in text
    with pytest.raises(HTTPException) as exc:
        s.require_finding(SimpleNamespace(subscription_id=sub, category="identity"))
    assert exc.value.status_code == 404
    s.require_finding(SimpleNamespace(subscription_id=sub, category="security"))  # their own subscription


def test_auditor_reads_every_subscription_but_no_identity_finding():
    with pytest.raises(HTTPException):
        scope(UserRole.AUDITOR).require_finding(SimpleNamespace(subscription_id="x", category="identity"))
    scope(UserRole.ANALYST).require_finding(SimpleNamespace(subscription_id="x", category="identity"))


def test_on_demand_scans_are_for_contributors_and_admins():
    from backend.api.dependencies.auth import require_analyst
    from backend.api.routes import scans

    for suffix in ("/start", "/cancel"):
        route = next(r for r in scans.router.routes if r.path.endswith(suffix) and "POST" in r.methods)
        assert any(d.call is require_analyst for d in route.dependant.dependencies), route.path
    for role in (UserRole.ANALYST, UserRole.ADMIN, UserRole.SUPER_ADMIN):
        asyncio.run(require_analyst(current_user=SimpleNamespace(role=role)))
    for role in (UserRole.AUDITOR, UserRole.VIEWER):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(require_analyst(current_user=SimpleNamespace(role=role)))
        assert exc.value.status_code == 403


def test_local_admin_is_restored_from_env_on_every_start():
    from backend.api.routes.auth import hash_password, verify_password
    from scripts.seed_admin import enforce_local_admin

    user = SimpleNamespace(hashed_password=hash_password("old-password-123"), role=UserRole.VIEWER, is_active=False,
                           deleted_at="2026-09-01", entra_managed=True, subscription_scoped=True, username="renamed")
    changes = enforce_local_admin(user, "admin", "env-password-456")
    assert set(changes) == {"password", "role", "re-enabled", "undeleted", "not Entra-managed", "unscoped", "username"}
    assert verify_password("env-password-456", user.hashed_password)
    assert (user.role, user.is_active, user.deleted_at, user.username) == (UserRole.SUPER_ADMIN, True, None, "admin")
    assert enforce_local_admin(user, "admin", "env-password-456") == []      # already as .env says


class FakeDB:
    def __init__(self, user):
        self.user = user

    async def get(self, model, key):
        return self.user

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass


def local_admin():
    return SimpleNamespace(id="local-admin", email=settings.ADMIN_EMAIL.upper(), role=UserRole.SUPER_ADMIN,
                           is_active=True, deleted_at=None, entra_managed=False, hashed_password="x", sso_provider=None)


def test_local_admin_cannot_be_disabled_demoted_deleted_or_reset_in_the_ui():
    from backend.api.routes import users

    other_admin = SimpleNamespace(id="other", role=UserRole.SUPER_ADMIN, username="other")
    attempts = [
        users.update_user(uuid4(), users.UserUpdate(is_active=False), FakeDB(local_admin()), other_admin),
        users.update_user(uuid4(), users.UserUpdate(role=UserRole.VIEWER), FakeDB(local_admin()), other_admin),
        users.deactivate_user(uuid4(), FakeDB(local_admin()), other_admin),
        users.admin_reset_password(uuid4(), FakeDB(local_admin()), other_admin),
    ]
    for attempt in attempts:
        with pytest.raises(HTTPException) as exc:
            asyncio.run(attempt)
        assert exc.value.status_code == 409 and "ADMIN_PASSWORD" in exc.value.detail


def test_daily_automatic_scan_runs_at_nine_ist():
    from workers.scan_worker import celery_app, cron_schedule

    assert (settings.FULL_SCAN_SCHEDULE, settings.SCAN_SCHEDULE_TIMEZONE) == ("0 9 * * *", "Asia/Kolkata")
    schedule = celery_app.conf.beat_schedule["full-scan-daily"]["schedule"]
    assert (schedule.hour, schedule.minute) == ({9}, {0})
    assert str(celery_app.conf.timezone) == "Asia/Kolkata"
    with pytest.raises(ValueError):
        cron_schedule("0 9 * *")


def test_daily_scan_is_skipped_while_no_subscription_is_connected(monkeypatch):
    from workers import scan_worker

    class NoSubscriptions:
        added = []

        def execute(self, _query):
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))

        def add(self, item):
            self.added.append(item)

        def commit(self):
            pass

        def close(self):
            pass

    db = NoSubscriptions()
    monkeypatch.setattr(scan_worker, "get_sync_db", lambda: db)
    monkeypatch.setattr(scan_worker.run_scan_job, "delay", lambda **_: pytest.fail("scan dispatched"))
    scan_worker.run_scheduled_full_scan()
    assert db.added == []
