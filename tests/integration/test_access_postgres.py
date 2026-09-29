"""Subscription-scoped access against PostgreSQL; everything runs in one transaction that is rolled back.

Run with ARG_TEST_DATABASE_URL set to an asyncpg PostgreSQL URL with migrations applied (alembic upgrade head).
Covers: who sees which subscription on every scoped read route, owner-managed reader grants, and Microsoft
sign-in (auto-provisioning, group roles, tenant binding) with a fake MSAL app.
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from backend.api.routes import auth as auth_routes
from backend.api.routes.costs import get_cost_summary
from backend.api.routes.dashboard import get_dashboard
from backend.api.routes.findings import get_finding, get_finding_stats, list_findings
from backend.api.routes.governance import get_governance_stats
from backend.api.routes.reports import generate_report, list_reports
from backend.api.routes.scans import get_scan, list_scans
from backend.api.routes.security import get_security_stats
from backend.api.routes.subscriptions import (
    AccessGrantCreate, add_reader, list_access, list_subscriptions, remove_reader,
)
from backend.core.config import settings
from backend.models.models import (
    Finding, ScanJob, SeverityLevel, Subscription, SubscriptionAccess, Tenant, User, UserRole,
)
from backend.services.access import load_scope

TENANT_GUID = str(uuid4())
ADMIN_GROUP, CONTRIB_GROUP = str(uuid4()), str(uuid4())
REQUEST = SimpleNamespace(client=None, headers={})


def paged(**kw):
    base = dict(severity=None, status=None, category=None, subscription_id=None, resource_group=None,
                tenant_id=None, finding_type=None, search=None, page=1, page_size=50, sort_desc=True)
    return {**base, **kw}


async def seed(db):
    tenant = Tenant(tenant_id=TENANT_GUID.upper(), display_name='Rollback-only', client_id=str(uuid4()),
                    client_secret_encrypted='unused-test-value')
    db.add(tenant)
    await db.flush()
    subs = [Subscription(subscription_id=str(uuid4()), display_name=f'Sub {n}', tenant_id=tenant.id) for n in range(2)]
    db.add_all(subs)
    await db.flush()
    for n, sub in enumerate(subs):
        for category in ('security', 'governance'):
            db.add(Finding(subscription_id=sub.id, finding_type=f'{category}-{n}', category=category,
                           severity=SeverityLevel.HIGH, title=f'{category} in {sub.display_name}',
                           description='Rollback-only fixture', estimated_monthly_savings_usd=10 * (n + 1)))
        db.add(ScanJob(subscription_id=sub.id))
    db.add(ScanJob(subscription_id=None))  # a scan over everything: never shown to scoped users

    def user(name, role, **kw):
        return User(email=f'{name}-{uuid4().hex[:6]}@example.test', username=f'{name}-{uuid4().hex[:6]}',
                    role=role, is_active=True, preferences={}, **kw)
    owner = user('owner', UserRole.VIEWER, sso_provider='azure_ad', sso_subject=str(uuid4()))
    reader = user('reader', UserRole.VIEWER)
    nobody = user('nobody', UserRole.VIEWER)
    expired = user('expired', UserRole.VIEWER, sso_provider='azure_ad', sso_subject=str(uuid4()))
    analyst = user('analyst', UserRole.ANALYST)
    db.add_all([owner, reader, nobody, expired, analyst])
    await db.flush()
    soon = datetime.now(timezone.utc) + timedelta(minutes=30)
    db.add(SubscriptionAccess(subscription_id=subs[0].id, tenant_id=TENANT_GUID, object_id=owner.sso_subject,
                              role='owner', source='azure', expires_at=soon, principal_name=owner.email))
    db.add(SubscriptionAccess(subscription_id=subs[1].id, user_id=reader.id, role='reader', source='manual',
                              principal_name=reader.email))
    db.add(SubscriptionAccess(subscription_id=subs[1].id, tenant_id=TENANT_GUID, object_id=expired.sso_subject,
                              role='owner', source='azure', expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)))
    await db.flush()
    return SimpleNamespace(tenant=tenant, subs=subs, owner=owner, reader=reader, nobody=nobody,
                           expired=expired, analyst=analyst)


async def visible(db, user, s):
    scope = await load_scope(db, user)
    subs = {row['id'] for row in await list_subscriptions(db, scope)}
    findings = await list_findings(db, scope, **paged())
    return scope, subs, {f['subscription_id'] for f in findings['items']}, findings['total']


async def check_isolation(db, s):
    sub0, sub1 = (str(x.id) for x in s.subs)

    scope, subs, finding_subs, total = await visible(db, s.owner, s)
    assert subs == {sub0} and finding_subs == {sub0} and total == 2
    assert scope.can_manage(sub0) and not scope.can_manage(sub1)
    other = (await db.execute(select(Finding).where(Finding.subscription_id == sub1))).scalars().first()
    with pytest.raises(HTTPException) as exc:
        await get_finding(other.id, db, scope)
    assert exc.value.status_code == 404
    stats = await get_finding_stats(db, scope, None)
    assert stats.total == 2
    dash = await get_dashboard(None, db, scope)
    assert dash.total_findings_open == 2 and dash.total_subscriptions == 1 and dash.entra_findings_open == 0
    assert (await get_dashboard(s.subs[1].subscription_id, db, scope)).total_findings_open == 0
    cost = await get_cost_summary(db, scope, None)
    assert cost.potential_monthly_savings == 20
    assert (await get_governance_stats(db, scope)).governance_score == 95
    assert (await get_security_stats(db, scope)).security_score == 95
    scans = await list_scans(1, 20, None, db, scope)
    assert scans.total == 1
    everything = (await db.execute(select(ScanJob).where(ScanJob.subscription_id.is_(None)))).scalars().first()
    with pytest.raises(HTTPException):
        await get_scan(everything.id, db, scope)

    _, subs, finding_subs, _ = await visible(db, s.reader, s)
    assert subs == {sub1} and finding_subs == {sub1}

    for nobody in (s.nobody, s.expired):  # no grants, or only an expired Owner lease: nothing at all
        scope, subs, finding_subs, total = await visible(db, nobody, s)
        assert subs == set() and total == 0
        assert (await get_dashboard(None, db, scope)).total_findings_open == 0
        assert (await list_scans(1, 20, None, db, scope)).total == 0

    scope, subs, _, total = await visible(db, s.analyst, s)
    assert {sub0, sub1} <= subs and total >= 4


async def check_grants(db, s, tmp_path, monkeypatch):
    sub0, sub1 = s.subs
    owner_scope = await load_scope(db, s.owner)
    grant = await add_reader(sub0.id, AccessGrantCreate(email=s.nobody.email.upper()), REQUEST, db, owner_scope)
    assert grant['kind'] == 'local' and grant['role'] == 'reader' and grant['removable']
    _, subs, _, _ = await visible(db, s.nobody, s)
    assert subs == {str(sub0.id)}
    with pytest.raises(HTTPException) as exc:  # twice
        await add_reader(sub0.id, AccessGrantCreate(email=s.nobody.email), REQUEST, db, owner_scope)
    assert exc.value.status_code == 409
    with pytest.raises(HTTPException) as exc:  # analysts already see everything
        await add_reader(sub0.id, AccessGrantCreate(email=s.analyst.email), REQUEST, db, owner_scope)
    assert exc.value.status_code == 409
    with pytest.raises(HTTPException) as exc:  # not visible to the owner at all
        await add_reader(sub1.id, AccessGrantCreate(email=s.nobody.email), REQUEST, db, owner_scope)
    assert exc.value.status_code == 404
    reader_scope = await load_scope(db, s.reader)
    with pytest.raises(HTTPException) as exc:  # a reader cannot manage access
        await list_access(sub1.id, db, reader_scope)
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:  # unknown person, no Graph permission: clear 400
        await add_reader(sub0.id, AccessGrantCreate(email='new@example.test'), REQUEST, db, owner_scope)
    assert exc.value.status_code == 400 and 'sign in to ARG with Microsoft once' in exc.value.detail

    rows = await list_access(sub0.id, db, owner_scope)
    owner_row = next(r for r in rows if r['role'] == 'owner')
    assert not owner_row['removable']
    with pytest.raises(HTTPException) as exc:
        await remove_reader(sub0.id, owner_row['id'], REQUEST, db, owner_scope)
    assert exc.value.status_code == 400
    await remove_reader(sub0.id, grant['id'], REQUEST, db, owner_scope)
    _, subs, _, _ = await visible(db, s.nobody, s)
    assert subs == set()

    # Reports: a scoped user's report holds only their subscriptions, and only they see it in history.
    monkeypatch.setattr(settings, 'REPORT_STORAGE_PATH', str(tmp_path))
    body = SimpleNamespace(report_type='technical', output_format='json', title=None, subscription_ids=None,
                           include_resolved=False)
    response = await generate_report(body, db, owner_scope)
    content = b''.join([chunk async for chunk in response.body_iterator])
    assert str(sub0.id).encode() in content and str(sub1.id).encode() not in content
    with pytest.raises(HTTPException):
        body.subscription_ids = [sub1.id]
        await generate_report(body, db, owner_scope)
    assert len((await list_reports(db, owner_scope))['items']) == 1
    assert (await list_reports(db, await load_scope(db, s.reader)))['items'] == []


class FakeMsal:
    def __init__(self, claims):
        self.claims = claims

    def acquire_token_by_authorization_code(self, **_):
        return {'id_token_claims': self.claims}


async def sign_in(db, monkeypatch, claims):
    monkeypatch.setattr(auth_routes, '_msal_app', lambda: FakeMsal(claims))
    state = jwt.encode({'exp': datetime.now(timezone.utc) + timedelta(minutes=5)},
                       settings.SECRET_KEY.get_secret_value(), algorithm=settings.ALGORITHM)
    response = await auth_routes.microsoft_callback(REQUEST, 'code', state, None, None, db)
    return response.headers['location']


async def check_sign_in(db, s, monkeypatch):
    def claims(email, groups=(), tid=TENANT_GUID):
        return {'tid': tid, 'oid': str(uuid4()), 'preferred_username': email, 'name': email, 'groups': list(groups)}

    newcomer = claims(f'new-{uuid4().hex[:6]}@example.test')
    location = await sign_in(db, monkeypatch, newcomer)
    assert '/oauth-callback#' in location and 'role=viewer' in location
    user = (await db.execute(select(User).where(User.sso_subject == newcomer['oid']))).scalar_one()
    assert user.entra_managed and user.role == UserRole.VIEWER and user.hashed_password is None
    assert (await visible(db, user, s))[1] == set()  # signed in, sees nothing until owner / reader access

    # A reader grant made for the Entra identity applies at sign-in (the object ID matches).
    db.add(SubscriptionAccess(subscription_id=s.subs[1].id, tenant_id=TENANT_GUID, object_id=newcomer['oid'],
                              role='reader', source='manual', principal_name=user.email))
    await db.flush()
    assert (await visible(db, user, s))[1] == {str(s.subs[1].id)}

    admin = claims(f'adm-{uuid4().hex[:6]}@example.test', [ADMIN_GROUP])
    assert 'role=admin' in await sign_in(db, monkeypatch, admin)
    contributor = claims(f'con-{uuid4().hex[:6]}@example.test', [CONTRIB_GROUP])
    assert 'role=analyst' in await sign_in(db, monkeypatch, contributor)
    # Group removed: back to viewer at the next sign-in.
    contributor['groups'] = []
    assert 'role=viewer' in await sign_in(db, monkeypatch, contributor)

    foreign = claims(f'x-{uuid4().hex[:6]}@example.test', tid=str(uuid4()))
    assert 'oauth_error=tenant_not_allowed' in await sign_in(db, monkeypatch, foreign)

    monkeypatch.setattr(settings, 'ENTRA_AUTO_PROVISION', False)
    unknown = claims(f'u-{uuid4().hex[:6]}@example.test')
    assert 'oauth_error=no_matching_account' in await sign_in(db, monkeypatch, unknown)


async def run(url, tmp_path, monkeypatch):
    engine = create_async_engine(url)
    try:
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                async with AsyncSession(bind=connection, expire_on_commit=False,
                                        join_transaction_mode='create_savepoint') as db:
                    s = await seed(db)
                    await check_isolation(db, s)
                    await check_grants(db, s, tmp_path, monkeypatch)
                    await check_sign_in(db, s, monkeypatch)
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


@pytest.mark.skipif(not os.getenv('ARG_TEST_DATABASE_URL'), reason='Set ARG_TEST_DATABASE_URL for PostgreSQL integration')
def test_scoped_access_postgres(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'AZURE_OAUTH_TENANT_ID', TENANT_GUID)
    monkeypatch.setattr(settings, 'AZURE_OAUTH_CLIENT_ID', str(uuid4()))
    monkeypatch.setattr(settings, 'AZURE_OAUTH_CLIENT_SECRET', 'unused')
    monkeypatch.setattr(settings, 'ENTRA_ADMIN_GROUP_IDS', [ADMIN_GROUP])
    monkeypatch.setattr(settings, 'ENTRA_CONTRIBUTOR_GROUP_IDS', [CONTRIB_GROUP])
    monkeypatch.setattr(settings, 'ENTRA_AUTO_PROVISION', True)
    asyncio.run(run(os.environ['ARG_TEST_DATABASE_URL'], tmp_path, monkeypatch))
