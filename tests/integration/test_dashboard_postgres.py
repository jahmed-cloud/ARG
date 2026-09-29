"""Optional PostgreSQL check; all fixtures are rolled back, never committed.

Run with ARG_TEST_DATABASE_URL set to an asyncpg PostgreSQL URL with migrations applied.
"""
import asyncio
import os
from datetime import date
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from backend.api.routes.dashboard import get_dashboard
from backend.models.models import (
    Tenant, Subscription, ResourceInventory, ResourceCost, Finding, SeverityLevel,
)


async def check_dashboard(url):
    engine = create_async_engine(url)
    try:
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                async with AsyncSession(bind=connection, expire_on_commit=False) as db:
                    tenant = Tenant(tenant_id=str(uuid4()), display_name='Rollback-only test',
                                    client_id=str(uuid4()), client_secret_encrypted='unused-test-value')
                    db.add(tenant)
                    await db.flush()
                    subs = [Subscription(subscription_id=str(uuid4()), display_name=f'Test {n}', tenant_id=tenant.id)
                            for n in range(2)]
                    db.add_all(subs)
                    await db.flush()
                    resource = ResourceInventory(subscription_id=subs[0].id, azure_resource_id='/test/resource',
                        resource_name='test-resource', resource_type='test', resource_group='test', location='test')
                    db.add(resource)
                    await db.flush()
                    db.add(ResourceCost(resource_id=resource.id, billing_month=date.today().strftime('%Y-%m'), cost_usd=42))
                    for level in [SeverityLevel.INFO, SeverityLevel.LOW, SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                        db.add(Finding(subscription_id=subs[0].id, resource_id=resource.id,
                            finding_type=f'test-{level.value}', category='security', severity=level,
                            title=level.value, description='Rollback-only fixture'))
                    db.add(Finding(subscription_id=subs[1].id, finding_type='other', category='security',
                        severity=SeverityLevel.CRITICAL, title='Must be excluded', description='Rollback-only fixture'))
                    await db.flush()
                    for scope in [subs[0].id, subs[0].subscription_id]:
                        result = await get_dashboard(scope, db, SimpleNamespace())
                        assert result.total_resources == 1
                        assert result.total_subscriptions == 1
                        assert result.total_findings_open == 4
                        assert [f.severity for f in result.top_findings] == ['critical', 'high', 'low', 'info']
                        assert result.cost_trend[0].total_cost == 42
                    empty = await get_dashboard(str(uuid4()), db, SimpleNamespace())
                    assert empty.total_resources == empty.total_findings_open == 0
                    assert empty.cost_trend == []
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


@pytest.mark.skipif(not os.getenv('ARG_TEST_DATABASE_URL'), reason='Set ARG_TEST_DATABASE_URL for PostgreSQL integration')
def test_dashboard_postgres():
    asyncio.run(check_dashboard(os.environ['ARG_TEST_DATABASE_URL']))
