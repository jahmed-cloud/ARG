"""Dashboard reads must respect a single-session transaction and missing evidence."""
import asyncio
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from backend.api.routes import dashboard
from backend.api.dependencies.database import get_db
from backend.api.dependencies.auth import get_current_user


class EmptyResult:
    def all(self):
        return []

    def first(self):
        return None

    def scalar_one_or_none(self):
        return None

    def scalars(self):
        return self


class Transaction:
    """Like asyncpg, reject a second query while the connection is busy."""
    def __init__(self):
        self.busy = False
        self.queries = []

    async def execute(self, query):
        assert not self.busy, 'Concurrent use of one database transaction'
        self.busy = True
        self.queries.append(query)
        try:
            await asyncio.sleep(0)
            return EmptyResult()
        finally:
            self.busy = False

    async def scalar(self, query):
        await self.execute(query)
        return 0


def client_for(db):
    app = FastAPI()
    app.include_router(dashboard.router, prefix='/dashboard')
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id='tester')
    return TestClient(app)


def test_empty_dashboard_has_no_invented_cost_or_assessment_dates():
    with client_for(Transaction()) as client:
        response = client.get('/dashboard')
    assert response.status_code == 200
    data = response.json()
    assert data['cost_trend'] == []
    assert data['last_scan_completed_at'] is None
    assert all(data[f'{category}_score']['last_updated'] is None
               for category in ('governance', 'security', 'identity'))


def test_subscription_filter_reaches_every_summary_query():
    db = Transaction()
    subscription_id = '11111111-1111-1111-1111-111111111111'
    with client_for(db) as client:
        assert client.get('/dashboard', params={'subscription_id': subscription_id}).status_code == 200
    assert db.queries
    for query in db.queries:
        compiled = query.compile(dialect=postgresql.dialect())
        assert subscription_id in compiled.params.values(), str(compiled)


def test_history_rejects_invalid_and_reversed_dates():
    with client_for(Transaction()) as client:
        assert client.get('/dashboard/score-history?start_date=garbage').status_code == 422
        assert client.get('/dashboard/score-history?start_date=2026-09-20&end_date=2026-09-01').status_code == 422
