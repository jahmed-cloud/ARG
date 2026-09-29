"""Readiness must fail for a broken database; liveness remains independent."""
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.dependencies.database import get_db
from backend.api.routes.health import router


def client_for(db):
    app = FastAPI()
    app.include_router(router, prefix="/health")
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def test_ready_with_database():
    db = AsyncMock()
    with client_for(db) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["components"]["database"] == "ok"
    db.execute.assert_awaited_once()
    db.rollback.assert_not_awaited()


def test_unavailable_database_is_not_ready():
    db = AsyncMock()
    db.execute.side_effect = ConnectionError("unavailable")
    with client_for(db) as client:
        response = client.get("/health")
        assert client.get("/health/live").status_code == 200
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    db.rollback.assert_awaited_once()
    db.execute.assert_awaited_once()


def test_database_timeout_is_not_ready():
    db = AsyncMock()
    db.execute.side_effect = TimeoutError()
    with client_for(db) as client:
        assert client.get("/health").status_code == 503
