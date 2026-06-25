"""
Health check endpoint — used by Docker/K8s liveness and readiness probes.
"""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("")
async def health_check(db: AsyncSession = Depends(get_db)) -> dict:
    """
    Liveness + readiness probe endpoint.

    Returns 200 if the app can reach the database.
    K8s readiness probe should call this; liveness probe can call /health/live.
    """
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as exc:
        logger.error("Health check DB failure: %s", exc)

    status = "healthy" if db_ok else "degraded"
    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "database": "ok" if db_ok else "error",
        },
    }


@router.get("/live")
async def liveness() -> dict:
    """Lightweight liveness check — no DB call, just confirms the process is up."""
    return {"status": "alive", "timestamp": datetime.now(timezone.utc).isoformat()}
