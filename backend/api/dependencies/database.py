"""
Azure Resource Guardian - Database Dependencies
===============================================
FastAPI dependency injection for database sessions.
"""

from typing import AsyncGenerator
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession


async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an async database session per request.
    Session is closed after request completes (success or error).
    """
    async with request.app.state.session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
