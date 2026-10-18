"""
Azure Resource Guardian - Authentication Dependencies
=====================================================
FastAPI dependency injection for JWT authentication and RBAC.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import settings
from backend.api.dependencies.database import get_db
from backend.models.models import ApiKey, User, UserRole

security = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

API_KEY_PREFIX = "arg_"
API_KEY_TOUCH_INTERVAL = timedelta(minutes=5)  # last_used_at is refreshed at most this often


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


async def _user_from_api_key(key: str, request: Request, db: AsyncSession) -> User:
    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired API key",
                                 headers={"WWW-Authenticate": "Bearer"})
    if not key.startswith(API_KEY_PREFIX):
        raise unauthorized
    api_key = (await db.execute(select(ApiKey).where(ApiKey.key_hash == hash_api_key(key)))).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if not api_key or api_key.revoked_at or (api_key.expires_at and api_key.expires_at <= now):
        raise unauthorized
    user = (await db.execute(
        select(User).where(User.id == api_key.user_id, User.deleted_at.is_(None)))).scalar_one_or_none()
    if not user:
        raise unauthorized
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    if not api_key.last_used_at or now - api_key.last_used_at > API_KEY_TOUCH_INTERVAL:
        api_key.last_used_at = now  # committed by get_db
    request.state.api_key_id = api_key.id
    return user


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Depends(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validate a JWT access token or a personal API key (`Bearer arg_...` / `X-API-Key`) and return the user.
    Raises 401 for invalid/missing credentials, 403 for inactive users.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if x_api_key:
        return await _user_from_api_key(x_api_key, request, db)
    if not credentials:
        raise credentials_exception
    if credentials.credentials.startswith(API_KEY_PREFIX):
        return await _user_from_api_key(credentials.credentials, request, db)

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM],
        )
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")

        if not user_id or token_type != "access":
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    result = await db.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if not user:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account disabled",
        )

    return user


async def get_session_user(request: Request, current_user: User = Depends(get_current_user)) -> User:
    """Signed-in user only: an API key cannot create or list API keys (a leaked key cannot mint new ones)."""
    if getattr(request.state, "api_key_id", None):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="API keys cannot manage API keys - sign in to ARG")
    return current_user


def require_roles(*roles: UserRole):
    """
    RBAC dependency factory.

    Usage:
        @router.get("/admin-only")
        async def admin_endpoint(
            current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SUPER_ADMIN))
        ):
            ...
    """
    async def _check(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {[r.value for r in roles]}",
            )
        return current_user
    return _check


# Pre-built role dependencies for common patterns
require_admin = require_roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
require_analyst = require_roles(UserRole.ANALYST, UserRole.ADMIN, UserRole.SUPER_ADMIN)
require_auditor = require_roles(UserRole.AUDITOR, UserRole.ANALYST, UserRole.ADMIN, UserRole.SUPER_ADMIN)
