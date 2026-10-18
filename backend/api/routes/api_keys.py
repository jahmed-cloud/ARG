"""
Personal API keys for CI/CD pipelines and scripts.

    curl -H "Authorization: Bearer arg_..." https://<arg-host>/api/v1/findings/gate?fail_on=high

A key acts as the user who created it (same role and subscription scope). The plain key is returned
once; only its SHA-256 hash is stored. Keys are managed from a signed-in session only, so a leaked key
cannot create new ones. Admins can list and revoke every user's keys.
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import API_KEY_PREFIX, get_session_user, hash_api_key
from backend.api.dependencies.database import get_db
from backend.models.models import ApiKey, User, UserRole

router = APIRouter()

MAX_ACTIVE_KEYS_PER_USER = 10
ADMIN_ROLES = (UserRole.ADMIN, UserRole.SUPER_ADMIN)


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="What uses the key, e.g. 'GitHub Actions - infra repo'")
    expires_in_days: Optional[int] = Field(90, ge=1, le=365, description="1-365 days; keys always expire")


class ApiKeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    user_id: str
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    revoked_at: Optional[datetime]
    active: bool


class ApiKeyCreated(ApiKeyOut):
    key: str = Field(..., description="Shown once - store it as a pipeline secret")


def _out(k: ApiKey) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "id": str(k.id), "name": k.name, "prefix": k.prefix, "user_id": str(k.user_id),
        "created_at": k.created_at or now, "expires_at": k.expires_at, "last_used_at": k.last_used_at,
        "revoked_at": k.revoked_at,
        "active": k.revoked_at is None and (k.expires_at is None or k.expires_at > now),
    }


@router.get("", response_model=List[ApiKeyOut], summary="List API keys")
async def list_api_keys(
    all_users: bool = Query(False, description="Admins only: every user's keys"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_session_user),
):
    query = select(ApiKey).order_by(ApiKey.created_at.desc())
    if not (all_users and current_user.role in ADMIN_ROLES):
        query = query.where(ApiKey.user_id == current_user.id)
    return [_out(k) for k in (await db.execute(query)).scalars().all()]


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED, summary="Create an API key")
async def create_api_key(
    body: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_session_user),
):
    now = datetime.now(timezone.utc)
    active = (await db.execute(select(ApiKey).where(
        ApiKey.user_id == current_user.id, ApiKey.revoked_at.is_(None)))).scalars().all()
    if sum(1 for k in active if k.expires_at is None or k.expires_at > now) >= MAX_ACTIVE_KEYS_PER_USER:
        raise HTTPException(status_code=400, detail=f"At most {MAX_ACTIVE_KEYS_PER_USER} active keys - revoke one first")
    plain = API_KEY_PREFIX + secrets.token_urlsafe(32)
    key = ApiKey(user_id=current_user.id, name=body.name.strip(), prefix=plain[:12], key_hash=hash_api_key(plain),
                 expires_at=now + timedelta(days=body.expires_in_days or 90))
    db.add(key)
    await db.flush()
    await db.refresh(key)
    return {**_out(key), "key": plain}


@router.delete("/{key_id}", response_model=ApiKeyOut, summary="Revoke an API key")
async def revoke_api_key(
    key_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_session_user),
):
    key = (await db.execute(select(ApiKey).where(ApiKey.id == str(key_id)))).scalar_one_or_none()
    if not key or (key.user_id != current_user.id and current_user.role not in ADMIN_ROLES):
        raise HTTPException(status_code=404, detail="API key not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
    return _out(key)
