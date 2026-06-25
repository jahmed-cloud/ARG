"""
Azure Resource Guardian - User Management Routes
=================================================
Admin-only CRUD for platform users (RBAC roles, activation, password
reset by an admin). Distinct from backend/api/routes/auth.py, which
covers self-service login, password change (current user, requires
current password), and the forgot/reset-password email flow.
"""
import logging
import secrets
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import get_current_user, require_admin
from backend.api.dependencies.database import get_db
from backend.api.routes.auth import hash_password
from backend.models.models import User, UserRole

logger = logging.getLogger(__name__)
router = APIRouter(tags=["users"])


class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    full_name: str | None = None
    role: UserRole = UserRole.VIEWER
    # If omitted, a random temporary password is generated and returned
    # once in the response — the admin is expected to relay it to the
    # new user (or have them use "Forgot password?" immediately).
    password: str | None = Field(None, min_length=12)


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: str | None
    role: str
    is_active: bool
    mfa_enabled: bool
    sso_provider: str | None
    last_login_at: datetime | None
    login_count: int
    created_at: datetime

    class Config:
        from_attributes = True


def _serialize(u: User) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "username": u.username,
        "full_name": u.full_name,
        "role": u.role.value,
        "is_active": u.is_active,
        "mfa_enabled": u.mfa_enabled,
        "sso_provider": u.sso_provider,
        "last_login_at": u.last_login_at,
        "login_count": u.login_count,
        "created_at": u.created_at,
    }


@router.get("", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> list[dict]:
    """List all platform users. Admin only."""
    result = await db.execute(
        select(User).where(User.deleted_at.is_(None)).order_by(User.created_at.desc())
    )
    return [_serialize(u) for u in result.scalars().all()]


@router.post("", response_model=dict, status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    """
    Create a new platform user. Admin only.

    Only an existing admin can grant access — there is no public
    self-registration, deliberately, since this is an internal tool
    scanning Azure subscriptions with real credentials.
    """
    existing = await db.execute(
        select(User).where((User.email == body.email) | (User.username == body.username))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A user with that email or username already exists")

    # Only a super_admin can create another super_admin — an ordinary
    # admin shouldn't be able to grant themselves (or anyone) the
    # highest privilege tier.
    if body.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(status_code=403, detail="Only a super admin can create another super admin")

    generated_password = None
    if body.password:
        password_to_hash = body.password
    else:
        generated_password = secrets.token_urlsafe(16)
        password_to_hash = generated_password

    user = User(
        email=body.email,
        username=body.username,
        full_name=body.full_name,
        hashed_password=hash_password(password_to_hash),
        role=body.role,
        is_active=True,
        is_verified=True,  # admin-created accounts are pre-verified
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    response = _serialize(user)
    if generated_password:
        # Returned exactly once — never retrievable again after this
        # response. The admin must relay it to the user or have them
        # use "Forgot password?" to set their own.
        response["generated_password"] = generated_password
    return response


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    """Update a user's role, name, or active status. Admin only."""
    user = await db.get(User, str(user_id))
    if not user or user.deleted_at is not None:
        raise HTTPException(status_code=404, detail="User not found")

    if body.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(status_code=403, detail="Only a super admin can grant the super admin role")

    # Prevent an admin from locking themselves out by deactivating or
    # demoting their own only-remaining super_admin account.
    if user.id == current_user.id and body.is_active is False:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")

    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active

    await db.commit()
    await db.refresh(user)
    return _serialize(user)


@router.post("/{user_id}/reset-password", response_model=dict)
async def admin_reset_password(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    """
    Admin-triggered password reset: generates a new random password and
    returns it once. Distinct from the self-service /auth/forgot-password
    flow — useful when a user is locked out and email delivery isn't
    configured (SMTP not set up) or isn't reachable.
    """
    user = await db.get(User, str(user_id))
    if not user or user.deleted_at is not None:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.hashed_password and user.sso_provider:
        raise HTTPException(status_code=400, detail="This is an SSO-only account and has no local password to reset")

    new_password = secrets.token_urlsafe(16)
    user.hashed_password = hash_password(new_password)
    user.password_reset_token_hash = None
    user.password_reset_expires_at = None
    await db.commit()

    logger.info(f"Admin {current_user.username} reset password for user {user.username}")
    return {"username": user.username, "temporary_password": new_password}


@router.delete("/{user_id}", status_code=204)
async def deactivate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Soft-deletes a user (sets deleted_at) — matches the existing
    soft-delete pattern already present on the User model. Does not
    hard-delete, preserving audit log / scan-trigger history that
    references this user's id.
    """
    if str(user_id) == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    user = await db.get(User, str(user_id))
    if not user or user.deleted_at is not None:
        raise HTTPException(status_code=404, detail="User not found")

    user.deleted_at = datetime.now(timezone.utc)
    user.is_active = False
    await db.commit()
