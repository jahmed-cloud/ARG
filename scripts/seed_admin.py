"""
Seed (or restore) the local super_admin of ARG.

Called automatically on every container start by docker/entrypoint.sh.
Safe to run repeatedly - idempotent:
  - If no admin exists: creates one from ADMIN_EMAIL/USERNAME/PASSWORD in .env
  - If the admin exists: restores it to exactly what .env says - active, not deleted, super_admin, not managed
    by Entra groups, ADMIN_USERNAME and ADMIN_PASSWORD. Microsoft sign-in (even one linked to the same email),
    Settings or another admin can therefore never lock the local admin out for longer than a restart; the users
    API also refuses to disable, delete or demote it.

This means your .env is always the source of truth for the local admin.
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from backend.core.config import get_settings
from backend.models.models import User, UserRole
from backend.api.routes.auth import hash_password, verify_password


def enforce_local_admin(user, username: str, password: str, username_taken: bool = False) -> list:
    """Restore the local admin in place; returns what changed (empty list = already as configured)."""
    changes = []
    if not user.hashed_password or not verify_password(password, user.hashed_password):
        user.hashed_password = hash_password(password)
        changes.append("password")
    if user.role != UserRole.SUPER_ADMIN:
        user.role = UserRole.SUPER_ADMIN
        changes.append("role")
    if not user.is_active:
        user.is_active = True
        changes.append("re-enabled")
    if getattr(user, "deleted_at", None) is not None:
        user.deleted_at = None
        changes.append("undeleted")
    if getattr(user, "entra_managed", False):
        user.entra_managed = False  # its role never follows Entra groups
        changes.append("not Entra-managed")
    if getattr(user, "subscription_scoped", False):
        user.subscription_scoped = False
        changes.append("unscoped")
    if user.username != username and not username_taken:
        user.username = username
        changes.append("username")
    return changes


async def seed_admin() -> None:
    settings = get_settings()
    password = settings.ADMIN_PASSWORD.get_secret_value()

    engine = create_async_engine(settings.DATABASE_URL)
    SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with SessionLocal() as db:
        result = await db.execute(
            select(User).where(User.email == settings.ADMIN_EMAIL)
        )
        existing = result.scalar_one_or_none()

        if existing:
            taken = (await db.execute(select(User.id).where(
                User.username == settings.ADMIN_USERNAME, User.id != existing.id))).first() is not None
            changes = enforce_local_admin(existing, settings.ADMIN_USERNAME, password, username_taken=taken)
            if changes:
                await db.commit()
                print(f"Restored local admin '{settings.ADMIN_EMAIL}' from .env: {', '.join(changes)}")
            else:
                print(f"Local admin '{settings.ADMIN_EMAIL}' matches .env - no changes.")
        else:
            admin = User(
                email=settings.ADMIN_EMAIL,
                username=settings.ADMIN_USERNAME,
                full_name="ARG Administrator",
                hashed_password=hash_password(password),
                role=UserRole.SUPER_ADMIN,
                is_active=True,
                is_verified=True,
            )
            db.add(admin)
            await db.commit()
            print(f"Created super_admin user: {settings.ADMIN_EMAIL} (username: {settings.ADMIN_USERNAME})")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed_admin())
