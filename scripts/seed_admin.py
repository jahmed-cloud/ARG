"""
Seed (or update) the super_admin user for Azure Resource Guardian.

Called automatically on every container start by docker/entrypoint.sh.
Safe to run repeatedly — idempotent:
  - If no admin exists: creates one from ADMIN_EMAIL/USERNAME/PASSWORD in .env
  - If admin already exists: updates the password from .env so changing
    ADMIN_PASSWORD and restarting the container always takes effect.

This means your .env is always the source of truth for the admin password.
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
from backend.api.routes.auth import hash_password


async def seed_admin() -> None:
    settings = get_settings()

    engine = create_async_engine(settings.DATABASE_URL)
    SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with SessionLocal() as db:
        result = await db.execute(
            select(User).where(User.email == settings.ADMIN_EMAIL)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Always sync password from .env — so changing ADMIN_PASSWORD
            # and restarting the container takes effect immediately without
            # needing to manually reset the password in the database.
            new_hash = hash_password(settings.ADMIN_PASSWORD.get_secret_value())
            if existing.hashed_password != new_hash:
                existing.hashed_password = new_hash
                await db.commit()
                print(f"Updated admin password for '{settings.ADMIN_EMAIL}' from .env")
            else:
                print(f"Admin user '{settings.ADMIN_EMAIL}' already exists — no changes.")
        else:
            admin = User(
                email=settings.ADMIN_EMAIL,
                username=settings.ADMIN_USERNAME,
                full_name="ARG Administrator",
                hashed_password=hash_password(settings.ADMIN_PASSWORD.get_secret_value()),
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
