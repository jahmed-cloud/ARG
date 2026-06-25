"""
Seed the initial super_admin user for Azure Resource Guardian.

Run after migrations have been applied:
  docker compose exec backend python -m scripts.seed_admin

Idempotent: if a user with ADMIN_EMAIL already exists, this script does
nothing rather than erroring or creating a duplicate — safe to re-run
on every container restart if wired into an entrypoint later.

Credentials come from environment variables (ADMIN_EMAIL, ADMIN_USERNAME,
ADMIN_PASSWORD — see .env.example) rather than being hardcoded, so the
default password isn't baked into the image or version control.
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
# Reuse the exact same hashing function the login flow verifies against,
# rather than reimplementing bcrypt hashing here and risking drift.
from backend.api.routes.auth import hash_password


async def seed_admin() -> None:
    settings = get_settings()

    engine = create_async_engine(settings.DATABASE_URL)
    SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with SessionLocal() as db:
        existing = await db.execute(
            select(User).where(User.email == settings.ADMIN_EMAIL)
        )
        if existing.scalar_one_or_none():
            print(f"Admin user '{settings.ADMIN_EMAIL}' already exists — skipping.")
            await engine.dispose()
            return

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
        print("⚠️  Log in and change this password immediately if it was left at the .env default.")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed_admin())
