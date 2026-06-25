"""
Alembic migration environment for Azure Resource Guardian.

Wired to:
  - backend.models.models.Base.metadata for autogenerate support
  - backend.core.config.Settings.DATABASE_URL_SYNC for the connection URL,
    so migrations always run against whatever DATABASE_URL is configured
    via environment variables / .env — no separate hardcoded URL to keep
    in sync with the application config.

Run migrations with:
  alembic upgrade head        # apply all pending migrations
  alembic revision --autogenerate -m "description"   # generate a new one
"""

import sys
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# Make the project root importable so `backend.*` resolves the same way
# it does when the app itself runs (this file lives in backend/migrations/).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.core.config import get_settings
from backend.models.models import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Our models' metadata — enables `alembic revision --autogenerate`
target_metadata = Base.metadata

# Override the alembic.ini placeholder URL with the real configured one.
# Alembic itself runs synchronously, so we use the sync (psycopg2) variant
# of DATABASE_URL rather than the asyncpg one the FastAPI app uses.
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL_SYNC)


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode — emits SQL to stdout without a live
    DB connection. Useful for generating a SQL script to review/apply
    manually: `alembic upgrade head --sql > migration.sql`
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,        # detect column type changes in autogenerate
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
