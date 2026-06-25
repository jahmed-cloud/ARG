#!/bin/sh
# =============================================================================
# Azure Resource Guardian — Backend entrypoint
# =============================================================================
# Runs on every container start:
#   1. Wait for Postgres to be ready
#   2. Run Alembic migrations (idempotent — safe to run on every start)
#   3. Seed the admin user from .env (idempotent — skips if user exists)
#   4. Start uvicorn
#
# The admin user credentials come from .env:
#   ADMIN_EMAIL, ADMIN_USERNAME, ADMIN_PASSWORD
# If the user already exists, step 3 prints "already exists — skipping"
# and continues immediately. No manual seed command needed.
# =============================================================================

set -e

echo "==> [1/3] Running database migrations..."
alembic upgrade head

echo "==> [2/3] Seeding admin user..."
python -m scripts.seed_admin

echo "==> [3/3] Starting ARG backend..."
exec uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port "${PORT:-8000}" \
    --workers "${UVICORN_WORKERS:-4}"
