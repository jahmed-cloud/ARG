"""Analysis settings (amortized cost, display currency, required VM extensions) and each subscription's billing rate.

Revision ID: f3b8d2a6c710
Revises: e7a3c5d1f204
"""
from alembic import op

revision = 'f3b8d2a6c710'
down_revision = 'e7a3c5d1f204'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE governance_configs ADD COLUMN IF NOT EXISTS analysis_settings JSONB NOT NULL DEFAULT '{}'::jsonb")
    op.execute("ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS billing_fx JSONB")


def downgrade():
    op.execute("ALTER TABLE subscriptions DROP COLUMN IF EXISTS billing_fx")
    op.execute("ALTER TABLE governance_configs DROP COLUMN IF EXISTS analysis_settings")
