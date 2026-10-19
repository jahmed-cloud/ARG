"""Governance config: analysis settings (optional checks, blocked resource providers, hourly rate).

Revision ID: a7c41e9d2b58
Revises: f3b8d2a6c917
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'a7c41e9d2b58'
down_revision = 'f3b8d2a6c917'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('governance_configs',
                  sa.Column('scanner_settings', postgresql.JSONB(), nullable=False, server_default='{}'))


def downgrade():
    op.drop_column('governance_configs', 'scanner_settings')
