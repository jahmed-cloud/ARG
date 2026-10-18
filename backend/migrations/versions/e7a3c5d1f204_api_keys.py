"""Personal API keys for CI/CD and scripts.

Revision ID: e7a3c5d1f204
Revises: d4e1a7c3b902
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'e7a3c5d1f204'
down_revision = 'd4e1a7c3b902'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=False), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('prefix', sa.String(16), nullable=False),
        sa.Column('key_hash', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'], unique=True)
    op.create_index('ix_api_keys_user_active', 'api_keys', ['user_id'], postgresql_where=sa.text('revoked_at IS NULL'))


def downgrade():
    op.drop_index('ix_api_keys_user_active', table_name='api_keys')
    op.drop_index('ix_api_keys_key_hash', table_name='api_keys')
    op.drop_table('api_keys')
