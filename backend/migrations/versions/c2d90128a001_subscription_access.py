"""Entra subscription access and bounded authorization leases.

Revision ID: c2d90128a001
Revises: 0b009e144f7a
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'c2d90128a001'
down_revision = '0b009e144f7a'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('subscription_scoped', sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column('users', sa.Column('sso_access_expires_at', sa.DateTime(timezone=True)))
    # Existing Microsoft accounts must reauthenticate under the new tenant-bound flow.
    op.execute("UPDATE users SET subscription_scoped = true WHERE sso_provider = 'azure_ad'")
    op.create_table('subscription_access',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('subscription_id', postgresql.UUID(as_uuid=False), sa.ForeignKey('subscriptions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tenant_id', sa.String(36), nullable=False),
        sa.Column('object_id', sa.String(36), nullable=False),
        sa.Column('role', sa.String(16), nullable=False),
        sa.Column('source', sa.String(16), nullable=False),
        sa.Column('granted_by', postgresql.UUID(as_uuid=False), sa.ForeignKey('users.id', ondelete='SET NULL')),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('subscription_id', 'tenant_id', 'object_id', 'source', name='uq_subscription_access_principal'),
        sa.CheckConstraint("role IN ('owner', 'reader') AND source IN ('azure', 'manual')", name='ck_subscription_access_values'))
    op.create_index('ix_subscription_access_principal', 'subscription_access', ['tenant_id', 'object_id'])


def downgrade():
    op.drop_table('subscription_access')
    op.drop_column('users', 'sso_access_expires_at')
    op.drop_column('users', 'subscription_scoped')
