"""Subscription-scoped access: reader grants for local accounts, Entra-managed users.

Revision ID: d4e1a7c3b902
Revises: c2d90128a001
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'd4e1a7c3b902'
down_revision = 'c2d90128a001'
branch_labels = None
depends_on = None


def upgrade():
    # Users created from Microsoft sign-in: their role follows Entra group membership at every sign-in.
    op.add_column('users', sa.Column('entra_managed', sa.Boolean(), server_default=sa.false(), nullable=False))

    # A grant targets either an Entra principal (tenant_id + object_id) or a local ARG account (user_id).
    op.add_column('subscription_access', sa.Column(
        'user_id', postgresql.UUID(as_uuid=False), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=True))
    op.add_column('subscription_access', sa.Column('principal_name', sa.String(255), nullable=True))
    op.alter_column('subscription_access', 'tenant_id', existing_type=sa.String(36), nullable=True)
    op.alter_column('subscription_access', 'object_id', existing_type=sa.String(36), nullable=True)
    op.create_check_constraint(
        'ck_subscription_access_principal', 'subscription_access',
        '(user_id IS NOT NULL) OR (tenant_id IS NOT NULL AND object_id IS NOT NULL)')
    op.create_unique_constraint(
        'uq_subscription_access_user', 'subscription_access', ['subscription_id', 'user_id', 'source'])
    op.create_index('ix_subscription_access_user', 'subscription_access', ['user_id'])


def downgrade():
    op.drop_index('ix_subscription_access_user', table_name='subscription_access')
    op.drop_constraint('uq_subscription_access_user', 'subscription_access', type_='unique')
    op.drop_constraint('ck_subscription_access_principal', 'subscription_access', type_='check')
    op.execute('DELETE FROM subscription_access WHERE object_id IS NULL OR tenant_id IS NULL')
    op.alter_column('subscription_access', 'object_id', existing_type=sa.String(36), nullable=False)
    op.alter_column('subscription_access', 'tenant_id', existing_type=sa.String(36), nullable=False)
    op.drop_column('subscription_access', 'principal_name')
    op.drop_column('subscription_access', 'user_id')
    op.drop_column('users', 'entra_managed')
