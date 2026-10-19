"""Estate snapshots: the cross-subscription inventory behind the admin Estate page.

Revision ID: f3b8d2a6c917
Revises: e7a3c5d1f204
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'f3b8d2a6c917'
down_revision = 'e7a3c5d1f204'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'estate_snapshots',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('triggered_by', sa.String(100), nullable=False),
        sa.Column('requested_by', postgresql.UUID(as_uuid=False), sa.ForeignKey('users.id', ondelete='SET NULL'),
                  nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('subscriptions_count', sa.Integer(), nullable=True),
        sa.Column('resources_count', sa.Integer(), nullable=True),
        sa.Column('suggestions_count', sa.Integer(), nullable=True),
        sa.Column('data', postgresql.JSONB(), nullable=True),
        sa.Column('overview_markdown', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_estate_snapshots_status_started', 'estate_snapshots', ['status', 'started_at'])
    op.create_index('uq_estate_snapshots_one_running', 'estate_snapshots', ['status'], unique=True,
                    postgresql_where=sa.text("status = 'running'"))


def downgrade():
    op.drop_index('uq_estate_snapshots_one_running', table_name='estate_snapshots')
    op.drop_index('ix_estate_snapshots_status_started', table_name='estate_snapshots')
    op.drop_table('estate_snapshots')
