"""analysis reports: the 5-part subscription analysis written after each scan

Revision ID: b5d2e8f1c3a7
Revises: a7c41e9d2b58
Create Date: 2026-10-06
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = 'b5d2e8f1c3a7'
down_revision = 'a7c41e9d2b58'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'analysis_reports',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('subscription_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('subscriptions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('scan_job_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('scan_jobs.id', ondelete='SET NULL'), nullable=True),
        sa.Column('status', sa.String(20), nullable=False, server_default='completed'),
        sa.Column('generated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('findings_count', sa.Integer(), nullable=True),
        sa.Column('summary', postgresql.JSONB(), nullable=True),
        sa.Column('thinking', postgresql.JSONB(), nullable=True),
        sa.Column('files', postgresql.JSONB(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_analysis_reports_subscription_generated', 'analysis_reports',
                    ['subscription_id', 'generated_at'])


def downgrade() -> None:
    op.drop_index('ix_analysis_reports_subscription_generated', table_name='analysis_reports')
    op.drop_table('analysis_reports')
