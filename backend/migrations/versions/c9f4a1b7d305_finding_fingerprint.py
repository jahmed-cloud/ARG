"""finding fingerprint: one row per issue and object, whatever casing Azure returned the resource ID in

Revision ID: c9f4a1b7d305
Revises: b5d2e8f1c3a7
Create Date: 2026-11-11

Adds findings.fingerprint (scanners/base/fingerprint.py) and fills it for findings on an Azure resource:
sha256("resource|<resource id, lower case>|<finding type>"). Findings without a resource (Entra ID objects) stay
NULL; the worker stamps them on the next scan. The index is not unique on purpose: older databases can hold
case-variant duplicates, which the worker merges as it meets them.
"""
from alembic import op

revision = 'c9f4a1b7d305'
down_revision = 'b5d2e8f1c3a7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64)")
    op.execute("""
        UPDATE findings f
           SET fingerprint = encode(sha256(convert_to(
                   'resource|' || lower(rtrim(btrim(r.azure_resource_id), '/')) || '|' || f.finding_type, 'UTF8')), 'hex')
          FROM resource_inventory r
         WHERE f.resource_id = r.id AND f.fingerprint IS NULL
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings (fingerprint)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_resource_inventory_lower_id "
               "ON resource_inventory (subscription_id, lower(azure_resource_id))")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_resource_inventory_lower_id")
    op.execute("DROP INDEX IF EXISTS ix_findings_fingerprint")
    op.drop_column('findings', 'fingerprint')
