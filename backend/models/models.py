"""
Azure Resource Guardian - Database Models
==========================================
Complete SQLAlchemy ORM models for all entities.

Design decisions:
- UUID primary keys for global uniqueness (multi-tenant safe)
- JSONB columns for flexible metadata without schema migrations
- Soft deletes on sensitive entities (audit trail)
- Composite indexes on high-cardinality query patterns
- Separate tables for cost/findings history (append-only pattern)
"""

import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional

from sqlalchemy import (
    Boolean, Column, Date, DateTime, Enum, Float, ForeignKey,
    Index, Integer, JSON, String, Text, UniqueConstraint,
    func, text
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, relationship


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """All models inherit from this base."""

    # Soft-delete support: deleted_at IS NULL = active record
    #
    # NOTE: no `: Column` type annotation here. Under SQLAlchemy 2.0's
    # Annotated Declarative system, a bare `: Column` annotation is
    # interpreted as a Mapped[]-style type hint and fails to map
    # correctly (Column is not a valid container type for that purpose).
    # Omitting the annotation falls back to legacy-style mapping, which
    # correctly infers the column from the right-hand side assignment.
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SeverityLevel(str, PyEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ScanStatus(str, PyEnum):
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"


class FindingStatus(str, PyEnum):
    OPEN        = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED    = "resolved"
    SUPPRESSED  = "suppressed"
    FALSE_POSITIVE = "false_positive"


class RemediationStatus(str, PyEnum):
    PENDING   = "pending"
    APPROVED  = "approved"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    REJECTED  = "rejected"


class UserRole(str, PyEnum):
    SUPER_ADMIN = "super_admin"
    ADMIN       = "admin"
    ANALYST     = "analyst"
    VIEWER      = "viewer"
    AUDITOR     = "auditor"


class ReportFormat(str, PyEnum):
    PDF   = "pdf"
    CSV   = "csv"
    EXCEL = "excel"
    JSON  = "json"


class DriftStatus(str, PyEnum):
    MANAGED     = "managed"       # In both Terraform state and Azure
    UNMANAGED   = "unmanaged"     # In Azure but NOT in Terraform
    MISSING     = "missing"       # In Terraform state but NOT in Azure
    DRIFTED     = "drifted"       # In both but configuration differs


# ---------------------------------------------------------------------------
# Users & Auth
# ---------------------------------------------------------------------------

class User(Base):
    """
    Platform users with RBAC roles.
    Supports local auth now; SSO metadata fields reserved for future OIDC.
    """
    __tablename__ = "users"

    id            = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    email         = Column(String(255), unique=True, nullable=False, index=True)
    username      = Column(String(100), unique=True, nullable=False, index=True)
    full_name     = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=True)  # NULL for SSO-only accounts
    role          = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active     = Column(Boolean, default=True, nullable=False)
    is_verified   = Column(Boolean, default=False, nullable=False)

    # MFA
    mfa_enabled   = Column(Boolean, default=False, nullable=False)
    mfa_secret    = Column(String(64), nullable=True)

    # SSO (future: Azure AD / OIDC)
    sso_provider  = Column(String(50), nullable=True)   # e.g. "azure_ad"
    sso_subject   = Column(String(255), nullable=True)  # OID / sub claim

    # Activity tracking
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    login_count   = Column(Integer, default=0, nullable=False)

    # Password reset — token is stored hashed (same pattern as refresh
    # tokens elsewhere in this codebase) so a database read alone can't
    # be used to reset an account; expires_at enforces a short window.
    password_reset_token_hash = Column(String(255), nullable=True)
    password_reset_expires_at = Column(DateTime(timezone=True), nullable=True)

    # Soft delete
    deleted_at    = Column(DateTime(timezone=True), nullable=True)

    # Preferences stored as JSON (theme, notification settings, etc.)
    preferences   = Column(JSONB, default=dict, nullable=False)

    # Relationships
    scan_jobs        = relationship("ScanJob", back_populates="triggered_by_user")
    audit_logs       = relationship("AuditLog", back_populates="user")
    remediation_tasks = relationship(
        "RemediationTask",
        back_populates="assigned_to_user",
        foreign_keys="RemediationTask.assigned_to",
    )
    reports          = relationship("Report", back_populates="generated_by_user")

    __table_args__ = (
        Index("ix_users_email_active", "email", postgresql_where=text("deleted_at IS NULL")),
    )


class RefreshToken(Base):
    """
    Stored refresh tokens for JWT rotation.
    Short TTL, indexed for fast lookup + revocation.
    """
    __tablename__ = "refresh_tokens"

    id         = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    user_id    = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)

    user = relationship("User")

    __table_args__ = (
        Index("ix_refresh_tokens_user_active", "user_id",
              postgresql_where=text("revoked_at IS NULL")),
    )


# ---------------------------------------------------------------------------
# Azure Organisation Hierarchy
# ---------------------------------------------------------------------------

class Tenant(Base):
    """
    Azure AD tenant.  One ARG instance can manage resources across
    multiple tenants (e.g., a managed service provider scenario).
    """
    __tablename__ = "tenants"

    id              = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    tenant_id       = Column(String(36), unique=True, nullable=False, index=True)  # Azure tenant GUID
    display_name    = Column(String(255), nullable=False)
    domain          = Column(String(255), nullable=True)   # primary domain e.g. contoso.com

    # Service principal credentials (encrypted at rest)
    client_id       = Column(String(36), nullable=False)
    client_secret_encrypted = Column(Text, nullable=False)  # AES-256 encrypted

    # Scope of access
    management_group_id = Column(String(255), nullable=True)  # root MG if specified
    is_active       = Column(Boolean, default=True, nullable=False)

    # Graph API permissions granted
    graph_permissions_granted = Column(JSONB, default=list, nullable=False)

    # Last successful scan metadata
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    subscriptions   = relationship("Subscription", back_populates="tenant")

    __table_args__ = (
        Index("ix_tenants_active", "is_active"),
    )


class Subscription(Base):
    """
    Azure subscription — the primary billing/governance boundary.
    Belongs to exactly one tenant in our model.
    """
    __tablename__ = "subscriptions"

    id                  = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    subscription_id     = Column(String(36), unique=True, nullable=False, index=True)
    display_name        = Column(String(255), nullable=False)
    tenant_id           = Column(UUID(as_uuid=False), ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False)
    state               = Column(String(20), nullable=False, default="Enabled")  # Enabled/Disabled/Warned
    management_group_id = Column(String(255), nullable=True, index=True)
    offer_type          = Column(String(50), nullable=True)  # EA, MCA, PAYG, etc.

    # Tags on the subscription itself
    tags                = Column(JSONB, default=dict, nullable=False)

    # Budget threshold (USD) for alerting
    monthly_budget_usd  = Column(Float, nullable=True)

    # Governance scores (0-100), recomputed each full scan
    governance_score    = Column(Float, nullable=True)
    security_score      = Column(Float, nullable=True)
    identity_score      = Column(Float, nullable=True)

    is_active           = Column(Boolean, default=True, nullable=False)
    last_scanned_at     = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    #
    # passive_deletes=True on every child relationship below is required
    # because each corresponding FK is declared ondelete="CASCADE" in the
    # database (see the Alembic migration). Without passive_deletes, the
    # ORM ignores that DB-level cascade entirely and instead tries to load
    # every related row into memory and individually set its subscription_id
    # to NULL before deleting the parent — which fails outright with a
    # NotNullViolationError, since these FK columns are NOT NULL by design.
    # This was the actual cause of "DELETE /subscriptions/{id}" returning a
    # 500 for any subscription with real scan history attached.
    tenant              = relationship("Tenant", back_populates="subscriptions")
    resource_inventory  = relationship("ResourceInventory", back_populates="subscription", passive_deletes=True)
    scan_jobs           = relationship("ScanJob", back_populates="subscription", passive_deletes=True)
    findings            = relationship("Finding", back_populates="subscription", passive_deletes=True)
    cost_savings        = relationship("CostSaving", back_populates="subscription", passive_deletes=True)
    score_snapshots     = relationship("ScoreSnapshot", passive_deletes=True)

    __table_args__ = (
        Index("ix_subscriptions_tenant", "tenant_id"),
    )


# ---------------------------------------------------------------------------
# Score Snapshots — daily point-in-time captures for trend charts
# ---------------------------------------------------------------------------

class ScoreSnapshot(Base):
    """
    A daily snapshot of governance/security/identity scores, taken once
    per day by a scheduled Celery task (see workers/scan_worker.py
    snapshot_scores). Governance/security/identity scores themselves are
    always computed live from current open findings (see
    backend/api/routes/governance.py, security.py, identity.py) — this
    table exists purely to retain a historical record for trend charts,
    since the live calculation has no memory of what the score was
    yesterday or last week.

    One row per (subscription_id, snapshot_date) — subscription_id is
    nullable to allow an org-wide aggregate snapshot alongside
    per-subscription ones.
    """
    __tablename__ = "score_snapshots"
    __table_args__ = (
        UniqueConstraint("subscription_id", "snapshot_date", name="uq_score_snapshot_sub_date"),
    )

    id              = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    subscription_id = Column(UUID(as_uuid=False), ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=True, index=True)
    snapshot_date   = Column(Date, nullable=False, index=True)

    governance_score = Column(Integer, nullable=False)
    security_score    = Column(Integer, nullable=False)
    identity_score    = Column(Integer, nullable=True)  # null when identity scanners haven't genuinely run

    total_findings_open = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ScanJob(Base):
    """
    Represents a single scan execution.
    Linked to Celery task for async execution tracking.
    """
    __tablename__ = "scan_jobs"

    id              = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    subscription_id = Column(UUID(as_uuid=False), ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=True)
    triggered_by    = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    celery_task_id  = Column(String(255), nullable=True, index=True)
    status          = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)

    # What to scan — list of scanner names, or ["all"]
    scanners_requested = Column(JSONB, default=list, nullable=False)
    scan_scope         = Column(JSONB, default=dict, nullable=False)  # {tenant_ids, subscription_ids, resource_groups}

    # Timing
    started_at      = Column(DateTime(timezone=True), nullable=True)
    completed_at    = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    # Results summary
    total_resources_scanned = Column(Integer, default=0, nullable=False)
    total_findings          = Column(Integer, default=0, nullable=False)
    findings_by_severity    = Column(JSONB, default=dict, nullable=False)  # {critical:N, high:N, ...}
    error_message           = Column(Text, nullable=True)
    error_details           = Column(JSONB, nullable=True)

    # Configuration snapshot at time of scan
    config_snapshot = Column(JSONB, default=dict, nullable=False)

    # Relationships
    subscription        = relationship("Subscription", back_populates="scan_jobs")
    triggered_by_user   = relationship("User", back_populates="scan_jobs")
    scan_results        = relationship("ScanResult", back_populates="scan_job", passive_deletes=True)

    __table_args__ = (
        Index("ix_scan_jobs_status_created", "status", "created_at"),
        Index("ix_scan_jobs_subscription", "subscription_id"),
    )


class ScanResult(Base):
    """
    Per-scanner result within a scan job.
    Allows tracking individual scanner success/failure independently.
    """
    __tablename__ = "scan_results"

    id              = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    scan_job_id     = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    scanner_name    = Column(String(100), nullable=False)
    scanner_version = Column(String(20), nullable=True)
    category        = Column(String(50), nullable=False)

    status          = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    started_at      = Column(DateTime(timezone=True), nullable=True)
    completed_at    = Column(DateTime(timezone=True), nullable=True)
    duration_ms     = Column(Integer, nullable=True)

    resources_scanned = Column(Integer, default=0)
    findings_count    = Column(Integer, default=0)
    error_message     = Column(Text, nullable=True)
    raw_output        = Column(JSONB, nullable=True)  # scanner-specific metadata

    # Relationships
    scan_job = relationship("ScanJob", back_populates="scan_results")

    __table_args__ = (
        Index("ix_scan_results_job_scanner", "scan_job_id", "scanner_name"),
    )


# ---------------------------------------------------------------------------
# Resource Inventory
# ---------------------------------------------------------------------------

class ResourceInventory(Base):
    """
    Complete snapshot of every Azure resource ARG has discovered.
    Updated on each full scan. History preserved via resource_history table.

    Using azure_resource_id as a stable natural key within subscription scope.
    """
    __tablename__ = "resource_inventory"

    id                  = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    subscription_id     = Column(UUID(as_uuid=False), ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False)

    # Azure native identifiers
    azure_resource_id   = Column(Text, nullable=False)  # /subscriptions/.../resourceGroups/.../...
    resource_name       = Column(String(255), nullable=False)
    resource_type       = Column(String(255), nullable=False, index=True)  # e.g. Microsoft.Compute/virtualMachines
    resource_group      = Column(String(255), nullable=False, index=True)
    location            = Column(String(100), nullable=False, index=True)

    # Metadata
    sku                 = Column(JSONB, nullable=True)
    tags                = Column(JSONB, default=dict, nullable=False)
    properties          = Column(JSONB, default=dict, nullable=False)  # full ARM properties blob

    # Ownership / governance
    owner_tag           = Column(String(255), nullable=True)
    environment_tag     = Column(String(100), nullable=True)
    cost_center_tag     = Column(String(100), nullable=True)

    # Lifecycle
    azure_created_at    = Column(DateTime(timezone=True), nullable=True)
    azure_modified_at   = Column(DateTime(timezone=True), nullable=True)

    # Computed / cached
    is_orphaned         = Column(Boolean, default=False, nullable=False, index=True)
    monthly_cost_usd    = Column(Float, nullable=True)
    last_activity_at    = Column(DateTime(timezone=True), nullable=True)

    # Terraform management
    terraform_managed   = Column(Boolean, nullable=True)  # NULL = unknown
    drift_status        = Column(Enum(DriftStatus), nullable=True, index=True)

    # Scan tracking
    first_seen_scan_id  = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id"), nullable=True)
    last_seen_scan_id   = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id"), nullable=True)
    last_seen_at        = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    subscription    = relationship("Subscription", back_populates="resource_inventory")
    findings        = relationship("Finding", back_populates="resource", passive_deletes=True)
    cost_savings    = relationship("CostSaving", back_populates="resource", passive_deletes=True)
    resource_costs  = relationship("ResourceCost", back_populates="resource", passive_deletes=True)

    __table_args__ = (
        UniqueConstraint("subscription_id", "azure_resource_id", name="uq_resource_subscription"),
        Index("ix_inventory_type_sub", "resource_type", "subscription_id"),
        Index("ix_inventory_rg_sub", "resource_group", "subscription_id"),
        Index("ix_inventory_orphaned", "is_orphaned", postgresql_where=text("is_orphaned = TRUE")),
    )


class ResourceCost(Base):
    """
    Monthly cost data per resource from Azure Cost Management.
    Append-only — one row per resource per billing month.
    """
    __tablename__ = "resource_costs"

    id              = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    resource_id     = Column(UUID(as_uuid=False), ForeignKey("resource_inventory.id", ondelete="CASCADE"), nullable=False)
    billing_month   = Column(String(7), nullable=False)  # YYYY-MM
    cost_usd        = Column(Float, nullable=False)
    currency        = Column(String(3), default="USD", nullable=False)
    service_name    = Column(String(255), nullable=True)
    meter_category  = Column(String(255), nullable=True)
    usage_quantity  = Column(Float, nullable=True)
    usage_unit      = Column(String(100), nullable=True)

    resource = relationship("ResourceInventory", back_populates="resource_costs")

    __table_args__ = (
        UniqueConstraint("resource_id", "billing_month", name="uq_resource_cost_month"),
        Index("ix_resource_costs_month", "billing_month"),
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class Finding(Base):
    """
    Core findings entity. Each scanner produces findings of specific types.

    De-duplication key: (subscription_id, azure_resource_id, finding_type)
    On re-scan, existing OPEN findings are updated; RESOLVED findings
    are re-opened if the issue recurs.
    """
    __tablename__ = "findings"

    id                  = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    subscription_id     = Column(UUID(as_uuid=False), ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False)
    resource_id         = Column(UUID(as_uuid=False), ForeignKey("resource_inventory.id", ondelete="CASCADE"), nullable=True)
    scan_job_id         = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)

    # Classification
    finding_type        = Column(String(100), nullable=False, index=True)
    category            = Column(String(50), nullable=False, index=True)  # compute, network, identity, etc.
    severity            = Column(Enum(SeverityLevel), nullable=False, index=True)
    title               = Column(String(500), nullable=False)
    description         = Column(Text, nullable=False)
    remediation_steps   = Column(Text, nullable=True)

    # Status lifecycle
    status              = Column(Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True)
    first_detected_at   = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_detected_at    = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at         = Column(DateTime(timezone=True), nullable=True)
    suppressed_until    = Column(DateTime(timezone=True), nullable=True)
    suppression_reason  = Column(Text, nullable=True)

    # Financial impact
    estimated_monthly_savings_usd = Column(Float, nullable=True)
    estimated_annual_savings_usd  = Column(Float, nullable=True)

    # Evidence / metadata
    evidence            = Column(JSONB, default=dict, nullable=False)  # scanner-specific data
    affected_resources  = Column(JSONB, default=list, nullable=False)  # secondary affected resource IDs

    # Policy / compliance mappings
    caf_control         = Column(String(100), nullable=True)
    nist_control        = Column(String(100), nullable=True)
    cis_control         = Column(String(100), nullable=True)

    # Runnable remediation scripts generated by the scanner at scan time.
    # Populated by _persist_finding in workers/scan_worker.py and used
    # by the remediation checklist generator to produce real executable
    # commands rather than just documentation comments.
    azure_cli_script    = Column(Text, nullable=True)
    powershell_script   = Column(Text, nullable=True)

    # Relationships
    subscription        = relationship("Subscription", back_populates="findings")
    resource            = relationship("ResourceInventory", back_populates="findings")
    remediation_tasks   = relationship("RemediationTask", back_populates="finding", passive_deletes=True)

    __table_args__ = (
        Index("ix_findings_severity_status", "severity", "status"),
        Index("ix_findings_category_sub", "category", "subscription_id"),
        Index("ix_findings_type_resource", "finding_type", "resource_id"),
    )


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

class Recommendation(Base):
    """
    Actionable recommendations generated by the analysis engine.
    More prescriptive than findings — includes specific scripts and steps.
    """
    __tablename__ = "recommendations"

    id                  = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    finding_id          = Column(UUID(as_uuid=False), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    subscription_id     = Column(UUID(as_uuid=False), ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=True)

    title               = Column(String(500), nullable=False)
    description         = Column(Text, nullable=False)
    priority            = Column(Integer, default=50, nullable=False)  # 1=highest, 100=lowest
    category            = Column(String(50), nullable=False)
    effort              = Column(String(20), nullable=False, default="medium")  # low/medium/high
    risk_level          = Column(String(20), nullable=False, default="low")   # low/medium/high

    # Scripts for different execution environments
    powershell_script   = Column(Text, nullable=True)
    azure_cli_script    = Column(Text, nullable=True)
    terraform_hcl       = Column(Text, nullable=True)
    arm_template        = Column(Text, nullable=True)

    estimated_savings_monthly_usd = Column(Float, nullable=True)

    is_automated        = Column(Boolean, default=False)  # Can ARG execute this automatically?
    requires_approval   = Column(Boolean, default=True)

    finding             = relationship("Finding")


# ---------------------------------------------------------------------------
# Remediation Tasks
# ---------------------------------------------------------------------------

class RemediationTask(Base):
    """
    Tracks the execution lifecycle of a remediation action.
    Supports approval workflows before execution.
    """
    __tablename__ = "remediation_tasks"

    id                  = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    finding_id          = Column(UUID(as_uuid=False), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    assigned_to         = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by         = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    status              = Column(Enum(RemediationStatus), default=RemediationStatus.PENDING, nullable=False, index=True)
    execution_method    = Column(String(50), nullable=False, default="manual")  # manual, powershell, cli, terraform

    notes               = Column(Text, nullable=True)
    approval_notes      = Column(Text, nullable=True)

    approved_at         = Column(DateTime(timezone=True), nullable=True)
    scheduled_at        = Column(DateTime(timezone=True), nullable=True)
    executed_at         = Column(DateTime(timezone=True), nullable=True)
    completed_at        = Column(DateTime(timezone=True), nullable=True)

    execution_log       = Column(Text, nullable=True)
    result              = Column(JSONB, nullable=True)

    # Relationships
    finding             = relationship("Finding", back_populates="remediation_tasks")
    assigned_to_user    = relationship("User", back_populates="remediation_tasks", foreign_keys=[assigned_to])
    approved_by_user    = relationship("User", foreign_keys=[approved_by])


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class Report(Base):
    """
    Generated reports with file storage references.
    Supports multiple formats and report types.
    """
    __tablename__ = "reports"

    id              = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    generated_by    = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    scan_job_id     = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)

    report_type     = Column(String(50), nullable=False)  # executive, technical, compliance, board
    format          = Column(Enum(ReportFormat), nullable=False)
    title           = Column(String(255), nullable=False)
    description     = Column(Text, nullable=True)

    # Storage
    file_path       = Column(Text, nullable=True)   # local path or S3 URI
    file_size_bytes = Column(Integer, nullable=True)
    file_hash       = Column(String(64), nullable=True)  # SHA-256 for integrity

    # Scope
    scope           = Column(JSONB, default=dict, nullable=False)  # which subscriptions/tenants
    date_range_start = Column(DateTime(timezone=True), nullable=True)
    date_range_end   = Column(DateTime(timezone=True), nullable=True)

    # Status
    is_ready        = Column(Boolean, default=False, nullable=False, index=True)
    error_message   = Column(Text, nullable=True)

    # Expiry (auto-delete old reports)
    expires_at      = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    generated_by_user = relationship("User", back_populates="reports")


# ---------------------------------------------------------------------------
# Audit Logs
# ---------------------------------------------------------------------------

class AuditLog(Base):
    """
    Immutable audit trail for all user actions and system events.
    Never deleted — only appended. Partitioned by month in production.
    """
    __tablename__ = "audit_logs"

    id          = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    user_id     = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    action      = Column(String(100), nullable=False, index=True)  # e.g. "scan.start", "finding.suppress"
    resource_type = Column(String(100), nullable=True)  # the ARG entity type, not Azure resource type
    resource_id   = Column(String(255), nullable=True)  # ARG entity ID
    description   = Column(Text, nullable=True)

    # Request context
    ip_address  = Column(String(45), nullable=True)
    user_agent  = Column(String(512), nullable=True)
    request_id  = Column(String(36), nullable=True)

    # Change data (before/after for mutations)
    old_values  = Column(JSONB, nullable=True)
    new_values  = Column(JSONB, nullable=True)

    # Always store outcome
    outcome     = Column(String(20), nullable=False, default="success")  # success / failure
    error       = Column(Text, nullable=True)

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_user_action", "user_id", "action"),
        Index("ix_audit_logs_created_at", "created_at"),
    )


# ---------------------------------------------------------------------------
# Scanner Plugin Registry
# ---------------------------------------------------------------------------

class ScannerPlugin(Base):
    """
    Registry of all scanner plugins — both built-in and community plugins.
    Enables dynamic plugin loading and version management.
    """
    __tablename__ = "scanner_plugins"

    id              = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    plugin_name     = Column(String(100), unique=True, nullable=False, index=True)
    display_name    = Column(String(255), nullable=False)
    description     = Column(Text, nullable=True)
    version         = Column(String(20), nullable=False)
    author          = Column(String(255), nullable=True)
    category        = Column(String(50), nullable=False)
    module_path     = Column(String(500), nullable=False)  # Python import path
    class_name      = Column(String(100), nullable=False)

    is_builtin      = Column(Boolean, default=True, nullable=False)
    is_enabled      = Column(Boolean, default=True, nullable=False, index=True)
    requires_graph  = Column(Boolean, default=False)  # Needs Microsoft Graph API
    requires_cost   = Column(Boolean, default=False)  # Needs Cost Management API

    # Configuration schema (JSON Schema draft-7)
    config_schema   = Column(JSONB, nullable=True)
    default_config  = Column(JSONB, default=dict, nullable=False)

    # Runtime stats
    last_run_at     = Column(DateTime(timezone=True), nullable=True)
    avg_duration_ms = Column(Integer, nullable=True)
    total_runs      = Column(Integer, default=0)
    total_findings  = Column(Integer, default=0)

    __table_args__ = (
        Index("ix_scanner_plugins_category", "category"),
    )


# ---------------------------------------------------------------------------
# Terraform State
# ---------------------------------------------------------------------------

class TerraformState(Base):
    """
    Imported Terraform state files.
    ARG compares these against live Azure inventory to detect drift.
    """
    __tablename__ = "terraform_states"

    id              = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    subscription_id = Column(UUID(as_uuid=False), ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False)

    workspace_name  = Column(String(255), nullable=False)
    state_file_path = Column(Text, nullable=True)       # path or remote backend reference
    backend_type    = Column(String(50), nullable=True)  # local, azurerm, s3, etc.
    backend_config  = Column(JSONB, nullable=True)

    # State content (parsed)
    terraform_version = Column(String(20), nullable=True)
    resource_count    = Column(Integer, default=0)
    resources         = Column(JSONB, default=list, nullable=False)  # parsed resource list

    # Drift summary (updated on each scan)
    drift_summary     = Column(JSONB, default=dict, nullable=False)
    last_drift_check  = Column(DateTime(timezone=True), nullable=True)
    managed_count     = Column(Integer, default=0)
    unmanaged_count   = Column(Integer, default=0)
    missing_count     = Column(Integer, default=0)
    drifted_count     = Column(Integer, default=0)

    imported_at       = Column(DateTime(timezone=True), server_default=func.now())

    subscription = relationship("Subscription")

    __table_args__ = (
        UniqueConstraint("subscription_id", "workspace_name", name="uq_tf_state_workspace"),
    )


# ---------------------------------------------------------------------------
# Entra ID Findings
# ---------------------------------------------------------------------------

class EntraFinding(Base):
    """
    Specialized findings for Microsoft Entra ID (Azure AD) objects.
    Stored separately from resource findings due to different schema needs.
    """
    __tablename__ = "entra_findings"

    id                  = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    tenant_id           = Column(UUID(as_uuid=False), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    scan_job_id         = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)

    # Entra object reference
    object_type         = Column(String(50), nullable=False, index=True)  # user, group, app, sp, mi
    object_id           = Column(String(36), nullable=False, index=True)  # Entra object ID
    object_display_name = Column(String(255), nullable=True)
    object_upn          = Column(String(255), nullable=True)  # userPrincipalName if user

    # Finding details
    finding_type        = Column(String(100), nullable=False, index=True)
    severity            = Column(Enum(SeverityLevel), nullable=False, index=True)
    title               = Column(String(500), nullable=False)
    description         = Column(Text, nullable=False)

    # Status
    status              = Column(Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False)
    first_detected_at   = Column(DateTime(timezone=True), server_default=func.now())
    last_detected_at    = Column(DateTime(timezone=True), server_default=func.now())

    # Evidence from Graph API
    evidence            = Column(JSONB, default=dict, nullable=False)
    last_sign_in_at     = Column(DateTime(timezone=True), nullable=True)

    # Risk score from Identity Protection (if available)
    risk_level          = Column(String(20), nullable=True)

    tenant = relationship("Tenant")

    __table_args__ = (
        Index("ix_entra_findings_tenant_type", "tenant_id", "object_type"),
        Index("ix_entra_findings_severity_status", "severity", "status"),
    )


# ---------------------------------------------------------------------------
# Cost Savings
# ---------------------------------------------------------------------------

class CostSaving(Base):
    """
    Aggregated cost saving opportunities.
    Computed from findings + cost data, presented in the dashboard.
    """
    __tablename__ = "cost_savings"

    id                      = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    subscription_id         = Column(UUID(as_uuid=False), ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False)
    resource_id             = Column(UUID(as_uuid=False), ForeignKey("resource_inventory.id", ondelete="CASCADE"), nullable=True)

    opportunity_type        = Column(String(100), nullable=False, index=True)
    description             = Column(Text, nullable=False)
    resource_type           = Column(String(255), nullable=True)
    resource_name           = Column(String(255), nullable=True)
    resource_group          = Column(String(255), nullable=True)

    current_monthly_cost_usd   = Column(Float, nullable=False, default=0.0)
    estimated_monthly_savings_usd = Column(Float, nullable=False, default=0.0)
    estimated_annual_savings_usd  = Column(Float, nullable=False, default=0.0)
    confidence_score        = Column(Float, nullable=False, default=0.8)  # 0.0-1.0

    action_required         = Column(String(100), nullable=False)  # delete, resize, rightsizing, etc.
    effort                  = Column(String(20), nullable=False, default="low")
    risk                    = Column(String(20), nullable=False, default="low")

    is_actioned             = Column(Boolean, default=False, nullable=False)
    actioned_at             = Column(DateTime(timezone=True), nullable=True)
    actual_savings_usd      = Column(Float, nullable=True)

    # Scan tracking
    first_identified_at     = Column(DateTime(timezone=True), server_default=func.now())
    last_confirmed_at       = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    subscription = relationship("Subscription", back_populates="cost_savings")
    resource     = relationship("ResourceInventory", back_populates="cost_savings")

    __table_args__ = (
        Index("ix_cost_savings_sub_type", "subscription_id", "opportunity_type"),
        Index("ix_cost_savings_amount", "estimated_monthly_savings_usd"),
    )


# ---------------------------------------------------------------------------
# Governance Configuration
# ---------------------------------------------------------------------------

class GovernanceConfig(Base):
    """
    Per-tenant governance configuration: which tags are required and
    which naming-convention patterns apply per resource type. Stored as
    JSONB so admins can add/remove entries without schema changes.

    One row per tenant_id (nullable = org-wide default when null).
    Created on first save; GET returns built-in defaults when no row exists.
    """
    __tablename__ = "governance_configs"

    id          = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    tenant_id   = Column(UUID(as_uuid=False), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, unique=True, index=True)

    # List of lowercase tag key names that must be present on every resource.
    # Default: ["owner", "environment", "cost-center", "application"]
    required_tags = Column(JSONB, default=list, nullable=False)

    # Dict mapping lowercase resource type → regex pattern string.
    # e.g. {"microsoft.compute/virtualmachines": "^vm-[a-z0-9]+-[a-z]+-[a-z]+-\\d{3}$"}
    naming_patterns = Column(JSONB, default=dict, nullable=False)

    tenant = relationship("Tenant")
