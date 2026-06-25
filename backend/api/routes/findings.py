"""
Findings API routes.

Findings are the core output of every scanner run. Resource details
(name, type, resource group, location) are NOT stored directly on the
Finding row — they live on the joined ResourceInventory row via
Finding.resource_id. We eager-load that relationship on every query to
avoid N+1 lookups when serializing a page of findings.

Status lifecycle (FindingStatus enum on the model):
  open -> acknowledged -> resolved
  open -> suppressed (sets suppressed_until / suppression_reason)
  open -> false_positive
  resolved -> open (re-opened automatically by the worker if a finding recurs)

Note: the model has no dedicated "acknowledged_at" timestamp or
"acknowledged_by" column — acknowledgement is tracked purely via the
status enum. If per-action audit trail is needed later, that belongs
in the existing AuditLog table rather than new columns here.
"""

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_, or_, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.dependencies.auth import require_analyst
from backend.api.dependencies.database import get_db
from backend.models.models import Finding, ResourceInventory, FindingStatus, Subscription, User
from scanners.base.base_scanner import ORPHAN_FINDING_TYPES

logger = logging.getLogger(__name__)
router = APIRouter(tags=["findings"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class FindingListItem(BaseModel):
    id: str
    finding_type: str
    title: str
    description: str
    severity: str
    status: str
    category: str
    resource_name: str | None
    resource_type: str | None
    azure_resource_id: str | None
    subscription_id: str
    resource_group: str | None
    location: str | None
    estimated_monthly_savings_usd: float | None
    first_detected_at: datetime
    last_detected_at: datetime
    resolved_at: datetime | None


class FindingDetail(FindingListItem):
    remediation_steps: str | None
    evidence: dict
    caf_control: str | None
    nist_control: str | None
    cis_control: str | None
    suppression_reason: str | None
    scan_job_id: str | None


class FindingStatusUpdate(BaseModel):
    status: str  # acknowledged | suppressed | false_positive | open | resolved
    reason: str | None = None  # used as suppression_reason when status == suppressed


class FindingStats(BaseModel):
    total: int
    open: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    acknowledged: int
    resolved: int
    suppressed: int
    false_positive: int
    total_monthly_savings: float


def _serialize(f: Finding) -> dict:
    """Flatten a Finding + its joined ResourceInventory into API shape."""
    resource = f.resource  # may be None for findings not tied to a single resource (e.g. Entra)
    return {
        "id": str(f.id),
        "finding_type": f.finding_type,
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
        "status": f.status.value if hasattr(f.status, "value") else f.status,
        "category": f.category,
        "resource_name": resource.resource_name if resource else None,
        "resource_type": resource.resource_type if resource else None,
        "azure_resource_id": resource.azure_resource_id if resource else None,
        "subscription_id": str(f.subscription_id),
        "resource_group": resource.resource_group if resource else None,
        "location": resource.location if resource else None,
        "estimated_monthly_savings_usd": f.estimated_monthly_savings_usd,
        "first_detected_at": f.first_detected_at,
        "last_detected_at": f.last_detected_at,
        "resolved_at": f.resolved_at,
        "remediation_steps": f.remediation_steps,
        "evidence": f.evidence or {},
        "caf_control": f.caf_control,
        "nist_control": f.nist_control,
        "cis_control": f.cis_control,
        "suppression_reason": f.suppression_reason,
        "scan_job_id": str(f.scan_job_id) if f.scan_job_id else None,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_model=dict)
async def list_findings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
    severity: list[str] | None = Query(None),
    status: list[str] | None = Query(None),
    category: str | None = Query(None),
    subscription_id: UUID | None = Query(None),
    resource_group: str | None = Query(None),
    tenant_id: UUID | None = Query(None, description="ARG internal tenant ID — filters via the finding's subscription"),
    finding_type: str | None = Query(None),
    search: str | None = Query(None, description="Full-text search on title/description"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_desc: bool = Query(True),
) -> dict:
    """List findings with filtering, pagination, and resource details joined in."""
    filters = []
    if severity:
        filters.append(Finding.severity.in_(severity))
    if status:
        filters.append(Finding.status.in_(status))
    if category:
        filters.append(Finding.category == category)
    if subscription_id:
        filters.append(Finding.subscription_id == subscription_id)
    if finding_type:
        filters.append(Finding.finding_type == finding_type)
    if search:
        term = f"%{search}%"
        filters.append(or_(Finding.title.ilike(term), Finding.description.ilike(term)))

    base_query = select(Finding).options(selectinload(Finding.resource))
    count_query = select(func.count(Finding.id))

    # resource_group lives on ResourceInventory, not Finding — both
    # queries need the join, but only when this filter is actually used,
    # to avoid an unnecessary join on every findings list request.
    if resource_group:
        base_query = base_query.join(ResourceInventory, Finding.resource_id == ResourceInventory.id)
        count_query = count_query.join(ResourceInventory, Finding.resource_id == ResourceInventory.id)
        filters.append(ResourceInventory.resource_group == resource_group)

    # tenant_id isn't a column on Finding at all — a finding belongs to
    # a Subscription, which belongs to a Tenant, so filtering "by tenant"
    # means filtering findings whose subscription's tenant_id matches.
    if tenant_id:
        base_query = base_query.join(Subscription, Finding.subscription_id == Subscription.id)
        count_query = count_query.join(Subscription, Finding.subscription_id == Subscription.id)
        filters.append(Subscription.tenant_id == tenant_id)

    if filters:
        base_query = base_query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))

    order_col = Finding.last_detected_at.desc() if sort_desc else Finding.last_detected_at.asc()
    base_query = base_query.order_by(order_col).offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(base_query)
    findings = result.scalars().all()
    total = (await db.execute(count_query)).scalar_one()

    return {
        "items": [_serialize(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/stats", response_model=FindingStats)
async def get_finding_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
    subscription_id: UUID | None = Query(None),
) -> FindingStats:
    """Aggregate finding statistics for dashboard widgets."""
    q = select(Finding)
    if subscription_id:
        q = q.where(Finding.subscription_id == subscription_id)

    result = await db.execute(q)
    all_findings = result.scalars().all()

    def sev(s):
        return sum(1 for f in all_findings if f.severity == s)

    def st(s):
        return sum(1 for f in all_findings if f.status == s)

    total_savings = sum(
        (f.estimated_monthly_savings_usd or 0) for f in all_findings if f.status == FindingStatus.OPEN
    )

    return FindingStats(
        total=len(all_findings),
        open=st(FindingStatus.OPEN),
        critical=sev("critical"),
        high=sev("high"),
        medium=sev("medium"),
        low=sev("low"),
        info=sev("info"),
        acknowledged=st(FindingStatus.ACKNOWLEDGED),
        resolved=st(FindingStatus.RESOLVED),
        suppressed=st(FindingStatus.SUPPRESSED),
        false_positive=st(FindingStatus.FALSE_POSITIVE),
        total_monthly_savings=round(total_savings, 2),
    )


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    result = await db.execute(
        select(Finding).options(selectinload(Finding.resource)).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _serialize(finding)


@router.patch("/{finding_id}/status", response_model=dict)
async def update_finding_status(
    finding_id: UUID,
    body: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """Update finding status. Tracks suppression reason and resolution timestamp."""
    allowed = {"acknowledged", "suppressed", "false_positive", "open", "resolved"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {', '.join(allowed)}")

    result = await db.execute(
        select(Finding).options(selectinload(Finding.resource)).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = FindingStatus(body.status)
    now = datetime.now(timezone.utc)

    if body.status == "resolved":
        finding.resolved_at = now
        # If this was an orphan-class finding, check whether the
        # resource has any other still-open orphan findings before
        # clearing is_orphaned — a resource can be flagged by more than
        # one orphan scanner (e.g. both "unused" and a naming check),
        # and resolving just one of them shouldn't un-flag it.
        if finding.resource and finding.finding_type in ORPHAN_FINDING_TYPES:
            other_open_orphan = await db.execute(
                select(Finding.id).where(
                    Finding.resource_id == finding.resource_id,
                    Finding.id != finding.id,
                    Finding.finding_type.in_(ORPHAN_FINDING_TYPES),
                    Finding.status == FindingStatus.OPEN,
                )
            )
            if not other_open_orphan.scalar_one_or_none():
                finding.resource.is_orphaned = False
    elif body.status == "suppressed":
        finding.suppression_reason = body.reason
    elif body.status == "open":
        finding.resolved_at = None
        finding.suppression_reason = None

    await db.commit()
    await db.refresh(finding, attribute_names=["resource"])
    return _serialize(finding)


@router.post("/bulk-status", response_model=dict)
async def bulk_update_status(
    finding_ids: list[UUID],
    body: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """Bulk update status for multiple findings (e.g. mass-acknowledge low severity)."""
    allowed = {"acknowledged", "suppressed", "false_positive", "open", "resolved"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")
    if len(finding_ids) > 500:
        raise HTTPException(status_code=400, detail="Cannot bulk-update more than 500 findings at once")

    update_data: dict = {"status": FindingStatus(body.status)}
    now = datetime.now(timezone.utc)
    if body.status == "resolved":
        update_data["resolved_at"] = now
    elif body.status == "suppressed":
        update_data["suppression_reason"] = body.reason

    stmt = update(Finding).where(Finding.id.in_(finding_ids)).values(**update_data)
    result = await db.execute(stmt)
    await db.commit()

    logger.info("User %s bulk-updated %d findings to '%s'", current_user.id, result.rowcount, body.status)
    return {"updated": result.rowcount}
