"""
Azure Resource Guardian - Scan Job Routes
=========================================
API endpoints for managing and triggering scan jobs.
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import get_current_user, require_analyst
from backend.api.dependencies.database import get_db
from backend.models.models import ScanJob, ScanResult, ScanStatus, Subscription, User

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ScanScope(BaseModel):
    subscription_ids: List[str] = Field(default_factory=list)
    resource_groups:  List[str] = Field(default_factory=list)
    scanners:         List[str] = Field(default=["all"])


class StartScanRequest(BaseModel):
    scope: ScanScope
    description: Optional[str] = None


class ScanJobResponse(BaseModel):
    id: str
    status: str
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    total_resources_scanned: int
    total_findings: int
    findings_by_severity: dict
    scanners_requested: list
    error_message: Optional[str]


class ScanListResponse(BaseModel):
    items: List[ScanJobResponse]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/start",
    response_model=ScanJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a new scan",
)
async def start_scan(
    body: StartScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Trigger a new scan job.

    The scan runs asynchronously via Celery workers.
    Returns immediately with the scan job ID to poll for status.

    Scopes:
    - subscription_ids: list of Azure subscription IDs to scan
    - resource_groups: optional filter to specific resource groups
    - scanners: ["all"] or specific scanner names
    """
    # Validate subscriptions
    if body.scope.subscription_ids:
        result = await db.execute(
            select(Subscription).where(
                Subscription.subscription_id.in_(body.scope.subscription_ids),
                Subscription.is_active == True,
            )
        )
        valid_subs = result.scalars().all()
        if len(valid_subs) != len(body.scope.subscription_ids):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="One or more subscription IDs not found or not active",
            )

    # Create scan job record
    job = ScanJob(
        triggered_by=current_user.id,
        status=ScanStatus.PENDING,
        scanners_requested=body.scope.scanners,
        scan_scope={
            "subscription_ids": body.scope.subscription_ids,
            "resource_groups": body.scope.resource_groups,
        },
        config_snapshot={
            "triggered_by": current_user.username,
            "description": body.description,
        },
    )
    db.add(job)
    await db.flush()  # Get the ID before commit

    # Dispatch to Celery worker.
    #
    # IMPORTANT: only ImportError should ever trigger the inline fallback
    # below — that's reserved for environments where Celery genuinely
    # isn't installed (e.g. a minimal test environment). Any other
    # exception here (Redis unreachable, serialization failure, etc.)
    # must propagate, not be swallowed — a silently-swallowed dispatch
    # failure previously left jobs stuck in PENDING forever with
    # celery_task_id never set and no error recorded anywhere, because
    # the inline fallback (_run_scan_inline) was an unimplemented stub.
    try:
        from workers.scan_worker import run_scan_job
    except ImportError as exc:
        logger.error(f"Celery worker module unavailable, cannot dispatch scan: {exc}")
        job.status = ScanStatus.FAILED
        job.error_message = (
            "Scan dispatch failed: worker module not available in this environment."
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan worker is not available. Contact your administrator.",
        )

    try:
        celery_task = run_scan_job.delay(
            job_id=job.id,
            subscription_ids=body.scope.subscription_ids,
            scanners=body.scope.scanners,
        )
        job.celery_task_id = celery_task.id
    except Exception as exc:
        # Broker unreachable, serialization error, etc. — fail loudly and
        # record why, rather than leaving the job stuck in PENDING with
        # no explanation.
        logger.error(f"Failed to dispatch scan job {job.id} to Celery: {exc}")
        job.status = ScanStatus.FAILED
        job.error_message = f"Failed to queue scan: {exc}"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to queue scan job. Check that the task queue is reachable.",
        )

    await db.commit()

    return ScanJobResponse(
        id=job.id,
        status=job.status.value,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        duration_seconds=job.duration_seconds,
        total_resources_scanned=job.total_resources_scanned,
        total_findings=job.total_findings,
        findings_by_severity=job.findings_by_severity,
        scanners_requested=job.scanners_requested,
        error_message=job.error_message,
    )


@router.get("", response_model=ScanListResponse, summary="List scan jobs")
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List scan jobs with pagination."""
    query = select(ScanJob).order_by(ScanJob.created_at.desc())

    if status_filter:
        try:
            status_enum = ScanStatus(status_filter)
            query = query.where(ScanJob.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")

    total = await db.scalar(select(func.count()).select_from(ScanJob))
    jobs = await db.execute(query.offset((page - 1) * page_size).limit(page_size))

    return ScanListResponse(
        items=[
            ScanJobResponse(
                id=j.id,
                status=j.status.value,
                created_at=j.created_at,
                started_at=j.started_at,
                completed_at=j.completed_at,
                duration_seconds=j.duration_seconds,
                total_resources_scanned=j.total_resources_scanned,
                total_findings=j.total_findings,
                findings_by_severity=j.findings_by_severity,
                scanners_requested=j.scanners_requested,
                error_message=j.error_message,
            )
            for j in jobs.scalars().all()
        ],
        total=total or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}", response_model=ScanJobResponse, summary="Get scan job details")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get details of a specific scan job."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    return ScanJobResponse(
        id=job.id,
        status=job.status.value,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        duration_seconds=job.duration_seconds,
        total_resources_scanned=job.total_resources_scanned,
        total_findings=job.total_findings,
        findings_by_severity=job.findings_by_severity,
        scanners_requested=job.scanners_requested,
        error_message=job.error_message,
    )


@router.post("/{scan_id}/cancel", summary="Cancel a running scan")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Cancel a pending or running scan job."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan in status: {job.status.value}")

    if job.celery_task_id:
        try:
            from workers.scan_worker import celery_app
            celery_app.control.revoke(job.celery_task_id, terminate=True)
        except Exception as exc:
            logger.warning(f"Failed to revoke Celery task {job.celery_task_id} for scan {scan_id}: {exc}")

    job.status = ScanStatus.CANCELLED
    await db.commit()
    return {"message": "Scan cancelled"}
