"""
Identity API routes — Entra ID hygiene findings.

Important: identity scanner output is persisted to the generic Finding
table (category="identity") via the same _persist_finding() path every
other scanner uses — NOT to the separate EntraFinding table. EntraFinding
exists in the schema but nothing in the scan pipeline writes to it; an
earlier version of this module queried it and would always show stale/
empty data regardless of what scans actually found. Resource-level
fields (resource_name etc.) are joined from ResourceInventory the same
way findings.py does, though identity findings are usually tied to an
Entra object rather than an Azure resource, so that join is often null
here — title/description carry the real detail instead.
"""
import logging
from datetime import datetime
from uuid import UUID
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.dependencies.auth import require_analyst
from backend.api.dependencies.database import get_db
from backend.models.models import Finding, FindingStatus, ScanResult, ScanJob, User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["identity"])

IDENTITY_SCANNER_NAMES = [
    "stale_guest_scanner",
    "dormant_user_scanner",
    "mfa_not_enabled_scanner",
    "permanent_global_admin_scanner",
    "expired_app_credential_scanner",
]


class IdentityStats(BaseModel):
    total_findings: int
    stale_guest_users: int
    dormant_users: int
    mfa_not_enabled: int
    permanent_global_admins: int
    expired_app_credentials: int
    never_used_service_principals: int
    identity_score: int | None
    # True only if at least one identity scanner has genuinely executed
    # against Microsoft Graph (not skipped due to missing permissions).
    # The score is meaningless — and was previously shown as a misleading
    # 100 — when this is False, since "no findings" and "nothing was
    # ever checked" are completely different things.
    graph_scan_completed: bool
    last_identity_scan_at: datetime | None
    coverage_message: str | None


def _was_skipped(scan_result: ScanResult) -> bool:
    msg = (scan_result.error_message or "").lower()
    return "prerequisites not met" in msg or "no client provided" in msg


async def _get_scan_coverage(db: AsyncSession) -> tuple[bool, datetime | None]:
    """
    Check the most recent scan_results row per identity scanner to
    determine whether identity checks have genuinely run with working
    Graph access, as opposed to being skipped every time.
    """
    latest_results = []
    for scanner_name in IDENTITY_SCANNER_NAMES:
        row = await db.execute(
            select(ScanResult, ScanJob.completed_at)
            .join(ScanJob, ScanResult.scan_job_id == ScanJob.id)
            .where(ScanResult.scanner_name == scanner_name)
            .order_by(desc(ScanJob.completed_at))
            .limit(1)
        )
        match = row.first()
        if match:
            latest_results.append(match)

    graph_scan_completed = bool(latest_results) and any(
        not _was_skipped(sr) for sr, _ in latest_results
    )
    last_scan_at = max((ts for _, ts in latest_results if ts), default=None)
    return graph_scan_completed, last_scan_at


@router.get("/stats", response_model=IdentityStats)
async def get_identity_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> IdentityStats:
    """Aggregate Entra ID hygiene statistics for dashboard widget."""
    result = await db.execute(
        select(Finding).where(
            and_(Finding.category == "identity", Finding.status == FindingStatus.OPEN)
        )
    )
    findings = result.scalars().all()

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.finding_type] = counts.get(f.finding_type, 0) + 1

    total = len(findings)
    graph_scan_completed, last_scan_at = await _get_scan_coverage(db)

    if not graph_scan_completed:
        score = None
        coverage_message = (
            "Identity scanners haven't run yet. Start a scan to check this subscription."
            if last_scan_at is None
            else "Identity scanners are configured to skip — Microsoft Graph access isn't "
            "enabled for this tenant. Enable Graph Access in Settings and ensure admin "
            "consent has been granted in Azure AD, then run a new scan."
        )
    else:
        deductions = (
            counts.get("permanent_global_admin", 0) * 15
            + counts.get("mfa_not_enabled", 0) * 5
            + counts.get("expired_app_credential", 0) * 3
            + counts.get("stale_guest_user", 0) * 1
            + counts.get("dormant_user", 0) * 1
        )
        score = max(0, 100 - deductions)
        coverage_message = None

    return IdentityStats(
        total_findings=total,
        stale_guest_users=counts.get("stale_guest_user", 0),
        dormant_users=counts.get("dormant_user", 0),
        mfa_not_enabled=counts.get("mfa_not_enabled", 0),
        permanent_global_admins=counts.get("permanent_global_admin", 0),
        expired_app_credentials=counts.get("expired_app_credential", 0),
        never_used_service_principals=counts.get("never_used_service_principal", 0),
        identity_score=score,
        graph_scan_completed=graph_scan_completed,
        last_identity_scan_at=last_scan_at,
        coverage_message=coverage_message,
    )


@router.get("/findings", response_model=dict)
async def list_identity_findings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
    finding_type: str | None = Query(None),
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> dict:
    """List identity (Entra ID) findings, sourced from the Finding table."""
    filters = [Finding.category == "identity"]
    if finding_type:
        filters.append(Finding.finding_type == finding_type)
    if status:
        filters.append(Finding.status == status)

    q = select(Finding).options(selectinload(Finding.resource)).where(and_(*filters))
    count_q = select(func.count(Finding.id)).where(and_(*filters))

    q = q.order_by(Finding.last_detected_at.desc())
    q = q.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(q)
    findings = result.scalars().all()
    total = (await db.execute(count_q)).scalar_one()

    return {
        "items": [
            {
                "id": str(f.id),
                "finding_type": f.finding_type,
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "status": f.status.value if hasattr(f.status, "value") else f.status,
                "title": f.title,
                "description": f.description,
                # Identity findings are tied to an Entra object, not an Azure
                # resource — evidence (set by the scanner) typically carries
                # the user/app principal name/ID; the resource join below
                # will usually be null and is included only for consistency
                # with other finding list endpoints.
                "display_name": f.resource.resource_name if f.resource else None,
                "evidence": f.evidence or {},
                "first_detected_at": f.first_detected_at,
                "last_detected_at": f.last_detected_at,
            }
            for f in findings
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }
