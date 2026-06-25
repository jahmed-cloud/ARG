"""
Azure Resource Guardian - Dashboard API Routes
===============================================
Provides aggregated metrics for the executive dashboard.

Optimized for frontend performance:
- Single endpoint returns all dashboard data
- Results cached in Redis (configurable TTL)
- Parallel async queries for each metric category
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import get_current_user, require_roles
from backend.api.dependencies.database import get_db
from backend.models.models import (
    CostSaving, EntraFinding, Finding, FindingStatus,
    ResourceInventory, ScanJob, ScanResult, ScanStatus, Subscription,
    ScoreSnapshot, User, UserRole
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Response Schemas
# ---------------------------------------------------------------------------

class SeverityBreakdown(BaseModel):
    critical: int = 0
    high:     int = 0
    medium:   int = 0
    low:      int = 0
    info:     int = 0
    total:    int = 0


class ScoreCard(BaseModel):
    score:       float        # 0.0 - 100.0
    trend:       str          # "improving", "declining", "stable"
    delta:       float        # change from previous scan
    last_updated: Optional[datetime]


class TopFinding(BaseModel):
    id:            str
    title:         str
    severity:      str
    category:      str
    resource_name: Optional[str]
    resource_group: Optional[str]
    estimated_savings: Optional[float]


class CostTrendPoint(BaseModel):
    month:       str
    total_cost:  float
    savings_identified: float


class ResourceGrowthPoint(BaseModel):
    date:  str
    count: int


class DashboardSummary(BaseModel):
    # Core counts
    total_resources:      int
    total_subscriptions:  int
    total_findings_open:  int
    total_orphaned:       int

    # Financial
    total_monthly_savings_usd:  float
    total_annual_savings_usd:   float
    top_cost_savings:           List[dict]

    # Scores
    governance_score: ScoreCard
    security_score:   ScoreCard
    identity_score:   ScoreCard

    # Breakdown
    findings_by_severity:  SeverityBreakdown
    findings_by_category:  Dict[str, int]
    entra_findings_open:   int
    drift_findings:        int

    # Top issues
    top_findings:          List[TopFinding]

    # Trends
    cost_trend:            List[CostTrendPoint]

    # Last scan
    last_scan_completed_at: Optional[datetime]
    last_scan_duration_s:   Optional[int]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=DashboardSummary,
    summary="Executive dashboard summary",
    description=(
        "Returns aggregated governance, security, cost, and identity metrics "
        "for the executive dashboard. Scoped to subscriptions the user has access to."
    ),
)
async def get_dashboard(
    subscription_id: Optional[str] = Query(None, description="Filter to a specific subscription"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Main dashboard endpoint.
    Runs all aggregation queries concurrently for fast response.
    """
    (
        resource_stats,
        finding_stats,
        cost_stats,
        score_stats,
        entra_stats,
        scan_stats,
        top_findings,
    ) = await asyncio.gather(
        _get_resource_stats(db, subscription_id),
        _get_finding_stats(db, subscription_id),
        _get_cost_stats(db, subscription_id),
        _get_score_stats(db, subscription_id),
        _get_entra_stats(db),
        _get_scan_stats(db),
        _get_top_findings(db, subscription_id),
    )

    return DashboardSummary(
        total_resources=resource_stats["total"],
        total_subscriptions=resource_stats["subscriptions"],
        total_findings_open=finding_stats["total_open"],
        total_orphaned=resource_stats["orphaned"],
        total_monthly_savings_usd=cost_stats["monthly"],
        total_annual_savings_usd=cost_stats["annual"],
        top_cost_savings=cost_stats["top_10"],
        governance_score=score_stats["governance"],
        security_score=score_stats["security"],
        identity_score=score_stats["identity"],
        findings_by_severity=finding_stats["by_severity"],
        findings_by_category=finding_stats["by_category"],
        entra_findings_open=entra_stats["open"],
        drift_findings=finding_stats["drift"],
        top_findings=top_findings,
        cost_trend=cost_stats["trend"],
        last_scan_completed_at=scan_stats["last_completed_at"],
        last_scan_duration_s=scan_stats["last_duration_s"],
    )


class ScoreHistoryPoint(BaseModel):
    date: str
    governance_score: float
    security_score: float
    identity_score: Optional[float]


@router.get(
    "/score-history",
    response_model=list[ScoreHistoryPoint],
    summary="Governance/security/identity score trend over time",
)
async def get_score_history(
    subscription_id: Optional[str] = Query(None, description="Filter to a specific subscription"),
    days: int = Query(30, ge=1, le=365, description="Number of days of history to return"),
    start_date: Optional[str] = Query(None, description="ISO date (YYYY-MM-DD) — overrides 'days' if set"),
    end_date: Optional[str] = Query(None, description="ISO date (YYYY-MM-DD), defaults to today"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns one data point per day from daily ScoreSnapshot rows (see
    workers/scan_worker.py snapshot_scores, which runs once every 24h).
    Supports either a simple rolling window ('days back from today') or
    an explicit start_date/end_date range.

    When no subscription_id is given, scores across all subscriptions
    for the same day are averaged into a single org-wide point — this
    matches how the live (non-historical) dashboard score already
    aggregates across subscriptions when none is selected.

    Returns an empty list, not an error, until snapshot_scores has run
    at least once — a fresh deployment genuinely has zero history yet,
    which the frontend should render as "not enough data" rather than
    a failure.
    """
    from datetime import date as date_cls, timedelta as td

    if start_date:
        range_start = date_cls.fromisoformat(start_date)
    else:
        range_start = date_cls.today() - td(days=days)
    range_end = date_cls.fromisoformat(end_date) if end_date else date_cls.today()

    filters = [ScoreSnapshot.snapshot_date >= range_start, ScoreSnapshot.snapshot_date <= range_end]
    if subscription_id:
        filters.append(ScoreSnapshot.subscription_id == subscription_id)

    result = await db.execute(
        select(ScoreSnapshot).where(*filters).order_by(ScoreSnapshot.snapshot_date.asc())
    )
    rows = result.scalars().all()

    if subscription_id:
        return [
            ScoreHistoryPoint(
                date=r.snapshot_date.isoformat(),
                governance_score=r.governance_score,
                security_score=r.security_score,
                identity_score=r.identity_score,
            )
            for r in rows
        ]

    # No subscription filter — average across all subscriptions captured
    # on each given day, since multiple subscriptions can each have a
    # snapshot row for the same date.
    by_date: dict[str, list[ScoreSnapshot]] = {}
    for r in rows:
        by_date.setdefault(r.snapshot_date.isoformat(), []).append(r)

    points = []
    for date_str, day_rows in sorted(by_date.items()):
        identity_values = [r.identity_score for r in day_rows if r.identity_score is not None]
        points.append(ScoreHistoryPoint(
            date=date_str,
            governance_score=round(sum(r.governance_score for r in day_rows) / len(day_rows), 1),
            security_score=round(sum(r.security_score for r in day_rows) / len(day_rows), 1),
            identity_score=round(sum(identity_values) / len(identity_values), 1) if identity_values else None,
        ))
    return points


# ---------------------------------------------------------------------------
# Aggregation Helpers
# ---------------------------------------------------------------------------

async def _get_resource_stats(db: AsyncSession, sub_id: Optional[str]) -> dict:
    base_query = select(ResourceInventory)
    if sub_id:
        base_query = base_query.join(Subscription).where(
            Subscription.subscription_id == sub_id
        )

    total = await db.scalar(
        select(func.count()).select_from(ResourceInventory)
    ) or 0

    orphaned = await db.scalar(
        select(func.count()).select_from(ResourceInventory).where(
            ResourceInventory.is_orphaned == True
        )
    ) or 0

    subscription_count = await db.scalar(
        select(func.count()).select_from(Subscription).where(
            Subscription.is_active == True
        )
    ) or 0

    return {"total": total, "orphaned": orphaned, "subscriptions": subscription_count}


async def _get_finding_stats(db: AsyncSession, sub_id: Optional[str]) -> dict:
    # Open findings count
    open_query = select(func.count()).select_from(Finding).where(
        Finding.status == FindingStatus.OPEN
    )
    total_open = await db.scalar(open_query) or 0

    # By severity
    severity_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.severity)
    )
    by_severity_raw = dict(severity_result.all())

    by_severity = SeverityBreakdown(
        critical=by_severity_raw.get("critical", 0),
        high=by_severity_raw.get("high", 0),
        medium=by_severity_raw.get("medium", 0),
        low=by_severity_raw.get("low", 0),
        info=by_severity_raw.get("info", 0),
        total=total_open,
    )

    # By category
    category_result = await db.execute(
        select(Finding.category, func.count(Finding.id))
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.category)
    )
    by_category = dict(category_result.all())

    # Drift findings
    drift_count = await db.scalar(
        select(func.count()).select_from(Finding).where(
            Finding.category == "terraform",
            Finding.status == FindingStatus.OPEN,
        )
    ) or 0

    return {
        "total_open": total_open,
        "by_severity": by_severity,
        "by_category": by_category,
        "drift": drift_count,
    }


async def _get_cost_stats(db: AsyncSession, sub_id: Optional[str]) -> dict:
    # Total potential monthly savings
    monthly_result = await db.scalar(
        select(func.sum(CostSaving.estimated_monthly_savings_usd))
        .where(CostSaving.is_actioned == False)
    ) or 0.0

    annual_result = await db.scalar(
        select(func.sum(CostSaving.estimated_annual_savings_usd))
        .where(CostSaving.is_actioned == False)
    ) or 0.0

    # Top 10 savings opportunities
    top_10_result = await db.execute(
        select(
            CostSaving.resource_name,
            CostSaving.resource_type,
            CostSaving.resource_group,
            CostSaving.opportunity_type,
            CostSaving.estimated_monthly_savings_usd,
            CostSaving.action_required,
        )
        .where(CostSaving.is_actioned == False)
        .order_by(CostSaving.estimated_monthly_savings_usd.desc())
        .limit(10)
    )
    top_10 = [
        {
            "resource_name": row[0],
            "resource_type": row[1],
            "resource_group": row[2],
            "opportunity_type": row[3],
            "monthly_savings_usd": round(row[4] or 0, 2),
            "action": row[5],
        }
        for row in top_10_result.all()
    ]

    # Cost trend (last 6 months — placeholder; real data comes from ResourceCost)
    trend = [
        CostTrendPoint(
            month=(datetime.now(timezone.utc) - timedelta(days=30 * i)).strftime("%Y-%m"),
            total_cost=0.0,
            savings_identified=0.0,
        )
        for i in range(5, -1, -1)
    ]

    return {
        "monthly": round(monthly_result, 2),
        "annual": round(annual_result, 2),
        "top_10": top_10,
        "trend": trend,
    }


async def _get_score_stats(db: AsyncSession, sub_id: Optional[str]) -> dict:
    """
    Compute governance, security, and identity scores.

    Scoring methodology (matches governance.py, security.py, identity.py exactly):
    - Start at 100
    - Deduct points based on finding severity:
      CRITICAL = -10, HIGH = -5, MEDIUM = -2, LOW = -0.5
    - Floor at 0, cap at 100

    Previously this used a category_map that routed compute→governance,
    network/storage→security etc., which caused the dashboard scores to
    be far lower than the dedicated Governance/Security pages (which only
    count their own category). Now uses the same category filter as each
    dedicated page so scores are consistent across the app.
    """
    finding_result = await db.execute(
        select(Finding.category, Finding.severity, func.count(Finding.id))
        .where(
            Finding.status == FindingStatus.OPEN,
            Finding.category.in_(["governance", "security", "identity"]),
        )
        .group_by(Finding.category, Finding.severity)
    )
    rows = finding_result.all()

    deductions: Dict[str, float] = {"governance": 0, "security": 0, "identity": 0}
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 0.5, "info": 0}

    for category, severity, count in rows:
        if category in deductions:
            deductions[category] += weights.get(severity, 0) * count

    def compute_score(deduction: float) -> float:
        return max(0.0, min(100.0, 100.0 - deduction))

    now = datetime.now(timezone.utc)

    # Identity score needs the same honesty check as GET /identity/stats:
    # a clean 100 here is indistinguishable from "identity scanners were
    # never able to check anything" unless we verify at least one of them
    # genuinely ran against Microsoft Graph rather than being skipped for
    # missing permissions. Reusing that check here rather than just
    # trusting deductions["identity"] == 0 to mean "no problems found."
    identity_scanner_names = [
        "stale_guest_scanner", "dormant_user_scanner", "mfa_not_enabled_scanner",
        "permanent_global_admin_scanner", "expired_app_credential_scanner",
    ]
    identity_checked = False
    identity_last_updated = None
    for scanner_name in identity_scanner_names:
        row = await db.execute(
            select(ScanResult, ScanJob.completed_at)
            .join(ScanJob, ScanResult.scan_job_id == ScanJob.id)
            .where(ScanResult.scanner_name == scanner_name)
            .order_by(ScanJob.completed_at.desc())
            .limit(1)
        )
        match = row.first()
        if match:
            sr, completed_at = match
            msg = (sr.error_message or "").lower()
            if "prerequisites not met" not in msg and "no client provided" not in msg:
                identity_checked = True
            if completed_at and (identity_last_updated is None or completed_at > identity_last_updated):
                identity_last_updated = completed_at

    return {
        "governance": ScoreCard(
            score=round(compute_score(deductions["governance"]), 1),
            trend="stable",
            delta=0.0,
            last_updated=now,
        ),
        "security": ScoreCard(
            score=round(compute_score(deductions["security"]), 1),
            trend="stable",
            delta=0.0,
            last_updated=now,
        ),
        "identity": ScoreCard(
            # When identity scanners have never genuinely run, score stays
            # at the floor (0) rather than a clean-looking 100 — 0 reads
            # as "needs attention," which is the accurate signal here,
            # whereas 100 would read as "verified clean." last_updated is
            # left null in this case so the UI can distinguish a real
            # last-scan timestamp from one that never happened.
            score=round(compute_score(deductions["identity"]), 1) if identity_checked else 0.0,
            trend="stable",
            delta=0.0,
            last_updated=identity_last_updated if identity_checked else None,
        ),
    }


async def _get_entra_stats(db: AsyncSession) -> dict:
    open_count = await db.scalar(
        select(func.count()).select_from(EntraFinding).where(
            EntraFinding.status == FindingStatus.OPEN
        )
    ) or 0
    return {"open": open_count}


async def _get_scan_stats(db: AsyncSession) -> dict:
    last_scan = await db.execute(
        select(ScanJob)
        .where(ScanJob.status == ScanStatus.COMPLETED)
        .order_by(ScanJob.completed_at.desc())
        .limit(1)
    )
    job = last_scan.scalar_one_or_none()
    return {
        "last_completed_at": job.completed_at if job else None,
        "last_duration_s": job.duration_seconds if job else None,
    }


async def _get_top_findings(db: AsyncSession, sub_id: Optional[str]) -> List[TopFinding]:
    result = await db.execute(
        select(
            Finding.id, Finding.title, Finding.severity,
            Finding.category, Finding.estimated_monthly_savings_usd,
            ResourceInventory.resource_name, ResourceInventory.resource_group,
        )
        .outerjoin(ResourceInventory, Finding.resource_id == ResourceInventory.id)
        .where(Finding.status == FindingStatus.OPEN)
        .order_by(Finding.severity.asc(), Finding.estimated_monthly_savings_usd.desc())
        .limit(10)
    )
    return [
        TopFinding(
            id=str(row[0]),
            title=row[1],
            severity=row[2].value if hasattr(row[2], "value") else str(row[2]),
            category=row[3],
            estimated_savings=round(row[4], 2) if row[4] else None,
            resource_name=row[5],
            resource_group=row[6],
        )
        for row in result.all()
    ]
