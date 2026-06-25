"""
Governance API routes — tag compliance, naming, CAF alignment.
"""
import logging
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import require_analyst
from backend.api.dependencies.database import get_db
from backend.models.models import Finding, FindingStatus, User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["governance"])


class GovernanceStats(BaseModel):
    governance_score: int
    missing_tags: int
    naming_violations: int
    policy_violations: int
    region_violations: int
    unlocked_resources: int
    caf_violations: int


@router.get("/stats", response_model=GovernanceStats)
async def get_governance_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> GovernanceStats:
    """Governance score and violation breakdown."""
    result = await db.execute(
        select(Finding).where(
            and_(Finding.category == "governance", Finding.status == FindingStatus.OPEN)
        )
    )
    findings = result.scalars().all()

    counts: dict[str, int] = {}
    deductions = 0.0
    for f in findings:
        counts[f.finding_type] = counts.get(f.finding_type, 0) + 1
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        deduction_map = {"critical": 10, "high": 5, "medium": 2, "low": 0.5}
        deductions += deduction_map.get(sev, 0)

    score = max(0, int(100 - deductions))
    return GovernanceStats(
        governance_score=score,
        missing_tags=counts.get("missing_required_tags", 0),
        naming_violations=counts.get("naming_convention_violation", 0),
        policy_violations=counts.get("policy_violation", 0),
        region_violations=counts.get("region_restriction_violation", 0),
        unlocked_resources=counts.get("missing_resource_lock", 0),
        caf_violations=counts.get("caf_alignment_violation", 0),
    )
