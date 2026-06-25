"""
Security API routes.
"""
import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import require_analyst
from backend.api.dependencies.database import get_db
from backend.models.models import Finding, FindingStatus, User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["security"])


class SecurityStats(BaseModel):
    security_score: int
    public_endpoints: int
    disabled_defender_plans: int
    missing_backups: int
    expired_certificates: int
    missing_diagnostics: int


@router.get("/stats", response_model=SecurityStats)
async def get_security_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> SecurityStats:
    """Security score and issue breakdown."""
    result = await db.execute(
        select(Finding).where(
            and_(Finding.category == "security", Finding.status == FindingStatus.OPEN)
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
    return SecurityStats(
        security_score=score,
        public_endpoints=counts.get("public_endpoint_exposed", 0) + counts.get("public_storage_account", 0) + counts.get("public_sql_server", 0),
        disabled_defender_plans=counts.get("defender_plan_disabled", 0),
        missing_backups=counts.get("missing_backup_configuration", 0),
        expired_certificates=counts.get("expired_certificate", 0),
        missing_diagnostics=counts.get("missing_diagnostic_settings", 0),
    )
