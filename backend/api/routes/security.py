"""
Security API routes.
"""
import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.database import get_db
from backend.models.models import Finding, FindingStatus
from backend.services.access import AccessScope, get_access_scope

logger = logging.getLogger(__name__)
router = APIRouter(tags=["security"])


# Tiles count finding types a scanner emits (tests/unit/test_stat_tiles.py); a tile nothing feeds reads as "0 - fine".
PUBLIC_EXPOSURE_TYPES = ("public_storage_account", "public_sql_server", "storage_public_network_access",
                         "key_vault_public_network_open", "ai_services_public_network_open",
                         "nsg_management_port_open_to_internet", "vm_public_ip_bypasses_bastion",
                         "managed_disk_public_network_access")
DATA_PROTECTION_TYPES = ("key_vault_purge_protection_disabled", "key_vault_soft_delete_disabled",
                         "storage_blob_soft_delete_disabled")
UNSUPPORTED_TYPES = ("vm_unsupported_os", "sql_server_end_of_support", "internet_facing_machine_unpatched",
                     "machine_vulnerability_scan_missing")


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
    scope: AccessScope = Depends(get_access_scope),
) -> SecurityStats:
    """Security score and issue breakdown."""
    result = await db.execute(
        select(Finding).where(
            and_(Finding.category == "security", Finding.status == FindingStatus.OPEN,
                 scope.findings())
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
        public_endpoints=sum(counts.get(t, 0) for t in PUBLIC_EXPOSURE_TYPES),
        disabled_defender_plans=counts.get("defender_plan_disabled", 0),
        missing_backups=sum(counts.get(t, 0) for t in DATA_PROTECTION_TYPES),
        expired_certificates=sum(counts.get(t, 0) for t in UNSUPPORTED_TYPES),
        missing_diagnostics=counts.get("missing_diagnostic_settings", 0),
    )
