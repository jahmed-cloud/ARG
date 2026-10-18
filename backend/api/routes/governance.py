"""
Governance API routes — tag compliance, naming, CAF alignment, and "what governs this resource?".
"""
import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.database import get_db
from backend.models.models import Finding, FindingStatus, Subscription, Tenant
from backend.services.access import AccessScope, get_access_scope

logger = logging.getLogger(__name__)
router = APIRouter(tags=["governance"])


# Findings from scanners/governance/policy_scanners.py (plus the legacy generic type).
POLICY_FINDING_TYPES = (
    "policy_violation", "no_policy_assignments", "policy_assignments_not_enforced", "policy_exemption_no_expiry",
    "policy_exemption_expired", "policy_exemption_orphaned", "policy_exemption_whole_initiative",
    "policy_remediation_never_run", "policy_definition_mode_skips_containers",
    "allowed_locations_skip_resource_groups", "resource_types_without_policy", "resource_type_denied_by_policy",
)


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
    scope: AccessScope = Depends(get_access_scope),
) -> GovernanceStats:
    """Governance score and violation breakdown."""
    result = await db.execute(
        select(Finding).where(
            and_(Finding.category == "governance", Finding.status == FindingStatus.OPEN,
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
    return GovernanceStats(
        governance_score=score,
        missing_tags=counts.get("missing_required_tags", 0),
        naming_violations=counts.get("naming_convention_violation", 0),
        policy_violations=sum(counts.get(t, 0) for t in POLICY_FINDING_TYPES),
        region_violations=counts.get("region_restriction_violation", 0),
        unlocked_resources=counts.get("missing_resource_lock", 0),
        caf_violations=counts.get("caf_alignment_violation", 0),
    )


RESOURCE_ID = re.compile(r"^/subscriptions/([0-9a-fA-F-]{36})(/[^\s?#]*)?$")


async def lookup_governance(tenant: Tenant, subscription_id: str, resource_id: str) -> dict[str, Any]:
    """Live Azure Policy lookup with the tenant's service principal (read-only Resource Graph queries)."""
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resourcegraph import ResourceGraphClient

    from backend.utils.encryption import decrypt
    from scanners.base.base_scanner import ScanContext
    from scanners.base.policy import what_governs

    credential = ClientSecretCredential(tenant_id=tenant.tenant_id, client_id=tenant.client_id,
                                        client_secret=decrypt(tenant.client_secret_encrypted))
    context = ScanContext(subscription_id=subscription_id, tenant_id=tenant.tenant_id, scan_job_id="what-governs",
                          resource_graph_client=ResourceGraphClient(credential))
    return await what_governs(context, resource_id)


@router.get("/what-governs")
async def get_what_governs(
    resource_id: str = Query(..., min_length=50, max_length=1024,
                             description="Full Azure resource id, resource group id or subscription id"),
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
) -> dict[str, Any]:
    """Which Azure Policy assignments apply to a resource (scope by scope), the exemptions that cover it, and
    its compliance state per policy - the question behind every 'RequestDisallowedByPolicy' error."""
    match = RESOURCE_ID.match(resource_id.strip())
    if not match:
        raise HTTPException(status_code=400, detail="Expected an id starting with /subscriptions/<subscription-id>")
    subscription = (await db.execute(
        select(Subscription).where(func.lower(Subscription.subscription_id) == match.group(1).lower())
    )).scalar_one_or_none()
    if subscription is None:
        raise HTTPException(status_code=404, detail="Not found")
    scope.require(subscription.id)
    tenant = await db.get(Tenant, subscription.tenant_id)
    if tenant is None or not tenant.is_active:
        raise HTTPException(status_code=404, detail="Not found")
    try:
        return await lookup_governance(tenant, subscription.subscription_id, resource_id.strip())
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("what-governs lookup failed for subscription %s: %s", subscription.subscription_id, exc)
        raise HTTPException(status_code=502, detail="Azure Policy data could not be read for this subscription. "
                                                    "The service principal needs Reader on it and on the "
                                                    "management groups above it.")
