"""
Costs API routes.

Cost data comes from two sources:
  - Spend: the amortized Cost Management cost of the last 30 days per subscription, collected by the estate refresh
    (EstateSnapshot.data["cost_30d"], backend/services/estate.py recorded_costs).
  - Finding (with estimated_monthly_savings_usd set): savings opportunities
    identified by scanners. Resource name/type come from the joined
    ResourceInventory row, not the Finding row itself.

The dedicated CostSaving table (aggregated, scanner-independent saving
opportunities) exists in the schema but isn't populated by the MVP scanners
yet — Finding rows with estimated_monthly_savings_usd > 0 are the current
source of truth for "top savings" until a dedicated cost-aggregation job
is added.
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.dependencies.database import get_db
from backend.api.routes.findings import finding_implementation
from backend.models.models import Finding, FindingStatus, Subscription
from scripts.subscription_analysis.guidance import cost_summary
from backend.services.access import AccessScope, get_access_scope

logger = logging.getLogger(__name__)
router = APIRouter(tags=["costs"])

# Structural suggestions (a region move is a migration): listed with their saving, but kept out of the potential
# savings total - the same rule as the local reports' wave 3.
STRUCTURAL_FINDING_TYPES = {"cheaper_region_available"}


class CostSummary(BaseModel):
    total_monthly_cost: float
    total_annual_cost: float
    potential_monthly_savings: float
    potential_annual_savings: float
    structural_monthly_savings: float = 0.0  # e.g. cheaper regions; not in potential_monthly_savings
    currency: str = "USD"
    top_savings: list[dict]


@router.get("/summary", response_model=CostSummary)
async def get_cost_summary(
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
    subscription_id: UUID | None = Query(None),
) -> CostSummary:
    """Aggregate cost summary + top 10 savings opportunities."""
    from backend.services.estate import recorded_costs

    # Spend: amortized Cost Management cost of the last 30 days per visible subscription, from the newest estate
    # refresh (USD; the UI shows it in the chosen currency)
    totals, _ = await recorded_costs(db, scope.where(Subscription.id), str(subscription_id) if subscription_id else None)
    total_monthly = sum(float(t.get("cost_usd") or 0) for t in totals.values())

    # Savings opportunities: open findings with a positive estimated saving
    savings_query = (
        select(Finding)
        .options(selectinload(Finding.resource))
        .where(
            and_(
                Finding.status == FindingStatus.OPEN,
                Finding.estimated_monthly_savings_usd.isnot(None),
                Finding.estimated_monthly_savings_usd > 0,
                scope.findings(),
            )
        )
    )
    if subscription_id:
        savings_query = savings_query.where(Finding.subscription_id == subscription_id)

    savings_result = await db.execute(savings_query)
    saving_findings = savings_result.scalars().all()

    total_savings = sum(f.estimated_monthly_savings_usd or 0 for f in saving_findings
                        if f.finding_type not in STRUCTURAL_FINDING_TYPES)
    structural_savings = sum(f.estimated_monthly_savings_usd or 0 for f in saving_findings
                             if f.finding_type in STRUCTURAL_FINDING_TYPES)

    top = sorted(
        saving_findings,
        key=lambda f: f.estimated_monthly_savings_usd or 0,
        reverse=True,
    )[:25]

    def implementation(f: Finding) -> dict:
        impl = finding_implementation(f)
        return {"why": impl.get("why"), "cost_to_implement": cost_summary(impl),
                "implementation_monthly_usd": impl.get("monthly_usd"),
                "net_monthly_usd": impl.get("net_monthly_usd"), "hours": impl.get("hours"),
                "saving_basis": (f.evidence or {}).get("saving_basis")}

    return CostSummary(
        total_monthly_cost=round(total_monthly, 2),
        total_annual_cost=round(total_monthly * 12, 2),
        potential_monthly_savings=round(total_savings, 2),
        potential_annual_savings=round(total_savings * 12, 2),
        structural_monthly_savings=round(structural_savings, 2),
        top_savings=[
            {
                "id": str(f.id),
                "title": f.title,
                "finding_type": f.finding_type,
                "structural": f.finding_type in STRUCTURAL_FINDING_TYPES,
                "resource_name": f.resource.resource_name if f.resource else None,
                "resource_type": f.resource.resource_type if f.resource else None,
                "monthly_saving": round(f.estimated_monthly_savings_usd or 0, 2),
                "annual_saving": round((f.estimated_monthly_savings_usd or 0) * 12, 2),
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "remediation_steps": f.remediation_steps,
                **implementation(f),
            }
            for f in top
        ],
    )
