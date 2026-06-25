"""
Costs API routes.

Cost data comes from two tables populated independently:
  - ResourceCost: actual monthly spend per resource, synced from Azure
    Cost Management by the cost worker. No subscription_id column directly —
    it's reached via resource_id -> ResourceInventory.subscription_id.
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
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.dependencies.auth import require_analyst
from backend.api.dependencies.database import get_db
from backend.models.models import Finding, ResourceCost, ResourceInventory, FindingStatus, User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["costs"])


class CostSummary(BaseModel):
    total_monthly_cost: float
    total_annual_cost: float
    potential_monthly_savings: float
    potential_annual_savings: float
    currency: str = "USD"
    top_savings: list[dict]


@router.get("/summary", response_model=CostSummary)
async def get_cost_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
    subscription_id: UUID | None = Query(None),
) -> CostSummary:
    """Aggregate cost summary + top 10 savings opportunities."""
    # Actual spend: ResourceCost joined through ResourceInventory for subscription filtering
    cost_query = select(func.coalesce(func.sum(ResourceCost.cost_usd), 0))
    if subscription_id:
        cost_query = cost_query.join(
            ResourceInventory, ResourceCost.resource_id == ResourceInventory.id
        ).where(ResourceInventory.subscription_id == subscription_id)

    cost_result = await db.execute(cost_query)
    total_monthly = float(cost_result.scalar_one() or 0)

    # Savings opportunities: open findings with a positive estimated saving
    savings_query = (
        select(Finding)
        .options(selectinload(Finding.resource))
        .where(
            and_(
                Finding.status == FindingStatus.OPEN,
                Finding.estimated_monthly_savings_usd.isnot(None),
                Finding.estimated_monthly_savings_usd > 0,
            )
        )
    )
    if subscription_id:
        savings_query = savings_query.where(Finding.subscription_id == subscription_id)

    savings_result = await db.execute(savings_query)
    saving_findings = savings_result.scalars().all()

    total_savings = sum(f.estimated_monthly_savings_usd or 0 for f in saving_findings)

    top = sorted(
        saving_findings,
        key=lambda f: f.estimated_monthly_savings_usd or 0,
        reverse=True,
    )[:10]

    return CostSummary(
        total_monthly_cost=round(total_monthly, 2),
        total_annual_cost=round(total_monthly * 12, 2),
        potential_monthly_savings=round(total_savings, 2),
        potential_annual_savings=round(total_savings * 12, 2),
        top_savings=[
            {
                "id": str(f.id),
                "title": f.title,
                "resource_name": f.resource.resource_name if f.resource else None,
                "resource_type": f.resource.resource_type if f.resource else None,
                "monthly_saving": round(f.estimated_monthly_savings_usd or 0, 2),
                "annual_saving": round((f.estimated_monthly_savings_usd or 0) * 12, 2),
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "remediation_steps": f.remediation_steps,
            }
            for f in top
        ],
    )
