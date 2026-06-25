"""
Subscriptions API routes.

Manage Azure subscriptions registered with ARG. Each subscription
belongs to exactly one tenant. Note the model's field names diverge from
Azure portal terminology slightly:
  - `subscription_id` is the Azure-native subscription GUID (natural key)
  - `display_name` is the human-readable name (Azure calls this "name" too,
    hence the API request/response schemas below use `name` for the
    human-facing label while mapping it onto display_name internally)
  - `state` is a free-text lifecycle string ("Enabled"/"Disabled"/"Warned"),
    not a boolean — there is no dedicated created_at timestamp on this table.
"""
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import require_admin, require_analyst
from backend.api.dependencies.database import get_db
from backend.models.models import Subscription, Tenant, User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["subscriptions"])


class SubscriptionCreate(BaseModel):
    name: str
    azure_subscription_id: str
    tenant_id: UUID
    tags: dict | None = None


class SubscriptionResponse(BaseModel):
    id: UUID
    name: str
    azure_subscription_id: str
    tenant_id: UUID
    state: str
    last_scanned_at: object | None = None

    class Config:
        from_attributes = True


def _serialize(sub: Subscription) -> dict:
    return {
        "id": sub.id,
        "name": sub.display_name,
        "azure_subscription_id": sub.subscription_id,
        "tenant_id": sub.tenant_id,
        "state": sub.state,
        "last_scanned_at": sub.last_scanned_at,
    }


@router.get("", response_model=list[SubscriptionResponse])
async def list_subscriptions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> list[dict]:
    """List all registered subscriptions."""
    result = await db.execute(select(Subscription).order_by(Subscription.display_name.asc()))
    return [_serialize(s) for s in result.scalars().all()]


@router.post("", response_model=SubscriptionResponse, status_code=201)
async def create_subscription(
    body: SubscriptionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    """Register a new Azure subscription with ARG."""
    tenant = await db.get(Tenant, body.tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    existing = await db.execute(
        select(Subscription).where(Subscription.subscription_id == body.azure_subscription_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Subscription already registered")

    sub = Subscription(
        display_name=body.name,
        subscription_id=body.azure_subscription_id,
        tenant_id=body.tenant_id,
        tags=body.tags or {},
    )
    db.add(sub)
    await db.commit()
    await db.refresh(sub)
    return _serialize(sub)


@router.delete("/{subscription_id}", status_code=204)
async def delete_subscription(
    subscription_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    """Unregister a subscription. Does not delete Azure resources."""
    sub = await db.get(Subscription, subscription_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    await db.delete(sub)
    await db.commit()
