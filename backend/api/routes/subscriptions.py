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
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import require_admin
from backend.api.dependencies.database import get_db
from backend.models.models import AuditLog, Subscription, SubscriptionAccess, Tenant, User, UserRole
from backend.services.access import AccessScope, get_access_scope
from backend.services.entra_access import LookupUnavailable, find_entra_user

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
    my_access: str | None = None  # all / owner / reader - how the caller sees this subscription
    can_manage_access: bool = False

    class Config:
        from_attributes = True


def _serialize(sub: Subscription, scope: AccessScope | None = None) -> dict:
    data = {
        "id": sub.id,
        "name": sub.display_name,
        "azure_subscription_id": sub.subscription_id,
        "tenant_id": sub.tenant_id,
        "state": sub.state,
        "last_scanned_at": sub.last_scanned_at,
    }
    if scope is not None:
        data["my_access"] = ("all" if not scope.scoped
                             else "owner" if str(sub.id) in scope.owned else "reader")
        data["can_manage_access"] = scope.can_manage(sub.id)
    return data


@router.get("", response_model=list[SubscriptionResponse])
async def list_subscriptions(
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
) -> list[dict]:
    """Registered subscriptions the caller may see."""
    result = await db.execute(
        select(Subscription).where(scope.where(Subscription.id)).order_by(Subscription.display_name.asc()))
    return [_serialize(s, scope) for s in result.scalars().all()]


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


# ---------------------------------------------------------------------------
# Access inside ARG: owners (from Azure) and admins add readers. Nothing is changed in Azure.
# ---------------------------------------------------------------------------

class AccessGrantCreate(BaseModel):
    email: str = Field(..., min_length=3, max_length=255,
                       description="ARG account email, or an Entra user (UPN or mail)")


class AccessGrantResponse(BaseModel):
    id: str
    principal: str | None
    kind: str  # local / entra
    role: str  # owner / reader
    source: str  # azure (Owner in Azure, re-checked at sign-in) / manual (added in ARG)
    expires_at: datetime | None = None
    removable: bool


async def _managed_subscription(db: AsyncSession, subscription_id: UUID, scope: AccessScope) -> Subscription:
    sub = await db.get(Subscription, str(subscription_id))
    if not sub or not scope.allows(sub.id):
        raise HTTPException(status_code=404, detail="Subscription not found")
    if not scope.can_manage(sub.id):
        raise HTTPException(status_code=403,
                            detail="Only an owner of this subscription or an admin can manage access")
    return sub


def _grant(row: SubscriptionAccess) -> dict:
    return {
        "id": str(row.id),
        "principal": row.principal_name,
        "kind": "local" if row.user_id else "entra",
        "role": row.role,
        "source": row.source,
        "expires_at": row.expires_at,
        "removable": row.source == "manual",
    }


def _audit(db: AsyncSession, request: Request, user: User, action: str, sub: Subscription, detail: str) -> None:
    db.add(AuditLog(
        user_id=user.id, action=action, resource_type="subscription_access", resource_id=str(sub.id),
        description=f"{detail} on {sub.display_name}",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:512],
        request_id=request.headers.get("x-request-id"),
        outcome="success",
    ))


@router.get("/{subscription_id}/access", response_model=list[AccessGrantResponse])
async def list_access(
    subscription_id: UUID,
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
) -> list[dict]:
    """Who can see this subscription in ARG besides admins, analysts and auditors."""
    sub = await _managed_subscription(db, subscription_id, scope)
    rows = (await db.execute(
        select(SubscriptionAccess).where(SubscriptionAccess.subscription_id == sub.id)
        .order_by(SubscriptionAccess.role.asc(), SubscriptionAccess.principal_name.asc())
    )).scalars().all()
    return [_grant(r) for r in rows]


@router.post("/{subscription_id}/access", response_model=AccessGrantResponse, status_code=201)
async def add_reader(
    subscription_id: UUID,
    body: AccessGrantCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
) -> dict:
    """Give someone read access to this subscription in ARG.

    An existing ARG account (local, or created by an earlier Microsoft sign-in) is matched by email. Otherwise
    the person is looked up in the subscription's Entra tenant (needs Microsoft Graph User.Read.All on the
    tenant's scanner principal) and gets access at their first Microsoft sign-in.
    """
    sub = await _managed_subscription(db, subscription_id, scope)
    email = body.email.strip()
    local = (await db.execute(select(User).where(
        func.lower(User.email) == email.lower(), User.deleted_at.is_(None)))).scalar_one_or_none()
    if local:
        if local.role != UserRole.VIEWER:
            raise HTTPException(status_code=409,
                                detail=f"{local.email} already sees every subscription ({local.role.value})")
        match = SubscriptionAccess.user_id == local.id
        grant = SubscriptionAccess(subscription_id=sub.id, user_id=local.id, principal_name=local.email,
                                   role="reader", source="manual", granted_by=scope.user.id)
    else:
        tenant = await db.get(Tenant, str(sub.tenant_id))
        try:
            found = await find_entra_user(tenant, email)
        except LookupUnavailable as exc:
            raise HTTPException(status_code=400, detail=(
                f"{email} has no ARG account yet and {exc}. Ask them to sign in to ARG with Microsoft once, "
                "then add them again - or grant User.Read.All to the tenant's scanner principal.")) from None
        if not found:
            raise HTTPException(status_code=404, detail=f"No user {email} in this subscription's Entra tenant")
        tenant_guid = str(UUID(tenant.tenant_id))
        match = and_(SubscriptionAccess.tenant_id == tenant_guid, SubscriptionAccess.object_id == found["id"])
        grant = SubscriptionAccess(subscription_id=sub.id, tenant_id=tenant_guid, object_id=found["id"],
                                   principal_name=found["upn"], role="reader", source="manual",
                                   granted_by=scope.user.id)
    existing = (await db.execute(select(SubscriptionAccess.id).where(
        SubscriptionAccess.subscription_id == sub.id, SubscriptionAccess.source == "manual", match))).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"{grant.principal_name} already has access")
    db.add(grant)
    _audit(db, request, scope.user, "subscription_access.grant", sub, f"Reader access for {grant.principal_name}")
    await db.commit()
    await db.refresh(grant)
    return _grant(grant)


@router.delete("/{subscription_id}/access/{grant_id}", status_code=204)
async def remove_reader(
    subscription_id: UUID,
    grant_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
) -> None:
    """Remove a reader added in ARG. Owner access comes from Azure and is removed there."""
    sub = await _managed_subscription(db, subscription_id, scope)
    grant = await db.get(SubscriptionAccess, str(grant_id))
    if not grant or str(grant.subscription_id) != str(sub.id):
        raise HTTPException(status_code=404, detail="Access grant not found")
    if grant.source != "manual":
        raise HTTPException(status_code=400, detail="Owner access comes from Azure; remove the Owner role there")
    await db.delete(grant)
    _audit(db, request, scope.user, "subscription_access.revoke", sub,
           f"Reader access for {grant.principal_name} removed")
    await db.commit()
