"""
Tenants API routes.

A Tenant represents an Azure Active Directory / Entra ID tenant. The
model stores client_id in plaintext (it's not secret — service principal
app IDs are visible in Azure AD app registrations) and only the client
secret is encrypted, via the existing `encrypt()` helper rather than the
combined-blob `encrypt_azure_credentials()` helper, since the model keeps
client_id as its own column rather than bundling it into the encrypted
payload.
"""
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import require_admin
from backend.api.dependencies.database import get_db
from backend.models.models import Tenant, User
from backend.utils.encryption import encrypt

logger = logging.getLogger(__name__)
router = APIRouter(tags=["tenants"])

# The actual Microsoft Graph Application permissions the five identity
# scanners require, traced directly from their Graph SDK calls in
# scanners/identity/identity_scanners.py — not a guess. Each must be
# added as an Application permission (not Delegated) on the Service
# Principal's app registration in Azure AD, with admin consent granted:
#   User.Read.All                  — stale_guest_scanner, dormant_user_scanner (users.get)
#   AuditLog.Read.All              — stale_guest_scanner, dormant_user_scanner (signInActivity filter)
#   Reports.Read.All               — mfa_not_enabled_scanner (authenticationMethods report)
#   RoleManagement.Read.Directory  — permanent_global_admin_scanner (directoryRoles + members)
#   Application.Read.All           — expired_app_credential_scanner (applications + credentials)
REQUIRED_GRAPH_PERMISSIONS = [
    "User.Read.All",
    "AuditLog.Read.All",
    "Reports.Read.All",
    "RoleManagement.Read.Directory",
    "Application.Read.All",
]


class TenantCreate(BaseModel):
    name: str
    azure_tenant_id: str
    client_id: str
    client_secret: str  # Encrypted on write, never returned on read
    # Whether the Service Principal has been granted Microsoft Graph API
    # read permissions needed by the identity scanners. Traced directly
    # from each scanner's actual Graph calls (see
    # scanners/identity/identity_scanners.py):
    #   - User.Read.All                  — stale guest / dormant user lookups
    #   - AuditLog.Read.All              — signInActivity filter (stale/dormant)
    #   - Reports.Read.All               — MFA registration report
    #   - RoleManagement.Read.Directory  — Global Admin role membership
    #   - Application.Read.All           — app credential expiry
    # If False, all five identity scanners are skipped — see
    # scanners/identity/identity_scanners.py requires_graph.
    graph_permissions_granted: bool = False


class TenantResponse(BaseModel):
    id: UUID
    name: str
    azure_tenant_id: str
    is_active: bool
    graph_permissions_granted: bool
    # Note: credentials are NEVER returned in responses

    class Config:
        from_attributes = True


def _serialize(t: Tenant) -> dict:
    return {
        "id": t.id,
        "name": t.display_name,
        "azure_tenant_id": t.tenant_id,
        "is_active": t.is_active,
        "graph_permissions_granted": bool(t.graph_permissions_granted),
    }


@router.get("", response_model=list[TenantResponse])
async def list_tenants(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> list[dict]:
    """List all registered tenants (admin only)."""
    result = await db.execute(select(Tenant).order_by(Tenant.display_name.asc()))
    return [_serialize(t) for t in result.scalars().all()]


@router.post("", response_model=TenantResponse, status_code=201)
async def create_tenant(
    body: TenantCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    """
    Register a new Azure tenant with an encrypted service principal secret.

    The client_secret is encrypted with AES-256-GCM before persisting and
    cannot be retrieved via the API afterward.
    """
    existing = await db.execute(select(Tenant).where(Tenant.tenant_id == body.azure_tenant_id))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Tenant already registered")

    tenant = Tenant(
        display_name=body.name,
        tenant_id=body.azure_tenant_id,
        client_id=body.client_id,
        client_secret_encrypted=encrypt(body.client_secret),
        is_active=True,
        # Stored as a list (column is JSONB) even though the API exposes
        # a simple boolean — a non-empty list is enough for the worker's
        # truthy check (see workers/scan_worker.py _build_scan_context).
        # A future enhancement could track specific granted scopes here
        # instead of a single flag.
        graph_permissions_granted=REQUIRED_GRAPH_PERMISSIONS if body.graph_permissions_granted else [],
    )
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return _serialize(tenant)


class TenantUpdate(BaseModel):
    graph_permissions_granted: bool


@router.patch("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: UUID,
    body: TenantUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    """
    Update a tenant's Graph API permission flag after granting (or revoking)
    admin consent in Azure AD — avoids needing to delete and re-register
    the tenant just to flip this, which would also discard the stored
    encrypted client secret.
    """
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant.graph_permissions_granted = (
        REQUIRED_GRAPH_PERMISSIONS if body.graph_permissions_granted else []
    )
    await db.commit()
    await db.refresh(tenant)
    return _serialize(tenant)


@router.delete("/{tenant_id}", status_code=204)
async def delete_tenant(
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    """Unregister a tenant. All subscriptions under this tenant must be removed first."""
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        await db.delete(tenant)
        await db.commit()
    except IntegrityError:
        # Subscription.tenant_id is ON DELETE RESTRICT by design — a tenant
        # with active subscriptions must not be silently orphaned or have
        # its subscriptions cascade-deleted alongside it. Surface this as a
        # clear, actionable error rather than a generic 500.
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Cannot delete this tenant — one or more subscriptions are still registered "
            "under it. Remove those subscriptions first, then delete the tenant.",
        )
