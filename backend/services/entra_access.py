"""Tenant-bound Entra principals and read-only Azure Owner verification."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from azure.identity.aio import ClientSecretCredential
from sqlalchemy import delete, select

from backend.core.config import settings
from backend.models.models import Subscription, SubscriptionAccess, Tenant, UserRole
from backend.utils.encryption import decrypt

logger = logging.getLogger(__name__)
OWNER_ROLE = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'


def identity_from_claims(claims):
    """Use only MSAL-validated claims, never user-supplied email as an identity key."""
    tenant_id = str(UUID(claims['tid']))
    object_id = str(UUID(claims['oid']))
    if tenant_id != str(UUID(settings.AZURE_OAUTH_TENANT_ID)):
        raise ValueError('Tenant not allowed')
    return tenant_id, object_id


def group_admin(claims):
    # Overage claims do not contain a complete membership list. Fail closed;
    # administrators can use the local recovery account to adjust configuration.
    if claims.get('hasgroups') or 'groups' in claims.get('_claim_names', {}):
        return False
    groups = {str(UUID(g)) for g in claims.get('groups', [])}
    configured = {str(UUID(g)) for g in settings.ENTRA_ADMIN_GROUP_IDS}
    return bool(groups & configured)


def is_owner_assignment(assignment, subscription_id):
    props = assignment.get('properties', {})
    scope = props.get('scope', '').lower().rstrip('/')
    return (
        props.get('roleDefinitionId', '').lower().rsplit('/', 1)[-1] == OWNER_ROLE
        and not props.get('condition')
        and (scope == f'/subscriptions/{subscription_id}'.lower()
             or scope.startswith('/providers/microsoft.management/managementgroups/')
             or scope == '')  # root inheritance returned by atScope()
    )


async def subscription_owner(client, token, subscription_id, object_id):
    url = f'https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments'
    params = {'api-version': '2022-04-01', '$filter': f"atScope() and assignedTo('{object_id}')"}
    for _ in range(100):
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or parsed.netloc != 'management.azure.com':
            raise ValueError('Untrusted ARM pagination URL')
        response = await client.get(url, params=params, headers={'Authorization': f'Bearer {token}'})
        response.raise_for_status()
        payload = response.json()
        if any(is_owner_assignment(row, subscription_id) for row in payload.get('value', [])):
            return True
        url = payload.get('nextLink')
        if not url:
            return False
        params = None
    raise ValueError('ARM pagination limit exceeded')


async def sync_entra_access(db, user, claims):
    tenant_id, object_id = identity_from_claims(claims)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.ENTRA_ACCESS_TTL_MINUTES)
    user.role = UserRole.ADMIN if group_admin(claims) else UserRole.VIEWER
    user.subscription_scoped = True
    user.sso_access_expires_at = expires_at
    # Delete previous discovery grants even if Azure becomes unavailable. Never
    # extend stale ownership after a permission or network failure.
    await db.execute(delete(SubscriptionAccess).where(
        SubscriptionAccess.tenant_id == tenant_id, SubscriptionAccess.object_id == object_id,
        SubscriptionAccess.source == 'azure'))
    if user.role == UserRole.ADMIN:
        return 0
    tenant = (await db.execute(select(Tenant).where(Tenant.tenant_id == tenant_id, Tenant.is_active.is_(True)))).scalar_one_or_none()
    if not tenant:
        return 0
    subscriptions = (await db.execute(select(Subscription).where(
        Subscription.tenant_id == tenant.id, Subscription.is_active.is_(True)))).scalars().all()
    try:
        async with ClientSecretCredential(tenant_id, tenant.client_id, decrypt(tenant.client_secret_encrypted)) as credential:
            token = await credential.get_token('https://management.azure.com/.default')
            async with httpx.AsyncClient(timeout=15) as client:
                semaphore = asyncio.Semaphore(5)
                async def verify(sub):
                    async with semaphore:
                        return sub if await subscription_owner(client, token.token, sub.subscription_id, object_id) else None
                results = await asyncio.wait_for(asyncio.gather(*(verify(s) for s in subscriptions)), timeout=90)
    except Exception as exc:
        # Do not log credential-bearing response bodies or tokens.
        logger.warning('Entra ownership discovery unavailable: %s', type(exc).__name__)
        user.preferences = {**(user.preferences or {}), 'ownership_sync': 'unavailable'}
        return 0
    owners = [sub for sub in results if sub is not None]
    for sub in owners:
        db.add(SubscriptionAccess(subscription_id=sub.id, tenant_id=tenant_id, object_id=object_id,
            role='owner', source='azure', expires_at=expires_at))
    user.preferences = {**(user.preferences or {}), 'ownership_sync': 'ok'}
    return len(owners)
