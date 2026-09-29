"""Which subscriptions a signed-in user may see, and who may manage access to them.

Roles (application level):
  super_admin / admin  - everything, including tenants, users and access grants
  analyst              - "contributor": every subscription, runs scans and manages findings
  auditor              - every subscription, read-only
  viewer               - only subscriptions they own in Azure (lease from sign-in) or were given reader access to

Every read route filters with AccessScope.where(<model>.subscription_id); single objects go through
AccessScope.require(). A scoped user with no grants sees nothing, never everything.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, HTTPException
from sqlalchemy import and_, false, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import get_current_user
from backend.api.dependencies.database import get_db
from backend.core.config import settings
from backend.models.models import SubscriptionAccess, User, UserRole

MANAGERS = (UserRole.SUPER_ADMIN, UserRole.ADMIN)


def is_scoped(user: User) -> bool:
    return user.role == UserRole.VIEWER


def principal_filter(user: User):
    """SubscriptionAccess rows that belong to this user: by ARG account, or by their Entra identity."""
    conditions = [SubscriptionAccess.user_id == user.id]
    if user.sso_provider == "azure_ad" and user.sso_subject and settings.entra_tenant_bound:
        conditions.append(and_(
            SubscriptionAccess.tenant_id == str(UUID(settings.AZURE_OAUTH_TENANT_ID)),
            SubscriptionAccess.object_id == user.sso_subject,
        ))
    now = datetime.now(timezone.utc)
    return and_(or_(*conditions),
                or_(SubscriptionAccess.expires_at.is_(None), SubscriptionAccess.expires_at > now))


@dataclass
class AccessScope:
    user: User
    subscription_ids: set[str] | None = None  # None = every subscription
    owned: set[str] = field(default_factory=set)

    @property
    def scoped(self) -> bool:
        return self.subscription_ids is not None

    def where(self, column):
        """SQL condition limiting `column` (a subscription id column) to what this user may see."""
        if not self.scoped:
            return true()
        return column.in_(sorted(self.subscription_ids)) if self.subscription_ids else false()

    def allows(self, subscription_id) -> bool:
        return not self.scoped or str(subscription_id) in self.subscription_ids

    def require(self, subscription_id) -> None:
        """404 (not 403) so a scoped user cannot probe which objects exist."""
        if subscription_id is None and self.scoped:
            raise HTTPException(status_code=404, detail="Not found")
        if subscription_id is not None and not self.allows(subscription_id):
            raise HTTPException(status_code=404, detail="Not found")

    def can_manage(self, subscription_id) -> bool:
        return self.user.role in MANAGERS or str(subscription_id) in self.owned


async def load_scope(db: AsyncSession, user: User) -> AccessScope:
    if not is_scoped(user):
        return AccessScope(user=user)
    rows = (await db.execute(
        select(SubscriptionAccess.subscription_id, SubscriptionAccess.role).where(principal_filter(user))
    )).all()
    return AccessScope(user=user, subscription_ids={str(s) for s, _ in rows},
                       owned={str(s) for s, role in rows if role == "owner"})


async def get_access_scope(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AccessScope:
    return await load_scope(db, current_user)
