from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from backend.core.config import settings
from backend.models.models import UserRole
from backend.services import entra_access
from backend.services.access import AccessScope, is_scoped

ADMIN_GROUP, CONTRIB_GROUP, OTHER_GROUP = (str(uuid4()) for _ in range(3))


@pytest.fixture
def groups(monkeypatch):
    monkeypatch.setattr(settings, 'ENTRA_ADMIN_GROUP_IDS', [ADMIN_GROUP])
    monkeypatch.setattr(settings, 'ENTRA_CONTRIBUTOR_GROUP_IDS', [CONTRIB_GROUP])


@pytest.mark.parametrize('member_of, role', [
    ([ADMIN_GROUP, CONTRIB_GROUP], UserRole.ADMIN),
    ([CONTRIB_GROUP], UserRole.ANALYST),
    ([OTHER_GROUP], UserRole.VIEWER),
    ([], UserRole.VIEWER),
])
def test_role_from_groups(groups, member_of, role):
    assert entra_access.role_from_groups({'groups': member_of}) == role


def test_group_overage_fails_closed(groups):
    assert entra_access.role_from_groups({'groups': [ADMIN_GROUP], 'hasgroups': True}) == UserRole.VIEWER
    assert entra_access.role_from_groups({'_claim_names': {'groups': 'src1'}}) == UserRole.VIEWER


def test_only_viewers_are_scoped():
    assert is_scoped(SimpleNamespace(role=UserRole.VIEWER))
    for role in (UserRole.ANALYST, UserRole.AUDITOR, UserRole.ADMIN, UserRole.SUPER_ADMIN):
        assert not is_scoped(SimpleNamespace(role=role))


def test_scoped_user_without_grants_sees_nothing():
    scope = AccessScope(user=SimpleNamespace(role=UserRole.VIEWER), subscription_ids=set())
    assert scope.scoped and not scope.allows(str(uuid4()))
    assert str(scope.where(SimpleNamespace(in_=None))) == 'false'
    with pytest.raises(HTTPException) as exc:
        scope.require(None)
    assert exc.value.status_code == 404


def test_unscoped_user_sees_everything_and_admin_manages():
    admin = AccessScope(user=SimpleNamespace(role=UserRole.ADMIN))
    analyst = AccessScope(user=SimpleNamespace(role=UserRole.ANALYST))
    sub = str(uuid4())
    assert admin.allows(sub) and str(admin.where(None)) == 'true'
    assert admin.can_manage(sub) and not analyst.can_manage(sub)


def test_owner_manages_only_owned_subscriptions():
    owned, read = str(uuid4()), str(uuid4())
    scope = AccessScope(user=SimpleNamespace(role=UserRole.VIEWER), subscription_ids={owned, read}, owned={owned})
    assert scope.can_manage(owned) and not scope.can_manage(read)
    scope.require(read)
    with pytest.raises(HTTPException):
        scope.require(str(uuid4()))


def test_tenant_binding(monkeypatch):
    monkeypatch.setattr(settings, 'AZURE_OAUTH_TENANT_ID', 'common')
    assert not settings.entra_tenant_bound
    monkeypatch.setattr(settings, 'AZURE_OAUTH_TENANT_ID', str(uuid4()))
    assert settings.entra_tenant_bound
