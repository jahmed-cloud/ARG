import asyncio
import uuid

from backend.api.routes import tenants


class FakeTenant:
    display_name, tenant_id, is_active = 'Contoso', '11111111-1111-1111-1111-111111111111', True

    def __init__(self):
        self.id = uuid.uuid4()
        self.client_id, self.client_secret_encrypted = 'app-old', 'enc(old)'
        self.graph_permissions_granted = list(tenants.REQUIRED_GRAPH_PERMISSIONS)


class FakeDb:
    def __init__(self, tenant):
        self.tenant, self.commits = tenant, 0

    async def get(self, model, key):
        return self.tenant

    async def commit(self):
        self.commits += 1

    async def refresh(self, obj):
        pass


def update(tenant, **body):
    db = FakeDb(tenant)
    result = asyncio.run(tenants.update_tenant(tenant.id, tenants.TenantUpdate(**body), db=db, current_user=None))
    return result, db


def test_secret_rotation_keeps_graph_flag(monkeypatch):
    monkeypatch.setattr(tenants, 'encrypt', lambda value: f'enc({value})')
    tenant = FakeTenant()
    result, db = update(tenant, client_id='app-new', client_secret='new')
    assert (tenant.client_id, tenant.client_secret_encrypted) == ('app-new', 'enc(new)')
    assert result['graph_permissions_granted'] is True
    assert 'client_secret' not in result and db.commits == 1


def test_graph_toggle_keeps_credentials():
    tenant = FakeTenant()
    result, _ = update(tenant, graph_permissions_granted=False)
    assert result['graph_permissions_granted'] is False
    assert (tenant.client_id, tenant.client_secret_encrypted) == ('app-old', 'enc(old)')
