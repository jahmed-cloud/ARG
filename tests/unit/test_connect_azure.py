import argparse

import pytest

from scripts import connect_azure as ca

TENANT = '11111111-1111-1111-1111-111111111111'
SUB_A = 'aaaaaaaa-0000-0000-0000-000000000001'
SUB_B = 'bbbbbbbb-0000-0000-0000-000000000002'
OTHER = 'cccccccc-0000-0000-0000-000000000003'


class FakeAz:
    def __init__(self, sp=None, roles=None):
        self.sp, self.roles, self.calls = sp, roles or {}, []

    def __call__(self, *args):
        self.calls.append(args)
        head = args[:3]
        if args[:2] == ('account', 'show'):
            return {'tenantId': TENANT, 'tenantDisplayName': 'Contoso', 'user': {'name': 'me@contoso.com'}}
        if args[:2] == ('account', 'list'):
            return [{'id': SUB_A, 'name': 'A', 'state': 'Enabled', 'tenantId': TENANT},
                    {'id': SUB_B, 'name': 'B', 'state': 'Enabled', 'tenantId': TENANT},
                    {'id': OTHER, 'name': 'Other', 'state': 'Enabled', 'tenantId': 'another'}]
        if head == ('ad', 'sp', 'list'):
            if '--filter' in args and 'appId' in args[args.index('--filter') + 1]:
                return 'obj-new'
            return self.sp
        if head == ('ad', 'sp', 'create-for-rbac'):
            return {'appId': 'app-new', 'password': 'secret-new'}
        if head == ('ad', 'app', 'credential'):
            return 'secret-reset'
        if head == ('role', 'assignment', 'list'):
            scope = args[args.index('--scope') + 1]
            return [{'roleDefinitionName': r} for r in self.roles.get(scope, [])]
        if head == ('role', 'assignment', 'create'):
            return {}
        raise AssertionError(args)

    def created_roles(self):
        return [(c[c.index('--role') + 1], c[c.index('--scope') + 1]) for c in self.calls
                if c[:3] == ('role', 'assignment', 'create')]


class FakeApi:
    def __init__(self, tenants=None, subs=None):
        self.tenants, self.subs, self.posts = tenants or [], subs or [], []

    def __call__(self, url, username, password):
        self.login = (url, username, password)
        return self

    def call(self, method, path, body=None):
        if method == 'GET':
            return {'/tenants': self.tenants, '/subscriptions': self.subs}[path]
        self.posts.append((path, body))
        return {'/tenants': {'id': 'arg-tenant', 'name': body and body.get('name')},
                '/scans/start': {'id': 'job-1'}}.get(path, {})


def args(**kw):
    base = dict(subscription=[], url='http://localhost:3000', user=None, tenant_name=None, scan=False,
                new_secret=False)
    return argparse.Namespace(**{**base, **kw})


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(ca, 'read_env', lambda: {'ADMIN_USERNAME': 'admin', 'ADMIN_PASSWORD': 'pw'})


def test_new_principal_gets_all_roles_and_registers_everything_in_tenant():
    fake_az, api = FakeAz(), FakeApi()
    ca.connect(args(scan=True), run=fake_az, api_factory=api, log=lambda *_: None)
    assert api.login == ('http://localhost:3000', 'admin', 'pw')
    tenant_post = api.posts[0]
    assert tenant_post == ('/tenants', {'name': 'Contoso', 'azure_tenant_id': TENANT, 'client_id': 'app-new',
                                        'client_secret': 'secret-new', 'graph_permissions_granted': False})
    assert [p[1]['azure_subscription_id'] for p in api.posts if p[0] == '/subscriptions'] == [SUB_A, SUB_B]
    assert api.posts[-1][0] == '/scans/start'
    assert len(fake_az.created_roles()) == 6  # 3 roles x 2 subscriptions, other tenant excluded


def test_existing_setup_is_reused_without_a_new_secret():
    scope_a = f'/subscriptions/{SUB_A}'
    fake_az = FakeAz(sp={'appId': 'app-old', 'id': 'obj-old'}, roles={scope_a: list(ca.ROLES)})
    api = FakeApi(tenants=[{'id': 't1', 'name': 'Contoso', 'azure_tenant_id': TENANT}],
                  subs=[{'azure_subscription_id': SUB_A}])
    ca.connect(args(subscription=[SUB_A.upper()]), run=fake_az, api_factory=api, log=lambda *_: None)
    assert not any(c[:3] in {('ad', 'app', 'credential'), ('ad', 'sp', 'create-for-rbac')} for c in fake_az.calls)
    assert fake_az.created_roles() == []
    assert api.posts == []


def test_existing_principal_without_arg_tenant_gets_an_appended_secret():
    fake_az = FakeAz(sp={'appId': 'app-old', 'id': 'obj-old'})
    api = FakeApi()
    ca.connect(args(subscription=[SUB_B]), run=fake_az, api_factory=api, log=lambda *_: None)
    reset = next(c for c in fake_az.calls if c[:3] == ('ad', 'app', 'credential'))
    assert '--append' in reset
    assert api.posts[0][1]['client_secret'] == 'secret-reset'
    assert {s for _, s in fake_az.created_roles()} == {f'/subscriptions/{SUB_B}'}


def test_unknown_subscription_is_rejected_before_any_change():
    fake_az, api = FakeAz(), FakeApi()
    with pytest.raises(ca.ConnectError, match=OTHER):
        ca.connect(args(subscription=[OTHER]), run=fake_az, api_factory=api, log=lambda *_: None)
    assert api.posts == [] and fake_az.created_roles() == []


def test_secret_is_never_logged():
    lines = []
    ca.connect(args(), run=FakeAz(), api_factory=FakeApi(), log=lines.append)
    assert not any('secret-new' in line for line in lines)


def test_new_secret_replaces_the_registered_tenant_credential():
    fake_az = FakeAz(sp={'appId': 'app-old', 'id': 'obj-old'}, roles={f'/subscriptions/{SUB_A}': list(ca.ROLES)})
    api = FakeApi(tenants=[{'id': 't1', 'name': 'Contoso', 'azure_tenant_id': TENANT}],
                  subs=[{'azure_subscription_id': SUB_A}])
    ca.connect(args(subscription=[SUB_A], new_secret=True), run=fake_az, api_factory=api, log=lambda *_: None)
    assert api.posts == [('/tenants/t1', {'client_id': 'app-old', 'client_secret': 'secret-reset'})]
