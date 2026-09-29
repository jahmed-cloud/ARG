import argparse

import pytest

from scripts import connect_azure as ca

TENANT = '11111111-1111-1111-1111-111111111111'
OTHER_TENANT = '22222222-2222-2222-2222-222222222222'
SUB_A = 'aaaaaaaa-0000-0000-0000-000000000001'
SUB_B = 'bbbbbbbb-0000-0000-0000-000000000002'
SUB_C = 'cccccccc-0000-0000-0000-000000000003'  # other tenant
SUB_OFF = 'dddddddd-0000-0000-0000-000000000004'  # disabled

ALL_SUBS = [
    {'id': SUB_A, 'name': 'A', 'state': 'Enabled', 'tenantId': TENANT, 'tenantDisplayName': 'Contoso'},
    {'id': SUB_B, 'name': 'B', 'state': 'Warned', 'tenantId': TENANT, 'tenantDisplayName': 'Contoso'},
    {'id': SUB_C, 'name': 'C', 'state': 'Enabled', 'tenantId': OTHER_TENANT, 'tenantDisplayName': 'Fabrikam'},
    {'id': SUB_OFF, 'name': 'Off', 'state': 'Disabled', 'tenantId': TENANT, 'tenantDisplayName': 'Contoso'},
]


class FakeAz:
    """Fake az CLI. `denied` = scopes where role assignment fails; `broken_tenants` = tenants az cannot use."""

    def __init__(self, sp=None, roles=None, denied=(), broken_tenants=()):
        self.sp, self.roles, self.denied, self.broken = sp, roles or {}, set(denied), set(broken_tenants)
        self.calls, self.active = [], SUB_A

    def tenant(self):
        return next(s['tenantId'] for s in ALL_SUBS if s['id'] == self.active)

    def __call__(self, *args):
        self.calls.append(args)
        head = args[:3]
        if args[:2] == ('account', 'show'):
            return {'id': SUB_A, 'tenantId': TENANT, 'user': {'name': 'me@contoso.com'}}
        if args[:2] == ('account', 'list'):
            return ALL_SUBS
        if args[:2] == ('account', 'set'):
            self.active = args[3]
            return None
        if self.tenant() in self.broken and args[0] == 'ad':
            raise ca.ConnectError('AADSTS50076: interaction required')
        if head == ('ad', 'sp', 'list'):
            if 'appId' in args[args.index('--filter') + 1]:
                return 'obj-new'
            return self.sp
        if head == ('ad', 'sp', 'create-for-rbac'):
            assert '--role' not in args
            return {'appId': 'app-new', 'password': 'secret-new'}
        if head == ('ad', 'app', 'credential'):
            return 'secret-reset'
        if head == ('role', 'assignment', 'list'):
            scope = args[args.index('--scope') + 1]
            return [{'roleDefinitionName': r} for r in self.roles.get(scope, [])]
        if head == ('role', 'assignment', 'create'):
            scope = args[args.index('--scope') + 1]
            if scope in self.denied:
                raise ca.ConnectError('az role assignment failed: (AuthorizationFailed) no rights')
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
        if path == '/tenants':
            return {'id': f'arg-{body["azure_tenant_id"][:4]}', 'name': body['name']}
        return {'/scans/start': {'id': 'job-1'}}.get(path, {})

    def registered_subs(self):
        return [b['azure_subscription_id'] for p, b in self.posts if p == '/subscriptions']


def args(**kw):
    base = dict(subscription=[], url='http://localhost:3000', user=None, tenant_name=None, scan=False,
                new_secret=False, current_tenant_only=False)
    return argparse.Namespace(**{**base, **kw})


def quiet(*_):
    pass


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(ca, 'read_env', lambda: {'ADMIN_USERNAME': 'admin', 'ADMIN_PASSWORD': 'pw'})
    monkeypatch.setattr(ca.time, 'sleep', lambda _: None)


def test_every_readable_subscription_in_every_tenant_is_connected():
    fake_az, api = FakeAz(), FakeApi()
    ca.connect(args(scan=True), run=fake_az, api_factory=api, log=quiet)
    assert api.login == ('http://localhost:3000', 'admin', 'pw')
    tenants = [b for p, b in api.posts if p == '/tenants']
    assert [(t['azure_tenant_id'], t['name'], t['client_id']) for t in tenants] == [
        (TENANT, 'Contoso', 'app-new'), (OTHER_TENANT, 'Fabrikam', 'app-new')]
    assert api.registered_subs() == [SUB_A, SUB_B, SUB_C]  # Warned included, Disabled not
    assert len(fake_az.created_roles()) == 9
    assert fake_az.calls[-1] == ('account', 'set', '--subscription', SUB_A)  # active subscription restored
    assert api.posts[-1][0] == '/scans/start'


def test_subscription_without_rights_is_skipped_and_the_rest_connect():
    fake_az = FakeAz(denied={f'/subscriptions/{SUB_B}'})
    api = FakeApi()
    lines = []
    ca.connect(args(current_tenant_only=True), run=fake_az, api_factory=api, log=lines.append)
    assert api.registered_subs() == [SUB_A]
    assert any(line.startswith('Skipped: B - you cannot assign roles here') for line in lines)


def test_missing_cost_role_still_connects_with_a_warning():
    scope = f'/subscriptions/{SUB_A}'
    fake_az, api = FakeAz(sp={'appId': 'app-old', 'id': 'obj-old'}, roles={scope: ['Reader']}, denied={scope}), FakeApi()
    lines = []
    ca.connect(args(subscription=[SUB_A]), run=fake_az, api_factory=api, log=lines.append)
    assert api.registered_subs() == [SUB_A]
    assert any('missing Cost Management Reader' in line for line in lines)


def test_tenant_az_cannot_use_is_skipped_with_login_hint():
    fake_az, api = FakeAz(broken_tenants={OTHER_TENANT}), FakeApi()
    lines = []
    ca.connect(args(), run=fake_az, api_factory=api, log=lines.append)
    assert api.registered_subs() == [SUB_A, SUB_B]
    assert any(f'az login --tenant {OTHER_TENANT}' in line for line in lines if line.startswith('Skipped: C'))


def test_nothing_connectable_fails():
    fake_az = FakeAz(denied={f'/subscriptions/{s}' for s in (SUB_A, SUB_B)})
    with pytest.raises(ca.ConnectError, match='No subscription'):
        ca.connect(args(current_tenant_only=True), run=fake_az, api_factory=FakeApi(), log=quiet)


def test_existing_setup_is_reused_without_a_new_secret():
    scope_a = f'/subscriptions/{SUB_A}'
    fake_az = FakeAz(sp={'appId': 'app-old', 'id': 'obj-old'}, roles={scope_a: list(ca.ROLES)})
    api = FakeApi(tenants=[{'id': 't1', 'name': 'Contoso', 'azure_tenant_id': TENANT}],
                  subs=[{'azure_subscription_id': SUB_A}])
    ca.connect(args(subscription=[SUB_A.upper()]), run=fake_az, api_factory=api, log=quiet)
    assert not any(c[:3] in {('ad', 'app', 'credential'), ('ad', 'sp', 'create-for-rbac')} for c in fake_az.calls)
    assert fake_az.created_roles() == []
    assert api.posts == []


def test_existing_principal_without_arg_tenant_gets_an_appended_secret():
    fake_az, api = FakeAz(sp={'appId': 'app-old', 'id': 'obj-old'}), FakeApi()
    ca.connect(args(subscription=[SUB_B]), run=fake_az, api_factory=api, log=quiet)
    reset = next(c for c in fake_az.calls if c[:3] == ('ad', 'app', 'credential'))
    assert '--append' in reset
    assert api.posts[0][1]['client_secret'] == 'secret-reset'
    assert {s for _, s in fake_az.created_roles()} == {f'/subscriptions/{SUB_B}'}


def test_new_secret_replaces_the_registered_tenant_credential():
    fake_az = FakeAz(sp={'appId': 'app-old', 'id': 'obj-old'}, roles={f'/subscriptions/{SUB_A}': list(ca.ROLES)})
    api = FakeApi(tenants=[{'id': 't1', 'name': 'Contoso', 'azure_tenant_id': TENANT}],
                  subs=[{'azure_subscription_id': SUB_A}])
    ca.connect(args(subscription=[SUB_A], new_secret=True), run=fake_az, api_factory=api, log=quiet)
    assert api.posts == [('/tenants/t1', {'client_id': 'app-old', 'client_secret': 'secret-reset'})]


def test_unknown_or_disabled_subscription_is_rejected_before_any_change():
    fake_az, api = FakeAz(), FakeApi()
    with pytest.raises(ca.ConnectError, match=SUB_OFF):
        ca.connect(args(subscription=[SUB_OFF]), run=fake_az, api_factory=api, log=quiet)
    assert api.posts == [] and fake_az.created_roles() == []


def test_secret_is_never_logged():
    lines = []
    ca.connect(args(), run=FakeAz(), api_factory=FakeApi(), log=lines.append)
    assert not any('secret-new' in line or 'secret-reset' in line for line in lines)
