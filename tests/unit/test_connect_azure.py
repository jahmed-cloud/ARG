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


# ---- existing service principal (tenants where users may not register applications) -----------------

class FakeHttp:
    def __init__(self, subs, pages=1):
        self.subs, self.pages, self.calls = subs, pages, []

    def __call__(self, method, url, data=None, headers=None, timeout=30):
        self.calls.append((method, url, data, headers))
        if url.endswith('/oauth2/v2.0/token'):
            return {'access_token': 'arm-token'}
        page = sum(1 for c in self.calls if c[0] == 'GET')
        chunk = self.subs[page - 1::self.pages]
        return {'value': chunk, 'nextLink': f'{ca.ARM_URL}/next{page}' if page < self.pages else None}


def arm_sub(sub_id, name, state='Enabled', tenant=TENANT):
    return {'subscriptionId': sub_id, 'displayName': name, 'state': state, 'tenantId': tenant}


def existing_args(**kw):
    return args(client_id='app-admin', tenant_id=TENANT, **kw)


def test_existing_principal_registers_every_subscription_it_reads_without_azure_changes():
    http = FakeHttp([arm_sub(SUB_A, 'a'), arm_sub(SUB_B, 'b', 'Warned'), arm_sub(SUB_OFF, 'off', 'Disabled'),
                     arm_sub(SUB_C, 'other-tenant', tenant=OTHER_TENANT)], pages=2)
    fake_az, api = FakeAz(), FakeApi(subs=[{'azure_subscription_id': SUB_B}])
    names = ca.connect_existing(existing_args(tenant_name='Contoso', scan=True), run=fake_az, api_factory=api,
                                log=quiet, http=http, secret='s3cret')
    assert names == ['a', 'b']
    token = http.calls[0]
    assert token[1] == f'{ca.LOGIN_URL}/{TENANT}/oauth2/v2.0/token' and token[2]['client_id'] == 'app-admin'
    assert token[2]['scope'] == f'{ca.ARM_URL}/.default'
    assert [c[3]['Authorization'] for c in http.calls[1:]] == ['Bearer arm-token'] * 2  # followed nextLink
    tenant = [b for p, b in api.posts if p == '/tenants'][0]
    assert (tenant['name'], tenant['client_id'], tenant['client_secret']) == ('Contoso', 'app-admin', 's3cret')
    assert api.registered_subs() == [SUB_A]  # SUB_B was already registered
    assert api.posts[-1][0] == '/scans/start'
    assert fake_az.calls == [] and fake_az.created_roles() == []  # no az call at all with --tenant-id


def test_existing_principal_updates_a_registered_tenant_and_never_logs_the_secret():
    lines = []
    api = FakeApi(tenants=[{'id': 'arg-1', 'name': 'Contoso', 'azure_tenant_id': TENANT}])
    patched = []
    api.call = (lambda orig: lambda m, p, b=None: patched.append((m, p, b)) or orig(m, p, b))(api.call)
    ca.connect_existing(existing_args(), api_factory=api, log=lines.append,
                        http=FakeHttp([arm_sub(SUB_A, 'a')]), secret='s3cret')
    assert ('PATCH', '/tenants/arg-1', {'client_id': 'app-admin', 'client_secret': 's3cret'}) in patched
    assert not any('s3cret' in line for line in lines)


def test_existing_principal_without_readable_subscriptions_fails_before_touching_arg():
    api = FakeApi()
    with pytest.raises(ca.ConnectError, match='Reader'):
        ca.connect_existing(existing_args(), api_factory=api, log=quiet,
                            http=FakeHttp([arm_sub(SUB_OFF, 'off', 'Disabled')]), secret='x')
    with pytest.raises(ca.ConnectError, match='cannot read'):
        ca.connect_existing(existing_args(subscription=[SUB_C]), api_factory=api, log=quiet,
                            http=FakeHttp([arm_sub(SUB_A, 'a')]), secret='x')
    assert api.posts == []


def test_blocked_app_registration_points_to_the_existing_principal_mode():
    reason = ca.short_reason(ca.ConnectError('az ad sp failed: ERROR: Directory permission is needed for the '
                                             'current user to register the application.'))
    assert '--client-id' in reason
