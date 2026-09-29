"""Connect the Docker stack to Azure with your own `az login` - one command, like the local scanner.

    az login
    python -m scripts.connect_azure                      # every enabled subscription in the current tenant
    python -m scripts.connect_azure --subscription <id>  # only these (repeat the flag)
    python -m scripts.connect_azure --scan               # and start a scan

The Docker worker cannot reuse `az login` (on Windows the CLI token cache is encrypted to your Windows
account), so this script does the service-principal work for you with your az session:

1. finds or creates the read-only service principal `arg-scanner`;
2. gives it Reader, Cost Management Reader and Security Reader on each subscription (skips existing ones);
3. registers the tenant and the subscriptions in ARG through its API.

The client secret goes from Azure straight to ARG, where it is stored encrypted; it is never printed or
written to disk. Run it again at any time to add subscriptions - an already registered tenant is reused.
`--new-secret` gives the registered tenant a fresh secret when the old one expires.
"""
import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SP_NAME = 'arg-scanner'
ROLES = ('Reader', 'Cost Management Reader', 'Security Reader')


class ConnectError(Exception):
    pass


def az(*args):
    """Run an Azure CLI command and return its JSON output (None for empty output)."""
    exe = shutil.which('az')
    if not exe:
        raise ConnectError('Azure CLI (az) not found. Install it, then run az login.')
    done = subprocess.run([exe, *args, '--only-show-errors', '-o', 'json'], capture_output=True, text=True)
    if done.returncode:
        raise ConnectError(f'az {" ".join(args[:3])} failed: {done.stderr.strip() or done.stdout.strip()}')
    return json.loads(done.stdout) if done.stdout.strip() else None


class ArgApi:
    def __init__(self, url, username, password):
        self.base = url.rstrip('/') + '/api/v1'
        self.token = None
        self.token = self.call('POST', '/auth/login', {'username': username, 'password': password})['access_token']

    def call(self, method, path, body=None):
        request = urllib.request.Request(self.base + path, method=method,
                                         data=json.dumps(body).encode() if body is not None else None)
        request.add_header('Content-Type', 'application/json')
        if self.token:
            request.add_header('Authorization', f'Bearer {self.token}')
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                text = response.read().decode()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors='replace')[:300]
            raise ConnectError(f'ARG {method} {path} returned {exc.code}: {detail}') from None
        except urllib.error.URLError as exc:
            raise ConnectError(f'Cannot reach ARG at {self.base} ({exc.reason}). Is the Docker stack running?') from None
        return json.loads(text) if text else None


def read_env():
    path = ROOT / '.env'
    if not path.exists():
        return {}
    pairs = (line.split('=', 1) for line in path.read_text(encoding='utf-8').splitlines()
             if '=' in line and not line.lstrip().startswith('#'))
    return {key.strip(): value.strip() for key, value in pairs}


def pick_subscriptions(account, all_subs, wanted):
    tenant = account['tenantId']
    enabled = [s for s in all_subs if s.get('state') == 'Enabled' and s.get('tenantId') == tenant]
    if not wanted:
        return enabled
    by_id = {s['id'].lower(): s for s in enabled}
    missing = [w for w in wanted if w.lower() not in by_id]
    if missing:
        raise ConnectError(f'Not an enabled subscription in tenant {tenant} for this az login: {", ".join(missing)}')
    return [by_id[w.lower()] for w in wanted]


def ensure_principal(run, scopes, need_secret):
    """Return (app_id, object_id, secret). secret is None when not needed."""
    found = run('ad', 'sp', 'list', '--filter', f"displayName eq '{SP_NAME}'", '--query', '[0].{appId:appId, id:id}')
    if not found:
        created = run('ad', 'sp', 'create-for-rbac', '--name', SP_NAME, '--role', 'Reader', '--scopes', *scopes)
        app_id = created['appId']
        for attempt in range(10):  # a new principal takes a moment to appear in the directory
            shown = run('ad', 'sp', 'list', '--filter', f"appId eq '{app_id}'", '--query', '[0].id')
            if shown:
                return app_id, shown, created['password']
            time.sleep(3)
        raise ConnectError(f'Service principal {app_id} was created but is not visible yet; run the command again.')
    secret = None
    if need_secret:
        secret = run('ad', 'app', 'credential', 'reset', '--id', found['appId'], '--append',
                     '--display-name', 'arg-docker', '--years', '1', '--query', 'password')
    return found['appId'], found['id'], secret


def ensure_roles(run, object_id, scope, sleep=time.sleep):
    have = {a['roleDefinitionName'] for a in
            run('role', 'assignment', 'list', '--assignee', object_id, '--scope', scope) or []}
    added = []
    for role in ROLES:
        if role in have:
            continue
        for attempt in range(6):  # role assignment can race directory replication of a new principal
            try:
                run('role', 'assignment', 'create', '--assignee-object-id', object_id,
                    '--assignee-principal-type', 'ServicePrincipal', '--role', role, '--scope', scope)
                break
            except ConnectError:
                if attempt == 5:
                    raise
                sleep(5)
        added.append(role)
    return added


def connect(args, run=az, api_factory=ArgApi, log=print):
    account = run('account', 'show')
    if not account:
        raise ConnectError('No az login session. Run az login first.')
    subs = pick_subscriptions(account, run('account', 'list') or [], args.subscription)
    if not subs:
        raise ConnectError('This az login sees no enabled subscriptions in the current tenant.')
    tenant_id = account['tenantId']
    log(f'Azure: {account["user"]["name"]}, tenant {tenant_id}')

    env = read_env()
    username = args.user or env.get('ADMIN_USERNAME') or 'admin'
    password = env.get('ADMIN_PASSWORD') if not args.user else None
    password = password or getpass.getpass(f'ARG password for {username}: ')
    api = api_factory(args.url, username, password)

    tenants = api.call('GET', '/tenants') or []
    registered = next((t for t in tenants if t['azure_tenant_id'].lower() == tenant_id.lower()), None)

    scopes = [f'/subscriptions/{s["id"]}' for s in subs]
    app_id, object_id, secret = ensure_principal(run, scopes, need_secret=registered is None or args.new_secret)
    log(f'Service principal: {SP_NAME} ({app_id})')
    for sub, scope in zip(subs, scopes):
        added = ensure_roles(run, object_id, scope)
        log(f'  {sub["name"]}: ' + (f'added {", ".join(added)}' if added else 'roles already in place'))

    if registered is None:
        registered = api.call('POST', '/tenants', {
            'name': args.tenant_name or account.get('tenantDisplayName') or f'Tenant {tenant_id[:8]}',
            'azure_tenant_id': tenant_id, 'client_id': app_id, 'client_secret': secret,
            'graph_permissions_granted': False})
        log(f'ARG: registered tenant {registered["name"]}')
    elif args.new_secret:
        api.call('PATCH', f'/tenants/{registered["id"]}', {'client_id': app_id, 'client_secret': secret})
        log(f'ARG: tenant {registered["name"]} now uses a new client secret')
    else:
        log(f'ARG: tenant {registered["name"]} already registered')

    known = {s['azure_subscription_id'].lower() for s in api.call('GET', '/subscriptions') or []}
    for sub in subs:
        if sub['id'].lower() in known:
            log(f'ARG: {sub["name"]} already registered')
            continue
        api.call('POST', '/subscriptions', {'name': sub['name'], 'azure_subscription_id': sub['id'],
                                            'tenant_id': registered['id']})
        log(f'ARG: registered {sub["name"]}')

    if args.scan:
        job = api.call('POST', '/scans/start', {'scope': {}, 'description': 'Started by connect_azure'})
        log(f'Scan started ({job["id"]}); follow it on the Scans page.')
    else:
        log('Done. Start a scan from the Scans page (or run again with --scan).')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--subscription', action='append', default=[], metavar='ID',
                        help='Subscription to connect (repeatable). Default: every enabled one in the tenant.')
    parser.add_argument('--url', default=os.environ.get('ARG_URL', 'http://localhost:3000'),
                        help='ARG web address (default http://localhost:3000)')
    parser.add_argument('--user', help='ARG admin user (default ADMIN_USERNAME from .env; prompts for its password)')
    parser.add_argument('--tenant-name', help='Display name for the tenant in ARG')
    parser.add_argument('--new-secret', action='store_true',
                        help='Give the registered tenant a new client secret (when the old one expires)')
    parser.add_argument('--scan', action='store_true', help='Start a scan when connected')
    args = parser.parse_args(argv)
    try:
        connect(args)
    except ConnectError as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    sys.exit(main())
