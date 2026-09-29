"""Connect the Docker stack to Azure with your own `az login` - one command, like the local scanner.

    az login
    python -m scripts.connect_azure                      # every subscription your az login can read, all tenants
    python -m scripts.connect_azure --subscription <id>  # only these (repeat the flag)
    python -m scripts.connect_azure --scan               # and start a scan

The Docker worker cannot reuse `az login` (on Windows the CLI token cache is encrypted to your Windows
account), so this script does the service-principal work for you with your az session:

1. per tenant, finds or creates the read-only service principal `arg-scanner`;
2. gives it Reader, Cost Management Reader and Security Reader on each subscription (skips existing ones); a
   subscription where you cannot assign Reader is skipped with the reason, the others carry on;
3. registers the tenant and the subscriptions in ARG through its API, then prints what was connected and skipped.

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
USABLE_STATES = ('Enabled', 'Warned', 'PastDue')  # readable; Disabled and Deleted are not


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


def pick_subscriptions(all_subs, wanted, current_tenant, current_only=False):
    """Subscriptions to connect: every readable one this az login sees, or the ones asked for."""
    usable = [s for s in all_subs if s.get('state') in USABLE_STATES
              and (not current_only or s.get('tenantId') == current_tenant)]
    if not wanted:
        return usable
    by_id = {s['id'].lower(): s for s in usable}
    missing = [w for w in wanted if w.lower() not in by_id]
    if missing:
        raise ConnectError(f'Not a subscription this az login can use: {", ".join(missing)}')
    return [by_id[w.lower()] for w in wanted]


def by_tenant(subs, current_tenant):
    """Group subscriptions per tenant, the current tenant first."""
    groups = {}
    for sub in subs:
        groups.setdefault(sub['tenantId'], []).append(sub)
    return sorted(groups.items(), key=lambda item: item[0] != current_tenant)


def find_or_create_principal(run, sleep=time.sleep):
    """Return (app_id, object_id, secret). secret is set only for a principal created now."""
    found = run('ad', 'sp', 'list', '--filter', f"displayName eq '{SP_NAME}'", '--query', '[0].{appId:appId, id:id}')
    if found:
        return found['appId'], found['id'], None
    # No role here: roles are assigned per subscription, so one subscription without rights cannot fail the rest.
    created = run('ad', 'sp', 'create-for-rbac', '--name', SP_NAME)
    app_id = created['appId']
    for attempt in range(10):  # a new principal takes a moment to appear in the directory
        shown = run('ad', 'sp', 'list', '--filter', f"appId eq '{app_id}'", '--query', '[0].id')
        if shown:
            return app_id, shown, created['password']
        sleep(3)
    raise ConnectError(f'Service principal {app_id} was created but is not visible yet; run the command again.')


def new_secret(run, app_id):
    """An additional secret; existing ones keep working."""
    return run('ad', 'app', 'credential', 'reset', '--id', app_id, '--append',
               '--display-name', 'arg-docker', '--years', '1', '--query', 'password')


def ensure_roles(run, object_id, scope, sleep=time.sleep):
    """Assign the missing roles. Returns (roles in place, {role: reason} for the ones that could not be added)."""
    have = {a['roleDefinitionName'] for a in
            run('role', 'assignment', 'list', '--assignee', object_id, '--scope', scope) or []}
    failed = {}
    for role in ROLES:
        if role in have:
            continue
        for attempt in range(6):
            try:
                run('role', 'assignment', 'create', '--assignee-object-id', object_id,
                    '--assignee-principal-type', 'ServicePrincipal', '--role', role, '--scope', scope)
                have.add(role)
                break
            except ConnectError as exc:
                # Only a new principal that has not replicated yet is worth waiting for; missing rights are final.
                if 'PrincipalNotFound' not in str(exc) or attempt == 5:
                    failed[role] = short_reason(exc)
                    break
                sleep(5)
    return have, failed


def short_reason(exc):
    text = str(exc)
    if 'AuthorizationFailed' in text or 'does not have authorization' in text:
        return 'you cannot assign roles here (needs Owner or User Access Administrator)'
    return text.splitlines()[0][:200] if text else type(exc).__name__


def connect_tenant(run, api, tenant_id, subs, registered, args, log):
    """Connect one tenant. Returns (connected names, {name: reason} skipped)."""
    app_id, object_id, secret = find_or_create_principal(run)
    log(f'  Service principal: {SP_NAME} ({app_id})')
    ready, skipped = [], {}
    for sub in subs:
        have, failed = ensure_roles(run, object_id, f'/subscriptions/{sub["id"]}')
        if 'Reader' not in have:
            skipped[sub['name']] = failed.get('Reader', 'Reader could not be assigned')
            log(f'  {sub["name"]}: skipped - {skipped[sub["name"]]}')
            continue
        missing = ', '.join(f'{role} ({reason})' for role, reason in failed.items())
        log(f'  {sub["name"]}: roles in place' + (f'; missing {missing} - partial results' if missing else ''))
        ready.append(sub)
    if not ready:
        return [], skipped

    if registered is None:
        own_name = args.tenant_name if tenant_id == args.current_tenant else None
        name = own_name or subs[0].get('tenantDisplayName') or f'Tenant {tenant_id[:8]}'
        registered = api.call('POST', '/tenants', {
            'name': name, 'azure_tenant_id': tenant_id, 'client_id': app_id,
            'client_secret': secret or new_secret(run, app_id), 'graph_permissions_granted': False})
        log(f'  ARG: registered tenant {registered["name"]}')
    elif args.new_secret:
        api.call('PATCH', f'/tenants/{registered["id"]}',
                 {'client_id': app_id, 'client_secret': new_secret(run, app_id)})
        log(f'  ARG: tenant {registered["name"]} now uses a new client secret')

    known = {s['azure_subscription_id'].lower() for s in api.call('GET', '/subscriptions') or []}
    for sub in ready:
        if sub['id'].lower() not in known:
            api.call('POST', '/subscriptions', {'name': sub['name'], 'azure_subscription_id': sub['id'],
                                                'tenant_id': registered['id']})
            log(f'  ARG: registered {sub["name"]}')
    return [s['name'] for s in ready], skipped


def connect(args, run=az, api_factory=ArgApi, log=print):
    account = run('account', 'show')
    if not account:
        raise ConnectError('No az login session. Run az login first.')
    current_tenant = args.current_tenant = account['tenantId']
    subs = pick_subscriptions(run('account', 'list', '--all') or [], args.subscription, current_tenant,
                              args.current_tenant_only)
    if not subs:
        raise ConnectError('This az login sees no subscriptions it can read.')
    groups = by_tenant(subs, current_tenant)
    log(f'Azure: {account["user"]["name"]} - {len(subs)} subscription(s) in {len(groups)} tenant(s)')

    env = read_env()
    username = args.user or env.get('ADMIN_USERNAME') or 'admin'
    password = env.get('ADMIN_PASSWORD') if not args.user else None
    password = password or getpass.getpass(f'ARG password for {username}: ')
    api = api_factory(args.url, username, password)
    registered = {t['azure_tenant_id'].lower(): t for t in api.call('GET', '/tenants') or []}

    connected, skipped = [], {}
    try:
        for tenant_id, tenant_subs in groups:
            log(f'Tenant {tenant_subs[0].get("tenantDisplayName") or tenant_id} ({tenant_id})')
            try:
                if tenant_id != current_tenant:  # az ad works on the tenant of the active subscription
                    run('account', 'set', '--subscription', tenant_subs[0]['id'])
                done, missed = connect_tenant(run, api, tenant_id, tenant_subs,
                                              registered.get(tenant_id.lower()), args, log)
            except ConnectError as exc:
                reason = short_reason(exc)
                if tenant_id != current_tenant:
                    reason += f' (sign in to it with: az login --tenant {tenant_id})'
                done, missed = [], {s['name']: reason for s in tenant_subs}
                log(f'  skipped tenant - {reason}')
            connected += done
            skipped.update(missed)
    finally:
        if any(t != current_tenant for t, _ in groups):
            run('account', 'set', '--subscription', account['id'])

    log('')
    log(f'Connected ({len(connected)}): ' + (', '.join(connected) or 'none'))
    for name, reason in skipped.items():
        log(f'Skipped: {name} - {reason}')
    if not connected:
        raise ConnectError('No subscription could be connected.')
    if args.scan:
        job = api.call('POST', '/scans/start', {'scope': {}, 'description': 'Started by connect_azure'})
        log(f'Scan started ({job["id"]}); follow it on the Scans page.')
    else:
        log('Start a scan from the Scans page (or run again with --scan).')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--subscription', action='append', default=[], metavar='ID',
                        help='Subscription to connect (repeatable). Default: every subscription your az login can read.')
    parser.add_argument('--current-tenant-only', action='store_true',
                        help='Only subscriptions of the tenant az is signed in to right now')
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
