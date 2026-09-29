# Connect Azure to the Docker stack

The Docker UI scans with a read-only **service principal** stored (encrypted) in ARG. A scan needs a registered tenant
**and** at least one registered subscription; without them it fails with "No active subscriptions found for scan".

The local scanner (`scripts.subscription_analysis`, local portal) needs none of this - it uses your `az login`
directly. The Docker worker cannot: on Windows the Azure CLI token cache is encrypted to your Windows account and
unreadable inside Linux containers, and a personal sign-in expires under Conditional Access while scheduled scans
keep running. The one-command option below gives the same experience: `az login`, then one command.

Pick one of the two ways. Both end in the same state.

## Option A - one command (recommended)

Prerequisites: the Docker stack is running (`http://localhost:3000`), the Azure CLI is installed, and your account
can create app registrations and assign roles on the subscriptions (Owner or User Access Administrator).

```bash
az login
python -m scripts.connect_azure                                   # every subscription your az login can read
python -m scripts.connect_azure --current-tenant-only             # only the tenant az is signed in to now
python -m scripts.connect_azure --subscription <subscription-id>  # only these (repeat the flag)
python -m scripts.connect_azure --scan                            # connect and start a scan
```

On Windows without `python` on the PATH use `.venv\Scripts\python.exe -m scripts.connect_azure` or
`py -m scripts.connect_azure`. The script uses only the Python standard library and the `az` CLI.

What it does, in order:

1. Lists every subscription your `az login` can see, in **all** signed-in tenants (`az account list --all`), in
   the states Azure still lets you read: Enabled, Warned and PastDue (Disabled and Deleted are left out). An unknown
   or disabled `--subscription` stops the run before any change.
2. Signs in to ARG with `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env` (or `--user`, then prompts for the
   password). `--url` points at another ARG address.
3. Per tenant (current tenant first; for another tenant it switches the active subscription so `az ad` works there,
   and switches back at the end): finds the service principal `arg-scanner`, or creates it without roles.
4. Assigns **Reader**, **Cost Management Reader** and **Security Reader** on each subscription, skipping roles that
   are already there (retries only while a new principal replicates in Entra ID).
   - No Reader possible (you are not Owner / User Access Administrator there): the subscription is **skipped** with
     the reason; the others carry on.
   - Reader in place but a cost or security role missing: connected, with a warning that those results are partial.
   - A tenant `az` cannot use (for example multi-factor sign-in needed): skipped with the `az login --tenant <id>`
     command to run first.
5. Registers the tenant in ARG if it is not registered yet. Only then is a client secret needed: a new principal's
   own secret, or - for an existing principal - an **additional** secret (`az ad app credential reset --append`,
   one year), so secrets used elsewhere keep working.
6. Registers each connected subscription that ARG does not know yet, and prints what was connected and skipped.
7. With `--scan`, starts a scan of all registered subscriptions.

Subscriptions in a tenant you have not signed in to with `az login` are invisible to the CLI; run
`az login --tenant <tenant-id>` for it, then the command again.

The client secret goes from Azure straight into ARG's API, where it is encrypted with `ENCRYPTION_KEY`. It is never
printed or written to disk. Run the command again at any time to add subscriptions; everything already in place is
reused and no new secret is created.

Graph permissions for the identity scanners are **not** granted by the script (that needs admin consent) - see
step 3 of Option B.

## Option B - manual

### 1. Create the service principal

```bash
az login
az account show --query "{tenant:tenantId, subscription:id, name:name}" -o table
az ad sp create-for-rbac --name "arg-scanner" --role Reader --scopes /subscriptions/<subscription-id>
```

Note `appId` (client ID), `password` (client secret) and `tenant` from the output. The secret is shown only once.
For several subscriptions list more scopes after `--scopes`. Portal alternative: Entra ID - App registrations -
New registration, then Certificates & secrets - New client secret, then Access control (IAM) on each subscription.

### 2. Assign the read-only roles

To every subscription you can manage, in one go (PowerShell, uses only `az`; preview first with `-WhatIf`):

```powershell
.\scripts\Grant-ArgRoles.ps1 -Assignee arg-scanner -IncludeReader -WhatIf
.\scripts\Grant-ArgRoles.ps1 -Assignee arg-scanner -IncludeReader
```

It assigns Cost Management Reader and Security Reader (plus Reader with `-IncludeReader`) on every subscription
your `az login` can see, in all signed-in tenants, skips roles already there (also inherited ones), skips
subscriptions where you cannot assign roles with the reason, and prints a summary. `-SubscriptionId` and
`-CurrentTenantOnly` limit it. The same script gives people the roles the **local scanner** needs:
`-Assignee me` (default) or `-Assignee colleague@contoso.com`.

Or one subscription at a time:

```bash
az role assignment create --assignee <appId> --role "Cost Management Reader" --scope /subscriptions/<subscription-id>
az role assignment create --assignee <appId> --role "Security Reader" --scope /subscriptions/<subscription-id>
```

Repeat per subscription (plus `--role Reader` for subscriptions not in the `create-for-rbac` scopes), or assign
the three roles once on a management group.

| Role | Used for |
|---|---|
| Reader | Resource Graph inventory, metrics, diagnostic settings, policy, posture scanners |
| Cost Management Reader | Cost, savings and budgets |
| Security Reader | Defender for Cloud plans, secure score, assessments |

### 3. Optional - identity scanners (Microsoft Graph)

Entra ID - App registrations - `arg-scanner` - API permissions - Add a permission - Microsoft Graph -
**Application** permissions: `User.Read.All`, `AuditLog.Read.All`, `Reports.Read.All`,
`RoleManagement.Read.Directory`, `Application.Read.All`. Then **Grant admin consent**. Without them the identity
scanners are skipped, not failed. MFA, dormant-user and stale-guest checks also need Entra ID P1/P2.

### 4. Register the tenant in ARG

Settings - Azure Tenants - **Register Tenant**: display name, Azure tenant ID, client ID (`appId`), client secret
(`password`). Tick "Microsoft Graph API permissions granted" only after step 3 (it can be switched later on the
tenant card).

### 5. Register the subscriptions

Subscriptions - **Register Subscription**: display name, Azure subscription ID and the tenant from step 4. One
entry per subscription.

### 6. Scan

Scans - **Start a Scan**. The Overview, Findings and Cost Savings pages fill in when it completes; Reports then
exports PDF, Excel, CSV or JSON.

## After connecting

- **Add a subscription:** run Option A again, or repeat steps 2 and 5.
- **Secret expiry:** `create-for-rbac` secrets last one year. Run
  `python -m scripts.connect_azure --new-secret`: it adds a new secret to `arg-scanner` and stores it on the
  registered tenant (`PATCH /api/v1/tenants/{id}` with `client_secret`), keeping subscriptions and scan history.
  Manually: `az ad app credential reset --id <appId> --append` and send the new secret with that API call. Do not
  delete and re-register the tenant for this - a tenant can only be deleted after its subscriptions, and deleting a
  subscription also deletes its findings and scan history.
- **Disconnect:** delete the subscriptions (this removes their findings and history), then the tenant, in ARG;
  then `az ad sp delete --id <appId>` removes the principal and its role assignments.

All access is read-only. Remediation scripts are generated for review and never run against Azure by ARG.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Scan FAILED - "No active subscriptions found for scan" | No subscription registered. Option A, or Option B step 5. |
| Scan completes with no cost data | Cost Management Reader missing, or new role not yet effective (can take a few minutes). |
| `AuthorizationFailed` in the worker log (`docker compose logs worker`) | A role is missing on that subscription; re-run Option A. |
| `AADSTS7000215: Invalid client secret` / `AADSTS7000222` (expired) | `python -m scripts.connect_azure --new-secret`. |
| `connect_azure`: "Cannot reach ARG" | Stack not running or another address: `docker compose ps`, `--url`. |
| `connect_azure`: 401 from `/auth/login` | Admin password differs from `.env` (restart the backend so it syncs), or pass `--user`. |
| `connect_azure`: `Insufficient privileges` / `AuthorizationFailed` from `az` | Your account cannot create app registrations or assign roles; ask an admin, or use Option B with a principal they create. |
