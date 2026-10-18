# Access control in the Docker UI

Who can sign in, what each person sees, and how subscription owners share access - all inside ARG. Nothing here
changes anything in Azure.

## Roles

| Role | Who gets it | Sees | Can do |
|---|---|---|---|
| **Super admin / admin** | Members of `ENTRA_ADMIN_GROUP_IDS`, the local admin from `.env`, or accounts an admin creates | Every subscription **and tenant-wide data** | Everything: tenants, subscriptions, users, access, scans, findings |
| **Contributor** (role `analyst`) | Members of `ENTRA_CONTRIBUTOR_GROUP_IDS`, or created by an admin | Every subscription **and tenant-wide data** | Start and cancel scans, change finding status, reports, remediation scripts, Terraform state - not tenants or users |
| **Auditor** | Created by an admin | Every subscription, read-only - **no tenant-wide data** | Read |
| **Viewer** (subscription owner or reader) | Everyone else who signs in with Microsoft, or created by an admin | **Only** subscriptions they own in Azure, or were given reader access to in ARG - **no tenant-wide data** | Read those subscriptions; owners also manage who else can read them |

A viewer with no owned or shared subscription sees an empty workspace, never everything.

### Tenant-wide data: admins and contributors only

Anything that describes the tenant rather than one subscription - **Identity** (Entra ID) findings, the identity
score and its trend, the dashboard's identity-issue count, tenants and users - is visible to **admins and
contributors only**. Subscription owners, readers (viewers) and auditors never see it: not on the Identity page
(hidden, and `/identity` redirects to the overview), not in Findings, exports, the dashboard or reports - even when an
identity finding is stored under a subscription they can read. Below contributor, Reports history shows only the
reports a person generated themselves. The API enforces the same rule (`AccessScope.findings()` /
`require_finding()` in `backend/services/access.py`, `TENANT_CATEGORIES`), so it cannot be bypassed by calling it
directly.

### Scans: daily automatic, on demand for contributors

Every active subscription is scanned automatically **every day at 09:00 IST** (`FULL_SCAN_SCHEDULE="0 9 * * *"` in
`SCAN_SCHEDULE_TIMEZONE="Asia/Kolkata"`; switch off with `FEATURE_SCHEDULED_SCANS=false`). **Starting and cancelling
a scan on demand** is for admins and contributors: the Scans page shows the buttons only to them and the API returns
403 to everyone else.

## How a viewer's subscriptions are decided

1. **Owner in Azure.** At every Microsoft sign-in (and every token refresh, about every 30 minutes) ARG asks Azure
   whether the person holds the **Owner** role on each registered subscription - directly, through a group, or
   inherited from a management group. It uses the tenant's scanner principal (Reader can list role assignments), not
   the person's own token. The answer is a lease of `ENTRA_ACCESS_TTL_MINUTES` (default 30); if Azure cannot be
   asked, the lease is dropped (fail closed).
2. **Reader in ARG.** An owner (or an admin) opens **Subscriptions - Manage access** (the people icon on the row),
   enters an email and clicks **Add reader**:
   - an existing ARG account (local, or created by an earlier Microsoft sign-in) is matched by email;
   - otherwise the person is looked up in the subscription's Entra tenant through Microsoft Graph and gets access at
     their first sign-in. The lookup needs **User.Read.All** (Application) on the tenant's scanner principal, the same
     permission the identity scanners use (Settings - Azure Tenants - Graph access). Without it, ask the person to
     sign in once, then add them.
   Readers added in ARG are removed in the same dialog. Owner rows come from Azure and are removed there.

Admins, analysts and auditors already see every subscription, so they are not added as readers.

## Sign-in

| Setting (`.env`) | Default | Meaning |
|---|---|---|
| `AZURE_OAUTH_CLIENT_ID` / `AZURE_OAUTH_CLIENT_SECRET` | - | The "Sign in with Microsoft" app registration (not the scanner principal) |
| `AZURE_OAUTH_TENANT_ID` | `common` | **Set your tenant GUID.** Scoped access, group roles and auto-provisioning work only for one tenant; with `common` only accounts an admin created can sign in, as before |
| `ENTRA_AUTO_PROVISION` | `true` | Anyone in the tenant can sign in and becomes a viewer. `false`: an admin creates accounts first |
| `ENTRA_ADMIN_GROUP_IDS` | `[]` | JSON list of security-group object IDs whose members are ARG admins |
| `ENTRA_CONTRIBUTOR_GROUP_IDS` | `[]` | JSON list of group object IDs whose members are analysts |
| `ENTRA_SESSION_HOURS` | `12` | Group membership is read at Microsoft sign-in; after this the person signs in again, so a group change takes effect within this time |
| `ENTRA_ACCESS_TTL_MINUTES` | `30` | How long an Azure Owner answer is trusted before it is asked again |

Group IDs are optional: without them everyone who signs in is a viewer, and the local `admin` account (see the
README, "Default sign-in") stays the administrator. Add them later and restart the backend
(`docker compose up -d backend`); roles change at each person's next sign-in.

### The local admin always stays

The local admin (`ADMIN_EMAIL` / `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `.env`) is never disabled and never changes
with Microsoft sign-in: password sign-in keeps working even when a Microsoft account with the same email is linked to
it, and its role is never taken from Entra groups. Settings - Users cannot deactivate, delete, demote or reset it
(409), Change Password refuses it, and every backend start restores it to exactly what `.env` says (active, super
admin, username and password). Change it only in `.env` (`python -m scripts.configure_env --rotate-admin`) and
restart the backend.

### App registration checklist

1. Entra ID - App registrations - New registration. Redirect URI (Web): `AZURE_OAUTH_REDIRECT_URI`
   (default `http://localhost:8000/api/v1/auth/microsoft/callback`).
2. Certificates & secrets - New client secret -> `AZURE_OAUTH_CLIENT_SECRET`; Application (client) ID ->
   `AZURE_OAUTH_CLIENT_ID`; Directory (tenant) ID -> `AZURE_OAUTH_TENANT_ID`.
3. API permissions: Microsoft Graph **User.Read** (Delegated).
4. Token configuration - **Add groups claim** - Security groups (ID token). Needed for the admin / contributor groups.
   People in more than 200 groups get an "overage" claim instead of a list; ARG then gives no group role (fail
   closed) - use a group-filtered claim (Token configuration - groups assigned to the application) for them.
5. Restart the backend: `docker compose up -d backend`.

## Rules worth knowing

- Accounts created by Microsoft sign-in are **Entra-managed**: their role is set from groups at every sign-in, so
  Settings - Users does not let you change it (change the group instead). Accounts an admin created keep the role
  set in ARG, even when they sign in with Microsoft.
- Local viewer accounts (created in Settings - Users with role viewer) are scoped the same way: they see only the
  subscriptions an owner or admin added them to.
- Scans of all subscriptions at once (including the daily automatic scan) are not shown to viewers (they would
  reveal other subscriptions); scans of their own subscriptions are.
- Reports of viewers and auditors contain only their subscriptions and no tenant-wide data, and only they see them in
  Reports history.
- Every grant and removal is written to the audit log (`subscription_access.grant` / `.revoke`).

## Checking it

Implementation: `backend/services/access.py` (the one filter every read route uses, tenant-wide data included),
`backend/services/entra_access.py` (groups, Owner leases, Graph lookup), `backend/api/routes/subscriptions.py`
(access endpoints), `scripts/seed_admin.py` and `backend/api/routes/users.py` (local admin). Tests:
`tests/unit/test_access_scope.py`, `tests/unit/test_tenant_scope.py`, `tests/unit/test_dashboard.py`, and
`tests/integration/test_access_postgres.py`
(isolation on every scoped route, grants, sign-in; run with `ARG_TEST_DATABASE_URL` pointing at a migrated database).
