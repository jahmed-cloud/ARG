# Access control in the Docker UI

Who can sign in, what each person sees, and how subscription owners share access - all inside ARG. Nothing here
changes anything in Azure.

## Roles

| Role | Who gets it | Sees | Can do |
|---|---|---|---|
| **Super admin / admin** | Members of `ENTRA_ADMIN_GROUP_IDS`, or accounts an admin creates | Every subscription | Everything: tenants, subscriptions, users, access, scans, findings |
| **Analyst** ("contributor") | Members of `ENTRA_CONTRIBUTOR_GROUP_IDS`, or created by an admin | Every subscription | Run scans, change finding status, reports, remediation scripts, Terraform state - not tenants or users |
| **Auditor** | Created by an admin | Every subscription, read-only | Read |
| **Viewer** | Everyone else who signs in with Microsoft, or created by an admin | **Only** subscriptions they own in Azure, or were given reader access to in ARG | Read those subscriptions; owners also manage who else can read them |

A viewer with no owned or shared subscription sees an empty workspace, never everything. Tenant-wide pages
(Identity / Entra findings, Remediation) and "Start a Scan" are hidden for viewers.

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
- Scans of all subscriptions at once are not shown to viewers (they would reveal other subscriptions); scans of
  their own subscriptions are.
- Viewers' reports contain only their subscriptions and only they see them in Reports history.
- Every grant and removal is written to the audit log (`subscription_access.grant` / `.revoke`).

## Checking it

Implementation: `backend/services/access.py` (the one filter every read route uses), `backend/services/entra_access.py`
(groups, Owner leases, Graph lookup), `backend/api/routes/subscriptions.py` (access endpoints). Tests:
`tests/unit/test_access_scope.py`, `tests/unit/test_dashboard.py`, and `tests/integration/test_access_postgres.py`
(isolation on every scoped route, grants, sign-in; run with `ARG_TEST_DATABASE_URL` pointing at a migrated database).
