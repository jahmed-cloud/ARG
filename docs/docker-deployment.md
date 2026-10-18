# Docker deployment and operations

Use source builds to deploy these changes. Existing Docker Hub `latest` images do not contain this local branch until a release is built and published.

## Prerequisites and configuration

- A running Docker Engine/Desktop with Linux containers and BuildKit.
- A current Docker Compose plugin (2.24.4+ recommended for override-tag support).
- Access to Python, Node, Nginx, PostgreSQL and Redis image registries and dependency registries during the first build.
- Python 3.12 on the host only if using the optional environment generator. The container runtime does not require host Python/Node.

From the repository root:

```bash
python -m scripts.configure_env
docker compose config -q
docker compose up -d --build --wait --wait-timeout 240
docker compose ps
```

Alternatively copy `.env.example` to `.env` and replace `POSTGRES_PASSWORD`, `SECRET_KEY`, `ENCRYPTION_KEY` and `ADMIN_PASSWORD`. Generate a 32-byte random hex JWT key and a base64-encoded 32-byte encryption key. Examples are templates, never shared deployment secrets. Preserve the encryption key with your backup; changing it makes existing stored Azure credentials unreadable.

The backend runs Alembic migrations and creates the initial administrator if absent. Open <http://localhost:3000> and sign in with `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env`. API docs are available on <http://localhost:8000/docs> in the base configuration. The PostgreSQL and API host ports bind to `127.0.0.1`; Redis remains internal.

The username is `ADMIN_USERNAME` (default `admin`) or `ADMIN_EMAIL`. The backend syncs the administrator password
from `ADMIN_PASSWORD` on every start, so a password changed in Settings is reset at the next restart - change it in
`.env`. To generate a new one: `python -m scripts.configure_env --rotate-admin` (writes it to `.env` and prints it),
then `docker compose up -d backend`.

## Connect Azure

```bash
az login
python -m scripts.connect_azure --scan
```

This covers every subscription your `az login` can read, in all signed-in tenants: it creates or reuses the
read-only service principal `arg-scanner` per tenant, assigns Reader, Cost Management Reader and Security Reader,
registers the tenant and subscriptions through the API, and skips (with the reason) subscriptions where you cannot
assign roles. The manual alternative (Settings -
Register Tenant, Subscriptions - Register Subscription) and secret rotation are in [Connect Azure](connect-azure.md).

Do not generate new credentials over an existing deployment. Match the existing PostgreSQL password and encryption key. The environment generator deliberately refuses to overwrite `.env`.

## Daily automatic scan

The `beat` container scans every active subscription once a day. Default: **09:00 India Standard Time**.

| Setting (`.env`) | Default | Meaning |
|---|---|---|
| `FULL_SCAN_SCHEDULE` | `0 9 * * *` | Cron (minute hour day month weekday), e.g. `30 6 * * 1-5` for 06:30 on weekdays |
| `SCAN_SCHEDULE_TIMEZONE` | `Asia/Kolkata` | IANA time zone the schedule is read in (`Europe/Zurich`, `UTC`, ...) |
| `FEATURE_SCHEDULED_SCANS` | `true` | `false` switches the automatic scan off |

Restart `worker` and `beat` after a change (`docker compose up -d worker beat`). On-demand scans (Scans - Start a
Scan) stay available to admins and contributors; see [access control](access-control.md#scans-daily-automatic-on-demand-for-contributors).
Before this release the schedule setting was ignored and the scan ran every 24 hours from whenever `beat` started.
Until a tenant is connected (`python -m scripts.connect_azure`) there is nothing to scan: the daily run is then
skipped and logged by `worker` ("Scheduled full scan skipped: no active subscriptions are connected") instead of
adding a failed job to the Scans page every day.

## Email

Password-reset emails go through SMTP when `SMTP_HOST` is set (`SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
`SMTP_FROM_EMAIL`, `SMTP_USE_TLS`). Without SMTP no reset email is sent and the link is **never written to the
log** (it is a credential: anyone who can read the log could reset that password); an admin resets the password
under **Settings - Users** instead. On a private development machine `LOG_PASSWORD_RESET_LINKS=true` writes the
link to the backend log again (warned about at every start). `GET /auth/system-status` returns booleans only.

**Requirement (planned, not built yet): send email through Microsoft Graph.** Exchange Online is retiring SMTP basic
authentication, and a Graph mail sender needs no SMTP relay or mailbox password:

- `MAIL_PROVIDER=graph` (default `smtp`) and `GRAPH_MAIL_SENDER=<shared mailbox>`, e.g. `arg-noreply@<domain>`.
- Sending uses `POST https://graph.microsoft.com/v1.0/users/{GRAPH_MAIL_SENDER}/sendMail` with an app-only token
  (client credentials) from an app registration with Microsoft Graph **Mail.Send** (Application) and admin consent -
  either the Sign in with Microsoft app or a dedicated one (`GRAPH_MAIL_CLIENT_ID` / `GRAPH_MAIL_CLIENT_SECRET`,
  tenant from `AZURE_OAUTH_TENANT_ID`); never the read-only scanner principal.
- Limit the app to the one sender mailbox with Exchange Online RBAC for Applications (or an application access
  policy), so Mail.Send cannot send as anyone else.
- Same messages as today (password reset), then scan-completed and scheduled-report notifications; delivery failures
  are logged and never block a sign-in or a scan; the Settings - Integrations card shows which provider is active.
- Tests with a mocked Graph endpoint; no secret or token is ever logged.

## Security settings

| Setting | Behaviour |
|---|---|
| Webhooks (`WEBHOOK_SLACK_URL`, `WEBHOOK_TEAMS_URL`, `WEBHOOK_CUSTOM_URL`) | Delivered only to `https://` URLs without credentials whose host resolves to **public** addresses; redirects are not followed. Loopback, private, link-local and the cloud metadata address (`169.254.169.254`) are refused, so a webhook cannot reach internal services. `WEBHOOK_ALLOW_PRIVATE_HOSTS=true` allows an internal receiver on purpose (metadata stays blocked). A rejected URL is logged and skipped; the test endpoint answers 400 |
| `FRONTEND_BASE_URL` | Must be `http(s)://host[:port][/path]` without credentials, query or fragment (the backend does not start otherwise); in production a non-`https` URL other than localhost is warned about at start, because reset links and Microsoft sign-in tokens use it |
| `APP_ENV=production` | The backend refuses to start with the placeholder `SECRET_KEY` / `ENCRYPTION_KEY` or a default or shorter-than-12-character `ADMIN_PASSWORD` - `python -m scripts.configure_env` generates all three |
| `LOG_PASSWORD_RESET_LINKS` | `false` (default). Development only, see [Email](#email) |

Refresh tokens, password-reset tokens and API keys are stored as SHA-256 hashes of 256+ bit random values - the usual
choice for high-entropy tokens (a slow password hash adds nothing at that entropy). Authentication uses bearer tokens,
not cookies.

### Rotating SECRET_KEY and ENCRYPTION_KEY

Rotate both keys if they were ever shared, committed or copied from another installation. The first commit of this
repository shipped generated values in `.env` / `.env.example`; an installation still using those must rotate.

1. Generate new values and put them in `.env`:
   `python -c "import secrets, base64; print('SECRET_KEY=' + secrets.token_hex(32)); print('ENCRYPTION_KEY=' + base64.b64encode(secrets.token_bytes(32)).decode())"`
2. `docker compose up -d` - a new `SECRET_KEY` signs out every session and invalidates reset links.
3. Tenant client secrets were encrypted with the old `ENCRYPTION_KEY` and can no longer be read: store them again with
   `python -m scripts.connect_azure` (it updates the registered tenants in place), then start a scan.

The CI secret scan (gitleaks, `.github/workflows/validate.yml`) fails on any new secret in the history;
`.gitleaksignore` lists only the revoked values from the first commit.

## Production overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml config -q
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build --wait --wait-timeout 240
```

The overlay explicitly clears PostgreSQL, Redis and backend host ports with `!reset []`; an ordinary empty list does not clear inherited port entries. Only the frontend remains published. It sets the application's actual `APP_ENV=production` setting, limits resources for every service, uses two API workers with smaller pools, and retains two Celery replicas. See [Compose merge rules](https://docs.docker.com/reference/compose-file/merge/).

Provide TLS through your ingress/reverse proxy and configure `FRONTEND_BASE_URL`, `ALLOWED_ORIGINS`, and optional OAuth callback/SMTP settings for the external URL. To limit the frontend to loopback behind a host proxy, use a local override with `ports: !override ["127.0.0.1:3000:80"]`. Tune worker replicas, concurrency and database connections against actual workload and memory; resource limits are starting defaults, not a capacity benchmark.

Keep one migration-owning backend service during startup and one Beat scheduler. This Compose configuration targets a single host. Multi-host operation needs shared report storage, coordinated migrations and external database/queue operations.

## Build changes

- Existing multi-stage builds are retained. Python runtimes use a non-root `arg` account, with compilers only in the builder.
- Dependency layers precede application copies, so source-only edits reuse installations.
- BuildKit cache mounts retain pip/npm downloads between builds without embedding the download cache in the runtime image. See [Docker cache guidance](https://docs.docker.com/build/cache/optimize/).
- Frontend installation uses strict `npm ci` and the committed lockfile. There is no fallback that silently resolves a new dependency tree.
- `.dockerignore` excludes `.env*`, local merge backups, virtual environments, reports and validation artifacts.
- Shell scripts use LF checkout endings, including on Windows. The backend build also strips CRLF from its entrypoint, covering existing working copies that predate the Git attributes.
- `VITE_API_URL` is a build argument. Rebuild the frontend if you change it; setting it only as a container environment variable cannot rewrite the bundle.

Base image tags and Python transitive dependencies are not digest/hash-locked. No image-size or cold-build speed claim is made without a Docker build measurement.

## Startup and health

PostgreSQL and Redis become healthy first. The backend migrates and seeds before serving HTTP. Worker, Beat and frontend wait for backend readiness. This prevents scan tasks from racing schema creation.

| Check | Meaning |
|---|---|
| `/api/v1/health/live` | Process is serving HTTP; independent of database |
| `/api/v1/health` | Database query succeeds; returns 503 when unavailable or timed out |
| `docker compose exec worker celery -A workers.scan_worker inspect ping` | A worker responds through the broker |

Compose's backend healthcheck uses database readiness. The frontend image checks nginx on `127.0.0.1` (busybox `wget` resolves `localhost` to `::1`, where nginx does not listen). Startup dependencies do not automatically restart already-running dependents when the database later fails; monitor service health and logs.

```bash
docker compose logs --tail=100 backend worker beat
docker compose exec backend alembic current
docker compose exec backend python -m scripts.seed_admin
```

The seed command creates the administrator if absent and synchronizes an existing administrator password from ADMIN_PASSWORD. Keep that setting consistent with your intended login. Use the same `-f` flags for all commands when operating the production stack. Direct host API access is disabled in production; use the frontend proxy or `docker compose exec backend curl -f http://localhost:8000/api/v1/health`.

## Persistent data, upgrades and rollback

| Volume | Data |
|---|---|
| `postgres_data` | Application database |
| `redis_data` | Broker/result data with append-only persistence |
| `report_data` | Backend report files under `/tmp/arg/reports` |
| `beat_data` | Scheduler state under `/app/beat` |

**Existing report files:** the old backend stored generated files under `/tmp/arg/reports` inside its container. Before recreating it, copy that directory out with `docker compose cp backend:/tmp/arg/reports ./report-backup` if it exists. Restore its contents into the new `report_data` volume at that same path and ensure the `arg` container user owns them. The original absolute path is retained so database `reports.file_path` values continue to resolve. For deployments with a custom `REPORT_STORAGE_PATH`, adapt both the mount target and environment value to preserve that path. Verify old report downloads before removing the old container/backup; creating a volume does not automatically recover files from an old container.

Before upgrading, record the deployed commit/image tag, retain `.env` securely, back up PostgreSQL using your database backup tooling, and copy/export the report volume consistently with the database. Test backup restoration. Then rebuild/start and check login, tenant settings, scan completion, findings and old/new report downloads.

For rollback, use the previous source commit/image tags and matching config. This optimization introduces no new schema migration beyond the upstream repository; older local versions may still be incompatible with upstream migrations. Restore the matching database/report backup if reverting across those migrations. Do not blindly downgrade the database.

`docker compose down` preserves named volumes. `docker compose down -v` deletes the database, queue, reports and Beat state; it is only appropriate for disposable environments.

## Validation status

The merged base, development and production Compose models are checked locally, including actual production port removal. Docker Engine was not running on the implementation host, so builds, image health, Postgres migrations against a running database and restart persistence remain unverified there. The new CI workflow builds the images, starts a disposable stack and probes API/worker health. See [the validation record](merge-validation.md) before deployment.
