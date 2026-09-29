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

The backend runs Alembic migrations and creates the initial administrator if absent. Open <http://localhost:3000> and sign in with `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env`. API docs are available on <http://localhost:8000/docs> in the base configuration. The PostgreSQL and API host ports bind to `127.0.0.1`; Redis remains internal. Use Settings to add tenant scanning credentials.

Do not generate new credentials over an existing deployment. Match the existing PostgreSQL password and encryption key. The environment generator deliberately refuses to overwrite `.env`.

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

Compose's backend healthcheck uses database readiness. Startup dependencies do not automatically restart already-running dependents when the database later fails; monitor service health and logs.

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
