# Local setup and development

Run module commands from the repository root. Use Python 3.12 for parity with Docker, Node 20+ for the React frontend, and Azure CLI for live analysis. The local portal works without Node, Docker, Redis or PostgreSQL.

## Option 1: local portal and analysis CLI

On Windows, after installing Python and Azure CLI:

```powershell
az login
.\scripts\Start-LocalPortal.ps1
```

On Linux/macOS:

```bash
az login
./scripts/start-local-portal.sh
```

Open <http://127.0.0.1:8765>. Use the portal credentials shown in the launch terminal, or set `ARG_PORTAL_USER` and `ARG_PORTAL_PASSWORD` before launching. The portal uses your Azure CLI session; its login does not request an Azure password. Launchers resolve their own repository location, so they can also be invoked with an absolute path from another folder.

Launchers create `.venv-local` and install `requirements-local.txt`. They record its SHA-256 after a successful install; unchanged environments start without a pip operation. If the environment has been manually altered, delete only `.venv-local/.requirements-local.sha256` to force dependency verification at the next launch.

For manual setup on Windows:

```powershell
py -3.12 -m venv .venv-local
.\.venv-local\Scripts\python.exe -m pip install -r requirements-local.txt
az login
.\.venv-local\Scripts\python.exe -m scripts.local_portal --no-browser
.\.venv-local\Scripts\python.exe -m scripts.subscription_analysis --subscription "subscription-id-or-name"
```

On Unix use `python3 -m venv .venv-local` and `.venv-local/bin/python`. `--all` analyzes all enabled subscriptions. Reports go to `<repo>/reports/`; use `--reports-dir` to override. Live access is limited by the permissions of the signed-in account. See the [subscription guide](subscription-analysis.md) for report interpretation, PDF export and required access.

## Option 2: full stack with host development servers

This mode runs React and the backend locally, with PostgreSQL and Redis either installed locally or supplied by Docker. It has its own users and tenant/service-principal settings.

### Install and configure

Windows:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt -r requirements-local.txt
python -m scripts.configure_env --local
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt -r requirements-local.txt
python -m scripts.configure_env --local
```

The generator creates `.env` with unique JWT, encryption, database and admin secrets. It refuses to overwrite an existing file. For an existing `.env`, configure these values yourself:

| Setting | Host-development value |
|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://arg:<password>@localhost:5432/arg` |
| `REDIS_URL` | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | `redis://localhost:6379/1` |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` |
| `FRONTEND_BASE_URL` | `http://localhost:5173` |
| `REPORT_STORAGE_PATH` | An existing/writable report directory |

If you use Docker for dependencies only:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres redis
```

These services publish to loopback. With native PostgreSQL, create the `arg` role and database matching `.env`; run Redis on port 6379. A custom password embedded in a connection URL must be URL-encoded; the generator uses URL-safe hex.

### Start services

With the virtual environment active, from the repository root:

```bash
python -m alembic upgrade head
python -m scripts.seed_admin
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

In a second terminal, activate the same virtual environment and start a worker:

```bash
python -m celery -A workers.scan_worker worker --loglevel=info -Q celery,scans,scanners,reports
```

For Windows development, append `--pool=solo` (serial development work); use Linux containers for production workers. If scheduled jobs are needed, run exactly one `python -m celery -A workers.scan_worker beat --loglevel=info` in another terminal.

In the frontend terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open <http://localhost:5173>; backend docs are at <http://localhost:8000/docs>. Sign in using `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `.env`. Vite proxies `/api/v1` to port 8000; set `VITE_BACKEND_URL` before starting Vite when that port differs. The full stack uses encrypted tenant credentials, not the local portal's CLI credential: `python -m scripts.connect_azure --url http://localhost:5173` registers them from your `az login` (or enter them in Settings; see [Connect Azure](connect-azure.md)).

## Validation

```bash
python -m pytest tests -q
python -m pip check
python -m alembic heads
cd frontend
npm ci
npm run build
```

The Python suite covers scanner fixtures, pagination, subscription reports, local portal auth and paths, export, readiness and environment generation. Browser checks with fixture data are recorded in [merge-validation.md](merge-validation.md). The CI workflow additionally builds and starts the container stack.

## Troubleshooting

- **Module not found:** use the correct virtual environment and run from the root, not `backend/`.
- **Portal connection refused:** keep the launcher running and use its printed port; see the existing troubleshooting section in the subscription guide.
- **Database errors:** verify PostgreSQL health, credentials and the async driver URL; apply migrations before starting the app.
- **Scans remain queued:** verify Redis URLs match between API/worker and all four queues are consumed.
- **New admin password appears ignored:** the Docker entrypoint syncs ADMIN_PASSWORD on startup; recreate the backend container after changing .env so its environment is refreshed (`python -m scripts.configure_env --rotate-admin` generates one). A password changed in Settings is reset the same way.
- **Scans fail with "No active subscriptions found for scan":** no tenant or subscription is registered; run `python -m scripts.connect_azure`.
- **Frontend can't reach API:** inspect `/api/v1/health`; check the Vite proxy target and the backend process.
