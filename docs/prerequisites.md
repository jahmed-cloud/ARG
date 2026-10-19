# Requirements and prerequisites

Everything you need before installing, running, developing or hosting ARG, by mode. Pick the mode first:

| Mode | Use it to | Needs |
|---|---|---|
| **A. Local CLI and portal** | Analyse subscriptions from your workstation with your own `az login`; markdown / HTML / PDF reports and the Estate page | Python 3.12, Azure CLI, three read-only Azure roles |
| **B. Docker stack** | Self-hosted web UI (React), scheduled scans, findings in PostgreSQL, multi-user access | Docker or Podman, a read-only service principal per tenant |
| **C. Development** | Change code, run tests, build the frontend | Mode A tools plus Node.js 20, optionally Docker |
| **D. Azure DevOps** | Host the repository and run the validation pipeline | An Azure DevOps project and a Microsoft-hosted (or Linux self-hosted) agent |

ARG is **read-only** in Azure in every mode: it never creates, changes or deletes Azure resources (the only
exception is `scripts.connect_azure` / `Grant-ArgRoles.ps1`, which you run yourself to create the scanning principal
or assign reader roles).

---

## A. Local CLI and portal

### Software

| Requirement | Version | Why / notes |
|---|---|---|
| Operating system | Windows 10/11, Linux or macOS | All three are supported; the PowerShell launchers are the tested path |
| PowerShell | 7.x (`pwsh`) recommended; Windows PowerShell 5.1 works | `scripts\Start-LocalPortal.ps1`, `scripts\Invoke-SubscriptionAnalysis.ps1`, `scripts\Grant-ArgRoles.ps1`. Linux / macOS use `scripts/start-local-portal.sh` or plain `python -m ...` |
| Python | **3.12** recommended (what CI and the containers use); the launchers accept 3.10+. On `PATH` (`py -3.12` on Windows) | The launchers create `.venv-local` from it on first run and install [requirements-local.txt](../requirements-local.txt) |
| Azure CLI (`az`) | Current 2.x | ARG reuses its sign-in token (`AzureCliCredential`); nothing else signs in to Azure |
| Microsoft Edge or Google Chrome | Any current version | Only for PDF export (headless print). Override the path with `ARG_PDF_BROWSER` |
| Git | Any current version | To clone the repository |

No Docker, database, Redis, Node.js or service principal is needed in this mode.

### Azure access (your own account)

| Role | Scope | Used for |
|---|---|---|
| **Reader** | Each subscription to analyse | Resource Graph inventory, ARM configuration, Azure Monitor metrics, Advisor, policy assignments |
| **Cost Management Reader** | Each subscription | 12-month cost trend, cost per resource / meter, budgets |
| **Security Reader** | Each subscription | Defender for Cloud plans, secure score and recommendations |

`.\scripts\Grant-ArgRoles.ps1 -IncludeReader -WhatIf` shows which assignments are missing; drop `-WhatIf` to add them
(you need Owner or User Access Administrator for that). A missing role does not stop a run: the affected scanners are
skipped and listed under *Collection Warnings* in `05-deep-dive/README.md`.

Entra ID (Microsoft Graph) scanners do **not** run in this mode; they need the Docker stack and a service principal.

### Network access

| Endpoint | Purpose |
|---|---|
| `login.microsoftonline.com` | Azure CLI token refresh |
| `management.azure.com` | Resource Graph, ARM, Azure Monitor metrics, Cost Management, Consumption budgets |
| `prices.azure.com` | Azure Retail Prices API (public, list prices for savings estimates) |
| `pypi.org`, `files.pythonhosted.org` | First-run package install only (or your internal PyPI mirror) |

The portal listens on `127.0.0.1:8765` only (loopback); nothing is exposed to the network.

### Configuration (environment variables)

| Variable | Required | Meaning |
|---|---|---|
| `ARG_PORTAL_USER` | No (default `admin`) | Local portal sign-in name. Protects the portal only, not Azure |
| `ARG_PORTAL_PASSWORD` | No | Local portal password. If unset, a one-time password is printed at start-up |
| `ARG_PORTAL_API_TOKEN` | No | Enables bearer-token access to the portal's `/api/v1` for scripts (24+ characters) |
| `ARG_PDF_BROWSER` | No | Full path to Edge / Chrome if it is not found automatically |

Set user-scope variables once, then open a **new** terminal (names are case-sensitive):

```powershell
[Environment]::SetEnvironmentVariable('ARG_PORTAL_USER', 'admin', 'User')
[Environment]::SetEnvironmentVariable('ARG_PORTAL_PASSWORD', '<choose-a-password>', 'User')
```

### Capacity and run time

| Workload | Typical time |
|---|---|
| One subscription, ~200 resources | 3-4 minutes |
| One subscription, ~2,000 resources | ~15 minutes |
| Estate inventory (`--all --estate`), ~12,000 resources | ~5 minutes |
| Every subscription (`--all --parallel 3`), ~140 subscriptions | ~1.5 hours |

Reports are written to `reports/` in the repository (git-ignored, they contain resource IDs, IPs and principal IDs).
Conditional Access can expire the CLI token about hourly: run `az login` again and re-run the step.

---

## B. Docker stack

### Software

| Requirement | Version | Notes |
|---|---|---|
| Docker Engine / Docker Desktop with Linux containers | 24+ with BuildKit | Or **Podman Desktop** on Windows with `podman-compose` (`python -m pip install podman-compose`), started with `scripts\Start-PodmanStack.ps1` |
| Docker Compose plugin | 2.24.4+ | Needed for the `!reset` tags in `docker-compose.prod.yml` |
| Python 3.12 on the host | Optional | Only for `python -m scripts.configure_env` (generates `.env`) and `python -m scripts.connect_azure` |
| Azure CLI | Optional | Only for `scripts.connect_azure` (creates the scanning principal from your `az login`) |

Images used: `python:3.12-slim` (backend, worker, beat), `node:20-alpine` (frontend build), `nginx:1.27-alpine`
(frontend runtime), `postgres:16-alpine`, `redis:7-alpine`. The first build needs access to Docker Hub (or a mirror),
PyPI and the npm registry. The runtime containers need no host Python or Node.

### Ports

| Port | Service | Bound to |
|---|---|---|
| 3000 (`FRONTEND_PORT`) | Web UI (nginx, also proxies `/api/v1`) | All interfaces - put a TLS reverse proxy in front for shared use |
| 8000 (`BACKEND_PORT`) | FastAPI backend and `/docs` | `127.0.0.1` |
| 5432 (`POSTGRES_PORT`) | PostgreSQL | `127.0.0.1` |
| 6379 | Redis | Internal network only (published on loopback only with `docker-compose.dev.yml`) |

### Required configuration (`.env`)

`python -m scripts.configure_env` writes a `.env` with fresh random values (it never overwrites an existing file).
By hand: copy [.env.example](../.env.example) to `.env` and set at least:

| Variable | Value |
|---|---|
| `POSTGRES_PASSWORD` | A strong database password |
| `SECRET_KEY` | 64 hex characters - signs JWTs: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ENCRYPTION_KEY` | Base64 of 32 random bytes - encrypts stored client secrets (AES-256-GCM): `python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"`. **Back it up**: losing it makes stored credentials unreadable |
| `ADMIN_PASSWORD` | The local admin password (synced from `.env` on every backend start) |

Optional groups in `.env.example`: Microsoft sign-in (`AZURE_OAUTH_*`, `ENTRA_*`), SMTP for password reset, webhooks,
scan schedule (`FULL_SCAN_SCHEDULE`, `SCAN_SCHEDULE_TIMEZONE`), worker scaling and feature flags. `.env` is git- and
docker-ignored; never commit it.

### Azure access (service principal per tenant)

| Permission | Type | Used for |
|---|---|---|
| Reader | Azure RBAC, each subscription | Inventory, configuration, metrics, policy |
| Cost Management Reader | Azure RBAC, each subscription | Cost analysis and budgets |
| Security Reader | Azure RBAC, each subscription | Defender for Cloud |
| `User.Read.All`, `AuditLog.Read.All`, `Reports.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All` | Microsoft Graph **application**, admin consent | Optional - Entra ID hygiene scanners (sign-in activity needs Entra ID P1/P2) |

`python -m scripts.connect_azure` creates (or reuses) the principal `arg-scanner`, assigns the three RBAC roles and
registers it in ARG; you need permission to create app registrations and to assign roles. Where users may not
register applications, ask an Entra admin for a principal and use `--client-id`. Details:
[connect-azure.md](connect-azure.md).

Optional **Sign in with Microsoft**: a separate Entra app registration (redirect URI
`<backend>/api/v1/auth/microsoft/callback`, delegated `User.Read`, groups claim) - see
[access-control.md](access-control.md).

### Network access (runtime)

`login.microsoftonline.com`, `management.azure.com`, `graph.microsoft.com` (identity scanners), `prices.azure.com`,
and your SMTP / webhook endpoints if configured.

### Container registry (optional)

Published images are on Docker Hub (`jahmed22/azure-resource-guardian-*`, see the README); `docker-compose.hub.yml`
runs them without the source. To publish your own build, set `REGISTRY` in `build-push.sh` to your registry
(Docker Hub account or Azure Container Registry) and run `./build-push.sh`.

---

## C. Development

Everything from mode A, plus:

| Requirement | Version | Used for |
|---|---|---|
| Node.js and npm | **Node 20** LTS | Frontend (`frontend/`): `npm ci`, `npm run dev`, `npm run build` (TypeScript check + Vite) |
| Python dev dependencies | [backend/requirements.txt](../backend/requirements.txt) + [backend/requirements-dev.txt](../backend/requirements-dev.txt) + [requirements-local.txt](../requirements-local.txt) | Tests (`pytest`), lint (`ruff` 0.4.4), type checks (`mypy`) |
| Docker / Podman | As in mode B | Full-stack checks and `tests/integration` (PostgreSQL) |
| PostgreSQL 16 and Redis 7 | Optional | Only when running the backend and worker on the host ([local-development.md](local-development.md)) |
| PSScriptAnalyzer | Optional | Lint for the PowerShell launchers |
| GNU make | Optional | Shortcuts in the [Makefile](../Makefile) (Linux / macOS / WSL) |

Python dependencies are pinned to exact versions. After changing any requirements file, run
`python -m pip install -r ...` in a clean virtual environment and `python -m pip check`.

---

## D. Azure DevOps

| Requirement | Notes |
|---|---|
| Azure DevOps organisation and project | With an Azure Repos Git repository for ARG |
| Permission to create pipelines and branch policies | Project Administrator or Build Administrator |
| A pipeline agent | Microsoft-hosted `ubuntu-latest` (Python, Node and Docker preinstalled) or a self-hosted Linux agent with Python 3.12, Node 20, Docker with Compose and `curl` |
| No service connections or secrets | The validation pipeline runs offline and generates a throw-away `.env` |

Set-up steps, branch policies and what stays local: [azure-devops.md](azure-devops.md).
