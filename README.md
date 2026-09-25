# 🛡️ Azure Resource Guardian (ARG)

> **Discover. Govern. Optimize.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.1-brightgreen.svg)](https://github.com/jahmed-cloud/ARG/releases)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://reactjs.org)
[![Docker](https://img.shields.io/badge/Docker-multi--arch-2496ED.svg)](https://www.docker.com)
[![Docker Hub](https://img.shields.io/badge/Docker_Hub-jahmed22-2496ED.svg)](https://hub.docker.com/u/jahmed22)

**Azure Resource Guardian** is a self-hosted, Docker-based, open-source Azure governance platform that gives organizations a single-pane-of-glass view across their entire Azure estate.

---

## 🎯 What Problems Does ARG Solve?

| Question | ARG's Answer |
|---|---|
| What resources are costing money unnecessarily? | Cost Optimization Engine with Azure Cost Management integration |
| Which resources are orphaned? | 20+ orphan/idle checks across Compute, Network, Storage, Database, Cost (63 scanners in total - see [docs/scanner-catalog.md](docs/scanner-catalog.md)) |
| Which resources violate governance standards? | Governance Module with CAF + Zero Trust scoring |
| Which Entra ID objects are security risks? | Full Microsoft Graph hygiene analysis |
| What resources are unmanaged by Terraform? | Terraform drift detection engine |
| How much money can we save? | Monthly/annual savings projection per resource |
| What can be safely deleted? | Remediation engine with approval workflows |

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     React Frontend (MUI)                         │
│          Dashboard │ Findings │ Costs │ Identity │ Reports       │
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST API / WebSocket
┌──────────────────────────▼──────────────────────────────────────┐
│                   FastAPI Backend (Python 3.12)                  │
│      Auth │ Scans │ Findings │ Reports │ Remediation │ RBAC      │
└──────┬────────────────────────────────────────┬─────────────────┘
       │                                        │
┌──────▼──────┐                    ┌────────────▼──────────────────┐
│ PostgreSQL  │                    │   Celery Workers + Redis       │
│  Database   │                    │   Scanner Orchestration        │
└─────────────┘                    └────────────┬──────────────────┘
                                                │
                           ┌────────────────────▼──────────────────┐
                           │           Scanner Plugins              │
                           │  Compute │ Network │ Storage │ Identity│
                           │  Governance │ Security │ Terraform     │
                           └────────────────────┬──────────────────┘
                                                │
                           ┌────────────────────▼──────────────────┐
                           │             Azure APIs                  │
                           │  Resource Graph │ Management │ Cost    │
                           │  Microsoft Graph │ Policy              │
                           └───────────────────────────────────────┘
```

---

## ✨ Features

### 🔍 Resource Discovery
- Full Azure resource inventory across subscriptions, management groups, and tenants
- Tag analysis and ownership tracking
- Resource history and change detection

### 💀 Orphan Detection (20+ checks)
- Unattached managed disks, old snapshots, deallocated VMs
- Unused public IPs, public IPs held by VM-less NICs, orphaned NICs and NSGs, empty load balancers
- Unused storage accounts (verified against 7-day transaction metrics), orphaned backups
- Idle SQL databases, idle Cosmos DB accounts, idle IoT Hubs, empty resource groups
- DDoS Network Protection plans that protect no VNet or public IP
- Private Link DNS zones with no endpoints

### 💰 Cost Optimization
- Azure Cost Management integration
- Per-resource monthly/annual savings estimates
- Top 10 cost-saving opportunities dashboard
- Cost trend analysis
- Previous-generation App Service plans (Premium v2 → v3) and CPU-saturated plans
- Hyperscale databases on the legacy storage meter
- Azure OpenAI / Foundry spend without an AI gateway, and AI account sprawl
- Storage account sprawl and transaction hotspots
- Budgets exceeded month after month, and Advisor reservation / savings-plan opportunities
- Marketplace SaaS plans: unsubscribed leftovers, suspended or never-activated plans, terms ending or auto-renewing

### 🆔 Entra ID Hygiene
- Stale/unused applications and service principals
- Expired certificates and secrets
- Guest users never logged in, dormant users, MFA gaps
- Permanent Global Admins, PIM assignments never activated
- Managed identities never used

### 🏛️ Governance
- Tag policy enforcement
- Naming standard validation
- Region restriction compliance
- CAF alignment scoring
- Zero Trust alignment scoring
- Governance Score (0-100)
- Environment tag vs name mismatches (e.g. a `-Test` database tagged `prod`) and tag-key typos
- Production and non-production sharing one App Service plan; app and data tiers split across regions
- Log Analytics daily caps that silently drop data, App Insights linked to deleted workspaces, missing Service Health alerts
- Many unrelated workloads sharing one subscription (landing-zone gap)

### 🔒 Security
- Public storage accounts, SQL servers, Key Vaults
- Disabled Defender plans, low secure score, and imported Defender for Cloud recommendations
- Missing backup configurations
- Expired certificates
- Missing diagnostic settings (verified per resource in live scans)
- RDP/SSH open to the Internet, VM public IPs next to Bastion, end-of-support OS images
- SQL "Allow Azure services" / ad-hoc single-IP firewall rules, Entra-only auth disabled
- Storage shared-key access and open networks; Key Vault access-policy model, soft delete, purge protection
- Azure OpenAI / AI Services key authentication and open networks
- Web apps allowing HTTP, EOL runtimes (.NET, Node, Python, PHP), weak TLS, no managed identity
- Excess subscription Owners, standing User Access Administrator, privileged service principals
- Security Score (0-100)

### 🌊 Terraform Drift Detection
- Compare Terraform state vs live Azure inventory
- Detect unmanaged resources, deleted resources, config drift
- Generate Terraform import commands
- Generate remediation plans

### 📊 Reporting
- Executive PDF summary
- Board-level reports
- Technical CSV/Excel/JSON exports
- Compliance reports

### 🧭 Subscription Analysis Report (CLI + local portal)
Run every scanner against your subscriptions from your own workstation - **no Docker, database or
service principal needed**. Azure access reuses your **`az login`** session (your own account).
📖 Full guide: [docs/subscription-analysis.md](docs/subscription-analysis.md) · PRD: [docs/PRD-subscription-analysis.md](docs/PRD-subscription-analysis.md)

**Where to run:** the PowerShell/bash launchers work **from any folder** (they switch to the repo root and
create `.venv-local` on first use). Plain `python -m …` commands must be run **from the ARG repository root**.
Reports always go to **`<ARG repo>/reports/`** unless you pass `-ReportsPath` / `--reports-dir`.

```powershell
az login                                                         # once, in a terminal

# Local portal - http://127.0.0.1:8765
C:\path\to\ARG\scripts\Start-LocalPortal.ps1                     # Linux/macOS: ./scripts/start-local-portal.sh

# Command line - one folder per subscription, plus an index
C:\path\to\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription '<subscription-id-or-name>'
C:\path\to\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -All
```

Python equivalents (from the repo root, after `pip install -r requirements-local.txt`):

```bash
python -m scripts.subscription_analysis --subscription "<subscription-id-or-name>"   # repeatable
python -m scripts.subscription_analysis --all                                        # every enabled subscription
python -m scripts.local_portal                                                       # the portal
# options: --reports-dir DIR  --tenant <id>  --scanners a,b  --config thresholds.json  --skip-cost
```

- **Portal login** is a simple local username/password that only protects the portal:
  `ARG_PORTAL_USER` (default `admin`) / `ARG_PORTAL_PASSWORD`. If no password is set, a one-time
  password is printed in the terminal at start-up. The portal never signs in to Azure itself.
- It shows which account the `az login` session uses, lists the subscriptions that account can see,
  lets you **Analyze** one or several (progress shown live), and renders every report page (markdown,
  mermaid diagrams, JSON evidence) in the browser. To switch account or tenant, run `az login` again
  and click **Refresh**.
- It listens on localhost only, checks the Host/Origin headers, and neutralises HTML in rendered
  reports.

Both write the same layout:

```
reports/
├── README.md                        # index: one row per analysed subscription
└── <subscription-name>/
    ├── README.md                    # executive summary, headline savings, top risks, action list
    ├── summary.json                 # machine-readable totals (used by the index/portal)
    ├── 01-current-findings/         # baseline, workloads, architecture diagram, resource inventory
    ├── 02-gap-analysis/             # gaps by area (structural, security, operations, performance, FinOps)
    ├── 03-cost-drivers/             # 12-month trend, service/RG/resource breakdown, savings register
    ├── 04-architectural-critique/   # inferred evolution, decision-by-decision critique, target, roadmap
    └── 05-deep-dive/                # per-area technical detail + raw JSON evidence
```

Your account needs **Reader**, **Cost Management Reader** and **Security Reader** on each subscription.
Savings estimates are calculated in USD (list prices or actual `CostUSD`) and shown in the billing
currency at the subscription's implied exchange rate. Re-running a subscription replaces its folder; subscriptions
that share a display name get `<name>_<first 8 of ID>/` so they never overwrite each other.
Reports contain resource IDs and principal IDs - `reports/` is git-ignored. Entra ID (Graph) scanners
are skipped in this mode.

### 📐 ARG vs. Azure FinOps hubs

ARG does **not** use or require [FinOps hubs](https://learn.microsoft.com/cloud-computing/finops/toolkit/hubs/finops-hubs-overview)
from the Microsoft FinOps toolkit. It reads cost data **live** at scan time, straight from the Azure APIs:

- **Cost Management Query API** (`Microsoft.CostManagement/query`) - 12-month cost by service, and 30-day
  cost by resource group, meter and resource
- **Consumption Budgets API** (`Microsoft.Consumption/budgets`) - budgets and overspend
- **Azure Retail Prices API** (`prices.azure.com`, public, USD) - list prices for savings estimates
- **Resource Graph** and **Azure Monitor metrics** - inventory and 30-day usage for idle detection

The two tools answer different questions and work well together:

| | Azure FinOps hubs (FinOps toolkit) | ARG |
|---|---|---|
| What it is | A data platform you deploy into Azure (Storage/ADLS, Data Factory, optionally Data Explorer or Fabric, Power BI) | A read-only scanner: local CLI/portal or the Docker stack |
| Cost data | Scheduled Cost Management exports (FOCUS), ingested and retained | Live Cost Management API queries on each run |
| Scope | Billing account / enrollment, across many subscriptions and tenants | One or more subscriptions per run |
| History | As long as you retain it (beyond the 13-month API window) | About 12 months, as returned by the API at run time |
| Output | Dashboards and KQL/Power BI analytics: trends, showback/chargeback, commitment utilisation | Actionable findings (`F-nnn`) with CLI remediation, savings estimates, security and architecture review |
| Running cost | Ongoing Azure spend (storage, ADF, ADX/Fabric) and upkeep | None beyond API calls |

**Where ARG adds value:** FinOps hubs show *where the money goes over time*; ARG ties the cost of each
resource to *what it is actually doing* (30-day metrics such as storage transactions, SQL CPU/DTU and
connections, IoT devices/messages, backup protected items) and adds security and architecture findings,
so the output is a concrete action list per subscription.

**What ARG does not do:** long-term cost history, the FOCUS schema, enterprise-wide showback/chargeback
or Power BI reporting - use FinOps hubs for those. A possible future integration is reading costs from a
hub's Data Explorer / FOCUS exports when one exists, and falling back to the live API otherwise.

---

## 🐳 Docker Hub Images

**ARG 0.1** is published to Docker Hub as multi-arch images (`linux/amd64` + `linux/arm64`):

| Image | Tags |
|-------|------|
| `jahmed22/azure-resource-guardian-backend` | `0.1`, `latest` |
| `jahmed22/azure-resource-guardian-worker` | `0.1`, `latest` |
| `jahmed22/azure-resource-guardian-frontend` | `0.1`, `latest` |

### Run directly from Docker Hub (no source code needed)

```bash
# Download just the compose file and .env template
curl -O https://raw.githubusercontent.com/jahmed-cloud/ARG/main/docker-compose.hub.yml
curl -O https://raw.githubusercontent.com/jahmed-cloud/ARG/main/.env.example

# Configure
cp .env.example .env
nano .env   # set POSTGRES_PASSWORD, SECRET_KEY, ENCRYPTION_KEY, ADMIN_PASSWORD

# Start
docker compose -f docker-compose.hub.yml up -d

# UI → http://localhost:3000
# Log in with the ADMIN_EMAIL / ADMIN_PASSWORD you set in .env
# The admin account is created automatically on first startup - no manual command needed.
```

### Pull a specific version

```bash
docker pull jahmed22/azure-resource-guardian-backend:0.1
docker pull jahmed22/azure-resource-guardian-worker:0.1
docker pull jahmed22/azure-resource-guardian-frontend:0.1
```

---

## 🚀 Quick Start

### Prerequisites
- Docker Engine 24+ and the Docker Compose plugin
- Azure Service Principal with Reader + Cost Management Reader roles
- (Optional) Microsoft Graph API permissions for Entra ID module

#### Installing Docker on Ubuntu

If Docker isn't already installed:

```bash
# Remove any old/conflicting packages first
sudo apt-get remove docker docker-engine docker.io containerd runc

# Install via the official Docker apt repository
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

**Permissions:** by default only `root` can run Docker commands. Running every command with `sudo` works, but the more common approach is to add your user to the `docker` group so you don't need `sudo` for every command:

```bash
sudo usermod -aG docker $USER
newgrp docker          # or log out and back in for the group change to take effect
docker run hello-world # verify it works without sudo
```

Be aware that membership in the `docker` group is effectively root-equivalent on the host (containers can mount the host filesystem), so only add trusted users to it.

If you'd rather not modify group membership, just prefix every `docker compose` command below with `sudo`.

### 1. Clone the repository

```bash
git clone https://github.com/jahmed-cloud/ARG.git
cd ARG
```

### 2. Configure environment

```bash
cp .env.example .env
nano .env   # set POSTGRES_PASSWORD, SECRET_KEY, ENCRYPTION_KEY, ADMIN_PASSWORD at minimum
```

Generate secure values for the two secret keys rather than leaving the placeholders:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"   # -> SECRET_KEY
python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"  # -> ENCRYPTION_KEY
```

### 3. Build and start the stack

```bash
docker compose up -d --build
```

This builds the backend, worker, beat, and frontend images, then starts Postgres, Redis, and all five application services. The backend container automatically runs `alembic upgrade head` on startup, so the database schema is created the first time it boots - no manual migration step needed.

Check that everything came up healthy:

```bash
docker compose ps
docker compose logs -f backend   # watch startup logs; Ctrl+C to stop tailing
```

### 4. Access the dashboard

```
http://localhost:3000
```

Log in with the `ADMIN_EMAIL` and `ADMIN_PASSWORD` you set in `.env`.
The admin account is **created automatically on first startup** - no manual command needed.

Log in with the `ADMIN_USERNAME` / `ADMIN_PASSWORD` you set in `.env`. Change the password immediately if you left it at a placeholder value.

The backend API and interactive docs are available directly at `http://localhost:8000/docs` if you want to explore or test endpoints outside the UI.

### Stopping / resetting

```bash
docker compose down          # stop containers, keep data
docker compose down -v       # stop containers AND delete all data (Postgres/Redis volumes)
```

---

## 🔑 Azure Permissions Required

| Module | Required Role |
|---|---|
| Resource Discovery | Reader |
| Cost Analysis | Cost Management Reader |
| Entra ID Hygiene | Global Reader (Graph API) |
| Policy Compliance | Reader |
| Security | Security Reader |
| Metrics, diagnostic settings, SQL firewall rules, site config (posture scanners) | Reader |

These are **Azure AD / Azure RBAC roles** assigned to the Service Principal you register in ARG's Settings page - separate from the Linux/Docker permissions discussed above. To create the Service Principal and assign Reader access:

```bash
az ad sp create-for-rbac --name "arg-scanner" --role Reader --scopes /subscriptions/<subscription-id>
```

This prints a `appId` (client ID) and `password` (client secret) - enter those along with your Azure AD tenant ID into ARG's Settings → Azure Tenants page after logging in. The secret is encrypted with AES-256-GCM before being stored.

---

## 📁 Project Structure

```
arg/
├── frontend/          # React + TypeScript + Material UI
├── backend/           # FastAPI + Python 3.12
├── workers/           # Celery worker definitions
├── scanners/          # Plugin-based scanner framework
│   ├── base/          # BaseScanner, PostureScanner, shared Azure API helpers
│   ├── compute/       # VM, disk, snapshot, App Service scanners
│   ├── network/       # IP, NIC, LB, NSG, DDoS, DNS scanners
│   ├── storage/       # Storage account scanners
│   ├── database/      # SQL, Hyperscale, Cosmos DB scanners
│   ├── cost/          # IoT, AI spend, commitment-discount scanners
│   ├── identity/      # Entra ID scanners
│   ├── governance/    # Tags, naming, policy, observability, budget scanners
│   ├── security/      # Security posture, Defender, RBAC scanners
│   └── terraform/     # Drift detection scanners
├── reports/           # Report generation engine
├── docs/              # User guide, PRD, scanner catalog (docs/README.md)
├── scripts/           # subscription_analysis CLI, local_portal, launchers (*.ps1, *.sh)
├── docker/            # Dockerfiles
├── helm/              # Helm charts for Kubernetes
├── terraform/         # Infrastructure as Code
└── tests/             # Unit, integration, e2e tests
```

---

## 🛠️ Development

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend
cd frontend
npm install
npm run dev

# Run all tests (unit tests run offline against the scanners' mock data)
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
make test
```

---

## 🤝 Contributing

Contributions are welcome - bug reports, scanner additions, and pull requests all help.

1. Fork the repo and create a feature branch off `main`
2. Keep changes focused - one feature or fix per PR makes review much faster
3. Test against a real `docker compose up --build` before opening a PR, not just `import` checks
4. Open a PR describing what changed and why

If you're adding a new scanner, follow the existing pattern in `scanners/` (subclass `BaseScanner`, register via `@register_scanner`, and provide a mock-data fallback so the scanner is testable without live Azure credentials).

For bugs or feature requests, open an issue on [GitHub](https://github.com/jahmed-cloud/ARG/issues).

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🗺️ Roadmap

See [ROADMAP.md](ROADMAP.md) for what's planned next.

---

## 👤 About / Author

Azure Resource Guardian was designed and built by **Junaid Ahmed**.

- Website: [jahmed.cloud](https://jahmed.cloud)
- GitHub: [github.com/jahmed-cloud](https://github.com/jahmed-cloud) · [ARG repository](https://github.com/jahmed-cloud/ARG)
- Docker Hub: [hub.docker.com/repositories/jahmed22](https://hub.docker.com/repositories/jahmed22)
- Email: [iam@jahmed.cloud](mailto:iam@jahmed.cloud)

This same information is also available in-app under **Settings → About**.

---

*Built for Azure engineers who want real visibility into their cloud estate without paying for another SaaS subscription.*
