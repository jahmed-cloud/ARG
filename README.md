# 🛡️ Azure Resource Guardian (ARG)

> **Discover. Govern. Optimize.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://reactjs.org)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg)](https://www.docker.com)
[![Docker Hub](https://img.shields.io/badge/Docker_Hub-jahmed22-2496ED.svg)](https://hub.docker.com/repositories/jahmed22)
[![GitHub Actions](https://img.shields.io/badge/CI-GitHub_Actions-2088FF.svg)](https://github.com/features/actions)

**Azure Resource Guardian** is a self-hosted, Docker-based, open-source Azure governance platform that gives organizations a single-pane-of-glass view across their entire Azure estate.

---

## 🎯 What Problems Does ARG Solve?

| Question | ARG's Answer |
|---|---|
| What resources are costing money unnecessarily? | Cost Optimization Engine with Azure Cost Management integration |
| Which resources are orphaned? | 15+ orphan scanners across Compute, Network, Storage, Database |
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

### 💀 Orphan Detection (15+ scanners)
- Unattached managed disks, old snapshots, deallocated VMs
- Unused public IPs, orphaned NICs, empty load balancers
- Unused storage accounts, orphaned backups
- Idle SQL databases, underutilized flexible servers

### 💰 Cost Optimization
- Azure Cost Management integration
- Per-resource monthly/annual savings estimates
- Top 10 cost-saving opportunities dashboard
- Cost trend analysis

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
- Governance Score (0–100)

### 🔒 Security
- Public storage accounts, SQL servers, Key Vaults
- Disabled Defender plans
- Missing backup configurations
- Expired certificates
- Missing diagnostic settings
- Security Score (0–100)

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

This builds the backend, worker, beat, and frontend images, then starts Postgres, Redis, and all five application services. The backend container automatically runs `alembic upgrade head` on startup, so the database schema is created the first time it boots — no manual migration step needed.

Check that everything came up healthy:

```bash
docker compose ps
docker compose logs -f backend   # watch startup logs; Ctrl+C to stop tailing
```

### 4. Create the initial admin user

```bash
docker compose exec backend python -m scripts.seed_admin
```

This is idempotent — safe to re-run; it does nothing if the admin user already exists.

### 5. Access the dashboard

```
http://localhost:3000
```

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

These are **Azure AD / Azure RBAC roles** assigned to the Service Principal you register in ARG's Settings page — separate from the Linux/Docker permissions discussed above. To create the Service Principal and assign Reader access:

```bash
az ad sp create-for-rbac --name "arg-scanner" --role Reader --scopes /subscriptions/<subscription-id>
```

This prints a `appId` (client ID) and `password` (client secret) — enter those along with your Azure AD tenant ID into ARG's Settings → Azure Tenants page after logging in. The secret is encrypted with AES-256-GCM before being stored.

---

## 📁 Project Structure

```
arg/
├── frontend/          # React + TypeScript + Material UI
├── backend/           # FastAPI + Python 3.12
├── workers/           # Celery worker definitions
├── scanners/          # Plugin-based scanner framework
│   ├── base/          # BaseScanner abstract class
│   ├── compute/       # VM, disk, snapshot scanners
│   ├── network/       # IP, NIC, LB scanners
│   ├── storage/       # Storage account scanners
│   ├── identity/      # Entra ID scanners
│   ├── governance/    # Tags, naming, policy scanners
│   ├── security/      # Security posture scanners
│   └── terraform/     # Drift detection scanners
├── reports/           # Report generation engine
├── docs/              # Documentation
├── scripts/           # Utility scripts
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

# Run all tests
make test
```

---

## 🤝 Contributing

Contributions are welcome — bug reports, scanner additions, and pull requests all help.

1. Fork the repo and create a feature branch off `main`
2. Keep changes focused — one feature or fix per PR makes review much faster
3. Test against a real `docker compose up --build` before opening a PR, not just `import` checks
4. Open a PR describing what changed and why

If you're adding a new scanner, follow the existing pattern in `scanners/` (subclass `BaseScanner`, register via `@register_scanner`, and provide a mock-data fallback so the scanner is testable without live Azure credentials).

For bugs or feature requests, open an issue on [GitHub](https://github.com/jahmed-cloud/ARG/issues).

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

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
