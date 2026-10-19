# Azure DevOps: repository, pipeline and source-control rules

How to host the ARG repository in Azure DevOps (instead of, or next to, GitHub), how the validation pipeline is set
up, and what must stay on your machine. Requirements: [prerequisites.md](prerequisites.md#d-azure-devops).

## 1. What is in the repository and what is not

**In the repository:** application code (`backend/`, `workers/`, `scanners/`, `frontend/`, `scripts/`), tests,
Docker and Compose files, the pipeline definition (`azure-pipelines.yml`), documentation and branding.

**Never in the repository** (enforced by [.gitignore](../.gitignore); the same paths are in
[.dockerignore](../.dockerignore) so they never reach an image either):

| Kind | Paths | Why |
|---|---|---|
| Secrets | `.env`, `.env.*`, `*.key`, `*.pem`, `secrets/` | Database, JWT and encryption keys, client secrets |
| Analysis output | `reports/` | Resource IDs, IP addresses, principal IDs, costs |
| AI-assistant tooling | `.claude/`, `.copilot/`, `.cursor/`, `AGENTS.md`, `CLAUDE.md`, `MEMORY.md` | Personal working aids, not part of the product |
| One-off bug-fix and investigation scripts | `scratch/`, `tmp/`, `local/`, `scripts/local/`, `*.local.ps1`, `*.local.py`, `*.local.sh`, `*.local.md` | Throw-away helpers; put anything you write to reproduce or patch a problem in one of these |
| Environments and caches | `.venv/`, `.venv-local/`, `node_modules/`, `frontend/dist/`, `.pytest_cache/`, `.ruff_cache/`, `__pycache__/` | Rebuilt on every machine |

Before committing, `git status --short` should list only files you meant to change. To check that nothing ignored is
tracked: `git ls-files -ci --exclude-standard` must print nothing.

`.github/` is tracked: it holds the GitHub Actions workflow (`.github/workflows/validate.yml`, the same checks as
the Azure DevOps pipeline) and the Copilot skill for ARG (`.github/skills/arg-subscription-analysis/`). Azure DevOps
ignores both.

## 2. First push of an existing local repository

Create an **empty** Git repository in the Azure DevOps project (no README, no .gitignore), then from the ARG folder:

```powershell
git remote add origin https://dev.azure.com/<organisation>/<project>/_git/<repository>
git push -u origin main
```

Authenticate with the Git Credential Manager (installed with Git for Windows) or a personal access token with
**Code (Read & write)** scope. Push other branches only when they should be shared (`git push -u origin <branch>`).

Before the first push, check for anything that must not be published - also in history:

```powershell
git ls-files -ci --exclude-standard                                  # tracked files that should be ignored: none
git log --all --oneline -- .env MEMORY.md reports                     # never committed: no output
git grep -nE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" $(git rev-list --all) -- . ':!frontend/package-lock.json'
```

The GUIDs ARG itself contains are Azure built-in role and policy definition IDs (the same in every tenant) and
dummy test values; anything else (tenant or subscription IDs) should be replaced with a placeholder.

## 3. Validation pipeline

[azure-pipelines.yml](../azure-pipelines.yml) runs on every push and on pull requests into `main`. It deploys nothing
and needs no service connection or secret.

| Job | What it checks |
|---|---|
| Python tests and lint | Installs the pinned requirements, `pip check`, `ruff check --select F,E9` (errors, unused imports and variables), `pytest tests` (offline; results published to the Tests tab) |
| Frontend build | `npm ci` and `npm run build` (TypeScript type check and Vite production build) |
| Container smoke test | Generates a throw-away `.env`, validates the Compose files, builds and starts the stack, checks API and nginx health, the database migration and a Celery worker ping, then removes everything |

Set it up once:

1. **Pipelines - New pipeline - Azure Repos Git** - select the repository.
2. **Existing Azure Pipelines YAML file** - branch `main`, path `/azure-pipelines.yml` - **Run**.
3. Rename the pipeline (for example `ARG validate`).

For a self-hosted agent, it needs Python 3.12, Node 20, Docker with the Compose plugin and `curl`.

## 4. Branch policy for `main`

**Repos - Branches - `main` - Branch policies:**

- **Require a minimum number of reviewers:** 1 (allow requestors to approve their own changes only for a one-person team).
- **Build validation:** add the `ARG validate` pipeline, trigger automatic, policy requirement required.
- **Limit merge types:** squash merge or rebase and fast-forward, to keep history linear.
- Optional: **Check for linked work items** and **Check for comment resolution**.

## 5. Day-to-day workflow

```powershell
git switch main; git pull
git switch -c feature/<short-name>                  # or fix/<short-name>
# ... change code, then validate locally (see docs/local-development.md)
git add -A; git status --short                       # only intended files
git commit -m "feat: <what and why>"                 # conventional prefix: feat:, fix:, docs:, chore:
git push -u origin feature/<short-name>
```

Open a pull request into `main` in Azure DevOps; the pipeline runs and must pass before completing it. Update
[CHANGELOG.md](../CHANGELOG.md) (under *Unreleased*) and the affected documentation in the same pull request.

## 6. Using ARG as a gate in other pipelines

This file is about the ARG repository's own pipeline. To run ARG **inside other teams' pipelines** (fail a build
on high findings, publish SARIF / JUnit) see [ci-cd.md](ci-cd.md#azure-devops).
