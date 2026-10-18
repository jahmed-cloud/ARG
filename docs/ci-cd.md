# ARG in CI/CD pipelines

ARG can run inside a pipeline and stop the build when serious findings remain. There are three ways to plug it in:

| Way | Runs where | Authentication | Best for |
|---|---|---|---|
| **CLI** (`python -m scripts.subscription_analysis`) | any pipeline agent | the pipeline's Azure login (OIDC / workload identity) | scheduled or per-change gates on one or more subscriptions |
| **Docker stack API** (`/api/v1`) | the shared ARG server | personal API key `arg_...` | gating on findings the server already collects (daily scan), triggering scans |
| **Local portal API** (`http://127.0.0.1:8765/api/v1`) | the same machine as the portal | `ARG_PORTAL_API_TOKEN` | scripts and self-hosted agents on an engineer's or a build VM |

Everything is read-only against Azure. CI artefacts (SARIF, JUnit, JSON, reports) contain resource IDs: keep them
inside the organisation, with short artefact retention, like the reports themselves.

## 1. CLI gate

```bash
pip install -r requirements-local.txt
az login ...    # or the pipeline's Azure login task (see below)
python -m scripts.subscription_analysis -s "<subscription name or ID>" \
  --fail-on high \
  --gate-ignore missing_required_tags,naming_convention_violation \
  --sarif arg.sarif --junit arg-junit.xml --ci-json arg-gate.json
```

| Option | What it does |
|---|---|
| `--fail-on {critical,high,medium,low,info}` | exit code **2** when findings at or above this severity remain |
| `--gate-ignore TYPES` | comma-separated finding types the gate ignores (they stay in the report) |
| `--sarif FILE` | SARIF 2.1.0: one rule per finding type, one result per finding, stable fingerprints (resource + type) |
| `--junit FILE` | JUnit XML: one test suite per subscription, one test case per finding type; blocking types fail |
| `--ci-json FILE` | gate result, totals and the first 50 blocking findings per subscription |
| `--gate-only` | evaluate existing report folders only (no Azure calls), e.g. after a portal run or in a later stage |

Exit codes: `0` passed (or no gate), `1` an analysis failed (artefacts are still written), `2` the gate failed.
All other options (`--all`, `--parallel`, `--skip-cost`, `--pdf`, `--auth default`) work as usual.

On GitHub Actions (`GITHUB_ACTIONS`) blocking findings become `::error` annotations and the totals go to the job
summary. On Azure DevOps (`TF_BUILD`) they become `##vso[task.logissue]` errors and `arg-summary.md` is attached to
the run summary.

The pipeline identity needs the same roles as a person: **Reader**, **Cost Management Reader** and **Security
Reader** on each subscription. ARG does not create identities or role assignments - ask the platform team for a
federated (secretless) identity.

### GitHub Actions

```yaml
name: ARG gate
on:
  schedule: [{ cron: '0 5 * * 1' }]
  workflow_dispatch:
permissions:
  id-token: write          # OIDC login to Azure
  contents: read
  security-events: write   # SARIF upload
jobs:
  arg:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # the ARG repository
      - uses: actions/setup-python@v5
        with: { python-version: '3.12', cache: pip, cache-dependency-path: requirements-local.txt }
      - run: pip install -r requirements-local.txt
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          allow-no-subscriptions: true
      - name: Analyse and gate
        run: >
          python -m scripts.subscription_analysis -s "${{ vars.B_ARG_SUBSCRIPTION }}"
          --fail-on high --sarif arg.sarif --junit arg-junit.xml --ci-json arg-gate.json
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: arg.sarif, category: arg }
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: arg
          retention-days: 14
          path: |
            reports/
            arg*
```

SARIF results point at the report page of each finding (`reports/<subscription>/05-deep-dive/<area>/README.md`);
the reports are not part of the repository, so code scanning shows the alert without a file preview. The resource ID
is in the alert's logical location and properties.

### Azure DevOps

```yaml
schedules:
  - cron: '0 5 * * 1'
    displayName: Weekly ARG gate
    branches: { include: [main] }
pool: { vmImage: ubuntu-latest }
steps:
  - task: UsePythonVersion@0
    inputs: { versionSpec: '3.12' }
  - script: pip install -r requirements-local.txt
  - task: AzureCLI@2
    displayName: Analyse and gate
    inputs:
      azureSubscription: arg-reader          # workload identity federation service connection
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: >
        python -m scripts.subscription_analysis -s "$(B_ARG_SUBSCRIPTION)"
        --fail-on high --junit $(Build.ArtifactStagingDirectory)/arg-junit.xml
        --sarif $(Build.ArtifactStagingDirectory)/CodeAnalysisLogs/arg.sarif
        --ci-json $(Build.ArtifactStagingDirectory)/arg-gate.json
  - task: PublishTestResults@2
    condition: always()
    inputs: { testResultsFormat: JUnit, testResultsFiles: '$(Build.ArtifactStagingDirectory)/arg-junit.xml', testRunTitle: ARG }
  - task: PublishBuildArtifacts@1
    condition: always()
    inputs: { PathtoPublish: '$(Build.ArtifactStagingDirectory)', ArtifactName: CodeAnalysisLogs }
```

The `CodeAnalysisLogs` artefact is what the Azure DevOps SARIF SAST Scans Tab extension reads.

## 2. Docker stack API

Create a key in **Settings → API keys (CI/CD)**. The key is shown once; store it as a pipeline secret
(`B_ARG_API_KEY`). It acts as you - same role and subscriptions - expires after 30-365 days and can be revoked
there. A key cannot create or list keys. Send it as `Authorization: Bearer arg_...` (or `X-API-Key: arg_...`); every
`/api/v1` endpoint accepts it, and the OpenAPI document is at `/api/v1/openapi.json`.

```bash
API="$B_ARG_URL/api/v1"; AUTH="Authorization: Bearer $B_ARG_API_KEY"

# Optional: start a scan (role analyst or above) and wait for it
SCAN=$(curl -sf -X POST -H "$AUTH" -H 'Content-Type: application/json' "$API/scans/start" \
  -d '{"scope": {"subscription_ids": ["<azure-subscription-guid>"]}}' | jq -r .id)
until [[ "$(curl -sf -H "$AUTH" "$API/scans/$SCAN" | jq -r .status)" =~ ^(completed|failed|cancelled)$ ]]; do sleep 30; done

# Gate: open findings at or above high, ignoring tag hygiene
curl -sf -H "$AUTH" "$API/findings/gate?fail_on=high&azure_subscription_id=<guid>&ignore=missing_required_tags" \
  | tee arg-gate.json | jq -e '.passed' > /dev/null
```

`GET /findings/gate` parameters: `fail_on` (default `high`), `ignore` (finding types), `status` (default `open`;
repeatable), `subscription_id` (ARG ID) or `azure_subscription_id` (Azure GUID), `category`. It always answers
HTTP 200 with `passed`, `blocking`, `total`, `findings_by_severity` and up to 50 `blocking_findings`; a subscription
the key cannot see is a 404, never a silent pass. Use `GET /findings?...` for the full list.

## 3. Local portal API

Start the portal with a token (24+ characters) and call it from the same machine:

```powershell
$env:ARG_PORTAL_API_TOKEN = '<long random value>'
.\scripts\Start-LocalPortal.ps1
$h = @{ Authorization = "Bearer $env:ARG_PORTAL_API_TOKEN" }
Invoke-RestMethod http://127.0.0.1:8765/api/v1/analyses -Method Post -Headers $h `
  -ContentType 'application/json' -Body '{"subscriptions": ["<name or ID>"]}'
Invoke-RestMethod "http://127.0.0.1:8765/api/v1/reports/<name or ID>/gate?fail_on=high" -Headers $h
```

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/subscriptions` | subscriptions visible to the `az login` session, with their report folder |
| `POST /api/v1/analyses` `{"subscriptions": [...]}` | queue analyses (names or IDs); `GET /api/v1/analyses[/{id}]` for status |
| `GET /api/v1/reports[/{key}]` | report summaries; `key` = folder, subscription ID or display name |
| `GET /api/v1/reports/{key}/findings` | findings, `min_severity`, `finding_type`, `limit`, `offset` |
| `GET /api/v1/reports/{key}/gate` | gate result, `fail_on`, `ignore` |
| `GET /api/v1/reports/{key}/sarif`, `/junit` | the same artefacts as the CLI |
| `GET /api/v1/openapi.json` | OpenAPI document of the endpoints above |

The token only opens `/api/*`, never the HTML portal; the portal still listens on loopback only and keeps its
cross-origin checks. Without `ARG_PORTAL_API_TOKEN` the API works with the browser session only.

## 4. AI prompt (API only)

Every report folder also contains `ai-prompt.md`: review instructions, the subscription context and the findings
(most severe first, at most 10 per finding type, GUIDs replaced by `<id-1>`, `<id-2>`, ...). Paste it into the AI
assistant your organisation approves; it is not linked from the UI. The same prompt is
available from `GET /api/v1/reports/{key}/ai-prompt` (local portal; `min_severity`, `max_findings`,
`mask_ids`, `download=1`) and `GET /api/v1/findings/ai-prompt` (Docker stack; the findings-list filters). Use approved
tools only and verify any AI suggestion before changing a resource.
