# PRD — Subscription Analysis (local CLI & portal)

Status: implemented (branch `feature/subscription-analysis-parity`). User guide: [subscription-analysis.md](./subscription-analysis.md).

## Problem Statement

Cloud architects and FinOps analysts are asked to review an Azure subscription: what exists, what's wrong with it,
why it costs what it costs, and what should have been built instead. Today that review is manual. Someone queries
Resource Graph, Cost Management, Azure Monitor, Defender and Advisor by hand, reconciles the numbers, and writes the
report. A single subscription takes a day or more, the results can't be repeated, and the next subscription starts
from zero.

ARG could not help with this. Its original 31 scanners covered only a handful of the findings a real review produces
(orphaned NICs, unattached IPs, public SQL/blob, missing tags). It also required the Docker stack with a **service
principal**, which many engineers aren't allowed to create in their tenant. They can sign in with their own account via
`az login`, but ARG had no way to use that. The output lived in a database and UI, not as documents that can be filed
with a customer, reviewed in a pull request or read offline.

## Solution

1. **Broader detection:** 31 new posture and FinOps scanners, so every finding of a manual subscription review is
   produced automatically (62 scanners in total). Examples: DDoS plans protecting nothing, prod/non-prod sharing a plan,
   EOL runtimes and OS images, SQL firewall and Entra auth, Hyperscale legacy pricing, storage/Key Vault/AI hardening,
   Defender, RBAC, observability gaps, budgets, AI spend and commitment discounts.
2. **Your own account:** a command-line analysis that runs on the engineer's workstation with their `az login`
   session. There's no Docker, database or service principal.
3. **A document-shaped result:** each subscription is written as a folder of markdown files (executive summary,
   current findings, gap analysis, cost drivers, architectural critique, deep dives, raw JSON evidence), plus an index
   across subscriptions.
4. **A small local portal** on `127.0.0.1` with a simple local login. It lists the subscriptions the CLI account can
   see, runs analyses with live progress, and renders the reports in the browser. The portal never signs in to Azure.
5. The same scanners also run in the Docker stack. The worker gets an ARM client, so live scans get metric-verified
   and configuration-verified findings.

## User Stories

1. As a cloud architect, I want to analyse a subscription with my own `az login`, so that I don't need a service principal I'm not allowed to create.
2. As a cloud architect, I want one command to analyse a subscription by name or ID, so that I don't have to look up GUIDs.
3. As a cloud architect, I want to analyse several subscriptions or all enabled subscriptions in one run, so that I can review a whole estate.
4. As a cloud architect, I want each subscription written to its own folder, so that I can file, share and diff reviews per subscription.
5. As a cloud architect, I want an index of all analysed subscriptions with cost, critical/high counts and savings, so that I can prioritise which to look at first.
6. As a cloud architect, I want the launch scripts to work from any folder, so that I don't have to remember where the repository lives.
7. As a cloud architect, I want reports to default to the repository's `reports` folder, so that I always know where to find them.
8. As a FinOps analyst, I want a 12-month cost trend and a 30-day breakdown by service, resource group and resource, so that I can explain why the subscription costs what it does.
9. As a FinOps analyst, I want every inefficiency to carry an estimated monthly saving, so that I can size the opportunity.
10. As a FinOps analyst, I want savings grouped into no-regret cleanup, optimisation and structural waves, so that I can plan the work in the right order.
11. As a FinOps analyst, I want savings shown in the billing currency as well as USD, so that the numbers match the invoice.
12. As a FinOps analyst, I want to know when a DDoS Network Protection plan protects no VNet or public IP, so that I can remove a large fixed cost.
13. As a FinOps analyst, I want previous-generation App Service plans flagged with the saving of moving to Premium v3, so that I can modernise and reserve.
14. As a FinOps analyst, I want Hyperscale databases on the legacy storage meter flagged, so that I can ask Microsoft about current pricing.
15. As a FinOps analyst, I want idle storage accounts, IoT Hubs, Cosmos DB accounts and SQL databases detected from real metrics, so that I don't delete something in use.
16. As a FinOps analyst, I want storage-account sprawl and transaction hotspots highlighted, so that I can consolidate and choose the right billing model.
17. As a FinOps analyst, I want material Azure OpenAI / Foundry spend without an AI gateway flagged, so that I can introduce quotas and caching.
18. As a FinOps analyst, I want budgets that are exceeded month after month (counted from the budget's start date) reported, so that I can fix the feedback loop.
19. As a FinOps analyst, I want Advisor reservation and savings-plan recommendations de-duplicated, so that commitments aren't double-counted.
20. As a security engineer, I want management ports open to the Internet reported, with latent vs effective exposure distinguished, so that I can prioritise.
21. As a security engineer, I want VMs on end-of-support images and VMs with public IPs next to Bastion flagged, so that I can remove unmanaged entry points.
22. As a security engineer, I want SQL "Allow Azure services", wide ranges and ad-hoc single-IP firewall rules reported, so that the data plane isn't open to any tenant.
23. As a security engineer, I want SQL servers without Entra-only auth or with an individual Entra admin reported, so that access is identity-based and survives staff changes.
24. As a security engineer, I want storage shared-key access, open networks and disabled soft delete reported, so that customer data is protected.
25. As a security engineer, I want Key Vaults on access policies, without soft delete or purge protection, or open to all networks reported, so that secrets are governed by RBAC.
26. As a security engineer, I want AI Services accounts with key authentication or open networks reported, so that model access is attributable.
27. As a security engineer, I want web apps allowing HTTP, weak TLS, FTP, EOL runtimes or no managed identity reported, so that apps are patched and secretless.
28. As a security engineer, I want Defender plans left on Free (where matching resources exist), the secure score and High-severity Defender recommendations imported, so that the review includes Microsoft's own assessment.
29. As a security engineer, I want excess subscription Owners, standing User Access Administrator and privileged service principals reported, so that I can move them to PIM.
30. As an operations engineer, I want Log Analytics daily caps that silently drop data flagged, so that telemetry isn't lost during incidents.
31. As an operations engineer, I want App Insights components linked to deleted workspaces found, so that broken telemetry is repaired.
32. As an operations engineer, I want missing diagnostic settings verified per resource, not guessed, so that the list is accurate.
33. As an operations engineer, I want a missing Service Health alert reported, so that platform incidents reach someone.
34. As an architect, I want production and non-production sharing one App Service plan detected, so that I can isolate environments.
35. As an architect, I want CPU-saturated plans and databases reported, so that I can separate load before scaling.
36. As an architect, I want app and data tiers in different regions detected, so that I can remove cross-region latency and egress.
37. As an architect, I want resources whose name says dev/test but whose tag says prod (and the reverse) reported, so that mislabelled production systems are found.
38. As an architect, I want tag-key typos, empty resource groups and unused Private Link zones reported, so that governance policies apply cleanly.
39. As an architect, I want many unrelated workloads in one subscription flagged, so that I can argue for landing-zone subscriptions.
40. As an architect, I want an architectural critique that explains the likely rationale, why it falls short and the alternatives for each design decision, so that the review goes beyond a findings list.
41. As an architect, I want an inferred timeline of how the estate evolved from resource creation dates, so that I can explain how it got here.
42. As an architect, I want a target architecture and a phased roadmap tied to the savings waves, so that stakeholders see where to go next.
43. As a reviewer, I want every finding to carry evidence, remediation steps and CLI commands, so that I can verify and act on it.
44. As a reviewer, I want remediation commands never executed by the tool, so that the analysis is safe to run in production.
45. As a reviewer, I want raw JSON for inventory, cost, findings and scanner runs, so that every number in the report can be traced.
46. As a reviewer, I want collection warnings (missing roles, throttling, skipped scanners) listed in the report, so that I know what's incomplete.
47. As a portal user, I want to open a local web page and sign in with a simple password, so that I can use the tool without the terminal.
48. As a portal user, I want to see which Azure account and tenant the CLI session uses, so that I know whose permissions apply.
49. As a portal user, I want clear guidance when `az login` is missing or expired, so that I can fix it myself.
50. As a portal user, I want to pick subscriptions, start analyses and watch progress, so that I know when the report is ready.
51. As a portal user, I want to browse the generated markdown with navigation, rendered tables and diagrams, so that I can read reviews comfortably.
52. As a portal user, I want the portal reachable only from my machine and protected against cross-site requests, so that nobody else can read or trigger reports.
53. As a portal user, I want report content from Azure rendered safely, so that a malicious tag can't inject script.
54. As a platform operator of the Docker stack, I want the new scanners to run in scheduled scans, so that the UI shows the same findings as the local report.
55. As a contributor, I want new scanners to follow one base class with a mock fallback, so that they're testable offline.
56. As a contributor, I want a generated scanner catalog, so that documentation doesn't drift from the code.

## Implementation Decisions

- **Scanner framework stays the same.** New scanners subclass a thin posture base (`BaseScanner` plus paginated
  Resource Graph with mock fallback, a live-mode check, and a subscription-level finding helper) and self-register.
  At most one finding per (resource, finding type), because the worker upserts on that pair. Per-rule and
  per-subnet details go into evidence.
- **Shared Azure API module:** paginated Resource Graph (optionally tenant-wide), an ARM REST client (GET, paging,
  POST, Azure Monitor metrics summary, Cost Management query), and helpers. Cost Management asks for `CostUSD`
  and falls back to billing currency only. There's 429/503 retry honouring `Retry-After` and the Cost Management
  rate-limit headers, a per-scan cache for per-resource cost and metric series, Defender plan lookup, and the public
  Retail Prices API. Retail prices are used in live mode only; offline tests use static fallback prices.
- **Scan context** gains an ARM client slot and a per-scan cache. The Docker worker injects the ARM client, so live
  scans verify metrics and configuration. Two existing scanners (unused storage, diagnostic settings) now verify
  instead of guessing, and fall back to the old advisory behaviour without live access.
- **Live vs mock:** without clients, scanners return their mock rows. That's the existing contract, and it keeps unit
  tests offline and deterministic.
- **Savings are in USD** (actual `CostUSD` or list price). Reports convert to billing currency at the
  subscription's implied rate (30-day cost ÷ 30-day `CostUSD`).
- **Report generator** is data-driven. A knowledge table maps each finding type to a gap area, a deep-dive folder, a
  savings wave and an architectural-critique key. Critique text (likely rationale, shortcomings, alternatives) is static
  knowledge, rendered only for decisions the findings point at. The "why" is labelled as inferred.
- **Folder contract:** `reports/<subscription>/` holds `README.md`, `summary.json` and `01-…` to `05-…`.
  `reports/README.md` indexes all subscriptions. Re-runs remove previously generated entries first. The folder name
  is the display name made filesystem-safe.
- **Authentication:** Azure CLI credential by default (`DefaultAzureCredential` optional, for automation). No
  interactive Azure sign-in exists anywhere in the local tooling. The portal caches CLI tokens per scope until
  shortly before expiry, so it doesn't spawn `az` for every call.
- **Portal:** a FastAPI app bound to loopback only. There's a single local user (env vars or a one-time password),
  in-memory sessions with an HttpOnly/SameSite=Strict cookie, Host allow-list, same-origin check on state-changing
  requests, and a strict CSP with no inline script. Markdown is rendered server-side with raw HTML neutralised except
  the few tags the generator emits. Analyses run on a small thread pool (default 2) with in-memory progress.
  Subscriptions can only be analysed if the CLI session can see them.
- **Launchers:** a PowerShell module bootstraps `.venv-local` from `requirements-local.txt` and checks the CLI
  session. Portal and CLI launchers work from any folder and resolve relative report paths from the caller's
  folder. There's a bash launcher for Linux/macOS, and make targets for portal, analyze and analyze-all.
- **Dependencies:** a minimal `requirements-local.txt` (identity, Resource Graph, httpx, FastAPI/uvicorn, Jinja2,
  python-multipart, markdown). Docker requirements are unchanged.

## Testing Decisions

- Good tests assert **external behaviour**: finding types, severities, savings and titles produced from given input
  rows; report files and their key content; HTTP status codes and redirects from the portal. They don't assert internal
  call sequences.
- **Scanners:** every new scanner runs in mock mode and must produce its expected finding types with no warnings,
  and at most one finding per resource and type. Detection helpers are tested directly: port-range coverage,
  Internet-source rules, OS/runtime end-of-support tables, SQL firewall classification, environment inference,
  tag-typo distance, storage account families, metric summarisation. Behavioural cases: latent vs effective RDP,
  Pv2→Pv3 saving, Hyperscale price ratio, budget months counted from the budget start, commitment de-duplication,
  `as_of` date handling.
- **Live helpers** are tested with a fake ARM client, which proves metric and cost caching per scan.
- **Report generator** is tested end-to-end from mock scanner output plus synthetic inventory and cost: the folder
  structure exists, key sections are present, references are unique, and the knowledge table is consistent.
- **Portal** is tested with FastAPI's test client, a fake CLI session and a fake job runner: login required, wrong
  password rejected, cross-origin and foreign-Host requests rejected, unknown subscriptions refused, the job writes
  the folder and index, reports render, path traversal is blocked, markdown sanitisation works, token caching works.
- Prior art: the existing scanners' mock-data convention. Everything runs offline via `make test`.
- Live verification was done manually against a real subscription through the CLI, the PowerShell launcher from
  another folder, and the portal in a browser.

## Out of Scope

- Microsoft Graph (Entra ID) scanners in local mode. They need Graph consent and stay Docker-only.
- Executing any remediation. Commands are for review only.
- Report history or diffing between runs. A re-run replaces the folder.
- Multi-user portal, remote access, SSO for the portal, or persistent job history across restarts.
- Showing the local markdown report inside the Docker React UI (listed in ROADMAP).
- Exchange-rate services. The implied rate from Cost Management is used.
- Regulatory-compliance standards and attack paths from Defender.

## Further Notes

- The inferred "why" in the critique is a hypothesis to confirm with workload owners. It isn't a fact from ADRs.
- The Hyperscale legacy-pricing saving must be validated with Microsoft or the CSP before acting.
- AI spend savings are an estimate (15% from caching and routing) and are labelled as such.
- Reports contain resource IDs, IPs and principal IDs. They're treated as internal and are git-ignored.
