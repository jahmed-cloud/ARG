# Azure Policy governance

ARG checks whether Azure Policy is actually doing its job on each subscription, not only what is assigned. Everything
here is read-only: Azure Resource Graph queries (`policyresources`, `resourcecontainers`, `resources`) with the
scanner's Reader access. Nothing is assigned, exempted or remediated by ARG.

| Need | Where |
|---|---|
| Find policies that exist but do nothing, exemptions nobody reviews, remediation that never ran | [Scanners](#scanners) (every scan) |
| "My deployment was blocked - which policy, assigned where, and am I exempt?" | [What governs this resource?](#what-governs-this-resource) (Governance page, API, CLI) |
| Rebuild the list of policy objects a deployment tool owns after its state is lost | [Find policy objects by `managedBy`](#find-policy-objects-by-managedby) (CLI) |
| Check that every VM carries the agents the organisation requires | [Required VM extensions](#required-vm-extensions) (opt-in scanner) |
| Look up a hard Azure Policy limit (assignments per scope, rule size, ...) | [Azure Policy limits](azure-policy-limits.md) |

## Permissions

Reader on the subscription **and on the management groups above it** - assignments and exemptions inherited from a
management group are only visible with read access there. With subscription-only Reader the scanners still run, but
inherited assignments are missing, so "no assignment applies" can be a false alarm.

## Scanners

All six share one policy snapshot per subscription (assignments on the subscription, its resource groups and
resources, and every ancestor management group; exemptions on the same scopes; compliance summary; remediation tasks).

| Scanner | Finding type | Why it matters |
|---|---|---|
| `policy_assignment_scanner` | `no_policy_assignments` | Nothing is assigned on the subscription or above it: no guardrail is evaluated |
| | `policy_assignments_not_enforced` | `DoNotEnforce`: Deny does not block and DeployIfNotExists / Modify do not deploy on create |
| `policy_exemption_scanner` | `policy_exemption_no_expiry` | Unbounded risk acceptance; compliance still counts the resources as covered |
| | `policy_exemption_expired` | No longer applies, still clutters the estate |
| | `policy_exemption_orphaned` | Points at an assignment that no longer exists |
| | `policy_exemption_whole_initiative` | Switches off every control in an initiative, not just the one that needed an exception |
| `policy_remediation_scanner` | `policy_remediation_never_run` | DeployIfNotExists / Modify only act on create or update; existing resources stay non-compliant until a remediation task runs (e.g. tags inherited from a subscription never reach existing resources) |
| `policy_effectiveness_scanner` | `policy_definition_mode_skips_containers` | A custom definition in `Indexed` mode that targets resource groups or subscriptions - Indexed never evaluates them, so the policy does nothing |
| | `allowed_locations_skip_resource_groups` | "Allowed locations" is Indexed and ignores resource groups; without "Allowed locations for resource groups" groups can be created in any region |
| `policy_coverage_scanner` | `resource_types_without_policy` | Resource types in use with no compliance record at all - no guardrail applies to them |
| `vm_required_extension_scanner` | `vm_required_extension_missing`, `vm_required_extension_failed` | See [Required VM extensions](#required-vm-extensions) |

Each finding carries the affected objects in its evidence and the `az` commands to fix them (exemption expiry or
deletion, remediation task creation, enforcement mode). Review the generated commands before running them.

## What governs this resource?

For one resource, resource group or subscription id: every assignment from the root management group down (with
`notScopes` exclusions applied), the exemptions covering it with their expiry, and its compliance state per policy.

- **Docker UI:** Governance page → *What governs this resource?*
- **API:** `GET /api/v1/governance/what-governs?resource_id=<id>` - the caller needs access to that subscription; the
  lookup uses the tenant's service principal.
- **CLI** (your `az login`, no Docker):

```bash
python -m scripts.what_governs --resource-id /subscriptions/<id>/resourceGroups/<rg>/providers/<type>/<name>
python -m scripts.what_governs --resource-id /subscriptions/<id>/resourceGroups/<rg> --non-compliant-only
python -m scripts.what_governs --resource-id <id> --json
```

No compliance data yet means the assignment is new: evaluation takes 5-30 minutes (`az policy state trigger-scan
--subscription <id>` forces it).

## Find policy objects by managedBy

Deployment tools (Terraform / OpenTofu modules, pipelines) often stamp `metadata.managedBy` on the definitions,
initiatives, assignments and exemptions they create. If the tool's state is lost, this lists what it owned so it
can be imported or cleaned up:

```bash
python -m scripts.find_managed_policy --managed-by <value> --management-group <mg-id>
python -m scripts.find_managed_policy --managed-by <value> --output managed-policy.json
```

Without `--management-group` it searches everything the signed-in identity can read. By default the full result is
written under `reports/` (git-ignored - it contains tenant identifiers).

## Required VM extensions

Off until you list the extensions every VM must carry. In `.env` (Docker stack) or the environment (CLI):

```bash
# comma-separated entries; "|" separates alternatives (extension name or type) that satisfy one entry
REQUIRED_VM_EXTENSIONS=AzureMonitorWindowsAgent|AzureMonitorLinuxAgent, MDE.Windows|MDE.Linux
REQUIRED_VM_EXTENSIONS_INCLUDE_ARC=false   # true also checks Azure Arc-enabled servers
```

For the CLI it can also come from the `--config` thresholds file: `{"required_vm_extensions": "...",
"include_arc_machines": true}`. A machine missing an entry gets `vm_required_extension_missing`; one whose extension
exists but is not provisioned gets `vm_required_extension_failed`.
