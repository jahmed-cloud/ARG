"""
Azure Resource Guardian - Azure Policy Scanners
================================================
Is Azure Policy actually doing its job on this subscription? Built on one shared, read-only policy snapshot
(scanners/base/policy.py) so the six scanners cost one set of Resource Graph queries per subscription.

Scanners in this module:
1. PolicyAssignmentScanner     - No assignment applies at all; assignments left in DoNotEnforce
2. PolicyExemptionScanner      - Exemptions without expiry, expired, orphaned, or waiving a whole initiative
3. PolicyRemediationScanner    - DeployIfNotExists / Modify policies with non-compliant resources that no
                                 remediation task ever fixed
4. PolicyEffectivenessScanner  - Indexed-mode definitions aimed at resource groups / subscriptions (never
                                 evaluated); "Allowed locations" without its resource-group counterpart
5. PolicyCoverageScanner       - Resource types in use that no assignment has ever evaluated
6. VmRequiredExtensionScanner  - Machines missing an agent extension the organisation requires (opt-in list)
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.policy import build_snapshot, exemption_counts, get_policy_snapshot
from scanners.base.posture_scanner import PostureScanner

MAX_LISTED = 25  # rows quoted in a description; evidence keeps them all


def _listed(items: List[str]) -> str:
    shown = items[:MAX_LISTED]
    more = len(items) - len(shown)
    return "; ".join(shown) + (f"; and {more} more" if more > 0 else "")


def mock_policy_snapshot(now: Optional[datetime] = None) -> Dict[str, Any]:
    """Offline snapshot exercising every policy scanner (placeholder ids only)."""
    now = now or datetime.now(timezone.utc)
    mg = "/providers/microsoft.management/managementgroups/mg-landing-zones"
    sub = "/subscriptions/sub-1"
    builtin = "/providers/microsoft.authorization/policydefinitions/"
    custom_def = f"{mg}/providers/microsoft.authorization/policydefinitions/inherit-tag-rg"
    initiative = f"{mg}/providers/microsoft.authorization/policysetdefinitions/baseline"
    assignments = [
        {"id": f"{mg}/providers/microsoft.authorization/policyassignments/allowed-locations",
         "name": "Allowed locations", "scope": mg, "definitionId": builtin + "e56962a6-4747-49cd-b67b-bf8b01975c4c",
         "enforcement": "Default"},
        {"id": f"{mg}/providers/microsoft.authorization/policyassignments/inherit-tag",
         "name": "Inherit CostCenter tag on resource groups", "scope": mg, "definitionId": custom_def,
         "enforcement": "Default"},
        {"id": f"{mg}/providers/microsoft.authorization/policyassignments/baseline",
         "name": "Security baseline", "scope": mg, "definitionId": initiative, "enforcement": "Default"},
        {"id": f"{sub}/providers/microsoft.authorization/policyassignments/diag-settings",
         "name": "Deploy diagnostic settings", "scope": sub,
         "definitionId": builtin + "00000000-0000-0000-0000-00000000d1a6", "enforcement": "DoNotEnforce"},
    ]
    definitions = [{"id": custom_def, "name": "Inherit a tag from the subscription to resource groups",
                    "mode": "Indexed",
                    "rule": {"if": {"field": "type", "equals": "Microsoft.Resources/subscriptions/resourceGroups"}}}]
    exemptions = [
        {"id": f"{sub}/resourcegroups/rg-legacy/providers/microsoft.authorization/policyexemptions/legacy-waiver",
         "name": "Legacy waiver", "scope": f"{sub}/resourcegroups/rg-legacy", "category": "Waiver", "expiresOn": "",
         "assignmentId": f"{mg}/providers/microsoft.authorization/policyassignments/baseline", "refIds": []},
        {"id": f"{sub}/providers/microsoft.authorization/policyexemptions/migration",
         "name": "Migration window", "scope": sub, "category": "Mitigated",
         "expiresOn": (now - timedelta(days=40)).isoformat(),
         "assignmentId": f"{mg}/providers/microsoft.authorization/policyassignments/allowed-locations",
         "refIds": []},
        {"id": f"{sub}/providers/microsoft.authorization/policyexemptions/old-pilot",
         "name": "Old pilot", "scope": sub, "category": "Waiver",
         "expiresOn": (now + timedelta(days=90)).isoformat(),
         "assignmentId": f"{mg}/providers/microsoft.authorization/policyassignments/deleted-assignment",
         "refIds": ["member-1"]},
    ]
    compliance = [
        {"assignmentId": f"{mg}/providers/microsoft.authorization/policyassignments/baseline",
         "refId": "deployVmBackup", "action": "deployifnotexists", "total": 12, "nonCompliant": 7, "exempt": 0},
        {"assignmentId": f"{mg}/providers/microsoft.authorization/policyassignments/baseline",
         "refId": "auditTls", "action": "audit", "total": 9, "nonCompliant": 4, "exempt": 0},
        {"assignmentId": f"{sub}/providers/microsoft.authorization/policyassignments/diag-settings",
         "refId": "", "action": "deployifnotexists", "total": 20, "nonCompliant": 20, "exempt": 0},
        {"assignmentId": f"{mg}/providers/microsoft.authorization/policyassignments/inherit-tag",
         "refId": "", "action": "modify", "total": 30, "nonCompliant": 11, "exempt": 0},
    ]
    remediations = [{"assignmentId": f"{mg}/providers/microsoft.authorization/policyassignments/inherit-tag",
                     "refId": "", "state": "Succeeded"}]
    usage = {"microsoft.compute/virtualmachines": 2, "microsoft.storage/storageaccounts": 3,
             "microsoft.web/sites": 4, "microsoft.network/privatednszones": 2,
             "microsoft.resources/subscriptions/resourcegroups": 5}
    evaluated = ["microsoft.compute/virtualmachines", "microsoft.storage/storageaccounts"]
    return build_snapshot("sub-1", ["mg-landing-zones", "mg-root"], assignments, definitions, exemptions,
                          compliance, remediations, usage, evaluated, now=now)


class PolicySnapshotScanner(PostureScanner):
    """Shared plumbing: the live snapshot, or the mock one offline."""

    category = ScannerCategory.GOVERNANCE

    async def snapshot(self, context: ScanContext) -> Optional[Dict[str, Any]]:
        if context.resource_graph_client is not None:
            return await get_policy_snapshot(context)
        return self._mock_data()[0]

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [mock_policy_snapshot()]

    async def scan(self, context: ScanContext) -> ScanOutput:
        try:
            snap = await self.snapshot(context)
        except Exception as e:  # policyresources needs Reader on the scope; say so instead of failing the scan
            return ScanOutput(warnings=[f"Azure Policy data unavailable: {e}"])
        if snap is None:
            return ScanOutput()
        findings = self.evaluate(context, snap)
        return ScanOutput(findings=findings, resources_scanned=len(snap.get("assignments") or []),
                          metadata={"assignments": len(snap.get("assignments") or []),
                                    "exemptions": len(snap.get("exemptions") or [])})

    def evaluate(self, context: ScanContext, snap: Dict[str, Any]) -> list:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 1. Assignments: none at all, or not enforced
# ---------------------------------------------------------------------------

@register_scanner
class PolicyAssignmentScanner(PolicySnapshotScanner):
    """
    Emits finding_type="no_policy_assignments" when nothing is assigned to the subscription or above it, and
    finding_type="policy_assignments_not_enforced" for assignments left in DoNotEnforce (they report, but
    Deny does not block and DeployIfNotExists / Modify do not deploy on create).
    """

    scanner_name = "policy_assignment_scanner"
    display_name = "Azure Policy Assignments"
    description = "Detects subscriptions without any Azure Policy assignment and assignments left in DoNotEnforce"
    severity = SeverityLevel.MEDIUM

    def evaluate(self, context, snap):
        assignments = snap.get("assignments") or []
        if not assignments:
            return [self.subscription_finding(
                context, finding_type="no_policy_assignments",
                title="No Azure Policy assignment applies to this subscription",
                description=("Nothing is assigned on the subscription, its resource groups or any management group "
                             "above it, so no guardrail (allowed regions, required tags, diagnostics, security "
                             "baseline) is evaluated or enforced."),
                remediation_steps=("1. Move the subscription under the management group that carries the "
                                   "organisation's baseline, or assign it directly.\n"
                                   "2. Start in audit (DoNotEnforce) to see the impact, then enforce."),
                azure_cli_script=(f"az policy assignment list --scope /subscriptions/{context.subscription_id} "
                                  "--disable-scope-strict-match -o table"),
                evidence={"management_groups": snap.get("ancestors") or []},
            )]
        off = [a for a in assignments if not a["enforced"]]
        if not off:
            return []
        return [self.subscription_finding(
            context, finding_type="policy_assignments_not_enforced", severity=SeverityLevel.LOW,
            title=f"{len(off)} Azure Policy assignment(s) are not enforced (DoNotEnforce)",
            description=("These assignments only report: Deny does not block and DeployIfNotExists / Modify do not "
                         "act on new resources: " + _listed([f"'{a['name']}' at {a['scope']}" for a in off]) +
                         ". Fine during an audit phase; a risk when it was meant to be a guardrail."),
            remediation_steps=("1. Review the compliance results of each assignment.\n"
                               "2. Exempt the justified exceptions (with an expiry date), then switch the assignment "
                               "to Default enforcement."),
            azure_cli_script="\n".join(f"az policy assignment update --name {a['id'].rsplit('/', 1)[-1]} "
                                       f"--scope {a['scope']} --enforcement-mode Default" for a in off[:MAX_LISTED]),
            evidence={"assignments": off},
        )]


# ---------------------------------------------------------------------------
# 2. Exemption hygiene
# ---------------------------------------------------------------------------

EXEMPTION_ISSUES = {
    "no_expiry": ("policy_exemption_no_expiry", SeverityLevel.MEDIUM,
                  "exemption(s) never expire",
                  "An exemption without an expiry date is an unbounded risk acceptance that nobody reviews again, "
                  "and compliance reports still count the resources as covered.",
                  "Set an expiry date (12 months at most) and record the ticket and approver in the exemption "
                  "metadata."),
    "expired": ("policy_exemption_expired", SeverityLevel.LOW,
                "exemption(s) have expired but are still present",
                "Expired exemptions no longer apply but clutter the estate and hide whether the risk was closed.",
                "Delete the exemption, or renew it with a new expiry if the exception is still approved."),
    "orphaned": ("policy_exemption_orphaned", SeverityLevel.LOW,
                 "exemption(s) point at an assignment that no longer exists",
                 "The assignment was deleted or replaced, so the exemption does nothing - or it will silently "
                 "apply again if an assignment with the same id comes back.",
                 "Delete the exemption, or re-create it against the assignment that replaced the old one."),
    "whole_initiative": ("policy_exemption_whole_initiative", SeverityLevel.MEDIUM,
                         "exemption(s) waive an entire initiative",
                         "Exempting a whole initiative switches off every control in it for that scope, including "
                         "ones that have nothing to do with the original exception.",
                         "Limit the exemption to the specific policy reference ids it is meant for."),
}


@register_scanner
class PolicyExemptionScanner(PolicySnapshotScanner):
    """
    Exemptions on the subscription, its resource groups / resources, or a management group above it - one
    finding per problem, listing every affected exemption. Emits:
    finding_type="policy_exemption_no_expiry", finding_type="policy_exemption_expired",
    finding_type="policy_exemption_orphaned", finding_type="policy_exemption_whole_initiative".
    """

    scanner_name = "policy_exemption_scanner"
    display_name = "Azure Policy Exemption Hygiene"
    description = "Detects exemptions without expiry, expired, orphaned, or waiving a whole initiative"
    severity = SeverityLevel.MEDIUM

    def evaluate(self, context, snap):
        exemptions = snap.get("exemptions") or []
        findings = []
        for issue, (finding_type, severity, what, why, fix) in EXEMPTION_ISSUES.items():
            hits = [e for e in exemptions if issue in (e.get("issues") or [])]
            if not hits:
                continue
            script = None
            if issue in ("expired", "orphaned"):
                script = "\n".join(f"az policy exemption delete --name {e['id'].rsplit('/', 1)[-1]} "
                                   f"--scope {e['scope']}" for e in hits[:MAX_LISTED])
            elif issue == "no_expiry":
                script = "\n".join(f"az policy exemption update --name {e['id'].rsplit('/', 1)[-1]} "
                                   f"--scope {e['scope']} --expires-on <yyyy-mm-dd>" for e in hits[:MAX_LISTED])
            findings.append(self.subscription_finding(
                context, finding_type=finding_type, severity=severity, title=f"{len(hits)} policy {what}",
                description=why + " Affected: " + _listed([f"'{e.get('name')}' at {e.get('scope')}" for e in hits]),
                remediation_steps=fix, azure_cli_script=script,
                evidence={"exemptions": hits, "counts": exemption_counts(exemptions)},
            ))
        return findings


# ---------------------------------------------------------------------------
# 3. Remediation never run
# ---------------------------------------------------------------------------

@register_scanner
class PolicyRemediationScanner(PolicySnapshotScanner):
    """
    DeployIfNotExists and Modify only act when a resource is created or updated. Resources that existed before
    the assignment (or before a subscription tag changed) stay non-compliant until a remediation task runs.
    Emits finding_type="policy_remediation_never_run".
    """

    scanner_name = "policy_remediation_scanner"
    display_name = "Policy Remediation Never Run"
    description = "Detects DeployIfNotExists / Modify policies with non-compliant resources and no remediation task"
    severity = SeverityLevel.HIGH

    def evaluate(self, context, snap):
        gaps = snap.get("remediation_gaps") or []
        if not gaps:
            return []
        total = sum(g["non_compliant"] for g in gaps)
        scripts = []
        for g in gaps[:MAX_LISTED]:
            ref = f" --definition-reference-id {g['reference']}" if g["reference"] else ""
            scripts.append(f"az policy remediation create --name remediate-{g['assignment_id'].rsplit('/', 1)[-1]}"
                           f"{'-' + g['reference'] if g['reference'] else ''} --policy-assignment {g['assignment_id']}"
                           f"{ref} --resource-discovery-mode ReEvaluateCompliance "
                           f"--subscription {context.subscription_id}")
        return [self.subscription_finding(
            context, finding_type="policy_remediation_never_run",
            title=f"{total} non-compliant resource(s) under {len(gaps)} policy(ies) that were never remediated",
            description=("These DeployIfNotExists / Modify policies only fix resources on create or update, and no "
                         "remediation task was ever created for them, so existing resources stay non-compliant: "
                         + _listed([f"'{g['assignment']}'" + (f" / {g['reference']}" if g['reference'] else "")
                                    + f" ({g['effect']}, {g['non_compliant']} non-compliant"
                                    + ("" if g["enforced"] else ", assignment not enforced") + ")" for g in gaps])),
            remediation_steps=("1. Check the assignment's managed identity has the roles the policy needs.\n"
                               "2. Create a remediation task per policy (ReEvaluateCompliance) and review its "
                               "deployments.\n3. Schedule it after changes the policy depends on, e.g. a "
                               "subscription tag change for tag inheritance."),
            azure_cli_script="\n".join(scripts),
            evidence={"gaps": gaps},
        )]


# ---------------------------------------------------------------------------
# 4. Policies that cannot see what they target
# ---------------------------------------------------------------------------

@register_scanner
class PolicyEffectivenessScanner(PolicySnapshotScanner):
    """
    Emits finding_type="policy_definition_mode_skips_containers" for assigned custom definitions in Indexed
    mode whose rule targets resource groups or subscriptions (Indexed never evaluates them, so the policy does
    nothing), and finding_type="allowed_locations_skip_resource_groups" when "Allowed locations" applies but
    "Allowed locations for resource groups" does not (the first is Indexed and ignores resource groups).
    """

    scanner_name = "policy_effectiveness_scanner"
    display_name = "Policies That Cannot Take Effect"
    description = "Detects Indexed-mode policies aimed at resource groups and region rules that skip resource groups"
    severity = SeverityLevel.HIGH

    def evaluate(self, context, snap):
        findings = []
        mismatches = snap.get("mode_mismatches") or []
        if mismatches:
            findings.append(self.subscription_finding(
                context, finding_type="policy_definition_mode_skips_containers",
                title=f"{len(mismatches)} assigned policy(ies) target resource groups or subscriptions in Indexed mode",
                description=("Indexed mode only evaluates resource types that support tags and location; resource "
                             "groups and subscriptions are never evaluated, so these policies have no effect on what "
                             "they were written for: " + _listed([f"'{m['definition']}' via '{m['assignment']}'"
                                                                   for m in mismatches])),
                remediation_steps=("1. Change the definition's mode to All (or split it: Indexed for resources, "
                                   "All for resource groups).\n2. Re-evaluate compliance and run a remediation task "
                                   "for Modify / DeployIfNotExists effects."),
                evidence={"definitions": mismatches},
            ))
        gap = snap.get("location_gap")
        if gap:
            findings.append(self.subscription_finding(
                context, finding_type="allowed_locations_skip_resource_groups", severity=SeverityLevel.MEDIUM,
                title="Resource-group regions are not governed",
                description=("'Allowed locations' applies (" + _listed([f"'{n}'" for n in gap["assignments"]]) +
                             ") but 'Allowed locations for resource groups' does not. The first is Indexed and "
                             "never evaluates resource groups, so groups - and the metadata they hold - can be "
                             "created in any region."),
                remediation_steps=("Assign the built-in 'Allowed locations for resource groups' "
                                   "(e765b5de-1225-4ba3-bd56-1ac6695af988) with the same region list, at the same "
                                   "scope, in audit first."),
                evidence=gap,
            ))
        return findings


# ---------------------------------------------------------------------------
# 5. Resource types no policy evaluates
# ---------------------------------------------------------------------------

@register_scanner
class PolicyCoverageScanner(PolicySnapshotScanner):
    """
    Resource types in use with no compliance record at all - no assignment evaluates them, so no guardrail
    (diagnostics, network exposure, encryption) applies. Emits finding_type="resource_types_without_policy".
    """

    scanner_name = "policy_coverage_scanner"
    display_name = "Resource Types Without Policy Coverage"
    description = "Detects resource types in use that no Azure Policy assignment evaluates"
    severity = SeverityLevel.LOW

    def evaluate(self, context, snap):
        if not snap.get("assignments"):
            return []  # policy_assignment_scanner already reports the subscription as ungoverned
        uncovered = snap.get("uncovered_types") or {}
        if not uncovered:
            return []
        rows = sorted(uncovered.items(), key=lambda kv: -kv[1])
        return [self.subscription_finding(
            context, finding_type="resource_types_without_policy",
            title=f"{len(uncovered)} resource type(s) in use that no policy evaluates",
            description=("No assignment has produced a compliance result for these types, so no guardrail applies "
                         "to them: " + _listed([f"{t} x{n}" for t, n in rows])),
            remediation_steps=("1. Check the built-in policies and initiatives for these types (e.g. Microsoft cloud "
                               "security benchmark, diagnostic settings, private endpoint).\n"
                               "2. Assign the relevant ones in audit and review the results."),
            evidence={"types": dict(rows)},
        )]


# ---------------------------------------------------------------------------
# 6. Required agent extensions on machines (opt-in)
# ---------------------------------------------------------------------------

MACHINES_QUERY = """
resources
| where type =~ 'microsoft.compute/virtualmachines' or type =~ 'microsoft.hybridcompute/machines'
| project id, name, type = tolower(type), resourceGroup, subscriptionId, location,
          os = tostring(coalesce(properties.storageProfile.osDisk.osType, properties.osType, properties.osName)),
          power = tostring(properties.extended.instanceView.powerState.code)
"""
EXTENSIONS_QUERY = """
resources
| where type in~ ('microsoft.compute/virtualmachines/extensions', 'microsoft.hybridcompute/machines/extensions')
| extend lid = tolower(id)
| project machine = substring(lid, 0, indexof(lid, '/extensions/')), name = tolower(name),
          extensionType = tolower(tostring(properties.type)), state = tostring(properties.provisioningState)
"""


def parse_requirements(value: Any) -> List[List[str]]:
    """'A|B, C' or ['A|B', 'C'] -> [['a', 'b'], ['c']]: each entry is satisfied by any one of its alternatives
    (e.g. the Windows and Linux flavour of the same agent)."""
    entries = value.split(",") if isinstance(value, str) else list(value or [])
    out = []
    for entry in entries:
        alternatives = [a.strip().lower() for a in str(entry).split("|") if a.strip()]
        if alternatives:
            out.append(alternatives)
    return out


def missing_extensions(machines: List[Dict[str, Any]], extensions: List[Dict[str, Any]],
                       requirements: List[List[str]]) -> List[Dict[str, Any]]:
    """Per machine, the requirements with no matching extension, and those whose extension is not Succeeded."""
    by_machine: Dict[str, List[Dict[str, Any]]] = {}
    for e in extensions:
        by_machine.setdefault((e.get("machine") or "").lower(), []).append(e)
    out = []
    for m in machines:
        present = by_machine.get((m.get("id") or "").lower(), [])
        missing, failed = [], []
        for alternatives in requirements:
            matches = [e for e in present if (e.get("name") or "").lower() in alternatives
                       or (e.get("extensionType") or "").lower() in alternatives]
            if not matches:
                missing.append(" | ".join(alternatives))
            elif not any((e.get("state") or "").lower() == "succeeded" for e in matches):
                failed.append(f"{matches[0].get('name')} ({matches[0].get('state') or 'unknown'})")
        if missing or failed:
            out.append({"machine": m, "missing": missing, "failed": failed})
    return out


@register_scanner
class VmRequiredExtensionScanner(PostureScanner):
    """
    Machines missing an agent extension the organisation requires (monitoring, EDR, backup agent...).
    Opt-in: set `required_vm_extensions` in the scanner config or REQUIRED_VM_EXTENSIONS in the environment,
    e.g. "AzureMonitorWindowsAgent|AzureMonitorLinuxAgent, MDE.Windows|MDE.Linux". Each entry matches an
    extension name or type; `|` separates alternatives. Arc-enabled servers are included when
    `include_arc_machines` / REQUIRED_VM_EXTENSIONS_INCLUDE_ARC is true.
    Emits finding_type="vm_required_extension_missing" and finding_type="vm_required_extension_failed".
    """

    scanner_name = "vm_required_extension_scanner"
    display_name = "Required VM Agent Extensions"
    description = "Detects VMs (and optionally Arc servers) missing or failing a required agent extension"
    category = ScannerCategory.COMPUTE
    severity = SeverityLevel.MEDIUM

    def requirements(self) -> List[List[str]]:
        return parse_requirements(self.setting("required_vm_extensions", os.getenv("REQUIRED_VM_EXTENSIONS", "")))

    def include_arc(self) -> bool:
        value = self.setting("include_arc_machines", os.getenv("REQUIRED_VM_EXTENSIONS_INCLUDE_ARC", "false"))
        return str(value).lower() in ("1", "true", "yes")

    async def scan(self, context: ScanContext) -> ScanOutput:
        requirements = self.requirements()
        if not requirements:
            return ScanOutput(metadata={"skipped": "no required_vm_extensions configured"})
        if context.resource_graph_client is not None:
            machines = await self.arg(context, MACHINES_QUERY)
            extensions = await self.arg(context, EXTENSIONS_QUERY)
        else:
            machines, extensions = self._mock_data()
        if not self.include_arc():
            machines = [m for m in machines if (m.get("type") or "") == "microsoft.compute/virtualmachines"]
        findings = []
        for row in missing_extensions(machines, extensions, requirements):
            m = row["machine"]
            kind = "Arc-enabled server" if "hybridcompute" in (m.get("type") or "") else "VM"
            if row["missing"]:
                findings.append(self.resource_finding(
                    m, finding_type="vm_required_extension_missing",
                    title=f"{kind} {m.get('name')} is missing required extension(s): {', '.join(row['missing'])}",
                    description=(f"The {kind} has none of the extensions listed for: {', '.join(row['missing'])}. "
                                 "Without the agent the machine is outside monitoring / protection coverage."
                                 + (" It is deallocated - the extension installs when it next runs."
                                    if "deallocated" in (m.get("power") or "") else "")),
                    remediation_steps=("1. Install the extension (or let the DeployIfNotExists policy that installs "
                                       "it remediate the machine).\n2. If the machine is exempt by design, record a "
                                       "policy exemption with an expiry date."),
                    evidence={"missing": row["missing"], "os": m.get("os"), "power": m.get("power")},
                ))
            if row["failed"]:
                findings.append(self.resource_finding(
                    m, finding_type="vm_required_extension_failed",
                    title=f"{kind} {m.get('name')} has a required extension that is not healthy",
                    description=f"Extension(s) present but not provisioned: {', '.join(row['failed'])}.",
                    remediation_steps=("Check the extension status message on the machine, fix the cause (network "
                                       "egress, agent version, OS support) and reinstall the extension."),
                    evidence={"failed": row["failed"], "os": m.get("os")},
                ))
        return ScanOutput(findings=findings, resources_scanned=len(machines))

    def _mock_data(self):
        vm = "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines"
        machines = [
            {"id": f"{vm}/vm-app-01", "name": "vm-app-01", "type": "microsoft.compute/virtualmachines",
             "resourceGroup": "rg-app", "subscriptionId": "sub-1", "location": "westeurope", "os": "Windows",
             "power": "PowerState/running"},
            {"id": f"{vm}/vm-app-02", "name": "vm-app-02", "type": "microsoft.compute/virtualmachines",
             "resourceGroup": "rg-app", "subscriptionId": "sub-1", "location": "westeurope", "os": "Linux",
             "power": "PowerState/running"},
            {"id": f"{vm}/vm-app-03", "name": "vm-app-03", "type": "microsoft.compute/virtualmachines",
             "resourceGroup": "rg-app", "subscriptionId": "sub-1", "location": "westeurope", "os": "Linux",
             "power": "PowerState/running"},
        ]
        extensions = [
            {"machine": f"{vm}/vm-app-01".lower(), "name": "azuremonitorwindowsagent",
             "extensionType": "azuremonitorwindowsagent", "state": "Succeeded"},
            {"machine": f"{vm}/vm-app-03".lower(), "name": "azuremonitorlinuxagent",
             "extensionType": "azuremonitorlinuxagent", "state": "Failed"},
        ]
        return machines, extensions
