"""
Azure Resource Guardian - Azure Policy estate analysis
======================================================
One read-only snapshot of the Azure Policy objects that govern a subscription, shared by the policy scanners
(scanners/governance/policy_scanners.py), the what-governs lookup and the managed-by finder:

- assignments that apply to the subscription (on it, a resource group / resource in it, or an ancestor
  management group), with the mode of the custom definition each one points at;
- exemptions on those scopes, judged for expiry, orphaned assignments and whole-initiative waivers;
- the compliance summary per assignment and the remediation tasks that ever ran for it;
- the resource types Azure Policy evaluated, against the types in use.

The pure functions take plain rows so they are testable without Azure; get_policy_snapshot() runs the Resource
Graph queries and caches the result on the ScanContext.
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from scanners.base.azure_api import query_resource_graph

logger = logging.getLogger(__name__)

ALLOWED_LOCATIONS = "e56962a6-4747-49cd-b67b-bf8b01975c4c"      # built-in "Allowed locations" (Indexed)
ALLOWED_RG_LOCATIONS = "e765b5de-1225-4ba3-bd56-1ac6695af988"   # built-in "Allowed locations for resource groups"
REMEDIABLE_EFFECTS = ("deployifnotexists", "modify")
# Types Azure Policy does not evaluate in Indexed mode, or that the platform manages.
UNEVALUATED_TYPE_PREFIXES = ("microsoft.resources/", "microsoft.alertsmanagement/", "microsoft.security/",
                             "microsoft.advisor/", "microsoft.insights/activitylogalerts")
CONTAINER_TYPES = ("microsoft.resources/subscriptions/resourcegroups", "microsoft.resources/subscriptions")
BUILTIN_PREFIXES = ("/providers/microsoft.authorization/policydefinitions/",
                    "/providers/microsoft.authorization/policysetdefinitions/")

ANCESTORS_QUERY = """
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project chain = properties.managementGroupAncestorsChain
"""
ASSIGNMENTS_QUERY = """
policyresources
| where type =~ 'microsoft.authorization/policyassignments'
| project id = tolower(id), name = tostring(properties.displayName), scope = tolower(tostring(properties.scope)),
          definitionId = tolower(tostring(properties.policyDefinitionId)),
          enforcement = tostring(properties.enforcementMode), notScopes = properties.notScopes,
          managedBy = tostring(properties.metadata.managedBy)
"""
# Resource Graph returns custom definitions only; built-ins are recognised by their id prefix.
DEFINITIONS_QUERY = """
policyresources
| where type in~ ('microsoft.authorization/policydefinitions', 'microsoft.authorization/policysetdefinitions')
| where tostring(properties.policyType) !~ 'BuiltIn'
| project id = tolower(id), name = tostring(properties.displayName), mode = tostring(properties.mode),
          rule = properties.policyRule
"""
EXEMPTIONS_QUERY = """
policyresources
| where type =~ 'microsoft.authorization/policyexemptions'
| extend lid = tolower(id)
| project id = lid, name = coalesce(tostring(properties.displayName), name),
          scope = substring(lid, 0, indexof(lid, '/providers/microsoft.authorization/policyexemptions/')),
          category = tostring(properties.exemptionCategory), expiresOn = tostring(properties.expiresOn),
          assignmentId = tolower(tostring(properties.policyAssignmentId)), refIds = properties.policyDefinitionReferenceIds
"""
COMPLIANCE_QUERY = """
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| summarize total = count(), nonCompliant = countif(tostring(properties.complianceState) =~ 'NonCompliant'),
            exempt = countif(tostring(properties.complianceState) =~ 'Exempt')
         by assignmentId = tolower(tostring(properties.policyAssignmentId)),
            refId = tostring(properties.policyDefinitionReferenceId),
            action = tolower(tostring(properties.policyDefinitionAction))
"""
EVALUATED_TYPES_QUERY = """
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| summarize by resourceType = tolower(tostring(properties.resourceType))
"""
REMEDIATIONS_QUERY = """
policyresources
| where type =~ 'microsoft.policyinsights/remediations'
| project assignmentId = tolower(tostring(properties.policyAssignmentId)),
          refId = tostring(properties.policyDefinitionReferenceId), state = tostring(properties.provisioningState)
"""
USAGE_QUERY = "Resources | summarize n = count() by type = tolower(type)"


# ---------------------------------------------------------------------------
# Scope and parsing helpers
# ---------------------------------------------------------------------------

def mg_scope(name: str) -> str:
    return f"/providers/microsoft.management/managementgroups/{name.lower()}"


def applies_to_subscription(scope: str, subscription_id: str, ancestors: Iterable[str]) -> bool:
    """True for the subscription itself, anything inside it, or one of its ancestor management groups."""
    scope = (scope or "").lower()
    sub = f"/subscriptions/{subscription_id.lower()}"
    return scope == sub or scope.startswith(sub + "/") or scope in {mg_scope(m) for m in ancestors}


def scope_chain(resource_id: str, ancestors: Iterable[str]) -> List[str]:
    """Every scope that can hold an assignment or exemption affecting resource_id, outermost first.
    `ancestors` is Resource Graph's managementGroupAncestorsChain order: nearest management group first."""
    rid = resource_id.lower().rstrip("/")
    parts = rid.split("/")
    chain = [mg_scope(m) for m in reversed(list(ancestors))]
    if len(parts) >= 3 and parts[1] == "subscriptions":
        chain.append("/".join(parts[:3]))
    if len(parts) >= 5 and parts[3] == "resourcegroups":
        chain.append("/".join(parts[:5]))
    if rid not in chain:
        chain.append(rid)
    return chain


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_initiative(definition_id: str) -> bool:
    return "/policysetdefinitions/" in (definition_id or "").lower()


def rule_targets_containers(rule: Any) -> bool:
    """The rule names resource groups or subscriptions - types an Indexed-mode definition never evaluates."""
    text = str(rule or "").lower()
    return any(t in text for t in CONTAINER_TYPES)


# ---------------------------------------------------------------------------
# Analysis (pure)
# ---------------------------------------------------------------------------

def classify_exemption(exemption: Dict[str, Any], assignment_ids: set, now: datetime) -> List[str]:
    """Hygiene problems with one exemption: no_expiry, expired, orphaned, whole_initiative."""
    issues = []
    expires = parse_time(exemption.get("expiresOn"))
    if expires is None:
        issues.append("no_expiry")
    elif expires < now:
        issues.append("expired")
    assignment = (exemption.get("assignmentId") or "").lower()
    if assignment and assignment not in assignment_ids:
        issues.append("orphaned")
    if exemption.get("initiative") and not exemption.get("refIds"):
        issues.append("whole_initiative")
    return issues


def remediation_gaps(assignments: List[Dict[str, Any]], compliance: List[Dict[str, Any]],
                     remediations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """DeployIfNotExists / Modify members with non-compliant resources and no remediation task ever created.
    Those effects only act on create / update, so existing resources stay non-compliant until a task runs."""
    remediated = {((r.get("assignmentId") or "").lower(), (r.get("refId") or "").lower()) for r in remediations}
    by_id = {a["id"]: a for a in assignments}
    gaps = []
    for c in compliance:
        aid = (c.get("assignmentId") or "").lower()
        if aid not in by_id or (c.get("action") or "").lower() not in REMEDIABLE_EFFECTS:
            continue
        if int(c.get("nonCompliant") or 0) <= 0 or (aid, (c.get("refId") or "").lower()) in remediated:
            continue
        gaps.append({"assignment": by_id[aid]["name"], "assignment_id": aid, "reference": c.get("refId") or None,
                     "effect": (c.get("action") or "").lower(), "non_compliant": int(c.get("nonCompliant") or 0),
                     "enforced": by_id[aid]["enforced"]})
    return sorted(gaps, key=lambda g: (-g["non_compliant"], g["assignment"]))


def mode_mismatches(assignments: List[Dict[str, Any]], definitions: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Assigned Indexed-mode custom definitions whose rule targets resource groups or subscriptions."""
    out = []
    for a in assignments:
        d = definitions.get(a["definitionId"])
        if d and (d.get("mode") or "").lower() == "indexed" and rule_targets_containers(d.get("rule")):
            out.append({"assignment": a["name"], "definition": d.get("name") or a["definitionId"],
                        "definition_id": a["definitionId"]})
    return out


def location_gap(assignments: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """'Allowed locations' applies to the whole subscription but 'Allowed locations for resource groups' does not."""
    whole = [a for a in assignments if not a["resource_group"]]
    resources = [a for a in whole if a["definitionId"].endswith(ALLOWED_LOCATIONS)]
    groups = [a for a in whole if a["definitionId"].endswith(ALLOWED_RG_LOCATIONS)]
    return {"assignments": sorted(a["name"] for a in resources)} if resources and not groups else None


def uncovered_types(usage: Dict[str, int], evaluated: Iterable[str]) -> Dict[str, int]:
    """Resource types in use that no assignment has evaluated (no compliance record of that type)."""
    seen = {t.lower() for t in evaluated if t}
    return {t: n for t, n in sorted(usage.items()) if t not in seen and not t.startswith(UNEVALUATED_TYPE_PREFIXES)}


def build_snapshot(subscription_id: str, ancestors: List[str], assignments: List[Dict[str, Any]],
                   definitions: List[Dict[str, Any]], exemptions: List[Dict[str, Any]],
                   compliance: List[Dict[str, Any]], remediations: List[Dict[str, Any]],
                   usage: Dict[str, int], evaluated: Iterable[str],
                   now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    all_ids = {(a.get("id") or "").lower() for a in assignments}
    defs = {(d.get("id") or "").lower(): d for d in definitions}
    applied = []
    for a in assignments:
        scope = (a.get("scope") or "").lower()
        if not applies_to_subscription(scope, subscription_id, ancestors):
            continue
        definition_id = (a.get("definitionId") or "").lower()
        applied.append({
            "id": (a.get("id") or "").lower(), "name": a.get("name") or "(unnamed)", "scope": scope,
            "definitionId": definition_id, "initiative": is_initiative(definition_id),
            "builtin": definition_id.startswith(BUILTIN_PREFIXES),
            "enforced": (a.get("enforcement") or "Default") != "DoNotEnforce",
            "inherited": scope.startswith("/providers/microsoft.management/"),
            "resource_group": scope.split("/resourcegroups/")[1].split("/")[0] if "/resourcegroups/" in scope else None,
            "managedBy": a.get("managedBy") or None,
        })
    initiative_ids = {(a.get("id") or "").lower() for a in assignments
                      if is_initiative(a.get("definitionId") or "")}
    ex_rows = []
    for e in exemptions:
        if not applies_to_subscription(e.get("scope") or "", subscription_id, ancestors):
            continue
        row = dict(e)
        row["initiative"] = (e.get("assignmentId") or "").lower() in initiative_ids
        row["issues"] = classify_exemption(row, all_ids, now)
        ex_rows.append(row)
    applied_ids = {a["id"] for a in applied}
    compliance = [c for c in compliance if (c.get("assignmentId") or "").lower() in applied_ids]
    return {
        "assignments": sorted(applied, key=lambda a: (not a["inherited"], a["scope"], a["name"].lower())),
        "exemptions": ex_rows,
        "compliance": compliance,
        "remediation_gaps": remediation_gaps(applied, compliance, remediations),
        "mode_mismatches": mode_mismatches(applied, defs),
        "location_gap": location_gap(applied),
        "uncovered_types": uncovered_types(usage, evaluated),
        "ancestors": list(ancestors),
    }


def exemption_counts(exemptions: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for e in exemptions:
        for issue in e.get("issues") or []:
            counts[issue] += 1
    return dict(counts)


# ---------------------------------------------------------------------------
# Live collection
# ---------------------------------------------------------------------------

async def get_ancestors(context: Any) -> List[str]:
    names: List[str] = []
    for row in await query_resource_graph(context, ANCESTORS_QUERY) or []:
        names += [str(m.get("name")) for m in (row.get("chain") or []) if isinstance(m, dict) and m.get("name")]
    return names


async def get_policy_snapshot(context: Any) -> Optional[Dict[str, Any]]:
    """Policy snapshot for context.subscription_id; None offline. Cached on the ScanContext."""
    cache = getattr(context, "cache", None)
    if cache is not None and "policy_snapshot" in cache:
        return cache["policy_snapshot"]
    if getattr(context, "resource_graph_client", None) is None:
        return None
    ancestors = await get_ancestors(context)
    # Assignments, definitions, exemptions and remediations also live on management groups: tenant scope.
    assignments = await query_resource_graph(context, ASSIGNMENTS_QUERY, tenant_scope=True) or []
    definitions = await query_resource_graph(context, DEFINITIONS_QUERY, tenant_scope=True) or []
    exemptions = await query_resource_graph(context, EXEMPTIONS_QUERY, tenant_scope=True) or []
    remediations = await query_resource_graph(context, REMEDIATIONS_QUERY, tenant_scope=True) or []
    compliance = await query_resource_graph(context, COMPLIANCE_QUERY) or []
    evaluated = [r.get("resourceType") for r in await query_resource_graph(context, EVALUATED_TYPES_QUERY) or []]
    usage = {r["type"]: int(r["n"]) for r in (await query_resource_graph(context, USAGE_QUERY) or []) if r.get("type")}
    result = build_snapshot(context.subscription_id, ancestors, assignments, definitions, exemptions,
                            compliance, remediations, usage, evaluated)
    if cache is not None:
        cache["policy_snapshot"] = result
    return result


# ---------------------------------------------------------------------------
# What governs this resource?
# ---------------------------------------------------------------------------

def kql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def governance_for_resource(resource_id: str, ancestors: List[str], assignments: List[Dict[str, Any]],
                            exemptions: List[Dict[str, Any]], states: List[Dict[str, Any]],
                            now: Optional[datetime] = None) -> Dict[str, Any]:
    """Assignments on each scope above resource_id, the exemptions that cover it, and its compliance states."""
    now = now or datetime.now(timezone.utc)
    chain = scope_chain(resource_id, ancestors)
    rid = resource_id.lower().rstrip("/")
    by_scope: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for a in assignments:
        scope = (a.get("scope") or "").lower()
        excluded = any(rid == str(n).lower() or rid.startswith(str(n).lower() + "/") for n in (a.get("notScopes") or []))
        if scope in chain and not excluded:
            by_scope[scope].append({"name": a.get("name") or "(unnamed)", "id": (a.get("id") or "").lower(),
                                    "definitionId": (a.get("definitionId") or "").lower(),
                                    "initiative": is_initiative(a.get("definitionId") or ""),
                                    "enforced": (a.get("enforcement") or "Default") != "DoNotEnforce"})
    covering = []
    for e in exemptions:
        scope = (e.get("scope") or "").lower()
        if scope not in chain:
            continue
        expires = parse_time(e.get("expiresOn"))
        covering.append({"name": e.get("name"), "scope": scope, "category": e.get("category"),
                         "expiresOn": e.get("expiresOn") or None, "assignmentId": e.get("assignmentId"),
                         "refIds": e.get("refIds") or [],
                         "status": "never expires" if expires is None else ("expired" if expires < now else "active"),
                         "whole_assignment": not e.get("refIds")})
    rows = sorted(({"state": s.get("state"), "effect": s.get("effect"), "policy": s.get("policy"),
                    "assignment": s.get("assignment"), "reference": s.get("refId") or None} for s in states),
                  key=lambda s: (s["state"] != "NonCompliant", s["state"] or "", s["policy"] or ""))
    return {
        "resource_id": resource_id,
        "scopes": [{"scope": s, "assignments": by_scope.get(s, [])} for s in chain],
        "exemptions": covering,
        "compliance": rows,
        "summary": {"evaluations": len(rows),
                    "non_compliant": sum(1 for r in rows if r["state"] == "NonCompliant"),
                    "exempt": sum(1 for r in rows if r["state"] == "Exempt"),
                    "assignments": sum(len(v) for v in by_scope.values())},
    }


async def what_governs(context: Any, resource_id: str) -> Dict[str, Any]:
    """Live lookup for one resource; context.subscription_id must be the resource's subscription."""
    rid = resource_id.lower().rstrip("/")
    ancestors = await get_ancestors(context)
    assignments = await query_resource_graph(context, ASSIGNMENTS_QUERY, tenant_scope=True) or []
    exemptions = await query_resource_graph(context, EXEMPTIONS_QUERY, tenant_scope=True) or []
    states = await query_resource_graph(context, f"""
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| where tolower(tostring(properties.resourceId)) == {kql_string(rid)}
| project state = tostring(properties.complianceState), effect = tostring(properties.policyDefinitionAction),
          policy = tostring(properties.policyDefinitionName), assignment = tostring(properties.policyAssignmentName),
          refId = tostring(properties.policyDefinitionReferenceId)
""") or []
    return governance_for_resource(resource_id, ancestors, assignments, exemptions, states)


# ---------------------------------------------------------------------------
# Policy objects stamped with metadata.managedBy (recovery after deployment state is lost)
# ---------------------------------------------------------------------------

def managed_by_query(managed_by: str) -> str:
    return f"""
policyresources
| where type in~ ('microsoft.authorization/policydefinitions', 'microsoft.authorization/policysetdefinitions',
                  'microsoft.authorization/policyassignments', 'microsoft.authorization/policyexemptions')
| where tostring(properties.metadata.managedBy) == {kql_string(managed_by)}
| project id, name, type = tolower(type), displayName = tostring(properties.displayName), metadata = properties.metadata
"""


def summarize_managed(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for r in rows:
        counts[(r.get("type") or "").lower()] += 1
    return dict(sorted(counts.items()))
