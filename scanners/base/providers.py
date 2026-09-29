"""
Azure Resource Guardian - Resource provider analysis
====================================================
Which resource providers a subscription accepts (registered) and which it does not, set against what it actually
uses, plus the Azure Policy "Allowed resource types" / "Not allowed resource types" assignments that apply to it
(directly or inherited from management groups). Shared by the report section, the estate and
resource_provider_policy_scanner; cached on the ScanContext so it is read once per scan.
"""

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from scanners.base.azure_api import query_resource_graph

logger = logging.getLogger(__name__)

ALLOWED_TYPES_POLICY = "a08ec900-254a-4555-9bf5-e42af04b5c5c"      # built-in "Allowed resource types"
NOT_ALLOWED_TYPES_POLICY = "6c112d4e-5bc7-47ae-a041-ea2d9dccd749"  # built-in "Not allowed resource types"

STATUS_ORDER = ("In use", "In use, not registered", "Registered, not in use", "Platform (always registered)",
                "Registering", "Unregistering", "Not registered")

USAGE_QUERY = "Resources | summarize n = count() by type = tolower(type)"
ANCESTORS_QUERY = """
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project chain = properties.managementGroupAncestorsChain
"""
POLICY_QUERY = f"""
policyresources
| where type =~ 'microsoft.authorization/policyassignments'
| extend def = tolower(tostring(properties.policyDefinitionId))
| where def endswith '{ALLOWED_TYPES_POLICY}' or def endswith '{NOT_ALLOWED_TYPES_POLICY}'
| project name = tostring(properties.displayName), scope = tolower(tostring(properties.scope)), def,
          enforcement = tostring(properties.enforcementMode),
          allowed = properties.parameters.listOfResourceTypesAllowed.value,
          denied = properties.parameters.listOfResourceTypesNotAllowed.value
"""


def provider_status(state: str, registration_policy: str, in_use: bool) -> str:
    """Registered = the subscription accepts that provider's resources; not registered = it cannot create them."""
    s = (state or "").lower()
    if s == "registered":
        if in_use:
            return "In use"
        return "Platform (always registered)" if (registration_policy or "") == "RegistrationFree" else \
            "Registered, not in use"
    if s in ("registering", "unregistering"):
        return s.title()
    return "In use, not registered" if in_use else "Not registered"


def applicable_policies(subscription_id: str, ancestors: List[str], assignments: List[Dict[str, Any]]
                        ) -> List[Dict[str, Any]]:
    """Allow / deny resource-type assignments that apply to the subscription (itself, a resource group, or an
    ancestor management group)."""
    sub_scope = f"/subscriptions/{subscription_id.lower()}"
    mg_scopes = {f"/providers/microsoft.management/managementgroups/{mg.lower()}" for mg in ancestors}
    out = []
    for a in assignments:
        scope = (a.get("scope") or "").lower()
        if scope == sub_scope or scope.startswith(sub_scope + "/resourcegroups/") or scope in mg_scopes:
            allowed = [str(t).lower() for t in (a.get("allowed") or [])]
            denied = [str(t).lower() for t in (a.get("denied") or [])]
            out.append({"name": a.get("name") or "(unnamed)", "scope": scope,
                        "effect": "allow list" if (a.get("def") or "").endswith(ALLOWED_TYPES_POLICY) else "deny list",
                        "enforced": (a.get("enforcement") or "Default") != "DoNotEnforce",
                        "resource_group": scope.split("/resourcegroups/")[1] if "/resourcegroups/" in scope else None,
                        "types": allowed or denied})
    return out


def denied_types(usage: Dict[str, int], policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Resource types in use that an applicable policy denies (listed as not allowed, or missing from an allow list)."""
    out = []
    for rtype, n in sorted(usage.items()):
        for p in policies:
            if p["resource_group"]:
                continue  # resource-group assignments cover part of the subscription only; listed, not judged here
            listed = rtype in p["types"]
            if (p["effect"] == "deny list" and listed) or (p["effect"] == "allow list" and not listed):
                out.append({"type": rtype, "resources": n, "policy": p["name"], "effect": p["effect"],
                            "enforced": p["enforced"]})
    return out


def build_analysis(subscription_id: str, providers: List[Dict[str, Any]], usage: Dict[str, int],
                   ancestors: List[str], assignments: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_namespace: Dict[str, Dict[str, int]] = defaultdict(dict)
    for rtype, n in usage.items():
        by_namespace[rtype.split("/")[0]][rtype] = n
    rows = []
    for p in providers:
        ns = p.get("namespace") or ""
        types = by_namespace.get(ns.lower(), {})
        status = provider_status(p.get("registrationState") or "", p.get("registrationPolicy") or "", bool(types))
        rows.append({"namespace": ns, "state": p.get("registrationState") or "",
                     "registration_policy": p.get("registrationPolicy") or "", "status": status,
                     "resources": sum(types.values()), "types": dict(sorted(types.items(), key=lambda kv: -kv[1]))})
    known = {r["namespace"].lower() for r in rows}
    for ns, types in by_namespace.items():  # in use but absent from the provider list (should not happen)
        if ns not in known:
            rows.append({"namespace": ns, "state": "", "registration_policy": "", "status": "In use, not registered",
                         "resources": sum(types.values()), "types": types})
    rows.sort(key=lambda r: (STATUS_ORDER.index(r["status"]), -r["resources"], r["namespace"].lower()))
    policies = applicable_policies(subscription_id, ancestors, assignments)
    counts: Dict[str, int] = defaultdict(int)
    for r in rows:
        counts[r["status"]] += 1
    return {"providers": rows, "counts": dict(counts), "policies": policies,
            "denied_in_use": denied_types(usage, policies)}


async def get_provider_analysis(context: Any) -> Optional[Dict[str, Any]]:
    """Provider registration vs usage vs policy for context.subscription_id; None offline."""
    cache = getattr(context, "cache", None)
    if cache is not None and "provider_analysis" in cache:
        return cache["provider_analysis"]
    if getattr(context, "arm_client", None) is None or getattr(context, "resource_graph_client", None) is None:
        return None
    sub = context.subscription_id
    providers = await context.arm_client.get_all(f"/subscriptions/{sub}/providers", "2021-04-01")
    usage = {r["type"]: int(r["n"]) for r in (await query_resource_graph(context, USAGE_QUERY) or []) if r.get("type")}
    ancestors: List[str] = []
    try:
        for row in await query_resource_graph(context, ANCESTORS_QUERY) or []:
            ancestors += [str(m.get("name")) for m in (row.get("chain") or []) if isinstance(m, dict) and m.get("name")]
        assignments = await query_resource_graph(context, POLICY_QUERY, tenant_scope=True) or []
    except Exception as exc:  # policy view is optional: registration and usage still stand
        logger.info("Policy assignments unavailable for provider analysis: %s", exc)
        assignments = []
    result = build_analysis(sub, providers, usage, ancestors, assignments)
    if cache is not None:
        cache["provider_analysis"] = result
    return result
