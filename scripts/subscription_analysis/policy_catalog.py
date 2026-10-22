"""
Azure Policy in force, for the landing-zone view: every assignment (management group and subscription scope) resolved
to the policies it applies with their effective effect, the definitions behind them (built-in, custom, ALZ reference),
exemptions and compliance.

Definitions are compacted to what a comparison needs: display name, source, the resource properties (aliases) the
rule reads, the resource types it targets, its default effect, and the deprecated / preview flags. Assignments that
apply the same definition with the same parameters (Defender's default initiative on every subscription) share one
"profile", so the stored result stays small.

Sources: Resource Graph (assignments, custom definitions and initiatives, exemptions, compliance states) and one
paged ARM list of the built-in definitions and initiatives (Resource Graph does not return built-ins).
"""

import asyncio
import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

PARAM_REF = re.compile(r"^\[parameters\('([^']+)'\)\]$", re.IGNORECASE)
FIELD = re.compile(r'"field"\s*:\s*"([^"]+)"')
TYPE_CONDITION = re.compile(r'"field"\s*:\s*"type"\s*,\s*"(?:equals|like|in)"\s*:\s*(\[[^\]]*\]|"[^"]+")', re.IGNORECASE)
# fields every policy can read - they say nothing about what a policy controls
GENERIC_FIELDS = {"type", "name", "location", "kind", "tags", "id", "fullname", "identity.type"}
BUILTIN_TTL_SECONDS = 12 * 3600

ASSIGNMENT_QUERY = """
policyresources
| where type =~ 'microsoft.authorization/policyassignments'
| project id = tolower(id), name, display = tostring(properties.displayName), scope = tolower(tostring(properties.scope)),
          definition = tolower(tostring(properties.policyDefinitionId)),
          enforcement = tostring(properties.enforcementMode), parameters = properties.parameters,
          not_scopes = array_length(properties.notScopes), not_scope_list = properties.notScopes,
          identity = tostring(identity.type), created = tostring(properties.metadata.createdOn)
"""
# Resource Graph also returns the built-in, static (regulatory control) and capability definitions - keep only the
# tenant's own; built-ins come from the ARM catalogue with their real source
CUSTOM_DEFINITION_QUERY = """
policyresources
| where type =~ 'microsoft.authorization/policydefinitions'
| where tostring(properties.policyType) =~ 'Custom'
| project id = tolower(id), props = properties
"""
CUSTOM_SET_QUERY = """
policyresources
| where type =~ 'microsoft.authorization/policysetdefinitions'
| where tostring(properties.policyType) =~ 'Custom'
| project id = tolower(id), props = properties
"""
EXEMPTION_QUERY = """
policyresources
| where type =~ 'microsoft.authorization/policyexemptions'
| project id = tolower(id), display = tostring(properties.displayName), category = tostring(properties.exemptionCategory),
          assignment = tolower(tostring(properties.policyAssignmentId)), expires = tostring(properties.expiresOn),
          references = array_length(properties.policyDefinitionReferenceIds)
"""
COMPLIANCE_QUERY = """
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend assignment = tolower(tostring(properties.policyAssignmentId)), resource = tolower(tostring(properties.resourceId)),
         noncompliant = tostring(properties.complianceState) =~ 'NonCompliant'
| summarize bad = max(toint(noncompliant)) by assignment, resource
| summarize noncompliant = sum(bad), resources = count() by assignment
"""
# policy analyzer: distinct non-compliant / evaluated resources per subscription, and per policy of each assignment
SUBSCRIPTION_COMPLIANCE_QUERY = """
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend resource = tolower(tostring(properties.resourceId)), sub = tolower(subscriptionId),
         bad = toint(tostring(properties.complianceState) =~ 'NonCompliant')
| summarize bad = max(bad) by sub, resource
| summarize noncompliant = sum(bad), resources = count() by sub
"""
POLICY_COMPLIANCE_QUERY = """
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| where tostring(properties.complianceState) =~ 'NonCompliant'
| summarize noncompliant = dcount(tolower(tostring(properties.resourceId)))
          by assignment = tolower(tostring(properties.policyAssignmentId)),
             definition = tolower(tostring(properties.policyDefinitionId))
"""


# ---------------------------------------------------------------------------
# Definitions
# ---------------------------------------------------------------------------

def rule_footprint(rule: Any) -> Tuple[List[str], List[str]]:
    """(aliases, resource types) a policy rule reads - what it actually controls."""
    text = json.dumps(rule or {})
    aliases = {f.lower().replace("[*]", "") for f in FIELD.findall(text)}
    types = set()
    for match in TYPE_CONDITION.findall(text):
        try:
            value = json.loads(match)
        except ValueError:
            continue
        types.update(str(v).lower() for v in (value if isinstance(value, list) else [value])
                     if isinstance(v, str) and "/" in v and "[" not in v)
    return sorted(a for a in aliases if a not in GENERIC_FIELDS and "/" in a), sorted(types)


def compact_definition(props: Dict[str, Any], source: str) -> Dict[str, Any]:
    metadata = props.get("metadata") or {}
    display = props.get("displayName") or ""
    effect = str(((props.get("policyRule") or {}).get("then") or {}).get("effect") or "")
    param = PARAM_REF.match(effect)
    effect_param = param.group(1) if param else None
    if effect_param:
        spec = (props.get("parameters") or {}).get(effect_param) or {}
        effect = str(spec.get("defaultValue") or "")
    aliases, types = rule_footprint(props.get("policyRule"))
    return {"display": display, "source": source, "category": metadata.get("category") or "",
            "version": props.get("version") or metadata.get("version") or "",
            "deprecated": bool(metadata.get("deprecated")) or display.lower().startswith("[deprecated]"),
            "preview": bool(metadata.get("preview")) or display.lower().startswith("[preview]"),
            "effect": effect.lower(), "effect_param": effect_param, "aliases": aliases, "types": types}


def compact_set(props: Dict[str, Any], source: str, key_of) -> Dict[str, Any]:
    metadata = props.get("metadata") or {}
    display = props.get("displayName") or ""
    members = []
    for m in props.get("policyDefinitions") or []:
        members.append({"def": key_of(m.get("policyDefinitionId") or ""),
                        "params": {k: (v or {}).get("value") for k, v in (m.get("parameters") or {}).items()}})
    return {"display": display, "source": source, "category": metadata.get("category") or "", "set": True,
            "deprecated": bool(metadata.get("deprecated")) or display.lower().startswith("[deprecated]"),
            "preview": bool(metadata.get("preview")) or display.lower().startswith("[preview]"),
            "defaults": {k: (v or {}).get("defaultValue") for k, v in (props.get("parameters") or {}).items()},
            "members": members}


def definition_key(definition_id: str) -> str:
    """A tenant definition's key: its lower-case resource ID."""
    return (definition_id or "").lower()


def library_key(definition_id: str) -> str:
    """An ALZ library reference: its own definitions sit on an example management group ('placeholder', 'contoso')
    and become 'alz:<name>'; built-ins keep their ID."""
    value = (definition_id or "").lower()
    if "/managementgroups/" in value or "${" in value:
        return "alz:" + value.rsplit("/", 1)[-1]
    return value


def _param_value(spec: Any) -> Any:
    return spec.get("value") if isinstance(spec, dict) and "value" in spec else spec


def member_effect(definition: Optional[Dict[str, Any]], member_params: Dict[str, Any],
                  set_defaults: Dict[str, Any], assignment_params: Dict[str, Any]) -> str:
    """The effect one policy of an assignment runs with: assignment parameter > initiative default > definition."""
    if not definition:
        return ""
    name = definition.get("effect_param")
    if not name:
        return definition.get("effect") or ""
    value = member_params.get(name) if member_params else None
    if value is None and not member_params:   # a policy assigned on its own
        value = _param_value(assignment_params.get(name))
    ref = PARAM_REF.match(str(value)) if isinstance(value, str) else None
    if ref:
        outer = ref.group(1)
        value = _param_value(assignment_params[outer]) if outer in assignment_params else set_defaults.get(outer)
    return str(value).lower() if value not in (None, "") else (definition.get("effect") or "")


# ---------------------------------------------------------------------------
# Built-ins (one paged ARM list each, cached per process)
# ---------------------------------------------------------------------------

_BUILTIN_CACHE: Dict[str, Any] = {"at": 0.0, "defs": None, "sets": None}
_BUILTIN_LOCK = threading.Lock()


def builtin_catalog(arm: Any) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """({key: compact definition}, {key: compact initiative}) of every built-in policy - about 7 s, cached 12 h."""
    with _BUILTIN_LOCK:
        if _BUILTIN_CACHE["defs"] is not None and time.time() - _BUILTIN_CACHE["at"] < BUILTIN_TTL_SECONDS:
            return _BUILTIN_CACHE["defs"], _BUILTIN_CACHE["sets"]
        query = {"$filter": "policyType eq 'BuiltIn'"}
        defs = {definition_key(d["id"]): compact_definition(d.get("properties") or {}, "BuiltIn")
                for d in arm._get_all_sync("/providers/Microsoft.Authorization/policyDefinitions", "2023-04-01", query)}
        sets = {definition_key(s["id"]): compact_set(s.get("properties") or {}, "BuiltIn", definition_key)
                for s in arm._get_all_sync("/providers/Microsoft.Authorization/policySetDefinitions", "2023-04-01",
                                           query)}
        _BUILTIN_CACHE.update(at=time.time(), defs=defs, sets=sets)
        return defs, sets


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def resolve(definition: str, parameters: Dict[str, Any], defs: Dict[str, Dict[str, Any]],
            sets: Dict[str, Dict[str, Any]], key_of=definition_key) -> List[Tuple[str, str]]:
    """[(policy definition key, effective effect)] an assignment of `definition` applies."""
    key = key_of(definition)
    params = parameters or {}
    if key in sets:
        s = sets[key]
        return [(m["def"], member_effect(defs.get(m["def"]), m.get("params") or {}, s.get("defaults") or {}, params))
                for m in s.get("members") or []]
    return [(key, member_effect(defs.get(key), {}, {}, params))]


def _profile_id(definition: str, parameters: Dict[str, Any]) -> str:
    raw = json.dumps([definition_key(definition), parameters or {}], sort_keys=True, default=str)
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def build_policy(assignments: Iterable[Dict[str, Any]], defs: Dict[str, Dict[str, Any]],
                 sets: Dict[str, Dict[str, Any]], exemptions: Iterable[Dict[str, Any]] = (),
                 compliance: Iterable[Dict[str, Any]] = (), extra_keys: Iterable[str] = ()) -> Dict[str, Any]:
    """The stored form: assignments -> shared profiles -> the definitions they (and the ALZ comparison) need."""
    profiles: Dict[str, Dict[str, Any]] = {}
    out_assignments = []
    states = {(c.get("assignment") or ""): c for c in compliance}
    for a in assignments:
        pid = _profile_id(a.get("definition") or "", a.get("parameters") or {})
        if pid not in profiles:
            profiles[pid] = {"def": definition_key(a.get("definition") or ""),
                             "members": [list(m) for m in resolve(a.get("definition") or "", a.get("parameters") or {},
                                                                  defs, sets)]}
        state = states.get(a.get("id") or "") or {}
        out_assignments.append({
            "id": a.get("id"), "name": a.get("name"), "display": a.get("display") or a.get("name"),
            "scope": a.get("scope") or "", "enforcement": a.get("enforcement") or "Default", "profile": pid,
            "not_scopes": a.get("not_scopes") or 0,
            "not_scope_list": [str(x).lower() for x in a.get("not_scope_list") or []],
            "identity": a.get("identity") or "", "created": (a.get("created") or "")[:10] or None,
            "noncompliant": state.get("noncompliant"), "resources": state.get("resources")})
    needed = {p["def"] for p in profiles.values()} | {m[0] for p in profiles.values() for m in p["members"]}
    needed |= set(extra_keys)
    definitions = {}
    for key in sorted(needed):
        if key in defs:
            definitions[key] = defs[key]
        elif key in sets:
            s = sets[key]
            definitions[key] = {k: s[k] for k in ("display", "source", "category", "deprecated", "preview", "set")}
            definitions[key]["members"] = len(s.get("members") or [])
    return {"collected_at": datetime.now(timezone.utc).isoformat(), "assignments": out_assignments,
            "profiles": profiles, "definitions": definitions,
            "exemptions": [dict(e) for e in exemptions]}


async def collect_policy(credential: Any, arg_rows, client: Any, extra_keys: Iterable[str] = ()) -> Dict[str, Any]:
    """Live collection - tenant scope (every subscription and management group the identity can read)."""
    from scanners.base.azure_api import ArmClient

    assignments = await arg_rows(client, ASSIGNMENT_QUERY)
    custom_defs = {definition_key(r["id"]): compact_definition(r.get("props") or {}, "Custom")
                   for r in await arg_rows(client, CUSTOM_DEFINITION_QUERY)}
    custom_sets = {definition_key(r["id"]): compact_set(r.get("props") or {}, "Custom", definition_key)
                   for r in await arg_rows(client, CUSTOM_SET_QUERY)}
    try:
        exemptions = await arg_rows(client, EXEMPTION_QUERY)
    except Exception:
        exemptions = []
    try:
        compliance = await arg_rows(client, COMPLIANCE_QUERY)
    except Exception:
        compliance = []
    detail: Dict[str, Any] = {}
    for key, query in (("by_subscription", SUBSCRIPTION_COMPLIANCE_QUERY), ("by_policy", POLICY_COMPLIANCE_QUERY)):
        try:   # the policy analyzer's breakdowns; the rest stands without them
            detail[key] = await arg_rows(client, query)
        except Exception:
            detail[key] = []
    builtin_defs, builtin_sets = await asyncio.to_thread(builtin_catalog, ArmClient(credential))
    result = with_reference(assignments, builtin_defs, builtin_sets, custom_defs, custom_sets, exemptions, compliance,
                            extra_keys)
    result["compliance"] = detail
    used = set(result["definitions"])
    result["unassigned_custom"] = sorted(
        ({"key": k, "display": d.get("display") or k, "category": d.get("category") or "", "set": bool(d.get("set"))}
         for k, d in {**custom_defs, **custom_sets}.items() if k not in used), key=lambda d: d["display"].lower())
    return result


def with_reference(assignments, builtin_defs, builtin_sets, custom_defs, custom_sets, exemptions=(), compliance=(),
                   extra_keys: Iterable[str] = ()) -> Dict[str, Any]:
    """build_policy plus the ALZ reference controls, resolved against the same built-ins."""
    from scripts.subscription_analysis import landing_zone

    reference = landing_zone.load_reference()
    defs = {**builtin_defs, **reference["definitions"], **custom_defs}
    sets = {**builtin_sets, **reference["sets"], **custom_sets}
    controls = landing_zone.reference_controls(reference, defs, sets)
    result = build_policy(assignments, defs, sets, exemptions, compliance,
                          set(extra_keys) | {k for members in controls.values() for k, _ in members})
    result["reference"] = {"release": reference["release"], "controls": controls}
    result["builtin_definitions"] = len(builtin_defs)
    # How many built-in policies read each property: one read by hundreds (VM image publisher, SKU name) only
    # selects resources and says nothing about what a policy controls.
    frequency: Dict[str, int] = {}
    for d in builtin_defs.values():
        for alias in d.get("aliases") or []:
            frequency[alias] = frequency.get(alias, 0) + 1
    stored = {a for d in result["definitions"].values() for a in d.get("aliases") or []}
    result["alias_frequency"] = {a: frequency[a] for a in stored if a in frequency}
    return result


def merge_policy(parts: Iterable[Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    """One policy collection from several tenants'."""
    out: Dict[str, Any] = {"assignments": [], "profiles": {}, "definitions": {}, "exemptions": [],
                           "compliance": {"by_subscription": [], "by_policy": []}, "unassigned_custom": []}
    seen = set()
    for part in parts:
        if not part or part.get("error"):
            continue
        out["collected_at"] = part.get("collected_at")
        for a in part.get("assignments") or []:
            if a.get("id") not in seen:
                seen.add(a.get("id"))
                out["assignments"].append(a)
        out["profiles"].update(part.get("profiles") or {})
        out["definitions"].update(part.get("definitions") or {})
        out["exemptions"].extend(part.get("exemptions") or [])
        for key in ("by_subscription", "by_policy"):
            out["compliance"][key].extend((part.get("compliance") or {}).get(key) or [])
        out["unassigned_custom"].extend(part.get("unassigned_custom") or [])
    return out
