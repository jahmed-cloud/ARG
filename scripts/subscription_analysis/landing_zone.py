"""
Landing-zone view: the tenant's management groups, policy and network compared with Microsoft's Azure Landing Zones
(ALZ) reference - github.com/Azure/Azure-Landing-Zones-Library (MIT), one pinned release in ./alz_library.

1. Structure. Each management group is mapped to an ALZ archetype (intermediate root, platform, connectivity,
   identity, management, landing zones, corp, online, sandbox, decommissioned): from the `landing_zone_mapping`
   setting, else from its name, else from its position (children of the intermediate root that hold subscriptions
   are landing zones). Groups outside the intermediate root get no root-level guardrails - said so.
2. Controls. Every ALZ policy assignment of an archetype is checked at the management groups mapped to it, against
   the policy in force there (assigned on the group or above, or on its subscriptions):
   in place / audit only (ALZ denies or remediates, the tenant only audits or does not enforce) / on some
   subscriptions / similar (the tenant's own policy reads the same resource properties - named, to confirm) /
   disabled / missing. An ALZ initiative counts member by member.
3. Policy depth per management group: what is assigned (initiative or policy, how many policies, built-in / custom,
   effects), non-compliant resources, exemptions (without expiry or expired), deprecated policies in force.
4. Connectivity: hubs (firewall and its policy, gateways, Bastion, DNS resolver) and per spoke - peered to a hub,
   default route through the firewall / NVA, DNS that resolves private endpoints, DDoS, subnets without NSG.
"""

import ipaddress
import json
import re
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from scripts.subscription_analysis.policy_catalog import (
    compact_definition,
    compact_set,
    library_key,
    resolve,
)

LIBRARY = Path(__file__).parent / "alz_library"
ARCHETYPE_LABELS = {
    "root": "Intermediate root", "platform": "Platform", "landing_zones": "Landing zones", "corp": "Corp",
    "online": "Online", "local": "Local", "sandbox": "Sandbox", "security": "Security",
    "management": "Management", "connectivity": "Connectivity", "identity": "Identity",
    "decommissioned": "Decommissioned",
}
# most specific first - a "Connectivity" group under "Platform" is connectivity, not platform
NAME_RULES: List[Tuple[str, re.Pattern]] = [
    ("decommissioned", re.compile(r"decommission", re.I)),
    ("sandbox", re.compile(r"sandbox", re.I)),
    ("connectivity", re.compile(r"connectivity|networking|\bhub\b", re.I)),
    ("identity", re.compile(r"identity", re.I)),
    ("management", re.compile(r"\bmanagement\b|\bmgmt\b|monitoring", re.I)),
    ("security", re.compile(r"\bsecurity\b|\bsoc\b", re.I)),
    ("platform", re.compile(r"platform", re.I)),
    ("corp", re.compile(r"\bcorp\b|corporate", re.I)),
    ("online", re.compile(r"\bonline\b", re.I)),
    ("local", re.compile(r"\blocal\b", re.I)),
    ("landing_zones", re.compile(r"landing ?zones?|\blz\b|workloads?", re.I)),
]
CANARY = re.compile(r"test|canary|epac|\bdev\b", re.I)
# third-party firewalls run as VMs in the hub (Palo Alto, Fortinet, Check Point, ...): recognised by name
FIREWALL_VM = re.compile(r"fw|firewall|palo|forti|checkpoint|\bnva\b|sophos|\basa\b", re.I)
SPECIAL_SUBNETS = {"gatewaysubnet", "azurefirewallsubnet", "azurefirewallmanagementsubnet", "azurebastionsubnet",
                   "routeserversubnet"}

IN_PLACE, AUDIT_ONLY, SOME_SUBS, SIMILAR, DISABLED, MISSING = (
    "in place", "audit only", "some subscriptions", "similar", "disabled", "missing")
UNRESOLVED = "not resolved"
STATUS_ORDER = [IN_PLACE, AUDIT_ONLY, SOME_SUBS, SIMILAR, DISABLED, MISSING]
SIMILAR_SHARE = 0.6
SELECTOR_FREQUENCY = 40   # a property read by more built-in policies than this only selects resources


# ---------------------------------------------------------------------------
# ALZ reference
# ---------------------------------------------------------------------------

def _read(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=2)
def load_reference(library: Path = LIBRARY) -> Dict[str, Any]:
    """Architecture, archetypes, assignments, definitions and initiatives of the pinned ALZ release."""
    architecture = _read(next((library / "architecture_definitions").glob("*.json")))
    archetypes = {}
    for path in (library / "archetype_definitions").glob("*.json"):
        doc = _read(path)
        archetypes[doc["name"]] = list(doc.get("policy_assignments") or [])
    assignments = {}
    for path in (library / "policy_assignments").glob("*.json"):
        doc = _read(path)
        p = doc.get("properties") or {}
        assignments[doc["name"]] = {"display": p.get("displayName") or doc["name"], "description": p.get("description") or "",
                                    "definition": p.get("policyDefinitionId") or "", "parameters": p.get("parameters") or {},
                                    "enforcement": p.get("enforcementMode") or "Default"}
    definitions = {library_key(f"/managementGroups/x/providers/Microsoft.Authorization/policyDefinitions/{d['name']}"):
                   compact_definition(d.get("properties") or {}, "ALZ")
                   for d in (_read(p) for p in (library / "policy_definitions").glob("*.json"))}
    sets = {library_key(f"/managementGroups/x/providers/Microsoft.Authorization/policySetDefinitions/{s['name']}"):
            compact_set(s.get("properties") or {}, "ALZ", library_key)
            for s in (_read(p) for p in (library / "policy_set_definitions").glob("*.json"))}
    source = library / "SOURCE.md"
    match = re.search(r"release `([^`]+)`", source.read_text(encoding="utf-8")) if source.is_file() else None
    return {"release": match.group(1) if match else "unknown", "groups": architecture.get("management_groups") or [],
            "archetypes": archetypes, "assignments": assignments, "definitions": definitions, "sets": sets}


def reference_controls(reference: Dict[str, Any], defs: Dict[str, Dict[str, Any]],
                       sets: Dict[str, Dict[str, Any]]) -> Dict[str, List[List[str]]]:
    """{ALZ assignment name: [[policy key, effect ALZ runs it with], ...]}."""
    out = {}
    for name, a in reference["assignments"].items():
        params = {k: v for k, v in (a.get("parameters") or {}).items()}
        out[name] = [list(m) for m in resolve(a["definition"], params, defs, sets, key_of=library_key)]
    return out


# ---------------------------------------------------------------------------
# Management-group mapping
# ---------------------------------------------------------------------------

def parse_mapping(text: Any) -> Dict[str, str]:
    """'Corp workloads = corp; Online apps = online' (or the setting's list of such lines) ->
    {name or ID (lower): archetype}."""
    if isinstance(text, dict):
        items = text.items()
    else:
        lines = text if isinstance(text, (list, tuple)) else [str(text or "")]
        items = (part.split("=", 1) for line in lines for part in re.split(r"[;\n]+", str(line)) if "=" in part)
    out = {}
    for name, archetype in items:
        key = str(archetype).strip().lower().replace(" ", "_").replace("landingzones", "landing_zones")
        if key in ARCHETYPE_LABELS or key in ("none", "outside"):
            out[str(name).strip().lower()] = key
    return out


def _tree(groups: Dict[str, Dict[str, Any]]) -> Tuple[Optional[str], Dict[str, List[str]]]:
    children: Dict[str, List[str]] = defaultdict(list)
    for name, g in groups.items():
        if g.get("parent") in groups:
            children[g["parent"]].append(name)
    roots = [n for n, g in groups.items() if g.get("parent") not in groups]
    return (roots[0] if roots else None), children


def map_groups(arch: Dict[str, Any], mapping: Any = None) -> Dict[str, Any]:
    """Archetype per management group, the tenant root, the intermediate root and subscription counts."""
    groups = arch.get("management_groups") or {}
    parents = arch.get("subscription_parents") or {}
    tenant_root, children = _tree(groups)
    direct = Counter(chain[0] for chain in parents.values() if chain)
    subtree: Dict[str, int] = {}

    def count(name: str) -> int:
        subtree[name] = direct.get(name, 0) + sum(count(c) for c in children.get(name, []))
        return subtree[name]
    if tenant_root:
        count(tenant_root)
    overrides = parse_mapping(mapping)

    def override(name: str) -> Optional[str]:
        g = groups.get(name) or {}
        return overrides.get(name.lower()) or overrides.get(str(g.get("displayName") or "").lower())

    candidates = [c for c in children.get(tenant_root, []) if override(c) != "outside"] if tenant_root else []
    root = next((n for n in groups if override(n) == "root"), None)
    if root is None:
        root = max(candidates, key=lambda c: subtree.get(c, 0), default=tenant_root)
        if root and subtree.get(root, 0) * 2 < subtree.get(tenant_root, 0):
            root = tenant_root   # no child holds most subscriptions: the tenant root is the root
    inside: set = set()

    def walk(name: str) -> None:
        inside.add(name)
        for c in children.get(name, []):
            walk(c)
    if root:
        walk(root)

    result: Dict[str, Dict[str, Any]] = {}

    def assign(name: str, inherited: Optional[str], depth: int) -> None:
        g = groups.get(name) or {}
        display = g.get("displayName") or name
        archetype, how = override(name), "setting"
        if archetype is None:
            if name == root:
                archetype, how = "root", "position"
            elif name not in inside:
                archetype, how = None, None
            else:
                archetype = next((a for a, rule in NAME_RULES if rule.search(display) or rule.search(name)), None)
                how = "name"
                if archetype is None and g.get("parent") == root and subtree.get(name, 0):
                    archetype, how = "landing_zones", "position"
                elif archetype is None and inherited:
                    archetype, how = inherited, "inherited"
        archetype = None if archetype in ("none", "outside") else archetype
        result[name] = {"name": name, "display": display, "parent": g.get("parent"), "depth": depth,
                        "archetype": archetype, "mapped_by": how if archetype else None,
                        "inside": name in inside, "tenant_root": name == tenant_root,
                        "canary": name not in inside and bool(CANARY.search(display)),
                        "subscriptions": direct.get(name, 0), "subtree_subscriptions": subtree.get(name, 0)}
        for c in sorted(children.get(name, []), key=lambda n: (groups[n].get("displayName") or n).lower()):
            assign(c, archetype if archetype not in (None, "root") else None, depth + 1)
    if tenant_root:
        assign(tenant_root, None, 0)
    return {"tenant_root": tenant_root, "root": root, "groups": result, "children": dict(children)}


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

def effect_class(effect: str) -> str:
    e = (effect or "").lower()
    if e in ("deny", "denyaction"):
        return "deny"
    if e in ("deployifnotexists", "modify", "append"):
        return "remediate"
    if e == "disabled":
        return "disabled"
    return "audit" if e else ""


def _scope_kind(scope: str) -> Tuple[str, str]:
    s = (scope or "").lower()
    if "/managementgroups/" in s:
        return "mg", s.rsplit("/", 1)[-1]
    if s.startswith("/subscriptions/"):
        return "sub", s.split("/")[2]
    return "other", s


def _ancestors(name: str, groups: Dict[str, Dict[str, Any]]) -> List[str]:
    chain, seen = [], set()
    while name and name in groups and name not in seen:
        seen.add(name)
        chain.append(name)
        name = groups[name].get("parent")
    return chain


class PolicyIndex:
    """Policy in force per management group and subscription, by definition."""

    def __init__(self, policy: Dict[str, Any], arch: Dict[str, Any]):
        self.policy = policy or {}
        self.groups = arch.get("management_groups") or {}
        self.sub_parents = arch.get("subscription_parents") or {}
        self.defs = self.policy.get("definitions") or {}
        self.profiles = self.policy.get("profiles") or {}
        self.by_group: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.by_sub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for a in self.policy.get("assignments") or []:
            kind, key = _scope_kind(a.get("scope") or "")
            if kind == "mg":
                self.by_group[key].append(a)
            elif kind == "sub":
                self.by_sub[key].append(a)

    def members(self, a: Dict[str, Any]) -> List[List[str]]:
        return (self.profiles.get(a.get("profile")) or {}).get("members") or []

    def in_force(self, group: str) -> List[Dict[str, Any]]:
        """Assignments on the group or any group above it."""
        return [a for g in _ancestors(group, self.groups) for a in self.by_group.get(g, [])]

    def subscriptions_under(self, group: str) -> List[str]:
        return [s for s, chain in self.sub_parents.items() if group in (chain or [])]


def _match(key: str, alz_effect: str, assignments: List[Dict[str, Any]], index: PolicyIndex
           ) -> Optional[Tuple[str, str]]:
    """(status, detail) when the same policy is assigned in `assignments`."""
    best = None
    for a in assignments:
        for member_key, effect in index.members(a):
            if member_key != key:
                continue
            tenant = effect_class(effect)
            wanted = effect_class(alz_effect)
            if tenant == "disabled":
                status = DISABLED
            elif (a.get("enforcement") or "Default") == "DoNotEnforce" or (
                    wanted in ("deny", "remediate") and tenant == "audit"):
                status = AUDIT_ONLY
            else:
                status = IN_PLACE
            detail = f"{a.get('display')} ({effect or 'default'}"
            detail += ", not enforced)" if (a.get("enforcement") or "") == "DoNotEnforce" else ")"
            if best is None or STATUS_ORDER.index(status) < STATUS_ORDER.index(best[0]):
                best = (status, detail)
    return best


def _distinctive(aliases: Iterable[str], index: PolicyIndex) -> set:
    """Properties that say what a policy controls - not the selectors hundreds of built-ins share."""
    frequency = index.policy.get("alias_frequency") or {}
    return {a for a in aliases if frequency.get(a, 0) <= SELECTOR_FREQUENCY}


def _similar(key: str, assignments: List[Dict[str, Any]], index: PolicyIndex) -> Optional[str]:
    """A tenant policy reading most of the same distinctive resource properties - named, for a person to confirm."""
    ref = index.defs.get(key) or {}
    wanted = _distinctive(ref.get("aliases") or [], index)
    types = set(ref.get("types") or [])
    if not wanted:
        return None
    best: Tuple[float, str] = (0.0, "")
    for a in assignments:
        for member_key, _ in index.members(a):
            d = index.defs.get(member_key) or {}
            shared = wanted & set(d.get("aliases") or [])
            if not shared or (types and d.get("types") and not types & set(d["types"])):
                continue
            share = len(shared) / len(wanted)
            if share >= SIMILAR_SHARE and share > best[0]:
                best = (share, f"{d.get('display') or member_key} in {a.get('display')}")
    return best[1] or None


def control_status(key: str, alz_effect: str, group: str, index: PolicyIndex) -> Tuple[str, str]:
    in_force = index.in_force(group)
    found = _match(key, alz_effect, in_force, index)
    if found and found[0] in (IN_PLACE, AUDIT_ONLY, DISABLED):
        return found
    subs = index.subscriptions_under(group)
    per_sub = [m for m in (_match(key, alz_effect, index.by_sub.get(s, []), index) for s in subs) if m]
    if per_sub:
        worst = max(per_sub, key=lambda m: STATUS_ORDER.index(m[0]))
        if len(per_sub) == len(subs):   # every subscription has it: as good as the weakest of them
            return worst[0], f"on every subscription (assigned per subscription): {worst[1]}"
        return SOME_SUBS, f"on {len(per_sub)} of {len(subs)} subscriptions ({worst[0]}): {worst[1]}"
    similar = _similar(key, in_force, index)
    if similar:
        return SIMILAR, similar
    return MISSING, ""


def evaluate_controls(mapping: Dict[str, Any], index: PolicyIndex, reference: Dict[str, Any],
                      controls: Dict[str, List[List[str]]]) -> Dict[str, Any]:
    """Per archetype: its ALZ assignments, rated at each management group mapped to it."""
    groups_by_archetype: Dict[str, List[str]] = defaultdict(list)
    for name, g in mapping["groups"].items():
        if g["archetype"] and g["mapped_by"] in ("setting", "name", "position"):
            groups_by_archetype[g["archetype"]].append(name)
    out = {}
    for archetype, names in reference["archetypes"].items():
        rows = []
        for alz_name in names:
            a = reference["assignments"].get(alz_name) or {}
            members = controls.get(alz_name) or []
            effects = Counter(effect_class(e) or "default" for _, e in members)
            row = {"name": alz_name, "display": a.get("display") or alz_name, "description": a.get("description") or "",
                   "policies": len(members), "effects": dict(effects), "groups": {}}
            for group in groups_by_archetype.get(archetype, []):
                statuses = [control_status(k, e, group, index) for k, e in members]
                counts = Counter(s for s, _ in statuses)
                if not members:   # its definitions are not in this tenant's catalogue: cannot be judged
                    row["groups"][group] = {"status": UNRESOLVED, "detail": "policy definitions not found",
                                            "counts": {}}
                    continue
                if len(members) == 1:
                    status, detail = statuses[0] if statuses else (MISSING, "")
                else:
                    status = (IN_PLACE if counts[IN_PLACE] == len(members) else
                              MISSING if counts[MISSING] == len(members) else "partly")
                    detail = ", ".join(f"{counts[s]} {s}" for s in STATUS_ORDER if counts[s]) + f" of {len(members)}"
                row["groups"][group] = {"status": status, "detail": detail, "counts": dict(counts)}
            rows.append(row)
        out[archetype] = {"groups": groups_by_archetype.get(archetype, []), "controls": rows}
    return out


# ---------------------------------------------------------------------------
# Policy depth, exemptions, deprecated
# ---------------------------------------------------------------------------

def _assignment_row(a: Dict[str, Any], index: PolicyIndex, exemptions: Dict[str, List[Dict[str, Any]]]
                    ) -> Dict[str, Any]:
    profile = index.profiles.get(a.get("profile")) or {}
    head = index.defs.get(profile.get("def")) or {}
    members = profile.get("members") or []
    sources = Counter((index.defs.get(k) or {}).get("source") or "?" for k, _ in members)
    effects = Counter(effect_class(e) or "default" for _, e in members)
    ex = exemptions.get(a.get("id") or "", [])
    return {"display": a.get("display"), "initiative": bool(head.get("set")), "policies": len(members),
            "source": head.get("source") or ("Custom" if "/managementgroups/" in (profile.get("def") or "") else "?"),
            "sources": dict(sources), "effects": dict(effects), "enforcement": a.get("enforcement") or "Default",
            "noncompliant": a.get("noncompliant"), "resources": a.get("resources"), "exemptions": len(ex),
            "deprecated": sum(1 for k, _ in members if (index.defs.get(k) or {}).get("deprecated"))}


def policy_depth(mapping: Dict[str, Any], index: PolicyIndex, subscription_names: Dict[str, str],
                 today: str) -> Dict[str, Any]:
    exemptions: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in index.policy.get("exemptions") or []:
        exemptions[e.get("assignment") or ""].append(e)
    by_group = {}
    for name in mapping["groups"]:
        by_group[name] = {"direct": [_assignment_row(a, index, exemptions) for a in index.by_group.get(name, [])],
                          "inherited": len(index.in_force(name)) - len(index.by_group.get(name, []))}
    group_names = {n: g["display"] for n, g in mapping["groups"].items()}

    def scope_label(scope: str) -> str:
        kind, key = _scope_kind(scope)
        if kind == "mg":
            return group_names.get(key, key)
        if kind == "sub":
            return subscription_names.get(key, key)
        return scope

    deprecated = []
    for a in index.policy.get("assignments") or []:
        for k, effect in index.members(a):
            d = index.defs.get(k) or {}
            if d.get("deprecated") and effect_class(effect) != "disabled":
                deprecated.append({"policy": d.get("display") or k, "assignment": a.get("display"),
                                   "scope": scope_label(a.get("scope") or "")})
    unique_deprecated = {(d["policy"], d["assignment"]): d for d in deprecated}
    exemption_rows = []
    assignment_names = {a.get("id"): a.get("display") for a in index.policy.get("assignments") or []}
    for e in index.policy.get("exemptions") or []:
        scope = (e.get("id") or "").split("/providers/microsoft.authorization/policyexemptions/")[0]
        expires = (e.get("expires") or "")[:10]
        exemption_rows.append({"display": e.get("display") or "", "scope": scope_label(scope) if scope else "",
                               "assignment": assignment_names.get(e.get("assignment"), e.get("assignment") or ""),
                               "category": e.get("category") or "", "expires": expires or "never",
                               "expired": bool(expires) and expires < today})
    sub_scope = Counter()
    for sub, items in index.by_sub.items():
        for a in items:
            sub_scope[a.get("display") or a.get("name")] += 1
    return {"by_group": by_group, "deprecated": sorted(unique_deprecated.values(), key=lambda d: d["policy"]),
            "deprecated_assignments": len(deprecated), "exemptions": exemption_rows,
            "subscription_scope": {"assignments": sum(sub_scope.values()), "subscriptions": len(index.by_sub),
                                   "most_common": sub_scope.most_common(8)}}


# ---------------------------------------------------------------------------
# Connectivity
# ---------------------------------------------------------------------------

def _networks(spaces: Iterable[str]) -> List[Any]:
    out = []
    for s in spaces or []:
        try:
            out.append(ipaddress.ip_network(str(s), strict=False))
        except ValueError:
            continue
    return out


def _in_any(ip: str, networks: List[Any]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in n for n in networks)


def connectivity(arch: Dict[str, Any], subscription_names: Dict[str, str]) -> Dict[str, Any]:
    vnets = {v["id"]: v for v in arch.get("vnets") or []}
    network = arch.get("network") or {}
    edge_by_vnet: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in network.get("edge") or []:
        for subnet in e.get("subnets") or []:
            edge_by_vnet[subnet.split("/subnets/")[0]].append(e)
    degree = Counter()
    for v in vnets.values():
        for p in v.get("peerings") or []:
            degree[v["id"]] += 1
    firewall_vms: Dict[str, List[str]] = defaultdict(list)
    for vm in network.get("vms") or []:
        name = (vm.get("id") or "").rsplit("/", 1)[-1]
        if FIREWALL_VM.search(name):
            for subnet in vm.get("subnets") or []:
                firewall_vms[subnet.split("/subnets/")[0]].append(name)
    subnet_names = {vid: {(s.get("name") or "").lower() for s in v.get("subnet_list") or []} for vid, v in vnets.items()}
    hubs = set()
    for vid, v in vnets.items():
        platform_edge = any(e.get("type") in ("microsoft.network/azurefirewalls", "microsoft.network/virtualnetworkgateways",
                                              "microsoft.network/networkvirtualappliances")
                            for e in edge_by_vnet.get(vid, []))
        platform_subnet = subnet_names[vid] & {"gatewaysubnet", "azurefirewallsubnet", "routeserversubnet"}
        if (degree[vid] >= 1 and (platform_subnet or platform_edge or firewall_vms.get(vid))) or degree[vid] >= 3:
            hubs.add(vid)
    hub_spaces = _networks(s for h in hubs for s in vnets[h].get("space") or [])
    routes = {r["id"]: r for r in network.get("route_tables") or []}
    pe_vnets = Counter((p.get("subnet") or "").split("/subnets/")[0] for p in network.get("private_endpoints") or [])
    links: Dict[str, List[str]] = defaultdict(list)
    for link in network.get("dns_links") or []:
        links[(link.get("vnet") or "").lower()].append(link.get("zone") or "")

    def peered(vid: str) -> List[str]:
        return [p.get("remote") for p in vnets[vid].get("peerings") or [] if p.get("remote") in vnets]

    hub_rows = []
    for vid in sorted(hubs, key=lambda h: vnets[h].get("name") or ""):
        v = vnets[vid]
        edge = edge_by_vnet.get(vid, [])
        firewalls = [e for e in edge if e.get("type") == "microsoft.network/azurefirewalls"]
        nva = sum(1 for e in edge if e.get("type") == "microsoft.network/networkvirtualappliances")
        nva_vms = sorted(set(firewall_vms.get(vid, [])))
        near = [vid] + peered(vid)
        hub_rows.append({
            "name": v.get("name"), "subscription": subscription_names.get(v.get("subscriptionId"), v.get("subscriptionId")),
            "subscriptionId": v.get("subscriptionId"), "location": v.get("location"), "spokes": degree[vid],
            "firewall": len(firewalls),
            # a policy is an Azure Firewall setting; NVAs carry their rules themselves
            "firewall_policy": all(e.get("firewall_policy") for e in firewalls) if firewalls else None,
            "nva": nva + len(nva_vms), "nva_vms": nva_vms[:6],
            "route_server": "routeserversubnet" in subnet_names[vid],
            "gateways": sorted({(e.get("gateway_type") or "gateway") for e in edge
                                if e.get("type") == "microsoft.network/virtualnetworkgateways"}),
            "bastion": any(e.get("type") == "microsoft.network/bastionhosts" for e in edge),
            "dns_resolver": any(e.get("type") == "microsoft.network/dnsresolvers"
                                for n in near for e in edge_by_vnet.get(n, [])),
            "ddos": bool(v.get("ddos"))})
    learns_from_hub = {h["name"] for h in hub_rows if h["route_server"] or h["gateways"]}

    spokes = []
    for vid, v in sorted(vnets.items(), key=lambda kv: (kv[1].get("name") or "").lower()):
        if vid in hubs or not v.get("subnets"):
            continue
        peers = [p for p in v.get("peerings") or []]
        to_hub = [p for p in peers if p.get("remote") in hubs or "/hv_" in (p.get("remote") or "")]
        vwan = any("/hv_" in (p.get("remote") or "") for p in peers)
        subnets = [s for s in v.get("subnet_list") or [] if (s.get("name") or "").lower() not in SPECIAL_SUBNETS]
        default_routes = []
        for s in subnets:
            table = routes.get(s.get("route_table") or "")
            default_routes.append((table or {}).get("default_route") or "")
        via_appliance = sum(1 for r in default_routes if r.startswith(("VirtualAppliance", "VirtualNetworkGateway")))
        explicit_internet = sum(1 for r in default_routes if r.startswith("Internet"))
        bgp = any(p.get("remote_gateways") and (vnets.get(p.get("remote")) or {}).get("name") in learns_from_hub
                  for p in to_hub)
        if vwan:
            route = "set by the virtual hub"
        elif subnets and via_appliance == len(subnets):
            route = "firewall / NVA"
        elif via_appliance:
            route = f"firewall / NVA on {via_appliance} of {len(subnets)} subnets"
        elif bgp and not explicit_internet:
            route = "learned from the hub (BGP)"
        else:
            route = "direct to Internet"
        dns = [d for d in v.get("dns") or [] if d]
        if dns and hub_spaces and all(_in_any(d, hub_spaces) for d in dns):
            dns_status = "hub DNS"
        elif dns:
            dns_status = "custom (" + ", ".join(dns[:2]) + ")"
        else:
            dns_status = "Azure DNS"
        privatelink = [z for z in links.get(vid.lower(), []) if z.startswith("privatelink.")]
        pe_count = pe_vnets.get(vid, 0)
        issues = []
        if peers and not to_hub:
            issues.append("peered, but not to a hub")
        elif not peers:
            issues.append("isolated - no peering")
        if route == "direct to Internet" and to_hub:
            issues.append("Internet traffic bypasses the hub firewall")
        if pe_count and dns_status == "Azure DNS" and not privatelink:
            issues.append(f"{pe_count} private endpoint(s) but no private DNS zone linked and no hub DNS")
        no_nsg = [s.get("name") for s in subnets if not s.get("nsg")]
        if no_nsg:
            issues.append(f"{len(no_nsg)} subnet(s) without NSG")
        spokes.append({"name": v.get("name"), "subscription": subscription_names.get(v.get("subscriptionId"),
                                                                                   v.get("subscriptionId")),
                       "subscriptionId": v.get("subscriptionId"), "location": v.get("location"),
                       "hub": bool(to_hub), "vwan": vwan, "gateway": any(p.get("remote_gateways") for p in to_hub),
                       "route": route, "dns": dns_status, "privatelink_zones": len(privatelink),
                       "private_endpoints": pe_count, "ddos": bool(v.get("ddos")), "subnets_without_nsg": len(no_nsg),
                       "issues": issues})
    return {"hubs": hub_rows, "spokes": spokes,
            "summary": {"hubs": len(hub_rows), "spokes": len(spokes),
                        "spokes_on_hub": sum(1 for s in spokes if s["hub"]),
                        "isolated": sum(1 for s in spokes if not s["hub"]),
                        "forced_tunnel": sum(1 for s in spokes if s["route"] in (
                            "firewall / NVA", "set by the virtual hub", "learned from the hub (BGP)")),
                        "bgp": sum(1 for s in spokes if s["route"] == "learned from the hub (BGP)"),
                        "dns_gaps": sum(1 for s in spokes if any("private DNS" in i for i in s["issues"])),
                        "ddos": sum(1 for s in spokes if s["ddos"]),
                        "hub_subscriptions": sorted({h["subscriptionId"] for h in hub_rows if h.get("subscriptionId")})}}


# ---------------------------------------------------------------------------
# Whole analysis
# ---------------------------------------------------------------------------

def analyse(data: Dict[str, Any], policy: Optional[Dict[str, Any]], mapping: Any = None,
            today: Optional[str] = None) -> Dict[str, Any]:
    """Everything the landing-zone diagram and page show. `data`: the estate (compact form); `policy`: the policy
    collection (policy_catalog) - without it only structure and connectivity are shown."""
    from datetime import date

    arch = data.get("architecture") or {}
    reference = load_reference()
    subscription_names = {s["id"].lower(): s.get("name") or s["id"] for s in data.get("subscriptions") or []}
    mapped = map_groups(arch, mapping)
    groups = mapped["groups"]
    policy = policy or {}
    index = PolicyIndex(policy, arch)
    controls = (policy.get("reference") or {}).get("controls") or {}
    evaluated = evaluate_controls(mapped, index, reference, controls) if controls else {}
    depth = policy_depth(mapped, index, subscription_names, today or date.today().isoformat()) if policy else {}
    network = connectivity(arch, subscription_names)

    for name, g in groups.items():
        rows = (depth.get("by_group") or {}).get(name) or {"direct": [], "inherited": 0}
        g["assignments"] = len(rows["direct"])
        g["inherited"] = rows["inherited"]
        g["noncompliant"] = sum(r.get("noncompliant") or 0 for r in rows["direct"])
        g["exemptions"] = sum(r.get("exemptions") or 0 for r in rows["direct"])
        tally = Counter()
        for archetype in [g["archetype"]] if g["archetype"] else []:
            for row in (evaluated.get(archetype) or {}).get("controls") or []:
                status = (row["groups"].get(name) or {}).get("status")
                if status and status != UNRESOLVED:
                    tally[_bucket(status)] += 1
        g["controls"] = dict(tally)

    present = defaultdict(list)
    for name, g in groups.items():
        if g["archetype"] and g["mapped_by"] in ("setting", "name", "position"):
            present[g["archetype"]].append(g["display"])
    reference_groups = []
    for ref in reference["groups"]:
        archetype = (ref.get("archetypes") or [None])[0]
        reference_groups.append({"id": ref["id"], "display": ref.get("display_name") or ref["id"],
                                 "parent": ref.get("parent_id"), "archetype": archetype,
                                 "controls": len(reference["archetypes"].get(archetype) or []),
                                 "mapped": sorted(present.get(archetype, []))})

    observations = _observations(mapped, network, depth, subscription_names)
    totals = Counter()
    for archetype, block in evaluated.items():
        for row in block["controls"]:
            for result in row["groups"].values():
                if result["status"] != UNRESOLVED:
                    totals[_bucket(result["status"])] += 1
    kpis = {"controls_in_place": totals[IN_PLACE], "controls_partly": totals["partly"],
            "controls_missing": totals[MISSING], "controls_evaluated": sum(totals.values()),
            "archetypes_present": sum(1 for r in reference_groups if r["mapped"]),
            "archetypes": len(reference_groups),
            "outside_root": sum(g["subscriptions"] for g in groups.values() if not g["inside"]),
            "exemptions_without_expiry": sum(1 for e in depth.get("exemptions") or [] if e["expires"] == "never"),
            "exemptions_expired": sum(1 for e in depth.get("exemptions") or [] if e["expired"]),
            "deprecated_in_force": len(depth.get("deprecated") or []),
            "noncompliant": sum((a.get("noncompliant") or 0) for a in policy.get("assignments") or []
                                if "/managementgroups/" in (a.get("scope") or ""))}
    return {"release": reference["release"], "policy_collected": bool(policy), "tenant_root": mapped["tenant_root"],
            "root": mapped["root"], "groups": groups, "children": mapped["children"], "reference": reference_groups,
            "controls": evaluated, "policy": depth, "connectivity": network, "observations": observations,
            "kpis": kpis}


def _bucket(status: str) -> str:
    """in place / missing / partly (everything between: audit only, some subscriptions, similar, disabled)."""
    return status if status in (IN_PLACE, MISSING) else "partly"


def _observations(mapped: Dict[str, Any], network: Dict[str, Any], depth: Dict[str, Any],
                  subscription_names: Dict[str, str]) -> List[str]:
    groups = mapped["groups"]
    root = groups.get(mapped["root"]) or {}
    archetypes = Counter(g["archetype"] for g in groups.values() if g["mapped_by"] in ("setting", "name", "position"))
    notes = []
    outside = [g for g in groups.values() if not g["inside"] and g["subscriptions"]]
    if outside:
        notes.append(f"{sum(g['subscriptions'] for g in outside)} subscription(s) sit outside the intermediate root "
                     f"'{root.get('display')}' ({', '.join(sorted({g['display'] for g in outside}))}) - no guardrail "
                     f"assigned at the root reaches them. ALZ keeps every subscription under the intermediate root, "
                     f"with sandbox and decommissioned as children of it.")
    lz = [g for g in groups.values() if g["archetype"] == "landing_zones" and g["mapped_by"] in ("position", "name")]
    if len(lz) > 1 and all(re.search(r"prod", g["display"], re.I) for g in lz):
        notes.append("Landing zones are split by environment (" + ", ".join(g["display"] for g in lz) + "). ALZ "
                     "groups by the policy a workload needs (corp, online) and keeps production and non-production "
                     "side by side under the same guardrails, with environment-specific differences in policy "
                     "parameters or subscriptions.")
    for archetype, why in (("platform", "shared platform services"), ("connectivity", "the hub network"),
                           ("management", "central logging and automation"), ("identity", "domain controllers"),
                           ("decommissioned", "subscriptions being retired")):
        if not archetypes.get(archetype):
            notes.append(f"No '{ARCHETYPE_LABELS[archetype]}' management group - ALZ keeps {why} there, with "
                         f"policies of its own.")
    hub_subs = network.get("summary", {}).get("hub_subscriptions") or []
    if hub_subs:
        names = sorted(subscription_names.get(sid, sid) for sid in hub_subs)
        notes.append(f"Hub networks live in {len(hub_subs)} subscription(s) ({', '.join(names)[:200]}) - in ALZ "
                     f"these sit under Platform > Connectivity.")
    unclassified = [g for g in groups.values() if g["mapped_by"] == "inherited" and g["subscriptions"]]
    if unclassified:
        notes.append("Not classified as corp or online: " + ", ".join(sorted({g["display"] for g in unclassified}))
                     + ". Corp (private, hub-connected) and online (Internet-facing) get different ALZ policies - "
                       "set them in Settings (landing_zone_mapping), e.g. 'Corp workloads = corp'.")
    if depth.get("exemptions"):
        never = sum(1 for e in depth["exemptions"] if e["expires"] == "never")
        if never:
            notes.append(f"{never} of {len(depth['exemptions'])} policy exemptions never expire - a waiver without "
                         f"an end date is a permanent hole.")
    return notes


# ---------------------------------------------------------------------------
# Page (Markdown)
# ---------------------------------------------------------------------------

STATUS_MARK = {IN_PLACE: "✅ in place", AUDIT_ONLY: "🟡 audit only", SOME_SUBS: "🟡 some subscriptions",
               SIMILAR: "🔵 similar", "partly": "🟡 partly", DISABLED: "⚪ disabled", MISSING: "❌ missing",
               UNRESOLVED: "⚪ not resolved"}


def _md_table(headers: List[str], rows: Iterable[Iterable[Any]]) -> List[str]:
    def cell(v: Any) -> str:
        return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return out


def markdown(result: Dict[str, Any]) -> str:
    k = result["kpis"]
    groups = result["groups"]
    lines = ["# Landing zone", "",
             f"Your management groups, policy and network compared with Microsoft's Azure Landing Zones reference "
             f"(ALZ library `{result['release']}`, [github.com/Azure/Azure-Landing-Zones-Library]"
             f"(https://github.com/Azure/Azure-Landing-Zones-Library), MIT).", ""]
    if result["policy_collected"]:
        lines += [f"- **ALZ controls:** {k['controls_in_place']} in place, {k['controls_partly']} partly, "
                  f"{k['controls_missing']} missing (of {k['controls_evaluated']} checks at the mapped groups)",
                  f"- **Archetypes present:** {k['archetypes_present']} of {k['archetypes']}",
                  f"- **Subscriptions outside the intermediate root:** {k['outside_root']}",
                  f"- **Exemptions:** {k['exemptions_without_expiry']} without expiry, {k['exemptions_expired']} expired",
                  f"- **Deprecated policies in force:** {k['deprecated_in_force']}", ""]
    else:
        lines += ["_Policy detail is collected with the next estate refresh._", ""]
    if result["observations"]:
        lines += ["## What stands out", ""] + [f"- {o}" for o in result["observations"]] + [""]

    lines += ["## Management groups", "",
              "Archetype: from the `landing_zone_mapping` setting, the group's name, or its position (children of "
              "the intermediate root holding subscriptions are landing zones); *inherited* = takes its parent's.", ""]
    rows = []
    for name, g in _ordered(result):
        archetype = ARCHETYPE_LABELS.get(g["archetype"], "") if g["archetype"] else (
            "tenant root" if g["tenant_root"] else "outside root (canary)" if g["canary"]
            else "outside root" if not g["inside"] else "")
        ctl = g.get("controls") or {}
        rows.append(["&nbsp;&nbsp;" * g["depth"] + g["display"], archetype,
                     g["mapped_by"] or "", g["subscriptions"], g["subtree_subscriptions"], g.get("assignments", 0),
                     g.get("inherited", 0),
                     (f"{ctl.get(IN_PLACE, 0)} / {ctl.get('partly', 0)} / {ctl.get(MISSING, 0)}" if ctl else ""),
                     g.get("exemptions") or ""])
    lines += _md_table(["Management group", "ALZ archetype", "Mapped by", "Subs", "Subs below", "Assigned here",
                        "Inherited", "ALZ controls in place / partly / missing", "Exemptions"], rows) + [""]

    lines += ["## ALZ reference", ""]
    lines += _md_table(["ALZ management group", "Archetype", "Reference policy assignments", "Your group(s)"],
                       [[r["display"], ARCHETYPE_LABELS.get(r["archetype"], r["archetype"]), r["controls"],
                         ", ".join(r["mapped"]) or "**not present**"] for r in result["reference"]]) + [""]

    for archetype, block in result["controls"].items():
        if not block["controls"]:
            continue
        names = [groups[g]["display"] for g in block["groups"]]
        lines += [f"## Controls - {ARCHETYPE_LABELS.get(archetype, archetype)}", ""]
        if not names:
            lines += [f"_No management group is mapped to this archetype - its {len(block['controls'])} reference "
                      f"assignment(s) are listed for planning._", ""]
            lines += _md_table(["ALZ assignment", "Policies", "Effects"],
                               [[f"{r['display']} (`{r['name']}`)", r["policies"], _effects(r["effects"])]
                                for r in block["controls"]]) + [""]
            continue
        headers = ["ALZ assignment", "Policies", "ALZ effect"] + [f"{n}" for n in names]
        rows = []
        for r in block["controls"]:
            cells = []
            for g in block["groups"]:
                res = r["groups"].get(g) or {}
                cells.append(STATUS_MARK.get(res.get("status"), res.get("status") or "")
                             + (f" - {res['detail']}" if res.get("detail") else ""))
            rows.append([f"{r['display']} (`{r['name']}`)", r["policies"], _effects(r["effects"])] + cells)
        lines += _md_table(headers, rows) + [""]

    depth = result.get("policy") or {}
    if depth:
        lines += ["## Policy assigned per management group", ""]
        rows = []
        for name, g in _ordered(result):
            for a in (depth["by_group"].get(name) or {}).get("direct") or []:
                rows.append([g["display"], a["display"],
                             f"initiative, {a['policies']} policies" if a["initiative"] else "policy",
                             ", ".join(f"{v} {k}" for k, v in sorted(a["sources"].items())), _effects(a["effects"]),
                             a["enforcement"], "" if a.get("noncompliant") is None else
                             f"{a['noncompliant']} of {a['resources']}", a["exemptions"] or "", a["deprecated"] or ""])
        lines += _md_table(["Management group", "Assignment", "Kind", "Sources", "Effects", "Enforcement",
                            "Non-compliant resources", "Exemptions", "Deprecated policies"], rows) + [""]
        sub = depth.get("subscription_scope") or {}
        if sub.get("assignments"):
            lines += [f"{sub['assignments']} assignments sit on {sub['subscriptions']} subscriptions directly (not "
                      f"inherited from a management group). Most common: "
                      + "; ".join(f"{name} ({n})" for name, n in sub["most_common"]) + ".", ""]
        if depth.get("deprecated"):
            lines += ["### Deprecated policies in force", ""]
            lines += _md_table(["Policy", "Assignment", "Scope"],
                               [[d["policy"], d["assignment"], d["scope"]] for d in depth["deprecated"][:60]]) + [""]
        if depth.get("exemptions"):
            lines += ["### Exemptions", ""]
            lines += _md_table(["Exemption", "Scope", "Assignment", "Category", "Expires"],
                               [[e["display"], e["scope"], e["assignment"], e["category"],
                                 ("expired " if e["expired"] else "") + e["expires"]]
                                for e in sorted(depth["exemptions"], key=lambda e: e["expires"])]) + [""]

    net = result["connectivity"]
    lines += ["## Connectivity landing zone", ""]
    if net["hubs"]:
        lines += _md_table(["Hub VNet", "Subscription", "Region", "Peerings", "Firewall", "Firewall policy",
                            "Gateways / Route Server", "Bastion", "DNS resolver (hub or peered)", "DDoS"],
                           [[h["name"], h["subscription"], h["location"], h["spokes"],
                             f"Azure Firewall ({h['firewall']})" if h["firewall"] else
                             ("NVA: " + ", ".join(h.get("nva_vms") or []) if h.get("nva_vms") else
                              f"NVA ({h['nva']})" if h["nva"] else "**none**"),
                             {True: "yes", False: "**no**", None: "n/a"}[h["firewall_policy"]],
                             ", ".join(h["gateways"] + (["Route Server"] if h.get("route_server") else [])) or "-",
                             _yes(h["bastion"]), _yes(h["dns_resolver"]), _yes(h["ddos"])] for h in net["hubs"]]) + [""]
    else:
        lines += ["_No hub VNet found (no VNet with a gateway or firewall subnet and peerings, or 3+ peerings)._", ""]
    s = net["summary"]
    lines += [f"{s['spokes']} other VNets: {s['spokes_on_hub']} peered to a hub, {s['isolated']} not; "
              f"{s['forced_tunnel']} send Internet traffic through the hub ({s.get('bgp', 0)} by routes learned over "
              f"BGP from the hub's Route Server or gateway - not visible in route tables, confirm with the effective "
              f"routes of a NIC); {s['dns_gaps']} have private endpoints that cannot resolve through private DNS; "
              f"{s['ddos']} have DDoS protection.", ""]
    with_issues = [sp for sp in net["spokes"] if sp["issues"]]
    if with_issues:
        lines += _md_table(["VNet", "Subscription", "Hub", "Default route", "DNS", "Private endpoints", "Issues"],
                           [[sp["name"], sp["subscription"], _yes(sp["hub"]), sp["route"], sp["dns"],
                             sp["private_endpoints"] or "", "; ".join(sp["issues"])]
                            for sp in with_issues[:200]]) + [""]
    lines += ["---", "",
              "_Mapping: Settings > `landing_zone_mapping`, one `management group = archetype` per line (archetypes: "
              + ", ".join(sorted(ARCHETYPE_LABELS)) + ", outside, none). 'Similar' means one of your policies reads "
              "most of the same resource properties - confirm it does the same thing._"]
    return "\n".join(lines) + "\n"


def _ordered(result: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    groups, children = result["groups"], result["children"]
    out: List[Tuple[str, Dict[str, Any]]] = []

    def walk(name: str) -> None:
        out.append((name, groups[name]))
        for c in sorted(children.get(name, []), key=lambda n: groups[n]["display"].lower()):
            walk(c)
    if result["tenant_root"] in groups:
        walk(result["tenant_root"])
    return out


def _effects(effects: Dict[str, int]) -> str:
    return ", ".join(f"{n} {e}" for e, n in sorted(effects.items(), key=lambda kv: -kv[1])) if effects else ""


def _yes(value: Any) -> str:
    return "yes" if value else "-"
