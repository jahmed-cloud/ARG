"""
Azure Policy analyzer: what policy is in force across the tenant and where it falls short.

- Assignments: every assignment (management group, subscription, resource group) with its policies and the effect
  each runs with, enforcement, managed identity, compliance, exemptions and excluded scopes.
- Subscriptions: the policy in effect on each subscription - inherited from its management groups and assigned
  directly - by effect, with its compliance.
- Policies: every policy in force once, with the effects it runs with, where it is assigned and its non-compliance.
- Exemptions: category, scope, expiry.
- Tree: the management-group hierarchy down to subscriptions (and resource groups with assignments), each node with
  the assignments made on it and how many reach it from above (excluded scopes left out).
- Issues: assignments that are not enforced, DeployIfNotExists / Modify without a managed identity (remediation
  cannot run), deprecated and preview policies in force, exemptions without an end date or expired, redundant
  assignments, assignments with every policy disabled, Deny policies with non-compliant resources, subscriptions
  without a Deny guardrail or the Microsoft cloud security benchmark, custom definitions nobody assigns.

Reads the estate refresh's policy collection (policy_catalog.py: reports/_estate/policy.json, or the Docker
snapshot's "policy") and the management-group hierarchy (estate architecture) - no Azure calls of its own.
"""

from collections import Counter, defaultdict
from datetime import date, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from scripts.subscription_analysis.landing_zone import _ancestors, effect_class

MCSB = "1f3afdf9-d0c9-4c3d-847f-89da613e70a8"   # Microsoft cloud security benchmark (Defender for Cloud default)
REMEDIATING = {"deployifnotexists", "modify"}     # need a managed identity to remediate
EXPIRING_DAYS = 30
SEVERITY_ORDER = ["high", "medium", "low", "info"]
CLASS_ORDER = ["deny", "remediate", "audit", "disabled"]
MAX_ITEMS = 200


def _scope(scope: str, groups: Dict[str, Any], subs: Dict[str, str]) -> Tuple[str, str, str]:
    """(kind, label, key): management group / subscription / resource group, a readable name, the lookup key."""
    s = (scope or "").lower()
    if "/managementgroups/" in s:
        name = s.rsplit("/", 1)[-1]
        g = next((v for k, v in groups.items() if k.lower() == name), {}) or {}
        return "Management group", g.get("displayName") or name, name
    if s.startswith("/subscriptions/"):
        parts = s.split("/")
        sub = parts[2] if len(parts) > 2 else ""
        if "/resourcegroups/" in s:
            rg = s.split("/resourcegroups/")[1].split("/")[0]
            return "Resource group", f"{subs.get(sub, sub)} / {rg}", sub
        return "Subscription", subs.get(sub, sub), sub
    return "Other", scope, s


def _covers(outer: str, inner: str, groups: Dict[str, Any], parents: Dict[str, List[str]]) -> bool:
    """True when scope `outer` contains scope `inner` (a different, lower scope)."""
    o, i = (outer or "").lower(), (inner or "").lower()
    if not o or o == i:
        return False
    if i.startswith(o + "/"):
        return True                          # subscription > resource group
    if "/managementgroups/" not in o:
        return False
    name = o.rsplit("/", 1)[-1]
    if "/managementgroups/" in i:
        return name in [g.lower() for g in _ancestors(i.rsplit("/", 1)[-1], groups)[1:]]
    sub = i.split("/")[2] if i.startswith("/subscriptions/") and len(i.split("/")) > 2 else ""
    return name in [g.lower() for g in parents.get(sub) or []]


OUTSIDE = "outside"
KIND_ORDER = {"Management group": 0, "Subscription": 1, "Resource group": 2}


def _node_scope(node_id: str) -> str:
    """The ARM scope of a tree node - what an assignment's notScopes entries are compared with."""
    kind, _, key = node_id.partition(":")
    if kind == "mg":
        return f"/providers/microsoft.management/managementgroups/{key}"
    if kind == "sub":
        return f"/subscriptions/{key}"
    if kind == "rg":
        sub, _, rg = key.partition("/")
        return f"/subscriptions/{sub}/resourcegroups/{rg}"
    return ""


def assignment_tree(rows: List[Dict[str, Any]], groups: Dict[str, Any], parents: Dict[str, List[str]],
                    subs: Dict[str, str]) -> Dict[str, Any]:
    """{"roots": [...], "nodes": {id: node}}: management groups > subscriptions > resource groups with assignments.
    A node lists the assignments made on it ("assigned") and counts those reaching it from above ("inherited")."""
    nodes: Dict[str, Dict[str, Any]] = {}

    def add(nid: str, kind: str, label: str, parent: Optional[str]) -> Dict[str, Any]:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "label": label, "parent": parent, "scope": _node_scope(nid),
                          "children": [], "assigned": []}
        return nodes[nid]

    lowered = {k.lower(): v for k, v in groups.items()}
    for name, g in lowered.items():
        add(f"mg:{name}", "Management group", g.get("displayName") or name, None)
    for name, g in lowered.items():
        parent = (g.get("parent") or "").lower()
        if parent and f"mg:{parent}" in nodes and parent != name:
            nodes[f"mg:{name}"]["parent"] = f"mg:{parent}"
    for r in rows:   # groups only known from an assignment's scope (outside what the identity can list)
        if r["scopeKind"] == "Management group":
            add(f"mg:{r['scope'].lower().rsplit('/', 1)[-1]}", "Management group", r["scopeLabel"], None)
    for sid, name in subs.items():
        chain = parents.get(sid) or []
        parent = next((f"mg:{g}" for g in chain if f"mg:{g}" in nodes), None)
        add(f"sub:{sid}", "Subscription", name or sid, parent or OUTSIDE)
    for r in rows:
        s = r["scope"].lower()
        if r["scopeKind"] == "Management group":
            nid = f"mg:{s.rsplit('/', 1)[-1]}"
        elif r["scopeKind"] in ("Subscription", "Resource group"):
            sid = s.split("/")[2]
            add(f"sub:{sid}", "Subscription", subs.get(sid) or f"{sid} (not in the inventory)", OUTSIDE)
            nid = f"sub:{sid}"
            if r["scopeKind"] == "Resource group":
                rg = s.split("/resourcegroups/")[1].split("/")[0]
                nid = add(f"rg:{sid}/{rg}", "Resource group", rg, f"sub:{sid}")["id"]
        else:
            continue
        nodes[nid]["assigned"].append(r["id"])
    if any(n["parent"] == OUTSIDE for n in nodes.values()):
        add(OUTSIDE, "Group", "Outside the management-group hierarchy", None)
    for n in nodes.values():
        if n["parent"]:
            nodes[n["parent"]]["children"].append(n["id"])
    for n in nodes.values():
        n["children"].sort(key=lambda c: (KIND_ORDER.get(nodes[c]["kind"], 9), nodes[c]["label"].lower()))

    by_id = {r["id"]: r for r in rows}

    def walk(nid: str, above: List[str]) -> Tuple[int, int]:
        """Fills the counts; returns (subscriptions, assignments) in this subtree."""
        n = nodes[nid]
        scope = n["scope"]
        reaching = [a for a in above if scope not in by_id[a]["notScopes"]]
        mine = [by_id[a] for a in n["assigned"]]
        effects: Counter = Counter()
        for r in mine:
            effects.update(r["effects"])
        n.update(inherited=len(reaching), effects={c: effects[c] for c in CLASS_ORDER if effects[c]},
                 notEnforced=sum(1 for r in mine if r["enforcement"] == "DoNotEnforce"),
                 issues=sum(1 for r in mine if r["issues"]))
        subs_below, assigned_below = (1 if n["kind"] == "Subscription" else 0), len(mine)
        for child in n["children"]:
            s_count, a_count = walk(child, reaching + n["assigned"] if n["kind"] != "Group" else [])
            subs_below += s_count
            assigned_below += a_count
        n["subscriptions"], n["assignedBelow"] = subs_below, assigned_below - len(mine)
        return subs_below, assigned_below

    roots = sorted((n["id"] for n in nodes.values() if n["parent"] is None),
                   key=lambda i: (i == OUTSIDE, -len(nodes[i]["children"]), nodes[i]["label"].lower()))
    for root in roots:
        walk(root, [])
    return {"roots": roots, "nodes": nodes}


def _mg_names(groups: Dict[str, Any]) -> Dict[str, str]:
    return {k.lower(): k for k in groups}


def analyse(data: Dict[str, Any], policy: Optional[Dict[str, Any]], today: Optional[date] = None) -> Dict[str, Any]:
    """The analyzer result from the estate (subscriptions, architecture) and its policy collection."""
    policy = policy or {}
    today = today or date.today()
    arch = (data or {}).get("architecture") or {}
    groups = arch.get("management_groups") or {}
    parents = {k.lower(): [g.lower() for g in v or []] for k, v in (arch.get("subscription_parents") or {}).items()}
    lowered_groups = {k.lower(): {**v, "parent": (v.get("parent") or "").lower() or None} for k, v in groups.items()}
    subs = {(s.get("id") or "").lower(): s.get("name") or s.get("id") for s in (data or {}).get("subscriptions") or []}
    defs = policy.get("definitions") or {}
    profiles = policy.get("profiles") or {}
    assignments = policy.get("assignments") or []
    compliance = policy.get("compliance") or {}
    by_policy = {(c.get("assignment") or "", c.get("definition") or ""): c.get("noncompliant") or 0
                 for c in compliance.get("by_policy") or []}
    by_sub = {(c.get("sub") or "").lower(): c for c in compliance.get("by_subscription") or []}
    exemptions_by_assignment: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in policy.get("exemptions") or []:
        exemptions_by_assignment[e.get("assignment") or ""].append(e)

    # -- assignments ------------------------------------------------------------------------------------
    rows: List[Dict[str, Any]] = []
    for a in assignments:
        profile = profiles.get(a.get("profile")) or {}
        head_key = profile.get("def") or ""
        head = defs.get(head_key) or {}
        kind, label, _ = _scope(a.get("scope") or "", groups, subs)
        members = []
        for key, effect in profile.get("members") or []:
            d = defs.get(key) or {}
            members.append({"key": key, "display": d.get("display") or key.rsplit("/", 1)[-1],
                            "category": d.get("category") or "", "source": d.get("source") or "",
                            "effect": effect or "", "class": effect_class(effect) or "audit",
                            "deprecated": bool(d.get("deprecated")), "preview": bool(d.get("preview")),
                            "noncompliant": by_policy.get((a.get("id") or "", key))})
        effects = Counter(m["class"] for m in members)
        evaluated, bad = a.get("resources"), a.get("noncompliant")
        rows.append({
            "id": a.get("id") or "", "name": a.get("name") or "", "display": a.get("display") or a.get("name") or "",
            "scope": a.get("scope") or "", "scopeKind": kind, "scopeLabel": label,
            "definition": head.get("display") or head_key.rsplit("/", 1)[-1], "definitionId": head_key,
            "initiative": bool(head.get("set")) or len(members) > 1,
            "source": head.get("source") or ("Custom" if "/managementgroups/" in head_key else ""),
            "category": head.get("category") or "", "policies": len(members),
            "effects": {c: effects[c] for c in CLASS_ORDER if effects[c]},
            "enforcement": a.get("enforcement") or "Default", "identity": a.get("identity") or "",
            "noncompliant": bad, "resources": evaluated,
            "compliance": round(100.0 * (evaluated - bad) / evaluated, 1) if evaluated else None,
            "exemptions": len(exemptions_by_assignment.get(a.get("id") or "", [])),
            "notScopes": a.get("not_scope_list") or [], "created": a.get("created"),
            "profile": a.get("profile"), "members": members, "issues": [],
        })
    by_id = {r["id"]: r for r in rows}

    # -- subscriptions: the policy in effect ------------------------------------------------------------
    mg_names = _mg_names(groups)
    sub_rows = []
    for sid, name in sorted(subs.items(), key=lambda kv: (kv[1] or "").lower()):
        chain = parents.get(sid) or []
        in_effect = []
        for r in rows:
            s = r["scope"].lower()
            if r["scopeKind"] == "Management group":
                applies = s.rsplit("/", 1)[-1] in chain
            elif r["scopeKind"] == "Subscription":
                applies = s == f"/subscriptions/{sid}"
            else:
                continue                      # resource-group assignments do not cover the whole subscription
            excluded = any(x == f"/subscriptions/{sid}" or (x.rsplit("/", 1)[-1] in chain and "/managementgroups/" in x)
                           for x in r["notScopes"])
            if applies and not excluded:
                in_effect.append(r)
        strongest: Dict[str, str] = {}
        for r in in_effect:
            if r["enforcement"] == "DoNotEnforce":
                continue
            for m in r["members"]:
                current = strongest.get(m["key"])
                if current is None or CLASS_ORDER.index(m["class"]) < CLASS_ORDER.index(current):
                    strongest[m["key"]] = m["class"]
        counts = Counter(strongest.values())
        state = by_sub.get(sid) or {}
        evaluated, bad = state.get("resources"), state.get("noncompliant")
        path = [(groups.get(mg_names.get(g, g)) or {}).get("displayName") or g for g in reversed(chain)]
        row = {"id": sid, "name": name, "path": " › ".join(path), "managementGroup": path[-1] if path else "",
               "assignments": len(in_effect),
               "inherited": sum(1 for r in in_effect if r["scopeKind"] == "Management group"),
               "direct": sum(1 for r in in_effect if r["scopeKind"] == "Subscription"),
               "resourceGroupAssignments": sum(1 for r in rows if r["scopeKind"] == "Resource group"
                                               and r["scope"].lower().startswith(f"/subscriptions/{sid}/")),
               "policies": len(strongest), "effects": {c: counts[c] for c in CLASS_ORDER if counts[c]},
               "deny": counts["deny"], "benchmark": any(r["definitionId"].endswith(MCSB) for r in in_effect),
               "noncompliant": bad, "resources": evaluated,
               "compliance": round(100.0 * (evaluated - bad) / evaluated, 1) if evaluated else None,
               "issues": []}
        if not row["deny"]:
            row["issues"].append("no Deny guardrail")
        if not row["benchmark"]:
            row["issues"].append("no Microsoft cloud security benchmark")
        if not chain:
            row["issues"].append("not in the management-group hierarchy")
        sub_rows.append(row)

    # -- policies in force ----------------------------------------------------------------------------------
    pol: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        for m in r["members"]:
            p = pol.setdefault(m["key"], {"key": m["key"], "display": m["display"], "category": m["category"],
                                          "source": m["source"], "deprecated": m["deprecated"],
                                          "preview": m["preview"], "effects": Counter(), "assignments": 0,
                                          "scopes": [], "noncompliant": 0, "notEnforced": 0})
            p["effects"][m["effect"] or "default"] += 1
            p["assignments"] += 1
            if r["scopeLabel"] not in p["scopes"]:
                p["scopes"].append(r["scopeLabel"])
            p["noncompliant"] += m["noncompliant"] or 0
            p["notEnforced"] += 1 if r["enforcement"] == "DoNotEnforce" else 0
    policies = []
    for p in pol.values():
        effects = p.pop("effects")
        p["effects"] = dict(effects.most_common())
        p["strongest"] = min((effect_class(e) or "audit" for e in effects), key=CLASS_ORDER.index)
        policies.append(p)
    policies.sort(key=lambda p: (-p["noncompliant"], p["display"].lower()))

    # -- exemptions -------------------------------------------------------------------------------------
    exemption_rows = []
    soon = (today + timedelta(days=EXPIRING_DAYS)).isoformat()
    for e in policy.get("exemptions") or []:
        scope = (e.get("id") or "").split("/providers/microsoft.authorization/policyexemptions/")[0]
        kind, label, _ = _scope(scope, groups, subs) if scope else ("", "", "")
        expires = (e.get("expires") or "")[:10]
        status = ("no end date" if not expires else "expired" if expires < today.isoformat()
                  else "expires soon" if expires <= soon else "active")
        target = by_id.get(e.get("assignment") or "")
        exemption_rows.append({"id": e.get("id") or "", "display": e.get("display") or "", "category": e.get("category") or "",
                               "scopeKind": kind, "scopeLabel": label, "scope": scope.lower(),
                               "assignmentId": e.get("assignment") or "",
                               "assignment": target["display"] if target else (e.get("assignment") or "").rsplit("/", 1)[-1],
                               "policies": e.get("references") or 0, "expires": expires or None, "status": status})

    # -- issues -----------------------------------------------------------------------------------------
    issues: List[Dict[str, Any]] = []

    def issue(key: str, severity: str, title: str, detail: str, items: List[str], fix: str) -> None:
        if items:
            issues.append({"key": key, "severity": severity, "title": title, "detail": detail, "count": len(items),
                           "items": items[:MAX_ITEMS], "fix": fix})

    def where(r: Dict[str, Any]) -> str:
        return f"{r['display']} ({r['scopeKind'].lower()} {r['scopeLabel']})"

    not_enforced = [r for r in rows if r["enforcement"] == "DoNotEnforce"
                    and (r["effects"].get("deny") or r["effects"].get("remediate"))]
    for r in not_enforced:
        r["issues"].append("not enforced")
    issue("not_enforced", "medium", "Assignments not enforced",
          "Enforcement mode DoNotEnforce: their Deny, DeployIfNotExists and Modify policies only report - nothing is "
          "blocked or remediated.",
          [f"{where(r)}: {r['effects'].get('deny', 0)} deny, {r['effects'].get('remediate', 0)} remediating"
           for r in not_enforced],
          "Set enforcement to Default once the compliance results are understood (test on a canary scope first).")

    knows_identity = any("identity" in a for a in assignments)   # collections before the analyzer lack it
    no_identity = [r for r in rows if knows_identity and not r["identity"] and r["enforcement"] != "DoNotEnforce"
                   and any((m["effect"] or "").lower() in REMEDIATING for m in r["members"])]
    for r in no_identity:
        r["issues"].append("no managed identity")
    issue("no_identity", "high", "DeployIfNotExists / Modify without a managed identity",
          "These assignments contain remediating policies but have no managed identity, so remediation tasks cannot "
          "deploy or change anything - non-compliant resources stay non-compliant.",
          [f"{where(r)}: {sum(1 for m in r['members'] if (m['effect'] or '').lower() in REMEDIATING)} remediating "
           f"polic{'y' if sum(1 for m in r['members'] if (m['effect'] or '').lower() in REMEDIATING) == 1 else 'ies'}"
           for r in no_identity],
          "Re-create the assignment with a system-assigned (or user-assigned) managed identity and grant it the roles "
          "the policies list (roleDefinitionIds), then run a remediation task."
          + (" Assignments named 'ASC …' are created by Defender for Cloud: turning the plan's component off and on "
             "again (Environment settings > Defender plans > Settings) recreates them with an identity."
             if any(r["display"].startswith("ASC ") for r in no_identity) else ""))

    deprecated = [(r, m) for r in rows for m in r["members"] if m["deprecated"] and m["class"] != "disabled"]
    for r in {id(r): r for r, _ in deprecated}.values():
        r["issues"].append("deprecated policies")
    issue("deprecated", "medium", "Deprecated policies in force",
          "Microsoft no longer maintains these definitions; most have a replacement.",
          sorted({f"{m['display']} - in {where(r)}" for r, m in deprecated}),
          "Replace each with its successor (the definition's description names it) or remove it from the initiative.")

    preview = [(r, m) for r in rows for m in r["members"] if m["preview"] and m["class"] in ("deny", "remediate")]
    issue("preview", "low", "Preview policies enforcing (Deny / remediation)",
          "Preview definitions can change or be withdrawn; enforcing them can block or change resources unexpectedly.",
          sorted({f"{m['display']} ({m['effect']}) - in {where(r)}" for r, m in preview}),
          "Run preview policies in Audit until they are generally available.")

    issue("exemption_no_expiry", "medium", "Exemptions without an end date",
          "A permanent exemption is never reviewed again; the exempted resources stay outside the control for good.",
          [f"{e['display']} - {e['assignment']} ({e['scopeLabel']}, {e['category'] or 'no category'})"
           for e in exemption_rows if e["status"] == "no end date"],
          "Give every exemption an expiry date and an owner; renew it deliberately.")
    issue("exemption_expired", "low", "Expired exemptions",
          "Expired exemptions no longer exempt anything - leftovers that make the exemption list harder to review.",
          [f"{e['display']} - expired {e['expires']}" for e in exemption_rows if e["status"] == "expired"],
          "Delete them, or renew the ones still needed with a new end date.")

    by_profile: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_profile[r["profile"]].append(r)
    redundant = []
    for same in by_profile.values():
        for outer in same:
            for inner in same:
                if _covers(outer["scope"], inner["scope"], lowered_groups, parents):
                    redundant.append((outer, inner))
                    inner["issues"].append("redundant")
    issue("redundant", "low", "Redundant assignments",
          "The same definition with the same parameters is already assigned at a scope above - the lower assignment "
          "adds nothing but evaluation load and a second compliance result.",
          [f"{i['display']} at {i['scopeLabel']} - already assigned at {o['scopeLabel']}" for o, i in redundant],
          "Delete the lower assignment (move its exemptions to the higher one first).")

    disabled = [r for r in rows if r["members"] and all(m["class"] == "disabled" for m in r["members"])]
    for r in disabled:
        r["issues"].append("all policies disabled")
    issue("all_disabled", "low", "Assignments with every policy disabled",
          "Every policy of these assignments runs with the Disabled effect - they do nothing.",
          [where(r) for r in disabled], "Delete them, or set the effects that were intended.")

    deny_bad = [r for r in rows if r["effects"].get("deny") and r["enforcement"] != "DoNotEnforce"
                and any(m["class"] == "deny" and (m["noncompliant"] or 0) > 0 for m in r["members"])]
    issue("deny_noncompliant", "info", "Deny policies with non-compliant resources",
          "Existing resources violate a Deny policy (they predate it or were exempted): every update to them is "
          "refused until they are fixed.",
          [f"{where(r)}: " + ", ".join(f"{m['display']} ({m['noncompliant']})" for m in r["members"]
                                       if m["class"] == "deny" and (m["noncompliant"] or 0) > 0)[:400]
           for r in deny_bad],
          "Fix the resources (or exempt them with an end date) so changes to them do not fail unexpectedly.")

    issue("sub_no_deny", "medium", "Subscriptions without a Deny guardrail",
          "No enforced Deny policy reaches these subscriptions - nothing prevents non-compliant deployments.",
          [f"{s['name']} ({s['path'] or 'outside the hierarchy'})" for s in sub_rows if not s["deny"]],
          "Place them under a management group with the landing-zone guardrails (see the Landing zone view).")
    issue("sub_no_benchmark", "low", "Subscriptions without the Microsoft cloud security benchmark",
          "Defender for Cloud's default initiative is the baseline its secure score and recommendations use.",
          [s["name"] for s in sub_rows if not s["benchmark"]],
          "Assign the Microsoft cloud security benchmark at the intermediate-root management group.")

    unassigned = policy.get("unassigned_custom") or []
    issue("unassigned_custom", "low", "Custom definitions nobody assigns",
          "Custom policy definitions and initiatives that no assignment uses (directly or through an initiative).",
          [f"{d['display']}{' (initiative)' if d.get('set') else ''}" for d in unassigned],
          "Delete the ones no longer needed; keep the rest in source control (EPAC / Bicep) with an owner.")

    issues.sort(key=lambda i: (SEVERITY_ORDER.index(i["severity"]), -i["count"]))
    tenant_bad = sum((c.get("noncompliant") or 0) for c in by_sub.values())
    tenant_res = sum((c.get("resources") or 0) for c in by_sub.values())
    summary = {
        "assignments": len(rows), "initiatives": sum(1 for r in rows if r["initiative"]),
        "byScope": dict(Counter(r["scopeKind"] for r in rows)), "policies": len(policies),
        "byEffect": dict(Counter(p["strongest"] for p in policies)),
        "subscriptions": len(sub_rows), "subscriptionsWithoutDeny": sum(1 for s in sub_rows if not s["deny"]),
        "noncompliant": tenant_bad, "evaluated": tenant_res,
        "compliance": round(100.0 * (tenant_res - tenant_bad) / tenant_res, 1) if tenant_res else None,
        "exemptions": len(exemption_rows),
        "exemptionsNoExpiry": sum(1 for e in exemption_rows if e["status"] == "no end date"),
        "issues": dict(Counter(i["severity"] for i in issues)),
        "complianceDetail": bool(compliance.get("by_policy") or compliance.get("by_subscription")),
    }
    # Initiatives repeat across scopes (the security benchmark on every subscription): assignments reference their
    # shared profile ([[policy key, effect]]), with only their own non-compliant counts.
    out_rows = []
    for r in sorted(rows, key=lambda r: (["Management group", "Subscription", "Resource group", "Other"]
                                         .index(r["scopeKind"]), r["scopeLabel"].lower(), r["display"].lower())):
        row = {k: v for k, v in r.items() if k != "members"}
        row["memberNoncompliant"] = {m["key"]: m["noncompliant"] for m in r["members"] if m["noncompliant"]}
        out_rows.append(row)
    return {"collected_at": policy.get("collected_at"), "summary": summary, "issues": issues,
            "assignments": out_rows, "tree": assignment_tree(rows, groups, parents, subs),
            "profiles": {r["profile"]: [[m["key"], m["effect"]] for m in r["members"]] for r in rows},
            "subscriptions": sub_rows, "policies": policies, "exemptions": exemption_rows}


def _table(headers: List[str], rows: Iterable[Iterable[Any]]) -> List[str]:
    clean = lambda v: str("" if v is None else v).replace("|", "\\|").replace("\n", " ")  # noqa: E731
    return (["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
            + ["| " + " | ".join(clean(v) for v in row) + " |" for row in rows])


def _effects(effects: Dict[str, int]) -> str:
    return ", ".join(f"{n} {c}" for c, n in effects.items()) or "-"


def _pct(value: Optional[float]) -> str:
    return "-" if value is None else f"{value:.1f} %"


def markdown(result: Dict[str, Any]) -> str:
    s = result["summary"]
    lines = ["# Azure Policy analysis", "",
             f"Policy collected {str(result.get('collected_at') or '')[:16].replace('T', ' ')} UTC with the estate "
             "refresh (read-only).", "",
             *_table(["", ""], [
                 ["Assignments", f"{s['assignments']} ({', '.join(f'{n} {k.lower()}' for k, n in s['byScope'].items())}), "
                                 f"{s['initiatives']} initiatives"],
                 ["Policies in force", f"{s['policies']} ({_effects(s['byEffect'])})"],
                 ["Compliance", f"{_pct(s['compliance'])} - {s['noncompliant']:,} of {s['evaluated']:,} evaluated resources "
                                "non-compliant"],
                 ["Subscriptions without a Deny guardrail", f"{s['subscriptionsWithoutDeny']} of {s['subscriptions']}"],
                 ["Exemptions", f"{s['exemptions']} ({s['exemptionsNoExpiry']} without an end date)"],
             ]), "", "## Issues", ""]
    if not result["issues"]:
        lines += ["No issues found.", ""]
    for i in result["issues"]:
        lines += [f"### {i['title']} ({i['count']}, {i['severity']})", "", i["detail"], "", f"**Fix:** {i['fix']}", ""]
        lines += [f"- {x}" for x in i["items"][:25]]
        if i["count"] > 25:
            lines.append(f"- … and {i['count'] - 25} more")
        lines.append("")
    lines += ["## Assignments", "", *_table(
        ["Assignment", "Scope", "Definition", "Policies", "Effects", "Enforcement", "Identity", "Non-compliant",
         "Compliance", "Exemptions", "Issues"],
        [[r["display"], f"{r['scopeKind']}: {r['scopeLabel']}", r["definition"], r["policies"], _effects(r["effects"]),
          r["enforcement"], r["identity"] or "-", "-" if r["noncompliant"] is None else r["noncompliant"],
          _pct(r["compliance"]), r["exemptions"], ", ".join(r["issues"]) or "-"] for r in result["assignments"]]), ""]
    lines += ["## Policy in effect per subscription", "", *_table(
        ["Subscription", "Management groups", "Assignments (inherited / direct)", "Policies", "Effects",
         "Compliance", "Issues"],
        [[x["name"], x["path"] or "-", f"{x['assignments']} ({x['inherited']} / {x['direct']})", x["policies"],
          _effects(x["effects"]), _pct(x["compliance"]), ", ".join(x["issues"]) or "-"]
         for x in result["subscriptions"]]), ""]
    tree = result.get("tree") or {}
    if tree.get("roots"):
        names = {r["id"]: f"{r['display']} [{'initiative' if r['initiative'] else 'policy'} {r['definition']}"
                          + (f", {r['policies']} policies]" if r["initiative"] else "]") for r in result["assignments"]}
        lines += ["## Assignment tree", "",
                  "Where each assignment is made, down the management-group hierarchy: *assigned* = made on that "
                  "scope, *inherited* = reaching it from a scope above.", ""]

        def branch(nid: str, depth: int) -> None:
            n = tree["nodes"][nid]
            if n["kind"] == "Subscription" and not n["assigned"] and not n["children"]:
                return   # subscriptions without their own assignments: counted on their group
            mine = [names.get(a, a) for a in n["assigned"]]
            detail = f"{len(mine)} assigned, {n['inherited']} inherited"
            if n["kind"] != "Subscription" and n["subscriptions"]:
                detail += f", {n['subscriptions']} subscriptions below"
            listed = "; ".join(mine[:8]) + (f"; … {len(mine) - 8} more" if len(mine) > 8 else "")
            lines.append(f"{'  ' * depth}- **{n['label']}** ({n['kind'].lower()}) - {detail}"
                         + (f": {listed}" if listed else ""))
            for child in n["children"]:
                branch(child, depth + 1)
        for root in tree["roots"]:
            branch(root, 0)
        lines.append("")
    if result["exemptions"]:
        lines += ["## Exemptions", "", *_table(
            ["Exemption", "Category", "Scope", "Assignment", "Expires", "Status"],
            [[e["display"], e["category"], f"{e['scopeKind']}: {e['scopeLabel']}", e["assignment"],
              e["expires"] or "never", e["status"]] for e in result["exemptions"]]), ""]
    return "\n".join(lines)
