"""
Policy assignment graph - how Azure Policy reaches a scope, in one picture (the Policy page's Graph view).

Two lenses over the policy analyzer's result (policy_analyzer.analyse):

- scope:      a management group, subscription or resource group with its chain of parent scopes. Every initiative or
              policy assigned along the chain hangs off the scope where it is assigned; inheritance flows down to the
              scope in focus; assignments that an excluded scope (notScopes) stops are drawn red and dashed to where
              they stop. The scope in focus gets what is in effect on it, its exemptions and the scopes below it.
- initiative: one initiative or policy definition, every assignment of it and what each reaches (subscriptions in
              effect, excluded scopes). Assignments on many subscriptions are summarised in one node.

Every initiative / assignment node opens in place: the assignment's facts (scope, enforcement, managed identity,
compliance, excluded scopes, exemptions, issues) and every policy it holds, grouped by the effect it runs with, with
its non-compliant resources. The SVG is self-contained and uses Microsoft's Azure architecture icons unchanged
(azure_icons/NOTICE.md), each with its name next to it. Clickable nodes carry data-focus / data-lens / data-expand
attributes: the local portal and the Docker UI turn a click into a new request (no links, no scripts in the SVG).
"""

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

from scripts.subscription_analysis.diagram import AZURE, DENY, INK, LINE, MUTED, WARN, Canvas, _esc, _fit
from scripts.subscription_analysis.diagram_icons import (
    POLICY_ICON,
    RESOURCE_GROUP_ICON,
    SUBSCRIPTION_ICON,
    TENANT_ICON,
)

SCOPE, INITIATIVE = "scope", "initiative"
CLASS_ORDER = ["deny", "remediate", "audit", "disabled"]
CLASS_LABELS = {"deny": "Deny", "remediate": "Remediate (DeployIfNotExists / Modify / Append)", "audit": "Audit",
                "disabled": "Disabled"}
CLASS_COLOURS = {"deny": DENY, "remediate": WARN, "audit": AZURE, "disabled": "#8A8886"}
SCOPE_ICONS = {"Management group": TENANT_ICON, "Subscription": SUBSCRIPTION_ICON, "Resource group": RESOURCE_GROUP_ICON}
EXEMPT = "#B4690E"
MAX_POLICY_LINES = 60          # policies listed in an opened node; the rest are counted
MAX_SUBSCRIPTION_NODES = 8     # more subscription-level assignments of one definition are summarised
MAX_CHILDREN = 12

X_LEFT, W_LEFT = 30, 380       # initiatives / policies
X_MID, W_MID = 480, 270        # scopes (scope lens) / assignments (initiative lens)
X_RIGHT, W_RIGHT = 820, 300    # in effect, below (scope lens) / reach (initiative lens)
WIDTH = X_RIGHT + W_RIGHT + 30
TOP = 92
LINE_H = 16


def _effect_class(effect: str) -> str:
    e = (effect or "").lower()
    if e in ("deny", "denyaction"):
        return "deny"
    if e in ("deployifnotexists", "modify", "append"):
        return "remediate"
    return "disabled" if e == "disabled" else "audit"


def _text(x: float, y: float, text: Any, size: float = 12, weight: int = 400, colour: str = INK,
          cls: str = "", anchor: str = "start") -> str:
    klass = f' class="{cls}"' if cls else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" fill="{colour}" '
            f'text-anchor="{anchor}"{klass}>{_esc(text)}</text>')


def _chip(x: float, y: float, label: str, colour: str) -> Tuple[str, float]:
    width = 10 + len(label) * 6.1
    return (f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="16" rx="8" fill="{colour}" fill-opacity="0.14" '
            f'stroke="{colour}" stroke-opacity="0.5" stroke-width="0.8"/>'
            + _text(x + width / 2, y + 11.5, label, 10.5, 600, colour, anchor="middle")), width + 6


def _chips(x: float, y: float, items: Iterable[Tuple[str, str]], max_x: float) -> Tuple[str, float]:
    """A row of chips, wrapping before max_x; returns (svg, height used)."""
    out, cx, cy = [], x, y
    for label, colour in items:
        svg, used = _chip(cx, cy, label, colour)
        if cx + used > max_x and cx > x:
            cx, cy = x, cy + 20
            svg, used = _chip(cx, cy, label, colour)
        out.append(svg)
        cx += used
    return "".join(out), (cy - y + 20) if out else 0


def _curve(x1: float, y1: float, x2: float, y2: float, colour: str = "#8A99A8", dashed: bool = False,
           width: float = 1.4, arrow: str = "arr") -> str:
    mid = (x1 + x2) / 2
    dash = ' stroke-dasharray="6 4"' if dashed else ""
    return (f'<path d="M{x1:.1f},{y1:.1f} C{mid:.1f},{y1:.1f} {mid:.1f},{y2:.1f} {x2:.1f},{y2:.1f}" fill="none" '
            f'stroke="{colour}" stroke-width="{width}"{dash} marker-end="url(#{arrow})"/>')


def _markers() -> str:
    def marker(mid: str, colour: str) -> str:
        return (f'<marker id="{mid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                f'orient="auto-start-reverse"><path d="M1,1 L9,5 L1,9" fill="none" stroke="{colour}" '
                f'stroke-width="1.6"/></marker>')
    return f'<defs>{marker("arr", "#8A99A8")}{marker("arr-x", DENY)}{marker("arr-focus", AZURE)}</defs>'


class Graph:
    """Shared state of one rendering: the analyzer result, its lookups and the canvas."""

    def __init__(self, result: Dict[str, Any], expand: Iterable[str] = ()):
        self.result = result
        self.tree = result.get("tree") or {"roots": [], "nodes": {}}
        self.nodes = self.tree["nodes"]
        self.assignments = {a["id"]: a for a in result.get("assignments") or []}
        self.policies = {p["key"]: p for p in result.get("policies") or []}
        self.profiles = result.get("profiles") or {}
        self.subscriptions = {s["id"]: s for s in result.get("subscriptions") or []}
        self.exemptions: Dict[str, List[Dict[str, Any]]] = {}
        for e in result.get("exemptions") or []:
            self.exemptions.setdefault(e.get("assignmentId") or "", []).append(e)
        self.expand = {x for x in expand if x}
        self.canvas = Canvas()

    def add(self, svg: str) -> None:
        self.canvas.add(svg)

    # -- scope node -------------------------------------------------------------------------------------------

    def scope_box(self, nid: str, x: float, y: float, w: float, focus: bool = False, note: str = "") -> float:
        n = self.nodes[nid]
        h = 62 if note else 52
        stem, kind = SCOPE_ICONS.get(n["kind"], (None, n["kind"]))
        stroke, fill, sw = (AZURE, "#EEF6FC", 2.2) if focus else (LINE, "#FFFFFF", 1)
        parts = [f'<g class="node" data-focus="{_esc(nid)}" data-lens="scope" data-label="{_esc(n["label"])}" '
                 f'tabindex="0" role="button" aria-label="Focus {_esc(n["label"])}"><title>{_esc(n["label"])} - '
                 f'{_esc(kind)}</title>',
                 f'<rect class="box" x="{x:.1f}" y="{y:.1f}" width="{w}" height="{h}" rx="8" fill="{fill}" '
                 f'stroke="{stroke}" stroke-width="{sw}"/>',
                 self.canvas.icon(stem, x + 10, y + 10, 32, n["label"]) if stem else "",
                 _text(x + 50, y + 22, kind if n["kind"] != "Group" else "", 10.5, 400, MUTED),
                 _text(x + 50, y + 39, _fit(n["label"], int((w - 60) / 7.2)), 13, 600, INK, "title")]
        if note:
            parts.append(_text(x + 50, y + 54, _fit(note, int((w - 60) / 5.8)), 10.5, 400, MUTED))
        parts.append("</g>")
        self.add("".join(parts))
        return h

    # -- assignment / initiative node ------------------------------------------------------------------------------

    def assignment_box(self, a: Dict[str, Any], x: float, y: float, w: float, heading: str = "definition",
                       excluded_at: Optional[str] = None, where: bool = True) -> float:
        """One assignment: definition (or assignment) name, effects, issues - opened: its facts and policies."""
        open_ = a["id"] in self.expand
        members = self.profiles.get(a.get("profile")) or []
        chars = int((w - 56) / 6.4)
        kind = (f"Azure Policy initiative · {a.get('policies', len(members))} policies" if a.get("initiative")
                else "Azure Policy definition")
        if heading == "definition":
            title, sub = a.get("definition") or a.get("display"), f"Assignment: {a.get('display')}"
        else:
            title, sub = a.get("display"), f"{a.get('scopeKind')}: {a.get('scopeLabel')}"
        body: List[str] = []
        cy = y
        body.append(self.canvas.icon(POLICY_ICON[0], x + 10, cy + 10, 28, "Azure Policy"))
        body.append(_text(x + 46, cy + 21, _fit(kind, int((w - 150) / 5.6)), 10.5, 400, MUTED))
        body.append(_text(x + 46, cy + 38, _fit(title, int((w - 120) / 6.9)), 13, 600,
                          DENY if excluded_at else INK, "title"))
        body.append(_text(x + w - 12, cy + 21, "▾ hide policies" if open_ else "▸ show policies", 10.5, 600, AZURE,
                          anchor="end"))
        body.append(_text(x + 46, cy + 54, _fit(sub, chars), 10.5, 400, MUTED))
        link = where and a.get("definitionId") and heading == "definition"
        cy += 76 if link else 62
        counts = Counter(_effect_class(e) for _, e in members)
        chip_items = [(f"{counts[c]} {c}", CLASS_COLOURS[c]) for c in CLASS_ORDER if counts[c]]
        if a.get("enforcement") == "DoNotEnforce":
            chip_items.append(("not enforced", WARN))
        chip_items += [(i, DENY) for i in a.get("issues") or [] if i != "not enforced"]
        if excluded_at:
            chip_items.insert(0, (f"excluded at {_fit(excluded_at, 34)}", DENY))
        chips, used = _chips(x + 12, cy, chip_items, x + w - 12)
        body.append(chips)
        cy += used + 6
        if open_:
            cy += 4
            body.append(f'<line x1="{x + 12:.1f}" y1="{cy:.1f}" x2="{x + w - 12:.1f}" y2="{cy:.1f}" stroke="{LINE}"/>')
            cy += 16
            for fact in self._facts(a):
                body.append(_text(x + 14, cy, _fit(fact, int((w - 28) / 5.9)), 10.5, 400, INK))
                cy += LINE_H - 2
            cy += 8
            cy = self._policy_lines(a, members, body, x, cy, w)
        h = cy - y + 6
        fill = "#FFF7F7" if excluded_at else "#FFFFFF"
        stroke = DENY if excluded_at else (AZURE if open_ else LINE)
        dash = ' stroke-dasharray="6 4"' if excluded_at else ""
        frame = (f'<rect class="box" x="{x:.1f}" y="{y:.1f}" width="{w}" height="{h:.1f}" rx="8" fill="{fill}" '
                 f'stroke="{stroke}" stroke-width="{1.6 if open_ else 1}"{dash}/>')
        toggle = (f'<g class="node" data-expand="{_esc(a["id"])}" data-label="{_esc(title)}" tabindex="0" role="button" '
                  f'aria-label="{"Hide" if open_ else "Show"} the policies of {_esc(title)}"><title>{_esc(title)} - '
                  f'{_esc(sub)}</title>')
        self.add(toggle + frame + "".join(body) + "</g>")
        if link:
            self.add(f'<g class="node" data-focus="{_esc(a["definitionId"])}" data-lens="initiative" tabindex="0" '
                     f'role="button" aria-label="Where else is {_esc(title)} assigned">'
                     f'<title>Every assignment of {_esc(title)}</title>'
                     + _text(x + 46, y + 70, "where else is it assigned? ›", 10.5, 600, AZURE)
                     + "</g>")
        return h

    def _facts(self, a: Dict[str, Any]) -> List[str]:
        facts = [f"Assigned at: {a.get('scopeKind')} {a.get('scopeLabel')}",
                 f"Assignment: {a.get('display')} ({a.get('name')})",
                 f"Definition: {a.get('definition')} · {a.get('source') or 'source unknown'}"
                 + (f" · {a['category']}" if a.get("category") else ""),
                 "Enforcement: " + ("not enforced (DoNotEnforce) - Deny and remediation do not act"
                                    if a.get("enforcement") == "DoNotEnforce" else "enforced (Default)"),
                 f"Managed identity: {a.get('identity') or 'none'}"]
        if a.get("resources"):
            facts.append(f"Compliance: {a.get('compliance')} % - {a.get('noncompliant'):,} of {a.get('resources'):,} "
                         "evaluated resources non-compliant")
        else:
            facts.append("Compliance: no evaluated resources")
        scopes = a.get("notScopes") or []
        if scopes:
            facts.append(f"Excluded scopes ({len(scopes)}): " + ", ".join(self._scope_name(s) for s in scopes[:4])
                         + (" …" if len(scopes) > 4 else ""))
        for e in self.exemptions.get(a["id"], [])[:4]:
            facts.append(f"Exemption: {e.get('display')} · {e.get('category') or 'no category'} · "
                         f"{e.get('scopeLabel')} · {e.get('expires') or 'no end date'}")
        if len(self.exemptions.get(a["id"], [])) > 4:
            facts.append(f"… {len(self.exemptions[a['id']]) - 4} more exemptions")
        if a.get("created"):
            facts.append(f"Created: {a['created']}")
        return facts

    def _policy_lines(self, a: Dict[str, Any], members: List[List[str]], body: List[str], x: float, cy: float,
                      w: float) -> float:
        bad = a.get("memberNoncompliant") or {}
        groups: Dict[str, List[Tuple[str, str]]] = {c: [] for c in CLASS_ORDER}
        for key, effect in members:
            groups[_effect_class(effect)].append((key, effect))
        shown = 0
        for c in CLASS_ORDER:
            items = sorted(groups[c], key=lambda m: (-(bad.get(m[0]) or 0),
                                                     str((self.policies.get(m[0]) or {}).get("display") or m[0])))
            if not items:
                continue
            body.append(f'<rect x="{x + 12:.1f}" y="{cy - 11:.1f}" width="4" height="14" fill="{CLASS_COLOURS[c]}"/>')
            body.append(_text(x + 22, cy, f"{CLASS_LABELS[c]} ({len(items)})", 11, 700, CLASS_COLOURS[c]))
            cy += LINE_H + 1
            for key, effect in items:
                if shown >= MAX_POLICY_LINES:
                    break
                p = self.policies.get(key) or {}
                flags = " ".join(f for f, on in (("[deprecated]", p.get("deprecated")), ("[preview]", p.get("preview")))
                                 if on)
                body.append(_text(x + 22, cy, "• " + _fit(f"{p.get('display') or key} {flags}".strip(),
                                                         int((w - 120) / 5.9)), 10.5, 400, INK))
                right = (f"{bad[key]:,} non-compliant · " if bad.get(key) else "") + (effect or "default")
                body.append(_text(x + w - 12, cy, right, 10.5, 400, DENY if bad.get(key) else MUTED, anchor="end"))
                cy += LINE_H - 1
                shown += 1
            cy += 6
        if len(members) > shown:
            body.append(_text(x + 14, cy, f"… {len(members) - shown} more policies - the Assignments view and the "
                                          "CSV list them all", 10.5, 400, MUTED))
            cy += LINE_H
        return cy

    def _scope_name(self, scope: str) -> str:
        s = (scope or "").lower()
        for n in self.nodes.values():
            if n.get("scope") == s:
                return n["label"]
        return s.rsplit("/", 1)[-1]

    # -- frame -----------------------------------------------------------------------------------------------------

    def header(self, title: str, subtitle: str) -> None:
        self.add(_text(X_LEFT, 32, title, 18, 700, INK))
        self.add(_text(X_LEFT, 52, subtitle, 11.5, 400, MUTED))
        legend = [("assigned / inherited", "#8A99A8", False), ("excluded (notScopes)", DENY, True)]
        lx = X_LEFT
        for label, colour, dashed in legend:
            dash = ' stroke-dasharray="6 4"' if dashed else ""
            self.add(f'<line x1="{lx:.1f}" y1="72" x2="{lx + 34:.1f}" y2="72" stroke="{colour}" stroke-width="1.6"{dash}/>')
            self.add(_text(lx + 40, 76, label, 10.5, 400, MUTED))
            lx += 48 + len(label) * 6.2
        for c in CLASS_ORDER:
            svg, used = _chip(lx, 64, c, CLASS_COLOURS[c])
            self.add(svg)
            lx += used
        self.add(_text(lx + 8, 76, "effects of the policies", 10.5, 400, MUTED))

    def svg(self, height: float, title: str) -> str:
        return self.canvas.svg(WIDTH, height, title).replace("<defs>", _markers() + "<defs>", 1)


# ---------------------------------------------------------------------------
# Scope lens
# ---------------------------------------------------------------------------

def _chain(graph: Graph, focus: str) -> List[str]:
    chain, nid = [], focus
    while nid and nid in graph.nodes:
        if graph.nodes[nid]["kind"] != "Group":
            chain.append(nid)
        nid = graph.nodes[nid].get("parent")
    return list(reversed(chain))


def render_scope(result: Dict[str, Any], focus: str, expand: Iterable[str] = ()) -> str:
    graph = Graph(result, expand)
    if focus not in graph.nodes:
        raise KeyError(focus)
    chain = _chain(graph, focus) or [focus]
    target = graph.nodes[focus]
    graph.header(f"How Azure Policy reaches {target['label']}",
                 "Initiatives and policies assigned on this scope and every scope above it. Click a scope to focus "
                 "it, an initiative to open its policies.")
    # what each scope of the chain contributes: (assignment, excluded at) - excluded = a scope between it and the
    # focus is in the assignment's notScopes
    blocks = []
    for i, nid in enumerate(chain):
        below = [graph.nodes[c]["scope"] for c in chain[i + 1:]]
        items = []
        for aid in graph.nodes[nid]["assigned"]:
            a = graph.assignments.get(aid)
            if not a:
                continue
            stop = next((s for s in below if s in (a.get("notScopes") or [])), None)
            items.append((a, stop))
        items.sort(key=lambda t: (t[1] is not None, (t[0].get("definition") or "").lower()))
        blocks.append((nid, items))

    y = TOP
    scope_pos: Dict[str, Tuple[float, float]] = {}
    pending: List[Tuple[float, float, str, bool]] = []   # (x, y) of an assignment's edge start, target scope, excluded
    for nid, items in blocks:
        top = y
        note = f"{len(items)} assigned here" if items else "nothing assigned here"
        h_scope = graph.scope_box(nid, X_MID, top, W_MID, focus=nid == focus, note=note)
        scope_pos[nid] = (top, top + h_scope)
        cy = top
        for a, stop in items:
            h = graph.assignment_box(a, X_LEFT, cy, W_LEFT, excluded_at=graph._scope_name(stop) if stop else None)
            pending.append((X_LEFT + W_LEFT, cy + 28, nid, False))
            if stop:
                stop_node = next((c for c in chain if graph.nodes[c]["scope"] == stop), None)
                if stop_node:
                    pending.append((X_LEFT + W_LEFT, cy + 40, stop_node, True))
            cy += h + 12
        y = max(top + h_scope, cy - 12) + 46
    for x1, y1, nid, excluded in pending:
        top, _bottom = scope_pos[nid]
        if excluded:
            graph.add(_curve(x1, y1, X_MID, top + 40, DENY, dashed=True, arrow="arr-x"))
            graph.add(_text(X_MID - 8, top + 52, "✕ excluded", 10.5, 700, DENY, anchor="end"))
        else:
            graph.add(_curve(x1, y1, X_MID, top + 26))
    for upper, lower in zip(chain, chain[1:]):
        (_, bottom), (top, _) = scope_pos[upper], scope_pos[lower]
        cx = X_MID + W_MID / 2
        graph.add(f'<line x1="{cx:.1f}" y1="{bottom + 2:.1f}" x2="{cx:.1f}" y2="{top - 4:.1f}" stroke="#8A99A8" '
                  f'stroke-width="1.6" marker-end="url(#arr)"/>')
        graph.add(_text(cx + 8, (bottom + top) / 2 + 4, "inherits", 10.5, 400, MUTED))

    bottom = _scope_summary(graph, focus, chain, scope_pos[focus][0])
    return graph.svg(max(y, bottom) + 30, f"Azure Policy reaching {target['label']}")


def _scope_summary(graph: Graph, focus: str, chain: List[str], top: float) -> float:
    """What is in effect on the scope in focus, its exemptions and the scopes below it."""
    n = graph.nodes[focus]
    reaching: List[Dict[str, Any]] = []
    for i, nid in enumerate(chain):
        below = [graph.nodes[c]["scope"] for c in chain[i + 1:]]
        for aid in graph.nodes[nid]["assigned"]:
            a = graph.assignments.get(aid)
            if a and not any(s in (a.get("notScopes") or []) for s in below):
                reaching.append(a)
    strongest: Dict[str, str] = {}
    for a in reaching:
        if a.get("enforcement") == "DoNotEnforce":
            continue
        for key, effect in graph.profiles.get(a.get("profile")) or []:
            c = _effect_class(effect)
            if key not in strongest or CLASS_ORDER.index(c) < CLASS_ORDER.index(strongest[key]):
                strongest[key] = c
    counts = Counter(strongest.values())
    x, w = X_RIGHT, W_RIGHT
    parts: List[str] = []
    cy = top + 24
    parts.append(_text(x + 14, cy, f"In effect on this {n['kind'].lower()}", 13, 700, INK))
    cy += 20
    parts.append(_text(x + 14, cy, f"{len(reaching)} assignments ({sum(1 for a in reaching if a['scope'].lower() != n['scope'])} "
                                   f"inherited) · {len(strongest)} policies enforced", 11, 400, INK))
    cy += 18
    total = max(1, len(strongest))
    for c in CLASS_ORDER:
        if not counts[c]:
            continue
        bar = (w - 150) * counts[c] / total
        parts.append(_text(x + 14, cy + 10, CLASS_LABELS[c].split(" (")[0], 10.5, 400, INK))
        parts.append(f'<rect x="{x + 90:.1f}" y="{cy:.1f}" width="{max(2, bar):.1f}" height="12" rx="3" '
                     f'fill="{CLASS_COLOURS[c]}" fill-opacity="0.75"/>')
        parts.append(_text(x + 96 + max(2, bar), cy + 10, str(counts[c]), 10.5, 600, CLASS_COLOURS[c]))
        cy += 18
    sub = graph.subscriptions.get(n["id"].split(":", 1)[1]) if n["kind"] == "Subscription" else None
    if sub and sub.get("resources"):
        cy += 4
        parts.append(_text(x + 14, cy, f"Compliance {sub['compliance']} % - {sub['noncompliant']:,} of "
                                       f"{sub['resources']:,} resources non-compliant", 11, 400, INK))
        cy += 18
    not_enforced = [a for a in reaching if a.get("enforcement") == "DoNotEnforce"]
    if not_enforced:
        parts.append(_text(x + 14, cy, f"{len(not_enforced)} assignment(s) not enforced - report only", 11, 600, WARN))
        cy += 18
    exemptions = [e for e in graph.result.get("exemptions") or []
                  if e.get("scope") and (e["scope"] == n["scope"] or e["scope"].startswith(n["scope"] + "/"))]
    if exemptions:
        cy += 4
        parts.append(_text(x + 14, cy, f"Exemptions on this scope ({len(exemptions)})", 11, 700, EXEMPT))
        cy += 16
        for e in exemptions[:6]:
            parts.append(_text(x + 20, cy, "• " + _fit(f"{e.get('display')} - {e.get('assignment')}", 46), 10.5, 400, INK))
            cy += 14
            parts.append(_text(x + 30, cy, f"{e.get('category') or 'no category'} · {e.get('expires') or 'no end date'}"
                                           f" · {e.get('status')}", 10.5, 400, MUTED))
            cy += 15
        if len(exemptions) > 6:
            parts.append(_text(x + 20, cy, f"… {len(exemptions) - 6} more", 10.5, 400, MUTED))
            cy += 15
    h = cy - top + 8
    graph.add(f'<rect x="{x:.1f}" y="{top:.1f}" width="{w}" height="{h:.1f}" rx="8" fill="#F8FAFC" stroke="{AZURE}" '
              f'stroke-width="1.2"/>' + "".join(parts))
    graph.add(f'<line x1="{X_MID + W_MID:.1f}" y1="{top + 26:.1f}" x2="{x - 4:.1f}" y2="{top + 26:.1f}" stroke="{AZURE}" '
              f'stroke-width="1.4" marker-end="url(#arr-focus)"/>')
    bottom = top + h
    children = [c for c in n.get("children") or [] if c in graph.nodes]
    if children:
        cy = bottom + 30
        graph.add(_text(x, cy - 10, f"Below this scope - {n.get('subscriptions', 0)} subscription(s), "
                                    f"{n.get('assignedBelow', 0)} more assignment(s)", 11, 700, INK))
        for c in children[:MAX_CHILDREN]:
            child = graph.nodes[c]
            note = (f"{child.get('subscriptions', 0)} subscriptions · " if child["kind"] == "Management group" else "") + \
                f"{len(child['assigned'])} assigned · {child.get('inherited', 0)} inherited"
            h_child = graph.scope_box(c, x, cy, w, note=note)
            cy += h_child + 8
        if len(children) > MAX_CHILDREN:
            graph.add(_text(x, cy + 10, f"… {len(children) - MAX_CHILDREN} more - the Tree view lists them", 10.5,
                            400, MUTED))
            cy += 20
        bottom = cy
    return bottom


# ---------------------------------------------------------------------------
# Initiative lens
# ---------------------------------------------------------------------------

def _subscriptions_below(graph: Graph, nid: str, not_scopes: List[str]) -> Tuple[int, List[str]]:
    """(subscriptions an assignment on `nid` reaches, the excluded scopes it stops at) - walking the tree."""
    reached, excluded = 0, []
    stack = [nid]
    while stack:
        cur = graph.nodes.get(stack.pop())
        if not cur:
            continue
        if cur["scope"] in not_scopes and cur["id"] != nid:
            excluded.append(cur["label"])
            continue
        if cur["kind"] == "Subscription":
            reached += 1
        stack.extend(cur.get("children") or [])
    return reached, excluded


def _scope_node_of(a: Dict[str, Any]) -> str:
    s = (a.get("scope") or "").lower()
    if "/managementgroups/" in s:
        return "mg:" + s.rsplit("/", 1)[-1]
    parts = s.split("/")
    if "/resourcegroups/" in s:
        return f"rg:{parts[2]}/{s.split('/resourcegroups/')[1].split('/')[0]}"
    return f"sub:{parts[2]}" if len(parts) > 2 else ""


def render_initiative(result: Dict[str, Any], definition: str, expand: Iterable[str] = ()) -> str:
    graph = Graph(result, expand)
    key = (definition or "").lower()
    mine = [a for a in graph.assignments.values() if (a.get("definitionId") or "").lower() == key]
    if not mine:
        raise KeyError(definition)
    first = mine[0]
    name = first.get("definition") or key.rsplit("/", 1)[-1]
    graph.header(f"Where {name} is assigned",
                 f"{len(mine)} assignment(s) of this {'initiative' if first.get('initiative') else 'policy'}, and what "
                 "each one reaches. Click an assignment to open its policies, a scope to focus it.")
    # the definition itself, opened with the policies of its most common assignment
    profiles = Counter(a.get("profile") for a in mine)
    model = max(mine, key=lambda a: profiles[a.get("profile")])
    card = dict(model, id="definition", issues=[], enforcement="Default", display=f"{len(mine)} assignment(s)",
                memberNoncompliant={})
    h_def = graph.assignment_box(card, X_LEFT, TOP, W_LEFT, where=False)
    if len(profiles) > 1:
        graph.add(_text(X_LEFT, TOP + h_def + 16, f"Effects as in {profiles[model['profile']]} of {len(mine)} "
                                                  "assignments - their parameters differ; open an assignment",
                        10.5, 400, WARN))
    def_mid = TOP + 28

    individual = [a for a in mine if a.get("scopeKind") != "Subscription"]
    per_sub = [a for a in mine if a.get("scopeKind") == "Subscription"]
    if len(per_sub) <= MAX_SUBSCRIPTION_NODES:
        individual += per_sub
        per_sub = []
    individual.sort(key=lambda a: (["Management group", "Resource group", "Subscription"].index(a.get("scopeKind"))
                                   if a.get("scopeKind") in ("Management group", "Resource group", "Subscription")
                                   else 9, (a.get("scopeLabel") or "").lower()))
    y = TOP
    for a in individual:
        h = graph.assignment_box(a, X_MID, y, W_MID, heading="assignment")
        graph.add(_curve(X_LEFT + W_LEFT, def_mid, X_MID, y + 28))
        nid = _scope_node_of(a)
        if nid in graph.nodes:
            reached, excluded = _subscriptions_below(graph, nid, a.get("notScopes") or [])
            node = graph.nodes[nid]
            note = (f"in effect on {reached} subscription(s)" if node["kind"] != "Resource group"
                    else "in effect on this resource group")
            h_scope = graph.scope_box(nid, X_RIGHT, y, W_RIGHT, note=note)
            graph.add(_curve(X_MID + W_MID, y + 28, X_RIGHT, y + 26))
            ey = y + h_scope + 14
            for label in excluded[:4]:
                graph.add(_text(X_RIGHT + 14, ey, f"✕ excluded: {_fit(label, 40)}", 10.5, 700, DENY))
                ey += 15
            h = max(h, ey - y)
        y += h + 16
    if per_sub:
        top = y
        names = sorted((a.get("scopeLabel") or "") for a in per_sub)
        parts = [f'<rect class="box" x="{X_MID:.1f}" y="{top:.1f}" width="{W_MID}" height="0" rx="8"/>']
        cy = top + 10
        parts.append(graph.canvas.icon(SUBSCRIPTION_ICON[0], X_MID + 10, cy, 28, "Subscription"))
        parts.append(_text(X_MID + 46, cy + 11, "Subscription", 10.5, 400, MUTED))
        parts.append(_text(X_MID + 46, cy + 28, f"{len(per_sub)} assignments, one per subscription", 13, 600, INK))
        cy += 46
        for label in names[:10]:
            parts.append(_text(X_MID + 16, cy, "• " + _fit(label, 38), 10.5, 400, INK))
            cy += 14
        if len(names) > 10:
            parts.append(_text(X_MID + 16, cy, f"… {len(names) - 10} more", 10.5, 400, MUTED))
            cy += 14
        not_enforced = sum(1 for a in per_sub if a.get("enforcement") == "DoNotEnforce")
        issues = sum(1 for a in per_sub if a.get("issues"))
        if not_enforced or issues:
            parts.append(_text(X_MID + 16, cy + 4, f"{not_enforced} not enforced · {issues} with issues", 10.5, 600, WARN))
            cy += 18
        h = cy - top + 4
        parts[0] = (f'<rect class="box" x="{X_MID:.1f}" y="{top:.1f}" width="{W_MID}" height="{h:.1f}" rx="8" '
                    f'fill="#FFFFFF" stroke="{LINE}"/>')
        graph.add("".join(parts))
        graph.add(_curve(X_LEFT + W_LEFT, def_mid, X_MID, top + 28))
        bad = sum(a.get("noncompliant") or 0 for a in per_sub)
        evaluated = sum(a.get("resources") or 0 for a in per_sub)
        summary = [_text(X_RIGHT + 14, top + 24, f"In effect on {len(per_sub)} subscription(s)", 13, 700, INK),
                   _text(X_RIGHT + 14, top + 44, (f"{bad:,} of {evaluated:,} evaluated resources non-compliant"
                                                  if evaluated else "no evaluated resources"), 11, 400, INK)]
        graph.add(f'<rect x="{X_RIGHT:.1f}" y="{top:.1f}" width="{W_RIGHT}" height="58" rx="8" fill="#F8FAFC" '
                  f'stroke="{AZURE}" stroke-width="1.2"/>' + "".join(summary))
        graph.add(_curve(X_MID + W_MID, top + 28, X_RIGHT, top + 28))
        y = top + max(h, 58) + 16
    return graph.svg(max(y, TOP + h_def + 40) + 30, f"Where {name} is assigned")


def render(result: Dict[str, Any], lens: str = SCOPE, focus: str = "", expand: Iterable[str] = ()) -> str:
    """The graph for a lens; focus = a tree node id (scope lens) or a definition id (initiative lens)."""
    if lens == INITIATIVE:
        return render_initiative(result, focus, expand)
    tree = result.get("tree") or {}
    if not focus:
        roots = [r for r in tree.get("roots") or [] if (tree.get("nodes") or {}).get(r, {}).get("kind") != "Group"]
        focus = roots[0] if roots else ""
    return render_scope(result, focus, expand)
