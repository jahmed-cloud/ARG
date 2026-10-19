"""
Architecture diagrams from the estate (estate.json / the Docker estate snapshot, both the compact format):

- render_tenant():       tenant root -> management groups -> subscriptions, with the Azure Policy assignments on each
                         scope (deny policies, allowed locations, allowed / not allowed resource types) and per
                         subscription its resources, 30-day cost and environment;
- render_subscription(): one subscription - its management-group path, the effective policy (what is allowed and
                         what is not, and what in use violates it), VNets with their peerings, and every resource
                         group with its services drawn with the official Azure icons and counts.

Both return one self-contained SVG (icons embedded unchanged as data URIs, see azure_icons/NOTICE.md), so the local
portal and the Docker UI show the same picture and "export" is just the file. Nodes carry data-label (search) and
data-subscription (drill-down) attributes for the viewer.
"""

import base64
import html
import math
import re
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scripts.subscription_analysis.diagram_icons import (
    POLICY_ICON,
    RESOURCE_GROUP_ICON,
    SHOWN_CHILD_TYPES,
    SUBSCRIPTION_ICON,
    TENANT_ICON,
    icon_for,
)

ICON_DIR = Path(__file__).parent / "azure_icons"
FONT = "Segoe UI, Segoe UI Web, Arial, sans-serif"
INK, MUTED, LINE = "#1B2A3A", "#5F6B7A", "#C8D3DE"
AZURE, DENY, ALLOW, WARN = "#0078D4", "#C50F1F", "#107C10", "#CA5010"
ENV_COLOURS = {"Production": "#107C10", "Non-production": "#CA5010", "Unknown": "#8A8886"}
STYLE = (f"text{{font-family:{FONT};fill:{INK}}} .muted{{fill:{MUTED}}} .small{{font-size:10.5px}} "
         ".node:hover rect.box{stroke-width:2.5} .hit rect.box{stroke:#f44336;stroke-width:3.5} "
         "a:hover .title{text-decoration:underline} [data-subscription]{cursor:pointer}")


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _fit(text: Any, chars: int) -> str:
    text = str(text or "")
    return text if len(text) <= chars else text[:max(1, chars - 1)] + "…"


def _slug(stem: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")


@lru_cache(maxsize=256)
def _icon_data(stem: str) -> Optional[str]:
    path = ICON_DIR / f"{stem}.svg"
    if not path.is_file():
        return None
    return "data:image/svg+xml;base64," + base64.b64encode(path.read_bytes()).decode()


class Canvas:
    """SVG builder that embeds each icon once (<symbol>) and reuses it (<use>)."""

    def __init__(self) -> None:
        self.parts: List[str] = []
        self.icons: Dict[str, str] = {}

    def add(self, svg: str) -> None:
        self.parts.append(svg)

    def icon(self, stem: Optional[str], x: float, y: float, size: float, fallback: str = "") -> str:
        data = _icon_data(stem) if stem else None
        if data is None:   # no Azure icon for this type: a neutral tile, never another service's icon
            letters = _esc("".join(w[0] for w in re.findall(r"[A-Za-z]+", fallback)[:2]).upper() or "?")
            return (f'<rect x="{x:.1f}" y="{y:.1f}" width="{size}" height="{size}" rx="4" fill="#E1E5EA"/>'
                    f'<text x="{x + size / 2:.1f}" y="{y + size * 0.64:.1f}" text-anchor="middle" '
                    f'font-size="{size * 0.42:.0f}" class="muted">{letters}</text>')
        sid = "ic-" + _slug(stem)
        self.icons.setdefault(sid, data)
        return f'<use href="#{sid}" xlink:href="#{sid}" x="{x:.1f}" y="{y:.1f}" width="{size}" height="{size}"/>'

    def svg(self, width: float, height: float, title: str) -> str:
        symbols = "".join(f'<symbol id="{sid}" viewBox="0 0 18 18"><image href="{data}" xlink:href="{data}" '
                          f'width="18" height="18"/></symbol>' for sid, data in self.icons.items())
        return (f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
                f'width="{width:.0f}" height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" role="img" '
                f'aria-label="{_esc(title)}"><title>{_esc(title)}</title><style>{STYLE}</style><defs>{symbols}</defs>'
                f'<rect width="100%" height="100%" fill="#FFFFFF"/>' + "".join(self.parts) + "</svg>")


# ---------------------------------------------------------------------------
# Shared data helpers
# ---------------------------------------------------------------------------

STATE_LABELS = {"running": "running", "deallocated": "deallocated", "stopped": "stopped, still billed"}


def vm_state(r: Dict[str, Any]) -> Optional[str]:
    """'running' / 'deallocated' / 'stopped' (stopped but not deallocated: compute still billed) for a VM."""
    if (r.get("type") or "").lower() != "microsoft.compute/virtualmachines":
        return None
    state = (r.get("state") or "").lower()
    if "deallocat" in state:
        return "deallocated"
    if "stop" in state:
        return "stopped"
    return "running" if state else None


def _subscription_stats(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    subs = data.get("subscriptions") or []
    stats = {s["id"]: {"resources": 0, "cost": 0.0, "currency": s.get("currency") or "", "env": Counter()}
             for s in subs}
    for r in data.get("resources") or []:
        idx = r.get("s", -1)
        if not 0 <= idx < len(subs):
            continue
        st = stats[subs[idx]["id"]]
        st["resources"] += 1
        st["cost"] += float(r.get("cost") or 0)
        st["currency"] = st["currency"] or r.get("cur") or ""
        st["env"][r.get("env") or "Unknown"] += 1
    return stats


def _sub_env(name: str) -> str:
    from scripts.subscription_analysis.estate import env_from_subscription

    return {"prod": "Production", "nonprod": "Non-production"}.get(env_from_subscription(name) or "", "Unknown")


def _scope_of_group(name: str) -> str:
    return f"/providers/microsoft.management/managementgroups/{name.lower()}"


def _policies_by_scope(arch: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in arch.get("policies") or []:
        out[(p.get("scope") or "").lower()].append(p)
    return out


def _is_deny(p: Dict[str, Any]) -> bool:
    return p.get("enforced", True) and "deny" in (p.get("effect") or "").lower()


def _defender_default(p: Dict[str, Any]) -> bool:
    """Assignments Defender for Cloud creates by itself ("ASC Default (subscription: ...)", "ASC provisioning ...")."""
    return (p.get("name") or "").startswith("ASC ")


def _policy_lines(policies: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """Up to four (text, colour) lines summarising the assignments on one scope."""
    if not policies:
        return []
    deny = sum(1 for p in policies if _is_deny(p))
    initiatives = sum(1 for p in policies if p.get("initiative"))
    off = sum(1 for p in policies if not p.get("enforced", True))
    lines = [(f"Policy: {len(policies)} assignment(s)" + (f" · {initiatives} initiative(s)" if initiatives else "")
              + (f" · {deny} deny" if deny else "") + (f" · {off} not enforced" if off else ""),
              DENY if deny else INK)]
    locations = sorted({loc for p in policies if p.get("enforced", True) for loc in p.get("allowed_locations") or []})
    if locations:
        lines.append(("Allowed locations: " + ", ".join(locations[:4]) + (f" +{len(locations) - 4}"
                                                                          if len(locations) > 4 else ""), ALLOW))
    allowed = {t for p in policies if p.get("enforced", True) for t in p.get("allowed_types") or []}
    denied = {t for p in policies if p.get("enforced", True) for t in p.get("denied_types") or []}
    if allowed:
        lines.append((f"Allowed resource types: {len(allowed)} (allow list)", ALLOW))
    if denied:
        lines.append((f"Not allowed resource types: {len(denied)}", DENY))
    return lines[:4]


# ---------------------------------------------------------------------------
# Tenant view
# ---------------------------------------------------------------------------

MG_MIN_W, CHIP_W, CHIP_H, CHIP_GAP, PAD, COL_GAP, ROW_GAP, MAX_ASSIGNMENTS = 300, 236, 40, 6, 10, 64, 14, 7
EFFECT_LABELS = {"deployifnotexists": "DINE", "modify": "Modify", "audit": "Audit", "auditifnotexists": "AINE",
                 "append": "Append", "disabled": "Disabled"}


def _assignment_lines(policies: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """The guardrails on one management group: what is allowed / denied first, then each assignment by effect."""
    if not policies:
        return []
    lines = _policy_lines(policies)[1:]   # allowed locations / allowed / not allowed resource types

    def rank(p: Dict[str, Any]) -> Tuple[int, str]:
        return (0 if _is_deny(p) else 1 if p.get("initiative") else 2, (p.get("name") or "").lower())

    shown = sorted(policies, key=rank)
    room = MAX_ASSIGNMENTS - len(lines)
    for p in shown[:room]:
        effect = (p.get("effect") or "").lower()
        if not p.get("enforced", True):
            tag, colour = "Not enforced", MUTED
        elif _is_deny(p):
            tag, colour = p.get("effect") or "Deny", DENY
        elif p.get("initiative"):
            tag, colour = "Initiative", INK
        else:
            tag = EFFECT_LABELS.get(effect, "Policy")
            colour = AZURE if effect in ("deployifnotexists", "modify") else INK
        lines.append((f"{tag} · {p.get('name') or ''}", colour))
    if len(shown) > room:
        lines.append((f"+{len(shown) - room} more assignment(s)", MUTED))
    return lines


def _chip_columns(count: int) -> int:
    return 0 if not count else 1 if count <= 4 else 2 if count <= 12 else 3 if count <= 30 else 4


def render_tenant(data: Dict[str, Any], link: Optional[str] = None) -> str:
    """Tenant root -> management groups (with their Azure Policy assignments) -> subscriptions as a compact grid in
    each group's block, child groups to the right. `link` ("...{id}...") makes subscriptions clickable."""
    arch = data.get("architecture") or {}
    groups: Dict[str, Dict[str, Any]] = dict(arch.get("management_groups") or {})
    parents: Dict[str, List[str]] = arch.get("subscription_parents") or {}
    subs = data.get("subscriptions") or []
    sub_by_id = {s["id"]: s for s in subs}
    stats = _subscription_stats(data)
    by_scope = _policies_by_scope(arch)

    UNPLACED = "__unplaced__"
    child_groups: Dict[Optional[str], List[str]] = defaultdict(list)
    group_subs: Dict[str, List[str]] = defaultdict(list)
    for name, g in groups.items():
        child_groups[g.get("parent") if g.get("parent") in groups else None].append(name)
    for s in subs:
        chain = parents.get(s["id"]) or []
        group_subs[chain[0] if chain and chain[0] in groups else UNPLACED].append(s["id"])
    if group_subs.get(UNPLACED):
        groups[UNPLACED] = {"name": UNPLACED, "displayName": "Placement not collected / no access", "parent": None}
        child_groups[None].append(UNPLACED)
    for key in child_groups:
        child_groups[key].sort(key=lambda n: (n == UNPLACED, groups[n]["displayName"].lower()))
    for key in group_subs:
        group_subs[key].sort(key=lambda i: ((sub_by_id.get(i) or {}).get("name") or i).lower())

    # block sizes, then a top-aligned tree: each group's children start right of it, one under the other
    lines = {g: _assignment_lines(by_scope.get(_scope_of_group(g), [])) if g != UNPLACED else [] for g in groups}
    size: Dict[str, Tuple[float, float, float]] = {}   # width, height, header height
    for name in groups:
        count = len(group_subs.get(name, []))
        cols = _chip_columns(count)
        header = 52 + 15 * len(lines[name]) + (4 if lines[name] else 0)
        grid = (math.ceil(count / cols) * (CHIP_H + CHIP_GAP) - CHIP_GAP + PAD) if cols else 0
        size[name] = (max(MG_MIN_W, cols * CHIP_W + max(cols - 1, 0) * CHIP_GAP + 2 * PAD), header + grid, header)

    boxes: Dict[str, Tuple[float, float]] = {}

    def place(name: str, left: float, top: float) -> float:
        boxes[name] = (left, top)
        bottom, child_top = top + size[name][1], top
        for kid in child_groups.get(name, []):
            child_top = place(kid, left + size[name][0] + COL_GAP, child_top) + ROW_GAP
            bottom = max(bottom, child_top - ROW_GAP)
        return bottom

    cursor = 104.0
    for root in child_groups.get(None, []):
        cursor = place(root, 24.0, cursor) + ROW_GAP * 2

    canvas = Canvas()
    for name, (x, y) in boxes.items():   # connectors first, under the blocks
        for kid in child_groups.get(name, []):
            cx, cy = boxes[kid]
            sx, sy, ty = x + size[name][0], y + 24, cy + 24
            mx = sx + COL_GAP / 2
            canvas.add(f'<path d="M{sx:.1f},{sy:.1f} H{mx:.1f} V{ty:.1f} H{cx:.1f}" fill="none" stroke="{LINE}" '
                       f'stroke-width="1.4"/>')

    for name, (x, y) in boxes.items():
        g = groups[name]
        w, h, header = size[name]
        root = g.get("parent") is None and name != UNPLACED
        count = len(group_subs.get(name, []))
        label = g["displayName"] + (" (tenant root)" if root else "")
        sub_note = f" · {count} subscription(s)" if count else ""
        body = [f'<rect class="box" x="{x:.1f}" y="{y:.1f}" width="{w:.0f}" height="{h:.1f}" rx="7" '
                f'fill="{"#E3EEFA" if root else "#F4F8FC"}" stroke="{AZURE}" stroke-width="1.2"/>',
                canvas.icon(TENANT_ICON[0], x + 10, y + 10, 26),
                f'<text x="{x + 44:.1f}" y="{y + 23:.1f}" font-size="13" font-weight="600">'
                f'{_esc(_fit(label, int((w - 54) / 7)))}</text>',
                f'<text x="{x + 44:.1f}" y="{y + 39:.1f}" class="muted small">'
                f'{_esc(_fit(TENANT_ICON[1] + sub_note + " · " + (name if name != UNPLACED else ""), int((w - 54) / 5.3)))}'
                f'</text>']
        for i, (text, colour) in enumerate(lines[name]):
            body.append(f'<text x="{x + 12:.1f}" y="{y + 60 + i * 15:.1f}" font-size="11" fill="{colour}">'
                        f'{_esc(_fit(text, int((w - 20) / 5.6)))}</text>')
        canvas.add(f'<g class="node" data-label="{_esc((g["displayName"] + " " + name).lower())}">'
                   + "".join(body) + "</g>")
        cols = _chip_columns(count)
        for i, sub_id in enumerate(group_subs.get(name, [])):
            cx = x + PAD + (i % cols) * (CHIP_W + CHIP_GAP)
            cy = y + header + (i // cols) * (CHIP_H + CHIP_GAP)
            canvas.add(_subscription_chip(canvas, sub_by_id.get(sub_id) or {"id": sub_id, "name": sub_id},
                                          stats.get(sub_id), by_scope.get(f"/subscriptions/{sub_id}", []), cx, cy,
                                          link))

    right = max((boxes[n][0] + size[n][0] for n in boxes), default=600)
    policies = arch.get("policies") or []
    canvas.add(f'<text x="24" y="34" font-size="20" font-weight="700">Tenant architecture</text>'
               f'<text x="24" y="56" class="muted" font-size="12">{len([g for g in groups if g != UNPLACED])} '
               f'management groups · {len(subs)} subscriptions · {len(policies)} policy assignments '
               f'({sum(1 for p in policies if _is_deny(p))} deny) · collected '
               f'{_esc(str(arch.get("collected_at") or data.get("inventory_at") or "")[:16].replace("T", " "))}</text>')
    canvas.add(_legend(24, 70))
    if not arch.get("subscription_parents"):
        canvas.add('<text x="24" y="96" font-size="12" fill="#CA5010">Management-group placement and policies were '
                   'not collected yet - refresh the estate inventory.</text>')
    return canvas.svg(max(right + 24, 760), max(cursor, 260), "Tenant architecture - management groups, "
                      "subscriptions and Azure Policy")


def _subscription_chip(canvas: Canvas, sub: Dict[str, Any], st: Optional[Dict[str, Any]],
                       policies: List[Dict[str, Any]], x: float, y: float, link: Optional[str]) -> str:
    st = st or {"resources": 0, "cost": 0.0, "currency": ""}
    key, name = sub["id"], sub.get("name") or sub["id"]
    own = [p for p in policies if not _defender_default(p)]
    cost = (f" · {st['cost']:,.0f}" + (f" {st['currency']}" if st['currency'] else "") + "/30 d") if st["cost"] else ""
    body = [f'<rect class="box" x="{x:.1f}" y="{y:.1f}" width="{CHIP_W}" height="{CHIP_H}" rx="5" fill="#FFFFFF" '
            f'stroke="{LINE}" stroke-width="1.1"/>',
            f'<rect x="{x:.1f}" y="{y:.1f}" width="4" height="{CHIP_H}" rx="2" '
            f'fill="{ENV_COLOURS[_sub_env(name)]}"/>',
            canvas.icon(SUBSCRIPTION_ICON[0], x + 9, y + 10, 20),
            f'<text x="{x + 35:.1f}" y="{y + 17:.1f}" font-size="11.5" font-weight="600" class="title">'
            f'{_esc(_fit(name, 29 if own else 31))}</text>',
            f'<text x="{x + 35:.1f}" y="{y + 31:.1f}" class="muted small">{st["resources"]:,} resources'
            f'{_esc(cost)}</text>']
    if own:   # assignments made directly on the subscription (Defender for Cloud's own ones left out)
        deny = any(_is_deny(p) for p in own)
        body.append(canvas.icon(POLICY_ICON[0], x + CHIP_W - 30, y + 6, 13))
        body.append(f'<text x="{x + CHIP_W - 14:.1f}" y="{y + 16:.1f}" font-size="10.5" font-weight="600" '
                    f'fill="{DENY if deny else MUTED}">{len(own)}</text>')
    defaults = len(policies) - len(own)
    tip = (f"{name}\n{key}\n{st['resources']:,} resources{cost}"
           + "".join(f"\nPolicy: {p.get('name')}" + (" (deny)" if _is_deny(p) else "") for p in own[:6])
           + (f"\n+ {defaults} Defender for Cloud default assignment(s)" if defaults else ""))
    node = (f'<g class="node" data-subscription="{_esc(key)}" data-label="{_esc((name + " " + key).lower())}">'
            f'<title>{_esc(tip)}</title>' + "".join(body) + "</g>")
    return f'<a href="{_esc(link.format(id=key))}">{node}</a>' if link else node


def _legend(x: float, y: float) -> str:
    items = [(ENV_COLOURS["Production"], "Production"), (ENV_COLOURS["Non-production"], "Non-production"),
             (ENV_COLOURS["Unknown"], "Environment unknown"), (DENY, "Deny policy / not allowed"),
             (ALLOW, "Allowed (allow list)"), (AZURE, "DeployIfNotExists / Modify")]
    out, cx = [], x
    for colour, text in items:
        out.append(f'<rect x="{cx}" y="{y}" width="10" height="10" rx="2" fill="{colour}"/>'
                   f'<text x="{cx + 14}" y="{y + 9}" class="muted small">{_esc(text)}</text>')
        cx += 30 + len(text) * 5.6
    return "".join(out)


# ---------------------------------------------------------------------------
# Subscription view
# ---------------------------------------------------------------------------

RG_W, TILE_W, TILE_H, MAX_TILES = 330, 158, 42, 14


def effective_policy(arch: Dict[str, Any], sub_id: str) -> Dict[str, Any]:
    """Assignments on the subscription and its management-group ancestors, and what they allow / deny."""
    chain = (arch.get("subscription_parents") or {}).get(sub_id) or []
    groups = arch.get("management_groups") or {}
    scopes = {f"/subscriptions/{sub_id}": "this subscription"}
    scopes.update({_scope_of_group(g): (groups.get(g) or {}).get("displayName") or g for g in chain})
    assigned = [dict(p, where=scopes[p["scope"]]) for p in arch.get("policies") or [] if p.get("scope") in scopes]
    enforced = [p for p in assigned if p.get("enforced", True)]
    location_sets = [set(p["allowed_locations"]) for p in enforced if p.get("allowed_locations")]
    allowed_locations = set.intersection(*location_sets) if location_sets else None
    type_sets = [set(p["allowed_types"]) for p in enforced if p.get("allowed_types")]
    allowed_types = set.intersection(*type_sets) if type_sets else None
    denied_types = {t for p in enforced for t in p.get("denied_types") or []}
    return {"assignments": assigned, "allowed_locations": allowed_locations, "allowed_types": allowed_types,
            "denied_types": denied_types, "chain": [(g, (groups.get(g) or {}).get("displayName") or g)
                                                    for g in reversed(chain)]}


def render_subscription(data: Dict[str, Any], sub_id: str, tenant_link: Optional[str] = None,
                        sub_link: Optional[str] = None) -> str:
    subs = data.get("subscriptions") or []
    index = next((i for i, s in enumerate(subs) if s["id"] == sub_id.lower()), None)
    if index is None:
        raise KeyError(sub_id)
    sub = subs[index]
    arch = data.get("architecture") or {}
    types = data.get("types") or {}
    resources = [r for r in data.get("resources") or [] if r.get("s") == index]
    policy = effective_policy(arch, sub["id"])
    canvas = Canvas()

    # --- header -------------------------------------------------------------------------------------------------
    cost = sum(float(r.get("cost") or 0) for r in resources)
    currency = next((r.get("cur") for r in resources if r.get("cur")), sub.get("currency") or "")
    path = " › ".join(name for _, name in policy["chain"]) or "management-group placement not collected"
    canvas.add(canvas.icon(SUBSCRIPTION_ICON[0], 24, 16, 34)
               + f'<text x="68" y="36" font-size="20" font-weight="700">{_esc(sub.get("name"))}</text>'
               f'<text x="68" y="55" class="muted" font-size="12">{_esc(SUBSCRIPTION_ICON[1])} {_esc(sub["id"])} · '
               f'{len(resources)} resources · {cost:,.0f} {_esc(currency)} last 30 days · {_esc(_sub_env(sub.get("name") or ""))}'
               f'</text><text x="24" y="80" font-size="12">{_esc(TENANT_ICON[1])} path: {_esc(path)}</text>')
    if tenant_link:
        canvas.add(f'<a href="{_esc(tenant_link)}"><text x="24" y="98" font-size="12" fill="{AZURE}" class="title">'
                   f'← tenant architecture</text></a>')

    # --- policy panel (left) ------------------------------------------------------------------------------------
    left_x, top = 24, 116
    lines: List[Tuple[str, str, int]] = []   # (text, colour, weight)

    def add(text: str, colour: str = INK, weight: int = 400) -> None:
        # long lists (allowed locations, ...) wrap at their commas instead of being cut off
        while len(text) > 70 and ", " in text[:70]:
            cut = text.rindex(", ", 0, 70) + 1
            lines.append((text[:cut], colour, weight))
            text = "    " + text[cut:].lstrip()
        lines.append((text, colour, weight))

    in_use_types = Counter((r.get("type") or "").lower() for r in resources)
    in_use_locations = Counter((r.get("loc") or "").lower() for r in resources if r.get("loc") not in (None, "", "global"))
    add("What is allowed", ALLOW, 700)
    if policy["allowed_locations"] is not None:
        add("Locations: " + (", ".join(sorted(policy["allowed_locations"])) or "none"), ALLOW)
    else:
        add("Locations: any (no 'Allowed locations' policy)", MUTED)
    if policy["allowed_types"] is not None:
        add(f"Resource types: allow list of {len(policy['allowed_types'])}", ALLOW)
    else:
        add("Resource types: any, unless denied below", MUTED)
    add("What is not allowed", DENY, 700)
    if policy["denied_types"]:
        for t in sorted(policy["denied_types"])[:10]:
            add("✕ " + t, DENY)
        if len(policy["denied_types"]) > 10:
            add(f"  … and {len(policy['denied_types']) - 10} more types", DENY)
    else:
        add("No resource type is denied", MUTED)
    deny = [p for p in policy["assignments"] if _is_deny(p) and not (p.get("denied_types") or p.get("allowed_types")
                                                                     or p.get("allowed_locations"))]
    if deny:
        add(f"Deny policies ({len(deny)}):", DENY, 600)
        for p in deny[:8]:
            add("• " + _fit(p["name"], 44) + f"  [{_fit(p['where'], 22)}]", DENY)
    violations = []
    if policy["allowed_locations"] is not None:
        violations += [f"{n} resource(s) in {loc}" for loc, n in in_use_locations.items()
                       if loc not in policy["allowed_locations"]]
    violations += [f"{n} x {t}" for t, n in in_use_types.items() if t in policy["denied_types"]]
    if policy["allowed_types"] is not None:
        violations += [f"{n} x {t}" for t, n in in_use_types.items()
                       if t and t.count("/") == 1 and t not in policy["allowed_types"]]
    add("In use but not allowed", WARN, 700)
    if violations:
        for v in violations[:8]:
            add("! " + v, WARN)
    else:
        add("Nothing in use violates these policies", MUTED)
    others = [p for p in policy["assignments"] if p not in deny and not (p.get("denied_types") or p.get("allowed_types")
                                                                         or p.get("allowed_locations"))]
    defaults = [p for p in others if _defender_default(p)]
    others = [p for p in others if not _defender_default(p)]
    add(f"Other assignments ({len(others)}): audit, deploy-if-not-exists, initiatives", INK, 700)
    for p in others[:12]:
        add("• " + _fit(p["name"], 44) + f"  [{_fit(p['where'], 22)}]"
            + ("" if p.get("enforced", True) else " (not enforced)"), MUTED)
    if defaults:
        add(f"• Defender for Cloud default assignments ({len(defaults)}) - created by Defender itself", MUTED)
    if len(others) > 12:
        add(f"  … and {len(others) - 12} more", MUTED)
    panel_h = 52 + 16 * len(lines)
    canvas.add(f'<rect x="{left_x}" y="{top}" width="420" height="{panel_h}" rx="8" fill="#FBFCFE" stroke="{LINE}"/>'
               + canvas.icon(POLICY_ICON[0], left_x + 12, top + 12, 24)
               + f'<text x="{left_x + 44}" y="{top + 29}" font-size="14" font-weight="700">{_esc(POLICY_ICON[1])} - '
                 f'effective on this subscription</text>')
    for i, (text, colour, weight) in enumerate(lines):
        canvas.add(f'<text x="{left_x + 14}" y="{top + 58 + i * 16}" font-size="11.5" font-weight="{weight}" '
                   f'fill="{colour}">{_esc(_fit(text, 70))}</text>')

    # --- network (right, top) -----------------------------------------------------------------------------------
    right_x, right_w = 470, 3 * RG_W + 2 * 18
    y = top
    vnets = [v for v in arch.get("vnets") or [] if v.get("subscriptionId") == sub["id"]]
    sub_names = {s["id"]: s.get("name") for s in subs}
    all_vnets = {v["id"]: v for v in arch.get("vnets") or []}
    if vnets:
        canvas.add(f'<text x="{right_x}" y="{y + 14}" font-size="14" font-weight="700">Networking - virtual networks '
                   f'and peerings</text>')
        y += 26
        pos: Dict[str, Tuple[float, float, float, float]] = {}
        per_row, vw, vh = 4, 236, 70
        for i, v in enumerate(vnets):
            vx = right_x + (i % per_row) * (vw + 14)
            vy = y + (i // per_row) * (vh + 16)
            pos[v["id"]] = (vx, vy, vw, vh)
        y = y + math.ceil(len(vnets) / per_row) * (vh + 16) + 18
        remote_ids = []
        for v in vnets:
            for p in v.get("peerings") or []:
                if p["remote"] not in pos and p["remote"] not in remote_ids:
                    remote_ids.append(p["remote"])
        for i, rid in enumerate(remote_ids):
            vx = right_x + (i % per_row) * (vw + 14)
            vy = y + (i // per_row) * (vh + 16)
            pos[rid] = (vx, vy, vw, vh)
        if remote_ids:
            y = y + math.ceil(len(remote_ids) / per_row) * (vh + 16) + 10
        for v in vnets:   # peering lines under the boxes
            ax, ay, aw, ah = pos[v["id"]]
            for p in v.get("peerings") or []:
                bx, by, bw, bh = pos[p["remote"]]
                ok = (p.get("state") or "").lower() == "connected"
                canvas.add(f'<line x1="{ax + aw / 2:.1f}" y1="{ay + ah:.1f}" x2="{bx + bw / 2:.1f}" y2="{by:.1f}" '
                           f'stroke="{AZURE if ok else DENY}" stroke-width="1.6"'
                           + ("" if ok else ' stroke-dasharray="5,4"') + "/>")
        for vid, (vx, vy, vw_, vh_) in pos.items():
            v = all_vnets.get(vid)
            local = v is not None and v.get("subscriptionId") == sub["id"]
            parts = vid.split("/")
            name = (v or {}).get("name") or parts[-1]
            remote_sub = parts[2] if len(parts) > 2 else ""
            detail = (", ".join((v or {}).get("space") or [])[:40] + f" · {(v or {}).get('subnets', 0)} subnets"
                      if v else f"in {sub_names.get(remote_sub) or remote_sub[:8]}")
            if v and not local:
                detail = f"in {sub_names.get(v.get('subscriptionId')) or v.get('subscriptionId', '')[:8]}"
            peers = len((v or {}).get("peerings") or []) if local else 0
            canvas.add(f'<g class="node" data-label="{_esc(name.lower())}"'
                       + (f' data-subscription="{_esc(remote_sub)}"' if not local and remote_sub else "") + ">"
                       f'<rect class="box" x="{vx:.1f}" y="{vy:.1f}" width="{vw_}" height="{vh_}" rx="6" '
                       f'fill="{"#FFFFFF" if local else "#F5F7FA"}" stroke="{AZURE if local else LINE}" '
                       f'stroke-width="1.2"' + ("" if local else ' stroke-dasharray="4,3"') + "/>"
                       + canvas.icon("Virtual-Networks", vx + 10, vy + 10, 26)
                       + f'<text x="{vx + 44}" y="{vy + 24}" font-size="12" font-weight="600">{_esc(_fit(name, 24))}</text>'
                       f'<text x="{vx + 44}" y="{vy + 40}" class="muted small">{_esc(_fit(detail, 32))}</text>'
                       f'<text x="{vx + 44}" y="{vy + 56}" class="muted small">'
                       f'{"Virtual network" + (f" · {peers} peering(s)" if peers else "") if local else "Peered virtual network (other subscription)"}'
                       f'</text></g>')

    # --- resource groups (right) --------------------------------------------------------------------------------
    by_rg: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in resources:
        rtype = (r.get("type") or "").lower()
        if rtype.count("/") > 1 and rtype not in SHOWN_CHILD_TYPES:
            continue
        by_rg[r.get("rg") or "(none)"].append(r)
    canvas.add(f'<text x="{right_x}" y="{y + 14}" font-size="14" font-weight="700">Resource groups and services '
               f'({len(by_rg)})</text>')
    y += 26
    columns = [y, y, y]
    ordered = sorted(by_rg.items(), key=lambda kv: (-sum(float(r.get("cost") or 0) for r in kv[1]), -len(kv[1]),
                                                     kv[0].lower()))
    for rg, items in ordered:
        tiles: Dict[str, Dict[str, Any]] = {}
        for r in items:
            rtype = (r.get("type") or "").lower()
            mapped = icon_for(rtype, r.get("kind"))
            label = mapped[1] if mapped else (types.get(r.get("type") or "") or {}).get("label") or rtype.split("/")[-1]
            tile = tiles.setdefault(label, {"stem": mapped[0] if mapped else None, "label": label, "n": 0, "cost": 0.0,
                                            "names": [], "states": Counter(), "idle": []})
            tile["n"] += 1
            tile["cost"] += float(r.get("cost") or 0)
            state = vm_state(r)
            if state:
                tile["states"][state] += 1
                if state != "running":
                    tile["idle"].append(f"{r.get('name')} ({STATE_LABELS[state]})")
            if len(tile["names"]) < 3:
                tile["names"].append(r.get("name") or "")
        shown = sorted(tiles.values(), key=lambda t: (-t["cost"], -t["n"], t["label"]))
        more = len(shown) - MAX_TILES
        shown = shown[:MAX_TILES]
        rows = math.ceil(len(shown) / 2)
        h = 46 + rows * (TILE_H + 6) + (18 if more > 0 else 0) + 6
        col = columns.index(min(columns))
        bx, by = right_x + col * (RG_W + 18), columns[col]
        rg_cost = sum(t["cost"] for t in tiles.values())
        body = [f'<rect class="box" x="{bx}" y="{by:.1f}" width="{RG_W}" height="{h:.1f}" rx="8" fill="#FFFFFF" '
                f'stroke="{LINE}" stroke-width="1.2"/>',
                canvas.icon(RESOURCE_GROUP_ICON[0], bx + 10, by + 9, 22),
                f'<text x="{bx + 38}" y="{by + 21}" font-size="12.5" font-weight="600">{_esc(_fit(rg, 34))}</text>',
                f'<text x="{bx + 38}" y="{by + 36}" class="muted small">{_esc(RESOURCE_GROUP_ICON[1])} · {len(items)} '
                f'resources' + (f' · {rg_cost:,.0f} {_esc(currency)}/30 d' if rg_cost else "") + "</text>"]
        for i, t in enumerate(shown):
            tx = bx + 10 + (i % 2) * (TILE_W + 4)
            ty = by + 46 + (i // 2) * (TILE_H + 6)
            states = t["states"]
            stopped, deallocated = states.get("stopped", 0), states.get("deallocated", 0)
            fill, stroke = (("#FDE7E9", DENY) if stopped else ("#FFF4CE", "#C19C00") if deallocated
                            else ("#F7F9FB", None))
            if stopped or deallocated:
                status = " · ".join(x for x in (f"{deallocated} deallocated" if deallocated else "",
                                                 f"{stopped} stopped, billed" if stopped else "") if x)
                second = (f'<text x="{tx + 40}" y="{ty + 33}" font-size="10" font-weight="600" '
                          f'fill="{DENY if stopped else "#8A6D00"}">{t["n"]} · {_esc(status)}</text>')
            else:
                second = (f'<text x="{tx + 40}" y="{ty + 33}" class="muted small">{t["n"]}'
                          + (f" · {t['cost']:,.0f} {_esc(currency)}" if t["cost"] >= 1 else "") + "</text>")
            tip = f"{t['label']}: {', '.join(t['names'])}{' …' if t['n'] > 3 else ''}"
            if t["idle"]:
                tip += "\nNot running: " + ", ".join(t["idle"][:8]) + (" …" if len(t["idle"]) > 8 else "")
                tip += ("\nStopped (not deallocated) VMs are still billed for compute - deallocate them."
                        if stopped else "\nDeallocated VMs cost only their disks and IPs.")
            body.append(f'<g class="tile" data-label="{_esc((t["label"] + " " + " ".join(t["names"])).lower())}'
                        + (" deallocated" if deallocated else "") + (" stopped" if stopped else "") + '">'
                        f'<title>{_esc(tip)}</title>'
                        f'<rect x="{tx:.1f}" y="{ty:.1f}" width="{TILE_W}" height="{TILE_H}" rx="5" fill="{fill}"'
                        + (f' stroke="{stroke}" stroke-width="1.2"' if stroke else "") + "/>"
                        + canvas.icon(t["stem"], tx + 6, ty + 7, 28, t["label"])
                        + f'<text x="{tx + 40}" y="{ty + 18}" font-size="11">{_esc(_fit(t["label"], 21))}</text>'
                        + second + "</g>")
        if more > 0:
            body.append(f'<text x="{bx + 12}" y="{by + h - 10:.1f}" class="muted small">+ {more} more service '
                        f'type(s)</text>')
        canvas.add(f'<g class="node" data-label="{_esc(rg.lower())}">' + "".join(body) + "</g>")
        columns[col] = by + h + 16

    height_ = max(top + panel_h, max(columns)) + 40
    width = right_x + right_w + 24
    canvas.add(f'<text x="24" y="{height_ - 14}" class="muted small">Icons: Microsoft Azure architecture icons, used '
               f'to represent their services. Child resources (extensions, rules) are folded into their parent.</text>')
    return canvas.svg(width, height_, f"Subscription architecture - {sub.get('name')}")
