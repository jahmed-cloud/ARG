"""
The landing-zone diagram (Architecture > Landing zone): the tenant's management groups (left) mapped to the Azure
Landing Zones reference (right), with per group the ALZ archetype, subscriptions, policy assigned and how many of the
archetype's reference controls are in place; KPIs above, the connectivity landing zone and what stands out below.
One self-contained SVG, like the other architecture views.
"""

import textwrap
from typing import Any, Dict, List, Tuple

from scripts.subscription_analysis.diagram import INK, LINE, MUTED, Canvas, _esc, _fit
from scripts.subscription_analysis.landing_zone import ARCHETYPE_LABELS, IN_PLACE, MISSING, _ordered

ARCHETYPE_COLOURS = {
    "root": "#0078D4", "platform": "#8661C5", "connectivity": "#038387", "identity": "#5C2D91",
    "management": "#4F6BED", "security": "#A4262C", "landing_zones": "#107C10", "corp": "#0B6A0B",
    "online": "#498205", "local": "#8A8886", "sandbox": "#CA5010", "decommissioned": "#605E5C",
}
OK, PART, BAD, GREY = "#107C10", "#CA5010", "#C50F1F", "#8A8886"
ROW, WIDTH = 46, 1640
LEFT_X, LEFT_W = 24, 880
RIGHT_X, RIGHT_W = 1080, 536


def _kpi(c: Canvas, x: float, y: float, w: float, value: str, label: str, colour: str = INK) -> None:
    c.add(f'<rect x="{x}" y="{y}" width="{w}" height="58" rx="6" fill="#F6F8FA" stroke="{LINE}"/>'
          f'<text x="{x + 12}" y="{y + 26}" font-size="19" font-weight="600" fill="{colour}">{_esc(value)}</text>'
          f'<text x="{x + 12}" y="{y + 46}" font-size="11" class="muted">{_esc(label)}</text>')


def _badge(c: Canvas, x: float, y: float, text: str, colour: str, faded: bool = False) -> float:
    w = 8 + 6.2 * len(text)
    c.add(f'<rect x="{x}" y="{y}" width="{w:.0f}" height="17" rx="8.5" fill="{colour}" '
          f'fill-opacity="{0.12 if faded else 0.9}" stroke="{colour}"/>'
          f'<text x="{x + 4}" y="{y + 12.5}" font-size="10.5" fill="{colour if faded else "#FFFFFF"}">{_esc(text)}</text>')
    return w


def _bar(c: Canvas, x: float, y: float, w: float, counts: Dict[str, int]) -> None:
    total = sum(counts.values())
    if not total:
        return
    cursor = x
    for key, colour in ((IN_PLACE, OK), ("partly", PART), (MISSING, BAD)):
        part = w * counts.get(key, 0) / total
        if part:
            c.add(f'<rect x="{cursor:.1f}" y="{y}" width="{part:.1f}" height="8" fill="{colour}"/>')
            cursor += part
    c.add(f'<rect x="{x}" y="{y}" width="{w}" height="8" fill="none" stroke="{LINE}"/>')


def render_landing(result: Dict[str, Any]) -> str:
    c = Canvas()
    k = result["kpis"]
    c.add(f'<text x="24" y="34" font-size="20" font-weight="600">Landing zone - your management groups vs Azure '
          f'Landing Zones</text><text x="24" y="54" font-size="12" class="muted">ALZ reference library '
          f'{_esc(result["release"])} (github.com/Azure/Azure-Landing-Zones-Library, MIT). Archetypes by name, '
          f'position or the landing_zone_mapping setting.</text>')
    y = 70
    tiles: List[Tuple[str, str, str]] = []
    if result["policy_collected"]:
        tiles.append((f"{k['controls_in_place']} / {k['controls_partly']} / {k['controls_missing']}",
                      "ALZ controls in place / partly / missing", INK))
    else:
        tiles.append(("-", "policy detail: next estate refresh", MUTED))
    tiles += [(f"{k['archetypes_present']} of {k['archetypes']}", "ALZ archetypes present", INK),
              (str(k["outside_root"]), "subscriptions outside the root", BAD if k["outside_root"] else OK),
              (str(k["exemptions_without_expiry"]), "exemptions without expiry",
               PART if k["exemptions_without_expiry"] else OK),
              (f"{k['noncompliant']:,}", "non-compliant (group assignments)", PART if k["noncompliant"] else OK)]
    net = result["connectivity"]["summary"]
    tiles.append((f"{net['spokes_on_hub']} of {net['spokes']}", "VNets peered to a hub", INK))
    tile_w = (WIDTH - 48 - 10 * (len(tiles) - 1)) / len(tiles)
    for i, (value, label, colour) in enumerate(tiles):
        _kpi(c, 24 + i * (tile_w + 10), y, tile_w, value, label, colour)
    y += 84

    c.add(f'<text x="{LEFT_X}" y="{y}" font-size="14" font-weight="600">Your management groups</text>'
          f'<text x="{RIGHT_X}" y="{y}" font-size="14" font-weight="600">Azure Landing Zones reference</text>')
    top = y + 14
    rows = _ordered(result)
    positions: Dict[str, float] = {}
    for i, (name, g) in enumerate(rows):
        ry = top + i * ROW
        indent = LEFT_X + 22 * g["depth"]
        archetype = g["archetype"]
        colour = ARCHETYPE_COLOURS.get(archetype, GREY)
        outside = not g["inside"] and not g["tenant_root"]
        positions[name] = ry + ROW / 2 - 4
        c.add(f'<g class="node" data-label="{_esc(g["display"].lower())}">'
              f'<rect class="box" x="{indent}" y="{ry}" width="{LEFT_X + LEFT_W - indent}" height="{ROW - 6}" rx="5" '
              f'fill="{"#F3F2F1" if outside else "#FFFFFF"}" stroke="{colour if archetype else LINE}"/>'
              f'<rect x="{indent}" y="{ry}" width="5" height="{ROW - 6}" rx="2" fill="{colour}"/>'
              f'<text x="{indent + 12}" y="{ry + 16}" font-size="12.5" font-weight="600">'
              f'{_esc(_fit(g["display"], 34))}</text>')
        bx = indent + 12
        if archetype:
            label = ARCHETYPE_LABELS[archetype] + ("" if g["mapped_by"] in ("name", "position", "setting")
                                                   else " (inherited)")
            bx += _badge(c, bx, ry + 21, label, colour, faded=g["mapped_by"] == "inherited") + 6
        else:
            bx += _badge(c, bx, ry + 21, "tenant root" if g["tenant_root"] else
                         "outside root (canary)" if g["canary"] else "outside root",
                         GREY if g["tenant_root"] or g["canary"] else BAD, faded=True) + 6
        info = f'{g["subscriptions"]} subs' + (f' ({g["subtree_subscriptions"]} below)'
                                               if g["subtree_subscriptions"] != g["subscriptions"] else "")
        c.add(f'<text x="{bx}" y="{ry + 33}" font-size="10.5" class="muted">{_esc(info)}</text>')
        col = LEFT_X + 470
        assigned = f'{g.get("assignments", 0)} assigned here, {g.get("inherited", 0)} inherited'
        c.add(f'<text x="{col}" y="{ry + 16}" font-size="11">{_esc(assigned)}</text>')
        extras = []
        if g.get("noncompliant"):
            extras.append(f'{g["noncompliant"]:,} non-compliant')
        if g.get("exemptions"):
            extras.append(f'{g["exemptions"]} exemptions')
        if extras:
            c.add(f'<text x="{col}" y="{ry + 32}" font-size="10.5" fill="{PART}">{_esc(" · ".join(extras))}</text>')
        ctl = g.get("controls") or {}
        if ctl:
            bar_x = LEFT_X + LEFT_W - 190
            c.add(f'<text x="{bar_x}" y="{ry + 14}" font-size="10.5" class="muted">ALZ controls '
                  f'{ctl.get(IN_PLACE, 0)} / {ctl.get("partly", 0)} / {ctl.get(MISSING, 0)}</text>')
            _bar(c, bar_x, ry + 22, 176, ctl)
        c.add("</g>")
    left_bottom = top + len(rows) * ROW

    ref_rows = _reference_rows(result["reference"])
    ref_pos: Dict[str, float] = {}
    for i, (ref, depth) in enumerate(ref_rows):
        ry = top + i * ROW
        x = RIGHT_X + 22 * depth
        colour = ARCHETYPE_COLOURS.get(ref["archetype"], GREY)
        present = bool(ref["mapped"])
        ref_pos[ref["archetype"]] = ry + ROW / 2 - 4
        c.add(f'<g class="node" data-label="{_esc(ref["display"].lower())}">'
              f'<rect class="box" x="{x}" y="{ry}" width="{RIGHT_X + RIGHT_W - x}" height="{ROW - 6}" rx="5" '
              f'fill="{"#FFFFFF" if present else "#FBFBFB"}" stroke="{colour}" '
              f'stroke-dasharray="{"" if present else "4 3"}"/>'
              f'<rect x="{x}" y="{ry}" width="5" height="{ROW - 6}" rx="2" fill="{colour}"/>'
              f'<text x="{x + 12}" y="{ry + 16}" font-size="12.5" font-weight="600">{_esc(ref["display"])}</text>'
              f'<text x="{x + 12}" y="{ry + 32}" font-size="10.5" fill="{MUTED if present else BAD}">'
              f'{_esc(_fit(", ".join(ref["mapped"]) if present else "not present", 52))}</text>'
              f'<text x="{RIGHT_X + RIGHT_W - 10}" y="{ry + 16}" font-size="10.5" text-anchor="end" class="muted">'
              f'{ref["controls"]} reference assignments</text></g>')
    for name, g in rows:
        if g["archetype"] and g["mapped_by"] in ("name", "position", "setting") and g["archetype"] in ref_pos:
            y1, y2 = positions[name] + 4, ref_pos[g["archetype"]] + 4
            x1, x2 = LEFT_X + LEFT_W, RIGHT_X - 4
            colour = ARCHETYPE_COLOURS.get(g["archetype"], GREY)
            c.add(f'<path d="M{x1},{y1:.0f} C{x1 + 90},{y1:.0f} {x2 - 90},{y2:.0f} {x2},{y2:.0f}" fill="none" '
                  f'stroke="{colour}" stroke-width="1.6" stroke-opacity="0.7"/>'
                  f'<circle cx="{x2}" cy="{y2:.0f}" r="3" fill="{colour}"/>')
    y = max(left_bottom, top + len(ref_rows) * ROW) + 26

    y = _connectivity(c, result["connectivity"], y)
    if result["observations"]:
        c.add(f'<text x="24" y="{y}" font-size="14" font-weight="600">What stands out</text>')
        y += 8
        for note in result["observations"]:
            lines = textwrap.wrap(note, 210)
            for j, line in enumerate(lines):
                y += 16
                c.add(f'<text x="{24 if j == 0 else 36}" y="{y}" font-size="11.5">{"• " if j == 0 else ""}'
                      f'{_esc(line)}</text>')
            y += 4
    _legend(c, y + 24)
    return c.svg(WIDTH, y + 60, "Landing zone")


def _reference_rows(reference: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], int]]:
    children: Dict[Any, List[Dict[str, Any]]] = {}
    for r in reference:
        children.setdefault(r["parent"], []).append(r)
    out: List[Tuple[Dict[str, Any], int]] = []

    def walk(parent: Any, depth: int) -> None:
        for r in children.get(parent, []):
            out.append((r, depth))
            walk(r["id"], depth + 1)
    walk(None, 0)
    return out


def _connectivity(c: Canvas, net: Dict[str, Any], y: float) -> float:
    s = net["summary"]
    c.add(f'<text x="24" y="{y}" font-size="14" font-weight="600">Connectivity landing zone</text>'
          f'<text x="230" y="{y}" font-size="11.5" class="muted">{s["spokes"]} VNets: {s["spokes_on_hub"]} peered '
          f'to a hub, {s["isolated"]} not · {s["forced_tunnel"]} route Internet traffic through the hub '
          f'({s.get("bgp", 0)} by BGP from Route Server / gateway, not visible in route tables) · '
          f'{s["dns_gaps"]} with private endpoints that cannot resolve · {s["ddos"]} with DDoS protection</text>')
    y += 14
    if not net["hubs"]:
        c.add(f'<text x="24" y="{y + 16}" font-size="11.5" class="muted">No hub VNet found.</text>')
        return y + 44
    w, gap = 300, 14
    per_row = max(1, int((WIDTH - 48 + gap) // (w + gap)))
    for i, h in enumerate(net["hubs"]):
        x = 24 + (i % per_row) * (w + gap)
        hy = y + (i // per_row) * 104
        firewall = ("Azure Firewall" if h["firewall"] else f"NVA firewall ({h['nva']})" if h["nva"] else "Firewall")
        checks = [(firewall, h["firewall"] > 0 or h["nva"] > 0),
                  ("Firewall policy" if h["firewall"] else "Policy n/a (NVA)", h["firewall_policy"]),
                  ("Route Server" if h.get("route_server") and not h["gateways"] else "Gateway",
                   bool(h["gateways"]) or bool(h.get("route_server"))),
                  ("Bastion", h["bastion"]), ("DNS resolver", h["dns_resolver"]), ("DDoS", h["ddos"])]
        c.add(f'<g class="node" data-label="{_esc(h["name"].lower())}"><rect class="box" x="{x}" y="{hy}" width="{w}" '
              f'height="92" rx="6" fill="#FFFFFF" stroke="{ARCHETYPE_COLOURS["connectivity"]}"/>'
              f'<text x="{x + 12}" y="{hy + 18}" font-size="12.5" font-weight="600">{_esc(_fit(h["name"], 34))}</text>'
              f'<text x="{x + 12}" y="{hy + 33}" font-size="10.5" class="muted">'
              f'{_esc(_fit(h["subscription"], 30))} · {_esc(h["location"])} · {h["spokes"]} peerings</text>')
        for j, (label, ok) in enumerate(checks):
            cx = x + 12 + (j % 3) * 96
            cy = hy + 54 + (j // 3) * 20
            colour = GREY if ok is None else OK if ok else BAD
            c.add(f'<circle cx="{cx + 4}" cy="{cy - 4}" r="4" fill="{colour}"/>'
                  f'<text x="{cx + 13}" y="{cy}" font-size="10.5">{_esc(_fit(label, 17))}</text>')
        c.add("</g>")
    rows = (len(net["hubs"]) + per_row - 1) // per_row
    return y + rows * 104 + 20


def _legend(c: Canvas, y: float) -> None:
    x = 24
    c.add(f'<text x="{x}" y="{y}" font-size="11" class="muted">ALZ controls:</text>')
    x += 80
    for label, colour in (("in place", OK), ("partly / audit only / similar", PART), ("missing", BAD)):
        c.add(f'<rect x="{x}" y="{y - 9}" width="12" height="10" fill="{colour}"/>'
              f'<text x="{x + 16}" y="{y}" font-size="11">{_esc(label)}</text>')
        x += 30 + 6.4 * len(label)
    c.add(f'<text x="{x + 20}" y="{y}" font-size="11" class="muted">Dashed reference box: no management group of '
          f'yours maps to it. Details: the table below the diagram.</text>')
