"""
Network diagrams from architecture.network (network.py), drawn with diagram.py's canvas and the official icons.

- render_network_tenant(): every VNet of the tenant as hub and spoke - hubs (gateway / firewall subnets or 3+
  peerings) with their spokes, peerings without a hub, isolated VNets - with address spaces, peering state and
  address-space overlaps between VNets that are connected (they break routing) or anywhere (they block peering
  later); on-premises connectivity and route next hops.
- render_network(): one subscription - entry points (internet, on-premises), each VNet with its subnets and what
  runs in them (VMs coloured by power state, private endpoints, gateways, firewalls, Bastion, App Gateway, AKS,
  Container Apps, flexible databases) with NSG / route / NAT / service-endpoint / delegation badges, and every PaaS
  service and app grouped by exposure (open to all networks, restricted, public access off, private endpoint);
  lines join a private endpoint to its target and an app to its VNet-integration subnet.

Both return self-contained SVG; nodes carry data-label (search) and data-subscription (drill-down).
"""

import ipaddress
import math
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from scripts.subscription_analysis.diagram import (
    ALLOW, AZURE, DENY, ENV_COLOURS, INK, LINE, MUTED, WARN, Canvas, _esc, _fit, _sub_env, vm_state,
)
from scripts.subscription_analysis.diagram_icons import ONPREM_ICON, SUBNET_ICON, SUBSCRIPTION_ICON, icon_for
from scripts.subscription_analysis.network import (
    APP_PUBLIC, APP_TYPES, CLOSED, EXPOSURE_LABELS, OPEN, PRIVATE, RESTRICTED, UNVERIFIED, exposure,
)

LANE_COLOURS = {OPEN: DENY, UNVERIFIED: "#8A8886", RESTRICTED: "#C19C00", CLOSED: "#038387", PRIVATE: ALLOW,
                APP_PUBLIC: AZURE}
STATE_FILL = {"running": "#FFFFFF", "deallocated": "#FFF4CE", "stopped": "#FDE7E9", None: "#FFFFFF"}
GATEWAY_SUBNETS = ("gatewaysubnet", "azurefirewallsubnet", "azurefirewallmanagementsubnet", "routeserversubnet")


def _icon(rtype: str) -> Tuple[Optional[str], str]:
    mapped = icon_for(rtype)
    return (mapped[0], mapped[1]) if mapped else (None, rtype.split("/")[-1])


def _sub_of(resource_id: str) -> str:
    parts = (resource_id or "").split("/")
    return parts[2].lower() if len(parts) > 2 else ""


def _vnet_of(subnet_id: str) -> str:
    return (subnet_id or "").lower().split("/subnets/")[0]


def _name_of(resource_id: str) -> str:
    return (resource_id or "").rstrip("/").split("/")[-1]


def _networks(prefixes: List[str]) -> List[Any]:
    out = []
    for p in prefixes or []:
        try:
            out.append(ipaddress.ip_network(p.strip(), strict=False))
        except ValueError:
            continue
    return out


def overlaps(vnets: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """{vnet id: [ids of VNets whose address space overlaps it]}."""
    nets = [(v["id"], _networks(v.get("space") or [])) for v in vnets]
    out: Dict[str, List[str]] = defaultdict(list)
    for i, (a, an) in enumerate(nets):
        for b, bn in nets[i + 1:]:
            if any(x.version == y.version and x.overlaps(y) for x in an for y in bn):
                out[a].append(b)
                out[b].append(a)
    return out


def _peering_graph(vnets: List[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """{vnet: {remote: peering}} in both directions (a one-sided peering is still drawn, as not connected)."""
    graph: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for v in vnets:
        for p in v.get("peerings") or []:
            graph[v["id"]][p["remote"]] = p
            graph[p["remote"]].setdefault(v["id"], {**p, "remote": v["id"], "reverse": True})
    return graph


def _is_hub(v: Dict[str, Any], degree: int) -> bool:
    names = {(s.get("name") or "").lower() for s in v.get("subnet_list") or []}
    return (bool(names & set(GATEWAY_SUBNETS)) and degree >= 1) or degree >= 3


def _next_hops(route_tables: List[Dict[str, Any]], vnets: List[Dict[str, Any]]) -> Dict[str, Counter]:
    """{vnet id: Counter(next-hop IP -> subnets routed to it)} for 0.0.0.0/0 routes to a virtual appliance."""
    out: Dict[str, Counter] = defaultdict(Counter)
    nets = [(v["id"], _networks(v.get("space") or [])) for v in vnets]
    for r in route_tables or []:
        hop = r.get("default_route") or ""
        if not hop.startswith("VirtualAppliance "):
            continue
        ip = hop.split(" ", 1)[1]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for vid, ns in nets:
            if any(addr.version == n.version and addr in n for n in ns):
                out[vid][ip] += len(r.get("subnets") or [])
                break
    return out


# ---------------------------------------------------------------------------
# Tenant network view
# ---------------------------------------------------------------------------

HUB_W, SPOKE_W, SPOKE_H, SPOKE_COLS, GAP = 330, 262, 54, 3, 10


def render_network_tenant(data: Dict[str, Any], link: Optional[str] = None) -> str:
    arch = data.get("architecture") or {}
    net = arch.get("network") or {}
    vnets = arch.get("vnets") or []
    subs = {s["id"]: s.get("name") or s["id"] for s in data.get("subscriptions") or []}
    by_id = {v["id"]: v for v in vnets}
    graph = _peering_graph(vnets)
    overlap = overlaps(vnets)
    edge = net.get("edge") or []
    gateways = defaultdict(list)
    for e in edge:
        for sn in e.get("subnets") or []:
            gateways[_vnet_of(sn)].append(e)
    hops = _next_hops(net.get("route_tables") or [], vnets)
    hubs = sorted([v for v in vnets if _is_hub(v, len(graph.get(v["id"], {})))],
                  key=lambda v: (-len(graph.get(v["id"], {})), v.get("name") or ""))
    hub_ids = {h["id"] for h in hubs}
    spokes: Dict[str, List[str]] = defaultdict(list)
    placed = set(hub_ids)
    for v in vnets:
        if v["id"] in hub_ids:
            continue
        peers = [r for r in graph.get(v["id"], {}) if r in hub_ids]
        if peers:
            via_gw = [r for r in peers if graph[v["id"]][r].get("remote_gateways")]
            spokes[(via_gw or peers)[0]].append(v["id"])
            placed.add(v["id"])
    # spokes of a hub that are not in the visible estate (other tenants / no access)
    for h in hubs:
        for r in graph.get(h["id"], {}):
            if r not in by_id and r not in spokes[h["id"]]:
                spokes[h["id"]].append(r)
    loose = [v for v in vnets if v["id"] not in placed and graph.get(v["id"])]
    isolated = [v for v in vnets if v["id"] not in placed and not graph.get(v["id"])]
    reused = sum(1 for v in isolated if overlap.get(v["id"]))

    canvas = Canvas()
    y = 120.0

    def spoke_card(vid: str, x: float, y: float, hub: Optional[str]) -> str:
        v = by_id.get(vid)
        sub = (v or {}).get("subscriptionId") or _sub_of(vid)
        peering = graph.get(vid, {}).get(hub) if hub else None   # the spoke's own peering to the hub
        ok = peering is None or (peering.get("state") or "").lower() == "connected"
        clash = [o for o in overlap.get(vid, []) if hub and (o == hub or o in spokes.get(hub, []))]
        name = (v or {}).get("name") or _name_of(vid)
        space = ", ".join((v or {}).get("space") or []) or "deleted, or in a subscription not scanned"
        stroke = DENY if (not ok or clash) else (AZURE if v else LINE)
        tip = [f"{name} - {subs.get(sub, sub)}", f"Address space: {space}"]
        if v:
            tip.append(f"{len(v.get('subnet_list') or [])} subnet(s), {v.get('location')}")
        if peering is not None:
            tip.append(f"Peering: {peering.get('state') or 'unknown'}"
                       + (", uses the hub's gateway" if peering.get("remote_gateways") else ""))
            if not ok:
                tip.append("Not connected: the remote VNet was deleted or its side of the peering is missing - "
                           "remove or re-create the peering.")
        if clash:
            tip.append("Address space overlaps: " + ", ".join(_name_of(o) for o in clash))
        hop_here = hops.get(vid, Counter())
        if hop_here:
            tip.append("Hosts the default-route next hop " + ", ".join(f"{ip} ({n} subnet(s))"
                                                                      for ip, n in hop_here.most_common(3)))
            space += f" · next hop for {sum(hop_here.values())} subnet(s)"
        attrs = f' data-subscription="{_esc(sub)}"' if sub in subs else ""
        node = (f'<g class="node"{attrs} data-label="{_esc((name + " " + subs.get(sub, "") + " " + space).lower())}">'
                f'<title>{_esc(chr(10).join(tip))}</title>'
                f'<rect class="box" x="{x:.1f}" y="{y:.1f}" width="{SPOKE_W}" height="{SPOKE_H}" rx="6" '
                f'fill="{"#FFFFFF" if v else "#F5F7FA"}" stroke="{stroke}" stroke-width="1.2"'
                + ("" if ok else ' stroke-dasharray="5,3"') + "/>"
                f'<rect x="{x:.1f}" y="{y:.1f}" width="4" height="{SPOKE_H}" rx="2" '
                f'fill="{ENV_COLOURS[_sub_env(subs.get(sub, ""))]}"/>'
                + canvas.icon("Virtual-Networks", x + 10, y + 9, 22)
                + f'<text x="{x + 38:.1f}" y="{y + 20:.1f}" font-size="11.5" font-weight="600">{_esc(_fit(name, 30))}'
                  f'</text><text x="{x + 38:.1f}" y="{y + 34:.1f}" class="muted small">'
                  f'{_esc(_fit(subs.get(sub, "not in the estate"), 34))}</text>'
                  f'<text x="{x + 38:.1f}" y="{y + 47:.1f}" font-size="10" '
                  f'fill="{DENY if clash else MUTED}">{_esc(_fit(space + (" · overlaps!" if clash else ""), 40))}'
                  f'</text></g>')
        return f'<a href="{_esc(link.format(id=sub))}">{node}</a>' if link and attrs else node

    def hub_card(h: Dict[str, Any], x: float, y: float) -> Tuple[str, float]:
        sub = h.get("subscriptionId") or ""
        kit = Counter(e["type"] for e in gateways.get(h["id"], []))
        lines = [", ".join(h.get("space") or []) or "-", f"{subs.get(sub, sub)} · {h.get('location')}"]
        icons = []
        for t, n in kit.most_common(6):
            stem, label = _icon(t)
            icons.append((stem, f"{n} {label}" if n > 1 else label))
        subnet_names = [s.get("name") for s in h.get("subnet_list") or []]
        if any((n or "").lower() == "azurefirewallsubnet" for n in subnet_names) and \
                "microsoft.network/azurefirewalls" not in kit:
            icons.append(("Firewalls", "AzureFirewallSubnet (firewall in another subscription?)"))
        dns = h.get("dns") or []
        if dns:
            lines.append("Custom DNS: " + ", ".join(dns[:3]))
        for ip, n in hops.get(h["id"], Counter()).most_common(2):
            lines.append(f"Firewall / NVA {ip}: default route of {n} subnet(s)")
        hh = 64 + 14 * len(lines) + (math.ceil(len(icons) / 2) * 24 if icons else 0)
        body = [f'<rect class="box" x="{x}" y="{y:.1f}" width="{HUB_W}" height="{hh}" rx="8" fill="#E3EEFA" '
                f'stroke="{AZURE}" stroke-width="1.6"/>',
                canvas.icon("Virtual-Networks", x + 12, y + 12, 30),
                f'<text x="{x + 50}" y="{y + 26:.1f}" font-size="13.5" font-weight="700">{_esc(_fit(h.get("name"), 30))}'
                f'</text><text x="{x + 50}" y="{y + 42:.1f}" class="muted small">Hub virtual network · '
                f'{len(spokes.get(h["id"], []))} spoke(s)</text>']
        for i, text in enumerate(lines):
            body.append(f'<text x="{x + 14}" y="{y + 62 + i * 14:.1f}" font-size="10.5">{_esc(_fit(text, 54))}</text>')
        iy = y + 62 + len(lines) * 14
        for i, (stem, label) in enumerate(icons):
            ix, iy2 = x + 14 + (i % 2) * 156, iy + (i // 2) * 24
            body.append(canvas.icon(stem, ix, iy2 - 2, 18, label)
                        + f'<text x="{ix + 22}" y="{iy2 + 11:.1f}" class="small">{_esc(_fit(label, 24))}</text>')
        attrs = f' data-subscription="{_esc(sub)}"' if sub in subs else ""
        node = (f'<g class="node"{attrs} data-label="{_esc((h.get("name") or "") .lower() + " hub")}">'
                + "".join(body) + "</g>")
        return (f'<a href="{_esc(link.format(id=sub))}">{node}</a>' if link and attrs else node), hh

    def section(title: str, note: str) -> None:
        nonlocal y
        canvas.add(f'<text x="24" y="{y + 16:.1f}" font-size="14.5" font-weight="700">{_esc(title)}</text>'
                   f'<text x="24" y="{y + 32:.1f}" class="muted small">{_esc(note)}</text>')
        y += 46

    if hubs:
        section(f"Hub and spoke ({len(hubs)} hub(s))", "Hubs: VNets with a gateway / firewall subnet or 3+ peerings. "
                "Dashed red: peering not connected. Red text: address space overlaps another VNet of the same hub.")
    for h in hubs:
        ids = spokes.get(h["id"], [])
        card, hh = hub_card(h, 24, y)
        rows = math.ceil(len(ids) / SPOKE_COLS) if ids else 0
        block_h = max(hh, rows * (SPOKE_H + GAP))
        sx0 = 24 + HUB_W + 60
        for i, vid in enumerate(ids):
            sx = sx0 + (i % SPOKE_COLS) * (SPOKE_W + GAP)
            sy = y + (i // SPOKE_COLS) * (SPOKE_H + GAP)
            if i % SPOKE_COLS == 0:   # one connector per row
                canvas.add(f'<path d="M{24 + HUB_W},{y + 24:.1f} H{sx0 - 30} V{sy + SPOKE_H / 2:.1f} H{sx0}" '
                           f'fill="none" stroke="{AZURE}" stroke-width="1.3" opacity="0.7"/>')
            canvas.add(spoke_card(vid, sx, sy, h["id"]))
        canvas.add(card)
        y += block_h + 28

    if loose:
        section(f"Peered without a hub ({len(loose)})", "VNets peered directly with each other (mesh) - "
                "each pair needs its own peering and routes do not transit.")
        for i, v in enumerate(loose):
            canvas.add(spoke_card(v["id"], 24 + (i % 5) * (SPOKE_W + GAP), y + (i // 5) * (SPOKE_H + GAP), None))
        y += math.ceil(len(loose) / 5) * (SPOKE_H + GAP) + 24

    if isolated:
        section(f"Isolated VNets ({len(isolated)})", "No peering: reachable only through their own public "
                "endpoints or private endpoints - fine for sandboxes, a gap for workloads that should use the hub. "
                + (f"{reused} reuse an address range used elsewhere (e.g. the 10.0.0.0/16 default) and cannot be "
                   f"peered without re-addressing." if reused else ""))
        for i, v in enumerate(sorted(isolated, key=lambda v: (subs.get(v.get("subscriptionId"), ""), v.get("name")))):
            canvas.add(spoke_card(v["id"], 24 + (i % 5) * (SPOKE_W + GAP), y + (i // 5) * (SPOKE_H + GAP), None))
        y += math.ceil(len(isolated) / 5) * (SPOKE_H + GAP) + 24

    # header and KPIs: an overlap matters between VNets that are connected (same hub, or peered)
    connected_overlaps = set()
    for hub, ids in spokes.items():
        group = [hub] + list(ids)
        for a in group:
            for b in overlap.get(a, []):
                if b in group:
                    connected_overlaps.add(tuple(sorted((a, b))))
    for a, peers in graph.items():
        for b in peers:
            if b in overlap.get(a, []):
                connected_overlaps.add(tuple(sorted((a, b))))

    nva = Counter(r["default_route"] for r in net.get("route_tables") or []
                  if (r.get("default_route") or "").startswith("VirtualAppliance"))
    gw = sum(1 for e in edge if e["type"] in ("microsoft.network/virtualnetworkgateways",
                                               "microsoft.network/expressroutecircuits"))
    kpis = [(len(vnets), "VNets"), (len(hubs), "hubs"), (sum(len(s) for s in spokes.values()), "spokes"),
            (len(isolated), "isolated"), (len(connected_overlaps), "overlaps between connected VNets"),
            (gw, "ER / VPN gateways & circuits"),
            (sum(nva.values()), "route tables via NVA / firewall"),
            (len(net.get("private_endpoints") or []), "private endpoints"),
            (len(net.get("public_ips") or []), "public IPs")]
    canvas.add('<text x="24" y="34" font-size="20" font-weight="700">Tenant network topology</text>'
               f'<text x="24" y="54" class="muted" font-size="12">Virtual networks, peerings and hubs across '
               f'{len(subs)} subscriptions · click a VNet to open its subscription\'s network view</text>')
    canvas.add(_kpi_strip(kpis, 24, 66, warn={"overlaps between connected VNets"}))
    width = max(24 + HUB_W + 60 + SPOKE_COLS * (SPOKE_W + GAP), 24 + 5 * (SPOKE_W + GAP)) + 24
    if not vnets:
        canvas.add('<text x="24" y="140" font-size="12" fill="#CA5010">No VNets in the inventory - refresh the '
                   'estate inventory.</text>')
    return canvas.svg(width, max(y + 20, 260), "Tenant network topology - hubs, spokes and peerings")


def _kpi_strip(kpis: List[Tuple[int, str]], x: float, y: float, warn: set = frozenset()) -> str:
    out, cx = [], x
    for n, label in kpis:
        w = 22 + len(label) * 5.8 + len(f"{n:,}") * 8
        colour = DENY if label in warn and n else INK
        out.append(f'<rect x="{cx:.1f}" y="{y}" width="{w:.1f}" height="28" rx="14" fill="#F3F6FA" stroke="{LINE}"/>'
                   f'<text x="{cx + 12:.1f}" y="{y + 19}" font-size="12"><tspan font-weight="700" fill="{colour}">'
                   f'{n:,}</tspan><tspan class="muted"> {_esc(label)}</tspan></text>')
        cx += w + 8
    return "".join(out)


# ---------------------------------------------------------------------------
# Subscription network view
# ---------------------------------------------------------------------------

LEFT_X, LEFT_W, MID_X, MID_W, RIGHT_X = 24, 196, 250, 660, 950
CHIP_W, CHIP_H, TILE_W, TILE_H, MAX_LANE = 132, 24, 292, 34, 60


def render_network(data: Dict[str, Any], sub_id: str, tenant_link: Optional[str] = None) -> str:
    subs = data.get("subscriptions") or []
    sub = next((s for s in subs if s["id"] == sub_id.lower()), None)
    if sub is None:
        raise KeyError(sub_id)
    sid = sub["id"]
    arch = data.get("architecture") or {}
    net = arch.get("network") or {}
    sub_names = {s["id"]: s.get("name") for s in subs}
    vnets = [v for v in arch.get("vnets") or [] if v.get("subscriptionId") == sid]
    all_vnets = {v["id"]: v for v in arch.get("vnets") or []}
    resources = {(r.get("id") or "").lower(): r for r in data.get("resources") or []}
    canvas = Canvas()

    # --- what sits in which subnet --------------------------------------------------------------------------------
    in_subnet: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    vm_count = Counter()
    for vm in net.get("vms") or []:
        r = resources.get(vm["id"]) or {"id": vm["id"], "name": _name_of(vm["id"]),
                                         "type": "microsoft.compute/virtualmachines"}
        state = vm_state(r)
        if vm.get("subscriptionId") == sid:
            vm_count[state or "unknown"] += 1
        for sn in vm.get("subnets") or []:
            in_subnet[sn].append({"kind": "vm", "id": vm["id"], "name": r.get("name") or _name_of(vm["id"]),
                                  "state": state, "public_ip": vm.get("public_ip")})
    for pe in net.get("private_endpoints") or []:
        if pe.get("subnet"):
            for t in pe.get("targets") or [{"id": "", "group": ""}]:
                in_subnet[pe["subnet"]].append({"kind": "pe", "id": pe["id"], "name": _name_of(t["id"]) or pe["name"],
                                                "target": t["id"], "group": t.get("group"),
                                                "target_sub": _sub_of(t["id"])})
    for e in net.get("edge") or []:
        for sn in e.get("subnets") or []:
            in_subnet[sn].append({"kind": "edge", "id": e["id"], "name": e.get("name"), "type": e["type"],
                                  "sku": e.get("sku")})
    routes = {sn: r for r in net.get("route_tables") or [] for sn in r.get("subnets") or []}
    paas = [p for p in net.get("paas") or [] if p.get("subscriptionId") == sid]
    integrated: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in paas:
        if p.get("integration"):
            integrated[p["integration"]].append(p)

    # --- middle: VNets and subnets --------------------------------------------------------------------------------
    y_mid = 165.0
    subnet_rows: Dict[str, Tuple[float, float]] = {}       # subnet id -> (y centre, right edge x)
    chip_pos: Dict[str, Tuple[float, float]] = {}          # chip key -> (x right, y centre)
    canvas.add(f'<text x="{MID_X}" y="{y_mid - 14:.1f}" font-size="14" font-weight="700">Virtual networks and '
               f'subnets ({len(vnets)})</text>')
    if not vnets:
        canvas.add(f'<text x="{MID_X}" y="{y_mid + 10:.1f}" class="muted" font-size="12">No VNet in this '
                   f'subscription - its services are reached through public or private endpoints only.</text>')
        y_mid += 30
    for v in vnets:
        y_mid = _draw_vnet(canvas, v, y_mid, in_subnet, routes, integrated, all_vnets, sub_names, subnet_rows,
                           chip_pos) + 18

    # --- right: PaaS and apps by exposure --------------------------------------------------------------------------
    y_right = 165.0
    tile_pos: Dict[str, Tuple[float, float]] = {}
    lanes: List[Tuple[str, str, List[Dict[str, Any]]]] = []
    data_items = [p for p in paas if p["type"] not in APP_TYPES]
    app_items = [p for p in paas if p["type"] in APP_TYPES]
    for cls in (OPEN, UNVERIFIED, RESTRICTED, CLOSED, PRIVATE):
        items = [p for p in data_items if exposure(p) == cls]
        if items:
            lanes.append((cls, f"Data & platform services - {EXPOSURE_LABELS[cls].lower()}", items))
    for cls in (APP_PUBLIC, RESTRICTED, PRIVATE, CLOSED):
        items = [p for p in app_items if exposure(p) == cls]
        if items:
            label = {APP_PUBLIC: "public endpoint", RESTRICTED: "access restricted",
                     PRIVATE: "private endpoint only", CLOSED: "public access off"}[cls]
            lanes.append((cls if cls != APP_PUBLIC else APP_PUBLIC, f"Apps (App Service, Functions, Logic Apps) - "
                                                                    f"{label}", items))
    canvas.add(f'<text x="{RIGHT_X}" y="{y_right - 14:.1f}" font-size="14" font-weight="700">PaaS services and apps '
               f'by exposure ({len(paas)})</text>')
    lane_heads: Dict[str, Tuple[float, float]] = {}
    for cls, title, items in lanes:
        y_right, head = _draw_lane(canvas, cls, title, items, y_right, tile_pos)
        lane_heads.setdefault(cls, head)
        y_right += 14

    # --- left: entry points ----------------------------------------------------------------------------------------
    y_left = 165.0
    canvas.add(f'<text x="{LEFT_X}" y="{y_left - 14:.1f}" font-size="14" font-weight="700">Entry points</text>')
    inet_y = y_left
    canvas.add(f'<g class="node" data-label="internet"><rect class="box" x="{LEFT_X}" y="{inet_y}" width="{LEFT_W}" '
               f'height="54" rx="27" fill="#FDF3F4" stroke="{DENY}" stroke-width="1.2"/>'
               f'<circle cx="{LEFT_X + 28}" cy="{inet_y + 27}" r="13" fill="none" stroke="{DENY}" stroke-width="1.4"/>'
               f'<ellipse cx="{LEFT_X + 28}" cy="{inet_y + 27}" rx="6" ry="13" fill="none" stroke="{DENY}" '
               f'stroke-width="1"/><line x1="{LEFT_X + 15}" y1="{inet_y + 27}" x2="{LEFT_X + 41}" y2="{inet_y + 27}" '
               f'stroke="{DENY}"/><text x="{LEFT_X + 50}" y="{inet_y + 24}" font-size="13" font-weight="700">Internet'
               f'</text><text x="{LEFT_X + 50}" y="{inet_y + 39}" class="muted small">public endpoints and IPs</text>'
               f'</g>')
    y_left += 70
    pips = [p for p in net.get("public_ips") or [] if p.get("subscriptionId") == sid]
    owners = Counter(_owner_kind(p.get("owner")) for p in pips)
    lines = [f"{len(pips)} public IP(s)"] + [f"  {n} {k}" for k, n in owners.most_common(6)]
    onprem = [e for e in net.get("edge") or [] if e.get("subscriptionId") == sid and e["type"] in (
        "microsoft.network/virtualnetworkgateways", "microsoft.network/expressroutecircuits")]
    via_hub = [v for v in vnets for p in v.get("peerings") or [] if p.get("remote_gateways")]
    if onprem or via_hub:
        canvas.add(f'<g class="node" data-label="on-premises"><rect class="box" x="{LEFT_X}" y="{y_left}" '
                   f'width="{LEFT_W}" height="58" rx="8" fill="#F3F0FA" stroke="#5C2E91" stroke-width="1.2"/>'
                   + canvas.icon(ONPREM_ICON[0], LEFT_X + 10, y_left + 13, 30)
                   + f'<text x="{LEFT_X + 48}" y="{y_left + 25}" font-size="12.5" font-weight="700">On-premises</text>'
                     f'<text x="{LEFT_X + 48}" y="{y_left + 41}" class="muted small">'
                     f'{_esc("gateway in this subscription" if onprem else "through the hub gateway")}</text></g>')
        y_left += 74
    canvas.add(f'<rect x="{LEFT_X}" y="{y_left}" width="{LEFT_W}" height="{24 + 15 * len(lines)}" rx="8" '
               f'fill="#FFFFFF" stroke="{LINE}"/>'
               + "".join(f'<text x="{LEFT_X + 12}" y="{y_left + 20 + i * 15}" font-size="11"'
                         + (' font-weight="600"' if i == 0 else ' class="muted"') + f'>{_esc(t)}</text>'
                         for i, t in enumerate(lines)))
    y_left += 34 + 15 * len(lines)
    if vm_count:
        canvas.add(f'<text x="{LEFT_X}" y="{y_left + 4}" font-size="12" font-weight="700">Virtual machines</text>')
        y_left += 12
        for state, n in sorted(vm_count.items(), key=lambda kv: ["running", "deallocated", "stopped",
                                                                   "unknown"].index(kv[0])):
            label = {"running": "running", "deallocated": "deallocated - disks still billed",
                     "stopped": "stopped, NOT deallocated - compute still billed", "unknown": "state unknown"}[state]
            canvas.add(f'<rect x="{LEFT_X}" y="{y_left}" width="14" height="14" rx="3" fill="{STATE_FILL.get(state, "#FFF")}"'
                       f' stroke="{DENY if state == "stopped" else "#C19C00" if state == "deallocated" else LINE}"/>'
                       f'<text x="{LEFT_X + 20}" y="{y_left + 11}" font-size="11"'
                       + (f' fill="{DENY}" font-weight="600"' if state == "stopped" else "") + f'>{n} {_esc(label)}</text>')
            y_left += 20

    # --- lines -----------------------------------------------------------------------------------------------------
    links = []
    for key, (cx, cy) in chip_pos.items():
        target = key.split("|", 1)[1]
        if target in tile_pos:
            tx, ty = tile_pos[target]
            links.append(f'<path d="M{cx:.1f},{cy:.1f} C{cx + 60:.1f},{cy:.1f} {tx - 60:.1f},{ty:.1f} {tx:.1f},{ty:.1f}" '
                         f'fill="none" stroke="{ALLOW}" stroke-width="1.2" stroke-dasharray="4,3" opacity="0.55"/>')
    for sn, items in integrated.items():
        if sn in subnet_rows:
            sy, sx = subnet_rows[sn]
            for p in items:
                if p["id"] in tile_pos:
                    tx, ty = tile_pos[p["id"]]
                    links.append(f'<path d="M{sx:.1f},{sy:.1f} C{sx + 70:.1f},{sy:.1f} {tx - 70:.1f},{ty:.1f} '
                                 f'{tx:.1f},{ty:.1f}" fill="none" stroke="{AZURE}" stroke-width="1.2" '
                                 f'stroke-dasharray="1,3" opacity="0.7"/>')
    for cls in (OPEN, APP_PUBLIC):
        if cls in lane_heads:
            hx, hy = lane_heads[cls]
            links.append(f'<path d="M{LEFT_X + LEFT_W},{inet_y + 27} C{LEFT_X + LEFT_W + 200},{inet_y + 27} '
                         f'{hx - 200:.1f},{hy:.1f} {hx:.1f},{hy:.1f}" fill="none" stroke="{LANE_COLOURS[cls]}" '
                         f'stroke-width="1.6" opacity="0.5"/>')
    canvas.parts[0:0] = links    # under everything else

    # --- header ------------------------------------------------------------------------------------------------------
    exp = Counter(exposure(p) for p in data_items)
    no_nsg = sum(1 for v in vnets for s in v.get("subnet_list") or []
                 if not s.get("nsg") and (s.get("name") or "").lower() not in GATEWAY_SUBNETS + ("azurebastionsubnet",)
                 and not s.get("delegations"))
    kpis = [(len(vnets), "VNets"), (sum(len(v.get("subnet_list") or []) for v in vnets), "subnets"),
            (no_nsg, "subnets without NSG"),
            (sum(1 for p in net.get("private_endpoints") or [] if p.get("subscriptionId") == sid), "private endpoints"),
            (exp.get(OPEN, 0), "open to all networks"), (exp.get(RESTRICTED, 0), "restricted"),
            (exp.get(PRIVATE, 0) + exp.get(CLOSED, 0), "private / public off"), (len(pips), "public IPs"),
            (vm_count.get("deallocated", 0), "VMs deallocated"), (vm_count.get("stopped", 0), "VMs stopped (billed)")]
    canvas.add(canvas.icon(SUBSCRIPTION_ICON[0], 24, 16, 34)
               + f'<text x="68" y="36" font-size="20" font-weight="700">{_esc(sub.get("name"))} - network</text>'
                 f'<text x="68" y="55" class="muted" font-size="12">{_esc(sid)} · '
                 f'{_esc(_sub_env(sub.get("name") or ""))} · how traffic gets in and out, what sits where and how '
                 f'exposed each service is</text>')
    canvas.add(_kpi_strip(kpis, 24, 70, warn={"subnets without NSG", "open to all networks", "VMs stopped (billed)"}))
    canvas.add(_legend(24, 110))
    if tenant_link:
        canvas.add(f'<a href="{_esc(tenant_link)}"><text x="{RIGHT_X + 2 * TILE_W - 120}" y="36" font-size="12" '
                   f'fill="{AZURE}" class="title">← tenant network</text></a>')
    if (net or {}).get("error") or not net:
        canvas.add(f'<text x="{MID_X}" y="{y_mid + 20:.1f}" font-size="12" fill="#CA5010">Network details were not '
                   f'collected yet - refresh the estate inventory.</text>')
    height = max(y_left, y_mid, y_right) + 40
    width = RIGHT_X + 2 * TILE_W + 12 + 24
    canvas.add(f'<text x="24" y="{height - 14}" class="muted small">Icons: Microsoft Azure architecture icons. Green '
               f'dashed: private endpoint to its service. Blue dotted: app outbound VNet integration. Exposure from '
               f'Resource Graph (publicNetworkAccess, firewall default action and rules, private endpoints).</text>')
    return canvas.svg(width, height, f"Network - {sub.get('name')}")


def _owner_kind(owner: Optional[str]) -> str:
    owner = (owner or "").lower()
    for key, label in (("/networkinterfaces/", "on VMs"), ("/loadbalancers/", "on load balancers"),
                       ("/applicationgateways/", "on application gateways"), ("/azurefirewalls/", "on firewalls"),
                       ("/bastionhosts/", "on Bastion"), ("/virtualnetworkgateways/", "on VPN / ER gateways"),
                       ("/natgateways/", "on NAT gateways")):
        if key in owner:
            return label
    return "unattached or other" if not owner else "on other resources"


def _legend(x: float, y: float) -> str:
    items = [(DENY, "open to all networks"), ("#C19C00", "restricted / deallocated"), (ALLOW, "private endpoint"),
             ("#038387", "public access off"), (AZURE, "public app / VNet integration"),
             ("#8A8886", "rules not in Resource Graph")]
    out, cx = [], x
    for colour, text in items:
        out.append(f'<rect x="{cx}" y="{y}" width="10" height="10" rx="2" fill="{colour}"/>'
                   f'<text x="{cx + 14}" y="{y + 9}" class="muted small">{_esc(text)}</text>')
        cx += 30 + len(text) * 5.6
    return "".join(out)


def _draw_vnet(canvas: Canvas, v: Dict[str, Any], y: float, in_subnet, routes, integrated, all_vnets, sub_names,
               subnet_rows, chip_pos) -> float:
    subnets = v.get("subnet_list") or []
    peer_text = []
    for p in (v.get("peerings") or [])[:4]:
        rv = all_vnets.get(p["remote"])
        ok = (p.get("state") or "").lower() == "connected"
        peer_text.append(f"{(rv or {}).get('name') or _name_of(p['remote'])}"
                         + (f" ({sub_names.get(rv.get('subscriptionId'), '')})" if rv and rv.get("subscriptionId")
                            != v.get("subscriptionId") else "")
                         + ("" if ok else " - NOT connected") + (" - via its gateway" if p.get("remote_gateways") else ""))
    more = len(v.get("peerings") or []) - 4
    header_lines = [", ".join(v.get("space") or []) + f" · {v.get('location')}"
                    + (" · DNS " + ", ".join(v.get("dns")[:2]) if v.get("dns") else " · Azure DNS")
                    + (" · DDoS plan" if v.get("ddos") else "")]
    if peer_text:
        header_lines.append("Peered with: " + "; ".join(peer_text) + (f" +{more}" if more > 0 else ""))
    top = y
    y += 50 + 14 * len(header_lines)
    rows_svg = []
    for s in subnets:
        items = in_subnet.get(s["id"], [])
        chips = _chips(items)
        apps = integrated.get(s["id"], [])
        badges = _badges(s, routes.get(s["id"]), len(apps),
                         pe_only=bool(items) and all(i["kind"] == "pe" for i in items))
        per_row = 3
        chip_rows = math.ceil(len(chips) / per_row) if chips else 0
        badge_rows = math.ceil(sum(len(b[0]) * 5.6 + 14 for b in badges) / 220) if badges else 0
        h = max(44 + 16 * max(0, badge_rows - 1), 10 + chip_rows * (CHIP_H + 4))
        x0, w = MID_X + 10, MID_W - 20
        name = s.get("name") or ""
        body = [f'<rect x="{x0}" y="{y:.1f}" width="{w}" height="{h:.1f}" rx="5" fill="#F7F9FB" stroke="{LINE}"/>',
                canvas.icon(SUBNET_ICON[0], x0 + 6, y + 6, 16),
                f'<text x="{x0 + 26}" y="{y + 17:.1f}" font-size="11.5" font-weight="600">{_esc(_fit(name, 26))}</text>'
                f'<text x="{x0 + 26}" y="{y + 30:.1f}" class="muted small">{_esc(s.get("prefix") or "")}</text>']
        bx, by = x0 + 8, y + 44
        for text, colour in badges:
            bw = len(text) * 5.6 + 10
            if bx + bw > x0 + 228:
                bx, by = x0 + 8, by + 16
            body.append(f'<rect x="{bx:.1f}" y="{by - 10:.1f}" width="{bw:.1f}" height="13" rx="6.5" fill="#FFFFFF" '
                        f'stroke="{colour}" stroke-width="0.9"/><text x="{bx + 5:.1f}" y="{by:.1f}" font-size="9.5" '
                        f'fill="{colour}">{_esc(text)}</text>')
            bx += bw + 4
        cx0 = x0 + 236
        for i, (key, chip) in enumerate(chips):
            cx = cx0 + (i % per_row) * (CHIP_W + 6)
            cy = y + 6 + (i // per_row) * (CHIP_H + 4)
            body.append(_chip(canvas, chip, cx, cy))
            if key:
                chip_pos[key] = (cx + CHIP_W, cy + CHIP_H / 2)
        rows_svg.append(f'<g class="node" data-label="{_esc((name + " " + (s.get("prefix") or "")).lower())}">'
                        + "".join(body) + "</g>")
        subnet_rows[s["id"]] = (y + h / 2, x0 + w)
        y += h + 6
    if not subnets:
        rows_svg.append(f'<text x="{MID_X + 14}" y="{y + 14:.1f}" class="muted small">No subnets.</text>')
        y += 24
    height = y - top + 6
    peer_tip = "\n".join(
        f"{(all_vnets.get(p['remote']) or {}).get('name') or _name_of(p['remote'])} - {p.get('state') or '?'}"
        + (" - uses its gateway" if p.get("remote_gateways") else "") for p in v.get("peerings") or [])
    canvas.add(f'<g class="node" data-label="{_esc((v.get("name") or "").lower())} vnet">'
               f'<title>{_esc(v.get("name"))}: {_esc(", ".join(v.get("space") or []))}'
               + (f"\nPeerings:\n{_esc(peer_tip)}" if peer_tip else "") + "</title>"
               f'<rect class="box" x="{MID_X}" y="{top:.1f}" width="{MID_W}" height="{height:.1f}" rx="8" '
               f'fill="#FFFFFF" stroke="{AZURE}" stroke-width="1.4"/>'
               + canvas.icon("Virtual-Networks", MID_X + 10, top + 10, 28)
               + f'<text x="{MID_X + 46}" y="{top + 24:.1f}" font-size="13.5" font-weight="700">'
                 f'{_esc(v.get("name"))}</text><text x="{MID_X + 46}" y="{top + 40:.1f}" class="muted small">Virtual '
                 f'network · {len(subnets)} subnet(s) · resource group {_esc(v.get("resourceGroup"))}</text>'
               + "".join(f'<text x="{MID_X + 12}" y="{top + 58 + i * 14:.1f}" font-size="10.5">{_esc(_fit(t, 118))}'
                         f'</text>' for i, t in enumerate(header_lines))
               + "</g>" + "".join(rows_svg))
    return y + 6


def _badges(s: Dict[str, Any], route: Optional[Dict[str, Any]], apps: int,
            pe_only: bool = False) -> List[Tuple[str, str]]:
    name = (s.get("name") or "").lower()
    out = []
    if s.get("nsg"):
        out.append((f"NSG {_name_of(s['nsg'])[:18]}", ALLOW))
    elif pe_only:
        out.append(("no NSG (private endpoints only)", MUTED))
    elif name not in GATEWAY_SUBNETS + ("azurebastionsubnet",) and not s.get("delegations"):
        out.append(("no NSG", DENY))
    if route:
        hop = route.get("default_route")
        out.append((f"0.0.0.0/0 → {hop}" if hop else f"route table ({route.get('routes', 0)} routes)",
                    WARN if hop and hop.startswith("VirtualAppliance") else MUTED))
    if s.get("nat"):
        out.append(("NAT gateway", AZURE))
    for d in s.get("delegations") or []:
        out.append((f"delegated: {d.split('/')[-1]}", "#5C2E91"))
    if s.get("service_endpoints"):
        out.append(("SE: " + ", ".join(x.replace("Microsoft.", "") for x in s["service_endpoints"][:4]), "#038387"))
    if apps:
        out.append((f"VNet integration: {apps} app(s)", AZURE))
    return out


def _chips(items: List[Dict[str, Any]]) -> List[Tuple[Optional[str], Dict[str, Any]]]:
    """Chips for a subnet: one per item, VMs summarised when there are many."""
    out: List[Tuple[Optional[str], Dict[str, Any]]] = []
    vms = [i for i in items if i["kind"] == "vm"]
    if len(vms) > 6:
        for state, n in Counter(v["state"] for v in vms).most_common():
            out.append((None, {"kind": "vm-summary", "name": f"{n} VMs {state or ''}".strip(), "state": state}))
    else:
        out += [(None, v) for v in sorted(vms, key=lambda v: (v["state"] != "stopped", v["state"] != "deallocated",
                                                               v["name"]))]
    for i in items:
        if i["kind"] == "pe":
            out.append((f"{i['id']}|{i['target']}", i))
        elif i["kind"] == "edge":
            out.append((None, i))
    return out


def _chip(canvas: Canvas, chip: Dict[str, Any], x: float, y: float) -> str:
    kind = chip["kind"]
    if kind in ("vm", "vm-summary"):
        state = chip.get("state")
        stem, fill = "Virtual-Machine", STATE_FILL.get(state, "#FFFFFF")
        stroke = DENY if state == "stopped" else "#C19C00" if state == "deallocated" else LINE
        label = chip["name"]
        tip = (f"VM {chip['name']} - {state or 'state unknown'}"
               + (" (compute still billed - deallocate it)" if state == "stopped" else "")
               + (" (public IP)" if chip.get("public_ip") else ""))
    elif kind == "pe":
        stem, label = "Private-Endpoints", chip["name"] + (f" · {chip['group']}" if chip.get("group") else "")
        fill, stroke = "#F1FAF1", ALLOW
        tip = f"Private endpoint to {chip['target'] or 'unknown target'}"
    else:
        stem, type_label = _icon(chip["type"])
        label = chip["name"]
        fill, stroke = "#EEF5FC", AZURE
        tip = f"{type_label}: {chip['name']}" + (f" ({chip['sku']})" if chip.get("sku") else "")
    return (f'<g data-label="{_esc((label + " " + tip).lower())}"><title>{_esc(tip)}</title>'
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{CHIP_W}" height="{CHIP_H}" rx="4" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="{1.4 if kind != "pe" and stroke in (DENY, "#C19C00") else 0.9}"/>'
            + canvas.icon(stem, x + 4, y + 4, 16, label)
            + f'<text x="{x + 24:.1f}" y="{y + 16:.1f}" font-size="10">{_esc(_fit(label, 19))}</text>'
            + (f'<circle cx="{x + CHIP_W - 6:.1f}" cy="{y + 6:.1f}" r="3.5" fill="{DENY}"><title>public IP</title>'
               f'</circle>' if chip.get("public_ip") else "") + "</g>")


def _draw_lane(canvas: Canvas, cls: str, title: str, items: List[Dict[str, Any]], y: float,
               tile_pos: Dict[str, Tuple[float, float]]) -> Tuple[float, Tuple[float, float]]:
    colour = LANE_COLOURS.get(cls, MUTED)
    shown = sorted(items, key=lambda p: (p["type"], p.get("name") or ""))[:MAX_LANE]
    rows = math.ceil(len(shown) / 2)
    h = 30 + rows * (TILE_H + 6) + (16 if len(items) > MAX_LANE else 0)
    w = 2 * TILE_W + 12
    out = [f'<rect x="{RIGHT_X}" y="{y:.1f}" width="{w}" height="{h:.1f}" rx="8" fill="#FFFFFF" stroke="{colour}" '
           f'stroke-width="1.3"/><rect x="{RIGHT_X}" y="{y:.1f}" width="{w}" height="24" rx="8" fill="{colour}" '
           f'opacity="0.12"/><text x="{RIGHT_X + 10}" y="{y + 16:.1f}" font-size="11.5" font-weight="700" '
           f'fill="{colour}">{_esc(title)} ({len(items)})</text>']
    for i, p in enumerate(shown):
        tx = RIGHT_X + 4 + (i % 2) * (TILE_W + 4)
        ty = y + 28 + (i // 2) * (TILE_H + 6)
        mapped = icon_for(p["type"], p.get("kind"))
        stem, label = (mapped if mapped else (None, p["type"].split("/")[-1]))
        bits = [label]
        if p.get("pe"):
            bits.append(f"PE ×{p['pe']}")
        if p.get("ip_rules"):
            bits.append(f"{p['ip_rules']} IP rule(s)")
        if p.get("vnet_rules"):
            bits.append(f"{p['vnet_rules']} VNet rule(s)")
        if p.get("integration"):
            bits.append("→ " + _name_of(p["integration"]))
        if p["type"] == "microsoft.logic/workflows":
            bits.append("trigger IP restrictions" if p.get("access_control") else "multi-tenant public endpoint")
        out.append(f'<g class="node" data-label="{_esc(((p.get("name") or "") + " " + label).lower())}">'
                   f'<title>{_esc(p.get("name"))} - {_esc(EXPOSURE_LABELS.get(exposure(p), ""))}\n'
                   f'{_esc(p["id"])}</title><rect x="{tx:.1f}" y="{ty:.1f}" width="{TILE_W}" height="{TILE_H}" rx="5" '
                   f'fill="#F7F9FB"/>' + canvas.icon(stem, tx + 6, ty + 6, 22, label)
                   + f'<text x="{tx + 34:.1f}" y="{ty + 15:.1f}" font-size="11">{_esc(_fit(p.get("name"), 38))}</text>'
                     f'<text x="{tx + 34:.1f}" y="{ty + 28:.1f}" class="muted small">{_esc(_fit(" · ".join(bits), 48))}'
                     f'</text></g>')
        tile_pos[p["id"]] = (tx, ty + TILE_H / 2)
    if len(items) > MAX_LANE:
        out.append(f'<text x="{RIGHT_X + 10}" y="{y + h - 6:.1f}" class="muted small">+ {len(items) - MAX_LANE} more'
                   f'</text>')
    canvas.add("".join(out))
    return y + h, (RIGHT_X, y + 12)


# ---------------------------------------------------------------------------
# One entry point for the viewers (local portal and Docker API)
# ---------------------------------------------------------------------------

VIEWS = ("resources", "network")


def architecture_svg(data: Dict[str, Any], subscription: str = "", view: str = "resources",
                     base: Optional[str] = None, policy: Optional[Dict[str, Any]] = None, mapping: Any = None) -> str:
    """The diagram for a view ('resources', 'network' or 'landing') of the tenant or one subscription.

    base: the page URL to link drill-downs to (local portal); None leaves the clicks to the page (Docker UI, which
    reads data-subscription). policy / mapping: the policy collection and the landing_zone_mapping setting (landing
    view, always tenant-wide). Raises KeyError for an unknown subscription."""
    from scripts.subscription_analysis import diagram

    if view == "landing":
        from scripts.subscription_analysis.landing_zone import analyse
        from scripts.subscription_analysis.landing_zone_diagram import render_landing

        return render_landing(analyse(data, policy, mapping))
    if view == "network":
        if subscription:
            return render_network(data, subscription, f"{base}?view=network" if base else None)
        return render_network_tenant(data, f"{base}?view=network&subscription={{id}}" if base else None)
    if subscription:
        return diagram.render_subscription(data, subscription, base)
    return diagram.render_tenant(data, f"{base}?subscription={{id}}" if base else None)
