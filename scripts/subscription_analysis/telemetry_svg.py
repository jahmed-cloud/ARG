"""
Local portal overview: the estate telemetry (telemetry.estate_telemetry) drawn as server-side SVG charts - no
script, so the portal's Content-Security-Policy stays strict. The Docker dashboard draws the same JSON with recharts.
"""

import html
import math
from typing import Any, Callable, Dict, List, Optional, Tuple

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _money(v: float, currency: str) -> str:
    return f"{v:,.0f} {currency}".strip()


def hbar_svg(items: List[Dict[str, Any]], currency: str = "", colour: str = "#0078D4", width: int = 440,
             key: str = "cost", value_of: Optional[Callable[[Dict[str, Any]], str]] = None) -> str:
    """Horizontal bars, one row per item (name on the left, value on the right)."""
    if not items:
        return '<p class="muted small">No data yet.</p>'
    top = max(float(x[key]) for x in items) or 1.0
    row, label_w = 24, 170
    bar_w = width - label_w - 96
    out = [f'<svg viewBox="0 0 {width} {row * len(items) + 4}" width="100%" role="img" class="tele-chart" '
           f'aria-label="Bar chart">']
    for i, x in enumerate(items):
        y = i * row + 2
        w = max(2.0, bar_w * float(x[key]) / top)
        name = str(x["name"])
        short = name if len(name) <= 26 else name[:25] + "…"
        value = value_of(x) if value_of else _money(float(x[key]), currency)
        out.append(f'<text x="{label_w - 6}" y="{y + 15}" text-anchor="end" font-size="11"><title>{_e(name)}</title>'
                   f'{_e(short)}</text><rect x="{label_w}" y="{y + 4}" width="{w:.1f}" height="15" rx="3" '
                   f'fill="{colour}"/><text x="{label_w + w + 6:.1f}" y="{y + 15}" font-size="11" fill="#5F6B7A">'
                   f'{_e(value)}</text>')
    return "".join(out) + "</svg>"


def donut_svg(parts: List[Tuple[str, int, str]], size: int = 150) -> str:
    """parts: (label, value, colour) - a donut with the total in the middle and a legend to the right."""
    total = sum(v for _, v, _ in parts)
    if not total:
        return '<p class="muted small">No data yet.</p>'
    r, cx, cy, sw = size / 2 - 14, size / 2, size / 2, 22
    out = [f'<svg viewBox="0 0 {size + 230} {max(size, 22 * len(parts) + 10)}" width="100%" role="img" '
           f'class="tele-chart" aria-label="Donut chart">']
    angle = -math.pi / 2
    for label, value, colour in parts:
        if not value:
            continue
        frac = value / total
        if frac >= 0.9999:
            out.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{colour}" stroke-width="{sw}">'
                       f'<title>{_e(label)}: {value:,}</title></circle>')
            break
        end = angle + 2 * math.pi * frac
        x1, y1 = cx + r * math.cos(angle), cy + r * math.sin(angle)
        x2, y2 = cx + r * math.cos(end), cy + r * math.sin(end)
        out.append(f'<path d="M{x1:.2f},{y1:.2f} A{r:.2f},{r:.2f} 0 {1 if frac > 0.5 else 0} 1 {x2:.2f},{y2:.2f}" '
                   f'fill="none" stroke="{colour}" stroke-width="{sw}"><title>{_e(label)}: {value:,}</title></path>')
        angle = end
    out.append(f'<text x="{cx}" y="{cy + 6}" text-anchor="middle" font-size="17" font-weight="700">{total:,}</text>')
    for i, (label, value, colour) in enumerate(parts):
        y = 16 + i * 22
        out.append(f'<rect x="{size + 10}" y="{y - 10}" width="12" height="12" rx="3" fill="{colour}"/>'
                   f'<text x="{size + 28}" y="{y}" font-size="11.5">{_e(label)} '
                   f'<tspan font-weight="700">{value:,}</tspan></text>')
    return "".join(out) + "</svg>"


def telemetry_html(t: Dict[str, Any]) -> str:
    """KPI tiles and chart cards for the local dashboard."""
    cur = t.get("currency") or ""
    power, util, net = t["vm_power"], t["vm_utilisation"], t["network"]
    data_exp, apps = net.get("data") or {}, net.get("apps") or {}
    tags = t.get("tag_coverage") or {}
    kpis = [
        (_money(t["spend_30d"], cur), "spend, last 30 days (analysed subscriptions)", ""),
        (f"{power['running']:,} / {power['deallocated']:,}", "VMs running / deallocated", ""),
        (f"{power['stopped']:,}", "VMs stopped but still billed", "bad" if power["stopped"] else ""),
        (f"{util['idle']:,}", "running VMs idle (P95 CPU under 5 %)", "warn" if util["idle"] else ""),
        (f"{data_exp.get('open', 0):,}", "data services open to all networks", "bad" if data_exp.get("open") else ""),
        (f"{net.get('vms_with_public_ip', 0):,}", "VMs with a public IP", "warn" if net.get("vms_with_public_ip") else ""),
        (f"{net.get('private_endpoints', 0):,}", "private endpoints", ""),
    ]
    if tags.get("resources_pct") is not None:
        kpis.append((f"{tags['resources_pct']:.0f} %", "resources carrying every required tag", ""))
    stopped = "".join(f'<p class="small tele-bad">Stopped, not deallocated: {_e(v["name"])} '
                      f'({_e(v["subscription"])}, {_e(v.get("size") or "")})</p>' for v in t["vm_stopped"][:6])
    collected = net.get("collected")
    severities = sorted((t["suggestions"]["by_severity"] or {}).items(),
                        key=lambda kv: SEVERITY_ORDER.index(kv[0]) if kv[0] in SEVERITY_ORDER else 9)
    cards = [
        ("Spend by category (30 days)", hbar_svg(t["spend_by_category"], cur)),
        ("Top services by spend", hbar_svg(t["top_services"], cur, "#5C2E91")),
        ("VM power state", donut_svg([("Running", power["running"], "#107C10"),
                                      ("Deallocated - disks still billed", power["deallocated"], "#C19C00"),
                                      ("Stopped - compute still billed", power["stopped"], "#C50F1F")]) + stopped),
        ("Running VMs by CPU, 30-day P95", donut_svg([("Idle, under 5 %", util["idle"], "#C19C00"),
                                                      ("Low, 5-30 %", util["low"], "#2196f3"),
                                                      ("Healthy, 30-80 %", util["healthy"], "#107C10"),
                                                      ("Hot, over 80 %", util["hot"], "#C50F1F"),
                                                      ("No metrics", util["no data"], "#C8D3DE")])),
        ("Data services by network exposure", donut_svg([
            ("Open to all networks", data_exp.get("open", 0), "#C50F1F"),
            ("Rules not in Resource Graph", data_exp.get("unverified", 0), "#8A8886"),
            ("Restricted (firewall / VNet rules)", data_exp.get("restricted", 0), "#C19C00"),
            ("Public access off", data_exp.get("closed", 0), "#038387"),
            ("Private endpoint", data_exp.get("private", 0), "#107C10")])
         if collected else '<p class="muted small">Refresh the estate inventory to collect it.</p>'),
        ("Apps by inbound exposure", donut_svg([("Public endpoint", apps.get("app-public", 0), "#0078D4"),
                                                ("Restricted", apps.get("restricted", 0), "#C19C00"),
                                                ("Private endpoint", apps.get("private", 0), "#107C10"),
                                                ("Public access off", apps.get("closed", 0), "#038387")])
         if collected else '<p class="muted small">Refresh the estate inventory to collect it.</p>'),
        ("Top subscriptions by spend", hbar_svg(t["spend_by_subscription"], cur, "#038387")),
        ("Suggestions by severity", hbar_svg([{"name": s.title(), "n": n} for s, n in severities], key="n",
                                             colour="#CA5010", value_of=lambda x: f"{x['n']:,}")),
    ]
    kpi_html = "".join(f'<div class="tele-kpi {cls}"><strong>{_e(v)}</strong><span>{_e(label)}</span></div>'
                       for v, label, cls in kpis)
    card_html = "".join(f'<div class="tele-card"><h3>{_e(title)}</h3>{body}</div>' for title, body in cards)
    return f'<div class="tele-kpis">{kpi_html}</div><div class="tele-grid">{card_html}</div>'
