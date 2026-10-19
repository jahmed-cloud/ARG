"""
Estate telemetry for the overview pages: where the money goes, how the VMs are used, how exposed the PaaS estate is
and how well it is tagged - computed from estate.json (local) or the Docker estate snapshot, so both overviews show
the same numbers.

estate_telemetry(data) returns plain JSON; the local portal draws it with telemetry_svg() (server-side SVG, no
script), the Docker dashboard with recharts (GET /estate/telemetry).
"""

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional

from scripts.subscription_analysis.diagram import vm_state
from scripts.subscription_analysis.network import APP_TYPES, exposure

TOP = 8


def _top(totals: Dict[str, float], n: int = TOP) -> List[Dict[str, Any]]:
    items = sorted(totals.items(), key=lambda kv: -kv[1])
    out = [{"name": k, "cost": round(v, 2)} for k, v in items[:n] if v > 0]
    rest = sum(v for _, v in items[n:])
    if rest > 0:
        out.append({"name": "Other", "cost": round(rest, 2)})
    return out


def utilisation_band(r: Dict[str, Any]) -> str:
    """idle / low / healthy / hot for a running VM from its 30-day CPU (P95 when known)."""
    cpu = r.get("cpu95") if r.get("cpu95") is not None else r.get("cpu")
    if cpu is None:
        return "no data"
    if cpu < 5:
        return "idle"
    if cpu < 30:
        return "low"
    return "healthy" if cpu <= 80 else "hot"


def estate_telemetry(data: Dict[str, Any], required_tags: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    resources = data.get("resources") or []
    subs = data.get("subscriptions") or []
    types = data.get("types") or {}
    currency = Counter(r.get("cur") for r in resources if r.get("cur")).most_common(1)
    currency = currency[0][0] if currency else ""

    def cost(r: Dict[str, Any]) -> float:
        return float(r.get("cost") or 0) if (r.get("cur") or currency) == currency else 0.0

    by_category: Dict[str, float] = defaultdict(float)
    by_env: Dict[str, float] = defaultdict(float)
    by_sub: Dict[int, float] = defaultdict(float)
    by_service: Dict[str, float] = defaultdict(float)
    service_count: Counter = Counter()
    power: Counter = Counter()
    bands: Counter = Counter()
    stopped: List[Dict[str, Any]] = []
    deallocated_cost = 0.0
    for r in resources:
        c = cost(r)
        meta = types.get(r.get("type") or "") or {}
        by_category[meta.get("category") or "Other"] += c
        by_env[r.get("env") or "Unknown"] += c
        by_sub[r.get("s", -1)] += c
        label = meta.get("label") or (r.get("type") or "").split("/")[-1]
        by_service[label] += c
        service_count[label] += 1
        state = vm_state(r)
        if state:
            power[state] += 1
            if state == "running":
                bands[utilisation_band(r)] += 1
            elif state == "deallocated":
                deallocated_cost += c
            if state == "stopped" and len(stopped) < 15:
                idx = r.get("s", -1)
                stopped.append({"name": r.get("name"), "subscription": subs[idx]["name"] if 0 <= idx < len(subs) else "",
                                "size": r.get("size")})
    top_subs = sorted(((i, v) for i, v in by_sub.items() if 0 <= i < len(subs)), key=lambda kv: -kv[1])[:10]

    arch = data.get("architecture") or {}
    net = arch.get("network") or {}
    exposure_counts: Counter = Counter()
    for p in net.get("paas") or []:
        group = "apps" if p.get("type") in APP_TYPES else "data"
        exposure_counts[f"{group}:{exposure(p)}"] += 1
    vnets = arch.get("vnets") or []
    peered = {v["id"] for v in vnets if v.get("peerings")} | {p["remote"] for v in vnets for p in v.get("peerings") or []}

    required = [t.lower() for t in (required_tags or [])]
    tagged = tagged_cost = total_cost = 0.0
    missed: Counter = Counter()
    if required:
        for r in resources:
            keys = {str(k).lower() for k in (r.get("tags") or {})}
            missing = [t for t in required if t not in keys]
            c = cost(r)
            total_cost += c
            if not missing:
                tagged += 1
                tagged_cost += c
            missed.update(missing)

    suggestions = data.get("suggestions") or []
    return {
        "generated_at": data.get("generated_at") or data.get("inventory_at"),
        "currency": currency, "resources": len(resources), "subscriptions": len(subs),
        "spend_30d": round(sum(cost(r) for r in resources), 2),
        "spend_by_category": _top(by_category),
        "spend_by_environment": _top(by_env, 4),
        "spend_by_subscription": [{"name": subs[i].get("name") or subs[i]["id"], "id": subs[i]["id"],
                                   "cost": round(v, 2)} for i, v in top_subs if v > 0],
        "top_services": [{**x, "count": service_count.get(x["name"], 0)} for x in _top(by_service, 10)
                         if x["name"] != "Other"],
        "vm_power": {k: power.get(k, 0) for k in ("running", "deallocated", "stopped")},
        "vm_stopped": stopped, "vm_deallocated_cost": round(deallocated_cost, 2),
        "vm_utilisation": {k: bands.get(k, 0) for k in ("idle", "low", "healthy", "hot", "no data")},
        "network": {
            "data": {k.split(":")[1]: n for k, n in exposure_counts.items() if k.startswith("data:")},
            "apps": {k.split(":")[1]: n for k, n in exposure_counts.items() if k.startswith("apps:")},
            "private_endpoints": len(net.get("private_endpoints") or []),
            "public_ips": len(net.get("public_ips") or []),
            "vms_with_public_ip": sum(1 for v in net.get("vms") or [] if v.get("public_ip")),
            "vnets": len(vnets), "isolated_vnets": sum(1 for v in vnets if v["id"] not in peered),
            "collected": bool(net) and not net.get("error"),
        },
        "tag_coverage": ({"required": list(required_tags or []),
                          "resources_pct": round(100 * tagged / len(resources), 1) if resources else None,
                          "cost_pct": round(100 * tagged_cost / total_cost, 1) if total_cost else None,
                          "most_missed": [{"tag": t, "resources": n} for t, n in missed.most_common(5)]}
                         if required else None),
        "suggestions": {"count": len(suggestions),
                        "by_severity": dict(Counter((s.get("sev") or s.get("severity") or "info").lower()
                                                    for s in suggestions))},
    }


def in_currency(t: Dict[str, Any], conv: Any, billing_rates: Dict[str, float]) -> Dict[str, Any]:
    """The telemetry's spend in the currency picked in the Currency dropdown (currency.Converter); unchanged when the
    spend currency's rate to USD is unknown."""
    factor, code = conv.from_billing(1.0, t.get("currency") or "", billing_rates.get(t.get("currency") or ""))
    if code == t.get("currency") or factor is None:
        return t
    out = dict(t, currency=code, spend_30d=round((t.get("spend_30d") or 0) * factor, 2),
               vm_deallocated_cost=round((t.get("vm_deallocated_cost") or 0) * factor, 2))
    for key in ("spend_by_category", "spend_by_environment", "spend_by_subscription", "top_services"):
        out[key] = [dict(x, cost=round((x.get("cost") or 0) * factor, 2)) for x in t.get(key) or []]
    return out
