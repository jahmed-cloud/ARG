"""
Markdown report renderer for the subscription analysis CLI.

Everything here is derived from AnalysisData (inventory, cost datasets and
scanner findings) - no hand-written numbers - so the same report can be
regenerated for any subscription.
"""

import json
import re
import shutil
import threading
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from scripts.subscription_analysis.collector import AnalysisData, to_jsonable
from scripts.subscription_analysis.knowledge import (
    AREAS,
    CRITIQUES,
    DEEP_DIVE_FOLDERS,
    WAVE_NAMES,
    WAVE_NO_REGRET,
    WAVE_OPTIMISE,
    WAVE_STRUCTURAL,
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_LABEL = {"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium", "low": "⚪ Low", "info": "ℹ️ Info"}
WORKLOAD_TAG_KEYS = ("projectname", "project", "application", "workload")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def md_table(headers: List[str], rows: Iterable[Iterable[Any]], align: Optional[List[str]] = None) -> str:
    rows = [[_cell(c) for c in r] for r in rows]
    align = align or ["---"] * len(headers)
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(align) + "|"]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(lines)


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def money(value: Optional[float], currency: str = "", decimals: int = 0) -> str:
    if value is None:
        return "n/a"
    return f"{value:,.{decimals}f}" + (f" {currency}" if currency else "")


def pct(part: float, whole: float) -> str:
    return f"{part / whole:.1%}" if whole else "n/a"


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def short_id(resource_id: Optional[str], subscription_id: str) -> str:
    return (resource_id or "").replace(f"/subscriptions/{subscription_id}", "").lstrip("/") or "(subscription)"


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Derived datasets
# ---------------------------------------------------------------------------

class Model:
    """Pre-computed aggregates shared by all report sections."""

    def __init__(self, data: AnalysisData):
        self.data = data
        self.sub = data.subscription
        self.currency = data.cost.get("currency") or "USD"
        self.fx = data.cost.get("usd_to_billing")
        self.findings = sorted(
            data.findings,
            key=lambda f: (sev_rank(f["severity"]), -(f.get("estimated_monthly_savings_usd") or 0), f["title"]),
        )
        for i, f in enumerate(self.findings, 1):
            f["ref"] = f"F-{i:03d}"
        self._monthly()
        self._last30()

    # cost --------------------------------------------------------------

    def _monthly(self) -> None:
        rows = self.data.cost.get("monthly_by_service") or []
        self.months: Dict[str, float] = defaultdict(float)
        self.service_months: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        for r in rows:
            month = str(r.get("BillingMonth") or r.get("UsageDate") or "")[:7]
            if len(month) == 8 and month.isdigit():
                month = f"{month[:4]}-{month[4:6]}"
            cost = float(r.get("Cost") or 0)
            self.months[month] += cost
            self.service_months[r.get("ServiceName") or "Other"][month] += cost
        self.month_keys = sorted(self.months)
        self.total_12m = sum(self.months.values())
        self.lumpy = self._is_lumpy()

    LUMPY_SHARE = 0.5
    LUMPY_PEAK_RATIO = 3.0

    def _is_lumpy(self) -> bool:
        """
        True when one month carries most of the year's charges (annual Marketplace SaaS, reservation purchases)
        and the subscription existed for the whole window - so a young or fast-growing subscription, whose early
        months are small simply because little was deployed yet, is not mistaken for one-off spend.
        """
        positive = sorted((v for v in self.months.values() if v > 0), reverse=True)
        if len(self.month_keys) < 2 or not positive or positive[0] / sum(positive) < self.LUMPY_SHARE:
            return False
        others = positive[1:]
        if others and positive[0] < self.LUMPY_PEAK_RATIO * others[len(others) // 2]:
            return False
        window_start = str((self.data.cost.get("window_12m") or {}).get("from") or "")
        created = sorted(str(r.get("createdTime") or "")[:10] for r in self.data.resources if r.get("createdTime"))
        return bool(window_start and created and created[0] <= window_start)

    @property
    def run_rate(self) -> float:
        """Monthly run-rate: last 30 days, or the 12-month average when one-off charges dominate."""
        return self.total_12m / 12 if self.lumpy else self.total_30

    @property
    def run_rate_label(self) -> str:
        return "12-month average; spend is lumpy" if self.lumpy else "last 30 days run-rate"

    def trend_summary(self) -> str:
        """
        One sentence on the monthly trend: first and last *full* month (the window's end month is
        month-to-date), the peak, credits/refunds, and a warning when one month dominates the year
        (annual Marketplace SaaS or reservation charges), because then 30 days is not a run-rate.
        """
        cur = self.currency
        current = str((self.data.cost.get("window_12m") or {}).get("to") or "")[:7]
        full = [k for k in self.month_keys if k != current]
        parts = []
        if len(full) >= 2:
            parts.append(f"monthly spend went from {money(self.months[full[0]], cur)} ({full[0]}) to "
                         f"{money(self.months[full[-1]], cur)} ({full[-1]}, last full month)")
        elif full:
            parts.append(f"{money(self.months[full[0]], cur)} in {full[0]} (the only full month with cost)")
        if current in self.months:
            parts.append(f"{money(self.months[current], cur)} so far in {current}")
        positive = {k: v for k, v in self.months.items() if v > 0}
        if len(positive) > 1:
            peak = max(positive, key=positive.get)
            parts.append(f"peak {money(positive[peak], cur)} in {peak}")
        credits = {k: v for k, v in self.months.items() if v < 0}
        if credits:
            parts.append(f"includes credits/refunds of {money(sum(credits.values()), cur)} ("
                         + ", ".join(sorted(credits)) + ")")
        total_positive = sum(positive.values())
        if self.lumpy:
            month = max(positive, key=positive.get)
            parts.append(f"{positive[month] / total_positive:.0%} of the charges fall in {month} - one-off or "
                         f"up-front charges (e.g. Marketplace SaaS, reservations), so the last 30 days are not a "
                         f"monthly run-rate")
        return "; ".join(parts)

    def _last30(self) -> None:
        rows = self.data.cost.get("last30_by_rg_service") or []
        self.service_30: Dict[str, float] = defaultdict(float)
        self.rg_30: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        for r in rows:
            cost = float(r.get("Cost") or 0)
            self.service_30[r.get("ServiceName") or "Other"] += cost
            self.rg_30[(r.get("ResourceGroupName") or "(none)").lower()][r.get("ServiceName") or "Other"] += cost
        self.total_30 = sum(self.service_30.values())
        per_resource = self.data.cost.get("last30_by_resource") or {}
        self.top_resources = sorted(per_resource.items(), key=lambda kv: -(kv[1].get("cost") or 0))

    def to_billing(self, usd: Optional[float]) -> Optional[float]:
        if usd is None:
            return None
        return usd * self.fx if self.fx else None

    def savings_by_wave(self) -> Dict[int, float]:
        totals = {WAVE_NO_REGRET: 0.0, WAVE_OPTIMISE: 0.0, WAVE_STRUCTURAL: 0.0}
        for f in self.findings:
            totals[f["wave"]] = totals.get(f["wave"], 0.0) + (f.get("estimated_monthly_savings_usd") or 0.0)
        return totals

    def savings_label(self, usd: Optional[float]) -> str:
        if not usd:
            return "-"
        billing = self.to_billing(usd)
        if billing is not None and self.currency != "USD":
            return f"{money(billing, self.currency)} (USD {usd:,.0f})"
        return money(usd, "USD")

    # inventory -----------------------------------------------------------

    def resource_count_by_rg(self) -> Counter:
        return Counter((r.get("id") or "").split("/")[4].lower() for r in self.data.resources if r.get("id"))

    def workload_of(self, resource: Dict[str, Any]) -> str:
        for k, v in (resource.get("tags") or {}).items():
            if k.lower() in WORKLOAD_TAG_KEYS and v:
                return str(v).strip()
        return "(untagged)"


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def render_readme(m: Model) -> str:
    sub, cur = m.sub, m.currency
    sev_counts = Counter(f["severity"] for f in m.findings)
    waves = m.savings_by_wave()
    top_services = sorted(m.service_30.items(), key=lambda kv: -kv[1])[:3]
    risks = [f for f in m.findings if f["severity"] in ("critical", "high") and f["area"] != AREAS[4]][:8]
    budgets = [b for b in (m.data.cost.get("budgets") or [])
               if ((b.get("properties") or {}).get("timeGrain") or "").lower() == "monthly"]
    amounts = sorted((float((b.get("properties") or {}).get("amount") or 0) for b in budgets), reverse=True)
    budget_amount = amounts[0] if amounts else 0.0
    first = m.month_keys[0] if m.month_keys else None

    lines = [
        f"# Subscription Analysis - `{sub['name']}`", "",
        "[← All subscriptions](../README.md)", "",
        md_table(["Property", "Value"], [
            ["Subscription ID", f"`{sub['id']}`"],
            ["Tenant", f"`{sub.get('tenant_id')}`"],
            ["Analysis date", m.data.generated_at.strftime("%Y-%m-%d")],
            ["Cost windows", f"12 months ({m.data.cost.get('window_12m', {}).get('from')} → "
                             f"{m.data.cost.get('window_12m', {}).get('to')}), last 30 days"],
            ["Billing currency", f"{cur} (actual cost). Savings estimates are computed in USD and converted at the "
                                 f"subscription's implied rate" if m.fx and cur != "USD" else cur],
            ["Method", "Azure Resource Guardian scanners (Resource Graph, ARM, Azure Monitor metrics, Cost Management, "
                       "Defender for Cloud, Advisor), read-only"],
        ]), "",
        "## Executive Summary", "",
        f"- **Resources:** {len(m.data.resources)} in {len(m.data.resource_groups)} resource groups, "
        f"{len({(r.get('location') or '').lower() for r in m.data.resources})} regions.",
        f"- **Cost:** {money(m.total_12m, cur)} over 12 months; {money(m.total_30, cur)} in the last 30 days"
        + (f"; {m.trend_summary()}." if first else "."),
    ]
    if budget_amount:
        over = sum(1 for k in m.month_keys if m.months[k] > budget_amount)
        label = " / ".join(money(a) for a in amounts) + f" {cur}/month"
        lines.append(f"- **Budget{'s' if len(amounts) > 1 else ''}:** {label} - "
                     f"{'the largest ' if len(amounts) > 1 else ''}exceeded in {over} of {len(m.month_keys)} months.")
    lines.append(f"- **Findings:** {len(m.findings)} - " + ", ".join(
        f"{sev_counts.get(s, 0)} {s}" for s in SEVERITIES if sev_counts.get(s)) + ".")
    lines += ["", "**Why it costs this much (last 30 days, by service):**", "",
              md_table(["#", "Service", f"{cur}", "Share"],
                       [[i, s, money(c, "", 2), pct(c, m.total_30)] for i, (s, c) in enumerate(top_services, 1)],
                       ["---:", "---", "---:", "---:"]), ""]
    lines += ["**Headline savings (estimated, per month):**", "",
              md_table(["Wave", "Per month", "Per year"], [
                  [WAVE_NAMES[w], m.savings_label(waves.get(w)), m.savings_label((waves.get(w) or 0) * 12)]
                  for w in (WAVE_NO_REGRET, WAVE_OPTIMISE)
              ] + [["**Total**", m.savings_label(waves[1] + waves[2]), m.savings_label((waves[1] + waves[2]) * 12)]]),
              ""]
    if m.total_30 and m.fx:
        lines.append(f"That is about **{pct(m.to_billing(waves[1] + waves[2]) or 0, m.total_30)}** of the last "
                     f"30 days' spend.")
        lines.append("")
    if risks:
        lines += ["**Top risks (security, operations, resilience):**", ""]
        lines += [f"- {SEV_LABEL[f['severity']]} - **{f['title']}** ({f['ref']})" for f in risks]
        lines.append("")
    lines += [
        "## Report Structure", "",
        md_table(["Folder", "Content"], [
            ["[01-current-findings](./01-current-findings/README.md)", "Architecture overview, workloads, baseline, inventory"],
            ["[02-gap-analysis](./02-gap-analysis/README.md)", "Gaps by area and severity"],
            ["[03-cost-drivers](./03-cost-drivers/README.md)", "Trend, breakdowns, inefficiencies, "
                                                               "[savings register](./03-cost-drivers/savings-register.md)"],
            ["[04-architectural-critique](./04-architectural-critique/README.md)",
             "Why the design looks like this, critique per decision, target architecture, roadmap"],
            ["[05-deep-dive](./05-deep-dive/README.md)", "Per-area technical detail and raw JSON evidence"],
        ]), "",
        "## Prioritised Action List", "",
    ]
    actions = sorted(m.findings, key=lambda f: (f["wave"], sev_rank(f["severity"]),
                                                -(f.get("estimated_monthly_savings_usd") or 0)))[:12]
    lines.append(md_table(["Ref", "Wave", "Severity", "Action", "Monthly impact"],
                          [[f["ref"], f["wave"], SEV_LABEL[f["severity"]], f["title"],
                            m.savings_label(f.get("estimated_monthly_savings_usd"))] for f in actions]))
    lines += ["", "> Generated by `python -m scripts.subscription_analysis`. Evidence for every finding is in "
                  "[05-deep-dive/raw](./05-deep-dive/raw). Estimates are marked as such in the finding text."]
    return "\n".join(lines)


def render_current_findings(m: Model) -> Tuple[str, str]:
    res = m.data.resources
    created = sorted((r.get("createdTime") or "")[:10] for r in res if r.get("createdTime"))
    by_rg = m.resource_count_by_rg()
    regions = Counter((r.get("location") or "unknown").lower() for r in res)
    types = Counter((r.get("type") or "").lower() for r in res)
    workloads: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in res:
        workloads[m.workload_of(r)].append(r)
    secure = next((f for f in m.findings if f["finding_type"] == "low_secure_score"), None)

    lines = ["# 01 - Current Findings & Overview", "", "[← Back to summary](../README.md) · "
             "Inventory: [resource-inventory.md](./resource-inventory.md)", "", "## 1. Baseline at a Glance", ""]
    lines.append(md_table(["Metric", "Value"], [
        ["Resource groups", len(m.data.resource_groups)],
        ["Resources (ARM)", len(res)],
        ["Regions", ", ".join(f"{k} ({v})" for k, v in regions.most_common())],
        ["Oldest / newest resource", f"{created[0] if created else 'n/a'} / {created[-1] if created else 'n/a'}"],
        ["Distinct resource types", len(types)],
        ["Secure score", f"{secure['evidence'].get('current')}/{secure['evidence'].get('max')}"
                         f" ({secure['evidence'].get('pct', 0):.0%})" if secure else "at or above target"],
        ["Scanners run", f"{sum(1 for s in m.data.scanner_runs if s['status'] == 'completed')} "
                         f"({sum(s['findings'] for s in m.data.scanner_runs)} findings)"],
    ]))
    lines += ["", "## 2. Workload Domains (by workload tag)", ""]
    lines.append(md_table(["Workload", "Resources", "Resource groups", "Regions", "Created"], [
        [w, len(items), ", ".join(sorted({(i.get('id') or '').split('/')[4] for i in items})[:6]),
         ", ".join(sorted({(i.get('location') or '').lower() for i in items})),
         _span([(i.get("createdTime") or "")[:7] for i in items])]
        for w, items in sorted(workloads.items(), key=lambda kv: -len(kv[1]))
    ]))
    lines += ["", "## 3. Architecture Overview (as built)", "", _architecture_mermaid(m), ""]
    lines += ["## 4. Baseline by Service", ""]
    lines += _service_baselines(m)
    lines += ["", "## 5. Resource Groups", ""]
    lines.append(md_table(["Resource group", "Location", "Resources", f"30-day cost ({m.currency})"], [
        [g["name"], g.get("location"), by_rg.get(g["name"].lower(), 0),
         money(sum(m.rg_30.get(g["name"].lower(), {}).values()), "", 2)]
        for g in sorted(m.data.resource_groups, key=lambda g: -sum(m.rg_30.get(g["name"].lower(), {}).values()))
    ], ["---", "---", "---:", "---:"]))
    lines += ["", "## 6. Findings Snapshot per Area", ""]
    lines.append(_area_matrix(m))
    return "\n".join(lines), _inventory(m)


def _span(months: List[str]) -> str:
    months = sorted(x for x in months if x)
    return f"{months[0]} → {months[-1]}" if months else "n/a"


def _architecture_mermaid(m: Model) -> str:
    by_region: Dict[str, Dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for r in m.data.resources:
        rid = r.get("id") or ""
        if "/providers/microsoft.eventgrid/systemtopics" in rid.lower():
            continue
        by_region[(r.get("location") or "global").lower()][rid.split("/")[4]][(r.get("type") or "").split("/")[-1]] += 1
    lines = ["```mermaid", "flowchart LR"]
    for i, (region, groups) in enumerate(sorted(by_region.items())):
        lines.append(f'  subgraph R{i}["{region}"]')
        for j, (rg, types) in enumerate(sorted(groups.items(), key=lambda kv: -sum(kv[1].values()))[:12]):
            top = "<br/>".join(f"{n} x {t}" for t, n in types.most_common(4))
            lines.append(f'    R{i}G{j}["{rg}<br/>{top}"]')
        lines.append("  end")
    lines.append("```")
    return "\n".join(lines)


def _service_baselines(m: Model) -> List[str]:
    res = m.data.resources
    out: List[str] = []

    def section(title: str, rtype: str, cols: List[str], row_fn) -> None:
        items = [r for r in res if (r.get("type") or "").lower() == rtype]
        if not items:
            return
        out.extend([f"### {title} ({len(items)})", "", md_table(cols, [row_fn(r) for r in items]), ""])

    def sku(r: Dict[str, Any]) -> str:
        s = r.get("sku") or {}
        return "/".join(str(x) for x in (s.get("name"), s.get("tier"), s.get("capacity")) if x)

    def cost(r: Dict[str, Any]) -> str:
        entry = (m.data.cost.get("last30_by_resource") or {}).get((r.get("id") or "").lower()) or {}
        return money(entry.get("cost"), "", 2)

    section("App Service plans", "microsoft.web/serverfarms", ["Name", "RG", "SKU", "Kind", f"30 d {m.currency}"],
            lambda r: [r["name"], r["id"].split("/")[4], sku(r), r.get("kind"), cost(r)])
    section("Virtual machines", "microsoft.compute/virtualmachines", ["Name", "RG", "Location", "Created"],
            lambda r: [r["name"], r["id"].split("/")[4], r.get("location"), (r.get("createdTime") or "")[:10]])
    section("SQL databases", "microsoft.sql/servers/databases", ["Database", "RG", "SKU", "Kind", f"30 d {m.currency}"],
            lambda r: [r["name"], r["id"].split("/")[4], sku(r), r.get("kind"), cost(r)])
    section("AI Services / Azure OpenAI", "microsoft.cognitiveservices/accounts",
            ["Account", "RG", "Location", "Kind", f"30 d {m.currency}"],
            lambda r: [r["name"], r["id"].split("/")[4], r.get("location"), r.get("kind"), cost(r)])
    storage = [r for r in res if (r.get("type") or "").lower() == "microsoft.storage/storageaccounts"]
    if storage:
        skus = Counter((r.get("sku") or {}).get("name") for r in storage)
        out.extend([f"### Storage accounts ({len(storage)})", "",
                    "SKU mix: " + ", ".join(f"{k} × {v}" for k, v in skus.most_common()), ""])
    return out


def _area_matrix(m: Model) -> str:
    counts: Dict[str, Counter] = defaultdict(Counter)
    for f in m.findings:
        counts[f["area"]][f["severity"]] += 1
    return md_table(["Area"] + [s.title() for s in SEVERITIES[:4]],
                    [[a] + [counts[a].get(s, 0) for s in SEVERITIES[:4]] for a in AREAS],
                    ["---", "---:", "---:", "---:", "---:"])


def _inventory(m: Model) -> str:
    lines = ["# Resource Inventory", "", "[← Back to Current Findings](./README.md)", "",
             "Raw data: [resources.json](../05-deep-dive/raw/inventory/resources.json)", ""]
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in m.data.resources:
        groups[(r.get("id") or "").split("/")[4].lower()].append(r)
    for rg in sorted(groups):
        items = [r for r in groups[rg] if (r.get("type") or "").lower() != "microsoft.eventgrid/systemtopics"]
        topics = len(groups[rg]) - len(items)
        lines += [f"## `{rg}`", ""]
        if topics:
            lines += [f"_{topics} Event Grid system topic(s) omitted._", ""]
        lines.append(md_table(["Type", "Name", "Location", "SKU", "Kind", "Created"], [
            [re.sub(r"(?i)^microsoft\.", "", r.get("type") or ""), f"`{r.get('name')}`", r.get("location"),
             " / ".join(str(x) for x in ((r.get("sku") or {}).get("name"), (r.get("sku") or {}).get("tier")) if x),
             r.get("kind"), (r.get("createdTime") or "")[:10]]
            for r in sorted(items, key=lambda r: ((r.get("type") or "").lower(), r.get("name") or ""))
        ]))
        lines.append("")
    return "\n".join(lines)


def render_gap_analysis(m: Model) -> str:
    lines = ["# 02 - Gap Analysis", "", "[← Back to summary](../README.md)", "",
             "Severity: **Critical** = exploitable exposure or major waste, act now; **High** = material risk/cost, "
             "within 30 days; **Medium** = best-practice gap, within the quarter; **Low** = hygiene.", "",
             "## Summary Matrix", "", _area_matrix(m), ""]
    for area in AREAS:
        items = [f for f in m.findings if f["area"] == area]
        if not items:
            continue
        lines += [f"## {area}", ""]
        lines.append(md_table(["Ref", "Severity", "Gap", "Resource", "Recommendation"], [
            [f["ref"], SEV_LABEL[f["severity"]], f"**{f['title']}** - {f['description']}",
             short_id(f.get("resource_id"), m.sub["id"]),
             (f.get("remediation_steps") or "").split("\n")[0]]
            for f in items
        ]))
        lines.append("")
    return "\n".join(lines)


def render_cost_drivers(m: Model) -> Tuple[str, str]:
    cur = m.currency
    amounts = sorted((float((b.get("properties") or {}).get("amount") or 0) for b in (m.data.cost.get("budgets") or [])
                      if ((b.get("properties") or {}).get("timeGrain") or "").lower() == "monthly"), reverse=True)
    amount = amounts[0] if amounts else 0.0
    lines = ["# 03 - Cost Drivers", "", "[← Back to summary](../README.md) · Itemised actions: "
             "[savings-register.md](./savings-register.md)", "",
             f"Source: Cost Management Query API (ActualCost, {cur}). Raw data: "
             "[05-deep-dive/raw/cost](../05-deep-dive/raw/cost).", ""]
    if m.month_keys:
        lines += ["## 1. 12-Month Trend", ""]
        prev = None
        rows = []
        for k in m.month_keys:
            v = m.months[k]
            top_move = ""
            if prev:
                deltas = sorted(((s, sm.get(k, 0) - sm.get(prev, 0)) for s, sm in m.service_months.items()),
                                key=lambda x: -abs(x[1]))
                if deltas and abs(deltas[0][1]) >= 0.1 * (m.months[prev] or 1):
                    top_move = f"{deltas[0][0]} {deltas[0][1]:+,.0f}"
            rows.append([k, money(v, "", 0), pct(v, amount) if amount else "-", top_move])
            prev = k
        rows.append(["**12-month total**", f"**{money(m.total_12m)}**", "", ""])
        lines.append(md_table(["Month", cur, "vs budget" + (f" ({amount:,.0f})" if amount else ""), "Largest change"],
                              rows, ["---", "---:", "---:", "---"]))
        lines += ["", "```mermaid", "xychart-beta", f'  title "Monthly actual cost ({cur})"',
                  "  x-axis [" + ", ".join(k[2:] for k in m.month_keys) + "]",
                  f'  y-axis "{cur}" {min(0, int(min(m.months.values()) * 1.15) - 1)} --> {int(max(m.months.values()) * 1.15) + 1}',
                  "  bar [" + ", ".join(str(int(m.months[k])) for k in m.month_keys) + "]", "```", ""]

    lines += ["## 2. Cost by Service", ""]
    services = sorted(set(m.service_months) | set(m.service_30),
                      key=lambda s: -(sum(m.service_months.get(s, {}).values()) + m.service_30.get(s, 0)))
    lines.append(md_table(["Service", f"12-month {cur}", "Share", f"Last 30 d {cur}", "Share"], [
        [s, money(sum(m.service_months.get(s, {}).values()), "", 0), pct(sum(m.service_months.get(s, {}).values()), m.total_12m),
         money(m.service_30.get(s, 0), "", 2), pct(m.service_30.get(s, 0), m.total_30)]
        for s in services if sum(m.service_months.get(s, {}).values()) + m.service_30.get(s, 0) >= 1
    ], ["---", "---:", "---:", "---:", "---:"]))

    lines += ["", "## 3. Cost by Resource Group (last 30 days)", ""]
    lines.append(md_table(["Resource group", cur, "Main contributors"], [
        [rg, money(sum(sv.values()), "", 2),
         " · ".join(f"{s} {c:,.0f}" for s, c in sorted(sv.items(), key=lambda kv: -kv[1])[:5] if c >= 1)]
        for rg, sv in sorted(m.rg_30.items(), key=lambda kv: -sum(kv[1].values()))
    ], ["---", "---:", "---"]))

    lines += ["", "## 4. Top 15 Cost Line Items (last 30 days)", ""]
    lines.append(md_table(["#", "Resource", "Largest meter", cur], [
        [i, short_id(rid, m.sub["id"]), max((e.get("meters") or {"-": 0}).items(), key=lambda kv: kv[1])[0],
         money(e.get("cost"), "", 2)]
        for i, (rid, e) in enumerate(m.top_resources[:15], 1)
    ], ["---:", "---", "---", "---:"]))

    lines += ["", "## 5. Why the Subscription Costs This Much - Inefficiencies", ""]
    costly = [f for f in m.findings if f.get("estimated_monthly_savings_usd")]
    costly.sort(key=lambda f: -(f.get("estimated_monthly_savings_usd") or 0))
    if costly:
        lines.append(md_table(["Ref", "Inefficiency", "Est. saving / month", "Wave"], [
            [f["ref"], f"**{f['title']}** - {f['description']}", m.savings_label(f["estimated_monthly_savings_usd"]),
             f["wave"]] for f in costly
        ]))
    else:
        lines.append("No finding carries a savings estimate.")
    waves = m.savings_by_wave()
    run_rate = m.run_rate
    lines += ["", "## 6. Forecast", "", md_table(["Scenario", f"Monthly {cur}", f"Annual {cur}"], [
        [f"Status quo ({m.run_rate_label})", money(run_rate), money(run_rate * 12)],
        ["After wave 1", money(run_rate - (m.to_billing(waves[1]) or 0)), money((run_rate - (m.to_billing(waves[1]) or 0)) * 12)],
        ["After waves 1 + 2", money(run_rate - (m.to_billing(waves[1] + waves[2]) or 0)),
         money((run_rate - (m.to_billing(waves[1] + waves[2]) or 0)) * 12)],
    ], ["---", "---:", "---:"])]
    if not m.fx:
        lines += ["", "> USD→billing-currency rate unavailable (CostUSD not returned); forecast ignores savings."]
    return "\n".join(lines), render_savings_register(m)


def render_savings_register(m: Model) -> str:
    lines = ["# Savings Register", "", "[← Back to Cost Drivers](./README.md)", "",
             "Commands are **for review only** - none were executed by the analysis. Run them after owner sign-off.", ""]
    waves = m.savings_by_wave()
    for wave in (WAVE_NO_REGRET, WAVE_OPTIMISE, WAVE_STRUCTURAL):
        items = [f for f in m.findings if f["wave"] == wave]
        if not items:
            continue
        items.sort(key=lambda f: (-(f.get("estimated_monthly_savings_usd") or 0), sev_rank(f["severity"])))
        lines += [f"## {WAVE_NAMES[wave]}", ""]
        lines.append(md_table(["Ref", "Action", "Resource", "Severity", "Monthly impact"], [
            [f["ref"], f["title"], short_id(f.get("resource_id"), m.sub["id"]), SEV_LABEL[f["severity"]],
             m.savings_label(f.get("estimated_monthly_savings_usd"))] for f in items
        ] + [["", f"**Total {WAVE_NAMES[wave].split(' - ')[0].lower()}**", "", "", f"**{m.savings_label(waves[wave])}**"]]))
        scripted = [f for f in items if f.get("azure_cli_script") and f.get("estimated_monthly_savings_usd")][:15]
        if scripted:
            lines += ["", "```bash"]
            for f in scripted:
                lines += [f"# {f['ref']} {f['title']}", f["azure_cli_script"], ""]
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


def render_critique(m: Model) -> str:
    res = m.data.resources
    lines = ["# 04 - Architectural Critique", "", "[← Back to summary](../README.md)", "",
             "> **How \"why\" is determined:** rationale is **inferred** from creation dates, SKUs, tags and naming. "
             "Treat it as a hypothesis to confirm with the workload owners.", "", "## 1. How the Estate Evolved (inferred)", ""]
    by_year: Dict[str, Counter] = defaultdict(Counter)
    first_seen: Dict[str, str] = {}
    for r in sorted(res, key=lambda r: r.get("createdTime") or "9999"):
        t = (r.get("type") or "").lower()
        year = (r.get("createdTime") or "")[:4]
        if not year or t == "microsoft.eventgrid/systemtopics":
            continue
        by_year[year][t.replace("microsoft.", "")] += 1
        first_seen.setdefault(t, year)
    firsts: Dict[str, List[str]] = defaultdict(list)
    for t, y in first_seen.items():
        firsts[y].append(t.replace("microsoft.", ""))
    lines.append(md_table(["Year", "Resources created", "Resource types first introduced"], [
        [y, sum(by_year[y].values()), ", ".join(sorted(firsts.get(y, []))[:10])] for y in sorted(by_year)
    ], ["---", "---:", "---"]))
    lines += ["", "## 2. Decision-by-Decision Critique", ""]

    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in m.findings:
        if f.get("critique"):
            groups[f["critique"]].append(f)
    ordered = sorted(groups.items(), key=lambda kv: (min(sev_rank(f["severity"]) for f in kv[1]),
                                                      -sum(f.get("estimated_monthly_savings_usd") or 0 for f in kv[1])))
    for n, (key, items) in enumerate(ordered, 1):
        c = CRITIQUES[key]
        saving = sum(f.get("estimated_monthly_savings_usd") or 0 for f in items)
        lines += [f"### Decision {n} - {c.title}", "",
                  f"- **What was found:** {len(items)} finding(s)"
                  + (f", {m.savings_label(saving)} per month at stake" if saving else "") + ":"]
        lines += [f"  - {SEV_LABEL[f['severity']]} {f['title']} ({f['ref']})" for f in items[:8]]
        if len(items) > 8:
            lines.append(f"  - … and {len(items) - 8} more (see [gap analysis](../02-gap-analysis/README.md))")
        lines += [f"- **Likely rationale:** {c.likely_rationale}",
                  f"- **Why it falls short:** {c.why_it_falls_short}",
                  "- **What should have been used instead:**"]
        lines += [f"  {i}. {alt}" for i, alt in enumerate(c.alternatives, 1)]
        lines.append("")

    waves = m.savings_by_wave()
    lines += ["## 3. Recommended Target Architecture", "", "```mermaid", "flowchart LR",
              '  AFD["Front Door + WAF"] --> APP["Prod App Service (Pv3, ≥2 instances, reserved)<br/>or Container Apps"]',
              '  APP --> PE["Private endpoints"] --> DATA[("SQL hot data · Storage per env · Key Vault RBAC")]',
              '  DATA -. archive .-> LAKE[("ADLS / Fabric / ADX history")]',
              '  APP --> GW["APIM AI Gateway<br/>token limits · cache · metrics"] --> FDY["Foundry per environment<br/>project per use-case"]',
              '  NP["Non-prod plan / scale-to-zero"] --> GW',
              '  subgraph LZ["Landing-zone subscriptions per workload & environment (IaC-managed)"]',
              "    APP", "    NP", "    DATA", "  end", "```", "",
              md_table(["", f"{m.currency} / month"], [
                  [f"Current ({m.run_rate_label})", money(m.run_rate)],
                  ["After waves 1 + 2 (estimate)", money(m.run_rate - (m.to_billing(waves[1] + waves[2]) or 0))],
              ], ["---", "---:"]), "", "## 4. Roadmap", ""]
    lines.append(md_table(["Phase", "Scope", "Findings", "Exit criteria"], [
        ["0 - Stop the bleeding (2 weeks)", WAVE_NAMES[1], sum(1 for f in m.findings if f["wave"] == 1),
         "All critical findings closed; wave-1 savings realised"],
        ["1 - Separate & govern (1-2 months)", WAVE_NAMES[2], sum(1 for f in m.findings if f["wave"] == 2),
         "Prod/non-prod separated; AI spend attributable; budgets per workload"],
        ["2 - Re-platform (3-6 months)", WAVE_NAMES[3], sum(1 for f in m.findings if f["wave"] == 3),
         "Landing-zone subscriptions via IaC; private data path"],
        ["3 - Commit", "Reservations / savings plan", sum(1 for f in m.findings if f["finding_type"] == "commitment_discount_opportunity"),
         "Commitment coverage of the stabilised baseline"],
    ]))
    return "\n".join(lines)


def render_deep_dives(m: Model) -> Dict[str, str]:
    pages: Dict[str, str] = {}
    index_rows = []
    for folder, title in DEEP_DIVE_FOLDERS.items():
        items = [f for f in m.findings if f["folder"] == folder]
        sev = Counter(f["severity"] for f in items)
        index_rows.append([f"[{folder}](./{folder}/README.md)", title, len(items),
                           ", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev.get(s)) or "-"])
        lines = [f"# Deep Dive - {title}", "", "[← Deep-dive index](../README.md)", ""]
        if not items:
            lines.append("No findings in this area.")
            pages[folder] = "\n".join(lines)
            continue
        lines.append(md_table(["Ref", "Severity", "Finding", "Resource", "Monthly impact"], [
            [f"[{f['ref']}](#{f['ref'].lower()})", SEV_LABEL[f["severity"]], f["title"],
             short_id(f.get("resource_id"), m.sub["id"]), m.savings_label(f.get("estimated_monthly_savings_usd"))]
            for f in items
        ]))
        lines.append("")
        for f in items:
            lines += [f"## {f['ref']}", "", f"**{f['title']}** - {SEV_LABEL[f['severity']]} · `{f['finding_type']}` · "
                      f"scanner `{f['scanner']}`", "", f.get("description") or "", "",
                      f"- Resource: `{f.get('resource_id')}`"]
            for label, key in (("CAF", "caf_control"), ("CIS", "cis_control"), ("NIST", "nist_control")):
                if f.get(key):
                    lines.append(f"- {label}: {f[key]}")
            if f.get("remediation_steps"):
                lines += ["", "**Remediation**", "", f["remediation_steps"]]
            if f.get("azure_cli_script"):
                lines += ["", "```bash", f["azure_cli_script"], "```"]
            if f.get("evidence"):
                evidence = json.dumps(f["evidence"], indent=2, default=str)
                if len(evidence) > 3000:
                    evidence = evidence[:3000] + "\n… (truncated - see raw/findings.json)"
                lines += ["", "<details><summary>Evidence</summary>", "", "```json", evidence, "```", "", "</details>"]
            lines.append("")
        pages[folder] = "\n".join(lines)

    runs = m.data.scanner_runs
    index = ["# 05 - Deep-Dive Details", "", "[← Back to summary](../README.md)", "",
             md_table(["Sub-folder", "Scope", "Findings", "By severity"], index_rows, ["---", "---", "---:", "---"]), "",
             "## Raw Evidence (`raw/`)", "",
             md_table(["File", "Content"], [
                 ["[inventory/resources.json](./raw/inventory/resources.json)", "ARM resource list with created/changed time"],
                 ["[inventory/resource-groups.json](./raw/inventory/resource-groups.json)", "Resource groups"],
                 ["[findings.json](./raw/findings.json)", "Every finding with evidence and scripts"],
                 ["[scanner-runs.json](./raw/scanner-runs.json)", "Scanner status, counts and warnings"],
                 ["[cost/](./raw/cost)", "Cost Management datasets and budgets"],
             ]), "",
             "## Scanner Runs", "",
             md_table(["Scanner", "Status", "Resources scanned", "Findings", "Warnings"], [
                 [r["scanner"], r["status"], r.get("resources_scanned", ""), r["findings"],
                  len(r.get("warnings") or []) or ""] for r in runs
             ], ["---", "---", "---:", "---:", "---:"]), "",
             "> The raw files contain resource IDs, IP addresses and principal IDs - treat them as internal. "
             "No secrets, keys or connection strings are collected."]
    if m.data.warnings:
        index += ["", "## Collection Warnings", ""] + [f"- {w}" for w in m.data.warnings[:50]]
    pages["__index__"] = "\n".join(index)
    return pages


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def write_report(data: AnalysisData, output: Path) -> Model:
    m = Model(data)
    output.mkdir(parents=True, exist_ok=True)
    write(output / "README.md", render_readme(m))
    current, inventory = render_current_findings(m)
    write(output / "01-current-findings" / "README.md", current)
    write(output / "01-current-findings" / "resource-inventory.md", inventory)
    write(output / "02-gap-analysis" / "README.md", render_gap_analysis(m))
    cost, register = render_cost_drivers(m)
    write(output / "03-cost-drivers" / "README.md", cost)
    write(output / "03-cost-drivers" / "savings-register.md", register)
    write(output / "04-architectural-critique" / "README.md", render_critique(m))
    for folder, page in render_deep_dives(m).items():
        write(output / "05-deep-dive" / ("README.md" if folder == "__index__" else f"{folder}/README.md"), page)

    raw = output / "05-deep-dive" / "raw"

    def dump(rel: str, obj: Any) -> None:
        write(raw / rel, json.dumps(to_jsonable(obj), indent=2, default=str))

    dump("inventory/resources.json", data.resources)
    dump("inventory/resource-groups.json", data.resource_groups)
    dump("findings.json", m.findings)
    dump("scanner-runs.json", data.scanner_runs)
    for key, value in data.cost.items():
        dump(f"cost/{key}.json", value)
    dump("metadata.json", {"subscription": data.subscription, "generated_at": data.generated_at,
                           "generator": "scripts.subscription_analysis", "warnings": data.warnings,
                           "report_generated": datetime.now(timezone.utc).isoformat()})
    write(output / SUMMARY_FILE, json.dumps(to_jsonable(summarize(m)), indent=2, default=str))
    return m


# ---------------------------------------------------------------------------
# Multi-subscription layout: reports/<subscription>/... + reports/README.md
# ---------------------------------------------------------------------------

SUMMARY_FILE = "summary.json"
GENERATED_ENTRIES = ("README.md", SUMMARY_FILE, "01-current-findings", "02-gap-analysis", "03-cost-drivers",
                     "04-architectural-critique", "05-deep-dive",
                     "report-summary.html", "report-summary.pdf", "report-full.html", "report-full.pdf")


OWNER_FILE = ".subscription-id"
_FOLDER_LOCK = threading.Lock()


def report_folder_name(subscription: Dict[str, Any]) -> str:
    """Folder name for a subscription's report: its display name made filesystem-safe (falls back to the ID)."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", subscription.get("name") or subscription["id"]).strip("._") or subscription["id"]


def _folder_owner(folder: Path) -> Optional[str]:
    """Subscription ID a report folder belongs to (owner marker, else its summary.json), or None if unclaimed."""
    marker = folder / OWNER_FILE
    if marker.is_file():
        return marker.read_text(encoding="utf-8").strip().lower() or None
    summary = folder / SUMMARY_FILE
    if summary.is_file():
        try:
            return ((json.loads(summary.read_text(encoding="utf-8")).get("subscription") or {}).get("id") or "").lower() or None
        except ValueError:
            return None
    return None


def resolve_report_folder(reports_dir: Path, subscription: Dict[str, Any]) -> Path:
    """
    reports_dir/<name>, unless that folder belongs to another subscription with the same display name
    (e.g. several "Visual Studio Professional Subscription"s) - then reports_dir/<name>_<first 8 of ID>.
    The folder is claimed with an owner marker so concurrent runs never share it.
    """
    sub_id = str(subscription["id"]).lower()
    base = report_folder_name(subscription)
    with _FOLDER_LOCK:
        for candidate in (reports_dir / base, reports_dir / f"{base}_{sub_id[:8]}", reports_dir / f"{base}_{sub_id}"):
            owner = _folder_owner(candidate)
            if owner in (None, sub_id):
                candidate.mkdir(parents=True, exist_ok=True)
                (candidate / OWNER_FILE).write_text(sub_id, encoding="utf-8")
                return candidate
    raise RuntimeError(f"No free report folder for subscription {sub_id}")


def display_names(summaries: List[Dict[str, Any]]) -> Dict[str, str]:
    """folder -> label; subscriptions sharing a display name get their short ID appended."""
    names = Counter((s.get("subscription") or {}).get("name") or s["folder"] for s in summaries)
    labels = {}
    for s in summaries:
        sub = s.get("subscription") or {}
        name = sub.get("name") or s["folder"]
        labels[s["folder"]] = f"{name} ({str(sub.get('id', ''))[:8]})" if names[name] > 1 and sub.get("id") else name
    return labels


def clean_generated(output: Path) -> None:
    """Remove files a previous run generated, so a re-run never leaves stale pages behind."""
    for entry in GENERATED_ENTRIES:
        target = output / entry
        if target.is_dir():
            shutil.rmtree(target)
        elif target.is_file():
            target.unlink()


def summarize(m: Model) -> Dict[str, Any]:
    waves = m.savings_by_wave()
    sev = Counter(f["severity"] for f in m.findings)
    return {
        "subscription": m.sub,
        "generated_at": m.data.generated_at,
        "resources": len(m.data.resources),
        "resource_groups": len(m.data.resource_groups),
        "findings": len(m.findings),
        "findings_by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
        "currency": m.currency,
        "cost_12m": round(m.total_12m, 2),
        "cost_30d": round(m.total_30, 2),
        "savings_usd": {"wave_1": round(waves[1], 2), "wave_2": round(waves[2], 2)},
        "savings_billing": {"wave_1": _round(m.to_billing(waves[1])), "wave_2": _round(m.to_billing(waves[2]))},
    }


def _round(value: Optional[float]) -> Optional[float]:
    return round(value, 2) if value is not None else None


def read_summaries(reports_dir: Path) -> List[Dict[str, Any]]:
    summaries = []
    if not reports_dir.is_dir():
        return summaries
    for child in sorted(p for p in reports_dir.iterdir() if p.is_dir()):
        path = child / SUMMARY_FILE
        if path.is_file():
            try:
                summary = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            summary["folder"] = child.name
            summaries.append(summary)
    return summaries


def write_index(reports_dir: Path) -> Path:
    """reports/README.md - one row per analysed subscription, linking into its folder."""
    rows = []
    summaries = read_summaries(reports_dir)
    labels = display_names(summaries)
    for s in summaries:
        sev = s.get("findings_by_severity") or {}
        saving = s.get("savings_billing") or {}
        cur = s.get("currency") or ""
        total_saving = (saving.get("wave_1") or 0) + (saving.get("wave_2") or 0) if saving.get("wave_1") is not None else None
        rows.append([
            f"[{labels[s['folder']]}](./{s['folder']}/README.md)",
            f"`{(s.get('subscription') or {}).get('id', '')}`",
            str(s.get("generated_at") or "")[:10],
            s.get("resources"),
            f"{sev.get('critical', 0)} / {sev.get('high', 0)}",
            money(s.get("cost_30d"), cur),
            money(total_saving, cur) if total_saving is not None else "n/a",
        ])
    content = "\n".join([
        "# Subscription Analysis Reports", "",
        "One folder per subscription (`<subscription>/README.md` → `01-…` to `05-…`). "
        "Generated by `python -m scripts.subscription_analysis` or the local portal (`python -m scripts.local_portal`).", "",
        md_table(["Subscription", "ID", "Analysed", "Resources", "Critical / High", "Last 30 days", "Est. savings / month"],
                 rows, ["---", "---", "---", "---:", "---:", "---:", "---:"]) if rows else "_No reports yet._",
    ])
    path = reports_dir / "README.md"
    write(path, content)
    return path
