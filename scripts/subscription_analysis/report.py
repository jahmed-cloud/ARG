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

from scanners.base.providers import STATUS_ORDER
from scripts.subscription_analysis import insights
from scripts.subscription_analysis.ai_prompt import PROMPT_FILE, build_prompt
from scripts.subscription_analysis.collector import AnalysisData, to_jsonable
from scripts.subscription_analysis.currency import localise_amounts
from scripts.subscription_analysis.estate import ESTATE_DIR, HYGIENE_TYPES, config_of, os_of, size_of, state_of
from scripts.subscription_analysis import reasoning, thinking
from scripts.subscription_analysis.guidance import (
    cost_summary,
    effort_label,
    implementation_analysis,
    story_points,
    total_effort_label,
)
from scripts.subscription_analysis.knowledge import (
    AREAS,
    CRITIQUES,
    DEEP_DIVE_FOLDERS,
    DEEP_DIVE_RESOURCE_TYPES,
    WAVE_NAMES,
    WAVE_NO_REGRET,
    WAVE_OPTIMISE,
    WAVE_STRUCTURAL,
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
WORKLOAD_TAG_KEYS = ("projectname", "project", "application", "workload")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

BLANK_CELLS = ("", "-", "n/a")


def md_table(headers: List[str], rows: Iterable[Iterable[Any]], align: Optional[List[str]] = None,
             drop_empty: bool = False) -> str:
    """Markdown table. drop_empty removes columns (other than the first) that are blank in every row."""
    rows = [[_cell(c) for c in r] for r in rows]
    align = align or ["---"] * len(headers)
    if drop_empty and rows:
        keep = [i for i in range(len(headers)) if i == 0 or any(r[i] not in BLANK_CELLS for r in rows if i < len(r))]
        headers, align = [headers[i] for i in keep], [align[i] for i in keep]
        rows = [[r[i] for i in keep] for r in rows]
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

    def __init__(self, data: AnalysisData, previous_findings: Optional[List[Dict[str, Any]]] = None):
        self.data = data
        self.previous_findings = previous_findings
        self.history: List[Dict[str, Any]] = []   # earlier analyses of this subscription (history.json)
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
        self._implementation()

    # implementation analysis ---------------------------------------------

    def _implementation(self) -> None:
        """Why / when not / cost of implementation / references for every finding (guidance.py)."""
        rate = (self.data.settings or {}).get("engineering_hourly_rate_usd")
        per_resource = self.data.cost.get("last30_by_resource") or {}
        for f in self.findings:
            entry = per_resource.get((f.get("resource_id") or "").lower()) or {}
            usd = entry.get("cost_usd")
            if usd is None and entry.get("cost") is not None and self.fx:
                usd = entry["cost"] / self.fx
            f["implementation"] = implementation_analysis(f, resource_monthly_usd=usd, hourly_rate_usd=rate)
        by_resource: Dict[str, List[str]] = defaultdict(list)
        for f in self.findings:
            if f.get("resource_id"):
                by_resource[f["resource_id"].lower()].append(f["title"])
        for f in self.findings:
            related = [t for t in by_resource.get((f.get("resource_id") or "").lower(), []) if t != f["title"]]
            f["reasoning"] = reasoning.reason(f, related, f["implementation"])

    def implementation_totals(self, findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        items = [f["implementation"] for f in (self.findings if findings is None else findings)]
        hours = [i["hours"] for i in items if i.get("hours")]
        extra = [i["monthly_usd"] for i in items if i.get("monthly_usd")]
        one_off = [i["one_off_usd"] for i in items if i.get("one_off_usd")]
        return {"monthly_usd": round(sum(extra), 2), "with_run_cost": len(extra),
                "usage_based": sum(1 for i in items if i.get("monthly_usd") is None),
                "hours": [round(sum(h[0] for h in hours), 1), round(sum(h[1] for h in hours), 1)],
                "one_off_usd": [sum(o[0] for o in one_off), sum(o[1] for o in one_off)] if one_off else None}

    def usd_label(self, usd: Optional[float]) -> str:
        """Like savings_label, but 0 is a real value ('0') and None means usage-based."""
        if usd is None:
            return "usage-based"
        return "0" if not usd else self.savings_label(usd)

    def subscription_label(self) -> str:
        return f"{self.sub.get('name') or self.sub['id']} (`{self.sub['id']}`)"

    # architect views (insights.py) ----------------------------------------

    @property
    def actionable(self) -> List[Dict[str, Any]]:
        return [f for f in self.findings if not insights.is_hygiene(f)]

    @property
    def hygiene(self) -> List[Dict[str, Any]]:
        return [f for f in self.findings if insights.is_hygiene(f)]

    def systemic(self) -> List[Dict[str, Any]]:
        return insights.systemic_issues(self.findings, self.data.resources)

    def allocation(self) -> Optional[Dict[str, Any]]:
        tags = (self.data.settings or {}).get("required_tags") or []
        return insights.allocation(self.data.resources, self.data.cost.get("last30_by_resource") or {}, tags) \
            if tags else None

    def environments(self) -> Dict[str, float]:
        return insights.environment_split(self.data.resources, self.data.cost.get("last30_by_resource") or {},
                                          self.sub.get("name") or "")

    def coverage(self) -> Dict[str, Any]:
        return insights.cost_coverage(self.top_resources, self.findings, self.total_30)

    def delta(self) -> Optional[Dict[str, Any]]:
        return insights.changes(self.previous_findings, self.findings)

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
        # Invoiced (actual) monthly totals: budgets are evaluated on these, not on the amortized basis above.
        self.months_actual: Dict[str, float] = defaultdict(float)
        for r in self.data.cost.get("monthly_actual") or []:
            month = str(r.get("BillingMonth") or r.get("UsageDate") or "")[:7]
            if len(month) == 8 and month.isdigit():
                month = f"{month[:4]}-{month[4:6]}"
            self.months_actual[month] += float(r.get("Cost") or 0)
        self.total_12m_actual = sum(self.months_actual.values()) if self.months_actual else None

    @property
    def amortized(self) -> bool:
        return (self.data.cost.get("cost_basis") or "ActualCost") == "AmortizedCost"

    @property
    def cost_basis_label(self) -> str:
        return "amortized cost" if self.amortized else "actual cost"

    def subscription_budgets(self) -> List[Dict[str, Any]]:
        """Budgets that cover the whole subscription without a filter - the only ones comparable to its total.
        Resource-group and filtered budgets are evaluated on their own scope by budget_scanner."""
        sub_scope = f"/subscriptions/{self.sub.get('id') or ''}".lower()
        return [b for b in (self.data.cost.get("budgets") or [])
                if str(b.get("id") or sub_scope).lower().split("/providers/microsoft.consumption/")[0] == sub_scope
                and not (b.get("properties") or {}).get("filter")]

    def budget_month_cost(self, month: str) -> float:
        """Budgets track invoiced cost: the actual month when known, else the report's own basis."""
        return self.months_actual[month] if self.months_actual else self.months.get(month, 0.0)

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

    @property
    def has_cost_data(self) -> bool:
        return bool(self.data.cost.get("last30_by_resource") or self.total_30 or self.total_12m)

    def cost30(self, resource_id: Optional[str]) -> str:
        """30-day cost of one resource: the amount, 0.00 when it had no charge, '-' without cost data."""
        entry = (self.data.cost.get("last30_by_resource") or {}).get((resource_id or "").lower()) or {}
        if entry.get("cost") is not None:
            return money(entry["cost"], "", 2)
        if "/providers/microsoft.consumption/" in (resource_id or "").lower():
            return "-"  # budgets and other Cost Management objects are not billed
        return "0.00" if resource_id and self.has_cost_data else "-"

    def impact_label(self, f: Dict[str, Any]) -> str:
        """The saving when there is one, else what kind of improvement it is (security, resilience, ...)."""
        usd = f.get("estimated_monthly_savings_usd")
        return self.savings_label(usd) if usd else (f.get("area") or "-").split(" / ")[0].split(" & ")[0]

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

    def localise(self, text: str) -> str:
        """A page in the subscription's billing currency at its amortized 30-day rate - unless the display_currency
        setting asks for USD (then the billing amount and its USD equivalent both stay)."""
        if (self.data.settings or {}).get("display_currency") == "USD":
            return text
        return localise_amounts(text, self.fx, self.currency)

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
    waves = m.savings_by_wave()
    top_services = sorted(m.service_30.items(), key=lambda kv: -kv[1])[:3]
    risks = [f for f in m.findings if f["severity"] in ("critical", "high") and f["area"] != AREAS[4]][:8]
    budgets = [b for b in m.subscription_budgets()
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
            ["Billing currency", f"{cur}" + (". Savings estimates are computed in USD and converted at the "
                                             "subscription's implied rate" if m.fx and cur != "USD" else "")],
            ["Cost basis", ("Amortized cost: reservation and savings-plan purchases are spread over the resources that "
                            "use them, so covered VMs and databases show their real share"
                            + (f"; invoiced (actual) cost over the same 12 months: {money(m.total_12m_actual, cur)}"
                               if m.total_12m_actual is not None else "")) if m.amortized else "Actual (invoiced) cost"],
            ["Method", "Azure Resource Guardian scanners (Resource Graph, ARM, Azure Monitor metrics, Cost Management, "
                       "Defender for Cloud, Advisor), read-only"],
        ]), "",
        "## Executive Summary", "",
        f"- **Resources:** {len(m.data.resources)} in {len(m.data.resource_groups)} resource groups, "
        f"{len({(r.get('location') or '').lower() for r in m.data.resources})} regions.",
        f"- **Cost ({m.cost_basis_label}):** {money(m.total_12m, cur)} over 12 months; {money(m.total_30, cur)} in the "
        f"last 30 days"
        + (f"; {m.trend_summary()}." if first else "."),
    ]
    if budget_amount:
        over = sum(1 for k in m.month_keys if m.budget_month_cost(k) > budget_amount)
        label = " / ".join(money(a) for a in amounts) + f" {cur}/month"
        lines.append(f"- **Budget{'s' if len(amounts) > 1 else ''}:** {label} - "
                     f"{'the largest ' if len(amounts) > 1 else ''}exceeded in {over} of {len(m.month_keys)} months"
                     + (" (actual, invoiced cost - what budgets track)." if m.months_actual else "."))
    actionable, hygiene = m.actionable, m.hygiene
    systemic_actionable = [x for x in m.systemic() if not x["hygiene"]]
    act_sev = Counter(f["severity"] for f in actionable)
    merged = m.data.correlation or {}
    lines.append(f"- **Findings:** {len(actionable)} actionable - " + (", ".join(
        f"{act_sev.get(s, 0)} {s}" for s in SEVERITIES if act_sev.get(s)) or "none")
        + (f" ({sum(x['count'] for x in systemic_actionable)} of them in {len(systemic_actionable)} systemic "
           f"issue(s) - one guardrail each, see [Systemic issues](#systemic-issues---fix-once-not-per-resource))"
           if systemic_actionable else "")
        + (f"; plus {len(hygiene)} tag / naming hygiene items, summarised below as cost allocation"
           if hygiene else "")
        + (f"; {merged.get('defender_recommendations_merged', 0) + merged.get('advisor_items_merged', 0)} "
           f"Defender / Advisor items merged into the matching ARG findings"
           if merged.get("defender_recommendations_merged") or merged.get("advisor_items_merged") else "") + ".")
    delta = m.delta()
    if delta is not None:
        lines.append(f"- **Since the previous analysis:** {len(delta['new'])} new, {len(delta['resolved'])} resolved"
                     + (f", {len(delta['worse'])} rated worse" if delta["worse"] else "")
                     + " - see [Changes](#changes-since-the-previous-analysis).")
    if m.total_30 and m.fx:
        saving_billing = m.to_billing(waves[1] + waves[2]) or 0
        lines.append(f"- **Savings identified:** {m.savings_label(waves[1] + waves[2])} per month, "
                     f"{pct(saving_billing, m.total_30)} of the last 30 days' spend (waves 1 + 2).")
    coverage = m.coverage()
    if coverage["rows"]:
        lines.append(f"- **Where the money is:** the {len(coverage['rows'])} costliest resources carry "
                     f"{coverage['top_share']:.0%} of the spend; "
                     + (f"**{coverage['uncovered_share']:.0%} ({money(coverage['uncovered_cost'], cur)}) sits in "
                        f"resources no finding addresses** - they need a design review, see "
                        f"[the table below](#where-the-money-is)." if coverage["uncovered_cost"] else
                        "every one of them has at least one recommendation."))
    alloc = m.allocation()
    if alloc:
        worst = next(iter(alloc["missing_by_tag"].items()), None)
        lines.append(f"- **Cost allocation:** {alloc['share']:.0%} of the spend is on resources carrying every "
                     f"required tag ({', '.join(alloc['required_tags'])})"
                     + (f"; the most-missed tag is '{worst[0]}' on {money(worst[1], cur)} of spend" if worst and worst[1]
                        else "") + "."
                     + (f" The required tags may not be the company standard - the tags used most here are "
                        f"{', '.join(alloc['tags_in_use'])}; set the standard in Settings (`required_tags`)."
                        if alloc["share"] < 0.05 and alloc["tags_in_use"] else ""))
    envs = {k: v for k, v in m.environments().items() if v}
    if len(envs) > 1 or (envs and "Unknown" not in envs):
        lines.append("- **By environment:** " + ", ".join(f"{k} {money(v, cur)} ({pct(v, m.total_30)})"
                                                         for k, v in envs.items()) + ".")
    resilience = insights.resilience(m.data.reliability or [], m.data.resources, sub.get("name") or "")
    zone = sum(g["production"] for g in resilience if g["sub_category"] == "ZoneResiliency")
    backup = sum(g["production"] for g in resilience if g["sub_category"] in ("DataProtectionAndRecovery",
                                                                               "RegionalResiliency"))
    if zone or backup:
        lines.append(f"- **Resilience (production):** {zone} zone-redundancy gap(s) and {backup} backup / "
                     f"geo-redundancy gap(s) reported by Azure Advisor - see "
                     f"[resilience posture](./01-current-findings/README.md#8-resilience-posture-azure-advisor).")
    calendar = insights.retirement_calendar(m.findings)
    if calendar:
        overdue = sum(1 for r in calendar if r["days_left"] is not None and r["days_left"] < 0)
        soon = sum(1 for r in calendar if r["days_left"] is not None and 0 <= r["days_left"] <= 90)
        lines.append(f"- **Retirements:** {len(calendar)} dated retirement / end-of-support item(s) - "
                     f"{overdue} overdue, {soon} within 90 days (see [calendar](#retirement-calendar)).")
    planned = [f for f in m.findings if f["wave"] in (WAVE_NO_REGRET, WAVE_OPTIMISE) and not insights.is_hygiene(f)]
    structural = [f for f in m.findings if f["wave"] == WAVE_STRUCTURAL]
    if planned:
        totals = m.implementation_totals(planned)
        lines.append(
            "- **Cost of implementing waves 1 + 2 (estimate):** "
            + (f"{m.savings_label(totals['monthly_usd'])} per month of additional Azure run cost "
               f"({totals['with_run_cost']} finding(s), e.g. private endpoints, gateways)"
               if totals["monthly_usd"] else "no additional Azure run cost for the estimated items")
            + (f", {totals['usage_based']} with usage-based cost" if totals["usage_based"] else "")
            + f"; effort about {total_effort_label(f['implementation'].get('hours') for f in planned)}"
            + (f" (≈ USD {totals['one_off_usd'][0]:,}-{totals['one_off_usd'][1]:,} one-off)"
               if totals["one_off_usd"] else "")
            + ". Per finding: why it is needed, when it is not, cost and references in the "
              "[deep dives](./05-deep-dive/README.md).")
    lines += _spend_to_fix_lines(m)
    ai = m.data.thinking or {}
    if ai.get("status") == "ok":
        challenged = sum(1 for f in m.findings if (f.get("ai_review") or {}).get("agree") is False)
        lines.append(f"- **AI review ({ai.get('model')}):** {ai.get('summary')} {len(ai.get('themes') or [])} "
                     f"theme(s); {challenged} recommendation(s) challenged - "
                     f"[thinking mode](./05-deep-dive/thinking.md).")
    elif ai.get("status") == "error":
        lines.append(f"- **AI review did not run:** {ai.get('reason')} - the built-in reasoning is in every "
                     f"finding.")
    if structural:
        effort = total_effort_label((f.get("implementation") or {}).get("hours") for f in structural)
        lines.append(f"- **Wave 3 (structural, {len(structural)} findings)** is project work of its own"
                     + (f" - about {effort} if all were done" if effort else "")
                     + "; plan it per decision in the "
                       "[architectural critique](./04-architectural-critique/README.md).")
    defender = m.data.defender or {}
    if defender.get("recommendations") and not _defender_imported(m):
        sev = defender.get("by_severity") or {}
        top = defender["recommendations"][:3]
        lines.append(f"- **Defender for Cloud:** {len(defender['recommendations'])} open recommendation(s) - "
                     + ", ".join(f"{sev[s]} {s.lower()}" for s in ("High", "Medium", "Low") if sev.get(s))
                     + "; top: " + "; ".join(f"{t['recommendation'].rstrip('.')} ({t['resources']})" for t in top)
                     + f". Work through them in [Defender for Cloud]({defender.get('portal')}) (exemptions, owners, due "
                       f"dates live there) - summary in the "
                       f"[security deep dive](./05-deep-dive/security-identity/README.md#defender-for-cloud-summary).")
    excluded = _excluded_defender_plans(m) or ([None] * int(defender.get("plan_upsells_left_out") or 0))
    if excluded:
        example = next((e for e in excluded if e), "Microsoft Defender CSPM should be enabled")
        lines.append(f"- **Not included:** {len(excluded)} Defender for Cloud plan-enablement recommendation(s) "
                     f"(paid-plan upsells such as \"{example}\") - plan choice is a central cost decision; "
                     f"switch them on with the `defender_plan_recommendations` setting.")
    lines += ["", "**Why it costs this much (last 30 days, by service):**", "",
              md_table(["#", "Service", f"{cur}", "Share"],
                       [[i, s, money(c, "", 2), pct(c, m.total_30)] for i, (s, c) in enumerate(top_services, 1)],
                       ["---:", "---", "---:", "---:"]), ""]
    if coverage["rows"]:
        lines += ["### Where the money is", "",
                  "The costliest resources and what addresses them. A resource with no recommendation is not "
                  "necessarily efficient - ARG has no analyser for it; review its sizing, tier and retention with "
                  "the owner.", "",
                  md_table(["#", "Resource", "Main meter", f"30 d {cur}", "Share", "Addressed by"], [
                      [i, _short_resource(r["resource_id"]), r["meter"], money(r["cost"], "", 0),
                       pct(r["cost"], m.total_30),
                       (", ".join(f"[{ref}](./05-deep-dive/{_folder_of(m, ref)}/README.md#{ref.lower()})"
                                  for ref in r["findings"][:4])
                        + (f" (saving {m.savings_label(r['saving_usd'])})" if r["saving_usd"] else ""))
                       if r["findings"] else "**No recommendation - design review**"]
                      for i, r in enumerate(coverage["rows"], 1)],
                      ["---:", "---", "---", "---:", "---:", "---"]), ""]
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
    lines += _systemic_lines(m) + _quick_win_lines(m) + _calendar_lines(m, calendar) + _delta_lines(m, delta)
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
            [f"[{BACKLOG_FILE}](./{BACKLOG_FILE})", "Azure Boards import (Boards → Queries → Import work items): one "
                                                    "task per systemic issue and per actionable finding, with why, "
                                                    "cost, steps, references and a done-when"],
        ]), "",
        "## Prioritised Action List", "",
    ]
    actions = sorted(m.actionable, key=lambda f: (f["wave"], sev_rank(f["severity"]),
                                                  -(f.get("estimated_monthly_savings_usd") or 0)))[:12]
    lines.append(md_table(["Ref", "Wave", "Severity", "Action", "Impact", "Cost to implement"],
                          [[f"[{f['ref']}](./05-deep-dive/{f['folder']}/README.md#{f['ref'].lower()})", f["wave"],
                            SEV_LABEL[f["severity"]], f["title"], m.impact_label(f),
                            cost_summary(f["implementation"])]
                           for f in actions]))
    lines += ["", "> Generated by `python -m scripts.subscription_analysis`. Evidence for every finding is in "
                  "[05-deep-dive/raw](./05-deep-dive/raw). Estimates are marked as such in the finding text.",
              "", f"_{BRAND_CREDIT}._"]
    return "\n".join(lines)


def _short_resource(resource_id: str) -> str:
    """'…/providers/microsoft.kusto/clusters/adx1' -> 'adx1 (kusto/clusters, rg)'."""
    parts = (resource_id or "").split("/")
    lowered = [p.lower() for p in parts]
    if "providers" not in lowered:
        return resource_id or "-"
    i = lowered.index("providers")
    rtype = "/".join(lowered[i + 1:i + 3]).replace("microsoft.", "")
    rg = parts[lowered.index("resourcegroups") + 1] if "resourcegroups" in lowered else ""
    return f"`{parts[-1]}` ({rtype}" + (f", {rg})" if rg else ")")


def _folder_of(m: Model, ref: str) -> str:
    return next((f["folder"] for f in m.findings if f.get("ref") == ref), "")


def _ref_link(m: Model, f: Dict[str, Any], prefix: str = "./") -> str:
    return f"[{f['ref']}]({prefix}05-deep-dive/{f['folder']}/README.md#{f['ref'].lower()})"


def _systemic_lines(m: Model) -> List[str]:
    systemic = m.systemic()
    if not systemic:
        return []
    rows = []
    for s in systemic:
        refs = s["refs"]
        span = f"{refs[0]} … {refs[-1]}" if len(refs) > 1 else refs[0]
        rows.append([f"**{s['label']}**" + (" (hygiene)" if s["hygiene"] else ""), s["count"],
                     f"{s['share']:.0%} of {s['population']}", SEV_LABEL[s["severity"]],
                     "<br>".join(s["guardrails"]) or "Fix in the IaC module / landing-zone template", span])
    return ["## Systemic issues - fix once, not per resource", "",
            "The same gap on many resources is a platform default, not an individual mistake. Fix the template "
            "(IaC module, landing-zone policy) and let Azure Policy keep it fixed: assign the guardrail at the "
            "management group in **Audit** first, remediate the existing resources (Modify / DeployIfNotExists "
            "policies do it with a remediation task), then switch to **Deny** for new ones.", "",
            md_table(["Issue", "Resources", "Share", "Severity", "Guardrail (built-in Azure Policy)", "Findings"], rows,
                     ["---", "---:", "---:", "---", "---", "---"]), ""]


def _quick_win_lines(m: Model) -> List[str]:
    wins = insights.quick_wins(m.findings)
    if not wins:
        return []
    return ["## Quick wins - an hour or less each, no extra run cost", "",
            md_table(["Ref", "Severity", "Action", "Impact", "Effort"], [
                [_ref_link(m, f), SEV_LABEL[f["severity"]], f["title"], m.impact_label(f),
                 cost_summary(f["implementation"])] for f in wins]), ""]


def _calendar_lines(m: Model, calendar: List[Dict[str, Any]]) -> List[str]:
    rows = [r for r in calendar if r["days_left"] is None or r["days_left"] <= 365][:20]
    later = [r for r in calendar if r["days_left"] is not None and r["days_left"] > 365]
    if not rows and not later:
        return []

    def when(r: Dict[str, Any]) -> str:
        if r["days_left"] is None:
            return "date not announced"
        return "**overdue**" if r["days_left"] < 0 else f"{r['days_left']} days"

    def affected(r: Dict[str, Any]) -> str:
        names = [n for n in r["resources"] if n]
        return f"{len(names)}: " + ", ".join(names[:3]) + (", …" if len(names) > 3 else "") if len(names) > 1 \
            else (names[0] if names else "-")

    def refs(r: Dict[str, Any]) -> str:
        return r["refs"][0] if len(r["refs"]) == 1 else f"{r['refs'][0]} … ({len(r['refs'])})" if r["refs"] else ""

    out = ["## Retirement calendar", "",
           "Retirements and end-of-support that affect this subscription, soonest first: overdue and the next 12 "
           "months (Azure Advisor's dated retirements and ARG's own end-of-support checks; undated Advisor upgrade "
           "advice is left out).", ""]
    if rows:
        out += [md_table(["Date", "In", "What retires", "Resources", "Findings", "Cost implication"], [
            [r["date"] or "-", when(r), r["what"], affected(r), refs(r), r["cost"] or ""] for r in rows],
            ["---", "---", "---", "---", "---", "---"], drop_empty=True), ""]
    if later:
        out += ["Later: " + "; ".join(f"{r['date']} {r['what']} ({len(r['resources'])})" for r in later[:8])
                + (" …" if len(later) > 8 else "") + ".", ""]
    return out


def _delta_lines(m: Model, delta: Optional[Dict[str, Any]]) -> List[str]:
    if delta is None:
        return []
    out = ["## Changes since the previous analysis", ""]
    if m.history:
        waves = m.savings_by_wave()
        act = Counter(f["severity"] for f in m.actionable)
        runs = m.history[-5:] + [{"date": f"{m.data.generated_at:%Y-%m-%d %H:%M} (this run)",
                                  "actionable": len(m.actionable), "critical": act.get("critical", 0),
                                  "high": act.get("high", 0), "cost_30d": m.total_30,
                                  "savings_usd": waves[1] + waves[2]}]
        out += [md_table(["Analysis", "Actionable", "Critical / High", f"Last 30 d {m.currency}", "Savings / month"], [
            [r.get("date"), r.get("actionable", "-"), f"{r.get('critical', 0)} / {r.get('high', 0)}",
             money(r.get("cost_30d")), m.savings_label(r.get("savings_usd"))] for r in runs],
            ["---", "---:", "---:", "---:", "---:"]), ""]
    if not (delta["new"] or delta["resolved"] or delta["worse"]):
        return out + ["No finding appeared, disappeared or changed severity.", ""]

    def table(items: List[Dict[str, Any]], resolved: bool = False) -> str:
        return md_table(["Ref" if not resolved else "Was", "Severity", "Finding", "Saving / month"], [
            [f.get("ref") or "-", SEV_LABEL.get(f["severity"], f["severity"]), f["title"],
             m.savings_label(f.get("estimated_monthly_savings_usd"))] for f in items[:15]])

    if delta["new"]:
        out += [f"**New ({len(delta['new'])})**", "", table(delta["new"]), ""]
    if delta["resolved"]:
        out += [f"**Resolved or no longer reported ({len(delta['resolved'])})**", "", table(delta["resolved"], True), ""]
    if delta["worse"]:
        out += [f"**Rated worse ({len(delta['worse'])})**", "", table(delta["worse"]), ""]
    return out


def _defender_imported(m: Model) -> bool:
    """True when the Defender recommendations scanner ran (setting on), i.e. they are findings too."""
    run = next((r for r in m.data.scanner_runs if r.get("scanner") == "defender_recommendations_scanner"), None)
    return bool(run) and run.get("status") == "completed"


def _excluded_defender_plans(m: Model) -> List[str]:
    """Defender plan-enablement recommendations the run left out (defender_plan_recommendations off)."""
    for run in m.data.scanner_runs:
        if run.get("scanner") == "defender_recommendations_scanner":
            return list((run.get("metadata") or {}).get("excluded_plan_recommendations") or [])
    return []


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
    lines += _resource_providers(m)
    lines += _resilience_lines(m)
    return "\n".join(lines), _inventory(m)


def _resilience_lines(m: Model) -> List[str]:
    groups = insights.resilience(m.data.reliability or [], m.data.resources, m.sub.get("name") or "")
    if not groups:
        return []
    return ["", "## 8. Resilience Posture (Azure Advisor)", "",
            "Open Azure Advisor reliability recommendations, production first (environment from tags, names and the "
            "subscription naming convention). Items ARG already reports as findings are not repeated. Zone "
            "redundancy and backup gaps on production data stores are the ones to decide on: each is a recovery-time "
            "/ data-loss exposure with a cost to close (ZRS / zone-redundant tiers cost more than LRS).", "",
            md_table(["Area", "Recommendation", "Production", "All resources", "Examples (production first)"], [
                [g["sub_category"], g["problem"], g["production"], g["resources"], ", ".join(g["examples"])]
                for g in groups[:25]], ["---", "---", "---:", "---:", "---"]),
            "", "Reference: [Advisor reliability recommendations]"
                "(https://learn.microsoft.com/azure/advisor/advisor-reference-reliability-recommendations) · "
                "[Availability zones](https://learn.microsoft.com/azure/reliability/availability-zones-overview)", ""]


def _resource_providers(m: Model) -> List[str]:
    """Which providers the subscription accepts (registered) and which not, against what it uses and policy."""
    rp = m.data.resource_providers or {}
    rows = rp.get("providers") or []
    if not rows:
        return []
    counts = rp.get("counts") or {}
    unused = [r for r in rows if r["status"] == "Registered, not in use" and not r.get("baseline")]
    blocked = {r["namespace"] for f in m.findings if f["finding_type"] == "resource_provider_blocked_registered"
               for r in (f.get("evidence") or {}).get("blocked_registered") or []}
    lines = ["", "## 7. Resource Providers", "",
             "A resource provider must be **registered** before the subscription accepts its resources; a **not "
             "registered** provider cannot be used until an Owner / Contributor registers it. Core services "
             "(Compute, Storage, Network, Key Vault, Web, ...) and the governance baseline (Defender, Policy, "
             "Monitor, Cost Management) are expected to be registered even without resources and are never "
             "unregister candidates. Niche providers registered but unused are shown for information only - "
             "unregistering saves nothing; restrict services with an 'Allowed / Not allowed resource types' policy. "
             "Every provider of the subscription: "
             "[resource-providers.md](./resource-providers.md); raw data: "
             "[resource-providers.json](../05-deep-dive/raw/inventory/resource-providers.json).", "",
             md_table(["Status", "Providers"], [[s, counts[s]] for s in STATUS_ORDER if counts.get(s)],
                      ["---", "---:"]), ""]
    if blocked:
        lines += [f"**Blocked but registered ({len(blocked)}):** " + ", ".join(sorted(blocked, key=str.lower))
                  + " - see the finding in the gap analysis.", ""]
    if unused:
        lines += [f"**Niche providers registered but unused - for information ({len(unused)}):** "
                  + ", ".join(r["namespace"] for r in unused) + ".", ""]
    shown = [r for r in rows if r["status"] != "Not registered"]
    lines += [f"### Registered and in-use providers ({len(shown)})", "",
              _provider_table(shown), ""]
    not_registered = [r["namespace"] for r in rows if r["status"] == "Not registered"]
    if not_registered:
        lines += [f"**Not registered ({len(not_registered)}):** the subscription does not accept these providers' "
                  f"resources - " + ", ".join(sorted(not_registered, key=str.lower)) + ".", ""]
    policies = rp.get("policies") or []
    lines += ["### Resource-type policies", ""]
    if policies:
        lines += [md_table(["Assignment", "Scope", "Effect", "Enforced", "Resource types"], [
            [p["name"], p["scope"], p["effect"], "yes" if p["enforced"] else "no (audit only)",
             ", ".join(p["types"][:8]) + (f" (+{len(p['types']) - 8} more)" if len(p["types"]) > 8 else "")]
            for p in policies]), ""]
        denied = rp.get("denied_in_use") or []
        lines += [("Resource types in use that these policies deny: " + ", ".join(
            f"{d['type']} ({d['resources']})" for d in denied) + " - see the finding in the gap analysis.")
                  if denied else "No resource type in use is denied by these policies.", ""]
    else:
        lines += ['No "Allowed resource types" or "Not allowed resource types" policy applies to this subscription '
                  "(directly or through its management groups): every registered provider's resource types may be "
                  "deployed.", ""]
    return lines


def _provider_table(rows: List[Dict[str, Any]]) -> str:
    def note(r: Dict[str, Any]) -> str:
        if r.get("baseline"):
            return "governance baseline"
        if r["status"] == "Registered, not in use":
            return "unregister candidate"
        return ""

    return md_table(["Provider", "Status", "Registration", "Resources", "Resource types in use", "Note"], [
        [r["namespace"], r["status"], "on request" if r["registration_policy"] == "RegistrationRequired"
         else ("automatic" if r["registration_policy"] == "RegistrationFree" else "-"),
         r["resources"] or "0",
         ", ".join(f"{t.split('/', 1)[1] if '/' in t else t} ({n})" for t, n in list(r["types"].items())[:6])
         + (f" (+{len(r['types']) - 6} more)" if len(r["types"]) > 6 else ""), note(r)]
        for r in rows], ["---", "---", "---", "---:", "---", "---"], drop_empty=True)


def render_resource_providers_page(m: Model) -> Optional[str]:
    """Every provider of the subscription - registered, platform, not registered - in one table."""
    rows = (m.data.resource_providers or {}).get("providers") or []
    if not rows:
        return None
    unused = [r for r in rows if r["status"] == "Registered, not in use" and not r.get("baseline")]
    lines = ["# Resource Providers", "", "[← Back to Current Findings](./README.md#7-resource-providers)", "",
             f"Subscription: {m.subscription_label()} - {len(rows)} providers. Raw data: "
             "[resource-providers.json](../05-deep-dive/raw/inventory/resource-providers.json).", "",
             "| Status | Meaning |", "|---|---|",
             "| In use | Registered and at least one resource exists |",
             "| Registered, not in use | Registered, no resources yet. Normal for core services (Compute, Storage, "
             "Network, ...) and the governance baseline; for niche providers, information only |",
             "| Platform (always registered) | Registration-free; Azure registers it automatically |",
             "| Not registered | The subscription cannot create these resources until someone registers it |", ""]
    if unused:
        lines += [f"## Niche providers registered but unused ({len(unused)})", "",
                  "For information. A registration costs nothing and unregistering saves nothing; it only stops the "
                  "service being deployed until someone registers it again (the portal does that automatically). "
                  "For services the company does not allow, a 'Not allowed resource types' policy at the management "
                  "group is the control that sticks. Only if a provider was registered by a one-off test that nobody "
                  "will use again:", "",
                  "```bash"] + [f"# az provider unregister --namespace {r['namespace']} --subscription {m.sub['id']}"
                                for r in unused] + ["```", ""]
    lines += [f"## All providers ({len(rows)})", "", _provider_table(rows), ""]
    return "\n".join(lines)


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
        out.extend([f"### {title} ({len(items)})", "", md_table(cols, [row_fn(r) for r in items], drop_empty=True), ""])

    def sku(r: Dict[str, Any]) -> str:
        return size_of(r) or "/".join(str(x) for x in ((r.get("sku") or {}).get(k) for k in ("name", "tier", "capacity")) if x)

    def cost(r: Dict[str, Any]) -> str:
        return m.cost30(r.get("id"))

    section("App Service plans", "microsoft.web/serverfarms", ["Name", "RG", "SKU", "Kind", f"30 d {m.currency}"],
            lambda r: [r["name"], r["id"].split("/")[4], sku(r), r.get("kind"), cost(r)])
    section("Virtual machines", "microsoft.compute/virtualmachines",
            ["Name", "RG", "Size", "OS", "State", "Location", "Created", f"30 d {m.currency}"],
            lambda r: [r["name"], r["id"].split("/")[4], size_of(r), os_of(r), state_of(r), r.get("location"),
                       (r.get("createdTime") or "")[:10], cost(r)])
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
        lines.append(md_table(["Type", "Name", "Location", "Size / SKU", "Configuration", "State", "Kind", "Created",
                               f"30 d {m.currency}"], [
            [re.sub(r"(?i)^microsoft\.", "", r.get("type") or ""), f"`{r.get('name')}`", r.get("location"),
             size_of(r) or " / ".join(str(x) for x in ((r.get("sku") or {}).get("name"), (r.get("sku") or {}).get("tier")) if x),
             config_of(r), state_of(r), r.get("kind"), (r.get("createdTime") or "")[:10], m.cost30(r.get("id"))]
            for r in sorted(items, key=lambda r: ((r.get("type") or "").lower(), r.get("name") or ""))
        ], drop_empty=True))
        lines.append("")
    return "\n".join(lines)


def _first_step(text: Optional[str]) -> str:
    """First actionable line of the remediation (skips 'Recommendation name:' headings)."""
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return next((line for line in lines if not line.endswith(":")), lines[0] if lines else "")


def _learn_more(f: Dict[str, Any]) -> str:
    refs = (f.get("implementation") or {}).get("references") or []
    return f"[{refs[0]['title']}]({refs[0]['url']})" if refs else ""


def render_gap_analysis(m: Model) -> str:
    lines = ["# 02 - Gap Analysis", "", "[← Back to summary](../README.md)", "",
             f"Subscription: {m.subscription_label()}", "",
             "Severity: **Critical** = exploitable exposure or major waste, act now; **High** = material risk/cost, "
             "within 30 days; **Medium** = best-practice gap, within the quarter; **Low** = hygiene.", "",
             "**Cost to implement** = additional Azure run cost per month (USD list price) and effort in story points "
             "(1 SP = 4h; a generic estimate of the size of the change, not measured hours); the deep dive of each "
             "finding explains why it is needed, when it is not, and how the cost was estimated.",
             "", "## Summary Matrix", "", _area_matrix(m), ""]
    # Gaps on many resources are one row each (with the guardrail); the deep dive lists every resource.
    collapsed = {s["finding_type"]: s for s in m.systemic() if s["count"] >= insights.SYSTEMIC_MIN_COUNT}
    for area in AREAS:
        items = [f for f in m.findings if f["area"] == area]
        if not items:
            continue
        lines += [f"## {area}", ""]
        rows, shown = [], set()
        for f in items:
            s = collapsed.get(f["finding_type"])
            if s is None:
                rows.append([f"[{f['ref']}](../05-deep-dive/{f['folder']}/README.md#{f['ref'].lower()})",
                             SEV_LABEL[f["severity"]], f"**{f['title']}** - {f['description']}",
                             short_id(f.get("resource_id"), m.sub["id"]), _first_step(f.get("remediation_steps")),
                             cost_summary(f["implementation"]), _learn_more(f)])
            elif f["finding_type"] not in shown:
                shown.add(f["finding_type"])
                rows.append([f"{s['refs'][0]} … {s['refs'][-1]}", SEV_LABEL[s["severity"]],
                             f"**{s['label']} - {s['count']} resources ({s['share']:.0%} of {s['population']})** - "
                             f"systemic; every resource is listed in the "
                             f"[deep dive](../05-deep-dive/{s['folder']}/README.md)",
                             f"{s['count']} resources",
                             "Guardrail: " + "; ".join(s["guardrails"]) if s["guardrails"]
                             else "Fix the IaC module / template default",
                             cost_summary(f["implementation"]) + " per resource", _learn_more(f)])
        lines.append(md_table(["Ref", "Severity", "Gap", "Resource", "Recommendation", "Cost to implement",
                               "Learn more"], rows, drop_empty=True))
        lines.append("")
    return "\n".join(lines)


def render_cost_drivers(m: Model) -> Tuple[str, str]:
    cur = m.currency
    amounts = sorted((float((b.get("properties") or {}).get("amount") or 0) for b in m.subscription_budgets()
                      if ((b.get("properties") or {}).get("timeGrain") or "").lower() == "monthly"), reverse=True)
    amount = amounts[0] if amounts else 0.0
    lines = ["# 03 - Cost Drivers", "", "[← Back to summary](../README.md) · Itemised actions: "
             "[savings-register.md](./savings-register.md)", "",
             f"Source: Cost Management Query API ({'AmortizedCost' if m.amortized else 'ActualCost'}, {cur})"
             + ("; reservation and savings-plan purchases are spread over the resources that use them, and the "
                "invoiced (actual) month is shown next to it - budgets are compared with the invoiced amount"
                if m.amortized else "") + ". Raw data: "
             "[05-deep-dive/raw/cost](../05-deep-dive/raw/cost).", ""]
    if m.month_keys:
        lines += ["## 1. 12-Month Trend", ""]
        prev = None
        rows = []
        for k in m.month_keys:
            v = m.months[k]
            top_move = "first month" if prev is None else "stable (no service moved 10 %+)"
            if prev:
                deltas = sorted(((s, sm.get(k, 0) - sm.get(prev, 0)) for s, sm in m.service_months.items()),
                                key=lambda x: -abs(x[1]))
                if deltas and abs(deltas[0][1]) >= 0.1 * (m.months[prev] or 1):
                    top_move = f"{deltas[0][0]} {deltas[0][1]:+,.0f}"
            rows.append([k, money(v, "", 0), money(m.months_actual.get(k), "", 0) if m.months_actual else "",
                         pct(m.budget_month_cost(k), amount) if amount else "-", top_move])
            prev = k
        rows.append(["**12-month total**", f"**{money(m.total_12m)}**",
                     f"**{money(m.total_12m_actual)}**" if m.total_12m_actual is not None else "", "", ""])
        lines.append(md_table(["Month", f"{cur} ({'amortized' if m.amortized else 'actual'})", f"{cur} (invoiced)",
                               "Invoiced vs budget" + (f" ({amount:,.0f})" if amount else ""), "Largest change"],
                              rows, ["---", "---:", "---:", "---:", "---"], drop_empty=True))
        lines += ["", "```mermaid", "xychart-beta",
                  f'  title "Monthly {m.cost_basis_label} ({cur})"',
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
         " · ".join(f"{s} {c:,.0f}" for s, c in sorted(sv.items(), key=lambda kv: -kv[1])[:5] if c >= 1)
         or " · ".join(f"{s} {c:,.2f}" for s, c in sorted(sv.items(), key=lambda kv: -kv[1])[:3]) or "no charges"]
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
             "Commands are **for review only** - none were executed by the analysis. Run them after owner sign-off.",
             "Each wave lists the actions with an estimated saving first, then the other actions (security, "
             "resilience, operations) by severity. Tag and naming hygiene is summarised - see the "
             "[gap analysis](../02-gap-analysis/README.md) for every item.", ""]
    waves = m.savings_by_wave()
    for wave in (WAVE_NO_REGRET, WAVE_OPTIMISE, WAVE_STRUCTURAL):
        items = [f for f in m.findings if f["wave"] == wave]
        if not items:
            continue
        lines += [f"## {WAVE_NAMES[wave]}", ""]
        saving = sorted((f for f in items if f.get("estimated_monthly_savings_usd")),
                        key=lambda f: -(f.get("estimated_monthly_savings_usd") or 0))
        hygiene = [f for f in items if not f.get("estimated_monthly_savings_usd") and f["finding_type"] in HYGIENE_TYPES]
        other = sorted((f for f in items if not f.get("estimated_monthly_savings_usd") and f not in hygiene),
                       key=lambda f: (sev_rank(f["severity"]), f["title"]))
        if saving:
            net_total = sum(f["implementation"].get("net_monthly_usd") or 0 for f in saving)
            lines += [f"### With an estimated saving ({len(saving)})", "",
                      "Net = saving minus the additional run cost of the change (where the change adds one; the AI "
                      "gateway saving is already net of the gateway).", "",
                      md_table(["Ref", "Action", "Resource", "Severity", "Monthly saving", "Cost to implement",
                                "Net / month"], [
                          [f["ref"], f["title"], short_id(f.get("resource_id"), m.sub["id"]), SEV_LABEL[f["severity"]],
                           m.savings_label(f.get("estimated_monthly_savings_usd")), cost_summary(f["implementation"]),
                           m.savings_label(f["implementation"].get("net_monthly_usd"))] for f in saving
                      ] + [["", f"**Total {WAVE_NAMES[wave].split(' - ')[0].lower()}**", "", "",
                            f"**{m.savings_label(waves[wave])}**", "", f"**{m.savings_label(net_total)}**"]]), ""]
            scripted = [f for f in saving if f.get("azure_cli_script")][:15]
            if scripted:
                lines += ["```bash"]
                for f in scripted:
                    lines += [f"# {f['ref']} {f['title']}", f["azure_cli_script"], ""]
                lines += ["```", ""]
        if other:
            lines += [f"### Other actions ({len(other)}) - risk and operations, no direct saving", "",
                      md_table(["Ref", "Action", "Resource", "Severity", "Area", "Cost to implement"], [
                          [f["ref"], f["title"], short_id(f.get("resource_id"), m.sub["id"]), SEV_LABEL[f["severity"]],
                           f.get("area"), cost_summary(f["implementation"])] for f in other
                      ]), ""]
        if hygiene:
            counts = Counter(f["finding_type"] for f in hygiene)
            lines += [f"### Tag and naming hygiene ({len(hygiene)})", "",
                      md_table(["Finding type", "Resources"], [[t, n] for t, n in counts.most_common()],
                               ["---", "---:"]), ""]
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


def type_of_id(resource_id: str) -> str:
    """'/subscriptions/s/resourceGroups/rg/providers/Microsoft.X/y/name' -> 'microsoft.x/y'."""
    parts = (resource_id or "").lower().split("/providers/")[-1].split("/")
    return "/".join(parts[:2]) if len(parts) >= 2 else ""


def _cost30(m: Model, resource_id: Optional[str]) -> Dict[str, Any]:
    return (m.data.cost.get("last30_by_resource") or {}).get((resource_id or "").lower()) or {}


def _folder_spend(m: Model, folder: str) -> List[Dict[str, Any]]:
    """Resources in the folder's scope with 30-day cost, costliest first (includes resources deleted since)."""
    prefixes = DEEP_DIVE_RESOURCE_TYPES.get(folder)
    if not prefixes:
        return []
    inventory = {(r.get("id") or "").lower(): r for r in m.data.resources}
    rows = []
    for rid, entry in m.top_resources:
        rtype = type_of_id(rid)
        if not rtype.startswith(prefixes) or not entry.get("cost"):
            continue
        rows.append({"id": rid, "type": rtype, "cost": entry["cost"], "meters": entry.get("meters") or {},
                     "resource": inventory.get(rid)})
    return rows


def _meters_label(meters: Dict[str, float], limit: int = 3) -> str:
    top = [(k, v) for k, v in sorted(meters.items(), key=lambda kv: -kv[1]) if round(v, 2)][:limit]
    return ", ".join(f"{k} {money(v, '', 2)}" for k, v in top) or "no charges"


def _deployments_label(deployments: List[Dict[str, Any]], limit: int = 6) -> str:
    labels = []
    for d in deployments[:limit]:
        label = d.get("model") or d.get("name") or "?"
        if d.get("sku"):
            label += f" {d['sku']}"
        if d.get("capacity"):
            label += f" x{d['capacity']}"
        labels.append(label)
    if not labels:
        return "none"
    more = len(deployments) - limit
    return ", ".join(labels) + (f" (+{more} more)" if more > 0 else "")


AI_TYPES = ("microsoft.cognitiveservices/accounts", "microsoft.machinelearningservices/workspaces",
            "microsoft.search/searchservices")


def _ai_overview(m: Model) -> List[str]:
    """AI accounts with kind, SKU, model deployments and 30-day spend by meter - shown even without findings."""
    cur = m.currency
    deployments = m.data.ai_deployments or {}
    accounts = [r for r in m.data.resources if (r.get("type") or "").lower() in AI_TYPES]
    spend = _folder_spend(m, "ai-foundry")
    if not accounts and not spend:
        return []
    lines = [f"## AI accounts, deployments and spend ({len(accounts)})", "",
             f"Last 30 days, {cur}. AI spend in scope: **{money(sum(e['cost'] for e in spend), cur, 2)}**. "
             f"Deployments are listed for Azure OpenAI / AI Services (Foundry) accounts.", ""]
    rows = []
    for r in sorted(accounts, key=lambda r: (-(_cost30(m, r.get("id")).get("cost") or 0), r.get("name") or "")):
        entry = _cost30(m, r.get("id"))
        deps = deployments.get((r.get("id") or "").lower())
        rows.append([r.get("name"), (r.get("id") or "").split("/")[4] if r.get("id") else "",
                     r.get("kind") or re.sub(r"(?i)^microsoft\.", "", r.get("type") or ""),
                     (r.get("sku") or {}).get("name") or "", r.get("location"), m.cost30(r.get("id")),
                     _meters_label(entry.get("meters") or {}),
                     _deployments_label(deps) if deps is not None else "not collected"])
    lines += [md_table(["Account", "RG", "Kind", "SKU", "Location", f"30 d {cur}", "Top meters", "Deployments"],
                       rows, ["---", "---", "---", "---", "---", "---:", "---", "---"]), ""]
    gone = [e for e in spend if e["resource"] is None]
    if gone:
        lines += ["Spend on AI resources no longer in the inventory (deleted within the window):", "",
                  md_table(["Resource", f"30 d {cur}", "Top meters"],
                           [[short_id(e["id"], m.sub["id"]), money(e["cost"], "", 2), _meters_label(e["meters"])]
                            for e in gone[:15]], ["---", "---:", "---"]), ""]
    return lines


def _spend_section(m: Model, folder: str, limit: int = 15) -> List[str]:
    """Per-area 30-day spend, so a page shows cost even where its findings carry no saving."""
    if folder == "ai-foundry":
        return _ai_overview(m)
    rows = _folder_spend(m, folder)
    if not rows:
        return []
    cur = m.currency
    return ["## Spend in scope (last 30 days)", "",
            f"{len(rows)} resource(s) in this area cost **{money(sum(r['cost'] for r in rows), cur, 2)}** in the "
            f"last 30 days" + (f"; the {limit} costliest:" if len(rows) > limit else ":"), "",
            md_table(["Resource", "Type", f"30 d {cur}", "Top meters"],
                     [[short_id(r["id"], m.sub["id"]), r["type"].replace("microsoft.", ""), money(r["cost"], "", 2),
                       _meters_label(r["meters"])] for r in rows[:limit]],
                     ["---", "---", "---:", "---"]), ""]


def _why_lines(impl: Dict[str, Any]) -> List[str]:
    """'Why it is needed' and 'When it is not needed' - per recommendation for multi-item Defender findings."""
    items = impl.get("items") or []
    out: List[str] = []
    if len(items) > 1:
        out += ["", "**Why it is needed**", ""] + [f"- **{i['label'].rstrip('.')}** - {i['why']}" for i in items]
        out += ["", "**When it is not needed**", ""] + [f"- **{i['label'].rstrip('.')}** - {i['skip_when']}"
                                                         for i in items if i.get("skip_when")]
        return out
    if impl.get("why"):
        out += ["", "**Why it is needed**", "", impl["why"]]
    if impl.get("skip_when"):
        out += ["", "**When it is not needed**", "", impl["skip_when"]]
    return out


def _cost_lines(m: Model, f: Dict[str, Any], impl: Dict[str, Any]) -> List[str]:
    if not impl or impl.get("source") == "generic":
        return []
    items = impl.get("items") or []
    rows = []
    if len(items) > 1:
        rows += [f"- **{i['label'].rstrip('.')}** - {i['run_cost']} Effort: {i['effort']} "
                 f"{effort_label(i['hours'])}" for i in items]
        rows.append(f"- Together: {cost_summary(impl)}.")
    else:
        rows.append(f"- Azure run cost: {impl.get('run_cost')}")
        if impl.get("effort"):
            estimate = effort_label(impl.get("hours"))
            rows.append(f"- Effort: {impl['effort']}" + (f" About {estimate}" if estimate else "")
                        + (f" (≈ USD {impl['one_off_usd'][0]:,}-{impl['one_off_usd'][1]:,})"
                           if impl.get("one_off_usd") else "") + ".")
    if impl.get("saving_usd"):
        rows.append(f"- Net effect: {m.savings_label(impl.get('net_monthly_usd'))} per month "
                    + ("(saving already net of the change's cost)" if impl.get("cost_included_in_saving")
                       else f"(saving {m.savings_label(impl['saving_usd'])} minus run cost "
                            f"{m.usd_label(impl.get('monthly_usd'))})"))
    if impl.get("monthly_usd"):
        rows.append(f"- Prices are USD list prices of {impl.get('prices_as_of')} (Azure Retail Prices API); "
                    f"enterprise agreements and other regions differ.")
    return ["", "**Cost of implementation (estimate)**", ""] + rows


TARGET_LABELS = {"private_endpoint": "private endpoint + private DNS, public access off",
                 "disable_public": "public access off (data nobody reads, or boot diagnostics moved to managed)",
                 "trusted_services": "trusted Microsoft services only", "service_endpoint": "service endpoints",
                 "ip_rules": "IP rules", "keep_public": "public by design, hardened"}


def _spend_to_fix_lines(m: Model) -> List[str]:
    """Does the report ask to buy something? Every recommendation that adds run cost, and the target architecture
    for the open endpoints (with the free interim step where the target needs prerequisites)."""
    paying = [f for f in m.findings if (f["implementation"].get("monthly_usd") or 0) > 0]
    decided = [(f, (f.get("evidence") or {}).get("access_decision")) for f in m.findings]
    decided = [(f, d) for f, d in decided if d]
    out = []
    if paying:
        total = sum(f["implementation"]["monthly_usd"] for f in paying)
        top = sorted(paying, key=lambda f: -f["implementation"]["monthly_usd"])[:4]
        out.append(f"- **Recommendations that add run cost:** {len(paying)}, about USD {total:,.0f}/month together - "
                   + "; ".join(f"[{f['ref']}](./05-deep-dive/{f['folder']}/README.md#{f['ref'].lower()}) "
                               f"{f['title'].split(':')[0]} (+USD {f['implementation']['monthly_usd']:,.2f})"
                               for f in top)
                   + ". Each shows the options considered and why the target is the right one.")
    if decided:
        targets = Counter(d["option"] for _, d in decided)
        interim = sum(1 for _, d in decided if d.get("interim"))
        pe_cost = sum(d["monthly_usd"] for _, d in decided if d["option"] == "private_endpoint")
        out.append(f"- **Open endpoints - target architecture ({len(decided)}):** "
                   + ", ".join(f"{n} {TARGET_LABELS.get(k, k)}" for k, n in targets.most_common())
                   + (f". Private endpoints add about USD {pe_cost:,.0f}/month together" if pe_cost else "")
                   + (f"; {interim} of them have a free interim step (service endpoint / IP rules) to close the "
                      f"internet exposure today while the prerequisites are put in place" if interim else "")
                   + ". Data nobody reads gets no network path at all rather than a private endpoint.")
    return out


def render_deep_dives(m: Model) -> Dict[str, str]:
    pages: Dict[str, str] = {}
    index_rows = []
    for folder, title in DEEP_DIVE_FOLDERS.items():
        items = [f for f in m.findings if f["folder"] == folder]
        sev = Counter(f["severity"] for f in items)
        index_rows.append([f"[{folder}](./{folder}/README.md)", title, len(items),
                           ", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev.get(s)) or "-"])
        lines = [f"# Deep Dive - {title}", "", "[← Deep-dive index](../README.md)", "",
                 f"Subscription: {m.subscription_label()}", ""]
        lines += _spend_section(m, folder)
        defender = m.data.defender or {}
        if folder == "security-identity" and defender.get("recommendations"):
            lines += ["## Defender for Cloud summary", "",
                      ("Defender recommendations are also imported as findings below (`defender_recommendations` is "
                       "on)." if _defender_imported(m) else
                       "Not repeated as findings: triage them in Defender for Cloud, where exemptions, owners and due "
                       "dates are tracked. Switch `defender_recommendations` on to import them as findings."),
                      f" [Open Defender for Cloud recommendations]({defender.get('portal')}).", "",
                      md_table(["Severity", "Recommendation", "Resources"], [
                          [r["severity"], f"[{r['recommendation']}]({r['link']})", r["resources"]]
                          for r in defender["recommendations"][:30]], ["---", "---", "---:"]), ""]
            if len(defender["recommendations"]) > 30:
                lines += [f"… and {len(defender['recommendations']) - 30} more in Defender for Cloud.", ""]
        excluded = _excluded_defender_plans(m) if folder == "security-identity" else []
        if excluded:
            lines += [f"> {len(excluded)} Defender for Cloud plan-enablement recommendation(s) are not listed: "
                      + "; ".join(excluded) + ". They ask to buy a paid plan rather than fix a configuration; plan "
                      "choice is a central cost decision (switch them on with the `defender_plan_recommendations` "
                      "setting).", ""]
        if not items:
            lines.append("No findings in this area.")
            pages[folder] = "\n".join(lines)
            continue
        if len(lines) > 6:
            lines += ["## Findings", ""]
        lines.append(md_table(["Ref", "Severity", "Finding", "Resource", f"30 d {m.currency}", "Impact",
                               "Cost to implement"], [
            [f"[{f['ref']}](#{f['ref'].lower()})", SEV_LABEL[f["severity"]], f["title"],
             short_id(f.get("resource_id"), m.sub["id"]), m.cost30(f.get("resource_id")), m.impact_label(f),
             cost_summary(f["implementation"])]
            for f in items
        ], ["---", "---", "---", "---", "---:", "---", "---"], drop_empty=True))
        lines.append("")
        for f in items:
            lines += [f"## {f['ref']}", "", f"**{f['title']}** - {SEV_LABEL[f['severity']]} · `{f['finding_type']}` · "
                      f"scanner `{f['scanner']}`", "", f.get("description") or "", "",
                      f"- Subscription: {m.subscription_label()}",
                      f"- Resource: `{f.get('resource_id')}`"]
            for label, key in (("CAF", "caf_control"), ("CIS", "cis_control"), ("NIST", "nist_control")):
                if f.get(key):
                    lines.append(f"- {label}: {f[key]}")
            impl = f.get("implementation") or {}
            lines += _why_lines(impl)
            lines += _cost_lines(m, f, impl)
            lines += reasoning.markdown(f.get("reasoning") or {})
            lines += thinking.finding_markdown(f.get("ai_review"))
            if f.get("remediation_steps"):
                lines += ["", "**Remediation**", "", f["remediation_steps"]]
            if f.get("azure_cli_script"):
                lines += ["", "```bash", f["azure_cli_script"], "```"]
            if impl.get("references"):
                lines += ["", "**References**", ""] + [f"- [{r['title']}]({r['url']})" for r in impl["references"]]
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
                 [r["scanner"], r["status"], r.get("resources_scanned") if r.get("resources_scanned") is not None
                  else "not reported", r["findings"], len(r.get("warnings") or [])] for r in runs
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

BACKLOG_FILE = "backlog.csv"
HISTORY_FILE = "history.json"
HISTORY_KEEP = 24
BOARDS_PRIORITY = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 4}


def read_previous_findings(folder: Path) -> Optional[List[Dict[str, Any]]]:
    """Findings of the report currently in the folder (None when there is none), read before it is replaced."""
    path = Path(folder) / "05-deep-dive" / "raw" / "findings.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None


def _html(text: Any) -> str:
    import html as html_lib

    return html_lib.escape(str(text or "")).replace("\n", "<br>")


def backlog_rows(m: Model) -> List[Dict[str, Any]]:
    """
    Azure Boards CSV import rows: one work item per systemic issue (guardrail + all affected resources) and one per
    remaining actionable finding. Hygiene items are covered by their systemic row or the allocation KPI.
    """
    sub_name = m.sub.get("name") or m.sub["id"]
    systemic = m.systemic()
    systemic_types = {s["finding_type"] for s in systemic}
    rows = []
    for s in systemic:
        items = [f for f in m.findings if f["finding_type"] == s["finding_type"]]
        impl = items[0].get("implementation") or {}
        description = (f"<p>{s['count']} resources ({s['share']:.0%} of {s['population']}) in subscription "
                       f"{_html(sub_name)} have the same gap: {_html(s['label'])}.</p>"
                       f"<p><b>Why</b><br>{_html(impl.get('why'))}</p>"
                       + (f"<p><b>Guardrail</b><br>{'<br>'.join(_html(g) for g in s['guardrails'])}</p>"
                          if s["guardrails"] else "<p><b>Fix</b><br>Change the IaC module / template default.</p>")
                       + f"<p><b>Resources</b><br>{'<br>'.join(_html(f.get('resource_id')) for f in items[:200])}</p>"
                       + "".join(f"<p><a href=\"{r['url']}\">{_html(r['title'])}</a></p>"
                                 for r in impl.get("references") or [])
                       + f"<p><b>Done when</b><br>The policy is assigned and ARG reports none of "
                         f"{s['refs'][0]} … {s['refs'][-1]} on the next analysis.</p>")
        rows.append({"Work Item Type": "Task",
                     "Title": f"[ARG] Guardrail: {s['label']} ({s['count']} resources, {sub_name})"[:255],
                     "Description": description, "Priority": BOARDS_PRIORITY.get(s["severity"], 3),
                     "Tags": f"ARG; {sub_name}; systemic; {s['finding_type']}",
                     "Remaining Work": 8})
    for f in m.actionable:
        if f["finding_type"] in systemic_types:
            continue
        impl = f.get("implementation") or {}
        points = story_points(impl.get("hours"))   # Remaining Work: the hours the story-point scale stands for
        description = (f"<p>{_html(f.get('description'))}</p>"
                       f"<p><b>Resource</b><br>{_html(f.get('resource_id'))}<br>Subscription {_html(sub_name)} "
                       f"({m.sub['id']})</p>"
                       + (f"<p><b>Why it is needed</b><br>{_html(impl.get('why'))}</p>" if impl.get("why") else "")
                       + (f"<p><b>When it is not needed</b><br>{_html(impl.get('skip_when'))}</p>"
                          if impl.get("skip_when") else "")
                       + f"<p><b>Cost</b><br>{_html(cost_summary(impl))}"
                       + (f"; saving {m.savings_label(f.get('estimated_monthly_savings_usd'))} per month"
                          if f.get("estimated_monthly_savings_usd") else "") + "</p>"
                       + (f"<p><b>Remediation</b><br>{_html(f.get('remediation_steps'))}</p>"
                          if f.get("remediation_steps") else "")
                       + (f"<pre>{_html(f.get('azure_cli_script')).replace('<br>', chr(10))}</pre>"
                          if f.get("azure_cli_script") else "")
                       + "".join(f"<p><a href=\"{r['url']}\">{_html(r['title'])}</a></p>"
                                 for r in impl.get("references") or [])
                       + f"<p><b>Done when</b><br>ARG no longer reports {f['finding_type']} on this resource.</p>")
        rows.append({"Work Item Type": "Task", "Title": f"[ARG {f['ref']}] {f['title']}"[:255],
                     "Description": description, "Priority": BOARDS_PRIORITY.get(f["severity"], 3),
                     "Tags": f"ARG; {sub_name}; {f.get('area')}; wave {f['wave']}; {f['finding_type']}",
                     "Remaining Work": points["hours"] if points else ""})
    return rows


def write_backlog(m: Model, path: Path) -> None:
    import csv

    rows = backlog_rows(m)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["Work Item Type", "Title", "Description", "Priority", "Tags",
                                                    "Remaining Work"])
        writer.writeheader()
        writer.writerows(rows)


def append_history(m: Model, path: Path) -> List[Dict[str, Any]]:
    """One line per analysis (kept outside the generated files, so re-runs build a trend)."""
    try:
        history = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
    except ValueError:
        history = []
    waves = m.savings_by_wave()
    act_sev = Counter(f["severity"] for f in m.actionable)
    history.append({"date": m.data.generated_at.strftime("%Y-%m-%d %H:%M"), "resources": len(m.data.resources),
                    "actionable": len(m.actionable), "hygiene": len(m.hygiene),
                    "critical": act_sev.get("critical", 0), "high": act_sev.get("high", 0),
                    "cost_30d": round(m.total_30, 2), "currency": m.currency,
                    "savings_usd": round(waves[1] + waves[2], 2)})
    history = history[-HISTORY_KEEP:]
    write(path, json.dumps(history, indent=2))
    return history


def write_report(data: AnalysisData, output: Path,
                 previous_findings: Optional[List[Dict[str, Any]]] = None) -> Model:
    m = Model(data, previous_findings)
    try:
        m.history = json.loads((output / HISTORY_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        m.history = []
    output.mkdir(parents=True, exist_ok=True)

    def page(path: Path, content: str) -> None:
        """A report page with every amount in the subscription's billing currency (setting display_currency)."""
        write(path, m.localise(content))

    page(output / "README.md", render_readme(m))
    current, inventory = render_current_findings(m)
    page(output / "01-current-findings" / "README.md", current)
    page(output / "01-current-findings" / "resource-inventory.md", inventory)
    providers_page = render_resource_providers_page(m)
    if providers_page:
        page(output / "01-current-findings" / "resource-providers.md", providers_page)
    page(output / "02-gap-analysis" / "README.md", render_gap_analysis(m))
    cost, register = render_cost_drivers(m)
    page(output / "03-cost-drivers" / "README.md", cost)
    page(output / "03-cost-drivers" / "savings-register.md", register)
    page(output / "04-architectural-critique" / "README.md", render_critique(m))
    for folder, text in render_deep_dives(m).items():
        page(output / "05-deep-dive" / ("README.md" if folder == "__index__" else f"{folder}/README.md"), text)
    if (m.data.thinking or {}).get("status") in ("ok", "error"):
        page(output / "05-deep-dive" / "thinking.md", thinking.markdown(m.data.thinking, m.findings))

    raw = output / "05-deep-dive" / "raw"

    def dump(rel: str, obj: Any) -> None:
        write(raw / rel, json.dumps(to_jsonable(obj), indent=2, default=str))

    dump("inventory/resources.json", data.resources)
    dump("inventory/resource-groups.json", data.resource_groups)
    dump("findings.json", m.findings)
    dump("scanner-runs.json", data.scanner_runs)
    if data.ai_deployments:
        dump("inventory/ai-deployments.json", data.ai_deployments)
    if data.resource_providers:
        dump("inventory/resource-providers.json", data.resource_providers)
    for key, value in data.cost.items():
        dump(f"cost/{key}.json", value)
    dump("metadata.json", {"subscription": data.subscription, "generated_at": data.generated_at,
                           "generator": "scripts.subscription_analysis", "warnings": data.warnings,
                           "report_generated": datetime.now(timezone.utc).isoformat()})
    write(output / SUMMARY_FILE, json.dumps(to_jsonable(summarize(m)), indent=2, default=str))
    write(output / PROMPT_FILE, build_prompt(to_jsonable(summarize(m)), m.findings))
    write_backlog(m, output / BACKLOG_FILE)
    append_history(m, output / HISTORY_FILE)
    return m


# ---------------------------------------------------------------------------
# Multi-subscription layout: reports/<subscription>/... + reports/README.md
# ---------------------------------------------------------------------------

SUMMARY_FILE = "summary.json"
BRAND_CREDIT = ("Built with Azure Resource Guardian (ARG) · Author: Junaid Ahmed · [jahmed.cloud](https://jahmed.cloud) · "
                "[github.com/jahmed-cloud/ARG](https://github.com/jahmed-cloud/ARG)")
GENERATED_ENTRIES = ("README.md", SUMMARY_FILE, PROMPT_FILE, "backlog.csv", "01-current-findings", "02-gap-analysis",
                     "03-cost-drivers", "04-architectural-critique", "05-deep-dive",
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
        "per_usd": m.fx,   # billing currency per USD at the subscription's amortized 30-day cost (Currency dropdown)
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
    estate_link = ("**Estate inventory** across all subscriptions (types, sizes, SKUs, regions, suggestions): "
                   f"[{ESTATE_DIR}/README.md](./{ESTATE_DIR}/README.md) · interactive with filters on the portal's "
                   "[Estate](/estate) page.") if (reports_dir / ESTATE_DIR / "README.md").is_file() else ""
    content = "\n".join([
        "# Subscription Analysis Reports", "",
        "One folder per subscription (`<subscription>/README.md` → `01-…` to `05-…`). "
        "Generated by `python -m scripts.subscription_analysis` or the local portal (`python -m scripts.local_portal`).", "",
        *([estate_link, ""] if estate_link else []),
        md_table(["Subscription", "ID", "Analysed", "Resources", "Critical / High", "Last 30 days", "Est. savings / month"],
                 rows, ["---", "---", "---", "---:", "---:", "---:", "---:"]) if rows else "_No reports yet._",
        "", f"_{BRAND_CREDIT}._",
    ])
    path = reports_dir / "README.md"
    write(path, content)
    return path
