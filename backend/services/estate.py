"""
Estate inventory for the Docker stack (the admin Estate page).

Runs the local scanner's estate engine (scripts/subscription_analysis/estate.py) headless: the Resource Graph
inventory, VM sizes and 30-day usage metrics are collected with each registered tenant's service principal, the
last-30-days cost per resource comes from Cost Management, and the open findings in the database take the place
of the local per-subscription report folders. The result is stored as an EstateSnapshot in the compact format the
local portal's estate.json uses, plus the same markdown overview.

Runs in the Celery worker (sync SQLAlchemy): workers/scan_worker.py refresh_estate.
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from backend.models.models import EstateSnapshot, Finding, FindingStatus, Subscription, Tenant
from scripts.subscription_analysis.compute import markdown as compute_markdown
from scripts.subscription_analysis.compute import merge_compute
from scripts.subscription_analysis.currency import exchange_rate
from scripts.subscription_analysis.estate import (
    build_estate,
    collect_inventory,
    compact,
    merge_architecture,
    render_estate_markdown,
)
from scripts.subscription_analysis.knowledge import classify
from scripts.subscription_analysis.policy_catalog import merge_policy

logger = logging.getLogger(__name__)

RUNNING, COMPLETED, FAILED = "running", "completed", "failed"
ESTATE_KEEP = 3  # finished snapshots kept; each holds the whole estate
RUNNING_STALE_AFTER = timedelta(hours=2)
COST_CONCURRENCY = 4  # Cost Management throttles hard per tenant
CURRENT_STATUSES = (FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED)
STALE_MESSAGE = "Did not finish within 2 hours (the worker was probably restarted); start a new refresh."


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Pure helpers (unit tested)
# ---------------------------------------------------------------------------

def finding_row(f: Any) -> Dict[str, Any]:
    """A Finding (resource loaded) in the shape the estate join expects from a local findings.json entry."""
    c = classify(f.finding_type, f.category or "")
    resource = f.resource
    severity = f.severity.value if hasattr(f.severity, "value") else f.severity
    return {
        "ref": str(f.id), "title": f.title, "severity": severity, "finding_type": f.finding_type,
        "area": c.area, "folder": c.folder, "wave": c.wave,
        "estimated_monthly_savings_usd": f.estimated_monthly_savings_usd,
        "resource_id": resource.azure_resource_id if resource else None,
        "resource_name": resource.resource_name if resource else None,
    }


def reports_from_database(subscriptions: Iterable[Dict[str, Any]], findings: Dict[str, List[Dict[str, Any]]],
                          costs: Dict[str, Optional[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """
    {subscription id: report} as build_estate reads it from report folders, from the database instead:
    findings per subscription and the Cost Management cost per resource (None = no cost access).
    """
    reports: Dict[str, Dict[str, Any]] = {}
    for s in subscriptions:
        sid = s["id"].lower()
        sub_costs = costs.get(sid) or {}
        currency = next((e.get("currency") for e in sub_costs.values() if e.get("currency")), "") or ""
        rate = exchange_rate([sub_costs])   # this subscription's own billing currency per USD (amortized cost)
        reports[sid] = {"folder": "", "name": s.get("name"), "generated_at": s.get("analysed_at"),
                        "currency": currency, "per_usd": rate["per_usd"] if rate else None,
                        "findings": findings.get(sid, []), "costs": sub_costs, "resources": []}
    return reports


def merge_inventories(inventories: List[Dict[str, Any]]) -> Dict[str, Any]:
    """One inventory from the per-tenant collect_inventory results."""
    usage: Dict[str, int] = defaultdict(int)
    providers: Dict[str, Any] = {}
    for inv in inventories:
        for key, value in (inv.get("usage") or {}).items():
            if isinstance(value, (int, float)):
                usage[key] += value
        providers.update(inv.get("providers") or {})
    return {
        "generated_at": min((i["generated_at"] for i in inventories if i.get("generated_at")), default=None),
        "source": "resource-graph",
        "subscriptions": [s for i in inventories for s in i.get("subscriptions") or []],
        "usage": dict(usage),
        "resources": [r for i in inventories for r in i.get("resources") or []],
        "providers": providers,
        "architecture": merge_architecture([i.get("architecture") or {} for i in inventories]),
        "policy": merge_policy(i.get("policy") for i in inventories),
        "compute": merge_compute(i.get("compute") for i in inventories),
    }


def build_snapshot(inventory: Dict[str, Any], reports: Dict[str, Dict[str, Any]],
                   costs: Dict[str, Optional[Dict[str, Any]]],
                   trend: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> Dict[str, Any]:
    """The estate (compact wire format), its markdown overview and counts."""
    estate = build_estate(None, inventory, reports)
    # build_estate reads "no cost row" as "no charge"; without cost access that would claim 0 for everything
    no_cost = {sid for sid, value in costs.items() if value is None}
    for r in estate["resources"]:
        if r["subscriptionId"] in no_cost:
            r.pop("cost30", None)
            r.pop("currency", None)
    data = compact(estate)
    data["cost_unavailable"] = sorted(no_cost)
    # the rate the invoice uses (billing-currency cost / USD cost) - the UI shows amounts in the billing currency
    data["fx"] = exchange_rate(costs.values())
    # policy in force for the landing-zone view; GET /estate leaves it out (the browser does not need it)
    data["policy"] = inventory.get("policy") or {}
    # amortized spend for the dashboard (recorded cost per month) and the Costs page (last 30 days), per subscription
    data["cost_30d"] = cost_totals(costs)
    data["cost_trend"] = trend or {}
    # the Compute page (GET /estate/compute); GET /estate leaves it out
    compute = inventory.get("compute") or {}
    data["compute"] = {} if compute.get("error") else compute
    compute_section = compute_markdown(data["compute"])
    return {
        "data": data,
        "markdown": render_estate_markdown(estate) + ("\n\n" + compute_section if compute_section else ""),
        "subscriptions": len(estate["subscriptions"]),
        "resources": len(estate["resources"]),
        "suggestions": len(estate["suggestions"]),
    }


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------

def tenant_credential(tenant: Tenant) -> Any:
    from azure.identity import ClientSecretCredential

    from backend.utils.encryption import decrypt

    return ClientSecretCredential(tenant_id=tenant.tenant_id, client_id=tenant.client_id,
                                  client_secret=decrypt(tenant.client_secret_encrypted))


def fetch_costs(credential: Any, subscription_ids: List[str],
                cost_basis: Optional[str] = None) -> Dict[str, Optional[Dict[str, Any]]]:
    """{subscription id: {lower(resource id): {cost, currency, ...}} or None without Cost Management access}, on the
    cost basis of the amortized_cost setting."""
    from scanners.base.azure_api import ArmClient, gather_limited, get_resource_costs

    async def run() -> Dict[str, Optional[Dict[str, Any]]]:
        arm = ArmClient(credential)
        out: Dict[str, Optional[Dict[str, Any]]] = {}

        async def one(sub_id: str) -> None:
            out[sub_id.lower()] = await get_resource_costs(
                SimpleNamespace(arm_client=arm, subscription_id=sub_id, cache={}, cost_basis=cost_basis))

        try:
            await gather_limited(subscription_ids, one, COST_CONCURRENCY)
        finally:
            arm.close()
        return out

    return asyncio.run(run())


def fetch_cost_trend(credential: Any, subscription_ids: List[str],
                     cost_basis: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """{subscription id: [{month, cost, cost_usd, currency}]} - cost per month (amortized unless the setting is off),
    last 6 months (the dashboard's recorded-cost chart). Subscriptions without Cost Management access are left out."""
    from scanners.base.azure_api import ArmClient, gather_limited, monthly_costs

    async def run() -> Dict[str, List[Dict[str, Any]]]:
        arm = ArmClient(credential)
        out: Dict[str, List[Dict[str, Any]]] = {}

        async def one(sub_id: str) -> None:
            months = await monthly_costs(SimpleNamespace(arm_client=arm, subscription_id=sub_id, cost_basis=cost_basis))
            if months:
                out[sub_id.lower()] = months

        try:
            await gather_limited(subscription_ids, one, COST_CONCURRENCY)
        finally:
            arm.close()
        return out

    return asyncio.run(run())


async def recorded_costs(db: Any, visible: Any, subscription: Optional[str] = None
                         ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """
    (30-day totals, monthly trend) of the newest completed estate snapshot - amortized Cost Management cost, per
    Azure subscription ID - limited to the subscriptions `visible` (a SQL condition on Subscription.id) allows and, if
    given, to one subscription (database or Azure ID). The dashboard chart and the Costs page read these.
    """
    from sqlalchemy import String, and_, cast, exists, or_

    condition = and_(visible, or_(cast(Subscription.id, String) == subscription,
                                  Subscription.subscription_id == subscription)) if subscription else visible
    allowed = {str(s).lower() for s in (await db.execute(select(Subscription.subscription_id).where(condition)))
               .scalars().all()}
    if not allowed:
        return {}, {}
    # the snapshot read carries the same condition, so no query of the dashboard runs unfiltered
    rows = (await db.execute(select(EstateSnapshot.data["cost_30d"], EstateSnapshot.data["cost_trend"])
                             .where(EstateSnapshot.status == COMPLETED, exists(select(Subscription.id).where(condition)))
                             .order_by(EstateSnapshot.started_at.desc()).limit(1))).all()
    if not rows:
        return {}, {}
    totals = rows[0][0] if isinstance(rows[0][0], dict) else {}
    trend = rows[0][1] if isinstance(rows[0][1], dict) else {}
    return ({k: v for k, v in totals.items() if k in allowed}, {k: v for k, v in trend.items() if k in allowed})


def trend_by_month(trend: Dict[str, List[Dict[str, Any]]]) -> List[Tuple[str, float]]:
    """[(month, USD)] summed over subscriptions; months a subscription reported without USD are left out."""
    totals: Dict[str, float] = defaultdict(float)
    for months in trend.values():
        for m in months or []:
            if m.get("month") and m.get("cost_usd") is not None:
                totals[m["month"]] += float(m["cost_usd"])
    return sorted((month, round(value, 2)) for month, value in totals.items())


def cost_totals(costs: Dict[str, Optional[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """{subscription id: {"cost", "cost_usd", "currency"}} - the 30-day amortized total of each subscription."""
    out = {}
    for sid, rows in costs.items():
        if not rows:
            continue
        usd = [e.get("cost_usd") for e in rows.values()]
        out[sid] = {"cost": round(sum(float(e.get("cost") or 0) for e in rows.values()), 2),
                    "cost_usd": round(sum(float(u) for u in usd if u is not None), 2) if any(u is not None for u in usd)
                    else None,
                    "currency": next((e.get("currency") for e in rows.values() if e.get("currency")), None)}
    return out


# ---------------------------------------------------------------------------
# Snapshot lifecycle (sync session, worker side)
# ---------------------------------------------------------------------------

def expire_stale(db: Session) -> None:
    db.execute(update(EstateSnapshot)
               .where(EstateSnapshot.status == RUNNING, EstateSnapshot.started_at < _now() - RUNNING_STALE_AFTER)
               .values(status=FAILED, completed_at=_now(), error_message=STALE_MESSAGE))
    db.commit()


def claim_refresh(db: Session, triggered_by: str, requested_by: Optional[str] = None) -> Optional[EstateSnapshot]:
    """A new running snapshot, or None when a refresh is already running (one at a time, by unique index)."""
    expire_stale(db)
    snapshot = EstateSnapshot(status=RUNNING, triggered_by=triggered_by, requested_by=requested_by,
                              started_at=_now())
    db.add(snapshot)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return None
    return snapshot


def prune(db: Session, keep: int = ESTATE_KEEP) -> None:
    old = db.execute(select(EstateSnapshot.id).where(EstateSnapshot.status != RUNNING)
                     .order_by(EstateSnapshot.started_at.desc()).offset(keep)).scalars().all()
    if old:
        db.execute(delete(EstateSnapshot).where(EstateSnapshot.id.in_(old)))
        db.commit()


def cost_basis(db: Session) -> str:
    """The Cost Management cost type of the amortized_cost setting (Settings > Analysis settings)."""
    from backend.api.routes.governance_config import effective_settings
    from backend.models.models import GovernanceConfig
    from scanners.base.azure_api import cost_basis_from

    row = db.execute(select(GovernanceConfig).where(GovernanceConfig.tenant_id.is_(None)).limit(1)).scalar_one_or_none()
    return cost_basis_from(effective_settings(getattr(row, "scanner_settings", None) if row else None))


def run_refresh(db: Session, snapshot_id: str, *, collect: Callable = collect_inventory,
                costs_for: Callable = fetch_costs, credential_for: Callable = tenant_credential,
                trend_for: Callable = fetch_cost_trend, basis_for: Callable = cost_basis) -> None:
    """Collect, join and store one estate snapshot; a failure is recorded on the snapshot, never raised."""
    snapshot = db.get(EstateSnapshot, snapshot_id)
    if snapshot is None or snapshot.status != RUNNING:
        logger.info("Estate snapshot %s is not running any more; nothing to do", snapshot_id)
        return
    started = _now()
    try:
        subs = db.execute(select(Subscription).where(Subscription.is_active.is_(True))).scalars().all()
        tenants = {t.id: t for t in db.execute(select(Tenant).where(
            Tenant.id.in_({s.tenant_id for s in subs}), Tenant.is_active.is_(True))).scalars().all()}
        groups: Dict[str, List[Subscription]] = defaultdict(list)
        for s in subs:
            if s.tenant_id in tenants:
                groups[s.tenant_id].append(s)
        if not groups:
            raise ValueError("No active subscriptions are connected - run python -m scripts.connect_azure first.")

        basis = basis_for(db)   # setting amortized_cost (default on)
        inventories, costs, trend = [], {}, {}
        for tenant_id, group in groups.items():
            credential = credential_for(tenants[tenant_id])
            inventories.append(collect(credential, [{"id": s.subscription_id, "name": s.display_name}
                                                    for s in group]))
            tenant_costs = costs_for(credential, [s.subscription_id for s in group], cost_basis=basis)
            costs.update(tenant_costs)
            try:   # the chart is an add-on: the estate stands without it
                trend.update(trend_for(credential, [sid for sid, rows in tenant_costs.items() if rows is not None],
                                       cost_basis=basis))
            except Exception as exc:
                logger.warning("Monthly cost trend unavailable: %s", exc)

        # Findings are read last so a scan that finished during the collection is included
        by_internal = {s.id: s for g in groups.values() for s in g}
        rows = db.execute(select(Finding).options(selectinload(Finding.resource)).where(
            Finding.subscription_id.in_(list(by_internal)), Finding.status.in_(CURRENT_STATUSES))).scalars().all()
        findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in rows:
            findings[by_internal[f.subscription_id].subscription_id.lower()].append(finding_row(f))
        reports = reports_from_database(
            [{"id": s.subscription_id, "name": s.display_name,
              "analysed_at": s.last_scanned_at.isoformat() if s.last_scanned_at else None}
             for s in by_internal.values()], findings, costs)
        result = build_snapshot(merge_inventories(inventories), reports, costs, trend)
        result["data"]["cost_basis"] = basis

        snapshot.data = result["data"]
        snapshot.overview_markdown = result["markdown"]
        snapshot.subscriptions_count = result["subscriptions"]
        snapshot.resources_count = result["resources"]
        snapshot.suggestions_count = result["suggestions"]
        snapshot.status = COMPLETED
        snapshot.completed_at = _now()
        db.commit()
        logger.info("Estate snapshot %s: %s resources, %s suggestions, %s subscriptions in %ss", snapshot_id,
                    result["resources"], result["suggestions"], result["subscriptions"],
                    int((_now() - started).total_seconds()))
        prune(db)
    except Exception as exc:
        logger.error("Estate refresh %s failed: %s", snapshot_id, exc, exc_info=True)
        db.rollback()
        db.execute(update(EstateSnapshot).where(EstateSnapshot.id == snapshot_id)
                   .values(status=FAILED, completed_at=_now(), error_message=str(exc)[:1000]))
        db.commit()
