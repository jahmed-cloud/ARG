"""
Data collection for the subscription analysis CLI: resolves the
subscription, builds a live ScanContext, runs every registered scanner and
gathers the inventory and cost datasets the report needs.
"""

import asyncio
import dataclasses
import logging
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from scanners.base.azure_api import ArmClient, get_resource_costs, run_cost_query
from scanners.base.base_scanner import ScanContext, ScannerRegistry

from scripts.subscription_analysis.knowledge import classify

logger = logging.getLogger("arg.analysis")

SCANNER_MODULES = (
    "scanners.compute.compute_scanners",
    "scanners.compute.compute_posture_scanners",
    "scanners.identity.identity_scanners",
    "scanners.network.network_scanners",
    "scanners.network.network_posture_scanners",
    "scanners.storage.storage_scanners",
    "scanners.storage.storage_posture_scanners",
    "scanners.governance.governance_scanners",
    "scanners.governance.governance_posture_scanners",
    "scanners.security.security_scanners",
    "scanners.security.security_posture_scanners",
    "scanners.database.database_scanners",
    "scanners.cost.cost_scanners",
    "scanners.terraform.terraform_scanners",
)


def load_scanners() -> None:
    import importlib

    for module in SCANNER_MODULES:
        importlib.import_module(module)


@dataclasses.dataclass
class AnalysisData:
    subscription: Dict[str, Any]
    generated_at: datetime
    resources: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    resource_groups: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    findings: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    scanner_runs: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    cost: Dict[str, Any] = dataclasses.field(default_factory=dict)
    warnings: List[str] = dataclasses.field(default_factory=list)


def to_jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    return value


async def resolve_subscription(arm: ArmClient, value: str) -> Dict[str, Any]:
    subs = await arm.get_all("/subscriptions", "2022-12-01")
    wanted = value.strip().lower()
    for s in subs:
        if wanted in ((s.get("subscriptionId") or "").lower(), (s.get("displayName") or "").lower()):
            return {"id": s["subscriptionId"], "name": s.get("displayName"), "tenant_id": s.get("tenantId"),
                    "state": s.get("state")}
    raise SystemExit(f"Subscription '{value}' not found among {len(subs)} subscriptions visible to the credential.")


def build_context(credential: Any, arm: ArmClient, subscription: Dict[str, Any]) -> ScanContext:
    from azure.mgmt.resourcegraph import ResourceGraphClient

    context = ScanContext(
        subscription_id=subscription["id"],
        tenant_id=subscription.get("tenant_id") or "",
        scan_job_id=f"cli-{datetime.now(timezone.utc):%Y%m%d%H%M%S}",
        resource_graph_client=ResourceGraphClient(credential),
        arm_client=arm,
    )
    try:
        from azure.mgmt.costmanagement import CostManagementClient
        context.cost_management_client = CostManagementClient(credential)
    except ImportError:
        # Cost-aware legacy scanners only check that *a* cost client exists;
        # posture scanners query Cost Management through the ArmClient.
        context.cost_management_client = arm
    return context


async def run_scanners(context: ScanContext, names: Optional[List[str]], config: Dict[str, Any],
                       data: AnalysisData) -> None:
    registry = ScannerRegistry.all()
    selected = [cls for name, cls in sorted(registry.items()) if not names or name in names]
    for cls in selected:
        if cls.requires_graph and context.graph_client is None:
            data.scanner_runs.append({"scanner": cls.scanner_name, "status": "skipped",
                                      "reason": "requires Microsoft Graph", "findings": 0})
            continue
        logger.info("Running %s", cls.scanner_name)
        output = await cls(config=dict(config)).execute(context)
        data.scanner_runs.append({
            "scanner": cls.scanner_name, "display_name": cls.display_name, "category": cls.category.value,
            "status": "completed", "findings": output.finding_count, "resources_scanned": output.resources_scanned,
            "warnings": output.warnings,
        })
        for finding in output.findings:
            record = to_jsonable(finding)
            c = classify(record["finding_type"], record["category"])
            record.update({"area": c.area, "folder": c.folder, "wave": c.wave, "critique": c.critique,
                           "scanner": cls.scanner_name})
            data.findings.append(record)
        data.warnings.extend(f"{cls.scanner_name}: {w}" for w in output.warnings)


async def collect_inventory(arm: ArmClient, data: AnalysisData) -> None:
    sub = data.subscription["id"]
    data.resources = await arm.get_all(f"/subscriptions/{sub}/resources", "2021-04-01",
                                       {"$expand": "createdTime,changedTime"})
    data.resource_groups = await arm.get_all(f"/subscriptions/{sub}/resourcegroups", "2021-04-01")


async def collect_costs(context: ScanContext, data: AnalysisData, months: int = 12, days: int = 30) -> None:
    today = date.today()
    start_12m = (today.replace(day=1) - timedelta(days=1)).replace(day=1)
    for _ in range(months - 2):
        start_12m = (start_12m - timedelta(days=1)).replace(day=1)
    start_30d = today - timedelta(days=days)
    service = [{"type": "Dimension", "name": "ServiceName"}]

    async def attempt(label: str, coro):
        try:
            return await coro
        except Exception as exc:
            data.warnings.append(f"cost query '{label}' failed: {exc}")
            return None

    data.cost["window_12m"] = {"from": start_12m.isoformat(), "to": today.isoformat()}
    data.cost["window_30d"] = {"from": start_30d.isoformat(), "to": today.isoformat()}
    data.cost["monthly_by_service"] = await attempt(
        "monthly by service", run_cost_query(context, start_12m, today, service, granularity="Monthly"))
    data.cost["last30_by_rg_service"] = await attempt(
        "30d by resource group", run_cost_query(context, start_30d, today,
                                                [{"type": "Dimension", "name": "ResourceGroupName"}] + service))
    data.cost["last30_by_service_meter"] = await attempt(
        "30d by meter", run_cost_query(context, start_30d, today, service + [{"type": "Dimension", "name": "Meter"}]))
    per_resource = await attempt("30d by resource", get_resource_costs(context, days=days))
    data.cost["last30_by_resource"] = per_resource or {}

    rows = data.cost.get("last30_by_rg_service") or []
    total = sum(float(r.get("Cost") or 0) for r in rows)
    total_usd = sum(float(r.get("CostUSD") or 0) for r in rows)
    currency = next((r.get("Currency") for r in rows if r.get("Currency")), "USD")
    data.cost["currency"] = currency
    data.cost["usd_to_billing"] = (total / total_usd) if total and total_usd else (1.0 if currency == "USD" else None)
    try:
        data.cost["budgets"] = await context.arm_client.get_all(
            f"/subscriptions/{context.subscription_id}/providers/Microsoft.Consumption/budgets", "2023-05-01")
    except Exception as exc:
        data.warnings.append(f"budgets unavailable: {exc}")
        data.cost["budgets"] = []


async def run_analysis(credential: Any, subscription: str, *, scanners: Optional[List[str]] = None,
                       config: Optional[Dict[str, Any]] = None, include_cost: bool = True) -> AnalysisData:
    load_scanners()
    arm = ArmClient(credential)
    try:
        sub = await resolve_subscription(arm, subscription)
        data = AnalysisData(subscription=sub, generated_at=datetime.now(timezone.utc))
        context = build_context(credential, arm, sub)
        logger.info("Collecting inventory for %s (%s)", sub["name"], sub["id"])
        await collect_inventory(arm, data)
        if include_cost:
            logger.info("Querying Cost Management")
            await collect_costs(context, data)
        await run_scanners(context, scanners, config or {}, data)
        return data
    finally:
        arm.close()


def run(credential: Any, subscription: str, **kwargs: Any) -> AnalysisData:
    return asyncio.run(run_analysis(credential, subscription, **kwargs))
