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
from typing import Any, Callable, Dict, List, Optional

from scanners.base.azure_api import (
    ACTUAL_COST,
    COST_BASIS,
    ArmClient,
    AzureAuthExpiredError,
    FailFastCredential,
    get_resource_costs,
    query_resource_graph,
    run_cost_query,
)
from scanners.base.base_scanner import ScanContext, ScannerRegistry
from scanners.base.providers import get_provider_analysis

from scripts.subscription_analysis.estate import DETAIL_COLUMNS, RESOURCE_DETAILS
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
    # {lower(account id): [{"name", "model", "version", "sku", "capacity"}]} for OpenAI / AI Services accounts
    ai_deployments: Dict[str, List[Dict[str, Any]]] = dataclasses.field(default_factory=dict)
    # Resource providers: registration state vs usage vs allow / deny resource-type policies (scanners.base.providers)
    resource_providers: Dict[str, Any] = dataclasses.field(default_factory=dict)


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


ProgressCallback = Callable[[str, int, int], None]


def _noop_progress(message: str, step: int, total: int) -> None:
    return None


async def run_scanners(context: ScanContext, names: Optional[List[str]], config: Dict[str, Any],
                       data: AnalysisData, progress: ProgressCallback = _noop_progress,
                       step_offset: int = 0, total_steps: Optional[int] = None) -> None:
    registry = ScannerRegistry.all()
    selected = [cls for name, cls in sorted(registry.items()) if not names or name in names]
    total = total_steps or len(selected)
    for index, cls in enumerate(selected, 1):
        progress(f"Scanner {cls.scanner_name}", step_offset + index, total)
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


INVENTORY_QUERY = ("Resources" + RESOURCE_DETAILS
                   + f"| project id, name, type, location, kind, sku, tags, resourceGroup, managedBy, {DETAIL_COLUMNS}")
CREATED_TIME_CONCURRENCY = 8


async def collect_inventory(context: ScanContext, arm: ArmClient, data: AnalysisData) -> None:
    """
    Resource list from Resource Graph (paginated, authoritative count), enriched
    with createdTime/changedTime from ARM listed per resource group. The
    subscription-wide ARM list is not used: it can stop paging early on large
    subscriptions.
    """
    sub = data.subscription["id"]
    data.resource_groups = await arm.get_all(f"/subscriptions/{sub}/resourcegroups", "2021-04-01")
    rows = await query_resource_graph(context, INVENTORY_QUERY)
    if rows is None:  # no Resource Graph client: fall back to ARM
        data.resources = await arm.get_all(f"/subscriptions/{sub}/resources", "2021-04-01",
                                           {"$expand": "createdTime,changedTime"})
        return

    times: Dict[str, Dict[str, Any]] = {}
    gate = asyncio.Semaphore(CREATED_TIME_CONCURRENCY)

    async def fetch(rg_name: str) -> None:
        async with gate:
            try:
                items = await arm.get_all(f"/subscriptions/{sub}/resourceGroups/{rg_name}/resources", "2021-04-01",
                                          {"$expand": "createdTime,changedTime"})
            except Exception as exc:
                data.warnings.append(f"inventory: creation dates unavailable for resource group {rg_name}: {exc}")
                return
            for item in items:
                times[(item.get("id") or "").lower()] = item

    await asyncio.gather(*(fetch(g["name"]) for g in data.resource_groups if g.get("name")))
    for row in rows:
        extra = times.get((row.get("id") or "").lower()) or {}
        row["createdTime"] = extra.get("createdTime")
        row["changedTime"] = extra.get("changedTime")
    data.resources = rows


AI_DEPLOYMENT_KINDS = ("openai", "aiservices")
AI_DEPLOYMENT_CONCURRENCY = 8


async def collect_ai_deployments(arm: ArmClient, data: AnalysisData) -> None:
    """Model deployments of every Azure OpenAI / AI Services (Foundry) account, for the AI deep dive."""
    accounts = [r for r in data.resources
                if (r.get("type") or "").lower() == "microsoft.cognitiveservices/accounts"
                and (r.get("kind") or "").lower() in AI_DEPLOYMENT_KINDS and r.get("id")]
    gate = asyncio.Semaphore(AI_DEPLOYMENT_CONCURRENCY)

    async def fetch(account: Dict[str, Any]) -> None:
        async with gate:
            try:
                items = await arm.get_all(f"{account['id']}/deployments", "2024-10-01")
            except Exception as exc:
                data.warnings.append(f"AI deployments unavailable for {account.get('name')}: {exc}")
                return
        rows = []
        for d in items:
            model, sku = (d.get("properties") or {}).get("model") or {}, d.get("sku") or {}
            rows.append({"name": d.get("name"), "model": model.get("name"), "version": model.get("version"),
                         "sku": sku.get("name"), "capacity": sku.get("capacity")})
        data.ai_deployments[account["id"].lower()] = rows

    await asyncio.gather(*(fetch(a) for a in accounts))


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

    data.cost["cost_basis"] = COST_BASIS
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
    # Invoiced (actual) monthly totals: what budgets are evaluated against, and the invoice view next to amortized.
    data.cost["monthly_actual"] = await attempt(
        "monthly actual", run_cost_query(context, start_12m, today, [], granularity="Monthly", cost_type=ACTUAL_COST))

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


async def list_subscriptions(credential: Any) -> List[Dict[str, Any]]:
    """Subscriptions visible to the credential, in the same shape resolve_subscription() returns."""
    arm = ArmClient(credential)
    try:
        subs = await arm.get_all("/subscriptions", "2022-12-01")
    finally:
        arm.close()
    return sorted(
        ({"id": s["subscriptionId"], "name": s.get("displayName"), "tenant_id": s.get("tenantId"),
          "state": s.get("state")} for s in subs),
        key=lambda s: (s["name"] or "").lower(),
    )


async def run_analysis(credential: Any, subscription: str, *, scanners: Optional[List[str]] = None,
                       config: Optional[Dict[str, Any]] = None, include_cost: bool = True,
                       progress: ProgressCallback = _noop_progress) -> AnalysisData:
    load_scanners()
    selected = [n for n in ScannerRegistry.all() if not scanners or n in scanners]
    total = len(selected) + 3
    credential = FailFastCredential(credential)
    arm = ArmClient(credential)
    try:
        progress("Resolving subscription", 0, total)
        sub = await resolve_subscription(arm, subscription)
        data = AnalysisData(subscription=sub, generated_at=datetime.now(timezone.utc))
        context = build_context(credential, arm, sub)
        logger.info("Collecting inventory for %s (%s)", sub["name"], sub["id"])
        progress("Collecting resource inventory", 1, total)
        await collect_inventory(context, arm, data)
        await collect_ai_deployments(arm, data)
        try:
            data.resource_providers = await get_provider_analysis(context) or {}
        except Exception as exc:
            data.warnings.append(f"resource providers unavailable: {exc}")
        if include_cost:
            progress("Querying Cost Management (throttled API, can take a minute)", 2, total)
            logger.info("Querying Cost Management")
            await collect_costs(context, data)
        await run_scanners(context, scanners, config or {}, data, progress=progress, step_offset=3, total_steps=total)
        if credential.error:
            # Scanners swallow per-call errors as warnings; an expired sign-in would
            # otherwise produce a silently incomplete report.
            raise AzureAuthExpiredError(credential.error + " No report was written for this run.")
        return data
    finally:
        arm.close()


def run(credential: Any, subscription: str, **kwargs: Any) -> AnalysisData:
    return asyncio.run(run_analysis(credential, subscription, **kwargs))
