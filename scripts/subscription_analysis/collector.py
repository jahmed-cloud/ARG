"""
Data collection for the subscription analysis CLI: resolves the
subscription, builds a live ScanContext, runs every registered scanner and
gathers the inventory and cost datasets the report needs.
"""

import asyncio
import dataclasses
import logging
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from scanners.base.azure_api import (
    ACTUAL_COST,
    ArmClient,
    AzureAuthExpiredError,
    FailFastCredential,
    cost_basis_from,
    cost_basis_of,
    get_resource_costs,
    missing_resources,
    query_resource_graph,
    run_cost_query,
    top_level_id,
)
from scanners.base.base_scanner import ScanContext, ScannerRegistry
from scanners.base.providers import get_provider_analysis

from scripts.subscription_analysis.correlate import correlate
from scripts.subscription_analysis.estate import DETAIL_COLUMNS, RESOURCE_DETAILS
from scripts.subscription_analysis.knowledge import classify
from scripts.subscription_analysis.settings import REPORT_SETTINGS

logger = logging.getLogger("arg.analysis")

SCANNER_MODULES = (
    "scanners.compute.compute_scanners",
    "scanners.compute.compute_posture_scanners",
    "scanners.compute.machine_security_scanners",
    "scanners.identity.identity_scanners",
    "scanners.network.network_scanners",
    "scanners.network.network_posture_scanners",
    "scanners.storage.storage_scanners",
    "scanners.storage.storage_posture_scanners",
    "scanners.governance.governance_scanners",
    "scanners.governance.governance_posture_scanners",
    "scanners.governance.policy_scanners",
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
    # Report-relevant settings of the run (switched-off checks, engineering hourly rate) - see settings.py
    settings: Dict[str, Any] = dataclasses.field(default_factory=dict)
    # Defender / Advisor items merged into native findings (correlate.py)
    correlation: Dict[str, int] = dataclasses.field(default_factory=dict)
    # Open Azure Advisor reliability recommendations (zone redundancy, backup, geo-replication, ...) for the
    # resilience section - an aggregate view, not findings
    reliability: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    # Defender for Cloud summary (open recommendations by severity) - shown instead of findings by default
    defender: Dict[str, Any] = dataclasses.field(default_factory=dict)
    # Thinking mode, deep step: the optional Azure OpenAI review (thinking.py)
    thinking: Dict[str, Any] = dataclasses.field(default_factory=dict)


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
    from scanners.base.azure_api import resource_graph_client

    context = ScanContext(
        subscription_id=subscription["id"],
        subscription_name=subscription.get("name") or "",
        tenant_id=subscription.get("tenant_id") or "",
        scan_job_id=f"cli-{datetime.now(timezone.utc):%Y%m%d%H%M%S}",
        resource_graph_client=resource_graph_client(credential),
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
        add_output(data, cls, output)


def add_output(data: AnalysisData, cls: Any, output: Any) -> None:
    """One scanner's run and findings into the analysis (local runs and the Docker worker's cloud report)."""
    data.scanner_runs.append({
        "scanner": cls.scanner_name, "display_name": cls.display_name, "category": cls.category.value,
        "status": "disabled" if (output.metadata or {}).get("disabled_by_setting") else "completed",
        "findings": output.finding_count, "resources_scanned": output.resources_scanned,
        "warnings": output.warnings, "metadata": to_jsonable(output.metadata or {}),
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


RELIABILITY_QUERY = """
advisorresources
| where type =~ 'microsoft.advisor/recommendations'
| where subscriptionId == '{subscription}'
| where tostring(properties.category) =~ 'HighAvailability'
| where tostring(properties.extendedProperties.recommendationSubCategory) != 'ServiceUpgradeAndRetirement'
{active}
| project resource_id = tostring(properties.resourceMetadata.resourceId),
          problem = tostring(properties.shortDescription.problem),
          sub_category = tostring(properties.extendedProperties.recommendationSubCategory),
          impact = tostring(properties.impact),
          impacted_type = tolower(tostring(properties.impactedField)),
          impacted_name = tostring(properties.impactedValue)
"""


DEFENDER_SUMMARY_QUERY = """
securityresources
| where type =~ 'microsoft.security/assessments'
| where subscriptionId == '{subscription}'
| where tostring(properties.status.code) =~ 'Unhealthy'
| summarize resources = dcount(tostring(properties.resourceDetails.Id)), key = take_any(name)
          by recommendation = tostring(properties.displayName), severity = tostring(properties.metadata.severity),
             category = tostring(properties.metadata.recommendationCategory)
"""
DEFENDER_PORTAL = "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/5"
DEFENDER_RECOMMENDATION = "https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/{}"


async def collect_defender_summary(context: ScanContext, data: AnalysisData, include_plans: bool = False) -> None:
    """Open Defender for Cloud recommendations by severity, OS-package updates folded into one row - the summary the
    report shows instead of one finding per resource (unless `defender_recommendations` is on)."""
    from scanners.security.defender_guidance import is_plan_recommendation, is_system_update

    try:
        rows = await query_resource_graph(context, DEFENDER_SUMMARY_QUERY.format(subscription=context.subscription_id))
    except Exception as exc:
        data.warnings.append(f"Defender for Cloud summary unavailable: {exc}")
        return
    if rows is None:
        return
    order = {"High": 0, "Medium": 1, "Low": 2}
    merged: Dict[str, Dict[str, Any]] = {}
    plans = 0
    for r in rows:
        name = r.get("recommendation") or ""
        if is_plan_recommendation(name) and not include_plans:
            plans += 1
            continue
        updates = is_system_update(name, r.get("category"))
        key = "Install missing OS / package updates" if updates else name
        severity = (r.get("severity") or "Low").title()
        entry = merged.setdefault(key, {"recommendation": key, "severity": severity, "resources": 0,
                                        "link": DEFENDER_PORTAL if updates or not r.get("key")
                                        else DEFENDER_RECOMMENDATION.format(r["key"])})
        count = int(r.get("resources") or 0)
        # package updates hit the same machines many times: the largest count, not the sum
        entry["resources"] = max(entry["resources"], count) if updates else entry["resources"] + count
        if order.get(severity, 3) < order.get(entry["severity"], 3):
            entry["severity"] = severity
    items = sorted(merged.values(), key=lambda e: (order.get(e["severity"], 3), -e["resources"], e["recommendation"]))
    data.defender = {"recommendations": items, "plan_upsells_left_out": plans, "portal": DEFENDER_PORTAL,
                     "by_severity": dict(Counter(e["severity"] for e in items))}


async def collect_reliability(context: ScanContext, data: AnalysisData) -> None:
    """Advisor reliability recommendations (retirements are a scanner of their own)."""
    from scanners.base.posture_scanner import ADVISOR_ACTIVE_FILTER

    try:
        rows = await query_resource_graph(context, RELIABILITY_QUERY.format(
            subscription=context.subscription_id, active=ADVISOR_ACTIVE_FILTER))
    except Exception as exc:
        data.warnings.append(f"Advisor reliability recommendations unavailable: {exc}")
        return
    gone = await missing_resources(context, [r.get("resource_id") for r in rows or []])
    data.reliability = [r for r in rows or [] if r.get("problem") and top_level_id(r.get("resource_id")) not in gone]


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

    data.cost["cost_basis"] = cost_basis_of(context)   # amortized unless the amortized_cost setting is off
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
    raw_credential = credential   # the AI review must not mark the whole run as signed out
    credential = FailFastCredential(credential)
    arm = ArmClient(credential)
    try:
        progress("Resolving subscription", 0, total)
        sub = await resolve_subscription(arm, subscription)
        data = AnalysisData(subscription=sub, generated_at=datetime.now(timezone.utc),
                            settings={k: v for k, v in (config or {}).items()
                                      if k in REPORT_SETTINGS or k == "required_tags"})
        context = build_context(credential, arm, sub)
        context.cost_basis = cost_basis_from(config)   # amortized unless the amortized_cost setting is off
        logger.info("Collecting inventory for %s (%s)", sub["name"], sub["id"])
        progress("Collecting resource inventory", 1, total)
        await collect_inventory(context, arm, data)
        await collect_ai_deployments(arm, data)
        await collect_reliability(context, data)
        await collect_defender_summary(context, data, bool((config or {}).get("defender_plan_recommendations")))
        try:
            data.resource_providers = await get_provider_analysis(context) or {}
        except Exception as exc:
            data.warnings.append(f"resource providers unavailable: {exc}")
        if include_cost:
            progress("Querying Cost Management (throttled API, can take a minute)", 2, total)
            logger.info("Querying Cost Management")
            await collect_costs(context, data)
        await run_scanners(context, scanners, config or {}, data, progress=progress, step_offset=3, total_steps=total)
        data.findings, data.correlation = correlate(data.findings)
        if (config or {}).get("ai_reasoning"):
            progress("Thinking mode: AI review", total, total)
            data.thinking = await think_about(data, config or {}, raw_credential)
        if credential.error:
            # Scanners swallow per-call errors as warnings; an expired sign-in would
            # otherwise produce a silently incomplete report.
            raise AzureAuthExpiredError(credential.error + " No report was written for this run.")
        return data
    finally:
        arm.close()


async def think_about(data: AnalysisData, config: Dict[str, Any], credential: Any) -> Dict[str, Any]:
    """The optional AI review of the analysed subscription (thinking.py); attaches finding["ai_review"]."""
    from scanners.base.naming import env_from_subscription
    from scripts.subscription_analysis.thinking import think

    sub = data.subscription
    env = {"prod": "production", "nonprod": "non-production"}.get(env_from_subscription(sub.get("name") or "") or "")
    return await think({"name": sub.get("name"), "environment": env}, data.findings, data.cost, config, credential)


def run(credential: Any, subscription: str, **kwargs: Any) -> AnalysisData:
    return asyncio.run(run_analysis(credential, subscription, **kwargs))
