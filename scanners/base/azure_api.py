"""
Azure Resource Guardian - Shared Azure API helpers for scanners
===============================================================
Scanners that need more than a single Resource Graph query (metrics,
diagnostic settings, SQL firewall rules, Cost Management, budgets) use
the helpers in this module instead of building SDK clients themselves,
so the "scanners must NOT create Azure SDK clients directly" rule from
ScanContext still holds.

- query_resource_graph(): paginated Resource Graph query (skip tokens),
  optionally tenant-scoped. Returns None when no client was injected so
  callers can fall back to their mock data.
- ArmClient: thin ARM REST client (GET / POST / paging / metrics / Cost
  Management query) built on httpx and an azure-identity credential,
  with 429/503 retry that honours Retry-After and the Cost Management
  x-ms-ratelimit-*-retry-after headers.
- get_resource_costs(): per-resource actual cost for the last N days,
  cached on the ScanContext so several scanners can share one Cost
  Management call (the API is throttled to a few calls per minute).
- get_retail_price(): public Azure Retail Prices API lookup (USD), used
  only in live mode to replace static fallback prices.
"""

import asyncio
import logging
import threading
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

ARM_ENDPOINT = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
RETAIL_PRICES_URL = "https://prices.azure.com/api/retail/prices"
HOURS_PER_MONTH = 730

_RETAIL_PRICE_CACHE: Dict[str, Optional[float]] = {}


# ---------------------------------------------------------------------------
# Resource Graph
# ---------------------------------------------------------------------------

async def query_resource_graph(
    context: Any,
    query: str,
    *,
    tenant_scope: bool = False,
    page_size: int = 1000,
) -> Optional[List[Dict[str, Any]]]:
    """
    Run a Resource Graph query with skip-token pagination.

    tenant_scope=True queries every subscription the credential can see -
    used to decide whether a referenced resource (e.g. a Log Analytics
    workspace linked from App Insights) exists anywhere, not just here.
    """
    client = getattr(context, "resource_graph_client", None)
    if client is None:
        return None

    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    rows: List[Dict[str, Any]] = []
    skip_token: Optional[str] = None
    while True:
        options = QueryRequestOptions(result_format="objectArray", top=page_size, skip_token=skip_token)
        request = QueryRequest(
            subscriptions=None if tenant_scope else [context.subscription_id],
            query=query,
            options=options,
        )
        response = await asyncio.to_thread(client.resources, request)
        rows.extend(response.data or [])
        skip_token = getattr(response, "skip_token", None)
        if not skip_token:
            break
    return rows


# ---------------------------------------------------------------------------
# ARM REST client
# ---------------------------------------------------------------------------

class ArmClient:
    """Minimal ARM REST client. All public methods are async (run in a thread)."""

    RETRY_STATUS = {429, 500, 502, 503, 504}

    def __init__(self, credential: Any, *, timeout: float = 60.0, max_retries: int = 3,
                 client_type: str = "AzureResourceGuardian"):
        import httpx

        self._credential = credential
        self._max_retries = max_retries
        self._client_type = client_type
        self._http = httpx.Client(base_url=ARM_ENDPOINT, timeout=timeout)
        self._token: Optional[str] = None
        self._token_expires_on: float = 0.0
        self._token_lock = threading.Lock()

    # -- plumbing ---------------------------------------------------------

    def _bearer(self) -> str:
        with self._token_lock:
            if not self._token or time.time() > self._token_expires_on - 300:
                token = self._credential.get_token(ARM_SCOPE)
                self._token = token.token
                self._token_expires_on = float(token.expires_on)
            return self._token

    @staticmethod
    def _retry_after_seconds(headers: Any) -> float:
        waits = []
        for key, value in headers.items():
            lowered = key.lower()
            if lowered == "retry-after" or (lowered.startswith("x-ms-ratelimit") and lowered.endswith("retry-after")):
                try:
                    waits.append(float(value))
                except (TypeError, ValueError):
                    continue
        return max(waits) if waits else 5.0

    def _request(self, method: str, url: str, *, params: Optional[Dict[str, Any]] = None,
                 json: Optional[Dict[str, Any]] = None) -> Any:
        attempt = 0
        while True:
            headers = {"Authorization": f"Bearer {self._bearer()}", "ClientType": self._client_type}
            response = self._http.request(method, url, params=params, json=json, headers=headers)
            if response.status_code in self.RETRY_STATUS and attempt < self._max_retries:
                wait = min(self._retry_after_seconds(response.headers), 120.0)
                logger.warning("ARM %s %s returned %s - retrying in %.0fs", method, url, response.status_code, wait)
                time.sleep(wait)
                attempt += 1
                continue
            response.raise_for_status()
            return response.json() if response.content else {}

    def _get_sync(self, path: str, api_version: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query = dict(params or {})
        query["api-version"] = api_version
        return self._request("GET", path, params=query)

    def _get_all_sync(self, path: str, api_version: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        payload = self._get_sync(path, api_version, params)
        items = list(payload.get("value", []))
        next_link = payload.get("nextLink")
        while next_link:
            payload = self._request("GET", next_link)
            items.extend(payload.get("value", []))
            next_link = payload.get("nextLink")
        return items

    def _post_sync(self, path: str, api_version: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", path, params={"api-version": api_version}, json=body)

    # -- public API ---------------------------------------------------------

    async def get(self, path: str, api_version: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await asyncio.to_thread(self._get_sync, path, api_version, params)

    async def get_all(self, path: str, api_version: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._get_all_sync, path, api_version, params)

    async def post(self, path: str, api_version: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return await asyncio.to_thread(self._post_sync, path, api_version, body)

    async def metrics_summary(
        self,
        resource_id: str,
        metric_names: Iterable[str],
        *,
        days: int = 30,
        interval: str = "P1D",
        aggregation: str = "Average,Maximum,Total",
    ) -> Dict[str, Dict[str, Optional[float]]]:
        """
        Return {metric: {"average", "maximum", "total", "latest_average"}} over
        the window. Missing data points are ignored rather than treated as 0.
        """
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        payload = await self.get(
            f"{resource_id}/providers/Microsoft.Insights/metrics",
            "2023-10-01",
            {
                "metricnames": ",".join(metric_names),
                "aggregation": aggregation,
                "interval": interval,
                "timespan": f"{start:%Y-%m-%dT%H:%M:%SZ}/{end:%Y-%m-%dT%H:%M:%SZ}",
            },
        )
        return summarize_metrics(payload)

    async def metric_totals_by(self, resource_id: str, metric: str, dimension: str, *,
                               days: int = 30) -> Dict[str, float]:
        """{dimension value: total over the window} for one metric split by one dimension (e.g. ApiName)."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        payload = await self.get(
            f"{resource_id}/providers/Microsoft.Insights/metrics",
            "2023-10-01",
            {
                "metricnames": metric,
                "aggregation": "Total",
                "interval": "P1D",
                "timespan": f"{start:%Y-%m-%dT%H:%M:%SZ}/{end:%Y-%m-%dT%H:%M:%SZ}",
                "$filter": f"{dimension} eq '*'",
                "top": str(METRIC_SPLIT_TOP),
            },
        )
        return totals_by_dimension(payload.get("value") or [])

    async def cost_query(self, scope: str, body: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Cost Management query; rows are returned as dicts keyed by column name."""
        payload = await self.post(f"{scope}/providers/Microsoft.CostManagement/query", "2023-11-01", body)
        rows = _cost_rows(payload)
        next_link = (payload.get("properties") or {}).get("nextLink")
        while next_link:
            payload = await asyncio.to_thread(self._request, "POST", next_link, json=body)
            rows.extend(_cost_rows(payload))
            next_link = (payload.get("properties") or {}).get("nextLink")
        return rows

    def close(self) -> None:
        self._http.close()


BURST_PCT = 90.0  # a point whose maximum reaches this had a burst (1-minute peaks count)


def percentile(values: List[float], pct: float) -> Optional[float]:
    """Nearest-rank percentile of already collected values; None when empty."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))]


def point_profile(averages: List[float], maxima: List[float]) -> Dict[str, Optional[float]]:
    """
    Shape of a utilisation series beyond its mean: the busiest point (busiest hour at PT1H), the 95th percentile
    of the point averages and how many points had a burst. A 30-day average of 1.5 % and a daily maximum of 100 %
    are both true for a plan that idles with nightly one-minute spikes - this tells the two apart.
    """
    return {
        "peak_average": max(averages) if averages else None,
        "p95_average": percentile(averages, 95),
        "burst_points": float(sum(1 for m in maxima if m >= BURST_PCT)) if maxima else None,
    }


def summarize_metrics(payload: Dict[str, Any]) -> Dict[str, Dict[str, Optional[float]]]:
    summary: Dict[str, Dict[str, Optional[float]]] = {}
    for metric in payload.get("value", []):
        name = (metric.get("name") or {}).get("value")
        points = [p for series in metric.get("timeseries", []) for p in series.get("data", [])]
        averages = [p["average"] for p in points if p.get("average") is not None]
        maxima = [p["maximum"] for p in points if p.get("maximum") is not None]
        totals = [p["total"] for p in points if p.get("total") is not None]
        summary[name] = {
            "average": sum(averages) / len(averages) if averages else None,
            "maximum": max(maxima) if maxima else None,
            "total": sum(totals) if totals else None,
            "latest_average": averages[-1] if averages else None,
            "points": float(len(points)),
            **point_profile(averages, maxima),
        }
    return summary


METRIC_SPLIT_TOP = 100  # Azure Monitor returns only 10 series per split unless asked for more

# Requests the platform makes against every storage account on its own (Defender for Storage, the portal, ARM
# inventory, CORS preflight, anonymous probes). About 120 a month with nobody using the account, so they say
# nothing about whether the data is read or written.
STORAGE_HOUSEKEEPING_APIS = frozenset(a.lower() for a in (
    "GetBlobServiceProperties", "GetFileServiceProperties", "GetQueueServiceProperties", "GetTableServiceProperties",
    "GetBlobServiceStats", "GetAccountInformation", "ListContainers", "ListShares", "ListQueues", "ListTables",
    "QueryTables", "GetContainerProperties", "GetContainerACL", "GetContainerServiceMetadata",
    "GetShareProperties", "GetShareStats", "BlobPreflightRequest", "FilePreflightRequest",
    "QueuePreflightRequest", "TablePreflightRequest",
))
# "Unknown" is anonymous or failed-auth traffic: a few dozen probes a month on any account, but a client that keeps
# calling (classic diagnostics, an app with a stale key) can make hundreds of thousands - only the excess counts.
STORAGE_UNKNOWN_ALLOWANCE = 50


def totals_by_dimension(values: List[Dict[str, Any]]) -> Dict[str, float]:
    """Sum each split series of a metrics response: {dimension value: total}."""
    out: Dict[str, float] = {}
    for metric in values:
        for series in metric.get("timeseries") or []:
            meta = series.get("metadatavalues") or []
            key = str(meta[0].get("value")) if meta else ""
            out[key] = out.get(key, 0.0) + sum(p.get("total") or 0.0 for p in series.get("data") or [])
    return out


def storage_data_operations(by_api: Dict[str, float]) -> float:
    """Transactions that actually read or write data: the ApiName split minus platform housekeeping."""
    total = 0.0
    for api, value in by_api.items():
        if api.lower() == "unknown":
            total += max(0.0, value - STORAGE_UNKNOWN_ALLOWANCE)
        elif api.lower() not in STORAGE_HOUSEKEEPING_APIS:
            total += value
    return total


def _cost_rows(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    props = payload.get("properties") or {}
    columns = [c.get("name") for c in props.get("columns", [])]
    return [dict(zip(columns, row)) for row in props.get("rows", [])]


# ---------------------------------------------------------------------------
# Cost helpers (shared per scan)
# ---------------------------------------------------------------------------

def _cost_body(start: date, end: date, grouping: List[Dict[str, str]], granularity: str = "None",
               include_usd: bool = True) -> Dict[str, Any]:
    aggregation = {"totalCost": {"name": "Cost", "function": "Sum"}}
    if include_usd:
        aggregation["totalCostUSD"] = {"name": "CostUSD", "function": "Sum"}
    return {
        "type": "ActualCost",
        "timeframe": "Custom",
        "timePeriod": {"from": start.isoformat(), "to": end.isoformat()},
        "dataset": {"granularity": granularity, "aggregation": aggregation, "grouping": grouping},
    }


async def run_cost_query(context: Any, start: date, end: date, grouping: List[Dict[str, str]],
                         granularity: str = "None") -> Optional[List[Dict[str, Any]]]:
    """
    Cost query that asks for CostUSD alongside the billing-currency Cost.
    Some agreement types reject CostUSD - retry once without it.
    """
    arm = getattr(context, "arm_client", None)
    if arm is None:
        return None
    scope = f"/subscriptions/{context.subscription_id}"
    try:
        return await arm.cost_query(scope, _cost_body(start, end, grouping, granularity, include_usd=True))
    except Exception as exc:
        logger.info("CostUSD aggregation rejected (%s); retrying with billing currency only", exc)
        return await arm.cost_query(scope, _cost_body(start, end, grouping, granularity, include_usd=False))


async def get_resource_costs(context: Any, days: int = 30) -> Optional[Dict[str, Dict[str, Any]]]:
    """
    {lower(resource_id): {"cost", "cost_usd", "currency", "meters": {subcategory: cost}}}
    for the last `days` days. Cached on context.cache for the whole scan.
    """
    cache = getattr(context, "cache", None)
    key = f"resource_costs:{days}"
    if cache is not None and key in cache:
        return cache[key]

    end = date.today()
    start = end - timedelta(days=days)
    try:
        rows = await run_cost_query(
            context, start, end,
            [{"type": "Dimension", "name": "ResourceId"}, {"type": "Dimension", "name": "MeterSubCategory"}],
        )
    except Exception as exc:
        logger.warning("Cost query failed: %s", exc)
        rows = None

    result: Optional[Dict[str, Dict[str, Any]]] = None
    if rows is not None:
        result = {}
        for row in rows:
            rid = (row.get("ResourceId") or "").lower()
            if not rid:
                continue
            entry = result.setdefault(rid, {"cost": 0.0, "cost_usd": 0.0, "currency": row.get("Currency"), "meters": {}})
            cost = float(row.get("Cost") or 0.0)
            entry["cost"] += cost
            if row.get("CostUSD") is not None:
                entry["cost_usd"] += float(row["CostUSD"])
            elif (row.get("Currency") or "").upper() == "USD":
                entry["cost_usd"] += cost
            else:
                entry["cost_usd"] = None if entry["cost_usd"] in (None, 0.0) else entry["cost_usd"]
            subcat = row.get("MeterSubCategory") or "unknown"
            entry["meters"][subcat] = entry["meters"].get(subcat, 0.0) + cost

    if cache is not None:
        cache[key] = result
    return result


def cost_for(costs: Optional[Dict[str, Dict[str, Any]]], resource_id: str) -> Optional[Dict[str, Any]]:
    if not costs or not resource_id:
        return None
    return costs.get(resource_id.lower())


async def cached_metrics(context: Any, resource_id: str, metric_names: List[str], *, days: int = 30,
                         interval: str = "P1D", aggregation: str = "Average,Maximum,Total") -> Dict[str, Dict[str, Optional[float]]]:
    """metrics_summary() memoised on context.cache so two scanners never fetch the same series twice."""
    key = f"metrics:{resource_id.lower()}:{','.join(metric_names)}:{days}:{interval}:{aggregation}"
    cache = getattr(context, "cache", None)
    if cache is not None and key in cache:
        return cache[key]
    result = await context.arm_client.metrics_summary(resource_id, metric_names, days=days,
                                                      interval=interval, aggregation=aggregation)
    if cache is not None:
        cache[key] = result
    return result


# ---------------------------------------------------------------------------
# Retail prices (public API, USD)
# ---------------------------------------------------------------------------

async def get_retail_price(context: Any, odata_filter: str, *, fallback: Optional[float] = None) -> Optional[float]:
    """
    Unit retail price (USD) for the first Consumption item matching the
    filter. Only queried in live mode (arm_client present) so unit tests
    and mock scans stay deterministic and offline.
    """
    if getattr(context, "arm_client", None) is None:
        return fallback
    if odata_filter in _RETAIL_PRICE_CACHE:
        cached = _RETAIL_PRICE_CACHE[odata_filter]
        return cached if cached is not None else fallback

    def _fetch() -> Optional[float]:
        import httpx

        response = httpx.get(RETAIL_PRICES_URL, params={"$filter": f"{odata_filter} and priceType eq 'Consumption'"}, timeout=30)
        response.raise_for_status()
        items = response.json().get("Items", [])
        return float(items[0]["retailPrice"]) if items else None

    try:
        price = await asyncio.to_thread(_fetch)
    except Exception as exc:
        logger.info("Retail price lookup failed (%s): %s", odata_filter, exc)
        price = None
    _RETAIL_PRICE_CACHE[odata_filter] = price
    return price if price is not None else fallback


# ---------------------------------------------------------------------------
# Small shared utilities
# ---------------------------------------------------------------------------

DEFAULT_ARM_CONCURRENCY = 8


async def gather_limited(items: Iterable[Any], fn, limit: int = DEFAULT_ARM_CONCURRENCY) -> List[Any]:
    """
    Run `await fn(item)` for every item with at most `limit` in flight. Used for
    per-resource ARM calls (metrics, diagnostic settings, config) that dominate
    scan time on large subscriptions. Results keep the input order.
    """
    gate = asyncio.Semaphore(max(1, int(limit)))

    async def run(item: Any) -> Any:
        async with gate:
            return await fn(item)

    return list(await asyncio.gather(*(run(i) for i in items)))

def rid_segment(resource_id: Optional[str], after: str) -> Optional[str]:
    """Return the path segment following `after` (case-insensitive) in an ARM ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    lowered = [p.lower() for p in parts]
    try:
        return parts[lowered.index(after.lower()) + 1]
    except (ValueError, IndexError):
        return None


def subscription_resource_id(subscription_id: str) -> str:
    return f"/subscriptions/{subscription_id}"


async def get_defender_plans(context: Any) -> Optional[Dict[str, str]]:
    """{plan name: pricing tier} from Defender for Cloud (cached per scan); None without a client."""
    cache = getattr(context, "cache", None)
    if cache is not None and "defender_plans" in cache:
        return cache["defender_plans"]
    rows = await query_resource_graph(context, f"""
        securityresources
        | where type =~ 'microsoft.security/pricings'
        | where subscriptionId == '{context.subscription_id}'
        | project name, tier = tostring(properties.pricingTier), sub_plan = tostring(properties.subPlan)
    """)
    plans = None if rows is None else {r.get("name"): r.get("tier") for r in rows}
    if cache is not None:
        cache["defender_plans"] = plans
    return plans
