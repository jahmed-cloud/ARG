"""
Utilisation profiles: a 30-day average of 1.5 % and a daily maximum of 100 % are both true for an App Service plan
that idles with one-minute nightly bursts. Saturation needs a busy hour; the busiest hour, P95 and burst hours are
reported next to the average (scanners and estate).
"""

import asyncio
from types import SimpleNamespace

import scanners.compute.compute_posture_scanners as compute
import scanners.database.database_scanners  # noqa: F401
from scanners.base.azure_api import percentile, point_profile, summarize_metrics
from scanners.base.base_scanner import ScanContext, ScannerRegistry


def test_percentile_uses_nearest_rank_at_boundaries():
    assert percentile([1, 2, 3, 4], 50) == 2
    assert percentile(list(range(1, 21)), 95) == 19
    assert percentile([8, 2, 5], 0) == 2
    assert percentile([8, 2, 5], 100) == 8


def test_point_profile_separates_bursts_from_busy_hours():
    hourly_avg = [1.5] * 700 + [8.2] + [3.0] * 19
    hourly_max = [4.0] * 680 + [100.0] * 40
    profile = point_profile(hourly_avg, hourly_max)
    assert profile == {"peak_average": 8.2, "p95_average": 1.5, "burst_points": 40.0}   # 700 of 720 hours at 1.5 %
    assert percentile([], 95) is None and percentile([5.0], 95) == 5.0
    payload = {"value": [{"name": {"value": "CpuPercentage"},
                          "timeseries": [{"data": [{"average": a, "maximum": m} for a, m in zip(hourly_avg, hourly_max)]}]}]}
    summary = summarize_metrics(payload)["CpuPercentage"]
    assert summary["maximum"] == 100.0 and summary["peak_average"] == 8.2 and round(summary["average"], 2) == 1.55


class PlanArm:
    """Hourly CpuPercentage / MemoryPercentage per plan name."""

    def __init__(self, plans):
        self.plans, self.calls = plans, []

    async def metrics_summary(self, resource_id, names, **kwargs):
        self.calls.append(kwargs)
        cpu, mem = self.plans[resource_id.rsplit("/", 1)[-1]]
        points = [{"average": a, "maximum": m} for a, m in cpu]
        return summarize_metrics({"value": [
            {"name": {"value": "CpuPercentage"}, "timeseries": [{"data": points}]},
            {"name": {"value": "MemoryPercentage"}, "timeseries": [{"data": [{"average": mem}]}]}]})

    async def cost_query(self, scope, body):
        return [{"ResourceId": _plan("quiet", "P2v3")["id"], "MeterSubCategory": "Premium v3", "Cost": 300.0,
                 "CostUSD": 300.0, "Currency": "USD"}]


def _plan(name, sku):
    return {"id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/serverfarms/{name}", "name": name,
            "type": "microsoft.web/serverfarms", "resourceGroup": "rg", "subscriptionId": "s",
            "location": "westeurope", "sku_name": sku, "capacity": 2, "sites": 4, "tags": {}}


class Graph:
    def __init__(self, rows):
        self.rows = rows

    def resources(self, request):
        return SimpleNamespace(data=self.rows, skip_token=None)


def test_plan_bursts_are_not_saturation_and_idle_plans_are_oversized():
    bursty = [(1.5, 4.0)] * 690 + [(8.2, 100.0)] * 30          # idles with nightly bursts: 1.5 % avg, 100 % peaks
    busy = [(20.0, 60.0)] * 600 + [(88.0, 100.0)] * 120        # a busy afternoon every day
    arm = PlanArm({"bursty": (bursty, 43.6), "busy": (busy, 50.0), "quiet": (bursty, 20.0)})
    ctx = ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j", arm_client=arm, cost_management_client=arm,
                      resource_graph_client=Graph([_plan("bursty", "P2v2"), _plan("busy", "P1v3"),
                                                   _plan("quiet", "P2v3")]))
    out = asyncio.run(ScannerRegistry.get("app_service_plan_utilization_scanner")(config={}).execute(ctx))
    found = {f.resource_name: f for f in out.findings}
    assert all(c.get("interval") == "PT1H" for c in arm.calls)
    assert found["busy"].finding_type == "app_service_plan_cpu_saturated"
    assert found["busy"].title == "CPU saturated (busiest hour 88%): busy"
    assert "bursty" not in found                                  # 43.6 % memory: one size down would not fit
    quiet = found["quiet"]
    assert quiet.finding_type == "app_service_plan_underutilized" and quiet.estimated_monthly_savings_usd == 150.0
    assert "P1v3" in quiet.azure_cli_script and "busiest hour 8.2%" in quiet.description
    assert "one-minute peaks reached 100% in 30 hour(s)" in quiet.description


def test_smaller_plan_sku():
    assert [compute.smaller_plan_sku(s) for s in ("P2v2", "P3v3", "P1v3", "P1v2", "S2", "B1", "P2mv3", "Y1", None)] == \
        ["P1v2", "P2v3", "P0v3", None, "S1", None, "P1mv3", None, None]


def test_sql_spikes_are_not_saturation():
    ctx = ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j")
    out = asyncio.run(ScannerRegistry.get("sql_database_utilization_scanner")(config={}).execute(ctx))
    by_type = {}
    for f in out.findings:
        by_type.setdefault(f.finding_type, set()).add(f.resource_name.split("/")[-1])
    assert by_type["sql_database_cpu_saturated"] == {"db-hs-1"}  # db-spiky: 100 % peaks, busiest hour 41 %
    assert by_type["idle_sql_database"] == {"db-analysis"}        # 3 % maintenance spikes, no connections: idle


def test_estate_hourly_profile_for_every_percentage_metric(monkeypatch):
    import scanners.base.azure_api as azure_api
    from scripts.subscription_analysis import estate

    class FakeArm:
        def __init__(self, credential):
            pass

        def close(self):
            pass

    class Cred:
        def get_token(self, scope):
            return SimpleNamespace(token="t", expires_on=9e12)

    def daily(token, sub, region, namespace, names, ids, start, end):
        values = [{"name": {"value": n}, "timeseries": [{"data": [{"average": 1.5, "maximum": 100.0}] * 30}]}
                  for n in names]
        return {rid.lower(): estate._summarize(values) for rid in ids}

    asked = []

    def hourly(token, sub, region, namespace, names, ids, start, end):
        asked.append(names)
        if len(names) > 1 and namespace == "microsoft.apimanagement/service":
            raise RuntimeError("400 time grain")                # retried metric by metric
        data = {"CpuPercentage": [{"average": 8.2, "maximum": 100.0}] + [{"average": 1.0, "maximum": 3.0}] * 719,
                "MemoryPercentage": [{"average": 61.0, "maximum": 70.0}] * 720,
                "Capacity": [{"average": 72.0, "maximum": 90.0}] * 720}
        values = [{"name": {"value": n}, "timeseries": [{"data": data.get(n, [])}]} for n in names]
        return {rid.lower(): estate._summarize(values) for rid in ids}

    monkeypatch.setattr(azure_api, "ArmClient", FakeArm)
    base = {"location": "westeurope", "subscriptionId": "s"}
    plan = dict(base, id="/plan", type="microsoft.web/serverfarms")
    apim = dict(base, id="/apim", type="microsoft.apimanagement/service")
    asyncio.run(estate.collect_usage(Cred(), [plan, apim], fetch=daily, fetch_hourly=hourly))
    assert (plan["cpuAvg"], plan["cpuMax"], plan["cpuPeakHour"], plan["burstHours"], plan["memPeakHour"]) == \
        (1.5, 100.0, 8.2, 1, 61.0)
    assert ["CpuPercentage", "MemoryPercentage"] in asked and ["Capacity"] in asked
    assert "capacity busiest hour 72 %" in estate.usage_of(apim)
    wire = estate.compact(estate.build_estate(__import__("pathlib").Path("none"), {
        "generated_at": None, "source": "resource-graph", "subscriptions": [], "resources": [plan]}))
    assert wire["resources"][0]["cpuHr"] == 8.2 and wire["resources"][0]["burst"] == 1
