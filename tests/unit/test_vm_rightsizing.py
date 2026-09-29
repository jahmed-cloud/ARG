"""
Validated VM right-sizing (vm_rightsizing_scanner): Azure Advisor's documented resize rules with the strict
user-facing limits, plus hardware compatibility, disk / network headroom and burstable baselines. A resize is
suggested only when every check passes - the aim is no false positives.
"""

import asyncio
from datetime import datetime, timezone

import scanners.compute.compute_posture_scanners as compute
from scanners.base.base_scanner import ScanContext, ScannerRegistry

GB = 1024 ** 3


def sku(name, family, vcpu, mem, **caps):
    base = {"vCPUs": str(vcpu), "MemoryGB": str(mem), "PremiumIO": "True", "HyperVGenerations": "V1,V2",
            "MaxDataDiskCount": "8", "MaxNetworkInterfaces": "2", "AcceleratedNetworkingEnabled": "True",
            "UncachedDiskIOPS": str(3200 * vcpu), "UncachedDiskBytesPerSecond": str(48000000 * vcpu),
            "CpuArchitectureType": "x64", "MaxResourceVolumeMB": "0"}
    base.update({k: str(v) for k, v in caps.items()})
    return {"name": name, "family": family, "caps": base, "restricted": False, "restricted_zones": set()}


D4 = sku("Standard_D4s_v5", "standardDSv5Family", 4, 16)
D2 = sku("Standard_D2s_v5", "standardDSv5Family", 2, 8)
QUIET = {"cpu_windows": 1440, "mem_windows": 1440, "cpu_avg": 1.9, "cpu_p95": 6.0, "cpu_p99": 14.0,
         "mem_used_p99_gb": 4.1, "disk_uncached_p95": 3.0, "disk_cached_p95": 0.0, "net_p95_mbps": 2.5}
VM = {"name": "vm1", "gen": "V2", "nics": 1, "dataDisks": 1}


def test_burstable_baselines_from_microsoft_learn():
    assert [compute.burst_baseline(s) for s in (
        "Standard_B2ms", "Standard_B4ms", "Standard_B8ms", "Standard_B2ats_v2", "Standard_B4als_v2",
        "Standard_B8as_v2", "Standard_B2s_v2", "Standard_B2pts_v2", "Standard_D4s_v5")] == \
        [30.0, 22.5, 17.0, 20.0, 30.0, 40.0, 40.0, None, None]


def test_profile_uses_30_minute_peaks_and_lowest_free_memory():
    def pts(**kw):
        return [dict(timeStamp=f"t{i}", **{k: v[i] for k, v in kw.items()}) for i in range(len(next(iter(kw.values()))))]
    payload = {"value": [
        {"name": {"value": "Percentage CPU"}, "timeseries": [{"data": pts(maximum=[5.0] * 94 + [90.0] * 6,
                                                                          average=[2.0] * 100)}]},
        {"name": {"value": "Available Memory Bytes"}, "timeseries": [{"data": pts(minimum=[12 * GB] * 97 + [4 * GB] * 3)}]},
        {"name": {"value": "Network Out Total"}, "timeseries": [{"data": pts(total=[225_000_000.0] * 100)}]},
        {"name": {"value": "VM Uncached IOPS Consumed Percentage"}, "timeseries": [{"data": pts(maximum=[2.0] * 100)}]},
        {"name": {"value": "VM Uncached Bandwidth Consumed Percentage"}, "timeseries": [{"data": pts(maximum=[7.0] * 100)}]},
    ]}
    p = compute.vm_profile(payload, 16.0)
    assert (p["cpu_windows"], p["cpu_p95"], p["cpu_p99"], p["cpu_avg"]) == (100, 90.0, 90.0, 2.0)
    assert p["mem_used_p99_gb"] == 12.0 and p["disk_uncached_p95"] == 7.0 and p["net_p95_mbps"] == 1.0


def test_exclusions():
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    ok = {"power": "PowerState/running", "created": "2025-01-01", "resourceGroup": "rg"}
    assert compute.rightsizing_exclusion(ok, now) is None
    assert compute.rightsizing_exclusion(dict(ok, offer="fortinet_fortigate-vm_v5"), now) == "network virtual appliance"
    assert compute.rightsizing_exclusion(dict(ok, priority="Spot"), now) == "Spot VM"
    assert compute.rightsizing_exclusion(dict(ok, resourceGroup="MC_aks_westeurope"), now).startswith("managed by")
    assert compute.rightsizing_exclusion(dict(ok, created="2026-09-10"), now).startswith("created 18 days ago")
    assert compute.rightsizing_exclusion(dict(ok, power="PowerState/deallocated"), now) == "not running"
    assert compute.rightsizing_exclusion(dict(ok, ephemeral="Local"), now).startswith("ephemeral")
    assert compute.rightsizing_exclusion(dict(ok, tags={"arg-reserved": "true"}), now).startswith("tagged")


def test_quiet_vm_passes_one_size_down():
    fails, projected = compute.evaluate_rightsizing(VM, D4, D2, QUIET)
    assert fails == []
    assert (projected["cpu_p95"], projected["cpu_p99"], round(projected["mem_p99_pct"])) == (12.0, 28.0, 51)
    assert projected["disk_uncached_p95"] == 6.0                       # half the disk limits: consumption doubles


def test_each_check_blocks_a_resize():
    def fails(vm=VM, cur=D4, tgt=D2, **profile):
        return compute.evaluate_rightsizing(vm, cur, tgt, dict(QUIET, **profile))[0]

    assert fails(cpu_p95=25.0) == ["CPU P95 would be 50% (limit 40%)"]
    assert fails(cpu_p99=45.0) == ["CPU P99 would be 90% (limit 80%)"]
    assert fails(mem_used_p99_gb=5.5) == ["memory P99 would be 69% (limit 60%)"]
    assert fails(disk_uncached_p95=25.0) == ["disk P95 would be 50% of the size's limits (limit 40%)"]
    assert fails(net_p95_mbps=250.0) == ["network P95 250 Mbps above the 100 Mbps check"]
    assert fails(cpu_windows=1000) == ["less than 90 % of the 30 days measured (CPU or memory)"]
    assert fails(disk_cached_p95=12.0) == ["the VM uses its host cache and the size has no cache"]
    with_temp = dict(D4, caps=dict(D4["caps"], MaxResourceVolumeMB="153600"))
    assert "Azure cannot resize to a size without one" in fails(cur=with_temp)[0]
    assert fails(tgt=dict(D2, caps=dict(D2["caps"], AcceleratedNetworkingEnabled="False")),
                 vm=dict(VM, accelerated=True)) == ["no Accelerated Networking (enabled on the VM's NIC)"]
    assert fails(tgt=dict(D2, caps=dict(D2["caps"], HyperVGenerations="V1"))) == ["no Hyper-V V2 support"]
    assert fails(tgt=dict(D2, restricted_zones={"2"}), vm=dict(VM, zones=["2"]))[0].startswith("not offered")
    assert fails(vm=dict(VM, dataDisks=12)) == ["12 data disks exceed the size's limit"]


def test_burstable_target_must_keep_its_credits():
    b8 = sku("Standard_B8as_v2", "standardBasv2Family", 8, 32, UncachedDiskIOPS=12800,
             UncachedDiskBytesPerSecond=290000000)
    d8 = sku("Standard_D8s_v5", "standardDSv5Family", 8, 32)
    quiet = dict(QUIET, mem_used_p99_gb=10.0)
    assert compute.evaluate_rightsizing(VM, d8, b8, quiet)[0] == []
    assert compute.evaluate_rightsizing(VM, d8, b8, dict(quiet, cpu_avg=35.0))[0] == \
        ["average CPU 35% would spend CPU credits (baseline 40%)"]


def test_candidates_are_advisor_target_and_one_size_down():
    cat = {s["name"].lower(): s for s in (D4, D2, sku("Standard_B4as_v2", "standardBasv2Family", 4, 16))}
    names = [(c["name"], c["source"]) for c in compute.rightsizing_candidates(D4, cat, "Standard_B4as_v2")]
    assert names == [("Standard_B4as_v2", "Azure Advisor"), ("Standard_D2s_v5", "one size down")]


def _mock_findings():
    ctx = ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j")
    return {f.resource_name: f for f in asyncio.run(ScannerRegistry.get("vm_rightsizing_scanner")(config={}).execute(ctx)).findings}


def test_scanner_recommends_only_what_passes():
    found = _mock_findings()
    assert set(found) == {"vm-app-01"}               # vm-search-01 is memory-bound, vm-batch-01 CPU-bound
    f = found["vm-app-01"]
    assert f.title == "Right-size vm-app-01: Standard_D4s_v5 to Standard_D2s_v5 (~USD 84/month)"
    assert f.estimated_monthly_savings_usd == 83.95 and f.evidence["covered_by_commitment"] is False
    assert "inside Microsoft's limits for user-facing workloads" in f.description
    assert f.azure_cli_script.endswith("--size Standard_D2s_v5")


def test_commitment_covered_vm_is_valued_on_amortized_cost():
    scanner = ScannerRegistry.get("vm_rightsizing_scanner")(config={})
    case = scanner._mock_data()[0]
    case["cost_usd"], case["actual_cost_usd"] = 168.0, 0.7   # amortized share vs pay-as-you-go invoiced here
    choice = asyncio.run(scanner._choose(ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j"), case))
    f = scanner._finding(case, choice)
    assert f.evidence["covered_by_commitment"] is True and f.estimated_monthly_savings_usd == 83.95
    assert f.evidence["amortized_cost_usd_30d"] == 168.0 and f.evidence["actual_cost_usd_30d"] == 0.7
    assert "frees that commitment for other VMs" in f.description


def test_uncovered_vm_saving_never_exceeds_its_amortized_cost():
    scanner = ScannerRegistry.get("vm_rightsizing_scanner")(config={})
    case = scanner._mock_data()[0]
    case["cost_usd"], case["actual_cost_usd"] = 40.0, 40.0   # part-month: less than the retail difference
    choice = asyncio.run(scanner._choose(ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j"), case))
    f = scanner._finding(case, choice)
    assert f.evidence["covered_by_commitment"] is False and f.estimated_monthly_savings_usd == 20.0
    assert f.title == "Right-size vm-app-01: Standard_D4s_v5 to Standard_D2s_v5 (~USD 20/month)"
    assert "Value: about USD 20/month (USD 240/year), scaled to this VM's 30-day amortized cost of USD 40" in f.description
    assert "the list-price difference is USD 84/month" in f.description and f.severity.value == "low"


def test_capped_saving_below_the_floor_is_not_suggested(monkeypatch):
    scanner = ScannerRegistry.get("vm_rightsizing_scanner")(config={})
    cases = scanner._mock_data()
    for case in cases:
        case["cost_usd"], case["actual_cost_usd"] = 10.0, 10.0   # ran a few days: resizing saves ~USD 5/month
    monkeypatch.setattr(scanner, "_mock_data", lambda: cases)
    ctx = ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j")
    assert asyncio.run(scanner.execute(ctx)).findings == []


def test_value_mentions_end_of_life_series():
    scanner = ScannerRegistry.get("vm_rightsizing_scanner")(config={})
    case = scanner._mock_data()[0]
    for spec in (case["current"], case["catalogue"]["standard_d2s_v5"]):
        spec["caps"] = dict(spec["caps"], RetirementDateUtc="11/15/2028")
    choice = asyncio.run(scanner._choose(ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j"), case))
    assert "end-of-life series retiring on 2028-11-15" in scanner._finding(case, choice).description


def test_estate_lists_validated_suggestions_first():
    from scripts.subscription_analysis.estate import _validated_rightsizing

    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    lines = _validated_rightsizing([{"id": rid, "subscription": "sub-a"}], [
        {"type": "vm_rightsizing_opportunity", "title": "Right-size vm1: Standard_D4s_v5 to Standard_D2s_v5 (~USD 84/month)",
         "savingsUsd": 83.95, "resourceName": "vm1", "resourceId": rid, "subscriptionId": "s"}])
    assert lines[0] == "### Validated right-sizing suggestions (1)"
    assert "| vm1 | Standard_D4s_v5 to Standard_D2s_v5 (~USD 84/month) | 84 | sub-a |" in "\n".join(lines)
