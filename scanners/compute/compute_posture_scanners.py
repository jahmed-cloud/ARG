"""
Azure Resource Guardian - Compute & App Service Posture Scanners
=================================================================
Scanners in this module:
1. UnsupportedOSImageScanner           - VMs built from end-of-support OS images
2. ManagedDiskNetworkAccessScanner     - Disks exportable from any network
3. AppServicePlanGenerationScanner     - Premium v2 plans (no reservations, older CPUs)
                                          and single-instance production plans
4. AppServicePlanUtilizationScanner    - Plans running hot (CPU saturation)
5. AppServiceMixedEnvironmentScanner   - Production and non-production on one plan
6. WebAppHttpsAndIdentityScanner       - HTTP allowed / no managed identity
7. WebAppConfigurationScanner          - EOL runtime stack, TLS, FTP, health check, 32-bit worker

Metric- and config-based checks run only when an ArmClient is injected
(live mode); mock rows carry the enriched values for offline testing.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from scanners.base.azure_api import (
    DEFAULT_ARM_CONCURRENCY,
    HOURS_BILLED_PER_MONTH,
    HOURS_PER_MONTH,
    compute_skus,
    cost_for,
    gather_limited,
    get_resource_costs,
    get_retail_price,
    percentile,
    vm_hourly_usd,
)
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.naming import env_from_name, env_from_tags, is_nva_image
from scanners.base.posture_scanner import PostureScanner


def _as_date(value: Any) -> date:
    if isinstance(value, date):
        return value
    return datetime.fromisoformat(str(value)).date()


# ---------------------------------------------------------------------------
# 1. End-of-support OS images
# ---------------------------------------------------------------------------

# (offer regex, sku regex, end-of-support date, label) - matched case-insensitively
# against storageProfile.imageReference. Dates are vendor end-of-support
# (no security updates without paid ESU).
OS_END_OF_SUPPORT: List[Tuple[str, str, str, str]] = [
    (r"windows-10", r".*", "2025-10-14", "Windows 10"),
    (r"windows-10", r"^(rs\d|19h1|19h2|20h1|20h2|21h1)", "2022-12-13", "Windows 10 (feature release)"),
    (r"windowsserver", r"2008", "2020-01-14", "Windows Server 2008 R2"),
    (r"windowsserver", r"2012", "2023-10-10", "Windows Server 2012 / 2012 R2"),
    (r"ubuntuserver", r"^16\.04", "2021-04-30", "Ubuntu 16.04 LTS"),
    (r"ubuntuserver", r"^18\.04", "2023-05-31", "Ubuntu 18.04 LTS"),
    (r"ubuntu-server-focal|ubuntu.*20_04", r".*", "2025-05-31", "Ubuntu 20.04 LTS"),
    (r"centos", r".*", "2024-06-30", "CentOS"),
    (r"^rhel$", r"^7", "2024-06-30", "RHEL 7"),
    (r"debian-10", r".*", "2024-06-30", "Debian 10"),
    (r"sles", r"12", "2024-10-31", "SLES 12"),
]


def os_end_of_support(offer: str, sku: str, as_of: date) -> Optional[Tuple[str, date]]:
    """Most specific (earliest) matching EoS entry that has passed as of `as_of`."""
    matches = []
    for offer_rx, sku_rx, eos, label in OS_END_OF_SUPPORT:
        if re.search(offer_rx, offer or "", re.I) and re.search(sku_rx, sku or "", re.I):
            eos_date = _as_date(eos)
            if eos_date <= as_of:
                matches.append((eos_date, label))
    if not matches:
        return None
    eos_date, label = min(matches)
    return label, eos_date


@register_scanner
class UnsupportedOSImageScanner(PostureScanner):
    """VMs whose marketplace image is past vendor end of support."""

    scanner_name = "unsupported_os_image_scanner"
    display_name = "End-of-Support Operating System"
    description = "Detects VMs built from operating system images past end of support"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.CRITICAL

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.compute/virtualmachines'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  publisher = tostring(properties.storageProfile.imageReference.publisher),
                  offer = tostring(properties.storageProfile.imageReference.offer),
                  sku = tostring(properties.storageProfile.imageReference.sku),
                  vm_size = tostring(properties.hardwareProfile.vmSize),
                  power_state = tostring(properties.extended.instanceView.powerState.code),
                  created = tostring(properties.timeCreated)
        """
        try:
            vms = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        as_of = _as_date(self.setting("as_of", date.today()))
        findings = []
        for vm in vms:
            hit = os_end_of_support(vm.get("offer"), vm.get("sku"), as_of)
            if not hit:
                continue
            label, eos = hit
            findings.append(self.resource_finding(
                vm,
                finding_type="vm_unsupported_os",
                title=f"End-of-support OS ({label}): {vm['name']}",
                description=(
                    f"VM '{vm['name']}' ({vm.get('vm_size')}) runs {vm.get('offer')}/{vm.get('sku')} - "
                    f"{label} reached end of support on {eos.isoformat()} and no longer receives "
                    f"security updates. Power state: {vm.get('power_state') or 'unknown'}."
                ),
                resource_type="microsoft.compute/virtualmachines",
                remediation_steps=(
                    "1. Decide whether the VM is still needed; decommission if not.\n"
                    "2. Otherwise rebuild on a supported image (Windows 11 / Server 2022+, Ubuntu 22.04+), "
                    "Trusted Launch, no public IP, access via Bastion/JIT.\n"
                    "3. As a stop-gap, isolate the VM (NSG deny inbound) until rebuilt."
                ),
                azure_cli_script=(
                    f"az vm show -g {vm.get('resourceGroup')} -n {vm['name']} --query storageProfile.imageReference\n"
                    f"# after sign-off:\naz vm delete -g {vm.get('resourceGroup')} -n {vm['name']} --yes"
                ),
                evidence={"publisher": vm.get("publisher"), "offer": vm.get("offer"), "sku": vm.get("sku"),
                          "end_of_support": eos.isoformat(), "power_state": vm.get("power_state"),
                          "created": vm.get("created")},
                nist_control="SI-2",
                estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(vms))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-vm/providers/Microsoft.Compute/virtualMachines/vm-win10-1",
            "name": "vm-win10-1", "type": "microsoft.compute/virtualmachines", "resourceGroup": "rg-vm",
            "subscriptionId": "sub-1", "location": "westeurope", "publisher": "MicrosoftWindowsDesktop",
            "offer": "Windows-10", "sku": "19h2-pro", "vm_size": "Standard_B2s",
            "power_state": "PowerState/deallocated", "created": "2020-03-30T13:38:00Z",
        }]


# ---------------------------------------------------------------------------
# 2. Managed disks exportable from any network
# ---------------------------------------------------------------------------

@register_scanner
class ManagedDiskNetworkAccessScanner(PostureScanner):
    """networkAccessPolicy=AllowAll lets anyone with RBAC generate a public SAS export URL."""

    scanner_name = "managed_disk_network_access_scanner"
    display_name = "Managed Disk Open Network Access"
    description = "Detects managed disks whose export/import is allowed from any network"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.LOW

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.compute/disks'
        | where tostring(properties.networkAccessPolicy) =~ 'AllowAll'
        | where tostring(properties.publicNetworkAccess) !~ 'Disabled'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  managed_by = tostring(managedBy), size_gb = toint(properties.diskSizeGB)
        """
        try:
            disks = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = [
            self.resource_finding(
                d,
                finding_type="managed_disk_public_network_access",
                title=f"Disk export open to any network: {d['name']}",
                description=(
                    f"Managed disk '{d['name']}' ({d.get('size_gb')} GB) allows SAS export/import from any "
                    f"network (networkAccessPolicy=AllowAll, public network access enabled)."
                ),
                resource_type="microsoft.compute/disks",
                remediation_steps="Set networkAccessPolicy to DenyAll (or AllowPrivate via a disk access resource).",
                azure_cli_script=(
                    f"az disk update -g {d.get('resourceGroup')} -n {d['name']} "
                    f"--network-access-policy DenyAll --public-network-access Disabled"
                ),
                evidence={"managed_by": d.get("managed_by"), "size_gb": d.get("size_gb")},
                estimated_monthly_savings_usd=0.0,
            )
            for d in disks
        ]
        return ScanOutput(findings=findings, resources_scanned=len(disks))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-vm/providers/Microsoft.Compute/disks/disk-os-1",
            "name": "disk-os-1", "type": "microsoft.compute/disks", "resourceGroup": "rg-vm",
            "subscriptionId": "sub-1", "location": "westeurope", "managed_by": None, "size_gb": 127,
        }]


# ---------------------------------------------------------------------------
# 3. App Service plan generation / single instance
# ---------------------------------------------------------------------------

# Premium v2 -> closest Premium v3 by vCPU (P1v2 1c, P2v2 2c, P3v2 4c).
PV2_TO_PV3 = {"P1v2": "P0v3", "P2v2": "P1v3", "P3v2": "P2v3"}
# Hourly USD list prices (westeurope, Aug 2026) used when the Retail API is unavailable.
APP_SERVICE_HOURLY_USD = {
    ("P1v2", False): 0.200, ("P2v2", False): 0.400, ("P3v2", False): 0.800,
    ("P0v3", False): 0.169, ("P1v3", False): 0.338, ("P2v3", False): 0.676, ("P3v3", False): 1.352,
    ("P1v2", True): 0.115, ("P2v2", True): 0.231, ("P3v2", True): 0.462,
    ("P0v3", True): 0.089, ("P1v3", True): 0.178, ("P2v3", True): 0.356, ("P3v3", True): 0.712,
}


def _meter_name(sku: str) -> str:
    # Retail API meter names: "P3 v2 App", "P1 v3 App", but "P0v3 App".
    return f"{sku} App" if sku == "P0v3" else f"{sku[:2]} {sku[2:]} App"


async def app_service_hourly_usd(context: ScanContext, sku: str, linux: bool, region: str) -> Optional[float]:
    family = "Premium v3" if sku.endswith("v3") else "Premium v2"
    product = f"Azure App Service {family} Plan" + (" - Linux" if linux else "")
    return await get_retail_price(
        context,
        f"serviceName eq 'Azure App Service' and armRegionName eq '{region}' "
        f"and productName eq '{product}' and meterName eq '{_meter_name(sku)}'",
        fallback=APP_SERVICE_HOURLY_USD.get((sku, linux)),
    )


@register_scanner
class AppServicePlanGenerationScanner(PostureScanner):
    """
    Premium v2 is a previous generation: slower cores, no reserved-instance
    option. The same core count on Premium v3 is cheaper PAYG and can be
    reserved (~35-45% off). Also flags production plans with one instance.
    """

    scanner_name = "app_service_plan_generation_scanner"
    display_name = "App Service Plan Generation & Redundancy"
    description = "Detects Premium v2 App Service plans and single-instance production plans"
    category = ScannerCategory.COMPUTE
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.web/serverfarms'
        | project id, name, type, resourceGroup, subscriptionId, location, tags, kind,
                  sku_name = tostring(sku.name), sku_tier = tostring(sku.tier),
                  capacity = toint(sku.capacity),
                  sites = toint(properties.numberOfSites),
                  zone_redundant = tobool(properties.zoneRedundant),
                  reserved = tobool(properties.reserved)
        """
        try:
            plans = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for plan in plans:
            sku = plan.get("sku_name") or ""
            capacity = plan.get("capacity") or 1
            linux = bool(plan.get("reserved")) or "linux" in (plan.get("kind") or "").lower()
            region = (plan.get("location") or "").replace(" ", "").lower()

            if sku in PV2_TO_PV3:
                target = PV2_TO_PV3[sku]
                old = await app_service_hourly_usd(context, sku, linux, region)
                new = await app_service_hourly_usd(context, target, linux, region)
                saving = round((old - new) * HOURS_PER_MONTH * capacity, 2) if old and new else None
                findings.append(self.resource_finding(
                    plan,
                    finding_type="app_service_plan_previous_generation",
                    title=f"Previous-generation plan {sku}: {plan['name']}",
                    description=(
                        f"App Service plan '{plan['name']}' runs {sku} x{capacity} ({'Linux' if linux else 'Windows'}). "
                        f"Premium v2 cannot be reserved and uses older hardware; {target} offers the same core "
                        f"count on newer CPUs"
                        + (f" for ~USD {saving:,.0f}/month less at PAYG, and a further ~35-45% with a 1-year "
                           f"reservation." if saving else ".")
                    ),
                    resource_type="microsoft.web/serverfarms",
                    remediation_steps=(
                        f"1. Scale the plan to {target} (in-place scale-up works when the stamp supports Pv3; "
                        f"otherwise redeploy into a new Pv3 plan).\n"
                        "2. Validate performance, then buy an App Service reserved instance for the steady-state count."
                    ),
                    azure_cli_script=f"az appservice plan update -g {plan.get('resourceGroup')} -n {plan['name']} --sku {target}",
                    powershell_script=(
                        f"Set-AzAppServicePlan -ResourceGroupName '{plan.get('resourceGroup')}' -Name '{plan['name']}' "
                        f"-Tier PremiumV3 -WorkerSize {'Small' if target in ('P0v3', 'P1v3') else 'Medium'}"
                    ),
                    evidence={"current_sku": sku, "recommended_sku": target, "instances": capacity,
                              "hourly_usd_current": old, "hourly_usd_target": new, "linux": linux},
                    estimated_monthly_savings_usd=saving,
                    caf_control="Cost Optimization",
                ))

            premium = (plan.get("sku_tier") or "").lower().startswith("premium")
            if premium and capacity == 1 and (plan.get("sites") or 0) > 0 and not plan.get("zone_redundant"):
                findings.append(self.resource_finding(
                    plan,
                    finding_type="app_service_plan_single_instance",
                    title=f"Single-instance Premium plan: {plan['name']}",
                    description=(
                        f"App Service plan '{plan['name']}' ({sku}) hosts {plan.get('sites')} app(s) on one "
                        f"instance without zone redundancy - platform upgrades and instance failures cause "
                        f"downtime for every app on it."
                    ),
                    resource_type="microsoft.web/serverfarms",
                    remediation_steps="Run production plans with at least 2 instances (3 for zone redundancy) and autoscale.",
                    azure_cli_script=f"az appservice plan update -g {plan.get('resourceGroup')} -n {plan['name']} --number-of-workers 2",
                    evidence={"instances": capacity, "sites": plan.get("sites"), "zone_redundant": False},
                    estimated_monthly_savings_usd=0.0,
                ))

        return ScanOutput(findings=findings, resources_scanned=len(plans))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/asp-shared-1",
            "name": "asp-shared-1", "type": "microsoft.web/serverfarms", "resourceGroup": "rg-web",
            "subscriptionId": "sub-1", "location": "westeurope", "kind": "app", "sku_name": "P3v2",
            "sku_tier": "PremiumV2", "capacity": 1, "sites": 5, "zone_redundant": False, "reserved": False,
        }]


# ---------------------------------------------------------------------------
# 4. App Service plan CPU saturation
# ---------------------------------------------------------------------------

@register_scanner
class AppServicePlanUtilizationScanner(PostureScanner):
    """
    30-day CpuPercentage per plan at an hourly grain (live mode). Saturated means a busy *hour* (or a busy month),
    not a one-minute spike: plans that idle with short nightly bursts show 100 % as their daily maximum while no
    hour averages above a few percent. Plans that stay far below their size are reported as over-provisioned.

    Emits finding_type="app_service_plan_cpu_saturated" and finding_type="app_service_plan_underutilized".
    """

    scanner_name = "app_service_plan_utilization_scanner"
    display_name = "App Service Plan CPU Utilisation"
    description = "Detects App Service plans whose CPU is saturated, or far below their size, over the last 30 days"
    category = ScannerCategory.COMPUTE
    severity = SeverityLevel.HIGH

    AVG_CPU_THRESHOLD = 60.0        # 30-day average
    PEAK_HOUR_THRESHOLD = 80.0      # busiest hour's average
    IDLE_P95_THRESHOLD = 10.0       # 95 % of hours below this ...
    IDLE_PEAK_HOUR_THRESHOLD = 30.0  # ... and no hour above this = over-provisioned
    MAX_MEMORY_FOR_DOWNSIZE = 40.0  # one size down halves the RAM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.web/serverfarms'
        | where toint(properties.numberOfSites) > 0
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  sku_name = tostring(sku.name), capacity = toint(sku.capacity),
                  sites = toint(properties.numberOfSites)
        """
        try:
            plans = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings = []
        if self.is_live(context):
            costs = await get_resource_costs(context)

            async def _enrich(plan):
                try:
                    m = await context.arm_client.metrics_summary(plan["id"], ["CpuPercentage", "MemoryPercentage"],
                                                                 interval="PT1H", aggregation="Average,Maximum")
                    cpu = m.get("CpuPercentage") or {}
                    plan.update(cpu_avg=cpu.get("average"), cpu_max=cpu.get("maximum"),
                                cpu_peak_hour=cpu.get("peak_average"), cpu_p95=cpu.get("p95_average"),
                                burst_hours=cpu.get("burst_points"),
                                mem_avg=(m.get("MemoryPercentage") or {}).get("average"))
                except Exception as exc:
                    warnings.append(f"Metrics unavailable for {plan['name']}: {exc}")
                plan["cost_usd_30d"] = (cost_for(costs, plan["id"]) or {}).get("cost_usd")
            await gather_limited(plans, _enrich, self.setting("arm_concurrency", DEFAULT_ARM_CONCURRENCY))

        findings = []
        for plan in plans:
            avg = plan.get("cpu_avg")
            if avg is None:
                continue
            peak_hour = plan.get("cpu_peak_hour")
            profile = self._profile_text(plan)
            evidence = {"cpu_avg_30d": avg, "cpu_busiest_hour": peak_hour, "cpu_p95_hourly": plan.get("cpu_p95"),
                        "cpu_max_1min": plan.get("cpu_max"), "hours_with_burst_90": plan.get("burst_hours"),
                        "memory_avg_30d": plan.get("mem_avg")}
            if avg >= float(self.setting("cpu_avg_threshold", self.AVG_CPU_THRESHOLD)) or (peak_hour or 0) >= float(
                    self.setting("cpu_peak_hour_threshold", self.PEAK_HOUR_THRESHOLD)):
                findings.append(self._saturated(plan, profile, evidence))
            elif self._underutilized(plan):
                findings.append(self._oversized(plan, profile, evidence))
        return ScanOutput(findings=findings, resources_scanned=len(plans), warnings=warnings)

    @staticmethod
    def _profile_text(plan: Dict[str, Any]) -> str:
        parts = [f"averaged {plan['cpu_avg']:.1f}% CPU"]
        if plan.get("cpu_peak_hour") is not None:
            parts.append(f"its busiest hour {plan['cpu_peak_hour']:.1f}%")
        if plan.get("cpu_p95") is not None:
            parts.append(f"95% of hours at or below {plan['cpu_p95']:.1f}%")
        text = ", ".join(parts)
        if plan.get("cpu_max") is not None:
            bursts = plan.get("burst_hours") or 0
            text += (f"; one-minute peaks reached {plan['cpu_max']:.0f}%"
                     + (f" in {bursts:,.0f} hour(s)" if bursts else ""))
        return text

    def _underutilized(self, plan: Dict[str, Any]) -> bool:
        p95, peak_hour, mem = plan.get("cpu_p95"), plan.get("cpu_peak_hour"), plan.get("mem_avg")
        return (p95 is not None and peak_hour is not None
                and p95 < float(self.setting("idle_p95_threshold", self.IDLE_P95_THRESHOLD))
                and peak_hour < float(self.setting("idle_peak_hour_threshold", self.IDLE_PEAK_HOUR_THRESHOLD))
                and (mem is None or mem < float(self.setting("max_memory_for_downsize", self.MAX_MEMORY_FOR_DOWNSIZE)))
                and smaller_plan_sku(plan.get("sku_name")) is not None)

    def _saturated(self, plan: Dict[str, Any], profile: str, evidence: Dict[str, Any]):
        return self.resource_finding(
            plan,
            finding_type="app_service_plan_cpu_saturated",
            title=f"CPU saturated (busiest hour {plan.get('cpu_peak_hour') or plan['cpu_avg']:.0f}%): {plan['name']}",
            description=(
                f"App Service plan '{plan['name']}' ({plan.get('sku_name')} x{plan.get('capacity')}, "
                f"{plan.get('sites')} app(s)) {profile} over 30 days. Every app and slot on the plan competes for "
                f"the same instances."
            ),
            resource_type="microsoft.web/serverfarms",
            remediation_steps=(
                "1. Move non-production slots/apps to their own plan.\n"
                "2. Add instances and an autoscale rule (CPU > 70% scale out).\n"
                "3. Profile the hottest app (App Insights) before scaling up."
            ),
            azure_cli_script=(
                f"az monitor autoscale create -g {plan.get('resourceGroup')} --resource {plan['id']} "
                f"--min-count 2 --max-count 4 --count 2\n"
                f"az monitor autoscale rule create -g {plan.get('resourceGroup')} --autoscale-name {plan['name']} "
                f"--condition \"CpuPercentage > 70 avg 10m\" --scale out 1"
            ),
            evidence=evidence,
            estimated_monthly_savings_usd=0.0,
        )

    def _oversized(self, plan: Dict[str, Any], profile: str, evidence: Dict[str, Any]):
        target = smaller_plan_sku(plan.get("sku_name"))
        cost = plan.get("cost_usd_30d")
        saving = round(cost / 2, 2) if cost else None
        return self.resource_finding(
            plan,
            finding_type="app_service_plan_underutilized",
            title=f"Over-provisioned plan ({plan.get('cpu_p95') or 0:.0f}% CPU at P95): {plan['name']}",
            description=(
                f"App Service plan '{plan['name']}' ({plan.get('sku_name')} x{plan.get('capacity')}, "
                f"{plan.get('sites')} app(s)) {profile} over 30 days, with {plan.get('mem_avg') or 0:.0f}% memory "
                f"used. One size down ({target}) keeps the instance count and still leaves headroom"
                + (f"; estimated saving USD {saving:,.0f}/month (one size down roughly halves the price)."
                   if saving else ".")
            ),
            resource_type="microsoft.web/serverfarms",
            severity=SeverityLevel.LOW,
            remediation_steps=(
                f"1. Check the busiest hour and the bursts above against the apps' own response times.\n"
                f"2. Scale the plan to {target} (keep at least 2 instances for production).\n"
                "3. Watch CPU and memory for a week; scale back up if the busiest hour passes 70%."
            ),
            azure_cli_script=f"az appservice plan update --ids {plan['id']} --sku {target}",
            evidence=evidence,
            estimated_monthly_savings_usd=saving,
        )

    def _mock_data(self) -> List[Dict[str, Any]]:
        common = {"type": "microsoft.web/serverfarms", "resourceGroup": "rg-web", "subscriptionId": "sub-1",
                  "location": "westeurope"}
        return [
            {**common, "id": "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/asp-shared-1",
             "name": "asp-shared-1", "sku_name": "P3v2", "capacity": 1, "sites": 5, "cpu_avg": 68.3,
             "cpu_max": 100.0, "cpu_peak_hour": 97.0, "cpu_p95": 91.0, "burst_hours": 310.0, "mem_avg": 32.2},
            {**common, "id": "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/asp-quiet-1",
             "name": "asp-quiet-1", "sku_name": "P2v3", "capacity": 2, "sites": 3, "cpu_avg": 1.5,
             "cpu_max": 100.0, "cpu_peak_hour": 8.2, "cpu_p95": 3.2, "burst_hours": 40.0, "mem_avg": 21.0,
             "cost_usd_30d": 420.0},
            {**common, "id": "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/asp-bursty-1",
             "name": "asp-bursty-1", "sku_name": "P2v2", "capacity": 2, "sites": 40, "cpu_avg": 1.5,
             "cpu_max": 100.0, "cpu_peak_hour": 8.2, "cpu_p95": 3.2, "burst_hours": 40.0, "mem_avg": 43.6},
        ]


def smaller_plan_sku(sku: Optional[str]) -> Optional[str]:
    """One size down in the same App Service family: P2v2 -> P1v2, P1v3 -> P0v3, S3 -> S2; None at the bottom."""
    m = re.match(r"^([A-Za-z]+)(\d)((?:m?v\d)?)$", sku or "")
    if not m:
        return None
    family, size, gen = m.group(1), int(m.group(2)), m.group(3)
    if size > 1:
        return f"{family}{size - 1}{gen}"
    if size == 1 and family.upper() == "P" and gen.lower() == "v3":
        return "P0v3"
    return None


# ---------------------------------------------------------------------------
# 5. Production and non-production on one plan
# ---------------------------------------------------------------------------

SITES_QUERY = """
Resources
| where type in~ ('microsoft.web/sites', 'microsoft.web/sites/slots')
| project id, name, type, resourceGroup, subscriptionId, location, tags, kind,
          state = tostring(properties.state),
          plan_id = tolower(tostring(properties.serverFarmId)),
          https_only = tobool(properties.httpsOnly),
          host_names = properties.hostNames,
          identity_type = tostring(identity.type)
"""


def custom_host_names(site: Dict[str, Any]) -> List[str]:
    return [h for h in (site.get("host_names") or []) if not str(h).lower().endswith(".azurewebsites.net")]


def site_environment(site: Dict[str, Any]) -> Optional[str]:
    leaf = (site.get("name") or "").split("/")[-1]
    if (site.get("type") or "").lower().endswith("/slots"):
        by_name = env_from_name(leaf)
        if by_name:
            return by_name
    if custom_host_names(site):
        return "prod"
    return env_from_tags(site.get("tags")) or env_from_name(leaf)


@register_scanner
class AppServiceMixedEnvironmentScanner(PostureScanner):
    """
    A production app (custom domain / prod tag) sharing a plan with running
    dev/test/stage apps or slots: non-prod load degrades prod, and the plan's
    cost cannot be attributed to an environment.
    """

    scanner_name = "app_service_mixed_environment_scanner"
    display_name = "Mixed Environments on One App Service Plan"
    description = "Detects App Service plans hosting both production and non-production workloads"
    category = ScannerCategory.GOVERNANCE
    severity = SeverityLevel.HIGH

    async def scan(self, context: ScanContext) -> ScanOutput:
        plan_query = """
        Resources
        | where type =~ 'microsoft.web/serverfarms'
        | project id, name, type, resourceGroup, subscriptionId, location, tags, sku_name = tostring(sku.name)
        """
        try:
            sites = await self._sites(context)
            plans = await self._plans(context, plan_query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        by_plan: Dict[str, List[Dict[str, Any]]] = {}
        for s in sites:
            by_plan.setdefault(s.get("plan_id") or "", []).append(s)

        findings = []
        for plan in plans:
            members = by_plan.get(plan["id"].lower(), [])
            prod = [s["name"] for s in members if site_environment(s) == "prod"]
            nonprod = [s["name"] for s in members
                       if site_environment(s) == "nonprod" and (s.get("state") or "").lower() == "running"]
            if not prod or not nonprod:
                continue
            findings.append(self.resource_finding(
                plan,
                finding_type="app_service_plan_mixed_environments",
                title=f"Prod and non-prod share plan: {plan['name']}",
                description=(
                    f"App Service plan '{plan['name']}' ({plan.get('sku_name')}) hosts production app(s) "
                    f"{', '.join(prod)} together with {len(nonprod)} running non-production app(s)/slot(s): "
                    f"{', '.join(nonprod)}."
                ),
                resource_type="microsoft.web/serverfarms",
                remediation_steps=(
                    "1. Create a separate non-production plan (e.g. P0v3/B-series) and move dev/test/stage apps there.\n"
                    "2. Keep only a 'staging' slot on the production plan for swap deployments.\n"
                    "3. Tag both plans with the correct environment for cost attribution."
                ),
                azure_cli_script=(
                    f"az appservice plan create -g {plan.get('resourceGroup')} -n {plan['name']}-nonprod --sku P0V3\n"
                    "# Slots cannot be moved between plans: recreate non-prod slots as apps on the new plan,\n"
                    "# then delete them from the production app:\n"
                    "# az webapp deployment slot delete -g <rg> -n <app> --slot <slot>"
                ),
                evidence={"production": prod, "non_production_running": nonprod, "total_members": len(members)},
                caf_control="Environment isolation",
                estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(plans))

    async def _sites(self, context: ScanContext) -> List[Dict[str, Any]]:
        if context.resource_graph_client is None:
            return mock_sites()
        return await self.arg(context, SITES_QUERY)

    async def _plans(self, context: ScanContext, query: str) -> List[Dict[str, Any]]:
        if context.resource_graph_client is None:
            return [{
                "id": "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/asp-shared-1",
                "name": "asp-shared-1", "type": "microsoft.web/serverfarms", "resourceGroup": "rg-web",
                "subscriptionId": "sub-1", "location": "westeurope", "sku_name": "P3v2",
            }]
        return await self.arg(context, query)


def mock_sites() -> List[Dict[str, Any]]:
    plan = "/subscriptions/sub-1/resourcegroups/rg-web/providers/microsoft.web/serverfarms/asp-shared-1"
    base = "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/sites"
    common = {"resourceGroup": "rg-web", "subscriptionId": "sub-1", "location": "westeurope", "plan_id": plan}
    return [
        {**common, "id": f"{base}/app-portal", "name": "app-portal", "type": "microsoft.web/sites",
         "state": "Running", "https_only": True, "identity_type": "SystemAssigned",
         "host_names": ["portal.contoso.com", "app-portal.azurewebsites.net"]},
        {**common, "id": f"{base}/app-portal/slots/dev", "name": "app-portal/dev", "type": "microsoft.web/sites/slots",
         "state": "Running", "https_only": False, "identity_type": "",
         "host_names": ["app-portal-dev.azurewebsites.net"]},
        {**common, "id": f"{base}/app-api", "name": "app-api", "type": "microsoft.web/sites",
         "state": "Running", "https_only": True, "identity_type": "",
         "host_names": ["app-api.azurewebsites.net"]},
    ]


# ---------------------------------------------------------------------------
# 6. HTTPS-only and managed identity
# ---------------------------------------------------------------------------

@register_scanner
class WebAppHttpsAndIdentityScanner(PostureScanner):
    """HTTP allowed on sites/slots; production sites without a managed identity."""

    scanner_name = "web_app_https_identity_scanner"
    display_name = "Web App HTTPS & Managed Identity"
    description = "Detects web apps/slots allowing HTTP and sites without a managed identity"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.HIGH

    async def scan(self, context: ScanContext) -> ScanOutput:
        try:
            sites = mock_sites() if context.resource_graph_client is None else await self.arg(context, SITES_QUERY)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for s in sites:
            rg, name = s.get("resourceGroup"), s.get("name") or ""
            is_slot = (s.get("type") or "").lower().endswith("/slots")
            app, _, slot = name.partition("/")
            slot_arg = f" --slot {slot}" if is_slot else ""

            if s.get("https_only") is False:
                findings.append(self.resource_finding(
                    s,
                    finding_type="web_app_https_not_enforced",
                    title=f"HTTP allowed: {name}",
                    description=f"{'Slot' if is_slot else 'Web app'} '{name}' accepts plain HTTP (httpsOnly=false).",
                    resource_type=s.get("type"),
                    remediation_steps="Enable HTTPS Only; enforce with policy 'App Service apps should only be accessible over HTTPS'.",
                    azure_cli_script=f"az webapp update -g {rg} -n {app}{slot_arg} --https-only true",
                    powershell_script=f"Set-AzWebApp{'Slot' if is_slot else ''} -ResourceGroupName '{rg}' -Name '{app}'"
                                      + (f" -Slot '{slot}'" if is_slot else "") + " -HttpsOnly $true",
                    evidence={"https_only": False, "slot": is_slot},
                    cis_control="9.2",
                    estimated_monthly_savings_usd=0.0,
                ))

            if not is_slot and not s.get("identity_type"):
                findings.append(self.resource_finding(
                    s,
                    finding_type="web_app_managed_identity_missing",
                    title=f"No managed identity: {name}",
                    description=(
                        f"Web app '{name}' has no managed identity, so it must use connection strings, keys "
                        f"or SQL logins to reach SQL, Storage and Key Vault."
                    ),
                    resource_type=s.get("type"),
                    severity=SeverityLevel.MEDIUM,
                    remediation_steps=(
                        "Enable a system-assigned identity, grant it data-plane roles, and replace secrets in "
                        "app settings with identity-based connections or Key Vault references."
                    ),
                    azure_cli_script=f"az webapp identity assign -g {rg} -n {app}",
                    evidence={"identity": None},
                    estimated_monthly_savings_usd=0.0,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(sites))


# ---------------------------------------------------------------------------
# 7. Runtime / TLS / FTP / health check / 32-bit worker
# ---------------------------------------------------------------------------

# (stack regex matched against "<stack>|<version>", end-of-support date)
RUNTIME_END_OF_SUPPORT: List[Tuple[str, str, str]] = [
    (r"^dotnet(core)?\|(1|2|3)\.", "2022-12-13", ".NET Core 1-3.1"),
    (r"^dotnet(core)?\|5\.0", "2022-05-10", ".NET 5"),
    (r"^dotnet(core)?\|6\.0", "2024-11-12", ".NET 6"),
    (r"^dotnet(core)?\|7\.0", "2024-05-14", ".NET 7"),
    (r"^dotnet(core)?\|8\.0", "2026-11-10", ".NET 8"),
    (r"^dotnet(core)?\|9\.0", "2026-11-10", ".NET 9"),
    (r"^node\|(10|12|14)", "2023-04-30", "Node.js <=14"),
    (r"^node\|16", "2023-09-11", "Node.js 16"),
    (r"^node\|18", "2025-04-30", "Node.js 18"),
    (r"^node\|20", "2026-04-30", "Node.js 20"),
    (r"^python\|3\.[0-7]($|\.)", "2023-06-27", "Python <=3.7"),
    (r"^python\|3\.8", "2024-10-07", "Python 3.8"),
    (r"^python\|3\.9", "2025-10-31", "Python 3.9"),
    (r"^php\|(5|7)\.", "2022-11-28", "PHP 7.x"),
    (r"^php\|8\.0", "2023-11-26", "PHP 8.0"),
    (r"^php\|8\.1", "2025-12-31", "PHP 8.1"),
]


def runtime_stack(config: Dict[str, Any]) -> Optional[str]:
    """Normalise site config to '<stack>|<version>' (Linux FX, or Windows .NET)."""
    fx = config.get("linuxFxVersion") or config.get("windowsFxVersion")
    if fx:
        return str(fx).lower()
    net = (config.get("netFrameworkVersion") or "").lower().lstrip("v")
    if net and not net.startswith(("2.", "4.")):
        return f"dotnet|{net}"
    return None


def runtime_end_of_support(stack: Optional[str]) -> Optional[Tuple[str, date]]:
    if not stack:
        return None
    for rx, eos, label in RUNTIME_END_OF_SUPPORT:
        if re.search(rx, stack, re.I):
            return label, _as_date(eos)
    return None


@register_scanner
class WebAppConfigurationScanner(PostureScanner):
    """Reads each production site's config/web (live mode) and checks runtime hygiene."""

    scanner_name = "web_app_configuration_scanner"
    display_name = "Web App Runtime & Configuration"
    description = "Detects EOL runtime stacks, weak TLS, FTP, missing health checks and 32-bit workers"
    category = ScannerCategory.COMPUTE
    severity = SeverityLevel.HIGH

    NEAR_EOL_DAYS = 120

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.web/sites'
        | project id, name, type, resourceGroup, subscriptionId, location, tags, kind
        """
        try:
            sites = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings = []
        if self.is_live(context):
            async def _enrich(s):
                try:
                    payload = await context.arm_client.get(f"{s['id']}/config/web", "2023-12-01")
                    s["config"] = payload.get("properties") or {}
                except Exception as exc:
                    warnings.append(f"config/web unavailable for {s['name']}: {exc}")
            await gather_limited(sites, _enrich, self.setting("arm_concurrency", DEFAULT_ARM_CONCURRENCY))

        as_of = _as_date(self.setting("as_of", date.today()))
        findings = []
        for s in sites:
            cfg = s.get("config")
            if not cfg:
                continue
            rg, name = s.get("resourceGroup"), s["name"]
            stack = runtime_stack(cfg)
            eos = runtime_end_of_support(stack)
            if eos:
                label, eos_date = eos
                days_left = (eos_date - as_of).days
                if days_left <= self.NEAR_EOL_DAYS:
                    past = days_left < 0
                    findings.append(self.resource_finding(
                        s,
                        finding_type="web_app_eol_runtime",
                        title=f"{label} {'end of support' if past else 'nearing end of support'}: {name}",
                        description=(
                            f"Web app '{name}' runs {stack} ({label}), "
                            + (f"out of support since {eos_date.isoformat()} - no security patches."
                               if past else f"which reaches end of support on {eos_date.isoformat()}.")
                        ),
                        resource_type="microsoft.web/sites",
                        severity=SeverityLevel.HIGH if past else SeverityLevel.MEDIUM,
                        remediation_steps="Upgrade the application to a supported LTS runtime and redeploy.",
                        azure_cli_script=f"az webapp config show -g {rg} -n {name} --query \"{{net:netFrameworkVersion,linux:linuxFxVersion}}\"",
                        evidence={"runtime": stack, "end_of_support": eos_date.isoformat()},
                        nist_control="SI-2",
                        estimated_monthly_savings_usd=0.0,
                    ))

            if (cfg.get("minTlsVersion") or "1.2") in ("1.0", "1.1"):
                findings.append(self.resource_finding(
                    s, finding_type="web_app_weak_tls", title=f"TLS {cfg.get('minTlsVersion')} allowed: {name}",
                    description=f"Web app '{name}' accepts TLS {cfg.get('minTlsVersion')}.",
                    resource_type="microsoft.web/sites", severity=SeverityLevel.HIGH,
                    remediation_steps="Set minimum TLS version to 1.2 or higher.",
                    azure_cli_script=f"az webapp config set -g {rg} -n {name} --min-tls-version 1.2",
                    evidence={"min_tls": cfg.get("minTlsVersion")}, estimated_monthly_savings_usd=0.0,
                ))

            if (cfg.get("ftpsState") or "").lower() == "allallowed":
                findings.append(self.resource_finding(
                    s, finding_type="web_app_ftp_enabled", title=f"Plain FTP allowed: {name}",
                    description=f"Web app '{name}' allows unencrypted FTP deployments.",
                    resource_type="microsoft.web/sites", severity=SeverityLevel.MEDIUM,
                    remediation_steps="Set FTP state to Disabled (or FtpsOnly if FTP deployment is required).",
                    azure_cli_script=f"az webapp config set -g {rg} -n {name} --ftps-state Disabled",
                    evidence={"ftps_state": cfg.get("ftpsState")}, estimated_monthly_savings_usd=0.0,
                ))

            if not cfg.get("healthCheckPath"):
                findings.append(self.resource_finding(
                    s, finding_type="web_app_health_check_missing", title=f"No health check: {name}",
                    description=(f"Web app '{name}' has no health-check path, so the platform cannot remove "
                                 f"an unhealthy instance from rotation."),
                    resource_type="microsoft.web/sites", severity=SeverityLevel.LOW,
                    remediation_steps="Expose a lightweight /health endpoint and configure it as the health-check path.",
                    azure_cli_script=f"az webapp config set -g {rg} -n {name} --generic-configurations '{{\"healthCheckPath\": \"/health\"}}'",
                    evidence={"health_check_path": None}, estimated_monthly_savings_usd=0.0,
                ))

            if cfg.get("use32BitWorkerProcess") is True and "linux" not in (s.get("kind") or "").lower():
                findings.append(self.resource_finding(
                    s, finding_type="web_app_32bit_worker", title=f"32-bit worker process: {name}",
                    description=(f"Web app '{name}' runs a 32-bit worker process, limiting each process to "
                                 f"~2-4 GB of address space regardless of the plan's memory."),
                    resource_type="microsoft.web/sites", severity=SeverityLevel.LOW,
                    remediation_steps="Switch the platform to 64-bit after confirming native dependencies support it.",
                    azure_cli_script=f"az webapp config set -g {rg} -n {name} --use-32bit-worker-process false",
                    evidence={"use32BitWorkerProcess": True}, estimated_monthly_savings_usd=0.0,
                ))

        return ScanOutput(findings=findings, resources_scanned=len(sites), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/sites/app-portal",
            "name": "app-portal", "type": "microsoft.web/sites", "resourceGroup": "rg-web",
            "subscriptionId": "sub-1", "location": "westeurope", "kind": "app",
            "config": {"netFrameworkVersion": "v6.0", "minTlsVersion": "1.2", "ftpsState": "FtpsOnly",
                       "healthCheckPath": None, "use32BitWorkerProcess": True},
        }]


# ---------------------------------------------------------------------------
# 8. VM right-sizing - validated, no guesswork
# ---------------------------------------------------------------------------
#
# Rules follow Azure Advisor's documented resize criteria (Microsoft Learn, "Optimize virtual machine (VM) or
# virtual machine scale set (VMSS) spend by resizing or shutting down underutilized instances"), using the stricter
# *user-facing* limits for every VM and a 30-day look-back instead of 7 days: on the target size, P95 of 30-minute
# CPU peaks <= 40 % and P99 of memory used <= 60 %; the target keeps Premium Storage / Accelerated Networking, is
# offered in the region and is cheaper at retail rates. Added here: P99 CPU <= 80 %, disk headroom (VM cached /
# uncached IOPS and bandwidth consumed %, projected on the target's limits), a network ceiling, burstable baselines
# (Microsoft Learn Bv1 / Bsv2 / Basv2 size pages), temp-disk / CPU architecture / Hyper-V generation / disk / NIC
# compatibility, 90 % data coverage and a 30-day minimum age.

RIGHTSIZE_LOOKBACK_DAYS = 30
RIGHTSIZE_WINDOWS = RIGHTSIZE_LOOKBACK_DAYS * 48          # 30-minute windows
RIGHTSIZE_LIMITS = {"cpu_p95": 40.0, "cpu_p99": 80.0, "mem_p99": 60.0, "disk_p95": 40.0, "net_p95_mbps": 100.0,
                    "coverage": 0.9, "burst_avg_share": 0.8, "min_saving_usd": 10.0}
UNCACHED_METRICS = ("VM Uncached IOPS Consumed Percentage", "VM Uncached Bandwidth Consumed Percentage")
CACHED_METRICS = ("VM Cached IOPS Consumed Percentage", "VM Cached Bandwidth Consumed Percentage")
RIGHTSIZE_METRICS = ("Percentage CPU", "Available Memory Bytes", "Network Out Total") + UNCACHED_METRICS + CACHED_METRICS
# General-purpose, memory- and compute-optimised families only; confidential (DC/EC), GPU, HPC, M and L series have
# hardware a size step does not preserve.
RIGHTSIZE_FAMILY = re.compile(r"^standard(a|b|d|e|f)", re.IGNORECASE)
CONFIDENTIAL_FAMILY = re.compile(r"^standard(dc|ec)", re.IGNORECASE)
# Base CPU performance of burstable sizes, % of the whole VM on the 0-100 % scale (Microsoft Learn: Bv1, Bsv2, Basv2).
B_V1_BASELINE = {"standard_b1ls": 5.0, "standard_b1s": 10.0, "standard_b1ms": 20.0, "standard_b2s": 20.0,
                 "standard_b2ms": 30.0, "standard_b4ms": 22.5, "standard_b8ms": 17.0, "standard_b12ms": 17.0,
                 "standard_b16ms": 17.0, "standard_b20ms": 17.0}
B_V2_SIZE = re.compile(r"^standard_b\d+a?(t|l)?s_v2$")  # Bsv2 (Intel) / Basv2 (AMD); Arm Bpsv2 is not covered


def burst_baseline(size: Optional[str]) -> Optional[float]:
    """Base CPU performance (%) of a burstable size, None for a non-burstable or undocumented one."""
    name = (size or "").lower()
    if name in B_V1_BASELINE:
        return B_V1_BASELINE[name]
    m = B_V2_SIZE.match(name)
    return {"t": 20.0, "l": 30.0}.get(m.group(1) or "", 40.0) if m else None


def _cap(spec: Dict[str, Any], name: str) -> float:
    try:
        return float((spec.get("caps") or {}).get(name) or 0)
    except (TypeError, ValueError):
        return 0.0


def _window_max(series: Dict[str, List[Dict[str, Any]]], names: Tuple[str, ...]) -> List[float]:
    """Per 30-minute window, the highest of several percentage metrics."""
    by_ts: Dict[str, float] = {}
    for name in names:
        for p in series.get(name) or []:
            if p.get("maximum") is not None:
                by_ts[p["timeStamp"]] = max(by_ts.get(p["timeStamp"], 0.0), p["maximum"])
    return list(by_ts.values())


def vm_profile(payload: Dict[str, Any], ram_gb: float) -> Dict[str, Any]:
    """30-minute windows over the look-back: CPU peaks, memory used (from minimum available), disk and network."""
    series = {(m.get("name") or {}).get("value"): [p for s in m.get("timeseries") or [] for p in s.get("data") or []]
              for m in payload.get("value") or []}
    cpu = series.get("Percentage CPU") or []
    cpu_max = [p["maximum"] for p in cpu if p.get("maximum") is not None]
    cpu_avg = [p["average"] for p in cpu if p.get("average") is not None]
    mem_min = [p["minimum"] for p in series.get("Available Memory Bytes") or [] if p.get("minimum") is not None]
    used_gb = [max(0.0, ram_gb - m / 1024 ** 3) for m in mem_min]
    net = [p["total"] * 8 / 1800 / 1e6 for p in series.get("Network Out Total") or [] if p.get("total") is not None]
    uncached, cached = _window_max(series, UNCACHED_METRICS), _window_max(series, CACHED_METRICS)
    return {
        "cpu_windows": len(cpu_max), "mem_windows": len(mem_min),
        "cpu_avg": sum(cpu_avg) / len(cpu_avg) if cpu_avg else None,
        "cpu_p95": percentile(cpu_max, 95), "cpu_p99": percentile(cpu_max, 99),
        "mem_used_p99_gb": percentile(used_gb, 99),
        "disk_uncached_p95": percentile(uncached, 95), "disk_cached_p95": percentile(cached, 95),
        "net_p95_mbps": percentile(net, 95),
    }


def rightsizing_exclusion(vm: Dict[str, Any], now: Optional[datetime] = None) -> Optional[str]:
    """Why a VM is never a right-sizing candidate, or None."""
    tags = {str(k).lower(): v for k, v in (vm.get("tags") or {}).items()}
    rg = (vm.get("resourceGroup") or "").lower()
    if tags.get("arg-ignore") or tags.get("arg-reserved"):
        return "tagged arg-ignore / arg-reserved"
    if (vm.get("power") or "").split("/")[-1] != "running":
        return "not running"
    if (vm.get("priority") or "").lower() == "spot":
        return "Spot VM"
    if vm.get("vmss") or vm.get("managedBy") or rg.startswith("mc_") or rg.startswith("databricks-rg"):
        return "managed by a scale set, AKS or Databricks"
    if is_nva_image(vm.get("offer"), vm.get("imageSku")):
        return "network virtual appliance"
    if vm.get("ephemeral"):
        return "ephemeral OS disk (tied to the size's cache / temp disk)"
    created = str(vm.get("created") or "")[:10]
    if created:
        age = ((now or datetime.now(timezone.utc)).date() - date.fromisoformat(created)).days
        if age < RIGHTSIZE_LOOKBACK_DAYS:
            return f"created {age} days ago (needs {RIGHTSIZE_LOOKBACK_DAYS} days of history)"
    return None


def rightsizing_candidates(current: Dict[str, Any], catalogue: Dict[str, Dict[str, Any]],
                           advisor_target: Optional[str]) -> List[Dict[str, Any]]:
    """Azure Advisor's target (any family) and one size down in the same family (half the vCPUs and memory)."""
    out: List[Dict[str, Any]] = []
    if advisor_target and advisor_target.lower() in catalogue and advisor_target.lower() != current["name"].lower():
        out.append(dict(catalogue[advisor_target.lower()], source="Azure Advisor"))
    vcpu, mem = _cap(current, "vCPUs"), _cap(current, "MemoryGB")
    for spec in catalogue.values():
        if (spec.get("family") == current.get("family") and _cap(spec, "vCPUs") == vcpu / 2 >= 2
                and _cap(spec, "MemoryGB") == mem / 2 and spec["name"].lower() not in {c["name"].lower() for c in out}):
            out.append(dict(spec, source="one size down"))
    return out


def _retirement_date(spec: Dict[str, Any]) -> Optional[str]:
    """Catalogue 'RetirementDateUtc' ('11/15/2028') as '2028-11-15'; None when the size is not retiring."""
    raw = str((spec.get("caps") or {}).get("RetirementDateUtc") or "").strip()
    try:
        return datetime.strptime(raw.split(" ")[0], "%m/%d/%Y").date().isoformat() if raw else None
    except ValueError:
        return raw or None


def _ratio(current: Dict[str, Any], target: Dict[str, Any], cap: str) -> Optional[float]:
    return _cap(current, cap) / _cap(target, cap) if _cap(target, cap) and _cap(current, cap) else None


def evaluate_rightsizing(vm: Dict[str, Any], current: Dict[str, Any], target: Dict[str, Any],
                         profile: Dict[str, Any], limits: Dict[str, float] = RIGHTSIZE_LIMITS
                         ) -> Tuple[List[str], Dict[str, Optional[float]]]:
    """(failed checks, projected utilisation on the target). No failures = safe to recommend."""
    fails: List[str] = []
    cc, tc = current.get("caps") or {}, target.get("caps") or {}
    if target.get("restricted") or set(vm.get("zones") or []) & set(target.get("restricted_zones") or ()):
        fails.append("not offered to this subscription in the VM's region / zone")
    if (tc.get("CpuArchitectureType") or "x64") != (cc.get("CpuArchitectureType") or "x64"):
        fails.append("different CPU architecture")
    if (vm.get("gen") or "V1") not in (tc.get("HyperVGenerations") or "V1").split(","):
        fails.append(f"no Hyper-V {vm.get('gen') or 'V1'} support")
    if _cap(current, "MaxResourceVolumeMB") > 0 and _cap(target, "MaxResourceVolumeMB") == 0:
        fails.append("the current size has a local temp disk and Azure cannot resize to a size without one")
    if cc.get("PremiumIO") == "True" and tc.get("PremiumIO") != "True":
        fails.append("no Premium Storage")
    if vm.get("accelerated") and tc.get("AcceleratedNetworkingEnabled") != "True":
        fails.append("no Accelerated Networking (enabled on the VM's NIC)")
    if (vm.get("dataDisks") or 0) > _cap(target, "MaxDataDiskCount"):
        fails.append(f"{vm.get('dataDisks')} data disks exceed the size's limit")
    if (vm.get("nics") or 1) > _cap(target, "MaxNetworkInterfaces"):
        fails.append(f"{vm.get('nics')} NICs exceed the size's limit")
    if tc.get("vCPUsAvailable") and _cap(target, "vCPUsAvailable") != _cap(target, "vCPUs"):
        fails.append("constrained-core size")

    need = limits["coverage"] * RIGHTSIZE_WINDOWS
    if profile.get("cpu_windows", 0) < need or profile.get("mem_windows", 0) < need:
        fails.append("less than 90 % of the 30 days measured (CPU or memory)")
        return fails, {}
    ratio = _cap(current, "vCPUs") / (_cap(target, "vCPUs") or 1)
    cpu_p95, cpu_p99 = (profile.get("cpu_p95") or 0) * ratio, (profile.get("cpu_p99") or 0) * ratio
    cpu_avg = (profile.get("cpu_avg") or 0) * ratio
    mem_pct = (profile.get("mem_used_p99_gb") or 0) / (_cap(target, "MemoryGB") or 1) * 100
    uncached_ratio = max(filter(None, [_ratio(current, target, "UncachedDiskIOPS"),
                                       _ratio(current, target, "UncachedDiskBytesPerSecond")]), default=None)
    cached_ratio = max(filter(None, [_ratio(current, target, "CombinedTempDiskAndCachedIOPS"),
                                     _ratio(current, target, "CombinedTempDiskAndCachedReadBytesPerSecond")]),
                       default=None)
    disk_uncached = (profile["disk_uncached_p95"] * uncached_ratio
                     if profile.get("disk_uncached_p95") is not None and uncached_ratio else None)
    cached_use = profile.get("disk_cached_p95") or 0.0
    disk_cached = cached_use * cached_ratio if cached_ratio else (0.0 if cached_use < 1 else None)
    projected = {"cpu_p95": cpu_p95, "cpu_p99": cpu_p99, "cpu_avg": cpu_avg, "mem_p99_pct": mem_pct,
                 "disk_uncached_p95": disk_uncached, "disk_cached_p95": disk_cached,
                 "net_p95_mbps": profile.get("net_p95_mbps")}
    if cpu_p95 > limits["cpu_p95"]:
        fails.append(f"CPU P95 would be {cpu_p95:.0f}% (limit {limits['cpu_p95']:.0f}%)")
    if cpu_p99 > limits["cpu_p99"]:
        fails.append(f"CPU P99 would be {cpu_p99:.0f}% (limit {limits['cpu_p99']:.0f}%)")
    if (target.get("family") or "").lower().startswith("standardb"):
        baseline = burst_baseline(target["name"])
        if baseline is None:
            fails.append("burstable size without a documented baseline")
        else:
            if cpu_avg > limits["burst_avg_share"] * baseline:
                fails.append(f"average CPU {cpu_avg:.0f}% would spend CPU credits (baseline {baseline:.0f}%)")
            if cpu_p95 > 2 * baseline:
                fails.append(f"CPU P95 {cpu_p95:.0f}% above twice the burstable baseline ({baseline:.0f}%)")
    if mem_pct > limits["mem_p99"]:
        fails.append(f"memory P99 would be {mem_pct:.0f}% (limit {limits['mem_p99']:.0f}%)")
    if disk_uncached is None:
        fails.append("disk limits or disk metrics unavailable")
    elif disk_uncached > limits["disk_p95"]:
        fails.append(f"disk P95 would be {disk_uncached:.0f}% of the size's limits (limit {limits['disk_p95']:.0f}%)")
    if disk_cached is None:
        fails.append("the VM uses its host cache and the size has no cache")
    elif disk_cached > limits["disk_p95"]:
        fails.append(f"cached disk P95 would be {disk_cached:.0f}% of the size's limits")
    if (profile.get("net_p95_mbps") or 0) > limits["net_p95_mbps"]:
        fails.append(f"network P95 {profile['net_p95_mbps']:.0f} Mbps above the {limits['net_p95_mbps']:.0f} Mbps check")
    return fails, projected


@register_scanner
class VmRightsizingScanner(PostureScanner):
    """
    Validated VM right-sizing: a resize is suggested only when the smaller (or cheaper) size passes every check in
    evaluate_rightsizing(), so the suggestion is safe to act on. Candidates are Azure Advisor's own target and one
    size down in the same family; the cheapest that passes wins, and Advisor targets that fail are named in the
    evidence.

    Emits finding_type="vm_rightsizing_opportunity".
    """

    scanner_name = "vm_rightsizing_scanner"
    display_name = "VM Right-Sizing (validated)"
    description = "Suggests smaller or cheaper VM sizes only when 30 days of CPU, memory, disk and network fit"
    category = ScannerCategory.COMPUTE
    severity = SeverityLevel.MEDIUM

    VM_QUERY = """
        Resources
        | where type =~ 'microsoft.compute/virtualmachines'
        | project id, name, type, resourceGroup, subscriptionId, location, tags, zones, managedBy,
                  size = tostring(properties.hardwareProfile.vmSize), os = tostring(properties.storageProfile.osDisk.osType),
                  license = tostring(properties.licenseType), priority = tostring(properties.priority),
                  vmss = tostring(properties.virtualMachineScaleSet.id),
                  ephemeral = tostring(properties.storageProfile.osDisk.diffDiskSettings.option),
                  created = tostring(properties.timeCreated),
                  offer = tostring(properties.storageProfile.imageReference.offer),
                  imageSku = tostring(properties.storageProfile.imageReference.sku),
                  power = tostring(properties.extended.instanceView.powerState.code),
                  gen = tostring(properties.extended.instanceView.hyperVGeneration),
                  avset = tostring(properties.availabilitySet.id),
                  dataDisks = array_length(properties.storageProfile.dataDisks),
                  nics = array_length(properties.networkProfile.networkInterfaces)
        """
    NIC_QUERY = """
        Resources
        | where type =~ 'microsoft.network/networkinterfaces' and isnotempty(properties.virtualMachine.id)
        | project vm = tolower(tostring(properties.virtualMachine.id)), an = tobool(properties.enableAcceleratedNetworking)
        """

    @staticmethod
    def advisor_query(subscription_id: str) -> str:
        return f"""
        advisorresources
        | where type =~ 'microsoft.advisor/recommendations' and subscriptionId == '{subscription_id}'
        | where tostring(properties.category) =~ 'Cost'
            and tostring(properties.impactedField) =~ 'microsoft.compute/virtualmachines'
        | project vm = tolower(tostring(properties.resourceMetadata.resourceId)),
                  target = tostring(properties.extendedProperties.targetSku),
                  rtype = tostring(properties.extendedProperties.recommendationType)
        """

    async def scan(self, context: ScanContext) -> ScanOutput:
        warnings: List[str] = []
        if not self.is_live(context) or context.resource_graph_client is None:
            cases = self._mock_data()
        else:
            try:
                cases = await self._live_cases(context, warnings)
            except Exception as e:
                return ScanOutput(warnings=[f"VM right-sizing unavailable: {e}"])
        findings = []
        for case in cases:
            choice = await self._choose(context, case)
            if choice is not None:
                findings.append(self._finding(case, choice))
        return ScanOutput(findings=findings, resources_scanned=len(cases), warnings=warnings)

    async def _live_cases(self, context: ScanContext, warnings: List[str]) -> List[Dict[str, Any]]:
        vms = await self.arg(context, self.VM_QUERY)
        accelerated = {r["vm"] for r in await self.arg(context, self.NIC_QUERY) if r.get("an")}
        try:
            advisor = {r["vm"]: r for r in await self.arg(context, self.advisor_query(context.subscription_id))}
        except Exception as exc:
            advisor = {}
            warnings.append(f"Azure Advisor recommendations unavailable (cross-check skipped): {exc}")
        costs = await get_resource_costs(context)
        cases: List[Dict[str, Any]] = []

        async def build(vm: Dict[str, Any]) -> None:
            if rightsizing_exclusion(vm):
                return
            try:
                catalogue = await compute_skus(context, vm["subscriptionId"], vm["location"])
            except Exception as exc:
                warnings.append(f"SKU catalogue unavailable for {vm['location']}: {exc}")
                return
            current = catalogue.get((vm.get("size") or "").lower())
            if not current or not RIGHTSIZE_FAMILY.match(current["family"]) or CONFIDENTIAL_FAMILY.match(current["family"]):
                return
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=RIGHTSIZE_LOOKBACK_DAYS)
            try:
                payload = await context.arm_client.get(f"{vm['id']}/providers/Microsoft.Insights/metrics", "2023-10-01", {
                    "metricnames": ",".join(RIGHTSIZE_METRICS), "aggregation": "Average,Maximum,Minimum,Total",
                    "interval": "PT30M", "timespan": f"{start:%Y-%m-%dT%H:%M:%SZ}/{end:%Y-%m-%dT%H:%M:%SZ}"})
            except Exception as exc:
                warnings.append(f"Metrics unavailable for {vm['name']}: {exc}")
                return
            cases.append({
                "vm": dict(vm, accelerated=vm["id"].lower() in accelerated),
                "current": current, "catalogue": catalogue,
                "profile": vm_profile(payload, _cap(current, "MemoryGB")),
                "advisor": advisor.get(vm["id"].lower()) or {},
                "cost_usd": (cost_for(costs, vm["id"]) or {}).get("cost_usd"),
                "prices": {},
            })

        await gather_limited(vms, build, self.setting("arm_concurrency", DEFAULT_ARM_CONCURRENCY))
        return cases

    @staticmethod
    async def _price(context: ScanContext, case: Dict[str, Any], size: str) -> Optional[float]:
        prices = case.setdefault("prices", {})
        if size not in prices:
            vm = case["vm"]
            windows = (vm.get("os") or "").lower() == "windows" and (vm.get("license") or "") not in (
                "Windows_Server", "Windows_Client")
            prices[size] = await vm_hourly_usd(context, size, vm["location"], windows)
        return prices[size]

    async def _choose(self, context: ScanContext, case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """The cheapest candidate that passes every check, or None."""
        vm, current, profile = case["vm"], case["current"], case["profile"]
        adv = case.get("advisor") or {}
        advisor_target = adv.get("target") if (adv.get("rtype") or "").lower() == "skuchange" else None
        cur_price = await self._price(context, case, current["name"])
        if not cur_price:
            return None
        best: Optional[Dict[str, Any]] = None
        rejected: Dict[str, List[str]] = {}
        for target in rightsizing_candidates(current, case["catalogue"], advisor_target):
            fails, projected = evaluate_rightsizing(vm, current, target, profile)
            if not fails:
                price = await self._price(context, case, target["name"])
                if not price or price >= cur_price:
                    fails = ["not cheaper at pay-as-you-go prices"]
                elif (cur_price - price) * HOURS_BILLED_PER_MONTH < RIGHTSIZE_LIMITS["min_saving_usd"]:
                    fails = [f"saves under USD {RIGHTSIZE_LIMITS['min_saving_usd']:.0f}/month"]
            if fails:
                rejected[target["name"]] = fails
                continue
            if best is None or price < best["price"]:
                best = {"target": target, "price": price, "projected": projected}
        if best is None:
            return None
        best.update(cur_price=cur_price, rejected=rejected, advisor_target=advisor_target)
        return best

    def _finding(self, case: Dict[str, Any], choice: Dict[str, Any]):
        vm, current, profile = case["vm"], case["current"], case["profile"]
        target, projected = choice["target"], choice["projected"]
        cur_name, tgt_name = current["name"], target["name"]
        retail = (choice["cur_price"] - choice["price"]) * HOURS_BILLED_PER_MONTH
        actual = case.get("cost_usd")
        covered = actual is not None and actual < 0.5 * choice["cur_price"] * HOURS_BILLED_PER_MONTH
        saving = retail if actual is None else min(retail, max(0.0, actual) * (1 - choice["price"] / choice["cur_price"]))
        spec = lambda s: f"{_cap(s, 'vCPUs'):.0f} vCPU / {_cap(s, 'MemoryGB'):g} GB"  # noqa: E731
        adv_target = choice.get("advisor_target")
        if adv_target and adv_target.lower() == tgt_name.lower():
            advisor_note = " Azure Advisor recommends the same resize."
        elif adv_target:
            reasons = choice["rejected"].get(adv_target) or ["not in this region's catalogue"]
            advisor_note = f" Azure Advisor suggests {adv_target}, which fails a check here ({reasons[0]})."
        else:
            advisor_note = ""
        retirement = _retirement_date(current)
        target_retirement = _retirement_date(target)
        if retirement and not target_retirement:
            lifecycle = f"; it also moves off {cur_name}, which Azure retires on {retirement}"
        elif target_retirement:
            lifecycle = (f"; note that {tgt_name} is in an end-of-life series retiring on {target_retirement} - "
                         f"plan the move to a current series before then")
        else:
            lifecycle = ""
        value = (f"Value: about USD {retail:,.0f}/month (USD {retail * 12:,.0f}/year) at pay-as-you-go prices"
                 + (f"; this VM's compute is mostly covered by a reservation or savings plan (30-day cost USD "
                    f"{actual:,.0f}), so the resize frees that commitment for other VMs rather than cutting this "
                    f"invoice line" if covered else "")
                 + lifecycle + ".")
        description = (
            f"VM '{vm['name']}' ({cur_name}, {spec(current)}) over the last {RIGHTSIZE_LOOKBACK_DAYS} days: CPU at "
            f"most {profile['cpu_p95']:.0f}% in 95% of 30-minute windows ({profile['cpu_p99']:.0f}% at P99, "
            f"{profile['cpu_avg']:.1f}% average), memory at most {profile['mem_used_p99_gb']:.1f} GB used (P99), "
            f"network {profile['net_p95_mbps'] or 0:.1f} Mbps (P95). On {tgt_name} ({spec(target)}) that projects to "
            f"{projected['cpu_p95']:.0f}% CPU at P95 and {projected['mem_p99_pct']:.0f}% memory at P99 - inside "
            f"Microsoft's limits for user-facing workloads (40% / 60%) - and "
            f"{projected['disk_uncached_p95']:.0f}% of the disk limits.{advisor_note} {value}"
        )
        remediation = (
            "1. Confirm with the owner that no growth, DR or release peak is planned for this VM.\n"
            f"2. Resize to {tgt_name} in a maintenance window - the VM restarts (a few minutes).\n"
            "3. Watch CPU and memory for a week; size back up if CPU P95 passes 60% or memory 80%."
            + ("\n4. The VM is in an availability set: if the size is not available on its current cluster, all "
               "VMs of the set must be deallocated to resize." if vm.get("avset") else "")
        )
        return self.resource_finding(
            vm,
            finding_type="vm_rightsizing_opportunity",
            title=f"Right-size {vm['name']}: {cur_name} to {tgt_name} (~USD {retail:,.0f}/month)",
            description=description,
            resource_type="microsoft.compute/virtualmachines",
            severity=SeverityLevel.MEDIUM if retail >= 100 else SeverityLevel.LOW,
            remediation_steps=remediation,
            azure_cli_script=f"az vm resize --ids {vm['id']} --size {tgt_name}",
            evidence={
                "current_size": cur_name, "target_size": tgt_name, "target_source": target.get("source"),
                "lookback_days": RIGHTSIZE_LOOKBACK_DAYS, "measured_windows": profile.get("cpu_windows"),
                "cpu_p95": profile.get("cpu_p95"), "cpu_p99": profile.get("cpu_p99"), "cpu_avg": profile.get("cpu_avg"),
                "memory_used_p99_gb": profile.get("mem_used_p99_gb"), "net_p95_mbps": profile.get("net_p95_mbps"),
                "disk_uncached_p95": profile.get("disk_uncached_p95"), "disk_cached_p95": profile.get("disk_cached_p95"),
                "projected": {k: round(v, 1) if isinstance(v, float) else v for k, v in projected.items()},
                "limits": RIGHTSIZE_LIMITS, "usd_per_hour": {cur_name: choice["cur_price"], tgt_name: choice["price"]},
                "retail_saving_usd_month": round(retail, 2), "actual_cost_usd_30d": actual,
                "covered_by_commitment": covered, "advisor_target": adv_target,
                "rejected_targets": choice["rejected"],
            },
            estimated_monthly_savings_usd=round(saving, 2),
        )

    def _mock_data(self) -> List[Dict[str, Any]]:
        def sku(name, family, vcpu, mem, **caps):
            base = {"vCPUs": str(vcpu), "MemoryGB": str(mem), "PremiumIO": "True", "HyperVGenerations": "V1,V2",
                    "MaxDataDiskCount": "8", "MaxNetworkInterfaces": "2", "AcceleratedNetworkingEnabled": "True",
                    "UncachedDiskIOPS": str(3200 * vcpu), "UncachedDiskBytesPerSecond": str(48000000 * vcpu),
                    "CpuArchitectureType": "x64", "MaxResourceVolumeMB": "0"}
            base.update({k: str(v) for k, v in caps.items()})
            return {"name": name, "family": family, "caps": base, "restricted": False, "restricted_zones": set()}

        catalogue = {s["name"].lower(): s for s in (
            sku("Standard_D8s_v5", "standardDSv5Family", 8, 32), sku("Standard_D4s_v5", "standardDSv5Family", 4, 16),
            sku("Standard_D2s_v5", "standardDSv5Family", 2, 8),
            sku("Standard_B8as_v2", "standardBasv2Family", 8, 32, UncachedDiskIOPS=12800,
                UncachedDiskBytesPerSecond=290000000))}
        quiet = {"cpu_windows": 1440, "mem_windows": 1440, "cpu_avg": 1.9, "cpu_p95": 6.0, "cpu_p99": 14.0,
                 "mem_used_p99_gb": 4.1, "disk_uncached_p95": 3.0, "disk_cached_p95": 0.0, "net_p95_mbps": 2.5}
        base = "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines"
        common = {"type": "microsoft.compute/virtualmachines", "resourceGroup": "rg-app", "subscriptionId": "sub-1",
                  "location": "westeurope", "os": "Linux", "power": "PowerState/running", "gen": "V2", "nics": 1,
                  "dataDisks": 1}
        prices = {"Standard_D8s_v5": 0.46, "Standard_D4s_v5": 0.23, "Standard_D2s_v5": 0.115,
                  "Standard_B8as_v2": 0.3448}
        return [
            {"vm": dict(common, id=f"{base}/vm-app-01", name="vm-app-01", size="Standard_D4s_v5"),
             "current": catalogue["standard_d4s_v5"], "catalogue": catalogue, "profile": quiet,
             "advisor": {}, "cost_usd": 168.0, "prices": dict(prices)},
            {"vm": dict(common, id=f"{base}/vm-search-01", name="vm-search-01", size="Standard_D8s_v5"),
             "current": catalogue["standard_d8s_v5"], "catalogue": catalogue,
             "profile": dict(quiet, mem_used_p99_gb=24.6), "cost_usd": 0.7, "prices": dict(prices),
             "advisor": {"target": "Standard_B8as_v2", "rtype": "SkuChange"}},
            {"vm": dict(common, id=f"{base}/vm-batch-01", name="vm-batch-01", size="Standard_D8s_v5"),
             "current": catalogue["standard_d8s_v5"], "catalogue": catalogue,
             "profile": dict(quiet, cpu_p95=31.0, cpu_p99=64.0, cpu_avg=9.0), "advisor": {}, "cost_usd": 336.0,
             "prices": dict(prices)},
        ]
