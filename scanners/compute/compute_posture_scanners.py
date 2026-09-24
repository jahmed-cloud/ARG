"""
Azure Resource Guardian - Compute & App Service Posture Scanners
=================================================================
Scanners in this module:
1. UnsupportedOSImageScanner           — VMs built from end-of-support OS images
2. ManagedDiskNetworkAccessScanner     — Disks exportable from any network
3. AppServicePlanGenerationScanner     — Premium v2 plans (no reservations, older CPUs)
                                          and single-instance production plans
4. AppServicePlanUtilizationScanner    — Plans running hot (CPU saturation)
5. AppServiceMixedEnvironmentScanner   — Production and non-production on one plan
6. WebAppHttpsAndIdentityScanner       — HTTP allowed / no managed identity
7. WebAppConfigurationScanner          — EOL runtime stack, TLS, FTP, health check, 32-bit worker

Metric- and config-based checks run only when an ArmClient is injected
(live mode); mock rows carry the enriched values for offline testing.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import re
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from scanners.base.azure_api import HOURS_PER_MONTH, get_retail_price
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.naming import env_from_name, env_from_tags
from scanners.base.posture_scanner import PostureScanner


def _as_date(value: Any) -> date:
    if isinstance(value, date):
        return value
    return datetime.fromisoformat(str(value)).date()


# ---------------------------------------------------------------------------
# 1. End-of-support OS images
# ---------------------------------------------------------------------------

# (offer regex, sku regex, end-of-support date, label) — matched case-insensitively
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
                    f"VM '{vm['name']}' ({vm.get('vm_size')}) runs {vm.get('offer')}/{vm.get('sku')} — "
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
                        f"instance without zone redundancy — platform upgrades and instance failures cause "
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
    """30-day CpuPercentage average/maximum on each plan (live mode)."""

    scanner_name = "app_service_plan_utilization_scanner"
    display_name = "App Service Plan CPU Saturation"
    description = "Detects App Service plans whose CPU is saturated over the last 30 days"
    category = ScannerCategory.COMPUTE
    severity = SeverityLevel.HIGH

    AVG_CPU_THRESHOLD = 60.0
    MAX_CPU_THRESHOLD = 95.0

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
            for plan in plans:
                try:
                    m = await context.arm_client.metrics_summary(plan["id"], ["CpuPercentage", "MemoryPercentage"])
                    plan["cpu_avg"] = (m.get("CpuPercentage") or {}).get("average")
                    plan["cpu_max"] = (m.get("CpuPercentage") or {}).get("maximum")
                    plan["mem_avg"] = (m.get("MemoryPercentage") or {}).get("average")
                except Exception as exc:
                    warnings.append(f"Metrics unavailable for {plan['name']}: {exc}")

        avg_limit = float(self.setting("cpu_avg_threshold", self.AVG_CPU_THRESHOLD))
        max_limit = float(self.setting("cpu_max_threshold", self.MAX_CPU_THRESHOLD))
        findings = []
        for plan in plans:
            avg, peak = plan.get("cpu_avg"), plan.get("cpu_max")
            if avg is None or not (avg >= avg_limit or (peak or 0) >= max_limit):
                continue
            findings.append(self.resource_finding(
                plan,
                finding_type="app_service_plan_cpu_saturated",
                title=f"CPU saturated ({avg:.0f}% avg): {plan['name']}",
                description=(
                    f"App Service plan '{plan['name']}' ({plan.get('sku_name')} x{plan.get('capacity')}, "
                    f"{plan.get('sites')} app(s)) averaged {avg:.1f}% CPU with peaks of {peak or 0:.0f}% over "
                    f"30 days. Every app and slot on the plan competes for the same instance."
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
                evidence={"cpu_avg_30d": avg, "cpu_max_30d": peak, "memory_avg_30d": plan.get("mem_avg")},
                estimated_monthly_savings_usd=0.0,
            ))
        return ScanOutput(findings=findings, resources_scanned=len(plans), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/asp-shared-1",
            "name": "asp-shared-1", "type": "microsoft.web/serverfarms", "resourceGroup": "rg-web",
            "subscriptionId": "sub-1", "location": "westeurope", "sku_name": "P3v2", "capacity": 1, "sites": 5,
            "cpu_avg": 68.3, "cpu_max": 100.0, "mem_avg": 32.2,
        }]


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
            for s in sites:
                try:
                    payload = await context.arm_client.get(f"{s['id']}/config/web", "2023-12-01")
                    s["config"] = payload.get("properties") or {}
                except Exception as exc:
                    warnings.append(f"config/web unavailable for {s['name']}: {exc}")

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
                            + (f"out of support since {eos_date.isoformat()} — no security patches."
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

