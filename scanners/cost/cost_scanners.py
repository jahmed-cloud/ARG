"""
Azure Resource Guardian - Cost Scanners
========================================
Scanners in this module:
1. IdleIoTHubScanner              - IoT Hubs with no connected devices and no messages
2. AISpendGovernanceScanner       - Foundry / Azure OpenAI spend with no gateway; AI account sprawl
3. CommitmentDiscountScanner      - Advisor reservation / savings-plan opportunities
4. MarketplaceSaaSScanner         - Marketplace SaaS: unsubscribed leftovers, suspended/unactivated plans,
                                    terms ending or auto-renewing, material SaaS commitments
5. CheaperRegionScanner           - VMs and App Service plans that list for less in another region of the same
                                    geography (and allowed by Azure Policy)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from datetime import date, datetime
from typing import Any, Dict, List, Optional

from scanners.base.azure_api import (
    ACTUAL_COST,
    DEFAULT_ARM_CONCURRENCY,
    HOURS_BILLED_PER_MONTH,
    cached_metrics,
    cost_for,
    gather_limited,
    get_resource_costs,
    get_retail_price,
    price_at_actual_cost,
    vm_prices_by_region,
)
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.posture_scanner import PostureScanner
from scanners.base.providers import get_allowed_locations
from scanners.compute.compute_posture_scanners import APP_SERVICE_HOURLY_USD, _meter_name

# USD per unit per month (list price).
IOT_HUB_UNIT_USD = {"F1": 0.0, "B1": 10.0, "B2": 50.0, "B3": 500.0, "S1": 25.0, "S2": 250.0, "S3": 2500.0}


@register_scanner
class IdleIoTHubScanner(PostureScanner):
    scanner_name = "idle_iot_hub_scanner"
    display_name = "Idle IoT Hubs"
    description = "Detects IoT Hubs with no connected devices and no messages in 30 days"
    category = ScannerCategory.COST
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.devices/iothubs'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  sku_name = tostring(sku.name), units = toint(sku.capacity)
        """
        try:
            hubs = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings = []
        if self.is_live(context):
            async def _enrich(hub):
                try:
                    m = await cached_metrics(context, hub["id"],
                                             ["devices.connectedDevices.allProtocol", "dailyMessageQuotaUsed"],
                                             aggregation="Maximum")
                    hub["max_connected"] = (m.get("devices.connectedDevices.allProtocol") or {}).get("maximum") or 0.0
                    hub["max_daily_messages"] = (m.get("dailyMessageQuotaUsed") or {}).get("maximum") or 0.0
                except Exception as exc:
                    warnings.append(f"Metrics unavailable for {hub['name']}: {exc}")
            await gather_limited(hubs, _enrich, self.setting("arm_concurrency", DEFAULT_ARM_CONCURRENCY))

        findings = []
        for hub in hubs:
            if hub.get("max_connected") != 0 or hub.get("max_daily_messages") != 0:
                continue
            sku, units = hub.get("sku_name") or "S1", hub.get("units") or 1
            saving = IOT_HUB_UNIT_USD.get(sku, 0.0) * units
            findings.append(await price_at_actual_cost(context, self.resource_finding(
                hub,
                finding_type="idle_iot_hub",
                title=f"Idle IoT Hub ({sku}): {hub['name']}",
                description=(f"IoT Hub '{hub['name']}' ({sku} x{units}) had no connected devices and sent no "
                             f"messages in the last 30 days."),
                resource_type="microsoft.devices/iothubs",
                severity=SeverityLevel.MEDIUM if saving else SeverityLevel.LOW,
                remediation_steps="Confirm no field devices depend on it (check registered device count), then delete.",
                azure_cli_script=(f"az iot hub device-identity list --hub-name {hub['name']} --query 'length(@)'\n"
                                  f"az iot hub delete -n {hub['name']} -g {hub.get('resourceGroup')}"),
                evidence={"max_connected_devices_30d": 0, "max_daily_messages_30d": 0, "sku": sku, "units": units},
                estimated_monthly_savings_usd=saving,
                caf_control="Cost Optimization",
            )))
        return ScanOutput(findings=findings, resources_scanned=len(hubs), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [{
            "id": "/subscriptions/sub-1/resourceGroups/rg-iot/providers/Microsoft.Devices/IotHubs/iot-idle-1",
            "name": "iot-idle-1", "type": "microsoft.devices/iothubs", "resourceGroup": "rg-iot",
            "subscriptionId": "sub-1", "location": "westeurope", "sku_name": "B2", "units": 1,
            "max_connected": 0.0, "max_daily_messages": 0.0,
        }]


@register_scanner
class AISpendGovernanceScanner(PostureScanner):
    """
    Pay-as-you-go model spend is the fastest-growing line in many
    subscriptions. Without an AI gateway (APIM) there are no per-app token
    limits, no caching and no attribution. Savings are an estimate
    (default 15% of spend from caching + model routing).
    """

    scanner_name = "ai_spend_governance_scanner"
    display_name = "AI Spend Governance"
    description = "Detects material Azure OpenAI / Foundry spend with no AI gateway, and AI account sprawl"
    category = ScannerCategory.COST
    severity = SeverityLevel.HIGH

    MIN_MONTHLY_USD = 100.0
    HIGH_MONTHLY_USD = 1000.0
    ESTIMATED_SAVING_RATIO = 0.15
    MAX_ACCOUNTS = 2

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.cognitiveservices/accounts'
        | where tolower(kind) in ('openai', 'aiservices')
        | project id, name, type, resourceGroup, subscriptionId, location, tags, kind
        """
        apim_query = "Resources | where type =~ 'microsoft.apimanagement/service' | project id, name"
        try:
            accounts = await self.arg(context, query)
            gateways = [] if context.resource_graph_client is None else await self.arg(context, apim_query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        warnings = []
        if self.is_live(context) and accounts:
            costs = await get_resource_costs(context)
            async def _enrich(acc):
                entry = cost_for(costs, acc["id"]) or {}
                acc["cost_30d"], acc["cost_usd_30d"], acc["currency"] = entry.get("cost"), entry.get("cost_usd"), entry.get("currency")
                try:
                    deployments = await context.arm_client.get_all(f"{acc['id']}/deployments", "2024-10-01")
                    acc["deployments"] = [{"name": d.get("name"),
                                           "model": ((d.get("properties") or {}).get("model") or {}).get("name"),
                                           "sku": (d.get("sku") or {}).get("name"),
                                           "capacity": (d.get("sku") or {}).get("capacity")} for d in deployments]
                except Exception as exc:
                    warnings.append(f"Deployments unavailable for {acc['name']}: {exc}")
            await gather_limited(accounts, _enrich, self.setting("arm_concurrency", DEFAULT_ARM_CONCURRENCY))

        min_usd = float(self.setting("ai_min_monthly_usd", self.MIN_MONTHLY_USD))
        findings = []
        total_usd = sum(a.get("cost_usd_30d") or 0.0 for a in accounts)
        for acc in accounts:
            usd = acc.get("cost_usd_30d") or 0.0
            if gateways or usd < min_usd:
                continue
            deployments = acc.get("deployments") or []
            tpm = sum(d.get("capacity") or 0 for d in deployments)
            findings.append(self.resource_finding(
                acc,
                finding_type="ai_spend_without_gateway",
                title=f"USD {usd:,.0f}/30d AI spend without gateway: {acc['name']}",
                description=(f"{acc.get('kind')} account '{acc['name']}' cost ~USD {usd:,.0f} in 30 days "
                             f"({len(deployments)} deployment(s), {tpm:,}K TPM provisioned) and there is no API "
                             f"Management AI gateway in the subscription: no per-app token limits, no semantic "
                             f"caching and no usage attribution. Saving shown is an estimate "
                             f"({self.ESTIMATED_SAVING_RATIO:.0%} from caching and model routing)."),
                resource_type="microsoft.cognitiveservices/accounts",
                severity=SeverityLevel.HIGH if usd >= self.HIGH_MONTHLY_USD else SeverityLevel.MEDIUM,
                remediation_steps=(
                    "1. Front model endpoints with APIM (llm-token-limit, llm-emit-token-metric, semantic cache).\n"
                    "2. Route simple calls to smaller models; reserve flagship models for hard steps.\n"
                    "3. Enable diagnostic logs on the account and a monthly AI budget per project."
                ),
                azure_cli_script=f"az cognitiveservices account deployment list -g {acc.get('resourceGroup')} -n {acc['name']} -o table",
                evidence={"cost_30d": acc.get("cost_30d"), "currency": acc.get("currency"), "cost_usd_30d": usd,
                          "deployments": deployments, "provisioned_tpm_k": tpm},
                estimated_monthly_savings_usd=round(usd * self.ESTIMATED_SAVING_RATIO, 2),
                caf_control="Cost Optimization",
            ))

        if len(accounts) > int(self.setting("max_ai_accounts", self.MAX_ACCOUNTS)):
            regions = sorted({a.get("location") for a in accounts})
            findings.append(self.subscription_finding(
                context,
                finding_type="ai_account_sprawl",
                title=f"{len(accounts)} AI Services accounts in {len(regions)} region(s)",
                description=("Generative-AI accounts: " + ", ".join(a["name"] for a in accounts)
                             + f". Capacity, quotas, content filters and logging are configured per account "
                             f"(30-day spend ~USD {total_usd:,.0f})."),
                severity=SeverityLevel.MEDIUM,
                remediation_steps="Consolidate to one Foundry resource per environment with a project per use-case, behind one gateway.",
                evidence={"accounts": [a["name"] for a in accounts], "regions": regions, "cost_usd_30d": total_usd},
            ))
        return ScanOutput(findings=findings, resources_scanned=len(accounts), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        base = "/subscriptions/sub-1/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts"
        common = {"type": "microsoft.cognitiveservices/accounts", "resourceGroup": "rg-ai", "subscriptionId": "sub-1",
                  "location": "germanywestcentral", "kind": "AIServices", "currency": "USD"}
        return [
            {**common, "id": f"{base}/ai-agents-1", "name": "ai-agents-1", "cost_30d": 2200.0, "cost_usd_30d": 2200.0,
             "deployments": [{"name": "gpt-large", "model": "gpt-large", "sku": "DataZoneStandard", "capacity": 2575}]},
            {**common, "id": f"{base}/ai-agents-2", "name": "ai-agents-2", "cost_30d": 40.0, "cost_usd_30d": 40.0},
            {**common, "id": f"{base}/ai-agents-3", "name": "ai-agents-3", "cost_30d": 150.0, "cost_usd_30d": 150.0},
        ]


@register_scanner
class CommitmentDiscountScanner(PostureScanner):
    """Advisor reservation / savings-plan recommendations, de-duplicated per recommendation (best term kept)."""

    scanner_name = "commitment_discount_scanner"
    display_name = "Commitment Discount Opportunities"
    description = "Imports Azure Advisor reserved-instance and savings-plan recommendations"
    category = ScannerCategory.COST
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = f"""
        advisorresources
        | where type =~ 'microsoft.advisor/recommendations'
        | where subscriptionId == '{context.subscription_id}'
        | where tostring(properties.category) =~ 'Cost'
        | extend solution = tostring(properties.shortDescription.solution)
        | where solution contains 'reserved' or solution contains 'savings plan' or solution contains 'reservation'
        | project solution, impact = tostring(properties.impact),
                  annual = todouble(properties.extendedProperties.annualSavingsAmount),
                  currency = tostring(properties.extendedProperties.savingsCurrency),
                  term = tostring(properties.extendedProperties.term),
                  sku = tostring(properties.extendedProperties.displaySKU)
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        best: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            key = r.get("solution") or "commitment"
            if key not in best or (r.get("annual") or 0) > (best[key].get("annual") or 0):
                best[key] = r
        if not best:
            return ScanOutput(resources_scanned=len(rows))

        usd_annual = sum(r.get("annual") or 0 for r in best.values() if (r.get("currency") or "USD").upper() == "USD")
        finding = self.subscription_finding(
            context,
            finding_type="commitment_discount_opportunity",
            title=f"{len(best)} commitment-discount opportunit{'y' if len(best) == 1 else 'ies'} (Advisor)",
            description=("Azure Advisor recommends: " + "; ".join(
                f"{k} - {r.get('annual') or 0:,.0f} {r.get('currency') or ''}/yr" for k, r in best.items())
                + ". Commit only after rightsizing and clean-up, otherwise the reservation locks in waste."),
            remediation_steps="Rightsize first, then purchase reservations / savings plan for the steady-state baseline.",
            evidence={"recommendations": list(best.values())},
            estimated_monthly_savings_usd=round(usd_annual / 12, 2) if usd_annual else None,
            caf_control="Cost Optimization",
        )
        return ScanOutput(findings=[finding], resources_scanned=len(rows))

    def _mock_data(self) -> List[Dict[str, Any]]:
        return [
            {"solution": "Consider SQL PaaS DB reserved instance to save over the pay-as-you-go costs",
             "impact": "High", "annual": 3311.0, "currency": "USD", "term": "P3Y", "sku": "Hyperscale Gen5"},
            {"solution": "Consider SQL PaaS DB reserved instance to save over the pay-as-you-go costs",
             "impact": "High", "annual": 1899.0, "currency": "USD", "term": "P1Y", "sku": "Hyperscale Gen5"},
            {"solution": "Consider purchasing a savings plan to unlock lower prices",
             "impact": "High", "annual": 1647.0, "currency": "USD", "term": "P1Y", "sku": ""},
        ]


def _parse_date(value: Any) -> Optional[date]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except ValueError:
        return None


@register_scanner
class MarketplaceSaaSScanner(PostureScanner):
    """
    Azure Marketplace SaaS subscriptions (microsoft.saas/resources) are billed to the Azure subscription
    - often as large up-front charges - but none of the resource-level rules apply to them. This scanner
    reads the SaaS status and term from Resource Graph and the 12-month cost per SaaS resource from
    Cost Management, and reports:

    - Unsubscribed SaaS resources left behind (no longer billing, but clutter inventory and cost views)
    - Suspended (usually a failed payment) or never-activated (PendingFulfillmentStart) plans
    - Terms ending soon: auto-renew on (renewal decision / re-negotiation due) or off (service stops)
    - Material SaaS commitments, so the spend has an owner and a review date
    """

    scanner_name = "marketplace_saas_scanner"
    display_name = "Marketplace SaaS Subscriptions"
    description = "Reviews Azure Marketplace SaaS plans: leftovers, suspended plans, renewals and material commitments"
    category = ScannerCategory.COST
    severity = SeverityLevel.MEDIUM

    RENEWAL_WINDOW_DAYS = 90
    URGENT_DAYS = 30
    COMMITMENT_MIN_USD = 1000.0
    COST_DAYS = 364  # Cost Management rejects custom periods longer than one year

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.saas/resources'
        | project id, name, type, resourceGroup, subscriptionId, location, tags,
                  status = tostring(properties.status), autoRenew = tobool(properties.autoRenew),
                  isFreeTrial = tobool(properties.isFreeTrial),
                  offerName = tostring(properties.offerName), planName = tostring(properties.planName),
                  publisherName = tostring(properties.publisherName), offerId = tostring(properties.offerId),
                  termUnit = tostring(properties.term.termUnit),
                  termStart = tostring(properties.term.startDate), termEnd = tostring(properties.term.endDate),
                  purchaserEmail = tostring(properties.purchaserEmail),
                  created = tostring(properties.created)
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])
        if not rows:
            return ScanOutput(resources_scanned=0)

        warnings = []
        if self.is_live(context):
            costs = await get_resource_costs(context, days=self.COST_DAYS, cost_type=ACTUAL_COST)
            if costs is None:
                warnings.append("12-month SaaS cost unavailable (Cost Management query failed); commitments not assessed.")
            for r in rows:
                entry = cost_for(costs, r["id"]) or {}
                r["cost_12m"], r["cost_usd_12m"], r["currency"] = entry.get("cost"), entry.get("cost_usd"), entry.get("currency")

        today = date.today()
        window = int(self.setting("saas_renewal_window_days", self.RENEWAL_WINDOW_DAYS))
        min_usd = float(self.setting("saas_commitment_min_usd", self.COMMITMENT_MIN_USD))
        findings = []
        for r in rows:
            status = (r.get("status") or "").lower()
            end = _parse_date(r.get("termEnd"))
            days_left = (end - today).days if end else None
            offer = r.get("offerName") or r.get("offerId") or "SaaS offer"
            plan = f"plan '{r['planName']}'" if r.get("planName") else "plan"
            publisher = r.get("publisherName") or "the publisher"
            cost = r.get("cost_12m")
            spend = (f" It was charged {cost:,.0f} {r.get('currency') or ''} in the last 12 months." if cost else "")
            evidence = {k: r.get(k) for k in ("status", "autoRenew", "isFreeTrial", "offerName", "planName",
                                                "publisherName", "termUnit", "termStart", "termEnd",
                                                "cost_12m", "cost_usd_12m", "currency")}
            evidence["days_to_term_end"] = days_left
            common = dict(resource_type="microsoft.saas/resources", evidence=evidence, caf_control="Cost Optimization")

            if status == "unsubscribed":
                findings.append(self.resource_finding(
                    r, finding_type="marketplace_saas_unsubscribed",
                    title=f"Unsubscribed Marketplace SaaS left behind: {r['name']}",
                    description=(f"{offer} ({plan}, {publisher}) is Unsubscribed"
                                 + (f" since its term ended on {end.isoformat()}" if end else "")
                                 + ". The resource no longer bills but still shows up in inventory, cost views and "
                                   "access reviews." + spend),
                    severity=SeverityLevel.LOW,
                    remediation_steps="Confirm with the owner that nothing depends on it, then delete the SaaS resource.",
                    azure_cli_script=f'az resource delete --ids "{r["id"]}"',
                    estimated_monthly_savings_usd=0.0, **common,
                ))
            elif status in ("suspended", "pendingfulfillmentstart"):
                suspended = status == "suspended"
                findings.append(self.resource_finding(
                    r, finding_type="marketplace_saas_inactive",
                    title=(f"Marketplace SaaS suspended: {r['name']}" if suspended
                           else f"Marketplace SaaS purchased but never activated: {r['name']}"),
                    description=(f"{offer} ({plan}, {publisher}) is "
                                 + ("Suspended - usually a failed payment; users lose the service and the plan is "
                                    "cancelled if it is not reinstated." if suspended else
                                    "PendingFulfillmentStart - it was bought but the publisher's landing page was "
                                    "never completed, so the service is not in use.") + spend),
                    severity=SeverityLevel.HIGH if suspended else SeverityLevel.MEDIUM,
                    remediation_steps=("Check the payment method / billing account and reinstate or cancel the plan."
                                       if suspended else
                                       "Complete activation on the publisher's landing page, or cancel the purchase."),
                    estimated_monthly_savings_usd=0.0, **common,
                ))
            elif status == "subscribed" and days_left is not None and days_left <= window:
                auto = bool(r.get("autoRenew"))
                findings.append(self.resource_finding(
                    r, finding_type="marketplace_saas_term_ending",
                    title=(f"Marketplace SaaS auto-renews in {max(days_left, 0)} days: {r['name']}" if auto
                           else f"Marketplace SaaS term ends in {max(days_left, 0)} days (auto-renew off): {r['name']}"),
                    description=(f"{offer} ({plan}, {publisher}) term {r.get('termUnit') or ''} ends on "
                                 f"{end.isoformat()}. "
                                 + ("Auto-renew is on, so the next term is charged automatically - review seats, "
                                    "usage and price before then." if auto else
                                    "Auto-renew is off, so the service stops at term end unless it is renewed.")
                                 + spend),
                    severity=(SeverityLevel.HIGH if not auto and days_left <= self.URGENT_DAYS else SeverityLevel.MEDIUM),
                    remediation_steps=("Agree with the owner whether to renew, change plan/quantity or cancel before "
                                       "the term end; for private offers, re-negotiate early."),
                    estimated_monthly_savings_usd=0.0, **common,
                ))
            elif status == "subscribed" and (r.get("cost_usd_12m") or 0) >= min_usd and not r.get("isFreeTrial"):
                findings.append(self.resource_finding(
                    r, finding_type="marketplace_saas_commitment",
                    title=f"Marketplace SaaS commitment: {offer} ({r['name']})",
                    description=(f"{offer} ({plan}, {publisher}) is an active Marketplace commitment"
                                 + (f" until {end.isoformat()}" if end else "")
                                 + f", auto-renew {'on' if r.get('autoRenew') else 'off'}." + spend
                                 + " Up-front SaaS charges make the subscription's monthly cost lumpy; the plan needs "
                                   "a named owner and a review date before the term ends."),
                    severity=SeverityLevel.LOW,
                    remediation_steps=("Record the owner and renewal date, compare licensed quantity with real usage, "
                                       "and add a budget that expects the up-front charge."),
                    estimated_monthly_savings_usd=None, **common,
                ))
        return ScanOutput(findings=findings, resources_scanned=len(rows), warnings=warnings)

    def _mock_data(self) -> List[Dict[str, Any]]:
        from datetime import timedelta

        today = date.today()
        base = "/subscriptions/sub-1/resourceGroups/rg-saas/providers/Microsoft.SaaS/resources"
        common = {"type": "microsoft.saas/resources", "resourceGroup": "rg-saas", "subscriptionId": "sub-1",
                  "location": "global", "publisherName": "Contoso Security", "offerName": "Contoso Mail Shield",
                  "termUnit": "P1Y", "isFreeTrial": False, "currency": "USD"}
        return [
            {**common, "id": f"{base}/mail-shield-2024", "name": "mail-shield-2024", "status": "Unsubscribed",
             "autoRenew": False, "planName": "Year 1", "termEnd": (today - timedelta(days=200)).isoformat()},
            {**common, "id": f"{base}/mail-shield", "name": "mail-shield", "status": "Subscribed", "autoRenew": True,
             "planName": "Year 2", "termEnd": (today + timedelta(days=45)).isoformat(),
             "cost_12m": 120000.0, "cost_usd_12m": 120000.0},
            {**common, "id": f"{base}/backup-saas", "name": "backup-saas", "status": "Subscribed", "autoRenew": False,
             "planName": "3-year", "termUnit": "P3Y", "termEnd": (today + timedelta(days=600)).isoformat(),
             "cost_12m": 24000.0, "cost_usd_12m": 24000.0},
            {**common, "id": f"{base}/analytics-saas", "name": "analytics-saas", "status": "Suspended", "autoRenew": True,
             "planName": "Monthly", "termUnit": "P1M", "termEnd": (today + timedelta(days=10)).isoformat()},
        ]


# ---------------------------------------------------------------------------
# 5. Cheaper region in the same geography
# ---------------------------------------------------------------------------

# Regions compared with each other: one geography keeps data residency, latency and compliance comparable.
# Settings: `region_groups` ({name: [regions]}) replaces these, `region_excluded` drops regions.
REGION_GROUPS: Dict[str, List[str]] = {
    "Europe": ["westeurope", "northeurope", "swedencentral", "germanywestcentral", "francecentral",
               "switzerlandnorth", "uksouth", "norwayeast", "italynorth", "polandcentral", "spaincentral"],
    "North America": ["eastus", "eastus2", "centralus", "southcentralus", "westus2", "westus3", "northcentralus",
                      "canadacentral"],
    "Asia Pacific": ["southeastasia", "eastasia", "centralindia", "southindia", "japaneast", "koreacentral",
                     "australiaeast"],
}


def region_group(region: str, groups: Dict[str, List[str]]) -> Optional[tuple]:
    """(group name, its regions) for a region; None when the region is in no group."""
    region = (region or "").lower().replace(" ", "")
    for name, regions in groups.items():
        if region in regions:
            return name, list(regions)
    return None


def cheaper_regions(current: str, prices: Dict[str, float], candidates, min_pct: float) -> List[Dict[str, Any]]:
    """Candidate regions at least `min_pct` % cheaper than the current one, cheapest first."""
    base = prices.get(current)
    if not base:
        return []
    found = [{"region": r, "usd_per_hour": round(p, 4), "cheaper_pct": round((1 - p / base) * 100, 1)}
             for r, p in prices.items() if r in candidates and r != current and p <= base * (1 - min_pct / 100)]
    return sorted(found, key=lambda a: (a["usd_per_hour"], a["region"]))


@register_scanner
class CheaperRegionScanner(PostureScanner):
    """
    VMs and Premium App Service plans whose size lists for less in another region of the same geography. A region
    move is a migration (data residency, latency, dependencies, egress, quota, region-bound reservations), so this is
    a structural suggestion - for new deployments, rebuilds and DR placement - valued at the resource's own price.
    Regions an 'Allowed locations' policy forbids are never suggested; tag a resource `arg-region-fixed` to skip it.
    """

    scanner_name = "region_price_scanner"
    display_name = "Cheaper Region Available"
    description = "Suggests regions in the same geography where a VM size or App Service plan lists for less"
    category = ScannerCategory.COST
    severity = SeverityLevel.LOW

    MIN_SAVING_PCT = 10.0
    MIN_SAVING_USD = 20.0

    VM_QUERY = """
    Resources
    | where type =~ 'microsoft.compute/virtualmachines'
    | project id, name, type, resourceGroup, subscriptionId, location, tags,
              size = tostring(properties.hardwareProfile.vmSize),
              os = tostring(properties.storageProfile.osDisk.osType),
              license = tostring(properties.licenseType),
              priority = tostring(properties.priority),
              power = tostring(properties.extended.instanceView.powerState.code)
    """
    PLAN_QUERY = """
    Resources
    | where type =~ 'microsoft.web/serverfarms'
    | project id, name, type, resourceGroup, subscriptionId, location, tags, kind,
              sku_name = tostring(sku.name), capacity = toint(sku.capacity), reserved = tobool(properties.reserved)
    """

    async def scan(self, context: ScanContext) -> ScanOutput:
        live = self.is_live(context) and getattr(context, "resource_graph_client", None) is not None
        try:
            cases = await self._live_cases(context) if live else self._mock_data()
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])
        allowed = await get_allowed_locations(context) if live else None
        groups = self.setting("region_groups", REGION_GROUPS)
        excluded = {str(r).lower() for r in self.setting("region_excluded", [])}
        findings = []
        for case in cases:
            finding = await self._evaluate(context, case, groups, excluded, allowed)
            if finding is not None:
                findings.append(finding)
        return ScanOutput(findings=findings, resources_scanned=len(cases))

    @staticmethod
    def _windows(vm: Dict[str, Any]) -> bool:
        # Windows meter only without Azure Hybrid Benefit (licenseType Windows_Server / Windows_Client).
        return (vm.get("os") or "").lower() == "windows" and (vm.get("license") or "") not in (
            "Windows_Server", "Windows_Client")

    @staticmethod
    def _vm_eligible(vm: Dict[str, Any]) -> bool:
        tags = {str(k).lower() for k in (vm.get("tags") or {})}
        return (bool(vm.get("size")) and (vm.get("power") or "").lower() == "powerstate/running"
                and (vm.get("priority") or "").lower() != "spot"
                and not (vm.get("resourceGroup") or "").lower().startswith("mc_")  # AKS node pools
                and "arg-region-fixed" not in tags)

    @staticmethod
    async def _plan_hourly(context: ScanContext, sku: str, linux: bool, region: str) -> Optional[float]:
        family = "Premium v3" if sku.endswith("v3") else "Premium v2"
        product = f"Azure App Service {family} Plan" + (" - Linux" if linux else "")
        # No fallback price: a region without a price is left out instead of assumed equal.
        return await get_retail_price(context, f"serviceName eq 'Azure App Service' and armRegionName eq '{region}' "
                                               f"and productName eq '{product}' and meterName eq '{_meter_name(sku)}'")

    async def _live_cases(self, context: ScanContext) -> List[Dict[str, Any]]:
        vms = [v for v in await self.arg(context, self.VM_QUERY) if self._vm_eligible(v)]
        prices: Dict[tuple, Dict[str, float]] = {}

        async def _fetch(key: tuple) -> None:
            prices[key] = await vm_prices_by_region(context, key[0], key[1])

        await gather_limited(sorted({(v["size"], self._windows(v)) for v in vms}), _fetch,
                             self.setting("arm_concurrency", DEFAULT_ARM_CONCURRENCY))
        cases = [{"row": v, "kind": "VM", "sku": v["size"], "units": 1,
                  "prices": prices.get((v["size"], self._windows(v)), {})} for v in vms]

        groups = self.setting("region_groups", REGION_GROUPS)
        premium = {sku for sku, _ in APP_SERVICE_HOURLY_USD}
        for plan in await self.arg(context, self.PLAN_QUERY):
            group = region_group(plan.get("location"), groups)
            if plan.get("sku_name") not in premium or not group:
                continue
            if "arg-region-fixed" in {str(k).lower() for k in (plan.get("tags") or {})}:
                continue
            linux = bool(plan.get("reserved")) or "linux" in (plan.get("kind") or "").lower()
            regional = {}
            for region in group[1]:
                price = await self._plan_hourly(context, plan["sku_name"], linux, region)
                if price:
                    regional[region] = price
            cases.append({"row": plan, "kind": "App Service plan", "sku": plan["sku_name"],
                          "units": plan.get("capacity") or 1, "prices": regional})
        return cases

    async def _evaluate(self, context: ScanContext, case: Dict[str, Any], groups: Dict[str, List[str]],
                        excluded: set, allowed: Optional[set]):
        row, prices = case["row"], case["prices"]
        region = (row.get("location") or "").lower().replace(" ", "")
        group = region_group(region, groups)
        if not group or region not in prices:
            return None
        candidates = set(group[1]) - excluded
        if allowed is not None:
            candidates &= allowed
        alts = cheaper_regions(region, prices, candidates,
                               float(self.setting("region_min_saving_pct", self.MIN_SAVING_PCT)))
        if not alts:
            return None
        best, current, units = alts[0], prices[region], case["units"]
        list_monthly = current * HOURS_BILLED_PER_MONTH * units
        list_saving = round((current - best["usd_per_hour"]) * HOURS_BILLED_PER_MONTH * units, 2)
        min_usd = float(self.setting("region_min_saving_usd", self.MIN_SAVING_USD))
        if list_saving < min_usd:
            return None
        kind, sku, name = case["kind"], case["sku"], row["name"]
        listed = ", ".join(f"{a['region']} USD {a['usd_per_hour']:.3f}/hour (-{a['cheaper_pct']:.0f}%)" for a in alts[:3])
        policy = (f" Only regions the 'Allowed locations' policy permits were compared ({', '.join(sorted(allowed))})."
                  if allowed is not None else "")
        finding = self.resource_finding(
            row,
            finding_type="cheaper_region_available",
            title=f"Cheaper region for {name}: {sku} lists {best['cheaper_pct']:.0f}% less in {best['region']}",
            description=(
                f"{kind} '{name}' runs {sku}{f' x{units}' if units > 1 else ''} in {region} at USD {current:.3f}/hour "
                f"(pay-as-you-go list price). In the same geography ({group[0]}) it lists for less in: {listed}; "
                f"about USD {list_saving:,.0f}/month at list prices.{policy} A region move is a migration, not a "
                f"setting: check data residency and compliance, latency to users and to the services it talks to "
                f"(they may have to move too), egress between regions, availability zones and quota for the size, "
                f"and that reservations are bought per region (savings plans are not). Best used for new "
                f"deployments, rebuilds and disaster-recovery placement."
            ),
            resource_type=(row.get("type") or "").lower(),
            remediation_steps=(
                "1. Confirm data residency, compliance and latency requirements allow the cheaper region.\n"
                "2. Check that the size and every dependent service exist there, and the subscription's quota.\n"
                "3. Plan the move with Azure Resource Mover or a redeployment from infrastructure as code; move or "
                "re-point dependent resources and exchange region-bound reservations.\n"
                "4. For new or rebuilt workloads, deploy to the cheaper region from the start."
            ),
            azure_cli_script=(
                f"az vm list-skus --location {best['region']} --size {sku} --all --output table\n"
                f"az vm list-usage --location {best['region']} --output table" if kind == "VM" else
                f"az appservice list-locations --sku {sku} --output table"
            ),
            evidence={"current_region": region, "region_group": group[0], "sku": sku, "units": units,
                      "usd_per_hour_current": round(current, 4), "alternatives": alts[:5],
                      "allowed_locations": sorted(allowed) if allowed is not None else None,
                      "list_price_monthly_usd": round(list_monthly, 2)},
            estimated_monthly_savings_usd=list_saving,
            caf_control="Cost Optimization",
        )
        # Scaled to what the resource actually costs (discounts, reservations, savings plans).
        finding = await price_at_actual_cost(context, finding, list_cost=list_monthly)
        if (finding.estimated_monthly_savings_usd or 0) < min_usd:
            return None
        return finding

    def _mock_data(self) -> List[Dict[str, Any]]:
        base = "/subscriptions/sub-1/resourceGroups/rg-app/providers"

        def row(kind: str, name: str, region: str) -> Dict[str, Any]:
            return {"id": f"{base}/{kind}/{name}", "name": name, "type": kind.lower(), "resourceGroup": "rg-app",
                    "subscriptionId": "sub-1", "location": region, "tags": {}}

        d8 = {"westeurope": 0.384, "northeurope": 0.352, "swedencentral": 0.336, "switzerlandnorth": 0.460}
        return [
            # swedencentral is 12.5 % cheaper; northeurope (8.3 %) stays under the 10 % floor
            {"row": row("Microsoft.Compute/virtualMachines", "vm-web-01", "westeurope"), "kind": "VM",
             "sku": "Standard_D8s_v5", "units": 1, "prices": d8},
            # already in the cheapest region of its geography: no finding
            {"row": row("Microsoft.Compute/virtualMachines", "vm-web-02", "swedencentral"), "kind": "VM",
             "sku": "Standard_D8s_v5", "units": 1, "prices": d8},
            {"row": row("Microsoft.Web/serverfarms", "asp-portal", "switzerlandnorth"), "kind": "App Service plan",
             "sku": "P1v3", "units": 2, "prices": {"switzerlandnorth": 0.404, "westeurope": 0.338, "northeurope": 0.320}},
        ]

