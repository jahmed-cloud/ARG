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

import json
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
    missing_resources,
    price_at_actual_cost,
    top_level_id,
    vm_prices_by_region,
)
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.guidance import PRICE
from scanners.base.posture_scanner import ADVISOR_ACTIVE_FILTER, PostureScanner
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


AI_GATEWAY_SKUS = {  # setting ai_gateway_sku -> (Retail Prices skuName, meterName, fallback USD / month)
    "Basic v2": ("Basic v2", "Basic v2 Unit", PRICE["apim_basic_v2"]),
    "Standard v2": ("Standard v2", "Standard v2 Unit", PRICE["apim_standard_v2"]),
    "Developer": ("Developer", "Developer Unit", PRICE["apim_developer"]),
}


@register_scanner
class AISpendGovernanceScanner(PostureScanner):
    """
    Pay-as-you-go model spend is the fastest-growing line in many
    subscriptions. Without an AI gateway (APIM) there are no per-app token
    limits, no caching and no attribution.

    The gateway is not free: one API Management unit (Basic v2 by default,
    `ai_gateway_sku`) is priced from the Retail Prices API and shared across
    the subscription's AI accounts by spend. The saving shown is the net of
    an assumed gross reduction (`ai_gateway_saving_ratio`, 15 % from caching,
    token limits and routing) minus that gateway cost; below break-even the
    finding stays, at Low severity with no saving, because the gateway's
    value is then governance (limits, attribution), not money.
    """

    scanner_name = "ai_spend_governance_scanner"
    display_name = "AI Spend Governance"
    description = "Detects material Azure OpenAI / Foundry spend with no AI gateway (net of the gateway's cost), and AI account sprawl"
    category = ScannerCategory.COST
    severity = SeverityLevel.HIGH
    finding_types = {"ai_spend_without_gateway", "ai_account_sprawl"}

    MIN_MONTHLY_USD = 100.0
    HIGH_MONTHLY_USD = 1000.0
    ESTIMATED_SAVING_RATIO = 0.15
    MAX_ACCOUNTS = 2

    async def gateway_monthly_usd(self, context: ScanContext, sku: str, region: str) -> float:
        sku_name, meter, fallback = AI_GATEWAY_SKUS.get(sku, AI_GATEWAY_SKUS["Basic v2"])
        hourly = await get_retail_price(
            context, f"serviceName eq 'API Management' and armRegionName eq '{region}' and skuName eq '{sku_name}' "
                     f"and meterName eq '{meter}'")
        return round(hourly * HOURS_BILLED_PER_MONTH, 2) if hourly else fallback

    async def _platform_gateways(self, context: ScanContext) -> List[Dict[str, Any]]:
        """API Management instances anywhere in the tenant (the landing zone's shared AI gateway lives in a platform
        subscription): reusing one is the target, at about no extra cost."""
        from scanners.base.azure_api import query_resource_graph

        try:
            rows = await query_resource_graph(
                context, "Resources | where type =~ 'microsoft.apimanagement/service' "
                         "| project name, subscriptionId, resourceGroup, sku = tostring(sku.name)", tenant_scope=True)
        except Exception:
            return []
        return rows or []

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
        ratio = float(self.setting("ai_gateway_saving_ratio", self.ESTIMATED_SAVING_RATIO))
        sku = str(self.setting("ai_gateway_sku", "Basic v2"))
        findings = []
        total_usd = sum(a.get("cost_usd_30d") or 0.0 for a in accounts)
        eligible = [] if gateways else [a for a in accounts if (a.get("cost_usd_30d") or 0.0) >= min_usd]
        eligible_usd = sum(a["cost_usd_30d"] for a in eligible)
        platform = await self._platform_gateways(context) if eligible else []
        gateway_usd = (await self.gateway_monthly_usd(context, sku, eligible[0].get("location") or "westeurope")
                       if eligible else 0.0)       # a dedicated gateway's list price
        effective_usd = 0.0 if platform else gateway_usd   # reusing the platform gateway adds about nothing
        net_total = eligible_usd * ratio - effective_usd
        break_even = gateway_usd / ratio if ratio else None
        for acc in eligible:
            usd = acc["cost_usd_30d"]
            deployments = acc.get("deployments") or []
            tpm = sum(d.get("capacity") or 0 for d in deployments)
            gateway_share = round(effective_usd * usd / eligible_usd, 2)
            gross = round(usd * ratio, 2)
            net = round(gross - gateway_share, 2)
            pays_off = net_total > 0 or bool(platform)
            reuse = ", ".join(f"{g.get('name')} ({g.get('sku')})" for g in platform[:3])
            findings.append(self.resource_finding(
                acc,
                finding_type="ai_spend_without_gateway",
                title=(f"USD {usd:,.0f}/30d AI spend not routed through the platform gateway: {acc['name']}"
                       if platform else f"USD {usd:,.0f}/30d AI spend without gateway: {acc['name']}" if pays_off else
                       f"AI spend without gateway, below break-even (USD {usd:,.0f}/30d): {acc['name']}"),
                description=(
                    f"{acc.get('kind')} account '{acc['name']}' cost ~USD {usd:,.0f} in 30 days "
                    f"({len(deployments)} deployment(s), {tpm:,}K TPM provisioned) and the subscription has no API "
                    f"Management AI gateway. What a gateway delivers: token consumption per app / team (chargeback), "
                    f"token-per-minute limits so one caller cannot exhaust the quota or the budget, managed-identity "
                    f"access to the models instead of keys in apps, load balancing and failover across deployments, "
                    f"and optionally a semantic cache for repeated prompts. "
                    + (f"Target: route it through the tenant's existing API Management ({reuse}) - the landing-zone "
                       f"pattern of one shared AI gateway in the platform subscription, about no extra cost. "
                       if platform else "")
                    + (f"A dedicated gateway would cost API Management {sku} about USD {gateway_usd:,.2f}/month "
                       f"instead. " if platform else
                       f"What it costs: API Management {sku} about USD {gateway_usd:,.2f}/month, of which USD "
                       f"{gateway_share:,.2f} is allocated to this account by spend (USD 0 extra if a shared platform "
                       f"APIM can be reused). ")
                    + f"Assuming a {ratio:.0%} reduction (USD {gross:,.2f}), the net saving is "
                    + (f"about USD {net:,.2f}/month." if pays_off else
                       f"negative at this volume: the gateway pays for itself only from about USD {break_even:,.0f}/month "
                       f"of AI spend in the subscription (now USD {eligible_usd:,.0f}). Introduce it for governance "
                       f"reasons, or reuse a shared gateway.")),
                resource_type="microsoft.cognitiveservices/accounts",
                severity=(SeverityLevel.HIGH if usd >= self.HIGH_MONTHLY_USD else SeverityLevel.MEDIUM) if pays_off
                else SeverityLevel.LOW,
                remediation_steps=(
                    "1. Look for a shared platform API Management instance first (incremental cost ~0); otherwise "
                    f"create one {sku} unit for all AI accounts of the workload (Developer tier, about USD "
                    f"{PRICE['apim_developer']:,.0f}/month, is for non-production only - it has no SLA).\n"
                    "2. Import the model endpoints as APIs; authenticate to them with APIM's managed identity and "
                    "disable key access on the accounts.\n"
                    "3. Policies: llm-token-limit per subscription key (app), llm-emit-token-metric with app / user "
                    "dimensions for chargeback, a backend pool with circuit breaker for failover.\n"
                    "4. Semantic cache only where prompts repeat (FAQ bots, classification): it needs Azure Managed "
                    f"Redis (from about USD {PRICE['managed_redis_b1']:,.0f}/month) and an embeddings deployment.\n"
                    "5. Independent of the gateway: route simple calls to smaller models and set a monthly AI budget "
                    "per project."
                ),
                azure_cli_script=(
                    "# Is there a gateway to reuse anywhere in the tenant?\n"
                    "az graph query -q \"Resources | where type =~ 'microsoft.apimanagement/service' "
                    "| project name, subscriptionId, resourceGroup, sku = sku.name\" -o table\n"
                    f"az cognitiveservices account deployment list -g {acc.get('resourceGroup')} -n {acc['name']} -o table\n"
                    "# Only if none can be reused:\n"
                    f"az apim create -g {acc.get('resourceGroup')} -n <apim-name> --publisher-name <team> "
                    f"--publisher-email <team-mail> --sku-name {sku.replace(' v2', 'V2')} --sku-capacity 1"),
                evidence={"cost_30d": acc.get("cost_30d"), "currency": acc.get("currency"), "cost_usd_30d": usd,
                          "deployments": deployments, "provisioned_tpm_k": tpm,
                          "gateway": {"sku": sku, "monthly_usd": gateway_usd, "allocated_usd": gateway_share,
                                      "assumed_reduction": ratio, "gross_saving_usd": gross, "net_saving_usd": net,
                                      "break_even_ai_spend_usd": round(break_even, 2) if break_even else None,
                                      "subscription_ai_spend_usd": round(eligible_usd, 2)},
                          "platform_gateways": platform[:5],
                          "cost_of_change": ({"monthly_usd": 0.0, "basis": f"reuse of the tenant's API Management "
                                                                           f"({reuse})"} if platform else
                                             {"monthly_usd": gateway_share, "included_in_saving": True,
                                              "basis": f"API Management {sku} (USD {gateway_usd:,.2f}/month list) "
                                                       f"shared by spend across {len(eligible)} AI account(s)"})},
                estimated_monthly_savings_usd=max(0.0, net),
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
    """
    Open Advisor reservation / savings-plan recommendations (completed, resolved and dismissed ones are left out),
    one per commitment - recommendation, SKU and region - keeping the best term / look-back variant.
    """

    scanner_name = "commitment_discount_scanner"
    display_name = "Commitment Discount Opportunities"
    description = "Imports open Azure Advisor reserved-instance and savings-plan recommendations"
    category = ScannerCategory.COST
    severity = SeverityLevel.MEDIUM

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = f"""
        advisorresources
        | where type =~ 'microsoft.advisor/recommendations'
        | where subscriptionId == '{context.subscription_id}'
        | where tostring(properties.category) =~ 'Cost'
        {ADVISOR_ACTIVE_FILTER}
        | extend solution = tostring(properties.shortDescription.solution)
        | where solution contains 'reserved' or solution contains 'savings plan' or solution contains 'reservation'
        | project solution, impact = tostring(properties.impact),
                  annual = todouble(properties.extendedProperties.annualSavingsAmount),
                  currency = tostring(properties.extendedProperties.savingsCurrency),
                  term = tostring(properties.extendedProperties.term),
                  sku = tostring(properties.extendedProperties.displaySKU),
                  region = tostring(properties.extendedProperties.region)
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        best: Dict[Any, Dict[str, Any]] = {}
        for r in rows:
            key = (r.get("solution") or "commitment", r.get("sku") or "", r.get("region") or "")
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
                f"{k[0]}{f' ({k[1]}' + (f', {k[2]}' if k[2] else '') + ')' if k[1] else ''} - "
                f"{r.get('annual') or 0:,.0f} {r.get('currency') or ''}/yr" for k, r in best.items())
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


COMMITMENT_SOLUTION = ("solution contains 'reserved' or solution contains 'savings plan' "
                       "or solution contains 'reservation'")


def _json_field(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value) if value else None
    except (TypeError, ValueError):
        return None


@register_scanner
class AdvisorCostScanner(PostureScanner):
    """
    Open Azure Advisor cost recommendations other than commitments (those are commitment_discount_scanner's), one
    finding per resource with Advisor's own saving: Data Explorer table cache policies, VM / App Service plan
    right-sizing, idle resources, Basic logs, ... - often where most of the money is (Data Explorer, Cosmos DB,
    Log Analytics) and ARG has no native analyser. The saving is capped at the resource's own 30-day cost; native
    ARG findings on the same resource take precedence (the report drops the Advisor duplicate).
    """

    scanner_name = "advisor_cost_scanner"
    display_name = "Advisor Cost Recommendations"
    description = "Imports open Azure Advisor cost recommendations (other than commitments) with Advisor's saving"
    category = ScannerCategory.COST
    severity = SeverityLevel.MEDIUM
    finding_types = {"advisor_cost_recommendation"}

    MAX_DETAILS = 25

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = f"""
        advisorresources
        | where type =~ 'microsoft.advisor/recommendations'
        | where subscriptionId == '{context.subscription_id}'
        | where tostring(properties.category) =~ 'Cost'
        {ADVISOR_ACTIVE_FILTER}
        | extend solution = tostring(properties.shortDescription.solution)
        | where not({COMMITMENT_SOLUTION})
        | project resource_id = tostring(properties.resourceMetadata.resourceId),
                  problem = tostring(properties.shortDescription.problem), solution,
                  sub_category = tostring(properties.extendedProperties.recommendationSubCategory),
                  impact = tostring(properties.impact),
                  impacted_type = tolower(tostring(properties.impactedField)),
                  impacted_name = tostring(properties.impactedValue),
                  annual = todouble(properties.extendedProperties.annualSavingsAmount),
                  currency = tostring(properties.extendedProperties.savingsCurrency),
                  message = tostring(properties.extendedProperties.recommendationMessage),
                  current_sku = tostring(properties.extendedProperties.currentSku),
                  target_sku = tostring(properties.extendedProperties.targetSku),
                  database = tostring(properties.extendedProperties.databaseName),
                  detail = tostring(properties.extendedProperties.recommendations)
        """
        try:
            rows = await self.arg(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])
        gone = await missing_resources(context, [r.get("resource_id") for r in rows])
        rows = [r for r in rows if top_level_id(r.get("resource_id")) not in gone]

        by_resource: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            rid = r.get("resource_id") or f"/subscriptions/{context.subscription_id}"
            res = by_resource.setdefault(rid.lower(), {"resource_id": rid, "name": r.get("impacted_name"),
                                                       "type": r.get("impacted_type"), "items": {}})
            item = res["items"].setdefault(r.get("problem") or "Advisor cost recommendation", {
                "problem": r.get("problem"), "solution": r.get("solution"), "sub_category": r.get("sub_category"),
                "impact": r.get("impact"), "annual_usd": 0.0, "other_currency": None, "count": 0, "details": []})
            item["count"] += 1
            annual = r.get("annual") or 0.0
            if (r.get("currency") or "USD").upper() == "USD":
                item["annual_usd"] += annual
            elif annual:
                item["other_currency"] = r.get("currency")
            detail = _json_field(r.get("detail"))
            if isinstance(detail, dict) and detail.get("tableName"):   # Data Explorer cache policy, per table
                text = detail.get("recommendationDescription") or ""
                item["details"].append({"database": r.get("database"), "table": detail.get("tableName"),
                                        "recommended": detail.get("recommendedCachePolicy"),
                                        "current": _between(text, "from ", " to "),
                                        "annual_usd": annual, "link": detail.get("updateCacheDataExplorerLink")})
            elif r.get("message"):
                item["details"].append({"message": r.get("message"), "current_sku": r.get("current_sku") or None,
                                        "target_sku": r.get("target_sku") or None, "annual_usd": annual})

        costs = await get_resource_costs(context) if self.is_live(context) and by_resource else {}
        findings = []
        for res in by_resource.values():
            items = sorted(res["items"].values(), key=lambda i: -i["annual_usd"])
            for i in items:
                i["details"] = sorted(i["details"], key=lambda d: -(d.get("annual_usd") or 0))[:self.MAX_DETAILS]
            advisor_monthly = sum(i["annual_usd"] for i in items) / 12
            entry = cost_for(costs, res["resource_id"]) or {} if costs else {}
            cost_usd = entry.get("cost_usd") if entry else None
            monthly = min(advisor_monthly, cost_usd) if cost_usd is not None else advisor_monthly
            capped = cost_usd is not None and advisor_monthly > cost_usd
            name = res["name"] or res["resource_id"].rsplit("/", 1)[-1]
            first = items[0]
            more = f" (+{len(items) - 1} more)" if len(items) > 1 else ""
            count = f" ({first['count']} tables)" if first["details"] and first["details"][0].get("table") else ""
            severity = (SeverityLevel.HIGH if monthly >= 1000 else SeverityLevel.MEDIUM if monthly >= 100
                        else SeverityLevel.LOW)
            findings.append(self._finding(context, res, name, items, round(monthly, 2), capped, cost_usd,
                                          title=(f"Advisor: {first['problem']}{count}{more} - up to USD "
                                                 f"{monthly:,.0f}/month ({name})" if monthly else
                                                 f"Advisor: {first['problem']}{count}{more} ({name})"),
                                          severity=severity))
        return ScanOutput(findings=findings, resources_scanned=len(rows))

    def _finding(self, context: ScanContext, res: Dict[str, Any], name: str, items: List[Dict[str, Any]],
                 monthly: float, capped: bool, cost_usd: Optional[float], *, title: str, severity: SeverityLevel):
        def describe(i: Dict[str, Any]) -> str:
            text = f"{i['problem']} - Advisor estimates USD {i['annual_usd']:,.0f}/year"
            if i["other_currency"]:
                text += f" (plus amounts in {i['other_currency']})"
            return text + (f" across {i['count']} recommendations" if i["count"] > 1 else "")

        steps = []
        for i in items:
            steps.append(f"{i['solution'] or i['problem']}:")
            for d in i["details"]:
                if d.get("table"):
                    steps.append(f"- {d['database']}.{d['table']}: hot cache {d.get('current') or '?'} → "
                                 f"{d.get('recommended')} (USD {d.get('annual_usd') or 0:,.0f}/year)"
                                 + (f" - {d['link']}" if d.get("link") else ""))
                elif d.get("message"):
                    steps.append(f"- {d['message']} (USD {d.get('annual_usd') or 0:,.0f}/year)")
        if any(d.get("table") for i in items for d in i["details"]):
            steps.append("Data Explorer: confirm with the data owners that queries older than the new hot period can "
                         "run from cold storage (slower), apply the cache policies, then enable optimized autoscale - "
                         "the saving materialises only when the cluster shrinks to the smaller hot cache.")
        cli = None
        tables = [d for i in items for d in i["details"] if d.get("table") and d.get("recommended")]
        if tables:
            cli = ("// Kusto management commands - run them in the Data Explorer web UI against each database\n"
                   + "\n".join(f"// database {d['database']}\n.alter table {d['table']} policy caching hot = "
                               f"{_kusto_timespan(d['recommended'])}" for d in tables[:self.MAX_DETAILS]))
        rid = res["resource_id"]
        parts = rid.split("/")
        lowered = [p.lower() for p in parts]
        rg = parts[lowered.index("resourcegroups") + 1] if "resourcegroups" in lowered else "(subscription)"
        provider_idx = lowered.index("providers") if "providers" in lowered else -1
        rtype = "/".join(lowered[provider_idx + 1:provider_idx + 3]) if provider_idx > 0 else (res["type"] or "")
        return self.make_finding(
            finding_type="advisor_cost_recommendation", title=title,
            description=("Open Azure Advisor cost recommendation(s) on '" + name + "': " + "; ".join(map(describe, items))
                         + "." + (f" Capped at the resource's own 30-day cost (USD {cost_usd:,.2f})." if capped else "")),
            resource_id=rid, resource_name=name, resource_type=rtype, resource_group=rg,
            subscription_id=context.subscription_id, severity=severity,
            remediation_steps="\n".join(steps), azure_cli_script=cli,
            evidence={"advisor": items, "advisor_monthly_usd": round(sum(i["annual_usd"] for i in items) / 12, 2),
                      "capped_at_cost_usd_30d": cost_usd if capped else None},
            estimated_monthly_savings_usd=monthly, caf_control="Cost Optimization",
        )

    def _mock_data(self) -> List[Dict[str, Any]]:
        adx = "/subscriptions/sub-1/resourcegroups/rg-data/providers/microsoft.kusto/clusters/adx-prod-1"
        table = ('{"tableName":"Telemetry","recommendedCachePolicy":"4 Day(s)","updateCacheDataExplorerLink":'
                 '"https://dataexplorer.azure.com/clusters/adx-prod-1.westeurope/databases/db1?query=.alter",'
                 '"recommendationDescription":"Reduce the cache period for table: Telemetry (in database: db1) '
                 'from 100 days to 4 days."}')
        return [
            {"resource_id": adx, "problem": "Reduce Data Explorer table cache policy to optimize costs",
             "solution": "Reduce Data Explorer table cache policy to optimize costs", "sub_category": "Other",
             "impact": "Medium", "impacted_type": "microsoft.kusto/clusters", "impacted_name": "adx-prod-1",
             "annual": 4800.0, "currency": "USD", "database": "db1", "detail": table},
            {"resource_id": adx, "problem": "Reduce Data Explorer table cache policy to optimize costs",
             "solution": "Reduce Data Explorer table cache policy to optimize costs", "sub_category": "Other",
             "impact": "Medium", "impacted_type": "microsoft.kusto/clusters", "impacted_name": "adx-prod-1",
             "annual": 1200.0, "currency": "USD", "database": "db1",
             "detail": table.replace("Telemetry", "Events").replace("100 days", "30 days")},
        ]


def _between(text: str, start: str, end: str) -> Optional[str]:
    i = text.find(start)
    j = text.find(end, i + len(start)) if i >= 0 else -1
    return text[i + len(start):j].strip() if i >= 0 and j > i else None


def _kusto_timespan(policy: str) -> str:
    """'4 Day(s)' -> '4d' (Kusto timespan literal); anything else is passed through."""
    parts = (policy or "").split()
    if len(parts) == 2 and parts[0].isdigit():
        unit = parts[1].lower()
        if unit.startswith("day"):
            return f"{parts[0]}d"
        if unit.startswith("hour"):
            return f"{parts[0]}h"
    return policy


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

