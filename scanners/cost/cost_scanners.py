"""
Azure Resource Guardian - Cost Scanners
========================================
Scanners in this module:
1. IdleIoTHubScanner              — IoT Hubs with no connected devices and no messages
2. AISpendGovernanceScanner       — Foundry / Azure OpenAI spend with no gateway; AI account sprawl
3. CommitmentDiscountScanner      — Advisor reservation / savings-plan opportunities
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from typing import Any, Dict, List

from scanners.base.azure_api import cached_metrics, cost_for, get_resource_costs
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.posture_scanner import PostureScanner

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
            for hub in hubs:
                try:
                    m = await cached_metrics(context, hub["id"],
                                             ["devices.connectedDevices.allProtocol", "dailyMessageQuotaUsed"],
                                             aggregation="Maximum")
                    hub["max_connected"] = (m.get("devices.connectedDevices.allProtocol") or {}).get("maximum") or 0.0
                    hub["max_daily_messages"] = (m.get("dailyMessageQuotaUsed") or {}).get("maximum") or 0.0
                except Exception as exc:
                    warnings.append(f"Metrics unavailable for {hub['name']}: {exc}")

        findings = []
        for hub in hubs:
            if hub.get("max_connected") != 0 or hub.get("max_daily_messages") != 0:
                continue
            sku, units = hub.get("sku_name") or "S1", hub.get("units") or 1
            saving = IOT_HUB_UNIT_USD.get(sku, 0.0) * units
            findings.append(self.resource_finding(
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
            ))
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
            for acc in accounts:
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
                f"{k} — {r.get('annual') or 0:,.0f} {r.get('currency') or ''}/yr" for k, r in best.items())
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
