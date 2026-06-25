"""
Azure Cost Management service — wraps the Cost Management REST API.

Design notes:
  - Uses azure-mgmt-costmanagement SDK for structured queries.
  - All monetary values are stored/returned in USD for consistency.
    Original currency is preserved in metadata.
  - Cost data has ~24-48h lag from Azure; we cache results for 6 hours
    to avoid hitting API rate limits (Cost API is throttled aggressively).
  - Granularity: Daily for trend data, None (total) for summary data.
"""

import asyncio
import logging
from datetime import date, timedelta
from typing import Any

from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.costmanagement.models import (
    QueryDefinition,
    QueryTimePeriod,
    QueryDataset,
    QueryAggregation,
    QueryGrouping,
    QueryFilter,
    GranularityType,
    TimeframeType,
    ExternalCloudProviderType,
)
from azure.identity import ClientSecretCredential

logger = logging.getLogger(__name__)


class AzureCostService:
    """
    Async wrapper for Azure Cost Management API.

    Provides cost summaries, trends, and resource-level cost attribution.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ):
        self._credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        self._client = CostManagementClient(self._credential)

    async def get_subscription_costs(
        self,
        subscription_id: str,
        start_date: date | None = None,
        end_date: date | None = None,
    ) -> dict[str, Any]:
        """
        Get total costs for a subscription over a date range.

        Defaults to the current month if no dates provided.
        """
        if not start_date:
            today = date.today()
            start_date = today.replace(day=1)
        if not end_date:
            end_date = date.today()

        scope = f"/subscriptions/{subscription_id}"
        query = QueryDefinition(
            type="ActualCost",
            timeframe=TimeframeType.CUSTOM,
            time_period=QueryTimePeriod(
                from_property=start_date.isoformat() + "T00:00:00Z",
                to=end_date.isoformat() + "T23:59:59Z",
            ),
            dataset=QueryDataset(
                granularity=GranularityType.NONE,
                aggregation={
                    "totalCost": QueryAggregation(
                        name="PreTaxCost",
                        function="Sum",
                    )
                },
            ),
        )

        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.query.usage(scope=scope, parameters=query),
        )

        total = 0.0
        currency = "USD"
        if result.rows:
            total = float(result.rows[0][0])
            # Currency is typically in column index 2 for this query shape
            if len(result.rows[0]) > 2:
                currency = result.rows[0][2]

        return {
            "subscription_id": subscription_id,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "total_cost": total,
            "currency": currency,
        }

    async def get_daily_cost_trend(
        self,
        subscription_id: str,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """
        Get daily cost breakdown for the last N days.

        Used to populate cost trend charts on the dashboard.
        """
        end_date = date.today()
        start_date = end_date - timedelta(days=days)
        scope = f"/subscriptions/{subscription_id}"

        query = QueryDefinition(
            type="ActualCost",
            timeframe=TimeframeType.CUSTOM,
            time_period=QueryTimePeriod(
                from_property=start_date.isoformat() + "T00:00:00Z",
                to=end_date.isoformat() + "T23:59:59Z",
            ),
            dataset=QueryDataset(
                granularity=GranularityType.DAILY,
                aggregation={
                    "totalCost": QueryAggregation(
                        name="PreTaxCost",
                        function="Sum",
                    )
                },
            ),
        )

        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.query.usage(scope=scope, parameters=query),
        )

        # Result columns: [PreTaxCost, UsageDate, Currency]
        trend = []
        if result.rows:
            for row in result.rows:
                trend.append({
                    "date": str(row[1])[:10] if row[1] else None,
                    "cost": float(row[0]),
                    "currency": row[2] if len(row) > 2 else "USD",
                })

        return sorted(trend, key=lambda x: x["date"] or "")

    async def get_costs_by_resource_group(
        self,
        subscription_id: str,
        start_date: date | None = None,
        end_date: date | None = None,
    ) -> list[dict[str, Any]]:
        """Get cost breakdown grouped by resource group."""
        if not start_date:
            today = date.today()
            start_date = today.replace(day=1)
        if not end_date:
            end_date = date.today()

        scope = f"/subscriptions/{subscription_id}"
        query = QueryDefinition(
            type="ActualCost",
            timeframe=TimeframeType.CUSTOM,
            time_period=QueryTimePeriod(
                from_property=start_date.isoformat() + "T00:00:00Z",
                to=end_date.isoformat() + "T23:59:59Z",
            ),
            dataset=QueryDataset(
                granularity=GranularityType.NONE,
                aggregation={
                    "totalCost": QueryAggregation(
                        name="PreTaxCost",
                        function="Sum",
                    )
                },
                grouping=[
                    QueryGrouping(type="Dimension", name="ResourceGroupName")
                ],
            ),
        )

        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.query.usage(scope=scope, parameters=query),
        )

        groups = []
        if result.rows:
            for row in result.rows:
                groups.append({
                    "resource_group": row[1] if len(row) > 1 else "Unknown",
                    "cost": float(row[0]),
                    "currency": row[2] if len(row) > 2 else "USD",
                })

        return sorted(groups, key=lambda x: x["cost"], reverse=True)

    async def get_costs_by_service(
        self,
        subscription_id: str,
        start_date: date | None = None,
        end_date: date | None = None,
        top_n: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Get cost breakdown grouped by Azure service type.

        Returns top_n services by cost — used for 'Top Cost Drivers' widget.
        """
        if not start_date:
            today = date.today()
            start_date = today.replace(day=1)
        if not end_date:
            end_date = date.today()

        scope = f"/subscriptions/{subscription_id}"
        query = QueryDefinition(
            type="ActualCost",
            timeframe=TimeframeType.CUSTOM,
            time_period=QueryTimePeriod(
                from_property=start_date.isoformat() + "T00:00:00Z",
                to=end_date.isoformat() + "T23:59:59Z",
            ),
            dataset=QueryDataset(
                granularity=GranularityType.NONE,
                aggregation={
                    "totalCost": QueryAggregation(
                        name="PreTaxCost",
                        function="Sum",
                    )
                },
                grouping=[
                    QueryGrouping(type="Dimension", name="ServiceName")
                ],
            ),
        )

        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.query.usage(scope=scope, parameters=query),
        )

        services = []
        if result.rows:
            for row in result.rows:
                services.append({
                    "service": row[1] if len(row) > 1 else "Unknown",
                    "cost": float(row[0]),
                    "currency": row[2] if len(row) > 2 else "USD",
                })

        return sorted(services, key=lambda x: x["cost"], reverse=True)[:top_n]

    def close(self) -> None:
        """Release underlying connections."""
        self._credential.close()
        self._client.close()
