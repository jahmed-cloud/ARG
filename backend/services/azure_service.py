"""
Azure Resource Graph service — thin async wrapper around the ARG REST API.

Why Azure Resource Graph vs iterating Management APIs?
  - ARG can query millions of resources across hundreds of subscriptions
    in a single KQL query, typically in < 5 seconds.
  - Direct Management API calls require per-resource-type iteration,
    throttle at ~12,000 req/hr per subscription, and can't do cross-
    subscription joins.
  - ARG results are eventually consistent (typically < 60s lag after a
    resource change), which is acceptable for governance scanning.

KQL (Kusto Query Language) is used for all queries. ARG supports a
subset of KQL — no time series functions, but full join/project/extend/
where/summarize/order support.
"""

import asyncio
import logging
from typing import Any, AsyncIterator

from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import (
    QueryRequest,
    QueryRequestOptions,
    ResultFormat,
)
from azure.identity import ClientSecretCredential

logger = logging.getLogger(__name__)

# ARG returns max 1000 rows per page; for large environments we paginate.
_PAGE_SIZE = 1000


class AzureResourceGraphService:
    """
    Async wrapper around Azure Resource Graph queries.

    Instantiate per-tenant using the tenant's decrypted credentials.
    The underlying SDK client is synchronous; we run it in a thread pool
    to avoid blocking the event loop.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_ids: list[str],
    ):
        self.tenant_id = tenant_id
        self.subscription_ids = subscription_ids
        self._credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        self._arg_client = ResourceGraphClient(self._credential)

    async def query(
        self,
        kql: str,
        subscriptions: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a KQL query against Azure Resource Graph.

        Automatically paginates to retrieve all results.
        Runs the synchronous SDK call in a thread pool executor.

        Args:
            kql: Kusto query string.
            subscriptions: Override which subscriptions to query.
                           Defaults to all tenant subscriptions.

        Returns:
            List of result rows as dicts.
        """
        subs = subscriptions or self.subscription_ids
        results: list[dict[str, Any]] = []
        skip_token: str | None = None

        while True:
            request = QueryRequest(
                subscriptions=subs,
                query=kql,
                options=QueryRequestOptions(
                    result_format=ResultFormat.OBJECT_ARRAY,
                    top=_PAGE_SIZE,
                    skip_token=skip_token,
                ),
            )
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda req=request: self._arg_client.resources(req),
            )

            if response.data:
                results.extend(response.data)

            skip_token = getattr(response, "skip_token", None)
            if not skip_token:
                break

        logger.debug(
            "ARG query returned %d rows across %d subscriptions",
            len(results),
            len(subs),
        )
        return results

    async def query_stream(
        self,
        kql: str,
        subscriptions: list[str] | None = None,
        batch_size: int = _PAGE_SIZE,
    ) -> AsyncIterator[list[dict[str, Any]]]:
        """
        Stream ARG query results page-by-page.

        Useful for large result sets where you want to start processing
        before all pages have been fetched.
        """
        subs = subscriptions or self.subscription_ids
        skip_token: str | None = None

        while True:
            request = QueryRequest(
                subscriptions=subs,
                query=kql,
                options=QueryRequestOptions(
                    result_format=ResultFormat.OBJECT_ARRAY,
                    top=batch_size,
                    skip_token=skip_token,
                ),
            )
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda req=request: self._arg_client.resources(req),
            )

            if response.data:
                yield response.data

            skip_token = getattr(response, "skip_token", None)
            if not skip_token:
                break

    async def get_all_resources(
        self,
        subscription_ids: list[str] | None = None,
        resource_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve complete resource inventory for given subscriptions.

        Optionally filter to specific resource types (e.g. 'microsoft.compute/disks').
        """
        type_filter = ""
        if resource_types:
            types_str = ", ".join(f"'{t.lower()}'" for t in resource_types)
            type_filter = f"| where type in~ ({types_str})"

        kql = f"""
        Resources
        {type_filter}
        | project
            id,
            name,
            type,
            location,
            resourceGroup,
            subscriptionId,
            tenantId,
            tags,
            sku,
            kind,
            properties,
            identity,
            zones,
            managedBy
        | order by type asc, name asc
        """
        return await self.query(kql, subscriptions=subscription_ids)

    async def get_resource_by_id(self, resource_id: str) -> dict[str, Any] | None:
        """Fetch a single resource by its full Azure resource ID."""
        kql = f"""
        Resources
        | where id =~ '{resource_id}'
        | limit 1
        """
        results = await self.query(kql)
        return results[0] if results else None

    async def count_resources_by_type(
        self,
        subscription_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Aggregate resource counts by type — used for dashboard metrics."""
        kql = """
        Resources
        | summarize count=count() by type
        | order by count desc
        """
        return await self.query(kql, subscriptions=subscription_ids)

    async def get_resources_without_tags(
        self,
        required_tags: list[str],
        subscription_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Find resources missing any of the specified required tags."""
        # Build KQL filter: resource has no tags OR is missing any required tag
        tag_checks = " or ".join(
            f"isnull(tags['{tag}'])" for tag in required_tags
        )
        kql = f"""
        Resources
        | where isnull(tags) or {tag_checks}
        | project id, name, type, resourceGroup, subscriptionId, tags, location
        | order by type asc
        """
        return await self.query(kql, subscriptions=subscription_ids)

    def close(self) -> None:
        """Release underlying HTTP connections."""
        self._credential.close()
        self._arg_client.close()
