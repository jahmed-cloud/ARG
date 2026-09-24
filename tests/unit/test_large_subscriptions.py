"""
Regression tests for result-size caps on large subscriptions:
- every scanner's Resource Graph query follows skip tokens (no 100/1000-row cap);
- the report inventory comes from paginated Resource Graph, with creation
  dates merged from ARM per resource group.
"""

import asyncio
from types import SimpleNamespace

import scanners.compute.compute_scanners  # noqa: F401
import scanners.governance.governance_scanners  # noqa: F401
import scanners.network.network_scanners  # noqa: F401
import scanners.security.security_scanners  # noqa: F401
import scanners.storage.storage_scanners  # noqa: F401
from scanners.base.azure_api import query_resource_graph
from scanners.base.base_scanner import ScanContext, ScannerRegistry
from scripts.subscription_analysis.collector import AnalysisData, collect_inventory


class PagedGraphClient:
    """Mimics ResourceGraphClient.resources(): serves `rows` in pages linked by skip tokens."""

    def __init__(self, rows, page_size=1000):
        self.rows, self.page_size, self.calls = rows, page_size, 0

    def resources(self, request):
        self.calls += 1
        start = int(request.options.skip_token or 0)
        end = start + self.page_size
        return SimpleNamespace(data=self.rows[start:end], skip_token=str(end) if end < len(self.rows) else None)


def _untagged(n):
    return [{"id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/app{i}", "name": f"app{i}",
             "type": "microsoft.web/sites", "resourceGroup": "rg", "subscriptionId": "s", "location": "westeurope",
             "tags": None} for i in range(n)]


def test_query_resource_graph_follows_skip_tokens():
    client = PagedGraphClient(_untagged(2500))
    ctx = ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j", resource_graph_client=client)
    rows = asyncio.run(query_resource_graph(ctx, "Resources"))
    assert len(rows) == 2500 and client.calls == 3


def test_legacy_scanner_is_no_longer_capped_at_1000():
    client = PagedGraphClient(_untagged(1500))
    ctx = ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j", resource_graph_client=client)
    scanner = ScannerRegistry.get("missing_required_tags_scanner")(config={"required_tags": ["owner"]})
    output = asyncio.run(scanner.execute(ctx))
    assert output.finding_count == 1500


class FakeArm:
    def __init__(self, groups, times):
        self.groups, self.times, self.paths = groups, times, []

    async def get_all(self, path, api_version, params=None):
        self.paths.append(path)
        if path.endswith("/resourcegroups"):
            return self.groups
        rg = path.split("/resourceGroups/")[1].split("/")[0]
        return self.times.get(rg, [])


def test_inventory_uses_resource_graph_and_merges_created_time():
    rows = _untagged(2300)
    client = PagedGraphClient(rows)
    ctx = ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j", resource_graph_client=client)
    arm = FakeArm([{"name": "rg"}], {"rg": [{"id": rows[5]["id"].upper(), "createdTime": "2019-01-01T00:00:00Z"}]})
    data = AnalysisData(subscription={"id": "s", "name": "s"}, generated_at=None)
    asyncio.run(collect_inventory(ctx, arm, data))
    assert len(data.resources) == 2300
    assert data.resources[5]["createdTime"] == "2019-01-01T00:00:00Z"
    assert data.resources[6]["createdTime"] is None
    assert not any(p.endswith("/resources") and "/resourceGroups/" not in p for p in arm.paths)
