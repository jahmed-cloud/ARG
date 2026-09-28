"""
Idle / dormant storage detection (unused_storage_account_scanner), DR replicas in the SQL idle check, and the AI /
spend sections of the deep dives.

Regression for accounts reported as "idle, delete" although they served real reads (static website, GetBlob,
PutBlob hidden under the old 200-transaction threshold) or held terabytes of kept data.
"""

import asyncio
from types import SimpleNamespace

import scanners.storage.storage_scanners  # noqa: F401
from scanners.base.azure_api import storage_data_operations, totals_by_dimension
from scanners.base.base_scanner import ScanContext, ScannerRegistry

GB = 1024 ** 3
HOUSEKEEPING = {"GetBlobServiceProperties": 74.0, "ListContainers": 45.0, "Unknown": 10.0}


def _sa(name, sku="Standard_LRS", kind="StorageV2"):
    return {"id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}",
            "name": name, "resourceGroup": "rg", "subscriptionId": "s", "location": "westeurope", "tags": {},
            "kind": kind, "sku_name": sku, "allow_blob_public_access": False, "access_tier": "Hot"}


class Graph:
    """Resource Graph fake: storage accounts for the account query, VM rows for the VM-reference query."""

    def __init__(self, accounts, vms=()):
        self.accounts, self.vms = accounts, list(vms)

    def resources(self, request):
        rows = self.vms if "virtualmachines" in request.query else self.accounts
        return SimpleNamespace(data=rows, skip_token=None)


class Arm:
    def __init__(self, by_api, used_gb, cost_usd=None, split_fails=False):
        self.by_api, self.used_gb, self.cost_usd, self.split_fails = by_api, used_gb, cost_usd or {}, split_fails

    async def metrics_summary(self, resource_id, names, **kwargs):
        name = resource_id.rsplit("/", 1)[-1]
        if names == ["Transactions"]:
            return {"Transactions": {"total": sum(self.by_api.get(name, {}).values())}}
        return {"UsedCapacity": {"latest_average": self.used_gb.get(name, 0.0) * GB}}

    async def metric_totals_by(self, resource_id, metric, dimension, days=30):
        if self.split_fails:
            raise RuntimeError("400 dimension not supported")
        return self.by_api.get(resource_id.rsplit("/", 1)[-1], {})

    async def cost_query(self, scope, body):
        return [{"ResourceId": _sa(n)["id"], "MeterSubCategory": "Blob", "Cost": c, "CostUSD": c, "Currency": "USD"}
                for n, c in self.cost_usd.items()]


def _scan(accounts, arm, vms=(), config=None):
    ctx = ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j",
                      resource_graph_client=Graph(accounts, vms), arm_client=arm,
                      cost_management_client=arm)
    scanner = ScannerRegistry.get("unused_storage_account_scanner")(config=config or {})
    return {f.resource_name: f for f in asyncio.run(scanner.execute(ctx)).findings}


def test_housekeeping_is_not_data_traffic():
    assert storage_data_operations(HOUSEKEEPING) == 0
    assert storage_data_operations(dict(HOUSEKEEPING, GetBlob=41.0, PutBlob=1.0)) == 42.0
    # a few anonymous probes are background; a client hammering the account (classic diagnostics) is not
    assert storage_data_operations(dict(HOUSEKEEPING, Unknown=764256.0)) == 764206.0
    values = [{"timeseries": [{"metadatavalues": [{"name": {"value": "apiname"}, "value": "GetBlob"}],
                               "data": [{"total": 3.0}, {"total": None}, {"total": 2.0}]}]}]
    assert totals_by_dimension(values) == {"GetBlob": 5.0}


def test_real_reads_under_the_old_threshold_are_not_idle():
    arm = Arm({"website": dict(HOUSEKEEPING, GetWebContent=30.0, GetWebContentProperties=41.0),
               "writer": dict(HOUSEKEEPING, PutBlob=31.0, ListBlobs=31.0),
               "empty": HOUSEKEEPING},
              {"website": 0.01, "writer": 1.4, "empty": 0.0}, {"empty": 2.0})
    found = _scan([_sa("website"), _sa("writer"), _sa("empty")], arm)
    assert set(found) == {"empty"}                                      # 71 / 62 real ops kept them out
    idle = found["empty"]
    assert idle.finding_type == "unused_storage_account" and idle.estimated_monthly_savings_usd == 2.0
    assert "no data reads or writes" in idle.description and idle.evidence["data_operations_30d"] == 0


def test_idle_account_holding_data_is_dormant_not_deletable():
    arm = Arm({"archive": HOUSEKEEPING, "vhds": {"GetBlobServiceProperties": 44.0, "ListContainers": 43.0,
                                                 "ListBlobs": 1.0}},                  # one portal browse
              {"archive": 3180.7, "vhds": 34.63}, {"archive": 96.0, "vhds": 363.0})
    found = _scan([_sa("archive", "Standard_RAGRS"), _sa("vhds", "Premium_LRS", "Storage")], arm)
    archive, vhds = found["archive"], found["vhds"]
    assert archive.finding_type == vhds.finding_type == "dormant_storage_data"
    assert archive.title.startswith("Dormant data: archive (3,180.7 GB")
    assert "delete" not in archive.azure_cli_script and "management-policy" in archive.azure_cli_script
    assert archive.estimated_monthly_savings_usd == round(96.0 - 3180.7 * 0.0045 * 2, 2)   # vs Cold tier, RA-GRS
    assert archive.severity.value == "low" and vhds.severity.value == "medium"
    assert "billed on provisioned size" in vhds.description
    assert vhds.title == "Dormant data: vhds (34.6 GB, 1 data operation in 30 days)"
    assert "the other 87 transactions are platform housekeeping" in vhds.description


def test_vm_references_skip_vhd_accounts_and_flag_boot_diagnostics():
    vms = [{"name": "legacy-vm", "osVhd": "https://vhdstore.blob.core.windows.net/vhds/os.vhd", "dataVhd": "",
            "bootDiag": "https://diagstore.blob.core.windows.net/"}]
    arm = Arm({"vhdstore": HOUSEKEEPING, "diagstore": HOUSEKEEPING}, {})
    found = _scan([_sa("vhdstore"), _sa("diagstore")], arm, vms)
    assert set(found) == {"diagstore"}
    assert found["diagstore"].evidence["boot_diagnostics_for"] == ["legacy-vm"]
    assert "managed boot diagnostics" in found["diagstore"].description


def test_total_threshold_is_the_fallback_without_the_api_split():
    arm = Arm({"quiet": HOUSEKEEPING, "busy": dict(HOUSEKEEPING, GetBlob=500.0)}, {}, split_fails=True)
    found = _scan([_sa("quiet"), _sa("busy")], arm)
    assert set(found) == {"quiet"}
    assert "data_operations_30d" not in found["quiet"].evidence


def test_geo_secondary_database_is_not_idle():
    import scanners.database.database_scanners  # noqa: F401

    ctx = ScanContext(subscription_id="s", tenant_id="t", scan_job_id="j")
    out = asyncio.run(ScannerRegistry.get("sql_database_utilization_scanner")(config={}).execute(ctx))
    idle = {f.resource_name for f in out.findings if f.finding_type == "idle_sql_database"}
    assert idle == {"sql-app-1/db-analysis"}                           # the Geo replica of it is DR, not waste


# ---------------------------------------------------------------------------
# Estate: the same rule on the metrics batch API
# ---------------------------------------------------------------------------

def test_estate_storage_idle_uses_data_operations(monkeypatch):
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

    def fetch(token, sub, region, namespace, names, ids, start, end):
        values = [{"name": {"value": "Transactions"}, "timeseries": [{"data": [{"total": 150.0}]}]}]
        return {rid.lower(): estate._summarize(values) for rid in ids}

    split = {"/quiet": HOUSEKEEPING, "/site": dict(HOUSEKEEPING, GetWebContent=21.0)}

    def fetch_split(token, sub, region, namespace, metric, dimension, ids, start, end):
        assert (metric, dimension) == ("Transactions", "ApiName")
        return {rid.lower(): split[rid] for rid in ids}

    monkeypatch.setattr(azure_api, "ArmClient", FakeArm)
    rows = [{"id": rid, "type": "microsoft.storage/storageaccounts", "location": "westeurope", "subscriptionId": "s"}
            for rid in split]
    asyncio.run(estate.collect_usage(Cred(), rows, fetch=fetch, fetch_split=fetch_split))
    quiet, site = rows
    assert quiet["activity"] == 0 and estate.is_idle(quiet)
    assert site["activity"] == 21.0 and not estate.is_idle(site)       # 150 total used to be "idle" (<= 200)
    assert estate.usage_of(site) == "21 data operations (of 150 transactions)"


# ---------------------------------------------------------------------------
# Report: AI accounts / deployments / spend and per-area spend
# ---------------------------------------------------------------------------

def test_ai_deep_dive_shows_accounts_deployments_and_spend():
    from scripts.subscription_analysis.collector import AnalysisData
    from scripts.subscription_analysis.report import Model, render_deep_dives

    oai = "/subscriptions/s/resourceGroups/openai/providers/Microsoft.CognitiveServices/accounts/research"
    gone = "/subscriptions/s/resourceGroups/openai/providers/Microsoft.CognitiveServices/accounts/deleted"
    sa = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/data"
    data = AnalysisData(
        subscription={"id": "s", "name": "sub"}, generated_at=None,
        resources=[{"id": oai, "name": "research", "type": "microsoft.cognitiveservices/accounts",
                    "kind": "OpenAI", "sku": {"name": "S0"}, "location": "swedencentral"},
                   {"id": sa, "name": "data", "type": "microsoft.storage/storageaccounts"}],
        cost={"currency": "CHF", "usd_to_billing": 0.8, "last30_by_resource": {
            oai.lower(): {"cost": 74.21, "meters": {"Azure OpenAI GPT5": 59.12, "Azure OpenAI": 15.09}},
            gone.lower(): {"cost": 3.5, "meters": {"Azure OpenAI": 3.5}},
            sa.lower(): {"cost": 12.0, "meters": {"Blob": 12.0}}}},
        ai_deployments={oai.lower(): [{"name": "gpt-5", "model": "gpt-5", "sku": "GlobalStandard", "capacity": 250}]},
    )
    pages = render_deep_dives(Model(data))
    ai = pages["ai-foundry"]
    assert "## AI accounts, deployments and spend (1)" in ai and "AI spend in scope: **77.71 CHF**" in ai
    assert "| research | openai | OpenAI | S0 | swedencentral | 74.21 | Azure OpenAI GPT5 59.12" in ai
    assert "gpt-5 GlobalStandard x250" in ai and "deleted within the window" in ai
    assert "## Spend in scope (last 30 days)" in pages["data-sql-storage"] and "12.00" in pages["data-sql-storage"]
    assert "No findings in this area." in ai
