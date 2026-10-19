"""
Resource Graph returns computed booleans (tobool, isnotnull, ...) as 1 / 0. These tests feed scanners rows shaped
exactly like the live API - the mock data elsewhere uses Python True / False and never exposed the difference.
"""

import asyncio
import copy
from types import SimpleNamespace

import scanners.compute.compute_posture_scanners  # noqa: F401
import scanners.database.database_scanners  # noqa: F401
import scanners.security.security_posture_scanners  # noqa: F401
import scanners.storage.storage_posture_scanners  # noqa: F401
from scanners.base.azure_api import bool_columns, normalise_bools, query_resource_graph
from scanners.base.base_scanner import ScanContext, ScannerRegistry
from scripts.subscription_analysis import network


class _Graph:
    """Resource Graph stand-in: returns the rows of the first marker found in the query."""

    def __init__(self, rows_by_marker):
        self.rows_by_marker = rows_by_marker

    def resources(self, request):
        for marker, rows in self.rows_by_marker.items():
            if marker in request.query.lower():
                return SimpleNamespace(data=copy.deepcopy(rows), skip_token=None)
        return SimpleNamespace(data=[], skip_token=None)


def _row(rid, **values):
    name = rid.rsplit("/", 1)[-1]
    return {"id": f"/subscriptions/sub-1/resourceGroups/rg/providers/{rid}", "name": name, "type": rid.rsplit("/", 1)[0],
            "resourceGroup": "rg", "subscriptionId": "sub-1", "location": "westeurope", "tags": {}, **values}


def _types(scanner_name, rows_by_marker):
    context = ScanContext(subscription_id="sub-1", tenant_id="tenant-1", scan_job_id="job-1")
    context.resource_graph_client = _Graph(rows_by_marker)
    output = asyncio.run(ScannerRegistry.get(scanner_name)(config={}).execute(context))
    return {(f.finding_type, f.resource_name) for f in output.findings}


def test_bool_columns_found_in_projections():
    query = """| project id, rbac = tobool(properties.enableRbacAuthorization), n = array_length(properties.x),
               has_ip = isnotnull(properties.ip), name_set=isnotempty(name), s = tostring(properties.state)"""
    assert bool_columns(query) == {"rbac", "has_ip", "name_set"}


def test_normalise_bools_keeps_counts_and_nulls():
    rows = normalise_bools("| project a = tobool(x), b = tobool(y), c = tobool(z), n = toint(w)",
                           [{"a": 1, "b": 0, "c": None, "n": 0}])
    assert rows == [{"a": True, "b": False, "c": None, "n": 0}]
    assert rows[0]["a"] is True and rows[0]["b"] is False


def test_query_resource_graph_returns_real_booleans():
    context = SimpleNamespace(subscription_id="sub-1",
                              resource_graph_client=_Graph({"storage": [{"shared_key": 0, "pe_count": 0}]}))
    rows = asyncio.run(query_resource_graph(
        context, "Resources | where type =~ 'microsoft.storage/storageaccounts' "
                 "| project shared_key = tobool(properties.allowSharedKeyAccess), "
                 "pe_count = array_length(properties.privateEndpointConnections)"))
    assert rows == [{"shared_key": False, "pe_count": 0}]
    assert rows[0]["shared_key"] is False


def test_storage_shared_key_disabled_is_not_flagged():
    closed = {"public_network": "Disabled", "default_action": "Deny", "pe_count": 0, "kind": "StorageV2"}
    found = _types("storage_access_hardening_scanner", {"microsoft.storage/storageaccounts": [
        _row("Microsoft.Storage/storageAccounts/stkeyoff", shared_key=0, **closed),
        _row("Microsoft.Storage/storageAccounts/stkeyon", shared_key=1, **closed),
        _row("Microsoft.Storage/storageAccounts/stdefault", shared_key=None, **closed),
    ]})
    shared = {name for t, name in found if t == "storage_shared_key_access_enabled"}
    assert shared == {"stkeyon", "stdefault"}   # not set = Azure's default, which allows shared keys


def test_key_vault_rbac_and_purge_protection_on_are_not_flagged():
    closed = {"public_network": "Disabled", "default_action": "Deny", "pe_count": 0}
    found = _types("key_vault_hardening_scanner", {"microsoft.keyvault/vaults": [
        _row("Microsoft.KeyVault/vaults/kv-good", rbac=1, soft_delete=1, purge_protection=1, **closed),
        _row("Microsoft.KeyVault/vaults/kv-bad", rbac=0, soft_delete=0, purge_protection=0, **closed),
    ]})
    assert {name for _, name in found} == {"kv-bad"}
    assert {t for t, _ in found} == {"key_vault_access_policy_model", "key_vault_soft_delete_disabled",
                                     "key_vault_purge_protection_disabled"}


def test_ai_services_local_auth_disabled_is_not_flagged():
    closed = {"public_network": "Disabled", "default_action": "Deny", "pe_count": 0, "kind": "OpenAI"}
    found = _types("ai_services_hardening_scanner", {"microsoft.cognitiveservices/accounts": [
        _row("Microsoft.CognitiveServices/accounts/ai-entra", local_auth_disabled=1, **closed),
        _row("Microsoft.CognitiveServices/accounts/ai-keys", local_auth_disabled=0, **closed),
    ]})
    assert {name for t, name in found if t == "ai_services_local_auth_enabled"} == {"ai-keys"}


def test_sql_entra_only_on_is_not_flagged():
    admin = {"admin_login": "grp-dba", "admin_type": "Group"}
    found = _types("sql_entra_auth_scanner", {"microsoft.sql/servers": [
        _row("Microsoft.Sql/servers/sql-entra", entra_only=1, **admin),
        _row("Microsoft.Sql/servers/sql-mixed", entra_only=0, **admin),
    ]})
    assert {name for t, name in found if t == "sql_entra_only_auth_disabled"} == {"sql-mixed"}


def test_web_app_http_allowed_is_flagged():
    site = {"kind": "app", "state": "Running", "plan_id": "", "identity_type": "SystemAssigned", "host_names": []}
    found = _types("web_app_https_identity_scanner", {"microsoft.web/sites": [
        _row("Microsoft.Web/sites/app-http", https_only=0, **site),
        _row("Microsoft.Web/sites/app-https", https_only=1, **site),
    ]})
    assert {name for t, name in found if t == "web_app_https_not_enforced"} == {"app-http"}


def test_cosmos_vnet_rules_without_filter_are_open_in_old_and_new_snapshots():
    cosmos = {"type": "microsoft.documentdb/databaseaccounts", "public": "Enabled", "acl": "", "ip_rules": 0,
              "vnet_rules": 2, "pe": 0}
    for off in (0, False):
        assert network.exposure({**cosmos, "vnet_filter": off}) == network.OPEN
    for on in (1, True, None):
        assert network.exposure({**cosmos, "vnet_filter": on}) == network.RESTRICTED
