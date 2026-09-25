"""
Tests for the estate inventory: normalisation (category, type, size/SKU, OS, state, environment), the join with
the per-subscription reports, the compact wire format and the markdown overview. No Azure calls.
"""

import json

import pytest

from scanners.base.naming import env_from_name, env_from_tags
from scripts.subscription_analysis.estate import (
    ESTATE_DIR,
    ESTATE_FILE,
    build_estate,
    category_of,
    compact,
    config_of,
    os_of,
    refresh_estate,
    size_of,
    state_of,
    type_label,
)

SUB_A = "aaaaaaaa-1111-2222-3333-444444444444"
SUB_B = "bbbbbbbb-1111-2222-3333-444444444444"
VM = f"/subscriptions/{SUB_A}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-app-prod-1"
DISK = f"/subscriptions/{SUB_A}/resourceGroups/rg-app/providers/Microsoft.Compute/disks/disk-old"
STORAGE = f"/subscriptions/{SUB_B}/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdata"


@pytest.mark.parametrize("row, expected", [
    ({"type": "Microsoft.Compute/virtualMachines", "vmSize": "Standard_D4s_v5"}, "Standard_D4s_v5"),
    ({"type": "microsoft.compute/disks", "sku": {"name": "Premium_LRS"}, "diskSizeGB": 128}, "Premium_LRS 128 GB"),
    ({"type": "microsoft.storage/storageaccounts", "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
      "accessTier": "Hot"}, "Standard_LRS · StorageV2 · Hot"),
    ({"type": "microsoft.web/serverfarms", "sku": {"name": "P1v3", "tier": "PremiumV3", "capacity": 2}},
     "P1v3 (PremiumV3) × 2"),
    ({"type": "microsoft.compute/virtualmachinescalesets", "sku": {"name": "Standard_B2s", "capacity": 3}},
     "Standard_B2s × 3"),
    ({"type": "microsoft.containerservice/managedclusters", "k8sVersion": "1.34.2",
      "agentPools": [{"vmSize": "Standard_D4ds_v5", "count": 2}, {"vmSize": "Standard_D8ds_v5", "count": 3}]},
     "k8s 1.34.2 · 2 pool(s), 5 node(s) · Standard_D4ds_v5, Standard_D8ds_v5"),
    ({"type": "microsoft.cache/redis", "innerSku": "Basic C1"}, "Basic C1"),
    ({"type": "microsoft.azurearcdata/sqlserverinstances", "productVersion": "SQL Server 2019", "edition": "Standard",
      "vCores": "4"}, "SQL Server 2019 · Standard · 4 vCores"),
    ({"type": "microsoft.sql/servers/databases", "sku": {"name": "GP_Gen5", "tier": "GeneralPurpose", "capacity": 2}},
     "GP_Gen5 / GeneralPurpose / 2"),
])
def test_size_of_reports_the_sizing_that_matters(row, expected):
    assert size_of(row) == expected


def test_os_state_category_and_labels():
    vm = {"osType": "Windows", "imageOffer": "WindowsServer", "imageSku": "2022-datacenter", "licenseType": "Windows_Server",
          "powerState": "PowerState/deallocated"}
    assert os_of(vm) == "Windows (WindowsServer 2022-datacenter) · AHB"
    assert os_of({"osType": "windows", "osSku": "Windows Server 2019 Standard"}) == "windows (Windows Server 2019 Standard)"
    assert state_of(vm) == "deallocated"
    assert state_of({"diskState": "Unattached"}) == "Unattached"
    assert state_of({"resourceState": "Succeeded"}) == ""
    assert category_of("Microsoft.Compute/virtualMachines") == "Compute"
    assert category_of("microsoft.compute/disks") == "Storage"
    assert category_of("microsoft.azurearcdata/sqlserverinstances") == "Hybrid & Arc"
    assert category_of("microsoft.unknownprovider/things") == "Other"
    assert type_label("microsoft.web/sites") == "App Service / Function app"
    assert type_label("microsoft.network/privatednszones/virtualnetworklinks") == "Private DNS zone VNet link"
    assert type_label("microsoft.keyvault/vaults/secrets") == "Key Vault › secrets"
    assert type_label("microsoft.foo/bars") == "foo/bars"


@pytest.mark.parametrize("row, size, config, os_label, state", [
    ({"type": "microsoft.desktopvirtualization/hostpools",
      "cfg": {"pool": "Pooled", "lb": "BreadthFirst", "max": 10, "app": "Desktop", "pna": "Disabled"}},
     "Pooled · BreadthFirst", "max 10 sessions · Desktop · private access only", "", ""),
    ({"type": "microsoft.compute/virtualmachines/extensions",
      "cfg": {"publisher": "Microsoft.Azure.Monitor", "ext": "AzureMonitorWindowsAgent", "ver": "1.2", "auto": True}},
     "AzureMonitorWindowsAgent · 1.2", "Microsoft.Azure.Monitor · auto-upgrade", "", ""),
    ({"type": "microsoft.network/networkinterfaces", "cfg": {"vm": None, "pe": None, "ip": "10.0.0.4", "accel": False}},
     "", "10.0.0.4", "", "Unattached"),
    ({"type": "microsoft.network/networkinterfaces",
      "cfg": {"vm": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", "ip": "10.0.0.5",
              "accel": True}},
     "Accelerated networking", "VM vm1 · 10.0.0.5", "", "Attached"),
    ({"type": "microsoft.web/sites", "kind": "app,linux",
      "cfg": {"plan": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/serverfarms/asp-1", "fx": "DOTNETCORE|8.0",
              "https": True}},
     "plan asp-1", "HTTPS only", "Linux · .NET 8.0", ""),
    ({"type": "microsoft.web/certificates", "cfg": {"expires": "2020-01-01T00:00:00Z", "subject": "app.contoso.com"}},
     "", "expires 2020-01-01 · app.contoso.com", "", "Expired"),
    ({"type": "microsoft.insights/scheduledqueryrules", "cfg": {"sev": 0, "on": False, "freq": "PT5M"}},
     "Sev 0", "every 5m", "", "Disabled"),
    ({"type": "microsoft.network/privateendpoints",
      "cfg": {"target": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/sql1", "group": "sqlServer",
              "status": "Pending"}},
     "sqlServer", "→ sql1", "", "Pending"),
    ({"type": "microsoft.app/containerapps",
      "cfg": {"cpu": 0.5, "mem": "1Gi", "image": "acr.io/app:1", "min": 0, "max": 10, "wp": "Consumption"}},
     "0.5 vCPU / 1Gi", "scale 0-10 · Consumption", "Container acr.io/app:1", ""),
    ({"type": "microsoft.network/networksecuritygroups", "cfg": {"rules": 3, "subnets": 0, "nics": 0}},
     "", "3 custom rules · 0 subnets · 0 NICs", "", "Unassociated"),
    ({"type": "microsoft.cognitiveservices/accounts", "kind": "OpenAI", "sku": {"name": "S0"}},
     "S0", "Azure OpenAI", "", ""),
    ({"type": "microsoft.compute/virtualmachines", "vmSize": "Standard_D4s_v5", "osType": "Linux",
      "powerState": "PowerState/running",
      "cfg": {"zones": ["1"], "data": 2, "nics": 1, "priority": "Spot", "avset": None, "host": "web01"}},
     "Standard_D4s_v5", "zone 1 · 2 data disks · 1 NIC · Spot · host web01", "Linux", "running"),
])
def test_type_profiles_fill_size_configuration_runtime_and_state(row, size, config, os_label, state):
    assert (size_of(row), config_of(row), os_of(row), state_of(row)) == (size, config, os_label, state)

@pytest.mark.parametrize("value, expected", [
    ("prod", "prod"), ("Core Prod", "prod"), ("public prod", "prod"), ("Non public-prod", "prod"),
    ("non prod", "nonprod"), ("nonprod", "nonprod"), ("Non-Prod", "nonprod"), ("public non-prod", "nonprod"),
    ("non public-non prod", "nonprod"), ("prep", "nonprod"), ("systest", "nonprod"), ("stage1", "nonprod"),
    ("dev", "nonprod"), ("infrastructure", None),
])
def test_environment_tag_values_seen_in_real_estates(value, expected):
    assert env_from_tags({"Environment": value}) == expected


def test_environment_from_names_still_works():
    assert env_from_name("apptimize0dev0client04") == "nonprod"
    assert env_from_name("vm-app-prod-1") == "prod"
    assert env_from_name("stage2-web") == "nonprod"
    assert env_from_name("lods-machineapi") is None


def _report(root, folder, sub_id, name, findings, costs, resources):
    base = root / folder
    raw = base / "05-deep-dive" / "raw"
    (raw / "cost").mkdir(parents=True)
    (raw / "inventory").mkdir(parents=True)
    (base / "summary.json").write_text(json.dumps({"subscription": {"id": sub_id, "name": name},
                                                   "generated_at": "2026-09-25T10:00:00+00:00", "currency": "CHF"}))
    (raw / "findings.json").write_text(json.dumps(findings))
    (raw / "cost" / "last30_by_resource.json").write_text(json.dumps(costs))
    (raw / "inventory" / "resources.json").write_text(json.dumps(resources))


@pytest.fixture
def reports(tmp_path):
    _report(tmp_path, "sub-a", SUB_A, "sub-a", [
        {"ref": "F-001", "title": "Unattached disk: disk-old", "severity": "high", "finding_type": "unattached_managed_disk",
         "resource_id": DISK, "folder": "compute-appservice", "wave": 1, "estimated_monthly_savings_usd": 20.0},
        {"ref": "F-002", "title": "Missing tags: vm-app-prod-1", "severity": "high", "finding_type": "missing_required_tags",
         "resource_id": VM, "folder": "observability-operations", "wave": 2},
        {"ref": "F-003", "title": "No budget on subscription", "severity": "medium", "finding_type": "budget_missing",
         "resource_id": f"/subscriptions/{SUB_A}", "resource_name": SUB_A, "folder": "cost-finops", "wave": 1},
    ], {VM.lower(): {"cost": 120.5, "currency": "CHF"}}, [
        {"id": VM, "name": "vm-app-prod-1", "type": "Microsoft.Compute/virtualMachines", "location": "westeurope",
         "resourceGroup": "rg-app", "tags": {"Environment": "Core Prod"}},
        {"id": DISK, "name": "disk-old", "type": "Microsoft.Compute/disks", "location": "westeurope",
         "resourceGroup": "rg-app", "sku": {"name": "Premium_LRS"}},
    ])
    _report(tmp_path, "sub-b", SUB_B, "sub-b", [], {}, [
        {"id": STORAGE, "name": "stdata", "type": "Microsoft.Storage/storageAccounts", "location": "northeurope",
         "resourceGroup": "rg-data", "sku": {"name": "Standard_LRS"}, "kind": "StorageV2"},
    ])
    return tmp_path


def test_estate_from_reports_joins_findings_and_costs(reports):
    estate = build_estate(reports)
    assert estate["source"] == "reports"
    by_name = {r["name"]: r for r in estate["resources"]}
    assert set(by_name) == {"vm-app-prod-1", "disk-old", "stdata"}
    vm, disk = by_name["vm-app-prod-1"], by_name["disk-old"]
    assert vm["cost30"] == 120.5 and vm["env"] == "Production" and vm["subscription"] == "sub-a"
    assert vm["suggestions"] == 0 and vm["hygiene"] == 1          # tags are hygiene, not actionable
    assert disk["suggestions"] == 1 and disk["maxSeverity"] == "high" and disk["category"] == "Storage"
    sub_level = [s for s in estate["suggestions"] if not s["resourceId"]]
    assert [s["type"] for s in sub_level] == ["budget_missing"] and sub_level[0]["category"] == "Subscription"
    assert {s["name"]: s["resources"] for s in estate["subscriptions"]} == {"sub-a": 2, "sub-b": 1}


def test_live_inventory_takes_precedence_and_covers_unanalysed_subscriptions(reports):
    sub_c = "cccccccc-1111-2222-3333-444444444444"
    inventory = {"generated_at": "2026-09-25T20:00:00+00:00", "source": "resource-graph",
                 "subscriptions": [{"id": SUB_A, "name": "sub-a"}, {"id": sub_c, "name": "sub-c"}],
                 "resources": [
                     {"id": VM, "name": "vm-app-prod-1", "type": "microsoft.compute/virtualmachines",
                      "subscriptionId": SUB_A, "resourceGroup": "rg-app", "location": "westeurope",
                      "vmSize": "Standard_D4s_v5", "powerState": "PowerState/running"},
                     {"id": f"/subscriptions/{sub_c}/resourceGroups/rg/providers/Microsoft.Web/sites/app",
                      "name": "app", "type": "microsoft.web/sites", "subscriptionId": sub_c, "resourceGroup": "rg"},
                 ]}
    estate = build_estate(reports, inventory)
    vm = next(r for r in estate["resources"] if r["name"] == "vm-app-prod-1")
    assert vm["size"] == "Standard_D4s_v5" and vm["state"] == "running" and vm["folder"] == "sub-a"
    app = next(r for r in estate["resources"] if r["name"] == "app")
    assert app["subscription"] == "sub-c" and app["folder"] == ""
    assert estate["source"] == "resource-graph"


def test_compact_format_and_written_files(reports):
    estate = refresh_estate(reports)
    folder = reports / ESTATE_DIR
    wire = json.loads((folder / ESTATE_FILE).read_text(encoding="utf-8"))
    assert wire["format"] == 2 and wire == json.loads(json.dumps(compact(estate), default=str))
    assert wire["types"]["microsoft.compute/disks"] == {"label": "Managed disk", "category": "Storage"}
    disk = next(r for r in wire["resources"] if r["name"] == "disk-old")
    assert disk["n"] == 1 and disk["sev"] == "high" and "cost" not in disk
    unattached = next(s for s in wire["suggestions"] if s["type"] == "unattached_managed_disk")
    assert wire["resources"][unattached["r"]]["name"] == "disk-old" and unattached["af"] == "compute-appservice"
    tags = next(s for s in wire["suggestions"] if s["type"] == "missing_required_tags")
    assert tags["hy"] == 1
    budget = next(s for s in wire["suggestions"] if s["type"] == "budget_missing")
    assert "r" not in budget and wire["subscriptions"][budget["s"]]["name"] == "sub-a"

    md = (folder / "README.md").read_text(encoding="utf-8")
    for heading in ("## Overview", "## By category", "## Top resource types", "## Sizing - what we run",
                    "## Regions and environments", "## Most common suggestions", "## Subscriptions"):
        assert heading in md
    assert "Resources with actionable suggestions | 1" in md
    assert "[sub-a](../sub-a/README.md)" in md
    assert "Junaid Ahmed" in md and "github.com/jahmed-cloud/ARG" in md


def test_estate_folder_is_not_mistaken_for_a_subscription_report(reports):
    from scripts.subscription_analysis.report import read_summaries, write_index

    refresh_estate(reports)
    assert {s["folder"] for s in read_summaries(reports)} == {"sub-a", "sub-b"}
    index = write_index(reports).read_text(encoding="utf-8")
    assert "_estate/README.md" in index
