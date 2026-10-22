"""
Compute view: OS / SQL Server lifecycle (scanners/base/lifecycle.py), the machine inventory
(scanners/compute/machine_inventory.py), the estate payload (scripts/subscription_analysis/compute.py) and the
machine security and end-of-support OS scanners.
"""

import asyncio
import json
from datetime import date

import pytest

import scanners.compute.compute_posture_scanners  # noqa: F401 - registers the OS scanner
import scanners.compute.machine_security_scanners as machine_security
from scanners.base.base_scanner import ScanContext, ScannerRegistry, SeverityLevel
from scanners.base.lifecycle import identify_os, identify_sql, runtime_end_of_support, support
from scanners.compute import machine_inventory
from scripts.subscription_analysis import compute, estate

TODAY = date(2026, 10, 22)
VM = "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/vm-web-01"
ARC = "/subscriptions/sub-1/resourceGroups/rg-arc/providers/Microsoft.HybridCompute/machines/srv-db-01"


@pytest.mark.parametrize("kwargs, label, status", [
    ({"name": "debian", "version": "11"}, "Debian 11", "ended"),
    ({"name": "debian", "version": "12"}, "Debian 12", "supported"),
    ({"name": "ubuntu", "version": "18.04"}, "Ubuntu 18.04 LTS", "ended"),
    ({"name": "Windows Server 2016 Datacenter", "version": "10.0.14393.7000"}, "Windows Server 2016", "ending"),
    ({"name": "Windows Server 2012 R2 Standard", "version": "6.3.9600"}, "Windows Server 2012 R2", "ended"),
    ({"name": "Windows 11 Enterprise multi-session", "version": "10.0.22631.4000"}, "Windows 11 23H2 Enterprise",
     "ending"),
    ({"name": "Windows 10 Pro", "version": "10.0.19045.5000"}, "Windows 10 22H2", "ended"),
    ({"name": "PAN-OS", "version": "11.1.0"}, "PAN-OS 11.1.0", "appliance"),
    ({"offer": "windows-11", "sku": "win11-25h2-ent"}, "Windows 11 25H2 Enterprise", "supported"),
    ({"offer": "0001-com-ubuntu-server-jammy", "sku": "22_04-lts-gen2"}, "Ubuntu 22.04 LTS", "supported"),
    ({"offer": "ubuntu-2204", "sku": "2204-gen2"}, "Ubuntu 22.04 LTS", "supported"),
    ({"offer": "almalinux-x86_64", "sku": "9-gen2"}, "AlmaLinux 9", "supported"),
    ({"offer": "RHEL", "sku": "7_9"}, "RHEL 7", "ended"),
    ({"offer": "sles-15-sp5", "sku": "gen2"}, "SLES 15", "unknown"),
])
def test_os_lifecycle_from_what_the_machine_reports_or_its_image(kwargs, label, status):
    s = support(identify_os(**kwargs), TODAY)
    assert (s.product.label, s.status) == (label, status)


def test_lifecycle_notes_name_the_esu_route_and_when_it_ends():
    assert "paid ESU through Azure Arc" in support(identify_os("Windows Server 2016 Standard"), TODAY).note
    assert "extended updates also ended 2026-10-13" in support(identify_os("Windows Server 2012 R2 Standard"),
                                                               TODAY).note
    covered = support(identify_os("Windows Server 2016 Standard"), date(2027, 3, 1), esu_assigned=True)
    assert covered.status == "esu" and "covered by Extended Security Updates" in covered.note
    assert support(None, TODAY).status == "unknown"


def test_sql_server_lifecycle_from_version_label_image_or_build():
    assert support(identify_sql("SQL Server 2016"), TODAY).status == "ended"
    assert "until 2029-07-10" in support(identify_sql("SQL Server 2016"), TODAY).note
    assert identify_sql(offer="SQL2017-WS2016").label == "SQL Server 2017"
    assert identify_sql(build="13.0.6435.1").label == "SQL Server 2016"
    assert identify_sql(build="10.50.6000.34").label == "SQL Server 2008 R2"
    assert identify_sql("SQL Server 2019").ends == "2030-01-08"


def test_php_82_runtime_has_its_end_of_support():
    assert runtime_end_of_support("php|8.2") == ("PHP 8.2", date(2026, 12, 31))
    assert runtime_end_of_support("php|8.3") == ("PHP 8.3", date(2027, 12, 31))
    assert runtime_end_of_support("dotnet-isolated|8.0") == (".NET 8", date(2026, 11, 10))
    assert runtime_end_of_support("node|24-lts") is None


def _raw():
    return machine_security.MachineSecurityScanner()._mock_raw()


def test_machine_inventory_joins_patches_scanner_coverage_exposure_and_sql():
    inv = machine_inventory.build(_raw(), TODAY, {"sub-1": "Sub One"})
    vm = next(m for m in inv["machines"] if m["kind"] == "vm")
    arc = next(m for m in inv["machines"] if m["kind"] == "arc")
    assert vm["id"] == VM and vm["publicIp"] is True and vm["exposed"] and vm["subscription"] == "Sub One"
    assert vm["patches"]["security"] == 2 and vm["patches"]["reboot"] is True
    assert vm["patches"]["names"] == ["nginx 1.18.0-6ubuntu14.8", "openssl 3.0.2-0ubuntu1.20"]
    assert vm["os"] == "Ubuntu 22.04 LTS" and vm["osSource"] == "machine" and vm["env"] == "Production"
    assert vm["scanner"] == "none" and "turned" not in vm["scannerNote"]
    # a pending security update on an internet-facing VM is the critical path; a missing scanner alone is not
    assert vm["criticalPath"] and vm["reasons"][-1] == "no vulnerability scanner"
    assert arc["publicIp"] is None and not arc["criticalPath"] and arc["scanner"] == "none"
    assert arc["sql"][0]["product"] == "SQL Server 2016" and arc["sql"][0]["support"] == "ended"
    assert arc["sql"][0]["esuEnabled"] is None and inv["sql"][0]["machine"] == ARC.lower()


def test_scanner_coverage_needs_an_agent_an_assessment_or_cve_results():
    assert machine_inventory._scanner(["Qualys"], "", "Free", None)[0] == "covered"
    assert machine_inventory._scanner([], "Healthy", "Free", None)[0] == "covered"
    assert machine_inventory._scanner(["Defender for Endpoint"], "", "P1", None)[0] == "covered"
    assert machine_inventory._scanner([], "Unhealthy", "P2", None)[0] == "none"
    assert machine_inventory._scanner([], "", "P2", None)[0] == "unverified"
    assert machine_inventory._scanner([], "", "", {"count": 3})[0] == "covered"


def test_machine_inventory_queries_keep_azure_ids_and_failed_sources_become_warnings():
    assert "project id, key = tolower(id)" in machine_inventory.QUERIES["machines"]
    assert "@'(CVE-\\d{4}-\\d{4,7})'" in machine_inventory.QUERIES["cves"]

    async def run(query):
        if "patchassessmentresources" in query:
            raise RuntimeError("AuthorizationFailed")
        return []
    raw = asyncio.run(machine_inventory.collect(run))
    assert raw["patch_results"] == [] and raw["warnings"][0].startswith("patch_results: AuthorizationFailed")


def test_compute_payload_adds_app_runtimes_with_exposure_and_merges_tenants():
    rows = [{"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/app-php", "name": "app-php",
             "type": "microsoft.web/sites", "kind": "app,linux", "subscriptionId": "sub-1", "resourceGroup": "rg",
             "cfg": {"fx": "PHP|8.2"}},
            {"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/app-net", "name": "app-net",
             "type": "microsoft.web/sites", "kind": "app", "subscriptionId": "sub-1", "resourceGroup": "rg", "cfg": {}},
            {"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/app-old", "name": "app-old",
             "type": "microsoft.web/sites", "kind": "app,linux", "subscriptionId": "sub-1", "resourceGroup": "rg",
             "cfg": {"fx": "NODE|18-lts"}}]
    paas = [{"id": rows[0]["id"].lower(), "type": "microsoft.web/sites", "public": "Enabled"}]
    payload = compute.build_compute(_raw(), {"sub-1": "Sub One"}, rows, paas, TODAY)
    apps = {a["name"]: a for a in payload["apps"]}
    assert set(apps) == {"app-php", "app-old"}                       # no runtime stack: not listed
    assert apps["app-php"]["runtime"] == "PHP 8.2" and apps["app-php"]["support"] == "ending"
    assert apps["app-php"]["exposure"] == "Public app endpoint" and apps["app-old"]["support"] == "ended"
    s = payload["summary"]
    assert s["machines"] == 2 and s["criticalPath"] == 1 and s["sql"]["ended"] == 1 and s["apps"]["ended"] == 1
    assert payload["machines"][0]["criticalPath"]                    # critical path first
    merged = compute.merge_compute([payload, payload, {"error": "x"}, None])
    assert merged["summary"]["machines"] == 4 and merged["summary"]["apps"]["total"] == 4
    assert compute.merge_compute([None, {"error": "x"}]) == {}
    text = compute.markdown(payload)
    assert "## Compute" in text and "SQL Server: 1 instances, 1 past end of support" in text


def test_estate_writes_compute_json_apart_and_adds_it_to_the_overview(tmp_path):
    payload = compute.build_compute(_raw(), {"sub-1": "Sub One"}, [], [], TODAY)
    inventory = {"generated_at": "2026-10-22T08:00:00+00:00", "source": "resource-graph",
                 "subscriptions": [{"id": "sub-1", "name": "Sub One"}], "resources": [], "compute": payload}
    estate.write_estate(tmp_path, estate.build_estate(tmp_path, inventory), inventory)
    folder = tmp_path / estate.ESTATE_DIR
    assert json.loads((folder / estate.COMPUTE_FILE).read_text(encoding="utf-8"))["summary"]["machines"] == 2
    assert "compute" not in json.loads((folder / estate.INVENTORY_FILE).read_text(encoding="utf-8"))
    assert "compute" not in json.loads((folder / estate.ESTATE_FILE).read_text(encoding="utf-8"))
    assert "## Compute" in (folder / "README.md").read_text(encoding="utf-8")
    estate.refresh_estate(tmp_path)                                  # offline re-join keeps the Compute section
    assert "## Compute" in (folder / "README.md").read_text(encoding="utf-8")
    assert estate.load_compute(tmp_path)["summary"]["vms"] == 1


def _run(name, config=None):
    ctx = ScanContext(subscription_id="sub-1", tenant_id="tenant-1", scan_job_id="job-1")
    return asyncio.run(ScannerRegistry.get(name)(config=config or {"as_of": "2026-10-22"}).execute(ctx))


def test_machine_security_scanner_findings_and_severities():
    by_type = {f.finding_type: f for f in _run("machine_security_scanner").findings}
    exposed = by_type["internet_facing_machine_unpatched"]
    assert exposed.severity == SeverityLevel.HIGH and exposed.resource_id == VM
    assert exposed.title == "Internet-facing VM with 2 security update(s) missing: vm-web-01"
    assert "--classifications-to-include-linux Critical Security" in exposed.azure_cli_script
    blind = by_type["machine_vulnerability_scan_missing"]
    assert blind.severity == SeverityLevel.HIGH and blind.evidence["count"] == 2 and blind.evidence["internet_facing"] == 1
    assert blind.evidence["cost_of_change"]["monthly_usd"] > 0 and "--subplan P1" in blind.azure_cli_script
    sql = by_type["sql_server_end_of_support"]
    assert sql.severity == SeverityLevel.HIGH and sql.title.startswith("End-of-support SQL Server (SQL Server 2016)")
    assert "No Extended Security Updates subscription" in sql.description
    assert "until 2029-07-10" in sql.remediation_steps


def test_os_scanner_reads_the_reported_os_covers_arc_and_warns_before_the_date():
    findings = {f.resource_name: f for f in _run("unsupported_os_image_scanner").findings}
    assert set(findings) == {"vm-win10-1", "srv-file-01"}             # Windows Server 2022 is fine
    assert findings["srv-file-01"].severity == SeverityLevel.CRITICAL
    assert findings["srv-file-01"].resource_type == "microsoft.hybridcompute/machines"
    assert findings["vm-win10-1"].severity == SeverityLevel.HIGH and "(VM deallocated)" in findings["vm-win10-1"].title
    assert findings["srv-file-01"].evidence["end_of_support"] == "2023-10-10"
    scanner = ScannerRegistry.get("unsupported_os_image_scanner")(config={"as_of": "2026-10-22"})
    row = {"id": ARC, "name": "srv-old-01", "type": "microsoft.hybridcompute/machines", "resourceGroup": "rg-arc",
           "subscriptionId": "sub-1", "os_name": "Windows Server 2016 Standard", "os_version": "10.0.14393",
           "agent_status": "Connected", "esu": "NotAssigned"}
    ending = scanner._finding(row, support(identify_os(row["os_name"], row["os_version"]), TODAY), True)
    assert ending.severity == SeverityLevel.MEDIUM and ending.title.startswith("OS support ends in 82 days")
