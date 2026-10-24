"""CVE check (scripts/subscription_analysis/cve.py): NVD affected versions and CISA KEV matched to the Compute
inventory - offline fixtures, no network."""

from datetime import date

import pytest

from scripts.subscription_analysis import cve

COMPUTE = {
    "machines": [
        {"id": "/vm/win-old", "name": "win-old", "kind": "vm", "subscription": "sub-a", "family": "Windows Server",
         "os": "Windows Server 2016", "osReported": "Windows Server 2016 Datacenter 10.0.14393.7699", "osType": "Windows",
         "running": True, "exposed": True, "sql": [], "patches": None, "packages": None},
        {"id": "/vm/win-new", "name": "win-new", "kind": "arc", "subscription": "sub-a", "family": "Windows Server",
         "os": "Windows Server 2016", "osReported": "Windows Server 2016 Standard 10.0.14393.9700", "osType": "windows",
         "running": True, "exposed": False,
         "sql": [{"id": "/sql/one", "name": "win-new_MSSQLSERVER", "product": "SQL Server 2016", "edition": "Standard",
                  "build": "13.0.6435.1"}],
         "patches": None, "packages": None},
        {"id": "/vm/web", "name": "web", "kind": "vm", "subscription": "sub-b", "family": "Ubuntu", "os": "Ubuntu 22.04 LTS",
         "osReported": "ubuntu 22.04", "osType": "Linux", "running": True, "exposed": True, "sql": [],
         "patches": {"names": ["openssl 3.0.2-0ubuntu1.20"]}, "packages": None},
        {"id": "/vm/fw", "name": "fw", "kind": "vm", "subscription": "sub-c", "family": "Network appliance",
         "os": "PAN-OS 11.1.0", "osReported": "PAN-OS 11.1.0", "osType": "Linux", "running": True, "exposed": True,
         "sql": [], "patches": None, "packages": None},
    ],
    "sql": [],
    "apps": [{"id": "/app/php", "name": "portal", "subscription": "sub-b", "stack": "PHP", "version": "8.3",
              "runtime": "PHP 8.3", "exposure": "Public app endpoint"},
             {"id": "/app/php85", "name": "tool", "subscription": "sub-b", "stack": "PHP", "version": "8.5",
              "runtime": "PHP 8.5", "exposure": ""}],
}


def match(criteria, **bounds):
    return {"vulnerable": True, "criteria": criteria, **bounds}


def record(*matches, description="A flaw.", status="Analyzed"):
    return {"id": "CVE-X", "vulnStatus": status, "published": "2026-10-21T00:00:00", "descriptions":
            [{"lang": "en", "value": description}], "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 9.2,
                                                                                               "baseSeverity": "CRITICAL"}}]},
            "configurations": [{"nodes": [{"cpeMatch": list(matches)}]}] if matches else []}


def facts():
    return cve.inventory_facts(COMPUTE)


def test_versions_and_ranges():
    assert cve.version_tuple("v11.1.0") == (11, 1, 0) and cve.version_tuple("20-lts") == (20,)
    assert cve.version_tuple("10.0.14393.7699") == (10, 0, 14393, 7699) and cve.version_tuple("") == ()
    r = {"versionStartIncluding": "8.3.0", "versionEndExcluding": "8.3.20"}
    assert cve.in_range((8, 3, 19), r) and not cve.in_range((8, 3, 20), r) and not cve.in_range((8, 4, 1), r)
    assert cve.branch_overlaps((8, 3), r) and not cve.branch_overlaps((8, 5), r)
    assert cve.branch_overlaps((8, 2), {"versionEndExcluding": "8.2.35"})


def test_inventory_facts_name_os_builds_firmware_sql_runtimes_and_pending_packages():
    by = {(f["id"], f["key"]): f for f in facts()}
    win = by[("/vm/win-old", "windows")]
    assert win["version"] == "10.0.14393.7699" and win["exact"] == "full" and win["cpeProducts"] == ["windows_server_2016"]
    assert by[("/sql/one", "sql_server")]["cpeProducts"] == ["sql_server_2016"]
    assert by[("/vm/web", "ubuntu")]["version"] == "22.04" and ("/vm/web", "linux_kernel") in by
    assert by[("/vm/web", "openssl")]["source"] == "security update pending"
    assert by[("/vm/fw", "panos")]["version"] == "11.1.0" and by[("/vm/fw", "panos")]["exact"] == "full"
    assert by[("/app/php", "php")]["exact"] == "branch" and by[("/app/php", "php")]["exposed"] is True


def test_php_cve_marks_affected_branches_and_leaves_patched_ones_out():
    rec = record(match("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", versionStartIncluding="8.3.0", versionEndExcluding="8.3.20"),
                 match("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", versionStartIncluding="8.4.0", versionEndExcluding="8.4.10"))
    res = cve.check("cve-2099-0101", rec, facts(), {"vulnerabilities": [{"cveID": "CVE-2099-0101",
                                                                           "dateAdded": "2026-01-15"}]})
    assert res["cve"] == "CVE-2099-0101" and res["kev"]["dateAdded"] == "2026-01-15" and res["severity"] == "CRITICAL"
    by = {r["name"]: r for r in res["results"]}
    assert by["portal"]["verdict"] == cve.POTENTIAL and by["portal"]["fixed"] == "8.3.20"
    assert "php -v" in by["portal"]["reason"] and by["tool"]["verdict"] == cve.NOT_AFFECTED
    assert res["counts"] == {cve.IMPACTED: 0, cve.POTENTIAL: 1, cve.NOT_AFFECTED: 1}


def test_windows_build_is_compared_exactly_and_firmware_by_its_version():
    rec = record(match("cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*", versionEndExcluding="10.0.14393.9612"),
                 match("cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", versionStartIncluding="11.1.0",
                       versionEndExcluding="11.1.3"))
    by = {r["name"]: r for r in cve.check("CVE-1", rec, facts())["results"]}
    assert by["win-old"]["verdict"] == cve.IMPACTED and by["win-old"]["fixed"] == "10.0.14393.9612"
    assert by["win-new"]["verdict"] == cve.NOT_AFFECTED
    assert by["fw"]["verdict"] == cve.IMPACTED and by["fw"]["kind"] == "Azure VM"
    assert [r["name"] for r in cve.check("CVE-1", rec, facts())["results"]][0] == "fw"   # impacted, internet-facing


def test_pending_package_update_and_os_releases_are_potential():
    rec = record(match("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", versionStartIncluding="3.0.0",
                       versionEndExcluding="3.0.15"),
                 match("cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*"),
                 match("cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:x64:*", versionEndExcluding="13.0.6450.1"))
    by = {(r["name"], r["label"].split()[0]): r for r in cve.check("CVE-2", rec, facts())["results"]}
    assert by[("web", "openssl")]["verdict"] == cve.POTENTIAL and "install it" in by[("web", "openssl")]["reason"]
    assert by[("web", "Ubuntu")]["verdict"] == cve.POTENTIAL
    assert by[("win-new_MSSQLSERVER", "SQL")]["verdict"] == cve.IMPACTED


def test_unanalysed_cve_falls_back_to_the_products_its_description_names():
    res = cve.check("CVE-3", record(description="A use-after-free in PHP allows remote code execution.",
                                    status="Awaiting Analysis"), facts())
    assert res["note"].startswith("NVD has not analysed") and {r["name"] for r in res["results"]} == {"portal", "tool"}
    assert cve.check("CVE-4", None, facts())["found"] is False


def test_kev_lists_recent_exploited_cves_for_products_in_the_estate():
    kev = {"catalogVersion": "2026.10.21", "vulnerabilities": [
        {"cveID": "CVE-A", "vendorProject": "Microsoft", "product": "Windows", "dateAdded": "2026-10-13",
         "dueDate": "2026-11-03", "knownRansomwareCampaignUse": "Unknown", "vulnerabilityName": "Win flaw"},
        {"cveID": "CVE-B", "vendorProject": "Palo Alto Networks", "product": "PAN-OS", "dateAdded": "2026-09-01"},
        {"cveID": "CVE-C", "vendorProject": "Plex", "product": "Media Server", "dateAdded": "2026-10-20"},
        {"cveID": "CVE-D", "vendorProject": "Microsoft", "product": "Windows", "dateAdded": "2025-01-01"}]}
    out = cve.kev_in_estate(kev, facts(), days=90, today=date(2026, 10, 22))
    assert [r["cve"] for r in out["rows"]] == ["CVE-A", "CVE-B"] and out["total"] == 4
    assert out["rows"][0]["resources"] == 2 and out["rows"][0]["exposed"] == 1
    assert out["rows"][1]["kinds"] == ["Azure VM"]


def test_sources_are_cached_and_a_failure_is_not_retried_at_once(tmp_path, monkeypatch):
    calls = []

    def fetch():
        calls.append(1)
        return {"ok": len(calls)}
    assert cve._cached("unit-a", 3600, fetch, tmp_path) == {"ok": 1}
    assert cve._cached("unit-a", 3600, fetch, tmp_path) == {"ok": 1} and len(calls) == 1
    cve._MEMORY.clear()
    assert cve._cached("unit-a", 3600, fetch, tmp_path) == {"ok": 1}        # from the file

    def broken():
        raise OSError("dns")
    with pytest.raises(RuntimeError):
        cve._cached("unit-b", 3600, broken, None)
    with pytest.raises(RuntimeError, match="retried"):
        cve._cached("unit-b", 3600, fetch, None)
    with pytest.raises(ValueError):
        cve.fetch_cve("not-a-cve")


IMAGES = {"machines": [], "sql": [], "apps": [
    {"id": "/app/off", "name": "closed", "subscription": "sub-b", "stack": "PHP", "version": "8.3", "runtime": "PHP 8.3",
     "exposure": "Public access off", "state": "Stopped"},
    {"id": "/app/portal", "name": "portal", "subscription": "sub-b", "stack": "PHP", "version": "8.3",
     "runtime": "PHP 8.3", "exposure": "Public app endpoint", "internet": True,
     "urls": ["https://portal.example.com", "https://portal.azurewebsites.net"]}],
    "images": [
    {"id": "/ca/cms", "name": "cms / wordpress", "kind": "Container App", "subscription": "sub-c",
     "image": "wordpress:6.5-php8.3", "repository": "library/wordpress", "tag": "6.5-php8.3", "exposed": True,
     "url": "https://cms.example.io", "packages": []},
    {"id": "/ca/cms", "name": "cms / php-worker", "kind": "Container App", "subscription": "sub-c",
     "image": "php:8.3.12-fpm", "repository": "library/php", "tag": "8.3.12-fpm", "exposed": False, "packages": []},
    {"id": "/aci/api", "name": "api", "kind": "Container Instance", "subscription": "sub-c",
     "image": "acr.azurecr.io/team/api:1.0", "repository": "team/api", "tag": "1.0", "exposed": False,
     "packages": ["php8.2-common", "openssl"]}]}


def test_container_images_are_checked_by_tag_and_by_their_defender_packages():
    rec = record(match("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", versionStartIncluding="8.3.0", versionEndExcluding="8.3.20"))
    res = cve.check("CVE-2099-0101", rec, cve.inventory_facts(IMAGES))
    by = {r["name"]: r for r in res["results"]}
    assert by["cms / wordpress"]["verdict"] == cve.POTENTIAL and "branch tag moves" in by["cms / wordpress"]["reason"]
    assert by["cms / wordpress"]["urls"] == ["https://cms.example.io"] and by["cms / wordpress"]["exposed"]
    assert by["cms / php-worker"]["verdict"] == cve.IMPACTED                    # 8.3.12 pinned, fixed in 8.3.20
    assert by["api"]["verdict"] == cve.POTENTIAL and by["api"]["source"] == "outdated package (Defender)"
    assert by["portal"]["urls"][0] == "https://portal.example.com" and by["portal"]["exposed"]
    assert by["closed"]["exposed"] is False                     # 'Public access off' is not internet-facing
    assert by["portal"]["running"] and not by["closed"]["running"]                # a stopped slot is not running
    assert [r["name"] for r in res["results"]][:2] == ["cms / php-worker", "cms / wordpress"]


def test_image_tags_name_the_product_and_how_exact_its_version_is():
    assert cve.image_products("library/php", "8.3-apache") == [("php", "8.3", "php:8.3-apache")]
    assert cve.image_products("library/wordpress", "6.5-php8.3")[1] == ("php", "8.3", "PHP 8.3 in wordpress:6.5-php8.3")
    assert cve.image_products("grafana/grafana-enterprise", "13.0")[0][:2] == ("grafana", "13.0")
    assert cve.image_products("team/web", "deadbeef" * 5) == []
    assert [cve.tag_exactness(v) for v in ("8.3.12", "8.3", "")] == ["full", "branch", "none"]
