"""
Azure Resource Guardian - Machine security scanner
===================================================
One scanner over a subscription's machine inventory (scanners/compute/machine_inventory.py):

1. internet_facing_machine_unpatched  - a running VM with a public IP and a known weakness: pending security /
                                        critical updates, outdated packages Defender rates high, critical / high
                                        CVEs, or an operating system past end of support
2. machine_vulnerability_scan_missing - running machines no vulnerability scanner covers, one finding per
                                        subscription listing them: nobody can tell whether a new CVE affects them
3. sql_server_end_of_support          - SQL Server instances (Azure Arc, SQL IaaS) past or near end of support,
                                        with the Extended Security Updates route

The end of support of the operating system itself is the End-of-Support Operating System scanner's finding
(vm_unsupported_os, compute_posture_scanners.py).
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from datetime import date
from typing import Any, Dict, List

from scanners.base.azure_api import query_resource_graph
from scanners.base.base_scanner import (
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)
from scanners.base.guidance import PRICE
from scanners.base.lifecycle import ENDED, ENDING, ESU
from scanners.base.posture_scanner import PostureScanner
from scanners.compute.machine_inventory import NONE, build, collect

LOWER = {SeverityLevel.CRITICAL: SeverityLevel.HIGH, SeverityLevel.HIGH: SeverityLevel.MEDIUM,
         SeverityLevel.MEDIUM: SeverityLevel.LOW, SeverityLevel.LOW: SeverityLevel.LOW}
MAX_LISTED = 100


def _as_date(value: Any) -> date:
    return value if isinstance(value, date) else date.fromisoformat(str(value)[:10])


def _leaf(resource_id: str) -> str:
    return (resource_id or "").rstrip("/").split("/")[-1]


@register_scanner
class MachineSecurityScanner(PostureScanner):
    """Patching and vulnerability-scan coverage of VMs / Arc servers, and SQL Server end of support."""

    scanner_name = "machine_security_scanner"
    display_name = "Machine Patching, Vulnerability Scanning & SQL Server Support"
    description = ("Internet-facing machines with missing security updates, machines no vulnerability scanner "
                   "covers, and SQL Server versions past end of support")
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.HIGH
    finding_types = {"internet_facing_machine_unpatched", "machine_vulnerability_scan_missing",
                     "sql_server_end_of_support"}

    SQL_NEAR_DAYS = 180

    async def scan(self, context: ScanContext) -> ScanOutput:
        if getattr(context, "resource_graph_client", None) is None:
            raw = self._mock_raw()
        else:
            raw = await collect(lambda query: query_resource_graph(context, query))
        inventory = build(raw, _as_date(self.setting("as_of", date.today())))
        machines, sql = inventory["machines"], inventory["sql"]
        findings = [self._exposed(m) for m in machines if m["criticalPath"] and m["kind"] == "vm"]
        coverage = self._coverage(context, machines)
        if coverage is not None:
            findings.append(coverage)
        findings.extend(f for f in (self._sql(s) for s in sql) if f is not None)
        return ScanOutput(findings=findings, resources_scanned=len(machines) + len(sql),
                          warnings=[f"Machine inventory query failed - {w}" for w in raw.get("warnings") or []])

    # -- 1. internet-facing VM with a known weakness -------------------------------------------------------

    def _exposed(self, m: Dict[str, Any]):
        weaknesses = [r for r in m["reasons"] if r != "no vulnerability scanner"]
        patches, packages, cves = m["patches"] or {}, m["packages"] or {}, m["cves"] or {}
        missing = (patches.get("security") or 0) + (patches.get("critical") or 0)
        if missing:
            headline = f"{missing} security update(s) missing"
        elif packages.get("high"):
            headline = f"{packages['high']} outdated package(s)"
        elif cves.get("critical") or cves.get("high"):
            headline = f"{(cves.get('critical') or 0) + (cves.get('high') or 0)} critical / high CVE(s)"
        else:
            headline = "end-of-support OS"
        severity = (SeverityLevel.CRITICAL if m["support"] == ENDED or cves.get("critical") or patches.get("critical")
                    else SeverityLevel.HIGH)
        rg, name = m["resourceGroup"], m["name"]
        linux = (m.get("osType") or "").lower() == "linux" or m.get("family") not in ("Windows", "Windows Server")
        classes = "--classifications-to-include-linux Critical Security" if linux else \
            "--classifications-to-include-win Critical Security"
        steps = []
        if m["support"] == ENDED:
            steps.append("The operating system itself is past end of support (see its End-of-Support OS finding) - "
                         "installing updates is not enough; upgrade or rebuild it.")
        steps += [
            "Install the missing security / critical updates now: Azure Update Manager > One-time update, or the "
            "command below; reboot if one is pending.",
            "Turn on periodic assessment and a patch schedule (maintenance configuration) so new missing updates show "
            "up daily and are installed on time.",
            "Remove the public IP: reach the VM through Azure Bastion or VPN, publish its service through "
            "Application Gateway (WAF) or a load balancer.",
            "Until then allow only the ports the service needs in the NSG, from known source addresses.",
        ]
        evidence = {"os": m["os"], "os_reported": m["osReported"] or None, "support": m["support"],
                    "support_note": m["supportNote"], "public_ip": True, "state": m["state"],
                    "patches": m["patches"], "packages": m["packages"],
                    "cves": ({**cves, "ids": (cves.get("ids") or [])[:50]} if cves else None),
                    "scanner": m["scanner"], "scanner_note": m["scannerNote"], "weaknesses": weaknesses}
        return self.resource_finding(
            {"id": m["id"], "name": name, "type": "microsoft.compute/virtualmachines", "resourceGroup": rg,
             "subscriptionId": m["subscriptionId"], "location": m["location"]},
            finding_type="internet_facing_machine_unpatched",
            title=f"Internet-facing VM with {headline}: {name}",
            description=(f"VM '{name}' ({m['os']}) is running with a public IP and " + "; ".join(weaknesses)
                         + ". A public IP is probed by every internet scanner within minutes; missing security fixes "
                           "on it are the most likely way in."),
            severity=severity,
            remediation_steps="\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1)),
            azure_cli_script=(f"az vm assess-patches -g {rg} -n {name}\n"
                              f"az vm install-patches -g {rg} -n {name} --maximum-duration PT2H "
                              f"--reboot-setting IfRequired {classes}"),
            evidence=evidence,
            nist_control="SI-2",
            estimated_monthly_savings_usd=0.0,
        )

    # -- 2. machines without a vulnerability scanner (one per subscription) ---------------------------------

    def _coverage(self, context: ScanContext, machines: List[Dict[str, Any]]):
        blind = [m for m in machines if m["running"] and m["scanner"] == NONE]
        if not blind:
            return None
        exposed = [m for m in blind if m["publicIp"]]
        prod = [m for m in blind if m["env"] == "Production"]
        severity = SeverityLevel.HIGH if exposed else SeverityLevel.MEDIUM if prod else SeverityLevel.LOW
        plan = next((m["defenderPlan"] for m in machines if m["defenderPlan"]), "")
        vms, arcs = sum(1 for m in blind if m["kind"] == "vm"), sum(1 for m in blind if m["kind"] == "arc")
        monthly = round(len(blind) * PRICE["defender_servers_p1"], 2)
        blind.sort(key=lambda m: (not m["publicIp"], m["env"] != "Production", m["name"].lower()))
        listed = ", ".join(m["name"] for m in blind[:10]) + (", …" if len(blind) > 10 else "")
        return self.subscription_finding(
            context,
            finding_type="machine_vulnerability_scan_missing",
            title=(f"{len(blind)} running machine(s) without vulnerability scanning"
                   + (f" ({len(exposed)} internet-facing)" if exposed else "")),
            description=(f"No vulnerability scanner covers {len(blind)} running machine(s) here ({vms} VM(s), "
                         f"{arcs} Arc server(s)): {listed}. Defender for Servers is "
                         f"{'Plan ' + plan[1:] if plan in ('P1', 'P2') else (plan or 'not configured')} and no "
                         "Defender for Endpoint or Qualys agent, vulnerability assessment or CVE result is visible. "
                         "When a CVE is published (a PHP, OpenSSL or OpenSSH flaw), nobody can tell from Azure "
                         "whether these machines are affected."),
            severity=severity,
            remediation_steps=(
                "1. Enable Defender for Servers Plan 1 (Defender for Endpoint with vulnerability management) for the "
                "subscription - Plan 2 for internet-facing and production servers (agentless scanning, just-in-time "
                "access). Arc servers are covered by the same plan.\n"
                "2. A day later check Defender for Cloud > Recommendations > \"Machines should have vulnerability "
                "findings resolved\": it lists the CVEs per machine, and the ARG Compute view shows them.\n"
                "3. Machines another scanner already covers (Tenable, Rapid7, Qualys outside Defender): record which "
                "and dismiss this finding for them."),
            azure_cli_script=(f"az security pricing create -n VirtualMachines --tier standard --subplan P1 "
                              f"--subscription {context.subscription_id}"),
            evidence={"count": len(blind), "internet_facing": len(exposed), "production": len(prod),
                      "defender_plan": plan or None,
                      "machines": [{"name": m["name"], "kind": m["kind"], "os": m["os"], "env": m["env"],
                                    "public_ip": m["publicIp"], "reason": m["scannerNote"]} for m in blind[:MAX_LISTED]],
                      "cost_of_change": {"monthly_usd": monthly,
                                         "basis": f"Defender for Servers Plan 1 list price for {len(blind)} machine(s)"}},
            estimated_monthly_savings_usd=0.0,
        )

    # -- 3. SQL Server past or near end of support -----------------------------------------------------------

    def _sql(self, s: Dict[str, Any]):
        status = s["support"]
        if status not in (ENDED, ESU) and not (status == ENDING and (s["daysLeft"] or 0) <= self.SQL_NEAR_DAYS):
            return None
        arc = s["type"] == "microsoft.azurearcdata/sqlserverinstances"
        host = _leaf(s["machine"]) or "its host"
        service = f" {s['service']}" if s["service"] and s["service"].lower() != "engine" else ""
        label = f"{s['product']}{service}"
        if status == ENDED:
            severity = SeverityLevel.MEDIUM if s["nonProduction"] else SeverityLevel.HIGH
            title = f"End-of-support SQL Server ({label}): {s['name']}"
        elif status == ESU:
            severity = SeverityLevel.LOW
            title = f"SQL Server on Extended Security Updates ({label}): {s['name']}"
        else:
            severity = SeverityLevel.LOW if s["nonProduction"] else SeverityLevel.MEDIUM
            title = f"SQL Server support ends in {s['daysLeft']} days ({label}): {s['name']}"
        disconnected = arc and s["status"] and s["status"].lower() != "connected"
        if disconnected:
            severity = LOWER[severity]
        edition = f" {s['edition']}" if s["edition"] else ""
        description = (f"SQL Server instance '{s['name']}' on {host} runs {s['product']}{edition}"
                       + (f" (build {s['build']})" if s["build"] else "") + f": {s['supportNote']}.")
        if status == ENDED and arc and s["esu"] and s["esuEnabled"] is not True:
            description += " No Extended Security Updates subscription is set on its Arc SQL Server extension."
        if s["nonProduction"]:
            description += f" The{edition} edition is licensed for non-production use only."
        if disconnected:
            description += f" The Arc agent reports it as {s['status']} - the inventory may be out of date."
        steps = ["Upgrade in place to SQL Server 2022 / 2025 after a compatibility check (Database Migration "
                 "Assistant / Azure SQL migration extension), or migrate the databases to Azure SQL Managed Instance.",
                 "Decommission instances nobody uses (check connections and jobs first)."]
        if s["esu"] and status != ESU:
            steps.insert(1, f"While the upgrade is planned: {s['esu']}"
                            + (f" until {s['esuUntil']}" if s["esuUntil"] else "")
                            + " - for Arc instances: SQL Server - Azure Arc > Extended Security Updates, billed per "
                              "core per month.")
        return self.resource_finding(
            {"id": s["id"], "name": s["name"], "type": s["type"], "resourceGroup": s["resourceGroup"],
             "subscriptionId": s["subscriptionId"], "location": s["location"]},
            finding_type="sql_server_end_of_support",
            title=title,
            description=description,
            severity=severity,
            remediation_steps="\n".join(f"{i}. {x}" for i, x in enumerate(steps, 1)),
            azure_cli_script=(f"az resource show --ids \"{s['id']}\" --query \"properties.{{version:version, "
                              f"edition:edition, build:currentVersion, status:status}}\""),
            evidence={"product": s["product"], "edition": s["edition"] or None, "build": s["build"] or None,
                      "service": s["service"] or None, "host": host, "status": s["status"] or None,
                      "support": status, "end_of_support": s["supportEnds"], "days_left": s["daysLeft"],
                      "esu": s["esu"] or None, "esu_until": s["esuUntil"], "esu_enabled": s["esuEnabled"],
                      "license": s["license"] or None, "non_production_edition": s["nonProduction"]},
            nist_control="SI-2",
            estimated_monthly_savings_usd=0.0,
        )

    def _mock_raw(self) -> Dict[str, Any]:
        vm = "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/vm-web-01"
        arc = "/subscriptions/sub-1/resourceGroups/rg-arc/providers/Microsoft.HybridCompute/machines/srv-db-01"
        return {
            "warnings": [],
            "machines": [
                {"id": vm, "key": vm.lower(), "name": "vm-web-01", "machineKind": "vm", "subscriptionId": "sub-1",
                 "resourceGroup": "rg-web", "location": "westeurope", "tags": {"environment": "prod"},
                 "osType": "Linux", "osName": "ubuntu", "osVersion": "22.04", "power": "PowerState/running"},
                {"id": arc, "key": arc.lower(), "name": "srv-db-01", "machineKind": "arc", "subscriptionId": "sub-1",
                 "resourceGroup": "rg-arc", "location": "westeurope", "tags": {},
                 "osType": "windows", "osName": "Windows Server 2019 Standard", "osVersion": "10.0.17763",
                 "agentStatus": "Connected", "esu": "NotAssigned"},
            ],
            "nics": [{"vm": vm.lower(), "publicIps": 1}],
            "extensions": [{"machine": arc.lower(), "ext": "windowsagent.sqlserver", "sqlEsu": None}],
            "plans": [{"subscriptionId": "sub-1", "tier": "Free", "plan": ""}],
            "assessments": [{"machine": arc.lower(), "va": "Unhealthy", "packages": [], "high": 0}],
            "patch_results": [{"machine": vm.lower(), "assessed": "2026-10-21T19:46:39Z", "result": "Succeeded",
                               "security": 2, "critical": 0, "other": 26, "reboot": True}],
            "patches": [{"machine": vm.lower(), "patch": "openssl", "version": "3.0.2-0ubuntu1.20"},
                        {"machine": vm.lower(), "patch": "nginx", "version": "1.18.0-6ubuntu14.8"}],
            "cves": [],
            "sql": [{"id": "/subscriptions/sub-1/resourceGroups/rg-arc/providers/Microsoft.AzureArcData/"
                           "SqlServerInstances/srv-db-01_MSSQLSERVER", "name": "srv-db-01_MSSQLSERVER",
                     "sqlType": "microsoft.azurearcdata/sqlserverinstances", "subscriptionId": "sub-1",
                     "resourceGroup": "rg-arc", "location": "westeurope", "machine": arc.lower(),
                     "version": "SQL Server 2016", "edition": "Standard", "build": "13.0.6435.1",
                     "service": "Engine", "status": "Connected", "license": "Paid"}],
        }
