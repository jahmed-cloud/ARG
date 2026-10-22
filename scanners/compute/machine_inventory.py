"""
Azure Resource Guardian - Machine inventory
===========================================
What runs on every VM and Azure Arc server and how well it is looked after - Resource Graph only, read-only:

- the operating system and version the machine reports (the image for deallocated VMs) and its end of support
  (scanners/base/lifecycle.py);
- whether a vulnerability scanner covers it: the Defender for Servers plan, the Defender for Endpoint / Qualys
  extension, Defender's "Machines should have a vulnerability assessment solution" assessment, CVE results;
- pending security / critical updates (Azure Update Manager) and packages Defender reports as outdated;
- CVEs from the vulnerability scan (Defender sub-assessments), when one runs;
- SQL Server instances (Azure Arc, SQL IaaS agent) with version, end of support and ESU;
- a public IP on the VM's network interfaces (internet-facing).

Used by the machine security scanner (one subscription) and the estate Compute view (all subscriptions): collect()
runs the queries through the caller's runner, build() turns the rows into one record per machine. Running services
and installed software need Change Tracking (Azure Monitor agent) - this inventory reports whether it is deployed.
"""

import re
from datetime import date
from typing import Any, Awaitable, Callable, Dict, List, Optional

from scanners.base.lifecycle import ENDED, ESU, UNKNOWN, identify_os, identify_sql, support
from scanners.base.naming import environment_of

VA_ASSESSMENT = "ffff0522-1e88-47fc-8382-2a80ba848f5d"   # Machines should have a vulnerability assessment solution
MACHINE_TYPES = "'microsoft.compute/virtualmachines', 'microsoft.hybridcompute/machines'"
MACHINE_ID = ("machine contains '/providers/microsoft.compute/virtualmachines/' "
              "or machine contains '/providers/microsoft.hybridcompute/machines/'")
MAX_NAMES = 25      # package / patch names kept per machine
MAX_CVES = 500

QUERIES: Dict[str, str] = {
    "machines": f"""
resources
| where type in~ ({MACHINE_TYPES})
| extend p = properties, arc = type =~ 'microsoft.hybridcompute/machines'
| project id, key = tolower(id), name, machineKind = iff(arc, 'arc', 'vm'), subscriptionId = tolower(subscriptionId),
          resourceGroup, location, tags,
          osType = tostring(coalesce(p.storageProfile.osDisk.osType, p.osType)),
          osName = iff(arc, tostring(coalesce(p.osSku, p.osName)), tostring(p.extended.instanceView.osName)),
          osVersion = iff(arc, tostring(p.osVersion), tostring(p.extended.instanceView.osVersion)),
          publisher = tostring(p.storageProfile.imageReference.publisher),
          offer = tostring(p.storageProfile.imageReference.offer),
          sku = tostring(p.storageProfile.imageReference.sku),
          power = tostring(p.extended.instanceView.powerState.code),
          agentStatus = tostring(p.status), lastSeen = tostring(p.lastStatusChange),
          vmSize = tostring(p.hardwareProfile.vmSize),
          computer = tostring(coalesce(p.osProfile.computerName, p.machineFqdn)),
          assessmentMode = tostring(coalesce(p.osProfile.windowsConfiguration.patchSettings.assessmentMode,
                                             p.osProfile.linuxConfiguration.patchSettings.assessmentMode)),
          esu = tostring(p.licenseProfile.esuProfile.licenseAssignmentState)
""",
    "nics": """
resources
| where type =~ 'microsoft.network/networkinterfaces'
| extend vm = tolower(tostring(properties.virtualMachine.id))
| where isnotempty(vm)
| mv-expand ipc = properties.ipConfigurations
| summarize publicIps = countif(isnotempty(tostring(ipc.properties.publicIPAddress.id))) by vm
""",
    "extensions": """
resources
| where type in~ ('microsoft.compute/virtualmachines/extensions', 'microsoft.hybridcompute/machines/extensions')
| project machine = tostring(split(tolower(id), '/extensions/')[0]), ext = tolower(tostring(properties.type)),
          sqlEsu = tobool(properties.settings.enableExtendedSecurityUpdates)
""",
    "plans": """
securityresources
| where type =~ 'microsoft.security/pricings' and name =~ 'VirtualMachines'
| project subscriptionId = tolower(subscriptionId), tier = tostring(properties.pricingTier),
          plan = tostring(properties.subPlan)
""",
    "assessments": f"""
securityresources
| where type =~ 'microsoft.security/assessments'
| extend machine = tolower(tostring(properties.resourceDetails.Id))
| where {MACHINE_ID}
| extend d = tostring(properties.displayName), status = tostring(properties.status.code)
| where name == '{VA_ASSESSMENT}' or (d startswith 'Update ' and status =~ 'Unhealthy')
| summarize va = take_anyif(status, name == '{VA_ASSESSMENT}'),
            packages = make_set_if(substring(d, 7), d startswith 'Update ', 400),
            high = countif(d startswith 'Update ' and tostring(properties.metadata.severity) =~ 'High')
          by machine
""",
    "patch_results": """
patchassessmentresources
| where type endswith '/patchassessmentresults'
| project machine = tostring(split(tolower(id), '/patchassessmentresults/')[0]),
          assessed = tostring(properties.lastModifiedDateTime), result = tostring(properties.status),
          security = toint(properties.availablePatchCountByClassification.security),
          critical = toint(properties.availablePatchCountByClassification.critical),
          other = toint(properties.availablePatchCountByClassification.other),
          reboot = tobool(properties.rebootPending)
""",
    "patches": """
patchassessmentresources
| where type endswith '/patchassessmentresults/softwarepatches'
| extend c = tostring(properties.classifications)
| where c has 'Security' or c has 'Critical'
| project machine = tostring(split(tolower(id), '/patchassessmentresults/')[0]),
          patch = tostring(properties.patchName), version = tostring(properties.version)
""",
    "cves": f"""
securityresources
| where type =~ 'microsoft.security/assessments/subassessments'
| extend machine = tostring(split(tolower(id), '/providers/microsoft.security/')[0])
| where {MACHINE_ID}
| where tostring(properties.status.code) =~ 'Unhealthy'
| extend found = extract_all(@'(CVE-\\d{{4}}-\\d{{4,7}})', tostring(properties))
| mv-expand cve = found to typeof(string)
| where isnotempty(cve)
| summarize severity = take_any(tolower(tostring(properties.status.severity))) by machine, cve
""",
    "sql": """
resources
| where type in~ ('microsoft.azurearcdata/sqlserverinstances', 'microsoft.sqlvirtualmachine/sqlvirtualmachines')
| extend p = properties
| project id, name, sqlType = tolower(type), subscriptionId = tolower(subscriptionId), resourceGroup,
          location, machine = tolower(tostring(coalesce(p.containerResourceId, p.virtualMachineResourceId))),
          version = tostring(p.version), edition = tostring(coalesce(p.edition, p.sqlImageSku)),
          build = tostring(coalesce(p.currentVersion, p.patchLevel)), offer = tostring(p.sqlImageOffer),
          service = tostring(p.serviceType), status = tostring(p.status),
          license = tostring(coalesce(p.licenseType, p.sqlServerLicenseType))
""",
}

# extension type -> agent name shown in the inventory
AGENTS = {
    "mde.windows": "Defender for Endpoint", "mde.linux": "Defender for Endpoint",
    "windowsagent.azuresecuritycenter": "Qualys", "linuxagent.azuresecuritycenter": "Qualys",
    "azuremonitorwindowsagent": "Azure Monitor agent", "azuremonitorlinuxagent": "Azure Monitor agent",
    "microsoftmonitoringagent": "Log Analytics agent (retired)", "omsagentforlinux": "Log Analytics agent (retired)",
    "changetracking-windows": "Change Tracking", "changetracking-linux": "Change Tracking",
    "dependencyagentwindows": "Dependency agent", "dependencyagentlinux": "Dependency agent",
    "windowspatchextension": "Update Manager", "linuxpatchextension": "Update Manager",
    "windowsagent.sqlserver": "SQL Server (Arc)", "sqliaasagent": "SQL IaaS agent", "sqliaasagentlinux": "SQL IaaS agent",
}
SCANNER_AGENTS = {"Defender for Endpoint", "Qualys"}
COVERED, NONE, UNVERIFIED = "covered", "none", "unverified"
NON_PRODUCTION_SQL = re.compile(r"developer|express|evaluation", re.I)


async def collect(run: Callable[[str], Awaitable[Optional[List[Dict[str, Any]]]]]) -> Dict[str, Any]:
    """Every query through `run` (one subscription or many); a failed query gives no rows and a warning."""
    rows: Dict[str, Any] = {"warnings": []}
    for key, query in QUERIES.items():
        try:
            rows[key] = list(await run(query) or [])
        except Exception as exc:   # one missing source (e.g. no patch data access) must not lose the rest
            rows[key] = []
            rows["warnings"].append(f"{key}: {str(exc)[:200]}")
    return rows


def _defender(plan_row: Optional[Dict[str, Any]]) -> str:
    if not plan_row:
        return ""
    if (plan_row.get("tier") or "").lower() != "standard":
        return "Free"
    return plan_row.get("plan") or "P2"


def _state(m: Dict[str, Any]) -> tuple:
    """(running, state label) - a VM's power state, an Arc server's agent status."""
    if m.get("machineKind") == "arc":
        status = m.get("agentStatus") or "Unknown"
        return status.lower() == "connected", status
    power = (m.get("power") or "").split("/")[-1]
    return power.lower() == "running", power or "unknown"


def _scanner(agents: List[str], va: str, plan: str, cves: Optional[Dict[str, Any]]) -> tuple:
    """(covered / none / unverified, why)."""
    if cves:
        return COVERED, "vulnerability scan results (CVEs) reported"
    if "Qualys" in agents:
        return COVERED, "Qualys vulnerability scanner (Defender)"
    if va == "Healthy":
        return COVERED, "Defender: a vulnerability assessment solution is installed"
    if "Defender for Endpoint" in agents and plan in ("P1", "P2"):
        return COVERED, f"Defender for Endpoint with Defender for Servers {plan}"
    if va == "Unhealthy":
        return NONE, "Defender: no vulnerability assessment solution on this machine"
    if plan in ("", "Free"):
        return NONE, "Defender for Servers is off for the subscription and no scanner agent is visible"
    return UNVERIFIED, f"Defender for Servers {plan} is on, but no scanner agent or assessment is visible yet"


def sql_record(s: Dict[str, Any], esu_enabled: Optional[bool], as_of: date) -> Dict[str, Any]:
    product = identify_sql(s.get("version"), s.get("build"), s.get("offer"))
    sup = support(product, as_of, esu_assigned=esu_enabled)
    return {"id": s.get("id"), "name": s.get("name"), "subscriptionId": s.get("subscriptionId"),
            "resourceGroup": s.get("resourceGroup"), "location": s.get("location"), "type": s.get("sqlType"),
            "machine": s.get("machine") or "", "product": product.label if product else (s.get("version") or ""),
            "edition": s.get("edition") or "", "build": s.get("build") or "", "service": s.get("service") or "",
            "status": s.get("status") or "", "license": s.get("license") or "",
            "nonProduction": bool(NON_PRODUCTION_SQL.search(s.get("edition") or "")),
            "support": sup.status, "supportEnds": sup.ends.isoformat() if sup.ends else None,
            "daysLeft": sup.days_left, "supportNote": sup.note, "esu": product.esu if product else "",
            "esuUntil": product.esu_until if product else None, "esuEnabled": esu_enabled}


def build(raw: Dict[str, Any], as_of: Optional[date] = None,
          sub_names: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """{"machines": [...], "sql": [...]} - one record per machine, SQL instances also listed on their host."""
    today = as_of or date.today()
    names = sub_names or {}
    plans = {r.get("subscriptionId"): r for r in raw.get("plans") or []}
    public = {r["vm"]: bool(r.get("publicIps")) for r in raw.get("nics") or [] if r.get("vm")}
    agents: Dict[str, set] = {}
    sql_esu: Dict[str, bool] = {}
    for e in raw.get("extensions") or []:
        machine = e.get("machine") or ""
        name = AGENTS.get(e.get("ext") or "")
        if name:
            agents.setdefault(machine, set()).add(name)
        if e.get("ext") == "windowsagent.sqlserver" and e.get("sqlEsu") is not None:
            sql_esu[machine] = bool(e.get("sqlEsu"))
    assessments = {r.get("machine"): r for r in raw.get("assessments") or []}
    results = {r.get("machine"): r for r in raw.get("patch_results") or []}
    patch_names: Dict[str, List[str]] = {}
    for p in raw.get("patches") or []:
        label = " ".join(x for x in (p.get("patch"), p.get("version")) if x)
        patch_names.setdefault(p.get("machine") or "", []).append(label)
    cves: Dict[str, Dict[str, str]] = {}
    for c in raw.get("cves") or []:
        cves.setdefault(c.get("machine") or "", {})[c["cve"]] = c.get("severity") or ""
    sql = [sql_record(s, sql_esu.get(s.get("machine") or ""), today) for s in raw.get("sql") or []]
    sql_by_machine: Dict[str, List[Dict[str, Any]]] = {}
    for s in sql:
        sql_by_machine.setdefault(s["machine"], []).append(s)

    machines = []
    for m in raw.get("machines") or []:
        mid = m.get("key") or (m.get("id") or "").lower()
        arc = m.get("machineKind") == "arc"
        running, state = _state(m)
        product = identify_os(m.get("osName"), m.get("osVersion"), m.get("offer"), m.get("sku"), m.get("publisher"))
        sup = support(product, today, esu_assigned=(m.get("esu") or "").lower() == "assigned")
        reported = " ".join(x for x in (m.get("osName"), m.get("osVersion")) if x)
        mine = sorted(agents.get(mid, set()))
        a = assessments.get(mid) or {}
        plan = _defender(plans.get(m.get("subscriptionId")))
        found = cves.get(mid) or {}
        cve = ({"count": len(found), "critical": sum(1 for s in found.values() if s == "critical"),
                "high": sum(1 for s in found.values() if s == "high"),
                "ids": sorted(found, key=lambda k: ({"critical": 0, "high": 1}.get(found[k], 2), k))[:MAX_CVES]}
               if found else None)
        scanner, scanner_note = _scanner(mine, a.get("va") or "", plan, cve)
        r = results.get(mid)
        patches = None
        if r:
            pending = sorted(set(patch_names.get(mid, [])))
            patches = {"assessed": r.get("assessed") or None, "result": r.get("result") or "",
                       "security": r.get("security") or 0, "critical": r.get("critical") or 0,
                       "other": r.get("other") or 0, "reboot": bool(r.get("reboot")), "names": pending[:MAX_NAMES],
                       "more": max(0, len(pending) - MAX_NAMES)}
        pkgs = sorted(a.get("packages") or [])
        packages = ({"count": len(pkgs), "high": a.get("high") or 0, "names": pkgs[:MAX_NAMES],
                     "more": max(0, len(pkgs) - MAX_NAMES)} if pkgs else None)
        public_ip = None if arc else public.get(mid, False)
        reasons = []
        if sup.status == ENDED:
            reasons.append(f"{sup.product.label}: {sup.note}")
        if patches and (patches["security"] or patches["critical"]):
            reasons.append(f"{patches['security'] + patches['critical']} security / critical update(s) pending")
        if packages and packages["high"]:
            reasons.append(f"{packages['high']} outdated package(s) Defender rates high")
        if cve and (cve["critical"] or cve["high"]):
            reasons.append(f"{cve['critical']} critical / {cve['high']} high CVE(s)")
        weaknesses = list(reasons)   # known weaknesses; a missing scanner is a blind spot, not a known weakness
        if scanner == NONE:
            reasons.append("no vulnerability scanner")
        exposed = bool(running and public_ip)
        machines.append({
            "id": m.get("id") or mid, "key": mid, "name": m.get("name") or "", "kind": "arc" if arc else "vm",
            "subscriptionId": m.get("subscriptionId") or "",
            "subscription": names.get(m.get("subscriptionId") or "") or m.get("subscriptionId") or "",
            "resourceGroup": m.get("resourceGroup") or "", "location": (m.get("location") or "").lower(),
            "env": environment_of({"tags": m.get("tags"), "name": m.get("name"),
                                   "resourceGroup": m.get("resourceGroup")}, names.get(m.get("subscriptionId"), "")),
            "running": running, "state": state, "lastSeen": (m.get("lastSeen") or None) if arc else None,
            "computer": m.get("computer") or "", "size": m.get("vmSize") or "", "osType": m.get("osType") or "",
            "os": sup.product.label if sup.product else (reported or m.get("osType") or ""),
            "osReported": reported, "osSource": "machine" if reported else ("image" if m.get("offer") else ""),
            "image": " ".join(x for x in (m.get("offer"), m.get("sku")) if x),
            "family": sup.product.family if sup.product else "",
            "support": sup.status, "supportEnds": sup.ends.isoformat() if sup.ends else None,
            "daysLeft": sup.days_left, "supportNote": sup.note,
            "esu": (m.get("esu") or "") if arc else "",
            "publicIp": public_ip, "defenderPlan": plan, "agents": mine,
            "scanner": scanner, "scannerNote": scanner_note,
            "patchAssessment": (m.get("assessmentMode") or "") or None,
            "patches": patches, "packages": packages, "cves": cve,
            "sql": sql_by_machine.get(mid, []),
            "changeTracking": "Change Tracking" in mine,
            "exposed": exposed,
            # internet-facing with a known weakness: what an attacker scanning the internet finds first
            "criticalPath": bool(exposed and weaknesses),
            "reasons": reasons,
        })
    return {"machines": machines, "sql": sql}


def summary(machines: List[Dict[str, Any]], sql: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Counts the Compute view shows above the table."""
    def count(pred) -> int:
        return sum(1 for m in machines if pred(m))
    families: Dict[str, int] = {}
    for m in machines:
        families[m["family"] or "Not identified"] = families.get(m["family"] or "Not identified", 0) + 1
    return {
        "machines": len(machines), "vms": count(lambda m: m["kind"] == "vm"),
        "arc": count(lambda m: m["kind"] == "arc"), "running": count(lambda m: m["running"]),
        "families": dict(sorted(families.items(), key=lambda kv: -kv[1])),
        "support": {s: count(lambda m, s=s: m["support"] == s)
                    for s in (ENDED, ESU, "ending", "supported", UNKNOWN, "appliance")},
        "noScanner": count(lambda m: m["running"] and m["scanner"] == NONE),
        "noScannerExposed": count(lambda m: m["exposed"] and m["scanner"] == NONE),
        "criticalPath": count(lambda m: m["criticalPath"]),
        "publicIp": count(lambda m: m["exposed"]),
        "pendingSecurity": count(lambda m: bool(m["patches"] and (m["patches"]["security"] or m["patches"]["critical"]))),
        "arcStale": count(lambda m: m["kind"] == "arc" and not m["running"]),
        "sources": {"osReported": count(lambda m: m["osSource"] == "machine"),
                    "patchAssessment": count(lambda m: m["patches"] is not None),
                    "defenderPackages": count(lambda m: m["packages"] is not None),
                    "cveScan": count(lambda m: m["cves"] is not None),
                    "changeTracking": count(lambda m: m["changeTracking"])},
        "sql": {"instances": len(sql), "ended": sum(1 for s in sql if s["support"] == ENDED),
                "ending": sum(1 for s in sql if s["support"] == "ending"),
                "esu": sum(1 for s in sql if s["support"] == ESU)},
    }
