"""
Compute view of the estate: which operating system and version every VM and Azure Arc server runs, its end of
support, whether a vulnerability scanner covers it, pending security updates, outdated packages, CVEs and SQL Server
instances - plus the language runtime of every App Service app. Collected with the estate refresh (read-only
Resource Graph, scanners/compute/machine_inventory.py) and stored next to estate.json as compute.json (local portal)
or under the snapshot's "compute" key (Docker); the Compute pages search it by name, OS, version, package, patch,
SQL Server version, runtime or CVE ID.
"""

from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from scanners.base.lifecycle import ENDED, ENDING, ENDING_DAYS, SUPPORTED, UNKNOWN, runtime_end_of_support
from scanners.compute import machine_inventory

APP_TYPES = ("microsoft.web/sites", "microsoft.web/sites/slots")
STACK_NAMES = {"dotnetcore": ".NET", "dotnet": ".NET", "dotnet-isolated": ".NET isolated", "node": "Node.js", "python": "Python", "php": "PHP",
               "java": "Java", "tomcat": "Tomcat", "jbosseap": "JBoss EAP", "powershell": "PowerShell",
               "docker": "Container", "compose": "Compose"}
CONTAINER_STACKS = {"docker", "compose"}


async def collect_compute(client: Any, subscription_ids: List[str], arg_rows) -> Dict[str, Any]:
    """The machine inventory rows for these subscriptions (arg_rows(client, query, subscriptions) pages ARG)."""
    return await machine_inventory.collect(lambda query: arg_rows(client, query, subscription_ids))


def _app_kind(kind: str) -> str:
    k = (kind or "").lower()
    base = "Function app" if "functionapp" in k else "Logic app" if "workflowapp" in k else "Web app"
    return f"{base} ({'Linux' if 'linux' in k else 'Windows'})"


def app_record(row: Dict[str, Any], sub_names: Dict[str, str], exposures: Dict[str, str],
               as_of: date) -> Optional[Dict[str, Any]]:
    """An App Service app with its language runtime and where that runtime stands; None without a runtime stack."""
    cfg = row.get("cfg") if isinstance(row.get("cfg"), dict) else {}
    fx = str(cfg.get("fx") or "")
    if "|" not in fx:
        return None
    stack, version = fx.split("|", 1)
    stack_key = stack.lower()
    hit = runtime_end_of_support(f"{stack_key}|{version.lower()}")
    if stack_key in CONTAINER_STACKS:
        status, ends, note = UNKNOWN, None, "custom container - the runtime and its version are inside the image"
    elif hit:
        label, eos = hit
        days = (eos - as_of).days
        status = ENDED if days < 0 else ENDING if days <= ENDING_DAYS else SUPPORTED
        ends = eos.isoformat()
        note = (f"{label} support ended {ends}" if days < 0 else f"{label} support ends {ends} (in {days} days)"
                if status == ENDING else f"supported until {ends}")
    else:
        status, ends, note = SUPPORTED, None, "no end-of-support date reached or tracked"
    sid = (row.get("subscriptionId") or "").lower()
    rid = row.get("id") or ""
    return {"id": rid, "name": row.get("name") or "", "subscriptionId": sid,
            "subscription": sub_names.get(sid) or sid, "resourceGroup": row.get("resourceGroup") or "",
            "kind": _app_kind(row.get("kind") or ""), "slot": (row.get("type") or "").lower().endswith("/slots"),
            "stack": STACK_NAMES.get(stack_key, stack), "version": version,
            "runtime": f"{STACK_NAMES.get(stack_key, stack)} {version}",
            "support": status, "supportEnds": ends, "supportNote": note,
            "exposure": exposures.get(rid.lower(), ""), "state": row.get("resourceState") or ""}


def build_compute(raw: Dict[str, Any], sub_names: Dict[str, str], resources: Iterable[Dict[str, Any]] = (),
                  paas: Iterable[Dict[str, Any]] = (), as_of: Optional[date] = None) -> Dict[str, Any]:
    """The Compute view payload from the machine inventory rows, the estate rows (apps) and the network PaaS list."""
    from scripts.subscription_analysis.network import EXPOSURE_LABELS, exposure

    today = as_of or date.today()
    inventory = machine_inventory.build(raw, today, sub_names)
    exposures = {(p.get("id") or "").lower(): EXPOSURE_LABELS.get(exposure(p), "") for p in paas or []}
    apps = [a for a in (app_record(r, sub_names, exposures, today) for r in resources or []
                        if (r.get("type") or "").lower() in APP_TYPES) if a]
    for s in inventory["sql"]:
        s["subscription"] = sub_names.get(s.get("subscriptionId") or "") or s.get("subscriptionId") or ""
    return finish({"collected_at": datetime.now(timezone.utc).isoformat(), "as_of": today.isoformat(),
                   "machines": inventory["machines"], "sql": inventory["sql"], "apps": apps,
                   "warnings": list(raw.get("warnings") or [])})


def finish(compute: Dict[str, Any]) -> Dict[str, Any]:
    """Sort and (re)count - also after merging several tenants."""
    compute["machines"].sort(key=lambda m: (not m["criticalPath"], m["subscription"].lower(), m["name"].lower()))
    compute["apps"].sort(key=lambda a: (a["stack"].lower(), a["version"], a["name"].lower()))
    compute["summary"] = machine_inventory.summary(compute["machines"], compute["sql"])
    apps = compute["apps"]
    compute["summary"]["apps"] = {"total": len(apps), "ended": sum(1 for a in apps if a["support"] == ENDED),
                                  "ending": sum(1 for a in apps if a["support"] == ENDING),
                                  "stacks": _stacks(apps)}
    return compute


def _stacks(apps: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for a in apps:
        out[a["runtime"]] = out.get(a["runtime"], 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


def merge_compute(parts: Iterable[Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    """One Compute payload from several tenants' payloads (Docker: one estate refresh per connected tenant)."""
    good = [p for p in parts if p and not p.get("error") and "machines" in p]
    if not good:
        return {}
    return finish({"collected_at": min(p.get("collected_at") or "" for p in good) or None,
                   "as_of": good[0].get("as_of"),
                   "machines": [m for p in good for m in p["machines"]], "sql": [s for p in good for s in p["sql"]],
                   "apps": [a for p in good for a in p.get("apps") or []],
                   "warnings": [w for p in good for w in p.get("warnings") or []]})


def markdown(compute: Optional[Dict[str, Any]]) -> str:
    """Compute section of the estate overview (README / overview.md)."""
    if not compute or not compute.get("summary"):
        return ""
    s = compute["summary"]
    sup, sql, src = s["support"], s["sql"], s["sources"]
    lines = ["## Compute: operating systems, patching and vulnerability scanning", "",
             f"{s['machines']} machines ({s['vms']} VMs, {s['arc']} Azure Arc servers), {s['running']} running or "
             f"connected. Collected {str(compute.get('collected_at') or '')[:16].replace('T', ' ')} UTC.", "",
             "| | Machines |", "|---|---:|",
             f"| Operating system past end of support | {sup.get('ended', 0)} |",
             f"| On Extended Security Updates | {sup.get('esu', 0)} |",
             f"| Support ends within {ENDING_DAYS} days | {sup.get('ending', 0)} |",
             f"| Running with a public IP | {s['publicIp']} |",
             f"| Internet-facing with a known weakness (critical path) | {s['criticalPath']} |",
             f"| Running without a vulnerability scanner | {s['noScanner']} ({s['noScannerExposed']} internet-facing) |",
             f"| Security / critical updates pending | {s['pendingSecurity']} |",
             f"| Arc agent disconnected or expired | {s['arcStale']} |", "",
             f"SQL Server: {sql['instances']} instances, {sql['ended']} past end of support, {sql['ending']} ending "
             f"within {ENDING_DAYS} days, {sql['esu']} on Extended Security Updates.", "",
             "Operating system families: " + ", ".join(f"{k} {v}" for k, v in s["families"].items()) + ".", ""]
    apps = s.get("apps") or {}
    if apps.get("total"):
        lines += [f"App Service runtimes: {apps['total']} apps, {apps['ended']} on a runtime past end of support, "
                  f"{apps['ending']} ending soon. " + ", ".join(f"{k} {v}" for k, v in list(apps["stacks"].items())[:12])
                  + ".", ""]
    lines += [f"Data sources: OS reported by {src['osReported']} machines, Update Manager assessment on "
              f"{src['patchAssessment']}, Defender package findings on {src['defenderPackages']}, CVE results on "
              f"{src['cveScan']}, Change Tracking on {src['changeTracking']}. Installed software and running services "
              "need Change Tracking (Azure Monitor agent); CVEs need a vulnerability scanner (Defender for Servers).",
              ""]
    return "\n".join(lines)
