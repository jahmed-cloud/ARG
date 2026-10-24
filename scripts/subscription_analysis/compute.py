"""
Compute view of the estate: which operating system and version every VM and Azure Arc server runs, its end of
support, whether a vulnerability scanner covers it, pending security updates, outdated packages, CVEs and SQL Server
instances - plus the language runtime of every App Service app. Collected with the estate refresh (read-only
Resource Graph, scanners/compute/machine_inventory.py) and stored next to estate.json as compute.json (local portal)
or under the snapshot's "compute" key (Docker); the Compute pages search it by name, OS, version, package, patch,
SQL Server version, runtime or CVE ID. Container images: every container Container Apps, Container Apps jobs, Container
Instances and App Service custom containers run, with the packages Defender reports outdated in that image.
"""
import json

from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from scanners.base.lifecycle import ENDED, ENDING, ENDING_DAYS, SUPPORTED, UNKNOWN, runtime_end_of_support
from scanners.compute import machine_inventory
from scripts.subscription_analysis.network import (EXPOSURE_LABELS, INTERNET_FACING, container_exposure, exposure,
                                                   web_endpoint)

APP_TYPES = ("microsoft.web/sites", "microsoft.web/sites/slots")
STACK_NAMES = {"dotnetcore": ".NET", "dotnet": ".NET", "dotnet-isolated": ".NET isolated", "node": "Node.js", "python": "Python", "php": "PHP",
               "java": "Java", "tomcat": "Tomcat", "jbosseap": "JBoss EAP", "powershell": "PowerShell",
               "docker": "Container", "compose": "Compose"}
CONTAINER_STACKS = {"docker", "compose"}
INTERNET_LABELS = {EXPOSURE_LABELS[k] for k in INTERNET_FACING}   # exposure labels that mean internet-facing

IMAGE_QUERY = """
resources
| where type in~ ('microsoft.app/containerapps', 'microsoft.app/jobs', 'microsoft.containerinstance/containergroups',
                  'microsoft.web/sites', 'microsoft.web/sites/slots')
| extend fx = tostring(coalesce(properties.siteConfig.linuxFxVersion, properties.siteConfig.windowsFxVersion))
| where type !in~ ('microsoft.web/sites', 'microsoft.web/sites/slots') or fx startswith 'DOCKER|'
| extend containers = case(type in~ ('microsoft.app/containerapps', 'microsoft.app/jobs'),
                           array_concat(coalesce(properties.template.containers, dynamic([])),
                                        coalesce(properties.template.initContainers, dynamic([]))),
                           type =~ 'microsoft.containerinstance/containergroups',
                           array_concat(coalesce(properties.containers, dynamic([])),
                                        coalesce(properties.initContainers, dynamic([]))),
                           pack_array(pack('image', substring(fx, 7), 'name', '')))
| mv-expand c = containers
| project id, name, type = tolower(type), kind, subscriptionId = tolower(subscriptionId), resourceGroup, location,
          image = tostring(coalesce(c.image, c.properties.image)), container = tostring(c.name),
          fqdn = tostring(properties.configuration.ingress.fqdn),
          external = tobool(properties.configuration.ingress.external), ipType = tostring(properties.ipAddress.type),
          environment = tolower(tostring(coalesce(properties.managedEnvironmentId, properties.environmentId))),
          access = tostring(properties.publicNetworkAccess), pe = array_length(properties.privateEndpointConnections),
          state = tostring(coalesce(properties.runningStatus, properties.state, properties.instanceView.state,
                                    properties.provisioningState))
"""
# packages Defender's container scanning reports outdated, per image (registry, repository, tags, digest)
IMAGE_FINDINGS_QUERY = """
securityresources
| where type =~ 'microsoft.security/assessments'
| where tostring(properties.resourceDetails.ResourceType) =~ '.containerimage'
| where tostring(properties.status.code) =~ 'Unhealthy'
| extend d = tostring(properties.displayName), extra = parse_json(tostring(properties.resourceAdditionalData))
| where d startswith 'Update '
| summarize packages = make_set(substring(d, 7), 400), high = countif(tostring(properties.metadata.severity) =~ 'High')
          by host = tolower(tostring(extra.RepositoryDetails.RegistryHost)),
             repo = tolower(tostring(extra.RepositoryDetails.RepositoryName)), tags = tostring(extra.Tags),
             digest = tolower(tostring(extra.Digest))
"""
# 'external' ingress of an app in a VNet-internal environment reaches the VNet, not the internet
ENVIRONMENT_QUERY = """
resources
| where type =~ 'microsoft.app/managedenvironments'
| project id = tolower(id), internal = tobool(properties.vnetConfiguration.internal)
"""
IMAGE_KINDS = {"microsoft.app/containerapps": "Container App", "microsoft.app/jobs": "Container Apps job",
               "microsoft.containerinstance/containergroups": "Container Instance",
               "microsoft.web/sites": "App Service (container)", "microsoft.web/sites/slots": "App Service (container)"}


async def collect_compute(client: Any, subscription_ids: List[str], arg_rows) -> Dict[str, Any]:
    """The machine inventory rows for these subscriptions (arg_rows(client, query, subscriptions) pages ARG), plus
    the container images in use and Defender's findings on them."""
    raw = await machine_inventory.collect(lambda query: arg_rows(client, query, subscription_ids))
    for key, query in (("images", IMAGE_QUERY), ("image_findings", IMAGE_FINDINGS_QUERY),
                       ("environments", ENVIRONMENT_QUERY)):
        try:
            raw[key] = list(await arg_rows(client, query, subscription_ids) or [])
        except Exception as exc:   # the machines stand without the images
            raw[key] = []
            raw.setdefault("warnings", []).append(f"{key}: {str(exc)[:200]}")
    return raw


def parse_image(ref: str) -> Dict[str, str]:
    """'acr.azurecr.io/team/api:1.4.1' -> registry, repository, tag, digest; Docker Hub names normalised."""
    ref = (ref or "").strip()
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    first = ref.split("/", 1)[0]
    if "/" in ref and ("." in first or ":" in first or first == "localhost"):
        registry, rest = first.lower(), ref.split("/", 1)[1]
    else:
        registry, rest = "docker.io", ref
    tag = ""
    if ":" in rest.rsplit("/", 1)[-1]:
        rest, tag = rest.rsplit(":", 1)
    repo = rest.lower()
    if registry == "docker.io" and "/" not in repo:
        repo = f"library/{repo}"
    return {"registry": registry, "repository": repo, "tag": tag or ("" if digest else "latest"),
            "digest": digest.lower()}


def _registry_label(registry: str) -> str:
    if registry.endswith(".azurecr.io"):
        return "Azure Container Registry"
    return {"docker.io": "Docker Hub", "mcr.microsoft.com": "Microsoft (MCR)", "ghcr.io": "GitHub"}.get(registry, registry)


def image_exposure(row: Dict[str, Any], internal: Iterable[str]) -> str:
    """network.py exposure key of the workload a container runs in."""
    rtype = (row.get("type") or "").lower()
    if rtype in ("microsoft.web/sites", "microsoft.web/sites/slots"):
        return exposure({"type": rtype, "public": row.get("access") or "", "pe": row.get("pe") or 0})
    return container_exposure(rtype, row.get("fqdn"), row.get("external"),
                              (row.get("environment") or "").lower() in internal, row.get("ipType"))


# Defender (Defender for Containers / CSPM) reports outdated packages of images in Azure Container Registry, and only
# unhealthy ones: an image without findings is up to date or was not scanned - Resource Graph cannot tell which.
SCAN_FINDINGS, SCAN_OTHER_TAGS, SCAN_NONE, SCAN_OUTSIDE = ("outdated packages", "no findings for this tag",
                                                           "no Defender findings", "not in Azure Container Registry")


def scan_status(img: Dict[str, str], found: Optional[Dict[str, Any]], scanned_repos: set) -> str:
    if found:
        return SCAN_FINDINGS
    if (img["registry"], img["repository"]) in scanned_repos:
        return SCAN_OTHER_TAGS   # other tags of this repository have findings: Defender scans it
    return SCAN_NONE if img["registry"].endswith(".azurecr.io") else SCAN_OUTSIDE


def image_records(raw: Dict[str, Any], sub_names: Dict[str, str]) -> List[Dict[str, Any]]:
    """One record per container of a workload, with the Defender findings of exactly that image."""
    internal = {(e.get("id") or "").lower() for e in raw.get("environments") or [] if e.get("internal")}
    findings: Dict[tuple, Dict[str, Any]] = {}
    for f in raw.get("image_findings") or []:
        try:
            tags = json.loads(f.get("tags") or "[]")
        except ValueError:
            tags = []
        entry = {"packages": sorted(f.get("packages") or []), "high": f.get("high") or 0}
        for tag in tags if isinstance(tags, list) else []:
            findings[(f.get("host"), f.get("repo"), str(tag).lower())] = entry
        if f.get("digest"):
            findings[(f.get("host"), f.get("repo"), f.get("digest"))] = entry
    scanned_repos = {(f.get("host"), f.get("repo")) for f in raw.get("image_findings") or []}
    out = []
    for r in raw.get("images") or []:
        if not r.get("image"):
            continue
        img = parse_image(r["image"])
        found = findings.get((img["registry"], img["repository"], img["digest"] or img["tag"].lower()))
        kind = IMAGE_KINDS.get(r.get("type"), r.get("type"))
        reach = image_exposure(r, internal)
        sid = r.get("subscriptionId") or ""
        container = r.get("container") or ""
        out.append({"id": r.get("id"), "name": r.get("name") + (f" / {container}" if container and container != r.get("name")
                                                                else ""),
                    "workload": r.get("name"), "kind": kind, "subscriptionId": sid,
                    "subscription": sub_names.get(sid) or sid, "resourceGroup": r.get("resourceGroup") or "",
                    "image": r["image"], "registry": img["registry"], "registryLabel": _registry_label(img["registry"]),
                    "repository": img["repository"], "tag": img["tag"], "digest": img["digest"],
                    "exposed": reach in INTERNET_FACING, "exposure": EXPOSURE_LABELS[reach],
                    "url": f"https://{r['fqdn'].lower()}" if r.get("fqdn") else "",
                    "running": (r.get("state") or "").lower() not in ("stopped", "suspended", "failed"),
                    "state": r.get("state") or "",
                    "scan": scan_status(img, found, scanned_repos),
                    "packages": (found or {}).get("packages") or [], "high": (found or {}).get("high") or 0})
    out.sort(key=lambda i: (not i["exposed"], i["subscription"].lower(), i["name"].lower()))
    return out


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
    endpoint = web_endpoint(row.get("type") or "", cfg) or {}
    reach = exposures.get(rid.lower()) or endpoint.get("exposure") or ""
    return {"id": rid, "name": row.get("name") or "", "subscriptionId": sid,
            "subscription": sub_names.get(sid) or sid, "resourceGroup": row.get("resourceGroup") or "",
            "kind": _app_kind(row.get("kind") or ""), "slot": (row.get("type") or "").lower().endswith("/slots"),
            "stack": STACK_NAMES.get(stack_key, stack), "version": version,
            "runtime": f"{STACK_NAMES.get(stack_key, stack)} {version}",
            "support": status, "supportEnds": ends, "supportNote": note,
            "exposure": reach, "internet": reach in INTERNET_LABELS, "host": endpoint.get("host") or "",
            "domains": endpoint.get("domains") or [], "urls": urls(endpoint), "state": row.get("resourceState") or "",
            "running": (row.get("resourceState") or "").lower() != "stopped"}


def urls(endpoint: Optional[Dict[str, Any]]) -> List[str]:
    """Custom domains first, then the platform hostname, as https:// URLs."""
    endpoint = endpoint or {}
    names = list(endpoint.get("domains") or []) + ([endpoint["host"]] if endpoint.get("host") else [])
    return [f"https://{n}" for n in names]


def build_compute(raw: Dict[str, Any], sub_names: Dict[str, str], resources: Iterable[Dict[str, Any]] = (),
                  paas: Iterable[Dict[str, Any]] = (), as_of: Optional[date] = None) -> Dict[str, Any]:
    """The Compute view payload from the machine inventory rows, the estate rows (apps) and the network PaaS list."""
    today = as_of or date.today()
    inventory = machine_inventory.build(raw, today, sub_names)
    exposures = {(p.get("id") or "").lower(): EXPOSURE_LABELS.get(exposure(p), "") for p in paas or []}
    apps = [a for a in (app_record(r, sub_names, exposures, today) for r in resources or []
                        if (r.get("type") or "").lower() in APP_TYPES) if a]
    for s in inventory["sql"]:
        s["subscription"] = sub_names.get(s.get("subscriptionId") or "") or s.get("subscriptionId") or ""
    return finish({"collected_at": datetime.now(timezone.utc).isoformat(), "as_of": today.isoformat(),
                   "machines": inventory["machines"], "sql": inventory["sql"], "apps": apps,
                   "images": image_records(raw, sub_names), "warnings": list(raw.get("warnings") or [])})


def finish(compute: Dict[str, Any]) -> Dict[str, Any]:
    """Sort and (re)count - also after merging several tenants."""
    compute["machines"].sort(key=lambda m: (not m["criticalPath"], m["subscription"].lower(), m["name"].lower()))
    compute["apps"].sort(key=lambda a: (a["stack"].lower(), a["version"], a["name"].lower()))
    compute["summary"] = machine_inventory.summary(compute["machines"], compute["sql"])
    apps = compute["apps"]
    compute["summary"]["apps"] = {"total": len(apps), "ended": sum(1 for a in apps if a["support"] == ENDED),
                                  "ending": sum(1 for a in apps if a["support"] == ENDING),
                                  "stacks": _stacks(apps)}
    images = compute.setdefault("images", [])
    compute["summary"]["images"] = {
        "total": len(images), "distinct": len({i["image"] for i in images}),
        "exposed": sum(1 for i in images if i["exposed"]),
        "withFindings": sum(1 for i in images if i["packages"]),
        "noFindings": sum(1 for i in images if i["scan"] in (SCAN_OTHER_TAGS, SCAN_NONE)),
        "outsideAcr": sum(1 for i in images if i["scan"] == SCAN_OUTSIDE),
        "registries": dict(sorted(_count(i["registryLabel"] for i in images).items(), key=lambda kv: -kv[1]))}
    return compute


def _count(values: Iterable[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


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
                   "images": [i for p in good for i in p.get("images") or []],
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
    images = s.get("images") or {}
    if images.get("total"):
        lines += [f"Containers: {images['total']} ({images['distinct']} distinct images), {images['exposed']} "
                  f"internet-facing, {images['withFindings']} with outdated packages reported by Defender, "
                  f"{images['outsideAcr']} pulled from outside Azure Container Registry. Registries: "
                  + ", ".join(f"{k} {v}" for k, v in images["registries"].items()) + ".", ""]
    lines += [f"Data sources: OS reported by {src['osReported']} machines, Update Manager assessment on "
              f"{src['patchAssessment']}, Defender package findings on {src['defenderPackages']}, CVE results on "
              f"{src['cveScan']}, Change Tracking on {src['changeTracking']}. Installed software and running services "
              "need Change Tracking (Azure Monitor agent); CVEs need a vulnerability scanner (Defender for Servers).",
              ""]
    return "\n".join(lines)
