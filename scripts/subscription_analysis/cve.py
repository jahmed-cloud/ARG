"""
CVE check: is a VM, Arc server, SQL Server instance, App Service app or container affected by a CVE?

Two public sources, read-only, cached (a full CVE database mirror is not worth it: ARG rarely knows exact patch
levels, so it would only add load, not precision):

- CISA Known Exploited Vulnerabilities (KEV) catalog - every CVE known to be exploited in the wild, one ~1.7 MB JSON,
  fetched at most once a day: which recently exploited CVEs concern products this estate runs;
- NVD CVE API 2.0, one CVE per request (cached a day): the affected products and version ranges (CPE configurations)
  of the CVE being checked.

Both are matched against what the Compute inventory knows (compute.py): the operating system and build each machine
reports, network appliance firmware (FortiOS, FortiWeb, PAN-OS), SQL Server version and build, App Service language runtimes,
the product and tag of official container images (php:8.3-apache, wordpress:6.5-php8.3, nginx:1.27...) and
packages with a pending security update (Update Manager) or a Defender finding (VMs, Arc servers and container images
in Azure Container Registry). Each resource gets a verdict:

- impacted:             product and exact version inside an affected range;
- potentially impacted: the product and branch match but the patch level is not known (App Service runtimes,
                        Windows / Linux releases whose fix is a monthly update, packages with an update pending);
- not affected:         the product is present in a version outside every affected range.

Nothing is sent to either service except the CVE ID being looked up.
"""

import json
import re
import threading
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_TTL = 24 * 3600
NVD_TTL = 24 * 3600
RETRY_AFTER = 600           # a failed fetch is retried after 10 minutes, not on every page load
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
IMPACTED, POTENTIAL, NOT_AFFECTED = "impacted", "potentially impacted", "not affected"
VERDICT_ORDER = [IMPACTED, POTENTIAL, NOT_AFFECTED]
KEV_DAYS = 90
PACKAGE_SOURCES = ("security update pending", "outdated package (Defender)")

# our product key -> the NVD CPE (vendor, product) pairs that name it
CPE_PRODUCTS: Dict[str, List[Tuple[str, str]]] = {
    "php": [("php", "php")],
    "node": [("nodejs", "node.js")],
    "python": [("python", "python")],
    "dotnet": [("microsoft", ".net"), ("microsoft", ".net_core"), ("microsoft", "asp.net_core")],
    "java": [("oracle", "jdk"), ("oracle", "jre"), ("oracle", "openjdk")],
    "tomcat": [("apache", "tomcat")],
    "fortios": [("fortinet", "fortios")],
    "fortiweb": [("fortinet", "fortiweb")],
    "panos": [("paloaltonetworks", "pan-os")],
    "ubuntu": [("canonical", "ubuntu_linux")],
    "debian": [("debian", "debian_linux")],
    "rhel": [("redhat", "enterprise_linux")],
    "linux_kernel": [("linux", "linux_kernel")],
    "openssl": [("openssl", "openssl")],
    "openssh": [("openbsd", "openssh")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx"), ("f5", "nginx_open_source")],
    "sudo": [("sudo_project", "sudo"), ("todd_miller", "sudo")],
    "glibc": [("gnu", "glibc")],
    "apache_httpd": [("apache", "http_server")],
    "curl": [("haxx", "curl")],
    "redis": [("redis", "redis")],
    "postgresql": [("postgresql", "postgresql")],
    "mysql": [("oracle", "mysql")],
    "mariadb": [("mariadb", "mariadb")],
    "grafana": [("grafana", "grafana")],
    "wordpress": [("wordpress", "wordpress")],
    "drupal": [("drupal", "drupal")],
    "nextcloud": [("nextcloud", "nextcloud_server")],
    "keycloak": [("redhat", "keycloak")],
    "mongodb": [("mongodb", "mongodb")],
    "traefik": [("traefik", "traefik")],
    "directus": [("monospace", "directus")],
}
# official / common container images (last part of the repository) -> our product key; the tag is that product's version
IMAGE_PRODUCTS = {"php": "php", "nginx": "nginx", "httpd": "apache_httpd", "apache2": "apache_httpd",
                  "tomcat": "tomcat", "node": "node", "python": "python", "redis": "redis", "postgres": "postgresql",
                  "postgresql": "postgresql", "mysql": "mysql", "mariadb": "mariadb", "grafana": "grafana",
                  "grafana-enterprise": "grafana", "grafana-oss": "grafana", "wordpress": "wordpress",
                  "drupal": "drupal", "nextcloud": "nextcloud", "keycloak": "keycloak", "mongo": "mongodb",
                  "mongodb": "mongodb", "traefik": "traefik", "directus": "directus"}
IMAGE_SOURCE = "container image tag"
# KEV vendorProject / product (lower case, regex) -> our product key
KEV_PRODUCTS: List[Tuple[str, str, str]] = [
    (r"^php$", r"php", "php"),
    (r"node\.?js", r".", "node"),
    (r"^microsoft$", r"\.net", "dotnet"),
    (r"^microsoft$", r"sql server", "sql_server"),
    (r"^microsoft$", r"^windows$|windows server|win32k|windows kernel|windows smb|windows common log|windows "
                     r"(print|server service|clfs|ntfs|mark of the web|smartscreen|error reporting|update)", "windows"),
    (r"^fortinet$", r"fortios|fortigate", "fortios"),
    (r"^fortinet$", r"fortiweb", "fortiweb"),
    (r"^palo alto networks$", r"pan-?os", "panos"),
    (r"^linux$", r"kernel", "linux_kernel"),
    (r"^openssl$", r".", "openssl"),
    (r"^(openbsd|openssh)$", r"openssh", "openssh"),
    (r"^(f5|nginx)$", r"nginx", "nginx"),
    (r"^sudo", r".", "sudo"),
    (r"^(gnu|glibc)$", r"glibc|c library", "glibc"),
    (r"^apache$", r"http server|httpd", "apache_httpd"),
    (r"^apache$", r"tomcat", "tomcat"),
]
WINDOWS_CPE = {  # lifecycle label (scanners/base/lifecycle.py) -> NVD CPE product names of that release
    "Windows Server 2008": ["windows_server_2008"], "Windows Server 2008 R2": ["windows_server_2008"],
    "Windows Server 2012": ["windows_server_2012"], "Windows Server 2012 R2": ["windows_server_2012"],
    "Windows Server 2016": ["windows_server_2016"], "Windows Server 2019": ["windows_server_2019"],
    "Windows Server 2022": ["windows_server_2022", "windows_server_2022_23h2"],
    "Windows Server 2025": ["windows_server_2025"],
}
PACKAGE_KEYS = {"openssl": "openssl", "libssl": "openssl", "openssh": "openssh", "nginx": "nginx", "sudo": "sudo",
                "glibc": "glibc", "libc6": "glibc", "libc-bin": "glibc", "apache2": "apache_httpd",
                "httpd": "apache_httpd", "curl": "curl", "libcurl": "curl", "php": "php"}
VERSION_COMMANDS = {"php": "php -v", "node": "node -v", "python": "python --version", "dotnet": "dotnet --list-runtimes",
                    "java": "java -version", "tomcat": "catalina.sh version"}
STACKS = {"PHP": "php", "Node.js": "node", "Python": "python", ".NET": "dotnet", ".NET isolated": "dotnet",
          "Java": "java", "Tomcat": "tomcat"}


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

def version_tuple(value: Any) -> Tuple[int, ...]:
    """'v11.1.0' -> (11, 1, 0); '20-lts' -> (20,); '10.0.14393.7000' -> (10, 0, 14393, 7000); '' -> ()."""
    return tuple(int(x) for x in re.findall(r"\d+", str(value or "").split("-")[0].split(",")[0])[:5])


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version: Tuple[int, ...], match: Dict[str, Any]) -> bool:
    lo_in, lo_ex = match.get("versionStartIncluding"), match.get("versionStartExcluding")
    hi_in, hi_ex = match.get("versionEndIncluding"), match.get("versionEndExcluding")
    if lo_in and _cmp(version, version_tuple(lo_in)) < 0:
        return False
    if lo_ex and _cmp(version, version_tuple(lo_ex)) <= 0:
        return False
    if hi_in and _cmp(version, version_tuple(hi_in)) > 0:
        return False
    if hi_ex and _cmp(version, version_tuple(hi_ex)) >= 0:
        return False
    return True


def branch_overlaps(branch: Tuple[int, ...], match: Dict[str, Any]) -> bool:
    """Does any version of branch (8, 3) fall in the range? Checks the branch's first and a far patch release."""
    low = branch + (0,) * 3
    high = branch + (99999,) * 3
    if in_range(low, match) or in_range(high, match):
        return True
    for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
        bound = version_tuple(match.get(key))
        if bound and bound[:len(branch)] == branch:
            return True
    return False


def _fixed_in(match: Dict[str, Any]) -> Optional[str]:
    return match.get("versionEndExcluding") or (f"after {match['versionEndIncluding']}"
                                                if match.get("versionEndIncluding") else None)


# ---------------------------------------------------------------------------
# What the estate runs
# ---------------------------------------------------------------------------

def inventory_facts(compute: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One fact per (resource, product): key, version, how exact the version is ('full', 'branch', 'none')."""
    facts: List[Dict[str, Any]] = []
    compute = compute or {}

    def fact(r: Dict[str, Any], kind: str, key: str, version: str, exact: str, label: str, source: str,
             cpe_products: Optional[List[str]] = None) -> None:
        facts.append({"id": r.get("id"), "name": r.get("name"), "kind": kind, "subscription": r.get("subscription"),
                      "key": key, "version": version or "", "exact": exact, "label": label, "source": source,
                      "cpeProducts": cpe_products or [], "running": r.get("running", True),
                      "exposed": bool(r.get("exposed")), "urls": list(r.get("urls") or [])})

    for m in compute.get("machines") or []:
        kind = "Arc server" if m.get("kind") == "arc" else "Azure VM"
        family, product = m.get("family") or "", m.get("os") or ""
        reported = m.get("osReported") or ""
        build = reported.split()[-1] if reported else ""
        # a full Windows build (10.0.14393.7428) is compared exactly with the build NVD lists as fixed
        exact_build = "full" if len(version_tuple(build)) >= 4 else "none"
        if family == "Windows Server":
            fact(m, kind, "windows", build, exact_build, product, "operating system",
                 WINDOWS_CPE.get(product) or WINDOWS_CPE.get(product.replace(" R2", "")) or [])
        elif family == "Windows":
            release = re.search(r"Windows (10|11) (\w+)", product)
            names = [f"windows_{release.group(1)}_{release.group(2).lower()}", f"windows_{release.group(1)}"] \
                if release else []
            fact(m, kind, "windows", build, exact_build, product, "operating system", names)
        elif family in ("Ubuntu", "Debian", "RHEL"):
            key = {"Ubuntu": "ubuntu", "Debian": "debian", "RHEL": "rhel"}[family]
            fact(m, kind, key, product.split()[1] if len(product.split()) > 1 else "", "branch", product,
                 "operating system")
        if (m.get("osType") or "").lower() == "linux" or family in ("Ubuntu", "Debian", "RHEL", "Rocky Linux",
                                                                    "AlmaLinux", "CentOS", "SLES", "Oracle Linux"):
            fact(m, kind, "linux_kernel", "", "none", f"Linux kernel ({product})", "operating system")
        if family == "Network appliance":
            text = reported.lower()
            key = "fortiweb" if "fortiweb" in text else "fortios" if "fortios" in text or "fortigate" in text \
                else "panos" if re.search(r"\bpan-?os\b", text) else ""
            if key:
                version = re.search(r"(\d+\.\d+(\.\d+)?)", reported)
                fact(m, kind, key, version.group(1) if version else "", "full" if version else "none", reported,
                     "appliance firmware")
        pending = (m.get("patches") or {}).get("names") or []
        flagged = (m.get("packages") or {}).get("names") or []
        for name in pending + flagged:
            pkg = name.split()[0].lower()
            key = PACKAGE_KEYS.get(pkg) or next((v for k, v in PACKAGE_KEYS.items() if pkg.startswith(k)), None)
            if key:
                fact(m, kind, key, name.split()[1] if len(name.split()) > 1 else "", "none", name,
                     "security update pending" if name in pending else "outdated package (Defender)")
        for s in m.get("sql") or []:
            fact({**s, "subscription": m.get("subscription"), "running": m.get("running"), "exposed": m.get("exposed")},
                 "SQL Server", "sql_server", s.get("build") or "", "full" if s.get("build") else "branch",
                 f"{s.get('product')} {s.get('edition') or ''}".strip(), "SQL Server instance",
                 [(s.get("product") or "").lower().replace(" ", "_")])
    for s in compute.get("sql") or []:
        if not any(f["id"] == s.get("id") for f in facts):
            fact(s, "SQL Server", "sql_server", s.get("build") or "", "full" if s.get("build") else "branch",
                 f"{s.get('product')} {s.get('edition') or ''}".strip(), "SQL Server instance",
                 [(s.get("product") or "").lower().replace(" ", "_")])
    for a in compute.get("apps") or []:
        key = STACKS.get(a.get("stack") or "")
        if key:
            internet = a["internet"] if "internet" in a else (a.get("exposure") or "") == "Public app endpoint"
            running = a["running"] if "running" in a else (a.get("state") or "").lower() != "stopped"
            fact({**a, "exposed": internet, "running": running}, "App Service", key, a.get("version") or "", "branch",
                 a.get("runtime") or "", "App Service runtime")
    for i in compute.get("images") or []:
        record = {**i, "urls": [i["url"]] if i.get("url") else []}
        kind = i.get("kind") or "Container"
        for key, version, label in image_products(i.get("repository") or "", i.get("tag") or ""):
            fact(record, kind, key, version, tag_exactness(version), label, IMAGE_SOURCE)
        for name in i.get("packages") or []:
            pkg = name.split()[0].lower()
            key = PACKAGE_KEYS.get(pkg) or next((v for k, v in PACKAGE_KEYS.items() if pkg.startswith(k)), None)
            if key:
                fact(record, kind, key, "", "none", f"{name} in {i.get('image')}", "outdated package (Defender)")
    return facts


def image_products(repository: str, tag: str) -> List[Tuple[str, str, str]]:
    """(key, version, label) of the products an image tag names: 'library/php' + '8.3-apache' -> php 8.3;
    'library/wordpress' + '6.5-php8.3' -> wordpress 6.5 and php 8.3; custom images name no product."""
    name = repository.rsplit("/", 1)[-1].lower()
    tag = (tag or "").lower()
    pinned = "" if re.fullmatch(r"[0-9a-f]{12,64}", tag) else tag.lstrip("v")
    version = ".".join(str(x) for x in version_tuple(pinned)[:3])
    out = []
    key = IMAGE_PRODUCTS.get(name)
    if key:
        out.append((key, version, f"{name}:{tag or 'latest'}"))
    php = re.search(r"php-?(\d+\.\d+)", tag)
    if php and key != "php":
        out.append(("php", php.group(1), f"PHP {php.group(1)} in {name}:{tag}"))
    return out


def tag_exactness(version: str) -> str:
    """A tag 8.3.12 pins a release; 8.3 is a moving branch tag; latest says nothing."""
    parts = len(version_tuple(version))
    return "full" if parts >= 3 else "branch" if parts else "none"


# ---------------------------------------------------------------------------
# Sources (cached)
# ---------------------------------------------------------------------------

_LOCK = threading.Lock()
_MEMORY: Dict[str, Tuple[float, Any]] = {}
_FAILED: Dict[str, float] = {}


def _cached(key: str, ttl: float, fetch, cache_dir: Optional[Path]) -> Any:
    """Memory, then a file in cache_dir, then the network; a failure is not retried for RETRY_AFTER seconds."""
    now = time.time()
    with _LOCK:
        hit = _MEMORY.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    path = cache_dir / (re.sub(r"[^A-Za-z0-9_.-]", "_", key) + ".json") if cache_dir else None
    if path and path.is_file() and now - path.stat().st_mtime < ttl:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            with _LOCK:
                _MEMORY[key] = (path.stat().st_mtime, value)
            return value
        except (OSError, ValueError):
            pass
    if now - _FAILED.get(key, 0) < RETRY_AFTER:
        raise RuntimeError("source unavailable - retried in a few minutes")
    try:
        value = fetch()
    except Exception as exc:
        _FAILED[key] = now
        if path and path.is_file():   # stale beats nothing
            return json.loads(path.read_text(encoding="utf-8"))
        raise RuntimeError(str(exc)[:200]) from exc
    with _LOCK:
        _MEMORY[key] = (now, value)
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
    return value


def fetch_kev(cache_dir: Optional[Path] = None) -> Dict[str, Any]:
    import httpx

    def get() -> Dict[str, Any]:
        r = httpx.get(KEV_URL, timeout=60, follow_redirects=True)
        r.raise_for_status()
        data = r.json()
        return {"catalogVersion": data.get("catalogVersion"), "dateReleased": data.get("dateReleased"),
                "vulnerabilities": data.get("vulnerabilities") or []}
    return _cached("kev", KEV_TTL, get, cache_dir)


def fetch_cve(cve_id: str, cache_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    import httpx

    cve_id = cve_id.strip().upper()
    if not CVE_ID.match(cve_id):
        raise ValueError("Not a CVE ID (CVE-YYYY-NNNN)")

    def get() -> Optional[Dict[str, Any]]:
        r = httpx.get(NVD_URL, params={"cveId": cve_id}, timeout=60)
        r.raise_for_status()
        items = r.json().get("vulnerabilities") or []
        return items[0]["cve"] if items else None
    return _cached(f"nvd-{cve_id}", NVD_TTL, get, cache_dir)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _cpe(criteria: str) -> Tuple[str, str, str, str]:
    parts = (criteria or "").split(":")
    return (parts[2] if len(parts) > 2 else "", parts[3] if len(parts) > 3 else "",
            parts[4] if len(parts) > 4 else "", parts[5] if len(parts) > 5 else "*")


def _matches(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for config in record.get("configurations") or []:
        for node in config.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable"):
                    out.append(m)
    return out


def _fact_matches(fact: Dict[str, Any], vendor: str, product: str) -> bool:
    if fact["key"] in ("windows", "sql_server"):
        names = fact.get("cpeProducts") or []
        if fact["key"] == "sql_server":
            return vendor == "microsoft" and (product in names or product == "sql_server")
        return vendor == "microsoft" and product in names
    return (vendor, product) in CPE_PRODUCTS.get(fact["key"], [])


def judge(fact: Dict[str, Any], match: Dict[str, Any]) -> Tuple[str, str, Optional[str]]:
    """(verdict, reason, fixed in) for one fact against one vulnerable CPE match."""
    part, vendor, product, cpe_version = _cpe(match.get("criteria"))
    has_range = any(match.get(k) for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
                                           "versionEndExcluding"))
    fixed = _fixed_in(match)
    if fact["source"] in PACKAGE_SOURCES:   # distributions backport fixes: the upstream version says little
        return POTENTIAL, f"{fact['source']}: {fact['label']} - install it", fixed
    ours = version_tuple(fact["version"])
    if fact["key"] == "sql_server" and cpe_version not in ("*", "-") and product == "sql_server":
        same = cpe_version in (fact.get("cpeProducts") or [""])[0]   # sql_server:2016 vs sql_server_2016
        return ((POTENTIAL, f"{fact['label']} is listed; install the security update for this CVE", fixed) if same
                else (NOT_AFFECTED, f"{fact['label']} is not listed", None))
    if cpe_version not in ("*", "-", ""):
        listed = version_tuple(cpe_version)
        if ours and listed and ours[:len(listed)] == listed[:len(ours)]:
            return IMPACTED if fact["exact"] == "full" else POTENTIAL, f"version {cpe_version} is listed", fixed
        return NOT_AFFECTED, f"listed version {cpe_version} differs from {fact['version'] or 'the version in use'}", None
    if not has_range:
        reason = ("every version of the product is listed - the fix is an update; check it is installed"
                  if fact["key"] in ("windows", "linux_kernel", "ubuntu", "debian", "rhel")
                  else "every version is listed")
        return POTENTIAL, reason, fixed
    if not ours or fact["exact"] == "none":
        return POTENTIAL, "the version in use is not known", fixed
    if fact["exact"] == "full":
        if in_range(ours, match):
            return IMPACTED, f"{fact['version']} is in the affected range", fixed
        return NOT_AFFECTED, f"{fact['version']} is outside the affected range", None
    if branch_overlaps(ours, match):
        command = VERSION_COMMANDS.get(fact["key"], "the runtime's version command")
        detail = (f"App Service applies runtime patches - confirm the patch level with {command} in the Kudu (SSH) "
                  "console" if fact["kind"] == "App Service" else
                  "a branch tag moves with every patch release - the version is the one pulled at the last deployment;"
                  " check the image digest or rebuild" if fact["source"] == IMAGE_SOURCE else "the patch level is not known")
        return POTENTIAL, f"branch {fact['version']} is affected up to {fixed or 'an unknown release'}; {detail}", fixed
    return NOT_AFFECTED, f"branch {fact['version']} is outside the affected range", None


def _words(record: Dict[str, Any]) -> str:
    return " ".join(d.get("value", "") for d in record.get("descriptions") or [] if d.get("lang") == "en")


def _cvss(record: Dict[str, Any]) -> Tuple[Optional[float], str]:
    metrics = record.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            if data.get("baseScore") is not None:
                return data["baseScore"], data.get("baseSeverity") or m.get("baseSeverity") or ""
    return None, ""


KEYWORDS = {"php": r"\bphp\b", "node": r"node\.js", "python": r"\bpython\b", "dotnet": r"\.net\b",
            "windows": r"\bwindows\b", "linux_kernel": r"linux kernel", "openssl": r"\bopenssl\b",
            "openssh": r"\bopenssh\b", "nginx": r"\bnginx\b", "sql_server": r"sql server", "fortios": r"fortios",
            "fortiweb": r"fortiweb", "panos": r"\bpan-?os\b", "sudo": r"\bsudo\b", "glibc": r"\bglibc\b", "apache_httpd": r"apache http",
            "tomcat": r"\btomcat\b", "curl": r"\bcurl\b", "redis": r"\bredis\b",
            "postgresql": r"postgresql", "mysql": r"\bmysql\b", "mariadb": r"\bmariadb\b", "grafana": r"\bgrafana\b",
            "wordpress": r"\bwordpress\b", "drupal": r"\bdrupal\b", "nextcloud": r"\bnextcloud\b",
            "keycloak": r"\bkeycloak\b", "mongodb": r"\bmongodb\b", "traefik": r"\btraefik\b",
            "directus": r"\bdirectus\b"}


def check(cve_id: str, record: Optional[Dict[str, Any]], facts: List[Dict[str, Any]],
          kev: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Every resource the CVE concerns, with its verdict; products of the CVE the estate does not run."""
    cve_id = cve_id.strip().upper()
    kev_entry = next((v for v in (kev or {}).get("vulnerabilities") or [] if v.get("cveID") == cve_id), None)
    if record is None:
        return {"cve": cve_id, "found": False, "kev": kev_entry, "results": [], "products": [],
                "note": "NVD has no record of this CVE (yet)."}
    matches = _matches(record)
    results: Dict[Tuple[str, str], Dict[str, Any]] = {}
    products = sorted({f"{_cpe(m['criteria'])[1]}:{_cpe(m['criteria'])[2]}" for m in matches})
    for f in facts:
        for m in matches:
            _, vendor, product, _ = _cpe(m.get("criteria"))
            if not _fact_matches(f, vendor, product):
                continue
            verdict, reason, fixed = judge(f, m)
            key = (f["id"], f["name"], f["key"])
            best = results.get(key)
            if best is None or VERDICT_ORDER.index(verdict) < VERDICT_ORDER.index(best["verdict"]):
                results[key] = {**{k: f[k] for k in ("id", "name", "kind", "subscription", "label", "version",
                                                     "source", "running", "exposed", "urls")},
                                "verdict": verdict, "reason": reason, "fixed": fixed}
    note = ""
    if not matches:   # not analysed by NVD yet: name the products the description mentions
        text = _words(record).lower()
        keys = {k for k, rx in KEYWORDS.items() if re.search(rx, text)}
        for f in facts:
            if f["key"] in keys and (f["id"], f["name"], f["key"]) not in results:
                results[(f["id"], f["name"], f["key"])] = {
                    **{k: f[k] for k in ("id", "name", "kind", "subscription", "label", "version", "source",
                                         "running", "exposed", "urls")},
                    "verdict": POTENTIAL, "reason": "NVD has not listed affected versions yet - the description names "
                                                    "this product", "fixed": None}
        note = "NVD has not analysed this CVE yet (no affected versions); matched by the products its description names."
    score, severity = _cvss(record)
    rows = sorted(results.values(), key=lambda r: (VERDICT_ORDER.index(r["verdict"]), not r["exposed"],
                                                   str(r["name"]).lower()))
    return {"cve": cve_id, "found": True, "status": record.get("vulnStatus"), "published": record.get("published"),
            "description": _words(record)[:1200], "score": score, "severity": severity, "kev": kev_entry,
            "products": products, "note": note, "results": rows,
            "counts": {v: sum(1 for r in rows if r["verdict"] == v) for v in VERDICT_ORDER}}


def kev_key(entry: Dict[str, Any]) -> Optional[str]:
    vendor, product = (entry.get("vendorProject") or "").lower(), (entry.get("product") or "").lower()
    for vrx, prx, key in KEV_PRODUCTS:
        if re.search(vrx, vendor) and re.search(prx, product):
            return key
    return None


def kev_in_estate(kev: Optional[Dict[str, Any]], facts: List[Dict[str, Any]], days: int = KEV_DAYS,
                  today: Optional[date] = None) -> Dict[str, Any]:
    """Known-exploited CVEs added in the last `days` that concern products the estate runs, newest first."""
    since = ((today or date.today()) - timedelta(days=days)).isoformat()
    by_key: Dict[str, List[Dict[str, Any]]] = {}
    for f in facts:
        by_key.setdefault(f["key"], []).append(f)
    rows = []
    for v in (kev or {}).get("vulnerabilities") or []:
        if (v.get("dateAdded") or "") < since:
            continue
        key = kev_key(v)
        if not key or key not in by_key:
            continue
        resources = by_key[key]
        rows.append({"cve": v.get("cveID"), "vendor": v.get("vendorProject"), "product": v.get("product"),
                     "name": v.get("vulnerabilityName"), "dateAdded": v.get("dateAdded"), "dueDate": v.get("dueDate"),
                     "ransomware": v.get("knownRansomwareCampaignUse"), "action": v.get("requiredAction"),
                     "description": v.get("shortDescription"),
                     "resources": len({r["id"] for r in resources}),
                     "exposed": len({r["id"] for r in resources if r["exposed"]}),
                     "kinds": sorted({r["kind"] for r in resources})})
    rows.sort(key=lambda r: (r["dateAdded"] or "", r["cve"] or ""), reverse=True)
    return {"catalogVersion": (kev or {}).get("catalogVersion"), "dateReleased": (kev or {}).get("dateReleased"),
            "days": days, "total": len((kev or {}).get("vulnerabilities") or []), "rows": rows}


def products_summary(facts: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in facts:
        out[f["key"]] = out.get(f["key"], 0) + 1
    return out
