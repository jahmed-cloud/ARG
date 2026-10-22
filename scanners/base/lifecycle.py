"""
Azure Resource Guardian - Product lifecycle
===========================================
When an operating system or SQL Server version stops receiving security updates. Shared by the end-of-support
scanners (scanners/compute/compute_posture_scanners.py) and the Compute inventory
(scripts/subscription_analysis/compute.py).

identify_os() names the product from what the machine itself reports (VM guest agent osName / osVersion, Arc
osSku / osVersion) and falls back to the marketplace image (offer / sku) for VMs that are not running.
identify_sql() does the same for SQL Server instances. support() turns a product into ended / ESU / ending /
supported with its date and the Extended Security Updates (ESU) route, if there is one.

Dates are the vendor's end of (extended) support: after them a product gets no security fixes unless ESU is bought
where the vendor sells it. Reviewed 2026-10-22 against the Microsoft, Canonical, Debian and Red Hat lifecycle pages.
A product without a date is supported for years or its lifecycle is not tracked here.
"""

import re
from datetime import date
from typing import Dict, List, NamedTuple, Optional, Tuple

ENDED, ESU, ENDING, SUPPORTED, UNKNOWN, APPLIANCE = "ended", "esu", "ending", "supported", "unknown", "appliance"
STATUS_LABELS = {ENDED: "Support ended", ESU: "Extended Security Updates", ENDING: "Support ending",
                 SUPPORTED: "Supported", UNKNOWN: "Not identified", APPLIANCE: "Network appliance"}
ENDING_DAYS = 180          # "ending" = vendor support ends within this many days
APPLIANCE_FAMILY = "Network appliance"
REVIEWED = "2026-10-22"


class Product(NamedTuple):
    family: str                       # "Windows Server", "Ubuntu", "SQL Server", ...
    label: str                        # "Windows Server 2016", "Ubuntu 22.04 LTS", ...
    ends: Optional[str] = None        # end of (extended) support, ISO date
    esu_until: Optional[str] = None   # last day of paid extended updates, ISO date
    esu: str = ""                     # how updates can be extended after `ends`
    tracked: bool = True              # False: the version (or its lifecycle) is not known - status unknown


class Support(NamedTuple):
    status: str
    product: Optional[Product]
    ends: Optional[date]
    days_left: Optional[int]
    note: str


def _d(value: Optional[str]) -> Optional[date]:
    return date.fromisoformat(value) if value else None


def support(product: Optional[Product], as_of: Optional[date] = None, esu_assigned: Optional[bool] = None) -> Support:
    """Where `product` stands on `as_of` (today). esu_assigned=True: an ESU licence is linked (Azure Arc)."""
    today = as_of or date.today()
    if product is None:
        return Support(UNKNOWN, None, None, None, "operating system not identified")
    if product.family == APPLIANCE_FAMILY:
        return Support(APPLIANCE, product, None, None,
                       "vendor firmware - follow the vendor's security advisories for this version")
    if not product.tracked:
        return Support(UNKNOWN, product, None, None, "version or lifecycle not identified")
    ends = _d(product.ends)
    if ends is None:
        return Support(SUPPORTED, product, None, None, "supported")
    days = (ends - today).days
    esu_until = _d(product.esu_until)
    if days < 0:
        esu_open = esu_until is None or esu_until >= today
        if esu_assigned and product.esu and esu_open:
            return Support(ESU, product, ends, days, f"support ended {ends.isoformat()}; covered by Extended Security "
                                                     f"Updates" + (f" until {esu_until.isoformat()}" if esu_until else ""))
        note = f"support ended {ends.isoformat()}"
        if product.esu and esu_open:
            note += f"; {product.esu}" + (f" until {esu_until.isoformat()}" if esu_until else "")
        elif esu_until is not None:
            note += f"; extended updates also ended {esu_until.isoformat()}"
        return Support(ENDED, product, ends, days, note)
    note = f"support ends {ends.isoformat()} (in {days} days)"
    if days <= ENDING_DAYS:
        return Support(ENDING, product, ends, days, note + (f"; then {product.esu}" if product.esu else ""))
    return Support(SUPPORTED, product, ends, days, f"supported until {ends.isoformat()}")


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

WINDOWS_SERVER: Dict[str, Tuple[Optional[str], Optional[str], str]] = {
    "2008": ("2020-01-14", "2024-01-09", "Extended Security Updates on Azure"),
    "2012": ("2023-10-10", "2026-10-13", "paid ESU through Azure Arc (free on Azure VMs)"),
    "2016": ("2027-01-12", None, "paid ESU through Azure Arc (up to 3 years)"),
    "2019": ("2029-01-09", None, ""),
    "2022": ("2031-10-14", None, ""),
    "2025": (None, None, ""),
}
WINDOWS_SERVER_BUILDS = {"6.0.": "2008", "6.1.": "2008", "6.2.": "2012", "6.3.": "2012", "10.0.14393": "2016",
                         "10.0.17763": "2019", "10.0.20348": "2022", "10.0.26100": "2025"}

# build: (version, Enterprise / Education end, Home / Pro end)
WINDOWS_10 = {
    "14393": ("1607", "2019-04-09", "2018-04-10"), "15063": ("1703", "2019-10-08", "2018-10-09"),
    "16299": ("1709", "2020-10-13", "2019-04-09"), "17134": ("1803", "2021-05-11", "2019-11-12"),
    "17763": ("1809", "2021-05-11", "2020-11-10"), "18362": ("1903", "2020-12-08", "2020-12-08"),
    "18363": ("1909", "2022-05-10", "2021-05-11"), "19041": ("2004", "2021-12-14", "2021-12-14"),
    "19042": ("20H2", "2023-05-09", "2022-05-10"), "19043": ("21H1", "2022-12-13", "2022-12-13"),
    "19044": ("21H2", "2024-06-11", "2023-06-13"), "19045": ("22H2", "2025-10-14", "2025-10-14"),
}
WINDOWS_10_LTSC = {"14393": ("LTSB 2016", "2026-10-13"), "17763": ("LTSC 2019", "2029-01-09"),
                   "19044": ("LTSC 2021", "2027-01-12")}
WINDOWS_11 = {
    "22000": ("21H2", "2024-10-08", "2023-10-10"), "22621": ("22H2", "2025-10-14", "2024-10-08"),
    "22631": ("23H2", "2026-11-10", "2025-11-11"), "26100": ("24H2", "2027-10-12", "2026-10-13"),
    "26200": ("25H2", "2028-10-10", "2027-10-12"),
}
IMAGE_RELEASES = {"rs1": "1607", "rs2": "1703", "rs3": "1709", "rs4": "1803", "rs5": "1809", "19h1": "1903",
                  "19h2": "1909", "20h1": "2004"}
ENTERPRISE = re.compile(r"enterprise|education|multi-session|(^|[-_ ])(ent|entn|avd|edu|evd)($|[-_ ])", re.I)


def _windows_build(version: str) -> Optional[str]:
    parts = (version or "").split(".")
    return parts[2] if len(parts) >= 3 and parts[0] == "10" else None


def _client(table: Dict[str, Tuple[str, str, str]], family: str, name: str, version: str, image: str
            ) -> Optional[Product]:
    build = _windows_build(version)
    if build not in table:
        token = re.search(r"(rs\d|\d{2}h\d)", image)
        release = IMAGE_RELEASES.get(token.group(1), token.group(1).upper()) if token else None
        build = next((b for b, row in table.items() if row[0] == release), None)
    if build not in table:
        if family == "Windows 10":   # every Windows 10 release is out of support since the last one ended
            return Product("Windows", family, "2025-10-14", "2028-10-10",
                           "paid ESU (included on Azure Virtual Desktop / Windows 365)")
        return Product("Windows", family, tracked=False)
    release, enterprise_end, pro_end = table[build]
    enterprise = bool(ENTERPRISE.search(name) or ENTERPRISE.search(image))
    esu = ("paid ESU (included on Azure Virtual Desktop / Windows 365)" if family == "Windows 10" and release == "22H2"
           else "")
    return Product("Windows", f"{family} {release}" + (" Enterprise" if enterprise else ""),
                   enterprise_end if enterprise else pro_end, "2028-10-10" if esu else None, esu)


def _windows(name: str, version: str, image: str) -> Optional[Product]:
    text = f"{name} {image}"
    if "windows" not in text and "win1" not in text:
        return None
    if re.search(r"ltsc|ltsb", text):
        build = _windows_build(version)
        if build in WINDOWS_10_LTSC:
            label, ends = WINDOWS_10_LTSC[build]
            if "iot" in text and build == "19044":
                label, ends = "IoT LTSC 2021", "2032-01-13"
            return Product("Windows", f"Windows 10 {label}", ends)
        return Product("Windows", "Windows 10 LTSC")
    if "windows 11" in name or (not name and re.search(r"windows-11|win11", image)):
        return _client(WINDOWS_11, "Windows 11", name, version, image)
    if "windows 10" in name or (not name and re.search(r"windows-10|win10", image)):
        return _client(WINDOWS_10, "Windows 10", name, version, image)
    year = re.search(r"(2008|2012|2016|2019|2022|2025)", name if "server" in name else image)
    key = year.group(1) if year else next((y for b, y in WINDOWS_SERVER_BUILDS.items()
                                           if (version or "").startswith(b)), None)
    if key is None and ("server" in name or "windowsserver" in image):
        return Product("Windows Server", "Windows Server", tracked=False)
    if key is None:
        return None
    r2 = bool(re.search(r"r2", name if "server" in name else image)) or (version or "").startswith(("6.1.", "6.3."))
    ends, esu_until, esu = WINDOWS_SERVER[key]
    return Product("Windows Server", f"Windows Server {key}" + (" R2" if r2 and key in ("2008", "2012") else ""),
                   ends, esu_until, esu)


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

UBUNTU_LTS = {"14.04": ("2019-04-30", "2024-04-30"), "16.04": ("2021-04-30", "2026-04-30"),
              "18.04": ("2023-05-31", "2028-05-31"), "20.04": ("2025-05-31", "2030-05-31"),
              "22.04": ("2027-05-31", "2032-05-31"), "24.04": ("2029-05-31", "2034-05-31"), "26.04": (None, None)}
UBUNTU_CODENAMES = {"trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04",
                    "noble": "24.04"}
# family: (regex naming it, {major: (end, extended until, extension route)})
LINUX: Dict[str, Tuple[str, Dict[str, Tuple[Optional[str], Optional[str], str]]]] = {
    "Debian": (r"debian", {"8": ("2020-06-30", None, ""), "9": ("2022-06-30", None, ""),
                           "10": ("2024-06-30", None, ""), "11": ("2026-08-31", None, ""),
                           "12": ("2028-06-30", None, ""), "13": (None, None, "")}),
    "CentOS Stream": (r"centos[- _]?stream", {"8": ("2024-05-31", None, ""), "9": ("2027-05-31", None, "")}),
    "CentOS": (r"centos", {"6": ("2020-11-30", None, ""), "7": ("2024-06-30", None, ""),
                           "8": ("2021-12-31", None, "")}),
    "RHEL": (r"rhel|red ?hat", {"6": ("2020-11-30", "2024-06-30", "paid Extended Life Cycle Support"),
                                "7": ("2024-06-30", "2028-06-30", "paid Extended Life Cycle Support"),
                                "8": ("2029-05-31", None, ""), "9": ("2032-05-31", None, ""),
                                "10": (None, None, "")}),
    "Rocky Linux": (r"rocky", {"8": ("2029-05-31", None, ""), "9": ("2032-05-31", None, ""), "10": (None, None, "")}),
    "AlmaLinux": (r"alma", {"8": ("2029-05-31", None, ""), "9": ("2032-05-31", None, ""), "10": (None, None, "")}),
    "Oracle Linux": (r"oracle|^ol\b", {"6": ("2021-03-01", None, ""), "7": ("2024-12-31", None, "paid Extended Support"),
                                       "8": ("2029-07-31", None, ""), "9": ("2032-06-30", None, "")}),
    "Azure Linux": (r"mariner|azure ?linux|azurelinux", {"1": ("2024-05-31", None, ""), "2": ("2025-07-31", None, ""),
                                                        "3": (None, None, "")}),
    "SLES": (r"sles|suse", {"12": ("2024-10-31", "2027-10-31", "paid Long Term Service Pack Support"),
                            "15": (None, None, "")}),
}
APPLIANCE_NAMES = re.compile(r"fortios|fortiweb|fortigate|forti|pan-?os|palo ?alto|check ?point|gaia|cisco|"
                             r"barracuda|sophos|juniper|junos|f5|big-?ip|citrix|netscaler|vyos|opnsense|pfsense", re.I)
APPLIANCE_PUBLISHERS = ("fortinet", "paloaltonetworks", "checkpoint", "cisco", "barracudanetworks", "sophos",
                        "juniper-networks", "f5-networks", "citrix", "netgate", "vyos")


def _numbers(text: str) -> list:
    """Version-like tokens, without architecture / generation markers (x86_64, gen2) that look like versions."""
    cleaned = re.sub(r"x86_64|aarch64|arm64|amd64|gen\d", " ", text, flags=re.I)
    return re.findall(r"(?<!\d)(\d{1,2})(?:[._](\d{1,2}))?(?!\d)", cleaned)


def _ubuntu(text: str) -> Optional[Product]:
    m = re.search(r"(?<!\d)(\d{2})[._](\d{2})(?!\d)", text) or re.search(r"ubuntu\D{0,3}(\d{2})(04|10)(?!\d)", text)
    release = f"{m.group(1)}.{m.group(2)}" if m else next((v for c, v in UBUNTU_CODENAMES.items() if c in text), None)
    if release is None:
        return Product("Ubuntu", "Ubuntu", tracked=False)
    if release in UBUNTU_LTS:
        ends, esm = UBUNTU_LTS[release]
        return Product("Ubuntu", f"Ubuntu {release} LTS", ends, esm, "Ubuntu Pro (ESM)" if esm else "")
    year, month = int(release[:2]), int(release[3:])
    if month == 4 and year % 2 == 0:          # an LTS newer than the table
        return Product("Ubuntu", f"Ubuntu {release} LTS", tracked=year > 26)
    month += 9                                # interim release: 9 months of support
    ends = date(2000 + year + (month - 1) // 12, (month - 1) % 12 + 1, 1).isoformat()
    return Product("Ubuntu", f"Ubuntu {release} (interim)", ends)


def _linux(text: str) -> Optional[Product]:
    if "ubuntu" in text or any(c in text for c in UBUNTU_CODENAMES):
        return _ubuntu(text)
    for family, (pattern, majors) in LINUX.items():
        m = re.search(pattern, text, re.I)
        if not m:
            continue
        rest = text[m.end():]
        major = next((n for n, _ in _numbers(rest) if n in majors), None) or \
            next((n for n, _ in _numbers(text) if n in majors), None)
        if major is None:
            return Product(family, family, tracked=False)
        ends, until, route = majors[major]
        if family == "SLES" and major == "15":   # support depends on the service pack, which is not reported
            return Product(family, "SLES 15", tracked=False)
        return Product(family, f"{family} {major}", ends, until, route)
    return None


def identify_os(name: str = "", version: str = "", offer: str = "", sku: str = "", publisher: str = ""
                ) -> Optional[Product]:
    """The OS product from what the machine reports (name / version), else from its marketplace image."""
    name, version = (name or "").strip(), (version or "").strip()
    reported = name.lower()
    image = f"{offer or ''} {sku or ''}".strip().lower()
    if APPLIANCE_NAMES.search(reported) or (publisher or "").lower() in APPLIANCE_PUBLISHERS:
        return Product(APPLIANCE_FAMILY, f"{name} {version}".strip() or offer or publisher)
    product = _windows(reported, version, image if not reported else "")
    if product is None and reported:
        product = _linux(f"{reported} {version}".lower())
    if product is None and image:
        product = _windows("", "", image) or _linux(image)
    return product


# ---------------------------------------------------------------------------
# App Service language runtimes
# ---------------------------------------------------------------------------

# (stack regex matched against "<stack>|<version>", end-of-support date, label)
RUNTIME_END_OF_SUPPORT: List[Tuple[str, str, str]] = [
    (r"^dotnet(core|-isolated)?\|(1|2|3)\.", "2022-12-13", ".NET Core 1-3.1"),
    (r"^dotnet(core|-isolated)?\|5\.0", "2022-05-10", ".NET 5"),
    (r"^dotnet(core|-isolated)?\|6\.0", "2024-11-12", ".NET 6"),
    (r"^dotnet(core|-isolated)?\|7\.0", "2024-05-14", ".NET 7"),
    (r"^dotnet(core|-isolated)?\|8\.0", "2026-11-10", ".NET 8"),
    (r"^dotnet(core|-isolated)?\|9\.0", "2026-11-10", ".NET 9"),
    (r"^node\|(10|12|14)", "2023-04-30", "Node.js <=14"),
    (r"^node\|16", "2023-09-11", "Node.js 16"),
    (r"^node\|18", "2025-04-30", "Node.js 18"),
    (r"^node\|20", "2026-04-30", "Node.js 20"),
    (r"^node\|22", "2027-04-30", "Node.js 22"),
    (r"^python\|3\.[0-7]($|\.)", "2023-06-27", "Python <=3.7"),
    (r"^python\|3\.8", "2024-10-07", "Python 3.8"),
    (r"^python\|3\.9", "2025-10-31", "Python 3.9"),
    (r"^python\|3\.10", "2026-10-31", "Python 3.10"),
    (r"^python\|3\.11", "2027-10-31", "Python 3.11"),
    (r"^php\|(5|7)\.", "2022-11-28", "PHP 7.x"),
    (r"^php\|8\.0", "2023-11-26", "PHP 8.0"),
    (r"^php\|8\.1", "2025-12-31", "PHP 8.1"),
    (r"^php\|8\.2", "2026-12-31", "PHP 8.2"),
    (r"^php\|8\.3", "2027-12-31", "PHP 8.3"),
    (r"^php\|8\.4", "2028-12-31", "PHP 8.4"),
]


def runtime_end_of_support(stack: Optional[str]) -> Optional[Tuple[str, date]]:
    """(label, end-of-support date) of an App Service stack ('php|8.1'), None when no date is tracked."""
    if not stack:
        return None
    for rx, eos, label in RUNTIME_END_OF_SUPPORT:
        if re.search(rx, stack, re.I):
            return label, date.fromisoformat(eos)
    return None


# ---------------------------------------------------------------------------
# SQL Server
# ---------------------------------------------------------------------------

SQL_SERVER: Dict[str, Tuple[Optional[str], Optional[str], str]] = {
    "2008": ("2019-07-09", "2022-07-12", "Extended Security Updates"),
    "2008 R2": ("2019-07-09", "2022-07-12", "Extended Security Updates"),
    "2012": ("2022-07-12", "2025-07-08", "paid ESU through Azure Arc"),
    "2014": ("2024-07-09", "2027-07-13", "paid ESU through Azure Arc"),
    "2016": ("2026-07-14", "2029-07-10", "paid ESU through Azure Arc or volume licensing"),
    "2017": ("2027-10-12", None, ""),
    "2019": ("2030-01-08", None, ""),
    "2022": ("2033-01-11", None, ""),
    "2025": (None, None, ""),
}
SQL_MAJOR = {"10.0": "2008", "10.50": "2008 R2", "11": "2012", "12": "2014", "13": "2016", "14": "2017",
             "15": "2019", "16": "2022", "17": "2025"}


def identify_sql(version: str = "", build: str = "", offer: str = "") -> Optional[Product]:
    """SQL Server product from the Arc version label ('SQL Server 2016'), the image offer ('SQL2017-WS2016') or the
    build number ('13.0.5026.0')."""
    text = f"{version or ''} {offer or ''}"
    m = re.search(r"sql\s*(?:server)?\s*(2008|2012|2014|2016|2017|2019|2022|2025)(\s*r2)?", text, re.I)
    key = None
    if m:
        key = m.group(1) + (" R2" if m.group(2) and m.group(1) == "2008" else "")
    elif build:
        parts = build.split(".")
        key = SQL_MAJOR.get(f"{parts[0]}.{parts[1]}" if len(parts) > 1 and parts[0] == "10" else parts[0])
    if key is None:
        return None
    ends, until, route = SQL_SERVER[key]
    return Product("SQL Server", f"SQL Server {key}", ends, until, route)
