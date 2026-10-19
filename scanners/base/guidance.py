"""
Azure Resource Guardian - Implementation guidance primitives
============================================================
Shared by the Defender assessment catalogue (scanners/security/defender_guidance.py) and the per-finding-type
catalogue (scripts/subscription_analysis/guidance.py): the Guidance record, the list prices used for
"cost of implementation" estimates, and helpers that turn Defender's HTML metadata into plain text and links.

Prices are USD pay-as-you-go list prices (West Europe or Global meters) from the public Azure Retail Prices API
(prices.azure.com), read on PRICES_AS_OF. They are estimates for planning - negotiated (EA / MCA) prices,
reservations and other regions differ - so every figure is shown together with its pricing page.
"""

import html
import re
from typing import List, NamedTuple, Optional, Tuple

HOURS_PER_MONTH = 730
PRICES_AS_OF = "2026-10-06"

# Monthly USD list prices (hourly meters x 730).
PRICE = {
    "private_endpoint": 7.30,               # Azure Private Link, 0.01 / hour per endpoint (+ 0.01 / GB processed)
    "private_dns_zone": 0.50,               # Azure DNS private zone, per zone / month
    "log_analytics_gb": 2.99,               # Analytics logs ingestion, per GB (first 5 GB / month free)
    "apim_basic_v2": 150.00,                # API Management Basic v2, 0.20548 / hour per unit
    "apim_standard_v2": 700.00,             # API Management Standard v2, 0.9589 / hour per unit
    "apim_developer": 48.03,                # API Management Developer (no SLA), 0.0658 / hour
    "managed_redis_b1": 27.74,              # Azure Managed Redis Balanced B1, 0.038 / hour
    "bastion_basic": 138.70,                # Azure Bastion Basic, 0.19 / hour
    "firewall_basic": 288.35,               # Azure Firewall Basic, 0.395 / hour (+ per-GB processing)
    "firewall_standard": 912.50,            # Azure Firewall Standard, 1.25 / hour (+ per-GB processing)
    "acr_basic": 5.07,                      # Container Registry Basic, 0.1666 / day
    "acr_premium": 50.70,                   # Container Registry Premium, 1.6666 / day
    "defender_servers_p1": 4.91,            # per server, 0.00672 / hour
    "defender_servers_p2": 14.60,           # per server, 0.02 / hour
    "defender_storage_account": 9.78,       # per storage account, 0.0134 / hour (73M transactions included)
    "defender_storage_malware_gb": 0.15,    # malware scanning, per GB scanned
    "defender_sql_server": 15.00,           # Azure SQL, per logical server / month
    "defender_app_service_instance": 14.60,  # per App Service plan instance, 0.02 / hour
    "defender_key_vault": 0.25,             # per vault, 0.00034 / hour
    "defender_arm_subscription": 5.04,      # Defender for Resource Manager, per subscription, 0.0069 / hour
    "defender_containers_vcore": 6.87,      # per AKS vCore, 0.00941 / hour
    "defender_cspm_resource": 5.00,         # Defender CSPM, per billable resource, 0.006849 / hour
    "defender_oss_db_server": 15.00,        # PostgreSQL / MySQL flexible server, per server / month
    "defender_cosmos_100ru": 0.88,          # per 100 RU/s provisioned, 0.0012 / hour
    "defender_ai_1k_tokens": 0.0008,        # Defender for AI Services, per 1,000 tokens
}

PRICING_PAGES = {
    "defender": ("Microsoft Defender for Cloud pricing", "https://azure.microsoft.com/pricing/details/defender-for-cloud/"),
    "apim": ("API Management pricing", "https://azure.microsoft.com/pricing/details/api-management/"),
    "private_link": ("Azure Private Link pricing", "https://azure.microsoft.com/pricing/details/private-link/"),
    "monitor": ("Azure Monitor pricing", "https://azure.microsoft.com/pricing/details/monitor/"),
    "bastion": ("Azure Bastion pricing", "https://azure.microsoft.com/pricing/details/azure-bastion/"),
    "firewall": ("Azure Firewall pricing", "https://azure.microsoft.com/pricing/details/azure-firewall/"),
    "acr": ("Container Registry pricing", "https://azure.microsoft.com/pricing/details/container-registry/"),
    "backup": ("Azure Backup pricing", "https://azure.microsoft.com/pricing/details/backup/"),
    "app_service": ("App Service pricing", "https://azure.microsoft.com/pricing/details/app-service/windows/"),
    "sql": ("Azure SQL Database pricing", "https://azure.microsoft.com/pricing/details/azure-sql-database/single/"),
    "disks": ("Managed Disks pricing", "https://azure.microsoft.com/pricing/details/managed-disks/"),
    "update_manager": ("Azure Update Manager pricing",
                       "https://azure.microsoft.com/pricing/details/azure-update-management-center/"),
}

Reference = Tuple[str, str]


class Guidance(NamedTuple):
    """
    What it takes to act on a finding, and whether it is worth it.

    why          - the mechanism: what goes wrong (or what is wasted) if nothing changes
    skip_when    - when the change is not needed or not worth it (the honest "does it really need it?")
    effort       - the work, downtime and prerequisites
    hours        - engineering hours per finding (low, high)
    monthly_usd  - change in Azure run cost per finding when the recommendation is implemented (+ = more cost);
                   None when it depends on usage (run_cost then explains how to estimate it)
    run_cost     - the run-cost change in words, with its basis
    references   - (title, url) - Microsoft Learn first, then the pricing page
    cost_factor  - optional: run-cost change as a share of the resource's own monthly cost (e.g. 1.0 = one more
                   instance of a single-instance plan); used when the report knows the resource's cost
    """
    why: str
    skip_when: str
    effort: str
    hours: Tuple[float, float]
    monthly_usd: Optional[float]
    run_cost: str
    references: Tuple[Reference, ...]
    cost_factor: Optional[float] = None


def pricing(key: str) -> Reference:
    return PRICING_PAGES[key]


# ---------------------------------------------------------------------------
# Defender metadata (HTML) -> plain text and links
# ---------------------------------------------------------------------------

_HREF = re.compile(r"""<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")
_LIST_ITEM = re.compile(r"<li[^>]*>", re.I)
_BREAK = re.compile(r"<br\s*/?>|</p>|</li>|</ol>|</ul>", re.I)


def html_to_text(value: Optional[str], limit: int = 1200) -> str:
    """Defender's HTML description / remediation as readable plain text (links keep their visible text)."""
    if not value:
        return ""
    text = _LIST_ITEM.sub("\n- ", value)
    text = _BREAK.sub("\n", text)
    text = _TAG.sub("", text)
    text = html.unescape(text)
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
    text = "\n".join(line for line in lines if line)
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + " …"


def html_links(value: Optional[str]) -> List[Reference]:
    """Documentation links in Defender's HTML (portal deep links with tenant / resource IDs are left out)."""
    out: List[Reference] = []
    for url, label in _HREF.findall(value or ""):
        url = html.unescape(url.strip())
        if not url.startswith("https://") or "portal.azure.com" in url:
            continue
        title = html.unescape(_TAG.sub("", label)).strip() or url
        if title.lower() in ("here", "link", "link.", "clicking here"):
            title = url.split("//", 1)[-1].split("?")[0]
        if url not in {u for _, u in out}:
            out.append((title, url))
    return out


def portal_link(value: Optional[str]) -> Optional[str]:
    """Defender's 'links.azurePortal' (stored without a scheme) as a clickable URL."""
    if not value:
        return None
    return value if value.startswith("https://") else "https://" + value.lstrip("/")
