"""
Analysis settings: which optional checks run and how implementation costs are expressed.

One definition for every place that edits or applies them:
- local runs (CLI and local portal) read <reports-dir>/settings.json, written by the portal's Settings page;
- the Docker stack stores them in governance_configs.scanner_settings (Settings → Governance Configuration);
- `--config file.json` still overrides both for a single CLI run.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional

from scanners.base.providers import DEFAULT_BLOCKED_PROVIDERS
from scanners.governance.governance_scanners import DEFAULT_REQUIRED_TAGS

SETTINGS_FILE = "settings.json"


class Setting(NamedTuple):
    key: str
    label: str
    kind: str          # bool | list | number | choice | text
    default: Any
    help: str
    choices: tuple = ()
    local_only: bool = False   # the Docker stack edits it elsewhere (required tags: Governance Configuration)


SETTINGS: List[Setting] = [
    Setting("required_tags", "Required tags (company tag standard)", "list", list(DEFAULT_REQUIRED_TAGS),
            "Tag names every resource must carry. Drives the missing-tag findings and the cost-allocation KPI "
            "(share of spend that can be charged back). Case-insensitive.", local_only=True),
    Setting("required_tags_check", "Missing-tag findings (one per resource)", "bool", False,
            "Raises a finding for every resource that misses a required tag. Off: the report shows tag coverage as "
            "one cost-weighted KPI (share of spend that can be charged back) instead of thousands of findings."),
    Setting("defender_recommendations", "Import Defender for Cloud recommendations as findings", "bool", False,
            "Off: the report shows a short Defender for Cloud summary (open recommendations by severity, the top ones "
            "with a link to open them in Defender) and you work through them in Defender for Cloud itself, where "
            "exemptions, owners and due dates live. On: each unhealthy recommendation becomes a ARG finding."),
    Setting("naming_convention_enabled", "Naming convention check", "bool", True,
            "Flags resources whose names do not match the naming patterns. Most Azure resources cannot be renamed in "
            "place, so switch it off unless a naming standard is being enforced."),
    Setting("defender_plan_recommendations", "Defender plan-enablement recommendations", "bool", False,
            "Includes Defender for Cloud recommendations that only ask to buy a paid plan (\"Microsoft Defender for "
            "Storage plan should be enabled ...\", \"Microsoft Defender CSPM should be enabled\"). Off: plan choice "
            "is a central cost decision, not a per-subscription gap."),
    Setting("defender_plan_coverage", "Defender plan coverage with cost per plan", "bool", False,
            "One finding per subscription listing the Defender plans on Free, what each would cost on the "
            "subscription's resources and when it is worth it. Use it when preparing the plan decision."),
    Setting("report_unused_providers", "Niche resource providers registered but unused", "bool", False,
            "Lists niche providers registered with no resources (core services such as Compute, Storage and "
            "Network, and the governance baseline, are never listed). Informational: unregistering saves nothing - "
            "restrict services with an 'Allowed / Not allowed resource types' policy instead."),
    Setting("blocked_resource_providers", "Blocked resource providers", "list", list(DEFAULT_BLOCKED_PROVIDERS),
            "Providers that must not be registered (raised as a finding when they are). Default: the retired classic "
            "(ASM) providers."),
    Setting("sensitive_data_tags", "Confidential-data tags (private endpoint required)", "list", [],
            "Tag=value pairs that mark confidential data, e.g. DataClassification=Confidential. An open storage account, Key "
            "Vault, database or AI endpoint carrying one gets a private endpoint recommendation. Without a match "
            "the cheapest control that fits the resource's use is recommended (public access off for data nobody "
            "reads, trusted services, service endpoints, IP rules) - a private endpoint costs about USD 7.30 per "
            "month each."),
    Setting("ai_reasoning", "AI review (thinking mode, Azure OpenAI in your tenant)", "bool", False,
            "After the built-in reasoning, an Azure OpenAI model in your own tenant reviews the subscription like a "
            "principal architect: challenges recommendations where the evidence points elsewhere, finds themes and "
            "asks the owner what the data cannot answer. Sends finding facts with GUIDs masked (no tag values, no "
            "secrets) to the endpoint below only; one request per subscription (typically 6-15k tokens). Sign-in: "
            "Entra ID - your az login locally, the service principal in Docker (role 'Cognitive Services OpenAI "
            "User' on the resource) - or the ARG_AOAI_API_KEY environment variable."),
    Setting("ai_endpoint", "AI review - Azure OpenAI endpoint", "text", "",
            "e.g. https://<name>.openai.azure.com (Azure OpenAI or AI Services resource in the company tenant)."),
    Setting("ai_deployment", "AI review - model deployment name", "text", "",
            "The deployment of a chat model that supports JSON output, e.g. gpt-4.1 or gpt-4o."),
    Setting("ai_max_findings", "AI review - findings per subscription", "number", 30,
            "The most severe / most expensive findings sent for review (tag and naming hygiene excluded)."),
    Setting("display_currency", "Currency shown in the web app and reports", "choice", "Billing currency",
            "Billing currency: savings, prices and costs in each subscription's own invoice currency (CHF, EUR, ...), "
            "converted at the rate Cost Management applied to that subscription's amortized cost (billing cost / USD "
            "cost, last 30 days) - report pages, the estate page and the Docker UI. USD: US dollars, the report "
            "showing the billing amount next to its USD equivalent.", ("Billing currency", "USD")),
    Setting("amortized_cost", "Amortized cost", "bool", True,
            "On (recommended): amortized cost - reservation and savings-plan purchases are spread over the resources "
            "and days that use them, so a covered VM or database shows its real share and savings are valued at "
            "what a resource really costs. Off: actual (invoiced) cost - purchases show in full in the month they "
            "are paid, on the subscription that bought them, and covered resources look free. Applies to the next "
            "analysis, scan and estate refresh. Budgets and Marketplace terms are always judged on invoiced cost."),
    Setting("required_vm_extensions", "Required VM agent extensions", "text", "",
            "Agent extensions every VM must carry (vm_required_extension_scanner; empty = check off). Comma-separated; "
            "'|' separates alternatives that satisfy one entry (extension name or type), e.g. "
            "AzureMonitorWindowsAgent|AzureMonitorLinuxAgent, MDE.Windows|MDE.Linux."),
    Setting("include_arc_machines", "Required VM extensions - also Azure Arc servers", "bool", False,
            "Also checks Azure Arc-enabled servers for the required agent extensions."),
    Setting("engineering_hourly_rate_usd", "Engineering hourly rate (USD)", "number", None,
            "Optional. When set, the effort hours of every recommendation are also shown as a one-off amount."),
    Setting("ai_gateway_sku", "AI gateway tier for cost estimates", "choice", "Basic v2",
            "API Management tier priced into the AI gateway recommendation.", ("Basic v2", "Standard v2", "Developer")),
    Setting("landing_zone_mapping", "Landing zone - management group archetypes", "list", [],
            "Maps your management groups to Azure Landing Zones archetypes for the Architecture > Landing zone view, "
            "one 'group = archetype' per line (display name or ID; a name used twice maps both), e.g. "
            "'Corp workloads = corp', 'Online apps = online'. Archetypes: root, platform, connectivity, identity, "
            "management, security, landing_zones, corp, online, local, sandbox, decommissioned, outside, none. "
            "Groups not listed are classified by their name and position."),
]
REPORT_SETTINGS = frozenset(s.key for s in SETTINGS)
DEFAULTS: Dict[str, Any] = {s.key: s.default for s in SETTINGS}


def normalize(values: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Known keys only, coerced to their type; unknown keys and invalid values are dropped."""
    out: Dict[str, Any] = {}
    for s in SETTINGS:
        if not values or s.key not in values:
            continue
        v = values[s.key]
        if s.kind == "bool":
            out[s.key] = v if isinstance(v, bool) else str(v).strip().lower() in ("1", "true", "on", "yes")
        elif s.kind == "list":
            items = v.replace(",", "\n").splitlines() if isinstance(v, str) else list(v or [])
            out[s.key] = sorted({str(i).strip() for i in items if str(i).strip()}, key=str.lower)
        elif s.kind == "number":
            try:
                out[s.key] = float(v) if v not in (None, "") and float(v) > 0 else None
            except (TypeError, ValueError):
                continue
        elif s.kind == "choice":
            if v in s.choices:
                out[s.key] = v
        elif s.kind == "text":
            out[s.key] = str(v or "").strip()[:300]
    return out


def load(reports_dir: Optional[Path]) -> Dict[str, Any]:
    """Saved local settings (normalized), {} when none were saved or the file is unreadable."""
    if reports_dir is None:
        return {}
    path = Path(reports_dir) / SETTINGS_FILE
    try:
        return normalize(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}


def save(reports_dir: Path, values: Dict[str, Any]) -> Dict[str, Any]:
    clean = normalize(values)
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    (Path(reports_dir) / SETTINGS_FILE).write_text(json.dumps(clean, indent=2), encoding="utf-8")
    return clean


def env_defaults() -> Dict[str, Any]:
    """Defaults set in the environment (.env): AMORTIZED_COST, DISPLAY_CURRENCY (billing / USD),
    REQUIRED_VM_EXTENSIONS, REQUIRED_VM_EXTENSIONS_INCLUDE_ARC. Saved settings still win."""
    raw = {}
    if os.getenv("AMORTIZED_COST", "").strip():
        raw["amortized_cost"] = os.environ["AMORTIZED_COST"]
    if os.getenv("DISPLAY_CURRENCY", "").strip():
        raw["display_currency"] = "USD" if os.environ["DISPLAY_CURRENCY"].strip().upper() == "USD"             else "Billing currency"
    if os.getenv("REQUIRED_VM_EXTENSIONS", "").strip():
        raw["required_vm_extensions"] = os.environ["REQUIRED_VM_EXTENSIONS"]
    if os.getenv("REQUIRED_VM_EXTENSIONS_INCLUDE_ARC", "").strip():
        raw["include_arc_machines"] = os.environ["REQUIRED_VM_EXTENSIONS_INCLUDE_ARC"]
    return normalize(raw)


def effective(reports_dir: Optional[Path]) -> Dict[str, Any]:
    return {**DEFAULTS, **env_defaults(), **load(reports_dir)}
