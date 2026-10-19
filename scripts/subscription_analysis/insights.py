"""
Architect-level views over a subscription's findings, inventory and cost - what the executive summary leads with:

- systemic_issues():   the same gap on many resources is a platform problem; fix it once with an Azure Policy
                       guardrail (built-in definitions below, names checked against the policy catalogue) instead of
                       N tickets;
- allocation():        how much of the spend can be charged back (required tags present), weighted by cost;
- environment_split(): production vs non-production spend;
- cost_coverage():     whether the resources that carry the money have any recommendation at all - spend nobody
                       looked at needs a design review, not a scanner;
- quick_wins():        material items that take an hour or less and add no run cost;
- retirement_calendar(): dated retirements and end-of-support across the subscription;
- changes():           what changed since the previous analysis of the same subscription.
"""

import re
from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Tuple

from scripts.subscription_analysis.estate import HYGIENE_TYPES, environment_of

# finding type -> built-in Azure Policy definitions / initiatives that prevent it (display names, as in the portal)
GUARDRAILS: Dict[str, Tuple[str, ...]] = {
    "storage_shared_key_access_enabled": ("Storage accounts should prevent shared key access (Audit, then Deny)",),
    "storage_public_network_access": ("Storage accounts should disable public network access (Audit / Deny)",
                                      "Configure storage accounts to disable public network access (Modify)"),
    "public_storage_account": ("Storage account public access should be disallowed (Deny)",
                               "Configure your Storage account public access to be disallowed (Modify)"),
    "managed_disk_public_network_access": ("Managed disks should disable public network access (Audit / Deny)",
                                           "Configure managed disks to disable public network access (Modify)"),
    "key_vault_access_policy_model": ("Azure Key Vault should use RBAC permission model (Deny for new vaults)",),
    "key_vault_purge_protection_disabled": ("Key vaults should have deletion protection enabled (Deny)",),
    "key_vault_soft_delete_disabled": ("Key vaults should have soft delete enabled (Deny)",),
    "key_vault_public_network_open": ("Azure Key Vault should disable public network access (Audit / Deny)",
                                      "Configure Azure Key Vaults with private endpoints (DeployIfNotExists)"),
    "ai_services_local_auth_enabled": ("Azure AI Services resources should have key access disabled (disable local "
                                       "authentication) (Deny)",),
    "ai_services_public_network_open": ("Azure AI Services resources should restrict network access (Deny)",),
    "missing_required_tags": ("Require a tag on resources (Deny, per tag)",
                              "Inherit a tag from the resource group if missing (Modify)"),
    "web_app_https_not_enforced": ("Configure App Service apps to only be accessible over HTTPS (Modify)",),
    "web_app_ftp_enabled": ("App Service apps should require FTPS only (AuditIfNotExists)",),
    "web_app_weak_tls": ("Configure App Service apps to use the latest TLS version (DeployIfNotExists)",),
    "web_app_managed_identity_missing": ("App Service apps should use managed identity (AuditIfNotExists)",),
    "sql_entra_only_auth_disabled": ("Azure SQL Database should have Microsoft Entra-only authentication enabled "
                                     "(Audit, then Deny)",),
    "public_sql_server": ("Public network access on Azure SQL Database should be disabled (Deny)",),
    "subnet_without_nsg": ("Subnets should be associated with a Network Security Group (AuditIfNotExists)",),
    "missing_diagnostic_settings": ("Enable allLogs category group resource logging for supported resources to Log "
                                    "Analytics (initiative, DeployIfNotExists)",),
    "nsg_management_port_open_to_internet": ("Management ports should be closed on your virtual machines "
                                             "(AuditIfNotExists)",),
    "service_health_alert_missing": ("Configure subscriptions to enable service health alert monitoring rule "
                                     "(DeployIfNotExists)",),
}
SYSTEMIC_MIN_COUNT = 10        # this many resources with the same gap ...
SYSTEMIC_MIN_SHARE = 0.5       # ... or at least 3 and half of all resources of that type
LABELS = {
    "missing_required_tags": "Required tags missing",
    "naming_convention_violation": "Names outside the naming convention",
    "storage_shared_key_access_enabled": "Storage accounts accept shared keys",
    "storage_public_network_access": "Storage accounts open to all networks",
    "storage_blob_soft_delete_disabled": "Blob soft delete off",
    "managed_disk_public_network_access": "Managed disks exportable from any network",
    "unused_storage_account": "Unused storage accounts",
    "missing_diagnostic_settings": "No diagnostic settings",
    "web_app_health_check_missing": "App Service health check missing",
    "environment_tag_name_mismatch": "Environment tag contradicts the name",
    "defender_recommendations": "Defender for Cloud recommendations",
}


LABELS.update({
    "sql_firewall_allow_all_azure_services": "SQL firewall allows all Azure services",
    "sql_firewall_individual_ip_rules": "SQL firewall rules for individual IPs",
    "sql_firewall_wide_ip_range": "SQL firewall rules for wide IP ranges",
    "public_sql_server": "SQL servers reachable from the internet",
    "sql_entra_only_auth_disabled": "SQL servers accept SQL logins",
    "app_service_plan_single_instance": "Single-instance App Service plans",
    "key_vault_access_policy_model": "Key Vaults on access policies",
    "key_vault_purge_protection_disabled": "Key Vaults without purge protection",
    "key_vault_public_network_open": "Key Vaults open to all networks",
    "ai_services_local_auth_enabled": "AI accounts accept API keys",
    "ai_services_public_network_open": "AI accounts open to all networks",
    "subnet_without_nsg": "Subnets without an NSG",
    "orphaned_nsg": "Unattached NSGs",
    "old_disk_snapshot": "Old disk snapshots",
    "dormant_storage_data": "Dormant data in hot storage",
    "web_app_managed_identity_missing": "Web apps without managed identity",
    "web_app_eol_runtime": "Web apps on end-of-support runtimes",
    "public_storage_account": "Storage accounts with anonymous blob access",
})
_ACRONYMS = {"sql": "SQL", "ip": "IP", "nsg": "NSG", "vm": "VM", "vms": "VMs", "ai": "AI", "tls": "TLS", "os": "OS",
             "ftp": "FTP", "eol": "EOL", "vmss": "VMSS", "saas": "SaaS", "ddos": "DDoS"}


def label(finding_type: str) -> str:
    if finding_type in LABELS:
        return LABELS[finding_type]
    words = [_ACRONYMS.get(w, w) for w in finding_type.split("_")]
    return " ".join([words[0][:1].upper() + words[0][1:]] + words[1:])


def is_hygiene(f: Dict[str, Any]) -> bool:
    return f.get("finding_type") in HYGIENE_TYPES


def systemic_issues(findings: List[Dict[str, Any]], resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Finding types that hit many resources (or most resources of their type), costliest / most severe first."""
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        rtype = (f.get("resource_type") or "").lower()
        if rtype == "microsoft.resources/subscriptions" or rtype.startswith("microsoft.consumption") or \
                f.get("finding_type") in ("defender_recommendations", "advisor_cost_recommendation",
                                          "service_retirement"):
            continue   # subscription-level, budgets, and imported findings that mix several issues
        by_type.setdefault(f["finding_type"], []).append(f)
    type_counts: Dict[str, int] = {}
    for r in resources:
        t = (r.get("type") or "").lower()
        type_counts[t] = type_counts.get(t, 0) + 1
    out = []
    for ftype, items in by_type.items():
        rtypes = {(i.get("resource_type") or "").lower() for i in items}
        population = sum(type_counts.get(t, 0) for t in rtypes) or len(items)
        share = len(items) / population if population else 1.0
        if len(items) < SYSTEMIC_MIN_COUNT and not (len(items) >= 3 and share >= SYSTEMIC_MIN_SHARE):
            continue
        refs = sorted(i.get("ref") or "" for i in items)
        out.append({"finding_type": ftype, "label": label(ftype), "count": len(items),
                    "population": population, "share": min(share, 1.0),
                    "severity": min((i["severity"] for i in items), key=_sev_rank),
                    "saving_usd": round(sum(i.get("estimated_monthly_savings_usd") or 0 for i in items), 2),
                    "guardrails": list(GUARDRAILS.get(ftype, ())), "refs": refs,
                    "folder": items[0].get("folder"), "hygiene": ftype in HYGIENE_TYPES})
    return sorted(out, key=lambda s: (s["hygiene"], _sev_rank(s["severity"]), -s["count"]))


def _sev_rank(sev: str) -> int:
    order = ["critical", "high", "medium", "low", "info"]
    return order.index(sev) if sev in order else len(order)


def _cost_index(costs: Dict[str, Dict[str, Any]]) -> Dict[str, float]:
    return {rid.lower(): float(e.get("cost") or 0) for rid, e in (costs or {}).items()}


def allocation(resources: List[Dict[str, Any]], costs: Dict[str, Dict[str, Any]], required_tags: Iterable[str]
               ) -> Optional[Dict[str, Any]]:
    """Share of the last 30 days' spend on resources carrying every required tag (case-insensitive keys)."""
    by_id = _cost_index(costs)
    total = sum(by_id.values())
    if not total:
        return None
    required = [t.lower() for t in required_tags or []]
    inventory = {(r.get("id") or "").lower(): r for r in resources}
    tagged = 0.0
    missing: Dict[str, float] = {t: 0.0 for t in required}
    unknown = 0.0
    for rid, cost in by_id.items():
        r = inventory.get(rid)
        if r is None:
            unknown += cost   # deleted since, or a scope that is not a resource (reservation, Marketplace)
            continue
        keys = {k.lower() for k in (r.get("tags") or {})}
        absent = [t for t in required if t not in keys]
        if not absent:
            tagged += cost
        for t in absent:
            missing[t] += cost
    in_use: Dict[str, int] = {}
    for r in resources:
        for k in r.get("tags") or {}:
            in_use[k] = in_use.get(k, 0) + 1
    return {"total": total, "tagged": tagged, "share": tagged / total, "not_in_inventory": unknown,
            "missing_by_tag": dict(sorted(missing.items(), key=lambda kv: -kv[1])), "required_tags": required,
            "tags_in_use": [k for k, _ in sorted(in_use.items(), key=lambda kv: -kv[1])[:6]],
            "resources": len(resources)}


def environment_split(resources: List[Dict[str, Any]], costs: Dict[str, Dict[str, Any]], subscription_name: str
                      ) -> Dict[str, float]:
    by_id = _cost_index(costs)
    inventory = {(r.get("id") or "").lower(): r for r in resources}
    split: Dict[str, float] = {}
    for rid, cost in by_id.items():
        r = inventory.get(rid) or {"id": rid, "name": rid.rsplit("/", 1)[-1],
                                   "resourceGroup": rid.split("/")[4] if rid.count("/") > 4 else ""}
        env = environment_of(r, subscription_name)
        split[env] = split.get(env, 0.0) + cost
    return dict(sorted(split.items(), key=lambda kv: -kv[1]))


def cost_coverage(top_resources: List[Tuple[str, Dict[str, Any]]], findings: List[Dict[str, Any]], total: float,
                  limit: int = 10) -> Dict[str, Any]:
    """For the costliest resources: which findings address them. Uncovered spend needs a design review."""
    by_resource: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        if not is_hygiene(f):
            by_resource.setdefault((f.get("resource_id") or "").lower(), []).append(f)
    rows = []
    for rid, entry in top_resources[:limit]:
        items = by_resource.get(rid.lower(), [])
        cost = float(entry.get("cost") or 0)
        rows.append({"resource_id": rid, "cost": cost, "share": cost / total if total else 0.0,
                     "findings": [f.get("ref") for f in items],
                     "saving_usd": round(sum(f.get("estimated_monthly_savings_usd") or 0 for f in items), 2),
                     "meter": max((entry.get("meters") or {"-": 0}).items(), key=lambda kv: kv[1])[0]})
    uncovered = [r for r in rows if not r["findings"]]
    return {"rows": rows, "uncovered_cost": sum(r["cost"] for r in uncovered),
            "uncovered_share": (sum(r["cost"] for r in uncovered) / total) if total else 0.0,
            "top_share": (sum(r["cost"] for r in rows) / total) if total else 0.0}


def quick_wins(findings: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    """Material items (a saving, or critical / high) that take at most an hour and add no run cost."""
    wins = []
    for f in findings:
        impl = f.get("implementation") or {}
        hours = impl.get("hours")
        if is_hygiene(f) or not hours or hours[1] > 1 or (impl.get("monthly_usd") or 0) > 0:
            continue
        saving = f.get("estimated_monthly_savings_usd") or 0
        if saving <= 0 and f.get("severity") not in ("critical", "high"):
            continue
        wins.append(f)
    return sorted(wins, key=lambda f: (-(f.get("estimated_monthly_savings_usd") or 0), _sev_rank(f["severity"])))[:limit]


def retirement_calendar(findings: List[Dict[str, Any]], today: Optional[date] = None) -> List[Dict[str, Any]]:
    """
    Dated retirements (Advisor) and end-of-support (OS images, runtimes), one row per retirement and date with the
    resources it affects, soonest first, overdue included.
    """
    today = today or date.today()
    groups: Dict[Tuple[Any, str], Dict[str, Any]] = {}

    def add(when: Any, what: str, f: Dict[str, Any], cost: Optional[str]) -> None:
        g = groups.setdefault((when, what), {"date": when, "what": what, "resources": [], "refs": [], "cost": cost})
        if f.get("resource_name") not in g["resources"]:
            g["resources"].append(f.get("resource_name"))
        if f.get("ref") and f["ref"] not in g["refs"]:
            g["refs"].append(f["ref"])

    for f in findings:
        evidence = f.get("evidence") or {}
        if f.get("finding_type") == "service_retirement":
            for r in evidence.get("retirements") or []:
                add(r.get("retirement_date"), r.get("feature") or r.get("problem"), f, r.get("cost_implication"))
        elif f.get("finding_type") in ("vm_unsupported_os", "web_app_eol_runtime") and evidence.get("end_of_support"):
            add(evidence["end_of_support"], f.get("title", "").split(":")[0], f, None)
    rows = list(groups.values())
    for r in rows:
        try:
            r["days_left"] = (date.fromisoformat(str(r["date"])[:10]) - today).days
        except (TypeError, ValueError):
            r["days_left"] = None
    return sorted(rows, key=lambda r: (r["days_left"] is None, r["days_left"] if r["days_left"] is not None else 0,
                                       -len(r["resources"])))


# Advisor reliability recommendations that a native ARG finding already reports (not repeated in the section).
RELIABILITY_COVERED = re.compile(r"soft delete to protect your blob data|create an azure service health alert|"
                                 r"enable health check for app service|minimum instance count for app service", re.I)
RELIABILITY_ORDER = ("ZoneResiliency", "DataProtectionAndRecovery", "RegionalResiliency", "Scalability",
                     "MonitoringAndAlerting", "GovernanceAndCompliance", "Other")


def resilience(rows: List[Dict[str, Any]], resources: List[Dict[str, Any]], subscription_name: str
               ) -> List[Dict[str, Any]]:
    """Advisor reliability recommendations grouped per recommendation, with how many affect production."""
    inventory = {(r.get("id") or "").lower(): r for r in resources}
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        if RELIABILITY_COVERED.search(row.get("problem") or ""):
            continue
        key = (row.get("sub_category") or "Other", row.get("problem") or "")
        g = groups.setdefault(key, {"sub_category": key[0], "problem": key[1], "impact": row.get("impact"),
                                    "resources": set(), "production": set(), "examples": []})
        rid = (row.get("resource_id") or "").lower()
        if rid in g["resources"]:
            continue
        g["resources"].add(rid)
        r = inventory.get(rid) or {"id": rid, "name": row.get("impacted_name") or rid.rsplit("/", 1)[-1],
                                   "resourceGroup": rid.split("/")[4] if rid.count("/") > 4 else ""}
        if environment_of(r, subscription_name) == "Production":
            g["production"].add(rid)
            if len(g["examples"]) < 4:
                g["examples"].append(r.get("name") or rid.rsplit("/", 1)[-1])
    out = []
    for g in groups.values():
        if not g["examples"]:
            g["examples"] = sorted(rid.rsplit("/", 1)[-1] for rid in g["resources"])[:4]
        out.append({**g, "resources": len(g["resources"]), "production": len(g["production"])})
    rank = {c: i for i, c in enumerate(RELIABILITY_ORDER)}
    return sorted(out, key=lambda g: (-g["production"], rank.get(g["sub_category"], 99), -g["resources"]))


def finding_key(f: Dict[str, Any]) -> str:
    return f"{(f.get('resource_id') or '').lower()}|{f.get('finding_type')}"


def changes(previous: Optional[List[Dict[str, Any]]], current: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """New, resolved and re-rated findings against the previous analysis of the same subscription."""
    if previous is None:
        return None
    before = {finding_key(f): f for f in previous}
    after = {finding_key(f): f for f in current}
    new = [after[k] for k in after.keys() - before.keys()]
    resolved = [before[k] for k in before.keys() - after.keys()]
    worse = [after[k] for k in after.keys() & before.keys()
             if _sev_rank(after[k]["severity"]) < _sev_rank(before[k]["severity"])]
    def key(f):
        return _sev_rank(f["severity"]), -(f.get("estimated_monthly_savings_usd") or 0)
    return {"new": sorted(new, key=key), "resolved": sorted(resolved, key=key), "worse": sorted(worse, key=key)}
