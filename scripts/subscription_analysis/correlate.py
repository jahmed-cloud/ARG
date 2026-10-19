"""
Cross-scanner correlation: one finding per issue.

Defender for Cloud and Azure Advisor re-report many issues ARG's own scanners already find with more context
(measured usage, cost, commands). After all scanners ran, this step
- removes Defender recommendations that a native finding on the same resource already covers, and records them on
  the native finding as corroboration (evidence["also_reported_by"]);
- removes Advisor cost items on resources where a native finding already carries a saving, so no saving is counted
  twice;
- drops a Defender / Advisor finding that has nothing left.

Works on finding dicts (local report) and ScannerFinding objects (Docker worker) alike.
"""

import re
from typing import Any, Dict, Iterable, List, Pattern, Tuple

# native finding type -> Defender recommendations it makes redundant on the same resource
DEFENDER_DUPLICATES: Dict[str, Pattern] = {k: re.compile(v, re.I) for k, v in {
    "key_vault_access_policy_model": r"role-based access control should be used on azure keyvault",
    "key_vault_purge_protection_disabled": r"key vaults should have (deletion|purge) protection enabled",
    "key_vault_soft_delete_disabled": r"key vaults should have soft delete enabled",
    "key_vault_public_network_open": r"key vaults should use private link|firewall should be enabled on key vault|"
                                     r"key vault should disable public network access",
    "storage_shared_key_access_enabled": r"storage accounts should prevent shared key access",
    "storage_public_network_access": r"storage account should use a private link|storage accounts should restrict "
                                     r"network access|storage accounts should disable public network access",
    "public_storage_account": r"storage account public access should be disallowed",
    "ai_services_local_auth_enabled": r"(foundry|ai services|cognitive services) resources should have key access "
                                      r"disabled",
    "ai_services_public_network_open": r"(foundry|ai services|cognitive services) resources should (restrict network "
                                       r"access|use azure private link)",
    "web_app_managed_identity_missing": r"managed identity should be enabled on (web|function|api) apps",
    "web_app_https_not_enforced": r"should only be accessible over https",
    "web_app_ftp_enabled": r"ftps (only )?should be required",
    "web_app_weak_tls": r"should use the latest tls version",
    "sql_entra_only_auth_disabled": r"azure sql database should have .*only authentication enabled",
    "public_sql_server": r"public network access on azure sql database should be disabled|private endpoint "
                         r"connections on azure sql database should be enabled",
    "excessive_subscription_owners": r"maximum of 3 owners should be designated",
    "nsg_management_port_open_to_internet": r"management ports should be closed|management ports of virtual "
                                            r"machines should be protected",
    "missing_diagnostic_settings": r"(diagnostic|resource) logs in .* should be enabled",
}.items()}


def _get(f: Any, key: str) -> Any:
    return f.get(key) if isinstance(f, dict) else getattr(f, key, None)


def _set(f: Any, key: str, value: Any) -> None:
    if isinstance(f, dict):
        f[key] = value
    else:
        setattr(f, key, value)


def _scope(f: Any) -> str:
    """Resource ID in lower case; Defender's subscription-level 'security entities' count as the subscription."""
    rid = (_get(f, "resource_id") or "").lower()
    if "/providers/microsoft.security/" in rid and "/resourcegroups/" not in rid:
        return rid.split("/providers/")[0]
    return rid


def _note(native: Any, source: str) -> None:
    evidence = dict(_get(native, "evidence") or {})
    seen = list(evidence.get("also_reported_by") or [])
    if source not in seen:
        seen.append(source)
    evidence["also_reported_by"] = seen
    _set(native, "evidence", evidence)


def _rebuild_defender(f: Any, remaining: List[Dict[str, Any]]) -> None:
    """Title, description, remediation and commands of a Defender finding from the recommendations it keeps."""
    labels = [(a.get("label") or a.get("assessment") or "").rstrip(".") for a in remaining]
    scope = _scope(f)
    on_subscription = "/resourcegroups/" not in scope
    target = "subscription" if on_subscription else (_get(f, "resource_name") or scope.rsplit("/", 1)[-1])
    _set(f, "title", f"Defender: {labels[0]} ({target})" if len(labels) == 1
         else f"{len(labels)} Defender recommendations on {target}: {labels[0]}, …")
    _set(f, "description", f"Defender for Cloud reports {len(labels)} unhealthy recommendation(s) on "
                           f"{'the subscription' if on_subscription else target}: " + "; ".join(labels) + ".")
    if all(a.get("steps") for a in remaining):
        _set(f, "remediation_steps", "\n\n".join(f"{label}:\n{a['steps']}" for label, a in zip(labels, remaining)))
    scripts = [f"# {label}\n{a['cli']}" for label, a in zip(labels, remaining) if a.get("cli")]
    _set(f, "azure_cli_script", "\n\n".join(scripts) or None)


def correlate(findings: Iterable[Any]) -> Tuple[List[Any], Dict[str, int]]:
    """(kept findings, counts of what was merged). The input list is not modified; kept objects may be."""
    findings = list(findings)
    natives: Dict[str, List[Any]] = {}
    for f in findings:
        if _get(f, "finding_type") not in ("defender_recommendations", "advisor_cost_recommendation",
                                           "service_retirement"):
            natives.setdefault(_scope(f), []).append(f)
    stats = {"defender_recommendations_merged": 0, "advisor_items_merged": 0, "findings_dropped": 0}
    kept: List[Any] = []
    for f in findings:
        ftype = _get(f, "finding_type")
        here = natives.get(_scope(f), [])
        if ftype == "defender_recommendations" and here:
            evidence = dict(_get(f, "evidence") or {})
            remaining = []
            for a in evidence.get("assessments") or []:
                name = a.get("assessment") or ""
                match = next((n for n in here if (p := DEFENDER_DUPLICATES.get(_get(n, "finding_type")))
                              and p.search(name)), None)
                if match is None:
                    remaining.append(a)
                else:
                    _note(match, f"Defender for Cloud: {a.get('label') or name}")
                    stats["defender_recommendations_merged"] += 1
            if not remaining:
                stats["findings_dropped"] += 1
                continue
            if len(remaining) != len(evidence.get("assessments") or []):
                evidence["assessments"] = remaining
                evidence["merged_into_native_findings"] = True
                _set(f, "evidence", evidence)
                _rebuild_defender(f, remaining)
        elif ftype == "service_retirement" and here:
            # Advisor runtime / OS retirements that ARG's end-of-support finding on the resource already dates
            eol = {(_get(n, "evidence") or {}).get("end_of_support"): n for n in here
                   if _get(n, "finding_type") in ("web_app_eol_runtime", "vm_unsupported_os")}
            evidence = dict(_get(f, "evidence") or {})
            items = evidence.get("retirements") or []
            remaining = [r for r in items if r.get("retirement_date") not in eol]
            for r in items:
                if r not in remaining:
                    _note(eol[r.get("retirement_date")], f"Azure Advisor: {r.get('problem')}")
                    stats["retirements_merged"] = stats.get("retirements_merged", 0) + 1
            if not remaining:
                stats["findings_dropped"] += 1
                continue
            if len(remaining) != len(items):
                evidence["retirements"] = remaining
                _set(f, "evidence", evidence)
        elif ftype == "advisor_cost_recommendation":
            with_saving = [n for n in here if (_get(n, "estimated_monthly_savings_usd") or 0) > 0]
            if with_saving:
                evidence = dict(_get(f, "evidence") or {})
                for item in evidence.get("advisor") or []:
                    _note(with_saving[0], f"Azure Advisor: {item.get('problem')}")
                stats["advisor_items_merged"] += len(evidence.get("advisor") or [])
                stats["findings_dropped"] += 1
                continue
        kept.append(f)
    return kept, stats
