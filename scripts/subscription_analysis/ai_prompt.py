"""
AI-ready prompt for ARG findings.

Builds one markdown prompt (instructions + subscription context + findings) that a user can paste into
the AI assistant they use for a second opinion: prioritisation, false-positive checks and read-only
verification commands. Shared by the CLI (ai-prompt.md in every report folder), the local portal and the
Docker API, so it must stay free of Azure / database imports.

GUIDs (subscription, tenant, principal IDs) are replaced by stable aliases (<id-1>, <id-2>, ...) by default;
resource names are kept because the analysis needs them.
"""

import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

PROMPT_FILE = "ai-prompt.md"
DEFAULT_MAX_FINDINGS = 150
DEFAULT_PER_TYPE = 10
SEVERITIES = ["critical", "high", "medium", "low", "info"]
GUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

INSTRUCTIONS = """You are a senior Azure cloud architect reviewing an ARG (Azure Resource Guardian) analysis
of an Azure subscription for FinOps, security and architecture. ARG is read-only and its savings are
estimates (USD per month at the resource's own amortized cost).

Using the findings below:
1. List the 10 actions with the best risk reduction and saving, in order, with a one-line reason each.
2. Group the actions into quick wins (no-regret, days), planned changes (weeks) and structural changes.
3. Flag findings that are likely false positives or expected (for example DR replicas, system resources)
   and say what to check to confirm.
4. For each top action give read-only Azure CLI or Resource Graph commands to verify it first.
5. Call out dependencies, risks and owners to involve. Never recommend deleting anything before the
   owner confirms it.
Answer in concise markdown with tables where useful."""


def _sev_rank(severity: Optional[str]) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _cell(value: Any, limit: int = 160) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split()).replace("|", "/")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _money(value: Optional[float], zero: str = "-") -> str:
    if value is None:
        return "-"
    return f"{value:,.0f}" if value else zero


def _savings(f: Dict[str, Any]) -> float:
    try:
        return float(f.get("estimated_monthly_savings_usd") or 0)
    except (TypeError, ValueError):
        return 0.0


class IdMasker:
    """Replaces every GUID with a stable alias, so related IDs still match inside one prompt."""

    def __init__(self) -> None:
        self._aliases: Dict[str, str] = {}

    def __call__(self, text: str) -> str:
        def alias(match: "re.Match[str]") -> str:
            key = match.group(0).lower()
            if key not in self._aliases:
                self._aliases[key] = f"<id-{len(self._aliases) + 1}>"
            return self._aliases[key]

        return GUID_RE.sub(alias, text)


def sort_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Most severe first, then by estimated saving, then by title (stable for tests and diffs)."""
    return sorted(findings, key=lambda f: (_sev_rank(f.get("severity")), -_savings(f), str(f.get("title") or "")))


def _context_lines(summary: Dict[str, Any]) -> List[str]:
    sub = summary.get("subscription") or {}
    sev = summary.get("findings_by_severity") or {}
    currency = summary.get("currency") or ""
    lines = [f"- Subscription: {sub.get('name') or '-'} (`{sub.get('id') or '-'}`)"]
    if summary.get("generated_at"):
        lines.append(f"- Analysed: {str(summary['generated_at'])[:16].replace('T', ' ')} UTC")
    if summary.get("resources") is not None:
        lines.append(f"- Resources: {summary.get('resources')} in {summary.get('resource_groups', '-')} resource groups")
    lines.append(f"- Findings: {summary.get('findings', sum(sev.values()) if sev else 0)} ("
                 + ", ".join(f"{sev.get(s, 0)} {s}" for s in SEVERITIES) + ")")
    if summary.get("cost_30d") is not None:
        lines.append(f"- Cost last 30 days: {_money(summary.get('cost_30d'), '0')} {currency} (amortized)")
    saving = summary.get("savings_billing") or {}
    if saving.get("wave_1") is not None:
        lines.append(f"- Estimated monthly savings: wave 1 (no-regret) {_money(saving.get('wave_1'), '0')} {currency}, "
                     f"wave 2 (optimise) {_money(saving.get('wave_2'), '0')} {currency}")
    return lines


def _by_type(findings: List[Dict[str, Any]]) -> List[str]:
    groups: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "severity": "info", "savings": 0.0})
    for f in findings:
        g = groups[f.get("finding_type") or "unknown"]
        g["count"] += 1
        g["savings"] += _savings(f)
        if _sev_rank(f.get("severity")) < _sev_rank(g["severity"]):
            g["severity"] = f.get("severity")
    rows = sorted(groups.items(), key=lambda kv: (_sev_rank(kv[1]["severity"]), -kv[1]["savings"], -kv[1]["count"]))
    lines = ["| Finding type | Highest severity | Count | Est. saving USD/month |", "|---|---|---:|---:|"]
    lines += [f"| {_cell(t)} | {g['severity']} | {g['count']} | {_money(g['savings'])} |" for t, g in rows]
    return lines


def _findings_table(findings: List[Dict[str, Any]]) -> List[str]:
    lines = ["| Ref | Severity | Area | Type | Resource | Resource group | Est. saving USD/month | Finding |",
             "|---|---|---|---|---|---|---:|---|"]
    for i, f in enumerate(findings, 1):
        resource = f.get("resource_name") or f.get("entra_display_name") or "-"
        lines.append("| " + " | ".join([
            _cell(f.get("ref") or f"#{i}"), _cell(f.get("severity")), _cell(f.get("area") or f.get("category") or "-"),
            _cell(f.get("finding_type")), _cell(resource, 80), _cell(f.get("resource_group") or "-", 60),
            _money(_savings(f)), _cell(f.get("title"), 200),
        ]) + " |")
    return lines


def _pick(ranked: List[Dict[str, Any]], max_findings: int, per_type: int) -> List[Dict[str, Any]]:
    """Most important findings, at most per_type of each finding type, so one noisy type cannot fill the table."""
    picked, seen = [], defaultdict(int)
    for f in ranked:
        if len(picked) >= max_findings:
            break
        key = f.get("finding_type") or "unknown"
        if seen[key] < per_type:
            seen[key] += 1
            picked.append(f)
    return picked


def build_prompt(summary: Dict[str, Any], findings: Iterable[Dict[str, Any]], *,
                 max_findings: int = DEFAULT_MAX_FINDINGS, mask_ids: bool = True,
                 min_severity: Optional[str] = None, per_type: int = DEFAULT_PER_TYPE) -> str:
    """Markdown prompt for one subscription (or any finding set, e.g. a filtered Docker UI view)."""
    ranked = sort_findings(findings)
    if min_severity in SEVERITIES:
        ranked = [f for f in ranked if _sev_rank(f.get("severity")) <= _sev_rank(min_severity)]
    shown = _pick(ranked, max(0, max_findings), max(1, per_type))
    lines = [INSTRUCTIONS, "", "## Context", ""] + _context_lines(summary)
    lines += ["", f"## Findings by type ({len(ranked)} findings)", ""] + (_by_type(ranked) if ranked else ["None."])
    lines += ["", f"## Findings, most severe first (up to {max(1, per_type)} per type)", ""]
    if shown:
        lines += _findings_table(shown)
        if len(ranked) > len(shown):
            lines += ["", f"{len(ranked) - len(shown)} more findings are not listed; the table by type above "
                          "counts them."]
    else:
        lines.append("None.")
    text = "\n".join(lines) + "\n"
    return IdMasker()(text) if mask_ids else text
