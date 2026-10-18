"""
What governs this resource? - every Azure Policy assignment that applies to one resource (scope by scope, from
the root management group down), the exemptions that cover it, and its compliance state per policy. The question
behind every "RequestDisallowedByPolicy" deployment error.

    python -m scripts.what_governs --resource-id /subscriptions/<id>/resourceGroups/<rg>/providers/<type>/<name>
    python -m scripts.what_governs --resource-id /subscriptions/<id>/resourceGroups/<rg> --non-compliant-only
    python -m scripts.what_governs --resource-id <id> --json > governs.json

Read-only: Azure Resource Graph queries with your `az login` (Reader on the subscription and on the management
groups above it). The same lookup is served by GET /api/v1/governance/what-governs in the Docker stack.
"""

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanners.base.base_scanner import ScanContext  # noqa: E402
from scanners.base.policy import what_governs  # noqa: E402

RESOURCE_ID = re.compile(r"^/subscriptions/([0-9a-fA-F-]{36})(/\S*)?$")


def render(result: Dict[str, Any], non_compliant_only: bool = False) -> List[str]:
    lines = [f"Resource: {result['resource_id']}", "", "== Compliance =="]
    rows = [r for r in result["compliance"] if not non_compliant_only or r["state"] == "NonCompliant"]
    if not result["compliance"]:
        lines += ["  No compliance data yet. A new assignment takes 5-30 minutes to evaluate; force it with:",
                  "    az policy state trigger-scan --subscription <subscription-id>"]
    for r in rows:
        ref = f" [{r['reference']}]" if r.get("reference") else ""
        lines.append(f"  {r['state'] or '?':<14} {r['effect'] or '':<20} {r['policy']}{ref}  via {r['assignment']}")
    s = result["summary"]
    lines += [f"  {s['evaluations']} evaluation(s): {s['non_compliant']} non-compliant, {s['exempt']} exempt", "",
              "== Scope chain (inheritance is additive; for Deny the most restrictive result wins) =="]
    for depth, level in enumerate(result["scopes"]):
        pad = "  " * (depth + 1)
        lines.append(f"{pad}{level['scope'].rsplit('/', 1)[-1]}  ({level['scope']})")
        for a in level["assignments"]:
            kind = "initiative" if a.get("initiative") else "policy"
            lines.append(f"{pad}  -> {a['name']}  [{'Enforced' if a['enforced'] else 'DoNotEnforce'}, {kind}]")
    lines += ["", "== Exemptions covering this resource =="]
    if not result["exemptions"]:
        lines.append("  None.")
    for e in result["exemptions"]:
        expiry = (e.get("expiresOn") or "")[:10] or "NEVER"
        lines.append(f"  {e['name']}  [{e.get('category')}]  expires {expiry}  ({e['status']})  at {e['scope']}")
        lines.append("    members: " + (", ".join(e["refIds"]) if e["refIds"] else
                                        "ENTIRE assignment - rarely what you want"))
    if any(e["status"] == "never expires" for e in result["exemptions"]):
        lines.append("  At least one exemption has NO EXPIRY: an unbounded risk acceptance nobody reviews again.")
    return lines


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m scripts.what_governs", description=__doc__.split("\n\n")[0])
    p.add_argument("--resource-id", required=True, help="Resource, resource group or subscription id")
    p.add_argument("--tenant", help="Tenant id for `az login` with several tenants")
    p.add_argument("--non-compliant-only", action="store_true", help="List only non-compliant evaluations")
    p.add_argument("--json", action="store_true", help="Print the raw result as JSON")
    args = p.parse_args(argv)

    match = RESOURCE_ID.match(args.resource_id.strip())
    if not match:
        p.error("--resource-id must start with /subscriptions/<subscription-id>")

    from azure.mgmt.resourcegraph import ResourceGraphClient

    from scanners.base.azure_api import CachedTokenCredential, az_cli_credential

    credential = CachedTokenCredential(az_cli_credential(args.tenant))
    context = ScanContext(subscription_id=match.group(1), tenant_id=args.tenant or "", scan_job_id="what-governs",
                          resource_graph_client=ResourceGraphClient(credential))
    try:
        result = asyncio.run(what_governs(context, args.resource_id.strip()))
    except Exception as exc:
        print(f"Azure Policy data could not be read: {exc}\n"
              "Run `az login` and check you have Reader on the subscription and the management groups above it.",
              file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2) if args.json else "\n".join(render(result, args.non_compliant_only)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
