"""
Find every Azure Policy object a deployment tool owns, by the `metadata.managedBy` value it stamps on them:
definitions, initiatives, assignments and exemptions. The recovery path when the tool's state (Terraform /
OpenTofu state, a pipeline's record) is lost: the list is what has to be imported or cleaned up.

    python -m scripts.find_managed_policy --managed-by <value> --management-group <mg-id> [--management-group ...]
    python -m scripts.find_managed_policy --managed-by <value> --output managed-policy.json

Without --management-group it searches everything the signed-in identity can read. Read-only: Azure Resource
Graph queries with your `az login`.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanners.base.policy import managed_by_query, summarize_managed  # noqa: E402


def run_query(client: Any, query: str, management_groups: Optional[List[str]]) -> List[Dict[str, Any]]:
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    rows: List[Dict[str, Any]] = []
    skip_token = None
    while True:
        request = QueryRequest(query=query, management_groups=management_groups or None,
                               options=QueryRequestOptions(result_format="objectArray", top=1000,
                                                           skip_token=skip_token))
        response = client.resources(request)
        rows.extend(response.data or [])
        skip_token = getattr(response, "skip_token", None)
        if not skip_token:
            return rows


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m scripts.find_managed_policy", description=__doc__.split("\n\n")[0])
    p.add_argument("--managed-by", required=True, help="The metadata.managedBy value to match (exact)")
    p.add_argument("--management-group", action="append", default=[],
                   help="Management group id (not display name) to search below; repeatable")
    p.add_argument("--tenant", help="Tenant id for `az login` with several tenants")
    p.add_argument("--output", help="Write the full result set to this JSON file")
    args = p.parse_args(argv)

    from azure.mgmt.resourcegraph import ResourceGraphClient

    from scanners.base.azure_api import CachedTokenCredential, az_cli_credential

    client = ResourceGraphClient(CachedTokenCredential(az_cli_credential(args.tenant)))
    try:
        rows = run_query(client, managed_by_query(args.managed_by), args.management_group)
    except Exception as exc:
        scope = ", ".join(args.management_group) or "the tenant"
        print(f"Resource Graph query failed - check Reader on {scope}: {exc}", file=sys.stderr)
        return 1

    if not rows:
        print("No policy objects found with that managedBy value. Either none exist, or you lack Reader on the "
              "scope - check before assuming they are gone.")
        return 0
    for kind, n in summarize_managed(rows).items():
        print(f"  {kind:<50} {n}")
    print(f"  Total: {len(rows)}")
    if args.output:
        target = Path(args.output)
    else:
        target = Path("reports") / f"managed-policy-{datetime.now():%Y-%m-%d_%H%M%S}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"Full result set written to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
