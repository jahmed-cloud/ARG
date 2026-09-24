"""
python -m scripts.subscription_analysis --subscription <id-or-name> [options]

Authentication uses the Azure CLI login by default (`az login`), or
DefaultAzureCredential (env vars / managed identity / VS Code) with
--auth default. The identity needs Reader, Cost Management Reader and
Security Reader on the subscription (Monitoring Reader is covered by Reader).
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.subscription_analysis.collector import run  # noqa: E402
from scripts.subscription_analysis.report import write_report  # noqa: E402


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m scripts.subscription_analysis",
                                description="Run all ARG scanners against one subscription and write a markdown review.")
    p.add_argument("--subscription", "-s", required=True, help="Subscription ID or display name")
    p.add_argument("--output", "-o", help="Output folder (default: ./reports/<subscription-name>)")
    p.add_argument("--auth", choices=["cli", "default"], default="cli", help="Credential type (default: cli)")
    p.add_argument("--tenant", help="Tenant ID for the credential (optional)")
    p.add_argument("--scanners", help="Comma-separated scanner names to run (default: all)")
    p.add_argument("--config", help="JSON file with scanner configuration overrides (thresholds, required_tags, ...)")
    p.add_argument("--skip-cost", action="store_true", help="Skip Cost Management datasets")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args(argv)


def _credential(kind: str, tenant: str = None):
    from azure.identity import AzureCliCredential, DefaultAzureCredential

    if kind == "cli":
        return AzureCliCredential(tenant_id=tenant) if tenant else AzureCliCredential()
    return DefaultAzureCredential(additionally_allowed_tenants=["*"])


def main(argv=None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from scanners.governance.governance_scanners import DEFAULT_REQUIRED_TAGS

    config = {"required_tags": DEFAULT_REQUIRED_TAGS, "timeout_seconds": 900}
    if args.config:
        config.update(json.loads(Path(args.config).read_text(encoding="utf-8")))

    data = run(
        _credential(args.auth, args.tenant),
        args.subscription,
        scanners=[s.strip() for s in args.scanners.split(",")] if args.scanners else None,
        config=config,
        include_cost=not args.skip_cost,
    )
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", data.subscription.get("name") or data.subscription["id"])
    output = Path(args.output) if args.output else Path("reports") / safe_name
    model = write_report(data, output)

    waves = model.savings_by_wave()
    print(f"Report written to {output.resolve()}")
    print(f"  resources: {len(data.resources)}  findings: {len(data.findings)}  "
          f"30-day cost: {model.total_30:,.2f} {model.currency}")
    print(f"  estimated monthly savings: wave 1 {model.savings_label(waves[1])} | wave 2 {model.savings_label(waves[2])}")
    if data.warnings:
        print(f"  {len(data.warnings)} collection warning(s) — see 05-deep-dive/README.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
