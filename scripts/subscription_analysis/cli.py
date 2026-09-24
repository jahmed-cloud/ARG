"""
python -m scripts.subscription_analysis --subscription <id-or-name> [options]
python -m scripts.subscription_analysis --all [options]

Authentication reuses your Azure CLI session — run `az login` in a terminal
first (no service principal needed). --auth default switches to
DefaultAzureCredential (env vars / managed identity) for automation.

The identity needs Reader, Cost Management Reader and Security Reader on
each subscription. Each subscription is written to
<reports-dir>/<subscription-name>/ and <reports-dir>/README.md indexes them.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.subscription_analysis.collector import list_subscriptions, run  # noqa: E402
from scripts.subscription_analysis.report import (  # noqa: E402
    clean_generated,
    report_folder_name,
    write_index,
    write_report,
)


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m scripts.subscription_analysis",
                                description="Run all ARG scanners against subscriptions and write markdown reviews.")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--subscription", "-s", action="append",
                        help="Subscription ID or display name (repeatable)")
    target.add_argument("--all", action="store_true", help="Analyse every enabled subscription the account can see")
    p.add_argument("--reports-dir", default="reports", help="Root folder for per-subscription reports (default: ./reports)")
    p.add_argument("--output", "-o", help="Exact output folder (single subscription only; overrides --reports-dir)")
    p.add_argument("--auth", choices=["cli", "default"], default="cli",
                   help="cli = reuse `az login` (default); default = DefaultAzureCredential")
    p.add_argument("--tenant", help="Tenant ID of the az login session to use (optional)")
    p.add_argument("--scanners", help="Comma-separated scanner names to run (default: all)")
    p.add_argument("--config", help="JSON file with scanner configuration overrides (thresholds, required_tags, ...)")
    p.add_argument("--skip-cost", action="store_true", help="Skip Cost Management datasets")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args(argv)


def make_credential(kind: str = "cli", tenant: str = None):
    from azure.identity import AzureCliCredential, DefaultAzureCredential

    if kind == "cli":
        return AzureCliCredential(tenant_id=tenant) if tenant else AzureCliCredential()
    return DefaultAzureCredential(additionally_allowed_tenants=["*"])


def default_config(path: str = None) -> dict:
    from scanners.governance.governance_scanners import DEFAULT_REQUIRED_TAGS

    config = {"required_tags": DEFAULT_REQUIRED_TAGS, "timeout_seconds": 900}
    if path:
        config.update(json.loads(Path(path).read_text(encoding="utf-8")))
    return config


def analyse_one(credential, subscription: str, reports_dir: Path, output: Path = None, **kwargs):
    data = run(credential, subscription, **kwargs)
    target = output or reports_dir / report_folder_name(data.subscription)
    clean_generated(target)
    model = write_report(data, target)
    return data, model, target


def main(argv=None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.output and (args.all or len(args.subscription) > 1):
        raise SystemExit("--output can only be used with a single --subscription; use --reports-dir instead.")

    import asyncio

    credential = make_credential(args.auth, args.tenant)
    reports_dir = Path(args.reports_dir)
    if args.all:
        targets = [s["id"] for s in asyncio.run(list_subscriptions(credential)) if s.get("state") == "Enabled"]
        print(f"Analysing {len(targets)} enabled subscription(s)")
    else:
        targets = args.subscription

    kwargs = dict(
        scanners=[s.strip() for s in args.scanners.split(",")] if args.scanners else None,
        config=default_config(args.config),
        include_cost=not args.skip_cost,
    )
    failures = 0
    for subscription in targets:
        try:
            data, model, target = analyse_one(credential, subscription, reports_dir,
                                              Path(args.output) if args.output else None, **kwargs)
        except Exception as exc:  # keep going with the next subscription
            failures += 1
            print(f"FAILED {subscription}: {exc}", file=sys.stderr)
            continue
        waves = model.savings_by_wave()
        print(f"{data.subscription['name']}: report written to {target.resolve()}")
        print(f"  resources: {len(data.resources)}  findings: {len(data.findings)}  "
              f"30-day cost: {model.total_30:,.2f} {model.currency}")
        print(f"  estimated monthly savings: wave 1 {model.savings_label(waves[1])} | "
              f"wave 2 {model.savings_label(waves[2])}")
        if data.warnings:
            print(f"  {len(data.warnings)} collection warning(s) — see 05-deep-dive/README.md")

    if not args.output:
        print(f"Index: {write_index(reports_dir).resolve()}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
