"""Entry point for `python -m scripts.subscription_analysis` — see scripts/subscription_analysis/cli.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.subscription_analysis.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
