#!/usr/bin/env bash
# Start the ARG local portal (http://127.0.0.1:8765) using your `az login` session.
# Usage: az login && ./scripts/start-local-portal.sh [--port 8765] [--reports-dir reports] [--no-browser]
set -euo pipefail

cd "$(dirname "$0")/.."
if [ ! -x .venv-local/bin/python ]; then
  python3 -m venv .venv-local
  .venv-local/bin/python -m pip install --quiet --upgrade pip
fi
.venv-local/bin/python -m pip install --quiet -r requirements-local.txt

if ! command -v az >/dev/null 2>&1; then
  echo "WARNING: Azure CLI (az) not found — install it and run 'az login'." >&2
elif ! az account show --output none >/dev/null 2>&1; then
  echo "WARNING: Azure CLI is not signed in — run 'az login', then click Refresh in the portal." >&2
fi

exec .venv-local/bin/python -m scripts.local_portal "$@"
