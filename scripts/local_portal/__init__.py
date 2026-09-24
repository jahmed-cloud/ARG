"""
ARG local portal — a small web UI on http://127.0.0.1:8765 for running the
subscription analysis and browsing the per-subscription markdown reports.

    az login                          # once, in a terminal (your own account)
    python -m scripts.local_portal    # then open http://127.0.0.1:8765

- Azure access reuses the Azure CLI session (AzureCliCredential). The portal
  never signs in to Azure itself and needs no service principal.
- Access to the portal is protected by a simple local username/password
  (ARG_PORTAL_USER / ARG_PORTAL_PASSWORD, or a one-time password printed at
  start-up) and it only listens on localhost.
- Reports are written to reports/<subscription>/ (README.md, 01-… to 05-…)
  and indexed in reports/README.md — the same layout as the CLI.
"""
