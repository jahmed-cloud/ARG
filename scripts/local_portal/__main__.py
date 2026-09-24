"""
python -m scripts.local_portal [--port 8765] [--reports-dir reports] [--tenant <id>] [--no-browser]

Prerequisite: `az login` in a terminal (your own account; no service principal).
Portal login: ARG_PORTAL_USER (default "admin") / ARG_PORTAL_PASSWORD; when no
password is set, a one-time password is generated and printed below.
"""

import argparse
import ipaddress
import os
import secrets
import sys
import threading
import webbrowser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m scripts.local_portal",
                                description="Local web portal for ARG subscription analysis reports.")
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1 — local only)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--reports-dir", default=str(REPO_ROOT / "reports"),
                   help="Folder holding <subscription>/ report folders (default: <ARG repo>/reports)")
    p.add_argument("--tenant", help="Tenant ID of the az login session to use (optional)")
    p.add_argument("--workers", type=int, default=2, help="Subscriptions analysed in parallel (default: 2)")
    p.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    return p.parse_args(argv)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv=None) -> int:
    args = _parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    if not _is_loopback(args.host):
        raise SystemExit("The local portal only binds to loopback addresses (127.0.0.1 / localhost).")

    import uvicorn

    from scripts.local_portal.app import create_app
    from scripts.local_portal.azure_session import AzureCliSession
    from scripts.local_portal.jobs import JobManager

    username = os.environ.get("ARG_PORTAL_USER") or "admin"
    password = os.environ.get("ARG_PORTAL_PASSWORD")
    generated = not password
    if generated:
        password = secrets.token_urlsafe(9)

    reports_dir = Path(args.reports_dir).resolve()
    azure = AzureCliSession(tenant_id=args.tenant)
    jobs = JobManager(reports_dir, lambda: azure.credential, max_workers=max(1, args.workers))
    app = create_app(reports_dir=reports_dir, username=username, password=password, azure=azure, jobs=jobs,
                     allowed_hosts=["127.0.0.1", "localhost", args.host])

    url = f"http://{'localhost' if args.host == 'localhost' else args.host}:{args.port}/"
    status = azure.status()
    print("ARG local portal")
    print(f"  URL          : {url}")
    print(f"  Portal login : {username} / {password if generated else '(ARG_PORTAL_PASSWORD)'}"
          + ("   <- one-time password for this run" if generated else ""))
    print(f"  Reports dir  : {reports_dir}")
    if status["signed_in"]:
        print(f"  Azure CLI    : {status['account']} (tenant {status['tenant_id']})")
    else:
        print(f"  Azure CLI    : NOT SIGNED IN — {status['error']}")
    print("  Stop with Ctrl+C")

    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
