"""
Webhooks API routes.

ARG can notify external systems (Slack, Teams, custom HTTP endpoints) when:
  - A scan completes
  - A critical/high severity finding is detected
  - A scan fails

Webhook URLs are configured via environment variables (WEBHOOK_SLACK_URL,
WEBHOOK_TEAMS_URL, WEBHOOK_CUSTOM_URL) for the MVP — this avoids storing
webhook secrets in the database. This module exposes a way to test
configured webhooks and view delivery status.

Every delivery is checked first (check_webhook_url): https only, no credentials in the URL, and the host must
resolve to public addresses - so a webhook can never reach cloud metadata (169.254.169.254), localhost or the
Docker network (SSRF). WEBHOOK_ALLOW_PRIVATE_HOSTS=true allows an internal receiver on purpose.
"""
import asyncio
import ipaddress
import logging
import hashlib
import hmac
import json
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.api.dependencies.auth import require_admin
from backend.core.config import get_settings
from backend.models.models import User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["webhooks"])
settings = get_settings()


class WebhookTestRequest(BaseModel):
    target: str  # "slack" | "teams" | "custom"


class WebhookStatus(BaseModel):
    slack_configured: bool
    teams_configured: bool
    custom_configured: bool


@router.get("/status", response_model=WebhookStatus)
async def get_webhook_status(
    current_user: User = Depends(require_admin),
) -> WebhookStatus:
    """Check which webhook integrations are configured via environment variables."""
    return WebhookStatus(
        slack_configured=bool(settings.WEBHOOK_SLACK_URL),
        teams_configured=bool(settings.WEBHOOK_TEAMS_URL),
        custom_configured=bool(settings.WEBHOOK_CUSTOM_URL),
    )


@router.post("/test")
async def test_webhook(
    body: WebhookTestRequest,
    current_user: User = Depends(require_admin),
) -> dict:
    """
    Send a test notification to the configured webhook target.

    Useful for verifying Slack/Teams integration during initial setup
    without waiting for a real scan to complete.
    """
    url_map = {
        "slack": settings.WEBHOOK_SLACK_URL,
        "teams": settings.WEBHOOK_TEAMS_URL,
        "custom": settings.WEBHOOK_CUSTOM_URL,
    }
    url = url_map.get(body.target)
    if not url:
        raise HTTPException(
            status_code=400,
            detail=f"No webhook URL configured for target '{body.target}'",
        )

    payload = _build_payload(body.target, current_user.email)

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await send_webhook(client, body.target, url, payload)
    except WebhookUrlError as exc:
        raise HTTPException(status_code=400, detail=f"Webhook URL rejected: {exc}")
    except httpx.HTTPError as exc:
        logger.error("Webhook test failed: %s", exc)
        raise HTTPException(status_code=502, detail="Webhook delivery failed - see the backend log")

    return {
        "delivered": response.status_code < 300,
        "status_code": response.status_code,
        "target": body.target,
    }


def _build_payload(target: str, triggered_by: str) -> dict:
    """Build a target-appropriate test payload."""
    timestamp = datetime.now(timezone.utc).isoformat()

    if target == "slack":
        return {
            "text": (
                f":white_check_mark: *Azure Resource Guardian* test notification\n"
                f"Triggered by {triggered_by} at {timestamp}"
            )
        }
    elif target == "teams":
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "ARG Test Notification",
            "themeColor": "00D4FF",
            "title": "Azure Resource Guardian — Test Notification",
            "text": f"Triggered by {triggered_by} at {timestamp}",
        }
    else:  # custom
        return {
            "event": "webhook_test",
            "triggered_by": triggered_by,
            "timestamp": timestamp,
        }


class WebhookUrlError(ValueError):
    """The webhook URL is not an https URL of a public host."""


# Cloud instance metadata: never a webhook receiver, even with WEBHOOK_ALLOW_PRIVATE_HOSTS.
METADATA_ADDRESSES = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}


async def _resolve(host: str, port: int) -> list:
    return await asyncio.get_running_loop().getaddrinfo(host, port, proto=socket.IPPROTO_TCP)


async def check_webhook_url(url: str) -> None:
    """Raise WebhookUrlError unless the URL is https, has no credentials and its host resolves to public IPs."""
    parsed = urlsplit(url or "")
    if parsed.scheme != "https" or not parsed.hostname:
        raise WebhookUrlError("only https://<host>/... URLs are allowed")
    if parsed.username or parsed.password:
        raise WebhookUrlError("credentials in the URL are not allowed - use WEBHOOK_SECRET")
    try:
        port = parsed.port or 443
    except ValueError:
        raise WebhookUrlError("invalid port")
    try:
        infos = await _resolve(parsed.hostname, port)
    except socket.gaierror:
        raise WebhookUrlError(f"cannot resolve {parsed.hostname}")
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        address = getattr(address, "ipv4_mapped", None) or address
        if address in METADATA_ADDRESSES:
            raise WebhookUrlError(f"{parsed.hostname} resolves to the cloud metadata service")
        if not address.is_global and not settings.WEBHOOK_ALLOW_PRIVATE_HOSTS:
            raise WebhookUrlError(f"{parsed.hostname} resolves to a non-public address ({address}); "
                                  "set WEBHOOK_ALLOW_PRIVATE_HOSTS=true for an internal receiver")


async def send_webhook(
    client: httpx.AsyncClient,
    target: str,
    url: str,
    payload: dict,
) -> httpx.Response:
    """
    Send a webhook payload, signing custom webhooks with HMAC-SHA256
    if WEBHOOK_SECRET is configured (allows the receiver to verify
    the request actually came from this ARG instance). The URL is
    checked first (check_webhook_url) and redirects are never followed.
    """
    await check_webhook_url(url)
    headers = {"Content-Type": "application/json"}

    if target == "custom" and settings.WEBHOOK_SECRET:
        body_bytes = json.dumps(payload).encode("utf-8")
        secret = settings.WEBHOOK_SECRET.get_secret_value().encode("utf-8")
        signature = hmac.new(secret, body_bytes, hashlib.sha256).hexdigest()
        headers["X-ARG-Signature"] = f"sha256={signature}"

    return await client.post(url, json=payload, headers=headers, follow_redirects=False)


async def notify_scan_completed(
    scan_id: str,
    total_findings: int,
    critical_count: int,
    duration_seconds: int,
) -> None:
    """
    Called by the scan worker after a scan completes.

    Fire-and-forget: notification failures should never fail the scan job.
    """
    if not (settings.WEBHOOK_SLACK_URL or settings.WEBHOOK_TEAMS_URL or settings.WEBHOOK_CUSTOM_URL):
        return

    severity_note = f" ({critical_count} critical findings)" if critical_count > 0 else ""
    message = (
        f"Scan {scan_id} completed in {duration_seconds}s — "
        f"{total_findings} findings detected.{severity_note}"
    )

    targets = [
        ("slack", settings.WEBHOOK_SLACK_URL, {"text": message}),
        ("teams", settings.WEBHOOK_TEAMS_URL, {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "ARG Scan Complete",
            "themeColor": "F44336" if critical_count > 0 else "00D4FF",
            "title": "Azure Resource Guardian — Scan Complete",
            "text": message,
        }),
        ("custom", settings.WEBHOOK_CUSTOM_URL, {
            "event": "scan_completed",
            "scan_id": scan_id,
            "total_findings": total_findings,
            "critical_count": critical_count,
            "duration_seconds": duration_seconds,
        }),
    ]

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        for target, url, payload in targets:
            if not url:
                continue
            try:
                await send_webhook(client, target, url, payload)
            except WebhookUrlError as exc:
                logger.warning("Skipped %s webhook: URL rejected (%s)", target, exc)
            except httpx.HTTPError as exc:
                logger.warning("Failed to deliver %s webhook: %s", target, exc)
