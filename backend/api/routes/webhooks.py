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
"""
import logging
import hashlib
import hmac
import json
from datetime import datetime, timezone

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
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await send_webhook(client, body.target, url, payload)
    except httpx.HTTPError as exc:
        logger.error("Webhook test failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"Webhook delivery failed: {exc}")

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


async def send_webhook(
    client: httpx.AsyncClient,
    target: str,
    url: str,
    payload: dict,
) -> httpx.Response:
    """
    Send a webhook payload, signing custom webhooks with HMAC-SHA256
    if WEBHOOK_SECRET is configured (allows the receiver to verify
    the request actually came from this ARG instance).
    """
    headers = {"Content-Type": "application/json"}

    if target == "custom" and settings.WEBHOOK_SECRET:
        body_bytes = json.dumps(payload).encode("utf-8")
        secret = settings.WEBHOOK_SECRET.get_secret_value().encode("utf-8")
        signature = hmac.new(secret, body_bytes, hashlib.sha256).hexdigest()
        headers["X-ARG-Signature"] = f"sha256={signature}"

    return await client.post(url, json=payload, headers=headers)


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

    severity_note = f" ⚠️ {critical_count} critical findings" if critical_count > 0 else ""
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

    async with httpx.AsyncClient(timeout=10.0) as client:
        for target, url, payload in targets:
            if not url:
                continue
            try:
                await send_webhook(client, target, url, payload)
            except httpx.HTTPError as exc:
                logger.warning("Failed to deliver %s webhook: %s", target, exc)
