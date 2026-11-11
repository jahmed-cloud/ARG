"""
Stable identity of a finding: one issue (finding type) on one object.

The Docker worker stores it on every Finding row and looks findings up by it, so a re-scan updates the row it
already has instead of adding a copy - whatever casing Azure returned the resource ID in, and for Entra ID objects
(users, apps) that have no Azure resource ID at all. Triage (acknowledged, suppressed, false positive) therefore
survives the next scan.

  resource findings      resource ID (lower case) + finding type
  Entra ID findings      tenant + object ID + finding type; tenant-wide, so one row per tenant, not per subscription
  anything else          subscription + finding type
"""

import hashlib
from typing import Any, Optional


def _get(finding: Any, key: str) -> Any:
    return finding.get(key) if isinstance(finding, dict) else getattr(finding, key, None)


def normalise_resource_id(resource_id: Optional[str]) -> str:
    """Azure resource IDs are case-insensitive and different APIs return different casing."""
    return (resource_id or "").strip().rstrip("/").lower()


def is_tenant_wide(finding: Any) -> bool:
    """An Entra ID object (user, guest, app registration): belongs to the tenant, not to one subscription."""
    return bool(_get(finding, "entra_object_id")) and not _get(finding, "resource_id")


def finding_fingerprint(finding: Any, *, subscription_id: str = "", tenant_id: str = "") -> str:
    """SHA-256 hex of the finding's identity. `finding` is a ScannerFinding or a finding dict."""
    finding_type = _get(finding, "finding_type") or ""
    resource_id = normalise_resource_id(_get(finding, "resource_id"))
    if resource_id:
        key = f"resource|{resource_id}"
    elif _get(finding, "entra_object_id"):
        key = f"entra|{(tenant_id or '').lower()}|{str(_get(finding, 'entra_object_id')).strip().lower()}"
    else:
        key = f"subscription|{(subscription_id or '').lower()}"
    return hashlib.sha256(f"{key}|{finding_type}".encode()).hexdigest()
