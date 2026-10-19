"""
Governance configuration API — required tags, naming patterns and analysis settings.

GET  /governance/config          → current config (or built-in defaults if never saved)
PUT  /governance/config          → save config
GET  /governance/config/defaults → built-in default values, for reset

Analysis settings (which optional checks run, blocked resource providers, engineering hourly rate) share their
definition with the local CLI / portal: scripts/subscription_analysis/settings.py.
"""
import re
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import get_current_user, require_admin
from backend.api.dependencies.database import get_db
from backend.models.models import GovernanceConfig, User
from scripts.subscription_analysis.settings import DEFAULTS as SETTINGS_DEFAULTS
from scripts.subscription_analysis.settings import SETTINGS, env_defaults, normalize

router = APIRouter(tags=["governance-config"])

# Built-in defaults — mirrors what the scanners use when no config row exists
DEFAULT_REQUIRED_TAGS = ["owner", "environment", "cost-center", "application"]

DEFAULT_NAMING_PATTERNS = {
    "microsoft.compute/virtualmachines":
        r"^vm-[a-z0-9]+-[a-z]+-[a-z]+-\d{3}$",
    "microsoft.network/virtualnetworks":
        r"^vnet-[a-z0-9]+-[a-z]+-[a-z]+$",
    "microsoft.storage/storageaccounts":
        r"^st[a-z0-9]{3,22}$",
    "microsoft.keyvault/vaults":
        r"^kv-[a-z0-9]+-[a-z]+-[a-z]+$",
    "microsoft.network/networksecuritygroups":
        r"^nsg-[a-z0-9]+-[a-z]+-[a-z]+$",
}

NAMING_PATTERN_DESCRIPTIONS = {
    "microsoft.compute/virtualmachines":
        "Virtual Machines — e.g. vm-myapp-prod-eastus-001",
    "microsoft.network/virtualnetworks":
        "Virtual Networks — e.g. vnet-myapp-prod-eastus",
    "microsoft.storage/storageaccounts":
        "Storage Accounts — e.g. stmyapp001 (3-24 chars, lowercase/digits only)",
    "microsoft.keyvault/vaults":
        "Key Vaults — e.g. kv-myapp-prod-eastus",
    "microsoft.network/networksecuritygroups":
        "Network Security Groups — e.g. nsg-myapp-prod-eastus",
}


SETTING_DEFINITIONS = [
    {"key": s.key, "label": s.label, "kind": s.kind, "default": s.default, "help": s.help, "choices": list(s.choices)}
    for s in SETTINGS if not s.local_only
]
DOCKER_SETTINGS = {d["key"] for d in SETTING_DEFINITIONS}


def effective_settings(saved: dict | None) -> dict[str, Any]:
    """Defaults overlaid with the saved (normalized) values - what the scanners receive. Required tags come from
    the Governance Configuration's own field, not from here."""
    values = {**SETTINGS_DEFAULTS, **env_defaults(), **normalize(saved or {})}
    return {k: v for k, v in values.items() if k in DOCKER_SETTINGS}


class GovernanceConfigSchema(BaseModel):
    required_tags: list[str]
    naming_patterns: dict[str, str]
    settings: dict[str, Any] | None = None  # omitted by older clients: saved settings are kept

    @field_validator("settings")
    @classmethod
    def known_settings(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return normalize(v) if v is not None else None

    @field_validator("required_tags")
    @classmethod
    def tags_lowercase(cls, v: list[str]) -> list[str]:
        return [t.strip().lower() for t in v if t.strip()]

    @field_validator("naming_patterns")
    @classmethod
    def validate_patterns(cls, v: dict[str, str]) -> dict[str, str]:
        for resource_type, pattern in v.items():
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex for {resource_type!r}: {e}")
        return {k.strip().lower(): v2 for k, v2 in v.items()}


class GovernanceConfigResponse(BaseModel):
    required_tags: list[str]
    naming_patterns: dict[str, str]
    naming_pattern_descriptions: dict[str, str]
    is_default: bool  # True when no custom config has been saved yet
    settings: dict[str, Any] = {}
    setting_definitions: list[dict[str, Any]] = SETTING_DEFINITIONS


@router.get("/config", response_model=GovernanceConfigResponse)
async def get_governance_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GovernanceConfigResponse:
    """Return current governance config, falling back to built-in defaults."""
    row = await db.scalar(
        select(GovernanceConfig).where(GovernanceConfig.tenant_id.is_(None)).limit(1)
    )
    if row:
        return GovernanceConfigResponse(
            required_tags=row.required_tags or DEFAULT_REQUIRED_TAGS,
            naming_patterns=row.naming_patterns or DEFAULT_NAMING_PATTERNS,
            naming_pattern_descriptions=NAMING_PATTERN_DESCRIPTIONS,
            is_default=False,
            settings=effective_settings(getattr(row, "scanner_settings", None)),
        )
    return GovernanceConfigResponse(
        required_tags=DEFAULT_REQUIRED_TAGS,
        naming_patterns=DEFAULT_NAMING_PATTERNS,
        naming_pattern_descriptions=NAMING_PATTERN_DESCRIPTIONS,
        is_default=True,
        settings=effective_settings(None),
    )


@router.put("/config", response_model=GovernanceConfigResponse)
async def update_governance_config(
    body: GovernanceConfigSchema,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> GovernanceConfigResponse:
    """Save governance config. Admin only. Changes take effect on next scan."""
    row = await db.scalar(
        select(GovernanceConfig).where(GovernanceConfig.tenant_id.is_(None)).limit(1)
    )
    if row:
        row.required_tags = body.required_tags
        row.naming_patterns = body.naming_patterns
        if body.settings is not None:
            row.scanner_settings = body.settings
    else:
        row = GovernanceConfig(
            tenant_id=None,
            required_tags=body.required_tags,
            naming_patterns=body.naming_patterns,
            scanner_settings=body.settings or {},
        )
        db.add(row)
    await db.commit()
    return GovernanceConfigResponse(
        required_tags=row.required_tags,
        naming_patterns=row.naming_patterns,
        naming_pattern_descriptions=NAMING_PATTERN_DESCRIPTIONS,
        is_default=False,
        settings=effective_settings(row.scanner_settings),
    )


@router.get("/config/defaults", response_model=GovernanceConfigResponse)
async def get_governance_defaults(
    current_user: User = Depends(require_admin),
) -> GovernanceConfigResponse:
    """Return the built-in default values so admins can reset to them."""
    return GovernanceConfigResponse(
        required_tags=DEFAULT_REQUIRED_TAGS,
        naming_patterns=DEFAULT_NAMING_PATTERNS,
        naming_pattern_descriptions=NAMING_PATTERN_DESCRIPTIONS,
        is_default=True,
        settings=effective_settings(None),
    )
