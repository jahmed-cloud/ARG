"""
Governance configuration API — required tags and naming patterns.

GET  /governance/config          → current config (or built-in defaults if never saved)
PUT  /governance/config          → save config
GET  /governance/config/defaults → built-in default values, for reset
"""
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies.auth import get_current_user, require_admin
from backend.api.dependencies.database import get_db
from backend.models.models import GovernanceConfig, User

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


class GovernanceConfigSchema(BaseModel):
    required_tags: list[str]
    naming_patterns: dict[str, str]

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
        )
    return GovernanceConfigResponse(
        required_tags=DEFAULT_REQUIRED_TAGS,
        naming_patterns=DEFAULT_NAMING_PATTERNS,
        naming_pattern_descriptions=NAMING_PATTERN_DESCRIPTIONS,
        is_default=True,
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
    else:
        row = GovernanceConfig(
            tenant_id=None,
            required_tags=body.required_tags,
            naming_patterns=body.naming_patterns,
        )
        db.add(row)
    await db.commit()
    return GovernanceConfigResponse(
        required_tags=row.required_tags,
        naming_patterns=row.naming_patterns,
        naming_pattern_descriptions=NAMING_PATTERN_DESCRIPTIONS,
        is_default=False,
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
    )
