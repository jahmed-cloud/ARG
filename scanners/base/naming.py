"""
Azure Resource Guardian - Naming helpers shared by scanners
===========================================================
Environment inference from resource names/tags, used by the mixed-
environment App Service check and the environment tag/name mismatch
governance check so both agree on what "dev" and "prod" mean.
"""

import re
from typing import Dict, List, Optional

NON_PROD_TOKENS = ("dev", "development", "test", "tst", "stage", "staging", "stg", "uat", "qa",
                   "sandbox", "sbx", "train", "training", "demo", "poc")
PROD_TOKENS = ("prod", "production", "prd", "live")
ENV_TAG_KEYS = ("environment", "env", "environmen")


def name_tokens(name: str) -> List[str]:
    """Split on any non-alphanumeric, and also on '0' separators used where '-' is illegal (storage/SQL names)."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", (name or "").lower()) if t]
    split_zero = [p for t in tokens for p in t.split("0") if p]
    return tokens + [t for t in split_zero if t not in tokens]


def env_from_name(name: str) -> Optional[str]:
    """'nonprod' / 'prod' / None based on name tokens (non-prod tokens win)."""
    tokens = name_tokens(name)
    if any(t in NON_PROD_TOKENS for t in tokens):
        return "nonprod"
    if any(t in PROD_TOKENS for t in tokens):
        return "prod"
    return None


def env_from_tags(tags: Optional[Dict[str, str]]) -> Optional[str]:
    """'prod' / 'nonprod' / None from an environment-like tag (case-insensitive key)."""
    lowered = {str(k).lower(): str(v).lower() for k, v in (tags or {}).items()}
    for key in ENV_TAG_KEYS:
        value = lowered.get(key)
        if value:
            if value in PROD_TOKENS:
                return "prod"
            if any(t in NON_PROD_TOKENS for t in name_tokens(value)):
                return "nonprod"
    return None
