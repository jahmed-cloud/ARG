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
                   "sandbox", "sbx", "train", "training", "demo", "poc", "nonprod", "preprod", "prep", "systest",
                   "perftest", "sit")
PROD_TOKENS = ("prod", "production", "prd", "live")
ENV_TAG_KEYS = ("environment", "env", "environmen")
# "non-prod", "non prod", "public non-prod", "non public-non prod" - but not "non public-prod" (non-public production).
NON_PROD_PHRASE = re.compile(r"non[\s_-]*prod")


def name_tokens(name: str) -> List[str]:
    """Split on any non-alphanumeric, and also on '0' separators used where '-' is illegal (storage/SQL names)."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", (name or "").lower()) if t]
    split_zero = [p for t in tokens for p in t.split("0") if p]
    return tokens + [t for t in split_zero if t not in tokens]


def _env_tokens(value: str) -> List[str]:
    """Name tokens plus the same tokens without a trailing number ("stage1" -> "stage")."""
    tokens = name_tokens(value)
    return tokens + [re.sub(r"\d+$", "", t) for t in tokens if re.search(r"\D\d+$", t)]


def env_from_name(name: str) -> Optional[str]:
    """'nonprod' / 'prod' / None based on name tokens (non-prod tokens win)."""
    tokens = _env_tokens(name)
    if any(t in NON_PROD_TOKENS for t in tokens):
        return "nonprod"
    if any(t in PROD_TOKENS for t in tokens):
        return "prod"
    return None


def env_from_tags(tags: Optional[Dict[str, str]]) -> Optional[str]:
    """'prod' / 'nonprod' / None from an environment-like tag (case-insensitive key)."""
    lowered = {str(k).lower(): str(v).lower() for k, v in (tags or {}).items()}
    for key in ENV_TAG_KEYS:
        value = (lowered.get(key) or "").strip()
        if value:
            if value in PROD_TOKENS:
                return "prod"
            tokens = _env_tokens(value)
            if NON_PROD_PHRASE.search(value) or any(t in NON_PROD_TOKENS for t in tokens):
                return "nonprod"
            if any(t in PROD_TOKENS for t in tokens):
                return "prod"
    return None
