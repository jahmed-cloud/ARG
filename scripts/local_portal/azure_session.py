"""
Azure access for the local portal: the user's existing `az login` session.

The portal never performs an Azure sign-in. It wraps AzureCliCredential and
reports who the CLI is signed in as (from the access-token claims), or tells
the user to run `az login` in a terminal.
"""

import base64
import json
import threading
import time
from typing import Any, Dict, Optional

ARM_SCOPE = "https://management.azure.com/.default"


def token_claims(token: str) -> Dict[str, Any]:
    """Decode (without verifying) the payload of a JWT access token - display purposes only."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
    except (IndexError, ValueError):
        return {}


class CachedTokenCredential:
    """
    AzureCliCredential shells out to `az` on every get_token call (seconds each).
    Cache tokens per scope until shortly before expiry so the portal and every
    analysis job share one token instead of spawning az repeatedly.
    """

    REFRESH_MARGIN_SECONDS = 300

    def __init__(self, inner: Any):
        self._inner = inner
        self._tokens: Dict[tuple, Any] = {}
        self._lock = threading.Lock()

    def get_token(self, *scopes: str, **kwargs: Any):
        key = (scopes, kwargs.get("tenant_id"))
        with self._lock:
            token = self._tokens.get(key)
            if token and token.expires_on - time.time() > self.REFRESH_MARGIN_SECONDS:
                return token
        token = self._inner.get_token(*scopes, **kwargs)
        with self._lock:
            self._tokens[key] = token
        return token

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if close:
            close()


class AzureCliSession:
    """Thread-safe holder for the AzureCliCredential used by every analysis job."""

    STATUS_TTL_SECONDS = 300

    def __init__(self, tenant_id: Optional[str] = None, credential_factory=None):
        self._tenant_id = tenant_id
        self._factory = credential_factory or self._default_factory
        self._lock = threading.Lock()
        self._credential = None
        self._status: Dict[str, Any] = {}
        self._checked_at = 0.0

    def _default_factory(self):
        from azure.identity import AzureCliCredential

        return AzureCliCredential(tenant_id=self._tenant_id) if self._tenant_id else AzureCliCredential()

    @property
    def credential(self):
        with self._lock:
            if self._credential is None:
                self._credential = CachedTokenCredential(self._factory())
            return self._credential

    def status(self, refresh: bool = False) -> Dict[str, Any]:
        """{'signed_in', 'account', 'display_name', 'tenant_id', 'error'} - cached for a few minutes."""
        with self._lock:
            fresh = time.time() - self._checked_at < self.STATUS_TTL_SECONDS
            if self._status and fresh and not refresh:
                return dict(self._status)
            if refresh:
                self._credential = None  # pick up a new `az login` (other account / tenant)
        try:
            token = self.credential.get_token(ARM_SCOPE)
            claims = token_claims(token.token)
            status = {
                "signed_in": True,
                "account": (claims.get("upn") or claims.get("unique_name") or claims.get("email")
                            or claims.get("name") or claims.get("appid")),
                "display_name": claims.get("name"),
                "tenant_id": claims.get("tid") or self._tenant_id,
                "error": None,
            }
        except Exception as exc:
            with self._lock:
                self._credential = None
            status = {"signed_in": False, "account": None, "display_name": None, "tenant_id": self._tenant_id,
                      "error": friendly_error(exc)}
        with self._lock:
            self._status, self._checked_at = status, time.time()
        return dict(status)


def friendly_error(exc: Exception) -> str:
    text = str(exc)
    lowered = text.lower()
    if "az login" in lowered or "please run" in lowered or "not logged in" in lowered:
        return "The Azure CLI is not signed in. Run `az login` in a terminal, then click Refresh."
    if "azure cli not found" in lowered or "not found on path" in lowered:
        return "The Azure CLI (az) was not found on PATH. Install it, run `az login`, then restart the portal."
    return text.splitlines()[0][:300] if text else exc.__class__.__name__
