"""
Encryption utilities for sensitive data (tenant credentials, secrets).

Uses AES-256-GCM for authenticated encryption — provides both confidentiality
and integrity. The encryption key comes from settings and should be a
32-byte (256-bit) randomly generated secret stored in Vault/Key Vault in prod.

Why AES-GCM over AES-CBC?
  - GCM is an AEAD cipher: it authenticates the ciphertext, preventing
    tampering without detection. CBC requires a separate HMAC step.
  - GCM is faster on modern CPUs with AES-NI hardware acceleration.
  - GCM doesn't require padding, eliminating padding oracle attacks.
"""

import base64
import os
import json
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from backend.core.config import get_settings

settings = get_settings()

# AES-GCM nonce size: 96 bits (12 bytes) is the recommended size.
# A new nonce is generated for every encryption operation.
NONCE_SIZE = 12


def _get_key() -> bytes:
    """
    Derive a 32-byte AES key from the configured encryption key.

    The raw key from settings may be a base64-encoded string or raw bytes.
    We normalize it to exactly 32 bytes for AES-256.
    """
    # settings.ENCRYPTION_KEY is a pydantic SecretStr — unwrap it to the
    # actual string value before any byte-level processing. Using it
    # directly (without get_secret_value()) raises a TypeError deep in
    # the KDF/AESGCM calls since SecretStr is not bytes-like.
    raw = settings.ENCRYPTION_KEY.get_secret_value()
    if isinstance(raw, str):
        raw = raw.encode()

    # If already 32 bytes, use directly
    if len(raw) == 32:
        return raw

    # If base64-encoded 32-byte key
    try:
        decoded = base64.b64decode(raw)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    # Otherwise derive 32-byte key via PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"arg-key-derivation-v1",  # static salt is OK here since raw is already high-entropy
        iterations=100_000,
    )
    return kdf.derive(raw)


def encrypt(plaintext: str) -> str:
    """
    Encrypt a string using AES-256-GCM.

    Returns a base64-encoded string in the format: nonce:ciphertext+tag
    The GCM tag is appended to the ciphertext by the AESGCM implementation.

    Args:
        plaintext: The string to encrypt.

    Returns:
        Base64-encoded encrypted payload.
    """
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Combine nonce + ciphertext into a single base64 blob
    payload = nonce + ciphertext
    return base64.b64encode(payload).decode("utf-8")


def decrypt(encrypted: str) -> str:
    """
    Decrypt an AES-256-GCM encrypted string.

    Args:
        encrypted: Base64-encoded encrypted payload (nonce + ciphertext).

    Returns:
        Decrypted plaintext string.

    Raises:
        ValueError: If decryption fails (wrong key or tampered data).
    """
    key = _get_key()
    aesgcm = AESGCM(key)

    try:
        payload = base64.b64decode(encrypted.encode("utf-8"))
        nonce = payload[:NONCE_SIZE]
        ciphertext = payload[NONCE_SIZE:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception as exc:
        raise ValueError("Decryption failed — invalid key or corrupted data") from exc


def encrypt_dict(data: dict[str, Any]) -> str:
    """Serialize a dict to JSON and encrypt it."""
    return encrypt(json.dumps(data))


def decrypt_dict(encrypted: str) -> dict[str, Any]:
    """Decrypt and deserialize a JSON dict."""
    return json.loads(decrypt(encrypted))


def generate_key() -> str:
    """
    Generate a new random 32-byte AES-256 key, base64-encoded.
    Use this during initial setup to create the ENCRYPTION_KEY env var.
    """
    return base64.b64encode(os.urandom(32)).decode("utf-8")


# ---------------------------------------------------------------------------
# Convenience wrappers for Azure credential storage
# ---------------------------------------------------------------------------

def encrypt_azure_credentials(
    client_id: str,
    client_secret: str,
    tenant_id: str,
) -> str:
    """
    Encrypt Azure service principal credentials as a JSON blob.

    Stored as a single encrypted field in the DB, so a compromise of the
    DB alone doesn't expose credentials without the encryption key.
    """
    return encrypt_dict({
        "client_id": client_id,
        "client_secret": client_secret,
        "tenant_id": tenant_id,
    })


def decrypt_azure_credentials(encrypted: str) -> dict[str, str]:
    """Decrypt and return Azure service principal credentials."""
    data = decrypt_dict(encrypted)
    return {
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
        "tenant_id": data["tenant_id"],
    }
