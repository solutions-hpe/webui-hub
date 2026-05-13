"""Helpers for encrypting Hub secrets before writing them to JSON.

The module builds a single Fernet instance from ``WEBUI_SECRET_KEY`` and uses
it for API keys, Aruba Central credentials, notification settings, and other
secrets that must be stored at rest. Callers typically serialize structured
data with ``encrypt_dict``/``decrypt_dict`` and use the string helpers for
single values. In ``dev`` only, an ephemeral key is generated when no key is
configured; other environments must provide a valid Fernet key.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.fernet import Fernet

from .config import get_settings

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        settings = get_settings()
        key = settings.webui_secret_key.strip()
        if not key:
            key = Fernet.generate_key().decode()
            import logging

            logging.getLogger(__name__).warning(
                "WEBUI_SECRET_KEY not set in dev — generated ephemeral key. "
                "Secrets will not survive restart. Set WEBUI_SECRET_KEY in .env"
            )
        try:
            _fernet = Fernet(key.encode())
        except Exception as exc:
            raise ValueError(
                "Invalid WEBUI_SECRET_KEY: must be a 32-byte URL-safe base64 Fernet key"
            ) from exc
    return _fernet


def encrypt_str(value: str) -> str:
    """Encrypt a plaintext string and return the Fernet ciphertext as text."""
    return _get_fernet().encrypt(value.encode()).decode()


def decrypt_str(ciphertext: str) -> str:
    """Decrypt a Fernet ciphertext string back to its original plaintext value."""
    return _get_fernet().decrypt(ciphertext.encode()).decode()


def encrypt_dict(data: dict) -> str:
    """Encrypt a dict as JSON. Returns ciphertext string."""
    return encrypt_str(json.dumps(data))


def decrypt_dict(ciphertext: str) -> dict:
    """Decrypt a ciphertext string back to dict."""
    return json.loads(decrypt_str(ciphertext))


def generate_api_key() -> str:
    """Generate a URL-safe random spoke relay API key for one-time approval flows."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
