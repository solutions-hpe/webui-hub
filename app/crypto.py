"""Helpers for encrypting Hub secrets before writing them to JSON."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

_fernet: Fernet | None = None
_value_fernet: Fernet | None = None

_logger = logging.getLogger(__name__)

# If this file exists on the Azure Files mount, its contents are used as
# WEBUI_SECRET_KEY instead of the env var.  This allows the key to be
# provisioned once on the persistent share and rotated without redeploying.
_KEY_FILE_PATH = Path(os.environ.get("DATA_DIR", "/data")) / "hub.key"


def _persist_key_to_file(path: Path, key: str) -> None:
    """Write key to hub.key so future restarts use the same key regardless of env var."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(key)
        _logger.info("WEBUI_SECRET_KEY persisted to key file: %s", path)
    except OSError as exc:
        _logger.warning("Could not persist key to %s: %s", path, exc)


def _load_key_from_file(path: Path) -> str | None:
    """Return the trimmed key string from the key file, or None if absent/unreadable."""
    try:
        if path.exists():
            key = path.read_text().strip()
            if key:
                _logger.info("WEBUI_SECRET_KEY loaded from key file: %s", path)
                return key
    except OSError as exc:
        _logger.warning("Could not read key file %s: %s — falling back to env var", path, exc)
    return None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        # Prefer key file on Azure Files share; fall back to env var
        key = _load_key_from_file(_KEY_FILE_PATH)
        if not key:
            settings = get_settings()
            key = settings.webui_secret_key.strip()
            if key:
                # Persist the env-var key to hub.key so future restarts use it
                # even if WEBUI_SECRET_KEY is later changed or rotated.
                _persist_key_to_file(_KEY_FILE_PATH, key)
        if not key:
            key = Fernet.generate_key().decode()
            _logger.warning(
                "WEBUI_SECRET_KEY not set in dev — generated ephemeral key. "
                "Secrets will not survive restart. Set WEBUI_SECRET_KEY in .env"
            )
            _persist_key_to_file(_KEY_FILE_PATH, key)
        try:
            _fernet = Fernet(key.encode())
        except Exception as exc:
            raise ValueError(
                "Invalid WEBUI_SECRET_KEY: must be a 32-byte URL-safe base64 Fernet key"
            ) from exc
    return _fernet


def _get_value_fernet() -> Fernet:
    global _value_fernet
    if _value_fernet is None:
        key = os.environ.get("ENCRYPTION_KEY", "").strip()
        if not key:
            raise RuntimeError("ENCRYPTION_KEY env var is not set")
        try:
            _value_fernet = Fernet(key.encode())
        except Exception as exc:
            raise RuntimeError(
                "Invalid ENCRYPTION_KEY: must be a 32-byte URL-safe base64 Fernet key"
            ) from exc
    return _value_fernet


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


def encrypt_value(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns a Fernet token safe to store."""
    return _get_value_fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted string. Raises ValueError on failure."""
    try:
        return _get_value_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt value: invalid ENCRYPTION_KEY or corrupted data") from exc


def generate_blob_container_sas(
    account_name: str,
    account_key: str,
    container: str,
    permissions: str = "rl",
    hours: int = 1,
) -> str:
    """Generate an Azure Blob Service SAS URL for a container."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expiry = (now + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sv = "2023-11-03"

    string_to_sign = "\n".join([
        permissions,
        start,
        expiry,
        f"/blob/{account_name}/{container}",
        "",
        "",
        "https",
        sv,
        "c",
        "",
        "",
        "",
        "",
        "",
        "",
    ])

    key_bytes = base64.b64decode(account_key)
    sig = base64.b64encode(
        hmac.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode()

    params = {
        "sv": sv,
        "sr": "c",
        "sp": permissions,
        "st": start,
        "se": expiry,
        "spr": "https",
        "sig": sig,
    }
    base = f"https://{account_name}.blob.core.windows.net/{container}"
    return f"{base}?{urllib.parse.urlencode(params)}"


def generate_api_key() -> str:
    """Generate a URL-safe random spoke relay API key for one-time approval flows."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
