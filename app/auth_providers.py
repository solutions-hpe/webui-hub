"""Auth provider stubs — SSO/OIDC, LDAP/AD, RADIUS. Inactive until configured."""
from __future__ import annotations

import logging
from typing import Optional

from .config import get_settings
from .data_models import User

logger = logging.getLogger(__name__)


class AuthProviderError(Exception):
    pass


# ── OIDC / SSO ────────────────────────────────────────────────────────────────

async def oidc_authenticate(token: str) -> Optional[User]:
    """Authenticate via OIDC/OAuth2. Stub — not yet implemented."""
    settings = get_settings()
    if not settings.oidc_enabled:
        return None
    # TODO: validate JWT token against OIDC discovery URL
    # 1. Fetch JWKS from {oidc_discovery_url}/.well-known/jwks.json
    # 2. Validate token signature and claims
    # 3. Extract username/email from claims
    # 4. Look up or auto-provision User in store
    logger.warning("OIDC auth attempted but not yet implemented")
    raise AuthProviderError("OIDC authentication not yet implemented")


# ── LDAP / Active Directory ───────────────────────────────────────────────────

async def ldap_authenticate(username: str, password: str) -> Optional[User]:
    """Authenticate via LDAP/AD. Stub — not yet implemented."""
    settings = get_settings()
    if not settings.ldap_enabled:
        return None
    # TODO: implement LDAP bind authentication
    # 1. Connect to settings.ldap_url
    # 2. Bind with settings.ldap_bind_dn / ldap_bind_password
    # 3. Search for user under ldap_user_search_base
    # 4. Attempt bind with user DN + provided password
    # 5. On success: look up or auto-provision User in store
    # Requires: pip install ldap3
    logger.warning("LDAP auth attempted but not yet implemented")
    raise AuthProviderError("LDAP/AD authentication not yet implemented")


# ── RADIUS ────────────────────────────────────────────────────────────────────

async def radius_authenticate(username: str, password: str) -> Optional[User]:
    """Authenticate via RADIUS. Stub — not yet implemented."""
    settings = get_settings()
    if not settings.radius_enabled:
        return None
    # TODO: implement RADIUS PAP/CHAP authentication
    # 1. Connect to settings.radius_host:radius_port
    # 2. Send Access-Request with username + password
    # 3. On Access-Accept: look up or auto-provision User in store
    # Requires: pip install pyrad
    logger.warning("RADIUS auth attempted but not yet implemented")
    raise AuthProviderError("RADIUS authentication not yet implemented")


# ── Provider registry ─────────────────────────────────────────────────────────

def get_enabled_providers() -> list[str]:
    """Return list of configured (but not necessarily active) provider names."""
    settings = get_settings()
    providers = ["password"]
    if settings.oidc_enabled:
        providers.append("oidc")
    if settings.ldap_enabled:
        providers.append("ldap")
    if settings.radius_enabled:
        providers.append("radius")
    return providers
