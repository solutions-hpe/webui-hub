from __future__ import annotations

import asyncio
import io
import logging
import socket
from typing import Optional

from .config import get_settings
from .data_models import HubAuthConfig, User

logger = logging.getLogger(__name__)


class AuthProviderError(Exception):
    pass


def _normalize_provider(value: str) -> str:
    provider = str(value or "local").strip().lower()
    return provider if provider in {"local", "ldap", "radius", "tacacs"} else "local"


def _normalize_default_role(value: str) -> str:
    role = str(value or "tenant_admin").strip().lower()
    return role if role in {"superadmin", "tenant_admin"} else "tenant_admin"


def _tenant_roles(tenant_id: str | None) -> list[dict[str, str]]:
    return [{"tenant_id": tenant_id, "role": "admin"}] if tenant_id else []


def _build_enterprise_user(username: str, is_superadmin: bool, tenant_id: str | None) -> User:
    return User(
        username=username,
        hashed_password="",
        is_superadmin=is_superadmin,
        tenant_roles=[] if is_superadmin else _tenant_roles(tenant_id),
    )


def _resolve_default_access(config: HubAuthConfig) -> tuple[bool, str | None]:
    if _normalize_default_role(config.auth_default_role) == "tenant_admin":
        tenant_id = (config.auth_ldap_tenant_id or "").strip()
        if not tenant_id:
            raise AuthProviderError("auth_ldap_tenant_id is required when auth_default_role is tenant_admin")
        return False, tenant_id
    return True, None


def _decrypt_secret(value: str) -> str:
    if not value:
        return ""
    from .crypto import decrypt_str

    try:
        return decrypt_str(value)
    except Exception as exc:  # pragma: no cover - defensive
        raise AuthProviderError(f"Unable to decrypt stored secret: {exc}") from exc


def _provision_enterprise_user(username: str, is_superadmin: bool, tenant_id: str | None) -> User:
    from . import store

    user = store.get_user(username)
    if user is None:
        user = _build_enterprise_user(username, is_superadmin, tenant_id)
    else:
        user.is_superadmin = is_superadmin
        user.tenant_roles = [] if is_superadmin else _tenant_roles(tenant_id)
        user.hashed_password = user.hashed_password or ""
    store.save_user(user)
    return user


async def oidc_authenticate(token: str) -> Optional[User]:
    settings = get_settings()
    if not settings.oidc_enabled:
        return None
    logger.warning("OIDC auth attempted but not yet implemented")
    raise AuthProviderError("OIDC authentication not yet implemented")


def _ldap_authenticate_sync(
    config: HubAuthConfig,
    username: str,
    password: str,
    *,
    provision: bool,
) -> Optional[User]:
    try:
        from ldap3 import ALL, Connection, Server
    except ImportError:
        logger.warning("ldap3 not installed — LDAP auth unavailable")
        return None

    try:
        bind_password = _decrypt_secret(config.auth_ldap_bind_password_enc)
        if not config.auth_ldap_url or not config.auth_ldap_bind_dn or not bind_password or not config.auth_ldap_user_base:
            return None

        server = Server(config.auth_ldap_url, get_info=ALL)
        search_filter = str(config.auth_ldap_user_filter or "(&(objectClass=user)(sAMAccountName={username}))").format(username=username)
        with Connection(server, user=config.auth_ldap_bind_dn, password=bind_password, auto_bind=True) as conn:
            conn.search(
                search_base=config.auth_ldap_user_base,
                search_filter=search_filter,
                attributes=["cn", "mail", "memberOf", "displayName"],
            )
            if not conn.entries:
                return None
            entry = conn.entries[0]
            user_dn = entry.entry_dn
            member_of = [str(group) for group in list(entry.memberOf)] if hasattr(entry, "memberOf") and entry.memberOf else []

        with Connection(server, user=user_dn, password=password, auto_bind=True) as user_conn:
            if not user_conn.bound:
                return None

        member_of_lower = [group.lower() for group in member_of]
        superadmin_group = (config.auth_ldap_group_superadmin or "").strip().lower()
        tenant_admin_group = (config.auth_ldap_group_tenant_admin or "").strip().lower()
        tenant_id = (config.auth_ldap_tenant_id or "").strip()

        is_superadmin = bool(superadmin_group and any(superadmin_group in group for group in member_of_lower))
        assigned_tenant_id: str | None = None
        if not is_superadmin and tenant_admin_group and tenant_id and any(tenant_admin_group in group for group in member_of_lower):
            assigned_tenant_id = tenant_id
        elif not is_superadmin:
            is_superadmin, assigned_tenant_id = _resolve_default_access(config)

        return _provision_enterprise_user(username, is_superadmin, assigned_tenant_id) if provision else _build_enterprise_user(username, is_superadmin, assigned_tenant_id)
    except Exception as exc:
        logger.warning("LDAP auth error for %s: %s", username, exc)
        return None


async def ldap_authenticate(username: str, password: str) -> Optional[User]:
    from . import store

    config = store.load_auth_config()
    if _normalize_provider(config.auth_provider) != "ldap":
        return None
    return await asyncio.to_thread(_ldap_authenticate_sync, config, username, password, provision=True)


def _radius_authenticate_sync(
    config: HubAuthConfig,
    username: str,
    password: str,
    *,
    provision: bool,
) -> Optional[User]:
    try:
        import pyrad.client
        import pyrad.dictionary
        import pyrad.packet
    except ImportError:
        logger.warning("pyrad not installed — RADIUS auth unavailable")
        return None

    try:
        secret = _decrypt_secret(config.auth_radius_secret_enc)
        if not config.auth_radius_host or not secret:
            return None

        dictionary = pyrad.dictionary.Dictionary(io.StringIO(
            "ATTRIBUTE User-Name 1 string\n"
            "ATTRIBUTE User-Password 2 string\n"
            "ATTRIBUTE Filter-Id 11 string\n"
            "ATTRIBUTE Class 25 string\n"
        ))
        client = pyrad.client.Client(
            server=config.auth_radius_host,
            authport=int(config.auth_radius_port or 1812),
            secret=secret.encode(),
            dict=dictionary,
        )
        client.timeout = 10
        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=username)
        req["User-Password"] = req.PwCrypt(password)
        reply = client.SendPacket(req)
        if reply.code != pyrad.packet.AccessAccept:
            return None

        role_attr = str(config.auth_radius_role_attr or "Filter-Id")
        superadmin_val = str(config.auth_radius_superadmin_val or "superadmin").strip().lower()
        is_superadmin = False
        values = reply.get(role_attr, []) if hasattr(reply, "get") else []
        for raw_value in values:
            attr_value = raw_value.decode(errors="ignore") if isinstance(raw_value, bytes) else str(raw_value)
            if attr_value.strip().lower() == superadmin_val:
                is_superadmin = True
                break

        assigned_tenant_id: str | None = None
        if not is_superadmin:
            is_superadmin, assigned_tenant_id = _resolve_default_access(config)

        return _provision_enterprise_user(username, is_superadmin, assigned_tenant_id) if provision else _build_enterprise_user(username, is_superadmin, assigned_tenant_id)
    except Exception as exc:
        logger.warning("RADIUS auth error for %s: %s", username, exc)
        return None


async def radius_authenticate(username: str, password: str) -> Optional[User]:
    from . import store

    config = store.load_auth_config()
    if _normalize_provider(config.auth_provider) != "radius":
        return None
    return await asyncio.to_thread(_radius_authenticate_sync, config, username, password, provision=True)


def _tacacs_authenticate_sync(
    config: HubAuthConfig,
    username: str,
    password: str,
    *,
    provision: bool,
) -> Optional[User]:
    try:
        import tacacs_plus.client as tacacs
    except ImportError:
        logger.warning("tacacs-plus not installed — TACACS+ auth unavailable")
        return None

    try:
        secret = _decrypt_secret(config.auth_tacacs_secret_enc)
        if not config.auth_tacacs_host or not secret:
            return None

        client = tacacs.TACACSClient(
            host=config.auth_tacacs_host,
            port=int(config.auth_tacacs_port or 49),
            secret=secret.encode(),
            timeout=10,
        )
        authen = client.authenticate(username, password)
        if not getattr(authen, "valid", False):
            return None

        author = client.authorize(username, arguments=[b"service=shell", b"cmd="])
        priv_lvl = 0
        for arg in getattr(author, "arguments", []) or []:
            arg_str = arg.decode() if isinstance(arg, bytes) else str(arg)
            if arg_str.startswith("priv-lvl="):
                try:
                    priv_lvl = int(arg_str.split("=", 1)[1])
                except Exception:
                    priv_lvl = 0
                break

        is_superadmin = priv_lvl >= int(config.auth_tacacs_superadmin_priv or 15)
        assigned_tenant_id: str | None = None
        if not is_superadmin:
            is_superadmin, assigned_tenant_id = _resolve_default_access(config)

        return _provision_enterprise_user(username, is_superadmin, assigned_tenant_id) if provision else _build_enterprise_user(username, is_superadmin, assigned_tenant_id)
    except Exception as exc:
        logger.warning("TACACS+ auth error for %s: %s", username, exc)
        return None


async def tacacs_authenticate(username: str, password: str) -> Optional[User]:
    from . import store

    config = store.load_auth_config()
    if _normalize_provider(config.auth_provider) != "tacacs":
        return None
    return await asyncio.to_thread(_tacacs_authenticate_sync, config, username, password, provision=True)


async def test_auth_provider(
    provider: str,
    config: HubAuthConfig,
    test_username: str = "",
    test_password: str = "",
) -> dict:
    provider_name = _normalize_provider(provider)
    if provider_name == "local":
        return {"ok": True, "message": "Local auth does not require external connectivity."}

    if provider_name == "ldap":
        try:
            from ldap3 import ALL, Connection, Server

            bind_password = _decrypt_secret(config.auth_ldap_bind_password_enc)
            if not config.auth_ldap_url or not config.auth_ldap_bind_dn or not bind_password:
                return {"ok": False, "message": "LDAP server URL, bind DN, and bind password are required."}
            server = Server(config.auth_ldap_url, get_info=ALL)
            with Connection(server, user=config.auth_ldap_bind_dn, password=bind_password, auto_bind=True):
                if test_username and test_password:
                    user = await asyncio.to_thread(_ldap_authenticate_sync, config, test_username, test_password, provision=False)
                    if not user:
                        return {"ok": False, "message": "LDAP test login failed."}
                    role = "superadmin" if user.is_superadmin else ("tenant-admin" if user.tenant_roles else "user")
                    return {"ok": True, "message": f"LDAP bind and test login succeeded ({role})."}
                return {"ok": True, "message": f"Connected to {config.auth_ldap_url}."}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    if provider_name == "radius":
        try:
            if not test_username or not test_password:
                return {"ok": False, "message": "RADIUS testing requires a username and password."}
            user = await asyncio.to_thread(_radius_authenticate_sync, config, test_username, test_password, provision=False)
            if not user:
                return {"ok": False, "message": "RADIUS authentication failed."}
            role = "superadmin" if user.is_superadmin else ("tenant-admin" if user.tenant_roles else "user")
            return {"ok": True, "message": f"RADIUS authentication succeeded ({role})."}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    if provider_name == "tacacs":
        try:
            if test_username and test_password:
                user = await asyncio.to_thread(_tacacs_authenticate_sync, config, test_username, test_password, provision=False)
                if not user:
                    return {"ok": False, "message": "TACACS+ authentication failed."}
                role = "superadmin" if user.is_superadmin else ("tenant-admin" if user.tenant_roles else "user")
                return {"ok": True, "message": f"TACACS+ authentication succeeded ({role})."}

            if not config.auth_tacacs_host:
                return {"ok": False, "message": "TACACS+ host is required."}
            sock = socket.create_connection((config.auth_tacacs_host, int(config.auth_tacacs_port or 49)), timeout=5)
            sock.close()
            return {"ok": True, "message": f"TCP connection to {config.auth_tacacs_host}:{config.auth_tacacs_port or 49} OK."}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    return {"ok": False, "message": f"Unsupported provider: {provider_name}"}


def get_enabled_providers() -> list[str]:
    from . import store

    settings = get_settings()
    config = store.load_auth_config()
    providers = ["password"]
    if settings.oidc_enabled:
        providers.append("oidc")
    selected = _normalize_provider(config.auth_provider)
    if selected != "local":
        providers.append(selected)
    return providers
