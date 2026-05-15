from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, Union
import uuid

from ..ws import ws_broadcast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .. import auth, store
from ..aruba import ArubaClient
from ..config import get_settings
from ..crypto import encrypt_dict, encrypt_str, decrypt_str, generate_api_key
from ..data_models import Command, Spoke, Tenant, User

router = APIRouter()


class TenantCreateRequest(BaseModel):
    name: str
    aruba_cid: Optional[str] = None
    aruba_config: dict[str, Any] = Field(default_factory=dict)


class ArubaConfigRequest(BaseModel):
    aruba_cid: Optional[str] = None
    config: dict[str, Any] = Field(default_factory=dict)


class ArubaTenantDiscoveryRequest(BaseModel):
    cluster_url: str
    client_id: str = ""
    client_secret: str = ""
    api_version: str = "new_central"
    auto_import: bool = False


class NotificationConfigRequest(BaseModel):
    teams_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    to_emails: Union[list[str], str] = Field(default_factory=list)
    from_email: str = "hub@localhost"
    enabled: bool = False


class ApprovePendingSpokeRequest(BaseModel):
    tenant_id: str
    label: Optional[str] = None


class CreateUserRequest(BaseModel):
    username: str
    password: str


class AssignRoleRequest(BaseModel):
    tenant_id: str
    role: Literal["admin", "viewer", "operator"]


class HubAuthConfigRequest(BaseModel):
    auth_provider: str
    auth_ldap_url: str = ""
    auth_ldap_bind_dn: str = ""
    auth_ldap_bind_password: str = ""
    auth_ldap_user_base: str = ""
    auth_ldap_user_filter: str = ""
    auth_ldap_group_superadmin: str = ""
    auth_ldap_group_tenant_admin: str = ""
    auth_ldap_tenant_id: str = ""
    auth_radius_host: str = ""
    auth_radius_port: int = 1812
    auth_radius_secret: str = ""
    auth_radius_role_attr: str = "Filter-Id"
    auth_radius_superadmin_val: str = "superadmin"
    auth_tacacs_host: str = ""
    auth_tacacs_port: int = 49
    auth_tacacs_secret: str = ""
    auth_tacacs_superadmin_priv: int = 15
    auth_default_role: str = "superadmin"


def _normalize_notification_config(payload: NotificationConfigRequest) -> dict[str, Any]:
    to_emails = payload.to_emails
    if isinstance(to_emails, str):
        to_emails = [item.strip() for item in to_emails.split(",") if item.strip()]
    return {
        "enabled": payload.enabled,
        "teams_webhook": payload.teams_webhook_url,
        "teams_webhook_url": payload.teams_webhook_url,
        "smtp_host": payload.smtp_host,
        "smtp_port": payload.smtp_port,
        "smtp_user": payload.smtp_user,
        "smtp_pass": payload.smtp_pass,
        "to_emails": to_emails,
        "from_email": payload.from_email,
    }


def _tenant_response(tenant: Tenant) -> dict[str, Any]:
    return {
        "id": tenant.id,
        "name": tenant.name,
        "aruba_cid": tenant.aruba_cid,
        "has_aruba_config": bool(tenant.aruba_config_enc),
        "has_notification_config": bool(tenant.notification_config_enc),
        "default_processing_mode": tenant.default_processing_mode.model_dump(),
        "hub_config_enabled": tenant.hub_config_enabled,
        "created_at": tenant.created_at,
        "created_by": tenant.created_by,
    }


def _user_response(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "is_superadmin": user.is_superadmin,
        "tenant_roles": user.tenant_roles,
        "created_at": user.created_at,
    }


def _build_approval_config_payload(
    tenant: "Tenant",
    seed_config: dict,
    plain_key: str,
    spoke_id: str,
    tenant_id: str,
    relay_server_url: str,
) -> dict:
    """Build config_update payload for a newly approved spoke.
    If hub_config_enabled, seed hub_config from first spoke or push existing hub_config.
    Returns (payload_dict, updated_tenant_or_None)."""
    base = {
        "relay_spoke_id": spoke_id,
        "relay_api_key": plain_key,
        "relay_tenant_id": tenant_id,
        "relay_server_url": relay_server_url,
    }
    if not tenant.hub_config_enabled:
        return base, None

    if not tenant.hub_config:
        # First spoke — seed hub_config from spoke's seed_config
        tenant.hub_config = dict(seed_config or {})
        store.save_tenant(tenant)
        base.update(tenant.hub_config)
        return base, tenant

    # Subsequent spoke — overwrite with hub's canonical config
    base.update(tenant.hub_config)
    return base, None


def _ensure_tenant_spoke_name_available(
    tenant_id: str,
    spoke_name: str,
    *,
    spoke_id: str,
    hostname: str,
) -> None:
    approved_conflict = store.find_spoke_name_conflict(
        tenant_id,
        spoke_name,
        exclude_spoke_id=spoke_id,
    )
    if approved_conflict and approved_conflict.hostname != hostname:
        raise HTTPException(
            status_code=409,
            detail={
                "conflict": "name_in_use",
                "message": (
                    f"Spoke name '{spoke_name}' is already in use by another approved spoke "
                    f"within tenant '{tenant_id}'. Choose a different name."
                ),
            },
        )

    pending_conflict = store.find_pending_spoke_name_conflict(
        tenant_id,
        spoke_name,
        exclude_spoke_id=spoke_id,
    )
    if pending_conflict and pending_conflict.hostname != hostname:
        raise HTTPException(
            status_code=409,
            detail={
                "conflict": "name_in_use",
                "message": (
                    f"Spoke name '{spoke_name}' is already registered and pending approval "
                    f"within tenant '{tenant_id}'. Choose a different name."
                ),
            },
        )


@router.post("/superadmin/tenants", status_code=status.HTTP_201_CREATED)
def create_tenant(payload: TenantCreateRequest, current_user: User = Depends(auth.require_superadmin)):
    tenant_id = payload.aruba_cid or None
    if tenant_id and store.get_tenant(tenant_id):
        raise HTTPException(status_code=409, detail="Tenant already exists")

    tenant = Tenant(
        id=tenant_id or str(uuid.uuid4()),
        name=payload.name,
        aruba_cid=payload.aruba_cid,
        created_by=current_user.username,
    )
    if payload.aruba_config:
        tenant.aruba_config_enc = encrypt_dict(payload.aruba_config)
    store.save_tenant(tenant)
    return _tenant_response(tenant)


@router.get("/superadmin/tenants")
def list_tenants(_: User = Depends(auth.require_superadmin)):
    return [_tenant_response(tenant) for tenant in store.list_tenants()]


@router.get("/superadmin/tenants/{tenant_id}")
def get_tenant_detail(tenant_id: str, _: User = Depends(auth.require_superadmin)):
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _tenant_response(tenant)


@router.delete("/superadmin/tenants/{tenant_id}")
def delete_tenant(tenant_id: str, _: User = Depends(auth.require_superadmin)):
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    store.delete_tenant(tenant_id)
    return {"status": "deleted"}


@router.post("/superadmin/tenants/{tenant_id}/aruba")
def update_tenant_aruba(
    tenant_id: str,
    payload: ArubaConfigRequest,
    _: User = Depends(auth.require_superadmin),
):
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    if payload.aruba_cid:
        tenant.aruba_cid = payload.aruba_cid
    if payload.config:
        tenant.aruba_config_enc = encrypt_dict(payload.config)
    store.save_tenant(tenant)
    return _tenant_response(tenant)


@router.post("/superadmin/aruba/discover-tenants")
async def discover_aruba_tenants(
    payload: ArubaTenantDiscoveryRequest,
    current_user: User = Depends(auth.require_superadmin),
):
    client = ArubaClient(
        {
            "cluster_url": payload.cluster_url,
            "client_id": payload.client_id,
            "client_secret": payload.client_secret,
            "api_version": payload.api_version,
        }
    )
    tenants = await client.discover_tenants()
    if payload.auto_import:
        for item in tenants:
            tenant_id = item.get("cid")
            if tenant_id and not store.get_tenant(tenant_id):
                store.save_tenant(
                    Tenant(
                        id=tenant_id,
                        name=item.get("name") or tenant_id,
                        aruba_cid=tenant_id,
                        created_by=current_user.username,
                    )
                )
    return tenants


@router.post("/superadmin/tenants/{tenant_id}/notification-config")
def update_tenant_notification_config(
    tenant_id: str,
    payload: NotificationConfigRequest,
    _: User = Depends(auth.require_superadmin),
):
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    tenant.notification_config_enc = encrypt_dict(_normalize_notification_config(payload))
    store.save_tenant(tenant)
    return {"status": "saved"}


class HubConfigRequest(BaseModel):
    hub_config_enabled: bool
    hub_config: dict[str, Any] = Field(default_factory=dict)


# ── Onboarding PSK ────────────────────────────────────────────────────────────

def _psk_require_tenant_admin(tenant_id: str, current_user: User = Depends(auth.get_current_user)) -> str:
    auth.require_tenant_access(tenant_id, current_user)
    if not current_user.is_superadmin and current_user.get_role(tenant_id) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return tenant_id


def _migrate_legacy_psk(tenant) -> None:
    """Move legacy onboarding_psk_enc into the list if not already there."""
    if tenant.onboarding_psk_enc and tenant.onboarding_psk_enc not in tenant.onboarding_psks_enc:
        tenant.onboarding_psks_enc.insert(0, tenant.onboarding_psk_enc)
        tenant.onboarding_psk_enc = ""


def _get_tenant_psks(tenant) -> list[str]:
    """Return all decrypted PSKs for a tenant (migrating legacy field if needed)."""
    _migrate_legacy_psk(tenant)
    psks = []
    for enc in tenant.onboarding_psks_enc:
        try:
            psks.append(decrypt_str(enc))
        except Exception:
            pass
    return psks


def _safe_decrypt_eq(enc: str, plain: str) -> bool:
    try:
        return decrypt_str(enc) == plain
    except Exception:
        return False


@router.get("/tenant/{tenant_id}/onboarding-psk")
def get_onboarding_psks(
    tenant_id: str = Depends(_psk_require_tenant_admin),
):
    """Return all onboarding PSKs for this tenant (values visible to tenant admins)."""
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    psks = _get_tenant_psks(tenant)
    return {"psks": psks, "has_psk": bool(psks)}


@router.post("/tenant/{tenant_id}/onboarding-psk")
def generate_onboarding_psk(
    tenant_id: str = Depends(_psk_require_tenant_admin),
):
    """Generate a new onboarding PSK and add it to the tenant's PSK list.

    Multiple PSKs may coexist — any valid PSK auto-approves a spoke registration.
    """
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    plain_psk = generate_api_key()
    _migrate_legacy_psk(tenant)
    tenant.onboarding_psks_enc.append(encrypt_str(plain_psk))
    store.save_tenant(tenant)
    return {"psk": plain_psk, "psks": _get_tenant_psks(tenant)}


@router.delete("/tenant/{tenant_id}/onboarding-psk", status_code=200)
def revoke_onboarding_psk(
    tenant_id: str = Depends(_psk_require_tenant_admin),
    body: dict = None,
):
    """Revoke one specific PSK (pass {\"psk\": \"<value>\"} in body) or all PSKs if no body."""
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    _migrate_legacy_psk(tenant)
    psk_to_revoke = (body or {}).get("psk", "").strip()
    if psk_to_revoke:
        tenant.onboarding_psks_enc = [
            enc for enc in tenant.onboarding_psks_enc
            if not _safe_decrypt_eq(enc, psk_to_revoke)
        ]
    else:
        tenant.onboarding_psks_enc = []
        tenant.onboarding_psk_enc = ""
    store.save_tenant(tenant)
    return {"psks": _get_tenant_psks(tenant), "has_psk": bool(tenant.onboarding_psks_enc)}


@router.get("/tenant/{tenant_id}/hub-config")
def get_tenant_hub_config(
    tenant_id: str,
    current_user: User = Depends(auth.require_superadmin),
):
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    hub_config = dict(tenant.hub_config or {})
    hub_config["usb_vidpids"] = store.get_tenant_usb_vidpids(tenant_id)
    return {
        "hub_config_enabled": tenant.hub_config_enabled,
        "hub_config": hub_config,
        "processing_modes": tenant.processing_modes,
    }


@router.put("/tenant/{tenant_id}/hub-config")
async def update_tenant_hub_config(
    tenant_id: str,
    payload: HubConfigRequest,
    request: Request,
    current_user: User = Depends(auth.require_superadmin),
):
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    tenant.hub_config_enabled = payload.hub_config_enabled
    tenant.hub_config = payload.hub_config or {}
    if isinstance(tenant.hub_config.get("usb_vidpids"), list):
        tenant.usb_vidpids = [dict(item) for item in tenant.hub_config.get("usb_vidpids") if isinstance(item, dict)]
    store.save_tenant(tenant)

    pushed_count = 0
    for spoke in store.list_spokes(tenant_id):
        if spoke.status != "approved":
            continue
        if tenant.hub_config_enabled and tenant.hub_config:
            spoke.config_version += 1
            store.save_spoke(spoke)
            store.ensure_config_update_command(tenant_id, spoke.id)
            pushed_count += 1
            continue

        if spoke.config_version > 0:
            spoke.config_version = 0
            spoke.applied_config_version = 0
            store.save_spoke(spoke)
            store.ensure_config_clear_command(tenant_id, spoke.id)
            pushed_count += 1

    return {"status": "saved", "hub_config_enabled": tenant.hub_config_enabled, "pushed_to_spokes": pushed_count}


@router.get("/superadmin/gkill-state")
def get_gkill_state(_: User = Depends(auth.require_superadmin)):
    from .. import tasks

    return tasks.gkill_state


@router.get("/superadmin/auth-providers")
def get_auth_provider_status(_: User = Depends(auth.require_superadmin)):
    from ..auth_providers import get_enabled_providers

    settings = get_settings()
    enabled = set(get_enabled_providers())
    config = store.load_auth_config()
    return {
        "providers": [
            {
                "name": "password",
                "enabled": True,
                "implemented": True,
                "description": "Local bcrypt password",
            },
            {
                "name": "oidc",
                "enabled": settings.oidc_enabled,
                "implemented": False,
                "description": "OIDC/OAuth2 SSO",
            },
            {
                "name": "ldap",
                "enabled": "ldap" in enabled,
                "implemented": True,
                "description": "LDAP / Active Directory",
            },
            {
                "name": "radius",
                "enabled": "radius" in enabled,
                "implemented": True,
                "description": "RADIUS",
            },
            {
                "name": "tacacs",
                "enabled": "tacacs" in enabled,
                "implemented": True,
                "description": "TACACS+",
            },
        ],
        "active_provider": config.auth_provider,
    }


@router.get("/superadmin/auth-config")
def get_auth_config(_: User = Depends(auth.require_superadmin)):
    config = store.load_auth_config()
    return {
        "auth_provider": config.auth_provider,
        "auth_ldap_url": config.auth_ldap_url,
        "auth_ldap_bind_dn": config.auth_ldap_bind_dn,
        "auth_ldap_bind_password_configured": bool(config.auth_ldap_bind_password_enc),
        "auth_ldap_user_base": config.auth_ldap_user_base,
        "auth_ldap_user_filter": config.auth_ldap_user_filter,
        "auth_ldap_group_superadmin": config.auth_ldap_group_superadmin,
        "auth_ldap_group_tenant_admin": config.auth_ldap_group_tenant_admin,
        "auth_ldap_tenant_id": config.auth_ldap_tenant_id,
        "auth_radius_host": config.auth_radius_host,
        "auth_radius_port": config.auth_radius_port,
        "auth_radius_secret_configured": bool(config.auth_radius_secret_enc),
        "auth_radius_role_attr": config.auth_radius_role_attr,
        "auth_radius_superadmin_val": config.auth_radius_superadmin_val,
        "auth_tacacs_host": config.auth_tacacs_host,
        "auth_tacacs_port": config.auth_tacacs_port,
        "auth_tacacs_secret_configured": bool(config.auth_tacacs_secret_enc),
        "auth_tacacs_superadmin_priv": config.auth_tacacs_superadmin_priv,
        "auth_default_role": config.auth_default_role,
    }


@router.post("/superadmin/auth-config")
def save_auth_config_endpoint(payload: HubAuthConfigRequest, _: User = Depends(auth.require_superadmin)):
    config = store.load_auth_config()
    config.auth_provider = payload.auth_provider
    config.auth_ldap_url = payload.auth_ldap_url
    config.auth_ldap_bind_dn = payload.auth_ldap_bind_dn
    if payload.auth_ldap_bind_password:
        config.auth_ldap_bind_password_enc = encrypt_str(payload.auth_ldap_bind_password)
    config.auth_ldap_user_base = payload.auth_ldap_user_base
    config.auth_ldap_user_filter = payload.auth_ldap_user_filter or "(&(objectClass=user)(sAMAccountName={username}))"
    config.auth_ldap_group_superadmin = payload.auth_ldap_group_superadmin
    config.auth_ldap_group_tenant_admin = payload.auth_ldap_group_tenant_admin
    config.auth_ldap_tenant_id = payload.auth_ldap_tenant_id
    config.auth_radius_host = payload.auth_radius_host
    config.auth_radius_port = payload.auth_radius_port
    if payload.auth_radius_secret:
        config.auth_radius_secret_enc = encrypt_str(payload.auth_radius_secret)
    config.auth_radius_role_attr = payload.auth_radius_role_attr
    config.auth_radius_superadmin_val = payload.auth_radius_superadmin_val
    config.auth_tacacs_host = payload.auth_tacacs_host
    config.auth_tacacs_port = payload.auth_tacacs_port
    if payload.auth_tacacs_secret:
        config.auth_tacacs_secret_enc = encrypt_str(payload.auth_tacacs_secret)
    config.auth_tacacs_superadmin_priv = payload.auth_tacacs_superadmin_priv
    config.auth_default_role = payload.auth_default_role
    store.save_auth_config(config)
    return {"status": "ok"}


@router.post("/superadmin/auth-test")
async def test_auth_config_endpoint(payload: dict, _: User = Depends(auth.require_superadmin)):
    from ..auth_providers import test_auth_provider

    config = store.load_auth_config()
    return await test_auth_provider(
        payload.get("provider", config.auth_provider),
        config,
        payload.get("username", ""),
        payload.get("password", ""),
    )


@router.get("/superadmin/pending-spokes")
def list_pending_spokes(_: User = Depends(auth.require_superadmin)):
    return store.list_pending_spokes()


@router.post("/superadmin/pending-spokes/{spoke_id}/approve")
async def approve_pending_spoke(
    spoke_id: str,
    payload: ApprovePendingSpokeRequest,
    request: Request,
    _: User = Depends(auth.require_superadmin),
):
    pending = store.get_pending_spoke(spoke_id)
    if not pending:
        raise HTTPException(status_code=404, detail="Pending spoke not found")

    tenant = store.get_tenant(payload.tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    _ensure_tenant_spoke_name_available(
        payload.tenant_id,
        pending.spoke_name,
        spoke_id=pending.id,
        hostname=pending.hostname,
    )

    spoke = Spoke(
        id=pending.id,
        tenant_id=payload.tenant_id,
        hostname=pending.hostname,
        label=payload.label if payload.label is not None else pending.label,
        spoke_name=pending.spoke_name,
        seed_config=pending.seed_config,
        config=pending.seed_config.copy(),
        processing_mode=tenant.default_processing_mode.model_copy(deep=True),
        status="approved",
        last_seen=pending.last_seen,
    )
    plain_key = generate_api_key()
    spoke.api_key_enc = encrypt_str(plain_key)
    store.save_spoke(spoke)
    store.delete_pending_spoke(spoke_id)

    relay_server_url = str(request.base_url).rstrip("/")
    cmd_payload, _ = _build_approval_config_payload(
        tenant, pending.seed_config, plain_key, spoke.id, payload.tenant_id, relay_server_url
    )
    store.enqueue_command(
        Command(
            spoke_id=spoke.id,
            tenant_id=payload.tenant_id,
            type="config_update",
            payload=cmd_payload,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    )
    await ws_broadcast({
        "type": "spoke_approved",
        "tenant_id": payload.tenant_id,
        "spoke_id": spoke.id,
        "hostname": spoke.hostname,
        "spoke_name": spoke.spoke_name,
    })

    return {
        "spoke_id": spoke.id,
        "api_key": plain_key,
        "message": "Spoke approved. API key shown once.",
    }


@router.delete("/superadmin/pending-spokes/{spoke_id}")
def delete_pending_spoke(spoke_id: str, _: User = Depends(auth.require_superadmin)):
    pending = store.get_pending_spoke(spoke_id)
    if not pending:
        raise HTTPException(status_code=404, detail="Pending spoke not found")
    store.delete_pending_spoke(spoke_id)
    return {"status": "deleted"}


# ── Tenant-admin pending spoke endpoints ─────────────────────────────────────
# Tenant admins can list and approve spokes that pre-registered with their
# tenant_id_hint.  Superadmins also have access via these endpoints.

@router.get("/tenant/{tenant_id}/pending-spokes")
def list_tenant_pending_spokes(
    tenant_id: str,
    current_user: User = Depends(auth.require_tenant_access),
):
    """Return pending spokes that pre-registered for this tenant."""
    all_pending = store.list_pending_spokes()
    return [p for p in all_pending if p.tenant_hint == tenant_id]


@router.post("/tenant/{tenant_id}/pending-spokes/{spoke_id}/approve", status_code=201)
async def tenant_approve_pending_spoke(
    tenant_id: str,
    spoke_id: str,
    request: Request,
    current_user: User = Depends(auth.require_tenant_access),
    label: Optional[str] = None,
):
    """Tenant admin approves a spoke pre-registered for their tenant."""
    pending = store.get_pending_spoke(spoke_id)
    if not pending:
        raise HTTPException(status_code=404, detail="Pending spoke not found")
    if pending.tenant_hint != tenant_id:
        raise HTTPException(status_code=403, detail="This spoke was not pre-registered for your tenant")

    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    _ensure_tenant_spoke_name_available(
        tenant_id,
        pending.spoke_name,
        spoke_id=pending.id,
        hostname=pending.hostname,
    )

    label = label if label is not None else pending.label
    spoke = Spoke(
        id=pending.id,
        tenant_id=tenant_id,
        hostname=pending.hostname,
        label=label,
        spoke_name=pending.spoke_name,
        seed_config=pending.seed_config,
        config=pending.seed_config.copy(),
        processing_mode=tenant.default_processing_mode.model_copy(deep=True),
        status="approved",
        last_seen=pending.last_seen,
    )
    plain_key = generate_api_key()
    spoke.api_key_enc = encrypt_str(plain_key)
    store.save_spoke(spoke)
    store.delete_pending_spoke(spoke_id)

    relay_server_url = str(request.base_url).rstrip("/")
    cmd_payload, _ = _build_approval_config_payload(
        tenant, pending.seed_config, plain_key, spoke.id, tenant_id, relay_server_url
    )
    store.enqueue_command(
        Command(
            spoke_id=spoke.id,
            tenant_id=tenant_id,
            type="config_update",
            payload=cmd_payload,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    )
    await ws_broadcast({
        "type": "spoke_approved",
        "tenant_id": tenant_id,
        "spoke_id": spoke.id,
        "hostname": spoke.hostname,
        "spoke_name": spoke.spoke_name,
    })

    return {
        "spoke_id": spoke.id,
        "api_key": plain_key,
        "message": "Spoke approved and assigned to your tenant.",
    }


@router.delete("/tenant/{tenant_id}/pending-spokes/{spoke_id}")
def tenant_reject_pending_spoke(
    tenant_id: str,
    spoke_id: str,
    current_user: User = Depends(auth.require_tenant_access),
):
    """Tenant admin rejects/removes a spoke pre-registered for their tenant."""
    pending = store.get_pending_spoke(spoke_id)
    if not pending:
        raise HTTPException(status_code=404, detail="Pending spoke not found")
    if pending.tenant_hint != tenant_id:
        raise HTTPException(status_code=403, detail="This spoke was not pre-registered for your tenant")
    store.delete_pending_spoke(spoke_id)
    return {"status": "rejected"}


@router.get("/superadmin/users")
def list_users(_: User = Depends(auth.require_superadmin)):
    return [_user_response(user) for user in store.list_users()]


@router.post("/superadmin/users", status_code=status.HTTP_201_CREATED)
def create_user(payload: CreateUserRequest, _: User = Depends(auth.require_superadmin)):
    if store.get_user(payload.username):
        raise HTTPException(status_code=409, detail="Username already exists")

    user = User(
        username=payload.username,
        hashed_password=auth.hash_password(payload.password),
        is_superadmin=False,
        tenant_roles=[],
    )
    store.save_user(user)
    return _user_response(user)


@router.delete("/superadmin/users/{user_id}")
def delete_user(user_id: str, _: User = Depends(auth.require_superadmin)):
    user = store.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    store.delete_user(user_id)
    return {"status": "deleted"}


@router.post("/superadmin/users/{user_id}/roles")
def assign_tenant_role(
    user_id: str,
    payload: AssignRoleRequest,
    _: User = Depends(auth.require_superadmin),
):
    user = store.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not store.get_tenant(payload.tenant_id):
        raise HTTPException(status_code=404, detail="Tenant not found")

    normalized_role = "viewer" if payload.role == "operator" else payload.role
    user.tenant_roles = [tr for tr in user.tenant_roles if tr["tenant_id"] != payload.tenant_id]
    user.tenant_roles.append({"tenant_id": payload.tenant_id, "role": normalized_role})
    store.save_user(user)
    return _user_response(user)


@router.delete("/superadmin/users/{user_id}/roles/{tenant_id}")
def remove_tenant_role(user_id: str, tenant_id: str, _: User = Depends(auth.require_superadmin)):
    user = store.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    updated_roles = [tr for tr in user.tenant_roles if tr["tenant_id"] != tenant_id]
    if len(updated_roles) == len(user.tenant_roles):
        raise HTTPException(status_code=404, detail="Tenant role not found")
    user.tenant_roles = updated_roles
    store.save_user(user)
    return _user_response(user)
