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
from ..crypto import encrypt_dict, encrypt_str, generate_api_key
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


@router.get("/tenant/{tenant_id}/hub-config")
def get_tenant_hub_config(
    tenant_id: str,
    current_user: User = Depends(auth.require_tenant_access),
):
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"hub_config_enabled": tenant.hub_config_enabled, "hub_config": tenant.hub_config}


@router.put("/tenant/{tenant_id}/hub-config")
async def update_tenant_hub_config(
    tenant_id: str,
    payload: HubConfigRequest,
    request: Request,
    current_user: User = Depends(auth.require_tenant_access),
):
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    tenant.hub_config_enabled = payload.hub_config_enabled
    if payload.hub_config:
        tenant.hub_config = payload.hub_config
    store.save_tenant(tenant)

    pushed_count = 0
    if tenant.hub_config_enabled and tenant.hub_config:
        relay_server_url = str(request.base_url).rstrip("/")
        for spoke in store.list_spokes(tenant_id):
            if spoke.status != "approved":
                continue
            updated_config = dict(spoke.config or {})
            updated_config.update(tenant.hub_config)
            if updated_config != spoke.config:
                spoke.config = updated_config
                spoke.config_version += 1
                store.save_spoke(spoke)
            store.enqueue_command(
                Command(
                    spoke_id=spoke.id,
                    tenant_id=tenant_id,
                    type="config_update",
                    payload={
                        **tenant.hub_config,
                        "__config_version": spoke.config_version,
                        "relay_server_url": relay_server_url,
                    },
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                )
            )
            pushed_count += 1

    return {"status": "saved", "hub_config_enabled": tenant.hub_config_enabled, "pushed_to_spokes": pushed_count}


@router.get("/superadmin/gkill-state")
def get_gkill_state(_: User = Depends(auth.require_superadmin)):
    from .. import tasks

    return tasks.gkill_state


@router.get("/superadmin/auth-providers")
def get_auth_provider_status(_: User = Depends(auth.require_superadmin)):
    settings = get_settings()
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
                "enabled": settings.ldap_enabled,
                "implemented": False,
                "description": "LDAP / Active Directory",
            },
            {
                "name": "radius",
                "enabled": settings.radius_enabled,
                "implemented": False,
                "description": "RADIUS",
            },
        ]
    }


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
