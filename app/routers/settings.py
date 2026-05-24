"""Tenant settings management endpoints."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal, Optional, Union

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import acme as acme_manager
from .. import auth, store
from ..config import get_settings
from ..crypto import decrypt_dict, encrypt_dict
from ..data_models import Spoke, ProcessingMode, Tenant, User

router = APIRouter()


ModeValue = Literal["centralized", "distributed"]
PROCESSING_FEATURES = ["aruba_polling", "teams_webhook", "email", "heartbeat", "gkill", "schedules", "repo_sync"]


class ArubaSettingsRequest(BaseModel):
    cluster_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    access_token: str = ""
    refresh_token: str = ""
    customer_id: str = ""
    workspace_id: str = ""
    api_version: str = "classic"


class NotificationSettingsRequest(BaseModel):
    teams_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    to_emails: Union[list[str], str] = Field(default_factory=list)
    from_email: str = "hub@localhost"
    enabled: bool = False


class GithubSettingsRequest(BaseModel):
    github_token: str = ""
    sim_repo_url: str = ""
    sim_repo_branch: str = "main"


class TenantSettingsPatchRequest(BaseModel):
    use_all_dongles: Optional[bool] = None


class ProcessingModeUpdateRequest(BaseModel):
    global_mode: ModeValue = "centralized"
    aruba_polling: Optional[ModeValue] = None
    teams_webhook: Optional[ModeValue] = None
    email: Optional[ModeValue] = None
    heartbeat: Optional[ModeValue] = None
    gkill: Optional[ModeValue] = None
    schedules: Optional[ModeValue] = None
    repo_sync: Optional[ModeValue] = None


class TenantProcessingModesRequest(BaseModel):
    central_api: Optional[ModeValue] = None
    teams: Optional[ModeValue] = None
    email: Optional[ModeValue] = None


def _get_tenant(tenant_id: str) -> Tenant:
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _get_spoke(tenant_id: str, spoke_id: str) -> Spoke:
    spoke = store.get_spoke(tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")
    return spoke


def _require_tenant_admin(tenant_id: str, user: User) -> User:
    auth.require_tenant_access(tenant_id, user)
    if user.is_superadmin:
        return user
    if user.get_role(tenant_id) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def _require_any_admin(user: User) -> User:
    if user.is_superadmin or any(role.get("role") == "admin" for role in user.tenant_roles):
        return user
    raise HTTPException(status_code=403, detail="Admin role required")


_SECRET_DNS_CREDENTIAL_KEYS = {
    "cf_api_token",
    "cf_api_key",
    "he_ddns_key",
    "godaddy_api_key",
    "godaddy_api_secret",
    "do_token",
    "porkbun_api_key",
    "porkbun_secret_key",
    "gcloud_service_account_json",
    "dnsimple_token",
    "azure_client_secret",
    "route53_secret_key",
    "namecheap_api_key",
}


def _masked_dns_credentials(credentials: dict[str, Any]) -> dict[str, str]:
    data: dict[str, str] = {}
    for key, value in (credentials or {}).items():
        text = "" if value is None else str(value)
        data[key] = "***" if key in _SECRET_DNS_CREDENTIAL_KEYS and text else text
    return data


def _configured_dns_credentials(credentials: dict[str, Any]) -> dict[str, str]:
    return {key: ("***" if value else "") for key, value in (credentials or {}).items()}


def _merge_dns_credentials(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing or {})
    for key, value in (incoming or {}).items():
        if value in (None, "", "***"):
            continue
        merged[key] = value
    return merged


def _serialize_processing_summary(tenant: Tenant) -> dict[str, Any]:
    islands = []
    for spoke in store.list_spokes(tenant.id):
        feature_overrides = {feature: getattr(spoke.processing_mode, feature) for feature in PROCESSING_FEATURES}
        effective_modes = {feature: spoke.processing_mode.resolve(feature) for feature in PROCESSING_FEATURES}
        islands.append(
            {
                "spoke_id": spoke.id,
                "hostname": spoke.hostname,
                "global_mode": spoke.processing_mode.global_mode,
                "feature_overrides": feature_overrides,
                "effective_modes": effective_modes,
            }
        )
    return {
        "tenant_id": tenant.id,
        "default_mode": tenant.default_processing_mode.global_mode,
        "islands": islands,
    }


def _normalize_notification_config(payload: NotificationSettingsRequest) -> dict[str, Any]:
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


def _serialize_aruba_config(tenant: Tenant) -> dict[str, Any]:
    if not tenant.aruba_config_enc:
        return {"configured": False}
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception:
        return {"configured": True, "error": "unreadable"}
    return {
        "configured": True,
        "cluster_url": cfg.get("cluster_url", ""),
        "client_id": cfg.get("client_id", ""),
        "customer_id": cfg.get("customer_id", ""),
        "workspace_id": cfg.get("workspace_id", ""),
        "api_version": cfg.get("api_version", "classic"),
        "client_secret_configured": bool(cfg.get("client_secret")),
        "access_token_configured": bool(cfg.get("access_token")),
        "refresh_token_configured": bool(cfg.get("refresh_token")),
    }


def _serialize_notification_config(tenant: Tenant) -> dict[str, Any]:
    if not tenant.notification_config_enc:
        return {"configured": False}
    try:
        cfg = decrypt_dict(tenant.notification_config_enc)
    except Exception:
        return {"configured": True, "error": "unreadable"}
    teams_webhook = cfg.get("teams_webhook") or cfg.get("teams_webhook_url") or ""
    to_emails = cfg.get("to_emails") or []
    if isinstance(to_emails, str):
        to_emails = [item.strip() for item in to_emails.split(",") if item.strip()]
    return {
        "configured": True,
        "enabled": bool(cfg.get("enabled")),
        "teams_webhook_configured": bool(teams_webhook),
        "smtp_host": cfg.get("smtp_host", ""),
        "smtp_port": cfg.get("smtp_port", 587),
        "smtp_user": cfg.get("smtp_user", ""),
        "smtp_pass_configured": bool(cfg.get("smtp_pass") or cfg.get("smtp_password")),
        "to_emails": to_emails,
        "from_email": cfg.get("from_email", "hub@localhost"),
    }


def _serialize_github_config(tenant: Tenant) -> dict[str, Any]:
    if not tenant.github_config_enc:
        return {
            "configured": False,
            "sim_repo_url": "",
            "sim_repo_branch": "main",
            "github_token_configured": False,
        }
    try:
        cfg = decrypt_dict(tenant.github_config_enc)
    except Exception:
        return {
            "configured": True,
            "error": "unreadable",
            "sim_repo_url": "",
            "sim_repo_branch": "main",
            "github_token_configured": False,
        }
    return {
        "configured": True,
        "sim_repo_url": cfg.get("sim_repo_url", ""),
        "sim_repo_branch": cfg.get("sim_repo_branch", "main") or "main",
        "github_token_configured": bool(cfg.get("github_token")),
    }


def _processing_mode_from_payload(payload: ProcessingModeUpdateRequest) -> ProcessingMode:
    return ProcessingMode(**payload.model_dump())


async def _save_config_updates_to_approved_spokes(tenant_id: str, spokes: list[Spoke]) -> None:
    # save_spoke() is synchronous and rewrites spoke state on disk, so persist all
    # version bumps before enqueuing config_update commands that read them back.
    await asyncio.gather(*[asyncio.to_thread(store.save_spoke, spoke) for spoke in spokes])
    for spoke in spokes:
        store.ensure_config_update_command(tenant_id, spoke.id)


def _push_config_updates_to_approved_spokes(tenant_id: str) -> int:
    spokes = []
    for spoke in store.list_spokes(tenant_id):
        if spoke.status != "approved":
            continue
        spoke.config_version += 1
        spokes.append(spoke)

    if not spokes:
        return 0

    asyncio.run(_save_config_updates_to_approved_spokes(tenant_id, spokes))
    return len(spokes)


@router.get("/acme/status")
def get_acme_status(current_user: User = Depends(auth.get_current_user)):
    _require_any_admin(current_user)
    return acme_manager.get_acme_status()


@router.get("/{tenant_id}/settings")
def get_tenant_settings(tenant_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(tenant_id)
    return {
        "tenant": {
            "id": tenant.id,
            "name": tenant.name,
            "aruba_cid": tenant.aruba_cid,
            "created_at": tenant.created_at,
            "created_by": tenant.created_by,
        },
        "aruba": _serialize_aruba_config(tenant),
        "notifications": _serialize_notification_config(tenant),
        "github": _serialize_github_config(tenant),
        "use_all_dongles": bool((tenant.hub_config or {}).get("use_all_dongles", False)),
        "processing_mode": tenant.default_processing_mode.model_dump(),
        "processing_modes": tenant.processing_modes,
    }


@router.patch("/{tenant_id}/settings")
def patch_tenant_settings(
    tenant_id: str,
    payload: TenantSettingsPatchRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(tenant_id)
    next_hub_config = dict(tenant.hub_config or {})
    changed = False

    if payload.use_all_dongles is not None:
        next_hub_config["use_all_dongles"] = bool(payload.use_all_dongles)
        changed = changed or next_hub_config != (tenant.hub_config or {})

    if changed:
        tenant.hub_config = next_hub_config
        store.save_tenant(tenant)

    pushed_count = 0
    if changed:
        pushed_count = _push_config_updates_to_approved_spokes(tenant_id)

    return {
        "use_all_dongles": bool((tenant.hub_config or {}).get("use_all_dongles", False)),
        "pushed_to_spokes": pushed_count,
    }


@router.post("/{tenant_id}/settings/aruba")
def update_aruba_settings(
    tenant_id: str,
    payload: ArubaSettingsRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(tenant_id)
    cfg = payload.model_dump()
    tenant.aruba_config_enc = encrypt_dict(cfg)
    tenant.aruba_cid = payload.customer_id or tenant.aruba_cid
    store.save_tenant(tenant)
    _push_config_updates_to_approved_spokes(tenant_id)
    return _serialize_aruba_config(tenant)


@router.post("/{tenant_id}/settings/notifications")
def update_notification_settings(
    tenant_id: str,
    payload: NotificationSettingsRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(tenant_id)
    tenant.notification_config_enc = encrypt_dict(_normalize_notification_config(payload))
    store.save_tenant(tenant)
    _push_config_updates_to_approved_spokes(tenant_id)
    return _serialize_notification_config(tenant)


@router.post("/{tenant_id}/settings/github")
def update_github_settings(
    tenant_id: str,
    payload: GithubSettingsRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(tenant_id)
    existing: dict[str, Any] = {}
    if tenant.github_config_enc:
        try:
            existing = decrypt_dict(tenant.github_config_enc)
        except Exception:
            existing = {}

    cfg = {
        "sim_repo_url": str(payload.sim_repo_url or existing.get("sim_repo_url") or "").strip(),
        "sim_repo_branch": str(payload.sim_repo_branch or existing.get("sim_repo_branch") or "main").strip() or "main",
    }
    github_token = str(payload.github_token or "")
    if github_token:
        cfg["github_token"] = github_token
    elif existing.get("github_token"):
        cfg["github_token"] = existing["github_token"]

    tenant.github_config_enc = encrypt_dict(cfg) if any(str(value).strip() for value in cfg.values()) else None
    store.save_tenant(tenant)
    return _serialize_github_config(tenant)


@router.get("/{tenant_id}/settings/processing-mode")
def get_default_processing_mode(tenant_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(tenant_id)
    return tenant.default_processing_mode.model_dump()


@router.post("/{tenant_id}/settings/processing-mode")
def update_default_processing_mode(
    tenant_id: str,
    payload: ProcessingModeUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(tenant_id)
    tenant.default_processing_mode = _processing_mode_from_payload(payload)
    store.save_tenant(tenant)
    return tenant.default_processing_mode.model_dump()


@router.patch("/hub/tenants/{tenant_id}/processing-modes")
def update_tenant_processing_modes(
    tenant_id: str,
    payload: TenantProcessingModesRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(tenant_id)
    updated = dict(tenant.processing_modes or {})
    for key, value in payload.model_dump(exclude_none=True).items():
        updated[key] = value
    tenant.processing_modes = updated
    store.save_tenant(tenant)

    pushed_count = _push_config_updates_to_approved_spokes(tenant_id)

    return {"processing_modes": tenant.processing_modes, "pushed_to_spokes": pushed_count}


@router.patch("/{tenant_id}/spokes/{spoke_id}/processing-mode")
def update_spoke_processing_mode(
    tenant_id: str,
    spoke_id: str,
    payload: ProcessingModeUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    spoke = _get_spoke(tenant_id, spoke_id)
    spoke.processing_mode = _processing_mode_from_payload(payload)
    store.save_spoke(spoke)
    return spoke.processing_mode.model_dump()


@router.get("/{tenant_id}/processing-summary")
def get_processing_summary(tenant_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    tenant = _get_tenant(tenant_id)
    return _serialize_processing_summary(tenant)


@router.get("/settings/acme")
def get_acme_settings(current_user: User = Depends(auth.get_current_user)):
    _require_any_admin(current_user)
    cfg = acme_manager.load_acme_config()
    data = asdict(cfg)
    data["dns_credentials"] = _masked_dns_credentials(cfg.dns_credentials)
    data["dns_credentials_configured"] = _configured_dns_credentials(cfg.dns_credentials)
    data["cert_info"] = acme_manager.get_cert_info()
    return data


@router.post("/settings/acme")
def save_acme_settings(payload: dict[str, Any], current_user: User = Depends(auth.get_current_user)):
    _require_any_admin(current_user)
    existing = acme_manager.load_acme_config()
    cfg = acme_manager.AcmeConfig(
        enabled=bool(payload.get("enabled", existing.enabled)),
        domain=str(payload.get("domain", existing.domain) or "").strip(),
        email=str(payload.get("email", existing.email) or "").strip(),
        challenge=str(payload.get("challenge", existing.challenge) or existing.challenge),
        ca=str(payload.get("ca", existing.ca) or existing.ca),
        dns_provider=str(payload.get("dns_provider", existing.dns_provider) or "").strip(),
        dns_credentials=_merge_dns_credentials(existing.dns_credentials, payload.get("dns_credentials") or {}),
        last_renewed=existing.last_renewed,
        last_error=existing.last_error,
        cert_expiry=existing.cert_expiry,
        last_log=existing.last_log,
        last_log_at=existing.last_log_at,
    )
    acme_manager.save_acme_config(cfg)
    data = asdict(cfg)
    data["dns_credentials"] = _masked_dns_credentials(cfg.dns_credentials)
    data["dns_credentials_configured"] = _configured_dns_credentials(cfg.dns_credentials)
    data["cert_info"] = acme_manager.get_cert_info()
    return data


@router.post("/settings/acme/request")
async def request_acme_certificate(current_user: User = Depends(auth.get_current_user)):
    _require_any_admin(current_user)
    cfg = acme_manager.load_acme_config()
    return await acme_manager.request_certificate(cfg, Path(get_settings().data_dir))
