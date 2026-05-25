"""Tenant-scoped spoke management endpoints."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import auth, store
from ..data_models import Spoke, User

router = APIRouter()


class ConfigUpdateRequest(BaseModel):
    config: dict[str, Any] = Field(default_factory=dict)


class LabelUpdateRequest(BaseModel):
    label: str


class AssignedSiteUpdateRequest(BaseModel):
    assigned_site: str = ""


def _serialize_spoke(spoke: Spoke, include_config: bool = True) -> dict[str, Any]:
    data = {
        "id": spoke.id,
        "tenant_id": spoke.tenant_id,
        "hostname": spoke.hostname,
        "label": spoke.label,
        "spoke_name": spoke.spoke_name,
        "assigned_site": spoke.assigned_site,
        "status": spoke.status,
        "seed_config": spoke.seed_config,
        "processing_mode": spoke.processing_mode,
        "config_version": spoke.config_version,
        "applied_config_version": spoke.applied_config_version,
        "last_config_applied_at": spoke.last_config_applied_at,
        "last_seen": spoke.last_seen,
        "telemetry": spoke.telemetry,
        "created_at": spoke.created_at,
    }
    if include_config:
        data["config"] = spoke.config
    return data


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


@router.get("/sites")
def list_sites_legacy():
    results = []
    for tenant in store.list_tenants():
        for spoke in store.list_spokes(tenant.id):
            if spoke.status != "approved":
                continue
            results.append(
                {
                    "id": spoke.id,
                    "hostname": spoke.hostname,
                    "label": spoke.label,
                    "spoke_name": spoke.spoke_name,
                    "status": spoke.status,
                    "last_seen": spoke.last_seen,
                    "telemetry": spoke.telemetry,
                    "workspace_id": spoke.tenant_id,
                }
            )
    return results


@router.get("/{tenant_id}/spokes")
def list_tenant_spokes(tenant_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    return [_serialize_spoke(spoke) for spoke in store.list_spokes(tenant_id)]


@router.get("/{tenant_id}/spokes/{spoke_id}")
def get_spoke_detail(tenant_id: str, spoke_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    return _serialize_spoke(_get_spoke(tenant_id, spoke_id))


@router.post("/{tenant_id}/spokes/{spoke_id}/revoke")
def revoke_spoke(tenant_id: str, spoke_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_tenant_admin(tenant_id, current_user)
    _get_spoke(tenant_id, spoke_id)
    store.revoke_spoke(tenant_id, spoke_id)
    return {"status": "revoked"}


@router.delete("/{tenant_id}/spokes/{spoke_id}")
def delete_spoke(tenant_id: str, spoke_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_tenant_admin(tenant_id, current_user)
    _get_spoke(tenant_id, spoke_id)
    store.delete_spoke(tenant_id, spoke_id)
    return {"status": "deleted"}


@router.patch("/{tenant_id}/spokes/{spoke_id}/config")
def update_spoke_config(
    tenant_id: str,
    spoke_id: str,
    payload: ConfigUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    spoke = _get_spoke(tenant_id, spoke_id)
    if spoke.status != "approved":
        raise HTTPException(status_code=409, detail="Spoke is not approved")

    spoke.config = payload.config
    spoke.config_version += 1
    store.save_spoke(spoke)
    return _serialize_spoke(spoke)


@router.patch("/{tenant_id}/spokes/{spoke_id}/label")
def update_spoke_label(
    tenant_id: str,
    spoke_id: str,
    payload: LabelUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    spoke = _get_spoke(tenant_id, spoke_id)
    spoke.label = payload.label
    store.save_spoke(spoke)
    return _serialize_spoke(spoke)


@router.patch("/tenant/{tenant_id}/spokes/{spoke_id}/assigned-site")
def update_spoke_assigned_site(
    tenant_id: str,
    spoke_id: str,
    payload: AssignedSiteUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    spoke = _get_spoke(tenant_id, spoke_id)
    spoke.assigned_site = (payload.assigned_site or "").strip()
    store.save_spoke(spoke)
    return _serialize_spoke(spoke)
