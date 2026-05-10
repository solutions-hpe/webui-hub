"""Tenant-scoped island management endpoints."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import auth, store
from ..data_models import Command, Island, User

router = APIRouter()


class ConfigUpdateRequest(BaseModel):
    config: dict[str, Any] = Field(default_factory=dict)


class LabelUpdateRequest(BaseModel):
    label: str


def _serialize_spoke(spoke: Island, include_config: bool = True) -> dict[str, Any]:
    data = {
        "id": spoke.id,
        "tenant_id": spoke.tenant_id,
        "hostname": spoke.hostname,
        "label": spoke.label,
        "status": spoke.status,
        "seed_config": spoke.seed_config,
        "processing_mode": spoke.processing_mode,
        "last_seen": spoke.last_seen,
        "telemetry": spoke.telemetry,
        "created_at": spoke.created_at,
    }
    if include_config:
        data["config"] = spoke.config
    return data


def _get_spoke(tenant_id: str, spoke_id: str) -> Island:
    spoke = store.get_spoke(tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Island not found")
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
                    "status": spoke.status,
                    "last_seen": spoke.last_seen,
                    "telemetry": spoke.telemetry,
                    "workspace_id": spoke.tenant_id,
                }
            )
    return results


@router.get("/{tenant_id}/islands")
def list_tenant_spokes(tenant_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    return [_serialize_spoke(spoke) for spoke in store.list_spokes(tenant_id)]


@router.get("/{tenant_id}/islands/{island_id}")
def get_spoke_detail(tenant_id: str, island_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    return _serialize_spoke(_get_spoke(tenant_id, island_id))


@router.post("/{tenant_id}/islands/{island_id}/revoke")
def revoke_spoke(tenant_id: str, island_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_tenant_admin(tenant_id, current_user)
    _get_spoke(tenant_id, island_id)
    store.revoke_spoke(tenant_id, island_id)
    return {"status": "revoked"}


@router.delete("/{tenant_id}/islands/{island_id}")
def delete_spoke(tenant_id: str, island_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_tenant_admin(tenant_id, current_user)
    _get_spoke(tenant_id, island_id)
    store.delete_spoke(tenant_id, island_id)
    return {"status": "deleted"}


@router.patch("/{tenant_id}/islands/{island_id}/config")
def update_spoke_config(
    tenant_id: str,
    island_id: str,
    payload: ConfigUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    spoke = _get_spoke(tenant_id, island_id)
    if spoke.status != "approved":
        raise HTTPException(status_code=409, detail="Island is not approved")

    spoke.config = payload.config
    store.save_spoke(spoke)
    store.enqueue_command(
        Command(
            spoke_id=spoke.id,
            tenant_id=tenant_id,
            type="config_update",
            payload=payload.config,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    )
    return _serialize_spoke(spoke)


@router.patch("/{tenant_id}/islands/{island_id}/label")
def update_spoke_label(
    tenant_id: str,
    island_id: str,
    payload: LabelUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    spoke = _get_spoke(tenant_id, island_id)
    spoke.label = payload.label
    store.save_spoke(spoke)
    return _serialize_spoke(spoke)
