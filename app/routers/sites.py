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


def _serialize_island(island: Island, include_config: bool = True) -> dict[str, Any]:
    data = {
        "id": island.id,
        "tenant_id": island.tenant_id,
        "hostname": island.hostname,
        "label": island.label,
        "status": island.status,
        "seed_config": island.seed_config,
        "processing_mode": island.processing_mode,
        "last_seen": island.last_seen,
        "telemetry": island.telemetry,
        "created_at": island.created_at,
    }
    if include_config:
        data["config"] = island.config
    return data


def _get_island(tenant_id: str, island_id: str) -> Island:
    island = store.get_island(tenant_id, island_id)
    if not island:
        raise HTTPException(status_code=404, detail="Island not found")
    return island


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
        for island in store.list_islands(tenant.id):
            if island.status != "approved":
                continue
            results.append(
                {
                    "id": island.id,
                    "hostname": island.hostname,
                    "label": island.label,
                    "status": island.status,
                    "last_seen": island.last_seen,
                    "telemetry": island.telemetry,
                    "workspace_id": island.tenant_id,
                }
            )
    return results


@router.get("/{tenant_id}/islands")
def list_tenant_islands(tenant_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    return [_serialize_island(island) for island in store.list_islands(tenant_id)]


@router.get("/{tenant_id}/islands/{island_id}")
def get_island_detail(tenant_id: str, island_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    return _serialize_island(_get_island(tenant_id, island_id))


@router.post("/{tenant_id}/islands/{island_id}/revoke")
def revoke_island(tenant_id: str, island_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_tenant_admin(tenant_id, current_user)
    _get_island(tenant_id, island_id)
    store.revoke_island(tenant_id, island_id)
    return {"status": "revoked"}


@router.delete("/{tenant_id}/islands/{island_id}")
def delete_island(tenant_id: str, island_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_tenant_admin(tenant_id, current_user)
    _get_island(tenant_id, island_id)
    store.delete_island(tenant_id, island_id)
    return {"status": "deleted"}


@router.patch("/{tenant_id}/islands/{island_id}/config")
def update_island_config(
    tenant_id: str,
    island_id: str,
    payload: ConfigUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    island = _get_island(tenant_id, island_id)
    if island.status != "approved":
        raise HTTPException(status_code=409, detail="Island is not approved")

    island.config = payload.config
    store.save_island(island)
    store.enqueue_command(
        Command(
            island_id=island.id,
            tenant_id=tenant_id,
            type="config_update",
            payload=payload.config,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    )
    return _serialize_island(island)


@router.patch("/{tenant_id}/islands/{island_id}/label")
def update_island_label(
    tenant_id: str,
    island_id: str,
    payload: LabelUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_tenant_admin(tenant_id, current_user)
    island = _get_island(tenant_id, island_id)
    island.label = payload.label
    store.save_island(island)
    return _serialize_island(island)
