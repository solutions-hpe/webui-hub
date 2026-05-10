from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import auth, store
from ..data_models import AuditEntry, Command, User

router = APIRouter()


class CreateCommandRequest(BaseModel):
    tenant_id: str
    island_id: str
    type: str
    target: str = "spoke"
    payload: dict[str, Any] = Field(default_factory=dict)


def _serialize_command(command: Command) -> dict[str, Any]:
    return command.model_dump(mode="json", by_alias=True)


def _get_approved_spoke(tenant_id: str, island_id: str):
    island = store.get_spoke(tenant_id, island_id)
    if not island:
        raise HTTPException(status_code=404, detail="Island not found")
    if island.status != "approved":
        raise HTTPException(status_code=409, detail="Island is not approved")
    return island


def _queue_command(
    tenant_id: str,
    island_id: str,
    command_type: str,
    payload: dict[str, Any],
    current_user: User,
    execution_mode: str = "centralized",
) -> Command:
    command = Command(
        spoke_id=island_id,
        tenant_id=tenant_id,
        type=command_type,
        payload=payload,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    store.enqueue_command(command)
    store.append_audit(
        AuditEntry(
            spoke_id=island_id,
            tenant_id=tenant_id,
            task_type=command_type,
            execution_mode=execution_mode,
            status="pending",
            detail=f"Queued command {command_type}",
            initiated_by=current_user.username,
            result={"payload": payload, "target": command.target},
        )
    )
    return command


@router.post("/commands")
def create_command(req: CreateCommandRequest, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(req.tenant_id, current_user)
    spoke = _get_approved_spoke(req.tenant_id, req.island_id)
    command = Command(
        spoke_id=req.island_id,
        tenant_id=req.tenant_id,
        type=req.type,
        target=req.target,
        payload=req.payload,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    store.enqueue_command(command)
    store.append_audit(
        AuditEntry(
            spoke_id=req.island_id,
            tenant_id=req.tenant_id,
            task_type=req.type,
            execution_mode=spoke.processing_mode.resolve(req.type) if hasattr(spoke.processing_mode, req.type) else "centralized",
            status="pending",
            detail=f"Queued command {req.type}",
            initiated_by=current_user.username,
            result={"payload": req.payload, "target": req.target},
        )
    )
    return {"id": command.id, "status": command.status}


@router.post("/{tenant_id}/islands/{island_id}/repo-sync")
def repo_sync_spoke(tenant_id: str, island_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    spoke = _get_approved_spoke(tenant_id, island_id)
    command = _queue_command(
        tenant_id,
        island_id,
        "repo_sync",
        {},
        current_user,
        execution_mode=spoke.processing_mode.resolve("repo_sync"),
    )
    return {"id": command.id, "status": command.status}


@router.get("/{tenant_id}/commands")
def list_commands(
    tenant_id: str,
    island_id: Optional[str] = None,
    current_user: User = Depends(auth.get_current_user),
):
    auth.require_tenant_access(tenant_id, current_user)
    if island_id and not store.get_spoke(tenant_id, island_id):
        raise HTTPException(status_code=404, detail="Island not found")
    return [_serialize_command(command) for command in store.list_commands(tenant_id, island_id)]


@router.get("/{tenant_id}/islands/{island_id}/audit")
def get_spoke_audit(tenant_id: str, island_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    if not store.get_spoke(tenant_id, island_id):
        raise HTTPException(status_code=404, detail="Island not found")
    return [entry.model_dump(mode="json", by_alias=True) for entry in store.get_audit(tenant_id, island_id)]
