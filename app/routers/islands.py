"""Island relay endpoints — used by spoke servers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from .. import store
from ..crypto import decrypt_str
from ..data_models import AuditEntry, PendingIsland
from ..ws import ws_broadcast

router = APIRouter()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _auth_island(tenant_id: str, island_id: str, api_key: str):
    island = store.get_island(tenant_id, island_id)
    if not island or island.status != "approved" or not island.api_key_enc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    try:
        if decrypt_str(island.api_key_enc) != api_key:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise exc
        raise HTTPException(status_code=401, detail="Invalid credentials") from exc
    return island


class RegisterPayload(BaseModel):
    hostname: str
    label: str = ""
    config: dict[str, Any] = Field(default_factory=dict)


@router.post("/islands/register", status_code=201)
def register_island(payload: RegisterPayload):
    approved = store.get_approved_island_by_hostname(payload.hostname)
    if approved:
        tenant_id, island = approved
        return {
            "island_id": island.id,
            "status": "approved",
            "tenant_id": tenant_id,
            "api_key": decrypt_str(island.api_key_enc) if island.api_key_enc else "",
        }

    existing = store.get_pending_by_hostname(payload.hostname)
    if existing:
        return {
            "island_id": existing.id,
            "status": "pending",
            "message": "Registration already pending approval.",
        }

    pending = PendingIsland(
        hostname=payload.hostname,
        label=payload.label,
        seed_config=payload.config,
    )
    store.save_pending_island(pending)
    return {
        "island_id": pending.id,
        "status": "pending",
        "message": "Registration received. Awaiting superadmin approval and tenant assignment.",
    }


@router.post("/{tenant_id}/islands/{island_id}/telemetry")
async def post_telemetry(
    tenant_id: str,
    island_id: str,
    payload: dict[str, Any],
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    _auth_island(tenant_id, island_id, x_api_key)
    store.update_island_telemetry(tenant_id, island_id, payload)
    await ws_broadcast({"type": "telemetry", "tenant_id": tenant_id, "island_id": island_id})
    return {"status": "ok"}


@router.get("/{tenant_id}/islands/{island_id}/inbox")
def get_inbox(
    tenant_id: str,
    island_id: str,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    _auth_island(tenant_id, island_id, x_api_key)
    commands = store.get_queued_commands(tenant_id, island_id)
    return [{"id": c.id, "target": c.target, "type": c.type, "payload": c.payload} for c in commands]


class AckResultPayload(BaseModel):
    success: Optional[bool] = None
    task_type: Optional[str] = None
    detail: str = ""
    output: Any = None
    timestamp: Optional[str] = None


class AckPayload(BaseModel):
    command_id: str
    status: str = "executed"
    result: Optional[AckResultPayload] = None


@router.post("/{tenant_id}/islands/{island_id}/ack")
async def ack_command_endpoint(
    tenant_id: str,
    island_id: str,
    payload: AckPayload,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    _auth_island(tenant_id, island_id, x_api_key)
    result = payload.result.model_dump(exclude_none=True) if payload.result else None
    store.ack_command(tenant_id, island_id, payload.command_id, result)
    if result and result.get("task_type"):
        task_status = "success" if result.get("success") else "failure"
        store.append_audit(
            AuditEntry(
                island_id=island_id,
                tenant_id=tenant_id,
                task_type=result.get("task_type", "command_ack"),
                execution_mode="distributed",
                status=task_status,
                detail=result.get("detail", ""),
                initiated_by="island",
                result=result,
            )
        )
        await ws_broadcast(
            {
                "type": "task_result",
                "tenant_id": tenant_id,
                "island_id": island_id,
                "task_type": result.get("task_type", "command_ack"),
                "status": task_status,
            }
        )
    return {"status": "ok"}
