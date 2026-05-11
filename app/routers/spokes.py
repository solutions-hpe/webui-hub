"""Spoke relay endpoints — used by spoke servers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .. import auth, store
from ..crypto import decrypt_str, encrypt_str, generate_api_key
from ..data_models import AuditEntry, PendingSpoke
from ..ws import ws_broadcast

router = APIRouter()

# In-memory registration log — last 100 attempts (survives until container restart)
_REG_LOG_MAX = 100
_registration_log: list[dict[str, Any]] = []


def _reg_log_append(event: str, **kwargs: Any) -> None:
    entry = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
             "event": event, **kwargs}
    _registration_log.append(entry)
    if len(_registration_log) > _REG_LOG_MAX:
        del _registration_log[:-_REG_LOG_MAX]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_valid_uuid(value: str) -> bool:
    candidate = (value or "").strip().lower()
    if not candidate:
        return False
    try:
        import uuid
        return str(uuid.UUID(candidate)) == candidate
    except (TypeError, ValueError, AttributeError):
        return False


def _auth_spoke(tenant_id: str, spoke_id: str, api_key: str):
    spoke = store.get_spoke(tenant_id, spoke_id)
    if not spoke or spoke.status != "approved" or not spoke.api_key_enc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    try:
        if decrypt_str(spoke.api_key_enc) != api_key:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise exc
        raise HTTPException(status_code=401, detail="Invalid credentials") from exc
    return spoke


class RegisterPayload(BaseModel):
    spoke_id: str = ""
    hostname: str
    label: str = ""
    spoke_name: str = ""
    tenant_id_hint: str = ""  # Optional: tenant ID pre-entered on spoke
    config: dict[str, Any] = Field(default_factory=dict)


@router.post("/spokes/register", status_code=201)
def register_spoke(payload: RegisterPayload, request: Request):
    spoke_name = payload.spoke_name.strip() or payload.hostname
    tenant_hint = payload.tenant_id_hint.strip()
    requested_spoke_id = payload.spoke_id.strip().lower()
    client_ip = request.client.host if request.client else "unknown"
    if requested_spoke_id and not _is_valid_uuid(requested_spoke_id):
        _reg_log_append("invalid_spoke_id", hostname=payload.hostname, spoke_name=spoke_name,
                        spoke_id=requested_spoke_id, ip=client_ip)
        requested_spoke_id = ""

    # Validate tenant hint if provided
    if tenant_hint and not store.get_tenant(tenant_hint):
        _reg_log_append("invalid_tenant_hint", hostname=payload.hostname,
                        spoke_name=spoke_name, tenant_hint=tenant_hint, ip=client_ip)
        tenant_hint = ""  # Silently ignore invalid tenant IDs

    approved = store.get_approved_spoke_by_id(requested_spoke_id) if requested_spoke_id else None
    if not approved:
        approved = store.get_approved_spoke_by_hostname(payload.hostname)
    if approved:
        tenant_id, spoke = approved
        if requested_spoke_id and spoke.id != requested_spoke_id:
            store.rekey_spoke(tenant_id, spoke.id, requested_spoke_id)
            spoke.id = requested_spoke_id
        changed = False
        if spoke.hostname != payload.hostname:
            spoke.hostname = payload.hostname
            changed = True
        if payload.label and spoke.label != payload.label:
            spoke.label = payload.label
            changed = True
        if spoke.spoke_name != spoke_name:
            spoke.spoke_name = spoke_name
            changed = True
        regenerated_api_key = False
        api_key = ""
        if spoke.api_key_enc:
            try:
                api_key = decrypt_str(spoke.api_key_enc)
            except Exception:
                api_key = ""
        if not api_key:
            api_key = generate_api_key()
            spoke.api_key_enc = encrypt_str(api_key)
            changed = True
            regenerated_api_key = True
        if changed:
            store.save_spoke(spoke)
        _reg_log_append("already_approved", hostname=payload.hostname,
                        spoke_name=spoke_name, spoke_id=spoke.id, tenant_id=tenant_id,
                        ip=client_ip, regenerated_api_key=regenerated_api_key)
        return {
            "spoke_id": spoke.id,
            "status": "approved",
            "tenant_id": tenant_id,
            "api_key": api_key,
        }

    # Check for spoke_name conflicts in approved spokes
    name_conflict_approved = store.get_spoke_by_name(spoke_name)
    if name_conflict_approved:
        _, conflict_spoke = name_conflict_approved
        if conflict_spoke.hostname != payload.hostname:
            _reg_log_append("name_conflict_approved", hostname=payload.hostname,
                            spoke_name=spoke_name, ip=client_ip)
            raise HTTPException(
                status_code=409,
                detail={
                    "conflict": "name_in_use",
                    "message": f"Spoke name '{spoke_name}' is already in use by an approved spoke. Choose a different name.",
                },
            )

    # Check for spoke_name conflicts in pending spokes
    name_conflict_pending = store.get_pending_spoke_by_name(spoke_name)
    if name_conflict_pending and name_conflict_pending.hostname != payload.hostname:
        _reg_log_append("name_conflict_pending", hostname=payload.hostname,
                        spoke_name=spoke_name, ip=client_ip)
        raise HTTPException(
            status_code=409,
            detail={
                "conflict": "name_in_use",
                "message": f"Spoke name '{spoke_name}' is already registered and pending approval. Choose a different name.",
            },
        )

    existing = store.get_pending_spoke(requested_spoke_id) if requested_spoke_id else None
    if not existing:
        existing = store.get_pending_by_hostname(payload.hostname)
        if existing and requested_spoke_id and existing.id != requested_spoke_id:
            store.rekey_pending_spoke(existing.id, requested_spoke_id)
            existing.id = requested_spoke_id
    if existing:
        changed = False
        if existing.hostname != payload.hostname:
            existing.hostname = payload.hostname
            changed = True
        if payload.label and existing.label != payload.label:
            existing.label = payload.label
            changed = True
        if existing.spoke_name != spoke_name:
            existing.spoke_name = spoke_name
            changed = True
        if tenant_hint and existing.tenant_hint != tenant_hint:
            existing.tenant_hint = tenant_hint
            changed = True
        if existing.seed_config != payload.config:
            existing.seed_config = payload.config
            changed = True
        if changed:
            store.save_pending_spoke(existing)
        _reg_log_append("already_pending", hostname=payload.hostname,
                        spoke_name=spoke_name, spoke_id=existing.id,
                        tenant_hint=existing.tenant_hint, ip=client_ip)
        return {
            "spoke_id": existing.id,
            "status": "pending",
            "tenant_hint": existing.tenant_hint,
            "message": "Registration already pending approval.",
        }

    pending_kwargs = {
        "hostname": payload.hostname,
        "label": payload.label,
        "spoke_name": spoke_name,
        "tenant_hint": tenant_hint,
        "seed_config": payload.config,
    }
    if requested_spoke_id:
        pending_kwargs["id"] = requested_spoke_id
    pending = PendingSpoke(**pending_kwargs)
    store.save_pending_spoke(pending)
    _reg_log_append("new_pending", hostname=payload.hostname, spoke_name=spoke_name,
                    spoke_id=pending.id, tenant_hint=tenant_hint, ip=client_ip)
    ws_broadcast({
        "type": "pending_spoke_registered",
        "hostname": payload.hostname,
        "spoke_name": spoke_name,
        "spoke_id": pending.id,
        "tenant_hint": tenant_hint,
    })
    msg = (
        f"Registration received. Pending approval by tenant '{tenant_hint}'."
        if tenant_hint
        else "Registration received. Awaiting superadmin approval and tenant assignment."
    )
    return {
        "spoke_id": pending.id,
        "status": "pending",
        "tenant_hint": tenant_hint,
        "message": msg,
    }


@router.get("/spokes/diag")
def spokes_diag(current_user: auth.User = Depends(auth.require_superadmin)):
    """Return hub-side registration diagnostics log."""
    return {
        "registration_log": list(reversed(_registration_log)),
        "pending_count": len(store.list_pending_spokes()),
    }


@router.post("/{tenant_id}/spokes/{spoke_id}/telemetry")
@router.post("/{tenant_id}/islands/{spoke_id}/telemetry")
async def post_telemetry(
    tenant_id: str,
    spoke_id: str,
    payload: dict[str, Any],
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    spoke = _auth_spoke(tenant_id, spoke_id, x_api_key)
    changed = False
    hostname = str(payload.get("hostname") or "").strip()
    spoke_name = str(payload.get("spoke_name") or "").strip()
    if hostname and spoke.hostname != hostname:
        spoke.hostname = hostname
        changed = True
    if spoke_name and spoke.spoke_name != spoke_name:
        spoke.spoke_name = spoke_name
        changed = True
    if changed:
        store.save_spoke(spoke)
    store.update_spoke_telemetry(tenant_id, spoke_id, payload)
    await ws_broadcast({"type": "telemetry", "tenant_id": tenant_id, "spoke_id": spoke_id})
    return {"status": "ok"}


@router.get("/{tenant_id}/spokes/{spoke_id}/inbox")
@router.get("/{tenant_id}/islands/{spoke_id}/inbox")
def get_inbox(
    tenant_id: str,
    spoke_id: str,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    _auth_spoke(tenant_id, spoke_id, x_api_key)
    commands = store.get_queued_commands(tenant_id, spoke_id)
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


@router.post("/{tenant_id}/spokes/{spoke_id}/ack")
@router.post("/{tenant_id}/islands/{spoke_id}/ack")
async def ack_command_endpoint(
    tenant_id: str,
    spoke_id: str,
    payload: AckPayload,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    _auth_spoke(tenant_id, spoke_id, x_api_key)
    result = payload.result.model_dump(exclude_none=True) if payload.result else None
    store.ack_command(tenant_id, spoke_id, payload.command_id, result)
    if result and result.get("task_type"):
        task_status = "success" if result.get("success") else "failure"
        store.append_audit(
            AuditEntry(
                spoke_id=spoke_id,
                tenant_id=tenant_id,
                task_type=result.get("task_type", "command_ack"),
                execution_mode="distributed",
                status=task_status,
                detail=result.get("detail", ""),
                initiated_by="spoke",
                result=result,
            )
        )
        await ws_broadcast(
            {
                "type": "task_result",
                "tenant_id": tenant_id,
                "spoke_id": spoke_id,
                "task_type": result.get("task_type", "command_ack"),
                "status": task_status,
            }
        )
    return {"status": "ok"}
