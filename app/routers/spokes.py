"""Spoke relay endpoints — used by spoke servers."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, ValidationError

from .. import auth, store
from ..crypto import decrypt_str, encrypt_str, generate_api_key
from ..data_models import AuditEntry, Command, PendingSpoke, User
from ..ws import push_spoke_commands, register_spoke as ws_register_spoke, unregister_spoke, ws_broadcast

# Imported lazily inside the handler to avoid a circular import at module load time.
# _handle_spoke_backup_progress(spoke_id, payload_dict) is defined in backups.py.
async def _relay_backup_progress(spoke_id: str, msg_type: str, data: dict) -> None:
    """Forward backup_progress / reseed_progress messages from a spoke to the backup subsystem."""
    from .backups import BackupProgressPayload, backup_jobs, _refresh_backup_job_status, _RESEED_ERROR_STATES
    import asyncio
    raw = data.get("payload") if isinstance(data.get("payload"), dict) else data
    # Ensure spoke_id propagates for reseed jobs (agent may omit it)
    if spoke_id and not raw.get("spoke_id"):
        raw = dict(raw)
        raw["spoke_id"] = spoke_id
    try:
        payload = BackupProgressPayload(**raw)
    except Exception as exc:
        logger.warning("Invalid %s payload from spoke %s: %s", msg_type, spoke_id, exc)
        return
    job = backup_jobs.get(payload.job_id)
    if job is None:
        logger.debug("Received %s for unknown job %s from spoke %s — ignoring", msg_type, payload.job_id, spoke_id)
        return
    if job.get("type") == "reseed":
        spoke_state = job.get("spoke_status", {}).get(payload.spoke_id or spoke_id)
        if spoke_state is None:
            logger.warning("Reseed progress from unknown spoke %s in job %s", payload.spoke_id or spoke_id, payload.job_id)
            return
        retry_count = int(spoke_state.get("retry_count", 0))
        next_status = payload.status
        if payload.status in _RESEED_ERROR_STATES:
            retry_count += 1
            if retry_count <= 3:
                next_status = "retrying"
                from .backups import _retry_reseed_after_delay
                asyncio.create_task(_retry_reseed_after_delay(job["job_id"], job["tenant_id"], payload.spoke_id or spoke_id, retry_count))
        spoke_state.update({"status": next_status, "step": payload.step, "error": payload.error, "retry_count": retry_count, "updated_at": datetime.utcnow().isoformat()})
    else:
        vm_state = job.get("vm_status", {}).get(payload.vm_id)
        if vm_state is None:
            logger.warning("Backup progress for unknown vm_id %s in job %s", payload.vm_id, payload.job_id)
            return
        vm_state.update({"status": payload.status, "pct": payload.pct, "size": payload.size, "file": payload.file, "error": payload.error})
    _refresh_backup_job_status(job)
    await ws_broadcast({"type": "backup_progress", "job": job})

router = APIRouter()
logger = logging.getLogger(__name__)

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


def _name_conflict_message(spoke_name: str, state: str, tenant_id: str) -> str:
    scope = f" within tenant '{tenant_id}'" if tenant_id else " within the same tenant"
    if state == "approved":
        return (
            f"Spoke name '{spoke_name}' is already in use by another approved spoke{scope}. "
            "Choose a different name."
        )
    return (
        f"Spoke name '{spoke_name}' is already registered and pending approval{scope}. "
        "Choose a different name."
    )


def _raise_name_conflict(spoke_name: str, state: str, tenant_id: str) -> None:
    raise HTTPException(
        status_code=409,
        detail={
            "conflict": "name_in_use",
            "message": _name_conflict_message(spoke_name, state, tenant_id),
        },
    )


def _ensure_name_available_for_tenant(
    spoke_name: str,
    tenant_id: str,
    *,
    hostname: str,
    exclude_spoke_id: str = "",
    log_context: Optional[dict[str, Any]] = None,
) -> None:
    if not tenant_id:
        return

    approved_conflict = store.find_spoke_name_conflict(
        tenant_id,
        spoke_name,
        exclude_spoke_id=exclude_spoke_id,
    )
    if approved_conflict and approved_conflict.hostname != hostname:
        _reg_log_append(
            "name_conflict_approved",
            hostname=hostname,
            spoke_name=spoke_name,
            tenant_id=tenant_id,
            **(log_context or {}),
        )
        _raise_name_conflict(spoke_name, "approved", tenant_id)

    pending_conflict = store.find_pending_spoke_name_conflict(
        tenant_id,
        spoke_name,
        exclude_spoke_id=exclude_spoke_id,
    )
    if pending_conflict and pending_conflict.hostname != hostname:
        _reg_log_append(
            "name_conflict_pending",
            hostname=hostname,
            spoke_name=spoke_name,
            tenant_id=tenant_id,
            **(log_context or {}),
        )
        _raise_name_conflict(spoke_name, "pending", tenant_id)


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


def _require_tenant_access(tenant_id: str, current_user: User) -> str:
    auth.require_tenant_access(tenant_id, current_user)
    return tenant_id


def _require_tenant_admin(tenant_id: str, current_user: User) -> str:
    auth.require_tenant_access(tenant_id, current_user)
    if not current_user.is_superadmin and current_user.get_role(tenant_id) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return tenant_id


def _require_spoke_admin(spoke_id: str, current_user: User) -> tuple[str, Any]:
    approved = store.get_approved_spoke_by_id(spoke_id)
    if not approved:
        raise HTTPException(status_code=404, detail="Spoke not found")

    tenant_id, spoke = approved
    auth.require_tenant_access(tenant_id, current_user)
    if not current_user.is_superadmin and current_user.get_role(tenant_id) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return tenant_id, spoke


def _serialize_spoke_command(command) -> dict[str, Any]:
    return {"id": command.id, "target": command.target, "type": command.type, "payload": command.payload}


def _build_spoke_central_feed(tenant_id: str, spoke_id: str) -> dict[str, Any]:
    from ..tasks import _hub_central_status

    tenant_data = _hub_central_status.get(tenant_id, {})
    spoke_data = tenant_data.get("spokes", {}).get(spoke_id, {})
    token_valid = bool(tenant_data.get("token_valid", False))
    token_state_str = tenant_data.get("token_state", "not_configured")
    return {
        "status": spoke_data.get("status", {}),
        "wireless_clients": spoke_data.get("wireless_clients", {}),
        "hardware_alerts": spoke_data.get("hardware_alerts", []),
        "client_count_status": {},
        "token_valid": token_valid,
        "token_state": {
            "state": token_state_str if token_valid else "not_configured",
            "detail": tenant_data.get("error", ""),
        },
        "site_mappings": spoke_data.get("site_mappings", {}),
        "monitored_checks": spoke_data.get("monitored_checks", []),
    }


async def _apply_spoke_telemetry(tenant_id: str, spoke_id: str, spoke, payload: dict[str, Any]) -> None:
    tenant = store.get_tenant(tenant_id)
    changed = False
    previous_config_version = spoke.config_version
    hostname = str(payload.get("hostname") or "").strip()
    spoke_name = str(payload.get("spoke_name") or "").strip()
    telemetry_config = payload.get("config") if isinstance(payload.get("config"), dict) else None
    if hostname and spoke.hostname != hostname:
        spoke.hostname = hostname
        changed = True
    if spoke_name and spoke.spoke_name != spoke_name:
        spoke.spoke_name = spoke_name
        changed = True
    if not spoke.config and telemetry_config:
        spoke.config = dict(telemetry_config)
        spoke.config_version = 1
        spoke.applied_config_version = 0
        changed = True
    if tenant and previous_config_version > 0 and not store.tenant_has_spoke_config_payload(tenant):
        spoke.config_version = 0
        spoke.applied_config_version = 0
        store.ensure_config_clear_command(tenant_id, spoke_id)
        changed = True
    if changed:
        store.save_spoke(spoke)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, store.update_spoke_telemetry, tenant_id, spoke_id, payload)
    await ws_broadcast({"type": "telemetry", "tenant_id": tenant_id, "spoke_id": spoke_id})


def _get_spoke_inbox(tenant_id: str, spoke_id: str) -> list[dict[str, Any]]:
    store.ensure_config_update_command(tenant_id, spoke_id)
    return [_serialize_spoke_command(c) for c in store.get_queued_commands(tenant_id, spoke_id)]


async def _handle_spoke_ack(tenant_id: str, spoke_id: str, payload: AckPayload) -> dict[str, str]:
    command = store.get_command(tenant_id, spoke_id, payload.command_id)
    result = payload.result.model_dump(exclude_none=True) if payload.result else None
    store.ack_command(tenant_id, spoke_id, payload.command_id, result)
    if command and command.type == "config_update" and (result or {}).get("success", True):
        version = int((command.payload or {}).get("__config_version", 0) or 0)
        if version > 0:
            store.mark_spoke_config_applied(tenant_id, spoke_id, version)
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


class RegisterPayload(BaseModel):
    spoke_id: str = ""
    hostname: str
    label: str = ""
    spoke_name: str = ""
    tenant_id_hint: str = ""  # Optional: tenant ID pre-entered on spoke
    onboarding_psk: str = ""  # Optional: PSK for auto-approval without human review
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
        if spoke.spoke_name != spoke_name:
            _ensure_name_available_for_tenant(
                spoke_name,
                tenant_id,
                hostname=payload.hostname,
                exclude_spoke_id=spoke.id,
                log_context={"spoke_id": spoke.id, "ip": client_ip},
            )
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
        # Update seed_config so the hub always reflects the spoke's current settings.
        # When hub_config_enabled is False the spoke drives its own config — also
        # update spoke.config and bump config_version so the hub's record stays current
        # and the config page shows fresh values.
        if payload.config and spoke.seed_config != payload.config:
            spoke.seed_config = dict(payload.config)
            tenant = store.get_tenant(tenant_id)
            hub_managed = bool(tenant and tenant.hub_config_enabled)
            if not hub_managed:
                spoke.config = dict(payload.config)
                spoke.config_version += 1
            changed = True
        if changed:
            store.save_spoke(spoke)
        if spoke.config_version > spoke.applied_config_version:
            store.ensure_config_update_command(tenant_id, spoke.id)
        _reg_log_append("already_approved", hostname=payload.hostname,
                        spoke_name=spoke_name, spoke_id=spoke.id, tenant_id=tenant_id,
                        ip=client_ip, regenerated_api_key=regenerated_api_key)
        return {
            "spoke_id": spoke.id,
            "status": "approved",
            "tenant_id": tenant_id,
            "api_key": api_key,
        }

    # ── PSK auto-approve ──────────────────────────────────────────────────────
    # If the spoke supplies tenant_id_hint + spoke_name + onboarding_psk and the
    # PSK matches what the tenant has configured, skip the approval queue entirely.
    psk_provided = payload.onboarding_psk.strip()
    if tenant_hint and spoke_name and psk_provided:
        tenant_obj = store.get_tenant(tenant_hint)
        psk_valid = False
        if tenant_obj and tenant_obj.onboarding_psk_enc:
            try:
                psk_valid = (decrypt_str(tenant_obj.onboarding_psk_enc) == psk_provided)
            except Exception:
                psk_valid = False

        if psk_valid:
            _ensure_name_available_for_tenant(
                spoke_name, tenant_hint,
                hostname=payload.hostname,
                exclude_spoke_id=requested_spoke_id,
                log_context={"spoke_id": requested_spoke_id, "ip": client_ip},
            )
            from ..data_models import Spoke as SpokeModel
            plain_key = generate_api_key()
            auto_spoke = SpokeModel(
                **({"id": requested_spoke_id} if requested_spoke_id else {}),
                tenant_id=tenant_hint,
                hostname=payload.hostname,
                label=payload.label or payload.hostname,
                spoke_name=spoke_name,
                seed_config=payload.config,
                config=payload.config.copy(),
                status="approved",
                api_key_enc=encrypt_str(plain_key),
            )
            store.save_spoke(auto_spoke)
            _reg_log_append("psk_auto_approved", hostname=payload.hostname,
                            spoke_name=spoke_name, spoke_id=auto_spoke.id,
                            tenant_id=tenant_hint, ip=client_ip)
            asyncio.create_task(ws_broadcast({
                "type": "spoke_approved",
                "spoke_id": auto_spoke.id,
                "tenant_id": tenant_hint,
                "auto": True,
            }))
            return {
                "spoke_id": auto_spoke.id,
                "status": "approved",
                "tenant_id": tenant_hint,
                "api_key": plain_key,
            }
        else:
            _reg_log_append("psk_rejected", hostname=payload.hostname,
                            spoke_name=spoke_name, tenant_hint=tenant_hint, ip=client_ip)
    # ── End PSK auto-approve ──────────────────────────────────────────────────

    existing = store.get_pending_spoke(requested_spoke_id) if requested_spoke_id else None
    if not existing:
        existing = store.get_pending_by_hostname(payload.hostname)
        if existing and requested_spoke_id and existing.id != requested_spoke_id:
            store.rekey_pending_spoke(existing.id, requested_spoke_id)
            existing.id = requested_spoke_id

    target_tenant_id = tenant_hint or (existing.tenant_hint if existing else "")
    exclude_spoke_id = existing.id if existing else requested_spoke_id
    _ensure_name_available_for_tenant(
        spoke_name,
        target_tenant_id,
        hostname=payload.hostname,
        exclude_spoke_id=exclude_spoke_id,
        log_context={"spoke_id": exclude_spoke_id, "ip": client_ip},
    )
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
    asyncio.create_task(ws_broadcast({
        "type": "pending_spoke_registered",
        "hostname": payload.hostname,
        "spoke_name": spoke_name,
        "spoke_id": pending.id,
        "tenant_hint": tenant_hint,
    }))
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


@router.delete("/spokes/{spoke_id}")
def delete_spoke(spoke_id: str, current_user: User = Depends(auth.get_current_user)):
    tenant_id, _ = _require_spoke_admin(spoke_id, current_user)
    store.delete_spoke(tenant_id, spoke_id)
    return {"ok": True}


@router.get("/{tenant_id}/spokes/{spoke_id}/config")
def get_spoke_config(tenant_id: str, spoke_id: str, current_user: User = Depends(auth.get_current_user)):
    """Return the spoke's current applied config and telemetry-reported settings."""
    resolved_tenant_id = _require_tenant_access(tenant_id, current_user)
    spoke = store.get_spoke(resolved_tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")
    return {"config": spoke.config or {}, "telemetry": spoke.telemetry or {}}


@router.post("/{tenant_id}/spokes/{spoke_id}/config")
async def push_spoke_config(
    tenant_id: str,
    spoke_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
    current_user: User = Depends(auth.get_current_user),
):
    """Push a config_update command to the spoke."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spoke = store.get_spoke(resolved_tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")

    next_config = dict(spoke.config or {})
    next_config.update(body or {})
    spoke.config = next_config
    spoke.config_version = (spoke.config_version or 0) + 1
    store.save_spoke(spoke)
    store.enqueue_command(
        Command(
            spoke_id=spoke_id,
            tenant_id=resolved_tenant_id,
            type="config_update",
            payload={**next_config, "__config_version": spoke.config_version},
            expires_at=_now() + timedelta(minutes=10),
        )
    )
    return {"ok": True, "config_version": spoke.config_version}


@router.post("/{tenant_id}/spokes/{spoke_id}/telemetry")
@router.post("/{tenant_id}/islands/{spoke_id}/telemetry")
async def post_telemetry(
    tenant_id: str,
    spoke_id: str,
    payload: dict[str, Any],
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    spoke = _auth_spoke(tenant_id, spoke_id, x_api_key)
    await _apply_spoke_telemetry(tenant_id, spoke_id, spoke, payload)
    return {"status": "ok"}


@router.get("/{tenant_id}/spokes/{spoke_id}/inbox")
@router.get("/{tenant_id}/islands/{spoke_id}/inbox")
def get_inbox(
    tenant_id: str,
    spoke_id: str,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    _auth_spoke(tenant_id, spoke_id, x_api_key)
    return _get_spoke_inbox(tenant_id, spoke_id)


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
    return await _handle_spoke_ack(tenant_id, spoke_id, payload)


@router.websocket("/{tenant_id}/spokes/{spoke_id}/ws")
async def spoke_websocket(
    websocket: WebSocket,
    tenant_id: str,
    spoke_id: str,
    api_key: str = Query(""),
):
    connection_api_key = str(api_key or "")
    try:
        spoke = _auth_spoke(tenant_id, spoke_id, connection_api_key)
    except HTTPException as exc:
        await websocket.close(code=4401 if exc.status_code == 401 else 4403, reason=str(exc.detail))
        return

    await ws_register_spoke(websocket, tenant_id, spoke_id)
    await push_spoke_commands(tenant_id, spoke_id)
    try:
        await websocket.send_json({"type": "central_feed", "payload": _build_spoke_central_feed(tenant_id, spoke_id)})
        while True:
            try:
                data = await websocket.receive_json()
                if not isinstance(data, dict):
                    raise ValueError("WebSocket payload must be a JSON object")
                msg_type = str(data.get("type") or "telemetry").strip().lower()
                if msg_type == "telemetry":
                    payload = data.get("payload") if isinstance(data.get("payload"), dict) else data
                    await _apply_spoke_telemetry(tenant_id, spoke_id, spoke, payload)
                    await websocket.send_json({"type": "telemetry_ack", "ts": _now().isoformat()})
                    await websocket.send_json({"type": "central_feed", "payload": _build_spoke_central_feed(tenant_id, spoke_id)})
                    await push_spoke_commands(tenant_id, spoke_id)
                elif msg_type == "ack":
                    raw_payload = data.get("payload") if isinstance(data.get("payload"), dict) else data
                    payload = AckPayload(**raw_payload)
                    await _handle_spoke_ack(tenant_id, spoke_id, payload)
                    await websocket.send_json({"type": "ack_ok", "command_id": payload.command_id})
                elif msg_type == "ping":
                    await websocket.send_json({"type": "pong"})
                elif msg_type == "sync":
                    await push_spoke_commands(tenant_id, spoke_id)
                    await websocket.send_json({"type": "central_feed", "payload": _build_spoke_central_feed(tenant_id, spoke_id)})
                elif msg_type in {"backup_progress", "reseed_progress"}:
                    await _relay_backup_progress(spoke_id, msg_type, data)
            except WebSocketDisconnect:
                raise
            except (json.JSONDecodeError, ValidationError, ValueError, TypeError) as exc:
                logger.warning("Invalid spoke websocket payload for %s/%s: %s", tenant_id, spoke_id, exc)
                await websocket.send_json({"type": "error", "error": str(exc)})
                continue
            except Exception as exc:
                logger.warning("Spoke websocket processing failed for %s/%s: %s", tenant_id, spoke_id, exc)
                await websocket.send_json({"type": "error", "error": str(exc)})
                continue
    except WebSocketDisconnect:
        pass
    finally:
        await unregister_spoke(tenant_id, spoke_id, websocket)


@router.get("/{tenant_id}/spokes/{spoke_id}/central-feed")
async def get_spoke_central_feed(
    tenant_id: str,
    spoke_id: str,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """Return hub-polled Aruba Central data for a spoke to consume in centralized mode."""
    _auth_spoke(tenant_id, spoke_id, x_api_key)
    return _build_spoke_central_feed(tenant_id, spoke_id)
