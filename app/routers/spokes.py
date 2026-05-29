"""Spoke relay endpoints — used by spoke servers."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, ValidationError

from .. import auth, store, ws as relay_ws
from ..crypto import decrypt_str, encrypt_str, generate_api_key
from ..data_models import AuditEntry, Command, PendingSpoke, User
from ..ws import push_spoke_commands, register_spoke as ws_register_spoke, route_shell_message, route_vnc_message, register_log_fetch, unregister_log_fetch, route_log_fetch_message, unregister_spoke, ws_broadcast

# In-memory update job store: job_id -> job dict
_update_jobs: dict[str, dict[str, Any]] = {}

# Auth/credential keys that must never be stored or pushed by the hub
_AUTH_KEYS: set[str] = {
    "admin_password", "auth_provider", "local_users",
    "auth_ldap_url", "auth_ldap_bind_dn", "auth_ldap_bind_password",
    "auth_ldap_user_base", "auth_ldap_user_filter",
    "auth_ldap_group_admin", "auth_ldap_group_viewer",
    "auth_radius_host", "auth_radius_port", "auth_radius_secret",
    "auth_radius_role_attr", "auth_radius_admin_val",
    "auth_tacacs_host", "auth_tacacs_port", "auth_tacacs_secret",
    "auth_tacacs_admin_priv",
}

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
        effective_spoke_id = payload.spoke_id or spoke_id
        spoke_state = job.get("spoke_status", {}).get(effective_spoke_id)
        if spoke_state is None:
            logger.warning("Reseed progress from unknown spoke %s in job %s", effective_spoke_id, payload.job_id)
            return
        retry_count = int(spoke_state.get("retry_count", 0))
        next_status = payload.status
        if payload.status in _RESEED_ERROR_STATES:
            retry_count += 1
            if retry_count <= 3:
                next_status = "retrying"
                from .backups import _retry_reseed_after_delay
                asyncio.create_task(_retry_reseed_after_delay(job["job_id"], job["tenant_id"], effective_spoke_id, retry_count))
        spoke_state.update({"status": next_status, "step": payload.step, "error": payload.error, "retry_count": retry_count, "updated_at": datetime.utcnow().isoformat()})
        _refresh_backup_job_status(job)
        await ws_broadcast({
            "type": "reseed_progress",
            "job_id": payload.job_id,
            "spoke_id": effective_spoke_id,
            "status": next_status,
            "step": payload.step,
            "error": payload.error,
            "retries": retry_count,
            "template_name": job.get("template_name"),
        })
    else:
        effective_spoke_id = payload.spoke_id or spoke_id
        vm_state = job.get("vm_status", {}).get(payload.vm_id)
        if vm_state is None:
            logger.warning("Backup progress for unknown vm_id %s in job %s", payload.vm_id, payload.job_id)
            return
        vm_state.update({"status": payload.status, "pct": payload.pct, "size": payload.size, "file": payload.file, "error": payload.error})
        _refresh_backup_job_status(job)
        await ws_broadcast({
            "type": "backup_progress",
            "job_id": payload.job_id,
            "vm_id": payload.vm_id,
            "status": payload.status,
            "pct": payload.pct,
            "size": payload.size,
            "file": payload.file,
            "error": payload.error,
            "spoke_id": effective_spoke_id,
        })

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


_USB_VIDPID_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{4}$", re.IGNORECASE)
_USB_DEVICE_TYPES = {"wireless", "wired", "storage", "generic"}


class TenantUsbConfigRequest(BaseModel):
    usb_vidpids: list[dict[str, Any]] = Field(default_factory=list)


class SpokeProxmoxCredentialsRequest(BaseModel):
    proxmox_token: Optional[str] = None
    proxmox_host: str = ""


def _is_spoke_online(spoke) -> bool:
    if not spoke or not spoke.last_seen:
        return False
    last_seen = spoke.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    # Use 300s to match the frontend isOnline() threshold — eliminates the
    # red/green flicker caused by the old 600s backend vs 300s frontend mismatch.
    return (_now() - last_seen).total_seconds() < 300


def _normalize_usb_vidpids(items: Any) -> list[dict[str, str]]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise HTTPException(status_code=400, detail="usb_vidpids must be a JSON array")
    deduped: dict[str, dict[str, str]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise HTTPException(status_code=400, detail=f"usb_vidpids[{index}] must be an object")
        vidpid = str(item.get("vidpid") or "").strip().lower()
        if not vidpid or not _USB_VIDPID_RE.fullmatch(vidpid):
            raise HTTPException(status_code=400, detail=f"usb_vidpids[{index}].vidpid must match XXXX:XXXX")
        device_type = str(item.get("type") or "generic").strip().lower() or "generic"
        if device_type not in _USB_DEVICE_TYPES:
            device_type = "generic"
        deduped[vidpid] = {
            "vidpid": vidpid,
            "type": device_type,
            "label": str(item.get("label") or "").strip(),
        }
    return [deduped[key] for key in sorted(deduped)]


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
        "total_clients": spoke_data.get("total_clients", {}),
        "hardware_alerts": spoke_data.get("hardware_alerts", []),
        "client_count_status": spoke_data.get("client_count_status", tenant_data.get("client_count_status", {})),
        "token_valid": token_valid,
        "token_state": {
            "state": token_state_str if token_valid else "not_configured",
            "detail": tenant_data.get("error", ""),
        },
        "site_mappings": spoke_data.get("site_mappings", {}),
        "monitored_checks": spoke_data.get("monitored_checks", []),
        "hardware_checks": spoke_data.get("hardware_checks", []),
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
    # Drift detection: if the hub's authoritative config has changed since the
    # last push, bump config_version so the next inbox fetch queues a correction.
    drifted = await loop.run_in_executor(None, store.check_and_fix_config_drift, tenant_id, spoke_id)
    if drifted:
        await loop.run_in_executor(None, store.ensure_config_update_command, tenant_id, spoke_id)
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
    api_key: str = ""         # Present on re-registration to prove identity
    config: dict[str, Any] = Field(default_factory=dict)


@router.post("/spokes/register", status_code=201)
async def register_spoke(payload: RegisterPayload, request: Request):
    # Strip auth/credential keys — the hub must never store or push spoke auth config
    payload.config = {k: v for k, v in payload.config.items() if k not in _AUTH_KEYS}
    spoke_name = payload.spoke_name.strip() or payload.hostname
    tenant_hint = payload.tenant_id_hint.strip()
    requested_spoke_id = payload.spoke_id.strip().lower()
    client_ip = request.client.host if request.client else "unknown"
    if requested_spoke_id and not _is_valid_uuid(requested_spoke_id):
        _reg_log_append("invalid_spoke_id", hostname=payload.hostname, spoke_name=spoke_name,
                        spoke_id=requested_spoke_id, ip=client_ip)
        requested_spoke_id = ""

    # Validate tenant hint if provided; resolve by id or name
    if tenant_hint:
        resolved = store.get_tenant_by_hint(tenant_hint)
        if resolved:
            tenant_hint = resolved.id  # normalize to canonical id
        else:
            _reg_log_append("invalid_tenant_hint", hostname=payload.hostname,
                            spoke_name=spoke_name, tenant_hint=tenant_hint, ip=client_ip)
            tenant_hint = ""  # Silently ignore invalid tenant IDs

    approved = store.get_approved_spoke_by_id(requested_spoke_id) if requested_spoke_id else None
    if not approved:
        approved = store.get_approved_spoke_by_hostname(payload.hostname)
    if not approved and payload.api_key:
        approved = store.get_approved_spoke_by_api_key(payload.api_key, tenant_hint)
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
        # If the spoke already has a key on file, require it to prove identity.
        # A spoke that has never received its key (api_key_enc empty) is allowed through
        # so the first post-approval registration succeeds without a credential.
        if api_key and payload.api_key and payload.api_key != api_key:
            _reg_log_append("re_register_key_mismatch", hostname=payload.hostname,
                            spoke_name=spoke_name, spoke_id=spoke.id, tenant_id=tenant_id,
                            ip=client_ip)
            raise HTTPException(status_code=401, detail="Invalid API key for this spoke")
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
        tenant_obj = store.get_tenant(tenant_hint)  # tenant_hint already normalized to id above
        psk_valid = False
        if tenant_obj:
            if tenant_obj.onboarding_psk_enc and tenant_obj.onboarding_psk_enc not in tenant_obj.onboarding_psks_enc:
                tenant_obj.onboarding_psks_enc.insert(0, tenant_obj.onboarding_psk_enc)
                tenant_obj.onboarding_psk_enc = ""
                store.save_tenant(tenant_obj)
            for enc in tenant_obj.onboarding_psks_enc:
                try:
                    if decrypt_str(enc) == psk_provided:
                        psk_valid = True
                        break
                except Exception:
                    pass

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
            # Clean up any stale pending entries for this hostname (e.g. from before
            # tenant resolution was fixed — those entries may have blank tenant_hint).
            stale = store.get_pending_by_hostname(payload.hostname)
            if stale:
                store.delete_pending_spoke(stale.id)
            if requested_spoke_id:
                leftover = store.get_pending_spoke(requested_spoke_id)
                if leftover:
                    store.delete_pending_spoke(requested_spoke_id)
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
                            spoke_name=spoke_name, tenant_hint=tenant_hint, ip=client_ip,
                            psks_configured=len(tenant_obj.onboarding_psks_enc) if tenant_obj else 0)
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


@router.get("/{tenant_id}/spokes/{spoke_id}/remote-logs")
async def get_spoke_remote_logs(
    tenant_id: str,
    spoke_id: str,
    source: str = Query(default="journal"),
    lines: int = Query(default=200, ge=10, le=2000),
    current_user: User = Depends(auth.get_current_user),
):
    """Fetch log lines from the spoke via the relay WebSocket.
    source: journal | agent | watchdog | install"""
    resolved_tenant_id = _require_tenant_access(tenant_id, current_user)
    spoke = store.get_spoke(resolved_tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")

    request_id = str(uuid.uuid4())
    queue = register_log_fetch(request_id)
    try:
        sent = await relay_ws.send_to_spoke(resolved_tenant_id, spoke_id, {
            "type": "log_fetch",
            "request_id": request_id,
            "source": str(source or "journal").strip().lower(),
            "lines": int(lines),
        })
        if not sent:
            raise HTTPException(status_code=502, detail="Spoke relay is offline")
        try:
            response = await asyncio.wait_for(queue.get(), timeout=15.0)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="Spoke did not respond in time")
    finally:
        unregister_log_fetch(request_id)

    if response.get("error"):
        raise HTTPException(status_code=502, detail=response["error"])
    return {"source": source, "lines": response.get("lines", [])}


@router.get("/{tenant_id}/spokes/{spoke_id}/proxmox-credentials")
def get_spoke_proxmox_credentials(
    tenant_id: str,
    spoke_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spoke = store.get_spoke(resolved_tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")
    proxmox_host = str(spoke.proxmox_host or "").strip() or str(spoke.hostname or "").strip()
    return {
        "proxmox_host": proxmox_host,
        "proxmox_token_configured": bool(str(spoke.proxmox_token_enc or "").strip()),
    }


@router.put("/{tenant_id}/spokes/{spoke_id}/proxmox-credentials")
def set_spoke_proxmox_credentials(
    tenant_id: str,
    spoke_id: str,
    payload: SpokeProxmoxCredentialsRequest,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spoke = store.get_spoke(resolved_tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")

    spoke.proxmox_host = str(payload.proxmox_host or "").strip()
    if payload.proxmox_token is not None:
        token = str(payload.proxmox_token).strip()
        spoke.proxmox_token_enc = encrypt_str(token) if token else ""
    store.save_spoke(spoke)

    # Push the API token to the spoke via config_update so it can use it locally
    # for the VNC relay (spoke needs the token to call Proxmox vncproxy).
    if payload.proxmox_token is not None:
        token = str(payload.proxmox_token).strip()
        _queue_spoke_config_push(resolved_tenant_id, spoke_id, {"proxmox_api_token": token})

    proxmox_host = spoke.proxmox_host or str(spoke.hostname or "").strip()
    return {
        "ok": True,
        "proxmox_host": proxmox_host,
        "proxmox_token_configured": bool(str(spoke.proxmox_token_enc or "").strip()),
    }


@router.get("/{tenant_id}/usb-config")
def get_tenant_usb_config(tenant_id: str, current_user: User = Depends(auth.get_current_user)):
    resolved_tenant_id = _require_tenant_access(tenant_id, current_user)
    tenant = store.get_tenant(resolved_tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"usb_vidpids": store.get_tenant_usb_vidpids(resolved_tenant_id)}



def _queue_spoke_config_push(tenant_id: str, spoke_id: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    spoke = store.get_spoke(tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")

    next_config = dict(spoke.config or {})
    next_config.update(body or {})
    for key in _AUTH_KEYS:
        next_config.pop(key, None)
    spoke.config = next_config
    spoke.config_version = (spoke.config_version or 0) + 1
    store.save_spoke(spoke)
    store.enqueue_command(
        Command(
            spoke_id=spoke_id,
            tenant_id=tenant_id,
            type="config_update",
            payload={**next_config, "__config_version": spoke.config_version},
            expires_at=_now() + timedelta(hours=24),
        )
    )
    return {"ok": True, "config_version": spoke.config_version}


@router.post("/{tenant_id}/usb-config/push-all")
async def push_tenant_usb_config_to_all_spokes(
    tenant_id: str,
    payload: TenantUsbConfigRequest,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = store.set_tenant_usb_vidpids(resolved_tenant_id, _normalize_usb_vidpids(payload.usb_vidpids))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    pushed_to: list[str] = []
    online_spokes: list[str] = []
    for spoke in store.list_spokes(resolved_tenant_id):
        if spoke.status != "approved":
            continue
        _queue_spoke_config_push(resolved_tenant_id, spoke.id, {"usb_vidpids": tenant.usb_vidpids})
        pushed_to.append(spoke.id)
        if _is_spoke_online(spoke):
            online_spokes.append(spoke.id)
    return {"ok": True, "pushed_to": pushed_to, "online_spokes": online_spokes, "usb_vidpids": tenant.usb_vidpids}


def _spoke_versions_snapshot(tenant_id: str) -> dict[str, dict[str, Any]]:
    """Capture current agent + spoke versions for all approved spokes."""
    snapshot: dict[str, dict[str, Any]] = {}
    for spoke in store.list_spokes(tenant_id):
        if spoke.status != "approved":
            continue
        tel = spoke.telemetry or {}
        proxmox = tel.get("proxmox") or {}
        health = (tel.get("api_server") or {}).get("health") or {}
        snapshot[spoke.id] = {
            "spoke_name": spoke.spoke_name or spoke.hostname or spoke.id,
            "agent_version_before": proxmox.get("agent_version"),
            "agent_version_after": None,
            "agent_status": "pending",
            "spoke_version_before": health.get("installer_version") or health.get("version"),
            "spoke_version_after": None,
            "spoke_status": "pending",
        }
    return snapshot


async def _poll_update_job(job_id: str, tenant_id: str) -> None:
    """Background task: poll telemetry every 15s, detect version changes.
    As soon as a spoke's proxmox agent is confirmed updated, immediately
    enqueue that spoke's self_update (no fixed delay needed since the WS
    connection is persistent and the command is delivered in real time)."""
    job = _update_jobs.get(job_id)
    if not job:
        return
    deadline = time.time() + 600  # 10-minute timeout
    while time.time() < deadline:
        await asyncio.sleep(15)
        job = _update_jobs.get(job_id)
        if not job:
            return
        all_done = True
        for spoke in store.list_spokes(tenant_id):
            sd = job["spokes"].get(spoke.id)
            if not sd:
                continue
            tel = spoke.telemetry or {}
            proxmox = tel.get("proxmox") or {}
            health = (tel.get("api_server") or {}).get("health") or {}
            cur_agent = proxmox.get("agent_version")
            cur_spoke = health.get("installer_version") or health.get("version")

            # Check agent version — as soon as it changes (or after 4 polls
            # with no change, meaning agent is already current), enqueue spoke self_update
            if sd["agent_status"] == "pending":
                if cur_agent and cur_agent != sd["agent_version_before"]:
                    sd["agent_status"] = "updated"
                    sd["agent_version_after"] = cur_agent
                    store.enqueue_command(Command(
                        spoke_id=spoke.id,
                        tenant_id=tenant_id,
                        type="self_update",
                        payload={},
                        expires_at=_now() + timedelta(hours=24),
                    ))
                elif sd.get("agent_check_count", 0) >= 4:
                    # Agent version unchanged after ~60s — already at latest; proceed to spoke update
                    sd["agent_status"] = "current"
                    sd["agent_version_after"] = cur_agent
                    store.enqueue_command(Command(
                        spoke_id=spoke.id,
                        tenant_id=tenant_id,
                        type="self_update",
                        payload={},
                        expires_at=_now() + timedelta(hours=24),
                    ))
                else:
                    sd["agent_check_count"] = sd.get("agent_check_count", 0) + 1
                    all_done = False

            # Check spoke version
            if sd["spoke_status"] == "pending":
                if cur_spoke and cur_spoke != sd["spoke_version_before"]:
                    sd["spoke_status"] = "updated"
                    sd["spoke_version_after"] = cur_spoke
                else:
                    all_done = False

        await ws_broadcast({"type": "update_job_status", "job_id": job_id, "job": job})
        if all_done:
            job["completed"] = True
            job["completed_at"] = datetime.now(timezone.utc).isoformat()
            await ws_broadcast({"type": "update_job_status", "job_id": job_id, "job": job})
            return

    # Timeout — mark anything still pending as timed out
    for sd in job["spokes"].values():
        if sd["agent_status"] == "pending":
            sd["agent_status"] = "timeout"
        if sd["spoke_status"] == "pending":
            sd["spoke_status"] = "timeout"
    job["completed"] = True
    job["completed_at"] = datetime.now(timezone.utc).isoformat()
    await ws_broadcast({"type": "update_job_status", "job_id": job_id, "job": job})


@router.post("/{tenant_id}/update-all")
async def update_all_spokes(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Trigger proxmox agent update on all spokes, then spoke self-update after a 2-minute delay.
    Returns a job_id for tracking progress via GET /{tenant_id}/update-status/{job_id}."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spokes = [s for s in store.list_spokes(resolved_tenant_id) if s.status == "approved"]
    if not spokes:
        raise HTTPException(status_code=404, detail="No approved spokes found")

    job_id = str(uuid.uuid4())
    job: dict[str, Any] = {
        "job_id": job_id,
        "tenant_id": resolved_tenant_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "completed": False,
        "completed_at": None,
        "spokes": _spoke_versions_snapshot(resolved_tenant_id),
    }
    _update_jobs[job_id] = job

    spoke_ids = [s.id for s in spokes]

    # Enqueue proxmox agent updates immediately for all spokes.
    # The polling task (_poll_update_job) will enqueue each spoke's self_update
    # as soon as it detects that spoke's agent version has changed in telemetry.
    for spoke in spokes:
        store.enqueue_command(Command(
            spoke_id=spoke.id,
            tenant_id=resolved_tenant_id,
            type="proxmox_agent_update",
            payload={},
            expires_at=_now() + timedelta(hours=24),
        ))

    asyncio.create_task(_poll_update_job(job_id, resolved_tenant_id))

    return {"ok": True, "job_id": job_id, "spokes": len(spokes), "spoke_ids": spoke_ids}


@router.post("/{tenant_id}/spokes/{spoke_id}/update-agent")
def update_spoke_proxmox_agent(
    tenant_id: str,
    spoke_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Queue a proxmox agent update for a single spoke."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spoke = _get_approved_spoke(resolved_tenant_id, spoke_id)
    store.enqueue_command(Command(
        spoke_id=spoke.id,
        tenant_id=resolved_tenant_id,
        type="proxmox_agent_update",
        payload={},
        expires_at=_now() + timedelta(hours=24),
    ))
    return {"ok": True, "spoke_id": spoke_id}


@router.get("/{tenant_id}/update-status/{job_id}")
async def get_update_status(
    tenant_id: str,
    job_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Return current status of an update-all job."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    job = _update_jobs.get(job_id)
    if not job or job["tenant_id"] != resolved_tenant_id:
        raise HTTPException(status_code=404, detail="Update job not found")
    return job


@router.post("/{tenant_id}/update-spokes")
async def update_spokes_via_agent(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Queue an update_spoke command to each spoke's proxmox agent so the agent
    calls the spoke's /api/self-update endpoint.  Useful when spokes are too old
    to handle the self_update WS command directly."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spokes = [s for s in store.list_spokes(resolved_tenant_id) if s.status == "approved"]
    if not spokes:
        raise HTTPException(status_code=404, detail="No approved spokes found")
    for spoke in spokes:
        store.enqueue_command(Command(
            spoke_id=spoke.id,
            tenant_id=resolved_tenant_id,
            type="proxmox_agent_command",
            payload={"action": "update_spoke"},
            expires_at=_now() + timedelta(hours=24),
        ))
    return {"ok": True, "queued": len(spokes), "spoke_ids": [s.id for s in spokes]}


@router.post("/{tenant_id}/update-spoke-servers")
async def force_update_spoke_servers(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Send self_update directly to all spokes — bypasses agent relay.
    Use this to deploy new spoke server.py before agents can relay commands."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spokes = [s for s in store.list_spokes(resolved_tenant_id) if s.status == "approved"]
    if not spokes:
        raise HTTPException(status_code=404, detail="No approved spokes found")
    queued = 0
    for spoke in spokes:
        store.enqueue_command(Command(
            spoke_id=spoke.id,
            tenant_id=resolved_tenant_id,
            type="self_update",
            payload={},
            expires_at=_now() + timedelta(hours=24),
        ))
        queued += 1
    return {"ok": True, "queued": queued, "spoke_ids": [s.id for s in spokes]}


@router.post("/{tenant_id}/spokes/{spoke_id}/config")
async def push_spoke_config(
    tenant_id: str,
    spoke_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
    current_user: User = Depends(auth.get_current_user),
):
    """Push a config_update command to the spoke."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    return _queue_spoke_config_push(resolved_tenant_id, spoke_id, body)


@router.post("/{tenant_id}/spokes/{spoke_id}/telemetry")
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
def get_inbox(
    tenant_id: str,
    spoke_id: str,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    _auth_spoke(tenant_id, spoke_id, x_api_key)
    return _get_spoke_inbox(tenant_id, spoke_id)


@router.get("/{tenant_id}/spokes/{spoke_id}/monitored-items")
def get_spoke_monitored_items(
    tenant_id: str,
    spoke_id: str,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    """Return hub-managed monitored items filtered to this spoke's assigned sites.
    If the spoke has no assigned sites, returns empty with has_sites=False."""
    spoke = _auth_spoke(tenant_id, spoke_id, x_api_key)
    assigned_sites = set(spoke.assigned_sites or [])
    if not assigned_sites:
        return {"items": [], "has_sites": False, "assigned_sites": []}
    cfg = store.get_tenant_central_sites_config(tenant_id)
    all_items = cfg.get("monitored_items") if isinstance(cfg.get("monitored_items"), list) else []
    filtered = []
    for item in all_items:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "site":
            # Only include site items whose identifier or name matches an assigned site
            if item.get("identifier") in assigned_sites or item.get("name") in assigned_sites:
                filtered.append(item)
        else:
            # Alerts, insights, clients are tenant-wide
            filtered.append(item)
    return {"items": filtered, "has_sites": True, "assigned_sites": sorted(assigned_sites)}


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
                    t0 = time.monotonic()
                    await _apply_spoke_telemetry(tenant_id, spoke_id, spoke, payload)
                    processing_ms = round((time.monotonic() - t0) * 1000)
                    await websocket.send_json({"type": "telemetry_ack", "ts": _now().isoformat(), "processing_ms": processing_ms})
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
                elif msg_type.startswith("shell_"):
                    route_shell_message(data)
                elif msg_type.startswith("vnc_"):
                    route_vnc_message(data)
                elif msg_type == "log_fetch_response":
                    route_log_fetch_message(data)
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
