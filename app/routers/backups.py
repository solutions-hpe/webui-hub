from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import os
from typing import Any, Optional
from uuid import uuid4
import xml.etree.ElementTree as ET

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .. import auth, crypto, store
from ..data_models import BackupConfig, Command, User
from ..ws import send_spoke_command, ws_broadcast

router = APIRouter()
backup_jobs: dict[str, dict[str, Any]] = {}
_LOCALHOSTS = {"127.0.0.1", "::1", "localhost"}
_RESEED_RETRY_DELAYS = {1: 300, 2: 900, 3: 1800}
_RESEED_SUCCESS_STATES = {"done", "completed"}
_RESEED_ERROR_STATES = {"error", "failed"}


def _get_azure_key(backup_config: BackupConfig) -> str:
    """Decrypt and return the Azure storage key. Raises HTTPException 503 if not available."""
    enc = (backup_config.azure_key_enc or "").strip()
    if not enc:
        raise HTTPException(status_code=503, detail="Azure storage key is not configured")
    try:
        return crypto.decrypt_value(enc)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Failed to decrypt Azure key: {exc}") from exc


class TriggerBackupRequest(BaseModel):
    azure_key: str


class SetAzureKeyRequest(BaseModel):
    azure_key: str


class ReseedRequest(BaseModel):
    template_name: str
    latest_blob: str
    spoke_ids: list[str]
    vm_id: int = 100


class BackupProgressPayload(BaseModel):
    job_id: str
    vm_id: Optional[int] = None
    status: str
    pct: int = 0
    size: Optional[int] = None
    file: Optional[str] = None
    error: Optional[str] = None
    spoke_id: Optional[str] = None
    step: Optional[str] = None


def _require_superadmin(current_user: User) -> None:
    if not current_user.is_superadmin:
        raise HTTPException(status_code=403, detail="Superadmin required")


def _get_backup_job(job_id: str) -> dict[str, Any]:
    job = backup_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Backup job not found")
    return job


def _xml_local_name(tag: str) -> str:
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


def _is_local_request(request: Request) -> bool:
    client = request.client.host if request.client else ""
    return client in _LOCALHOSTS


def _parse_blob_entries(xml_text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise HTTPException(status_code=502, detail=f"Invalid Azure Blob API response: {exc}")

    blobs: list[dict[str, Any]] = []
    for blob in root.iter():
        if _xml_local_name(blob.tag) != "Blob":
            continue
        entry: dict[str, Any] = {"name": "", "size": 0, "last_modified": ""}
        for child in blob:
            tag = _xml_local_name(child.tag)
            if tag == "Name":
                entry["name"] = child.text or ""
            elif tag == "Properties":
                for prop in child:
                    prop_tag = _xml_local_name(prop.tag)
                    if prop_tag == "Content-Length":
                        try:
                            entry["size"] = int(prop.text or "0")
                        except ValueError:
                            entry["size"] = 0
                    elif prop_tag == "Last-Modified":
                        entry["last_modified"] = prop.text or ""
        if entry["name"]:
            blobs.append(entry)
    return blobs


def _build_reseed_command_payload(
    backup_config: BackupConfig,
    job_id: str,
    template_name: str,
    blob_url: str,
    vm_id: int,
) -> dict[str, Any]:
    return {
        "cmd_type": "reseed",
        "job_id": job_id,
        "blob_url": blob_url,
        "vm_id": vm_id,
        "template_name": template_name,
        "azure_account": backup_config.azure_account,
        "azure_container": backup_config.azure_container,
        "retry_max": 3,
    }


def _blob_last_modified_key(blob: dict[str, Any]) -> datetime:
    value = str(blob.get("last_modified") or "").strip()
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _build_spoke_command(command_id: str, command_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": command_id,
        "target": "spoke",
        "type": command_type,
        "payload": payload,
    }


async def _send_or_queue_reseed_command(
    tenant_id: str,
    spoke_id: str,
    job_id: str,
    command_payload: dict[str, Any],
    *,
    retry_count: int = 0,
) -> str:
    command_id = f"{job_id}-{spoke_id}-{retry_count}"
    command = _build_spoke_command(command_id, "reseed", dict(command_payload))
    if await send_spoke_command(tenant_id, spoke_id, command):
        return "sent"

    store.enqueue_command(
        Command(
            id=command_id,
            spoke_id=spoke_id,
            tenant_id=tenant_id,
            type="reseed",
            target="spoke",
            payload=dict(command_payload),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    )
    return "queued"


def _refresh_backup_job_status(job: dict[str, Any]) -> None:
    if job.get("type") == "reseed":
        spoke_states = [state.get("status") for state in job.get("spoke_status", {}).values()]
        if not spoke_states:
            job["status"] = "completed"
        elif all(state in _RESEED_SUCCESS_STATES for state in spoke_states):
            job["status"] = "completed"
        elif all(state in _RESEED_SUCCESS_STATES | _RESEED_ERROR_STATES for state in spoke_states):
            job["status"] = "failed" if any(state in _RESEED_ERROR_STATES for state in spoke_states) else "completed"
        else:
            job["status"] = "running"
        return

    vm_states = list(job.get("vm_status", {}).values())
    if vm_states and all(state["status"] in {"done", "error"} for state in vm_states):
        job["status"] = "failed" if any(state["status"] == "error" for state in vm_states) else "completed"


async def _retry_reseed_after_delay(job_id: str, tenant_id: str, spoke_id: str, retry_count: int) -> None:
    delay = _RESEED_RETRY_DELAYS.get(retry_count)
    if delay is None:
        return

    await asyncio.sleep(delay)
    job = backup_jobs.get(job_id)
    if not job or job.get("type") != "reseed":
        return

    spoke_state = job.get("spoke_status", {}).get(spoke_id)
    if not spoke_state or spoke_state.get("status") != "retrying" or spoke_state.get("retry_count") != retry_count:
        return

    dispatch_status = await _send_or_queue_reseed_command(
        tenant_id,
        spoke_id,
        job_id,
        job["command_payload"],
        retry_count=retry_count,
    )
    spoke_state.update(
        {
            "status": "running" if dispatch_status == "sent" else "queued",
            "step": "retry_sent" if dispatch_status == "sent" else "retry_queued",
            "last_retry_at": datetime.utcnow().isoformat(),
        }
    )
    _refresh_backup_job_status(job)
    await ws_broadcast({"type": "backup_progress", "job": job})


@router.get("/backup/config", response_model=BackupConfig)
def get_backup_config(_: User = Depends(auth.get_current_user)):
    return store.load_backup_config()


@router.post("/backup/config", response_model=BackupConfig)
def save_backup_config(payload: BackupConfig, current_user: User = Depends(auth.get_current_user)):
    _require_superadmin(current_user)
    store.save_backup_config(payload)
    return payload


@router.post("/backup/config/key")
def set_azure_key(
    payload: SetAzureKeyRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_superadmin(current_user)
    key = payload.azure_key.strip()
    if not key:
        raise HTTPException(status_code=422, detail="azure_key must not be empty")
    try:
        encrypted = crypto.encrypt_value(key)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    config = store.load_backup_config()
    config.azure_key_enc = encrypted
    store.save_backup_config(config)
    return {"detail": "Azure key encrypted and saved"}


@router.get("/backup/installer/sas-token")
async def get_installer_sas_token(request: Request):
    """
    Generate a short-lived read-only SAS token for the installer to download blobs.
    Authenticated via X-Installer-Key header (must match INSTALLER_API_KEY env var).
    """
    installer_key = os.environ.get("INSTALLER_API_KEY", "").strip()
    if not installer_key:
        raise HTTPException(status_code=503, detail="INSTALLER_API_KEY not configured on hub")
    provided = (request.headers.get("X-Installer-Key") or "").strip()
    if not provided or provided != installer_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Installer-Key")
    backup_config = store.load_backup_config()
    azure_key = _get_azure_key(backup_config)
    try:
        sas_url = crypto.generate_blob_container_sas(
            account_name=backup_config.azure_account,
            account_key=azure_key,
            container=backup_config.azure_container,
            permissions="rl",
            hours=2,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate SAS token: {exc}") from exc
    return {
        "sas_url": sas_url,
        "account": backup_config.azure_account,
        "container": backup_config.azure_container,
        "expires_in_hours": 2,
    }


@router.post("/backup/trigger/{tenant_id}/{spoke_id}")
async def trigger_backup(
    tenant_id: str,
    spoke_id: str,
    payload: TriggerBackupRequest,
    current_user: User = Depends(auth.get_current_user),
):
    _require_superadmin(current_user)

    spoke = store.get_spoke(tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")
    if spoke.status != "approved":
        raise HTTPException(status_code=409, detail="Spoke is not approved")

    backup_config = store.load_backup_config()
    spoke_config = backup_config.spokes.get(spoke_id)
    if not spoke_config or not spoke_config.vm_ids:
        raise HTTPException(status_code=400, detail="No VMs configured for this spoke")

    azure_key = payload.azure_key.strip()
    if not azure_key:
        azure_key = _get_azure_key(backup_config)

    job_id = f"backup-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
    vm_ids = list(spoke_config.vm_ids)
    command_payload = {
        "cmd_type": "backup",
        "vm_ids": vm_ids,
        "azure_account": backup_config.azure_account,
        "azure_container": backup_config.azure_container,
        "azure_key": azure_key,
        "retention": backup_config.retention,
        "spoke_id": spoke_id,
        "blob_prefix": f"{spoke_id}/{tenant_id}",
        "job_id": job_id,
    }
    backup_jobs[job_id] = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "spoke_id": spoke_id,
        "vm_ids": vm_ids,
        "started_at": datetime.utcnow().isoformat(),
        "status": "running",
        "vm_status": {
            vm_id: {"status": "pending", "pct": 0, "size": None, "file": None}
            for vm_id in vm_ids
        },
    }
    command = _build_spoke_command(job_id, "backup", command_payload)

    sent = False
    try:
        sent = await send_spoke_command(tenant_id, spoke_id, command)
    finally:
        payload.azure_key = ""
        command_payload.pop("azure_key", None)
        azure_key = ""

    if not sent:
        backup_jobs.pop(job_id, None)
        raise HTTPException(status_code=409, detail="Spoke is not connected")

    return {"job_id": job_id, "status": "triggered"}


@router.get("/backup/status")
def get_backup_status(current_user: User = Depends(auth.get_current_user)):
    _require_superadmin(current_user)
    return list(backup_jobs.values())


@router.get("/backup/status/{job_id}")
def get_backup_job_status(job_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_superadmin(current_user)
    return _get_backup_job(job_id)


@router.get("/backup/templates")
async def list_templates(_: User = Depends(auth.get_current_user)):
    backup_config = store.load_backup_config()
    url = f"https://{backup_config.azure_account}.blob.core.windows.net/{backup_config.azure_container}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, params={"restype": "container", "comp": "list"})
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Azure Blob API error: {exc.response.status_code}")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Azure Blob API request failed: {exc}")

    templates: dict[str, dict[str, Any]] = {}
    for blob in _parse_blob_entries(response.text):
        parts = blob["name"].split("/")
        template_name = parts[0] if len(parts) > 1 else blob["name"]
        current = templates.get(template_name)
        if current is None or _blob_last_modified_key(blob) > _blob_last_modified_key(current):
            templates[template_name] = {
                "name": template_name,
                "latest_blob": blob["name"],
                "size": blob["size"],
                "last_modified": blob["last_modified"],
            }

    return {"templates": sorted(templates.values(), key=lambda template: template["name"])}


@router.post("/backup/reseed")
async def trigger_reseed(
    tenant_id: str,
    req: ReseedRequest,
    current_user: User = Depends(auth.get_current_user),
):
    auth.require_tenant_access(tenant_id, current_user)
    backup_config = store.load_backup_config()

    if req.spoke_ids == ["all"]:
        spoke_ids = [spoke.id for spoke in store.list_spokes(tenant_id) if spoke.status == "approved"]
    else:
        spoke_ids = []
        for spoke_id in req.spoke_ids:
            spoke = store.get_spoke(tenant_id, spoke_id)
            if not spoke:
                raise HTTPException(status_code=404, detail=f"Spoke not found: {spoke_id}")
            if spoke.status != "approved":
                raise HTTPException(status_code=409, detail=f"Spoke is not approved: {spoke_id}")
            spoke_ids.append(spoke_id)

    if not spoke_ids:
        raise HTTPException(status_code=400, detail="No approved spokes available for reseed")

    job_id = str(uuid4())[:8]
    blob_url = (
        f"https://{backup_config.azure_account}.blob.core.windows.net/"
        f"{backup_config.azure_container}/{req.latest_blob}"
    )
    command_payload = _build_reseed_command_payload(
        backup_config,
        job_id,
        req.template_name,
        blob_url,
        req.vm_id,
    )

    backup_jobs[job_id] = {
        "job_id": job_id,
        "type": "reseed",
        "tenant_id": tenant_id,
        "template_name": req.template_name,
        "latest_blob": req.latest_blob,
        "blob_url": blob_url,
        "vm_id": req.vm_id,
        "started_at": datetime.utcnow().isoformat(),
        "status": "running",
        "command_payload": command_payload,
        "spoke_status": {
            spoke_id: {"status": "pending", "step": None, "retry_count": 0, "error": None}
            for spoke_id in spoke_ids
        },
    }

    job = backup_jobs[job_id]
    for spoke_id in spoke_ids:
        dispatch_status = await _send_or_queue_reseed_command(tenant_id, spoke_id, job_id, command_payload)
        job["spoke_status"][spoke_id].update(
            {
                "status": "running" if dispatch_status == "sent" else "queued",
                "step": "command_sent" if dispatch_status == "sent" else "queued_offline",
            }
        )

    return {"job_id": job_id, "spoke_count": len(spoke_ids)}


@router.post("/backup/progress")
async def update_backup_progress(payload: BackupProgressPayload, request: Request):
    if not _is_local_request(request):
        raise HTTPException(status_code=403, detail="Local access required")

    job = _get_backup_job(payload.job_id)
    if job.get("type") == "reseed":
        if not payload.spoke_id:
            raise HTTPException(status_code=400, detail="spoke_id is required for reseed progress")

        spoke_state = job.get("spoke_status", {}).get(payload.spoke_id)
        if spoke_state is None:
            raise HTTPException(status_code=404, detail="Spoke not found in reseed job")

        next_status = payload.status
        retry_count = int(spoke_state.get("retry_count", 0))
        if payload.status in _RESEED_ERROR_STATES:
            retry_count += 1
            if retry_count <= 3:
                next_status = "retrying"
                asyncio.create_task(
                    _retry_reseed_after_delay(job["job_id"], job["tenant_id"], payload.spoke_id, retry_count)
                )

        spoke_state.update(
            {
                "status": next_status,
                "step": payload.step,
                "error": payload.error,
                "retry_count": retry_count,
                "updated_at": datetime.utcnow().isoformat(),
            }
        )
        _refresh_backup_job_status(job)
        await ws_broadcast({"type": "backup_progress", "job": job})
        return {"status": "ok"}

    if payload.vm_id is None:
        raise HTTPException(status_code=400, detail="vm_id is required for backup progress")

    vm_state = job["vm_status"].get(payload.vm_id)
    if vm_state is None:
        raise HTTPException(status_code=404, detail="VM not found in backup job")

    vm_state.update(
        {
            "status": payload.status,
            "pct": payload.pct,
            "size": payload.size,
            "file": payload.file,
            "error": payload.error,
        }
    )

    _refresh_backup_job_status(job)
    await ws_broadcast({"type": "backup_progress", "job": job})
    return {"status": "ok"}


@router.get("/backup/blobs/{tenant_id}/{spoke_id}")
async def list_backup_blobs(tenant_id: str, spoke_id: str, current_user: User = Depends(auth.get_current_user)):
    _require_superadmin(current_user)

    spoke = store.get_spoke(tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")
    if spoke.status != "approved":
        raise HTTPException(status_code=409, detail="Spoke is not approved")

    backup_config = store.load_backup_config()
    prefix = f"{spoke_id}/{tenant_id}"
    url = f"https://{backup_config.azure_account}.blob.core.windows.net/{backup_config.azure_container}"

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                url,
                params={"restype": "container", "comp": "list", "prefix": prefix},
            )
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Azure Blob API error: {exc.response.status_code}")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Azure Blob API request failed: {exc}")

    return _parse_blob_entries(response.text)
