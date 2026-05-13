from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
import xml.etree.ElementTree as ET

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .. import auth, store
from ..data_models import BackupConfig, User
from ..ws import send_spoke_command, ws_broadcast

router = APIRouter()
backup_jobs: dict[str, dict[str, Any]] = {}
_LOCALHOSTS = {"127.0.0.1", "::1", "localhost"}


class TriggerBackupRequest(BaseModel):
    azure_key: str


class BackupProgressPayload(BaseModel):
    job_id: str
    vm_id: int
    status: str
    pct: int = 0
    size: Optional[int] = None
    file: Optional[str] = None
    error: Optional[str] = None


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


@router.get("/backup/config", response_model=BackupConfig)
def get_backup_config(_: User = Depends(auth.get_current_user)):
    return store.load_backup_config()


@router.post("/backup/config", response_model=BackupConfig)
def save_backup_config(payload: BackupConfig, current_user: User = Depends(auth.get_current_user)):
    _require_superadmin(current_user)
    store.save_backup_config(payload)
    return payload


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
        raise HTTPException(status_code=400, detail="Azure key is required")

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
    command = {
        "id": job_id,
        "target": "spoke",
        "type": "backup",
        "payload": command_payload,
    }

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


@router.post("/backup/progress")
async def update_backup_progress(payload: BackupProgressPayload, request: Request):
    if not _is_local_request(request):
        raise HTTPException(status_code=403, detail="Local access required")

    job = _get_backup_job(payload.job_id)
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

    vm_states = list(job["vm_status"].values())
    if vm_states and all(state["status"] in {"done", "error"} for state in vm_states):
        job["status"] = "failed" if any(state["status"] == "error" for state in vm_states) else "completed"

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

    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as exc:
        raise HTTPException(status_code=502, detail=f"Invalid Azure Blob API response: {exc}")

    blobs: list[dict[str, Any]] = []
    for blob in root.iter():
        if _xml_local_name(blob.tag) != "Blob":
            continue
        entry: dict[str, Any] = {"name": None, "size": None, "last_modified": None}
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
                            entry["size"] = None
                    elif prop_tag == "Last-Modified":
                        entry["last_modified"] = prop.text or ""
        if entry["name"]:
            blobs.append(entry)

    return blobs
