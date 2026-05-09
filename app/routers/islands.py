from __future__ import annotations

import json
import uuid
from datetime import datetime

from fastapi import APIRouter, Body, Depends, Header, HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Command, Site
from ..schemas import CommandAckRequest, MessageResponse, SiteRegisterRequest, SiteRegisterResponse

router = APIRouter()


def _parse_json(raw: str | None):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


def get_island_by_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> Site:
    site = db.scalar(select(Site).where(Site.api_key == x_api_key))
    if not site or site.status != "approved":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid island API key")
    return site


def _expire_commands(db: Session) -> None:
    now = datetime.utcnow()
    expired = db.scalars(
        select(Command).where(
            Command.status.in_(["queued", "delivered"]),
            Command.expires_at <= now,
        )
    ).all()
    for command in expired:
        command.status = "expired"
    if expired:
        db.commit()


def _command_targets_site(command: Command, site: Site) -> bool:
    if command.site_id and command.site_id == site.id:
        return True
    if command.target == "all":
        return True
    if command.target == site.hostname:
        return True
    if command.target == "proxmox" and "proxmox" in site.hostname.lower():
        return True
    return False


@router.post("/register", response_model=SiteRegisterResponse, status_code=status.HTTP_201_CREATED)
def register_island(payload: SiteRegisterRequest, db: Session = Depends(get_db)):
    site = db.scalar(select(Site).where(Site.hostname == payload.hostname))
    if site:
        site.label = payload.label or site.label
        if site.status == "revoked":
            site.status = "pending"
            site.api_key = None
        db.commit()
        db.refresh(site)
        return SiteRegisterResponse(site_id=site.id)

    site = Site(hostname=payload.hostname, label=payload.label, status="pending")
    db.add(site)
    db.commit()
    db.refresh(site)
    return SiteRegisterResponse(site_id=site.id)


@router.post("/{site_id}/telemetry", response_model=MessageResponse)
def push_telemetry(
    site_id: uuid.UUID,
    telemetry: dict = Body(...),
    site: Site = Depends(get_island_by_api_key),
    db: Session = Depends(get_db),
):
    if site.id != site_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Island ID and API key do not match")

    site.telemetry_json = json.dumps(telemetry)
    site.last_seen = datetime.utcnow()
    db.commit()
    return MessageResponse(message="Telemetry accepted")


@router.get("/{site_id}/inbox")
def get_inbox(
    site_id: uuid.UUID,
    site: Site = Depends(get_island_by_api_key),
    db: Session = Depends(get_db),
):
    if site.id != site_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Island ID and API key do not match")

    _expire_commands(db)
    commands = db.scalars(
        select(Command).where(
            and_(
                Command.status == "queued",
                or_(Command.site_id.is_(None), Command.site_id == site.id),
                or_(Command.workspace_id.is_(None), Command.workspace_id == site.workspace_id),
            )
        ).order_by(Command.created_at.asc())
    ).all()

    now = datetime.utcnow()
    results = []
    delivered = False
    for command in commands:
        if not _command_targets_site(command, site):
            continue
        command.status = "delivered"
        command.delivered_at = now
        delivered = True
        results.append(
            {
                "id": str(command.id),
                "site_id": str(command.site_id) if command.site_id else None,
                "workspace_id": str(command.workspace_id) if command.workspace_id else None,
                "target": command.target,
                "type": command.type,
                "payload": _parse_json(command.payload_json) or {},
                "created_at": command.created_at.isoformat(),
                "expires_at": command.expires_at.isoformat(),
            }
        )
    if delivered:
        db.commit()

    return {"commands": results}


@router.post("/{site_id}/ack", response_model=MessageResponse)
def ack_command(
    site_id: uuid.UUID,
    payload: CommandAckRequest,
    site: Site = Depends(get_island_by_api_key),
    db: Session = Depends(get_db),
):
    if site.id != site_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Island ID and API key do not match")

    command = db.get(Command, payload.command_id)
    if not command:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Command not found")
    if command.site_id and command.site_id != site.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Command does not belong to this island")

    command.status = payload.status if payload.status in {"queued", "delivered", "executed", "expired"} else "executed"
    command.executed_at = datetime.utcnow()
    command.result_json = json.dumps(payload.result or {})
    db.commit()
    return MessageResponse(message="Command acknowledged")
