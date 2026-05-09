from __future__ import annotations

import json
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..database import get_db
from ..models import Command, Site, Workspace
from ..schemas import CommandCreate, CommandResponse, MessageResponse

router = APIRouter()


def _loads(raw: str | None):
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


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


def _serialize(command: Command) -> CommandResponse:
    return CommandResponse(
        id=command.id,
        site_id=command.site_id,
        workspace_id=command.workspace_id,
        target=command.target,
        type=command.type,
        payload=_loads(command.payload_json),
        status=command.status,
        created_at=command.created_at,
        expires_at=command.expires_at,
        delivered_at=command.delivered_at,
        executed_at=command.executed_at,
        result=_loads(command.result_json) if command.result_json else None,
    )


@router.get("", response_model=list[CommandResponse])
def list_commands(
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    _expire_commands(db)
    commands = db.scalars(select(Command).order_by(Command.created_at.desc()).limit(200)).all()
    return [_serialize(command) for command in commands]


@router.post("", response_model=CommandResponse, status_code=status.HTTP_201_CREATED)
def create_command(
    payload: CommandCreate,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    if payload.site_id and not db.get(Site, payload.site_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    if payload.workspace_id and not db.get(Workspace, payload.workspace_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")

    command = Command(
        site_id=payload.site_id,
        workspace_id=payload.workspace_id,
        target=payload.target,
        type=payload.type,
        payload_json=json.dumps(payload.payload or {}),
        status="queued",
    )
    db.add(command)
    db.commit()
    db.refresh(command)
    return _serialize(command)


@router.delete("/{command_id}", response_model=MessageResponse)
def delete_command(
    command_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    command = db.get(Command, command_id)
    if not command:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Command not found")

    db.delete(command)
    db.commit()
    return MessageResponse(message="Command deleted")
