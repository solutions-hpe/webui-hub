from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..database import get_db
from ..models import Workspace
from ..schemas import MessageResponse, WorkspaceCreate, WorkspaceResponse, WorkspaceUpdate

router = APIRouter()


def _loads(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


def _serialize(workspace: Workspace) -> WorkspaceResponse:
    return WorkspaceResponse(
        id=workspace.id,
        name=workspace.name,
        aruba_workspace_id=workspace.aruba_workspace_id,
        ownership=workspace.ownership,
        aruba_config=_loads(workspace.aruba_config),
        notification_config=_loads(workspace.notification_config),
        central_poll_enabled=workspace.central_poll_enabled,
        created_at=workspace.created_at,
    )


@router.get("", response_model=list[WorkspaceResponse])
def list_workspaces(
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    workspaces = db.scalars(select(Workspace).order_by(Workspace.created_at.desc())).all()
    return [_serialize(workspace) for workspace in workspaces]


@router.post("", response_model=WorkspaceResponse, status_code=status.HTTP_201_CREATED)
def create_workspace(
    payload: WorkspaceCreate,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    workspace = Workspace(
        name=payload.name,
        aruba_workspace_id=payload.aruba_workspace_id,
        ownership=payload.ownership,
        aruba_config=json.dumps(payload.aruba_config or {}),
        notification_config=json.dumps(payload.notification_config or {}),
        central_poll_enabled=payload.central_poll_enabled,
    )
    db.add(workspace)
    db.commit()
    db.refresh(workspace)
    return _serialize(workspace)


@router.get("/{workspace_id}", response_model=WorkspaceResponse)
def get_workspace(
    workspace_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    workspace = db.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
    return _serialize(workspace)


@router.patch("/{workspace_id}", response_model=WorkspaceResponse)
def update_workspace(
    workspace_id: uuid.UUID,
    payload: WorkspaceUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    workspace = db.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")

    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        if field in {"aruba_config", "notification_config"} and value is not None:
            setattr(workspace, field, json.dumps(value))
        else:
            setattr(workspace, field, value)

    db.commit()
    db.refresh(workspace)
    return _serialize(workspace)


@router.delete("/{workspace_id}", response_model=MessageResponse)
def delete_workspace(
    workspace_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    workspace = db.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")

    db.delete(workspace)
    db.commit()
    return MessageResponse(message="Workspace deleted")
