from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..auth import get_current_user
from ..database import get_db
from ..models import Check, Command, Site, Workspace
from ..schemas import (
    CheckResponse,
    CommandResponse,
    MessageResponse,
    SiteBaseResponse,
    WorkspaceCreate,
    WorkspaceDetail,
    WorkspaceResponse,
    WorkspaceUpdate,
)

router = APIRouter(prefix="/api/admin/workspaces")


def _loads(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


def _serialize_site(site: Site) -> SiteBaseResponse:
    return SiteBaseResponse(
        id=site.id,
        hostname=site.hostname,
        workspace_id=site.workspace_id,
        label=site.label,
        status=site.status,
        last_seen=site.last_seen,
        created_at=site.created_at,
        telemetry=_loads(site.telemetry_json) if site.telemetry_json else None,
    )


def _serialize_check(check: Check) -> CheckResponse:
    return CheckResponse(
        id=check.id,
        workspace_id=check.workspace_id,
        check_name=check.check_name,
        check_type=check.check_type,
        timeout_minutes=check.timeout_minutes,
        status=check.status,
        last_confirmed_at=check.last_confirmed_at,
        last_reported_at=check.last_reported_at,
        created_at=check.created_at,
    )


def _serialize_command(command: Command) -> CommandResponse:
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


def _build_check_summary(checks: list[Check]) -> dict[str, int]:
    return {
        "green": sum(1 for check in checks if check.status == "green"),
        "yellow": sum(1 for check in checks if check.status == "yellow"),
        "red": sum(1 for check in checks if check.status == "red"),
    }


def _serialize_workspace(workspace: Workspace) -> WorkspaceResponse:
    return WorkspaceResponse(
        id=workspace.id,
        name=workspace.name,
        aruba_workspace_id=workspace.aruba_workspace_id,
        ownership=workspace.ownership,
        aruba_config=_loads(workspace.aruba_config),
        notification_config=_loads(workspace.notification_config),
        central_poll_enabled=workspace.central_poll_enabled,
        created_at=workspace.created_at,
        site_count=len(workspace.sites),
        check_summary=_build_check_summary(workspace.checks),
    )


def _get_workspace_or_404(db: Session, workspace_id: uuid.UUID) -> Workspace:
    workspace = db.scalar(
        select(Workspace)
        .options(
            selectinload(Workspace.sites),
            selectinload(Workspace.checks),
            selectinload(Workspace.commands),
        )
        .where(Workspace.id == workspace_id)
    )
    if not workspace:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
    return workspace


@router.get("", response_model=list[WorkspaceResponse])
async def list_workspaces(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    workspaces = db.scalars(
        select(Workspace)
        .options(selectinload(Workspace.sites), selectinload(Workspace.checks))
        .order_by(Workspace.created_at.desc())
    ).all()
    return [_serialize_workspace(workspace) for workspace in workspaces]


@router.post("", response_model=WorkspaceResponse, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    payload: WorkspaceCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
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
    return _serialize_workspace(workspace)


@router.get("/{workspace_id}", response_model=WorkspaceDetail)
async def get_workspace(
    workspace_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    workspace = _get_workspace_or_404(db, workspace_id)
    recent_commands = sorted(workspace.commands, key=lambda command: command.created_at, reverse=True)[:10]
    return WorkspaceDetail(
        **_serialize_workspace(workspace).model_dump(),
        sites=[_serialize_site(site) for site in sorted(workspace.sites, key=lambda site: site.created_at, reverse=True)],
        checks=[_serialize_check(check) for check in sorted(workspace.checks, key=lambda check: check.created_at, reverse=True)],
        recent_commands=[_serialize_command(command) for command in recent_commands],
    )


@router.put("/{workspace_id}", response_model=WorkspaceResponse)
async def update_workspace(
    workspace_id: uuid.UUID,
    payload: WorkspaceUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    workspace = _get_workspace_or_404(db, workspace_id)
    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        if field in {"aruba_config", "notification_config"} and value is not None:
            setattr(workspace, field, json.dumps(value))
        else:
            setattr(workspace, field, value)
    db.commit()
    db.refresh(workspace)
    return _serialize_workspace(workspace)


@router.delete("/{workspace_id}", response_model=MessageResponse)
async def delete_workspace(
    workspace_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    workspace = _get_workspace_or_404(db, workspace_id)
    db.delete(workspace)
    db.commit()
    return MessageResponse(message="Workspace deleted")
