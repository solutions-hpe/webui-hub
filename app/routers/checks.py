from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..database import get_db
from ..models import Check, Workspace
from ..schemas import CheckCreate, CheckResponse, CheckStateResponse, CheckUpdate, MessageResponse

router = APIRouter()


def _serialize(check: Check) -> CheckResponse:
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


@router.get("", response_model=list[CheckResponse])
def list_checks(
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    checks = db.scalars(select(Check).order_by(Check.created_at.desc())).all()
    return [_serialize(check) for check in checks]


@router.post("", response_model=CheckResponse, status_code=status.HTTP_201_CREATED)
def create_check(
    payload: CheckCreate,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    if not db.get(Workspace, payload.workspace_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")

    check = Check(**payload.model_dump())
    db.add(check)
    db.commit()
    db.refresh(check)
    return _serialize(check)


@router.patch("/{check_id}", response_model=CheckResponse)
def update_check(
    check_id: uuid.UUID,
    payload: CheckUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    check = db.get(Check, check_id)
    if not check:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Check not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(check, field, value)

    db.commit()
    db.refresh(check)
    return _serialize(check)


@router.delete("/{check_id}", response_model=MessageResponse)
def delete_check(
    check_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    check = db.get(Check, check_id)
    if not check:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Check not found")

    db.delete(check)
    db.commit()
    return MessageResponse(message="Check deleted")


@router.get("/state", response_model=CheckStateResponse)
def get_check_state(
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    checks = db.scalars(select(Check).order_by(Check.created_at.desc())).all()
    items = [_serialize(check) for check in checks]
    summary: dict[str, int] = {}
    for item in items:
        summary[item.status] = summary.get(item.status, 0) + 1
    return CheckStateResponse(summary=summary, items=items)
