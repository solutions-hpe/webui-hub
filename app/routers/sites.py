from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..database import get_db
from ..models import Site
from ..schemas import ApproveSiteResponse, MessageResponse, SiteDetailResponse

router = APIRouter()


def _parse_json_blob(raw: str | None):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


def _serialize_site(site: Site) -> SiteDetailResponse:
    return SiteDetailResponse(
        id=site.id,
        hostname=site.hostname,
        workspace_id=site.workspace_id,
        label=site.label,
        status=site.status,
        last_seen=site.last_seen,
        created_at=site.created_at,
        telemetry=_parse_json_blob(site.telemetry_json),
    )


@router.get("", response_model=list[SiteDetailResponse])
def list_sites(
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_optional_current_user),
):
    sites = db.scalars(select(Site).order_by(Site.created_at.desc())).all()
    return [_serialize_site(site) for site in sites]


@router.get("/{site_id}", response_model=SiteDetailResponse)
def get_site(
    site_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    return _serialize_site(site)


@router.post("/{site_id}/approve", response_model=ApproveSiteResponse)
def approve_site(
    site_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")

    site.status = "approved"
    site.api_key = str(uuid.uuid4())
    db.commit()
    db.refresh(site)
    return ApproveSiteResponse(site_id=site.id, api_key=site.api_key)


@router.post("/{site_id}/revoke", response_model=MessageResponse)
def revoke_site(
    site_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")

    site.status = "revoked"
    site.api_key = None
    db.commit()
    return MessageResponse(message="Site revoked")


@router.delete("/{site_id}", response_model=MessageResponse)
def delete_site(
    site_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user),
):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")

    db.delete(site)
    db.commit()
    return MessageResponse(message="Site deleted")
