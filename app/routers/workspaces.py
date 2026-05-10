from fastapi import APIRouter, Depends, HTTPException, status

from .. import auth, store
from ..data_models import User

router = APIRouter()


@router.get("/workspaces")
def list_workspaces():
    return []


@router.post("/workspaces", status_code=status.HTTP_501_NOT_IMPLEMENTED)
def create_workspace():
    return {"detail": "Not implemented yet"}


@router.get("/{tenant_id}/workspaces")
def get_tenant_workspaces(tenant_id: str, current_user: User = Depends(auth.get_current_user)):
    auth.require_tenant_access(tenant_id, current_user)
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {
        "items": [
            {
                "id": tenant.id,
                "name": tenant.name,
                "tenant_id": tenant.id,
                "aruba_cid": tenant.aruba_cid,
                "created_at": tenant.created_at,
            }
        ]
    }
