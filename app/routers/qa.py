"""QA router — token exchange and QA-specific endpoints.

POST /api/qa/auth
    Exchange a tenant-scoped QA API key for a short-lived JWT.
    The JWT grants read-only access to the key's tenant and is used by the
    QA runner for all subsequent API calls.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import auth, store

router = APIRouter()


class _QAAuthRequest(BaseModel):
    qa_api_key: str


@router.post("/qa/auth")
def qa_auth(body: _QAAuthRequest):
    """Exchange a QA API key for a short-lived, tenant-scoped JWT.

    The returned token is valid for 2 hours and grants read-only access to the
    tenant the key was created for.  Pass it as a standard Bearer token in the
    ``Authorization`` header for all QA runner calls.

    Returns 401 if the key is invalid or has been revoked.
    """
    qa_key = store.validate_qa_api_key(body.qa_api_key)
    if not qa_key:
        raise HTTPException(status_code=401, detail="Invalid or revoked QA API key")

    token = auth.create_qa_runner_token(
        tenant_id=qa_key.tenant_id,
        key_id=qa_key.id,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "tenant_id": qa_key.tenant_id,
        "expires_in_minutes": auth._QA_TOKEN_EXPIRE_MINUTES,
    }
