from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from .. import auth, store
from ..config import get_settings

ALL_PROVIDERS = ["password", "oidc", "ldap", "radius"]
IMPLEMENTED_PROVIDERS = {"password"}

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    username: str
    is_superadmin: bool
    tenant_roles: list[dict[str, str]]


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.get("/providers")
def list_auth_providers():
    from ..auth_providers import get_enabled_providers

    enabled = get_enabled_providers()
    active = [provider for provider in enabled if provider in IMPLEMENTED_PROVIDERS]
    return {"providers": ALL_PROVIDERS, "active": active}


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest):
    from ..auth_providers import AuthProviderError, get_enabled_providers, ldap_authenticate, radius_authenticate

    settings = get_settings()
    user = auth.authenticate_user(payload.username, payload.password)

    if not user and settings.ldap_enabled:
        try:
            user = await ldap_authenticate(payload.username, payload.password)
        except AuthProviderError:
            pass

    if not user and settings.radius_enabled:
        try:
            user = await radius_authenticate(payload.username, payload.password)
        except AuthProviderError:
            pass

    if not user:
        enabled = get_enabled_providers()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Invalid username or password",
                "providers": ALL_PROVIDERS,
                "active": [provider for provider in enabled if provider in IMPLEMENTED_PROVIDERS],
            },
        )

    token = auth.create_access_token(
        {"sub": user.username},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserResponse)
def me(current_user=Depends(auth.get_current_user)):
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        is_superadmin=current_user.is_superadmin,
        tenant_roles=current_user.tenant_roles,
    )


@router.post("/change-password")
def change_password(payload: ChangePasswordRequest, current_user=Depends(auth.get_current_user)):
    if not auth.verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
    current_user.hashed_password = auth.hash_password(payload.new_password)
    store.save_user(current_user)
    return {"status": "ok", "message": "Password updated"}
