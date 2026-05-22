from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Optional
from uuid import uuid4

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from . import store
from .config import get_settings
from .data_models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
oauth2_optional = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# ── Server boot nonce ──────────────────────────────────────────────────────────
# A random ID generated once when this module is first imported (i.e. at server
# startup).  Every JWT issued while the server is running embeds this value in a
# "bid" (boot-ID) claim.  When the server restarts (or is redeployed), a new
# nonce is generated and all previously issued tokens become invalid — their
# "bid" no longer matches, so callers receive a 401 and must log in again.
# This is intentional: redeployment should require re-authentication.
SERVER_BOOT_ID: str = str(uuid4())


def hash_password(password: str) -> str:
    # bcrypt truncates at 72 bytes — enforce explicitly to avoid ValueError
    return pwd_context.hash(password.encode()[:72])


def verify_password(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    return pwd_context.verify(plain.encode()[:72], hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode["exp"] = expire
    # Embed the server boot nonce so this token is only valid for the current
    # server instance.  Tokens from before a redeploy will fail validation.
    to_encode["bid"] = SERVER_BOOT_ID
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def authenticate_user(username: str, password: str) -> Optional[User]:
    user = store.get_user(username)
    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        return None
    return user


def _decode_token(token: str) -> User:
    settings = get_settings()
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username = payload.get("sub")
        if not username:
            raise exc
        # Validate boot nonce — reject tokens issued by a previous server instance
        # (e.g. before a redeploy).  Missing "bid" is also treated as invalid so
        # that old tokens issued before this feature was deployed are rejected cleanly.
        if payload.get("bid") != SERVER_BOOT_ID:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired after server restart — please log in again",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise exc
    user = store.get_user(username)
    if not user:
        raise exc
    return user


def decode_access_token(token: str) -> User:
    return _decode_token(token)


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    return decode_access_token(token)


def get_optional_current_user(
    token: Annotated[Optional[str], Depends(oauth2_optional)],
) -> Optional[User]:
    if not token:
        return None
    try:
        return decode_access_token(token)
    except HTTPException:
        return None


def require_superadmin(user: User = Depends(get_current_user)) -> User:
    if not user.is_superadmin:
        raise HTTPException(status_code=403, detail="Superadmin required")
    return user


def require_tenant_access(tenant_id: str, user: User = Depends(get_current_user)) -> User:
    if user.is_superadmin:
        return user
    if tenant_id not in user.tenant_ids():
        raise HTTPException(status_code=403, detail="Access denied to this tenant")
    return user


def require_tenant_member(tenant_id: str, user: User) -> User:
    """Like require_tenant_access but explicitly blocks superadmin.

    Use this for remote-control endpoints (proxmox-command, console, spoke shell)
    where only an explicit tenant member should be allowed — even superadmin cannot
    remote-control a tenant's infrastructure they are not a member of.
    """
    if tenant_id not in user.tenant_ids():
        raise HTTPException(
            status_code=403,
            detail="Remote control is restricted to tenant members only",
        )
    return user


def ensure_admin() -> None:
    """Bootstrap superadmin user on first start."""
    import os
    settings = get_settings()
    # force_password=True when ADMIN_PASSWORD was explicitly set in the environment
    # so operators can reset credentials by changing the env var and restarting.
    force_password = bool(os.environ.get("ADMIN_PASSWORD") or os.environ.get("FIRST_ADMIN_PASSWORD"))
    store.ensure_admin(
        username=settings.first_admin_username,
        hashed_password=hash_password(settings.first_admin_password),
        force_password=force_password,
    )
