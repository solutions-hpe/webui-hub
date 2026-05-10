from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Optional

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


def hash_password(password: str) -> str:
    # bcrypt truncates at 72 bytes — enforce explicitly to avoid ValueError
    return pwd_context.hash(password.encode()[:72])


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain.encode()[:72], hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def authenticate_user(username: str, password: str) -> Optional[User]:
    user = store.get_user(username)
    if not user or not verify_password(password, user.hashed_password):
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
    except JWTError:
        raise exc
    user = store.get_user(username)
    if not user:
        raise exc
    return user


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    return _decode_token(token)


def get_optional_current_user(
    token: Annotated[Optional[str], Depends(oauth2_optional)],
) -> Optional[User]:
    if not token:
        return None
    try:
        return _decode_token(token)
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


def ensure_admin() -> None:
    """Bootstrap superadmin user on first start."""
    settings = get_settings()
    store.ensure_admin(
        username=settings.first_admin_username,
        hashed_password=hash_password(settings.first_admin_password),
    )
