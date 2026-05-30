from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Annotated, Optional
from uuid import uuid4

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

from . import store
from .config import get_settings
from .data_models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
oauth2_optional = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# ── Server boot nonce ──────────────────────────────────────────────────────────
# All gunicorn workers must agree on the same boot ID.  Using a per-process
# uuid4() causes cross-worker 401 failures: login hits worker A, /me hits
# worker B, the IDs differ, the token is rejected, and the user is immediately
# logged out again.
#
# Solution: derive the ID from APP_VERSION (the git SHA injected at build time
# via the Docker ARG / ENV pipeline).  All workers in the same container share
# the same env, so they all compute the same value.  When the container is
# rebuilt and redeployed the SHA changes → all previously issued tokens become
# invalid and users are prompted to re-authenticate.  If APP_VERSION is not set
# (local dev), fall back to a uuid4 so behaviour is still correct for that
# single-process case.
import os as _os
from pathlib import Path as _Path

def _get_boot_id() -> str:
    # All gunicorn workers must use the same boot ID or cross-worker 401s occur.
    # The VERSION file is baked into the image by redeploy-prod.sh (contains the
    # git SHA at deploy time) — identical for every worker process in the same
    # container.  A redeploy writes a new SHA → old tokens are invalidated.
    # Falls back to APP_VERSION env var, then uuid4 for local single-process dev.
    version_file = _Path(__file__).resolve().parent.parent / "VERSION"
    try:
        content = version_file.read_text().strip()
        if content and content not in ("dev", ""):
            return content
    except Exception:
        pass
    env_ver = _os.getenv("APP_VERSION", "").strip()
    if env_ver:
        return env_ver
    # Local dev only — single process so no cross-worker issue.
    return str(uuid4())

SERVER_BOOT_ID: str = _get_boot_id()


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


# ── QA runner token ────────────────────────────────────────────────────────────
# QA API keys are tenant-scoped and superadmin-generated.  Exchanging a valid
# key via POST /api/qa/auth returns a short-lived JWT that grants read-only
# access to exactly one tenant.  The JWT sub is "__qa_runner__" so _decode_token
# constructs a synthetic User without a database lookup.

_QA_RUNNER_SUB = "__qa_runner__"
_QA_TOKEN_EXPIRE_MINUTES = 120  # 2 hours — long enough for a full QA run


def create_qa_runner_token(tenant_id: str, key_id: str) -> str:
    """Issue a short-lived JWT scoped to a single tenant for the QA runner."""
    return create_access_token(
        {"sub": _QA_RUNNER_SUB, "qa_tenant": tenant_id, "qa_key_id": key_id},
        expires_delta=timedelta(minutes=_QA_TOKEN_EXPIRE_MINUTES),
    )


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

    # Synthetic QA runner user — tenant-scoped, read-only, no DB lookup needed.
    if username == _QA_RUNNER_SUB:
        qa_tenant = payload.get("qa_tenant", "")
        if not qa_tenant:
            raise exc
        return User(
            id="__qa_runner__",
            username="__qa_runner__",
            is_superadmin=False,
            hashed_password="",
            tenant_roles=[{"tenant_id": qa_tenant, "role": "viewer"}],
        )

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


def require_tenant_admin(tenant_id: str, user: User = Depends(get_current_user)) -> User:
    """Require tenant admin (or superadmin) role — viewers are rejected."""
    if user.is_superadmin:
        return user
    role = user.get_role(tenant_id)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Tenant admin role required")
    return user


def require_tenant_member(tenant_id: str, user: User) -> User:
    """Like require_tenant_access but requires explicit tenant membership.

    Use this for remote-control endpoints (proxmox-command, console, spoke shell)
    where only an explicit tenant member should normally be allowed.  Superadmins
    are permitted but their actions are audit-logged as a warning.
    """
    if user.is_superadmin:
        logger.warning(
            "Superadmin '%s' remote-controlling tenant %s infrastructure "
            "(not an explicit tenant member — add them as a tenant member to suppress this)",
            user.username,
            tenant_id,
        )
        return user
    if tenant_id not in user.tenant_ids():
        raise HTTPException(
            status_code=403,
            detail=(
                "Remote control is restricted to explicit tenant members. "
                "Ask a superadmin to add your account to this tenant with admin role."
            ),
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
