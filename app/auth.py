from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import SessionLocal, get_db
from .models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
oauth2_optional = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = db.scalar(select(User).where(User.username == username))
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def _decode_token(token: str, db: Session) -> User:
    settings = get_settings()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError as exc:
        raise credentials_exception from exc

    user = db.scalar(select(User).where(User.username == username))
    if not user:
        raise credentials_exception
    return user


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
) -> User:
    return _decode_token(token, db)


def get_optional_current_user(
    token: Annotated[Optional[str], Depends(oauth2_optional)],
    db: Session = Depends(get_db),
) -> Optional[User]:
    if not token:
        return None
    try:
        return _decode_token(token, db)
    except HTTPException:
        return None


def ensure_admin() -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        user_count = db.scalar(select(func.count()).select_from(User)) or 0
        if user_count == 0:
            db.add(User(username=settings.first_admin_username, hashed_password=hash_password(settings.first_admin_password)))
            db.commit()
    finally:
        db.close()
