from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    aruba_workspace_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ownership: Mapped[str] = mapped_column(String(32), nullable=False, default="local")
    aruba_config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notification_config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    central_poll_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    sites: Mapped[List["Site"]] = relationship("Site", back_populates="workspace")
    commands: Mapped[List["Command"]] = relationship("Command", back_populates="workspace")
    checks: Mapped[List["Check"]] = relationship("Check", back_populates="workspace", cascade="all, delete-orphan")


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    api_key: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, unique=True, index=True)
    workspace_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid, ForeignKey("workspaces.id"), nullable=True)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    telemetry_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    workspace: Mapped[Optional[Workspace]] = relationship("Workspace", back_populates="sites")
    commands: Mapped[List["Command"]] = relationship("Command", back_populates="site")


class Command(Base):
    __tablename__ = "commands"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    site_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid, ForeignKey("sites.id"), nullable=True, index=True)
    workspace_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid, ForeignKey("workspaces.id"), nullable=True, index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.utcnow() + timedelta(hours=1))
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    site: Mapped[Optional[Site]] = relationship("Site", back_populates="commands")
    workspace: Mapped[Optional[Workspace]] = relationship("Workspace", back_populates="commands")


class Check(Base):
    __tablename__ = "checks"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("workspaces.id"), nullable=False, index=True)
    check_name: Mapped[str] = mapped_column(String(255), nullable=False)
    check_type: Mapped[str] = mapped_column(String(32), nullable=False)
    timeout_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    last_confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_reported_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    workspace: Mapped[Workspace] = relationship("Workspace", back_populates="checks")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
