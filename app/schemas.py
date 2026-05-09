from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    created_at: datetime


class SiteRegisterRequest(BaseModel):
    hostname: str
    label: Optional[str] = None


class SiteRegisterResponse(BaseModel):
    site_id: uuid.UUID


class SiteBaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    workspace_id: Optional[uuid.UUID] = None
    label: Optional[str] = None
    status: str
    last_seen: Optional[datetime] = None
    created_at: datetime


class SiteDetailResponse(SiteBaseResponse):
    telemetry: Optional[Dict[str, Any]] = None


class ApproveSiteResponse(BaseModel):
    site_id: uuid.UUID
    api_key: str


class WorkspaceBase(BaseModel):
    name: str
    aruba_workspace_id: Optional[str] = None
    ownership: str = "local"
    aruba_config: Dict[str, Any] = Field(default_factory=dict)
    notification_config: Dict[str, Any] = Field(default_factory=dict)
    central_poll_enabled: bool = False


class WorkspaceCreate(WorkspaceBase):
    pass


class WorkspaceUpdate(BaseModel):
    name: Optional[str] = None
    aruba_workspace_id: Optional[str] = None
    ownership: Optional[str] = None
    aruba_config: Optional[Dict[str, Any]] = None
    notification_config: Optional[Dict[str, Any]] = None
    central_poll_enabled: Optional[bool] = None


class WorkspaceResponse(WorkspaceBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime


class CommandCreate(BaseModel):
    site_id: Optional[uuid.UUID] = None
    workspace_id: Optional[uuid.UUID] = None
    target: str
    type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class CommandResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    site_id: Optional[uuid.UUID] = None
    workspace_id: Optional[uuid.UUID] = None
    target: str
    type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    status: str
    created_at: datetime
    expires_at: datetime
    delivered_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None


class CommandAckRequest(BaseModel):
    command_id: uuid.UUID
    status: str = "executed"
    result: Optional[Dict[str, Any]] = None


class CheckCreate(BaseModel):
    workspace_id: uuid.UUID
    check_name: str
    check_type: str
    timeout_minutes: int = 60
    status: str = "unknown"
    last_confirmed_at: Optional[datetime] = None
    last_reported_at: Optional[datetime] = None


class CheckUpdate(BaseModel):
    check_name: Optional[str] = None
    check_type: Optional[str] = None
    timeout_minutes: Optional[int] = None
    status: Optional[str] = None
    last_confirmed_at: Optional[datetime] = None
    last_reported_at: Optional[datetime] = None


class CheckResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    check_name: str
    check_type: str
    timeout_minutes: int
    status: str
    last_confirmed_at: Optional[datetime] = None
    last_reported_at: Optional[datetime] = None
    created_at: datetime


class CheckStateResponse(BaseModel):
    summary: Dict[str, int]
    items: List[CheckResponse]
