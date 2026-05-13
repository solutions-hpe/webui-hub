"""Pydantic models that define Hub persistence objects in the JSON store.

These schemas replace the old SQLAlchemy models from the legacy application.
Instances are serialized directly to JSON files under ``/data`` for users,
tenants, islands, command queues, and audit history, while still giving the
application validated types and default factories.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class User(BaseModel):
    id: str = Field(default_factory=_uuid)
    username: str
    hashed_password: str
    is_superadmin: bool = False
    tenant_roles: list[dict[str, str]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)

    def get_role(self, tenant_id: str) -> Optional[str]:
        for tr in self.tenant_roles:
            if tr["tenant_id"] == tenant_id:
                return tr["role"]
        return None

    def tenant_ids(self) -> list[str]:
        return [tr["tenant_id"] for tr in self.tenant_roles]


class ProcessingMode(BaseModel):
    """Processing mode config — centralized or distributed per feature."""

    global_mode: str = "centralized"
    aruba_polling: Optional[str] = None
    teams_webhook: Optional[str] = None
    email: Optional[str] = None
    heartbeat: Optional[str] = None
    gkill: Optional[str] = None
    schedules: Optional[str] = None
    repo_sync: Optional[str] = None

    def resolve(self, feature: str) -> str:
        val = getattr(self, feature, None)
        return val if val else self.global_mode


class Tenant(BaseModel):
    id: str = Field(default_factory=_uuid)
    name: str
    aruba_cid: Optional[str] = None
    aruba_config_enc: Optional[str] = None
    notification_config_enc: Optional[str] = None
    github_config_enc: Optional[str] = None
    default_processing_mode: ProcessingMode = Field(default_factory=ProcessingMode)
    processing_modes: dict[str, str] = Field(default_factory=lambda: {
        "central_api": "centralized",
        "teams": "centralized",
        "email": "centralized",
    })
    hub_config_enabled: bool = False
    hub_config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_now)
    created_by: str = ""


class Spoke(BaseModel):
    id: str = Field(default_factory=_uuid)
    tenant_id: str
    hostname: str
    label: str = ""
    spoke_name: str = ""
    status: str = "pending"
    api_key_enc: Optional[str] = None
    seed_config: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    processing_mode: ProcessingMode = Field(default_factory=ProcessingMode)
    config_version: int = 0
    applied_config_version: int = 0
    last_config_applied_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    telemetry: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_now)


class PendingSpoke(BaseModel):
    """Spoke registration before tenant assignment."""

    id: str = Field(default_factory=_uuid)
    hostname: str
    label: str = ""
    spoke_name: str = ""
    tenant_hint: str = ""  # Tenant ID the spoke pre-registered for (may be empty)
    seed_config: dict[str, Any] = Field(default_factory=dict)
    registered_at: datetime = Field(default_factory=_now)
    last_seen: Optional[datetime] = None


class Command(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=_uuid)
    spoke_id: str = Field(validation_alias=AliasChoices("spoke_id", "island_id"), serialization_alias="spoke_id")
    tenant_id: str
    target: str = "spoke"
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    status: str = "queued"
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime
    delivered_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    result: Optional[dict[str, Any]] = None


class AuditEntry(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=_uuid)
    spoke_id: str = Field(validation_alias=AliasChoices("spoke_id", "island_id"), serialization_alias="spoke_id")
    tenant_id: str
    task_type: str
    execution_mode: str
    status: str
    detail: str = ""
    initiated_by: str = ""
    result: Optional[dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=_now)


class SpokeBackupConfig(BaseModel):
    vm_ids: list[int] = Field(default_factory=list)


class BackupConfig(BaseModel):
    spokes: dict[str, SpokeBackupConfig] = Field(default_factory=dict)
    retention: int = 3
    azure_account: str = "csvmstorage"
    azure_container: str = "vms"
    azure_key_enc: str = "gAAAAABqBJh3Y-hvGAVJXju-Cp2qBDjR73zbyYoJ1ukCCd2JoWbYhemtXxlTVdHmYqOrKs9NjfAvNGnD1s-mC7MA8hDN8jE2-smgeh_SHeqCTXzIqi1GwWV82gf-kQNe_j6OgO7CeXMZeWHOjTgV1Q780Z0yRsQ5KCZAiaJdMy7doyqd8sQnR-ZGBeaxHXQJmXs2tlX-bkWo"
