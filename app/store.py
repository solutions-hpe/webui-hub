"""Thread-safe JSON-backed data access layer for Hub.

The application does not use PostgreSQL, SQLite, or any ORM. Instead, all
persistent state is stored as JSON files under ``DATA_DIR`` and accessed through
this module. Callers should treat this file as the single read/write boundary
for users, tenants, spokes, command queues, and audit history. A process-local
re-entrant lock protects multi-step file operations so concurrent FastAPI
requests and background tasks do not corrupt on-disk state.
"""
from __future__ import annotations

import json
import shutil
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .config import get_settings
from .crypto import decrypt_str, encrypt_str, generate_api_key
from .data_models import AuditEntry, Command, Spoke, PendingSpoke, Tenant, User

_lock = threading.RLock()


def _data_dir() -> Path:
    return Path(get_settings().data_dir)


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, default=str)
    tmp.replace(path)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _users_path() -> Path:
    return _data_dir() / "users.json"


def _load_users() -> list[User]:
    raw = _read_json(_users_path()) or []
    return [User(**u) for u in raw]


def _save_users(users: list[User]) -> None:
    _write_json(_users_path(), [u.model_dump(mode="json") for u in users])


def get_user(username: str) -> Optional[User]:
    with _lock:
        for u in _load_users():
            if u.username == username:
                return u
    return None


def get_user_by_id(user_id: str) -> Optional[User]:
    with _lock:
        for u in _load_users():
            if u.id == user_id:
                return u
    return None


def list_users() -> list[User]:
    with _lock:
        return _load_users()


def save_user(user: User) -> None:
    with _lock:
        users = _load_users()
        users = [u for u in users if u.id != user.id]
        users.append(user)
        _save_users(users)


def delete_user(user_id: str) -> None:
    with _lock:
        users = [u for u in _load_users() if u.id != user_id]
        _save_users(users)


def ensure_admin(username: str, hashed_password: str, force_password: bool = False) -> None:
    """Create or update the bootstrap superadmin.

    If the store has no users, create the superadmin unconditionally.
    If ``force_password`` is True (i.e. ADMIN_PASSWORD was explicitly set in
    the environment), always update the superadmin's password so operators can
    reset credentials by changing the env var and restarting the container.
    """
    with _lock:
        users = _load_users()
        if not users:
            admin = User(username=username, hashed_password=hashed_password, is_superadmin=True)
            _save_users([admin])
            return
        if force_password:
            for user in users:
                if user.username == username and user.is_superadmin:
                    user.hashed_password = hashed_password
                    _save_users(users)
                    break


def _tenants_path() -> Path:
    return _data_dir() / "tenants.json"


def _load_tenants() -> list[Tenant]:
    raw = _read_json(_tenants_path()) or []
    return [Tenant(**t) for t in raw]


def _save_tenants(tenants: list[Tenant]) -> None:
    _write_json(_tenants_path(), [t.model_dump(mode="json") for t in tenants])


def get_tenant(tenant_id: str) -> Optional[Tenant]:
    with _lock:
        for t in _load_tenants():
            if t.id == tenant_id:
                return t
    return None


def list_tenants() -> list[Tenant]:
    with _lock:
        return _load_tenants()


def save_tenant(tenant: Tenant) -> None:
    with _lock:
        tenants = _load_tenants()
        tenants = [t for t in tenants if t.id != tenant.id]
        tenants.append(tenant)
        _save_tenants(tenants)


def delete_tenant(tenant_id: str) -> None:
    with _lock:
        tenants = [t for t in _load_tenants() if t.id != tenant_id]
        _save_tenants(tenants)

        users = _load_users()
        changed = False
        for user in users:
            updated_roles = [tr for tr in user.tenant_roles if tr["tenant_id"] != tenant_id]
            if len(updated_roles) != len(user.tenant_roles):
                user.tenant_roles = updated_roles
                changed = True
        if changed:
            _save_users(users)

        tenant_dir = _data_dir() / tenant_id
        if tenant_dir.exists():
            shutil.rmtree(tenant_dir)


def _pending_dir() -> Path:
    return _data_dir() / "pending"


def get_pending_spoke(spoke_id: str) -> Optional[PendingIsland]:
    with _lock:
        raw = _read_json(_pending_dir() / f"{spoke_id}.json")
        return PendingIsland(**raw) if raw else None


def list_pending_spokes() -> list[PendingIsland]:
    with _lock:
        d = _pending_dir()
        if not d.exists():
            return []
        results = []
        for f in d.glob("*.json"):
            raw = _read_json(f)
            if raw:
                results.append(PendingIsland(**raw))
        return results


def get_pending_by_hostname(hostname: str) -> Optional[PendingIsland]:
    with _lock:
        for p in list_pending_spokes():
            if p.hostname == hostname:
                return p
    return None


def get_spoke_by_pending_hostname(hostname: str) -> Optional[PendingIsland]:
    return get_pending_by_hostname(hostname)


def save_pending_spoke(spoke: PendingIsland) -> None:
    with _lock:
        _write_json(_pending_dir() / f"{spoke.id}.json", spoke.model_dump(mode="json"))


def delete_pending_spoke(spoke_id: str) -> None:
    with _lock:
        p = _pending_dir() / f"{spoke_id}.json"
        if p.exists():
            p.unlink()


def _spoke_path(tenant_id: str) -> Path:
    return _data_dir() / tenant_id / "islands.json"


def _load_spokes(tenant_id: str) -> list[Spoke]:
    raw = _read_json(_spoke_path(tenant_id)) or []
    return [Spoke(**i) for i in raw]


def _save_spokes(tenant_id: str, spokes: list[Spoke]) -> None:
    _write_json(_spoke_path(tenant_id), [i.model_dump(mode="json") for i in spokes])


def get_spoke(tenant_id: str, spoke_id: str) -> Optional[Spoke]:
    with _lock:
        for i in _load_spokes(tenant_id):
            if i.id == spoke_id:
                return i
    return None


def get_spoke_by_api_key(tenant_id: str, api_key: str) -> Optional[Spoke]:
    """Return the approved spoke whose encrypted API key matches the plaintext key."""
    with _lock:
        for i in _load_spokes(tenant_id):
            if i.api_key_enc:
                try:
                    if decrypt_str(i.api_key_enc) == api_key:
                        return i
                except Exception:
                    pass
    return None


def get_approved_spoke_by_hostname(hostname: str) -> Optional[tuple[str, Spoke]]:
    """Return (tenant_id, spoke) for the first approved spoke matching hostname across all tenants."""
    with _lock:
        for tenant in _load_tenants():
            for spoke in _load_spokes(tenant.id):
                if spoke.status == "approved" and spoke.hostname == hostname:
                    return tenant.id, spoke
    return None


def get_spoke_by_name(spoke_name: str) -> Optional[tuple[str, Spoke]]:
    """Return (tenant_id, spoke) for the first approved spoke matching spoke_name across all tenants."""
    name = spoke_name.strip().lower()
    if not name:
        return None
    with _lock:
        for tenant in _load_tenants():
            for spoke in _load_spokes(tenant.id):
                if spoke.status == "approved" and spoke.spoke_name.strip().lower() == name:
                    return tenant.id, spoke
    return None


def get_pending_spoke_by_name(spoke_name: str) -> Optional[PendingIsland]:
    """Return first pending spoke matching spoke_name."""
    name = spoke_name.strip().lower()
    if not name:
        return None
    with _lock:
        for p in list_pending_spokes():
            if p.spoke_name.strip().lower() == name:
                return p
    return None



    with _lock:
        return _load_spokes(tenant_id)


def save_spoke(spoke: Spoke) -> None:
    with _lock:
        spokes = _load_spokes(spoke.tenant_id)
        spokes = [i for i in spokes if i.id != spoke.id]
        spokes.append(spoke)
        _save_spokes(spoke.tenant_id, spokes)


def get_processing_stats(tenant_id: str) -> dict:
    """Return count of islands in centralized vs distributed mode per feature."""
    spokes = list_spokes(tenant_id)
    features = ["aruba_polling", "teams_webhook", "email", "heartbeat", "gkill", "schedules", "repo_sync"]
    stats = {feature: {"centralized": 0, "distributed": 0} for feature in features}
    approved_spokes = [spoke for spoke in spokes if spoke.status == "approved"]
    for spoke in approved_spokes:
        for feature in features:
            mode = spoke.processing_mode.resolve(feature)
            stats[feature][mode] += 1
    return {"total_spokes": len(approved_spokes), "by_feature": stats}


def get_spoke_processing_stats(tenant_id: str) -> dict:
    return get_processing_stats(tenant_id)


def delete_spoke(tenant_id: str, spoke_id: str) -> None:
    with _lock:
        spokes = [i for i in _load_spokes(tenant_id) if i.id != spoke_id]
        _save_spokes(tenant_id, spokes)

        queue_path = _queue_path(tenant_id, spoke_id)
        if queue_path.exists():
            queue_path.unlink()

        audit_path = _audit_path(tenant_id, spoke_id)
        if audit_path.exists():
            audit_path.unlink()


def approve_spoke(tenant_id: str, spoke_id: str) -> Optional[str]:
    """Approve a spoke, persist a newly encrypted API key, and return it once."""
    with _lock:
        spokes = _load_spokes(tenant_id)
        for i in spokes:
            if i.id == spoke_id:
                plain_key = generate_api_key()
                i.api_key_enc = encrypt_str(plain_key)
                i.status = "approved"
                _save_spokes(tenant_id, spokes)
                return plain_key
    return None


def revoke_spoke(tenant_id: str, spoke_id: str) -> None:
    with _lock:
        spokes = _load_spokes(tenant_id)
        for i in spokes:
            if i.id == spoke_id:
                i.status = "revoked"
                i.api_key_enc = None
                break
        _save_spokes(tenant_id, spokes)


def update_spoke_telemetry(tenant_id: str, spoke_id: str, telemetry: dict) -> None:
    with _lock:
        spokes = _load_spokes(tenant_id)
        for i in spokes:
            if i.id == spoke_id:
                i.telemetry = telemetry
                i.last_seen = _now()
                break
        _save_spokes(tenant_id, spokes)


def _queue_path(tenant_id: str, spoke_id: str) -> Path:
    return _data_dir() / tenant_id / "queue" / f"{spoke_id}.json"


def _load_queue(tenant_id: str, spoke_id: str) -> list[Command]:
    raw = _read_json(_queue_path(tenant_id, spoke_id)) or []
    return [Command(**c) for c in raw]


def _save_queue(tenant_id: str, spoke_id: str, commands: list[Command]) -> None:
    _write_json(_queue_path(tenant_id, spoke_id), [c.model_dump(mode="json") for c in commands])


def enqueue_command(command: Command) -> None:
    with _lock:
        cmds = _load_queue(command.tenant_id, command.spoke_id)
        now = _now()
        cmds = [c for c in cmds if c.expires_at > now]
        cmds.append(command)
        _save_queue(command.tenant_id, command.spoke_id, cmds)


def get_queued_commands(tenant_id: str, spoke_id: str) -> list[Command]:
    """Return queued commands, mark as delivered, purge expired."""
    with _lock:
        now = _now()
        cmds = _load_queue(tenant_id, spoke_id)
        active = [c for c in cmds if c.expires_at > now]
        queued = [c for c in active if c.status == "queued"]
        for c in queued:
            c.status = "delivered"
            c.delivered_at = now
        _save_queue(tenant_id, spoke_id, active)
        return queued


def list_commands(tenant_id: str, spoke_id: Optional[str] = None) -> list[Command]:
    with _lock:
        now = _now()
        if spoke_id:
            commands = [c for c in _load_queue(tenant_id, spoke_id) if c.expires_at > now]
            return sorted(commands, key=lambda c: c.created_at, reverse=True)

        commands: list[Command] = []
        for spoke in _load_spokes(tenant_id):
            commands.extend(c for c in _load_queue(tenant_id, spoke.id) if c.expires_at > now)
        return sorted(commands, key=lambda c: c.created_at, reverse=True)


def ack_command(tenant_id: str, spoke_id: str, command_id: str, result: Optional[dict] = None) -> None:
    with _lock:
        cmds = _load_queue(tenant_id, spoke_id)
        for c in cmds:
            if c.id == command_id:
                c.status = "executed"
                c.executed_at = _now()
                if result:
                    c.result = result
                break
        _save_queue(tenant_id, spoke_id, cmds)


def purge_expired_commands() -> int:
    """Remove command queue entries whose 24-hour TTL has elapsed and return the purge count."""
    total = 0
    now = _now()
    base = _data_dir()
    if not base.exists():
        return 0
    with _lock:
        for queue_file in base.glob("*/queue/*.json"):
            raw = _read_json(queue_file) or []
            before = len(raw)
            fresh = [c for c in raw if datetime.fromisoformat(c["expires_at"]) > now]
            if len(fresh) < before:
                _write_json(queue_file, fresh)
                total += before - len(fresh)
    return total


def _audit_path(tenant_id: str, spoke_id: str) -> Path:
    return _data_dir() / tenant_id / "audit" / f"{spoke_id}.json"


def _load_audit(tenant_id: str, spoke_id: str) -> list[AuditEntry]:
    raw = _read_json(_audit_path(tenant_id, spoke_id)) or []
    return [AuditEntry(**e) for e in raw]


def append_audit(entry: AuditEntry) -> None:
    """Append audit entry and trim to 7-day rolling window."""
    with _lock:
        entries = _load_audit(entry.tenant_id, entry.spoke_id)
        entries.append(entry)
        cutoff = _now() - timedelta(days=7)
        entries = [e for e in entries if e.timestamp > cutoff]
        _write_json(
            _audit_path(entry.tenant_id, entry.spoke_id),
            [e.model_dump(mode="json") for e in entries],
        )


def get_audit(tenant_id: str, spoke_id: str) -> list[AuditEntry]:
    with _lock:
        return _load_audit(tenant_id, spoke_id)


def purge_old_audit() -> int:
    """Trim per-spoke audit logs to the rolling 7-day retention window."""
    total = 0
    cutoff = _now() - timedelta(days=7)
    base = _data_dir()
    if not base.exists():
        return 0
    with _lock:
        for audit_file in base.glob("*/audit/*.json"):
            raw = _read_json(audit_file) or []
            before = len(raw)
            fresh = [e for e in raw if datetime.fromisoformat(e["timestamp"]) > cutoff]
            if len(fresh) < before:
                _write_json(audit_file, fresh)
                total += before - len(fresh)
    return total


def init_store() -> None:
    """Create the base JSON store layout so startup can safely persist data files."""
    base = _data_dir()
    for d in [base, base / "pending"]:
        d.mkdir(parents=True, exist_ok=True)
