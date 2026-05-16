"""Thread-safe JSON-backed data access layer for Hub.

The application does not use PostgreSQL, SQLite, or any ORM. Instead, all
persistent state is stored as JSON files under ``DATA_DIR`` and accessed through
this module. Callers should treat this file as the single read/write boundary
for users, tenants, spokes, command queues, and audit history. A process-local
re-entrant lock protects multi-step file operations so concurrent FastAPI
requests and background tasks do not corrupt on-disk state.
"""
from __future__ import annotations

import contextlib
import json
import logging
import shutil
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .config import get_settings
from .crypto import decrypt_dict, decrypt_str, encrypt_str, generate_api_key
from .data_models import AuditEntry, BackupConfig, Command, HubAuthConfig, MacProfile, MacProfileEntry, OuiPoolEntry, Spoke, PendingSpoke, Tenant, User

_lock = threading.RLock()


logger = logging.getLogger(__name__)

_RELAY_CONFIG_KEYS = {
    "relay_server_url",
    "relay_api_key",
    "relay_tenant_id",
    "hub_tls_verify",
    "relay_spoke_id",
    "relay_spoke_name",
}
_HUB_LOCAL_CONFIG_KEYS = {
    "repo_url",
    "sim_repo_url",
    "sim_repo_branch",
}
_PROCESSING_MODE_DEFAULTS = {
    "central_api": "centralized",
    "teams": "centralized",
    "email": "centralized",
}


def _data_dir() -> Path:
    return Path(get_settings().data_dir)


DATA_DIR = _data_dir()
_BACKUP_CONFIG_FILE = DATA_DIR / "backup_config.json"
_AUTH_CONFIG_FILE = _data_dir() / "auth_config.json"


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        logger.error("Corrupt JSON in %s: %s — returning None", path, exc)
        return None
    except OSError as exc:
        logger.error("Failed to read %s: %s — returning None", path, exc)
        return None


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2, default=str)
        tmp.replace(path)
    except OSError as exc:
        logger.error("Failed to write %s: %s", path, exc)
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _users_path() -> Path:
    return _data_dir() / "users.json"


def _load_users() -> list[User]:
    raw = _read_json(_users_path()) or []
    return [User(**u) for u in raw]


def _save_users(users: list[User]) -> None:
    _write_json(_users_path(), [u.model_dump(mode="json") for u in users])


def load_backup_config() -> BackupConfig:
    with _lock:
        raw = _read_json(_BACKUP_CONFIG_FILE)
        if not raw:
            return BackupConfig()
        return BackupConfig(**raw)


def save_backup_config(config: BackupConfig) -> None:
    with _lock:
        _write_json(_BACKUP_CONFIG_FILE, config.model_dump(mode="json"))


def load_auth_config() -> HubAuthConfig:
    with _lock:
        raw = _read_json(_AUTH_CONFIG_FILE)
        if not raw:
            return HubAuthConfig()
        return HubAuthConfig(**raw)


def save_auth_config(config: HubAuthConfig) -> None:
    with _lock:
        _write_json(_AUTH_CONFIG_FILE, config.model_dump(mode="json"))


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


def get_tenant_by_hint(hint: str) -> Optional[Tenant]:
    """Look up a tenant by id first, then by name (both case-insensitive)."""
    if not hint:
        return None
    with _lock:
        tenants = _load_tenants()
        hint_lower = hint.lower()
        for t in tenants:
            if t.id.lower() == hint_lower:
                return t
        for t in tenants:
            if t.name.lower() == hint_lower:
                return t
    return None


def get_tenant_central_sites_config(tenant_id: str) -> dict[str, Any]:
    tenant = get_tenant(tenant_id)
    return dict(tenant.central_sites_config or {}) if tenant else {}


def set_tenant_central_sites_config(tenant_id: str, config: dict[str, Any]) -> None:
    tenant = get_tenant(tenant_id)
    if tenant:
        tenant.central_sites_config = dict(config or {})
        save_tenant(tenant)


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


def get_pending_spoke(spoke_id: str) -> Optional[PendingSpoke]:
    with _lock:
        raw = _read_json(_pending_dir() / f"{spoke_id}.json")
        return PendingSpoke(**raw) if raw else None


def list_pending_spokes() -> list[PendingSpoke]:
    with _lock:
        d = _pending_dir()
        if not d.exists():
            return []
        results = []
        for f in d.glob("*.json"):
            raw = _read_json(f)
            if raw:
                results.append(PendingSpoke(**raw))
        return results


def get_pending_by_hostname(hostname: str) -> Optional[PendingSpoke]:
    with _lock:
        for p in list_pending_spokes():
            if p.hostname == hostname:
                return p
    return None


def rekey_pending_spoke(old_spoke_id: str, new_spoke_id: str) -> bool:
    with _lock:
        if old_spoke_id == new_spoke_id:
            return True
        pending = get_pending_spoke(old_spoke_id)
        if not pending:
            return False
        target = _pending_dir() / f"{new_spoke_id}.json"
        if target.exists():
            raise ValueError("Pending spoke ID already exists")
        delete_pending_spoke(old_spoke_id)
        pending.id = new_spoke_id
        save_pending_spoke(pending)
        return True


def get_spoke_by_pending_hostname(hostname: str) -> Optional[PendingSpoke]:
    return get_pending_by_hostname(hostname)


def save_pending_spoke(spoke: PendingSpoke) -> None:
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


def get_approved_spoke_by_id(spoke_id: str) -> Optional[tuple[str, Spoke]]:
    """Return (tenant_id, spoke) for the first approved spoke matching ID across all tenants."""
    with _lock:
        for tenant in _load_tenants():
            for spoke in _load_spokes(tenant.id):
                if spoke.status == "approved" and spoke.id == spoke_id:
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


def find_spoke_name_conflict(
    tenant_id: str,
    spoke_name: str,
    *,
    exclude_spoke_id: str = "",
) -> Optional[Spoke]:
    """Return the first approved spoke in tenant_id whose spoke_name conflicts."""
    name = spoke_name.strip().lower()
    if not tenant_id or not name:
        return None
    excluded = exclude_spoke_id.strip().lower()
    with _lock:
        for spoke in _load_spokes(tenant_id):
            if spoke.status != "approved":
                continue
            if excluded and spoke.id.strip().lower() == excluded:
                continue
            if spoke.spoke_name.strip().lower() == name:
                return spoke
    return None


def get_pending_spoke_by_name(spoke_name: str) -> Optional[PendingSpoke]:
    """Return first pending spoke matching spoke_name."""
    name = spoke_name.strip().lower()
    if not name:
        return None
    with _lock:
        for p in list_pending_spokes():
            if p.spoke_name.strip().lower() == name:
                return p
    return None


def find_pending_spoke_name_conflict(
    tenant_hint: str,
    spoke_name: str,
    *,
    exclude_spoke_id: str = "",
) -> Optional[PendingSpoke]:
    """Return the first pending spoke in tenant_hint whose spoke_name conflicts."""
    name = spoke_name.strip().lower()
    if not tenant_hint or not name:
        return None
    excluded = exclude_spoke_id.strip().lower()
    with _lock:
        for pending in list_pending_spokes():
            if pending.tenant_hint != tenant_hint:
                continue
            if excluded and pending.id.strip().lower() == excluded:
                continue
            if pending.spoke_name.strip().lower() == name:
                return pending
    return None


def list_spokes(tenant_id: str) -> list[Spoke]:
    with _lock:
        return _load_spokes(tenant_id)


def save_spoke(spoke: Spoke) -> None:
    with _lock:
        spokes = _load_spokes(spoke.tenant_id)
        spokes = [i for i in spokes if i.id != spoke.id]
        spokes.append(spoke)
        _save_spokes(spoke.tenant_id, spokes)


def mark_spoke_config_applied(tenant_id: str, spoke_id: str, version: int) -> None:
    with _lock:
        spoke = get_spoke(tenant_id, spoke_id)
        if not spoke:
            return
        if version > spoke.applied_config_version:
            spoke.applied_config_version = version
        spoke.last_config_applied_at = _now()
        save_spoke(spoke)


def get_command(tenant_id: str, spoke_id: str, command_id: str) -> Optional[Command]:
    with _lock:
        for command in _load_queue(tenant_id, spoke_id):
            if command.id == command_id:
                return command
    return None


def _tenant_processing_modes(tenant: Tenant | None) -> dict[str, str]:
    modes = dict(_PROCESSING_MODE_DEFAULTS)
    if tenant:
        for key, default in _PROCESSING_MODE_DEFAULTS.items():
            value = str((tenant.processing_modes or {}).get(key, default)).strip().lower()
            modes[key] = value if value in {"centralized", "distributed"} else default
    return modes



def _tenant_usb_vidpids(tenant: Tenant | None) -> list[dict[str, Any]]:
    if not tenant:
        return []
    configured = tenant.usb_vidpids if isinstance(tenant.usb_vidpids, list) else []
    legacy = (tenant.hub_config or {}).get("usb_vidpids")
    if configured:
        return [dict(item) for item in configured if isinstance(item, dict)]
    if isinstance(legacy, list):
        return [dict(item) for item in legacy if isinstance(item, dict)]
    return []



def get_tenant_usb_vidpids(tenant_id: str) -> list[dict[str, Any]]:
    with _lock:
        tenant = get_tenant(tenant_id)
        return _tenant_usb_vidpids(tenant)



def set_tenant_usb_vidpids(tenant_id: str, usb_vidpids: list[dict[str, Any]]) -> Optional[Tenant]:
    with _lock:
        tenants = _load_tenants()
        for tenant in tenants:
            if tenant.id != tenant_id:
                continue
            tenant.usb_vidpids = [dict(item) for item in (usb_vidpids or []) if isinstance(item, dict)]
            tenant.hub_config = dict(tenant.hub_config or {})
            tenant.hub_config["usb_vidpids"] = [dict(item) for item in tenant.usb_vidpids]
            _save_tenants(tenants)
            return tenant
    return None



def _hub_core_config(tenant: Tenant | None) -> dict[str, Any]:
    if not tenant:
        return {}
    hub_config = tenant.hub_config or {}
    payload = {
        key: value
        for key, value in hub_config.items()
        if key not in _RELAY_CONFIG_KEYS and key not in _HUB_LOCAL_CONFIG_KEYS and key != "usb_vidpids"
    }
    if tenant.usb_vidpids or "usb_vidpids" in hub_config:
        payload["usb_vidpids"] = _tenant_usb_vidpids(tenant)
    return payload



def _hub_github_config(tenant: Tenant | None) -> dict[str, Any]:
    if not tenant or not tenant.github_config_enc:
        return {}
    try:
        cfg = decrypt_dict(tenant.github_config_enc)
    except Exception:
        logger.warning("Unable to decrypt GitHub config for tenant %s", tenant.id if tenant else "unknown")
        return {}
    return {
        "repo_branch": str(cfg.get("sim_repo_branch") or "").strip(),
        "github_token": str(cfg.get("github_token") or "").strip(),
    }



def tenant_has_spoke_config_payload(tenant: Tenant | None) -> bool:
    return any(value is not None for value in _build_spoke_config_payload(tenant).values())



def _hub_central_config(tenant: Tenant | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not tenant or not tenant.aruba_config_enc:
        return None, None
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception:
        logger.warning("Unable to decrypt Aruba config for tenant %s", tenant.id)
        return None, None

    api_version = str(cfg.get("api_version") or "classic").strip().lower()
    if api_version == "new_central":
        central_api = {
            "mode": "central",
            "classic": {"url": "", "username": ""},
            "central": {
                "url": cfg.get("cluster_url", ""),
                "client_id": cfg.get("client_id", ""),
                "customer_id": cfg.get("customer_id", ""),
                "client_secret": cfg.get("client_secret", ""),
            },
        }
    else:
        central_api = {
            "mode": "classic",
            "classic": {
                "url": cfg.get("cluster_url", ""),
                "username": cfg.get("username", ""),
                "password": cfg.get("password", ""),
            },
            "central": {"url": "", "client_id": "", "customer_id": "", "client_secret": ""},
        }

    central_config = {
        "api_version": api_version,
        "cluster_url": cfg.get("cluster_url", ""),
        "client_id": cfg.get("client_id", ""),
        "client_secret": cfg.get("client_secret", ""),
        "customer_id": cfg.get("customer_id", ""),
        "access_token": cfg.get("access_token", ""),
        "refresh_token": cfg.get("refresh_token", ""),
    }
    return central_api, central_config



def _hub_notification_config(tenant: Tenant | None) -> dict[str, Any]:
    if not tenant or not tenant.notification_config_enc:
        return {}
    try:
        cfg = decrypt_dict(tenant.notification_config_enc)
    except Exception:
        logger.warning("Unable to decrypt notification config for tenant %s", tenant.id)
        return {}

    to_emails = cfg.get("to_emails") or []
    if isinstance(to_emails, str):
        to_emails = [item.strip() for item in to_emails.split(",") if item.strip()]
    return {
        "teams_webhook_url": cfg.get("teams_webhook_url") or cfg.get("teams_webhook") or "",
        "smtp_host": cfg.get("smtp_host", ""),
        "smtp_port": cfg.get("smtp_port", 587),
        "smtp_user": cfg.get("smtp_user", ""),
        "smtp_password": cfg.get("smtp_password") or cfg.get("smtp_pass") or "",
        "smtp_from": cfg.get("from_email", ""),
        "smtp_to": to_emails,
    }



def _build_spoke_config_payload(tenant: Tenant | None) -> dict[str, Any]:
    payload = _hub_core_config(tenant)
    payload.update(_hub_github_config(tenant))
    modes = _tenant_processing_modes(tenant)
    central_api, central_config = _hub_central_config(tenant)
    notifications = _hub_notification_config(tenant)

    if modes["central_api"] == "distributed":
        payload["central_api"] = central_api or {
            "mode": "classic",
            "classic": {"url": "", "username": ""},
            "central": {"url": "", "client_id": "", "customer_id": "", "client_secret": ""},
        }
        payload["central_config"] = central_config or {
            "api_version": "classic",
            "cluster_url": "",
            "client_id": "",
            "client_secret": "",
            "customer_id": "",
            "access_token": "",
            "refresh_token": "",
        }
    else:
        payload["central_api"] = None
        payload["central_config"] = None

    payload["teams_webhook_url"] = notifications.get("teams_webhook_url", "") if modes["teams"] == "distributed" else None
    for key in ("smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from", "smtp_to"):
        payload[key] = notifications.get(key) if modes["email"] == "distributed" else None
    return payload



def ensure_config_update_command(tenant_id: str, spoke_id: str) -> None:
    with _lock:
        spoke = get_spoke(tenant_id, spoke_id)
        if not spoke or spoke.status != "approved" or spoke.config_version <= spoke.applied_config_version:
            return
        commands = _load_queue(tenant_id, spoke_id)
        target_version = spoke.config_version
        for command in commands:
            payload_version = int((command.payload or {}).get("config_version") or (command.payload or {}).get("__config_version", 0) or 0)
            if command.type == "config_update" and payload_version == target_version and command.status in {"queued", "delivered", "executed"}:
                return
        tenant = get_tenant(tenant_id)
        merged_payload = _build_spoke_config_payload(tenant)
        command_payload = {
            "command": "config_update",
            "config": merged_payload,
            "config_version": target_version,
            "__config_version": target_version,
        }
        commands.append(
            Command(
                spoke_id=spoke_id,
                tenant_id=tenant_id,
                type="config_update",
                payload=command_payload,
                expires_at=_now() + timedelta(hours=24),
            )
        )
        _save_queue(tenant_id, spoke_id, commands)



def ensure_config_clear_command(tenant_id: str, spoke_id: str) -> None:
    with _lock:
        spoke = get_spoke(tenant_id, spoke_id)
        if not spoke or spoke.status != "approved":
            return
        commands = _load_queue(tenant_id, spoke_id)
        for command in commands:
            if command.type == "config_clear" and command.status in {"queued", "delivered"}:
                return
        commands.append(
            Command(
                spoke_id=spoke_id,
                tenant_id=tenant_id,
                type="config_clear",
                payload={"command": "config_clear"},
                expires_at=_now() + timedelta(hours=24),
            )
        )
        _save_queue(tenant_id, spoke_id, commands)


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


def rekey_spoke(tenant_id: str, old_spoke_id: str, new_spoke_id: str) -> bool:
    with _lock:
        if old_spoke_id == new_spoke_id:
            return True
        spokes = _load_spokes(tenant_id)
        if any(spoke.id == new_spoke_id for spoke in spokes):
            raise ValueError("Spoke ID already exists")
        for spoke in spokes:
            if spoke.id == old_spoke_id:
                spoke.id = new_spoke_id
                _save_spokes(tenant_id, spokes)
                old_queue_path = _queue_path(tenant_id, old_spoke_id)
                new_queue_path = _queue_path(tenant_id, new_spoke_id)
                if old_queue_path.exists():
                    new_queue_path.parent.mkdir(parents=True, exist_ok=True)
                    old_queue_path.replace(new_queue_path)
                old_audit_path = _audit_path(tenant_id, old_spoke_id)
                new_audit_path = _audit_path(tenant_id, new_spoke_id)
                if old_audit_path.exists():
                    new_audit_path.parent.mkdir(parents=True, exist_ok=True)
                    old_audit_path.replace(new_audit_path)
                return True
    return False


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

    with contextlib.suppress(Exception):
        from .ws import notify_spoke_command

        notify_spoke_command(command.tenant_id, command.spoke_id)


def peek_queued_commands(tenant_id: str, spoke_id: str) -> list[Command]:
    with _lock:
        now = _now()
        cmds = _load_queue(tenant_id, spoke_id)
        active = [c for c in cmds if c.expires_at > now]
        if len(active) != len(cmds):
            _save_queue(tenant_id, spoke_id, active)
        return [c for c in active if c.status == "queued"]


def mark_commands_delivered(tenant_id: str, spoke_id: str, command_ids: list[str]) -> None:
    if not command_ids:
        return
    with _lock:
        now = _now()
        ids = set(command_ids)
        cmds = _load_queue(tenant_id, spoke_id)
        active = [c for c in cmds if c.expires_at > now]
        for command in active:
            if command.id in ids and command.status == "queued":
                command.status = "delivered"
                command.delivered_at = now
        _save_queue(tenant_id, spoke_id, active)


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


def clear_command_queue(tenant_id: str, spoke_id: Optional[str] = None) -> int:
    """Clear all pending/queued commands for a spoke or all spokes in a tenant. Returns count cleared."""
    total = 0
    with _lock:
        if spoke_id:
            cmds = _load_queue(tenant_id, spoke_id)
            total = len(cmds)
            _save_queue(tenant_id, spoke_id, [])
        else:
            for spoke in _load_spokes(tenant_id):
                cmds = _load_queue(tenant_id, spoke.id)
                total += len(cmds)
                _save_queue(tenant_id, spoke.id, [])
    return total


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
            fresh = []
            for row in raw:
                try:
                    expires_at = datetime.fromisoformat(str(row.get("expires_at") or ""))
                except ValueError as exc:
                    logger.warning(
                        "Skipping command %s in %s due to invalid expires_at %r: %s",
                        row.get("id", "unknown"),
                        queue_file,
                        row.get("expires_at"),
                        exc,
                    )
                    continue
                if expires_at > now:
                    fresh.append(row)
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


# ── T3 MAC Profile store ──────────────────────────────────────────────────────

def _mac_profiles_path(tenant_id: str) -> Path:
    return _data_dir() / tenant_id / "mac_profiles.json"


def _oui_pool_path() -> Path:
    return _data_dir() / "oui_pool.json"


def get_mac_profile(tenant_id: str, spoke_id: str) -> Optional[MacProfile]:
    with _lock:
        raw = _read_json(_mac_profiles_path(tenant_id)) or {}
        data = raw.get(spoke_id)
        if not data:
            return None
        return MacProfile(**data)


def save_mac_profile(tenant_id: str, spoke_id: str, profile: MacProfile) -> None:
    with _lock:
        path = _mac_profiles_path(tenant_id)
        raw = _read_json(path) or {}
        raw[spoke_id] = profile.model_dump(mode="json")
        _write_json(path, raw)


def list_mac_profiles(tenant_id: str) -> dict[str, MacProfile]:
    with _lock:
        raw = _read_json(_mac_profiles_path(tenant_id)) or {}
        result = {}
        for spoke_id, data in raw.items():
            try:
                result[spoke_id] = MacProfile(**data)
            except Exception:
                pass
        return result


def delete_mac_profile(tenant_id: str, spoke_id: str) -> None:
    with _lock:
        path = _mac_profiles_path(tenant_id)
        raw = _read_json(path) or {}
        if spoke_id in raw:
            del raw[spoke_id]
            _write_json(path, raw)


def get_oui_pool() -> list[OuiPoolEntry]:
    with _lock:
        raw = _read_json(_oui_pool_path()) or []
        result = []
        for item in raw:
            try:
                result.append(OuiPoolEntry(**item))
            except Exception:
                pass
        return result


def save_oui_pool(entries: list[OuiPoolEntry]) -> None:
    with _lock:
        _write_json(_oui_pool_path(), [e.model_dump(mode="json") for e in entries])


def get_oui_pool_raw() -> list[dict]:
    """Return raw dicts for API serialization without model overhead."""
    with _lock:
        return _read_json(_oui_pool_path()) or []


def save_oui_pool_raw(entries: list[dict]) -> None:
    with _lock:
        _write_json(_oui_pool_path(), entries)
