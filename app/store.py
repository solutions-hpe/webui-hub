"""Thread-safe JSON-backed data access layer for Hub.

The application does not use PostgreSQL, SQLite, or any ORM. Instead, all
persistent state is stored as JSON files under ``DATA_DIR`` and accessed through
this module. Callers should treat this file as the single read/write boundary
for users, tenants, spokes, command queues, and audit history. A process-local
re-entrant lock protects multi-step file operations so concurrent FastAPI
requests and background tasks do not corrupt on-disk state.

For the command queue specifically, gunicorn runs multiple worker processes that
each have their own threading lock. Cross-process safety for queue writes is
provided by ``fcntl.flock`` (exclusive file lock) on a per-spoke lock file.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import logging
import os
import shutil
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .config import get_settings
from .crypto import decrypt_dict, decrypt_str, encrypt_str, generate_api_key
from .data_models import AuditEntry, BackupConfig, Command, HubAuthConfig, MacProfile, MacProfileEntry, OuiPoolEntry, QAApiKey, Spoke, PendingSpoke, Tenant, User

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
    # Serialise first so any encoding errors surface before we touch disk.
    content = json.dumps(data, indent=2, default=str)
    # Write directly without atomic rename — callers always hold _file_lock
    # (fcntl.flock) so concurrent writes are already serialised.  The prior
    # temp-file + rename approach caused data loss on Azure Files SMB because
    # Path.replace() on CIFS mounts can delete the destination before the
    # rename completes; if the rename then fails, the original file is gone.
    try:
        with open(path, "w") as f:
            f.write(content)
    except OSError as exc:
        logger.error("Failed to write %s: %s", path, exc)
        raise


@contextlib.contextmanager
def _file_lock(lock_path: Path):
    """Cross-process exclusive lock via fcntl.flock.

    Combines with the module-level threading.RLock (_lock) so that both
    intra-process and inter-process (gunicorn multi-worker) concurrent
    read-modify-write cycles are serialised.  Always acquire _lock first
    (caller's responsibility), then this context manager for flock.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _users_path() -> Path:
    return _data_dir() / "users.json"


def _users_lock_path() -> Path:
    return _data_dir() / "users.lock"


def _load_users() -> list[User]:
    raw = _read_json(_users_path()) or []
    users = []
    for u in raw:
        try:
            users.append(User(**u))
        except Exception as exc:
            logger.error("Skipping unreadable user record: %s — %s", u.get("username", "?"), exc)
    return users


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
        with _file_lock(_data_dir() / "backup_config.lock"):
            _write_json(_BACKUP_CONFIG_FILE, config.model_dump(mode="json"))


def load_auth_config() -> HubAuthConfig:
    with _lock:
        raw = _read_json(_AUTH_CONFIG_FILE)
        if not raw:
            return HubAuthConfig()
        return HubAuthConfig(**raw)


def save_auth_config(config: HubAuthConfig) -> None:
    with _lock:
        with _file_lock(_data_dir() / "auth_config.lock"):
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
        with _file_lock(_users_lock_path()):
            users = _load_users()
            users = [u for u in users if u.id != user.id]
            users.append(user)
            _save_users(users)


def delete_user(user_id: str) -> None:
    with _lock:
        with _file_lock(_users_lock_path()):
            users = [u for u in _load_users() if u.id != user_id]
            _save_users(users)


def ensure_admin(username: str, hashed_password: str, force_password: bool = False) -> None:
    """Create or update the bootstrap superadmin.

    If the store has no users, create the superadmin unconditionally ONLY on a
    genuine first-run where the data directory has no prior data at all.
    If ``force_password`` is True (i.e. ADMIN_PASSWORD was explicitly set in
    the environment), always update the superadmin's password so operators can
    reset credentials by changing the env var and restarting the container.

    Multiple safeguards prevent accidental user wipes:
      1. If users.json exists (even empty/corrupt), skip bootstrap.
      2. If any other data files exist (tenants.json etc.), skip bootstrap —
         prior data means this is NOT a fresh install.
      3. Path.exists() can silently return False on IO/mount errors, so we
         also catch OSError and treat it as "file exists" to err safely.
      4. _load_users() skips individual bad records rather than throwing, so
         partial data is never mistaken for an empty store.
    """
    with _lock:
        with _file_lock(_users_lock_path()):
            users_path = _users_path()

            # ── Guard 1: check for file existence, treating IO errors as "exists" ──
            file_exists: bool = False
            try:
                file_exists = users_path.exists()
            except OSError:
                # Can't stat the file — assume it exists to avoid any bootstrap
                logger.warning(
                    "ensure_admin: could not stat %s (mount error?) — "
                    "skipping bootstrap to prevent data loss.",
                    users_path,
                )
                return

            # ── Guard 2: check for ANY other data files as evidence of prior use ──
            data_dir = _data_dir()
            prior_data_exists = False
            try:
                # tenants.json, global_config.json, oui_pool.json, or tenant dirs
                sentinel_paths = [
                    data_dir / "tenants.json",
                    data_dir / "global_config.json",
                    data_dir / "oui_pool.json",
                ]
                prior_data_exists = any(p.exists() for p in sentinel_paths) or any(
                    p.is_dir() for p in data_dir.iterdir()
                    if p.name not in {"tls", "pending", "tmp"}
                )
            except OSError:
                prior_data_exists = True  # if we can't check, assume prior data

            users = _load_users()

            if not users:
                if file_exists:
                    logger.warning(
                        "ensure_admin: %s exists but loaded 0 users — "
                        "possible mount/read error; skipping bootstrap to prevent data loss.",
                        users_path,
                    )
                    return
                if prior_data_exists:
                    logger.warning(
                        "ensure_admin: users.json absent but other data files exist — "
                        "this does not look like a fresh install; skipping bootstrap "
                        "to prevent data loss. Restore users.json from backup if needed.",
                    )
                    return
                # Genuine first run: no users, no prior data
                admin = User(username=username, hashed_password=hashed_password, is_superadmin=True)
                _save_users([admin])
                logger.info("ensure_admin: bootstrapped superadmin '%s' (first run).", username)
                return

            if force_password:
                for user in users:
                    if user.username == username and user.is_superadmin:
                        user.hashed_password = hashed_password
                        _save_users(users)
                        break


def _tenants_path() -> Path:
    return _data_dir() / "tenants.json"


def _tenants_lock_path() -> Path:
    return _data_dir() / "tenants.lock"


def _load_tenants() -> list[Tenant]:
    tenants_path = _tenants_path()
    bak_path = _data_dir() / "tenants.json.bak"
    # Runtime auto-restore: if tenants.json disappears but a backup exists,
    # restore silently so the hub keeps serving tenant data without a restart.
    if not tenants_path.exists() and bak_path.exists():
        try:
            import shutil as _shutil
            _shutil.copy2(str(bak_path), str(tenants_path))
            logger.warning("_load_tenants: tenants.json missing — auto-restored from backup")
        except OSError as exc:
            logger.error("_load_tenants: could not restore tenants.json from backup: %s", exc)
    raw = _read_json(tenants_path) or []
    tenants: list[Tenant] = []
    for t in raw:
        try:
            tenants.append(Tenant(**t))
        except Exception as exc:
            logger.error("_load_tenants: skipping bad record id=%s: %s", t.get("id", "?"), exc)
    return tenants


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


def list_tenants(include_deleted: bool = False) -> list[Tenant]:
    """List all tenants. By default, exclude soft-deleted tenants unless include_deleted=True."""
    with _lock:
        tenants = _load_tenants()
        if not include_deleted:
            tenants = [t for t in tenants if t.deleted_at is None]
        return tenants


def save_tenant(tenant: Tenant) -> None:
    with _lock:
        with _file_lock(_tenants_lock_path()):
            tenants = _load_tenants()
            tenants = [t for t in tenants if t.id != tenant.id]
            tenants.append(tenant)
            _save_tenants(tenants)


def delete_tenant(tenant_id: str) -> None:
    """Soft delete a tenant by setting deleted_at timestamp. Tenant data is preserved for 30 days."""
    with _lock:
        with _file_lock(_tenants_lock_path()):
            from datetime import datetime, timezone
            tenants = _load_tenants()
            for tenant in tenants:
                if tenant.id == tenant_id:
                    tenant.deleted_at = datetime.now(timezone.utc)
                    break
            _save_tenants(tenants)


def restore_tenant(tenant_id: str) -> bool:
    """Restore a soft-deleted tenant. Returns True if restored, False if not found or not deleted."""
    with _lock:
        with _file_lock(_tenants_lock_path()):
            tenants = _load_tenants()
            for tenant in tenants:
                if tenant.id == tenant_id and tenant.deleted_at is not None:
                    tenant.deleted_at = None
                    _save_tenants(tenants)
                    return True
            return False


def purge_old_deleted_tenants(days: int = 30) -> list[str]:
    """Permanently delete tenants that were soft-deleted more than 'days' ago. Returns list of purged tenant IDs."""
    from datetime import datetime, timedelta, timezone
    with _lock:
        with _file_lock(_tenants_lock_path()):
            tenants = _load_tenants()
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            purged_ids = []
            remaining = []

            for tenant in tenants:
                if tenant.deleted_at and tenant.deleted_at < cutoff:
                    purged_ids.append(tenant.id)
                    tenant_dir = _data_dir() / tenant.id
                    if tenant_dir.exists():
                        import shutil
                        shutil.rmtree(tenant_dir, ignore_errors=True)
                    logger.info(f"Purged tenant {tenant.id} (deleted {tenant.deleted_at}, >30 days old)")
                else:
                    remaining.append(tenant)

            if purged_ids:
                _save_tenants(remaining)

            return purged_ids

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
    return _data_dir() / tenant_id / "spokes.json"


def _spokes_lock_path(tenant_id: str) -> Path:
    return _data_dir() / tenant_id / "spokes.lock"


# ── Per-spoke volatile state (telemetry + last_seen) ─────────────────────────
# Written to individual files so concurrent gunicorn workers never contend on
# the shared spokes.json.  Each spoke's WS connection is pinned to one worker,
# so only one process ever writes a given spoke's state file.

_SPOKE_STATE_FIELDS = frozenset({"telemetry", "last_seen"})
_SPOKE_CONFIG_FIELDS = frozenset(
    f for f in Spoke.model_fields if f not in _SPOKE_STATE_FIELDS
)


def _spoke_state_dir(tenant_id: str) -> Path:
    return _data_dir() / tenant_id / "spoke_state"


def _spoke_state_path(tenant_id: str, spoke_id: str) -> Path:
    return _spoke_state_dir(tenant_id) / f"{spoke_id}.json"


def _load_spoke_state(tenant_id: str, spoke_id: str) -> dict:
    """Return {last_seen, telemetry} for a single spoke, or empty dict."""
    raw = _read_json(_spoke_state_path(tenant_id, spoke_id))
    return raw if isinstance(raw, dict) else {}


def _save_spoke_state(tenant_id: str, spoke_id: str, last_seen, telemetry: dict) -> None:
    """Write only volatile state fields to a per-spoke file (no locking needed —
    only the worker owning that spoke's WS connection ever writes this file)."""
    state_dir = _spoke_state_dir(tenant_id)
    state_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        _spoke_state_path(tenant_id, spoke_id),
        {
            "last_seen": last_seen.isoformat() if hasattr(last_seen, "isoformat") else last_seen,
            "telemetry": telemetry or {},
        },
    )


def _merge_spoke_state(spoke: Spoke, state: dict) -> Spoke:
    """Merge volatile state into a spoke config object (in-place)."""
    if "last_seen" in state and state["last_seen"]:
        try:
            from datetime import datetime, timezone
            ls = state["last_seen"]
            if isinstance(ls, str):
                spoke.last_seen = datetime.fromisoformat(ls)
            elif isinstance(ls, (int, float)):
                spoke.last_seen = datetime.fromtimestamp(ls, tz=timezone.utc)
        except Exception:
            pass
    if "telemetry" in state:
        spoke.telemetry = state["telemetry"]
    return spoke


def _load_spokes(tenant_id: str) -> list[Spoke]:
    raw = _read_json(_spoke_path(tenant_id)) or []
    spokes = []
    for item in raw:
        try:
            spoke = Spoke(**item)
            # Merge volatile state from per-spoke file (fast, no contention)
            state = _load_spoke_state(tenant_id, spoke.id)
            if state:
                _merge_spoke_state(spoke, state)
            spokes.append(spoke)
        except Exception as exc:
            logger.warning("store: skipping malformed spoke entry: %s", exc)
    return spokes


def _save_spokes(tenant_id: str, spokes: list[Spoke]) -> None:
    """Persist only config fields — no telemetry, no last_seen.
    Keeps spokes.json tiny (<5 KB for any realistic fleet) so concurrent writes
    from multiple gunicorn workers never produce multi-MB collisions."""
    rows = []
    for s in spokes:
        d = s.model_dump(mode="json")
        rows.append({k: v for k, v in d.items() if k in _SPOKE_CONFIG_FIELDS})
    _write_json(_spoke_path(tenant_id), rows)


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
                    logger.warning("Failed to decrypt API key for spoke %s", i.id)
    return None


def get_approved_spoke_by_api_key(api_key: str, tenant_id: str = "") -> Optional[tuple[str, Spoke]]:
    """Return (tenant_id, spoke) for an approved spoke matching the plaintext API key."""
    if not api_key:
        return None
    with _lock:
        tenants = [t for t in _load_tenants() if not tenant_id or t.id == tenant_id]
        for tenant in tenants:
            for spoke in _load_spokes(tenant.id):
                if spoke.status != "approved" or not spoke.api_key_enc:
                    continue
                try:
                    if decrypt_str(spoke.api_key_enc) == api_key:
                        return tenant.id, spoke
                except Exception:
                    logger.warning("Failed to decrypt API key for spoke %s", spoke.id)
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
    """Persist spoke config to spokes.json and volatile state to per-spoke file."""
    with _lock:
        with _file_lock(_spokes_lock_path(spoke.tenant_id)):
            spokes = _load_spokes(spoke.tenant_id)
            spokes = [i for i in spokes if i.id != spoke.id]
            spokes.append(spoke)
            _save_spokes(spoke.tenant_id, spokes)
    # Persist volatile state separately (outside the config lock — no contention)
    if spoke.last_seen or spoke.telemetry:
        _save_spoke_state(spoke.tenant_id, spoke.id, spoke.last_seen, spoke.telemetry)


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



def _global_config_path() -> Path:
    return _data_dir() / "global_config.json"


def _load_global_config() -> dict[str, Any]:
    """Read global config without acquiring the lock (safe to call under _lock)."""
    raw = _read_json(_global_config_path())
    return raw if isinstance(raw, dict) else {}


def get_global_usb_vidpids() -> list[dict[str, Any]]:
    """Return the platform-wide (superadmin-certified) USB device list."""
    with _lock:
        devices = _load_global_config().get("usb_vidpids", [])
        return [dict(d) for d in devices if isinstance(d, dict)]


def set_global_usb_vidpids(devices: list[dict[str, Any]]) -> None:
    """Persist the platform-wide USB device list."""
    with _lock:
        config = _load_global_config()
        config["usb_vidpids"] = [dict(d) for d in (devices or []) if isinstance(d, dict)]
        _write_json(_global_config_path(), config)


def get_global_usb_ignored_vidpids() -> list[dict[str, Any]]:
    """Return the platform-wide (superadmin-ignored) USB device list."""
    with _lock:
        devices = _load_global_config().get("usb_ignored_vidpids", [])
        return [dict(d) for d in devices if isinstance(d, dict)]


def set_global_usb_ignored_vidpids(devices: list[dict[str, Any]]) -> None:
    """Persist the platform-wide USB ignored device list."""
    with _lock:
        config = _load_global_config()
        config["usb_ignored_vidpids"] = [dict(d) for d in (devices or []) if isinstance(d, dict)]
        _write_json(_global_config_path(), config)


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


def _effective_usb_vidpids_from(
    global_devices: list[dict[str, Any]],
    tenant: Tenant | None,
) -> list[dict[str, Any]]:
    """Merge global + tenant USB devices.

    Global devices (superadmin-certified) are listed first with source='global'.
    Tenant-specific devices are appended with source='tenant'.
    If the same vidpid appears in both, the global entry wins (it already covers it).
    """
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for d in global_devices:
        vp = d.get("vidpid", "")
        if vp and vp not in seen:
            seen.add(vp)
            result.append({**d, "source": "global"})
    for d in _tenant_usb_vidpids(tenant):
        vp = d.get("vidpid", "")
        if vp and vp not in seen:
            seen.add(vp)
            result.append({**d, "source": "tenant"})
    return result


def get_tenant_usb_vidpids(tenant_id: str) -> list[dict[str, Any]]:
    """Return only the tenant-specific USB devices (no global merge)."""
    with _lock:
        tenant = get_tenant(tenant_id)
        return _tenant_usb_vidpids(tenant)


def get_effective_usb_vidpids(tenant_id: str) -> list[dict[str, Any]]:
    """Return the merged effective USB device list (global + tenant) for a tenant."""
    with _lock:
        global_devices = _load_global_config().get("usb_vidpids", [])
        tenant = get_tenant(tenant_id)
        return _effective_usb_vidpids_from(global_devices, tenant)



def get_discovered_usb_vidpids() -> list[dict[str, Any]]:
    """Aggregate all unique VID:PIDs seen in spoke telemetry OR tenant-certified lists.

    Returns devices that have been physically seen on at least one spoke OR are
    tenant-certified but not yet globally certified.  Annotated with which
    spoke(s)/tenant(s) reported them and whether they are already in the global
    certified list.  Sorted by vidpid ascending.
    """
    with _lock:
        global_cfg = _load_global_config()
        global_set = {d.get("vidpid") for d in global_cfg.get("usb_vidpids", []) if d.get("vidpid")}
        # Normalise to lowercase for consistent comparison
        global_set_lower = {v.lower() for v in global_set if v}
        global_ignored_lower = {
            str(d.get("vidpid") or "").lower()
            for d in global_cfg.get("usb_ignored_vidpids", [])
            if d.get("vidpid")
        }
        # vidpid → {"vidpid", "name", "seen_on": [...], "is_global", "locally_ignored"}
        discovered: dict[str, dict[str, Any]] = {}

        def _ensure(vidpid: str, name: str = "", locally_ignored: bool = False) -> None:
            if vidpid not in discovered:
                discovered[vidpid] = {
                    "vidpid": vidpid,
                    "name": name,
                    "seen_on": [],
                    "is_global": vidpid in global_set_lower,
                    "locally_ignored": locally_ignored,
                }
            else:
                if not discovered[vidpid]["name"] and name:
                    discovered[vidpid]["name"] = name
                # Once flagged locally_ignored, keep it (other spokes may not have it ignored)
                if locally_ignored:
                    discovered[vidpid]["locally_ignored"] = True

        for tenant in _load_tenants():
            tenant_label = tenant.name or tenant.id

            # ── Include tenant-certified devices that aren't globally certified ──
            for dev in _tenant_usb_vidpids(tenant):
                vidpid = str(dev.get("vidpid") or "").strip().lower()
                if not vidpid or vidpid in global_set_lower:
                    continue
                _ensure(vidpid, dev.get("label") or dev.get("name") or "")
                entry = {"tenant_name": tenant_label, "spoke_name": "(tenant certified)"}
                if entry not in discovered[vidpid]["seen_on"]:
                    discovered[vidpid]["seen_on"].append(entry)

            # ── Include devices seen in spoke telemetry ────────────────────────
            for spoke in _load_spokes(tenant.id):
                telemetry = spoke.telemetry or {}
                proxmox = telemetry.get("proxmox") or {}
                raw_devices: list[dict[str, Any]] = []
                usb_devices = telemetry.get("usb_devices")
                if isinstance(usb_devices, list):
                    raw_devices.extend(usb_devices)
                usb_state = proxmox.get("usb_state") if isinstance(proxmox, dict) else None
                if isinstance(usb_state, list):
                    raw_devices.extend(usb_state)
                present_usb = proxmox.get("present_usb") if isinstance(proxmox, dict) else None
                if isinstance(present_usb, list):
                    raw_devices.extend(present_usb)

                spoke_label = spoke.spoke_name or spoke.hostname or spoke.id
                for dev in raw_devices:
                    if not isinstance(dev, dict):
                        continue
                    vidpid = str(dev.get("vidpid") or "").strip().lower()
                    if not vidpid:
                        continue
                    _ensure(vidpid, dev.get("name") or "")
                    entry = {"tenant_name": tenant_label, "spoke_name": spoke_label}
                    if entry not in discovered[vidpid]["seen_on"]:
                        discovered[vidpid]["seen_on"].append(entry)

                # ── Include devices locally ignored on this spoke but not globally ignored ──
                spoke_cfg = spoke.config or {}
                ignored_str = spoke_cfg.get("usb_ignored_vidpids", "[]")
                try:
                    locally_ignored_vids: list[str] = json.loads(ignored_str) if isinstance(ignored_str, str) else list(ignored_str)
                except Exception:
                    locally_ignored_vids = []
                for vidpid_raw in locally_ignored_vids:
                    vidpid = str(vidpid_raw or "").strip().lower()
                    if not vidpid or vidpid in global_ignored_lower:
                        continue
                    _ensure(vidpid, "", locally_ignored=True)
                    entry = {"tenant_name": tenant_label, "spoke_name": spoke_label}
                    if entry not in discovered[vidpid]["seen_on"]:
                        discovered[vidpid]["seen_on"].append(entry)

        return sorted(discovered.values(), key=lambda d: d["vidpid"])


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
    # Push the effective (global + tenant) USB certified list to spokes.
    global_devices = _load_global_config().get("usb_vidpids", [])
    effective = _effective_usb_vidpids_from(global_devices, tenant)
    if effective or "usb_vidpids" in hub_config:
        # Strip the source annotation before sending to spokes
        payload["usb_vidpids"] = [{k: v for k, v in d.items() if k != "source"} for d in effective]
    # Push the effective global USB ignored list to spokes.  Merge with any
    # tenant-level usb_ignored_vidpids already in hub_config (stored as a JSON
    # string by the spoke, so we send a JSON string back).
    global_ignored = _load_global_config().get("usb_ignored_vidpids", [])
    if global_ignored:
        global_vids: set[str] = {str(d.get("vidpid") or "").lower() for d in global_ignored if d.get("vidpid")}
        # Merge with whatever the tenant already has in hub_config
        existing_str = hub_config.get("usb_ignored_vidpids", "[]")
        try:
            existing: list[str] = json.loads(existing_str) if isinstance(existing_str, str) else list(existing_str)
        except Exception:
            existing = []
        merged = list(global_vids | {str(v).lower() for v in existing if v})
        payload["usb_ignored_vidpids"] = json.dumps(sorted(merged))
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
        "repo_url": str(cfg.get("sim_repo_url") or "").strip(),
        "repo_branch": str(cfg.get("sim_repo_branch") or "main").strip() or "main",
        "github_token": str(cfg.get("github_token") or "").strip(),
    }


def _hub_conf_overrides(tenant: Tenant | None) -> dict[str, Any]:
    """Return hub-managed simulation.conf and user-overrides.conf override text.

    Both values are included in every config_update payload so the spoke always
    has the current state.  None means 'no override — use GitHub file as-is'.
    An empty string means 'override is cleared'.
    """
    if not tenant:
        return {"sim_conf_override": None, "user_conf_override": None}
    return {
        "sim_conf_override": tenant.sim_conf_override,
        "user_conf_override": tenant.user_conf_override,
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
                "workspace_id": cfg.get("workspace_id", ""),
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
            "central": {"url": "", "client_id": "", "customer_id": "", "workspace_id": "", "client_secret": ""},
        }

    central_config = {
        "api_version": api_version,
        "cluster_url": cfg.get("cluster_url", ""),
        "client_id": cfg.get("client_id", ""),
        "client_secret": cfg.get("client_secret", ""),
        "customer_id": cfg.get("customer_id", ""),
        "workspace_id": cfg.get("workspace_id", ""),
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
    payload.update(_hub_conf_overrides(tenant))
    modes = _tenant_processing_modes(tenant)
    central_api, central_config = _hub_central_config(tenant)
    notifications = _hub_notification_config(tenant)

    if modes["central_api"] == "distributed":
        payload["central_api"] = central_api or {
            "mode": "classic",
            "classic": {"url": "", "username": ""},
            "central": {"url": "", "client_id": "", "customer_id": "", "workspace_id": "", "client_secret": ""},
        }
        payload["central_config"] = central_config or {
            "api_version": "classic",
            "cluster_url": "",
            "client_id": "",
            "client_secret": "",
            "customer_id": "",
            "workspace_id": "",
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
        # Record the hash of what we just queued so drift detection can detect
        # future changes without relying solely on config_version accounting.
        spoke.last_pushed_config_hash = _authoritative_config_hash(tenant, merged_payload)
        save_spoke(spoke)


def _authoritative_config_hash(tenant: "Tenant | None", payload: dict | None = None) -> str:
    """Return a short hash of the hub-authoritative slice of a config payload.

    When hub_config_enabled=True, all non-None keys are authoritative.
    When hub_config_enabled=False, only USB cert keys are authoritative (the hub
    always owns USB certs regardless of the broader config management flag).
    """
    if payload is None:
        payload = _build_spoke_config_payload(tenant) if tenant else {}
    usb_always = {"usb_vidpids"}
    if tenant and tenant.hub_config_enabled:
        auth = {k: v for k, v in payload.items() if v is not None}
    else:
        auth = {k: payload.get(k) for k in usb_always}
    blob = json.dumps(auth, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def check_and_fix_config_drift(tenant_id: str, spoke_id: str) -> bool:
    """Detect and self-heal config drift between the hub's desired state and the
    last config pushed to a spoke.

    Called on every telemetry heartbeat.  Only acts when the spoke appears
    current (config_version == applied_config_version) — if there is already a
    pending push we leave it alone and return False.

    When the authoritative-config hash has changed since the last push, the
    spoke's config_version is bumped so that the next inbox fetch triggers
    ensure_config_update_command to queue a corrective push.

    Returns True if drift was detected and the version was bumped.
    """
    with _lock:
        spoke = get_spoke(tenant_id, spoke_id)
        if not spoke or spoke.status != "approved":
            return False
        # Skip if there's already an unacked push in flight — it will self-correct.
        if spoke.config_version > spoke.applied_config_version:
            return False
        tenant = get_tenant(tenant_id)
        if not tenant:
            return False
        current_hash = _authoritative_config_hash(tenant)
        if spoke.last_pushed_config_hash == current_hash:
            return False  # In sync — nothing to do.
        # Drift detected: bump version so ensure_config_update_command queues a push.
        spoke.config_version = spoke.applied_config_version + 1
        save_spoke(spoke)
        logger.info(
            "Config drift detected for spoke %s (tenant %s) — hash %s → %s; queuing corrective push",
            spoke_id, tenant_id, spoke.last_pushed_config_hash, current_hash,
        )
        return True



def get_spoke_config_diag(tenant_id: str, spoke_id: str) -> dict[str, Any]:
    """Return a diagnostic snapshot for a spoke's hub-managed config state.

    Includes the config payload preview (what would be sent on the next push),
    the current command queue for this spoke, version accounting, and hash
    comparison so operators can see exactly why a spoke may not have received
    its USB cert list or other hub-managed settings.
    """
    with _lock:
        spoke = get_spoke(tenant_id, spoke_id)
        if not spoke:
            return {"error": "Spoke not found"}
        tenant = get_tenant(tenant_id)

        # Build the config payload preview (strip secrets)
        _SECRET_KEYS = {
            "relay_api_key", "client_secret", "access_token", "refresh_token",
            "smtp_password", "teams_webhook_url", "proxmox_token",
        }
        payload = _build_spoke_config_payload(tenant)
        safe_payload: dict[str, Any] = {}
        for k, v in payload.items():
            if k in _SECRET_KEYS:
                safe_payload[k] = "***"
            elif isinstance(v, dict):
                safe_payload[k] = {dk: ("***" if dk in _SECRET_KEYS else dv) for dk, dv in v.items()}
            else:
                safe_payload[k] = v

        # USB cert details
        global_devices = _load_global_config().get("usb_vidpids", [])
        effective = _effective_usb_vidpids_from(global_devices, tenant)

        # Command queue
        commands = _load_queue(tenant_id, spoke_id)
        now = _now()
        active_cmds = [c for c in commands if c.expires_at > now]
        pending_config_cmds = [
            {
                "id": c.id,
                "type": c.type,
                "status": c.status,
                "config_version": int((c.payload or {}).get("config_version") or (c.payload or {}).get("__config_version") or 0),
                "usb_vidpids_in_payload": (c.payload or {}).get("config", {}).get("usb_vidpids") is not None
                    if isinstance((c.payload or {}).get("config"), dict) else False,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "expires_at": c.expires_at.isoformat() if c.expires_at else None,
            }
            for c in active_cmds if c.type in {"config_update", "config_clear"}
        ]

        # Hash comparison
        current_hash = _authoritative_config_hash(tenant, payload)
        in_sync = spoke.last_pushed_config_hash == current_hash

        return {
            "spoke_id": spoke.id,
            "spoke_hostname": spoke.hostname,
            "status": spoke.status,
            "config_version": spoke.config_version,
            "applied_config_version": spoke.applied_config_version,
            "push_pending": spoke.config_version > spoke.applied_config_version,
            "last_pushed_config_hash": spoke.last_pushed_config_hash,
            "current_authoritative_hash": current_hash,
            "config_in_sync": in_sync,
            "global_usb_cert_count": len(global_devices),
            "effective_usb_cert_count": len(effective),
            "effective_usb_certs": effective,
            "usb_vidpids_in_next_payload": "usb_vidpids" in payload,
            "pending_config_commands": pending_config_cmds,
            "config_payload_preview": safe_payload,
        }


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
    """Write telemetry + last_seen to the per-spoke state file only.
    Never touches spokes.json — eliminates the 116 KB concurrent-write race."""
    _save_spoke_state(tenant_id, spoke_id, _now(), telemetry)


def _queue_lock_path(tenant_id: str, spoke_id: str) -> Path:
    return _data_dir() / tenant_id / "queue" / f"{spoke_id}.lock"


def _queue_path(tenant_id: str, spoke_id: str) -> Path:
    return _data_dir() / tenant_id / "queue" / f"{spoke_id}.json"


def _load_queue(tenant_id: str, spoke_id: str) -> list[Command]:
    raw = _read_json(_queue_path(tenant_id, spoke_id)) or []
    return [Command(**c) for c in raw]


def _save_queue(tenant_id: str, spoke_id: str, commands: list[Command]) -> None:
    _write_json(_queue_path(tenant_id, spoke_id), [c.model_dump(mode="json") for c in commands])


def enqueue_command(command: Command) -> None:
    # Use both a threading lock (intra-process) and an exclusive flock (cross-process
    # across gunicorn workers) to prevent concurrent read-modify-write races on the
    # queue JSON file.
    lock_path = _queue_lock_path(command.tenant_id, command.spoke_id)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with open(lock_path, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                cmds = _load_queue(command.tenant_id, command.spoke_id)
                now = _now()
                cmds = [c for c in cmds if c.expires_at > now]
                cmds.append(command)
                _save_queue(command.tenant_id, command.spoke_id, cmds)
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

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
    """Create the base JSON store layout so startup can safely persist data files.

    Also creates a rolling backup of users.json (→ users.json.bak) each time the
    hub starts so that even if the file is accidentally overwritten, the previous
    snapshot can be recovered by renaming users.json.bak → users.json.
    """
    base = _data_dir()
    for d in [base, base / "pending"]:
        d.mkdir(parents=True, exist_ok=True)

    # Migrate legacy islands.json → spokes.json for all tenant directories
    for tenant_dir in base.iterdir():
        if not tenant_dir.is_dir() or tenant_dir.name in ("pending", "tls"):
            continue
        old_spoke_file = tenant_dir / "islands.json"
        new_spoke_file = tenant_dir / "spokes.json"
        if old_spoke_file.exists() and not new_spoke_file.exists():
            try:
                old_spoke_file.rename(new_spoke_file)
                logger.info("init_store: migrated %s → %s", old_spoke_file, new_spoke_file)
            except OSError as exc:
                logger.error("init_store: could not migrate islands.json → spokes.json: %s", exc)

    # Rolling startup backup: copy users.json → users.json.bak (if readable)
    users_path = base / "users.json"
    backup_path = base / "users.json.bak"
    try:
        if users_path.exists() and users_path.stat().st_size > 2:
            shutil.copy2(str(users_path), str(backup_path))
            logger.info("init_store: backed up %s → %s", users_path, backup_path)
    except OSError as exc:
        logger.warning("init_store: could not back up users.json: %s", exc)

    # Rolling startup backup: copy tenants.json → tenants.json.bak (if readable)
    tenants_path = base / "tenants.json"
    tenants_bak = base / "tenants.json.bak"
    try:
        if tenants_path.exists() and tenants_path.stat().st_size > 2:
            shutil.copy2(str(tenants_path), str(tenants_bak))
            logger.info("init_store: backed up %s → %s", tenants_path, tenants_bak)
        elif not tenants_path.exists() and tenants_bak.exists() and tenants_bak.stat().st_size > 2:
            # tenants.json disappeared but backup exists — auto-restore
            shutil.copy2(str(tenants_bak), str(tenants_path))
            logger.warning(
                "init_store: tenants.json missing — restored from backup %s", tenants_bak
            )
    except OSError as exc:
        logger.warning("init_store: could not back up/restore tenants.json: %s", exc)

    # Rolling startup backup: copy spokes.json → spokes.json.bak for each tenant
    for tenant_dir in base.iterdir():
        if not tenant_dir.is_dir() or tenant_dir.name in ("pending", "tls"):
            continue
        spokes_path = tenant_dir / "spokes.json"
        spokes_bak = tenant_dir / "spokes.json.bak"
        try:
            spokes_ok = spokes_path.exists() and spokes_path.stat().st_size > 2
            bak_ok = spokes_bak.exists() and spokes_bak.stat().st_size > 2
            if spokes_ok:
                shutil.copy2(str(spokes_path), str(spokes_bak))
                logger.info("init_store: backed up %s → %s", spokes_path, spokes_bak)
            elif bak_ok:
                # Restore if missing OR effectively empty (≤2 bytes = "[]" or "")
                shutil.copy2(str(spokes_bak), str(spokes_path))
                logger.warning(
                    "init_store: spokes.json missing/empty — restored from backup %s", spokes_bak
                )
        except OSError as exc:
            logger.warning("init_store: could not back up/restore spokes.json for %s: %s", tenant_dir.name, exc)

    # Migrate spokes.json to config-only format (strip telemetry & last_seen).
    # After the telemetry-split refactor, spokes.json must only contain config
    # fields so it stays tiny and is never written by frequent telemetry updates.
    # This runs once at startup and is safe: _load_spokes merges in per-spoke
    # state files, and _save_spokes now strips telemetry before writing.
    for tenant_dir in base.iterdir():
        if not tenant_dir.is_dir() or tenant_dir.name in ("pending", "tls"):
            continue
        spokes_path = tenant_dir / "spokes.json"
        if not spokes_path.exists():
            continue
        try:
            raw = _read_json(spokes_path) or []
            if not isinstance(raw, list) or not raw:
                continue
            # Check if any entry still has telemetry or last_seen (old format)
            if any("telemetry" in entry or "last_seen" in entry for entry in raw):
                spokes = [Spoke(**entry) for entry in raw]
                # Save state to per-spoke files before stripping from spokes.json
                for spoke in spokes:
                    if spoke.last_seen or spoke.telemetry:
                        _save_spoke_state(tenant_dir.name, spoke.id, spoke.last_seen, spoke.telemetry)
                _save_spokes(tenant_dir.name, spokes)
                logger.info(
                    "init_store: migrated %s to config-only format (%d spokes, %d bytes)",
                    spokes_path, len(spokes), spokes_path.stat().st_size,
                )
        except Exception as exc:
            logger.warning("init_store: could not migrate spokes.json for %s: %s", tenant_dir.name, exc)


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
                logger.warning("Skipping malformed MAC profile for spoke %s", spoke_id)
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
                logger.warning("Skipping malformed OUI pool entry: %s", item)
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


# ── QA API Keys ────────────────────────────────────────────────────────────────

def _qa_api_keys_path() -> Path:
    return _data_dir() / "qa_api_keys.json"


def list_qa_api_keys(tenant_id: str | None = None) -> list[QAApiKey]:
    """Return all QA API keys, optionally filtered to a single tenant."""
    with _lock:
        raw: list[dict] = _read_json(_qa_api_keys_path()) or []
    result = []
    for item in raw:
        try:
            key = QAApiKey(**item)
            if tenant_id is None or key.tenant_id == tenant_id:
                result.append(key)
        except Exception:
            logger.warning("Skipping malformed QA API key entry: %s", item)
    return result


def save_qa_api_key(key: QAApiKey) -> None:
    with _lock:
        raw: list[dict] = _read_json(_qa_api_keys_path()) or []
        raw = [r for r in raw if r.get("id") != key.id]
        raw.append(key.model_dump(mode="json"))
        _write_json(_qa_api_keys_path(), raw)


def delete_qa_api_key(key_id: str) -> bool:
    """Remove a QA API key by ID.  Returns True if a key was removed."""
    with _lock:
        raw: list[dict] = _read_json(_qa_api_keys_path()) or []
        new_raw = [r for r in raw if r.get("id") != key_id]
        if len(new_raw) == len(raw):
            return False
        _write_json(_qa_api_keys_path(), new_raw)
    return True


def validate_qa_api_key(raw_key: str) -> QAApiKey | None:
    """Return the matching QAApiKey if the raw key is valid, else None.

    Also updates last_used_at on a successful match.
    """
    import hashlib as _hashlib
    key_hash = _hashlib.sha256(raw_key.encode()).hexdigest()
    with _lock:
        raw: list[dict] = _read_json(_qa_api_keys_path()) or []
        for i, item in enumerate(raw):
            if item.get("key_hash") == key_hash:
                from datetime import datetime, timezone
                item["last_used_at"] = datetime.now(timezone.utc).isoformat()
                raw[i] = item
                _write_json(_qa_api_keys_path(), raw)
                try:
                    return QAApiKey(**item)
                except Exception:
                    return None
    return None
