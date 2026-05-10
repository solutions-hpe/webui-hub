"""Background workers for Hub maintenance, monitoring, and command routing.

These coroutines are started from the FastAPI lifespan hook and run on fixed
intervals: gkill polling every 5 minutes, heartbeat checks every 30 seconds,
auto-recovery every 30 minutes, schedule evaluation every minute, Aruba polling
every 5 minutes, state-transition notifications every minute, and maintenance
purges every 5 minutes. Each worker evaluates tenant and island processing
mode so Hub either executes centrally or queues work for distributed spoke
execution through the island inbox/ack relay.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from . import store
from .aruba import ArubaClient
from .crypto import decrypt_dict
from .data_models import AuditEntry, Command
from .notifications import get_notification_config
from .ws import ws_broadcast

logger = logging.getLogger(__name__)

GKILL_SWITCH_URL = "https://raw.githubusercontent.com/solutions-hpe/main/main/gkill"

gkill_state: dict[str, Any] = {"value": "off", "last_fetched": 0.0, "error": None}
island_online: dict[str, dict[str, bool]] = {}


def _now() -> datetime:
    """Return the current UTC timestamp for task scheduling and retention checks."""
    return datetime.now(timezone.utc)


def _cmd(island_id: str, tenant_id: str, cmd_type: str, payload: dict[str, Any]) -> Command:
    """Build a 24-hour command queue entry destined for a specific island."""
    return Command(
        island_id=island_id,
        tenant_id=tenant_id,
        type=cmd_type,
        payload=payload,
        expires_at=_now() + timedelta(hours=24),
    )


def _audit(island_id: str, tenant_id: str, task_type: str, mode: str, status: str, detail: str = "") -> AuditEntry:
    """Create a normalized audit record for work initiated by background tasks."""
    return AuditEntry(
        island_id=island_id,
        tenant_id=tenant_id,
        task_type=task_type,
        execution_mode=mode,
        status=status,
        detail=detail,
        initiated_by="system",
    )


async def gkill_switch_poller() -> None:
    """Poll global kill switch from GitHub every 5 minutes. Broadcast changes."""
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            try:
                resp = await client.get(GKILL_SWITCH_URL)
                value = resp.text.strip().lower()
                if value not in {"on", "off"}:
                    value = "off"
                prev = gkill_state["value"]
                gkill_state["value"] = value
                gkill_state["last_fetched"] = _now().timestamp()
                gkill_state["error"] = None
                if value != prev:
                    logger.warning("GKill switch changed: %s → %s", prev, value)
                    await _broadcast_gkill(value)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                gkill_state["error"] = str(exc)
                logger.warning("GKill switch fetch failed: %s", exc)
            await asyncio.sleep(300)


async def _broadcast_gkill(value: str) -> None:
    """Publish a new gkill value to the UI and queue updates for distributed islands."""
    await ws_broadcast({"type": "gkill_switch_update", "value": value})
    for tenant in store.list_tenants():
        for island in store.list_islands(tenant.id):
            if island.status != "approved":
                continue
            mode = island.processing_mode.resolve("gkill")
            if mode == "distributed":
                store.enqueue_command(_cmd(island.id, tenant.id, "gkill_update", {"value": value}))
            store.append_audit(_audit(island.id, tenant.id, "gkill", mode, "success", f"gkill={value}"))


async def heartbeat_monitor() -> None:
    """Check island last_seen every 30 seconds. Update online state, broadcast changes."""
    await asyncio.sleep(30)
    while True:
        try:
            changed = False
            for tenant in store.list_tenants():
                tenant_state = island_online.setdefault(tenant.id, {})
                for island in store.list_islands(tenant.id):
                    if island.status != "approved":
                        continue
                    online = bool(island.last_seen and (_now() - island.last_seen).total_seconds() < 120)
                    prev = tenant_state.get(island.id)
                    if prev != online:
                        tenant_state[island.id] = online
                        changed = True
                        logger.info(
                            "Island %s (%s) went %s",
                            island.hostname,
                            island.id,
                            "online" if online else "offline",
                        )
            if changed:
                await ws_broadcast(
                    {
                        "type": "heartbeat_update",
                        "island_online": {tenant_id: dict(values) for tenant_id, values in island_online.items()},
                    }
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Heartbeat monitor error: %s", exc)
        await asyncio.sleep(30)


async def auto_recovery_check() -> None:
    """Check for islands offline > configured threshold and queue recovery commands."""
    await asyncio.sleep(1800)
    while True:
        try:
            for tenant in store.list_tenants():
                for island in store.list_islands(tenant.id):
                    if island.status != "approved":
                        continue
                    timeout_hours = island.config.get("vm_silent_timeout", 24)
                    if not island.last_seen:
                        continue
                    offline_secs = (_now() - island.last_seen).total_seconds()
                    if offline_secs > timeout_hours * 3600:
                        mode = island.processing_mode.resolve("heartbeat")
                        store.enqueue_command(
                            _cmd(
                                island.id,
                                tenant.id,
                                "auto_recovery",
                                {"reason": f"Island offline for {offline_secs / 3600:.1f}h"},
                            )
                        )
                        store.append_audit(
                            _audit(
                                island.id,
                                tenant.id,
                                "auto_recovery",
                                mode,
                                "pending",
                                f"Offline {offline_secs / 3600:.1f}h — recovery queued",
                            )
                        )
                        await ws_broadcast(
                            {
                                "type": "notification",
                                "level": "warning",
                                "tenant_id": tenant.id,
                                "message": f"Auto-recovery: island {island.hostname} offline {offline_secs / 3600:.1f}h",
                            }
                        )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Auto-recovery error: %s", exc)
        await asyncio.sleep(1800)


_last_schedule_trigger: dict[str, str] = {}


async def schedule_check() -> None:
    """Check per-island schedules every 60 seconds."""
    await asyncio.sleep(60)
    while True:
        try:
            now = _now()
            day_names = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
            current_day = day_names[now.weekday()]

            for tenant in store.list_tenants():
                for island in store.list_islands(tenant.id):
                    if island.status != "approved":
                        continue
                    cfg = island.config
                    if cfg.get("reclone_schedule_enabled") != "on":
                        continue
                    cron = cfg.get("reclone_schedule_cron", "sunday 02:00")
                    parts = cron.strip().lower().split()
                    if len(parts) != 2:
                        continue
                    sched_day = parts[0]
                    try:
                        sched_hour, sched_min = map(int, parts[1].split(":"))
                    except ValueError:
                        continue

                    if current_day != sched_day or now.hour != sched_hour or now.minute != sched_min:
                        continue

                    trigger_key = now.strftime("%Y-%m-%d %H:%M")
                    if _last_schedule_trigger.get(island.id) == trigger_key:
                        continue
                    _last_schedule_trigger[island.id] = trigger_key

                    mode = island.processing_mode.resolve("schedules")
                    store.enqueue_command(_cmd(island.id, tenant.id, "reclone_schedule", {}))
                    store.append_audit(_audit(island.id, tenant.id, "schedule", mode, "pending", f"Scheduled reclone: {cron}"))
                    logger.info("Schedule triggered reclone for island %s (%s)", island.hostname, island.id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Schedule check error: %s", exc)
        await asyncio.sleep(60)


_aruba_clients: dict[str, ArubaClient] = {}
_aruba_client_hashes: dict[str, str] = {}


def _get_aruba_client(tenant_id: str) -> ArubaClient | None:
    """Return a cached Aruba client for a tenant, rebuilding it when config changes."""
    tenant = store.get_tenant(tenant_id)
    if not tenant or not tenant.aruba_config_enc:
        _aruba_clients.pop(tenant_id, None)
        _aruba_client_hashes.pop(tenant_id, None)
        return None
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
        cfg_hash = hashlib.md5(json.dumps(cfg, sort_keys=True, default=str).encode()).hexdigest()
        cached = _aruba_clients.get(tenant_id)
        if cached and _aruba_client_hashes.get(tenant_id) == cfg_hash:
            return cached
        client = ArubaClient(cfg)
        _aruba_clients[tenant_id] = client
        _aruba_client_hashes[tenant_id] = cfg_hash
        return client
    except Exception as exc:
        logger.warning("Failed to load Aruba config for tenant %s: %s", tenant_id, exc)
        _aruba_clients.pop(tenant_id, None)
        _aruba_client_hashes.pop(tenant_id, None)
        return None


async def aruba_poller() -> None:
    """Poll Aruba Central every 5 minutes per tenant. Centralized or push config to islands."""
    await asyncio.sleep(60)
    while True:
        try:
            for tenant in store.list_tenants():
                islands = [island for island in store.list_islands(tenant.id) if island.status == "approved"]
                if not islands:
                    continue

                client = _get_aruba_client(tenant.id)
                tenant_config: dict[str, Any] | None = None
                if any(island.processing_mode.resolve("aruba_polling") == "distributed" for island in islands):
                    if tenant.aruba_config_enc:
                        try:
                            tenant_config = decrypt_dict(tenant.aruba_config_enc)
                        except Exception as exc:
                            logger.warning("Failed to load Aruba config for tenant %s: %s", tenant.id, exc)

                distributed_islands = [island for island in islands if island.processing_mode.resolve("aruba_polling") == "distributed"]
                for island in distributed_islands:
                    if not tenant_config:
                        store.append_audit(_audit(island.id, tenant.id, "aruba_poll", "distributed", "failure", "Aruba config unavailable"))
                        continue
                    store.enqueue_command(_cmd(island.id, tenant.id, "aruba_config_update", tenant_config))
                    store.append_audit(_audit(island.id, tenant.id, "aruba_poll", "distributed", "pending", "Aruba config pushed"))

                centralized_islands = [island for island in islands if island.processing_mode.resolve("aruba_polling") == "centralized"]
                if not centralized_islands:
                    continue
                if not client or not client.is_configured():
                    continue

                try:
                    findings = await client.poll_alerts_and_insights()
                except Exception as exc:
                    for island in centralized_islands:
                        store.append_audit(_audit(island.id, tenant.id, "aruba_poll", "centralized", "failure", str(exc)))
                    continue

                finding_payload = [
                    {"site": finding.site_name, "check": finding.check_name, "status": finding.status, "source": finding.source}
                    for finding in findings
                ]
                for island in centralized_islands:
                    store.append_audit(
                        _audit(island.id, tenant.id, "aruba_poll", "centralized", "success", f"{len(findings)} findings")
                    )
                    await ws_broadcast(
                        {
                            "type": "aruba_update",
                            "tenant_id": tenant.id,
                            "island_id": island.id,
                            "findings": finding_payload,
                        }
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Aruba poller error: %s", exc)
        await asyncio.sleep(300)


async def send_notification(tenant_id: str, island_id: str, title: str, message: str, mode: str = "centralized") -> None:
    """Send notifications centrally or queue island-side delivery based on feature mode."""
    from .notifications import send_email, send_teams_webhook

    cfg = get_notification_config(tenant_id)
    if not cfg:
        return

    island = store.get_island(tenant_id, island_id) if island_id else None
    teams_mode = island.processing_mode.resolve("teams_webhook") if island else mode
    email_mode = island.processing_mode.resolve("email") if island else mode

    distributed_cfg: dict[str, Any] = {"enabled": True}
    distributed = False
    centralized = False

    if cfg.get("teams_webhook"):
        if teams_mode == "distributed":
            distributed_cfg["teams_webhook"] = cfg["teams_webhook"]
            distributed_cfg["teams_webhook_url"] = cfg["teams_webhook"]
            distributed = True
        else:
            await send_teams_webhook(cfg["teams_webhook"], title, message)
            centralized = True

    if cfg.get("smtp_host") and cfg.get("to_emails"):
        if email_mode == "distributed":
            distributed_cfg.update(
                {
                    "smtp_host": cfg["smtp_host"],
                    "smtp_port": cfg.get("smtp_port", 587),
                    "smtp_user": cfg.get("smtp_user", ""),
                    "smtp_pass": cfg.get("smtp_pass", ""),
                    "to_emails": cfg.get("to_emails", []),
                    "from_email": cfg.get("from_email", "hub@localhost"),
                }
            )
            distributed = True
        else:
            await send_email(
                cfg["smtp_host"],
                cfg.get("smtp_port", 587),
                cfg.get("smtp_user", ""),
                cfg.get("smtp_pass", ""),
                cfg.get("from_email", "hub@localhost"),
                cfg["to_emails"],
                title,
                message,
            )
            centralized = True

    if distributed and island_id:
        store.enqueue_command(
            _cmd(
                island_id,
                tenant_id,
                "notification_push",
                {"title": title, "message": message, "config": distributed_cfg},
            )
        )
        store.append_audit(_audit(island_id, tenant_id, "notification", "distributed", "pending", title))
    if centralized and island_id:
        store.append_audit(_audit(island_id, tenant_id, "notification", "centralized", "success", title))


async def maintenance_loop() -> None:
    """Purge expired commands and old audit entries every 5 minutes."""
    while True:
        await asyncio.sleep(300)
        try:
            purged_cmds = store.purge_expired_commands()
            purged_audit = store.purge_old_audit()
            if purged_cmds or purged_audit:
                logger.info("Maintenance: purged %s expired commands, %s old audit entries", purged_cmds, purged_audit)
        except Exception as exc:
            logger.warning("Maintenance error: %s", exc)


async def check_state_engine() -> None:
    """Evaluate island online/offline status and fire notifications on transitions."""
    await asyncio.sleep(60)
    prev_online: dict[str, bool] = {}
    while True:
        try:
            for tenant in store.list_tenants():
                for island in store.list_islands(tenant.id):
                    if island.status != "approved":
                        continue
                    key = f"{tenant.id}:{island.id}"
                    online = bool(island.last_seen and (_now() - island.last_seen).total_seconds() < 120)
                    was_online = prev_online.get(key)
                    if was_online is True and not online:
                        await send_notification(
                            tenant.id,
                            island.id,
                            f"🔴 Island Offline: {island.hostname}",
                            f"Island {island.hostname} has gone offline (no telemetry in 2 minutes).",
                        )
                    prev_online[key] = online
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Check state engine error: %s", exc)
        await asyncio.sleep(60)
