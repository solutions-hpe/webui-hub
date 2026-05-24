"""Background workers for Hub maintenance, monitoring, and command routing.

These coroutines are started from the FastAPI lifespan hook and run on fixed
intervals: gkill polling every 5 minutes, heartbeat checks every 30 seconds,
auto-recovery every 30 minutes, schedule evaluation every minute, Aruba polling
every 5 minutes, state-transition notifications every minute, and maintenance
purges every 5 minutes. Each worker evaluates tenant and spoke processing
mode so Hub either executes centrally or queues work for distributed spoke
execution through the spoke inbox/ack relay.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from . import store
from .aruba import (
    ArubaClient,
    DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS,
    DEFAULT_NEW_CENTRAL_MONITORED_CHECKS,
    validate_cluster_url,
)
from .crypto import decrypt_dict
from .data_models import AuditEntry, Command
from .config import get_settings
from .notifications import get_notification_config
from .ws import ws_broadcast

logger = logging.getLogger(__name__)

GKILL_SWITCH_URL = "https://raw.githubusercontent.com/solutions-hpe/main/main/gkill"

gkill_state: dict[str, Any] = {"value": "off", "last_fetched": 0.0, "error": None}
spoke_online: dict[str, dict[str, bool]] = {}
# Hub-side Aruba Central status cache: tenant_id → polled status
_hub_central_status: dict[str, dict] = {}
_cache_updated_at: dict[str, float] = {}
# Per-tenant rolling 60-min client count samples: tenant_id → {wsite → [(ts, count), ...]}
_hub_client_samples: dict[str, dict[str, list[tuple[float, int]]]] = {}
_hub_client_baseline: dict[str, dict[str, dict[str, float]]] = {}

HUB_CLIENT_COUNT_MIN_SAMPLES = 3
HUB_CLIENT_COUNT_DROP_PCT = 25.0
HUB_CLIENT_WINDOW_SECS = 3600


def _set_hub_central_status(tenant_id: str, payload: dict[str, Any]) -> None:
    _hub_central_status[tenant_id] = payload
    _cache_updated_at[tenant_id] = time.time()


def _clear_hub_central_status(tenant_id: str) -> None:
    _hub_central_status.pop(tenant_id, None)
    _cache_updated_at.pop(tenant_id, None)


def _now() -> datetime:
    """Return the current UTC timestamp for task scheduling and retention checks."""
    return datetime.now(timezone.utc)


def _cmd(spoke_id: str, tenant_id: str, cmd_type: str, payload: dict[str, Any]) -> Command:
    """Build a 24-hour command queue entry destined for a specific spoke."""
    return Command(
        spoke_id=spoke_id,
        tenant_id=tenant_id,
        type=cmd_type,
        payload=payload,
        expires_at=_now() + timedelta(hours=24),
    )


def _audit(spoke_id: str, tenant_id: str, task_type: str, mode: str, status: str, detail: str = "") -> AuditEntry:
    """Create a normalized audit record for work initiated by background tasks."""
    return AuditEntry(
        spoke_id=spoke_id,
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
        for spoke in store.list_spokes(tenant.id):
            if spoke.status != "approved":
                continue
            mode = spoke.processing_mode.resolve("gkill")
            if mode == "distributed":
                store.enqueue_command(_cmd(spoke.id, tenant.id, "gkill_update", {"value": value}))
            store.append_audit(_audit(spoke.id, tenant.id, "gkill", mode, "success", f"gkill={value}"))


async def heartbeat_monitor() -> None:
    """Check spoke last_seen every 30 seconds. Update online state, broadcast changes."""
    await asyncio.sleep(30)
    while True:
        try:
            changed = False
            for tenant in store.list_tenants():
                tenant_state = spoke_online.setdefault(tenant.id, {})
                for spoke in store.list_spokes(tenant.id):
                    if spoke.status != "approved":
                        continue
                    # Use 300s to match the frontend isOnline() threshold — keeps the
                    # WS heartbeat_update in sync with what the browser displays.
                    online = bool(spoke.last_seen and (_now() - spoke.last_seen).total_seconds() < 300)
                    prev = tenant_state.get(spoke.id)
                    if prev != online:
                        tenant_state[spoke.id] = online
                        changed = True
                        logger.info(
                            "Spoke %s (%s) went %s",
                            spoke.hostname,
                            spoke.id,
                            "online" if online else "offline",
                        )
            if changed:
                await ws_broadcast(
                    {
                        "type": "heartbeat_update",
                        "island_online": {tenant_id: dict(values) for tenant_id, values in spoke_online.items()},
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
                for spoke in store.list_spokes(tenant.id):
                    if spoke.status != "approved":
                        continue
                    timeout_hours = float(spoke.config.get("vm_silent_timeout", 24))
                    if not spoke.last_seen:
                        continue
                    offline_secs = (_now() - spoke.last_seen).total_seconds()
                    if offline_secs > timeout_hours * 3600:
                        mode = spoke.processing_mode.resolve("heartbeat")
                        store.enqueue_command(
                            _cmd(
                                spoke.id,
                                tenant.id,
                                "auto_recovery",
                                {"reason": f"Spoke offline for {offline_secs / 3600:.1f}h"},
                            )
                        )
                        store.append_audit(
                            _audit(
                                spoke.id,
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
                                "message": f"Auto-recovery: spoke {spoke.hostname} offline {offline_secs / 3600:.1f}h",
                            }
                        )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Auto-recovery error: %s", exc)
        await asyncio.sleep(1800)


_last_schedule_trigger: dict[str, str] = {}


async def schedule_check() -> None:
    """Check per-spoke schedules every 60 seconds."""
    await asyncio.sleep(60)
    while True:
        try:
            now = _now()
            day_names = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
            current_day = day_names[now.weekday()]

            for tenant in store.list_tenants():
                for spoke in store.list_spokes(tenant.id):
                    if spoke.status != "approved":
                        continue
                    cfg = spoke.config
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
                    if _last_schedule_trigger.get(spoke.id) == trigger_key:
                        continue
                    _last_schedule_trigger[spoke.id] = trigger_key

                    mode = spoke.processing_mode.resolve("schedules")
                    store.enqueue_command(_cmd(spoke.id, tenant.id, "reclone_schedule", {}))
                    store.append_audit(_audit(spoke.id, tenant.id, "schedule", mode, "pending", f"Scheduled reclone: {cron}"))
                    logger.info("Schedule triggered reclone for spoke %s (%s)", spoke.hostname, spoke.id)
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
        cfg["cluster_url"] = validate_cluster_url(cfg.get("cluster_url", ""))
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


def _normalize_site_token(value: Any) -> str:
    return " ".join(str(value or "").strip().casefold().split())


async def _auto_discover_hub_central_config(tenant_id: str, client: ArubaClient) -> dict[str, Any]:
    config = dict(store.get_tenant_central_sites_config(tenant_id) or {})
    site_mappings = dict(config.get("site_mappings") or {}) if isinstance(config.get("site_mappings"), dict) else {}
    monitored_checks = list(config.get("monitored_checks") or []) if isinstance(config.get("monitored_checks"), list) else []
    hardware_checks = list(config.get("hardware_checks") or []) if isinstance(config.get("hardware_checks"), list) else []
    changed = False

    discovered_sites = await client.list_sites()
    existing_wsites = {_normalize_site_token(name) for name in site_mappings}
    existing_central = {_normalize_site_token(name) for name in site_mappings.values()}
    for site in discovered_sites:
        site_name = str((site or {}).get("name") or "").strip()
        normalized = _normalize_site_token(site_name)
        if not normalized or normalized in existing_wsites or normalized in existing_central:
            continue
        site_mappings[site_name] = site_name
        existing_wsites.add(normalized)
        existing_central.add(normalized)
        changed = True

    if client.api_version == "new_central" and not monitored_checks:
        monitored_checks = [dict(item) for item in DEFAULT_NEW_CENTRAL_MONITORED_CHECKS]
        changed = True
    if client.api_version == "new_central" and not hardware_checks:
        hardware_checks = [dict(item) for item in DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS]
        changed = True

    normalized_config = {
        "site_mappings": {str(wsite).strip(): str(central_site).strip() for wsite, central_site in site_mappings.items() if str(wsite).strip() and str(central_site).strip()},
        "monitored_checks": [dict(item) for item in monitored_checks if isinstance(item, dict)],
        "hardware_checks": [dict(item) for item in hardware_checks if isinstance(item, dict)],
    }
    if changed:
        store.set_tenant_central_sites_config(tenant_id, normalized_config)
    return normalized_config


def _load_hub_client_baseline(tenant_id: str) -> None:
    if tenant_id in _hub_client_baseline:
        return
    tenant = store.get_tenant(tenant_id)
    saved = ((tenant.hub_config or {}).get("hub_client_baseline", {}) if tenant else {}) or {}
    baseline: dict[str, dict[str, float]] = {}
    if isinstance(saved, dict):
        for wsite, info in saved.items():
            if not isinstance(info, dict):
                continue
            try:
                hourly_avg = float(info.get("hourly_avg") or 0.0)
                recorded_at = float(info.get("recorded_at") or 0.0)
            except (TypeError, ValueError):
                continue
            baseline[str(wsite)] = {"hourly_avg": hourly_avg, "recorded_at": recorded_at}
    _hub_client_baseline[tenant_id] = baseline


def _refresh_hub_client_baseline(tenant_id: str) -> None:
    tenant_samples = _hub_client_samples.get(tenant_id, {})
    baseline = _hub_client_baseline.setdefault(tenant_id, {})
    for wsite, samples in tenant_samples.items():
        if len(samples) < HUB_CLIENT_COUNT_MIN_SAMPLES:
            continue
        baseline[wsite] = {
            "hourly_avg": sum(sample[1] for sample in samples) / len(samples),
            "recorded_at": samples[-1][0],
        }


def _persist_hub_client_baseline(tenant_id: str) -> None:
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        return
    baseline = _hub_client_baseline.get(tenant_id, {})
    payload = {
        str(wsite): {
            "hourly_avg": float(info.get("hourly_avg") or 0.0),
            "recorded_at": float(info.get("recorded_at") or 0.0),
        }
        for wsite, info in baseline.items()
        if isinstance(info, dict)
    }
    hub_config = dict(tenant.hub_config or {})
    if hub_config.get("hub_client_baseline") == payload:
        return
    hub_config["hub_client_baseline"] = payload
    tenant.hub_config = hub_config
    store.save_tenant(tenant)


def _hub_client_count_payload(tenant_id: str, site_mappings: dict[str, str]) -> dict[str, Any]:
    _load_hub_client_baseline(tenant_id)
    tenant_samples = _hub_client_samples.get(tenant_id, {})
    baseline = _hub_client_baseline.get(tenant_id, {})
    result: dict[str, Any] = {}
    for wsite, samples in tenant_samples.items():
        if not samples:
            continue
        current = samples[-1][1]
        site_name = site_mappings.get(wsite, wsite)
        if len(samples) < HUB_CLIENT_COUNT_MIN_SAMPLES:
            saved = baseline.get(wsite)
            if saved:
                avg = float(saved.get("hourly_avg") or 0.0)
                drop_pct = max(0.0, (avg - current) / avg * 100.0) if avg >= 1 else 0.0
                status = "DEGRADED" if drop_pct >= HUB_CLIENT_COUNT_DROP_PCT else "OK"
                result[wsite] = {
                    "site_name": site_name,
                    "current": current,
                    "hourly_avg": avg,
                    "drop_pct": drop_pct,
                    "status": status,
                    "ts": samples[-1][0],
                    "baseline_stale": True,
                    "baseline_recorded_at": saved.get("recorded_at"),
                }
            else:
                result[wsite] = {
                    "site_name": site_name,
                    "current": current,
                    "hourly_avg": current,
                    "drop_pct": 0.0,
                    "status": "NO_DATA",
                    "ts": samples[-1][0],
                    "baseline_stale": False,
                }
            continue
        avg = sum(sample[1] for sample in samples) / len(samples)
        drop_pct = max(0.0, (avg - current) / avg * 100.0) if avg >= 1 else 0.0
        status = "DEGRADED" if drop_pct >= HUB_CLIENT_COUNT_DROP_PCT else "OK"
        result[wsite] = {
            "site_name": site_name,
            "current": current,
            "hourly_avg": avg,
            "drop_pct": drop_pct,
            "status": status,
            "ts": samples[-1][0],
            "baseline_stale": False,
        }
    return result


async def hub_baseline_saver() -> None:
    await asyncio.sleep(HUB_CLIENT_WINDOW_SECS)
    while True:
        try:
            active_tenant_ids = {tenant.id for tenant in store.list_tenants()}
            for tenant_id in list(_hub_client_baseline):
                if tenant_id not in active_tenant_ids:
                    _hub_client_baseline.pop(tenant_id, None)
                    _hub_client_samples.pop(tenant_id, None)
                    continue
                _refresh_hub_client_baseline(tenant_id)
                _persist_hub_client_baseline(tenant_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Hub baseline saver error: %s", exc)
        await asyncio.sleep(HUB_CLIENT_WINDOW_SECS)


async def aruba_poller() -> None:
    """Poll Aruba Central every 5 minutes per tenant. Centralized or push config to islands."""
    await asyncio.sleep(60)
    while True:
        try:
            tenants = store.list_tenants()
            active_tenant_ids = {tenant.id for tenant in tenants}
            for tenant in tenants:
                spokes = [spoke for spoke in store.list_spokes(tenant.id) if spoke.status == "approved"]
                if not spokes:
                    continue

                client = _get_aruba_client(tenant.id)
                tenant_config: dict[str, Any] | None = None
                if any(spoke.processing_mode.resolve("aruba_polling") == "distributed" for spoke in spokes):
                    if tenant.aruba_config_enc:
                        try:
                            tenant_config = decrypt_dict(tenant.aruba_config_enc)
                        except Exception as exc:
                            logger.warning("Failed to load Aruba config for tenant %s: %s", tenant.id, exc)

                distributed_spokes = [spoke for spoke in spokes if spoke.processing_mode.resolve("aruba_polling") == "distributed"]
                for spoke in distributed_spokes:
                    if not tenant_config:
                        store.append_audit(_audit(spoke.id, tenant.id, "aruba_poll", "distributed", "failure", "Aruba config unavailable"))
                        continue
                    store.enqueue_command(_cmd(spoke.id, tenant.id, "aruba_config_update", tenant_config))
                    store.append_audit(_audit(spoke.id, tenant.id, "aruba_poll", "distributed", "pending", "Aruba config pushed"))

                centralized_spokes = [spoke for spoke in spokes if spoke.processing_mode.resolve("aruba_polling") == "centralized"]
                if not centralized_spokes:
                    _clear_hub_central_status(tenant.id)
                    continue
                if not client or not client.is_configured():
                    _set_hub_central_status(
                        tenant.id,
                        {
                            "spokes": {},
                            "token_valid": False,
                            "token_state": "not_configured",
                            "client_count_status": {},
                            "central_sites_config": store.get_tenant_central_sites_config(tenant.id),
                        },
                    )
                    continue

                try:
                    findings = await client.poll_alerts_and_insights()
                except Exception as exc:
                    _set_hub_central_status(
                        tenant.id,
                        {
                            "spokes": {},
                            "token_valid": False,
                            "token_state": {"state": "error", "detail": str(exc)},
                            "client_count_status": {},
                            "central_sites_config": store.get_tenant_central_sites_config(tenant.id),
                        },
                    )
                    await ws_broadcast(
                        {
                            "type": "aruba_update",
                            "tenant_id": tenant.id,
                            "findings": [],
                            "status": {},
                            "wireless_clients": {},
                            "hardware_alerts": [],
                            "client_count_status": {},
                            "central_sites_config": store.get_tenant_central_sites_config(tenant.id),
                            "token_state": {"state": "error", "detail": str(exc)},
                        }
                    )
                    for spoke in centralized_spokes:
                        store.append_audit(_audit(spoke.id, tenant.id, "aruba_poll", "centralized", "failure", str(exc)))
                    continue

                finding_payload = [
                    {"site": finding.site_name, "check": finding.check_name, "status": finding.status, "source": finding.source}
                    for finding in findings
                ]
                for spoke in centralized_spokes:
                    store.append_audit(
                        _audit(spoke.id, tenant.id, "aruba_poll", "centralized", "success", f"{len(findings)} findings")
                    )

                try:
                    site_raw: dict[str, dict[str, Any]] = {}
                    spokes_status: dict[str, dict[str, Any]] = {}
                    hub_sites_cfg = await _auto_discover_hub_central_config(tenant.id, client)
                    hub_site_mappings = hub_sites_cfg.get("site_mappings", {}) if isinstance(hub_sites_cfg.get("site_mappings"), dict) else {}
                    hub_monitored_checks = hub_sites_cfg.get("monitored_checks", []) if isinstance(hub_sites_cfg.get("monitored_checks"), list) else []
                    hub_hardware_checks = hub_sites_cfg.get("hardware_checks", []) if isinstance(hub_sites_cfg.get("hardware_checks"), list) else []
                    unique_sites = {
                        str(site_name).strip()
                        for site_name in hub_site_mappings.values()
                        if str(site_name).strip()
                    }
                    hw_check_ids = {
                        str(check.get("id") or "").strip()
                        for check in hub_hardware_checks
                        if isinstance(check, dict) and str(check.get("id") or "").strip()
                    }

                    for central_site in unique_sites:
                        site_raw[central_site] = await client.poll_site_data(central_site, hw_check_ids=hw_check_ids)

                    now = time.time()
                    cutoff = now - HUB_CLIENT_WINDOW_SECS
                    _load_hub_client_baseline(tenant.id)
                    tenant_samples = _hub_client_samples.setdefault(tenant.id, {})
                    for wsite, central_site in hub_site_mappings.items():
                        raw = site_raw.get(central_site, {})
                        wl_count = int(raw.get("client_count") or raw.get("wireless_clients") or 0)
                        samples = tenant_samples.setdefault(wsite, [])
                        samples.append((now, wl_count))
                        tenant_samples[wsite] = [sample for sample in samples if sample[0] >= cutoff]
                    _refresh_hub_client_baseline(tenant.id)
                    client_count_status = _hub_client_count_payload(tenant.id, hub_site_mappings)

                    aggregated_status: dict[str, dict[str, Any]] = {}
                    aggregated_wireless_clients: dict[str, int] = {}
                    hw_sites: dict[str, dict[str, list[str]]] = {
                        str(check.get("id")): {}
                        for check in hub_hardware_checks
                        if isinstance(check, dict) and str(check.get("id") or "").strip()
                    }

                    for wsite, central_site in hub_site_mappings.items():
                        raw = site_raw.get(central_site, {})
                        alert_type_counts = raw.get("alert_type_counts", {}) if isinstance(raw.get("alert_type_counts"), dict) else {}
                        insight_cat_counts = raw.get("insight_cat_counts", {}) if isinstance(raw.get("insight_cat_counts"), dict) else {}
                        site_hw_devices = raw.get("hw_devices", {}) if isinstance(raw.get("hw_devices"), dict) else {}
                        site_status: dict[str, Any] = {}

                        for check in hub_monitored_checks:
                            if not isinstance(check, dict):
                                continue
                            check_type = str(check.get("type") or "")
                            check_id = str(check.get("id") or "").strip()
                            check_name = str(check.get("name") or check_id)
                            if not check_id:
                                continue
                            if check_type == "alert":
                                count = int(alert_type_counts.get(check_id, 0) or 0)
                            elif check_type == "insight":
                                count = int(insight_cat_counts.get(check_id, 0) or 0)
                            else:
                                continue
                            site_status[check_id] = {
                                "status": "OK" if count > 0 else "ERROR",
                                "count": count,
                                "check_name": check_name,
                                "check_type": check_type,
                                "ts": now,
                            }

                        aggregated_status[wsite] = site_status
                        aggregated_wireless_clients[wsite] = int(raw.get("wireless_clients") or raw.get("client_count") or 0)

                        for check in hub_hardware_checks:
                            if not isinstance(check, dict):
                                continue
                            check_id = str(check.get("id") or "").strip()
                            if not check_id:
                                continue
                            devices_for_check = site_hw_devices.get(check_id, {}) if isinstance(site_hw_devices.get(check_id), dict) else {}
                            device_names = sorted(str(name).strip() for name in devices_for_check if str(name).strip())
                            if device_names:
                                hw_sites.setdefault(check_id, {})[wsite] = device_names

                    aggregated_hardware_alerts: list[dict[str, Any]] = []
                    for check in hub_hardware_checks:
                        if not isinstance(check, dict):
                            continue
                        check_id = str(check.get("id") or "").strip()
                        if not check_id:
                            continue
                        devices_by_site = hw_sites.get(check_id, {})
                        aggregated_hardware_alerts.append(
                            {
                                "id": check_id,
                                "name": check.get("name") or check_id,
                                "device_type": check.get("device_type") or check_id,
                                "total": sum(len(devices) for devices in devices_by_site.values()),
                                "sites": {
                                    wsite: {"site_name": hub_site_mappings.get(wsite, wsite), "devices": devices}
                                    for wsite, devices in devices_by_site.items()
                                },
                            }
                        )

                    for spoke in centralized_spokes:
                        spokes_status[spoke.id] = {
                            "status": dict(aggregated_status),
                            "wireless_clients": dict(aggregated_wireless_clients),
                            "hardware_alerts": list(aggregated_hardware_alerts),
                            "client_count_status": dict(client_count_status),
                            "site_mappings": dict(hub_site_mappings),
                            "monitored_checks": list(hub_monitored_checks),
                            "hardware_checks": list(hub_hardware_checks),
                        }

                    _set_hub_central_status(
                        tenant.id,
                        {
                            "spokes": spokes_status,
                            "token_valid": True,
                            "token_state": "connected",
                            "client_count_status": client_count_status,
                            "central_sites_config": hub_sites_cfg,
                        },
                    )
                    await ws_broadcast(
                        {
                            "type": "aruba_update",
                            "tenant_id": tenant.id,
                            "findings": finding_payload,
                            "status": aggregated_status,
                            "wireless_clients": aggregated_wireless_clients,
                            "hardware_alerts": aggregated_hardware_alerts,
                            "client_count_status": client_count_status,
                            "central_sites_config": hub_sites_cfg,
                            "token_state": {"state": "connected", "detail": ""},
                        }
                    )
                except Exception as exc:
                    _set_hub_central_status(
                        tenant.id,
                        {
                            "spokes": {},
                            "token_valid": False,
                            "token_state": {"state": "error", "detail": str(exc)},
                            "client_count_status": {},
                            "central_sites_config": store.get_tenant_central_sites_config(tenant.id),
                        },
                    )
                    await ws_broadcast(
                        {
                            "type": "aruba_update",
                            "tenant_id": tenant.id,
                            "findings": finding_payload,
                            "status": {},
                            "wireless_clients": {},
                            "hardware_alerts": [],
                            "client_count_status": {},
                            "central_sites_config": store.get_tenant_central_sites_config(tenant.id),
                            "token_state": {"state": "error", "detail": str(exc)},
                        }
                    )
                    for spoke in centralized_spokes:
                        store.append_audit(_audit(spoke.id, tenant.id, "aruba_poll", "centralized", "failure", str(exc)))

            for tenant_id in list(_hub_central_status):
                if tenant_id not in active_tenant_ids:
                    _clear_hub_central_status(tenant_id)
            for tenant_id in list(_hub_client_samples):
                if tenant_id not in active_tenant_ids:
                    _hub_client_samples.pop(tenant_id, None)
                    _hub_client_baseline.pop(tenant_id, None)
            for tenant_id in list(_aruba_clients):
                if tenant_id not in active_tenant_ids:
                    _aruba_clients.pop(tenant_id, None)
                    _aruba_client_hashes.pop(tenant_id, None)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Aruba poller error: %s", exc)
        await asyncio.sleep(300)


async def send_notification(tenant_id: str, spoke_id: str, title: str, message: str, mode: str = "centralized") -> None:
    """Send notifications centrally or queue spoke-side delivery based on feature mode."""
    from .notifications import send_email, send_teams_webhook

    cfg = get_notification_config(tenant_id)
    if not cfg:
        return

    spoke = store.get_spoke(tenant_id, spoke_id) if spoke_id else None
    teams_mode = spoke.processing_mode.resolve("teams_webhook") if spoke else mode
    email_mode = spoke.processing_mode.resolve("email") if spoke else mode

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

    if distributed and spoke_id:
        store.enqueue_command(
            _cmd(
                spoke_id,
                tenant_id,
                "notification_push",
                {"title": title, "message": message, "config": distributed_cfg},
            )
        )
        store.append_audit(_audit(spoke_id, tenant_id, "notification", "distributed", "pending", title))
    if centralized and spoke_id:
        store.append_audit(_audit(spoke_id, tenant_id, "notification", "centralized", "success", title))


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


async def acme_renewal_check() -> None:
    """Check ACME certificates on startup and every 24 hours thereafter."""
    settings = get_settings()
    from .acme import get_cert_info, renew_if_needed

    while True:
        try:
            renewed = await renew_if_needed(Path(settings.data_dir))
            if renewed:
                cert_info = get_cert_info()
                logger.info("ACME certificate renewed; expires %s", cert_info.get("expires", ""))
                await ws_broadcast({"type": "cert_renewed", "expires": cert_info.get("expires", "")})
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("ACME renewal check error: %s", exc)
        await asyncio.sleep(86400)


async def check_state_engine() -> None:
    """Evaluate spoke online/offline status and fire notifications on transitions."""
    await asyncio.sleep(60)
    prev_online: dict[str, bool] = {}
    while True:
        try:
            for tenant in store.list_tenants():
                for spoke in store.list_spokes(tenant.id):
                    if spoke.status != "approved":
                        continue
                    key = f"{tenant.id}:{spoke.id}"
                    # Use 300s to match the frontend isOnline() threshold.
                    online = bool(spoke.last_seen and (_now() - spoke.last_seen).total_seconds() < 300)
                    was_online = prev_online.get(key)
                    if was_online is True and not online:
                        await send_notification(
                            tenant.id,
                            spoke.id,
                            f"🔴 Spoke Offline: {spoke.hostname}",
                            f"Spoke {spoke.hostname} has gone offline (no telemetry in 10 minutes).",
                        )
                    prev_online[key] = online
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Check state engine error: %s", exc)
        await asyncio.sleep(60)
