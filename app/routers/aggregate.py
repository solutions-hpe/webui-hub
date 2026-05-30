"""Tenant-scoped aggregate telemetry endpoints."""
from __future__ import annotations

import json
import base64
from collections import Counter
from datetime import datetime, timedelta, timezone
import logging
import secrets
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import auth, store
from ..aruba import (
    ArubaClient,
    DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS,
    DEFAULT_NEW_CENTRAL_MONITORED_CHECKS,
    validate_cluster_url,
)
from ..crypto import decrypt_dict, encrypt_dict
from ..data_models import AuditEntry, Command, Spoke, Tenant, User

router = APIRouter()
logger = logging.getLogger(__name__)

FAIL_STATUSES = {"error", "fail", "failed", "degraded", "critical"}
PASS_STATUSES = {"ok", "pass", "passed", "healthy", "connected"}
WARNING_STATUSES = {"warn", "warning", "unknown", "no_data", "stale"}
MODE_VALUES = {"centralized", "distributed"}
CENTRAL_WEBHOOK_HOST = "cs-hub.westus3.azurecontainer.io:8443"
_central_browse_cache: dict[str, dict[str, Any]] = {}
_central_browse_cache_ts: dict[str, float] = {}
_CENTRAL_BROWSE_TTL = 300


def _browse_cache_path(tenant_id: str) -> Path:
    return store._data_dir() / tenant_id / "central_browse_cache.json"


def _load_browse_disk_cache(tenant_id: str) -> dict[str, Any] | None:
    try:
        p = _browse_cache_path(tenant_id)
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _save_browse_disk_cache(tenant_id: str, data: dict[str, Any]) -> None:
    try:
        p = _browse_cache_path(tenant_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), encoding="utf-8")
    except Exception as exc:
        logger.warning("central_browse: could not write disk cache: %s", exc)


def _is_individual_browse_client(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    return any(key in item for key in ("mac", "hostname", "ip", "ap", "ssid", "status", "os", "vlan"))


def _has_legacy_client_summary_rows(data: dict[str, Any] | None) -> bool:
    clients = data.get("clients") if isinstance(data, dict) else None
    if not isinstance(clients, list) or not clients:
        return False
    has_individual = any(_is_individual_browse_client(item) for item in clients)
    has_summary = any(
        isinstance(item, dict) and any(key in item for key in ("total", "wired", "wireless"))
        for item in clients
    )
    return has_summary and not has_individual


def _normalize_browse_cache(data: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    normalized = dict(data)
    clients = normalized.get("clients")
    if not _has_legacy_client_summary_rows(normalized):
        if not isinstance(clients, list):
            normalized["clients"] = []
        return normalized

    clients_by_site = normalized.get("clients_by_site")
    if not isinstance(clients_by_site, dict):
        derived: dict[str, dict[str, Any]] = {}
        for item in clients:
            if not isinstance(item, dict):
                continue
            site_name = str(item.get("site") or "—").strip() or "—"
            derived[site_name] = {
                "total": int(item.get("total") or 0),
                "wired": int(item.get("wired") or 0),
                "wireless": int(item.get("wireless") or 0),
            }
        normalized["clients_by_site"] = derived

    normalized["clients"] = []
    return normalized


def _central_webhook_endpoint_url(tenant_id: str) -> str:
    return f"https://{CENTRAL_WEBHOOK_HOST}/api/{tenant_id}/webhook/central"


def _load_aruba_config(tenant: Tenant) -> dict[str, Any]:
    if not tenant.aruba_config_enc:
        raise HTTPException(status_code=400, detail="Aruba Central credentials are not configured for this tenant.")
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt Aruba Central credentials: {exc}") from exc
    cfg["cluster_url"] = _validated_cluster_url_or_400(cfg.get("cluster_url", ""))
    return cfg


def _persist_aruba_config(tenant: Tenant, cfg: dict[str, Any]) -> None:
    tenant.aruba_cid = cfg.get("customer_id") or tenant.aruba_cid
    tenant.aruba_config_enc = (
        encrypt_dict(cfg)
        if any(str(value).strip() for key, value in cfg.items() if key != "api_version") or cfg.get("client_secret")
        else None
    )
    store.save_tenant(tenant)


class ConfigPushRequest(BaseModel):
    tenant_id: str = ""
    config: dict[str, Any] = Field(default_factory=dict)


class CentralConfigPayload(BaseModel):
    api_version: str = "classic"
    cluster_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    access_token: str = ""
    customer_id: str = ""
    workspace_id: str = ""


class CentralUpdateRequest(BaseModel):
    tenant_id: str = ""
    mode: str = "distributed"
    hub_central_config: CentralConfigPayload = Field(default_factory=CentralConfigPayload)
    central_browse_interval_minutes: int = 5


class CentralSitesConfigPayload(BaseModel):
    site_mappings: dict[str, str] = Field(default_factory=dict)
    monitored_checks: list[dict[str, Any]] = Field(default_factory=list)
    hardware_checks: list[dict[str, Any]] = Field(default_factory=list)
    excluded_sites: list[str] = Field(default_factory=list)


class SimulationConfUpdateRequest(BaseModel):
    content: str = ""


def _resolve_tenant_id(tenant_id: Optional[str], current_user: User) -> str:
    if tenant_id:
        auth.require_tenant_access(tenant_id, current_user)
        return tenant_id

    tenant_ids = [tenant.id for tenant in store.list_tenants()] if current_user.is_superadmin else current_user.tenant_ids()
    if not tenant_ids:
        raise HTTPException(status_code=404, detail="No tenant available")
    if len(tenant_ids) == 1:
        return tenant_ids[0]
    raise HTTPException(status_code=400, detail="tenant_id query parameter is required")



def _require_tenant_admin(tenant_id: str, current_user: User) -> str:
    auth.require_tenant_access(tenant_id, current_user)
    role = current_user.get_role(tenant_id)
    if current_user.is_superadmin or role == "admin":
        return tenant_id
    raise HTTPException(status_code=403, detail="Admin role required")


def _require_tenant_access(tenant_id: str, current_user: User) -> str:
    """Allow any authenticated user with tenant access (viewer or admin)."""
    auth.require_tenant_access(tenant_id, current_user)
    return tenant_id


def _require_tenant_demo_or_above(tenant_id: str, current_user: User) -> str:
    """Allow demo, viewer, and admin roles (any authenticated tenant member)."""
    auth.require_tenant_access(tenant_id, current_user)
    return tenant_id


def _approved_spokes(tenant_id: str) -> list[Spoke]:
    return [spoke for spoke in store.list_spokes(tenant_id) if spoke.status == "approved"]



def _get_tenant(tenant_id: str) -> Tenant:
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant



def _is_online(spoke: Spoke) -> bool:
    if not spoke.last_seen:
        return False
    last_seen = spoke.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    # Use 300s to match the frontend isOnline() threshold — eliminates the
    # red/green flicker caused by the old 600s backend vs 300s frontend mismatch.
    return (datetime.now(timezone.utc) - last_seen).total_seconds() < 300



def _telemetry_clients(spoke: Spoke) -> list[dict[str, Any]]:
    clients = (spoke.telemetry or {}).get("clients")
    return clients if isinstance(clients, list) else []



def _telemetry_dict(spoke: Spoke, key: str) -> dict[str, Any]:
    value = (spoke.telemetry or {}).get(key)
    return value if isinstance(value, dict) else {}



def _telemetry_list(spoke: Spoke, *keys: str) -> list[dict[str, Any]]:
    telemetry = spoke.telemetry or {}
    for key in keys:
        value = telemetry.get(key)
        if isinstance(value, list):
            return value
    return []



def _coerce_int(value: Any, default: int = 0, *, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        number = int(str(value).strip())
    except (AttributeError, TypeError, ValueError):
        number = default
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number



def _setting_toggle(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}



def _spoke_usb_capacity(spoke: Spoke) -> tuple[int, int, int, bool]:
    """Return (used_slots, total_slots, dongle_count, auto_provision).

    used_slots   — provisioned VMs (active entries in usb_state)
    total_slots  — effective capacity = min(dongle_count, usb_max_slots)
    dongle_count — raw USB dongles physically present
    auto_provision — whether auto-provision is enabled on this spoke
    """
    proxmox = _telemetry_dict(spoke, "proxmox")
    api_server = _telemetry_dict(spoke, "api_server")
    usb_devices = _telemetry_list(spoke, "usb_devices") or (proxmox.get("usb_state") if isinstance(proxmox.get("usb_state"), list) else [])
    # Slots in use = provisioned VMs (active entries in usb_state), not raw USB dongle count
    usb_state = proxmox.get("usb_state") if isinstance(proxmox.get("usb_state"), list) else usb_devices
    used_slots = sum(
        1 for entry in usb_state
        if isinstance(entry, dict) and entry.get("prov_status") in ("active", "provisioning", "tearing_down", "missing")
    ) if usb_state else 0
    # Dongle count = physically present USB devices reported by the agent
    present_usb = proxmox.get("present_usb")
    if isinstance(present_usb, list):
        dongle_count = len(present_usb)
    else:
        dongle_count = _coerce_int(proxmox.get("usb_count") or 0, 0, minimum=0)
    spoke_config = spoke.config or {}
    usb_max_slots = _coerce_int(
        spoke_config.get("usb_max_slots")
        or api_server.get("usb_max_slots")
        or proxmox.get("usb_max_slots")
        or 0,
        0,
        minimum=0,
    )
    # Effective capacity: if max_slots is configured, cap at min(dongles, max_slots);
    # otherwise fall back to raw dongle count.
    if usb_max_slots > 0:
        total_slots = min(dongle_count, usb_max_slots)
    else:
        total_slots = dongle_count
    # Use explicit priority: spoke.config > api_server telemetry > proxmox telemetry.
    # Cannot use `or` because False (disabled) is falsy and would be skipped.
    _ap_sources = [
        spoke_config.get("usb_auto_provision"),
        api_server.get("usb_auto_provision"),
        proxmox.get("usb_auto_provision"),
    ]
    _ap_val = next((v for v in _ap_sources if v is not None), None)
    auto_provision = _setting_toggle(_ap_val)
    return used_slots, total_slots, dongle_count, auto_provision



def _central_telemetry(spoke: Spoke) -> dict[str, Any]:
    telemetry = spoke.telemetry or {}
    central = telemetry.get("central")
    return central if isinstance(central, dict) else telemetry



def _hardware_type(client: dict[str, Any]) -> str:
    return str(client.get("hw_type") or client.get("platform") or "Unknown").strip() or "Unknown"



def _normalize_lookup_value(value: Any) -> str:
    return str(value or "").strip().lower()



def _spoke_usb_lookup(spoke: Spoke) -> tuple[set[str], set[str], dict[str, str]]:
    proxmox = _telemetry_dict(spoke, "proxmox")
    usb_devices = _telemetry_list(spoke, "usb_devices")
    if not usb_devices and isinstance(proxmox.get("usb_state"), list):
        usb_devices = proxmox.get("usb_state")
    proxmox_vms = _telemetry_list(spoke, "proxmox_vms")
    if not proxmox_vms and isinstance(proxmox.get("vms"), list):
        proxmox_vms = proxmox.get("vms")

    usb_vmids = {
        str(device.get("vmid")).strip()
        for device in usb_devices
        if isinstance(device, dict) and device.get("vmid") is not None and str(device.get("vmid")).strip()
    }
    usb_hostnames = {
        _normalize_lookup_value(device.get("hostname") or device.get("vm_name"))
        for device in usb_devices
        if isinstance(device, dict)
    }
    usb_hostnames.discard("")

    vmids_by_hostname: dict[str, str] = {}
    for vm in proxmox_vms:
        if not isinstance(vm, dict):
            continue
        hostname = _normalize_lookup_value(vm.get("name") or vm.get("hostname"))
        vmid = str(vm.get("vmid")).strip() if vm.get("vmid") is not None else ""
        if hostname and vmid:
            vmids_by_hostname[hostname] = vmid
        # VMs with has_usb_config or reclone_bus_path have USB passthrough in Proxmox config
        if vmid and (vm.get("has_usb_config") or vm.get("reclone_bus_path")):
            usb_vmids.add(vmid)

    return usb_vmids, usb_hostnames, vmids_by_hostname



def _spoke_t3_lookup(spoke: Spoke) -> set[str]:
    proxmox = _telemetry_dict(spoke, "proxmox")
    proxmox_vms = _telemetry_list(spoke, "proxmox_vms")
    if not proxmox_vms and isinstance(proxmox.get("vms"), list):
        proxmox_vms = proxmox.get("vms")
    t3_pci_devices = proxmox.get("t3_pci_devices") if isinstance(proxmox.get("t3_pci_devices"), list) else []
    t3_addrs = {
        _normalize_lookup_value(device.get("id"))
        for device in t3_pci_devices
        if isinstance(device, dict)
    }
    t3_addrs.discard("")
    if not t3_addrs:
        return set()

    t3_vmids: set[str] = set()
    for vm in proxmox_vms:
        if not isinstance(vm, dict):
            continue
        vmid = str(vm.get("vmid")).strip() if vm.get("vmid") is not None else ""
        pci_passthrough_addrs = vm.get("pci_passthrough_addrs") if isinstance(vm.get("pci_passthrough_addrs"), list) else []
        if vmid and any(_normalize_lookup_value(addr) in t3_addrs for addr in pci_passthrough_addrs):
            t3_vmids.add(vmid)
    return t3_vmids



def _client_has_usb(client: dict[str, Any], usb_vmids: set[str], usb_hostnames: set[str], vmids_by_hostname: dict[str, str]) -> bool:
    vmid = str(client.get("vmid") or client.get("proxmox_vmid") or "").strip()
    hostname = _normalize_lookup_value(client.get("hostname"))
    if not vmid and hostname:
        vmid = vmids_by_hostname.get(hostname, "")
    if vmid and vmid in usb_vmids:
        return True
    return bool(hostname and hostname in usb_hostnames)



def _client_has_t3_pci(client: dict[str, Any], t3_vmids: set[str], vmids_by_hostname: dict[str, str]) -> bool:
    vmid = str(client.get("vmid") or client.get("proxmox_vmid") or "").strip()
    hostname = _normalize_lookup_value(client.get("hostname"))
    if not vmid and hostname:
        vmid = vmids_by_hostname.get(hostname, "")
    return bool(vmid and vmid in t3_vmids)



def _record_check(summary: dict[str, int], raw_status: Any) -> None:
    status = str(raw_status or "unknown").strip().lower()
    if status in PASS_STATUSES:
        summary["pass"] += 1
    elif status in FAIL_STATUSES:
        summary["fail"] += 1
    else:
        summary["warning"] += 1



def _build_checks_summary(spokes: list[Spoke]) -> dict[str, int]:
    summary = {"pass": 0, "fail": 0, "warning": 0}
    for spoke in spokes:
        central = _central_telemetry(spoke)
        status_map = central.get("status") or {}
        if isinstance(status_map, dict):
            for checks in status_map.values():
                if not isinstance(checks, dict):
                    continue
                for info in checks.values():
                    if isinstance(info, dict):
                        _record_check(summary, info.get("status"))

        hw_alerts = central.get("hardware_alerts") or []
        if isinstance(hw_alerts, list):
            for alert in hw_alerts:
                if not isinstance(alert, dict):
                    continue
                total = alert.get("total")
                try:
                    affected = int(total)
                except (TypeError, ValueError):
                    affected = 0
                summary["fail" if affected > 0 else "pass"] += 1

        client_count_status = central.get("client_count_status") or {}
        if isinstance(client_count_status, dict):
            for info in client_count_status.values():
                if isinstance(info, dict):
                    _record_check(summary, info.get("status"))
    return summary



def _serialize_hub_central_config(tenant: Tenant) -> dict[str, Any]:
    if not tenant.aruba_config_enc:
        return {"configured": False, "api_version": "classic", "central_browse_interval_minutes": tenant.central_browse_interval_minutes}
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception:
        return {"configured": True, "error": "unreadable", "api_version": "classic", "central_browse_interval_minutes": tenant.central_browse_interval_minutes}
    return {
        "configured": True,
        "cluster_url": cfg.get("cluster_url", ""),
        "client_id": cfg.get("client_id", ""),
        "customer_id": cfg.get("customer_id", ""),
        "workspace_id": cfg.get("workspace_id", ""),
        "api_version": cfg.get("api_version", "classic"),
        "client_secret_configured": bool(cfg.get("client_secret")),
        "access_token_configured": bool(cfg.get("access_token")),
        "refresh_token_configured": bool(cfg.get("refresh_token")),
        "webhook_registered": bool(cfg.get("webhook_id")),
        "central_browse_interval_minutes": tenant.central_browse_interval_minutes,
    }



def _github_repo_settings(tenant: Tenant) -> dict[str, str]:
    if not tenant.github_config_enc:
        return {"github_token": "", "sim_repo_url": "", "sim_repo_branch": "main"}
    try:
        cfg = decrypt_dict(tenant.github_config_enc)
    except Exception:
        raise HTTPException(status_code=500, detail="GitHub settings could not be read")
    return {
        "github_token": str(cfg.get("github_token") or "").strip(),
        "sim_repo_url": str(cfg.get("sim_repo_url") or "").strip(),
        "sim_repo_branch": str(cfg.get("sim_repo_branch") or "main").strip() or "main",
    }



def _parse_github_repo(repo_url: str) -> tuple[str, str]:
    normalized = str(repo_url or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="Simulation repo URL is not configured")
    parsed = urlparse(normalized)
    path = parsed.path if parsed.scheme else normalized
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Simulation repo URL must be a GitHub owner/repo URL")
    owner = parts[0]
    repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    if not owner or not repo:
        raise HTTPException(status_code=400, detail="Simulation repo URL must include owner and repo")
    return owner, repo



def _github_api_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }



def _require_sim_repo_config(tenant: Tenant) -> tuple[str, str, str, str]:
    cfg = _github_repo_settings(tenant)
    github_token = cfg.get("github_token", "")
    repo_url = cfg.get("sim_repo_url", "")
    branch = cfg.get("sim_repo_branch", "main")
    if not github_token:
        raise HTTPException(status_code=400, detail="GitHub token is not configured for this tenant. Open Setup to add it.")
    if not repo_url:
        raise HTTPException(status_code=400, detail="Simulation repo URL is not configured. Open Setup to add it.")
    owner, repo = _parse_github_repo(repo_url)
    return github_token, owner, repo, branch



def _github_error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except Exception as exc:
        logger.warning("Failed to parse GitHub error payload (%s): %s", response.status_code, exc)
        payload = {}
    return payload.get("message") or response.text or f"GitHub API error ({response.status_code})"



async def _fetch_simulation_conf_from_github(tenant: Tenant) -> tuple[str, str, str]:
    github_token, owner, repo, branch = _require_sim_repo_config(tenant)
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/configs/simulation.conf"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=_github_api_headers(github_token), params={"ref": branch})
    if response.status_code == 404:
        raise HTTPException(status_code=404, detail=f"configs/simulation.conf was not found in {owner}/{repo} on branch {branch}.")
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=_github_error_detail(response))
    payload = response.json()
    encoded = str(payload.get("content") or "").replace("\n", "")
    try:
        content = base64.b64decode(encoded).decode("utf-8")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"GitHub returned unreadable simulation.conf content: {exc}") from exc
    return content, str(payload.get("sha") or ""), branch


async def _fetch_user_overrides_conf_from_github(tenant: Tenant) -> tuple[str, str, str]:
    github_token, owner, repo, branch = _require_sim_repo_config(tenant)
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/configs/user-overrides.conf"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=_github_api_headers(github_token), params={"ref": branch})
    if response.status_code == 404:
        # File missing is non-fatal — return empty content
        return "", "", branch
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=_github_error_detail(response))
    payload = response.json()
    encoded = str(payload.get("content") or "").replace("\n", "")
    try:
        content = base64.b64decode(encoded).decode("utf-8")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"GitHub returned unreadable user-overrides.conf content: {exc}") from exc
    return content, str(payload.get("sha") or ""), branch



def _validated_cluster_url_or_400(cluster_url: str) -> str:
    try:
        return validate_cluster_url(cluster_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid cluster_url: {exc}") from exc


def _queue_repo_sync_for_all_spokes(tenant_id: str, current_user: User) -> int:
    queued = 0
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    for spoke in _approved_spokes(tenant_id):
        store.enqueue_command(
            Command(
                spoke_id=spoke.id,
                tenant_id=tenant_id,
                type="repo_sync",
                payload={},
                expires_at=expires_at,
            )
        )
        store.append_audit(
            AuditEntry(
                spoke_id=spoke.id,
                tenant_id=tenant_id,
                task_type="repo_sync",
                execution_mode=spoke.processing_mode.resolve("repo_sync"),
                status="pending",
                detail="Queued repo sync after simulation.conf update",
                initiated_by=current_user.username,
                result={"target": "spoke"},
            )
        )
        queued += 1
    return queued



def _central_mode(tenant: Tenant) -> str:
    mode = tenant.default_processing_mode.resolve("aruba_polling")
    return mode if mode in MODE_VALUES else "distributed"



def _normalize_central_sites_config(config: dict[str, Any] | None) -> dict[str, Any]:
    raw = config if isinstance(config, dict) else {}
    site_mappings = raw.get("site_mappings") if isinstance(raw.get("site_mappings"), dict) else {}
    monitored_checks = raw.get("monitored_checks") if isinstance(raw.get("monitored_checks"), list) else []
    hardware_checks = raw.get("hardware_checks") if isinstance(raw.get("hardware_checks"), list) else []
    excluded_sites = raw.get("excluded_sites") if isinstance(raw.get("excluded_sites"), list) else []
    result: dict[str, Any] = {
        "site_mappings": {
            str(wsite).strip(): str(site_name).strip()
            for wsite, site_name in site_mappings.items()
            if str(wsite).strip() and str(site_name).strip()
        },
        "monitored_checks": [check for check in monitored_checks if isinstance(check, dict)],
        "hardware_checks": [check for check in hardware_checks if isinstance(check, dict)],
        "excluded_sites": [str(s).strip().casefold() for s in excluded_sites if str(s).strip()],
    }
    # Preserve any extra fields (e.g. monitored_items) stored in the raw config
    for key, value in raw.items():
        if key not in result:
            result[key] = value
    return result


def _aggregate_central_payload(tenant_id: str) -> dict[str, Any]:
    from ..tasks import _cache_updated_at, _hub_central_status

    tenant = _get_tenant(tenant_id)
    spokes = _approved_spokes(tenant_id)
    mode = _central_mode(tenant)
    central_sites_config = _normalize_central_sites_config(store.get_tenant_central_sites_config(tenant_id))

    # Pull live client_count_status and per-spoke data from hub's in-memory cache (centralized mode).
    agg_client_count_status: dict[str, Any] = {}
    hub_spokes_data: dict[str, Any] = {}
    if mode == "centralized":
        is_stale = time.time() - _cache_updated_at.get(tenant_id, 0) > 300
        if not is_stale:
            tenant_data = _hub_central_status.get(tenant_id, {})
            ccs = tenant_data.get("client_count_status")
            if isinstance(ccs, dict):
                agg_client_count_status = ccs
            spokes_cache = tenant_data.get("spokes")
            if isinstance(spokes_cache, dict):
                hub_spokes_data = spokes_cache

    spokes_out = []
    for spoke in spokes:
        central = _central_telemetry(spoke)
        spoke_ccs: dict[str, Any] = {}
        if mode == "distributed":
            ccs = central.get("client_count_status")
            if isinstance(ccs, dict):
                spoke_ccs = ccs
                for wsite, info in spoke_ccs.items():
                    if wsite not in agg_client_count_status and isinstance(info, dict):
                        agg_client_count_status[wsite] = info
        else:
            # Centralized: spoke shares the tenant-level client count status
            spoke_ccs = agg_client_count_status

        # Build sites list from hub cache (centralized) or spoke telemetry (distributed)
        spoke_hub_data = hub_spokes_data.get(spoke.id, {}) if isinstance(hub_spokes_data.get(spoke.id), dict) else {}
        site_mappings = spoke_hub_data.get("site_mappings", {}) if isinstance(spoke_hub_data.get("site_mappings"), dict) else {}
        if not site_mappings:
            site_mappings = dict(central_sites_config.get("site_mappings") or {}) if isinstance(central_sites_config.get("site_mappings"), dict) else {}
        spoke_status = spoke_hub_data.get("status", {}) if isinstance(spoke_hub_data.get("status"), dict) else {}
        spoke_wireless = spoke_hub_data.get("wireless_clients", {}) if isinstance(spoke_hub_data.get("wireless_clients"), dict) else {}
        sites = [
            {
                "wsite": wsite,
                "central_site": central_site,
                "wireless_clients": spoke_wireless.get(wsite),
                "status_map": spoke_status.get(wsite, {}) if isinstance(spoke_status.get(wsite), dict) else {},
            }
            for wsite, central_site in site_mappings.items()
        ]

        spokes_out.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "spoke_online": _is_online(spoke),
            "last_seen": spoke.last_seen,
            "assigned_sites": spoke.assigned_sites or [],
            "client_count_status": spoke_ccs,
            "sites": sites,
            "central_status": central,
        })

    return {
        "tenant_id": tenant_id,
        "hub_central_config": _serialize_hub_central_config(tenant),
        "central_sites_config": central_sites_config,
        "mode": mode,
        "client_count_status": agg_client_count_status,
        "spokes": spokes_out,
    }


def _store_and_queue_tenant_config(
    tenant_id: str,
    hub_config_updates: dict[str, Any],
    *,
    spoke_config_updates: dict[str, Any] | None = None,
    force_push: bool = False,
) -> list[dict[str, Any]]:
    tenant = _get_tenant(tenant_id)
    next_hub_config = dict(tenant.hub_config or {})
    next_hub_config.update(hub_config_updates or {})
    tenant_changed = next_hub_config != (tenant.hub_config or {})
    if tenant_changed:
        tenant.hub_config = next_hub_config
        store.save_tenant(tenant)

    effective_spoke_updates = dict(spoke_config_updates if spoke_config_updates is not None else hub_config_updates or {})
    updated_spokes: list[dict[str, Any]] = []
    for spoke in _approved_spokes(tenant_id):
        config_changed = False
        next_spoke_config = dict(spoke.config or {})
        if effective_spoke_updates:
            next_spoke_config.update(effective_spoke_updates)
            config_changed = next_spoke_config != (spoke.config or {})
            if config_changed:
                spoke.config = next_spoke_config

        should_queue = force_push or tenant_changed or config_changed
        if should_queue:
            spoke.config_version += 1
            store.save_spoke(spoke)
            store.ensure_config_update_command(tenant_id, spoke.id)
        elif config_changed:
            store.save_spoke(spoke)

        updated_spokes.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "config_version": spoke.config_version,
            "applied_config_version": spoke.applied_config_version,
            "last_config_applied_at": spoke.last_config_applied_at,
        })
    return updated_spokes


@router.get("/{tenant_id}/config/simulation-conf")
async def get_simulation_conf(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    cfg = _github_repo_settings(tenant)
    if not cfg.get("github_token"):
        # No GitHub API key — serve hub-managed override content.
        # If no override has been saved yet, fall back to sim_conf_content
        # from the first online spoke that includes it in telemetry.
        content = tenant.sim_conf_override or ""
        if not content:
            for spoke in _approved_spokes(resolved_tenant_id):
                spoke_content = (spoke.telemetry or {}).get("sim_conf_content", "")
                if spoke_content:
                    content = spoke_content
                    break
        return {
            "content": content,
            "sha": "",
            "branch": "",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "mode": "override",
        }
    content, sha, branch = await _fetch_simulation_conf_from_github(tenant)
    return {
        "content": content,
        "sha": sha,
        "branch": branch,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "mode": "github",
    }


@router.put("/{tenant_id}/config/simulation-conf")
async def save_simulation_conf(
    tenant_id: str,
    payload: SimulationConfUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    cfg = _github_repo_settings(tenant)
    if not cfg.get("github_token"):
        # No GitHub API key — save as hub-managed override pushed to all spokes.
        tenant.sim_conf_override = payload.content
        store.save_tenant(tenant)
        pushed = _push_conf_overrides_to_spokes(resolved_tenant_id, current_user)
        return {"ok": True, "pushed_to_spokes": pushed, "mode": "override"}
    github_token, owner, repo, branch = _require_sim_repo_config(tenant)
    _, sha, _ = await _fetch_simulation_conf_from_github(tenant)
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/configs/simulation.conf"
    body = {
        "message": f"Update configs/simulation.conf via hub for tenant {resolved_tenant_id}",
        "content": base64.b64encode(payload.content.encode("utf-8")).decode("ascii"),
        "sha": sha,
        "branch": branch,
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.put(url, headers=_github_api_headers(github_token), json=body)
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=_github_error_detail(response))
    response_payload = response.json()
    commit_sha = str((response_payload.get("commit") or {}).get("sha") or "")
    synced_spokes = _queue_repo_sync_for_all_spokes(resolved_tenant_id, current_user)
    return {"ok": True, "commit_sha": commit_sha, "synced_spokes": synced_spokes, "mode": "github"}


# ── Hub-managed conf overrides ────────────────────────────────────────────────
# These allow a tenant admin to override configs/simulation.conf and
# configs/user-overrides.conf without needing GitHub write access.
# Overrides are stored on the hub and pushed to connected spokes via
# config_update.  When the spoke is standalone (no hub), GitHub files apply.

class ConfOverrideRequest(BaseModel):
    content: str  # Raw INI text in the same format as the .conf file


def _push_conf_overrides_to_spokes(tenant_id: str, current_user: User) -> int:
    """Bump config_version on all approved spokes to push updated overrides."""
    count = 0
    for spoke in store.get_spokes(tenant_id):
        if spoke.status != "approved":
            continue
        spoke.config_version = (spoke.config_version or 0) + 1
        store.save_spoke(spoke)
        store.ensure_config_update_command(tenant_id, spoke.id)
        count += 1
    return count


@router.get("/{tenant_id}/config/sim-conf-override")
def get_sim_conf_override(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Return the hub-managed simulation.conf override (INI text), or null if unset."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    return {"content": tenant.sim_conf_override, "active": tenant.sim_conf_override is not None}


@router.put("/{tenant_id}/config/sim-conf-override")
def save_sim_conf_override(
    tenant_id: str,
    payload: ConfOverrideRequest,
    current_user: User = Depends(auth.get_current_user),
):
    """Save hub-managed simulation.conf override and push to all approved spokes."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    tenant.sim_conf_override = payload.content
    store.save_tenant(tenant)
    pushed = _push_conf_overrides_to_spokes(resolved_tenant_id, current_user)
    return {"ok": True, "pushed_to_spokes": pushed}


@router.delete("/{tenant_id}/config/sim-conf-override")
def clear_sim_conf_override(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Clear hub-managed simulation.conf override — spokes revert to GitHub file."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    tenant.sim_conf_override = None
    store.save_tenant(tenant)
    pushed = _push_conf_overrides_to_spokes(resolved_tenant_id, current_user)
    return {"ok": True, "cleared": True, "pushed_to_spokes": pushed}


@router.get("/{tenant_id}/config/user-conf-override")
def get_user_conf_override(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Return the hub-managed user-overrides.conf override (INI text), or null if unset."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    return {"content": tenant.user_conf_override, "active": tenant.user_conf_override is not None}


@router.put("/{tenant_id}/config/user-conf-override")
def save_user_conf_override(
    tenant_id: str,
    payload: ConfOverrideRequest,
    current_user: User = Depends(auth.get_current_user),
):
    """Save hub-managed user-overrides.conf override and push to all approved spokes."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    tenant.user_conf_override = payload.content
    store.save_tenant(tenant)
    pushed = _push_conf_overrides_to_spokes(resolved_tenant_id, current_user)
    return {"ok": True, "pushed_to_spokes": pushed}


@router.delete("/{tenant_id}/config/user-conf-override")
def clear_user_conf_override(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Clear hub-managed user-overrides.conf override — spokes revert to GitHub file."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    tenant.user_conf_override = None
    store.save_tenant(tenant)
    pushed = _push_conf_overrides_to_spokes(resolved_tenant_id, current_user)
    return {"ok": True, "cleared": True, "pushed_to_spokes": pushed}


# ── User-overrides.conf editor endpoints ─────────────────────────────────────
# These are always in "override" mode (no GitHub path needed).

@router.get("/{tenant_id}/config/user-overrides-conf")
async def get_user_overrides_conf(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Return user-overrides.conf content.
    If a GitHub token is configured, fetches configs/user-overrides.conf from the repo.
    Otherwise serves the hub-managed override (tenant.user_conf_override)."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    cfg = _github_repo_settings(tenant)
    if not cfg.get("github_token"):
        # No GitHub API key — serve hub-managed override content only.
        return {
            "content": tenant.user_conf_override or "",
            "sha": "",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "mode": "override",
        }
    # GitHub token available — read the file from the repo.
    # If the hub-managed override is set (non-empty), it takes precedence (admin explicitly set it).
    if tenant.user_conf_override:
        return {
            "content": tenant.user_conf_override,
            "sha": "",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "mode": "override",
        }
    content, sha, branch = await _fetch_user_overrides_conf_from_github(tenant)
    return {
        "content": content,
        "sha": sha,
        "branch": branch,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "mode": "github",
    }


@router.put("/{tenant_id}/config/user-overrides-conf")
def save_user_overrides_conf(
    tenant_id: str,
    payload: ConfOverrideRequest,
    current_user: User = Depends(auth.get_current_user),
):
    """Save hub-managed user-overrides.conf and push to all approved spokes.
    Saving empty content clears the hub-managed override so GitHub is used instead."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    # Empty content → clear the override so the GitHub file is served again.
    tenant.user_conf_override = payload.content if payload.content and payload.content.strip() else None
    store.save_tenant(tenant)
    pushed = _push_conf_overrides_to_spokes(resolved_tenant_id, current_user)
    return {"ok": True, "pushed_to_spokes": pushed, "mode": "override"}


# ── Demo Scenario Endpoints ────────────────────────────────────────────────────
# Hub → Spoke relay for demo user scenario triggers.
# Demo scenarios are ephemeral (in-memory on spoke, cleared on hub/spoke reboot
# and auto-expired after 120 minutes).

class DemoScenarioRequest(BaseModel):
    scenario: str  # e.g. "dns_fail", "dhcp_fail", "normal"


class ClientSimOverrideRequest(BaseModel):
    simulation: str  # e.g. "dns_fail", "ping_test"
    enabled: bool


async def _relay_demo_command(tenant_id: str, spoke_id: str, message: dict) -> bool:
    """Send a demo command to a spoke via WebSocket relay. Returns True if sent."""
    from ..ws import relay_ws
    return await relay_ws.send_to_spoke(tenant_id, spoke_id, message)


@router.post("/{tenant_id}/spokes/{spoke_id}/clients/{hostname}/demo-scenario")
async def hub_demo_set_scenario(
    tenant_id: str,
    spoke_id: str,
    hostname: str,
    payload: DemoScenarioRequest,
    current_user: User = Depends(auth.get_current_user),
):
    """Trigger a named demo scenario on a specific client via spoke WebSocket relay.

    Accessible to demo, viewer, and admin roles.  The spoke applies the scenario
    in-memory — it reverts automatically after 120 minutes or on hub/spoke reboot.
    """
    _require_tenant_demo_or_above(tenant_id, current_user)
    sent = await _relay_demo_command(tenant_id, spoke_id, {
        "type": "demo_scenario",
        "hostname": hostname,
        "scenario": payload.scenario,
        "triggered_by": current_user.username,
    })
    if not sent:
        raise HTTPException(status_code=502, detail="Spoke relay is offline")
    return {"ok": True, "hostname": hostname, "scenario": payload.scenario}


@router.delete("/{tenant_id}/spokes/{spoke_id}/clients/{hostname}/demo-scenario")
async def hub_demo_clear_scenario(
    tenant_id: str,
    spoke_id: str,
    hostname: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Clear the demo scenario for a specific client on a spoke."""
    _require_tenant_demo_or_above(tenant_id, current_user)
    sent = await _relay_demo_command(tenant_id, spoke_id, {
        "type": "demo_clear",
        "hostname": hostname,
    })
    if not sent:
        raise HTTPException(status_code=502, detail="Spoke relay is offline")
    return {"ok": True, "hostname": hostname, "cleared": True}


@router.get("/{tenant_id}/clients/sim-overrides")
def get_client_sim_overrides(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Return all hub-managed permanent sim overrides for a tenant (hostname → [sim, ...])."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    return {"client_sim_overrides": tenant.client_sim_overrides or {}}


@router.put("/{tenant_id}/clients/{hostname}/sim-override")
def set_client_sim_override(
    tenant_id: str,
    hostname: str,
    payload: ClientSimOverrideRequest,
    current_user: User = Depends(auth.get_current_user),
):
    """Enable or disable a simulation permanently for a specific client.

    Stored as a hub-managed local override — no GitHub key required.
    Merged into active_simulations when serving aggregate client data so the
    dashboard reflects the admin-selected state immediately.
    """
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    overrides: dict[str, list[str]] = dict(tenant.client_sim_overrides or {})
    current = list(overrides.get(hostname, []))
    sim = payload.simulation
    if payload.enabled:
        if sim not in current:
            current.append(sim)
    else:
        current = [s for s in current if s != sim]
    overrides[hostname] = current
    tenant.client_sim_overrides = overrides
    store.save_tenant(tenant)
    return {"ok": True, "hostname": hostname, "simulation": sim, "enabled": payload.enabled,
            "active_overrides": current}


class UsbVidpidEntry(BaseModel):
    vidpid: str
    type: str = ""
    label: str = ""


@router.get("/{tenant_id}/usb-vidpids")
def get_tenant_usb_vidpids(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Return the effective USB device list for a tenant (global + tenant-specific).

    Any user with access to the tenant can read this list.  Devices inherited from
    the global (superadmin) list are annotated with source='global'; devices
    added by the tenant admin have source='tenant'.
    """
    auth.require_tenant_access(tenant_id, current_user)
    return {"usb_vidpids": store.get_effective_usb_vidpids(tenant_id)}


@router.post("/{tenant_id}/usb-vidpids")
def add_tenant_usb_vidpid(
    tenant_id: str,
    entry: UsbVidpidEntry,
    current_user: User = Depends(auth.get_current_user),
):
    """Add or update a device in the tenant-level certified USB list.

    Requires tenant admin role.  Global (superadmin) devices are already included
    in the effective list; adding the same vidpid here is a no-op.
    """
    _require_tenant_admin(tenant_id, current_user)

    # If the vidpid is already globally certified it is already effective for all spokes.
    global_vidpids = {d.get("vidpid") for d in store.get_global_usb_vidpids()}
    if entry.vidpid in global_vidpids:
        return {
            "status": "already_global",
            "message": "Device is already globally certified; no tenant entry needed.",
        }

    current = store.get_tenant_usb_vidpids(tenant_id)
    # Replace existing entry for the same vidpid or append
    updated = [d for d in current if d.get("vidpid") != entry.vidpid]
    updated.append({"vidpid": entry.vidpid, "type": entry.type, "label": entry.label})
    store.set_tenant_usb_vidpids(tenant_id, updated)

    # Push updated USB config to all approved spokes.
    # USB cert changes always propagate regardless of hub_config_enabled.
    pushed_count = 0
    tenant = store.get_tenant(tenant_id)
    if tenant:
        for spoke in store.list_spokes(tenant_id):
            if spoke.status != "approved":
                continue
            spoke.config_version += 1
            store.save_spoke(spoke)
            store.ensure_config_update_command(tenant_id, spoke.id)
            pushed_count += 1

    return {"status": "saved", "pushed_to_spokes": pushed_count}


@router.delete("/{tenant_id}/usb-vidpids/{vidpid:path}")
def delete_tenant_usb_vidpid(
    tenant_id: str,
    vidpid: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Remove a device from the tenant-level certified USB list.

    Requires tenant admin role.  Globally certified devices cannot be removed
    here; use PUT /api/superadmin/global-usb-vidpids to manage those.
    """
    _require_tenant_admin(tenant_id, current_user)

    global_vidpids = {d.get("vidpid") for d in store.get_global_usb_vidpids()}
    if vidpid in global_vidpids:
        raise HTTPException(
            status_code=400,
            detail="Cannot remove a globally certified device via the tenant endpoint. "
                   "Use the superadmin global USB endpoint instead.",
        )

    current = store.get_tenant_usb_vidpids(tenant_id)
    updated = [d for d in current if d.get("vidpid") != vidpid]
    if len(updated) == len(current):
        raise HTTPException(status_code=404, detail="Device not found in tenant certified list")
    store.set_tenant_usb_vidpids(tenant_id, updated)

    # Push updated USB config to all approved spokes.
    # USB cert changes always propagate regardless of hub_config_enabled.
    pushed_count = 0
    tenant = store.get_tenant(tenant_id)
    if tenant:
        for spoke in store.list_spokes(tenant_id):
            if spoke.status != "approved":
                continue
            spoke.config_version += 1
            store.save_spoke(spoke)
            store.ensure_config_update_command(tenant_id, spoke.id)
            pushed_count += 1

    return {"status": "deleted", "pushed_to_spokes": pushed_count}


@router.post("/{tenant_id}/usb-vidpids/resync")
def resync_tenant_usb_vidpids(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Force-push the current USB certified list to all approved spokes in this tenant.

    No change is made to the list itself — the current effective list (global + tenant)
    is simply re-queued for delivery.  Useful when a spoke missed a previous push due
    to being offline, in isolation mode, or running outdated software.

    Requires tenant admin role.
    """
    _require_tenant_admin(tenant_id, current_user)
    pushed_count = 0
    for spoke in store.list_spokes(tenant_id):
        if spoke.status != "approved":
            continue
        spoke.config_version += 1
        store.save_spoke(spoke)
        store.ensure_config_update_command(tenant_id, spoke.id)
        pushed_count += 1
    return {"status": "resynced", "pushed_to_spokes": pushed_count}



def get_aggregate_dashboard(
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    spokes = _approved_spokes(resolved_tenant_id)
    clients = [client for spoke in spokes for client in _telemetry_clients(spoke)]
    hardware_breakdown = dict(sorted(Counter(_hardware_type(client) for client in clients).items()))
    return {
        "tenant_id": resolved_tenant_id,
        "client_count": len(clients),
        "hardware_breakdown": hardware_breakdown,
        "checks_summary": _build_checks_summary(spokes),
        "spokes_online": sum(1 for spoke in spokes if _is_online(spoke)),
        "spokes_total": len(spokes),
    }


@router.get("/aggregate/clients")
def get_aggregate_clients(
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    # Load hub-managed per-client sim overrides once (no GitHub needed).
    tenant = _get_tenant(resolved_tenant_id)
    admin_sim_overrides: dict[str, list[str]] = dict(tenant.client_sim_overrides or {})
    # Collect all candidate rows keyed by MAC (or hostname fallback) so we can
    # deduplicate VMs that appear on multiple spokes due to client_history.json
    # retention.  A client with active simulations beats a stale historical one.
    candidates: dict[str, dict[str, Any]] = {}
    for spoke in _approved_spokes(resolved_tenant_id):
        spoke_name = spoke.spoke_name or spoke.hostname
        usb_vmids, usb_hostnames, vmids_by_hostname = _spoke_usb_lookup(spoke)
        t3_vmids = _spoke_t3_lookup(spoke)
        proxmox_tel = _telemetry_dict(spoke, "proxmox")
        t3_pci_devices: list[dict[str, Any]] = []
        if isinstance(proxmox_tel.get("t3_pci_devices"), list):
            t3_pci_devices = proxmox_tel["t3_pci_devices"]
        t3_pci_count = int(proxmox_tel.get("t3_pci_count") or len(t3_pci_devices))
        for client in _telemetry_clients(spoke):
            row = dict(client)
            # Merge hub-managed permanent sim overrides into active_simulations.
            # These are set by admins via the UI and stored locally — no GitHub key needed.
            hostname = str(row.get("hostname") or "")
            extra_sims = admin_sim_overrides.get(hostname, [])
            if extra_sims:
                merged = list(set(list(row.get("active_simulations") or []) + list(extra_sims)))
                row["active_simulations"] = merged
            row.update({
                "tenant_id": resolved_tenant_id,
                "spoke_id": spoke.id,
                "spoke_name": spoke_name,
                "spoke_hostname": spoke.hostname,
                "spoke_label": spoke.label,
                # Trust the spoke's own has_usb if True (serialize_client sets it via
                # _hostname_has_usb which has direct access to proxmox_state). Fall back
                # to the hub's telemetry-based lookup in case the spoke hasn't set it.
                "has_usb": bool(row.get("has_usb")) or _client_has_usb(row, usb_vmids, usb_hostnames, vmids_by_hostname),
                # T3 stays node-scoped for section counts, but client classification must
                # follow the VM's own PCI passthrough config.
                "has_t3_pci": _client_has_t3_pci(row, t3_vmids, vmids_by_hostname),
                "t3_pci_count": t3_pci_count,
                "t3_pci_devices": t3_pci_devices,
            })
            # Dedup key: prefer MAC, fall back to hostname. VMs that appear in
            # multiple spokes' client_history.json should only be counted once —
            # on whichever spoke has them actively simulated.
            dedup_key = str(row.get("mac") or row.get("hostname") or "").lower().strip()
            if not dedup_key:
                candidates[id(row)] = row  # no key available, always include
                continue
            existing = candidates.get(dedup_key)
            if existing is None:
                candidates[dedup_key] = row
            else:
                # Prefer the spoke that has an active simulation running
                existing_active = bool(existing.get("active_simulations"))
                new_active = bool(row.get("active_simulations"))
                if new_active and not existing_active:
                    candidates[dedup_key] = row
    rows = sorted(candidates.values(),
                  key=lambda item: (str(item.get("spoke_name") or "").lower(),
                                    str(item.get("hostname") or "").lower()))
    return {"tenant_id": resolved_tenant_id, "clients": rows}


@router.get("/aggregate/simulations")
def get_aggregate_simulations(
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    rows: list[dict[str, Any]] = []
    for spoke in _approved_spokes(resolved_tenant_id):
        counts: Counter[str] = Counter()
        for client in _telemetry_clients(spoke):
            names = [str(name).strip() for name in (client.get("active_simulations") or []) if str(name).strip()]
            if not names:
                fallback = str(client.get("simulation_id") or "").strip()
                if fallback:
                    names = [fallback]
            for name in names:
                counts[name] += 1

        spoke_name = spoke.spoke_name or spoke.hostname
        online = _is_online(spoke)
        status = "Running" if online else "Spoke Offline"
        if counts:
            for simulation_name, client_count in sorted(counts.items()):
                rows.append({
                    "tenant_id": resolved_tenant_id,
                    "spoke_id": spoke.id,
                    "spoke_name": spoke_name,
                    "spoke_hostname": spoke.hostname,
                    "simulation_name": simulation_name,
                    "status": status,
                    "client_count": client_count,
                    "spoke_online": online,
                })
        else:
            rows.append({
                "tenant_id": resolved_tenant_id,
                "spoke_id": spoke.id,
                "spoke_name": spoke_name,
                "spoke_hostname": spoke.hostname,
                "simulation_name": "—",
                "status": "Idle" if online else "Spoke Offline",
                "client_count": 0,
                "spoke_online": online,
            })

    rows.sort(key=lambda item: (str(item.get("spoke_name") or "").lower(), str(item.get("simulation_name") or "").lower()))
    return {"tenant_id": resolved_tenant_id, "simulations": rows}


@router.get("/aggregate/proxmox")
def get_aggregate_proxmox(
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    hosts: list[dict[str, Any]] = []
    # Fetch effective USB list (global + tenant) once — same for all spokes.
    effective_usb_vidpids = [{k: v for k, v in d.items() if k != "source"}
                              for d in store.get_effective_usb_vidpids(resolved_tenant_id)]
    for spoke in _approved_spokes(resolved_tenant_id):
        proxmox = _telemetry_dict(spoke, "proxmox")
        vms = _telemetry_list(spoke, "proxmox_vms") or (proxmox.get("vms") if isinstance(proxmox.get("vms"), list) else [])
        usb_devices = _telemetry_list(spoke, "usb_devices") or (proxmox.get("usb_state") if isinstance(proxmox.get("usb_state"), list) else [])
        # Join prov_status from usb_state into each VM — the agent reports them separately.
        # usb_state entries have vmid + prov_status (active/provisioning/tearing_down/missing).
        _usb_prov_by_vmid: dict[int, str] = {
            int(u["vmid"]): u["prov_status"]
            for u in usb_devices
            if isinstance(u, dict) and u.get("vmid") is not None and u.get("prov_status")
        }
        if _usb_prov_by_vmid:
            vms = [
                {**vm, "prov_status": _usb_prov_by_vmid.get(int(vm["vmid"]), vm.get("prov_status"))}
                if isinstance(vm, dict) and vm.get("vmid") is not None
                else vm
                for vm in vms
            ]
        _used_slots, _total_slots, _dongle_count, auto_provision = _spoke_usb_capacity(spoke)
        tel = spoke.telemetry or {}
        hosts.append({
            "tenant_id": resolved_tenant_id,
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "spoke_online": _is_online(spoke),
            "last_seen": spoke.last_seen,
            "hub_rtt_ms": tel.get("hub_rtt_ms"),
            "hub_processing_ms": tel.get("hub_processing_ms"),
            "hub_loop_lag_ms": tel.get("hub_loop_lag_ms"),
            "telemetry_build_ms": tel.get("telemetry_build_ms"),
            "ws_reconnect_count": tel.get("ws_reconnect_count"),
            "ws_last_error": tel.get("ws_last_error"),
            "sim_conf_read_error": tel.get("sim_conf_read_error"),
            "node": proxmox.get("node") if isinstance(proxmox.get("node"), dict) else {},
            "proxmox": proxmox,
            "proxmox_vms": vms,
            "usb_devices": usb_devices,
            "vm_count": int(proxmox.get("vm_count") or len(vms)),
            "usb_count": int(proxmox.get("usb_count") or len(usb_devices)),
            "reclone_state": _telemetry_dict(spoke, "reclone_state"),
            "spoke_config": {
                "usb_max_slots": str((spoke.config or {}).get("usb_max_slots", "24")),
                "vmid_start": int((spoke.config or {}).get("vmid_start", 0) or 0),
                "usb_vidpids": effective_usb_vidpids,
                "hostname": spoke.hostname or "",
                # Read auto_provision from telemetry via _spoke_usb_capacity so the
                # hub reflects the spoke's actual runtime state, not just hub DB config.
                "usb_auto_provision": "on" if auto_provision else "off",
                "usb_missing_timeout": str((spoke.config or {}).get("usb_missing_timeout", "60")),
                "usb_sim_phy": (spoke.config or {}).get("usb_sim_phy", "wireless"),
                "usb_ignored_vidpids": (spoke.config or {}).get("usb_ignored_vidpids", "[]"),
                "reclone_concurrency": str((spoke.config or {}).get("reclone_concurrency", "1")),
            },
        })
    hosts.sort(key=lambda item: str(item.get("spoke_name") or "").lower())
    return {"tenant_id": resolved_tenant_id, "hosts": hosts}


@router.post("/{tenant_id}/aggregate/fleet-reclone")
async def fleet_reclone(
    tenant_id: str,
    body: dict = Body(default={}),
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    concurrency = _coerce_int(body.get("concurrency"), 3, minimum=1, maximum=10)
    tenant = _get_tenant(resolved_tenant_id)
    hub_config = dict(tenant.hub_config or {})
    hub_config["fleet_reclone_concurrency"] = concurrency
    if hub_config != tenant.hub_config:
        tenant.hub_config = hub_config
        store.save_tenant(tenant)

    queued = 0
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    for spoke in _approved_spokes(resolved_tenant_id):
        store.enqueue_command(
            Command(
                spoke_id=spoke.id,
                tenant_id=resolved_tenant_id,
                type="proxmox_reclone_all",
                payload={"concurrency": concurrency},
                expires_at=expires_at,
            )
        )
        queued += 1
    return {"tenant_id": resolved_tenant_id, "queued": queued, "concurrency": concurrency}


@router.post("/{tenant_id}/aggregate/fleet-reclone-clear")
async def fleet_reclone_clear(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Queue a clear_reclone_state command on every approved spoke to dismiss stale error state."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)

    queued = 0
    for spoke in _approved_spokes(resolved_tenant_id):
        store.enqueue_command(
            Command(
                spoke_id=spoke.id,
                tenant_id=resolved_tenant_id,
                type="clear_reclone_state",
                payload={},
            )
        )
        queued += 1
    return {"tenant_id": resolved_tenant_id, "queued": queued}


@router.post("/{tenant_id}/aggregate/fleet-reclone-clear-spoke")
async def fleet_reclone_clear_spoke(
    tenant_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
    current_user: User = Depends(auth.get_current_user),
):
    """Queue a clear_reclone_state command on a single spoke."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spoke_id = str(body.get("spoke_id") or "").strip()
    if not spoke_id:
        raise HTTPException(status_code=400, detail="spoke_id is required")

    spoke = store.get_spoke(resolved_tenant_id, spoke_id)
    if not spoke or spoke.status != "approved":
        raise HTTPException(status_code=404, detail="Approved spoke not found")

    store.enqueue_command(
        Command(
            spoke_id=spoke_id,
            tenant_id=resolved_tenant_id,
            type="clear_reclone_state",
            payload={},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    )
    return {"tenant_id": resolved_tenant_id, "spoke_id": spoke_id, "queued": 1}


@router.post("/{tenant_id}/aggregate/unlock-template")
async def unlock_template(
    tenant_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    requested_spoke_id = str(body.get("spoke_id") or "").strip()
    approved_spokes = list(_approved_spokes(resolved_tenant_id))
    if requested_spoke_id:
        approved_spokes = [spoke for spoke in approved_spokes if spoke.id == requested_spoke_id]
        if not approved_spokes:
            raise HTTPException(status_code=404, detail="Approved spoke not found")

    queued = 0
    for spoke in approved_spokes:
        store.enqueue_command(
            Command(
                spoke_id=spoke.id,
                tenant_id=resolved_tenant_id,
                type="unlock_template",
                payload={},
            )
        )
        queued += 1
    return {"tenant_id": resolved_tenant_id, "queued": queued, "spoke_id": requested_spoke_id or None}


@router.post("/{tenant_id}/aggregate/proxmox-approve-agent")
async def hub_proxmox_approve_agent(
    tenant_id: str,
    body: dict[str, Any] = Body(...),
    current_user: User = Depends(auth.get_current_user),
):
    """Queue a proxmox_approve_agent command to a specific spoke so the hub can approve a
    Proxmox agent from the VM Server screen without logging into the spoke directly."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spoke_id = str(body.get("spoke_id") or "").strip()
    hostname = str(body.get("hostname") or "").strip()
    if not spoke_id or not hostname:
        raise HTTPException(status_code=400, detail="spoke_id and hostname are required")
    approved_spokes = list(_approved_spokes(resolved_tenant_id))
    spoke = next((s for s in approved_spokes if s.id == spoke_id), None)
    if not spoke:
        raise HTTPException(status_code=404, detail="Approved spoke not found")
    store.enqueue_command(Command(
        spoke_id=spoke.id,
        tenant_id=resolved_tenant_id,
        type="proxmox_approve_agent",
        payload={"hostname": hostname},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    ))
    return {"tenant_id": resolved_tenant_id, "spoke_id": spoke_id, "hostname": hostname, "queued": 1}


@router.post("/{tenant_id}/aggregate/proxmox-revoke-agent")
async def hub_proxmox_revoke_agent(
    tenant_id: str,
    body: dict[str, Any] = Body(...),
    current_user: User = Depends(auth.get_current_user),
):
    """Queue a proxmox_revoke_agent command to a specific spoke to revoke an approved agent key."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    spoke_id = str(body.get("spoke_id") or "").strip()
    hostname = str(body.get("hostname") or "").strip()
    if not spoke_id or not hostname:
        raise HTTPException(status_code=400, detail="spoke_id and hostname are required")
    approved_spokes = list(_approved_spokes(resolved_tenant_id))
    spoke = next((s for s in approved_spokes if s.id == spoke_id), None)
    if not spoke:
        raise HTTPException(status_code=404, detail="Approved spoke not found")
    store.enqueue_command(Command(
        spoke_id=spoke.id,
        tenant_id=resolved_tenant_id,
        type="proxmox_revoke_agent",
        payload={"hostname": hostname},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    ))
    return {"tenant_id": resolved_tenant_id, "spoke_id": spoke_id, "hostname": hostname, "queued": 1}


@router.get("/{tenant_id}/aggregate/fleet-reclone-status")
def get_fleet_reclone_status(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    total_vms = 0
    completed = 0
    failed = 0
    any_running = False
    spokes_out: list[dict[str, Any]] = []
    for spoke in _approved_spokes(resolved_tenant_id):
        reclone = _telemetry_dict(spoke, "reclone_state")
        spoke_total = _coerce_int(reclone.get("total"), 0, minimum=0)
        spoke_completed = _coerce_int(reclone.get("completed"), 0, minimum=0)
        spoke_failed = _coerce_int(reclone.get("failed"), 0, minimum=0)
        status = str(reclone.get("status") or "idle")
        total_vms += spoke_total
        completed += spoke_completed
        failed += spoke_failed
        any_running = any_running or status == "running"
        spokes_out.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "status": status,
            "total": spoke_total,
            "completed": spoke_completed,
            "failed": spoke_failed,
        })
    spokes_out.sort(key=lambda item: str(item.get("spoke_name") or "").lower())
    return {
        "tenant_id": resolved_tenant_id,
        "any_running": any_running,
        "total_vms": total_vms,
        "completed": completed,
        "failed": failed,
        "default_concurrency": _coerce_int((tenant.hub_config or {}).get("fleet_reclone_concurrency"), 3, minimum=1, maximum=10),
        "spokes": spokes_out,
    }


@router.get("/{tenant_id}/aggregate/usb-provisioning-status")
def get_usb_provisioning_status(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    total_slots = 0
    used_slots = 0
    spokes_out: list[dict[str, Any]] = []
    for spoke in _approved_spokes(resolved_tenant_id):
        used, total, dongles, auto_provision = _spoke_usb_capacity(spoke)
        total_slots += total
        used_slots += used
        spokes_out.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "used": used,
            "total": total,
            "dongle_count": dongles,
            "auto_provision": auto_provision,
        })
    spokes_out.sort(key=lambda item: str(item.get("spoke_name") or "").lower())
    total_dongles = sum(s.get("dongle_count", 0) for s in spokes_out)
    # auto_provision_on: true only if ALL spokes with dongles have it enabled
    # (reflects toggle-all state accurately; any-spoke-on was misleading after disabling)
    enabled_spokes = [s for s in spokes_out if s["auto_provision"]]
    auto_provision_on = len(enabled_spokes) > 0 and len(enabled_spokes) == len(spokes_out)
    return {
        "tenant_id": resolved_tenant_id,
        "total_slots": total_slots,
        "used_slots": used_slots,
        "total_dongles": total_dongles,
        "auto_provision_on": auto_provision_on,
        "spokes": spokes_out,
    }


@router.post("/{tenant_id}/aggregate/toggle-auto-provision")
def toggle_auto_provision(
    tenant_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
    current_user: User = Depends(auth.get_current_user),
):
    """Toggle usb_auto_provision on/off for all approved spokes in this tenant."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    enable: bool = bool(body.get("enable", False))
    new_val = "on" if enable else "off"
    updated = 0
    for spoke in _approved_spokes(resolved_tenant_id):
        next_config = dict(spoke.config or {})
        next_config["usb_auto_provision"] = new_val
        spoke.config = next_config
        spoke.config_version = (spoke.config_version or 0) + 1
        store.save_spoke(spoke)
        store.enqueue_command(Command(
            spoke_id=spoke.id,
            tenant_id=resolved_tenant_id,
            type="config_update",
            payload={**next_config, "__config_version": spoke.config_version},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        ))
        updated += 1
    return {"ok": True, "auto_provision": new_val, "updated_spokes": updated}


@router.post("/{tenant_id}/aggregate/refresh-webui")
def aggregate_refresh_webui(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Queue a refresh_webui command on all approved spokes so they download the latest cs-webui frontend."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    queued = 0
    for spoke in _approved_spokes(resolved_tenant_id):
        store.enqueue_command(Command(
            spoke_id=spoke.id,
            tenant_id=resolved_tenant_id,
            type="refresh_webui",
            payload={},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ))
        queued += 1
    return {"ok": True, "queued": queued}


@router.post("/{tenant_id}/aggregate/update-all-spokes")
def aggregate_update_all_spokes(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Queue self_update and proxmox_agent_update commands on all approved spokes."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    queued = 0
    for spoke in _approved_spokes(resolved_tenant_id):
        for cmd_type in ("proxmox_agent_update", "self_update"):
            store.enqueue_command(Command(
                spoke_id=spoke.id,
                tenant_id=resolved_tenant_id,
                type=cmd_type,
                payload={},
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ))
        queued += 1
    return {"ok": True, "spokes_queued": queued}


@router.post("/{tenant_id}/aggregate/test-central")
async def test_central_connection(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Test Aruba Central credentials and return token status + discovered sites."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    if not tenant.aruba_config_enc:
        return {"ok": False, "error": "No Aruba Central credentials configured for this tenant."}
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception as exc:
        return {"ok": False, "error": f"Failed to decrypt credentials: {exc}"}
    client = ArubaClient(cfg)
    if not client.is_configured():
        return {"ok": False, "error": "Cluster URL is not set."}
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15, verify=True) as hc:
            token = await client._ensure_token(hc)
            # For new_central, also return the raw API response to aid debugging
            raw_response = None
            if client.api_version == "new_central":
                try:
                    async with httpx.AsyncClient(timeout=30) as dbg:
                        raw_response = await client._get(dbg, "/network-monitoring/v1alpha1/sites-health")
                except Exception as raw_exc:
                    raw_response = {"error": str(raw_exc)}
            sites = await client.list_sites()
        result: dict[str, Any] = {
            "ok": True,
            "token_obtained": True,
            "api_version": client.api_version,
            "cluster_url": client.cluster_url,
            "sites_discovered": len(sites),
            "sites": [s.get("name") for s in sites if isinstance(s, dict)],
        }
        if raw_response is not None:
            result["raw_sites_response"] = raw_response
        return result
    except httpx.HTTPStatusError as exc:
        body = ""
        try:
            body = exc.response.text[:500]
        except Exception:
            pass
        detail = f"HTTP {exc.response.status_code} from {exc.request.url}: {body or exc.response.reason_phrase}"
        logger.warning("test-central HTTP error: %s", detail)
        return {"ok": False, "token_obtained": False, "error": detail}
    except httpx.ConnectError as exc:
        detail = f"Connection error: {exc}" if str(exc) else f"Could not connect to {client.cluster_url} — check the cluster URL and network access"
        logger.warning("test-central connect error: %s", detail)
        return {"ok": False, "token_obtained": False, "error": detail}
    except httpx.TimeoutException as exc:
        detail = f"Timeout connecting to {client.cluster_url}"
        logger.warning("test-central timeout: %s", exc)
        return {"ok": False, "token_obtained": False, "error": detail}
    except Exception as exc:
        detail = str(exc) or repr(exc)
        logger.exception("test-central unexpected error")
        return {"ok": False, "token_obtained": False, "error": detail}


@router.post("/{tenant_id}/aggregate/register-central-webhook")
async def register_central_webhook(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Register the hub as a Central webhook receiver."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    cfg = _load_aruba_config(tenant)
    client = ArubaClient(cfg)
    if not client.is_configured():
        raise HTTPException(status_code=400, detail="Aruba Central cluster URL is not configured.")

    endpoint_url = _central_webhook_endpoint_url(resolved_tenant_id)
    api_key = secrets.token_urlsafe(32)
    webhook_name = f"ClientSim Hub - {tenant.name}" if tenant.name else "ClientSim Hub"
    existing_webhook_id = str(cfg.get("webhook_id") or "").strip()
    if existing_webhook_id:
        await client.delete_webhook(existing_webhook_id)
    created = await client.register_webhook(webhook_name, endpoint_url, api_key)
    webhook_id = str(created.get("id") or created.get("webhookId") or created.get("webhook_id") or "").strip()
    if not webhook_id:
        raise HTTPException(status_code=502, detail="Central did not return a webhook ID.")
    cfg["webhook_id"] = webhook_id
    cfg["webhook_api_key"] = api_key
    _persist_aruba_config(tenant, cfg)
    return {"ok": True, "webhook_id": webhook_id, "endpoint_url": endpoint_url}


@router.delete("/{tenant_id}/aggregate/register-central-webhook")
async def deregister_central_webhook(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Remove the hub webhook from Central."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    endpoint_url = _central_webhook_endpoint_url(resolved_tenant_id)
    if not tenant.aruba_config_enc:
        return {"ok": True, "registered": False, "endpoint_url": endpoint_url}
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt Aruba Central credentials: {exc}") from exc
    webhook_id = str(cfg.get("webhook_id") or "").strip()
    if webhook_id and str(cfg.get("cluster_url") or "").strip():
        cfg["cluster_url"] = _validated_cluster_url_or_400(cfg.get("cluster_url", ""))
        client = ArubaClient(cfg)
        if client.is_configured():
            await client.delete_webhook(webhook_id)
    cfg.pop("webhook_id", None)
    cfg.pop("webhook_api_key", None)
    _persist_aruba_config(tenant, cfg)
    return {"ok": True, "registered": False, "endpoint_url": endpoint_url}


@router.get("/{tenant_id}/aggregate/register-central-webhook")
async def get_central_webhook_status(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Get current webhook registration status."""
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    webhook_id = ""
    webhook_api_key = ""
    if tenant.aruba_config_enc:
        try:
            cfg = decrypt_dict(tenant.aruba_config_enc)
            webhook_id = str(cfg.get("webhook_id") or "").strip()
            webhook_api_key = str(cfg.get("webhook_api_key") or "").strip()
        except Exception:
            webhook_id = ""
            webhook_api_key = ""
    return {
        "registered": bool(webhook_id),
        "webhook_id": webhook_id,
        "webhook_api_key": webhook_api_key,
        "endpoint_url": _central_webhook_endpoint_url(resolved_tenant_id),
    }


@router.get("/aggregate/api-server")
def get_aggregate_api_server(
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    spokes = [
        {
            "tenant_id": resolved_tenant_id,
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "spoke_online": _is_online(spoke),
            "last_seen": spoke.last_seen,
            "api_server": _telemetry_dict(spoke, "api_server"),
        }
        for spoke in _approved_spokes(resolved_tenant_id)
    ]
    spokes.sort(key=lambda item: str(item.get("spoke_name") or "").lower())
    return {"tenant_id": resolved_tenant_id, "spokes": spokes}


@router.get("/aggregate/central")
def get_aggregate_central(
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    return _aggregate_central_payload(resolved_tenant_id)


@router.get("/{tenant_id}/aggregate/central-sites-config")
def get_tenant_aggregate_central_sites_config(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    return _normalize_central_sites_config(store.get_tenant_central_sites_config(resolved_tenant_id))


@router.post("/{tenant_id}/aggregate/central-sites-config")
def set_tenant_aggregate_central_sites_config(
    tenant_id: str,
    payload: CentralSitesConfigPayload,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    # Merge with existing stored config so unrelated fields (e.g. monitored_items) are preserved
    existing = store.get_tenant_central_sites_config(resolved_tenant_id) or {}
    merged = dict(existing)
    merged.update(_normalize_central_sites_config(payload.model_dump()))
    store.set_tenant_central_sites_config(resolved_tenant_id, merged)
    return _normalize_central_sites_config(merged)


@router.get("/aggregate/central-status")
async def get_aggregate_central_status(
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    """Aggregate Aruba Central status across spokes.
    Centralized mode: from hub's own polling. Distributed mode: from spoke relay telemetry.
    """
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    mode = _central_mode(tenant)
    spokes = _approved_spokes(resolved_tenant_id)

    if mode == "centralized":
        from ..tasks import _cache_updated_at, _hub_central_status

        is_stale = time.time() - _cache_updated_at.get(resolved_tenant_id, 0) > 300
        tenant_data = {} if is_stale else _hub_central_status.get(resolved_tenant_id, {})
        token_valid = False if is_stale else bool(tenant_data.get("token_valid", False))
        token_state = "stale" if is_stale else tenant_data.get("token_state", "not_configured")
        aggregate_status = {} if is_stale or not isinstance(tenant_data.get("status"), dict) else tenant_data.get("status", {})
        wireless_clients = {} if is_stale or not isinstance(tenant_data.get("wireless_clients"), dict) else tenant_data.get("wireless_clients", {})
        hardware_alerts = [] if is_stale or not isinstance(tenant_data.get("hardware_alerts"), list) else tenant_data.get("hardware_alerts", [])
        client_count_status = {} if is_stale or not isinstance(tenant_data.get("client_count_status"), dict) else tenant_data.get("client_count_status", {})
        central_sites_config = _normalize_central_sites_config(store.get_tenant_central_sites_config(resolved_tenant_id))
        tenant_spokes_data = tenant_data.get("spokes", {}) if isinstance(tenant_data.get("spokes"), dict) else {}
        spoke_map = {spoke.id: spoke for spoke in spokes}
        ordered_spoke_ids = [spoke.id for spoke in spokes]
        ordered_spoke_ids.extend(spoke_id for spoke_id in tenant_spokes_data if spoke_id not in spoke_map)
        spokes_out = []
        for spoke_id in ordered_spoke_ids:
            spoke = spoke_map.get(spoke_id)
            spoke_data = tenant_spokes_data.get(spoke_id, {}) if isinstance(tenant_spokes_data.get(spoke_id), dict) else {}
            site_mappings = spoke_data.get("site_mappings", {}) if isinstance(spoke_data.get("site_mappings"), dict) else {}
            # Fall back to tenant-level config when spoke cache is empty (e.g. fresh start
            # before the background task has run). In centralized mode the hub monitors all
            # sites on behalf of every spoke, so the tenant config is always authoritative.
            if not site_mappings:
                site_mappings = dict(central_sites_config.get("site_mappings") or {}) if isinstance(central_sites_config.get("site_mappings"), dict) else {}
            status = spoke_data.get("status", {}) if isinstance(spoke_data.get("status"), dict) else {}
            wireless = spoke_data.get("wireless_clients", {}) if isinstance(spoke_data.get("wireless_clients"), dict) else {}
            hw_alerts = spoke_data.get("hardware_alerts", []) if isinstance(spoke_data.get("hardware_alerts"), list) else []
            sites = []
            for wsite, central_site in site_mappings.items():
                site_status = status.get(wsite, {}) if isinstance(status.get(wsite), dict) else {}
                ok = sum(1 for value in site_status.values() if isinstance(value, dict) and value.get("status") == "OK")
                fail = sum(1 for value in site_status.values() if isinstance(value, dict) and value.get("status") == "ERROR")
                unk = max(len(site_status) - ok - fail, 0)
                sites.append({
                    "wsite": wsite,
                    "central_site": central_site,
                    "check_ok": ok,
                    "check_fail": fail,
                    "check_unknown": unk,
                    "wireless_clients": wireless.get(wsite),
                    "status_map": site_status,
                })
            spokes_out.append({
                "spoke_id": spoke_id,
                "spoke_name": (spoke.spoke_name or spoke.hostname) if spoke else spoke_id,
                "hostname": spoke.hostname if spoke else "",
                "assigned_sites": spoke.assigned_sites if spoke else [s for s in [str(spoke_data.get("assigned_site") or "").strip()] if s],
                "spoke_online": _is_online(spoke) if spoke else False,
                "last_seen": spoke.last_seen if spoke else None,
                "sites": sites,
                "hardware_alerts": hw_alerts,
                "client_count_status": spoke_data.get("client_count_status", client_count_status),
            })
        return {
            "tenant_id": resolved_tenant_id,
            "mode": "centralized",
            "token_valid": token_valid,
            "token_state": token_state,
            "status": aggregate_status,
            "wireless_clients": wireless_clients,
            "hardware_alerts": hardware_alerts,
            "central_sites_config": central_sites_config,
            "client_count_status": client_count_status,
            "spokes": spokes_out,
        }

    spokes_out = []
    aggregate_client_count_status: dict[str, Any] = {}
    for spoke in spokes:
        central = _central_telemetry(spoke)
        site_mappings = central.get("site_mappings", {})
        status = central.get("status", {})
        wireless = central.get("wireless_clients", {})
        hw_alerts = central.get("hardware_alerts", [])
        client_count_status = central.get("client_count_status", {}) if isinstance(central.get("client_count_status"), dict) else {}
        for wsite, info in client_count_status.items():
            if wsite not in aggregate_client_count_status and isinstance(info, dict):
                aggregate_client_count_status[wsite] = info
        token_valid_spoke = bool(central.get("token_valid", False))
        token_state_spoke = central.get("token_state", {})
        sites = []
        for wsite, central_site in site_mappings.items():
            site_status = status.get(wsite, {})
            ok = sum(1 for value in site_status.values() if isinstance(value, dict) and value.get("status") == "OK")
            fail = sum(1 for value in site_status.values() if isinstance(value, dict) and value.get("status") == "ERROR")
            unk = max(len(site_status) - ok - fail, 0)
            sites.append({
                "wsite": wsite,
                "central_site": central_site,
                "check_ok": ok,
                "check_fail": fail,
                "check_unknown": unk,
                "wireless_clients": wireless.get(wsite),
                "status_map": site_status,
            })
        spokes_out.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "hostname": spoke.hostname,
            "assigned_sites": spoke.assigned_sites,
            "spoke_online": _is_online(spoke),
            "last_seen": spoke.last_seen,
            "token_valid": token_valid_spoke,
            "token_state": token_state_spoke,
            "sites": sites,
            "hardware_alerts": hw_alerts,
            "client_count_status": client_count_status,
        })
    return {
        "tenant_id": resolved_tenant_id,
        "mode": "distributed",
        "token_valid": None,
        "token_state": None,
        "client_count_status": aggregate_client_count_status,
        "spokes": spokes_out,
    }


@router.get("/central/available")
async def hub_central_available(
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    """Return Aruba Central alert, insight, and hardware catalogs for the hub UI."""
    resolved_tid = _resolve_tenant_id(tenant_id, current_user)
    tenant = _get_tenant(resolved_tid)
    if not tenant.aruba_config_enc:
        return {"alerts": [], "insights": [], "hardware": [], "warning": "Central not configured on hub."}
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
        cfg["cluster_url"] = validate_cluster_url(cfg.get("cluster_url", ""))
    except Exception as exc:
        logger.warning("Unable to read Aruba config for tenant %s: %s", resolved_tid, exc)
        return {"alerts": [], "insights": [], "hardware": [], "warning": "Could not read Central API config."}

    client = ArubaClient(cfg)
    if not client.is_configured():
        return {"alerts": [], "insights": [], "hardware": [], "warning": "Central not configured on hub."}
    try:
        return await client.available_checks()
    except Exception as exc:
        logger.warning("Unable to fetch Central catalog for tenant %s: %s", resolved_tid, exc)
        return {"alerts": [], "insights": [], "hardware": [], "warning": str(exc)}


@router.get("/central/devices")
async def hub_central_devices(
    site: str = Query(..., description="Site name to filter devices by"),
    tenant_id: Optional[str] = Query(None),
    current_user: User = Depends(auth.get_current_user),
):
    """Fetch network devices from Central API filtered by site name. Hub-side endpoint for CNX mode."""
    resolved_tid = _resolve_tenant_id(tenant_id, current_user)
    tenant = _get_tenant(resolved_tid)

    if not tenant.aruba_config_enc:
        return {"devices": [], "count": 0, "warning": "Central API not configured on hub."}

    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception:
        return {"devices": [], "count": 0, "warning": "Could not decrypt Central API config."}

    api_version = cfg.get("api_version", "classic")
    if api_version != "new_central":
        return {"devices": [], "count": 0, "warning": "Device list requires New Central API mode."}

    cluster_url = (cfg.get("cluster_url") or "").rstrip("/")
    client_id = cfg.get("client_id", "")
    client_secret = cfg.get("client_secret", "")

    if not all([cluster_url, client_id, client_secret]):
        return {"devices": [], "count": 0, "warning": "Central API credentials incomplete."}

    cfg["cluster_url"] = _validated_cluster_url_or_400(cluster_url)
    aruba_client = ArubaClient(cfg)

    try:
        async with httpx.AsyncClient() as client:
            access_token = await aruba_client._ensure_token(client)
            headers = aruba_client._headers(access_token)

            site_id = None
            site_lookup_error = ""
            try:
                sh_resp = await client.get(
                    f"{aruba_client.cluster_url}/network-monitoring/v1alpha1/sites-health",
                    headers=headers,
                    timeout=20,
                )
                if sh_resp.status_code != 200:
                    site_lookup_error = f"Sites health fetch failed: {sh_resp.status_code}"
                else:
                    for item in sh_resp.json().get("items", []):
                        sname = item.get("siteName") or item.get("site_name") or ""
                        if sname.lower() == site.lower():
                            site_id = item.get("siteId") or item.get("site_id")
                            break
            except Exception as exc:
                logger.warning("Central site lookup failed for tenant %s site %s: %s", resolved_tid, site, exc)
                site_lookup_error = str(exc)

            if site_lookup_error:
                return {
                    "devices": [],
                    "count": 0,
                    "warning": "Failed to look up site in Central.",
                    "error": site_lookup_error,
                }
            if not site_id:
                return {"devices": [], "count": 0, "warning": f"Site '{site}' not found in Central."}

            params: dict[str, Any] = {"limit": 500}
            if site_id:
                params["filter"] = f"siteId eq '{site_id}'"

            dev_resp = await client.get(
                f"{aruba_client.cluster_url}/network-monitoring/v1alpha1/devices",
                headers=headers,
                params=params,
                timeout=20,
            )
            if dev_resp.status_code != 200:
                return {"devices": [], "count": 0, "warning": f"Devices fetch failed: {dev_resp.status_code}"}

            raw_devices = dev_resp.json().get("items", [])
            if site_id:
                raw_devices = [d for d in raw_devices if d.get("siteId") == site_id]

            devices = [
                {
                    "name": d.get("deviceName") or d.get("id") or "—",
                    "type": d.get("deviceType", "—"),
                    "model": d.get("model", "—"),
                    "ip": d.get("ipv4") or d.get("ip", "—"),
                    "mac": d.get("macAddress") or d.get("mac", "—"),
                    "status": d.get("status", "—"),
                    "site": d.get("siteId", "—"),
                    "serial": d.get("serialNumber") or d.get("serial", "—"),
                    "sw_ver": d.get("softwareVersion") or d.get("firmwareVersion") or d.get("swVersion", "—"),
                }
                for d in raw_devices
            ]

            return {"devices": devices, "count": len(devices)}

    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Error fetching Central devices for tenant %s site %s: %s", resolved_tid, site, exc)
        return {"devices": [], "count": 0, "warning": "Error fetching devices.", "error": str(exc)}


@router.get("/central/site-alerts")
async def hub_central_site_alerts(
    site: str = Query(..., description="Site name to fetch alerts for"),
    tenant_id: Optional[str] = Query(None),
    current_user: User = Depends(auth.get_current_user),
):
    """Fetch site alerts from Central API. Hub-side endpoint."""
    resolved_tid = _resolve_tenant_id(tenant_id, current_user)
    tenant = _get_tenant(resolved_tid)

    if not tenant.aruba_config_enc:
        return {"alerts": [], "count": 0, "warning": "Central API not configured on hub."}

    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception:
        return {"alerts": [], "count": 0, "warning": "Could not decrypt Central API config."}

    api_version = cfg.get("api_version", "classic")
    cluster_url = (cfg.get("cluster_url") or "").rstrip("/")
    client_id = cfg.get("client_id", "")
    client_secret = cfg.get("client_secret", "")

    if not all([cluster_url, client_id, client_secret]):
        return {"alerts": [], "count": 0, "warning": "Central API credentials incomplete."}

    cfg["cluster_url"] = _validated_cluster_url_or_400(cluster_url)
    aruba_client = ArubaClient(cfg)

    try:
        async with httpx.AsyncClient() as client:
            access_token = await aruba_client._ensure_token(client)
            headers = aruba_client._headers(access_token)

            alerts: list[dict[str, Any]] = []
            ts_now = int(time.time())

            if api_version == "new_central":
                site_id = None
                health_score = None
                site_found = False
                site_lookup_error = ""
                try:
                    sh_resp = await client.get(
                        f"{aruba_client.cluster_url}/network-monitoring/v1alpha1/sites-health",
                        headers=headers,
                        timeout=20,
                    )
                    if sh_resp.status_code != 200:
                        site_lookup_error = f"Sites health fetch failed: {sh_resp.status_code}"
                    else:
                        for item in sh_resp.json().get("items", []):
                            sname = item.get("siteName") or item.get("site_name") or ""
                            if sname.lower() == site.lower():
                                site_found = True
                                site_id = item.get("siteId") or item.get("site_id")
                                health_score = int(item.get("healthScore", item.get("health_score", 100)))
                                break
                except Exception as exc:
                    logger.warning("Central alerts site lookup failed for tenant %s site %s: %s", resolved_tid, site, exc)
                    site_lookup_error = str(exc)

                if site_lookup_error:
                    return {
                        "alerts": [],
                        "count": 0,
                        "warning": "Failed to look up site in Central.",
                        "error": site_lookup_error,
                    }
                if not site_found:
                    return {"alerts": [], "count": 0, "warning": f"Site '{site}' not found in Central."}

                if health_score is not None and health_score < 100:
                    severity = "CRITICAL" if health_score < 50 else "MAJOR" if health_score < 80 else "MINOR"
                    alerts.append({
                        "type": "SITE_HEALTH",
                        "name": "Site Health Score",
                        "severity": severity,
                        "state": "active",
                        "site": site,
                        "device": site,
                        "ts": ts_now,
                        "message": f"Site health score is {health_score}/100",
                    })

                if site_id:
                    device_fetch_error = ""
                    try:
                        params: dict[str, Any] = {"limit": 500, "filter": f"siteId eq '{site_id}'"}
                        dev_resp = await client.get(
                            f"{aruba_client.cluster_url}/network-monitoring/v1alpha1/devices",
                            headers=headers,
                            params=params,
                            timeout=20,
                        )
                        if dev_resp.status_code != 200:
                            device_fetch_error = f"Devices fetch failed: {dev_resp.status_code}"
                        else:
                            _TYPE_MAP = {
                                "ACCESS_POINT": ("AP_DOWN", "AP Down"),
                                "SWITCH": ("SWITCH_DOWN", "Switch Down"),
                                "GATEWAY": ("GATEWAY_DOWN", "Gateway Down"),
                            }
                            for dev in dev_resp.json().get("items", []):
                                if dev.get("siteId") != site_id:
                                    continue
                                status = (dev.get("status") or "").upper()
                                if status in ("UP", "ONLINE"):
                                    continue
                                dtype = (dev.get("deviceType") or "").upper()
                                atype, aname = _TYPE_MAP.get(dtype, ("DEVICE_DOWN", "Device Down"))
                                alerts.append({
                                    "type": atype,
                                    "name": aname,
                                    "severity": "CRITICAL",
                                    "state": "active",
                                    "site": site,
                                    "device": dev.get("deviceName") or dev.get("id") or "—",
                                    "ts": ts_now,
                                    "message": f"{dev.get('model', dtype)} — status: {dev.get('status', 'Unknown')} | IP: {dev.get('ipv4') or dev.get('ip', '—')}",
                                })
                    except Exception as exc:
                        logger.warning("Central device alert fetch failed for tenant %s site %s: %s", resolved_tid, site, exc)
                        device_fetch_error = str(exc)
                    if device_fetch_error:
                        return {
                            "alerts": alerts,
                            "count": len(alerts),
                            "warning": "Failed to fetch site devices from Central.",
                            "error": device_fetch_error,
                        }
            else:
                thirty_days_ago = ts_now - 30 * 86400
                alerts_fetch_error = ""
                for path in ["/monitoring/v1/alerts", "/monitoring/v2/alerts"]:
                    try:
                        resp = await client.get(
                            f"{aruba_client.cluster_url}{path}",
                            headers=headers,
                            params={"site": site, "limit": 500, "from_timestamp": thirty_days_ago},
                            timeout=20,
                        )
                        if resp.status_code == 200:
                            for alert in resp.json().get("alerts", []):
                                alert_site = alert.get("site_name") or alert.get("site") or ""
                                if alert_site and alert_site.lower() != site.lower():
                                    continue
                                alerts.append({
                                    "type": alert.get("alert_type") or alert.get("type", ""),
                                    "name": alert.get("alert_type_name") or alert.get("alert_type", ""),
                                    "severity": alert.get("severity", ""),
                                    "state": alert.get("state", ""),
                                    "site": alert.get("site_name") or site,
                                    "device": alert.get("device_name") or alert.get("hostname", ""),
                                    "ts": alert.get("timestamp") or alert.get("raised_at", ""),
                                    "message": alert.get("details") or alert.get("description", ""),
                                })
                            alerts_fetch_error = ""
                            break
                        if resp.status_code == 404:
                            continue
                        alerts_fetch_error = f"{path} returned {resp.status_code}"
                        logger.warning("Central alerts fetch failed for tenant %s site %s via %s: %s", resolved_tid, site, path, resp.status_code)
                    except Exception as exc:
                        logger.warning("Central alerts fetch failed for tenant %s site %s via %s: %s", resolved_tid, site, path, exc)
                        alerts_fetch_error = str(exc)
                        continue

                if alerts_fetch_error and not alerts:
                    return {
                        "alerts": [],
                        "count": 0,
                        "warning": "Failed to fetch site alerts from Central.",
                        "error": alerts_fetch_error,
                    }

            warning = None if alerts else "No alerts detected for this site."
            return {"alerts": alerts, "count": len(alerts), "warning": warning}

    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Error fetching Central alerts for tenant %s site %s: %s", resolved_tid, site, exc)
        return {"alerts": [], "count": 0, "warning": "Error fetching alerts.", "error": str(exc)}


@router.get("/central/browse")
async def hub_central_browse(
    tenant_id: Optional[str] = Query(default=None),
    force: bool = Query(default=False),
    current_user: User = Depends(auth.get_current_user),
):
    """Return Central browse data from the in-memory cache (refreshed every 5 min by background task).
    force=true performs a synchronous refresh before returning the current payload."""
    resolved_tid = _resolve_tenant_id(tenant_id, current_user)

    # Load disk cache into memory if cold (e.g. first request after restart)
    if resolved_tid not in _central_browse_cache:
        disk = _load_browse_disk_cache(resolved_tid)
        if disk:
            _central_browse_cache[resolved_tid] = disk
            _central_browse_cache_ts[resolved_tid] = disk.get("cached_at", 0)

    cached = _central_browse_cache.get(resolved_tid)

    # Also refresh when clients is empty but clients_by_site has data — stale disk cache from old format
    def _needs_client_refresh(d: dict | None) -> bool:
        if not isinstance(d, dict):
            return False
        return not d.get("clients") and bool(d.get("clients_by_site"))

    if force or _has_legacy_client_summary_rows(cached) or _needs_client_refresh(cached):
        await _refresh_central_browse(resolved_tid)
        cached = _central_browse_cache.get(resolved_tid)

    if cached:
        normalized_cached = _normalize_browse_cache(cached) or {}
        if normalized_cached != cached:
            _central_browse_cache[resolved_tid] = normalized_cached
            _save_browse_disk_cache(resolved_tid, normalized_cached)
        return {**normalized_cached, "cached": True}

    # Nothing in memory or on disk yet — do a blocking fetch (first-ever load)
    await _refresh_central_browse(resolved_tid)
    cached = _central_browse_cache.get(resolved_tid, {})
    normalized_cached = _normalize_browse_cache(cached) or {}
    if normalized_cached != cached:
        _central_browse_cache[resolved_tid] = normalized_cached
        _save_browse_disk_cache(resolved_tid, normalized_cached)
    return {**normalized_cached, "cached": False}


async def _refresh_central_browse(tenant_id: str) -> None:
    """Fetch fresh Central browse data for one tenant and store in memory + disk."""
    now = time.time()
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        return
    mode = _central_mode(tenant)

    if mode == "centralized":
        if not tenant.aruba_config_enc:
            result = {"sites": [], "alerts": [], "insights": [], "clients": [],
                      "mode": mode, "warning": "Central not configured on hub.",
                      "cached_at": now}
        else:
            try:
                cfg = decrypt_dict(tenant.aruba_config_enc)
                cfg["cluster_url"] = validate_cluster_url(cfg.get("cluster_url", ""))
            except Exception:
                result = {"sites": [], "alerts": [], "insights": [], "clients": [],
                          "mode": mode, "warning": "Could not read Central config.",
                          "cached_at": now}
                _central_browse_cache[tenant_id] = result
                _central_browse_cache_ts[tenant_id] = now
                _save_browse_disk_cache(tenant_id, result)
                return
            aruba = ArubaClient(cfg)
            if not aruba.is_configured():
                result = {"sites": [], "alerts": [], "insights": [], "clients": [],
                          "mode": mode, "warning": "Central not configured.",
                          "cached_at": now}
            else:
                try:
                    data = await aruba.browse_all()
                    result = {**data, "mode": mode, "cached_at": now,
                              "warning": data.get("warning")}
                except Exception as exc:
                    logger.warning("central_browse refresh failed for %s: %s", tenant_id, exc)
                    # Keep existing cache on error — don't overwrite with empty
                    return
    else:
        sites_map: dict[str, dict[str, Any]] = {}
        alerts: list[dict[str, Any]] = []
        insights: list[dict[str, Any]] = []
        clients: list[dict[str, Any]] = []
        devices_by_site: dict[str, list[dict[str, Any]]] = {}
        clients_by_site: dict[str, dict[str, Any]] = {}
        # Track seen alert/insight/device keys to deduplicate across spokes sharing the same sites
        seen_alert_keys: set[tuple[str, str]] = set()
        seen_insight_keys: set[tuple[str, str]] = set()
        seen_device_keys: set[tuple[str, str]] = set()
        for spoke in _approved_spokes(tenant_id):
            central = _central_telemetry(spoke)
            for wsite, central_site in (central.get("site_mappings") or {}).items():
                if wsite not in sites_map:
                    wc = (central.get("wireless_clients") or {}).get(wsite)
                    sites_map[wsite] = {"name": wsite, "central_site": central_site,
                                        "wireless_clients": wc, "health_score": None,
                                        "site_id": "", "status": central_site or "—"}
            spoke_nc_alerts = central.get("central_alerts") or []
            if spoke_nc_alerts:
                for alert in spoke_nc_alerts:
                    key = (str(alert.get("name") or "").lower(), str(alert.get("site") or "").lower())
                    if key not in seen_alert_keys:
                        seen_alert_keys.add(key)
                        alerts.append(alert)
            else:
                for wsite, checks in (central.get("status") or {}).items():
                    for check_id, info in (checks or {}).items():
                        if info and info.get("status") == "ERROR":
                            key = (check_id, wsite)
                            if key not in seen_alert_keys:
                                seen_alert_keys.add(key)
                                alerts.append({"name": info.get("check_name") or check_id,
                                               "site": wsite, "severity": "error",
                                               "detail": f"Count: {info.get('count', 0)}",
                                               "ts": info.get("ts")})
            for insight in (central.get("central_insights") or []):
                key = (str(insight.get("name") or "").lower(), str(insight.get("site") or "").lower())
                if key not in seen_insight_keys:
                    seen_insight_keys.add(key)
                    insights.append(insight)
            for site_name, devs in (central.get("central_devices_by_site") or {}).items():
                for dev in devs:
                    key = (site_name, str(dev.get("name") or dev.get("serial") or "").lower())
                    if key not in seen_device_keys:
                        seen_device_keys.add(key)
                        devices_by_site.setdefault(site_name, []).append(dev)
            for site_name, counts in (central.get("central_clients_by_site") or {}).items():
                # First-seen wins: multiple spokes report the same Central site counts
                # (they all query the same Aruba Central API). Adding them together
                # would multiply the real count by the number of spokes.
                if site_name not in clients_by_site:
                    clients_by_site[site_name] = counts
            seen_client_keys: set[str] = {
                str(c.get("mac") or c.get("hostname") or "")
                for c in clients if isinstance(c, dict)
            }
            for client in _telemetry_clients(spoke):
                if not isinstance(client, dict):
                    continue
                # Deduplicate across spokes by MAC (preferred) or hostname
                key = str(client.get("mac") or client.get("hostname") or "")
                if key and key in seen_client_keys:
                    continue
                if key:
                    seen_client_keys.add(key)
                clients.append(client)
        result = {
            "sites": sorted(sites_map.values(), key=lambda item: str(item.get("name") or "").casefold()),
            "alerts": alerts, "insights": insights, "clients": clients,
            "clients_by_site": clients_by_site, "devices_by_site": devices_by_site,
            "mode": mode, "cached_at": now, "warning": None,
        }

    _central_browse_cache[tenant_id] = result
    _central_browse_cache_ts[tenant_id] = now
    _save_browse_disk_cache(tenant_id, result)
    logger.debug("central_browse: refreshed cache for tenant %s", tenant_id)


# ── Monitored Items ──────────────────────────────────────────────────────────

class MonitoredItemCreate(BaseModel):
    type: str  # "site", "alert", "insight", "client"
    name: str
    identifier: str  # lookup key: site/alert/insight name, or client MAC


@router.get("/{tenant_id}/aggregate/monitored-items")
async def get_monitored_items(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Return all monitored items for a tenant (viewer-accessible for button state)."""
    resolved_tenant_id = _require_tenant_access(tenant_id, current_user)
    cfg = store.get_tenant_central_sites_config(resolved_tenant_id)
    items = cfg.get("monitored_items") if isinstance(cfg.get("monitored_items"), list) else []
    return {"items": items}


@router.post("/{tenant_id}/aggregate/monitored-items")
async def add_monitored_item(
    tenant_id: str,
    body: MonitoredItemCreate,
    current_user: User = Depends(auth.get_current_user),
):
    """Add an item to the monitored items list (idempotent by type + identifier)."""
    import uuid as _uuid
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    cfg = store.get_tenant_central_sites_config(resolved_tenant_id)
    items: list[dict[str, Any]] = list(cfg.get("monitored_items") or [])
    existing = next(
        (item for item in items if isinstance(item, dict)
         and item.get("type") == body.type
         and item.get("identifier") == body.identifier),
        None,
    )
    if existing:
        return {"item": existing, "created": False}
    new_item: dict[str, Any] = {
        "id": str(_uuid.uuid4()),
        "type": str(body.type),
        "name": str(body.name),
        "identifier": str(body.identifier),
        "added_at": time.time(),
        "consecutive_failures": 0,
        "last_seen": None,
        "last_notified": None,
        "status": "ok",
    }
    items.append(new_item)
    cfg["monitored_items"] = items
    store.set_tenant_central_sites_config(resolved_tenant_id, cfg)
    return {"item": new_item, "created": True}


@router.delete("/{tenant_id}/aggregate/monitored-items/{item_id}")
async def delete_monitored_item(
    tenant_id: str,
    item_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """Remove a monitored item by ID."""
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    cfg = store.get_tenant_central_sites_config(resolved_tenant_id)
    items = [
        item for item in (cfg.get("monitored_items") or [])
        if isinstance(item, dict) and item.get("id") != item_id
    ]
    cfg["monitored_items"] = items
    store.set_tenant_central_sites_config(resolved_tenant_id, cfg)
    return {"ok": True}


@router.post("/aggregate/central")
async def update_aggregate_central(
    payload: CentralUpdateRequest,
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    requested_tenant_id = payload.tenant_id or tenant_id
    resolved_tenant_id = _require_tenant_admin(_resolve_tenant_id(requested_tenant_id, current_user), current_user)
    tenant = _get_tenant(resolved_tenant_id)
    mode = str(payload.mode or "distributed").strip().lower()
    if mode not in MODE_VALUES:
        raise HTTPException(status_code=400, detail="mode must be centralized or distributed")

    existing_cfg: dict[str, Any] = {}
    if tenant.aruba_config_enc:
        try:
            existing_cfg = decrypt_dict(tenant.aruba_config_enc)
        except Exception:
            existing_cfg = {}
    incoming = payload.hub_central_config.model_dump()
    cfg = {
        "api_version": str(incoming.get("api_version") or existing_cfg.get("api_version") or "classic"),
        "cluster_url": str(incoming.get("cluster_url") or "").strip(),
        "client_id": str(incoming.get("client_id") or "").strip(),
        "customer_id": str(incoming.get("customer_id") or "").strip(),
        "workspace_id": str(incoming.get("workspace_id") or "").strip(),
    }
    client_secret = str(incoming.get("client_secret") or "")
    if client_secret:
        cfg["client_secret"] = client_secret
    elif existing_cfg.get("client_secret"):
        cfg["client_secret"] = existing_cfg["client_secret"]
    # access_token: prefer newly submitted value; fall back to existing encrypted value
    access_token = str(incoming.get("access_token") or "").strip()
    if access_token:
        cfg["access_token"] = access_token
    elif existing_cfg.get("access_token"):
        cfg["access_token"] = existing_cfg["access_token"]
    for key in ("refresh_token", "webhook_id", "webhook_api_key"):
        if key == "refresh_token" and access_token:
            continue
        if existing_cfg.get(key):
            cfg[key] = existing_cfg[key]

    tenant.aruba_cid = cfg.get("customer_id") or tenant.aruba_cid
    tenant.central_browse_interval_minutes = max(1, min(60, payload.central_browse_interval_minutes or 5))
    # Safeguard: only update the encrypted config if the form actually contains values.
    # If all fields are empty (e.g. a masked form was submitted without changes), keep
    # the existing encrypted config rather than wiping it.  Use a dedicated DELETE
    # endpoint to intentionally clear the config.
    _has_new_aruba_values = (
        any(str(value).strip() for key, value in cfg.items() if key != "api_version")
        or bool(cfg.get("client_secret"))
    )
    if _has_new_aruba_values:
        tenant.aruba_config_enc = encrypt_dict(cfg)
    elif not tenant.aruba_config_enc:
        # No existing config and nothing new — store None (first-time empty save)
        tenant.aruba_config_enc = None
    # else: keep existing aruba_config_enc unchanged to prevent accidental wipe
    tenant.default_processing_mode.aruba_polling = mode
    store.save_tenant(tenant)

    # Bump config_version on all approved spokes so the new Central config
    # is queued as a config_update command on the next relay cycle.
    for spoke in _approved_spokes(resolved_tenant_id):
        spoke.config_version += 1
        store.save_spoke(spoke)
        store.ensure_config_update_command(resolved_tenant_id, spoke.id)

    if mode == "centralized" and tenant.aruba_config_enc:
        central_sites_config = _normalize_central_sites_config(store.get_tenant_central_sites_config(resolved_tenant_id))
        if cfg.get("api_version") == "new_central":
            if not central_sites_config.get("monitored_checks"):
                central_sites_config["monitored_checks"] = [dict(item) for item in DEFAULT_NEW_CENTRAL_MONITORED_CHECKS]
            if not central_sites_config.get("hardware_checks"):
                central_sites_config["hardware_checks"] = [dict(item) for item in DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS]
        try:
            discover_client = ArubaClient(cfg)
            discovered_sites = await discover_client.list_sites() if discover_client.is_configured() else []
        except Exception as exc:
            logger.warning("Unable to auto-discover Aruba Central sites for tenant %s: %s", resolved_tenant_id, exc)
            discovered_sites = []
        existing_wsites = {str(name).strip().casefold() for name in central_sites_config.get("site_mappings", {})}
        existing_central = {str(name).strip().casefold() for name in central_sites_config.get("site_mappings", {}).values()}
        excluded = {str(s).strip().casefold() for s in central_sites_config.get("excluded_sites", []) if s}
        for site in discovered_sites:
            site_name = str((site or {}).get("name") or "").strip()
            if not site_name:
                continue
            normalized = site_name.casefold()
            if normalized in existing_wsites or normalized in existing_central or normalized in excluded:
                continue
            central_sites_config.setdefault("site_mappings", {})[site_name] = site_name
            existing_wsites.add(normalized)
            existing_central.add(normalized)
        store.set_tenant_central_sites_config(resolved_tenant_id, central_sites_config)

    return _aggregate_central_payload(resolved_tenant_id)


@router.post("/{tenant_id}/aggregate/central-clear-secrets")
async def clear_aggregate_central_secrets(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    tenant = _get_tenant(resolved_tenant_id)
    if not tenant.aruba_config_enc:
        return _serialize_hub_central_config(tenant)
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt Aruba Central credentials: {exc}") from exc
    cfg.pop("client_secret", None)
    cfg.pop("access_token", None)
    cfg.pop("refresh_token", None)
    _persist_aruba_config(tenant, cfg)
    return _serialize_hub_central_config(tenant)


@router.post("/aggregate/config-push")
def push_tenant_config(
    payload: ConfigPushRequest,
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    requested_tenant_id = payload.tenant_id or tenant_id
    resolved_tenant_id = _require_tenant_admin(_resolve_tenant_id(requested_tenant_id, current_user), current_user)
    updated_spokes = _store_and_queue_tenant_config(resolved_tenant_id, payload.config or {})
    return {"tenant_id": resolved_tenant_id, "config": payload.config, "spokes": updated_spokes}


# ── QA endpoints ──────────────────────────────────────────────────────────────

@router.get("/{tenant_id}/qa/provisioning-check")
def get_qa_provisioning_check(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """QA check: verify the dongle → VM → reporting-client pipeline per spoke.

    For each approved spoke the response reports:
    - dongle_count   : USB dongles physically present (from Proxmox agent telemetry)
    - vm_count       : VMs currently tracked by Proxmox
    - reporting_clients : clients that have posted a status update recently
    - pass           : True when all three counts match and the spoke is online

    Typical assertion: 3 spokes × 10 dongles → overall_pass=true, actual_clients=30.
    """
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    spokes_out: list[dict[str, Any]] = []

    for spoke in _approved_spokes(resolved_tenant_id):
        _used_slots, _total_slots, dongle_count, auto_provision = _spoke_usb_capacity(spoke)
        proxmox = _telemetry_dict(spoke, "proxmox")
        vm_count = int(proxmox.get("vm_count") or 0)
        proxmox_connected = bool(proxmox.get("connected", False))
        reporting_clients = len(_telemetry_clients(spoke))
        spoke_online = _is_online(spoke)

        issues: list[str] = []
        if not spoke_online:
            issues.append("spoke is offline")
        if not proxmox_connected:
            issues.append("Proxmox agent is not connected")
        if auto_provision and dongle_count > 0 and vm_count != dongle_count:
            issues.append(
                f"VM count ({vm_count}) does not match dongle count ({dongle_count})"
            )
        if dongle_count > 0 and reporting_clients != dongle_count:
            issues.append(
                f"reporting clients ({reporting_clients}) does not match dongle count ({dongle_count})"
            )

        spokes_out.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "spoke_online": spoke_online,
            "proxmox_connected": proxmox_connected,
            "auto_provision": auto_provision,
            "dongle_count": dongle_count,
            "vm_count": vm_count,
            "reporting_clients": reporting_clients,
            "pass": spoke_online and len(issues) == 0,
            "issues": issues,
        })

    spokes_out.sort(key=lambda s: str(s.get("spoke_name") or "").lower())
    total_dongles = sum(s["dongle_count"] for s in spokes_out)
    total_clients = sum(s["reporting_clients"] for s in spokes_out)
    overall_pass = bool(spokes_out) and all(s["pass"] for s in spokes_out)

    return {
        "tenant_id": resolved_tenant_id,
        "overall_pass": overall_pass,
        "expected_clients": total_dongles,
        "actual_clients": total_clients,
        "delta": total_clients - total_dongles,
        "spokes": spokes_out,
    }


@router.get("/aggregate/qa/system-health")
def get_qa_system_health(
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    """Full-stack QA health check across hub, spokes, Proxmox agents, and clients.

    Returns all_ok=true only when every approved spoke is online, every Proxmox
    agent is connected, and at least one client is reporting for any spoke that
    has dongles present.
    """
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    spokes = _approved_spokes(resolved_tenant_id)

    spokes_online = sum(1 for s in spokes if _is_online(s))
    proxmox_agents_connected = sum(
        1 for s in spokes if bool(_telemetry_dict(s, "proxmox").get("connected", False))
    )
    total_clients = sum(len(_telemetry_clients(s)) for s in spokes)

    # Spokes that have dongles but zero reporting clients are flagged.
    spokes_with_dongles_no_clients: list[str] = []
    for s in spokes:
        _u, _t, dongle_count, _ap = _spoke_usb_capacity(s)
        if dongle_count > 0 and len(_telemetry_clients(s)) == 0:
            spokes_with_dongles_no_clients.append(s.spoke_name or s.hostname)

    issues: list[str] = []
    if spokes_online < len(spokes):
        issues.append(f"{len(spokes) - spokes_online} spoke(s) offline")
    if proxmox_agents_connected < len(spokes):
        issues.append(f"{len(spokes) - proxmox_agents_connected} Proxmox agent(s) not connected")
    for name in spokes_with_dongles_no_clients:
        issues.append(f"spoke '{name}' has dongles but no clients reporting")

    return {
        "hub_ok": True,
        "tenant_id": resolved_tenant_id,
        "spokes_total": len(spokes),
        "spokes_online": spokes_online,
        "proxmox_agents_connected": proxmox_agents_connected,
        "total_clients": total_clients,
        "issues": issues,
        "all_ok": len(issues) == 0,
    }


@router.post("/{tenant_id}/qa/teardown-all-vms")
def qa_teardown_all_vms(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """QA: Queue deletion of every auto-provisioned sim VM (vmid > 9000) across all spokes.

    Each VM found in spoke telemetry is queued as a `proxmox_agent_command` so the
    spoke forwards a `delete_vm` action to its local Proxmox agent.

    Returns the number of VMs queued per spoke so the caller can poll
    `GET /{tenant_id}/qa/teardown-status` until complete.
    """
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    spokes_out: list[dict[str, Any]] = []
    total_queued = 0

    for spoke in _approved_spokes(resolved_tenant_id):
        proxmox_vms = _telemetry_list(spoke, "proxmox_vms")
        proxmox = _telemetry_dict(spoke, "proxmox")
        if not proxmox_vms and isinstance(proxmox.get("vms"), list):
            proxmox_vms = proxmox["vms"]

        sim_vms = [
            vm for vm in proxmox_vms
            if vm.get("vmid") is not None and int(vm.get("vmid", 0)) > 9000
            and not vm.get("is_template", False)
        ]

        for vm in sim_vms:
            vmid = int(vm["vmid"])
            vm_type = str(vm.get("type") or "qemu").strip().lower()
            if vm_type not in {"qemu", "lxc"}:
                vm_type = "qemu"
            store.enqueue_command(Command(
                spoke_id=spoke.id,
                tenant_id=resolved_tenant_id,
                type="proxmox_agent_command",
                payload={"action": "delete_vm", "args": {"vmid": vmid, "vm_type": vm_type}},
                expires_at=expires_at,
            ))

        queued = len(sim_vms)
        total_queued += queued
        spokes_out.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "vms_found": queued,
            "vms_queued": queued,
        })

    # Push commands immediately rather than waiting for the next spoke telemetry cycle.
    from ..ws import notify_spoke_command
    for sp in spokes_out:
        if sp["vms_queued"] > 0:
            notify_spoke_command(resolved_tenant_id, sp["spoke_id"])

    return {
        "ok": True,
        "tenant_id": resolved_tenant_id,
        "total_vms_queued": total_queued,
        "spokes": spokes_out,
    }


@router.get("/{tenant_id}/qa/teardown-status")
def qa_teardown_status(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """QA: Check whether all auto-provisioned VMs have been deleted across all spokes.

    Reads the current proxmox telemetry from each spoke and counts VMs with vmid > 9000.
    Returns complete=true when every spoke reports zero sim VMs remaining.
    """
    resolved_tenant_id = _resolve_tenant_id(tenant_id, current_user)
    spokes_out: list[dict[str, Any]] = []
    total_remaining = 0

    for spoke in _approved_spokes(resolved_tenant_id):
        proxmox_vms = _telemetry_list(spoke, "proxmox_vms")
        proxmox = _telemetry_dict(spoke, "proxmox")
        if not proxmox_vms and isinstance(proxmox.get("vms"), list):
            proxmox_vms = proxmox["vms"]

        sim_vms_remaining = [
            vm for vm in proxmox_vms
            if vm.get("vmid") is not None and int(vm.get("vmid", 0)) > 9000
            and not vm.get("is_template", False)
        ]
        remaining = len(sim_vms_remaining)
        total_remaining += remaining
        spokes_out.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "spoke_online": _is_online(spoke),
            "proxmox_connected": bool(proxmox.get("connected", False)),
            "sim_vms_remaining": remaining,
            "complete": remaining == 0,
        })

    return {
        "tenant_id": resolved_tenant_id,
        "complete": total_remaining == 0,
        "total_remaining": total_remaining,
        "spokes": spokes_out,
    }


@router.post("/{tenant_id}/qa/enable-autoprov")
def qa_enable_autoprov(
    tenant_id: str,
    current_user: User = Depends(auth.get_current_user),
):
    """QA: Enable Auto-Provisioning on all approved spokes and return expected client count.

    Pushes `usb_auto_provision=on` to every spoke via config_update command.
    Returns the expected number of clients (= total dongle count across all spokes)
    so the caller can poll `GET /{tenant_id}/qa/provisioning-check` until
    actual_clients matches expected_clients.
    """
    resolved_tenant_id = _require_tenant_admin(tenant_id, current_user)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    expected_clients = 0
    updated_spokes: list[dict[str, Any]] = []

    for spoke in _approved_spokes(resolved_tenant_id):
        _used, _total, dongle_count, _auto = _spoke_usb_capacity(spoke)
        expected_clients += dongle_count

        next_config = dict(spoke.config or {})
        next_config["usb_auto_provision"] = "on"
        spoke.config = next_config
        spoke.config_version = (spoke.config_version or 0) + 1
        store.save_spoke(spoke)
        store.enqueue_command(Command(
            spoke_id=spoke.id,
            tenant_id=resolved_tenant_id,
            type="config_update",
            payload={**next_config, "__config_version": spoke.config_version},
            expires_at=expires_at,
        ))
        updated_spokes.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "dongle_count": dongle_count,
        })

    return {
        "ok": True,
        "tenant_id": resolved_tenant_id,
        "auto_provision": "on",
        "expected_clients": expected_clients,
        "updated_spokes": len(updated_spokes),
        "spokes": updated_spokes,
    }
