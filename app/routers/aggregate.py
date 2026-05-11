"""Tenant-scoped aggregate telemetry endpoints."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import auth, store
from ..crypto import decrypt_dict, encrypt_dict
from ..data_models import Spoke, Tenant, User

router = APIRouter()

FAIL_STATUSES = {"error", "fail", "failed", "degraded", "critical"}
PASS_STATUSES = {"ok", "pass", "passed", "healthy", "connected"}
WARNING_STATUSES = {"warn", "warning", "unknown", "no_data", "stale"}
MODE_VALUES = {"centralized", "distributed"}


class ConfigPushRequest(BaseModel):
    tenant_id: str = ""
    config: dict[str, Any] = Field(default_factory=dict)


class CentralConfigPayload(BaseModel):
    api_version: str = "classic"
    cluster_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    customer_id: str = ""


class CentralUpdateRequest(BaseModel):
    tenant_id: str = ""
    mode: str = "distributed"
    hub_central_config: CentralConfigPayload = Field(default_factory=CentralConfigPayload)


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
    return (datetime.now(timezone.utc) - last_seen).total_seconds() < 120



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



def _central_telemetry(spoke: Spoke) -> dict[str, Any]:
    telemetry = spoke.telemetry or {}
    central = telemetry.get("central")
    return central if isinstance(central, dict) else telemetry



def _hardware_type(client: dict[str, Any]) -> str:
    return str(client.get("hw_type") or client.get("platform") or "Unknown").strip() or "Unknown"



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
        return {"configured": False, "api_version": "classic"}
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception:
        return {"configured": True, "error": "unreadable", "api_version": "classic"}
    return {
        "configured": True,
        "cluster_url": cfg.get("cluster_url", ""),
        "client_id": cfg.get("client_id", ""),
        "customer_id": cfg.get("customer_id", ""),
        "api_version": cfg.get("api_version", "classic"),
        "client_secret_configured": bool(cfg.get("client_secret")),
        "access_token_configured": bool(cfg.get("access_token")),
        "refresh_token_configured": bool(cfg.get("refresh_token")),
    }



def _central_mode(tenant: Tenant) -> str:
    mode = tenant.default_processing_mode.resolve("aruba_polling")
    return mode if mode in MODE_VALUES else "distributed"



def _aggregate_central_payload(tenant_id: str) -> dict[str, Any]:
    tenant = _get_tenant(tenant_id)
    spokes = _approved_spokes(tenant_id)
    return {
        "tenant_id": tenant_id,
        "hub_central_config": _serialize_hub_central_config(tenant),
        "mode": _central_mode(tenant),
        "spokes": [
            {
                "spoke_id": spoke.id,
                "spoke_name": spoke.spoke_name or spoke.hostname,
                "spoke_online": _is_online(spoke),
                "last_seen": spoke.last_seen,
                "central_status": _central_telemetry(spoke),
            }
            for spoke in spokes
        ],
    }


@router.get("/aggregate/dashboard")
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
    rows: list[dict[str, Any]] = []
    for spoke in _approved_spokes(resolved_tenant_id):
        spoke_name = spoke.spoke_name or spoke.hostname
        for client in _telemetry_clients(spoke):
            row = dict(client)
            row.update({
                "tenant_id": resolved_tenant_id,
                "spoke_id": spoke.id,
                "spoke_name": spoke_name,
                "spoke_hostname": spoke.hostname,
                "spoke_label": spoke.label,
            })
            rows.append(row)
    rows.sort(key=lambda item: (str(item.get("spoke_name") or "").lower(), str(item.get("hostname") or "").lower()))
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
    for spoke in _approved_spokes(resolved_tenant_id):
        proxmox = _telemetry_dict(spoke, "proxmox")
        vms = _telemetry_list(spoke, "proxmox_vms") or (proxmox.get("vms") if isinstance(proxmox.get("vms"), list) else [])
        usb_devices = _telemetry_list(spoke, "usb_devices") or (proxmox.get("usb_state") if isinstance(proxmox.get("usb_state"), list) else [])
        hosts.append({
            "tenant_id": resolved_tenant_id,
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "spoke_online": _is_online(spoke),
            "last_seen": spoke.last_seen,
            "node": proxmox.get("node") if isinstance(proxmox.get("node"), dict) else {},
            "proxmox": proxmox,
            "proxmox_vms": vms,
            "usb_devices": usb_devices,
            "vm_count": int(proxmox.get("vm_count") or len(vms)),
            "usb_count": int(proxmox.get("usb_count") or len(usb_devices)),
        })
    hosts.sort(key=lambda item: str(item.get("spoke_name") or "").lower())
    return {"tenant_id": resolved_tenant_id, "hosts": hosts}


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


@router.post("/aggregate/central")
def update_aggregate_central(
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
    }
    client_secret = str(incoming.get("client_secret") or "")
    if client_secret:
        cfg["client_secret"] = client_secret
    elif existing_cfg.get("client_secret"):
        cfg["client_secret"] = existing_cfg["client_secret"]
    for key in ("access_token", "refresh_token"):
        if existing_cfg.get(key):
            cfg[key] = existing_cfg[key]

    tenant.aruba_cid = cfg.get("customer_id") or tenant.aruba_cid
    tenant.aruba_config_enc = encrypt_dict(cfg) if any(str(value).strip() for key, value in cfg.items() if key != "api_version") or cfg.get("client_secret") else None
    tenant.default_processing_mode.aruba_polling = mode
    store.save_tenant(tenant)
    return _aggregate_central_payload(resolved_tenant_id)


@router.post("/aggregate/config-push")
def push_tenant_config(
    payload: ConfigPushRequest,
    tenant_id: Optional[str] = Query(default=None),
    current_user: User = Depends(auth.get_current_user),
):
    requested_tenant_id = payload.tenant_id or tenant_id
    resolved_tenant_id = _require_tenant_admin(_resolve_tenant_id(requested_tenant_id, current_user), current_user)
    updated_spokes: list[dict[str, Any]] = []
    for spoke in _approved_spokes(resolved_tenant_id):
        updated_config = dict(spoke.config or {})
        updated_config.update(payload.config or {})
        if updated_config != spoke.config:
            spoke.config = updated_config
            spoke.config_version += 1
            store.save_spoke(spoke)
        updated_spokes.append({
            "spoke_id": spoke.id,
            "spoke_name": spoke.spoke_name or spoke.hostname,
            "config_version": spoke.config_version,
            "applied_config_version": spoke.applied_config_version,
            "last_config_applied_at": spoke.last_config_applied_at,
        })
    return {"tenant_id": resolved_tenant_id, "config": payload.config, "spokes": updated_spokes}
