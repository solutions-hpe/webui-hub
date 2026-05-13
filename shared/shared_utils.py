"""
shared_utils.py — HPE Client-Sim shared Python utilities

Used by both webui-hub and webui-spoke server.py.

In webui-hub:   imported directly (lives in shared/ alongside app/).
In webui-spoke: copied to the install directory by the installer at deploy time,
                then imported as a local module.
"""

from __future__ import annotations

import time
from typing import Any


# ── Client telemetry ──────────────────────────────────────────────────────────

def serialize_client(hostname: str, client: dict[str, Any]) -> dict[str, Any]:
    """
    Serialize one client's in-memory state dict into the telemetry wire format.

    This is the canonical version used by the spoke when posting telemetry to
    the hub.  Both repos import this function so the schema stays in sync.
    """
    last_seen_raw = client.get("last_seen")
    if last_seen_raw is None:
        last_seen_iso = None
        online = False
    else:
        from datetime import datetime, timezone
        if isinstance(last_seen_raw, (int, float)):
            dt = datetime.fromtimestamp(last_seen_raw, tz=timezone.utc)
        elif isinstance(last_seen_raw, datetime):
            dt = last_seen_raw.astimezone(timezone.utc)
        else:
            dt = datetime.fromisoformat(str(last_seen_raw)).astimezone(timezone.utc)
        last_seen_iso = dt.isoformat().replace("+00:00", "Z")
        online = (time.time() - dt.timestamp()) < 120

    config: dict[str, Any] = {
        k: client.get(k)
        for k in ("simulation_id", "site", "ssid", "vlan", "gateway",
                  "vh_host", "vh_port", "silent_timeout")
        if client.get(k) is not None
    }
    effective_config: dict[str, Any] = client.get("effective_config") or {}
    overrides: dict[str, Any] = client.get("overrides") or {}

    return {
        "hostname": hostname,
        "simulation_id": client.get("simulation_id", ""),
        "platform": client.get("platform", ""),
        "hw_type": client.get("hw_type") or "",
        "iteration": client.get("iteration", 0),
        "connected_ssid": client.get("connected_ssid") or "",
        "gateway_reachable": bool(client.get("gateway_reachable", False)),
        "vh_connected": bool(client.get("vh_connected", False)),
        "active_simulations": list(client.get("active_simulations", [])),
        "config": config,
        "effective_config": effective_config,
        "overrides": overrides,
        "last_seen": last_seen_iso,
        "online": online,
        "recent_errors": list(client.get("recent_errors", [])),
        "error_count": int(client.get("error_count", 0)),
    }


# ── Proxmox / Reclone telemetry summaries ────────────────────────────────────

def proxmox_summary(proxmox_state: dict[str, Any]) -> dict[str, Any]:
    """
    Build a lean, telemetry-safe summary of Proxmox state.

    Strips large arrays (log lines, pending agents) and returns only what
    the hub needs to render the Server tab in the spoke modal.
    """
    vms = proxmox_state.get("vms", [])
    return {
        "connected": proxmox_state.get("connected", False),
        "last_seen": proxmox_state.get("last_seen"),
        "node": proxmox_state.get("node", {}),   # cpu_percent, mem_used_kb, mem_total_kb, storage[]
        "vm_count": len(vms),
        "running_count": sum(1 for v in vms if v.get("status") == "running"),
        "vms": [
            {
                "vmid": v.get("vmid"),
                "name": v.get("name", ""),
                "status": v.get("status", ""),
                "type": v.get("type", ""),
            }
            for v in vms
        ],
        "usb_count": len(proxmox_state.get("usb_state", [])),
        "agent_version": proxmox_state.get("agent_version"),
        "pve_version": proxmox_state.get("pve_version"),
    }


def reclone_summary(reclone_state: dict[str, Any]) -> dict[str, Any]:
    """
    Build a lean, telemetry-safe summary of reclone state.

    Strips the full log (can be hundreds of entries) — only metadata is sent.
    """
    return {
        "status": reclone_state.get("status", "idle"),
        "type": reclone_state.get("type"),
        "total": reclone_state.get("total", 0),
        "completed": reclone_state.get("completed", 0),
        "failed": reclone_state.get("failed", 0),
        "current_vm": reclone_state.get("current_vm"),
        "phase": reclone_state.get("phase"),
        "last_run": reclone_state.get("last_run"),
        "started_at": reclone_state.get("started_at"),
    }


# ── Shared library fetch (used by both installers and server.py) ──────────────

HUB_REPO_RAW_DEFAULT = "https://raw.githubusercontent.com/solutions-hpe/webui-hub"


def shared_lib_urls(branch: str, hub_repo_raw: str = HUB_REPO_RAW_DEFAULT) -> dict[str, str]:
    """Return the raw GitHub URLs for the shared library files at a given branch."""
    base = f"{hub_repo_raw}/{branch}/shared"
    return {
        "shared.js":  f"{base}/shared.js",
        "shared.css": f"{base}/shared.css",
    }
