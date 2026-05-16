from __future__ import annotations

import asyncio
import inspect
import logging
import ssl
import time
import urllib.parse
import uuid
from typing import Any

import httpx
import websockets
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from .. import auth, store
from ..crypto import decrypt_str
from ..data_models import User

router = APIRouter()
logger = logging.getLogger(__name__)

_sessions: dict[str, dict[str, Any]] = {}
SESSION_TTL = 60
_CONNECT_HEADER_ARG = (
    "additional_headers"
    if "additional_headers" in inspect.signature(websockets.connect).parameters
    else "extra_headers"
)


def _cleanup_sessions() -> None:
    now = time.time()
    expired = [key for key, value in _sessions.items() if value.get("expires", 0) < now]
    for key in expired:
        _sessions.pop(key, None)


def _proxmox_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"PVEAPIToken={token}"}


def _proxmox_error_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        detail = payload.get("detail") or payload.get("message") or payload.get("error")
        if isinstance(detail, str) and detail.strip():
            return detail.strip()
        errors = payload.get("errors")
        if isinstance(errors, dict) and errors:
            return "; ".join(f"{key}: {value}" for key, value in errors.items())
    text = response.text.strip()
    return text or f"HTTP {response.status_code}"


def _resolve_spoke_node(spoke) -> str:
    telemetry = spoke.telemetry if isinstance(spoke.telemetry, dict) else {}
    proxmox = telemetry.get("proxmox") if isinstance(telemetry.get("proxmox"), dict) else {}
    proxmox_node = proxmox.get("node") if isinstance(proxmox.get("node"), dict) else {}
    node = telemetry.get("node") if isinstance(telemetry.get("node"), dict) else {}
    candidates = [
        node.get("hostname"),
        proxmox_node.get("hostname"),
        spoke.hostname,
    ]
    for candidate in candidates:
        value = str(candidate or "").strip()
        if value:
            return value
    return ""


async def _request_vnc_proxy(
    *,
    proxmox_host: str,
    proxmox_token: str,
    node: str,
    vmid: int,
    vmtype: str,
) -> dict[str, Any]:
    path = f"/api2/json/nodes/{urllib.parse.quote(node, safe='')}/{vmtype}/{vmid}/vncproxy"
    url = f"https://{proxmox_host}:8006{path}"
    async with httpx.AsyncClient(verify=False, timeout=20.0) as client:
        response = await client.post(
            url,
            headers=_proxmox_headers(proxmox_token),
            data={"websocket": 1},
        )
    if not response.is_success:
        raise HTTPException(status_code=502, detail=_proxmox_error_message(response))
    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Invalid response from Proxmox vncproxy") from exc
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Missing Proxmox vncproxy response data")
    ticket = str(data.get("ticket") or "").strip()
    port = data.get("port")
    if not ticket or port is None:
        raise HTTPException(status_code=502, detail="Proxmox vncproxy did not return ticket and port")
    return {"ticket": ticket, "port": int(port)}


async def _browser_to_proxmox(websocket: WebSocket, upstream) -> None:
    while True:
        message = await websocket.receive()
        message_type = message.get("type")
        if message_type == "websocket.disconnect":
            raise WebSocketDisconnect(code=message.get("code", 1000))
        if message_type != "websocket.receive":
            continue
        if message.get("bytes") is not None:
            await upstream.send(message["bytes"])
        elif message.get("text") is not None:
            await upstream.send(message["text"])


async def _proxmox_to_browser(upstream, websocket: WebSocket) -> None:
    while True:
        message = await upstream.recv()
        if isinstance(message, bytes):
            await websocket.send_bytes(message)
        else:
            await websocket.send_text(message)


@router.post("/api/{tenant_id}/spokes/{spoke_id}/console/{vmid}")
async def create_console_session(
    tenant_id: str,
    spoke_id: str,
    vmid: int,
    vmtype: str = Query("qemu"),
    current_user: User = Depends(auth.get_current_user),
):
    auth.require_tenant_access(tenant_id, current_user)
    _cleanup_sessions()

    spoke = store.get_spoke(tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")
    if spoke.status != "approved":
        raise HTTPException(status_code=409, detail="Spoke is not approved")

    normalized_vmtype = str(vmtype or "qemu").strip().lower()
    if normalized_vmtype not in {"qemu", "lxc"}:
        raise HTTPException(status_code=400, detail="vmtype must be qemu or lxc")

    token_enc = str(getattr(spoke, "proxmox_token_enc", "") or "").strip()
    if not token_enc:
        raise HTTPException(status_code=400, detail="Configure Proxmox credentials first.")
    try:
        proxmox_token = decrypt_str(token_enc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to decrypt Proxmox credentials") from exc

    node = _resolve_spoke_node(spoke)
    if not node:
        raise HTTPException(status_code=400, detail="Spoke telemetry is missing the Proxmox node hostname")

    proxmox_host = str(getattr(spoke, "proxmox_host", "") or "").strip() or str(spoke.hostname or "").strip()
    if not proxmox_host:
        raise HTTPException(status_code=400, detail="Spoke is missing a Proxmox host")

    proxy = await _request_vnc_proxy(
        proxmox_host=proxmox_host,
        proxmox_token=proxmox_token,
        node=node,
        vmid=vmid,
        vmtype=normalized_vmtype,
    )

    session_id = str(uuid.uuid4())
    _sessions[session_id] = {
        "spoke_id": spoke_id,
        "vmid": vmid,
        "vmtype": normalized_vmtype,
        "node": node,
        "ticket": proxy["ticket"],
        "port": proxy["port"],
        "proxmox_host": proxmox_host,
        "proxmox_token": proxmox_token,
        "expires": time.time() + SESSION_TTL,
    }
    return {"session_id": session_id, "expires_in": SESSION_TTL}


@router.websocket("/ws/console/{session_id}")
async def console_websocket(websocket: WebSocket, session_id: str):
    _cleanup_sessions()
    session = _sessions.pop(session_id, None)
    if not session or session.get("expires", 0) < time.time():
        await websocket.close(code=4404, reason="Invalid or expired console session")
        return

    await websocket.accept()

    params = urllib.parse.urlencode(
        {
            "port": session["port"],
            "vncticket": session["ticket"],
        }
    )
    path = (
        f"/api2/json/nodes/{urllib.parse.quote(session['node'], safe='')}/"
        f"{session['vmtype']}/{session['vmid']}/vncwebsocket?{params}"
    )
    upstream_url = f"wss://{session['proxmox_host']}:8006{path}"

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    connect_kwargs: dict[str, Any] = {
        "ssl": ssl_context,
        "open_timeout": 20,
        "max_size": None,
        _CONNECT_HEADER_ARG: _proxmox_headers(session["proxmox_token"]),
    }

    upstream = None
    relay_tasks: list[asyncio.Task[Any]] = []
    try:
        async with websockets.connect(upstream_url, **connect_kwargs) as upstream:
            relay_tasks = [
                asyncio.create_task(_browser_to_proxmox(websocket, upstream)),
                asyncio.create_task(_proxmox_to_browser(upstream, websocket)),
            ]
            done, pending = await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*relay_tasks, return_exceptions=True)
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, (WebSocketDisconnect, websockets.ConnectionClosed)):
                    raise exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Console relay failed for session %s: %s", session_id, exc)
        if websocket.application_state != WebSocketState.DISCONNECTED:
            await websocket.close(code=1011, reason="Console relay failed")
    finally:
        for task in relay_tasks:
            if not task.done():
                task.cancel()
        if relay_tasks:
            await asyncio.gather(*relay_tasks, return_exceptions=True)
        if websocket.application_state != WebSocketState.DISCONNECTED:
            await websocket.close()
