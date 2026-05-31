from __future__ import annotations

import asyncio
import json
from typing import Optional

from fastapi import HTTPException, WebSocket, WebSocketDisconnect

from .auth import decode_access_token
from .data_models import User

# Maps each browser WebSocket to the set of tenant IDs it may see.
# None means the connection belongs to a superadmin who sees all tenants.
browser_connections: dict[WebSocket, Optional[frozenset[str]]] = {}
spoke_connections: dict[tuple[str, str], WebSocket] = {}
_spoke_send_locks: dict[tuple[str, str], asyncio.Lock] = {}
_shell_queues: dict[str, asyncio.Queue] = {}
_vnc_queues: dict[str, asyncio.Queue] = {}
_log_fetch_queues: dict[str, asyncio.Queue] = {}
_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _main_loop
    _main_loop = loop


def _extract_ws_token(message: str) -> str:
    candidate = str(message or "").strip()
    if not candidate:
        return ""
    if not candidate.startswith("{"):
        return candidate
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        return ""
    if not isinstance(payload, dict):
        return ""
    token = payload.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()
    inner = payload.get("payload")
    if isinstance(inner, dict):
        nested = inner.get("token")
        if isinstance(nested, str):
            return nested.strip()
    return ""


async def _close_unauthorized(websocket: WebSocket, reason: str) -> None:
    await websocket.close(code=4401, reason=reason)


async def _authenticate_browser_websocket(websocket: WebSocket) -> Optional[User]:
    """Authenticate a browser WebSocket. Returns the User on success, None on failure."""
    token = str(websocket.query_params.get("token") or "").strip()
    if token:
        try:
            user = decode_access_token(token)
        except HTTPException:
            await _close_unauthorized(websocket, "Invalid credentials")
            return None
        await websocket.accept()
        return user

    await websocket.accept()
    try:
        token = _extract_ws_token(await asyncio.wait_for(websocket.receive_text(), timeout=10))
    except asyncio.TimeoutError:
        await _close_unauthorized(websocket, "Authentication timeout")
        return None
    except WebSocketDisconnect:
        return None
    except Exception:
        await _close_unauthorized(websocket, "Authentication required")
        return None

    if not token:
        await _close_unauthorized(websocket, "Authentication required")
        return None

    try:
        user = decode_access_token(token)
    except HTTPException:
        await _close_unauthorized(websocket, "Invalid credentials")
        return None
    return user


async def ws_connect(websocket: WebSocket) -> None:
    user = await _authenticate_browser_websocket(websocket)
    if user is None:
        return
    # Superadmins get None (see all tenants); others get a frozenset of their tenant IDs.
    tenant_scope: Optional[frozenset[str]] = None if user.is_superadmin else frozenset(user.tenant_ids())
    browser_connections[websocket] = tenant_scope
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        browser_connections.pop(websocket, None)


async def register_spoke(websocket: WebSocket, tenant_id: str, spoke_id: str) -> None:
    await websocket.accept()
    key = (tenant_id, spoke_id)
    spoke_connections[key] = websocket
    _spoke_send_locks.setdefault(key, asyncio.Lock())


async def unregister_spoke(tenant_id: str, spoke_id: str, websocket: WebSocket | None = None) -> None:
    key = (tenant_id, spoke_id)
    current = spoke_connections.get(key)
    if websocket is None or current is websocket:
        spoke_connections.pop(key, None)
        _spoke_send_locks.pop(key, None)


async def ws_broadcast(data: dict) -> None:
    # Extract the tenant_id this event belongs to (may be top-level or nested in "job").
    tenant_id: Optional[str] = data.get("tenant_id") or (data.get("job") or {}).get("tenant_id")
    dead = set()
    message = json.dumps(data)
    for ws, tenant_scope in tuple(browser_connections.items()):
        # tenant_scope is None → superadmin, sees everything.
        # Otherwise only send if tenant_id matches the connection's allowed set.
        if tenant_id and tenant_scope is not None and tenant_id not in tenant_scope:
            continue
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    for ws in dead:
        browser_connections.pop(ws, None)


def register_shell_session(session_id: str) -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue()
    _shell_queues[session_id] = queue
    return queue


def unregister_shell_session(session_id: str) -> None:
    _shell_queues.pop(session_id, None)


def route_shell_message(message: dict) -> None:
    session_id = str(message.get("session_id") or "").strip()
    if not session_id:
        return
    queue = _shell_queues.get(session_id)
    if queue is not None:
        queue.put_nowait(message)


def register_vnc_session(request_id: str) -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue()
    _vnc_queues[request_id] = queue
    return queue


def unregister_vnc_session(request_id: str) -> None:
    _vnc_queues.pop(request_id, None)


def route_vnc_message(message: dict) -> None:
    request_id = str(message.get("request_id") or "").strip()
    if not request_id:
        return
    queue = _vnc_queues.get(request_id)
    if queue is not None:
        queue.put_nowait(message)


# ── Proxmox token provisioning session queues ─────────────────────
_provision_queues: dict[str, asyncio.Queue] = {}


def register_provision_session(request_id: str) -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue()
    _provision_queues[request_id] = queue
    return queue


def unregister_provision_session(request_id: str) -> None:
    _provision_queues.pop(request_id, None)


def route_provision_message(message: dict) -> None:
    request_id = str(message.get("request_id") or "").strip()
    if not request_id:
        return
    queue = _provision_queues.get(request_id)
    if queue is not None:
        queue.put_nowait(message)


async def send_to_spoke(tenant_id: str, spoke_id: str, message: dict) -> bool:
    key = (tenant_id, spoke_id)
    websocket = spoke_connections.get(key)
    if websocket is None:
        return False
    lock = _spoke_send_locks.setdefault(key, asyncio.Lock())
    try:
        async with lock:
            await websocket.send_json(message)
    except Exception:
        await unregister_spoke(tenant_id, spoke_id, websocket)
        return False
    return True


async def send_spoke_command(tenant_id: str, spoke_id: str, command: dict) -> bool:
    return await send_to_spoke(tenant_id, spoke_id, {"type": "commands", "commands": [command]})


async def push_spoke_commands(tenant_id: str, spoke_id: str) -> bool:
    websocket = spoke_connections.get((tenant_id, spoke_id))
    if websocket is None:
        return False

    from . import store

    commands = store.peek_queued_commands(tenant_id, spoke_id)
    if not commands:
        return True

    payload = {
        "type": "commands",
        "commands": [
            {"id": c.id, "target": c.target, "type": c.type, "payload": c.payload}
            for c in commands
        ],
    }
    sent = await send_to_spoke(tenant_id, spoke_id, payload)
    if not sent:
        return False

    store.mark_commands_delivered(tenant_id, spoke_id, [command.id for command in commands])
    return True


def notify_spoke_command(tenant_id: str, spoke_id: str) -> None:
    if _main_loop is None:
        return
    asyncio.run_coroutine_threadsafe(push_spoke_commands(tenant_id, spoke_id), _main_loop)


def register_log_fetch(request_id: str) -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue()
    _log_fetch_queues[request_id] = queue
    return queue


def unregister_log_fetch(request_id: str) -> None:
    _log_fetch_queues.pop(request_id, None)


def route_log_fetch_message(message: dict) -> None:
    request_id = str(message.get("request_id") or "").strip()
    if not request_id:
        return
    queue = _log_fetch_queues.get(request_id)
    if queue is not None:
        queue.put_nowait(message)


# ── Command trace queues (hub → spoke → hub round-trip for debug) ─────────────
_command_trace_queues: dict[str, asyncio.Queue] = {}


def register_command_trace(request_id: str) -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue()
    _command_trace_queues[request_id] = queue
    return queue


def unregister_command_trace(request_id: str) -> None:
    _command_trace_queues.pop(request_id, None)


def route_command_trace_message(message: dict) -> None:
    request_id = str(message.get("request_id") or "").strip()
    if not request_id:
        return
    queue = _command_trace_queues.get(request_id)
    if queue is not None:
        queue.put_nowait(message)
